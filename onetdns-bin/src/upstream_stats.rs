//! Saves upstream stats to a file and loads them on restart.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;

use crate::atomic_file::atomic_write;
use crate::{read_text_limited, sleep_or_shutdown};

const UPSTREAM_STATS_FILE: &str = "upstream-stats.json";

const MAX_UPSTREAM_STATS_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn upstream_stats_path(
    config_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    Some(config_path?.parent()?.join(UPSTREAM_STATS_FILE))
}

/// So a restart does not forget which upstreams did well.
pub(crate) fn save_upstream_stats(
    path: &std::path::Path,
    reports: &[onetdns_forward::UpstreamStatReport],
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Consecutive save failures; warned at powers of two.
    static CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);

    match atomic_write(path, upstream_stats_json(reports).as_bytes()) {
        Ok(()) => {
            let failures = CONSECUTIVE_FAILURES.swap(0, Ordering::Relaxed);
            if failures > 0 {
                onetdns_core::info!(
                    event = "upstream.stats_save_recovered",
                    path = %path.display(),
                    failed_attempts = failures,
                    "Saving upstream DNS server statistics works again"
                );
            }
        }
        Err(error) => {
            let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;

            if failures.is_power_of_two() {
                onetdns_core::warn!(
                    event = "upstream.stats_save_failed",
                    path = %path.display(),
                    consecutive_failures = failures,
                    %error,
                    "Could not save upstream DNS server statistics to file"
                );
            }
        }
    }
}

/// The file format.
pub(crate) fn upstream_stats_json(reports: &[onetdns_forward::UpstreamStatReport]) -> String {
    let items: Vec<String> = reports
        .iter()
        .map(|r| {
            format!(
                "{{\"label\":{},\"queries\":{},\"ok\":{},\"fail\":{},\"ewma_ms\":{:.1}}}",
                onetdns_core::json::escape(&r.label),
                r.queries,
                r.ok,
                r.fail,
                r.ewma_ms
            )
        })
        .collect();
    format!("{{\"version\":1,\"reports\":[{}]}}", items.join(","))
}

pub(crate) enum UpstreamStatsError {
    Json(String),
    NotObject,
    Format,
}

impl std::fmt::Display for UpstreamStatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamStatsError::Json(error) => write!(f, "not valid JSON: {error}"),
            UpstreamStatsError::NotObject => f.write_str("not a JSON object"),
            UpstreamStatsError::Format => f.write_str("does not match the current format"),
        }
    }
}

/// Rejects the whole text on any deviation from the file format.
pub(crate) fn parse_upstream_stats(
    text: &str,
) -> Result<Vec<onetdns_forward::UpstreamStatReport>, UpstreamStatsError> {
    let json = onetdns_core::json::parse(text).map_err(UpstreamStatsError::Json)?;
    let onetdns_core::json::Json::Obj(fields) = &json else {
        return Err(UpstreamStatsError::NotObject);
    };
    let reports = (|| {
        if fields.len() != 2
            || fields
                .iter()
                .any(|(key, _)| !matches!(key.as_str(), "version" | "reports"))
            || json
                .get("version")
                .and_then(onetdns_core::json::Json::as_u64)
                != Some(1)
        {
            return None;
        }
        let items = json.get("reports")?.as_array()?;
        items
            .iter()
            .map(|item| {
                let onetdns_core::json::Json::Obj(fields) = item else {
                    return None;
                };
                if fields.len() != 5
                    || fields.iter().any(|(key, _)| {
                        !matches!(
                            key.as_str(),
                            "label" | "queries" | "ok" | "fail" | "ewma_ms"
                        )
                    })
                {
                    return None;
                }
                let ewma_ms = item.get("ewma_ms")?.as_num()?;
                if !ewma_ms.is_finite() || ewma_ms < 0.0 {
                    return None;
                }
                Some(onetdns_forward::UpstreamStatReport {
                    label: item.get("label")?.as_str()?.to_string(),
                    queries: item.get("queries")?.as_u64()?,
                    ok: item.get("ok")?.as_u64()?,
                    fail: item.get("fail")?.as_u64()?,
                    ewma_ms,
                })
            })
            .collect::<Option<Vec<_>>>()
    })();
    reports.ok_or(UpstreamStatsError::Format)
}

pub(crate) fn load_upstream_stats(
    path: &std::path::Path,
) -> Vec<onetdns_forward::UpstreamStatReport> {
    let text = match read_text_limited(path, MAX_UPSTREAM_STATS_BYTES) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return vec![],
        Err(error) => {
            onetdns_core::warn!(
                event = "upstream.stats_load_failed",
                path = %path.display(),
                %error,
                "Could not read the upstream DNS server statistics file; starting fresh for this run"
            );
            return vec![];
        }
    };
    match parse_upstream_stats(&text) {
        Ok(reports) => reports,
        Err(UpstreamStatsError::Json(error)) => {
            onetdns_core::warn!(
                event = "upstream.stats_parse_failed",
                path = %path.display(),
                %error,
                "Upstream DNS server statistics file is corrupted; starting fresh for this run"
            );
            vec![]
        }
        Err(UpstreamStatsError::NotObject) => {
            onetdns_core::warn!(
                event = "upstream.stats_format_invalid",
                path = %path.display(),
                "Upstream DNS server statistics file does not hold a JSON object; starting fresh"
            );
            vec![]
        }
        Err(UpstreamStatsError::Format) => {
            onetdns_core::warn!(
                event = "upstream.stats_format_invalid",
                path = %path.display(),
                "Upstream DNS server statistics file does not match the current format; starting fresh"
            );
            vec![]
        }
    }
}

/// Spawned even without a forwarding path: a later hot apply may build a forwarding resolver whose
/// stats land in this slot. Writes once more on shutdown.
pub(crate) fn spawn_flush(
    path: std::path::PathBuf,
    stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    flush_secs: u64,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let flush_secs = flush_secs.max(1);
    std::thread::Builder::new()
        .name("upstream-stats-flush".into())
        .spawn(move || loop {
            let stop = sleep_or_shutdown(flush_secs, &shutdown);
            let snapshot = stats.lock_recover().as_ref().map(|h| h.snapshot());
            if let Some(reports) = snapshot {
                save_upstream_stats(&path, &reports);
            }
            if stop {
                break;
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_stats_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-upstat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(UPSTREAM_STATS_FILE);
        let reports = vec![onetdns_forward::UpstreamStatReport {
            label: "tls://dns.example".to_string(),
            queries: 42,
            ok: 40,
            fail: 2,
            ewma_ms: 12.3,
        }];
        save_upstream_stats(&path, &reports);
        let loaded = load_upstream_stats(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].label, "tls://dns.example");
        assert_eq!(loaded[0].queries, 42);
        assert_eq!(loaded[0].ok, 40);
        assert_eq!(loaded[0].fail, 2);
        assert!((loaded[0].ewma_ms - 12.3).abs() < 0.05);

        let current = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, current.replacen("\"version\":1", "\"version\":2", 1)).unwrap();
        assert!(load_upstream_stats(&path).is_empty());
        std::fs::write(
            &path,
            r#"{"version":1,"reports":[{"label":"x","queries":1,"ok":1,"fail":0}]}"#,
        )
        .unwrap();
        assert!(load_upstream_stats(&path).is_empty());

        assert!(load_upstream_stats(&dir.join("없는파일.json")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
