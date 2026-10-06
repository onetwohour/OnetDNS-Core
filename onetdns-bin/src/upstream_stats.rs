/*!
 * @brief 업스트림 통계를 파일에 저장하고 다시 시작할 때 읽는다.
 */

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use onetdns_core::MutexExt;

use crate::atomic_file::atomic_write;
use crate::{read_text_limited, sleep_or_shutdown};

/** @brief 업스트림 성적을 담아 둘 파일 이름. */
const UPSTREAM_STATS_FILE: &str = "upstream-stats.json";

/** @brief 읽어들일 업스트림 성적 파일 크기 상한. */
const MAX_UPSTREAM_STATS_BYTES: u64 = 16 * 1024 * 1024;

/** @brief 업스트림 성적 파일 경로. */
pub(crate) fn upstream_stats_path(
    config_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    Some(config_path?.parent()?.join(UPSTREAM_STATS_FILE))
}

/** @brief 업스트림 성적을 저장한다. 재시작해도 어느 업스트림이 좋았는지 잊지 않으려는 것이다. */
pub(crate) fn save_upstream_stats(
    path: &std::path::Path,
    reports: &[onetdns_forward::UpstreamStatReport],
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /** @brief 연달아 실패한 횟수. 계속 실패하면 경고 소리를 줄인다. */
    static CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);

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
    match atomic_write(
        path,
        format!("{{\"version\":1,\"reports\":[{}]}}", items.join(",")).as_bytes(),
    ) {
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

/** @brief 저장된 업스트림 성적을 읽는다. */
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
    let json = match onetdns_core::json::parse(&text) {
        Ok(json) => json,
        Err(error) => {
            onetdns_core::warn!(
                event = "upstream.stats_parse_failed",
                path = %path.display(),
                %error,
                "Upstream DNS server statistics file is corrupted; starting fresh for this run"
            );
            return vec![];
        }
    };
    let onetdns_core::json::Json::Obj(fields) = &json else {
        onetdns_core::warn!(
            event = "upstream.stats_format_invalid",
            path = %path.display(),
            "Upstream DNS server statistics file does not hold a JSON object; starting fresh"
        );
        return vec![];
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
    let Some(reports) = reports else {
        onetdns_core::warn!(
            event = "upstream.stats_format_invalid",
            path = %path.display(),
            "Upstream DNS server statistics file does not match the current format; starting fresh"
        );
        return vec![];
    };
    reports
}

/**
 * @brief 업스트림 성적을 주기마다 파일에 쓰는 스레드를 띄운다.
 * @details 전달 경로가 없어도 띄운다. 핫 적용이 나중에 전달 리졸버를 만들면 그 통계가 이 슬롯에
 *          들어온다. 종료 신호를 받으면 한 번 더 쓰고 끝난다.
 */
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
/** @brief 업스트림 통계 파일의 저장과 복원. */
mod tests {
    use super::*;

    #[test]
    /** @brief 업스트림 성적이 저장됐다 읽히는지. */
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
