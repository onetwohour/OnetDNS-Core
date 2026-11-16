//! Saves statistics and the recent query log so they survive a restart.
//!
//! Files read back are untrusted. Any deviation from the format discards the whole file,
//! because half-applied statistics are worse than none.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use onetdns_core::json::{self, Json};
use onetdns_core::Transport;

use onetdns_proto::Name;

use crate::metrics::{
    intern_action, intern_transport, MetricBucket, Metrics, PersistOpts, QueryEvent, TopCounters,
};

const MAX_STATS_FILE: usize = 16 * 1024 * 1024;
const MAX_QUERYLOG_LINE: usize = 64 * 1024;

/// Writes `data` to a temporary file and renames it over `path`. Only the owner can read the
/// result, since the query log holds client addresses. On Unix the directory is synced too,
/// or the rename may not reach the disk.
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("onetdns");
    let nonce = u64::from_le_bytes(onetdns_core::rng::try_random_array::<8>()?);
    let tmp_name = format!(
        ".{fname}.tmp.{}.{}.{nonce:016x}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(directory) = dir {
        create_dir_private(directory)?;
    }
    let tmp = match dir {
        Some(d) => d.join(&tmp_name),
        None => std::path::PathBuf::from(&tmp_name),
    };
    let write_result = (|| -> std::io::Result<()> {
        let mut f = onetdns_core::fs::create_private_replacing(&tmp, path)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = replace_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(directory) = dir {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
/// Windows keeps the folder's ACL here; each file is created private instead.
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(not(windows))]
fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(windows)]
fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(once(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(once(0)).collect();
    let ok = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Reads the saved query log, dropping entries past retention or over the count limit. A
/// missing file is an empty log.
pub(crate) fn load_querylog(
    path: &Path,
    cap: usize,
    retention_ms: u64,
    now_ms: u64,
) -> VecDeque<QueryEvent> {
    let mut out = VecDeque::new();
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return out,
        Err(error) => {
            onetdns_core::warn!(
                event = "querylog.restore_open_failed",
                path = %path.display(),
                %error,
                "Could not open the existing query log file; starting with an empty log"
            );
            return out;
        }
    };
    let cutoff = if retention_ms > 0 {
        now_ms.saturating_sub(retention_ms)
    } else {
        0
    };
    let mut reader = BufReader::new(f);
    let mut oversized = 0u64;
    let mut malformed = 0u64;
    loop {
        let line = match read_bounded_line(&mut reader, MAX_QUERYLOG_LINE, &mut oversized) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                onetdns_core::warn!(
                    event = "querylog.restore_read_failed",
                    path = %path.display(),
                    %error,
                    "Error reading the query log file; starting with an empty log"
                );
                return VecDeque::new();
            }
        };
        let Ok(line) = std::str::from_utf8(&line) else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            malformed = malformed.saturating_add(1);
            continue;
        }
        if let Some(ev) = parse_event(line) {
            if cutoff > 0 && ev.ts_ms < cutoff {
                continue;
            }
            out.push_back(ev);
            if out.len() > cap {
                out.pop_front();
            }
        } else {
            malformed = malformed.saturating_add(1);
        }
    }
    if oversized > 0 || malformed > 0 {
        onetdns_core::warn!(
            event = "querylog.restore_invalid",
            path = %path.display(),
            oversized,
            malformed,
            "Query log file is corrupted; starting with an empty log"
        );
        return VecDeque::new();
    }
    out
}

/// Reads one line of at most `max` bytes. A longer line is consumed to its end and counted in
/// `oversized_lines`, so the next read starts on a line boundary.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max: usize,
    oversized_lines: &mut u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if oversized {
                *oversized_lines = oversized_lines.saturating_add(1);
            }
            return Ok((!line.is_empty() && !oversized).then_some(line));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let segment_len = newline.unwrap_or(available.len());
        if !oversized {
            if line.len().saturating_add(segment_len) <= max {
                line.extend_from_slice(&available[..segment_len]);
            } else {
                line.clear();
                oversized = true;
            }
        }
        let consumed = newline.map_or(segment_len, |index| index + 1);
        reader.consume(consumed);
        if newline.is_some() {
            if oversized {
                *oversized_lines = oversized_lines.saturating_add(1);
                line.clear();
                oversized = false;
                continue;
            }
            return Ok(Some(line));
        }
    }
}

/// Parses one log line. Unknown or missing fields mean this format did not write it.
fn parse_event(line: &str) -> Option<QueryEvent> {
    let j = json::parse(line).ok()?;
    let Json::Obj(fields) = &j else {
        return None;
    };
    if fields.len() != 16
        || fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "id" | "ts_ms"
                    | "client"
                    | "name"
                    | "qtype"
                    | "transport"
                    | "action"
                    | "rcode"
                    | "reason"
                    | "stage"
                    | "detail"
                    | "answers"
                    | "upstream"
                    | "rule"
                    | "list"
                    | "latency_us"
            )
        })
    {
        return None;
    }
    let ts_ms = j.get("ts_ms")?.as_u64()?;
    let name = j.get("name")?.as_str()?;
    let name = (!name.is_empty())
        .then(|| Name::from_str(name))
        .transpose()
        .ok()?;
    let qtype = j.get("qtype")?.as_str()?.to_string();
    let transport = j.get("transport")?.as_str()?;
    if !Transport::ALL.iter().any(|known| known.name() == transport) {
        return None;
    }
    let action = j.get("action")?.as_str()?;
    if !matches!(
        action,
        "resolved" | "blocked" | "rewritten" | "denied" | "throttled" | "servfail" | "refused"
    ) {
        return None;
    }
    let parse_u64 = |key: &str| j.get(key)?.as_u64();
    let s = |key: &str| Some(j.get(key)?.as_str()?.to_string());
    Some(QueryEvent {
        id: parse_u64("id")?,
        ts_ms,
        client: s("client")?.parse().ok()?,
        name,
        qtype,
        transport: intern_transport(transport),
        action: intern_action(action),
        rcode: s("rcode")?,
        reason: s("reason")?,
        stage: s("stage")?,
        detail: s("detail")?,
        answers: s("answers")?,
        upstream: s("upstream")?,
        rule: s("rule")?,
        list: s("list")?,
        latency_us: parse_u64("latency_us")?,
        log: true,
        stat: false,
    })
}

pub(crate) fn save_querylog(path: &Path, buf: &VecDeque<QueryEvent>) -> std::io::Result<()> {
    let mut s = String::with_capacity(buf.len() * 80);
    for ev in buf {
        s.push_str(&ev.to_json());
        s.push('\n');
    }
    atomic_write(path, s.as_bytes())
}

pub(crate) fn save_stats(path: &Path, m: &Metrics, top: &TopCounters) -> std::io::Result<()> {
    atomic_write(path, stats_json(m, top).as_bytes())
}

/// One line in the statistics file format.
pub(crate) fn stats_json(m: &Metrics, top: &TopCounters) -> String {
    let snapshot = m.current_snapshot();
    let mut s = String::with_capacity(4096);
    s.push_str("{\"version\":1,\"metrics\":{");
    s.push_str(&format!("\"total\":\"{}\"", snapshot.total));
    s.push_str(&format!(",\"resolved\":\"{}\"", snapshot.resolved));
    s.push_str(&format!(",\"blocked\":\"{}\"", snapshot.blocked));
    s.push_str(&format!(",\"rewritten\":\"{}\"", snapshot.rewritten));
    s.push_str(&format!(",\"denied\":\"{}\"", snapshot.denied));
    s.push_str(&format!(",\"refused\":\"{}\"", snapshot.refused));
    s.push_str(&format!(",\"throttled\":\"{}\"", snapshot.throttled));
    s.push_str(&format!(",\"servfail\":\"{}\"", snapshot.servfail));
    s.push_str(&format!(
        ",\"latency_sum_us\":\"{}\"",
        snapshot.latency_sum_us
    ));
    s.push_str(&format!(
        ",\"latency_count\":\"{}\"",
        snapshot.latency_count
    ));
    s.push_str(&format!(",\"cache_hits\":\"{}\"", snapshot.cache_hits));
    s.push_str(&format!(
        ",\"cache_lookups\":\"{}\"",
        snapshot.cache_lookups
    ));
    s.push_str(&format!(
        ",\"dropped_log_events\":\"{}\"",
        snapshot.dropped_log_events
    ));
    s.push_str(&format!(
        ",\"dropped_stat_events\":\"{}\"",
        snapshot.dropped_stat_events
    ));
    s.push_str(&format!(
        ",\"dropped_stream_events\":\"{}\"",
        snapshot.dropped_stream_events
    ));
    s.push_str(&format!(
        ",\"persist_failures\":\"{}\"",
        snapshot.persist_failures
    ));
    s.push_str(",\"by_transport\":[");
    for (i, (_, count)) in snapshot.by_transport.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&json::escape(&count.to_string()));
    }
    s.push_str("]},\"top\":{");
    write_pairs(&mut s, "domains", &top.domains);
    s.push(',');
    write_pairs(&mut s, "blocked", &top.blocked);
    s.push(',');
    write_pairs(&mut s, "clients", &top.clients);
    s.push_str("}}");
    s
}

fn write_pairs<K: std::fmt::Display>(s: &mut String, key: &str, map: &HashMap<K, u64>) {
    s.push_str(&json::escape(key));
    s.push_str(":[");
    for (i, (k, v)) in map.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        s.push_str(&json::escape(&k.to_string()));
        s.push(',');
        s.push_str(&json::escape(&v.to_string()));
        s.push(']');
    }
    s.push(']');
}

/// Reads saved statistics and applies them. Nothing is applied until the whole file parses.
pub(crate) fn load_stats(path: &Path, m: &Metrics, top: &mut TopCounters) {
    if let Some(saved) = read_stats(path, m.by_transport.len()) {
        m.add_totals(&saved);
        top.add_counts(saved.domains, saved.top_blocked, saved.clients);
    }
}

/// The saved statistics, if the whole file parses. Top lists over their cap keep the largest counts.
fn read_stats(path: &Path, transport_count: usize) -> Option<PersistedStatsSnapshot> {
    let mut bytes = Vec::new();
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            onetdns_core::warn!(
                event = "stats.restore_open_failed",
                path = %path.display(),
                %error,
                "Could not open the existing statistics file; starting statistics fresh"
            );
            return None;
        }
    };
    if let Err(error) = file
        .take((MAX_STATS_FILE + 1) as u64)
        .read_to_end(&mut bytes)
    {
        onetdns_core::warn!(
            event = "stats.restore_read_failed",
            path = %path.display(),
            %error,
            "Could not read the existing statistics file; starting statistics fresh"
        );
        return None;
    }
    if bytes.len() > MAX_STATS_FILE {
        onetdns_core::warn!(
            event = "stats.restore_too_large",
            path = %path.display(),
            bytes = bytes.len(),
            limit = MAX_STATS_FILE,
            "Existing statistics file exceeds the size limit; not restoring it"
        );
        return None;
    }
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            onetdns_core::warn!(
                event = "stats.restore_invalid_utf8",
                path = %path.display(),
                %error,
                "Existing statistics file is not valid text; not restoring it"
            );
            return None;
        }
    };
    let j = match json::parse_with_limit(&text, MAX_STATS_FILE) {
        Ok(j) => j,
        Err(error) => {
            onetdns_core::warn!(
                event = "stats.restore_invalid_json",
                path = %path.display(),
                %error,
                "Existing statistics file is not valid JSON; not restoring it"
            );
            return None;
        }
    };
    let mut restored = match parse_stats_snapshot(&j, transport_count) {
        Ok(restored) => restored,
        Err(reason) => {
            onetdns_core::warn!(
                event = "stats.restore_invalid_value",
                path = %path.display(),
                reason,
                "Existing statistics file has invalid values; skipping the whole restore"
            );
            return None;
        }
    };

    cap_restored_top(path, "domains", &mut restored.domains);
    cap_restored_top(path, "blocked", &mut restored.top_blocked);
    cap_restored_top(path, "clients", &mut restored.clients);
    Some(restored)
}

/// Trims a restored top list to its cap, keeping the largest counts. Eviction replaces entries
/// without shrinking the map, so an oversized restore would stay oversized until exit.
fn cap_restored_top<K: Eq + std::hash::Hash + Ord + std::fmt::Display>(
    path: &Path,
    kind: &'static str,
    map: &mut HashMap<K, u64>,
) {
    if map.len() <= crate::metrics::TOP_CAP {
        return;
    }
    let dropped = map.len() - crate::metrics::TOP_CAP;
    let mut pairs: Vec<(K, u64)> = std::mem::take(map).into_iter().collect();
    // Ties break by name so the kept entries do not vary between runs.
    pairs.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    pairs.truncate(crate::metrics::TOP_CAP);
    map.extend(pairs);
    onetdns_core::warn!(
        event = "stats.restore_top_truncated",
        path = %path.display(),
        kind,
        dropped,
        "Saved top list exceeds its limit; dropped the entries with the lowest counts"
    );
}

#[derive(Default)]
/// Statistics read from a file and fully validated. Only this form is applied.
pub(crate) struct PersistedStatsSnapshot {
    pub(crate) total: u64,
    pub(crate) resolved: u64,
    pub(crate) blocked: u64,
    pub(crate) rewritten: u64,
    pub(crate) denied: u64,
    pub(crate) refused: u64,
    pub(crate) throttled: u64,
    pub(crate) servfail: u64,
    pub(crate) latency_sum_us: u64,
    pub(crate) latency_count: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_lookups: u64,
    pub(crate) dropped_log_events: u64,
    pub(crate) dropped_stat_events: u64,
    pub(crate) dropped_stream_events: u64,
    pub(crate) persist_failures: u64,
    pub(crate) by_transport: Vec<u64>,
    pub(crate) domains: HashMap<Name, u64>,
    pub(crate) top_blocked: HashMap<Name, u64>,
    pub(crate) clients: HashMap<std::net::IpAddr, u64>,
}

/// What a running process hands to the one replacing it: totals and top lists, the query log, the
/// ID the next logged query gets, and the graph history.
pub(crate) struct CarriedStats {
    pub(crate) totals: PersistedStatsSnapshot,
    /// Oldest first, IDs ascending and below `next_event_id`.
    pub(crate) recent: VecDeque<QueryEvent>,
    pub(crate) next_event_id: u64,
    pub(crate) seconds: Vec<MetricBucket>,
    pub(crate) minutes: Vec<MetricBucket>,
}

/// Bumped with the handoff protocol version when the format changes.
const CARRIED_VERSION: u64 = 1;

/// A header line with the next query log ID and the graph history, a line in the statistics file
/// format, then the query log in its file format.
pub(crate) fn encode_carried(
    stats_line: &str,
    recent: &VecDeque<QueryEvent>,
    next_event_id: u64,
    seconds: &VecDeque<MetricBucket>,
    minutes: &VecDeque<MetricBucket>,
) -> Vec<u8> {
    let mut s = format!(
        "{{\"version\":{CARRIED_VERSION},\"next_event_id\":\"{next_event_id}\",\"seconds\":"
    );
    write_buckets(&mut s, seconds);
    s.push_str(",\"minutes\":");
    write_buckets(&mut s, minutes);
    s.push_str("}\n");
    s.push_str(stats_line);
    s.push('\n');
    for event in recent {
        s.push_str(&event.to_json());
        s.push('\n');
    }
    s.into_bytes()
}

fn write_buckets(s: &mut String, buckets: &VecDeque<MetricBucket>) {
    s.push('[');
    for (i, b) in buckets.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "[\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"]",
            b.ts_sec,
            b.span_secs,
            b.queries,
            b.blocked,
            b.latency_sum_us,
            b.latency_count,
            b.cache_hits,
            b.cache_lookups
        ));
    }
    s.push(']');
}

/// Rejects the whole state on any deviation, as the saved files are.
pub(crate) fn decode_carried(bytes: &[u8], transport_count: usize) -> Result<CarriedStats, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "The state is not valid text".to_string())?;
    let mut lines = text.split('\n');
    let header = lines.next().unwrap_or_default();
    let header = json::parse_with_limit(header, MAX_STATS_FILE)
        .map_err(|error| format!("header: {error}"))?;
    let Json::Obj(fields) = &header else {
        return Err("header: must be an object".to_string());
    };
    if fields.len() != 4
        || fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "version" | "next_event_id" | "seconds" | "minutes"
            )
        })
    {
        return Err("header: entries do not match the current format".to_string());
    }
    if header.get("version").and_then(Json::as_u64) != Some(CARRIED_VERSION) {
        return Err(format!("header: version must be {CARRIED_VERSION}"));
    }
    let next_event_id =
        json_u64(&header, "next_event_id").map_err(|reason| format!("next_event_id: {reason}"))?;
    let seconds = parse_buckets(&header, "seconds")?;
    let minutes = parse_buckets(&header, "minutes")?;

    let stats = lines
        .next()
        .ok_or_else(|| "The statistics line is missing".to_string())?;
    let stats = json::parse_with_limit(stats, MAX_STATS_FILE)
        .map_err(|error| format!("statistics: {error}"))?;
    let totals = parse_stats_snapshot(&stats, transport_count)?;

    let mut recent = VecDeque::new();
    let mut previous_id = 0;
    let mut ended = false;
    for (index, line) in lines.enumerate() {
        if ended {
            return Err(format!("query log line {index}: follows an empty line"));
        }
        if line.is_empty() {
            ended = true;
            continue;
        }
        if line.len() > MAX_QUERYLOG_LINE {
            return Err(format!("query log line {index}: too long"));
        }
        let event =
            parse_event(line).ok_or_else(|| format!("query log line {index}: invalid event"))?;
        if event.id <= previous_id || event.id >= next_event_id {
            return Err(format!(
                "query log line {index}: IDs must ascend and stay below next_event_id"
            ));
        }
        previous_id = event.id;
        recent.push_back(event);
    }
    if !ended {
        return Err("The state does not end with a newline".to_string());
    }
    Ok(CarriedStats {
        totals,
        recent,
        next_event_id,
        seconds,
        minutes,
    })
}

/// Each bucket is `[end, span, queries, blocked, latency_sum_us, latency_count, cache_hits,
/// cache_lookups]`, ends ascending.
fn parse_buckets(header: &Json, key: &str) -> Result<Vec<MetricBucket>, String> {
    let array = header
        .get(key)
        .and_then(Json::as_array)
        .ok_or_else(|| format!("{key}: must be an array"))?;
    let mut out: Vec<MetricBucket> = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let values = entry
            .as_array()
            .filter(|values| values.len() == 8)
            .ok_or_else(|| format!("{key}[{index}]: must be an array of eight counts"))?
            .iter()
            .map(exact_u64)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|reason| format!("{key}[{index}]: {reason}"))?;
        let bucket = MetricBucket {
            ts_sec: values[0],
            span_secs: values[1],
            queries: values[2],
            blocked: values[3],
            latency_sum_us: values[4],
            latency_count: values[5],
            cache_hits: values[6],
            cache_lookups: values[7],
        };
        if out.last().is_some_and(|last| last.ts_sec >= bucket.ts_sec) {
            return Err(format!("{key}[{index}]: ends must ascend"));
        }
        out.push(bucket);
    }
    Ok(out)
}

/// The saved statistics and query log as a predecessor would have handed them over, for when it
/// ended without doing so. The graph history is not saved, so it is empty.
pub(crate) fn read_saved(
    persist: &PersistOpts,
    log_cap: usize,
    retention_ms: u64,
    now_ms: u64,
    transport_count: usize,
) -> CarriedStats {
    let totals = persist
        .stats_file
        .as_deref()
        .and_then(|path| read_stats(path, transport_count))
        .unwrap_or_default();
    let mut recent = persist
        .querylog_file
        .as_deref()
        .map(|path| load_querylog(path, log_cap, retention_ms, now_ms))
        .unwrap_or_default();
    let next_event_id = number_events(&mut recent);
    CarriedStats {
        totals,
        recent,
        next_event_id,
        seconds: Vec::new(),
        minutes: Vec::new(),
    }
}

/// Gives events saved without an ID the next free one; returns the ID after the last.
pub(crate) fn number_events(events: &mut VecDeque<QueryEvent>) -> u64 {
    let mut next = 1u64;
    for event in events.iter_mut() {
        if event.id == 0 {
            event.id = next;
        }
        next = next.max(event.id.saturating_add(1));
    }
    next
}

fn parse_stats_snapshot(
    root: &Json,
    transport_count: usize,
) -> Result<PersistedStatsSnapshot, String> {
    let Json::Obj(root_fields) = root else {
        return Err("Top-level value must be an object".to_string());
    };
    if root_fields.len() != 3
        || root_fields
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), "version" | "metrics" | "top"))
    {
        return Err("Top-level entries do not match the current format".to_string());
    }
    if root.get("version").and_then(Json::as_u64) != Some(1) {
        return Err("version must be the current format 1".to_string());
    }
    let metrics = root
        .get("metrics")
        .ok_or_else(|| "Missing metrics entry".to_string())?;
    let Json::Obj(metric_fields) = metrics else {
        return Err("metrics must be an object".to_string());
    };
    if metric_fields.len() != 17
        || metric_fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "total"
                    | "resolved"
                    | "blocked"
                    | "rewritten"
                    | "denied"
                    | "refused"
                    | "throttled"
                    | "servfail"
                    | "latency_sum_us"
                    | "latency_count"
                    | "cache_hits"
                    | "cache_lookups"
                    | "dropped_log_events"
                    | "dropped_stat_events"
                    | "dropped_stream_events"
                    | "persist_failures"
                    | "by_transport"
            )
        })
    {
        return Err("metrics entries do not match the current format".to_string());
    }
    let counter =
        |key: &str| json_u64(metrics, key).map_err(|reason| format!("metrics.{key}: {reason}"));

    let array = metrics
        .get("by_transport")
        .and_then(Json::as_array)
        .ok_or_else(|| "metrics.by_transport: array is missing or invalid".to_string())?;
    if array.len() != transport_count {
        return Err(format!(
            "metrics.by_transport: must have {transport_count} entries in the current format"
        ));
    }
    let by_transport = array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            exact_u64(value).map_err(|reason| format!("metrics.by_transport[{index}]: {reason}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let top = root
        .get("top")
        .ok_or_else(|| "Missing top entry".to_string())?;
    let Json::Obj(top_fields) = top else {
        return Err("top must be an object".to_string());
    };
    if top_fields.len() != 3
        || top_fields
            .iter()
            .any(|(key, _)| !matches!(key.as_str(), "domains" | "blocked" | "clients"))
    {
        return Err("top entries do not match the current format".to_string());
    }
    Ok(PersistedStatsSnapshot {
        total: counter("total")?,
        resolved: counter("resolved")?,
        blocked: counter("blocked")?,
        rewritten: counter("rewritten")?,
        denied: counter("denied")?,
        refused: counter("refused")?,
        throttled: counter("throttled")?,
        servfail: counter("servfail")?,
        latency_sum_us: counter("latency_sum_us")?,
        latency_count: counter("latency_count")?,
        cache_hits: counter("cache_hits")?,
        cache_lookups: counter("cache_lookups")?,
        dropped_log_events: counter("dropped_log_events")?,
        dropped_stat_events: counter("dropped_stat_events")?,
        dropped_stream_events: counter("dropped_stream_events")?,
        persist_failures: counter("persist_failures")?,
        by_transport,
        // Use the live aggregation's key rule, or names differing only in case stay split and are
        // rewritten on every flush. Names that collide after folding mean the file used the old
        // rule, so it is discarded.
        domains: parse_pairs(top, "domains", |n| {
            Name::from_str(n)
                .ok()
                .map(|n| n.to_ascii_lower_name().into_owned())
        })?,
        top_blocked: parse_pairs(top, "blocked", |n| {
            Name::from_str(n)
                .ok()
                .map(|n| n.to_ascii_lower_name().into_owned())
        })?,
        clients: parse_pairs(top, "clients", |n| n.parse().ok())?,
    })
}

fn json_u64(object: &Json, key: &str) -> Result<u64, String> {
    exact_u64(object.get(key).ok_or_else(|| "Missing entry".to_string())?)
}

/// Reads a JSON number as an exact u64. Counters can exceed what a float holds exactly.
pub(crate) fn exact_u64(value: &Json) -> Result<u64, String> {
    if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Must be a non-negative decimal integer".to_string());
        }
        return text
            .parse::<u64>()
            .map_err(|_| "Must fit in a non-negative 64-bit integer".to_string());
    }
    Err("Must be a non-negative 64-bit integer written as a decimal string".to_string())
}

fn parse_pairs<K, F>(top: &Json, key: &str, to_key: F) -> Result<HashMap<K, u64>, String>
where
    K: Eq + std::hash::Hash,
    F: Fn(&str) -> Option<K>,
{
    let value = top.get(key).ok_or_else(|| format!("top.{key}: missing"))?;
    let array = value
        .as_array()
        .ok_or_else(|| format!("top.{key}: must be an array"))?;
    if array.len() > 10_000 {
        return Err(format!("top.{key}: more than 10,000 entries"));
    }
    let mut out = HashMap::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        let pair = entry
            .as_array()
            .ok_or_else(|| format!("top.{key}[{index}]: must be a [name, count] array"))?;
        if pair.len() != 2 {
            return Err(format!(
                "top.{key}[{index}]: entry must have exactly two values, name and count"
            ));
        }
        let name = pair[0]
            .as_str()
            .ok_or_else(|| format!("top.{key}[{index}][0]: name must be a string"))?;
        if name.is_empty() || name.len() > 4_096 {
            return Err(format!(
                "top.{key}[{index}][0]: name length is out of range"
            ));
        }
        let count =
            exact_u64(&pair[1]).map_err(|reason| format!("top.{key}[{index}][1]: {reason}"))?;
        let parsed =
            to_key(name).ok_or_else(|| format!("top.{key}[{index}][0]: invalid {name}"))?;
        if out.insert(parsed, count).is_some() {
            return Err(format!("top.{key}: duplicate entry {name}"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// The state a running process hands to its successor, as version 1 writes it.
    const CARRIED_EXAMPLE: &str = concat!(
        r#"{"version":1,"next_event_id":"3","seconds":[["1700000000","1","3","1","240","2","1","2"]],"minutes":[["1699999980","1","3","1","240","2","1","2"]]}"#,
        "\n",
        r#"{"version":1,"metrics":{"total":"3","resolved":"2","blocked":"1","rewritten":"0","denied":"0","refused":"0","throttled":"0","servfail":"0","latency_sum_us":"240","latency_count":"2","cache_hits":"1","cache_lookups":"2","dropped_log_events":"0","dropped_stat_events":"0","dropped_stream_events":"0","persist_failures":"0","by_transport":["0","0","0","3","0","0","0"]},"top":{"domains":[["a.example.","2"],["b.example.","1"]],"blocked":[["a.example.","1"]],"clients":[["192.0.2.1","3"]]}}"#,
        "\n",
        r#"{"id":1,"ts_ms":1699999999000,"client":"192.0.2.1","name":"a.example.","qtype":"A","transport":"doh","action":"blocked","rcode":"NOERROR","reason":"","stage":"","detail":"","answers":"","upstream":"","rule":"","list":"","latency_us":120}"#,
        "\n",
        r#"{"id":2,"ts_ms":1700000000000,"client":"192.0.2.1","name":"b.example.","qtype":"A","transport":"doh","action":"resolved","rcode":"NOERROR","reason":"","stage":"","detail":"","answers":"","upstream":"","rule":"","list":"","latency_us":120}"#,
        "\n",
    );

    #[test]
    fn the_carried_state_format_reads_its_example() {
        let carried = decode_carried(CARRIED_EXAMPLE.as_bytes(), Transport::COUNT).unwrap();
        assert_eq!(carried.next_event_id, 3);
        assert_eq!(carried.totals.total, 3);
        assert_eq!(carried.totals.blocked, 1);
        assert_eq!(carried.totals.by_transport, [0, 0, 0, 3, 0, 0, 0]);
        let name = |n: &str| Name::from_str(n).unwrap();
        assert_eq!(carried.totals.domains.get(&name("a.example.")), Some(&2));
        assert_eq!(
            carried.totals.top_blocked.get(&name("a.example.")),
            Some(&1)
        );
        assert_eq!(
            carried.totals.clients.get(&"192.0.2.1".parse().unwrap()),
            Some(&3)
        );
        let ids: Vec<u64> = carried.recent.iter().map(|event| event.id).collect();
        assert_eq!(ids, [1, 2]);
        assert_eq!(carried.recent[0].action, "blocked");
        assert_eq!(carried.seconds.len(), 1);
        assert_eq!(carried.seconds[0].ts_sec, 1_700_000_000);
        assert_eq!(carried.seconds[0].queries, 3);
        assert_eq!(carried.minutes[0].ts_sec, 1_699_999_980);
        assert_eq!(carried.minutes[0].cache_lookups, 2);
    }

    #[test]
    fn a_carried_state_off_the_format_is_rejected_whole() {
        let broken = [
            CARRIED_EXAMPLE.replace(r#""version":1,"next"#, r#""version":2,"next"#),
            CARRIED_EXAMPLE.replace(r#""next_event_id":"3""#, r#""next_event_id":"2""#),
            CARRIED_EXAMPLE.replace(r#"{"id":2,"#, r#"{"id":1,"#),
            CARRIED_EXAMPLE.replace(r#"[["1699999980""#, r#"[["1800000000""#)
                .replace(r#""minutes":[["1800000000","1","3","1","240","2","1","2"]]"#,
                    r#""minutes":[["1800000000","1","3","1","240","2","1","2"],["1700000000","1","3","1","240","2","1","2"]]"#),
            CARRIED_EXAMPLE.replace(r#""minutes":"#, r#""extra":[],"minutes":"#),
            CARRIED_EXAMPLE.trim_end_matches('\n').to_string(),
            format!("{CARRIED_EXAMPLE}\n"),
            CARRIED_EXAMPLE.replace(r#""by_transport":["0","0","0","3","0","0","0"]"#, r#""by_transport":["3"]"#),
        ];
        for (index, state) in broken.iter().enumerate() {
            assert_ne!(
                state, CARRIED_EXAMPLE,
                "case {index} did not change the example"
            );
            assert!(
                decode_carried(state.as_bytes(), Transport::COUNT).is_err(),
                "case {index} was accepted"
            );
        }
    }

    #[test]
    fn restored_top_lists_are_capped() {
        let cap = crate::metrics::TOP_CAP;
        let mut map: HashMap<String, u64> = HashMap::new();
        for i in 0..(cap + 500) {
            map.insert(format!("d{i:07}.test."), i as u64);
        }
        cap_restored_top(Path::new("/nonexistent/stats.json"), "domains", &mut map);

        assert_eq!(map.len(), cap, "상한을 넘겨 가지고 있으면 안 됩니다");
        assert!(
            map.contains_key(&format!("d{:07}.test.", cap + 499)),
            "가장 많이 물은 이름이 남아야 합니다"
        );
        assert!(
            !map.contains_key("d0000000.test."),
            "가장 적게 물은 이름은 잘려야 합니다"
        );

        let mut small: HashMap<String, u64> = HashMap::new();
        small.insert("only.test.".to_string(), 1);
        cap_restored_top(Path::new("/nonexistent/stats.json"), "domains", &mut small);
        assert_eq!(small.len(), 1, "상한 아래는 건드리지 않아야 합니다");
    }

    fn ev(ts: u64, client: &str, name: &str, action: &'static str) -> QueryEvent {
        QueryEvent {
            id: ts,
            ts_ms: ts,
            client: client.parse().expect("테스트용 주소"),
            name: Some(Name::from_str(name).expect("테스트용 이름")),
            qtype: "A".to_string(),
            transport: "doh",
            action,
            rcode: String::new(),
            reason: String::new(),
            stage: String::new(),
            detail: String::new(),
            answers: String::new(),
            upstream: String::new(),
            rule: String::new(),
            list: String::new(),
            latency_us: 0,
            log: true,
            stat: true,
        }
    }

    #[test]
    fn querylog_roundtrip_and_retention() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("onetdns-qlog-test-{}.jsonl", std::process::id()));
        let mut buf = VecDeque::new();
        buf.push_back(ev(1_000, "10.0.0.1", "old.example", "resolved"));
        let mut blocked = ev(9_000, "10.0.0.2", "ads.example", "blocked");
        blocked.rule = "||ads.example^".to_string();
        blocked.list = "https://lists.example/ads.txt".to_string();
        buf.push_back(blocked);
        save_querylog(&path, &buf).unwrap();

        let all = load_querylog(&path, 100, 0, 10_000);
        assert_eq!(all.len(), 2);
        assert_eq!(
            all[1].name.as_ref().map(Name::to_string),
            Some("ads.example.".to_string())
        );
        assert_eq!(all[1].action, "blocked");
        assert_eq!(all[1].transport, "doh");
        assert_eq!(all[1].rule, "||ads.example^");
        assert_eq!(all[1].list, "https://lists.example/ads.txt");
        assert_eq!(all[0].list, "");

        let recent = load_querylog(&path, 100, 5_000, 10_000);
        assert_eq!(recent.len(), 1);
        assert_eq!(
            recent[0].name.as_ref().map(Name::to_string),
            Some("ads.example.".to_string())
        );

        let capped = load_querylog(&path, 1, 0, 10_000);
        assert_eq!(capped.len(), 1);
        assert_eq!(
            capped[0].name.as_ref().map(Name::to_string),
            Some("ads.example.".to_string())
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn querylog_rejects_the_entire_file_after_an_oversized_line() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-qlog-oversized-test-{}.jsonl",
            std::process::id()
        ));
        let valid = ev(9_000, "10.0.0.2", "valid.example", "resolved").to_json();
        let mut data = vec![b'x'; MAX_QUERYLOG_LINE + 1];
        data.push(b'\n');
        data.extend_from_slice(valid.as_bytes());
        data.push(b'\n');
        std::fs::write(&path, data).unwrap();

        let loaded = load_querylog(&path, 10, 0, 10_000);
        assert!(loaded.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn atomic_write_creates_missing_parent_directories() {
        let root = std::env::temp_dir().join(format!(
            "onetdns-persist-dir-test-{}-{}",
            std::process::id(),
            u64::from_le_bytes(onetdns_core::rng::random_array::<8>())
        ));
        let path = root.join("nested").join("querylog.jsonl");
        atomic_write(&path, b"ok").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_tightens_existing_sensitive_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "onetdns-persist-permissions-{}-{:016x}.jsonl",
            std::process::id(),
            u64::from_le_bytes(onetdns_core::rng::random_array::<8>())
        ));
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write(&path, b"new").unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn atomic_write_leaves_only_the_owner_acl_on_windows() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-persist-acl-{}-{:016x}.jsonl",
            std::process::id(),
            u64::from_le_bytes(onetdns_core::rng::random_array::<8>())
        ));
        std::fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new").unwrap();

        assert_eq!(
            onetdns_core::fs::access_rules(&path).unwrap(),
            onetdns_core::fs::private_rules(&path).unwrap()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn stats_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("onetdns-stats-test-{}.json", std::process::id()));
        let m = Metrics::default();
        m.total.store(42, Ordering::Relaxed);
        m.blocked.store(7, Ordering::Relaxed);
        m.latency_sum_us.store(12_000, Ordering::Relaxed);
        m.latency_count.store(3, Ordering::Relaxed);
        m.cache_hits.store(8, Ordering::Relaxed);
        m.cache_lookups.store(10, Ordering::Relaxed);
        m.dropped_log_events.store(2, Ordering::Relaxed);
        m.dropped_stat_events.store(3, Ordering::Relaxed);
        m.dropped_stream_events.store(4, Ordering::Relaxed);
        m.persist_failures.store(6, Ordering::Relaxed);
        m.by_transport[3].store(5, Ordering::Relaxed);
        let mut top = TopCounters::default();
        top.domains
            .insert(Name::from_str("a.example.").expect("테스트용 이름"), 9);
        top.blocked
            .insert(Name::from_str("ads.example.").expect("테스트용 이름"), 4);
        top.clients
            .insert("10.0.0.1".parse().expect("테스트용 주소"), 3);
        save_stats(&path, &m, &top).unwrap();

        let m2 = Metrics::default();
        let mut top2 = TopCounters::default();
        load_stats(&path, &m2, &mut top2);
        assert_eq!(m2.total.load(Ordering::Relaxed), 42);
        assert_eq!(m2.blocked.load(Ordering::Relaxed), 7);
        assert_eq!(m2.latency_sum_us.load(Ordering::Relaxed), 12_000);
        assert_eq!(m2.latency_count.load(Ordering::Relaxed), 3);
        assert_eq!(m2.cache_hits.load(Ordering::Relaxed), 8);
        assert_eq!(m2.cache_lookups.load(Ordering::Relaxed), 10);
        assert_eq!(m2.dropped_log_events.load(Ordering::Relaxed), 2);
        assert_eq!(m2.dropped_stat_events.load(Ordering::Relaxed), 3);
        assert_eq!(m2.dropped_stream_events.load(Ordering::Relaxed), 4);
        assert_eq!(m2.persist_failures.load(Ordering::Relaxed), 6);
        assert_eq!(m2.by_transport[3].load(Ordering::Relaxed), 5);
        assert_eq!(
            top2.domains
                .get(&Name::from_str("a.example.").expect("테스트용 이름")),
            Some(&9)
        );
        assert_eq!(
            top2.blocked
                .get(&Name::from_str("ads.example.").expect("테스트용 이름")),
            Some(&4)
        );
        assert_eq!(
            top2.clients
                .get(&"10.0.0.1".parse().expect("테스트용 주소")),
            Some(&3)
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stats_larger_than_http_json_limit_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-large-stats-test-{}.json",
            std::process::id()
        ));
        let m = Metrics::default();
        let mut top = TopCounters::default();
        for index in 0..8_000 {
            let label = "a".repeat(60);
            let key = format!("{index:05}.{label}.{label}.example.");
            top.domains.insert(
                Name::from_str(&key).expect("테스트용 이름"),
                index as u64 + 1,
            );
        }
        save_stats(&path, &m, &top).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > 1024 * 1024);

        let mut loaded = TopCounters::default();
        load_stats(&path, &Metrics::default(), &mut loaded);
        let label = "a".repeat(60);
        let key = format!("{:05}.{label}.{label}.example.", 7_999);
        assert_eq!(
            loaded
                .domains
                .get(&Name::from_str(&key).expect("테스트용 이름")),
            Some(&8_000)
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stats_roundtrip_preserves_values_above_json_safe_integer() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-large-counter-test-{}.json",
            std::process::id()
        ));
        let metrics = Metrics::default();
        let expected = 9_007_199_254_740_993u64;
        metrics.total.store(expected, Ordering::Relaxed);
        save_stats(&path, &metrics, &TopCounters::default()).unwrap();

        let restored = Metrics::default();
        load_stats(&path, &restored, &mut TopCounters::default());
        assert_eq!(restored.total.load(Ordering::Relaxed), expected);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stats_parser_accepts_only_the_complete_current_format() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-current-stats-test-{}.json",
            std::process::id()
        ));
        save_stats(&path, &Metrics::default(), &TopCounters::default()).unwrap();
        let current = std::fs::read_to_string(&path).unwrap();
        let parse = |text: &str| {
            let json = json::parse(text).unwrap();
            parse_stats_snapshot(&json, Metrics::default().by_transport.len())
        };

        assert!(parse(&current).is_ok());
        assert!(parse(&current.replacen("\"version\":1", "\"version\":2", 1)).is_err());
        assert!(parse(&current.replacen("\"total\":\"0\"", "\"total\":0", 1)).is_err());
        assert!(parse(&current.replacen(",\"persist_failures\":\"0\"", "", 1)).is_err());
        assert!(parse(&current.replacen(",\"by_transport\":[", ",\"removed\":[", 1)).is_err());
        assert!(parse(&current.replacen("\"top\":{", "\"removed\":{", 1)).is_err());
        assert!(parse(&current.replacen("\"clients\":[]", "\"removed\":[]", 1)).is_err());
        assert!(parse(&current.replacen("}", ",\"extra\":0}", 1)).is_err());
        assert!(parse(&current.replacen(
            "\"by_transport\":[",
            "\"extra\":0,\"by_transport\":[",
            1
        ))
        .is_err());
        assert!(
            parse(&current.replacen("\"clients\":[]", "\"clients\":[],\"extra\":[]", 1)).is_err()
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_stats_file_is_not_partially_applied() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-invalid-stats-test-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            br#"{"metrics":{"total":99,"blocked":-1},"top":{"domains":[["bad.example",4]]}}"#,
        )
        .unwrap();

        let metrics = Metrics::default();
        metrics.total.store(7, Ordering::Relaxed);
        metrics.blocked.store(3, Ordering::Relaxed);
        let mut top = TopCounters::default();
        top.domains
            .insert(Name::from_str("kept.example.").expect("테스트용 이름"), 2);
        load_stats(&path, &metrics, &mut top);

        assert_eq!(metrics.total.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.blocked.load(Ordering::Relaxed), 3);
        assert_eq!(
            top.domains
                .get(&Name::from_str("kept.example.").expect("테스트용 이름")),
            Some(&2)
        );
        assert!(!top
            .domains
            .contains_key(&Name::from_str("bad.example.").expect("테스트용 이름")));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn querylog_accepts_only_the_complete_current_shape() {
        let good = ev(1, "127.0.0.1", "ok.example", "resolved").to_json();
        assert!(parse_event(&good).is_some());
        assert!(parse_event(
            r#"{"id":1,"ts_ms":1,"name":"bad.example","qtype":"A","transport":"smtp","action":"resolved","latency_us":0}"#
        )
        .is_none());
        assert!(parse_event(&good.replacen("\"id\":1", "\"id\":1.5", 1)).is_none());
        assert!(parse_event(&good.replacen(",\"client\":\"127.0.0.1\"", "", 1)).is_none());
        assert!(parse_event(&good.replacen("}", ",\"extra\":0}", 1)).is_none());
    }
}
