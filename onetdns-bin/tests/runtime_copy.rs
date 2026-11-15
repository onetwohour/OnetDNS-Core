//! Operational logs and user-facing errors must stay readable English. Whoever reads the log in an
//! outage did not write the code, and implementation terms or bare values do not say what went
//! wrong. Losing the logs is the same problem, so call and event-code counts have floors.
//!
//! Server text is English only; the dashboard and schema dictionaries handle other languages, so
//! the schema dictionary is exempt from the Hangul check. Tests are not scanned.
//!
//! The floors are pinned on purpose; lower them only for a change that deliberately removes
//! logging.

mod common;

use common::{collect, is_test_module_file, production_files, production_prefix, read, rel, root};
use std::path::PathBuf;

const MIN_LOG_CALLS: usize = 400;

const MIN_EXPLICIT_EVENTS: usize = 350;

const LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// Implementation terms with an operator's word to replace them. "upstream" is not one: the config
/// key is upstream_urls and the dashboard uses the same word.
const BANNED_IN_PUBLIC: &[&str] = &[
    "zone backend",
    "subscription backend",
    "filter backend",
    "generation swap",
    "hot-reload",
    "hotreload",
    "zone CRUD",
    "dry explain",
    "native stack",
    "vendor DB",
];

const TERSE_DIAGNOSTICS: &[&str] = &[
    "parse failed",
    "decode failed",
    "overflow error",
    "format error",
    "length error",
    "range error",
    "size error",
    "deadline elapsed",
    "length checked",
    "SASLContinue expected",
    "envelope",
    "fallback origin/serial",
    "delta serial",
];

/// Its Korean is translation data for the dashboard, not server text.
const LOCALIZATION_SOURCES: &[&str] = &["crates/onetdns-config/src/schema.rs"];

/// Messages that are only a value, with nothing saying what it is.
const DYNAMIC_ONLY: &[&str] = &["{label}", "{warning}", "{error}"];

struct LogCall {
    where_: String,
    line: usize,
    level: &'static str,
    event: String,
    message: String,
}

fn has_korean(text: &str) -> bool {
    text.chars().any(|ch| ('가'..='힣').contains(&ch))
}

fn contains_any(haystack: &str, needles: &[&str]) -> Vec<String> {
    let lowered = haystack.to_lowercase();
    needles
        .iter()
        .filter(|needle| lowered.contains(&needle.to_lowercase()))
        .map(|needle| (*needle).to_string())
        .collect()
}

fn production_sources() -> Vec<PathBuf> {
    let repo = root();
    let mut out = Vec::new();
    collect(&repo.join("onetdns-bin/src"), "rs", &mut out);
    let entries = std::fs::read_dir(repo.join("crates")).expect("crates 를 읽지 못했습니다");
    for entry in entries.flatten() {
        collect(&entry.path().join("src"), "rs", &mut out);
    }
    out.retain(|path| !is_test_module_file(path));
    out.sort();
    assert!(
        out.len() > 50,
        "소스를 거의 찾지 못했습니다. 작업공간 배치가 바뀌었습니까"
    );
    out
}

/// Skips string and char literals.
fn balanced_end(source: &str, from: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 1usize;
    let mut index = from;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    while index < bytes.len() && depth > 0 {
        let ch = bytes[index];
        match quote {
            Some(open) => {
                if escaped {
                    escaped = false;
                } else if ch == b'\\' {
                    escaped = true;
                } else if ch == open {
                    quote = None;
                }
            }
            None => match ch {
                b'\'' | b'"' => quote = Some(ch),
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            },
        }
        index += 1;
    }
    index.saturating_sub(1)
}

/// Escapes are kept as written.
fn plain_strings(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let start = index + 1;
            let mut end = start;
            while end < bytes.len() {
                match bytes[end] {
                    b'\\' => end += 2,
                    b'"' => break,
                    _ => end += 1,
                }
            }
            if end >= bytes.len() {
                break;
            }
            out.push(body[start..end].to_string());
            index = end + 1;
            continue;
        }
        index += body[index..].chars().next().map_or(1, char::len_utf8);
    }
    out
}

/// Keeps `my_error!` from matching `error!`.
fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Empty when absent.
fn event_code(body: &str) -> String {
    for head in ["event = \"", "event=\""] {
        if let Some(at) = body.find(head) {
            let start = at + head.len();
            if let Some(offset) = body[start..].find('"') {
                return body[start..start + offset].to_string();
            }
        }
    }
    String::new()
}

fn macro_calls(where_: &str, source: &str) -> Vec<LogCall> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    for level in LOG_LEVELS {
        let mut from = 0usize;
        while let Some(at) = source[from..].find(level) {
            let start = from + at;
            from = start + level.len();
            if start > 0 && is_identifier_byte(bytes[start - 1]) {
                continue;
            }
            let mut cursor = from;
            if bytes.get(cursor) != Some(&b'!') {
                continue;
            }
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b'(') {
                continue;
            }
            let body_start = cursor + 1;
            let body_end = balanced_end(source, body_start);
            let body = &source[body_start..body_end];
            let strings = plain_strings(body);
            let event = event_code(body);
            out.push(LogCall {
                where_: where_.to_string(),
                line: source[..start].matches('\n').count() + 1,
                level,
                event,
                message: strings
                    .last()
                    .map(|text| text.replace("\\n", " ").trim().to_string())
                    .unwrap_or_default(),
            });
        }
    }
    out.sort_by_key(|call| call.line);
    out
}

/// Single-line literals only, as (line, value); multi-line ones are help text, not error messages.
fn string_literals(source: &str) -> Vec<(usize, String)> {
    every_literal(source)
        .into_iter()
        .filter(|(_, value)| !value.contains("\\n") && value.chars().count() <= 600)
        .collect()
}

/// Every literal as (line, value), skipping comments and char literals.
fn every_literal(source: &str) -> Vec<(usize, String)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    let mut block_depth = 0usize;
    while index < bytes.len() {
        if block_depth > 0 {
            if source[index..].starts_with("/*") {
                block_depth += 1;
                index += 2;
            } else if source[index..].starts_with("*/") {
                block_depth -= 1;
                index += 2;
            } else {
                index += source[index..].chars().next().map_or(1, char::len_utf8);
            }
            continue;
        }
        if source[index..].starts_with("//") {
            index = source[index..]
                .find('\n')
                .map_or(bytes.len(), |offset| index + offset + 1);
            continue;
        }
        if source[index..].starts_with("/*") {
            block_depth = 1;
            index += 2;
            continue;
        }

        let raw_start = if source[index..].starts_with("br") || source[index..].starts_with("cr") {
            index + 1
        } else {
            index
        };
        if bytes.get(raw_start) == Some(&b'r') {
            let mut quote = raw_start + 1;
            while bytes.get(quote) == Some(&b'#') {
                quote += 1;
            }
            if bytes.get(quote) == Some(&b'"') {
                let hashes = quote - raw_start - 1;
                let terminator = format!("\"{}", "#".repeat(hashes));
                let Some(offset) = source[quote + 1..].find(&terminator) else {
                    return out;
                };
                let end = quote + 1 + offset;
                let value = &source[quote + 1..end];
                out.push((source[..index].matches('\n').count() + 1, value.to_string()));
                index = end + terminator.len();
                continue;
            }
        }

        let char_quote = if bytes[index] == b'\'' {
            Some(index)
        } else if source[index..].starts_with("b'") {
            Some(index + 1)
        } else {
            None
        };
        if let Some(start) = char_quote {
            let mut end = start + 1;
            end += if bytes.get(end) == Some(&b'\\') { 2 } else { 1 };
            if bytes.get(end) == Some(&b'\'') {
                index = end + 1;
                continue;
            }
        }

        let quote = if bytes[index] == b'"' {
            Some(index)
        } else if source[index..].starts_with("b\"") || source[index..].starts_with("c\"") {
            Some(index + 1)
        } else {
            None
        };
        if let Some(start) = quote {
            let mut end = start + 1;
            while end < bytes.len() {
                match bytes[end] {
                    b'\\' => end += 2,
                    b'"' => break,
                    _ => end += 1,
                }
            }
            if end >= bytes.len() {
                return out;
            }
            let value = &source[start + 1..end];
            out.push((source[..index].matches('\n').count() + 1, value.to_string()));
            index = end + 1;
            continue;
        }
        index += source[index..].chars().next().map_or(1, char::len_utf8);
    }
    out
}

fn all_log_calls() -> Vec<LogCall> {
    production_sources()
        .iter()
        .flat_map(|path| {
            let text = read(path);
            macro_calls(&rel(path), production_prefix(&text))
        })
        .collect()
}

#[test]
fn operational_logging_does_not_collapse() {
    let calls = all_log_calls();
    assert!(
        calls.len() >= MIN_LOG_CALLS,
        "운영 기록이 {}건까지 줄었습니다. 최소 기준은 {MIN_LOG_CALLS}건입니다",
        calls.len()
    );
    let explicit = calls.iter().filter(|call| !call.event.is_empty()).count();
    assert!(
        explicit >= MIN_EXPLICIT_EVENTS,
        "이벤트 코드를 단 기록이 {explicit}건까지 줄었습니다. 최소 기준은 {MIN_EXPLICIT_EVENTS}건입니다"
    );
}

#[test]
fn every_log_call_says_something() {
    let calls = all_log_calls();
    let empty: Vec<String> = calls
        .iter()
        .filter(|call| call.message.is_empty())
        .map(|call| format!("{}:{}", call.where_, call.line))
        .collect();
    assert!(
        empty.is_empty(),
        "읽을 문구가 없는 기록이 있습니다:\n  - {}",
        empty.join("\n  - ")
    );

    let dynamic: Vec<String> = calls
        .iter()
        .filter(|call| DYNAMIC_ONLY.contains(&call.message.as_str()))
        .map(|call| format!("{}:{} {:?}", call.where_, call.line, call.message))
        .collect();
    assert!(
        dynamic.is_empty(),
        "무엇에 대한 값인지 알 수 없는 기록이 있습니다:\n  - {}",
        dynamic.join("\n  - ")
    );
}

/// Operators search logs and paste them into issues, so they stay in one language.
#[test]
fn log_messages_are_english() {
    let korean: Vec<String> = all_log_calls()
        .iter()
        .filter(|call| has_korean(&call.message))
        .map(|call| format!("{}:{} {:?}", call.where_, call.line, call.message))
        .collect();
    assert!(
        korean.is_empty(),
        "한국어로 남은 운영 기록이 있습니다:\n  - {}",
        korean.join("\n  - ")
    );
}

#[test]
fn the_structured_logger_keeps_its_fixed_fields() {
    let logger = read(&root().join("crates/onetdns-core/src/log.rs"));
    for required in [
        "fallback_event_code",
        "\\\"pid\\\"",
        "thread",
        "source",
        "utc_timestamp",
    ] {
        assert!(
            logger.contains(required),
            "기록 항목이 빠졌습니다: {required}"
        );
    }

    let metrics = read(&root().join("crates/onetdns-control/src/metrics.rs"));
    assert!(
        metrics.contains("event = \"metrics.minute_summary\""),
        "주기 운영 요약 기록이 사라졌습니다"
    );
}

#[test]
fn user_facing_errors_avoid_implementation_wording() {
    let repo = root();
    let mut found = Vec::new();
    let mut paths = production_files(&["onetdns-bin/src"]);
    for name in [
        "crates/onetdns-control/src/api.rs",
        "crates/onetdns-config/src/settings.rs",
        "crates/onetdns-filter/src/cache.rs",
    ] {
        paths.push(repo.join(name));
    }
    for path in paths {
        let name = rel(&path);
        let text = read(&path);
        for (line, value) in string_literals(production_prefix(&text)) {
            let hits = contains_any(&value, BANNED_IN_PUBLIC);
            if !hits.is_empty() {
                found.push(format!("{name}:{line} {value:?} {hits:?}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "사용자가 보는 오류에 구현 용어가 남아 있습니다:\n  - {}",
        found.join("\n  - ")
    );
}

#[test]
fn runtime_strings_are_english() {
    let mut found = Vec::new();
    for path in production_sources() {
        let name = rel(&path);
        if LOCALIZATION_SOURCES.contains(&name.as_str()) {
            continue;
        }
        let text = read(&path);
        for (line, value) in every_literal(production_prefix(&text)) {
            if has_korean(&value) {
                let shown: String = value.chars().take(80).collect();
                found.push(format!("{name}:{line} {shown:?}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "한국어로 남은 서버 문자열이 있습니다:\n  - {}",
        found.join("\n  - ")
    );
}

#[test]
fn no_terse_diagnostic_remains() {
    let mut found = Vec::new();
    for path in production_sources() {
        let text = read(&path);
        for (line, value) in string_literals(production_prefix(&text)) {
            let hits = contains_any(&value, TERSE_DIAGNOSTICS);
            if !hits.is_empty() {
                found.push(format!("{}:{line} {value:?} {hits:?}", rel(&path)));
            }
        }
    }
    assert!(
        found.is_empty(),
        "무엇이 잘못됐는지 알려 주지 않는 진단 문구가 남아 있습니다:\n  - {}",
        found.join("\n  - ")
    );
}

#[test]
fn the_string_scanner_behaves() {
    let sample = concat!(
        "const A: &str = \"first\";\n",
        "const RAW: &str = r#\"raw \" quote\"#;\n",
        "let quote = '\"'; // \"comment\"\n",
        "/* \"block comment\" */\n",
        "const B: &[u8] = b\"last\";"
    );
    let values: Vec<String> = string_literals(sample)
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(values, vec!["first", "raw \" quote", "last"]);

    // Takes the last string and the event code from the macro body.
    let source = "    warn!(event = \"a.b\", client = %addr, \"무엇이 잘못됐는지\");\n";
    let calls = macro_calls("보기", source);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].level, "warn");
    assert_eq!(calls[0].event, "a.b");
    assert_eq!(calls[0].message, "무엇이 잘못됐는지");

    // A macro whose name only ends the same is not a log call.
    assert!(macro_calls("보기", "    my_error!(\"x\");\n").is_empty());
}

#[test]
fn the_scan_covers_production_sources_only() {
    let scanned: Vec<String> = production_sources().iter().map(|path| rel(path)).collect();
    assert!(
        scanned.iter().any(|path| path == "onetdns-bin/src/main.rs"),
        "본체 소스를 찾지 못했습니다"
    );
    assert!(
        !scanned.iter().any(|path| path.contains("/tests/")),
        "테스트 소스가 검사 범위에 들어왔습니다"
    );
}
