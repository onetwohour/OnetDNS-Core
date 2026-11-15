//! User-facing text must stay readable, and the dashboard must cope with untranslated server text.
//! Management API and CLI errors are read by operators, not developers; implementation terms or a
//! lone word do not say what to fix. The server answers in English, so a non-English dashboard
//! showing unknown server text as is has the same problem.
//!
//! Strings inside test modules are not shown to users and are skipped.

mod common;

use common::{production_files, production_prefix, read, rel, root};

/// Too short to say what went wrong.
const FORBIDDEN_EXACT: &[&str] = &[
    "invalid content-length",
    "invalid last-event-id",
    "missing host header",
    "csrf check failed",
    "too many login attempts",
    "invalid credentials",
    "unauthorized",
    "Unauthorized",
    "not found",
    "Not found",
    "forbidden: read-only token",
    "query: domain required",
    "cert: --host required",
    "DHCPv4 disabled",
    "Raft HA disabled",
    "empty patch",
];

/// Implementation terms showing through.
const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "  mode={:?}  backend={:?}",
    "  listen={:?}",
    "length checked",
    "XFR response envelope",
    "SOA response envelope",
    "fallback origin/serial",
    "delta serial",
];

/// What the config check command must show in readable form.
const REQUIRED_CLI_COPY: &[&str] = &[
    "The configuration file is valid.",
    "Mode: {mode_label}",
    "Query resolution: {backend_label}",
    "Plain DNS listening addresses:",
    "Per-client rate limit:",
    "Per-subnet response limit:",
];

/// How the dashboard handles server errors per language: English shows the server text as is; other
/// languages translate it from the dictionary, or show a translated fallback followed by the
/// original.
const REQUIRED_DASHBOARD: &[&str] = &[
    "if(this.state.lang==='en'||translated!==raw)return translated;",
    "'요청을 처리하지 못했습니다':'The request could not be completed'",
    "'요청을 처리하지 못했습니다':'リクエストを処理できませんでした'",
    "\"요청을 처리하지 못했습니다\":\"无法处理请求\"",
    "'서버에서 요청을 처리하지 못했습니다':'The server could not complete the request'",
    "'서버에서 요청을 처리하지 못했습니다':'サーバーでリクエストを処理できませんでした'",
    "\"서버에서 요청을 처리하지 못했습니다\":\"服务器无法处理请求\"",
];

fn string_literals(source: &str) -> Vec<(usize, String)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    let mut line = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                line += 1;
                index += 1;
            }
            b'"' => {
                let start_line = line;
                let mut value = String::new();
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' && index + 1 < bytes.len() {
                        // A newline escape counts as one space.
                        if bytes[index + 1] == b'n' {
                            value.push(' ');
                        } else {
                            value.push('\\');
                            value.push(bytes[index + 1] as char);
                        }
                        index += 2;
                        continue;
                    }
                    if bytes[index] == b'\n' {
                        line += 1;
                    }
                    let ch = source[index..].chars().next().unwrap_or('"');
                    value.push(ch);
                    index += ch.len_utf8();
                }
                index += 1;
                out.push((start_line, value));
            }
            _ => index += source[index..].chars().next().map_or(1, char::len_utf8),
        }
    }
    out
}

/// Every binary source is read, not a chosen list, so code that moves to another file stays
/// covered.
fn public_sources() -> Vec<(String, String)> {
    let repo = root();
    let mut paths = production_files(&["onetdns-bin/src"]);
    paths.push(repo.join("crates/onetdns-control/src/api.rs"));
    paths.push(repo.join("crates/onetdns-config/src/settings.rs"));
    paths
        .into_iter()
        .map(|path| {
            let text = read(&path);
            (rel(&path), production_prefix(&text).to_string())
        })
        .collect()
}

fn binary_production_source() -> String {
    production_files(&["onetdns-bin/src"])
        .iter()
        .map(|path| production_prefix(&read(path)).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_terse_or_untranslated_public_message_remains() {
    let mut found = Vec::new();
    for (path, source) in public_sources() {
        for (line, value) in string_literals(&source) {
            if FORBIDDEN_EXACT.contains(&value.as_str()) {
                found.push(format!("{path}:{line} {value:?}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "짧거나 번역되지 않은 공개 문구가 남아 있습니다:\n  - {}",
        found.join("\n  - ")
    );
}

#[test]
fn no_implementation_wording_reaches_the_user() {
    let combined: String = public_sources()
        .into_iter()
        .map(|(_, source)| source)
        .collect::<Vec<_>>()
        .join("\n");
    let remaining: Vec<&&str> = FORBIDDEN_FRAGMENTS
        .iter()
        .filter(|fragment| combined.contains(**fragment))
        .collect();
    assert!(
        remaining.is_empty(),
        "구현 용어가 그대로 노출되는 문구가 남아 있습니다: {remaining:?}"
    );
}

#[test]
fn the_configuration_summary_stays_human_readable() {
    let source = binary_production_source();
    let missing: Vec<&&str> = REQUIRED_CLI_COPY
        .iter()
        .filter(|text| !source.contains(**text))
        .collect();
    assert!(
        missing.is_empty(),
        "설정 요약에서 빠진 항목이 있습니다: {missing:?}"
    );
}

#[test]
fn the_dashboard_localizes_unmatched_server_errors() {
    let dashboard = read(&root().join("crates/onetdns-control/dashboard/index.html"));
    let missing: Vec<&&str> = REQUIRED_DASHBOARD
        .iter()
        .filter(|text| !dashboard.contains(**text))
        .collect();
    assert!(
        missing.is_empty(),
        "서버 오류의 언어별 대비가 빠졌습니다: {missing:?}"
    );

    let start = dashboard
        .find("\n  errorText(r){")
        .expect("errorText 를 찾지 못했습니다");
    let end = dashboard[start..]
        .find("\n  }")
        .map(|offset| start + offset)
        .expect("errorText 의 끝을 찾지 못했습니다");
    let body = &dashboard[start..end];
    assert!(
        body.contains("statusMessage") && body.contains("this.t(statusMessage)"),
        "errorText 가 번역된 대비 문구를 내놓지 않습니다"
    );
}

#[test]
fn the_parsing_helpers_behave() {
    let source = "let a = \"보임\";\n#[cfg(test)]\nmod tests {\n    let b = \"안 보임\";\n}\n";
    let prefix = production_prefix(source);
    assert!(prefix.contains("보임") && !prefix.contains("안 보임"));

    let documented = "let a = \"보임\";\n#[cfg(test)]\n/// 설명.\n// 메모.\nmod tests {\n    let b = \"안 보임\";\n}\n";
    let prefix = production_prefix(documented);
    assert!(prefix.contains("보임") && !prefix.contains("안 보임"));

    // cfg(test) on something that is not a test module does not cut.
    let other = "#[cfg(test)]\nfn helper() {}\nlet c = \"보임\";\n";
    assert!(production_prefix(other).contains("보임"));

    let literals = string_literals("let x = \"첫\";\nlet y = \"둘\\n셋\";\n");
    assert_eq!(literals[0], (1, "첫".to_string()));
    assert_eq!(literals[1], (2, "둘 셋".to_string()));
}
