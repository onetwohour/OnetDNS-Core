/*!
 * @brief 사람이 보는 문구가 읽을 만한 문장으로 남아 있는지, 화면에 번역 대비가 있는지
 *        검사한다.
 *
 * @details 관리 API 와 CLI 의 오류 문구는 개발자가 아니라 운영자가 읽는다. 구현 용어를
 *          그대로 노출하거나 단어 하나만 던지면 무엇을 고쳐야 할지 알 수 없다. 서버는
 *          영어로 답하므로, 화면이 모르는 서버 문구를 영어 아닌 화면에 그대로 내보내는
 *          것도 같은 문제다.
 * @note 테스트 모듈 안의 문자열은 사용자에게 보이지 않으므로 검사에서 제외한다.
 */

mod common;

use common::{production_files, production_prefix, read, rel, root};

/** @brief 이 문장 그대로는 내보내지 않는다. 무엇이 잘못됐는지 알 수 없을 만큼 짧다. */
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

/** @brief 구현 내부 용어가 그대로 드러난 조각. */
const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "  mode={:?}  backend={:?}",
    "  listen={:?}",
    "length checked",
    "XFR response envelope",
    "SOA response envelope",
    "fallback origin/serial",
    "delta serial",
];

/** @brief 설정 확인 명령이 사람이 읽을 수 있게 내놓아야 할 항목. */
const REQUIRED_CLI_COPY: &[&str] = &[
    "The configuration file is valid.",
    "Mode: {mode_label}",
    "Query resolution: {backend_label}",
    "Plain DNS listening addresses:",
    "Per-client rate limit:",
    "Per-subnet response limit:",
];

/**
 * @brief 화면이 서버 오류를 언어별로 되받아 주는 장치.
 * @details 영어 화면은 서버 문구를 그대로 쓰고, 다른 화면은 사전에 있으면 번역하고
 *          없으면 번역된 대비 문구 뒤에 원문을 붙인다.
 */
const REQUIRED_DASHBOARD: &[&str] = &[
    "if(this.state.lang==='en'||translated!==raw)return translated;",
    "'요청을 처리하지 못했습니다':'The request could not be completed'",
    "'요청을 처리하지 못했습니다':'リクエストを処理できませんでした'",
    "\"요청을 처리하지 못했습니다\":\"无法处理请求\"",
    "'서버에서 요청을 처리하지 못했습니다':'The server could not complete the request'",
    "'서버에서 요청을 처리하지 못했습니다':'サーバーでリクエストを処理できませんでした'",
    "\"서버에서 요청을 처리하지 못했습니다\":\"服务器无法处理请求\"",
];

/** @brief 소스에 든 문자열 리터럴을 줄 번호와 함께 모은다. */
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
                        /* 줄바꿈 이스케이프는 한 칸으로 본다. 원본 검사기와 같은 취급이다. */
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

/**
 * @brief 사용자에게 보이는 문구를 담은 검사 대상 소스.
 * @details 바이너리 소스는 파일을 고르지 않고 전부 읽는다. 코드가 다른 파일로 옮겨 가도
 *          검사 범위에서 빠지지 않게 하려는 것이다.
 */
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

/** @brief 바이너리의 운영 코드 전체를 이어 붙인 것. */
fn binary_production_source() -> String {
    production_files(&["onetdns-bin/src"])
        .iter()
        .map(|path| production_prefix(&read(path)).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/** @brief 짧거나 번역되지 않은 문구가 그대로 남아 있으면 실패한다. */
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

/** @brief 구현 용어가 사용자 문구에 드러나면 실패한다. */
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

/** @brief 설정 확인 명령의 사람이 읽는 요약이 빠지면 실패한다. */
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

/** @brief 영어가 아닌 화면이 번역되지 않은 서버 오류를 그대로 보여 주면 실패한다. */
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

/** @brief 문자열과 테스트 모듈 판정이 실제로 구분하는지 확인한다. */
#[test]
fn the_parsing_helpers_behave() {
    let source = "let a = \"보임\";\n#[cfg(test)]\nmod tests {\n    let b = \"안 보임\";\n}\n";
    let prefix = production_prefix(source);
    assert!(prefix.contains("보임") && !prefix.contains("안 보임"));

    /* cfg(test) 가 붙었어도 테스트 모듈이 아니면 자르지 않는다. */
    let other = "#[cfg(test)]\nfn helper() {}\nlet c = \"보임\";\n";
    assert!(production_prefix(other).contains("보임"));

    let literals = string_literals("let x = \"첫\";\nlet y = \"둘\\n셋\";\n");
    assert_eq!(literals[0], (1, "첫".to_string()));
    assert_eq!(literals[1], (2, "둘 셋".to_string()));
}
