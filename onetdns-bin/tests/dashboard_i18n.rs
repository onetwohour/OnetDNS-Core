//! Every Korean string the dashboard shows must have en, ja, and zh translations. Template text is
//! translated at run time by localizeDom, and React code calls this.t or this.tr; both look up the
//! Korean source as the key and return the key itself when it is missing, so a gap shows Korean on
//! an English screen with no error. localizeDom only covers elements under data-dc-tpl, which React
//! elements lack, so a Korean string passed to React shows as is even when the dictionary has it.
//!
//! Server strings are checked too: the management API answers in English, so error bodies must be
//! keys in the ko, ja, and zh dictionaries, or errorText shows a fallback followed by the English
//! original. Those strings live in Rust, not in the HTML.
//!
//! Not caught: removing t from a variable at the render site, since the source alone does not show
//! what the variable holds.

mod common;

use common::{collect, production_prefix, read, rel, root};
use std::collections::{BTreeMap, BTreeSet};

/// Where a suffix match may start; must match the runtime rule in t.
const SUFFIX_STARTS: &[&str] = &[" ", "개 ", "개를 ", "번 ", "\" DNS"];

/// Render data keys whose values are shown as is.
const RENDER_DATA_KEYS: &[&str] = &[
    "label",
    "val",
    "desc",
    "text",
    "title",
    "name",
    "hint",
    "placeholder",
];

/// Data translated at the render site, pinned on purpose. ACT and TRANSPORT are class fields built
/// before this.state exists, so translating them there would freeze the language they were built
/// in; the query diagnostics panel translates the rest in explainEl. Add an entry only after
/// checking that it goes through t.
const RENDER_DATA_LITERALS: &[(&str, &str)] = &[
    ("label", "정상 응답"),
    ("label", "차단"),
    ("label", "응답 변경"),
    ("label", "거부"),
    ("label", "속도 제한"),
    ("label", "실패"),
    ("label", "거절"),
    ("desc", "암호화하지 않은 DNS(포트 53)"),
    ("desc", "HTTPS / 포트 443"),
    ("desc", "TLS / 포트 853"),
    ("desc", "QUIC / 포트 853"),
    ("name", "이름"),
    ("label", "정책"),
    ("label", "필터"),
    ("label", "처리 경로"),
    ("label", "원인"),
    ("label", "구간"),
    ("label", "매칭 규칙"),
    ("label", "전송"),
    ("label", "응답 서버"),
    ("label", "처리시간"),
    ("label", "응답"),
];

const TRANSLATING_CALLS: &[&str] = &["this.t(", "this.tr(", "toastMsg(", "confirmDestructive("];

fn has_korean(text: &str) -> bool {
    text.chars().any(|ch| ('가'..='힣').contains(&ch))
}

fn unescape(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\'", "'")
        .replace("\\\"", "\"")
}

/// Start and end of each quoted string's contents within a line.
fn quoted_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == b'\'' || ch == b'"' {
            let start = index + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != ch && bytes[end] != b'\n' {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == ch {
                out.push((start, end));
                index = end + 1;
                continue;
            }
            index += 1;
            continue;
        }
        index += text[index..].chars().next().map_or(1, char::len_utf8);
    }
    out
}

/// Keys in a dictionary block: Korean source for screen copy, English for server copy. A key is a
/// string followed by a colon. When no colon follows, the quote did not open a key, so this moves
/// on by one character instead of past the closing quote; some keys start with a double quote, and
/// skipping would miss them all.
fn literal_keys(segment: &str) -> BTreeSet<String> {
    let bytes = segment.as_bytes();
    let mut found = BTreeSet::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index += segment[index..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        let start = index + 1;
        let mut cursor = start;
        while cursor < bytes.len() && bytes[cursor] != quote && bytes[cursor] != b'\n' {
            cursor += segment[cursor..].chars().next().map_or(1, char::len_utf8);
        }
        if cursor >= bytes.len() || bytes[cursor] != quote {
            index += 1;
            continue;
        }
        let mut after = cursor + 1;
        while bytes.get(after).is_some_and(u8::is_ascii_whitespace) {
            after += 1;
        }
        if bytes.get(after) != Some(&b':') {
            index += 1;
            continue;
        }
        found.insert(unescape(&segment[start..cursor]));
        index = after + 1;
    }
    found
}

fn balanced_object(text: &str, brace: usize) -> &str {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut index = brace;
    while index < bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[brace..=index];
                }
            }
            _ => {}
        }
        index += 1;
    }
    panic!("사전 객체의 괄호가 닫히지 않았습니다");
}

fn call_end(source: &str, open: usize) -> usize {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == b'\'' || ch == b'"' {
            index += 1;
            while index < bytes.len() && bytes[index] != ch {
                index += if bytes[index] == b'\\' { 2 } else { 1 };
            }
        } else if ch == b'(' {
            depth += 1;
        } else if ch == b')' {
            depth -= 1;
            if depth == 0 {
                return index;
            }
        }
        index += 1;
    }
    bytes.len()
}

fn translating_spans(script: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for head in TRANSLATING_CALLS {
        let mut from = 0usize;
        while let Some(at) = script[from..].find(*head) {
            let open = from + at + head.len() - 1;
            out.push((open, call_end(script, open)));
            from = from + at + head.len();
        }
    }
    out
}

fn rendering_spans(script: &str) -> Vec<(usize, usize)> {
    let bytes = script.as_bytes();
    let mut out = Vec::new();

    let head = "React.createElement(";
    let mut from = 0usize;
    while let Some(at) = script[from..].find(head) {
        let open = from + at + head.len() - 1;
        out.push((open, call_end(script, open)));
        from = from + at + head.len();
    }

    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'R' && bytes[index + 1] == b'(' {
            let before = if index == 0 {
                None
            } else {
                Some(bytes[index - 1])
            };
            let attached = before
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.');
            if !attached {
                out.push((index + 1, call_end(script, index + 1)));
            }
        }
        index += 1;
    }
    out
}

fn within(position: usize, spans: &[(usize, usize)]) -> bool {
    spans
        .iter()
        .any(|(start, end)| *start < position && position < *end)
}

fn dictionary(text: &str, lang: &str) -> BTreeSet<String> {
    let start = text
        .find("const I18N = {")
        .expect("사전 선언을 찾지 못했습니다");
    let end = text[start..]
        .find("\n};")
        .map(|offset| start + offset)
        .expect("사전 선언의 끝을 찾지 못했습니다");
    let block = &text[start..end];

    let mut keys = BTreeSet::new();
    let marker = format!("{lang}: {{");
    if let Some(at) = block.find(&marker) {
        let rest = &block[at..];
        let next = ["\n  en: {", "\n  ja: {", "\n  ko: {", "\n  zh: {"]
            .iter()
            .filter_map(|head| rest.find(head))
            .filter(|offset| *offset > 0)
            .min();
        keys.extend(literal_keys(next.map_or(rest, |offset| &rest[..offset])));
    }

    let assign = format!("Object.assign(I18N.{lang},");
    let mut from = 0usize;
    while let Some(at) = text[from..].find(&assign) {
        let start = from + at + assign.len();
        from = start;
        let Some(brace) = text[start..].find('{').map(|offset| start + offset) else {
            break;
        };
        keys.extend(literal_keys(balanced_object(text, brace)));
    }
    keys
}

/// Exactly, or by the prefix and suffix matches t uses.
fn resolvable(key: &str, keys: &BTreeSet<String>) -> bool {
    if keys.contains(key) {
        return true;
    }
    keys.iter().any(|source| {
        if source.chars().count() <= 2 {
            return false;
        }
        if !source.starts_with(' ') && source.ends_with(' ') && key.starts_with(source.as_str()) {
            return true;
        }
        SUFFIX_STARTS
            .iter()
            .any(|head| source.starts_with(head) && key.ends_with(source.as_str()))
    })
}

/// Test modules are skipped; their responses are mocks.
fn server_error_strings() -> BTreeMap<String, String> {
    let repo = root();
    let mut sources = Vec::new();
    collect(&repo.join("crates"), "rs", &mut sources);
    collect(&repo.join("onetdns-bin/src"), "rs", &mut sources);
    sources.sort();

    let mut found = BTreeMap::new();
    for path in sources {
        let where_ = rel(&path);
        if where_.contains("/tests/") {
            continue;
        }
        let text = read(&path);
        let body = production_prefix(&text);
        for (value, at) in escaped_error_bodies(body) {
            if !value.chars().any(char::is_alphabetic) {
                continue;
            }
            let line = body[..at].matches('\n').count() + 1;
            found
                .entry(unescape(&value))
                .or_insert_with(|| format!("{where_}:{line}"));
        }
    }
    found
}

/// Error bodies inside Rust string literals, with their start positions.
fn escaped_error_bodies(body: &str) -> Vec<(String, usize)> {
    let bytes = body.as_bytes();
    let head = "\\\"error\\\"";
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = body[from..].find(head) {
        let start = from + at;
        from = start + head.len();
        let mut cursor = from;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b':') {
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'\\') || bytes.get(cursor + 1) != Some(&b'"') {
            continue;
        }
        let value_start = cursor + 2;
        let mut index = value_start;
        let mut ok = false;
        while index < bytes.len() {
            if bytes[index] == b'\\' && bytes.get(index + 1) == Some(&b'"') {
                ok = true;
                break;
            }
            if bytes[index] == b'"' {
                break;
            }
            index += if bytes[index] == b'\\' {
                2
            } else {
                body[index..].chars().next().map_or(1, char::len_utf8)
            };
        }
        if ok && index <= bytes.len() {
            out.push((body[value_start..index].to_string(), value_start));
        }
    }
    out
}

fn template_chunks(template: &str) -> Vec<&str> {
    let bytes = template.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    let mut text_start = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'<' {
            out.push(&template[text_start..index]);
            match template[index..].find('>') {
                Some(offset) => index += offset + 1,
                None => {
                    text_start = bytes.len();
                    break;
                }
            }
            text_start = index;
            continue;
        }
        index += template[index..].chars().next().map_or(1, char::len_utf8);
    }
    out.push(&template[text_start..]);
    out
}

fn wanted_strings(
    template: &str,
    script: &str,
    translating: &[(usize, usize)],
) -> BTreeMap<String, String> {
    let mut wanted: BTreeMap<String, String> = BTreeMap::new();
    let mut want = |value: &str, origin: &str| {
        if !value.is_empty() && has_korean(value) && !value.contains("{{") {
            wanted
                .entry(value.to_string())
                .or_insert_with(|| origin.to_string());
        }
    };

    for chunk in template_chunks(template) {
        for piece in chunk.split('\n') {
            want(piece.trim(), "템플릿 텍스트");
        }
    }
    for attribute in ["placeholder", "title", "aria-label", "alt"] {
        let head = format!("{attribute}=\"");
        let mut from = 0usize;
        while let Some(at) = template[from..].find(&head) {
            let start = from + at + head.len();
            let Some(offset) = template[start..].find('"') else {
                break;
            };
            let end = start + offset;
            want(template[start..end].trim(), &format!("템플릿 {attribute}"));
            from = end + 1;
        }
    }
    for (start, end) in quoted_spans(script) {
        let raw = &script[start..end];
        if has_korean(raw) && within(start, translating) {
            want(&unescape(raw), "번역 호출 인자");
        }
    }
    wanted
}

fn untranslated_render_strings(
    script: &str,
    line_offset: usize,
    translating: &[(usize, usize)],
    rendering: &[(usize, usize)],
) -> Vec<String> {
    quoted_spans(script)
        .into_iter()
        .filter(|(start, end)| has_korean(&script[*start..*end]))
        .filter(|(start, _)| !within(*start, translating) && within(*start, rendering))
        .map(|(start, end)| {
            let line = script[..start].matches('\n').count() + line_offset;
            format!("{line}행 {:?}", unescape(&script[start..end]))
        })
        .collect()
}

fn raw_render_data(script: &str, translating: &[(usize, usize)]) -> BTreeSet<(String, String)> {
    let bytes = script.as_bytes();
    let mut out = BTreeSet::new();
    for key in RENDER_DATA_KEYS {
        let mut from = 0usize;
        while let Some(at) = script[from..].find(*key) {
            let start = from + at;
            from = start + key.len();
            let attached =
                start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
            if attached {
                continue;
            }
            let mut cursor = from;
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b':') {
                continue;
            }
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            let Some(&quote) = bytes.get(cursor) else {
                continue;
            };
            if quote != b'\'' && quote != b'"' {
                continue;
            }
            let value_start = cursor + 1;
            let mut end = value_start;
            while end < bytes.len() && bytes[end] != quote && bytes[end] != b'\n' {
                end += 1;
            }
            if end >= bytes.len() || bytes[end] != quote {
                continue;
            }
            let value = &script[value_start..end];
            if has_korean(value) && !within(value_start, translating) {
                out.insert(((*key).to_string(), unescape(value)));
            }
        }
    }
    out
}

#[test]
fn every_korean_string_the_dashboard_shows_has_a_translation() {
    let source = root().join("crates/onetdns-control/dashboard/index.html");
    // Template attributes can span lines, and dictionary keys hold LF; a CRLF checkout would make
    // equal strings differ.
    let text = read(&source).replace("\r\n", "\n");
    let english = dictionary(&text, "en");
    let japanese = dictionary(&text, "ja");
    let chinese = dictionary(&text, "zh");
    let korean = dictionary(&text, "ko");
    assert!(
        english.len() > 500 && japanese.len() > 500 && chinese.len() > 500,
        "사전을 거의 읽지 못했습니다. en {} / ja {} / zh {}",
        english.len(),
        japanese.len(),
        chinese.len()
    );
    let screen_languages = [("en", &english), ("ja", &japanese), ("zh", &chinese)];
    let server_languages = [("ko", &korean), ("ja", &japanese), ("zh", &chinese)];

    let open = text.find("<x-dc>").expect("템플릿 시작을 찾지 못했습니다");
    let close = text.find("</x-dc>").expect("템플릿 끝을 찾지 못했습니다");
    let template = &text[open..close];
    let script = &text[close..];
    let line_offset = text[..close].matches('\n').count() + 1;

    let translating = translating_spans(script);
    let rendering = rendering_spans(script);
    let wanted = wanted_strings(template, script, &translating);
    assert!(
        wanted.len() > 400,
        "화면 문구를 거의 읽지 못했습니다: {}개",
        wanted.len()
    );

    let mut problems: Vec<String> =
        untranslated_render_strings(script, line_offset, &translating, &rendering)
            .into_iter()
            .map(|item| format!("React 렌더 문자열가 t 를 거치지 않습니다 ({item})"))
            .collect();

    let pinned: BTreeSet<(String, String)> = RENDER_DATA_LITERALS
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    let raw = raw_render_data(script, &translating);
    for (key, value) in raw.difference(&pinned) {
        problems.push(format!(
            "렌더 데이터에 번역하지 않은 한글이 붙었습니다 ({key}): {value:?}"
        ));
    }
    for (key, value) in pinned.difference(&raw) {
        problems.push(format!(
            "목록에 적힌 렌더 데이터가 소스에 없습니다. 목록에서 지우십시오 ({key}): {value:?}"
        ));
    }

    let server_errors = server_error_strings();
    assert!(
        !server_errors.is_empty(),
        "관리 API 오류 본문을 하나도 읽지 못했습니다"
    );
    for (message, origin) in &server_errors {
        for (lang, keys) in server_languages {
            if !resolvable(message, keys) {
                problems.push(format!(
                    "{lang} 번역 없음 (관리 API 오류 본문 {origin}): {message:?}"
                ));
            }
        }
    }
    for (key, origin) in &wanted {
        for (lang, keys) in screen_languages {
            if !resolvable(key, keys) {
                problems.push(format!("{lang} 번역 없음 ({origin}): {key:?}"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "화면 번역이 {}건 비어 있습니다:\n  - {}",
        problems.len(),
        problems.join("\n  - ")
    );
}

#[test]
fn the_scanning_helpers_behave() {
    let script = "R('div', this.t('가'), '나')";
    let translating = translating_spans(script);
    let rendering = rendering_spans(script);
    let spans = quoted_spans(script);
    let korean: Vec<(&str, bool, bool)> = spans
        .iter()
        .map(|(start, end)| {
            (
                &script[*start..*end],
                within(*start, &translating),
                within(*start, &rendering),
            )
        })
        .collect();
    assert_eq!(
        korean,
        vec![
            ("div", false, true),
            ("가", true, true),
            ("나", false, true)
        ]
    );

    // An R ending a name is not a render call.
    assert!(rendering_spans("myR('가')").is_empty());

    // A key only when a colon follows.
    assert_eq!(
        literal_keys("{'가':'A','나'}")
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["가".to_string()]
    );

    // Prefix and suffix matches.
    let keys: BTreeSet<String> = ["삭제 실패: ".to_string(), "개 항목".to_string()]
        .into_iter()
        .collect();
    assert!(resolvable("삭제 실패: 무엇", &keys));
    assert!(resolvable("세 개 항목", &keys));
    assert!(!resolvable("알 수 없음", &keys));
}
