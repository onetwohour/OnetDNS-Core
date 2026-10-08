/*!
 * @brief 대시보드가 보여 주는 한국어 문구에 영어, 일본어, 중국어 번역이 있는지 검사한다.
 *
 * @details 대시보드는 두 경로로 화면을 그린다. 템플릿 텍스트는 localizeDom 이 실행
 *          중에 바꾸고, React 쪽 코드는 this.t 나 this.tr 로 직접 바꾼다. 둘 다 한국어
 *          원문을 키로 삼아 사전을 찾고, 키가 없으면 그 키를 그대로 돌려준다. 그래서
 *          번역이 없어도 오류가 나지 않고 영어 화면에 한국어가 그대로 나온다.
 * @details localizeDom 은 data-dc-tpl 이 붙은 요소 아래만 바꾼다. React 가 만든
 *          요소에는 그 표시가 없어서, React 에 넘긴 한국어 문자열은 영어 화면에도
 *          그대로 나온다. 사전만 확인해서는 이 경우를 잡을 수 없다. 문자열이 사전에
 *          있는데 아무도 찾지 않은 것이기 때문이다.
 * @details 서버가 보내는 문자열도 함께 확인한다. 관리 API 는 영어로 답하므로, 오류
 *          본문은 한국어, 일본어, 중국어 사전에 영어 원문을 키로 올라 있어야 한다.
 *          그렇지 않으면 errorText 가 대비 문구 뒤에 영어 원문을 붙여 보여 준다. 그
 *          문자열은 Rust 쪽에 있어서 HTML 만으로는 찾을 수 없다.
 * @note 한 가지는 여기서 잡히지 않는다. 렌더 위치에서 변수에 붙은 t 를 빼는 경우다.
 *       소스 텍스트만으로는 그 변수에 무엇이 담기는지 알 수 없다.
 */

mod common;

use common::{collect, production_prefix, read, rel, root};
use std::collections::{BTreeMap, BTreeSet};

/** @brief t 가 접미 일치로 키를 찾을 때 쓰는 시작 조각. 실행 중 규칙과 같아야 한다. */
const SUFFIX_STARTS: &[&str] = &[" ", "개 ", "개를 ", "번 ", "\" DNS"];

/** @brief 값이 그대로 화면에 표시되는 렌더 데이터 키. */
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

/**
 * @brief 렌더 위치에서 번역하기로 정한 데이터. 의도적으로 고정한 목록이다.
 * @details ACT 와 TRANSPORT 는 this.state 가 만들어지기 전에 생성되는 클래스 항목이라,
 *          여기서 번역하면 생성 시점의 언어가 그대로 굳는다. 나머지는 질의 진단 패널이
 *          explainEl 에서 번역한다. 새 항목은 실제로 t 를 거치는지 확인한 뒤에 적는다.
 */
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

/** @brief 번역을 거치는 호출 이름. */
const TRANSLATING_CALLS: &[&str] = &["this.t(", "this.tr(", "toastMsg(", "confirmDestructive("];

/** @brief 한글이 한 글자라도 들어 있는지 알려 준다. */
fn has_korean(text: &str) -> bool {
    text.chars().any(|ch| ('가'..='힣').contains(&ch))
}

/** @brief 자바스크립트 이스케이프 표기를 실제 문자열로 되돌린다. */
fn unescape(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\'", "'")
        .replace("\\\"", "\"")
}

/**
 * @brief 한 줄 안에서 따옴표로 둘러싸인 문자열의 위치를 모은다.
 * @return 내용의 시작 위치와 끝 위치.
 */
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

/**
 * @brief 사전 블록에 선언된 키.
 * @details 화면 문구는 한국어 원문이, 서버 문구는 영어 원문이 키다.
 * @details 키는 뒤에 콜론이 따라오는 문자열이다. 콜론이 없으면 그 따옴표는 키를 여는
 *          곳이 아니었다는 뜻이므로, 닫는 위치 뒤로 건너뛰지 않고 한 글자만
 *          나아가 다시 확인한다. 큰따옴표로 시작하는 키가 실제로 있어서, 건너뛰면
 *          그 키를 전부 놓친다.
 */
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

/** @brief 여는 중괄호에서 시작하는 객체 리터럴 전체. */
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

/** @brief 여는 괄호에 짝이 되는 닫는 괄호 위치. */
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

/** @brief 번역을 거치는 호출들이 차지하는 구간. */
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

/** @brief 렌더 호출들이 차지하는 구간. */
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

/** @brief 주어진 위치가 구간 안에 들어 있는지 알려 준다. */
fn within(position: usize, spans: &[(usize, usize)]) -> bool {
    spans
        .iter()
        .any(|(start, end)| *start < position && position < *end)
}

/** @brief 한 언어에 등록된 키 전부. */
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

/** @brief t 가 이 문자열을 그대로, 또는 접두나 접미 일치로 찾을 수 있는지 알려 준다. */
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

/**
 * @brief 관리 API 가 돌려줄 수 있는 오류 본문.
 * @note 테스트 모듈은 흉내 낸 응답이라 세지 않는다.
 */
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

/**
 * @brief Rust 문자열 리터럴 안에 적힌 error 본문을 추출한다.
 * @return 본문과 그 시작 위치.
 */
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

/** @brief 템플릿에서 태그를 걷어 낸 텍스트 조각. */
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

/** @brief 화면에 표시되는 한국어 문자열과 그 출처. */
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

/** @brief 렌더 호출 안에서 번역을 거치지 않은 한국어 문자열을 모은다. */
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

/** @brief 렌더 데이터에 직접 붙은 한국어 문자열을 모은다. */
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

/** @brief 화면 문구와 서버 오류 본문이 화면의 모든 언어로 번역되는지 확인한다. */
#[test]
fn every_korean_string_the_dashboard_shows_has_a_translation() {
    let source = root().join("crates/onetdns-control/dashboard/index.html");
    /*
     * 템플릿 속성은 줄을 넘길 수 있고 사전 키는 줄바꿈을 한 글자로 담는다. 작업본이
     * 두 글자짜리 줄바꿈으로 받아져 있으면 같은 문자열이 서로 다르게 보인다.
     */
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

/** @brief 문자열 추출과 구간 판정이 실제로 동작하는지 확인한다. */
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

    /* 이름 끝에 붙은 R 은 렌더 호출이 아니다. */
    assert!(rendering_spans("myR('가')").is_empty());

    /* 뒤에 콜론이 따라올 때만 키로 센다. */
    assert_eq!(
        literal_keys("{'가':'A','나'}")
            .into_iter()
            .collect::<Vec<_>>(),
        vec!["가".to_string()]
    );

    /* 접두와 접미 규칙이 실제로 동작한다. */
    let keys: BTreeSet<String> = ["삭제 실패: ".to_string(), "개 항목".to_string()]
        .into_iter()
        .collect();
    assert!(resolvable("삭제 실패: 무엇", &keys));
    assert!(resolvable("세 개 항목", &keys));
    assert!(!resolvable("알 수 없음", &keys));
}
