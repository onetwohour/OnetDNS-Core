/*!
 * @brief 소스 주석이 줄 주석 없이 블록 주석으로만 쓰였는지 검사한다.
 *
 * @details 이 저장소의 주석은 Doxygen 블록 하나로 쓴다. 항목 앞에는 문서 주석을, 함수
 *          본문 안에는 일반 블록 주석을 둔다. 줄 주석은 편집하다 보면 계속 섞여 들어오므로
 *          글로 적은 규칙만으로는 막지 못한다.
 * @note 계층 순서와 hot-apply 단계를 표시하는 줄 주석 넷은 lane_gate_drift 가 그 글자를
 *       찾아 구간을 잘라 내므로 그대로 둔다.
 */

mod common;

use common::{read, rel, rust_sources};

/** @brief 다른 테스트가 글자 그대로 찾는 표시. 파일과 줄 주석 글자의 쌍이다. */
const MARKERS: &[(&str, &str)] = &[
    ("onetdns-bin/src/resolver_chain.rs", "// layer-order:begin"),
    ("onetdns-bin/src/resolver_chain.rs", "// layer-order:end"),
    ("onetdns-bin/src/hot_apply.rs", "// hot-apply:begin"),
    ("onetdns-bin/src/hot_apply.rs", "// hot-apply:end"),
];

/** @brief 식별자를 이루는 글자인지. 리터럴 접두사가 식별자의 일부인지 가를 때 쓴다. */
fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/** @brief index 에서 시작하는 블록 주석이 끝난 다음 위치. 블록 주석은 중첩된다. */
fn block_comment_end(source: &str, mut index: usize) -> usize {
    let mut depth = 0usize;
    while index < source.len() {
        let rest = &source[index..];
        if rest.starts_with("/*") {
            depth += 1;
            index += 2;
        } else if rest.starts_with("*/") {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return index;
            }
        } else {
            index += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    source.len()
}

/**
 * @brief index 에서 r, br, cr 접두사의 원시 문자열이 시작하면 그것이 끝난 다음 위치.
 * @return 원시 문자열이 아니면 None.
 */
fn raw_string_end(source: &str, index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if index > 0 && is_ident(bytes[index - 1]) {
        return None;
    }
    let rest = &source[index..];
    let prefix = ["br", "cr", "r"]
        .into_iter()
        .find(|prefix| rest.starts_with(prefix))?;
    let hashes = rest[prefix.len()..]
        .bytes()
        .take_while(|byte| *byte == b'#')
        .count();
    let open = index + prefix.len() + hashes;
    if bytes.get(open) != Some(&b'"') {
        return None;
    }
    let terminator = format!("\"{}", "#".repeat(hashes));
    let close = source[open + 1..]
        .find(&terminator)
        .map_or(source.len(), |offset| open + 1 + offset + terminator.len());
    Some(close)
}

/** @brief index 의 큰따옴표로 시작한 문자열이 끝난 다음 위치. 이스케이프를 건너뛴다. */
fn string_end(bytes: &[u8], mut index: usize) -> usize {
    index += 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/**
 * @brief index 의 작은따옴표가 문자 리터럴을 열면 그것이 끝난 다음 위치.
 * @details 수명과 레이블도 작은따옴표로 시작하므로, 글자 하나 뒤에 닫는 따옴표가 없으면
 *          따옴표 하나만 건너뛴다.
 */
fn quote_end(source: &str, index: usize) -> usize {
    let rest = &source[index + 1..];
    if rest.starts_with('\\') {
        return rest
            .get(2..)
            .and_then(|tail| tail.find('\''))
            .map_or(source.len(), |offset| index + 1 + 2 + offset + 1);
    }
    let mut chars = rest.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), Some('\'')) => index + 1 + ch.len_utf8() + 1,
        _ => index + 1,
    }
}

/**
 * @brief 리터럴 밖에 있는 줄 주석을 모두 찾는다.
 * @return 줄 번호와 줄 끝 공백을 뗀 주석 글자의 쌍.
 */
fn line_comments(source: &str) -> Vec<(usize, &str)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let rest = &source[index..];
        if rest.starts_with("//") {
            let end = rest.find('\n').map_or(bytes.len(), |offset| index + offset);
            let line = source[..index].matches('\n').count() + 1;
            out.push((line, source[index..end].trim_end()));
            index = end;
        } else if rest.starts_with("/*") {
            index = block_comment_end(source, index);
        } else if let Some(end) = raw_string_end(source, index) {
            index = end;
        } else if bytes[index] == b'"' {
            index = string_end(bytes, index);
        } else if bytes[index] == b'\'' {
            index = quote_end(source, index);
        } else {
            index += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

#[test]
/** @brief 표시 마커 말고는 어떤 Rust 소스에도 줄 주석이 없다. */
fn sources_use_block_comments_only() {
    let mut found = Vec::new();
    for path in rust_sources(&["crates", "onetdns-bin", "tools"]) {
        let name = rel(&path);
        let source = read(&path).replace("\r\n", "\n");
        for (line, comment) in line_comments(&source) {
            if !MARKERS.contains(&(name.as_str(), comment)) {
                found.push(format!("{name}:{line}: {comment}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "줄 주석이 있습니다. 항목 앞이면 문서 주석으로, 본문 안이면 블록 주석으로 바꾸십시오:\n{}",
        found.join("\n")
    );
}

#[test]
/** @brief 리터럴 안의 두 빗금은 주석으로 세지 않고, 리터럴 밖의 것은 모두 센다. */
fn line_comments_skip_literals() {
    let source = concat!(
        "let url = \"https://example.test\";\n",
        "let raw = r#\"a \"// b\"#;\n",
        "let bytes = br\"//\";\n",
        "let quote = '\"'; let slash = '/'; let escaped = '\\''; let wide = '가';\n",
        "fn keep<'a>(text: &'a str) -> &'a str { text } // trailing\n",
        "/* outer /* inner // */ still comment */\n",
        "/// item doc\n",
        "    //! inner doc\n",
        "let r#type = 1; // after raw identifier\n",
    );
    let comments: Vec<_> = line_comments(source);
    assert_eq!(
        comments,
        vec![
            (5, "// trailing"),
            (7, "/// item doc"),
            (8, "//! inner doc"),
            (9, "// after raw identifier"),
        ],
        "리터럴 경계를 잘못 읽었습니다"
    );
}
