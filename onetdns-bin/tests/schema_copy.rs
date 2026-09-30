/*!
 * @brief 설정 항목마다 ko/en/ja/zh 문구가 실제로 그 항목을 설명하는지 검사한다.
 *
 * @details 변수 이름을 그대로 옮긴 딱지나, 여러 항목에 같은 문장을 복사한 설명은
 *          화면을 채우기만 할 뿐 아무것도 알려 주지 않는다. 번역칸을 한국어로 채운
 *          것도 마찬가지다. 이런 것들을 통과시키면 설정 화면이 거짓으로 완성돼 보인다.
 * @warning 항목 수 252 는 계산해서 나온 값이 아니라 일부러 고정해 둔 것이다. 설정을
 *          더하거나 뺐다면 그것이 의도한 변경인지 스스로 판단하고 손으로 고쳐야 한다.
 */

mod common;

use common::{read, root};
use std::collections::BTreeMap;

/** @brief 설명이라기보다 곳만 채운 문장들. */
const GENERIC_PHRASES: &[&str] = &[
    "관련 보안",
    "이 설정에 대한 설명",
    "Value, address, or path used by",
    "Review the security and performance impact",
    "この設定の説明",
    "用途と影響を確認",
];

/**
 * @brief 설정 화면에서 더 쓰지 않는 한국어 용어.
 *
 * @note 업스트림은 여기 없다. 설정 키 이름이 upstream_urls 라서, 화면만 다른 말을 쓰면
 *       읽는 사람이 자기가 적은 항목과 이어 붙이지 못한다.
 */
const DEPRECATED_KO: &[&str] = &["리스너", "프리페치", "스테일", "롤백", "세대 교체"];

/** @brief 변수 이름을 그대로 옮긴 티가 나는 영어 단어. */
const GENERATED_EN: &[&str] = &[
    "Secs",
    "Pct",
    "Inflight",
    "Synthall",
    "Nxdomain",
    "Aaaa",
    "Ratelimit",
    "Ids",
    "Nsid",
    "Zonemd",
    "Dnssec",
    "Cname",
    "Dname",
    "Lmdb",
    "Etcd",
    "Mtu",
    "Querylog",
];

/** @brief 일본어 딱지에 그대로 남은 영어 변수 조각. */
const GENERATED_JA: &[&str] = &[
    "secs",
    "pct",
    "inflight",
    "synthall",
    "blocklists",
    "allowlists",
    "recursive",
    "probe",
    "backoff",
    "blocked",
    "search",
    "aaaa",
    "bogus",
    "needed",
    "priv",
    "empty",
    "track",
    "rule",
    "rewrites",
    "service",
    "ratelimit",
    "val",
    "rfc5011",
    "trust",
    "minimisation",
    "harden",
    "recurse",
    "split",
    "dir",
    "db",
    "keys",
    "check",
    "reject",
    "absence",
    "enable",
    "tokens",
    "clients",
    "querylog",
];

/** @brief 스키마 소스. */
fn schema() -> String {
    read(&root().join("crates/onetdns-config/src/schema.rs"))
}

/**
 * @brief 여는 따옴표 다음 위치에서 Rust 문자열 리터럴 하나를 읽는다.
 * @return 내용과, 닫는 따옴표 다음 위치.
 */
fn string_at(source: &str, open: usize) -> (String, usize) {
    let bytes = source.as_bytes();
    let mut out = String::new();
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                // 이 소스에서 쓰이는 이스케이프는 내용 비교에 영향이 없으므로 그대로 담는다.
                out.push('\\');
                if index + 1 < bytes.len() {
                    out.push(bytes[index + 1] as char);
                }
                index += 2;
            }
            b'"' => return (out, index + 1),
            _ => {
                let rest = &source[index..];
                let ch = rest.chars().next().unwrap_or('"');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    (out, index)
}

/** @brief 지정한 표지 다음에 나오는 문자열 리터럴 하나. */
fn string_after(source: &str, from: usize, marker: &str) -> Option<(String, usize)> {
    let at = source[from..].find(marker)? + from + marker.len();
    let quote = source[at..].find('"')? + at;
    Some(string_at(source, quote))
}

/** @brief FIELD_COPY 선언이 시작하는 위치. 그 앞이 항목 선언 구역이다. */
fn copy_start(source: &str) -> usize {
    source
        .find("static FIELD_COPY")
        .expect("schema.rs 에서 static FIELD_COPY 를 찾지 못했습니다")
}

/** @brief f("키" 형태로 선언된 설정 항목 이름. */
fn field_keys(source: &str) -> Vec<String> {
    let head = &source[..copy_start(source)];
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = head[from..].find("f(") {
        let call = from + at + 2;
        let rest = head[call..].trim_start();
        if rest.starts_with('"') {
            let quote = call + (head[call..].len() - rest.len());
            let (key, next) = string_at(head, quote);
            out.push(key);
            from = next;
        } else {
            from = call;
        }
    }
    out
}

/** @brief 한 항목의 언어별 딱지와 설명. 순서는 ko, en, ja, zh 이다. */
struct Copy {
    key: String,
    label: [String; 4],
    description: [String; 4],
}

/** @brief FieldCopy 선언을 모두 읽는다. */
fn copies(source: &str) -> Vec<Copy> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = source[from..].find("FieldCopy {") {
        let start = from + at;
        let Some((key, mut cursor)) = string_after(source, start, "key:") else {
            break;
        };
        let mut values = Vec::new();
        let mut ok = true;
        for marker in [
            "label_ko:",
            "label_en:",
            "label_ja:",
            "label_zh:",
            "description_ko:",
            "description_en:",
            "description_ja:",
            "description_zh:",
        ] {
            match string_after(source, cursor, marker) {
                Some((value, next)) => {
                    values.push(value);
                    cursor = next;
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            out.push(Copy {
                key,
                label: [
                    values[0].clone(),
                    values[1].clone(),
                    values[2].clone(),
                    values[3].clone(),
                ],
                description: [
                    values[4].clone(),
                    values[5].clone(),
                    values[6].clone(),
                    values[7].clone(),
                ],
            });
        }
        from = cursor.max(start + 11);
    }
    out
}

/** @brief 한글이 들어 있는지. */
fn has_hangul(text: &str) -> bool {
    text.chars().any(|c| ('가'..='힣').contains(&c))
}

/** @brief 영문 단어 단위로 정확히 일치하는 것이 있는지. */
fn has_word(text: &str, words: &[&str]) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| words.contains(&word))
}

/** @brief 항목과 문구가 1대1로 맞물리는지. */
#[test]
fn every_field_has_exactly_one_copy_entry() {
    let source = schema();
    let keys = field_keys(&source);
    let entries = copies(&source);
    assert!(
        entries.len() > 200,
        "문구 선언을 거의 찾지 못했습니다({}개). 파싱이 깨졌습니다",
        entries.len()
    );
    assert_eq!(
        entries.len(),
        keys.len(),
        "항목 수와 문구 수가 다릅니다: 항목 {} / 문구 {}",
        keys.len(),
        entries.len()
    );
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for entry in &entries {
        *seen.entry(entry.key.as_str()).or_default() += 1;
    }
    let duplicates: Vec<&&str> = seen
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(key, _)| key)
        .collect();
    assert!(duplicates.is_empty(), "문구가 중복된 항목: {duplicates:?}");
    let declared: std::collections::BTreeSet<&str> = keys.iter().map(String::as_str).collect();
    let described: std::collections::BTreeSet<&str> =
        entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(
        declared, described,
        "선언된 항목과 문구가 붙은 항목이 다릅니다"
    );
}

/** @brief 문구가 너무 짧거나 곳만 채운 문장이면 실패한다. */
#[test]
fn every_copy_is_specific_enough() {
    let source = schema();
    let mut bad = Vec::new();
    for entry in copies(&source) {
        for (index, language) in [(0, "ko"), (1, "en"), (2, "ja"), (3, "zh")] {
            let label = entry.label[index].trim();
            let description = entry.description[index].trim();
            if label.chars().count() < 2 {
                bad.push(format!("{} {language}: 딱지가 너무 짧습니다", entry.key));
            }
            if description.chars().count() < 12 {
                bad.push(format!("{} {language}: 설명이 너무 짧습니다", entry.key));
            }
            if GENERIC_PHRASES
                .iter()
                .any(|phrase| description.contains(phrase))
            {
                bad.push(format!("{} {language}: 곳만 채운 설명입니다", entry.key));
            }
        }
        if DEPRECATED_KO
            .iter()
            .any(|term| entry.label[0].contains(term) || entry.description[0].contains(term))
        {
            bad.push(format!("{} ko: 더 쓰지 않는 용어입니다", entry.key));
        }
        if has_hangul(&entry.label[1]) || has_hangul(&entry.description[1]) {
            bad.push(format!("{} en: 한국어가 남아 있습니다", entry.key));
        }
        if has_hangul(&entry.label[2]) || has_hangul(&entry.description[2]) {
            bad.push(format!("{} ja: 한국어가 남아 있습니다", entry.key));
        }
        if has_hangul(&entry.label[3]) || has_hangul(&entry.description[3]) {
            bad.push(format!("{} zh: 한국어가 남아 있습니다", entry.key));
        }
        if has_word(&entry.label[1], GENERATED_EN) || entry.label[1].contains("Control Control") {
            bad.push(format!(
                "{} en: 변수 이름에서 만든 딱지입니다 ({})",
                entry.key, entry.label[1]
            ));
        }
        if has_word(&entry.label[2].to_ascii_lowercase(), GENERATED_JA) {
            bad.push(format!(
                "{} ja: 변수 이름에서 만든 딱지입니다 ({})",
                entry.key, entry.label[2]
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "설정 문구가 항목을 설명하지 못합니다:\n  - {}",
        bad.join("\n  - ")
    );
}

/** @brief 같은 설명을 여러 항목에 복사해 붙이면 실패한다. */
#[test]
fn no_description_is_pasted_across_many_fields() {
    let source = schema();
    let entries = copies(&source);
    let mut repeated = Vec::new();
    for (index, language) in [(0, "ko"), (1, "en"), (2, "ja"), (3, "zh")] {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &entries {
            *counts.entry(entry.description[index].as_str()).or_default() += 1;
        }
        for (text, count) in counts {
            if count > 3 {
                repeated.push(format!("{language} {count}회: {text}"));
            }
        }
    }
    assert!(
        repeated.is_empty(),
        "여러 항목에 같은 설명이 붙어 있습니다:\n  - {}",
        repeated.join("\n  - ")
    );
}

/** @brief 선택지 항목의 값마다 딱지가 붙어 있는지. */
#[test]
fn every_enum_value_has_a_label() {
    let source = schema();
    let head = &source[..copy_start(&source)];
    let mut declared = std::collections::BTreeSet::new();
    let mut from = 0usize;
    while let Some(at) = head[from..].find("f(") {
        let call = from + at + 2;
        let mut cursor = call;
        let mut values = Vec::new();
        // 한 호출 안의 문자열 인자들을 순서대로 읽는다.
        let end = head[call..]
            .find("\n    f(")
            .map_or(head.len(), |offset| call + offset);
        while let Some(quote) = head[cursor..end].find('"') {
            let (value, next) = string_at(head, cursor + quote);
            values.push(value);
            cursor = next;
        }
        if values.len() >= 4 && values[1] == "enum" {
            for value in values[3].split('|').filter(|v| !v.is_empty()) {
                assert!(
                    !value.contains('('),
                    "선택지의 원값에 설명이 섞여 있습니다: {value}"
                );
                declared.insert((values[0].clone(), value.to_string()));
            }
        }
        from = end.max(call);
    }

    let mut mapped = std::collections::BTreeSet::new();
    let source = source.as_str();
    let mut from = 0usize;
    while let Some(at) = source[from..].find("=>") {
        let arrow = from + at;
        let head_of_arm = source[..arrow].trim_end();
        if head_of_arm.ends_with(')') {
            if let Some(open) = head_of_arm.rfind("(\"") {
                let (key, next) = string_at(source, open + 1);
                if let Some(second) = source[next..arrow].find('"') {
                    let (value, _) = string_at(source, next + second);
                    mapped.insert((key, value));
                }
            }
        }
        from = arrow + 2;
    }

    assert!(
        declared.len() > 10,
        "선택지 항목을 거의 찾지 못했습니다({}개). 검사가 헛돌고 있습니다",
        declared.len()
    );
    let missing: Vec<_> = declared.difference(&mapped).collect();
    let extra: Vec<_> = mapped.difference(&declared).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "선택지 딱지가 맞지 않습니다. 없는 것: {missing:?} / 남는 것: {extra:?}"
    );
}

/** @brief 단위 필드에 단위가 아닌 것이 새어 들어오면 실패한다. */
#[test]
fn the_unit_column_carries_only_units() {
    let source = schema();
    assert!(
        source.contains("fn field_unit(field: &Field)")
            && source.contains("let unit = field_unit(fd);"),
        "설정 스키마가 단위 필드를 다른 정보로 쓰고 있습니다"
    );
    let start = source
        .find("fn field_unit")
        .expect("field_unit 을 찾지 못했습니다");
    let end = source
        .find("pub fn schema_json")
        .expect("schema_json 을 찾지 못했습니다");
    let body = &source[start..end];
    for forbidden in ["127.0.0.1/32", "IP 또는 URL", "dnssec=true"] {
        assert!(
            !body.contains(forbidden),
            "단위가 아닌 것이 단위 필드에 들어 있습니다: {forbidden}"
        );
    }
}

/** @brief 문자열 리터럴과 단어 판정이 실제로 구분하는지 확인한다. */
#[test]
fn the_parsing_helpers_behave() {
    let source = r#"key: "a\"b", next: "c""#;
    let (first, after) = string_at(source, source.find('"').unwrap());
    assert_eq!(first, "a\\\"b", "이스케이프된 따옴표에서 끊겼습니다");
    assert!(source[after..].contains("next"));

    assert!(has_hangul("영문 mixed"));
    assert!(!has_hangul("plain english"));
    assert!(has_word("Cache Secs", GENERATED_EN));
    assert!(!has_word("Seconds of cache", GENERATED_EN));
}
