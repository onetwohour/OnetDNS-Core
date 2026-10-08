/*!
 * @brief 설정 키가 실제로 동작에 연결돼 있는지 검사한다.
 *
 * @details 죽은 설정 키를 두지 않는 것이 이 저장소의 규칙이다. 그런데 스키마 테스트는
 *          키마다 화면 문구가 있고 KNOWN_KEYS 에 들어 있다는 것만 본다. 아무도 읽지
 *          않는 키도 그 둘을 만족할 수 있다.
 * @note 읽는다고 보는 기준은 두 가지다. 설정 크레이트의 선언 파일 바깥에서 그 필드를
 *       읽거나, settings.rs 안에서라도 검증이나 교차 규칙 같은 실제 논리가 읽는
 *       경우다. 구조체 선언, Default 구현, 디코더 대입, 덤프용 kv 호출은 동작을
 *       증명하지 않으므로 세지 않는다.
 */

mod common;

use common::{block_after, read, root, rust_sources};

/** @brief Config 구조체의 공개 필드 이름. */
fn config_fields(source: &str) -> Vec<String> {
    let body = block_after(source, "pub struct Config {")
        .expect("settings.rs 에서 pub struct Config 를 찾지 못했습니다");
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            out.push(name.to_string());
        }
    }
    out
}

/**
 * @brief settings.rs 에서 동작의 증거가 되는 줄만 남긴다.
 * @details 덤프용 kv 호출은 값을 찍기만 하므로 그 키가 동작한다는 증거가 아니다.
 */
fn logic_lines(settings: &str) -> String {
    settings
        .lines()
        .filter(|line| line.contains("self.") && !line.contains("kv("))
        .collect::<Vec<_>>()
        .join("\n")
}

/** @brief 바깥에서도 논리에서도 읽히지 않는 필드. */
fn dead_fields<'a>(fields: &'a [String], external: &str, logic: &str) -> Vec<&'a String> {
    fields
        .iter()
        .filter(|field| {
            !external.contains(&format!(".{field}")) && !logic.contains(&format!("self.{field}"))
        })
        .collect()
}

/** @brief 설정 키가 어디에서도 읽히지 않으면 실패한다. */
#[test]
fn every_config_key_is_wired_to_behavior() {
    let repo = root();
    let settings_path = repo.join("crates/onetdns-config/src/settings.rs");
    let schema_path = repo.join("crates/onetdns-config/src/schema.rs");
    let settings = read(&settings_path);
    let fields = config_fields(&settings);
    assert!(
        !fields.is_empty(),
        "Config 필드를 하나도 읽지 못했습니다. 구조체 모양이 바뀌었습니다"
    );

    let external: String = rust_sources(&["onetdns-bin/src", "crates"])
        .into_iter()
        .filter(|path| *path != settings_path && *path != schema_path)
        .map(|path| read(&path))
        .collect::<Vec<_>>()
        .join("\n");

    let dead = dead_fields(&fields, &external, &logic_lines(&settings));
    assert!(
        dead.is_empty(),
        "아무도 읽지 않는 설정 키가 있습니다. 동작에 연결하거나 키를 지우십시오: {dead:?}"
    );
}

/**
 * @brief 판정 자체가 죽은 키를 골라내는지 합성 입력으로 확인한다.
 * @details 실제 소스에 가짜 필드를 넣으면 크레이트가 컴파일되지 않으므로, 판정
 *          함수만 떼어 내 확인한다. 이것이 없으면 위 테스트는 언제나 통과하는
 *          테스트가 되어도 아무도 모른다.
 */
#[test]
fn the_check_actually_finds_an_unread_key() {
    let source = "pub struct Config {\n    pub used_key: bool,\n    pub never_read: bool,\n}\n";
    let fields = config_fields(source);
    assert_eq!(
        fields,
        vec!["used_key".to_string(), "never_read".to_string()]
    );

    let external = "if cfg.used_key { act(); }";
    let dead = dead_fields(&fields, external, "");
    assert_eq!(dead, vec![&"never_read".to_string()]);

    /* settings.rs 안의 논리가 읽어도 살아 있는 것으로 본다. */
    let dead = dead_fields(&fields, external, "if self.never_read { reject(); }");
    assert!(dead.is_empty(), "논리에서 읽는 키를 죽었다고 봤습니다");

    /* 덤프용 kv 호출만으로는 살아 있다고 보지 않는다. */
    let only_dump = logic_lines("    kv(\"never_read\", self.never_read);\n");
    let dead = dead_fields(&fields, external, &only_dump);
    assert_eq!(dead, vec![&"never_read".to_string()]);
}
