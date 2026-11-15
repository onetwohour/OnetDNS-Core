//! Each config key must be wired to behavior. The schema tests only check that a key has dashboard
//! text and is in KNOWN_KEYS, which a key nobody reads can satisfy.
//!
//! A key counts as read when its field is read outside the config crate's declaration file, or by
//! real logic such as validation or cross-key rules in settings.rs. Struct declarations, Default,
//! decoder assignments, and dump kv calls prove nothing and are not counted.

mod common;

use common::{block_after, read, root, rust_sources};

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

/// Dump kv calls only print values, so they are no evidence.
fn logic_lines(settings: &str) -> String {
    settings
        .lines()
        .filter(|line| line.contains("self.") && !line.contains("kv("))
        .collect::<Vec<_>>()
        .join("\n")
}

fn dead_fields<'a>(fields: &'a [String], external: &str, logic: &str) -> Vec<&'a String> {
    fields
        .iter()
        .filter(|field| {
            !external.contains(&format!(".{field}")) && !logic.contains(&format!("self.{field}"))
        })
        .collect()
}

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

/// A fake field in the real sources would break the build, so the predicate is tested alone;
/// without this, the test above could pass forever unnoticed.
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

    // Logic in settings.rs counts as a read.
    let dead = dead_fields(&fields, external, "if self.never_read { reject(); }");
    assert!(dead.is_empty(), "논리에서 읽는 키를 죽었다고 봤습니다");

    // A dump kv call alone does not.
    let only_dump = logic_lines("    kv(\"never_read\", self.never_read);\n");
    let dead = dead_fields(&fields, external, &only_dump);
    assert_eq!(dead, vec![&"never_read".to_string()]);
}
