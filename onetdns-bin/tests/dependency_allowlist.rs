//! Keeps external crates to the allowlist: the networking and protocol stack uses none besides the
//! allowed crypto crates and Unix bindings. Checked both ways: an unlisted crate fails, and so does
//! a listed crate nobody declares.
//!
//! The lists match docs/principles/constraints.md; change both together.

mod common;

use common::{read, rel, root};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const RUNTIME_ALLOWED: &[&str] = &[
    // Vetted crypto crates.
    "x25519-dalek",
    "ed25519-dalek",
    "chacha20poly1305",
    "aes-gcm",
    "sha2",
    "sha1",
    "hkdf",
    "hmac",
    "p256",
    "p384",
    "zeroize",
    // Raw block ciphers for QUIC header protection and DNSCrypt's crypto_secretbox, which the AEAD
    // crates do not expose. All three already come in through those crates.
    "aes",
    "chacha20",
    "poly1305",
    // Unix platform bindings. Windows service control uses in-tree bindings.
    "libc",
];

/// Tests and benches only; never in the shipped binary.
const DEV_ALLOWED: &[&str] = &[
    // Cross-checks this server's codec output.
    "hickory-proto",
    // Generates test certificates.
    "rcgen",
    // Turns WASM text into binary.
    "wat",
];

fn manifests() -> Vec<PathBuf> {
    let repo = root();
    let mut found = vec![repo.join("Cargo.toml"), repo.join("onetdns-bin/Cargo.toml")];
    let mut crates: Vec<PathBuf> = std::fs::read_dir(repo.join("crates"))
        .expect("crates 디렉터리를 읽지 못했습니다")
        .flatten()
        .map(|entry| entry.path().join("Cargo.toml"))
        .filter(|path| path.exists())
        .collect();
    crates.sort();
    found.extend(crates);
    assert!(
        found.len() >= 3,
        "매니페스트를 찾지 못했습니다. 작업공간 배치가 바뀌었습니까"
    );
    found
}

/// (dependency section, dev-only). Array tables like [[bench]] must be recognized too, or their
/// `name` entries would count as dependencies of the section before.
fn dependency_section(name: &str) -> (bool, bool) {
    let tail = name.rsplit('.').next().unwrap_or(name);
    let is_deps = matches!(
        tail,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    );
    (is_deps, tail == "dev-dependencies")
}

fn section_name(line: &str) -> Option<&str> {
    let line = line.trim();
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let inner = inner.strip_suffix(']').unwrap_or(inner);
    (!inner.is_empty() && !inner.contains(']')).then_some(inner)
}

fn entry_name(line: &str) -> Option<&str> {
    let line = line.trim();
    let (name, _) = line.split_once('=')?;
    let name = name.trim();
    (!name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(name)
}

/// Declared external crates, as (runtime, dev).
fn declared() -> (
    BTreeMap<String, BTreeSet<String>>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut runtime: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut dev: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for manifest in manifests() {
        let where_ = rel(&manifest);
        let (mut in_deps, mut is_dev) = (false, false);
        for line in read(&manifest).lines() {
            if let Some(name) = section_name(line) {
                (in_deps, is_dev) = dependency_section(name);
                continue;
            }
            if !in_deps {
                continue;
            }
            let Some(crate_name) = entry_name(line) else {
                continue;
            };
            if crate_name.starts_with("onetdns") {
                continue;
            }
            let target = if is_dev { &mut dev } else { &mut runtime };
            target
                .entry(crate_name.to_string())
                .or_default()
                .insert(where_.clone());
        }
    }
    // A crate also used at runtime is not dev-only.
    for crate_name in runtime.keys() {
        dev.remove(crate_name);
    }
    (runtime, dev)
}

#[test]
fn no_crate_enters_outside_the_allowlist() {
    let (runtime, dev) = declared();
    let mut problems = Vec::new();
    for (crate_name, where_) in &runtime {
        if !RUNTIME_ALLOWED.contains(&crate_name.as_str()) {
            problems.push(format!(
                "런타임 의존 {crate_name:?} (선언: {})",
                where_.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    for (crate_name, where_) in &dev {
        if !DEV_ALLOWED.contains(&crate_name.as_str()) {
            problems.push(format!(
                "dev 의존 {crate_name:?} (선언: {})",
                where_.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "허용 목록에 없는 외부 크레이트가 선언됐습니다. 트리 안에서 만들 수 없는 이유를 적고 \
         docs/principles/constraints.md 의 목록을 같은 커밋에서 갱신하십시오:\n  - {}",
        problems.join("\n  - ")
    );
}

#[test]
fn the_allowlist_has_no_stale_entry() {
    let (runtime, dev) = declared();
    let mut unused: Vec<&str> = RUNTIME_ALLOWED
        .iter()
        .filter(|name| !runtime.contains_key(**name))
        .copied()
        .collect();
    unused.extend(
        DEV_ALLOWED
            .iter()
            .filter(|name| !dev.contains_key(**name))
            .copied(),
    );
    unused.sort_unstable();
    assert!(
        unused.is_empty(),
        "허용 목록에만 있고 실제로는 쓰지 않는 크레이트가 있습니다. 목록이 낡았으니 \
         지우십시오: {unused:?}"
    );
}

#[test]
fn section_and_entry_parsing_separate_arrays_from_dependencies() {
    assert_eq!(section_name("[dependencies]"), Some("dependencies"));
    assert_eq!(section_name("[[bench]]"), Some("bench"));
    assert_eq!(
        section_name("[target.'cfg(unix)'.dependencies]"),
        Some("target.'cfg(unix)'.dependencies")
    );
    assert_eq!(section_name("libc = \"0.2\""), None);

    assert_eq!(dependency_section("dependencies"), (true, false));
    assert_eq!(dependency_section("dev-dependencies"), (true, true));
    assert_eq!(dependency_section("build-dependencies"), (true, false));
    assert_eq!(
        dependency_section("target.'cfg(unix)'.dependencies"),
        (true, false)
    );
    assert_eq!(dependency_section("bench"), (false, false));

    assert_eq!(
        entry_name("hickory-proto = { version = \"0.24\" }"),
        Some("hickory-proto")
    );
    assert_eq!(entry_name("name = \"query\""), Some("name"));
    assert_eq!(entry_name("# 주석"), None);
}
