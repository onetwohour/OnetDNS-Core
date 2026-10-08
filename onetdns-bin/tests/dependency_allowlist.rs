/*!
 * @brief 허용 목록에 없는 외부 크레이트가 트리에 들어오지 못하게 막는다.
 *
 * @details 이 저장소는 네트워크와 프로토콜 스택에 외부 크레이트를 쓰지 않는다는 전제 위에 있다.
 *          허용한 암호 크레이트와 Unix 플랫폼 바인딩 말고 새 의존이 들어오면 그 전제가
 *          무너진다. 양방향으로 검사한다. 목록에 없는 크레이트가 선언돼도 걸리고,
 *          목록에만 있고 아무도 쓰지 않아도 걸린다.
 * @warning 여기 목록은 docs/principles/constraints.md 의 목록과 1:1로 유지한다. 한쪽만
 *          고치면 문서와 실제가 갈라진다.
 */

mod common;

use common::{read, rel, root};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/** @brief 실행되는 바이너리에 들어와도 되는 외부 크레이트. */
const RUNTIME_ALLOWED: &[&str] = &[
    /* 검증된 암호 크레이트 */
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
    /*
     * QUIC 헤더 보호와 DNSCrypt 의 crypto_secretbox 구성은 AEAD 가 노출하지 않는 원시
     * 블록 연산이 필요하다. 세 크레이트는 위 AEAD 의 전이 의존이라 새 코드가 아니다.
     */
    "aes",
    "chacha20",
    "poly1305",
    /* Unix 플랫폼 바인딩. Windows 서비스 제어는 트리 안 바인딩을 쓴다. */
    "libc",
];

/** @brief 테스트와 벤치에서만 쓰는 크레이트. 출하 바이너리에 들어가지 않는다. */
const DEV_ALLOWED: &[&str] = &[
    /* 이 서버의 코덱 결과와 교차 대조한다. */
    "hickory-proto",
    /* 테스트용 인증서를 만든다. */
    "rcgen",
    /* WASM 텍스트를 바이너리로 바꾼다. */
    "wat",
];

/** @brief 검사할 매니페스트 전부. */
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

/**
 * @brief 절 이름이 의존성 절인지, dev 전용인지.
 * @details [[bench]] 같은 배열 절도 반드시 잡아야 한다. 놓치면 그 안의 name 항목이
 *          앞 절의 의존성으로 새어 들어온다.
 */
fn dependency_section(name: &str) -> (bool, bool) {
    let tail = name.rsplit('.').next().unwrap_or(name);
    let is_deps = matches!(
        tail,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    );
    (is_deps, tail == "dev-dependencies")
}

/** @brief 절 헤더가면 그 이름. */
fn section_name(line: &str) -> Option<&str> {
    let line = line.trim();
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let inner = inner.strip_suffix(']').unwrap_or(inner);
    (!inner.is_empty() && !inner.contains(']')).then_some(inner)
}

/** @brief 항목 줄이면 그 크레이트 이름. */
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

/** @brief 매니페스트에서 선언된 외부 크레이트를 런타임과 dev 로 갈라 모은다. */
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
    /* 런타임에도 나오는 크레이트는 dev 전용이 아니다. */
    for crate_name in runtime.keys() {
        dev.remove(crate_name);
    }
    (runtime, dev)
}

/** @brief 목록에 없는 크레이트가 선언되면 실패한다. */
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

/** @brief 목록에만 있고 아무도 쓰지 않는 크레이트가 있으면 실패한다. */
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

/** @brief 절과 항목을 구분하는 판정이 실제로 구분하는지 확인한다. */
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
    /* 배열 절을 의존성으로 보면 그 안의 name 항목이 크레이트로 새어 들어온다. */
    assert_eq!(dependency_section("bench"), (false, false));

    assert_eq!(
        entry_name("hickory-proto = { version = \"0.24\" }"),
        Some("hickory-proto")
    );
    assert_eq!(entry_name("name = \"query\""), Some("name"));
    assert_eq!(entry_name("# 주석"), None);
}
