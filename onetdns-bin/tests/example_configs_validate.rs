//! Every example config in the repository must parse and validate, so an operator copying one does
//! not fail to start.

use std::path::{Path, PathBuf};

use onetdns_config::Config;

const EXAMPLE_DIRS: &[&str] = &["benchmarks", "examples", "docs"];
/// TOML files that are not server configs; the scan reads every TOML it finds as one.
/// architecture.toml registers document ownership, and docs_drift reads it.
const SKIP_FILE_NAMES: &[&str] = &["Cargo.toml", "deny.toml", "architecture.toml"];

fn collect_tomls(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_tomls(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "toml")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !SKIP_FILE_NAMES.contains(&name))
        {
            out.push(path);
        }
    }
}

#[test]
fn repo_example_configs_parse_and_validate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("작업공간의 최상위 디렉터리가 있어야 합니다")
        .to_path_buf();
    let mut files = Vec::new();
    for dir in EXAMPLE_DIRS {
        collect_tomls(&root.join(dir), &mut files);
    }
    assert!(
        !files.is_empty(),
        "예제 설정을 찾지 못했습니다. 예제 디렉터리를 옮겼다면 EXAMPLE_DIRS 목록을 갱신해야 합니다"
    );
    for path in files {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} 읽지 못했습니다: {error}", path.display()));
        let config = Config::from_toml_str(&text)
            .unwrap_or_else(|error| panic!("{} 해석하지 못했습니다: {error:?}", path.display()));
        config
            .validate()
            .unwrap_or_else(|error| panic!("{} 검증에 실패했습니다: {error:?}", path.display()));
    }
}
