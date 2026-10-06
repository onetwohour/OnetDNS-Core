/*!
 * @brief 저장소 전체를 훑는 회귀 테스트들이 함께 쓰는 헬퍼 함수.
 *
 * @details 소스 글자를 읽어 규약이 지켜지는지 보는 테스트가 여럿이라, 파일을 모으는
 *          일과 루트를 찾는 일을 한 곳에 둔다.
 * @note 테스트마다 쓰는 함수가 달라 일부는 특정 테스트에서만 호출된다.
 */
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/** @brief 작업공간 루트. */
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("작업공간 루트를 찾지 못했습니다")
        .to_path_buf()
}

/** @brief 확장자가 맞는 파일을 모두 모은다. 빌드 산출물은 건너뛴다. */
pub fn collect(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, ext, out);
        } else if path.extension().is_some_and(|found| found == ext) {
            out.push(path);
        }
    }
}

/** @brief 주어진 디렉터리들 아래의 모든 Rust 소스 경로. */
pub fn rust_sources(bases: &[&str]) -> Vec<PathBuf> {
    let repo = root();
    let mut out = Vec::new();
    for base in bases {
        collect(&repo.join(base), "rs", &mut out);
    }
    out.sort();
    out
}

/**
 * @brief 부모 모듈이 #[cfg(test)] 아래에서 선언한 파일인지.
 * @details native/tests.rs 처럼 테스트만 담은 파일은 mod tests 로 감싸지 않으므로
 *          production_prefix 로는 걸러지지 않는다. 선언한 쪽을 보고 판단한다.
 */
pub fn is_test_module_file(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    let Some(dir) = path.parent() else {
        return false;
    };
    let declaration = format!("mod {stem};");
    [dir.join("mod.rs"), dir.with_extension("rs")]
        .iter()
        .filter_map(|parent| std::fs::read_to_string(parent).ok())
        .any(|text| {
            text.match_indices(&declaration)
                .any(|(at, _)| text[..at].trim_end().ends_with("#[cfg(test)]"))
        })
}

/** @brief 주어진 디렉터리들 아래에서 테스트 전용 파일을 뺀 Rust 소스 경로. */
pub fn production_files(bases: &[&str]) -> Vec<PathBuf> {
    rust_sources(bases)
        .into_iter()
        .filter(|path| !is_test_module_file(path))
        .collect()
}

/** @brief 파일 하나를 읽는다. 읽지 못하면 그 자리에서 멈춘다. */
pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} 를 읽지 못했습니다: {error}", path.display()))
}

/** @brief 저장소 기준 상대 경로를 슬래시 표기로 돌려준다. */
pub fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/**
 * @brief 중괄호 짝을 세어 선언 본문을 잘라 낸다.
 * @param head 본문을 여는 선언. 예를 들어 pub struct Config {
 * @return 여는 중괄호 다음부터 짝이 맞는 닫는 중괄호 직전까지.
 */
pub fn block_after<'a>(source: &'a str, head: &str) -> Option<&'a str> {
    let start = source.find(head)? + head.len();
    let mut depth = 1usize;
    for (offset, ch) in source[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[start..start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/**
 * @brief 테스트 모듈 앞까지만 남긴다.
 * @details 테스트 안의 문자열은 사용자에게 보이지 않으므로 검사 대상이 아니다. 속성과
 *          mod tests 사이에 문서 주석이 있어도 테스트 모듈로 본다.
 */
pub fn production_prefix(source: &str) -> &str {
    let mut from = 0usize;
    while let Some(at) = source[from..].find("#[cfg(test)]") {
        let start = from + at;
        let mut after = source[start + "#[cfg(test)]".len()..].trim_start();
        while let Some(rest) = after.strip_prefix("/*") {
            after = rest
                .split_once("*/")
                .map_or("", |(_, tail)| tail)
                .trim_start();
        }
        if after.starts_with("mod tests") {
            return &source[..start];
        }
        from = start + "#[cfg(test)]".len();
    }
    source
}
