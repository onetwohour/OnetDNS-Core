//! Helpers for tests that scan the repository's sources for convention checks.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("작업공간 루트를 찾지 못했습니다")
        .to_path_buf()
}

/// Skips build output.
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

pub fn rust_sources(bases: &[&str]) -> Vec<PathBuf> {
    let repo = root();
    let mut out = Vec::new();
    for base in bases {
        collect(&repo.join(base), "rs", &mut out);
    }
    out.sort();
    out
}

/// Files holding only tests, such as native/tests.rs, are not wrapped in mod tests, so
/// production_prefix does not filter them; this checks the declaring module.
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

pub fn production_files(bases: &[&str]) -> Vec<PathBuf> {
    rust_sources(bases)
        .into_iter()
        .filter(|path| !is_test_module_file(path))
        .collect()
}

/// Panics if the file cannot be read.
pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} 를 읽지 못했습니다: {error}", path.display()))
}

/// With forward slashes.
pub fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Counts braces to cut out a declaration body. `head` opens it, as in `pub struct Config {`.
/// Returns the text from after the opening brace to just before its matching close.
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

/// Strings inside tests are never shown to users. A test module still counts with a doc comment
/// between the attribute and `mod tests`, or as `pub(crate) mod tests`.
pub fn production_prefix(source: &str) -> &str {
    let mut from = 0usize;
    while let Some(at) = source[from..].find("#[cfg(test)]") {
        let start = from + at;
        let mut after = source[start + "#[cfg(test)]".len()..].trim_start();
        loop {
            let tail = if let Some(rest) = after.strip_prefix("//") {
                rest.split_once('\n').map_or("", |(_, tail)| tail)
            } else if let Some(rest) = after.strip_prefix("/*") {
                rest.split_once("*/").map_or("", |(_, tail)| tail)
            } else {
                break;
            };
            after = tail.trim_start();
        }
        if after
            .strip_prefix("pub(crate) ")
            .unwrap_or(after)
            .starts_with("mod tests")
        {
            return &source[..start];
        }
        from = start + "#[cfg(test)]".len();
    }
    source
}
