//! Where zone data comes from. Files, directories, memory, and the database backends all implement
//! one trait. Text-based sources end in parse_zone, so guarding the parser guards every input path.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
const MAX_ZONE_FILE: u64 = 64 * 1024 * 1024;
const MAX_ZONE_FILES: usize = 100_000;

/// Checks the metadata size first, then the bytes actually read: the file can grow between check
/// and read, and special files report no real length.
pub(crate) fn read_file_limited(path: &Path, max: u64, kind: &str) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > max {
        return Err(format!(
            "{}: {kind} file size or format is out of range",
            path.display()
        ));
    }
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(meta.len().min(1024 * 1024) as usize);
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > max {
        return Err(format!(
            "{}: {kind} file exceeds the size limit",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Rejects non-UTF-8.
pub fn read_zone_text(path: &Path) -> Result<String, String> {
    let bytes = read_file_limited(path, MAX_ZONE_FILE, "zone")?;
    String::from_utf8(bytes).map_err(|_| format!("{}: not valid UTF-8", path.display()))
}

/// Content digest of a zone file, recording which content an in-memory zone came from. Before
/// rewriting the file, this server compares it with the current file's digest so outside edits are
/// not overwritten. Modification times are coarse and editors may preserve them, so content is
/// compared instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceDigest([u8; 32]);

impl SourceDigest {
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::digest(bytes).into())
    }

    /// None when the file does not exist; an error when it exists but cannot be read.
    pub fn of_file(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
            Ok(_) => {
                read_file_limited(path, MAX_ZONE_FILE, "zone").map(|bytes| Some(Self::of(&bytes)))
            }
        }
    }
}

/// Attaches the content digest.
pub fn load_zone_file(path: &Path, default_origin: &str) -> Result<Zone, String> {
    let text = read_zone_text(path)?;
    parse_zone(&text, default_origin)
        .map(|zone| zone.with_source_digest(SourceDigest::of(text.as_bytes())))
        .map_err(|e| format!("{}: {e}", path.display()))
}

use crate::{parse_zone, Zone, ZoneStore};

pub trait ZoneSource: Send + Sync {
    /// Fails entirely if any zone fails: swapping in a half-filled store would make the other zones
    /// seem to vanish.
    fn load(&self) -> Result<ZoneStore, String>;

    /// Defaults to false: a source that cannot detect changes is safer not reread.
    fn changed_since(&self, _last: SystemTime) -> bool {
        false
    }

    fn describe(&self) -> String;
}

/// Zone files with explicit origins.
pub struct FileZoneSource {
    pub zones: Vec<(String, PathBuf)>,
}

impl FileZoneSource {
    pub fn new(zones: Vec<(String, PathBuf)>) -> Self {
        FileZoneSource { zones }
    }

    fn newest_mtime(&self) -> Option<SystemTime> {
        self.zones.iter().filter_map(|(_, p)| file_mtime(p)).max()
    }
}

impl ZoneSource for FileZoneSource {
    /// An empty origin is the root.
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for (origin, path) in &self.zones {
            let o = if origin.is_empty() {
                "."
            } else {
                origin.as_str()
            };
            store.add(load_zone_file(path, o)?);
        }
        Ok(store)
    }

    fn changed_since(&self, last: SystemTime) -> bool {
        self.newest_mtime().map(|m| m > last).unwrap_or(false)
    }

    fn describe(&self) -> String {
        format!("file({} zones)", self.zones.len())
    }
}

/// Reads every zone-extension file in a directory.
pub struct DirZoneSource {
    pub dir: PathBuf,
}

impl DirZoneSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        DirZoneSource { dir: dir.into() }
    }

    /// Sorted. Past the limit it errors instead of truncating: silently dropping files would start
    /// normally with some zones missing, and their names would get NXDOMAIN.
    fn zone_files_with_limit(&self, limit: usize) -> Result<Vec<PathBuf>, String> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|error| format!("{}: {error}", self.dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("{}: {error}", self.dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("zone") {
                continue;
            }
            if out.len() >= limit {
                return Err(format!(
                    "{}: more than {limit} zone files",
                    self.dir.display()
                ));
            }
            out.push(path);
        }
        out.sort();
        Ok(out)
    }

    fn zone_files(&self) -> Result<Vec<PathBuf>, String> {
        self.zone_files_with_limit(MAX_ZONE_FILES)
    }

    /// Includes the directory itself, to catch files added or removed.
    fn newest_mtime(&self) -> Result<Option<SystemTime>, String> {
        let mut newest = file_mtime(&self.dir);
        for p in self.zone_files()? {
            let m = file_mtime(&p);
            newest = match (newest, m) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        Ok(newest)
    }
}

impl ZoneSource for DirZoneSource {
    /// The file name without extension is the origin; a directive in the file can override it.
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for path in self.zone_files()? {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(".");
            store.add(load_zone_file(&path, stem)?);
        }
        Ok(store)
    }

    /// A failed scan counts as changed; false would never apply changes made while the directory
    /// was briefly unreadable.
    fn changed_since(&self, last: SystemTime) -> bool {
        match self.newest_mtime() {
            Ok(Some(modified)) => modified > last,
            Ok(None) => false,

            Err(_) => true,
        }
    }

    fn describe(&self) -> String {
        format!("dir({})", self.dir.display())
    }
}

/// Already parsed zones, for tests and control-plane edits.
pub struct MemoryZoneSource {
    pub zones: Vec<Zone>,
}

impl ZoneSource for MemoryZoneSource {
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for z in &self.zones {
            store.add(z.clone());
        }
        Ok(store)
    }

    fn describe(&self) -> String {
        format!("memory({} zones)", self.zones.len())
    }
}

fn file_mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal zone with SOA, NS, and glue.
    fn write_zone(dir: &Path, name: &str, origin: &str) -> PathBuf {
        let p = dir.join(format!("{name}.zone"));
        let text = format!(
            "$ORIGIN {origin}.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n"
        );
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        p
    }

    #[test]
    fn dir_source_loads_all_zones() {
        let dir = std::env::temp_dir().join(format!("onetdns-zones-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        write_zone(&dir, "a", "alpha.test");
        write_zone(&dir, "b", "beta.test");

        let src = DirZoneSource::new(&dir);
        let store = src.load().expect("로드");
        assert_eq!(store.zones().len(), 2, "디렉터리의 두 영역 로드");

        let z = store.zone_for(&crate::Name::from_str("ns1.alpha.test").unwrap());
        assert!(z.is_some(), "alpha.test 영역이 ns1.alpha.test를 포함");
        let resp = store.query(
            &crate::Name::from_str("ns1.alpha.test").unwrap(),
            crate::RecordType::A,
        );
        assert!(resp.is_some());
        assert_eq!(
            resp.unwrap().rcode,
            0,
            "ns1.alpha.test A 정상 응답($ORIGIN 존중)"
        );

        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        assert!(!src.changed_since(future));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_source_rejects_unreadable_or_truncated_zone_sets() {
        let missing =
            std::env::temp_dir().join(format!("onetdns-missing-zones-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let missing_source = DirZoneSource::new(&missing);
        assert!(missing_source.load().is_err());
        assert!(missing_source.changed_since(SystemTime::now()));

        let dir = std::env::temp_dir().join(format!("onetdns-zone-limit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        write_zone(&dir, "a", "alpha.test");
        write_zone(&dir, "b", "beta.test");
        write_zone(&dir, "c", "gamma.test");
        let source = DirZoneSource::new(&dir);
        assert!(source.zone_files_with_limit(2).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_source_with_explicit_origin() {
        let dir = std::env::temp_dir().join(format!("onetdns-fz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = write_zone(&dir, "z", "explicit.test");
        let src = FileZoneSource::new(vec![("explicit.test".to_string(), p)]);
        let store = src.load().expect("로드");
        assert_eq!(store.zones().len(), 1);
        assert!(store
            .zones()
            .iter()
            .any(|z| z.origin().to_ascii_lower() == "explicit.test"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn limited_reader_rechecks_actual_bytes() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-limited-read-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"12345").unwrap();

        assert_eq!(read_file_limited(&path, 5, "test").unwrap(), b"12345");
        assert!(read_file_limited(&path, 4, "test").is_err());

        let _ = std::fs::remove_file(path);
    }
}
