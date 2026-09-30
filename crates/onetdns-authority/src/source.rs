/*!
 * @brief zone 데이터를 어디서 가져올지 정하는 추상.
 *
 * @details 파일, 디렉터리, 메모리, 그리고 각종 DB 백엔드가 모두 같은 트레이트를 구현한다.
 *          어느 경로로 오든 최종적으로는 parse_zone을 거치므로, 파서 하나만 지키면 모든
 *          입력 경로가 함께 지켜진다.
 */

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
/** @brief zone 파일 하나의 크기 상한. */
const MAX_ZONE_FILE: u64 = 64 * 1024 * 1024;
/** @brief 디렉터리에서 읽어들일 zone 파일 수 상한. */
const MAX_ZONE_FILES: usize = 100_000;

/**
 * @brief 크기 상한을 걸어 파일을 읽는다.
 * @details 메타데이터의 크기를 먼저 보고, 실제로 읽은 바이트 수도 다시 확인한다. 검사와
 *          읽기 사이에 파일이 커질 수 있고, 특수 파일은 메타데이터가 실제 길이를
 *          말해 주지 않기 때문이다.
 */
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

/** @brief zone 파일을 텍스트로 읽는다. UTF-8이 아니면 거부한다. */
pub fn read_zone_text(path: &Path) -> Result<String, String> {
    let bytes = read_file_limited(path, MAX_ZONE_FILE, "zone")?;
    String::from_utf8(bytes).map_err(|_| format!("{}: not valid UTF-8", path.display()))
}

use crate::{parse_zone, Zone, ZoneStore};

/** @brief zone 공급자. 모든 백엔드가 이 세 가지만 제공하면 된다. */
pub trait ZoneSource: Send + Sync {
    /**
     * @brief zone 전부를 읽어 새 저장소를 만든다.
     * @return 하나라도 실패하면 전부 오류다. 절반만 담긴 저장소로 바꿔치면 나머지 zone이
     *         갑자기 사라진 것처럼 보인다.
     */
    fn load(&self) -> Result<ZoneStore, String>;

    /**
     * @brief 이 시각 이후로 원본이 바뀌었는지.
     * @note 기본은 거짓이다. 변경을 알 수 없는 공급자는 다시 읽지 않는 쪽이 안전하다.
     */
    fn changed_since(&self, _last: SystemTime) -> bool {
        false
    }

    /** @brief 로그와 진단에 쓸 짧은 설명. */
    fn describe(&self) -> String;
}

/** @brief origin을 명시해 zone 파일을 지정하는 공급자. */
pub struct FileZoneSource {
    /** @brief origin 이름과 파일 경로의 짝. */
    pub zones: Vec<(String, PathBuf)>,
}

impl FileZoneSource {
    /** @brief origin과 경로 목록으로 만든다. */
    pub fn new(zones: Vec<(String, PathBuf)>) -> Self {
        FileZoneSource { zones }
    }

    /** @brief 지정된 파일들 중 가장 최근 수정 시각. */
    fn newest_mtime(&self) -> Option<SystemTime> {
        self.zones.iter().filter_map(|(_, p)| file_mtime(p)).max()
    }
}

impl ZoneSource for FileZoneSource {
    /** @brief 설정에 적힌 origin으로 각 파일을 파싱한다. 빈 origin은 루트로 본다. */
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for (origin, path) in &self.zones {
            let text = read_zone_text(path)?;
            let o = if origin.is_empty() {
                "."
            } else {
                origin.as_str()
            };
            match parse_zone(&text, o) {
                Ok(z) => store.add(z),
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Ok(store)
    }

    /** @brief 파일 중 하나라도 더 새로우면 참. */
    fn changed_since(&self, last: SystemTime) -> bool {
        self.newest_mtime().map(|m| m > last).unwrap_or(false)
    }

    /** @brief 공급자 설명. */
    fn describe(&self) -> String {
        format!("file({} zones)", self.zones.len())
    }
}

/** @brief 디렉터리의 zone 확장자 파일을 모두 읽는 공급자. */
pub struct DirZoneSource {
    /** @brief 훑을 디렉터리. */
    pub dir: PathBuf,
}

impl DirZoneSource {
    /** @brief 디렉터리 경로로 만든다. */
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        DirZoneSource { dir: dir.into() }
    }

    /**
     * @brief zone 확장자 파일을 정렬해 모은다.
     * @details 개수가 상한을 넘으면 잘라 내지 않고 오류를 낸다. 조용히 자르면 일부 zone이
     *          빠진 채 정상 시작해, 있어야 할 이름이 NXDOMAIN으로 나간다.
     */
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

    /** @brief 기본 상한으로 zone 파일 목록을 얻는다. */
    fn zone_files(&self) -> Result<Vec<PathBuf>, String> {
        self.zone_files_with_limit(MAX_ZONE_FILES)
    }

    /** @brief 디렉터리 자신과 파일들 중 가장 최근 수정 시각. 파일 추가·삭제도 잡으려고 둘 다 본다. */
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
    /** @brief 파일 이름(확장자 제외)을 origin으로 삼는다. 파일 안의 지시자가 이를 덮을 수 있다. */
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for path in self.zone_files()? {
            let text = read_zone_text(&path)?;

            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(".");
            match parse_zone(&text, stem) {
                Ok(z) => store.add(z),
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
        Ok(store)
    }

    /**
     * @brief 디렉터리 안이 바뀌었는지.
     * @note 훑기에 실패하면 바뀐 것으로 본다. 거짓을 돌려주면 디렉터리가 잠깐 읽히지 않는
     *       동안의 변경이 영영 반영되지 않는다.
     */
    fn changed_since(&self, last: SystemTime) -> bool {
        match self.newest_mtime() {
            Ok(Some(modified)) => modified > last,
            Ok(None) => false,

            Err(_) => true,
        }
    }

    /** @brief 공급자 설명. */
    fn describe(&self) -> String {
        format!("dir({})", self.dir.display())
    }
}

/** @brief 이미 파싱된 zone을 그대로 쓰는 공급자. 테스트와 컨트롤 플레인 편집에 쓴다. */
pub struct MemoryZoneSource {
    /** @brief 그대로 담을 zone들. */
    pub zones: Vec<Zone>,
}

impl ZoneSource for MemoryZoneSource {
    /** @brief 가진 zone을 복제해 저장소를 만든다. */
    fn load(&self) -> Result<ZoneStore, String> {
        let mut store = ZoneStore::new();
        for z in &self.zones {
            store.add(z.clone());
        }
        Ok(store)
    }

    /** @brief 공급자 설명. */
    fn describe(&self) -> String {
        format!("memory({} zones)", self.zones.len())
    }
}

/** @brief 수정 시각. 읽을 수 없으면 None. */
fn file_mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

/** @brief 공급자별 로드와 변경 감지, 그리고 상한 초과 시 거부. */
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /** @brief SOA·NS·glue를 갖춘 최소 zone 파일을 만든다. */
    fn write_zone(dir: &Path, name: &str, origin: &str) -> PathBuf {
        let p = dir.join(format!("{name}.zone"));
        let text = format!(
            "$ORIGIN {origin}.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n"
        );
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(text.as_bytes()).unwrap();
        p
    }

    /** @brief 디렉터리의 zone이 모두 담기고 파일 안의 origin 지시자가 존중되는지. */
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

    /** @brief 읽을 수 없는 디렉터리는 변경으로 보고, 상한을 넘으면 자르지 않고 실패한다. */
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

    /** @brief 설정에 적은 origin이 그대로 쓰이는지. */
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

    /** @brief 메타데이터가 아니라 실제로 읽은 바이트 수로도 상한을 확인하는지. */
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
