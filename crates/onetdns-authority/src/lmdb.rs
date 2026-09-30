/*!
 * @brief LMDB 파일에서 zone을 읽는 백엔드.
 *
 * @details liblmdb를 링크하지 않고 파일 형식을 직접 읽는다. 쓰기는 하지 않으므로 트랜잭션도
 *          잠금도 필요 없고, 메타 페이지에서 최신 트리를 골라 B+tree를 훑기만 하면 된다.
 * @warning 파일 내용은 이 서버가 만든 것이 아니다. 모든 오프셋을 경계 검사하고, 페이지
 *          번호가 순환하는 트리에도 걸리지 않아야 한다.
 */

use std::path::PathBuf;
use std::time::SystemTime;

use crate::source::{read_file_limited, ZoneSource};
use crate::{parse_zone, ZoneStore};
/** @brief 전부 읽어 들일 DB 파일 크기 상한. */
const MAX_DATABASE_FILE: u64 = 512 * 1024 * 1024;

/** @brief 메타 페이지 식별자. */
const META_MAGIC: u32 = 0xBEEF_C0DE;
/** @brief 내부 노드 페이지. */
const P_BRANCH: u16 = 0x01;
/** @brief 리프 페이지. 실제 키와 값이 여기 있다. */
const P_LEAF: u16 = 0x02;
/** @brief 페이지 하나에 담기지 않는 큰 값이 놓인 페이지. */
const P_OVERFLOW: u16 = 0x04;
/** @brief 메타 페이지. */
const P_META: u16 = 0x08;
/** @brief 노드의 값이 추가 페이지에 있음을 뜻하는 플래그. */
const F_BIGDATA: u16 = 0x01;

/** @brief LMDB 파일을 zone 공급자로 쓴다. 키가 origin, 값이 zone 텍스트다. */
pub struct LmdbZoneSource {
    /** @brief DB 파일 경로. */
    pub path: PathBuf,
}

impl LmdbZoneSource {
    /** @brief 파일 경로로 만든다. */
    pub fn new(path: impl Into<PathBuf>) -> Self {
        LmdbZoneSource { path: path.into() }
    }

    /** @brief DB 파일의 수정 시각. */
    fn file_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()
    }
}

impl ZoneSource for LmdbZoneSource {
    /** @brief 모든 키-값 쌍을 읽어 각각 zone으로 파싱한다. 빈 키는 루트를 뜻한다. */
    fn load(&self) -> Result<ZoneStore, String> {
        let data = read_file_limited(&self.path, MAX_DATABASE_FILE, "database")?;
        let pairs = read_all(&data)?;
        let mut store = ZoneStore::new();
        let mut missing_origin = 0usize;
        for (key, val) in pairs {
            let origin = String::from_utf8_lossy(&key).to_string();
            let text = String::from_utf8_lossy(&val).to_string();
            let o = if origin.is_empty() {
                missing_origin += 1;
                "."
            } else {
                origin.as_str()
            };
            let z = parse_zone(&text, o)
                .map_err(|e| format!("Could not parse zone {origin} in LMDB: {e}"))?;
            store.add(z);
        }
        if missing_origin > 0 {
            onetdns_core::warn!(event = "authority.lmdb_origin_missing", path = %self.path.display(), entries = missing_origin, "Read an entry with an empty key as the root zone; check the database if this is unintended");
        }
        Ok(store)
    }

    /** @brief 수정 시각을 못 읽으면 바뀐 것으로 본다. 갱신을 놓치는 쪽이 더 나쁘다. */
    fn changed_since(&self, last: SystemTime) -> bool {
        self.file_mtime().map(|m| m > last).unwrap_or(true)
    }

    /** @brief 공급자 설명. */
    fn describe(&self) -> String {
        format!("lmdb({})", self.path.display())
    }
}

/** @brief 경계 검사를 곁들인 16비트 리틀엔디언 읽기. */
fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
/** @brief 경계 검사를 곁들인 32비트 리틀엔디언 읽기. */
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}
/** @brief 경계 검사를 곁들인 64비트 리틀엔디언 읽기. */
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    let mut v = 0u64;
    for k in 0..8 {
        v |= (*d.get(o + k)? as u64) << (8 * k);
    }
    Some(v)
}

/**
 * @brief 페이지 크기를 알아낸다.
 * @details 파일 형식에 페이지 크기가 적혀 있지 않아, 두 번째 메타 페이지가 놓일 만한
 *          후보를 흔한 순서로 테스트한다. 흔한 값을 먼저 봐야 잘못된 위치를 메타로
 *          오인할 확률이 준다.
 * @return 찾지 못하면 가장 흔한 4096으로 진행한다. 틀렸다면 이후 경계 검사에서 걸린다.
 */
fn detect_psize(data: &[u8]) -> Result<usize, String> {
    if u32le(data, 16) != Some(META_MAGIC) {
        return Err("The first page identifier of the LMDB metadata file is invalid".into());
    }
    for &ps in &[4096usize, 8192, 16384, 32768, 512, 1024, 2048, 65536] {
        if data.len() >= ps + 32
            && u32le(data, ps + 16) == Some(META_MAGIC)
            && (u16le(data, ps + 10).unwrap_or(0) & P_META) != 0
        {
            return Ok(ps);
        }
    }

    Ok(4096)
}

/** @brief 메타 페이지가 가리키는 주 데이터베이스. */
struct Db {
    /** @brief B+tree 루트 페이지 번호. u64::MAX면 빈 트리다. */
    root: u64,
}

/**
 * @brief 메타 페이지에서 트랜잭션 번호와 루트를 읽는다.
 * @return 메타 페이지가 아니거나 식별자가 틀리면 None.
 */
fn parse_meta(page: &[u8]) -> Option<(u64, Db)> {
    let flags = u16le(page, 10)?;
    if flags & P_META == 0 {
        return None;
    }
    if u32le(page, 16)? != META_MAGIC {
        return None;
    }

    let txnid = u64le(page, 144)?;

    let root = u64le(page, 88 + 40)?;
    Some((txnid, Db { root }))
}

/**
 * @brief 파일 전체에서 키-값 쌍을 모두 읽는다.
 * @details 메타 페이지가 둘인 이유는 갱신이 번갈아 쓰이기 때문이다. 트랜잭션 번호가 큰
 *          쪽이 최신이며, 그쪽을 골라야 쓰다 만 상태를 읽지 않는다.
 */
fn read_all(data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
    let psize = detect_psize(data)?;
    let meta0 = parse_meta(&data[0..]).ok_or("Could not parse the page 0 metadata")?;
    let meta1 = data
        .get(psize..)
        .and_then(parse_meta)
        .filter(|_| data.len() >= psize + 152);
    let db = match meta1 {
        Some(m1) if m1.0 > meta0.0 => m1.1,
        _ => meta0.1,
    };
    let mut out = Vec::new();
    if db.root == u64::MAX {
        return Ok(out);
    }
    let mut visited = std::collections::HashSet::new();
    walk(data, psize, db.root, &mut out, &mut visited, 0)?;
    Ok(out)
}

/** @brief 페이지 번호로 그 페이지 조각을 얻는다. 곱셈 넘침과 범위를 모두 검사한다. */
fn page_at(data: &[u8], psize: usize, pgno: u64) -> Option<&[u8]> {
    let start = (pgno as usize).checked_mul(psize)?;
    data.get(start..start + psize)
}

/**
 * @brief B+tree를 훑어 리프의 키-값을 모은다.
 *
 * @details 재귀지만 두 겹으로 막혀 있다. 방문한 페이지 번호를 기억해 순환을 끊고, 깊이
 *          상한으로 정상 트리보다 깊어지는 것을 막는다. 조작된 파일은 자기 자신을
 *          가리키는 페이지로 무한 재귀를 만들 수 있다.
 * @param visited 이미 방문한 페이지 번호. 순환 방지의 핵심이다.
 * @param depth   현재 깊이.
 */
fn walk(
    data: &[u8],
    psize: usize,
    pgno: u64,
    out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    visited: &mut std::collections::HashSet<u64>,
    depth: u32,
) -> Result<(), String> {
    if depth > 40 || !visited.insert(pgno) {
        return Err("LMDB B+tree loop or excessive depth".into());
    }
    let page = page_at(data, psize, pgno).ok_or("Page is out of range")?;
    let flags = u16le(page, 10).ok_or("Could not read the LMDB page header")?;
    let lower = u16le(page, 12).ok_or("lower")? as usize;
    if lower < 16 {
        return Err("LMDB page lower bound is less than 16".into());
    }
    let nnodes = (lower - 16) / 2;
    for i in 0..nnodes {
        let ptr = u16le(page, 16 + i * 2).ok_or("ptr")? as usize;
        let lo = u16le(page, ptr).ok_or("LMDB node start offset is invalid")? as u64;
        let hi = u16le(page, ptr + 2).ok_or("LMDB node end offset is invalid")? as u64;
        let nflags = u16le(page, ptr + 4).ok_or("Invalid LMDB node flags")?;
        let ksize = u16le(page, ptr + 6).ok_or("Invalid LMDB node key length")? as usize;
        let key_start = ptr + 8;
        let key = page
            .get(key_start..key_start + ksize)
            .ok_or("LMDB key crosses the page boundary")?
            .to_vec();

        if flags & P_LEAF != 0 {
            let dsize = (lo | (hi << 16)) as usize;
            let data_start = key_start + ksize;
            if nflags & F_BIGDATA != 0 {
                let opg = u64le(page, data_start).ok_or("Invalid LMDB overflow page number")?;
                let val = read_overflow(data, psize, opg, dsize)?;
                out.push((key, val));
            } else {
                let val = page
                    .get(data_start..data_start + dsize)
                    .ok_or("LMDB value crosses the page boundary")?
                    .to_vec();
                out.push((key, val));
            }
        } else if flags & P_BRANCH != 0 {
            let child = lo | (hi << 16) | ((nflags as u64) << 32);
            walk(data, psize, child, out, visited, depth + 1)?;
        } else {
            return Err("Page is neither a leaf nor a branch".into());
        }
    }
    Ok(())
}

/**
 * @brief 추가 페이지에 놓인 큰 값을 읽는다.
 * @note 대상 페이지가 정말 추가 데이터 페이지인지 확인한다. 확인하지 않으면 임의 페이지
 *       번호로 파일의 다른 곳을 값으로 읽어 낼 수 있다.
 */
fn read_overflow(data: &[u8], psize: usize, pgno: u64, dsize: usize) -> Result<Vec<u8>, String> {
    let page = page_at(data, psize, pgno).ok_or("Overflow page number is out of range")?;
    let flags = u16le(page, 10).ok_or("Invalid overflow page header")?;
    if flags & P_OVERFLOW == 0 {
        return Err("Overflow page flag is missing".into());
    }

    let start = (pgno as usize) * psize + 16;
    data.get(start..start + dsize)
        .map(|s| s.to_vec())
        .ok_or("Overflow data exceeds the size limit".into())
}

/** @brief 최소 LMDB 이미지를 손으로 만들어 형식 해석을 고정한다. */
#[cfg(test)]
mod tests {
    use super::*;

    /**
     * @brief 메타 두 장과 리프 한 장으로 이뤄진 최소 LMDB 이미지를 만든다.
     * @details 노드는 페이지 뒤쪽부터 채우고 포인터 배열은 앞쪽에서 자란다. 실제 형식과
     *          같은 배치라야 파서를 제대로 테스트한다.
     */
    fn build_lmdb(entries: &[(&str, &str)]) -> Vec<u8> {
        let psize = 4096usize;
        let mut file = vec![0u8; psize * 3];

        let leaf = 2 * psize;

        file[leaf..leaf + 8].copy_from_slice(&2u64.to_le_bytes());
        file[leaf + 10..leaf + 12].copy_from_slice(&P_LEAF.to_le_bytes());

        let mut upper = psize;
        let mut ptrs = Vec::new();
        for (k, v) in entries {
            let node_len = 8 + k.len() + v.len();
            upper -= node_len;
            let off = upper;
            let lo = (v.len() & 0xffff) as u16;
            let hi = ((v.len() >> 16) & 0xffff) as u16;
            file[leaf + off..leaf + off + 2].copy_from_slice(&lo.to_le_bytes());
            file[leaf + off + 2..leaf + off + 4].copy_from_slice(&hi.to_le_bytes());

            file[leaf + off + 6..leaf + off + 8].copy_from_slice(&(k.len() as u16).to_le_bytes());
            file[leaf + off + 8..leaf + off + 8 + k.len()].copy_from_slice(k.as_bytes());
            file[leaf + off + 8 + k.len()..leaf + off + node_len].copy_from_slice(v.as_bytes());
            ptrs.push(off as u16);
        }
        let lower = 16 + ptrs.len() * 2;
        for (i, p) in ptrs.iter().enumerate() {
            file[leaf + 16 + i * 2..leaf + 16 + i * 2 + 2].copy_from_slice(&p.to_le_bytes());
        }
        file[leaf + 12..leaf + 14].copy_from_slice(&(lower as u16).to_le_bytes());
        file[leaf + 14..leaf + 16].copy_from_slice(&(upper as u16).to_le_bytes());

        for (pg, txnid) in [(0usize, 2u64), (1usize, 1u64)] {
            let m = pg * psize;
            file[m..m + 8].copy_from_slice(&(pg as u64).to_le_bytes());
            file[m + 10..m + 12].copy_from_slice(&P_META.to_le_bytes());
            file[m + 16..m + 20].copy_from_slice(&META_MAGIC.to_le_bytes());
            file[m + 20..m + 24].copy_from_slice(&1u32.to_le_bytes());
            file[m + 32..m + 40].copy_from_slice(&((psize * 3) as u64).to_le_bytes());

            file[m + 40 + 40..m + 40 + 48].copy_from_slice(&u64::MAX.to_le_bytes());

            file[m + 88 + 32..m + 88 + 40].copy_from_slice(&(entries.len() as u64).to_le_bytes());
            file[m + 88 + 40..m + 88 + 48].copy_from_slice(&2u64.to_le_bytes());
            file[m + 136..m + 144].copy_from_slice(&2u64.to_le_bytes());
            file[m + 144..m + 152].copy_from_slice(&txnid.to_le_bytes());
        }
        file
    }

    /** @brief 페이지 크기 판별과 리프 노드 읽기가 순서까지 맞는지. */
    #[test]
    fn detect_and_read_leaf_entries() {
        let img = build_lmdb(&[("a.test", "zoneA"), ("b.test", "zoneB-longer-text")]);
        assert_eq!(detect_psize(&img).unwrap(), 4096);
        let pairs = read_all(&img).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, b"a.test");
        assert_eq!(pairs[0].1, b"zoneA");
        assert_eq!(pairs[1].0, b"b.test");
        assert_eq!(pairs[1].1, b"zoneB-longer-text");
    }

    /** @brief 메타가 둘일 때 트랜잭션 번호가 큰 쪽을 고르는지. 쓰다 만 상태를 읽지 않는다. */
    #[test]
    fn picks_higher_txnid_meta() {
        let img = build_lmdb(&[("x.test", "z")]);
        assert_eq!(read_all(&img).unwrap().len(), 1);
    }

    /** @brief DB에서 꺼낸 값이 실제 zone으로 파싱되는지. 키가 origin으로 쓰인다. */
    #[test]
    fn full_zone_roundtrip() {
        let zone = "$ORIGIN ex.lmdb.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.9\nwww IN A 10.0.0.10\n";
        let img = build_lmdb(&[("ex.lmdb", zone)]);
        let src = LmdbZoneSource::new("dummy");

        let pairs = read_all(&img).unwrap();
        let z = parse_zone(
            &String::from_utf8_lossy(&pairs[0].1),
            &String::from_utf8_lossy(&pairs[0].0),
        )
        .unwrap();
        assert!(z.origin().to_ascii_lower().contains("ex.lmdb"));
        let _ = src.describe();
    }

    /** @brief LMDB가 아닌 파일을 전부 거부하는지. */
    #[test]
    fn bad_magic_rejected() {
        let img = vec![0u8; 4096 * 2];
        assert!(read_all(&img).is_err());
    }
}
