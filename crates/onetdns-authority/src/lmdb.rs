//! Reads zones from an LMDB file by parsing the file format directly, without linking liblmdb.
//! Read-only, so no transactions or locks: pick the newest tree from the meta pages and walk the
//! B+tree.
//!
//! The file is not written by this server: every offset is bounds-checked, and trees whose page
//! numbers form a cycle must not trap the reader.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::source::{read_file_limited, ZoneSource};
use crate::{parse_zone, ZoneStore};
/// The file is read whole.
const MAX_DATABASE_FILE: u64 = 512 * 1024 * 1024;

const META_MAGIC: u32 = 0xBEEF_C0DE;
const P_BRANCH: u16 = 0x01;
const P_LEAF: u16 = 0x02;
const P_OVERFLOW: u16 = 0x04;
const P_META: u16 = 0x08;
/// The node's value is on overflow pages.
const F_BIGDATA: u16 = 0x01;

/// Keys are origins, values zone text.
pub struct LmdbZoneSource {
    pub path: PathBuf,
}

impl LmdbZoneSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        LmdbZoneSource { path: path.into() }
    }

    fn file_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()
    }
}

impl ZoneSource for LmdbZoneSource {
    /// An empty key is the root.
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

    /// An unreadable time counts as changed; missing an update is worse.
    fn changed_since(&self, last: SystemTime) -> bool {
        self.file_mtime().map(|m| m > last).unwrap_or(true)
    }

    fn describe(&self) -> String {
        format!("lmdb({})", self.path.display())
    }
}

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    let mut v = 0u64;
    for k in 0..8 {
        v |= (*d.get(o + k)? as u64) << (8 * k);
    }
    Some(v)
}

/// The file does not record its page size, so candidate offsets for the second meta page are tried,
/// most common first, which lowers the chance of mistaking another page for a meta page. Falls back
/// to 4096 when none matches; a wrong guess fails the bounds checks later.
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

struct Db {
    /// u64::MAX is an empty tree.
    root: u64,
}

/// Transaction ID and root; None unless it is a meta page with the right magic.
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

/// Two meta pages alternate between commits; the one with the larger transaction ID is newest, and
/// choosing it avoids a half-written state.
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

/// Checks multiplication overflow and range.
fn page_at(data: &[u8], psize: usize, pgno: u64) -> Option<&[u8]> {
    let start = (pgno as usize).checked_mul(psize)?;
    data.get(start..start + psize)
}

/// Recursive, with two guards: visited page numbers break cycles, and a depth cap stops trees
/// deeper than any real one. A crafted file can point a page at itself to recurse forever.
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

/// Checks the target really is an overflow page; otherwise an arbitrary page number would read
/// another part of the file as the value.
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

/// Builds minimal LMDB images by hand to pin format handling.
#[cfg(test)]
mod tests {
    use super::*;

    /// Two meta pages and one leaf. Nodes fill from the end of the page and the pointer array grows
    /// from the front, the real layout, so the parser is tested properly.
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

    /// Otherwise a half-written state would be read.
    #[test]
    fn picks_higher_txnid_meta() {
        let img = build_lmdb(&[("x.test", "z")]);
        assert_eq!(read_all(&img).unwrap().len(), 1);
    }

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

    #[test]
    fn bad_magic_rejected() {
        let img = vec![0u8; 4096 * 2];
        assert!(read_all(&img).is_err());
    }
}
