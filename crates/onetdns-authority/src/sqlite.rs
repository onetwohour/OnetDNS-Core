//! Reads zones from an SQLite file by parsing the file format directly, without linking libsqlite.
//! Read-only, so no locks or journal rollback: find the table's root page in the schema table and
//! walk the B-tree. A WAL file, when present, takes precedence with its latest commit.
//!
//! The file is not written by this server: every offset is bounds-checked, and trees whose pages
//! form a cycle must not trap the reader.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::source::{read_file_limited, ZoneSource};
use crate::{parse_zone, ZoneStore};
/// The file is read whole.
const MAX_DATABASE_FILE: u64 = 512 * 1024 * 1024;
/// A second guard beside cycle detection.
const MAX_BTREE_DEPTH: usize = 64;
const MAX_TABLE_ROWS: usize = 1_000_000;
const MAX_OVERFLOW_PAGES: usize = 131_072;

/// Reads the origin and zone columns.
pub struct SqliteZoneSource {
    pub path: PathBuf,
    pub table: String,
    /// Whether the last check failed to read the file time, so only state changes get logged.
    unreadable: std::sync::atomic::AtomicBool,
}

impl SqliteZoneSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_table(path, "zones")
    }

    pub fn with_table(path: impl Into<PathBuf>, table: impl Into<String>) -> Self {
        SqliteZoneSource {
            path: path.into(),
            table: table.into(),
            unreadable: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl SqliteZoneSource {
    /// Follows SQLite's -wal naming.
    fn wal_path(&self) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push("-wal");
        PathBuf::from(s)
    }
}

impl ZoneSource for SqliteZoneSource {
    /// A missing WAL is normal, but one that exists and cannot be read is an error: reading only
    /// the main file would serve without changes already committed.
    fn load(&self) -> Result<ZoneStore, String> {
        let data = read_file_limited(&self.path, MAX_DATABASE_FILE, "database")?;

        let wal_path = self.wal_path();
        let wal = match std::fs::metadata(&wal_path) {
            Ok(_) => Some(read_file_limited(
                &wal_path,
                MAX_DATABASE_FILE,
                "SQLite WAL",
            )?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("{}: {error}", wal_path.display())),
        };
        let rows = read_table_wal(&data, wal.as_deref(), &self.table)?;
        let mut store = ZoneStore::new();
        for (origin, text) in rows {
            let z = parse_zone(&text, &origin)
                .map_err(|e| format!("{}[{}]: {e}", self.path.display(), origin))?;
            store.add(z);
        }
        Ok(store)
    }

    /// Checks whichever of the main file and WAL is newer; often only the WAL changes. An
    /// unreadable main file time counts as changed: false would never even try a reload, the zone
    /// would silently freeze, and load() would never report the real cause.
    fn changed_since(&self, last: SystemTime) -> bool {
        use std::sync::atomic::Ordering;
        let mt = |p: &std::path::Path| std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
        let Some(main) = mt(&self.path) else {
            if !self.unreadable.swap(true, Ordering::Relaxed) {
                onetdns_core::warn!(event = "authority.sqlite_unreadable", path = %self.path.display(), "Could not read the SQLite file's modification time; treating it as changed and rereading");
            }
            return true;
        };
        if self.unreadable.swap(false, Ordering::Relaxed) {
            onetdns_core::info!(event = "authority.sqlite_readable", path = %self.path.display(), "SQLite file is readable again");
        }
        let newest = mt(&self.wal_path()).map_or(main, |wal| main.max(wal));
        newest > last
    }

    fn describe(&self) -> String {
        format!("sqlite({}, table={})", self.path.display(), self.table)
    }
}

/// SQLite's five storage classes.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Value {
    fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
    fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
}

struct Db<'a> {
    data: &'a [u8],
    page_size: usize,

    /// Smaller than page_size by the reserved tail.
    usable: usize,

    /// Pages recovered from the WAL; they win over the main file.
    wal: std::collections::HashMap<u32, Vec<u8>>,
}

/// Without a WAL.
#[cfg(test)]
fn read_table(data: &[u8], table: &str) -> Result<Vec<(String, String)>, String> {
    read_table_wal(data, None, table)
}

/// Column order differs between files, so the CREATE statement is parsed to find origin and zone;
/// fixed positions would swap the values in databases made by other tools.
fn read_table_wal(
    data: &[u8],
    wal: Option<&[u8]>,
    table: &str,
) -> Result<Vec<(String, String)>, String> {
    let db = Db::open(data, wal)?;

    let mut master_rows = Vec::new();
    db.walk_table(1, &mut master_rows)?;
    let mut rootpage = None;
    let mut create_sql = String::new();
    for row in &master_rows {
        let ty = row.first().and_then(Value::as_text).unwrap_or("");
        let name = row.get(1).and_then(Value::as_text).unwrap_or("");
        if ty == "table" && name.eq_ignore_ascii_case(table) {
            rootpage = row.get(3).and_then(Value::as_int);
            create_sql = row
                .get(4)
                .and_then(Value::as_text)
                .unwrap_or("")
                .to_string();
        }
    }
    let rootpage = rootpage.ok_or_else(|| format!("Table not found: {table}"))?;
    let rootpage = u32::try_from(rootpage)
        .ok()
        .filter(|page| *page > 0)
        .ok_or_else(|| format!("Invalid root page for {table}: {rootpage}"))?;

    let cols = parse_columns(&create_sql);
    let oi = cols
        .iter()
        .position(|c| c.eq_ignore_ascii_case("origin"))
        .ok_or_else(|| format!("{table} has no origin column (schema: {create_sql})"))?;
    let zi = cols
        .iter()
        .position(|c| c.eq_ignore_ascii_case("zone"))
        .ok_or_else(|| format!("{table} has no zone column (schema: {create_sql})"))?;

    let mut rows = Vec::new();
    db.walk_table(rootpage, &mut rows)?;
    let mut out = Vec::new();
    for row in rows {
        let origin = row.get(oi).and_then(Value::as_text);
        let zone = row.get(zi).and_then(Value::as_text);
        if let (Some(o), Some(z)) = (origin, zone) {
            out.push((o.to_string(), z.to_string()));
        }
    }
    Ok(out)
}

/// Accepts names quoted with double quotes, single quotes, backticks, or brackets, and skips
/// constraint entries. Empty when the statement does not have that shape.
fn parse_columns(sql: &str) -> Vec<String> {
    let Some(start) = sql.find('(') else {
        return Vec::new();
    };
    let Some(end) = sql.rfind(')') else {
        return Vec::new();
    };

    if end < start + 1 {
        return Vec::new();
    }
    let inner = &sql[start + 1..end];
    inner
        .split(',')
        .filter_map(|part| {
            let t = part.trim();
            if t.is_empty() {
                return None;
            }

            let first = t.chars().next()?;
            let name = match first {
                '"' | '\'' | '`' => t[1..].split(first).next()?.to_string(),
                '[' => t[1..].split(']').next()?.to_string(),
                _ => t.split_whitespace().next()?.to_string(),
            };

            let upper = name.to_ascii_uppercase();
            if ["PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT"].contains(&upper.as_str()) {
                return None;
            }
            Some(name)
        })
        .collect()
}

impl<'a> Db<'a> {
    /// Page size must be a power of two in range; reserved bytes larger than the page would make
    /// the usable space negative. Only UTF-8 encoding is accepted: reading another encoding as
    /// UTF-8 would silently corrupt zone names.
    fn open(data: &'a [u8], wal: Option<&[u8]>) -> Result<Db<'a>, String> {
        if data.len() < 100 || &data[..16] != b"SQLite format 3\0" {
            return Err("Invalid SQLite database header".to_string());
        }
        let raw = u16::from_be_bytes([data[16], data[17]]);
        let page_size = if raw == 1 { 65536 } else { raw as usize };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(format!("SQLite page size is out of range: {raw}"));
        }
        let reserved = data[20] as usize;
        if reserved >= page_size || data.len() < page_size {
            return Err(format!(
                "Invalid usable space in SQLite pages: page_size={page_size}, reserved={reserved}"
            ));
        }

        let enc = u32::from_be_bytes([data[56], data[57], data[58], data[59]]);
        if enc != 1 && enc != 0 {
            return Err(format!("This SQLite database's text encoding is not supported; use a UTF-8 database: {enc}"));
        }

        let wal_map = match wal {
            Some(w) if !w.is_empty() => parse_wal(w, page_size)?,
            _ => std::collections::HashMap::new(),
        };
        Ok(Db {
            data,
            page_size,
            usable: page_size - reserved,
            wal: wal_map,
        })
    }

    /// The WAL copy wins. Pages are numbered from 1; 0 is rejected explicitly.
    fn page(&self, n: u32) -> Result<&[u8], String> {
        if n == 0 {
            return Err("SQLite page number 0 is not allowed".to_string());
        }
        if let Some(p) = self.wal.get(&n) {
            if p.len() != self.page_size {
                return Err(format!("WAL page {n} size mismatch"));
            }
            return Ok(p.as_slice());
        }
        let index = usize::try_from(n - 1)
            .map_err(|_| format!("Could not convert SQLite page {n} to an internal index"))?;
        let start = index
            .checked_mul(self.page_size)
            .ok_or_else(|| format!("Page {n} offset calculation overflowed"))?;
        let end = start
            .checked_add(self.page_size)
            .ok_or_else(|| format!("Page {n} end offset calculation overflowed"))?;
        self.data
            .get(start..end)
            .ok_or_else(|| format!("The SQLite file has no page {n}"))
    }

    fn walk_table(&self, page_no: u32, out: &mut Vec<Vec<Value>>) -> Result<(), String> {
        let mut visited = std::collections::HashSet::new();
        self.walk_table_inner(page_no, out, &mut visited, 0)
    }

    /// Remembers visited pages to break cycles and caps depth beyond any real tree: a crafted file
    /// can list a page as its own child to recurse forever.
    fn walk_table_inner(
        &self,
        page_no: u32,
        out: &mut Vec<Vec<Value>>,
        visited: &mut std::collections::HashSet<u32>,
        depth: usize,
    ) -> Result<(), String> {
        if depth > MAX_BTREE_DEPTH {
            return Err(format!(
                "SQLite B-tree nesting exceeds the limit ({MAX_BTREE_DEPTH})"
            ));
        }
        if !visited.insert(page_no) {
            return Err(format!(
                "SQLite B-tree refers to the same page more than once: {page_no}"
            ));
        }
        let result = (|| {
            let page = self.page(page_no)?;
            let usable = self.usable.min(page.len());
            let hdr = if page_no == 1 { 100 } else { 0 };
            let base_header = page
                .get(hdr..hdr + 8)
                .ok_or_else(|| format!("SQLite page {page_no} has no B-tree header"))?;
            let ptype = base_header[0];
            let ncells = u16::from_be_bytes([base_header[3], base_header[4]]) as usize;
            let header_len = match ptype {
                0x0D => 8,
                0x05 => 12,
                t => {
                    return Err(format!(
                        "SQLite page {page_no} is not a table B-tree page: type={t:#x}"
                    ))
                }
            };
            let cells_at = hdr.checked_add(header_len).ok_or_else(|| {
                format!("Could not compute the start of the cell pointer array on SQLite page {page_no}")
            })?;
            let ptr_bytes = ncells.checked_mul(2).ok_or_else(|| {
                format!(
                    "Could not compute the size of the cell pointer array on SQLite page {page_no}"
                )
            })?;
            let ptr_end = cells_at.checked_add(ptr_bytes).ok_or_else(|| {
                format!(
                    "Could not compute the end of the cell pointer array on SQLite page {page_no}"
                )
            })?;
            if ptr_end > usable {
                return Err(format!(
                    "The cell pointer array on SQLite page {page_no} is outside the page: cells={ncells}, usable_bytes={usable}"
                ));
            }

            for i in 0..ncells {
                let at = cells_at + i * 2;
                let pointer = page
                    .get(at..at + 2)
                    .ok_or_else(|| format!("SQLite page {page_no} has no pointer for cell {i}"))?;
                let off = u16::from_be_bytes([pointer[0], pointer[1]]) as usize;
                if off < ptr_end || off >= usable {
                    return Err(format!(
                        "Invalid offset of cell {i} on SQLite page {page_no}: offset={off}, valid_range={ptr_end}..{usable}"
                    ));
                }
                match ptype {
                    0x0D => {
                        if out.len() >= MAX_TABLE_ROWS {
                            return Err(format!(
                                "SQLite table has more rows than allowed ({MAX_TABLE_ROWS})"
                            ));
                        }
                        let payload = self.leaf_cell_payload(page, off)?;
                        out.push(parse_record(&payload)?);
                    }
                    0x05 => {
                        let child_bytes = page.get(off..off + 4).ok_or_else(|| {
                            format!("SQLite interior page {page_no} has no child page pointer")
                        })?;
                        let child = u32::from_be_bytes(child_bytes.try_into().map_err(|_| {
                            format!("Malformed child page pointer on SQLite page {page_no}")
                        })?);
                        self.walk_table_inner(child, out, visited, depth + 1)?;
                    }
                    _ => unreachable!(),
                }
            }

            if ptype == 0x05 {
                let right_bytes = page.get(hdr + 8..hdr + 12).ok_or_else(|| {
                    format!("SQLite interior page {page_no} has no rightmost child pointer")
                })?;
                let right = u32::from_be_bytes(right_bytes.try_into().map_err(|_| {
                    format!("Malformed rightmost child pointer on SQLite page {page_no}")
                })?);
                self.walk_table_inner(right, out, visited, depth + 1)?;
            }
            Ok(())
        })();

        result
    }

    /// Follows the overflow chain for long payloads. How much stays in the cell is SQLite's own
    /// formula; following it exactly is what lets files from other implementations read. Every
    /// intermediate step checks for overflow.
    ///
    /// Overflow chains can cycle, so visited pages are remembered and their count is capped. A
    /// collected length that differs from the recorded one is an error; passing a short payload on
    /// would make the record parser read garbage.
    fn leaf_cell_payload(&self, page: &[u8], off: usize) -> Result<Vec<u8>, String> {
        let mut pos = off;
        let payload_len = usize::try_from(read_varint(page, &mut pos)?)
            .map_err(|_| "SQLite cell payload length is too large for this system".to_string())?;
        let _rowid = read_varint(page, &mut pos)?;

        let u = self.usable.min(page.len());
        if u < 480 || off >= u {
            return Err("SQLite cell starts outside the usable area of the page".to_string());
        }
        let x = u
            .checked_sub(35)
            .ok_or("SQLite usable page area is too small for data")?;
        if payload_len <= x {
            let end = pos
                .checked_add(payload_len)
                .ok_or_else(|| "Cell payload end offset calculation overflowed".to_string())?;
            return page
                .get(pos..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| "SQLite cell data is outside the page".to_string());
        }

        let m = u
            .checked_sub(12)
            .and_then(|value| value.checked_mul(32))
            .map(|value| value / 255)
            .and_then(|value| value.checked_sub(23))
            .ok_or("Could not compute the local payload size of a SQLite cell")?;
        let remainder = u
            .checked_sub(4)
            .ok_or("SQLite page size is too small to compute overflow data")?;
        let k = if payload_len >= m {
            m.checked_add((payload_len - m) % remainder)
                .ok_or("Could not compute the local payload length of a SQLite cell")?
        } else {
            payload_len
        };
        let inline = if k <= x { k } else { m };
        let inline_end = pos
            .checked_add(inline)
            .ok_or_else(|| "Cell inline end offset calculation overflowed".to_string())?;
        let mut out = page
            .get(pos..inline_end)
            .map(|s| s.to_vec())
            .ok_or_else(|| "SQLite local cell data is outside the page".to_string())?;
        let op = pos
            .checked_add(inline)
            .ok_or("Could not compute the location of the SQLite overflow page pointer")?;
        let next_bytes = page
            .get(
                op..op
                    .checked_add(4)
                    .ok_or("Could not compute the end of the SQLite overflow page pointer")?,
            )
            .ok_or("The SQLite overflow page pointer is missing")?;
        let mut next = u32::from_be_bytes(
            next_bytes
                .try_into()
                .map_err(|_| "Malformed SQLite overflow page pointer")?,
        );
        let mut overflow_seen = std::collections::HashSet::new();
        while next != 0 && out.len() < payload_len {
            if overflow_seen.len() >= MAX_OVERFLOW_PAGES || !overflow_seen.insert(next) {
                return Err("SQLite overflow pages repeat or exceed the allowed count".to_string());
            }
            let opage = self.page(next)?;
            let header = opage
                .get(..4)
                .ok_or("SQLite overflow page has no next page pointer")?;
            next = u32::from_be_bytes(
                header
                    .try_into()
                    .map_err(|_| "Malformed next page pointer on a SQLite overflow page")?,
            );
            let want = (payload_len - out.len()).min(u - 4);
            let chunk = opage
                .get(
                    4..4usize
                        .checked_add(want)
                        .ok_or("Could not compute the end of SQLite overflow data")?,
                )
                .ok_or("SQLite overflow data is outside the page")?;
            out.extend_from_slice(chunk);
        }
        if out.len() != payload_len {
            return Err(
                "SQLite overflow pages hold less data than the recorded length".to_string(),
            );
        }
        Ok(out)
    }
}

/// Picks the committed pages from the WAL. Frame checksums form a chain, so the first mismatch
/// stops it, as does a frame with a different salt, which belongs to an earlier generation. Only
/// frames up to the last commit mark count; later ones are uncommitted.
///
/// A malformed WAL or one with a different page size yields an empty map: not an error, but a
/// decision to ignore the WAL and use the main file.
fn parse_wal(
    wal: &[u8],
    db_page_size: usize,
) -> Result<std::collections::HashMap<u32, Vec<u8>>, String> {
    use std::collections::HashMap;
    if wal.len() < 32 {
        return Ok(HashMap::new());
    }
    let magic = u32::from_be_bytes([wal[0], wal[1], wal[2], wal[3]]);

    let big_endian = match magic {
        0x377f_0682 => false,
        0x377f_0683 => true,
        _ => return Ok(HashMap::new()),
    };
    let page_size = u32::from_be_bytes([wal[8], wal[9], wal[10], wal[11]]) as usize;
    if page_size != db_page_size {
        return Ok(HashMap::new());
    }
    let salt = &wal[16..24];

    let (mut s0, mut s1) = wal_checksum(0, 0, &wal[0..24], big_endian);
    let hdr_c1 = u32::from_be_bytes([wal[24], wal[25], wal[26], wal[27]]);
    let hdr_c2 = u32::from_be_bytes([wal[28], wal[29], wal[30], wal[31]]);
    if (s0, s1) != (hdr_c1, hdr_c2) {
        return Ok(HashMap::new());
    }

    let frame_size = 24 + page_size;
    let mut frames: Vec<(u32, usize)> = Vec::new();
    let mut commit_upto: Option<usize> = None;
    let mut pos = 32;
    while pos + frame_size <= wal.len() {
        let fh = &wal[pos..pos + 24];
        let page_no = u32::from_be_bytes([fh[0], fh[1], fh[2], fh[3]]);
        let commit = u32::from_be_bytes([fh[4], fh[5], fh[6], fh[7]]);

        if &fh[8..16] != salt {
            break;
        }
        let page_data = &wal[pos + 24..pos + frame_size];
        let (n0, n1) = wal_checksum(s0, s1, &fh[0..8], big_endian);
        let (n0, n1) = wal_checksum(n0, n1, page_data, big_endian);
        let fc1 = u32::from_be_bytes([fh[16], fh[17], fh[18], fh[19]]);
        let fc2 = u32::from_be_bytes([fh[20], fh[21], fh[22], fh[23]]);
        if (n0, n1) != (fc1, fc2) {
            break;
        }
        s0 = n0;
        s1 = n1;
        frames.push((page_no, pos + 24));
        if commit != 0 {
            commit_upto = Some(frames.len() - 1);
        }
        pos += frame_size;
    }

    let mut map = HashMap::new();
    if let Some(upto) = commit_upto {
        for &(page_no, off) in &frames[..=upto] {
            map.insert(page_no, wal[off..off + page_size].to_vec());
        }
    }
    Ok(map)
}

/// Continues from the previous frame's value. `big_endian` comes from the header magic and depends
/// on the machine that wrote the file.
fn wal_checksum(mut s0: u32, mut s1: u32, data: &[u8], big_endian: bool) -> (u32, u32) {
    let rd = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    let mut i = 0;
    while i + 8 <= data.len() {
        let w0 = rd(&data[i..i + 4]);
        let w1 = rd(&data[i + 4..i + 8]);
        s0 = s0.wrapping_add(w0).wrapping_add(s1);
        s1 = s1.wrapping_add(w1).wrapping_add(s0);
        i += 8;
    }
    (s0, s1)
}

/// The header lists each column's serial type, then the body follows. Reading past the header while
/// reading serial types is rejected; otherwise body bytes would be read as types.
fn parse_record(payload: &[u8]) -> Result<Vec<Value>, String> {
    let mut pos = 0usize;
    let hdr_len = usize::try_from(read_varint(payload, &mut pos)?)
        .map_err(|_| "SQLite record header length is too large for this system".to_string())?;
    if hdr_len < pos || hdr_len > payload.len() {
        return Err(format!(
            "Invalid SQLite record header range: header_bytes={hdr_len}, parsed_bytes={pos}, record_bytes={}",
            payload.len()
        ));
    }
    let mut serials = Vec::new();
    while pos < hdr_len {
        serials.push(read_varint(payload, &mut pos)?);
        if pos > hdr_len {
            return Err("SQLite record serial types extend past the header".to_string());
        }
    }
    let mut body = hdr_len;
    let mut out = Vec::with_capacity(serials.len());
    for st in serials {
        let (v, n) = decode_value(payload, body, st)?;
        out.push(v);
        body = body.checked_add(n).ok_or_else(|| {
            "Could not compute where to read the next value in the SQLite record body".to_string()
        })?;
    }
    Ok(out)
}

/// Integers take 1, 2, 3, 4, 6, or 8 bytes, sign-extended from the top bit. Types 8 and 9 take no
/// body and mean 0 and 1. Odd types from 13 are text and even ones from 12 are blobs, with the
/// length in the type number. Returns the value and the body bytes consumed.
fn decode_value(buf: &[u8], at: usize, serial: u64) -> Result<(Value, usize), String> {
    let slice = |len: usize, label: &str| -> Result<&[u8], String> {
        let end = at
            .checked_add(len)
            .ok_or_else(|| format!("Could not compute the end of the {label} data"))?;
        buf.get(at..end)
            .ok_or_else(|| format!("{label} data extends past the record"))
    };
    let int_be = |n: usize| -> Result<i64, String> {
        let s = slice(n, "record integer body")?;
        let mut v: i64 = if s.first().is_some_and(|byte| byte & 0x80 != 0) {
            -1
        } else {
            0
        };
        for &b in s {
            v = (v << 8) | b as i64;
        }
        Ok(v)
    };
    Ok(match serial {
        0 => (Value::Null, 0),
        1 => (Value::Int(int_be(1)?), 1),
        2 => (Value::Int(int_be(2)?), 2),
        3 => (Value::Int(int_be(3)?), 3),
        4 => (Value::Int(int_be(4)?), 4),
        5 => (Value::Int(int_be(6)?), 6),
        6 => (Value::Int(int_be(8)?), 8),
        7 => {
            let s = slice(8, "real")?;
            let bytes: [u8; 8] = s
                .try_into()
                .map_err(|_| "Real value byte length mismatch".to_string())?;
            (Value::Real(f64::from_be_bytes(bytes)), 8)
        }
        8 => (Value::Int(0), 0),
        9 => (Value::Int(1), 0),
        n if n >= 13 && n % 2 == 1 => {
            let len = usize::try_from((n - 13) / 2)
                .map_err(|_| "SQLite text length is too large for this system".to_string())?;
            let s = slice(len, "text")?;
            (
                Value::Text(
                    String::from_utf8(s.to_vec()).map_err(|_| "SQLite text is not valid UTF-8")?,
                ),
                len,
            )
        }
        n if n >= 12 => {
            let len = usize::try_from((n - 12) / 2)
                .map_err(|_| "SQLite blob length is too large for this system".to_string())?;
            let s = slice(len, "blob")?;
            (Value::Blob(s.to_vec()), len)
        }
        n => return Err(format!("Unsupported SQLite serial type: {n}")),
    })
}

/// Up to 9 bytes: 7 bits from each of the first 8 and all 8 bits of the ninth. Advances `pos` past
/// what it read.
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut v: u64 = 0;
    for i in 0..9 {
        let b = *buf.get(*pos).ok_or("SQLite varint data ended early")?;
        *pos += 1;
        if i == 8 {
            v = (v << 8) | b as u64;
            return Ok(v);
        }
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Ok(v)
}

/// Builds minimal SQLite images by hand to pin format handling and rejection. Files from real
/// sqlite3 would test the parser only narrowly; hand-built ones can carry crafted shapes such as
/// out-of-bounds pointers and cycles.
#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 512;

    /// Counterpart of read_varint.
    fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        let mut bytes = Vec::new();
        loop {
            bytes.push((v & 0x7f) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        bytes.reverse();
        let n = bytes.len();
        for (i, b) in bytes.iter().enumerate() {
            out.push(if i + 1 < n { b | 0x80 } else { *b });
        }
    }

    /// The header length field counts itself, so it is recomputed when its width grows.
    fn record(values: &[Value]) -> Vec<u8> {
        let mut serials = Vec::new();
        let mut body = Vec::new();
        for v in values {
            match v {
                Value::Text(s) => {
                    serials.push(13 + 2 * s.len() as u64);
                    body.extend_from_slice(s.as_bytes());
                }
                Value::Int(i) if (0..=127).contains(i) => {
                    serials.push(1);
                    body.push(*i as u8);
                }
                _ => panic!("테스트용 기록기가 지원하지 않는 값"),
            }
        }

        let mut hdr = Vec::new();
        for s in &serials {
            put_varint(&mut hdr, *s);
        }
        let mut hl = hdr.len() + 1;
        let mut hl_v = Vec::new();
        put_varint(&mut hl_v, hl as u64);
        if hl_v.len() > 1 {
            hl = hdr.len() + hl_v.len();
            hl_v.clear();
            put_varint(&mut hl_v, hl as u64);
        }
        let mut out = hl_v;
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&body);
        out
    }

    /// Spills long payloads into an overflow chain. Cells grow from the end of the page and the
    /// pointer array from the front, matching what the parser expects. `first_page` starts after
    /// the 100-byte file header.
    fn leaf_page(
        records: &[(u64, Vec<u8>)],
        next_overflow_page: &mut u32,
        overflows: &mut Vec<Vec<u8>>,
        first_page: bool,
    ) -> Vec<u8> {
        let hdr_at = if first_page { 100 } else { 0 };
        let mut page = vec![0u8; PAGE];
        let u = PAGE;
        let x = u - 35;
        let mut cells: Vec<Vec<u8>> = Vec::new();
        for (rowid, payload) in records {
            let mut cell = Vec::new();
            put_varint(&mut cell, payload.len() as u64);
            put_varint(&mut cell, *rowid);
            if payload.len() <= x {
                cell.extend_from_slice(payload);
            } else {
                let m = (u - 12) * 32 / 255 - 23;
                let k = m + (payload.len() - m) % (u - 4);
                let inline = if k <= x { k } else { m };
                cell.extend_from_slice(&payload[..inline]);

                let mut rest = &payload[inline..];
                cell.extend_from_slice(&next_overflow_page.to_be_bytes());
                while !rest.is_empty() {
                    let take = rest.len().min(u - 4);
                    let mut op = vec![0u8; PAGE];
                    let next = if take < rest.len() {
                        *next_overflow_page + 1
                    } else {
                        0
                    };
                    op[..4].copy_from_slice(&next.to_be_bytes());
                    op[4..4 + take].copy_from_slice(&rest[..take]);
                    overflows.push(op);
                    *next_overflow_page += 1;
                    rest = &rest[take..];
                }
            }
            cells.push(cell);
        }

        let mut content_end = PAGE;
        let mut ptrs = Vec::new();
        for cell in &cells {
            content_end -= cell.len();
            page[content_end..content_end + cell.len()].copy_from_slice(cell);
            ptrs.push(content_end as u16);
        }
        page[hdr_at] = 0x0D;
        page[hdr_at + 3..hdr_at + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        page[hdr_at + 5..hdr_at + 7].copy_from_slice(&(content_end as u16).to_be_bytes());
        let cells_at = hdr_at + 8;
        for (i, p) in ptrs.iter().enumerate() {
            page[cells_at + i * 2..cells_at + i * 2 + 2].copy_from_slice(&p.to_be_bytes());
        }
        page
    }

    /// The last child goes in the header, not a cell.
    fn interior_page(children: &[(u32, u64)], rightmost: u32) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        let mut content_end = PAGE;
        let mut ptrs = Vec::new();
        for (child, key) in children {
            let mut cell = Vec::new();
            cell.extend_from_slice(&child.to_be_bytes());
            put_varint(&mut cell, *key);
            content_end -= cell.len();
            page[content_end..content_end + cell.len()].copy_from_slice(&cell);
            ptrs.push(content_end as u16);
        }
        page[0] = 0x05;
        page[3..5].copy_from_slice(&(children.len() as u16).to_be_bytes());
        page[5..7].copy_from_slice(&(content_end as u16).to_be_bytes());
        page[8..12].copy_from_slice(&rightmost.to_be_bytes());
        let cells_at = 12;
        for (i, p) in ptrs.iter().enumerate() {
            page[cells_at + i * 2..cells_at + i * 2 + 2].copy_from_slice(&p.to_be_bytes());
        }
        page
    }

    /// A schema table row; the parser finds the root page and column names here.
    fn master_record(table: &str, rootpage: i64, sql: &str) -> Vec<u8> {
        record(&[
            Value::Text("table".into()),
            Value::Text(table.into()),
            Value::Text(table.into()),
            Value::Int(rootpage),
            Value::Text(sql.into()),
        ])
    }

    fn file_header(npages: u32) -> Vec<u8> {
        let mut h = vec![0u8; 100];
        h[..16].copy_from_slice(b"SQLite format 3\0");
        h[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
        h[18] = 1;
        h[19] = 1;
        h[21] = 64;
        h[22] = 32;
        h[23] = 32;
        h[28..32].copy_from_slice(&npages.to_be_bytes());
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        h
    }

    /// Length grows with the host count, to push values onto overflow pages.
    fn zone_text(origin: &str, extra_hosts: usize) -> String {
        let mut t = format!(
            "$ORIGIN {origin}.\n$TTL 300\n@ IN SOA ns1 admin 7 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n"
        );
        for i in 0..extra_hosts {
            t.push_str(&format!("host-{i:04} IN A 10.9.{}.{}\n", i / 256, i % 256));
        }
        t
    }

    fn build_db(pages: Vec<Vec<u8>>) -> Vec<u8> {
        let mut data = Vec::with_capacity(pages.len() * PAGE);
        for (i, mut p) in pages.into_iter().enumerate() {
            assert_eq!(p.len(), PAGE);
            if i == 0 {
                p[..100].copy_from_slice(&file_header(1));
            }
            data.extend_from_slice(&p);
        }
        data
    }

    #[test]
    fn reads_simple_zones_table() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut ovf_pages = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut ovf_pages,
            true,
        );
        let za = zone_text("alpha.db", 0);
        let zb = zone_text("beta.db", 0);
        let p2 = leaf_page(
            &[
                (
                    1,
                    record(&[Value::Text("alpha.db".into()), Value::Text(za)]),
                ),
                (2, record(&[Value::Text("beta.db".into()), Value::Text(zb)])),
            ],
            &mut ovf,
            &mut ovf_pages,
            false,
        );
        assert!(ovf_pages.is_empty(), "소형 행은 인라인");
        let data = build_db(vec![p1, p2]);

        let rows = read_table(&data, "zones").expect("읽기");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "alpha.db");

        let tmp = std::env::temp_dir().join(format!("onetdns-sql-{}.db", std::process::id()));
        std::fs::write(&tmp, &data).unwrap();
        let src = SqliteZoneSource::new(&tmp);
        let store = src.load().expect("로드");
        assert_eq!(store.zones().len(), 2);
        assert!(store
            .zones()
            .iter()
            .any(|z| z.origin().to_ascii_lower() == "alpha.db"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn reads_large_zone_via_overflow_chain() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf_pages = Vec::new();
        let big = zone_text("big.db", 400);
        assert!(big.len() > 4 * PAGE, "overflow 보장");
        let mut next_ovf = 3u32;
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut next_ovf,
            &mut ovf_pages,
            true,
        );
        assert_eq!(next_ovf, 3);
        let p2 = leaf_page(
            &[(
                1,
                record(&[Value::Text("big.db".into()), Value::Text(big.clone())]),
            )],
            &mut next_ovf,
            &mut ovf_pages,
            false,
        );
        assert!(!ovf_pages.is_empty(), "overflow 페이지 생성");
        let mut pages = vec![p1, p2];
        pages.extend(ovf_pages);
        let data = build_db(pages);

        let rows = read_table(&data, "zones").expect("overflow 포함 읽기");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, big, "overflow 체인을 건너 전체 텍스트 복원");

        let z = parse_zone(&rows[0].1, &rows[0].0).unwrap();
        assert_eq!(z.axfr_records().len(), 400 + 2 + 2);
    }

    #[test]
    fn walks_interior_pages() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 10u32;
        let mut ovf_pages = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut ovf_pages,
            true,
        );
        let p2 = interior_page(&[(3, 1)], 4);
        let p3 = leaf_page(
            &[(
                1,
                record(&[
                    Value::Text("one.db".into()),
                    Value::Text(zone_text("one.db", 0)),
                ]),
            )],
            &mut ovf,
            &mut ovf_pages,
            false,
        );
        let p4 = leaf_page(
            &[(
                2,
                record(&[
                    Value::Text("two.db".into()),
                    Value::Text(zone_text("two.db", 0)),
                ]),
            )],
            &mut ovf,
            &mut ovf_pages,
            false,
        );
        let data = build_db(vec![p1, p2, p3, p4]);
        let rows = read_table(&data, "zones").expect("내부 페이지 워크");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "one.db");
        assert_eq!(rows[1].0, "two.db");
    }

    #[test]
    fn rejects_cell_pointer_array_out_of_bounds() {
        let mut page = vec![0u8; PAGE];
        page[..100].copy_from_slice(&file_header(1));
        page[100] = 0x0D;
        page[103..105].copy_from_slice(&u16::MAX.to_be_bytes());
        let error = read_table(&page, "zones").unwrap_err();
        assert!(error.contains("is outside the page"), "{error}");
    }

    #[test]
    fn rejects_cell_pointer_into_header() {
        let mut page = vec![0u8; PAGE];
        page[..100].copy_from_slice(&file_header(1));
        page[100] = 0x0D;
        page[103..105].copy_from_slice(&1u16.to_be_bytes());
        page[105..107].copy_from_slice(&200u16.to_be_bytes());
        page[108..110].copy_from_slice(&100u16.to_be_bytes());
        let error = read_table(&page, "zones").unwrap_err();
        assert!(error.contains("Invalid offset of cell 0"), "{error}");
    }

    #[test]
    fn rejects_btree_page_cycle() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut overflow = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut overflow,
            true,
        );
        let p2 = interior_page(&[], 2);
        let data = build_db(vec![p1, p2]);
        let error = read_table(&data, "zones").unwrap_err();
        assert!(error.contains("same page more than once"), "{error}");
    }

    #[test]
    fn decode_value_rejects_offset_overflow() {
        assert!(decode_value(&[], usize::MAX, 1).is_err());
        assert!(decode_value(&[], usize::MAX, 13).is_err());
    }

    #[test]
    fn rejects_non_sqlite_and_missing_table() {
        assert!(read_table(b"not a database", "zones").is_err());
        let sql = "CREATE TABLE other (origin TEXT, zone TEXT)";
        let mut ovf = 2u32;
        let mut o = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("other", 2, sql))],
            &mut ovf,
            &mut o,
            true,
        );
        let p2 = leaf_page(&[], &mut ovf, &mut o, false);
        let data = build_db(vec![p1, p2]);
        let err = read_table(&data, "zones").unwrap_err();
        assert!(err.contains("Table not found"), "{err}");
    }

    #[test]
    fn parse_columns_variants() {
        assert_eq!(
            parse_columns("CREATE TABLE zones (origin TEXT, zone TEXT)"),
            vec!["origin", "zone"]
        );
        assert_eq!(
            parse_columns("CREATE TABLE t (\"id\" INTEGER PRIMARY KEY, [origin] TEXT, `zone` TEXT, PRIMARY KEY(id))"),
            vec!["id", "origin", "zone"]
        );
    }

    fn build_wal(salt1: u32, salt2: u32, frames: &[(u32, bool, Vec<u8>)]) -> Vec<u8> {
        let mut wal = vec![0u8; 32];
        wal[0..4].copy_from_slice(&0x377f_0683u32.to_be_bytes());
        wal[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        wal[8..12].copy_from_slice(&(PAGE as u32).to_be_bytes());
        wal[12..16].copy_from_slice(&1u32.to_be_bytes());
        wal[16..20].copy_from_slice(&salt1.to_be_bytes());
        wal[20..24].copy_from_slice(&salt2.to_be_bytes());
        let (h0, h1) = wal_checksum(0, 0, &wal[0..24], true);
        wal[24..28].copy_from_slice(&h0.to_be_bytes());
        wal[28..32].copy_from_slice(&h1.to_be_bytes());
        let (mut s0, mut s1) = (h0, h1);
        for (page_no, is_commit, page_bytes) in frames {
            assert_eq!(page_bytes.len(), PAGE);
            let mut fh = vec![0u8; 24];
            fh[0..4].copy_from_slice(&page_no.to_be_bytes());

            fh[4..8].copy_from_slice(&(if *is_commit { 2u32 } else { 0 }).to_be_bytes());
            fh[8..12].copy_from_slice(&salt1.to_be_bytes());
            fh[12..16].copy_from_slice(&salt2.to_be_bytes());
            let (n0, n1) = wal_checksum(s0, s1, &fh[0..8], true);
            let (n0, n1) = wal_checksum(n0, n1, page_bytes, true);
            fh[16..20].copy_from_slice(&n0.to_be_bytes());
            fh[20..24].copy_from_slice(&n1.to_be_bytes());
            s0 = n0;
            s1 = n1;
            wal.extend_from_slice(&fh);
            wal.extend_from_slice(page_bytes);
        }
        wal
    }

    fn leaf_for(origin: &str, zone: &str) -> Vec<u8> {
        let mut ovf = 99u32;
        let mut o = Vec::new();
        leaf_page(
            &[(
                1,
                record(&[Value::Text(origin.into()), Value::Text(zone.into())]),
            )],
            &mut ovf,
            &mut o,
            false,
        )
    }

    #[test]
    fn wal_overrides_main_db_page() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut o = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut o,
            true,
        );
        let p2 = leaf_for("base.db", &zone_text("base.db", 0));
        let data = build_db(vec![p1, p2]);

        let rows = read_table_wal(&data, None, "zones").unwrap();
        assert_eq!(rows[0].0, "base.db");

        let new_leaf = leaf_for("wal-new.db", &zone_text("wal-new.db", 0));
        let wal = build_wal(0x1111_1111, 0x2222_2222, &[(2, true, new_leaf)]);
        let rows = read_table_wal(&data, Some(&wal), "zones").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].0, "wal-new.db",
            "WAL 프레임이 메인 DB 페이지를 오버라이드"
        );

        let z = parse_zone(&rows[0].1, &rows[0].0).unwrap();
        assert_eq!(z.origin().to_ascii_lower(), "wal-new.db");
    }

    #[test]
    fn wal_uncommitted_frame_ignored() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut o = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut o,
            true,
        );
        let p2 = leaf_for("base.db", &zone_text("base.db", 0));
        let data = build_db(vec![p1, p2]);

        let new_leaf = leaf_for("uncommitted.db", &zone_text("uncommitted.db", 0));
        let wal = build_wal(0x1111_1111, 0x2222_2222, &[(2, false, new_leaf)]);
        let rows = read_table_wal(&data, Some(&wal), "zones").unwrap();
        assert_eq!(rows[0].0, "base.db", "미커밋 프레임은 무시");
    }

    #[test]
    fn wal_latest_commit_wins_over_earlier() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut o = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut o,
            true,
        );
        let p2 = leaf_for("base.db", &zone_text("base.db", 0));
        let data = build_db(vec![p1, p2]);

        let v1 = leaf_for("first.db", &zone_text("first.db", 0));
        let v2 = leaf_for("second.db", &zone_text("second.db", 0));
        let wal = build_wal(0x1111_1111, 0x2222_2222, &[(2, true, v1), (2, true, v2)]);
        let rows = read_table_wal(&data, Some(&wal), "zones").unwrap();
        assert_eq!(rows[0].0, "second.db", "나중 커밋 프레임이 우선");
    }

    #[test]
    fn wal_corrupt_checksum_falls_back_to_main() {
        let sql = "CREATE TABLE zones (origin TEXT, zone TEXT)";
        let mut ovf = 3u32;
        let mut o = Vec::new();
        let p1 = leaf_page(
            &[(1, master_record("zones", 2, sql))],
            &mut ovf,
            &mut o,
            true,
        );
        let p2 = leaf_for("base.db", &zone_text("base.db", 0));
        let data = build_db(vec![p1, p2]);

        let new_leaf = leaf_for("corrupt.db", &zone_text("corrupt.db", 0));
        let mut wal = build_wal(0x1111_1111, 0x2222_2222, &[(2, true, new_leaf)]);

        let frame_data_at = 32 + 24;
        wal[frame_data_at + 10] ^= 0xFF;
        let rows = read_table_wal(&data, Some(&wal), "zones").unwrap();
        assert_eq!(
            rows[0].0, "base.db",
            "체크섬 실패 프레임은 무시(메인 DB 폴백)"
        );
    }
}
