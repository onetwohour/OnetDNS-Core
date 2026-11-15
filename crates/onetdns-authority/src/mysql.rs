//! Reads zones from MySQL or MariaDB by speaking the wire protocol directly, without linking a
//! client library. Only connect, authenticate, and simple queries are needed, so the protocol is
//! not implemented in full.
//!
//! Bytes from the server are untrusted: the handshake parser, reached before authentication, and
//! the row parser must not panic on any input.

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};

/// The protocol's own limit.
const MAX_MYSQL_PACKET: usize = 16 * 1024 * 1024;
/// The query uses two.
const MAX_MYSQL_COLUMNS: usize = 64;
const MAX_MYSQL_ROWS: usize = 100_000;
/// Row count alone does not bound memory.
const MAX_MYSQL_RESULT_BYTES: usize = 512 * 1024 * 1024;
/// Stops a server that keeps demanding auth switches.
const MAX_AUTH_ROUNDS: usize = 16;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;

pub struct MysqlZoneSource {
    /// Loopback only.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: onetdns_core::SecretString,
    pub database: String,
    pub table: String,
}

impl MysqlZoneSource {
    /// Reports, at config time, what can be checked without connecting: an address that connect
    /// would refuse and a table name that cannot go into the query.
    pub fn check(&self) -> Result<(), String> {
        crate::loopback_socket_addr(&self.host, self.port, "MySQL")?;
        sanitize_table(&self.table).map(|_| ())
    }

    /// Without credentials, the user is root.
    pub fn from_url(url: &str, table: &str) -> Option<MysqlZoneSource> {
        let rest = url
            .strip_prefix("mysql://")
            .or_else(|| url.strip_prefix("mariadb://"))?;
        let (creds_host, database) = match rest.split_once('/') {
            Some((a, b)) => (a, b.split(['?', '&']).next().unwrap_or(b)),
            None => (rest, ""),
        };
        let (creds, hostport) = match creds_host.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, creds_host),
        };
        let (user, password) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (c.to_string(), String::new()),
            },
            None => ("root".to_string(), String::new()),
        };
        let (host, port) = crate::split_host_port(hostport, 3306)?;
        Some(MysqlZoneSource {
            host,
            port,
            user,
            password: password.into(),
            database: database.to_string(),
            table: table.to_string(),
        })
    }

    /// Opens a new connection every time.
    fn fetch_rows(&self) -> Result<Vec<(String, String)>, String> {
        let mut conn = MyConn::connect(&self.host, self.port, Duration::from_secs(10))?;
        conn.handshake(&self.user, &self.password, &self.database)?;
        let sql = format!("SELECT origin, zone FROM {}", sanitize_table(&self.table)?);
        conn.query(&sql)
    }
}

impl ZoneSource for MysqlZoneSource {
    /// An empty origin is the root.
    fn load(&self) -> Result<ZoneStore, String> {
        let rows = self.fetch_rows()?;
        let mut store = ZoneStore::new();
        let mut missing_origin = 0usize;
        for (origin, text) in rows {
            let o = if origin.is_empty() {
                missing_origin += 1;
                "."
            } else {
                origin.as_str()
            };
            let z = parse_zone(&text, o).map_err(|e| format!("mysql[{origin}]: {e}"))?;
            store.add(z);
        }
        if missing_origin > 0 {
            onetdns_core::warn!(event = "authority.mysql_origin_missing", table = %self.table, rows = missing_origin, "Read a row with an empty origin as the root zone; check the table if this is unintended");
        }
        Ok(store)
    }

    /// Always true: there is no cheap way to ask the server for a change time, and rereading every
    /// cycle beats missing updates.
    fn changed_since(&self, _last: SystemTime) -> bool {
        true
    }

    /// Leaves out the password.
    fn describe(&self) -> String {
        format!("mysql({}:{}/{})", self.host, self.port, self.database)
    }
}

/// Identifiers cannot be bound as placeholders and go into the query text, so only letters, digits,
/// underscore, and dot are allowed, which rules out SQL injection.
fn sanitize_table(t: &str) -> Result<String, String> {
    if !t.is_empty()
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        Ok(t.to_string())
    } else {
        Err(format!("Invalid table name: {t}"))
    }
}

/// The packet sequence number travels with the connection, or the protocol falls out of step.
struct MyConn {
    stream: DeadlineTcp,
    /// Reset to 0 for each command.
    seq: u8,
}

impl MyConn {
    /// Loopback addresses only: a remote database would receive credentials in the clear.
    fn connect(host: &str, port: u16, timeout: Duration) -> Result<MyConn, String> {
        let deadline = Instant::now() + timeout;
        let addr = crate::loopback_socket_addr(host, port, "MySQL")?;
        let stream = DeadlineTcp::connect(addr, deadline).map_err(|e| e.to_string())?;
        Ok(MyConn { stream, seq: 0 })
    }

    /// Checks the length against the limit and the sequence number; a mismatched sequence means the
    /// protocol is already out of step, and continuing would read the wrong bytes as results.
    fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        let mut head = [0u8; 4];
        self.stream
            .read_exact(&mut head)
            .map_err(|e| e.to_string())?;
        let len = (head[0] as usize) | ((head[1] as usize) << 8) | ((head[2] as usize) << 16);
        if len > MAX_MYSQL_PACKET {
            return Err("MySQL packet exceeds the size limit".into());
        }
        if head[3] != self.seq {
            return Err(format!(
                "MySQL packet sequence mismatch: expected {}, got {}",
                self.seq, head[3]
            ));
        }
        self.seq = self.seq.wrapping_add(1);
        let mut body = vec![0u8; len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| e.to_string())?;
        Ok(body)
    }

    fn write_packet(&mut self, body: &[u8]) -> Result<(), String> {
        if body.len() > MAX_MYSQL_PACKET {
            return Err("Outgoing MySQL packet exceeds the size limit".into());
        }
        let mut pkt = Vec::with_capacity(body.len() + 4);
        pkt.push((body.len() & 0xff) as u8);
        pkt.push(((body.len() >> 8) & 0xff) as u8);
        pkt.push(((body.len() >> 16) & 0xff) as u8);
        pkt.push(self.seq);
        self.seq = self.seq.wrapping_add(1);
        pkt.extend_from_slice(body);
        self.stream.write_all(&pkt).map_err(|e| e.to_string())
    }

    /// The server may demand auth method switches, so this can take several round trips, capped so
    /// a server repeating switches cannot hold it. caching_sha2 full authentication is refused: it
    /// sends the password nearly in the clear, which is unsafe without TLS.
    fn handshake(&mut self, user: &str, password: &str, database: &str) -> Result<(), String> {
        let hs = self.read_packet()?;
        let (scramble, plugin) = parse_handshake(&hs)?;

        let auth = compute_auth(&plugin, password.as_bytes(), &scramble);
        let resp = build_handshake_response(user, &auth, database, &plugin);
        self.write_packet(&resp)?;

        for _ in 0..MAX_AUTH_ROUNDS {
            let pkt = self.read_packet()?;
            match pkt.first().copied() {
                Some(0x00) => return Ok(()),
                Some(0xff) => return Err(err_packet(&pkt)),
                Some(0xfe) => {

                    let mut i: usize = 1;
                    let pstart = i;
                    while i < pkt.len() && pkt[i] != 0 {
                        i += 1;
                    }
                    let new_plugin = String::from_utf8_lossy(&pkt[pstart..i]).to_string();
                    let next = i.checked_add(1).ok_or("Auth switch length calculation overflowed")?;
                    let new_scramble = trim_nul(pkt.get(next..).ok_or("Auth switch packet is too short")?);
                    let auth = compute_auth(&new_plugin, password.as_bytes(), &new_scramble);
                    self.write_packet(&auth)?;
                }
                Some(0x01) => {

                    match pkt.get(1).copied() {
                        Some(0x03) => {}
                        Some(0x04) => {
                            return Err(
                                "Full caching_sha2_password authentication is not supported over this connection; use TLS or configure the account with mysql_native_password".into(),
                            )
                        }
                        _ => {}
                    }
                }
                _ => return Err("Unexpected handshake response".into()),
            }
        }
        Err("Too many MySQL authentication round trips".into())
    }

    /// Sends a query and fetches two text columns. The response is column count, column
    /// definitions, an optional EOF, rows, and a final EOF; server versions differ on the middle
    /// EOF, so that slot is checked and skipped. Counts both rows and total bytes: counting rows
    /// alone lets a few huge rows fill memory.
    fn query(&mut self, sql: &str) -> Result<Vec<(String, String)>, String> {
        self.seq = 0;
        let mut body = vec![0x03u8];
        body.extend_from_slice(sql.as_bytes());
        self.write_packet(&body)?;

        let first = self.read_packet()?;
        if first.first() == Some(&0xff) {
            return Err(err_packet(&first));
        }
        if first.first() == Some(&0x00) {
            return Ok(Vec::new());
        }

        let (ncols, _) = lenenc_int(&first, 0).ok_or("Could not parse the column count")?;
        let ncols = usize::try_from(ncols).map_err(|_| "Column count is out of range")?;
        if ncols == 0 || ncols > MAX_MYSQL_COLUMNS {
            return Err("MySQL column count exceeds the limit".into());
        }

        for _ in 0..ncols {
            self.read_packet()?;
        }

        let mut peek = self.read_packet()?;
        let is_eof = |p: &[u8]| p.first() == Some(&0xfe) && p.len() < 9;
        if is_eof(&peek) {
            peek = self.read_packet()?;
        }

        let mut rows = Vec::new();
        let mut result_bytes = 0usize;
        let mut cur = peek;
        loop {
            if cur.first() == Some(&0xfe) && cur.len() < 9 {
                break;
            }
            if cur.first() == Some(&0xff) {
                return Err(err_packet(&cur));
            }
            let cols = parse_text_row(&cur, ncols)?;
            let origin = cols.first().cloned().flatten().unwrap_or_default();
            let zone = cols.get(1).cloned().flatten().unwrap_or_default();
            if rows.len() >= MAX_MYSQL_ROWS {
                return Err("MySQL result exceeds the row limit".into());
            }
            result_bytes = result_bytes
                .checked_add(origin.len())
                .and_then(|n| n.checked_add(zone.len()))
                .ok_or("MySQL result size calculation overflowed")?;
            if result_bytes > MAX_MYSQL_RESULT_BYTES {
                return Err("MySQL result exceeds the size limit".into());
            }
            rows.push((origin, zone));
            cur = self.read_packet()?;
        }
        Ok(rows)
    }
}

/// Extracts the scramble and auth plugin name from the server's first handshake. The scramble comes
/// in two separate pieces that must be joined. Every offset is checked for overflow; these bytes
/// are not yet authenticated.
fn parse_handshake(p: &[u8]) -> Result<(Vec<u8>, String), String> {
    if p.first() != Some(&0x0a) {
        return Err("Not a MySQL protocol v10 handshake".into());
    }
    let mut i = 1usize;
    let server_end = p
        .get(i..)
        .and_then(|tail| tail.iter().position(|&b| b == 0))
        .map(|n| i + n)
        .ok_or("The server version string is not terminated")?;
    i = server_end
        .checked_add(1)
        .ok_or("Handshake length calculation overflowed")?;
    i = i
        .checked_add(4)
        .ok_or("Handshake length calculation overflowed")?;

    let part1_end = i
        .checked_add(8)
        .ok_or("Handshake length calculation overflowed")?;
    let mut scramble = p
        .get(i..part1_end)
        .ok_or("Handshake is too short")?
        .to_vec();
    i = part1_end
        .checked_add(1)
        .ok_or("Handshake length calculation overflowed")?;

    let cap_low_end = i
        .checked_add(2)
        .ok_or("Handshake length calculation overflowed")?;
    if cap_low_end > p.len() {
        return Err("Handshake capability field is too short".into());
    }
    i = cap_low_end;
    if i == p.len() {
        return Ok((scramble, "mysql_native_password".into()));
    }

    let fixed_end = i
        .checked_add(6)
        .ok_or("Handshake length calculation overflowed")?;
    let fixed = p
        .get(i..fixed_end)
        .ok_or("Handshake extension is too short")?;
    let adl = fixed[5] as usize;
    i = fixed_end
        .checked_add(10)
        .ok_or("Handshake length calculation overflowed")?;
    if i > p.len() {
        return Err("Handshake reserved field is too short".into());
    }

    let available = p.len().saturating_sub(i);
    let requested = adl.saturating_sub(8).max(13);
    let part2_len = requested.min(available);
    if part2_len > 0 {
        let end = i
            .checked_add(part2_len)
            .ok_or("Handshake length calculation overflowed")?;
        scramble.extend_from_slice(&trim_nul(&p[i..end]));
        i = end;
    }

    let plugin = if i < p.len() {
        let tail = &p[i..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..end]).to_string()
    } else {
        String::new()
    };

    Ok((
        scramble,
        if plugin.is_empty() {
            "mysql_native_password".into()
        } else {
            plugin
        },
    ))
}

/// Scramble pieces come padded with zeros.
fn trim_nul(b: &[u8]) -> Vec<u8> {
    let mut e = b.len();
    while e > 0 && b[e - 1] == 0 {
        e -= 1;
    }
    b[..e].to_vec()
}

/// An empty password gets an empty response; hashing it makes the server reject authentication.
fn compute_auth(plugin: &str, password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    match plugin {
        "caching_sha2_password" => scramble_sha256(password, scramble),
        _ => scramble_native(password, scramble),
    }
}

/// mysql_native_password: SHA1(password) XOR SHA1(scramble ‖ SHA1(SHA1(password))). The server
/// stores only SHA1(SHA1(password)), so the password itself never crosses the wire.
fn scramble_native(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    let h1 = sha1(password);
    let h2 = sha1(&h1);
    let mut cat = scramble.to_vec();
    cat.extend_from_slice(&h2);
    let h3 = sha1(&cat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// caching_sha2_password fast path; the concatenation order is the reverse of native. An empty
/// server cache falls back to full authentication, which this server refuses.
fn scramble_sha256(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    let h1 = sha256(password);
    let h2 = sha256(&h1);
    let mut cat = h2.to_vec();
    cat.extend_from_slice(scramble);
    let h3 = sha256(&cat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/// Requests only the features this server uses; enabling compression or multi-statements would mean
/// handling their response formats too.
fn build_handshake_response(user: &str, auth: &[u8], database: &str, plugin: &str) -> Vec<u8> {
    let mut caps =
        CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_LONG_PASSWORD;
    if !database.is_empty() {
        caps |= CLIENT_CONNECT_WITH_DB;
    }
    let mut b = Vec::new();
    b.extend_from_slice(&caps.to_le_bytes());
    b.extend_from_slice(&(16u32 * 1024 * 1024).to_le_bytes());
    b.push(45);
    b.extend_from_slice(&[0u8; 23]);
    b.extend_from_slice(user.as_bytes());
    b.push(0);
    b.push(auth.len() as u8);
    b.extend_from_slice(auth);
    if !database.is_empty() {
        b.extend_from_slice(database.as_bytes());
        b.push(0);
    }
    b.extend_from_slice(plugin.as_bytes());
    b.push(0);
    b
}

/// Skips the SQL state when present.
fn err_packet(p: &[u8]) -> String {
    if p.len() < 3 {
        return "MySQL server returned an error".into();
    }
    let mut i = 3;
    if p.get(3) == Some(&b'#') {
        i = 9;
    }
    format!(
        "MySQL error: {}",
        String::from_utf8_lossy(&p[i.min(p.len())..])
    )
}

/// The first byte selects the form: 0xfb is the NULL marker, read as 0, and the others take the 2,
/// 3, or 8 bytes that follow. Returns the value and next position; None when bytes run out.
fn lenenc_int(b: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *b.get(pos)?;
    match first {
        0xfb => Some((0, pos + 1)),
        0xfc => {
            let v = u16::from_le_bytes([*b.get(pos + 1)?, *b.get(pos + 2)?]) as u64;
            Some((v, pos + 3))
        }
        0xfd => {
            let v = (*b.get(pos + 1)? as u64)
                | ((*b.get(pos + 2)? as u64) << 8)
                | ((*b.get(pos + 3)? as u64) << 16);
            Some((v, pos + 4))
        }
        0xfe => {
            let mut v = 0u64;
            for k in 0..8 {
                v |= (*b.get(pos + 1 + k)? as u64) << (8 * k);
            }
            Some((v, pos + 9))
        }
        n => Some((n as u64, pos + 1)),
    }
}

/// Length arithmetic is overflow-checked: a crafted length that wraps the position would reread
/// bytes or run out of bounds. NULL is None.
fn parse_text_row(b: &[u8], ncols: usize) -> Result<Vec<Option<String>>, String> {
    let mut pos: usize = 0;
    let mut out = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        if b.get(pos) == Some(&0xfb) {
            out.push(None);
            pos += 1;
            continue;
        }
        let (len, np) = lenenc_int(b, pos).ok_or("Could not parse a length-encoded integer")?;
        pos = np;
        let len = usize::try_from(len).map_err(|_| "Row value length is out of range")?;
        let end = pos
            .checked_add(len)
            .ok_or("Row value length calculation overflowed")?;
        let s = b.get(pos..end).ok_or("Row value is out of range")?;
        out.push(Some(String::from_utf8_lossy(s).to_string()));
        pos = end;
    }
    Ok(out)
}

/// Fixed by the auth method.
fn sha1(d: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(d);
    h.finalize().into()
}

fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let s = MysqlZoneSource::from_url("mysql://dns:pw@h:3307/zdb", "zones").unwrap();
        assert_eq!(s.user, "dns");
        assert_eq!(s.password.as_str(), "pw");
        assert_eq!(format!("{:?}", s.password), "<redacted>");
        assert_eq!(s.host, "h");
        assert_eq!(s.port, 3307);
        assert_eq!(s.database, "zdb");
        let d = MysqlZoneSource::from_url("mariadb://h/db", "z").unwrap();
        assert_eq!(d.user, "root");
        assert_eq!(d.port, 3306);
    }

    #[test]
    fn lenenc_variants() {
        assert_eq!(lenenc_int(&[0x05], 0), Some((5, 1)));
        assert_eq!(lenenc_int(&[0xfc, 0x10, 0x01], 0), Some((0x0110, 3)));
        assert_eq!(
            lenenc_int(&[0xfd, 0x01, 0x02, 0x03], 0),
            Some((0x030201, 4))
        );
    }

    /// Mixing them would turn the origin into the root.
    #[test]
    fn text_row_parse_with_null() {
        let mut b = vec![6];
        b.extend_from_slice(b"ex.com");
        b.push(0xfb);
        let cols = parse_text_row(&b, 2).unwrap();
        assert_eq!(cols[0].as_deref(), Some("ex.com"));
        assert_eq!(cols[1], None);
    }

    /// An empty password must give an empty response.
    #[test]
    fn native_scramble_known_vector() {
        let scramble: Vec<u8> = (0u8..20).collect();
        let r = scramble_native(b"pass", &scramble);
        assert_eq!(r.len(), 20);

        assert!(compute_auth("mysql_native_password", b"", &scramble).is_empty());

        assert_eq!(r, scramble_native(b"pass", &scramble));

        let h1 = sha1(b"pass");
        let recovered: Vec<u8> = r.iter().zip(h1.iter()).map(|(a, b)| a ^ b).collect();
        let h2 = sha1(&h1);
        let mut cat = scramble.clone();
        cat.extend_from_slice(&h2);
        assert_eq!(recovered, sha1(&cat).to_vec());
    }

    #[test]
    fn sha256_scramble_shape() {
        let scramble: Vec<u8> = (0u8..20).collect();
        let r = scramble_sha256(b"secret", &scramble);
        assert_eq!(r.len(), 32);
    }

    #[test]
    fn handshake_v10_parse() {
        let mut p = vec![0x0a];
        p.extend_from_slice(b"8.0.0");
        p.push(0);
        p.extend_from_slice(&[1, 2, 3, 4]);
        p.extend_from_slice(&[10, 11, 12, 13, 14, 15, 16, 17]);
        p.push(0);
        p.extend_from_slice(&[0xff, 0xf7]);
        p.push(45);
        p.extend_from_slice(&[0x02, 0x00]);
        p.extend_from_slice(&[0xff, 0x81]);
        p.push(21);
        p.extend_from_slice(&[0u8; 10]);
        p.extend_from_slice(&[20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0]);
        p.extend_from_slice(b"mysql_native_password");
        p.push(0);
        let (scramble, plugin) = parse_handshake(&p).unwrap();
        assert_eq!(plugin, "mysql_native_password");
        assert_eq!(scramble.len(), 20);
        assert_eq!(&scramble[..8], &[10, 11, 12, 13, 14, 15, 16, 17]);
    }
}

/// These parsers are crate-private, out of reach of the integration sweep, so they are fuzzed here.
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    #[test]
    fn wire_parsers_never_panic_on_malformed_bytes() {
        let mut handshake = vec![10u8];
        handshake.extend_from_slice(b"8.0.36\0");
        handshake.extend_from_slice(&[1, 0, 0, 0]);
        handshake.extend_from_slice(b"ABCDEFGH\0");
        handshake.extend_from_slice(&[0xFF, 0xFF, 0x2D, 0x02, 0x00, 0xFF, 0xC3, 21]);
        handshake.extend_from_slice(&[0; 10]);
        handshake.extend_from_slice(b"IJKLMNOPQRST\0");
        handshake.extend_from_slice(b"caching_sha2_password\0");

        let row = vec![5u8, b'a', b'.', b'c', b'o', b'm', 1, b'A', 0xFB];

        let mut rng = Rng::new(0x4D59_5351_4C00_0001);
        for index in 0..20_000u32 {
            let bytes = match index % 3 {
                0 => rng.rand_bytes(200),
                1 => havoc(&mut rng, &handshake),
                _ => havoc(&mut rng, &row),
            };
            let _ = parse_handshake(&bytes);
            for ncols in [0usize, 1, 3, 64] {
                let _ = parse_text_row(&bytes, ncols);
            }
        }
    }
}
