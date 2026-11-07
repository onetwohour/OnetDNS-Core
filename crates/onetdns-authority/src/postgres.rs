//! Zone backend that speaks the PostgreSQL wire protocol. It authenticates with SCRAM-SHA-256
//! only and checks the server's signature, so the password never goes out in cleartext. Server
//! bytes are untrusted: every SCRAM parameter has a cap and the parsers never panic.

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime};

use hmac::{Mac, SimpleHmac};
use sha2::{Digest, Sha256};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};

type HmacSha256 = SimpleHmac<Sha256>;

const MAX_PG_MESSAGE: usize = 64 * 1024 * 1024;
const MAX_ZONE_ROWS: usize = 100_000;
const MAX_ZONE_RESULT_BYTES: usize = 512 * 1024 * 1024;
/// Keeps a server from stalling authentication forever.
const MAX_PG_AUTH_MESSAGES: usize = 1024;
/// One message per row, plus slack.
const MAX_PG_QUERY_MESSAGES: usize = MAX_ZONE_ROWS + 4096;
/// Tighter than for queries: the server is not authenticated yet.
const MAX_PG_AUTH_PAYLOAD: usize = 64 * 1024;
/// A lower count is a server forcing a weak hash.
const MIN_SCRAM_ITERATIONS: u32 = 4096;
/// Keeps a server from burning this host's CPU.
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

/// Reads zones from a PostgreSQL table, one `(origin, zone)` row per zone.
pub struct PostgresZoneSource {
    /// Loopback only.
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: onetdns_core::SecretString,
    pub database: String,
    pub table: String,
}

impl PostgresZoneSource {
    /// Reports what fails before connecting: an address the connection would refuse, and a table
    /// name that cannot go into the query.
    pub fn check(&self) -> Result<(), String> {
        crate::loopback_socket_addr(&self.host, self.port, "PostgreSQL")?;
        sanitize_table(&self.table).map(|_| ())
    }

    /// Percent-decodes the password, since special characters must be encoded in a URL.
    pub fn from_url(url: &str, table: &str) -> Option<PostgresZoneSource> {
        let rest = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))?;
        let (creds_host, database) = match rest.split_once('/') {
            Some((a, b)) => (a, b.split(['?', '&']).next().unwrap_or(b)),
            None => (rest, "postgres"),
        };
        let (creds, hostport) = match creds_host.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, creds_host),
        };
        let (user, password) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (u.to_string(), pct_decode(p)),
                None => (c.to_string(), String::new()),
            },
            None => ("postgres".to_string(), String::new()),
        };
        let (host, port) = crate::split_host_port(hostport, 5432)?;
        Some(PostgresZoneSource {
            host,
            port,
            user,
            password: password.into(),
            database: if database.is_empty() {
                "postgres".to_string()
            } else {
                database.to_string()
            },
            table: table.to_string(),
        })
    }

    fn fetch_rows(&self) -> Result<Vec<(String, String)>, String> {
        let mut conn = PgConn::connect(&self.host, self.port, Duration::from_secs(10))?;
        conn.startup(&self.user, &self.database, &self.password)?;
        let sql = format!("SELECT origin, zone FROM {}", sanitize_table(&self.table)?);
        conn.simple_query(&sql)
    }
}

impl ZoneSource for PostgresZoneSource {
    /// An empty origin is the root zone.
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
            let z = parse_zone(&text, o).map_err(|e| format!("postgres[{origin}]: {e}"))?;
            store.add(z);
        }
        if missing_origin > 0 {
            onetdns_core::warn!(event = "authority.postgres_origin_missing", table = %self.table, rows = missing_origin, "Read a row with an empty origin as the root zone; check the table if this is unintended");
        }
        Ok(store)
    }

    /// There is no cheap way to ask for a change time, so every cycle rereads.
    fn changed_since(&self, _last: SystemTime) -> bool {
        true
    }

    /// Leaves out the password.
    fn describe(&self) -> String {
        format!("postgres({}:{}/{})", self.host, self.port, self.database)
    }
}

/// Identifiers cannot be bound, so the name goes into the query as is.
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

struct PgConn {
    stream: DeadlineTcp,
}

impl PgConn {
    /// Loopback only: there is no TLS, so zone data would cross the network in the clear.
    fn connect(host: &str, port: u16, timeout: Duration) -> Result<PgConn, String> {
        let deadline = Instant::now() + timeout;
        let addr = crate::loopback_socket_addr(host, port, "PostgreSQL")?;
        let stream = DeadlineTcp::connect(addr, deadline).map_err(|e| e.to_string())?;
        Ok(PgConn { stream })
    }

    /// `tag` 0 sends the untagged startup message. The length field counts its own four bytes.
    fn send(&mut self, tag: u8, body: &[u8]) -> Result<(), String> {
        let wire_len = body
            .len()
            .checked_add(4)
            .ok_or("Postgres outgoing length calculation overflowed")?;
        if wire_len > MAX_PG_MESSAGE || wire_len > u32::MAX as usize {
            return Err("Outgoing Postgres message exceeds the size limit".into());
        }
        let mut msg = Vec::with_capacity(body.len() + 5);
        if tag != 0 {
            msg.push(tag);
        }
        msg.extend_from_slice(&(wire_len as u32).to_be_bytes());
        msg.extend_from_slice(body);
        self.stream.write_all(&msg).map_err(|e| e.to_string())
    }

    /// A length under 4 would make the body length negative.
    fn recv(&mut self) -> Result<(u8, Vec<u8>), String> {
        let mut head = [0u8; 5];
        self.stream
            .read_exact(&mut head)
            .map_err(|e| e.to_string())?;
        let tag = head[0];
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if !(4..=MAX_PG_MESSAGE).contains(&len) {
            return Err("Invalid message length".into());
        }
        let mut body = vec![0u8; len - 4];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| e.to_string())?;
        Ok((tag, body))
    }

    /// Refuses cleartext and MD5 authentication: the first hands the password to whatever
    /// answers on the port, the second rests on a hash with practical collisions. Caps the message
    /// count so a server sending only notices cannot hold the connection.
    fn startup(&mut self, user: &str, database: &str, password: &str) -> Result<(), String> {
        let mut body = Vec::new();
        body.extend_from_slice(&196608u32.to_be_bytes());
        for (k, v) in [
            ("user", user),
            ("database", database),
            ("client_encoding", "UTF8"),
        ] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        self.send(0, &body)?;

        for _ in 0..MAX_PG_AUTH_MESSAGES {
            let (tag, body) = self.recv()?;
            match tag {
                b'R' => {
                    if body.len() > MAX_PG_AUTH_PAYLOAD {
                        return Err("Authentication message exceeds the size limit".into());
                    }
                    let code = body.get(..4).ok_or("Authentication message is too short")?;
                    let sub = u32::from_be_bytes([code[0], code[1], code[2], code[3]]);
                    match sub {
                        0 => {}
                        3 => {
                            return Err(
                                "PostgreSQL cleartext password authentication is not supported; use SCRAM-SHA-256"
                                    .into(),
                            )
                        }
                        10 => self.scram(user, password, &body[4..])?,
                        5 => {
                            return Err(
                                "PostgreSQL MD5 authentication is not supported; use SCRAM-SHA-256"
                                    .into(),
                            )
                        }
                        other => return Err(format!("Unsupported authentication method {other}")),
                    }
                }
                b'E' => return Err(format!("Postgres error: {}", error_text(&body))),
                b'S' | b'K' | b'N' => {}
                b'Z' => return Ok(()),
                _ => {}
            }
        }
        Err("Too many Postgres startup messages".into())
    }

    /// Checks that the server's nonce extends ours, which stops replay, and verifies the server's
    /// signature so nothing else can pass as the server. Salt, nonce and iteration count are all
    /// capped.
    fn scram(&mut self, user: &str, password: &str, mechs: &[u8]) -> Result<(), String> {
        let mech_list = String::from_utf8_lossy(mechs);
        if !mech_list.contains("SCRAM-SHA-256") {
            return Err(format!("Unsupported SASL mechanism: {mech_list}"));
        }
        let mut nonce = [0u8; 18];
        onetdns_tls::sys::fill_random(&mut nonce);
        let client_nonce = b64_encode(&nonce);
        let client_first_bare = format!("n={},r={}", saslprep(user), client_nonce);
        let initial = format!("n,,{client_first_bare}");

        let mut body = Vec::new();
        body.extend_from_slice(b"SCRAM-SHA-256");
        body.push(0);
        body.extend_from_slice(&(initial.len() as u32).to_be_bytes());
        body.extend_from_slice(initial.as_bytes());
        self.send(b'p', &body)?;

        let (tag, body) = self.recv()?;
        if tag == b'E' {
            return Err(format!("Postgres error: {}", error_text(&body)));
        }
        if tag != b'R' {
            return Err("A SASLContinue message is required".into());
        }
        let code = body.get(..4).ok_or("SASLContinue message is too short")?;
        let sub = u32::from_be_bytes([code[0], code[1], code[2], code[3]]);
        if sub != 11 {
            return Err("A SASLContinue (11) message is required".into());
        }
        if body.len() > MAX_PG_AUTH_PAYLOAD {
            return Err("SASLContinue message exceeds the size limit".into());
        }
        let server_first = String::from_utf8_lossy(&body[4..]).to_string();
        if server_first.len() > 8192 {
            return Err("SCRAM server parameters exceed the size limit".into());
        }
        let (r, s, i) = parse_server_first(&server_first)?;
        if s.len() > 2048 || r.len() > 4096 {
            return Err("SCRAM server parameters exceed the size limit".into());
        }
        if !r.starts_with(&client_nonce) {
            return Err("The server nonce does not contain the client nonce".into());
        }
        let salt = b64_decode(&s).ok_or("Invalid Base64 password salt")?;
        if salt.is_empty() || salt.len() > 1024 {
            return Err("SCRAM server parameters exceed the size limit".into());
        }

        let salted = pbkdf2_sha256(password.as_bytes(), &salt, i);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let client_final_bare = format!("c=biws,r={r}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let client_final = format!("{client_final_bare},p={}", b64_encode(&proof));
        self.send(b'p', client_final.as_bytes())?;

        let (tag, body) = self.recv()?;
        if tag == b'E' {
            return Err(format!("Postgres error: {}", error_text(&body)));
        }
        if tag != b'R' {
            return Err("A SASLFinal message is required".into());
        }
        let code = body.get(..4).ok_or("SASLFinal message is too short")?;
        let sub = u32::from_be_bytes([code[0], code[1], code[2], code[3]]);
        if sub != 12 {
            return Err("A SASLFinal (12) message is required".into());
        }
        if body.len() > MAX_PG_AUTH_PAYLOAD {
            return Err("SASLFinal message exceeds the size limit".into());
        }
        let server_final =
            std::str::from_utf8(&body[4..]).map_err(|_| "SASLFinal is not valid UTF-8")?;
        let mut verifier: Option<&str> = None;
        for attr in server_final.split(',') {
            let (key, value) = attr
                .split_once('=')
                .ok_or("Malformed SASLFinal attribute")?;
            match key {
                "v" if verifier.is_none() && !value.is_empty() => verifier = Some(value),
                "e" => return Err(format!("SCRAM server error: {value}")),
                "v" => return Err("SASLFinal verifier is duplicated or empty".into()),
                _ => return Err(format!("Unknown SASLFinal attribute: {key}")),
            }
        }
        let verifier = verifier.ok_or("SASLFinal response has no server signature")?;
        let server_key = hmac_sha256(&salted, b"Server Key");
        let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
        if b64_decode(verifier).as_deref() != Some(&server_sig[..]) {
            return Err(
                "The authentication signature sent by the PostgreSQL server does not match; closing the connection".into(),
            );
        }
        Ok(())
    }

    /// Counts rows, bytes and messages: no one of them alone bounds both memory and time.
    fn simple_query(&mut self, sql: &str) -> Result<Vec<(String, String)>, String> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        self.send(b'Q', &body)?;

        let mut rows = Vec::new();
        let mut result_bytes = 0usize;
        for _ in 0..MAX_PG_QUERY_MESSAGES {
            let (tag, body) = self.recv()?;
            match tag {
                b'D' => {
                    let cols = parse_data_row(&body)?;
                    let origin = cols.first().cloned().flatten().unwrap_or_default();
                    let zone = cols.get(1).cloned().flatten().unwrap_or_default();
                    if rows.len() >= MAX_ZONE_ROWS {
                        return Err("Postgres result exceeds the row limit".into());
                    }
                    result_bytes = result_bytes
                        .checked_add(origin.len())
                        .and_then(|n| n.checked_add(zone.len()))
                        .ok_or("Postgres result size calculation overflowed")?;
                    if result_bytes > MAX_ZONE_RESULT_BYTES {
                        return Err("Postgres result exceeds the size limit".into());
                    }
                    rows.push((origin, zone));
                }
                b'C' => {}
                b'E' => return Err(format!("Query error: {}", error_text(&body))),
                b'Z' => return Ok(rows),
                _ => {}
            }
        }
        Err("Too many Postgres query messages".into())
    }
}

/// Column lengths are signed: -1 is NULL, which an unsigned read turns into a huge length.
fn parse_data_row(body: &[u8]) -> Result<Vec<Option<String>>, String> {
    if body.len() < 2 {
        return Err("DataRow is too short".into());
    }
    let ncols = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut pos: usize = 2;
    let mut out = Vec::with_capacity(ncols);
    for _ in 0..ncols {
        let Some(header_end) = pos.checked_add(4) else {
            return Err("DataRow length calculation overflowed".into());
        };
        if header_end > body.len() {
            return Err("Invalid DataRow length".into());
        }
        let len = i32::from_be_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
        pos += 4;
        if len < 0 {
            out.push(None);
        } else {
            let len = usize::try_from(len).map_err(|_| "Invalid DataRow value length")?;
            let end = pos
                .checked_add(len)
                .ok_or("DataRow value length calculation overflowed")?;
            let bytes = body
                .get(pos..end)
                .ok_or("PostgreSQL row data crosses the message boundary")?;
            out.push(Some(String::from_utf8_lossy(bytes).to_string()));
            pos = end;
        }
    }
    Ok(out)
}

/// Only the human-readable message field.
fn error_text(body: &[u8]) -> String {
    let mut pos = 0;
    while pos < body.len() && body[pos] != 0 {
        let field = body[pos];
        pos += 1;
        let start = pos;
        while pos < body.len() && body[pos] != 0 {
            pos += 1;
        }
        let val = String::from_utf8_lossy(&body[start..pos]).to_string();
        pos += 1;
        if field == b'M' {
            return val;
        }
    }
    "The server returned an error without a reason".to_string()
}

/// Returns the nonce, salt and iteration count; the count must lie within the SCRAM bounds.
fn parse_server_first(s: &str) -> Result<(String, String, u32), String> {
    let mut r = None;
    let mut salt = None;
    let mut iter = None;
    for part in s.split(',') {
        if let Some(v) = part.strip_prefix("r=") {
            r = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("s=") {
            salt = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("i=") {
            iter = v.parse().ok();
        }
    }
    Ok((
        r.ok_or("The first PostgreSQL SCRAM server response has no nonce (r)")?,
        salt.ok_or("The first PostgreSQL SCRAM server response has no salt (s)")?,
        {
            let iterations = iter
                .ok_or("The first PostgreSQL SCRAM server response has no iteration count (i)")?;
            if !(MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(&iterations) {
                return Err("SCRAM iteration count is out of range".into());
            }
            iterations
        },
    ))
}

/// Replaces `=` before `,`; the other order would escape the `=` in `=2C` again.
fn saslprep(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.finalize().into()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("The HMAC key length matches the algorithm requirement");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// One output block is enough: SCRAM uses only the hash length. The caller range-checks the
/// iteration count.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &block);
    let mut t = u;
    for _ in 1..iters {
        u = hmac_sha256(password, &u);
        for k in 0..32 {
            t[k] ^= u[k];
        }
    }
    t
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 0x3f] as char);
        out.push(B64[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// `None` on a character outside the alphabet.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let s = PostgresZoneSource::from_url("postgres://dns:s3cret@db.host:6543/zonesdb", "zones")
            .unwrap();
        assert_eq!(s.user, "dns");
        assert_eq!(s.password.as_str(), "s3cret");
        assert_eq!(format!("{:?}", s.password), "<redacted>");
        assert_eq!(s.host, "db.host");
        assert_eq!(s.port, 6543);
        assert_eq!(s.database, "zonesdb");
        assert_eq!(s.table, "zones");

        let d = PostgresZoneSource::from_url("postgresql://host/db", "z").unwrap();
        assert_eq!(d.user, "postgres");
        assert_eq!(d.port, 5432);
        assert_eq!(d.host, "host");
    }

    /// -1 must read as NULL.
    #[test]
    fn data_row_parse() {
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&3i32.to_be_bytes());
        body.extend_from_slice(b"abc");
        body.extend_from_slice(&(-1i32).to_be_bytes());
        let cols = parse_data_row(&body).unwrap();
        assert_eq!(cols[0].as_deref(), Some("abc"));
        assert_eq!(cols[1], None);
    }

    /// The RFC 7677 vector, both the proof and the server signature.
    #[test]
    fn pbkdf2_rfc7677_vector() {
        let salt = b64_decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let salted = pbkdf2_sha256(b"pencil", &salt, 4096);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let client_sig = hmac_sha256(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        assert_eq!(
            b64_encode(&proof),
            "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );

        let server_key = hmac_sha256(&salted, b"Server Key");
        let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
        assert_eq!(
            b64_encode(&server_sig),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
    }

    #[test]
    fn server_first_parse() {
        let (r, s, i) = parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap();
        assert_eq!(r, "abc123");
        assert_eq!(s, "W22ZaJ0SNY7soEsUEjb6gQ==");
        assert_eq!(i, 4096);
    }

    #[test]
    fn table_sanitize() {
        assert!(sanitize_table("zones").is_ok());
        assert!(sanitize_table("schema.zones").is_ok());
        assert!(sanitize_table("zones; DROP TABLE x").is_err());
    }

    #[test]
    fn the_password_never_goes_out_in_cleartext() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0u8; 4];
            socket.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            socket.read_exact(&mut startup).unwrap();
            socket.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3]).unwrap();
            let mut received = Vec::new();
            let _ = socket.read_to_end(&mut received);
            received
        });
        let mut conn = PgConn::connect("127.0.0.1", port, Duration::from_secs(2)).unwrap();
        assert!(conn.startup("dns", "zones", "s3cret-pw").is_err());
        drop(conn);
        let received = server.join().unwrap();
        assert!(
            !received.windows(9).any(|window| window == b"s3cret-pw"),
            "{received:?}"
        );
    }
}

/// Panic sweep for the wire parsers, which the integration sweep cannot reach.
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    #[test]
    fn wire_parsers_never_panic_on_malformed_bytes() {
        let mut row = vec![0u8, 2];
        row.extend_from_slice(&5i32.to_be_bytes());
        row.extend_from_slice(b"a.com");
        row.extend_from_slice(&(-1i32).to_be_bytes());

        let first = b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";

        let mut rng = Rng::new(0x5047_5351_4C00_0002);
        for index in 0..20_000u32 {
            let bytes = match index % 3 {
                0 => rng.rand_bytes(200),
                1 => havoc(&mut rng, &row),
                _ => havoc(&mut rng, first),
            };
            let _ = parse_data_row(&bytes);
            let _ = parse_server_first(&String::from_utf8_lossy(&bytes));
        }
    }
}
