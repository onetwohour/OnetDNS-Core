//! Zone source backed by etcd through its v3 JSON gateway, with a small HTTP/1.1 client here
//! instead of a gRPC stack. Every key under the prefix is one zone. Server responses are
//! untrusted: headers, bodies and chunked encoding are bounded and checked, and ambiguous framing
//! is refused.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use onetdns_tls::{client_handshake, ClientConfig, TlsConnection, TrustStore};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};
const MAX_HTTP_HEADER: usize = 64 * 1024;
const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;
/// Reading stops at this many bytes.
const MAX_HTTP_RESPONSE: usize = MAX_HTTP_HEADER + MAX_HTTP_BODY;
const MAX_HTTP_HEADERS: usize = 200;
const MAX_HTTP_HEADER_LINE: usize = 8 * 1024;
/// For the whole request, not each read.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Keys are zone origins and values zone text.
pub struct EtcdZoneSource {
    pub endpoint: String,

    /// Every key under it is a zone.
    pub prefix: String,

    /// Used instead of resolving the endpoint name, which could go through this server itself.
    connect_addr: Option<SocketAddr>,

    /// Required for https.
    tls: Option<TrustStore>,

    /// `None` connects without authentication.
    creds: Option<(String, onetdns_core::SecretString)>,

    /// Reused so each request does not sign in again.
    token: Mutex<Option<onetdns_core::SecretString>>,

    /// Key count and highest revision last seen, for change detection.
    seen: Mutex<(usize, u64)>,

    /// Whether the last change check failed, so only transitions are logged.
    unreachable: std::sync::atomic::AtomicBool,
}

impl EtcdZoneSource {
    pub fn new(endpoint: impl Into<String>, prefix: impl Into<String>) -> Self {
        EtcdZoneSource {
            endpoint: endpoint.into(),
            prefix: prefix.into(),
            connect_addr: None,
            tls: None,
            creds: None,
            token: Mutex::new(None),
            seen: Mutex::new((0, 0)),
            unreachable: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn with_default_prefix(endpoint: impl Into<String>) -> Self {
        Self::new(endpoint, "/onetdns/zones/")
    }

    /// Required for https endpoints.
    pub fn with_tls(mut self, roots: TrustStore) -> Self {
        self.tls = Some(roots);
        self
    }

    pub fn with_auth(
        mut self,
        user: impl Into<String>,
        password: impl Into<onetdns_core::SecretString>,
    ) -> Self {
        self.creds = Some((user.into(), password.into()));
        self
    }

    /// Connects here instead of resolving the endpoint name, which could loop back through this
    /// server during startup. TLS still verifies the certificate against the endpoint name.
    pub fn with_connect_addr(mut self, addr: SocketAddr) -> Self {
        self.connect_addr = Some(addr);
        self
    }

    pub fn endpoint_host_port(&self) -> Result<(String, u16), String> {
        endpoint_parts(&self.endpoint)
            .map(|parts| (parts.host, parts.port))
            .map_err(|error| error.to_string())
    }

    fn is_https(&self) -> bool {
        self.endpoint.starts_with("https://")
    }

    /// Plain http reaches only this machine and never carries credentials: etcd takes the password
    /// itself, and zone data could be read or replaced on the way.
    pub fn check(&self) -> Result<(), String> {
        let parts = endpoint_parts(&self.endpoint).map_err(|error| error.to_string())?;
        if parts.https {
            return Ok(());
        }
        if self.creds.is_some() {
            return Err(
                "etcd credentials need an https:// endpoint; over http:// the password is sent unencrypted"
                    .to_string(),
            );
        }
        let loopback = parts.host.eq_ignore_ascii_case("localhost")
            || parts
                .host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err(format!(
                "A remote etcd server needs an https:// endpoint; http:// is allowed only for localhost and loopback addresses: {}",
                self.endpoint
            ));
        }
        Ok(())
    }

    /// Reuses the token when there is one; `None` without credentials.
    fn ensure_token(&self) -> Result<Option<onetdns_core::SecretString>, String> {
        let Some((user, pass)) = &self.creds else {
            return Ok(None);
        };
        {
            let g = self.token.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(t) = g.as_ref() {
                return Ok(Some(t.clone()));
            }
        }
        let body = format!(
            "{{\"name\":{},\"password\":{}}}",
            onetdns_core::json::escape(user),
            onetdns_core::json::escape(pass)
        );
        let resp = self.request("/v3/auth/authenticate", &body, None)?;
        let j = onetdns_core::json::parse(&resp)
            .map_err(|e| format!("Could not parse the etcd authentication response JSON: {e}"))?;
        let token: onetdns_core::SecretString = j
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "The etcd authentication response has no token".to_string())?
            .to_string()
            .into();
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token.clone());
        Ok(Some(token))
    }

    /// Gets a new token and retries once when the server rejects the current one; retrying only
    /// once keeps wrong credentials from signing in endlessly.
    fn request(&self, path: &str, body: &str, _retry: Option<()>) -> Result<String, String> {
        self.check()?;
        let token = if path == "/v3/auth/authenticate" {
            None
        } else {
            self.ensure_token()?
        };
        match http_post(
            &self.endpoint,
            self.connect_addr,
            self.tls.as_ref(),
            path,
            body,
            token.as_deref(),
        ) {
            Ok(resp) => Ok(resp),
            Err(HttpError::Unauthorized) if token.is_some() => {
                *self.token.lock().unwrap_or_else(|p| p.into_inner()) = None;
                let fresh = self.ensure_token()?;
                http_post(
                    &self.endpoint,
                    self.connect_addr,
                    self.tls.as_ref(),
                    path,
                    body,
                    fresh.as_deref(),
                )
                .map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// With `keys_only`, values are left out: change detection needs only keys and revisions, not
    /// the zone text every cycle.
    fn range_body(&self, keys_only: bool) -> String {
        let key = b64(self.prefix.as_bytes());
        let range_end = b64(&prefix_end(self.prefix.as_bytes()));
        if keys_only {
            format!("{{\"key\":\"{key}\",\"range_end\":\"{range_end}\",\"keys_only\":true}}")
        } else {
            format!("{{\"key\":\"{key}\",\"range_end\":\"{range_end}\"}}")
        }
    }

    /// Entries, their count and the highest mod revision; both count and revision are needed to
    /// catch deletes as well as edits.
    fn range(&self, keys_only: bool) -> Result<(Vec<(String, String, u64)>, usize, u64), String> {
        let body = self.request("/v3/kv/range", &self.range_body(keys_only), None)?;
        let j = onetdns_core::json::parse(&body)
            .map_err(|e| format!("Invalid etcd response JSON: {e}"))?;
        let mut kvs = Vec::new();
        let mut max_mod = 0u64;
        if let Some(arr) = j.get("kvs").and_then(|v| v.as_array()) {
            for kv in arr {
                let decode = |field: &str| {
                    kv.get(field)
                        .and_then(|v| v.as_str())
                        .and_then(b64_decode)
                        .and_then(|b| String::from_utf8(b).ok())
                };
                let key = decode("key").unwrap_or_else(|| {
                    onetdns_core::warn!(event = "authority.etcd_key_undecodable", prefix = %self.prefix, "Could not read the key of an etcd entry; skipping this zone");
                    String::new()
                });
                let value = if keys_only {
                    String::new()
                } else {
                    decode("value").unwrap_or_else(|| {
                        onetdns_core::warn!(event = "authority.etcd_value_undecodable", key = %key, "Could not read the value of an etcd entry; skipping this zone");
                        String::new()
                    })
                };
                let mod_rev = num_field(kv, "mod_revision");
                max_mod = max_mod.max(mod_rev);
                kvs.push((key, value, mod_rev));
            }
        }
        let count = kvs.len();
        Ok((kvs, count, max_mod))
    }
}

impl ZoneSource for EtcdZoneSource {
    /// Refuses https without a trust store; TLS without verifying the peer would let any server
    /// feed zones.
    fn load(&self) -> Result<ZoneStore, String> {
        if self.is_https() && self.tls.is_none() {
            return Err("https etcd endpoints need tls_ca (a trust store)".to_string());
        }
        let (kvs, count, max_mod) = self.range(false)?;
        let mut store = ZoneStore::new();
        for (key, value, _) in kvs {
            let origin = key.strip_prefix(&self.prefix).unwrap_or(&key);
            if origin.is_empty() || value.is_empty() {
                continue;
            }
            let z = parse_zone(&value, origin)
                .map_err(|e| format!("Could not parse the DNS zone at etcd key {key}: {e}"))?;
            store.add(z);
        }
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = (count, max_mod);
        Ok(store)
    }

    /// False when the query fails; treating a brief outage as a change would reload every cycle.
    fn changed_since(&self, _last: SystemTime) -> bool {
        let (_, count, max_mod) = match self.range(true) {
            Ok(range) => {
                if self
                    .unreachable
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
                {
                    onetdns_core::info!(event = "authority.etcd_reachable", endpoint = %self.endpoint, "etcd is reachable again; resumed watching zone changes");
                }
                range
            }
            Err(error) => {
                if !self
                    .unreachable
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    onetdns_core::warn!(event = "authority.etcd_unreachable", endpoint = %self.endpoint, %error, "Cannot reach etcd, so zone changes are not being watched; still answering from the zones already loaded");
                }
                return false;
            }
        };
        let seen = *self.seen.lock().unwrap_or_else(|p| p.into_inner());
        (count, max_mod) != seen
    }

    fn describe(&self) -> String {
        format!("etcd({}, prefix={})", self.endpoint, self.prefix)
    }
}

/// etcd sends 64-bit numbers as strings or numbers.
fn num_field(j: &onetdns_core::json::Json, key: &str) -> u64 {
    match j.get(key) {
        Some(v) => v
            .as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| v.as_u64())
            .unwrap_or(0),
        None => 0,
    }
}

/// The prefix with its last byte incremented. When every byte is 0xff there is nothing to
/// increment, and the single 0 byte returned means all keys to etcd.
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    for i in (0..end.len()).rev() {
        if end[i] < 0xff {
            end[i] += 1;
            end.truncate(i + 1);
            return end;
        }
    }
    vec![0]
}

#[derive(Debug)]
enum HttpError {
    /// Kept apart so the caller can drop the token and sign in again.
    Unauthorized,
    Other(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Unauthorized => write!(f, "etcd HTTP 401 (authentication failed)"),
            HttpError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// A new connection per call; etcd is called a few times per reload, so keeping one open is
/// not worth the state. An endpoint given by name needs a connect address, or resolving it could
/// loop back through this server during startup.
fn http_post(
    endpoint: &str,
    connect_addr: Option<SocketAddr>,
    tls: Option<&TrustStore>,
    path: &str,
    body: &str,
    token: Option<&str>,
) -> Result<String, HttpError> {
    let parts = endpoint_parts(endpoint)?;
    let addr = match connect_addr {
        Some(addr) if addr.port() == parts.port => addr,
        Some(addr) => SocketAddr::new(addr.ip(), parts.port),
        None if parts.host.eq_ignore_ascii_case("localhost") => {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), parts.port)
        }
        None => SocketAddr::new(
            parts.host.parse::<IpAddr>().map_err(|_| {
                HttpError::Other(format!(
                    "An etcd server given by host name needs a connection address resolved by the initial DNS lookup: hostname={}",
                    parts.host
                ))
            })?,
            parts.port,
        ),
    };
    let auth = token
        .map(|t| format!("Authorization: {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        parts.authority,
        body.len()
    );
    let deadline = Instant::now() + HTTP_TIMEOUT;
    let mut stream = DeadlineTcp::connect(addr, deadline)
        .map_err(|error| HttpError::Other(format!("{addr}: {error}")))?;

    let resp = if parts.https {
        let roots = tls.ok_or_else(|| {
            HttpError::Other("There is no trust store for the HTTPS connection".into())
        })?;
        let cfg = ClientConfig {
            server_name: parts.host,
            verify_name: true,
            roots: Some(roots.clone()),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut stream, &cfg)
            .map_err(|e| HttpError::Other(format!("etcd TLS handshake failed: {e}")))?;
        conn.write_app(&mut stream, req.as_bytes())
            .map_err(|e| HttpError::Other(format!("etcd TLS write failed: {e}")))?;
        read_tls_response(&mut conn, &mut stream)?
    } else {
        stream
            .write_all(req.as_bytes())
            .map_err(|e| HttpError::Other(e.to_string()))?;
        read_plain_response(&mut stream)?
    };

    parse_http_response(&resp)
}

struct EndpointParts {
    https: bool,
    /// Also the name the TLS certificate is checked against.
    host: String,
    /// Default port filled in when omitted.
    port: u16,
    /// As written, for the Host header.
    authority: String,
}

/// Refuses a path or control characters, which would end up in the Host header.
fn endpoint_parts(endpoint: &str) -> Result<EndpointParts, HttpError> {
    let (https, authority) = endpoint
        .strip_prefix("https://")
        .map(|rest| (true, rest))
        .or_else(|| endpoint.strip_prefix("http://").map(|rest| (false, rest)))
        .ok_or_else(|| {
            HttpError::Other(format!(
                "The etcd endpoint must start with `http://` or `https://`: {endpoint}"
            ))
        })?;
    let authority = authority.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') || authority.chars().any(char::is_control) {
        return Err(HttpError::Other(format!(
            "Invalid etcd endpoint: {endpoint}"
        )));
    }
    let default_port = if https { 443 } else { 80 };
    let (host, port) = crate::split_host_port(authority, default_port)
        .ok_or_else(|| HttpError::Other(format!("Invalid etcd endpoint: {endpoint}")))?;
    Ok(EndpointParts {
        https,
        host,
        port,
        authority: authority.to_string(),
    })
}

/// Stops once Content-Length is satisfied instead of waiting for the peer to close.
fn read_plain_response(stream: &mut DeadlineTcp) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| HttpError::Other(error.to_string()))?;
        if read == 0 {
            break;
        }
        if out.len().saturating_add(read) > MAX_HTTP_RESPONSE {
            return Err(HttpError::Other(
                "etcd HTTP response exceeds the size limit".into(),
            ));
        }
        out.extend_from_slice(&chunk[..read]);
        if response_content_length_complete(&out)? {
            break;
        }
    }
    Ok(out)
}

/// Stops on the same conditions as the plain path.
fn read_tls_response(
    conn: &mut TlsConnection,
    stream: &mut DeadlineTcp,
) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        match conn.read_app(stream) {
            Ok(d) if d.is_empty() => break,
            Ok(d) => {
                if out.len().saturating_add(d.len()) > MAX_HTTP_RESPONSE {
                    return Err(HttpError::Other(
                        "etcd TLS response exceeds the size limit".into(),
                    ));
                }
                out.extend_from_slice(&d);
                if response_content_length_complete(&out)? {
                    break;
                }
            }
            Err(error) => {
                return Err(HttpError::Other(format!(
                    "Could not receive the etcd TLS response: {error}"
                )))
            }
        }
    }
    Ok(out)
}

/// Always false for chunked responses, which are read until close.
fn response_content_length_complete(response: &[u8]) -> Result<bool, HttpError> {
    let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        if response.len() > MAX_HTTP_HEADER {
            return Err(HttpError::Other(
                "etcd HTTP headers exceed the size limit".into(),
            ));
        }
        return Ok(false);
    };
    if split > MAX_HTTP_HEADER {
        return Err(HttpError::Other(
            "etcd HTTP headers exceed the size limit".into(),
        ));
    }
    let head = parse_http_head(&response[..split])?;
    if head.chunked {
        return Ok(false);
    }
    Ok(head
        .content_length
        .is_some_and(|length| response.len() - split - 4 >= length))
}

/// The parts of a response head this client uses.
#[derive(Clone, Copy)]
struct ParsedHttpHead {
    status: u16,
    /// `None` when chunked.
    content_length: Option<usize>,
    chunked: bool,
}

fn valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/// Names must be tokens and values free of control characters; a line break in a value would
/// smuggle in a header.
fn parse_http_field(line: &str) -> Result<(&str, &str), HttpError> {
    if line.len() > MAX_HTTP_HEADER_LINE {
        return Err(HttpError::Other("etcd HTTP header line is too long".into()));
    }
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| HttpError::Other("Malformed HTTP header".into()))?;
    if !valid_http_header_name(name) {
        return Err(HttpError::Other("Invalid HTTP header name".into()));
    }
    if value
        .bytes()
        .any(|byte| byte != b'\t' && (byte < b' ' || byte == 0x7f))
    {
        return Err(HttpError::Other(
            "HTTP header value contains a character that is not allowed".into(),
        ));
    }
    Ok((name, value.trim_matches([' ', '\t'])))
}

/// Accepts HTTP/1.0 and 1.1 only.
fn parse_http_status(line: &str) -> Result<u16, HttpError> {
    if line.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(HttpError::Other(
            "HTTP status line contains a character that is not allowed".into(),
        ));
    }
    let (version, rest) = line
        .split_once(' ')
        .ok_or_else(|| HttpError::Other("Malformed HTTP status line".into()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpError::Other("Unsupported HTTP version".into()));
    }
    let code = rest.split_once(' ').map_or(rest, |(code, _)| code);
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::Other("Invalid HTTP status code".into()));
    }
    code.parse::<u16>()
        .ok()
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| HttpError::Other("Invalid HTTP status code".into()))
}

/// Refuses ambiguous framing: two Content-Lengths, Content-Length with Transfer-Encoding, or a
/// transfer coding other than chunked. Loose checks let this client and intermediaries disagree
/// on body boundaries, which is how smuggling works.
fn parse_http_head(head: &[u8]) -> Result<ParsedHttpHead, HttpError> {
    let head = std::str::from_utf8(head)
        .map_err(|_| HttpError::Other("HTTP header is not valid UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let status = parse_http_status(
        lines
            .next()
            .ok_or_else(|| HttpError::Other("HTTP status line is missing".into()))?,
    )?;
    let mut content_length = None;
    let mut chunked = false;
    let mut header_count = 0usize;
    for line in lines {
        header_count = header_count.saturating_add(1);
        if header_count > MAX_HTTP_HEADERS {
            return Err(HttpError::Other(
                "etcd HTTP response has too many headers".into(),
            ));
        }
        let (name, value) = parse_http_field(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::Other("Duplicate Content-Length".into()));
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError::Other("Invalid Content-Length".into()));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| HttpError::Other("Invalid Content-Length".into()))?;
            if length > MAX_HTTP_BODY {
                return Err(HttpError::Other(
                    "etcd HTTP body exceeds the size limit".into(),
                ));
            }
            content_length = Some(length);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(HttpError::Other(
                    "Unsupported or duplicate Transfer-Encoding".into(),
                ));
            }
            chunked = true;
        }
    }
    if chunked && content_length.is_some() {
        return Err(HttpError::Other(
            "Transfer-Encoding and Content-Length cannot be used together".into(),
        ));
    }
    Ok(ParsedHttpHead {
        status,
        content_length,
        chunked,
    })
}

/// Content-Length must match the body exactly: shorter is truncated, longer has another
/// response mixed in. 401 is returned as its own error for token renewal.
fn parse_http_response(resp: &[u8]) -> Result<String, HttpError> {
    if resp.len() > MAX_HTTP_RESPONSE {
        return Err(HttpError::Other(
            "etcd HTTP response exceeds the size limit".into(),
        ));
    }
    let split = resp
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| HttpError::Other("Malformed HTTP response".into()))?;
    if split > MAX_HTTP_HEADER {
        return Err(HttpError::Other(
            "etcd HTTP headers exceed the size limit".into(),
        ));
    }
    let head = parse_http_head(&resp[..split])?;
    let body = &resp[split + 4..];
    if head.status == 401 {
        return Err(HttpError::Unauthorized);
    }
    if head.status != 200 {
        return Err(HttpError::Other(format!(
            "etcd returned HTTP error {}: {}",
            head.status,
            String::from_utf8_lossy(&body[..body.len().min(200)])
        )));
    }
    let decoded = if head.chunked {
        dechunk(body)?
    } else {
        if let Some(expected) = head.content_length {
            if body.len() != expected {
                return Err(HttpError::Other(format!(
                    "etcd HTTP body length mismatch: expected={expected} actual={}",
                    body.len()
                )));
            }
        }
        if body.len() > MAX_HTTP_BODY {
            return Err(HttpError::Other(
                "etcd HTTP body exceeds the size limit".into(),
            ));
        }
        body.to_vec()
    };
    String::from_utf8(decoded).map_err(|_| HttpError::Other("etcd JSON is not valid UTF-8".into()))
}

/// Reads the size up to any `;` extension. Leading zeros and spaces are refused, since one size
/// written several ways lets intermediaries and this client disagree on boundaries.
fn dechunk(body: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_end = body[pos..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|relative| pos + relative)
            .ok_or_else(|| HttpError::Other("Chunk size line is truncated".into()))?;
        let size_text = std::str::from_utf8(&body[pos..line_end]).map_err(|_| {
            HttpError::Other("Chunk size line has an invalid character encoding".into())
        })?;
        if size_text.bytes().any(|byte| byte < b'!' || byte == 0x7f) {
            return Err(HttpError::Other(
                "Chunk size line contains a character that is not allowed".into(),
            ));
        }
        let size_token = size_text.split(';').next().unwrap_or("");
        if size_token.is_empty() || !size_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HttpError::Other("Invalid chunk size".into()));
        }
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| HttpError::Other("Invalid chunk size".into()))?;
        pos = line_end + 2;
        if size == 0 {
            let trailers = &body[pos..];
            if trailers == b"\r\n" {
                return Ok(out);
            }
            let trailer_end = trailers
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .ok_or_else(|| HttpError::Other("Chunk trailer is truncated".into()))?;
            if trailer_end + 4 != trailers.len() {
                return Err(HttpError::Other("Extra data after the chunked body".into()));
            }
            let trailers = std::str::from_utf8(&trailers[..trailer_end])
                .map_err(|_| HttpError::Other("Chunk trailer has an invalid encoding".into()))?;
            for (index, line) in trailers.split("\r\n").enumerate() {
                if index >= MAX_HTTP_HEADERS {
                    return Err(HttpError::Other("Chunk trailer has too many fields".into()));
                }
                let (name, _) = parse_http_field(line)?;
                if name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                {
                    return Err(HttpError::Other(
                        "Chunk trailers cannot contain framing fields".into(),
                    ));
                }
            }
            return Ok(out);
        }
        let end = pos
            .checked_add(size)
            .filter(|end| *end <= body.len())
            .ok_or_else(|| HttpError::Other("Chunked body is truncated".into()))?;
        if out.len().saturating_add(size) > MAX_HTTP_BODY {
            return Err(HttpError::Other(
                "etcd response body exceeds the size limit".into(),
            ));
        }
        out.extend_from_slice(&body[pos..end]);
        if body.get(end..end + 2) != Some(b"\r\n") {
            return Err(HttpError::Other(
                "Chunk is missing its trailing CRLF".into(),
            ));
        }
        pos = end + 2;
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// etcd's JSON carries keys and values in base64.
fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
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
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn content_length_response_does_not_wait_for_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });

        let started = Instant::now();
        let response = http_post(
            &format!("http://{addr}"),
            None,
            None,
            "/v3/kv/range",
            "{}",
            None,
        )
        .unwrap();
        assert_eq!(response, "{}");
        assert!(started.elapsed() < Duration::from_millis(200));
        server.join().unwrap();
    }

    #[test]
    fn hostname_requires_explicit_bootstrap_address() {
        let error = http_post(
            "http://etcd.invalid:2379",
            None,
            None,
            "/v3/kv/range",
            "{}",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("resolved by the initial DNS lookup"),
            "{error}"
        );
    }

    /// Connects to the given address but keeps the name for the Host header and certificate check.
    #[test]
    fn bootstrap_address_preserves_hostname_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains(&format!("Host: etcd.invalid:{}\r\n", addr.port())));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        });

        let response = http_post(
            &format!("http://etcd.invalid:{}", addr.port()),
            Some(addr),
            None,
            "/v3/kv/range",
            "{}",
            None,
        )
        .unwrap();
        assert_eq!(response, "{}");
        server.join().unwrap();
    }

    #[test]
    fn endpoint_parser_handles_ipv6_and_default_ports() {
        let https = endpoint_parts("https://[::1]:1234/").unwrap();
        assert_eq!(https.host, "::1");
        assert_eq!(https.port, 1234);
        assert_eq!(https.authority, "[::1]:1234");
        assert!(https.https);

        let http = endpoint_parts("http://127.0.0.1").unwrap();
        assert_eq!(http.port, 80);
        assert!(!http.https);
        assert!(endpoint_parts("http://host:0").is_err());
        assert!(endpoint_parts("http://host/path").is_err());
    }

    #[test]
    fn rejects_ambiguous_etcd_http_framing() {
        for response in [
            b"HTTP/1.1\t200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\nX-Test: value\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".as_slice(),
        ] {
            assert!(response_content_length_complete(response).is_err());
            assert!(parse_http_response(response).is_err(), "{response:?}");
        }

        assert!(parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\nsmuggled"
        )
        .is_err());
    }

    /// Minimal etcd for range queries; bumping the returned revision simulates a change.
    fn fake_etcd(zones: Vec<(&'static str, String)>) -> (String, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rev = Arc::new(AtomicU64::new(1));
        let rev2 = rev.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 8192];
                let mut got = Vec::new();

                loop {
                    match s.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            got.extend_from_slice(&buf[..n]);
                            let text = String::from_utf8_lossy(&got);
                            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                                let cl: usize = head
                                    .lines()
                                    .find_map(|l| {
                                        let (k, v) = l.split_once(':')?;
                                        k.eq_ignore_ascii_case("content-length")
                                            .then(|| v.trim().parse().ok())?
                                    })
                                    .unwrap_or(0);
                                if body.len() >= cl {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let req = String::from_utf8_lossy(&got).to_string();
                let keys_only = req.contains("\"keys_only\":true");
                let r = rev2.load(Ordering::SeqCst);
                let kvs: Vec<String> = zones
                    .iter()
                    .map(|(origin, text)| {
                        let key = b64(format!("/onetdns/zones/{origin}").as_bytes());
                        if keys_only {
                            format!("{{\"key\":\"{key}\",\"mod_revision\":\"{r}\"}}")
                        } else {
                            format!(
                                "{{\"key\":\"{key}\",\"value\":\"{}\",\"mod_revision\":\"{r}\"}}",
                                b64(text.as_bytes())
                            )
                        }
                    })
                    .collect();
                let body = format!(
                    "{{\"header\":{{\"revision\":\"{r}\"}},\"kvs\":[{}],\"count\":\"{}\"}}",
                    kvs.join(","),
                    zones.len()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), rev)
    }

    /// A server certificate for `localhost`, and the DER to trust it by.
    fn self_signed_localhost() -> (onetdns_tls::ServerConfig, Vec<u8>) {
        use p256::pkcs8::DecodePrivateKey;

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        let config = onetdns_tls::ServerConfig {
            cert_chain: vec![cert_der.clone()],
            sign_scheme: 0x0403,
            sign: std::sync::Arc::new(move |content: &[u8]| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn: vec![],
            client_ca: None,
            resumption: None,
        };
        (config, cert_der)
    }

    /// etcd over TLS requiring authentication: issues a token and rejects requests without it.
    /// Returns the endpoint, the request heads it saw, and the DER to trust.
    fn fake_etcd_auth(
        zones: Vec<(&'static str, String)>,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>, Vec<u8>) {
        let (server_config, ca_der) = self_signed_localhost();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let observed: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let obs2 = observed.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let Ok(mut conn) = onetdns_tls::server_handshake(&mut s, &server_config) else {
                    continue;
                };
                let mut got = Vec::new();
                loop {
                    match conn.read_app(&mut s) {
                        Ok(data) if !data.is_empty() => {
                            got.extend_from_slice(&data);
                            let text = String::from_utf8_lossy(&got);
                            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                                let cl: usize = head
                                    .lines()
                                    .find_map(|l| {
                                        let (k, v) = l.split_once(':')?;
                                        k.eq_ignore_ascii_case("content-length")
                                            .then(|| v.trim().parse().ok())?
                                    })
                                    .unwrap_or(0);
                                if body.len() >= cl {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                let req = String::from_utf8_lossy(&got).to_string();
                let head = req.split("\r\n\r\n").next().unwrap_or("").to_string();
                obs2.lock().unwrap().push(head.clone());
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                let body = if path == "/v3/auth/authenticate" {
                    "{\"token\":\"tok-12345\"}".to_string()
                } else if !head.contains("Authorization: tok-12345") {
                    let b = "{\"error\":\"unauthenticated\"}";
                    let resp = format!(
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    );
                    let _ = conn.write_app(&mut s, resp.as_bytes());
                    continue;
                } else {
                    let keys_only = req.contains("\"keys_only\":true");
                    let r = 1;
                    let kvs: Vec<String> = zones
                        .iter()
                        .map(|(origin, text)| {
                            let key = b64(format!("/onetdns/zones/{origin}").as_bytes());
                            if keys_only {
                                format!("{{\"key\":\"{key}\",\"mod_revision\":\"{r}\"}}")
                            } else {
                                format!(
                                    "{{\"key\":\"{key}\",\"value\":\"{}\",\"mod_revision\":\"{r}\"}}",
                                    b64(text.as_bytes())
                                )
                            }
                        })
                        .collect();
                    format!(
                        "{{\"kvs\":[{}],\"count\":\"{}\"}}",
                        kvs.join(","),
                        zones.len()
                    )
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_app(&mut s, resp.as_bytes());
            }
        });
        (format!("https://localhost:{port}"), observed, ca_der)
    }

    fn zone_text(origin: &str) -> String {
        format!(
            "$ORIGIN {origin}.\n$TTL 300\n@ IN SOA ns1 admin 3 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n"
        )
    }

    #[test]
    fn loads_zones_from_etcd_and_detects_changes() {
        let (endpoint, rev) = fake_etcd(vec![
            ("etcd-a.test", zone_text("etcd-a.test")),
            ("etcd-b.test", zone_text("etcd-b.test")),
        ]);
        let src = EtcdZoneSource::with_default_prefix(endpoint);
        let store = src.load().expect("etcd 로드");
        assert_eq!(store.zones().len(), 2);
        assert!(store
            .zones()
            .iter()
            .any(|z| z.origin().to_ascii_lower() == "etcd-a.test"));

        let resp = store
            .query(
                &crate::Name::from_str("ns1.etcd-b.test").unwrap(),
                crate::RecordType::A,
            )
            .expect("권한 응답");
        assert_eq!(resp.rcode, 0);

        assert!(
            !src.changed_since(SystemTime::now()),
            "revision 동일: 변경 없음"
        );

        rev.fetch_add(1, Ordering::SeqCst);
        assert!(
            src.changed_since(SystemTime::now()),
            "revision 증가: 변경 감지"
        );
        let _ = src.load().expect("재로드");
        assert!(!src.changed_since(SystemTime::now()), "재로드 후 변경 없음");
    }

    #[test]
    fn rejects_https_without_trust_store() {
        let src = EtcdZoneSource::with_default_prefix("https://127.0.0.1:2379");
        let err = match src.load() {
            Err(e) => e,
            Ok(_) => panic!("신뢰 스토어 없는 https는 거부되어야"),
        };
        assert!(err.contains("tls_ca"), "{err}");
    }

    /// Gets a token, reuses it, and signs in again when it is rejected.
    #[test]
    fn auth_token_flow() {
        let (endpoint, observed, ca_der) =
            fake_etcd_auth(vec![("auth.test", zone_text("auth.test"))]);
        let password = onetdns_core::SecretString::from("pw");
        let password_ptr = password.as_ptr();
        let src = EtcdZoneSource::with_default_prefix(endpoint)
            .with_tls(TrustStore::from_ders([ca_der.as_slice()]))
            .with_auth("root", password);
        assert_eq!(src.creds.as_ref().unwrap().1.as_ptr(), password_ptr);
        let store = src.load().expect("인증 후 로드");
        assert_eq!(store.zones().len(), 1);
        assert_eq!(
            format!(
                "{:?}",
                src.token.lock().unwrap().as_ref().expect("발급 토큰")
            ),
            "<redacted>"
        );

        let seen = observed.lock().unwrap();
        assert!(
            seen.iter().any(|h| h.contains("Authorization: tok-12345")),
            "range에 토큰 부착"
        );
        assert!(
            seen.iter().any(|h| h.contains("/v3/auth/authenticate")),
            "토큰 발급 호출"
        );
    }

    #[test]
    fn plain_http_reaches_only_loopback_and_never_carries_credentials() {
        for endpoint in [
            "http://127.0.0.1:2379",
            "http://localhost:2379",
            "http://[::1]:2379",
            "https://etcd.example:2379",
        ] {
            assert!(
                EtcdZoneSource::with_default_prefix(endpoint)
                    .check()
                    .is_ok(),
                "{endpoint} was refused"
            );
        }
        for endpoint in ["http://192.0.2.10:2379", "http://etcd.example:2379"] {
            assert!(
                EtcdZoneSource::with_default_prefix(endpoint)
                    .check()
                    .is_err(),
                "{endpoint} was accepted for plain http"
            );
        }
        assert!(
            EtcdZoneSource::with_default_prefix("https://etcd.example:2379")
                .with_auth("root", "pw")
                .check()
                .is_ok()
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let src = EtcdZoneSource::with_default_prefix(endpoint).with_auth("root", "pw");
        let error = src.load().err().expect("credentials over http were used");
        assert!(error.contains("https://"), "{error}");
        assert!(
            listener.accept().is_err(),
            "the client connected to send the password over plain http"
        );
    }

    #[test]
    fn https_etcd_self_tls() {
        use onetdns_tls::server_handshake;

        let (scfg, ca_der) = self_signed_localhost();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = format!(
            "{{\"kvs\":[{{\"key\":\"{}\",\"value\":\"{}\",\"mod_revision\":\"1\"}}],\"count\":\"1\"}}",
            b64(b"/onetdns/zones/tls.test"),
            b64(zone_text("tls.test").as_bytes())
        );
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                if let Ok(mut conn) = server_handshake(&mut s, &scfg) {
                    let _ = conn.read_app(&mut s);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = conn.write_app(&mut s, resp.as_bytes());
                }
            }
        });

        let endpoint = format!("https://localhost:{port}");
        let src = EtcdZoneSource::with_default_prefix(endpoint)
            .with_tls(TrustStore::from_ders([ca_der.as_slice()]));
        let store = src.load().expect("HTTPS etcd 로드");
        assert_eq!(store.zones().len(), 1);
        assert!(store
            .zones()
            .iter()
            .any(|z| z.origin().to_ascii_lower() == "tls.test"));
    }

    #[test]
    fn b64_roundtrip_and_prefix_end() {
        assert_eq!(b64(b"abc"), "YWJj");
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(
            b64_decode(&b64(b"/onetdns/zones/x.test")).unwrap(),
            b"/onetdns/zones/x.test"
        );
        assert_eq!(prefix_end(b"/a/"), b"/a0".to_vec());
        assert_eq!(prefix_end(&[0x2f, 0xff]), vec![0x30]);
        assert_eq!(prefix_end(&[0xff, 0xff]), vec![0]);
    }

    #[test]
    fn dechunk_decodes() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n4\r\n bye\r\n0\r\n\r\n").unwrap(),
            b"hello bye"
        );
    }
}

/// Panic sweep of the HTTP parsers, which the integration sweep cannot reach inside the crate.
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    #[test]
    fn http_parsers_never_panic_on_malformed_bytes() {
        let seed = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n{\"kvs\":[],\"more\":0}\r\n0\r\n\r\n";

        let mut rng = Rng::new(0xE7CD_0000_0000_0003);
        for index in 0..20_000u32 {
            let bytes = if index % 3 == 0 {
                rng.rand_bytes(300)
            } else {
                havoc(&mut rng, seed)
            };
            let _ = parse_http_response(&bytes);
            let _ = parse_http_head(&bytes);
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                let _ = parse_http_field(line);
                let _ = parse_http_status(line);
            }
        }
    }
}
