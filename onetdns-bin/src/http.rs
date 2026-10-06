/*!
 * @brief HTTP/1.1 클라이언트.
 *
 * @details 인증서 발급과 목록 내려받기에 쓴다. 외부 클라이언트를 들이지 않으므로
 *          여기서 요청·응답·전송 계층을 다 다룬다.
 * @warning 이름 해석을 운영체제에 맡기지 않는다. 이 서버가 그 기계의 DNS일 수 있어 순환이
 *          된다. 부를 쪽에서 해석 방법을 넘겨야 한다.
 * @note 응답 구획을 애매하게 만드는 것은 전부 거부한다. 길이와 조각 전송이 함께 오거나
 *       길이가 겹쳐 오면, 이 서버와 중간 장치가 응답 경계를 다르게 읽어 다음 응답이
 *       앞 응답의 본문으로 섞인다.
 */

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_tls::{client_handshake, ClientConfig, TlsError, TrustStore};

/** @brief 받아들일 응답 크기 상한. */
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;

/** @brief 따라갈 넘김 횟수. 서로 가리키는 순환에서 멈추게 한다. */
const MAX_REDIRECTS: usize = 6;
/** @brief 헤더 전체 크기 상한. */
const MAX_HEADER_BYTES: usize = 64 * 1024;
/** @brief 헤더 줄 수 상한. */
const MAX_HEADER_COUNT: usize = 200;
/** @brief 헤더 한 줄 길이 상한. */
const MAX_HEADER_LINE: usize = 8 * 1024;

/**
 * @brief 이름을 주소로 푸는 방법.
 * @warning 운영체제 해석을 쓰지 않으려는 것이다. 이 서버가 그 기계의 DNS면 순환이 된다.
 */
pub type HostResolver =
    Arc<dyn Fn(&str, Duration) -> Result<Vec<IpAddr>, String> + Send + Sync + 'static>;

#[derive(Debug)]
/** @brief 요청이 실패한 까닭. */
pub enum HttpError {
    /** @brief 주소 표기가 어긋났다. */
    Url(String),
    /** @brief 접속하지 못했다. */
    Connect(String),
    /** @brief TLS 핸드셰이크에 실패했다. */
    Tls(String),
    /** @brief 주고받는 중 오류가 났다. */
    Io(String),
    /** @brief 응답이 프로토콜에 맞지 않는다. */
    Protocol(String),
    /** @brief 넘김을 너무 많이 따라갔다. */
    TooManyRedirects,
}

impl std::fmt::Display for HttpError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Url(s) => write!(f, "Invalid URL: {s}"),
            HttpError::Connect(s) => write!(f, "Could not connect: {s}"),
            HttpError::Tls(s) => write!(f, "TLS error: {s}"),
            HttpError::Io(s) => write!(f, "I/O error: {s}"),
            HttpError::Protocol(s) => write!(f, "HTTP protocol error: {s}"),
            HttpError::TooManyRedirects => write!(f, "Followed too many HTTP redirects"),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Clone, Copy)]
/** @brief 주소 형식. */
enum Scheme {
    /** @brief 평문. */
    Http,
    /** @brief TLS. */
    Https,
}

/** @brief 쪼개 둔 주소. */
struct Url {
    /** @brief 평문인지 TLS인지. */
    scheme: Scheme,
    /** @brief 붙을 대상 이름. */
    host: String,
    /** @brief 붙을 포트. */
    port: u16,
    /** @brief 요청할 경로. */
    path: String,
}

/**
 * @brief 주소 문자열을 쪼갠다.
 * @warning 포트와 대괄호 표기를 엄격히 본다. 애매한 것을 받아들이면 이 서버가 뜻한 곳과
 *          다른 곳에 접속한다.
 */
fn parse_url(s: &str) -> Result<Url, HttpError> {
    if s.is_empty()
        || s.chars()
            .any(|ch| ch.is_ascii_whitespace() || ch.is_control())
    {
        return Err(HttpError::Url(
            "URL contains spaces or control characters".to_string(),
        ));
    }
    let (scheme, rest) = if let Some(r) = s.strip_prefix("http://") {
        (Scheme::Http, r)
    } else if let Some(r) = s.strip_prefix("https://") {
        (Scheme::Https, r)
    } else {
        return Err(HttpError::Url(format!("URL has no scheme: {s}")));
    };

    let split = rest
        .char_indices()
        .find(|(_, ch)| matches!(ch, '/' | '?' | '#'))
        .map(|(index, _)| index);
    let (authority, suffix) = match split {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(HttpError::Url(format!("Invalid authority: {s}")));
    }
    let path_without_fragment = suffix.split('#').next().unwrap_or("");
    let path = if path_without_fragment.is_empty() {
        "/".to_string()
    } else if path_without_fragment.starts_with('?') {
        format!("/{path_without_fragment}")
    } else {
        path_without_fragment.to_string()
    };
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| HttpError::Url(format!("Malformed IPv6 brackets: {authority}")))?;
        let host = &bracketed[..close];
        let tail = &bracketed[close + 1..];
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')
                .ok_or_else(|| HttpError::Url(format!("Invalid IPv6 authority: {authority}")))?
                .parse::<u16>()
                .map_err(|_| HttpError::Url(format!("Invalid port: {authority}")))?
        };
        (host.to_string(), port)
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| HttpError::Url(format!("Invalid authority: {authority}")))?;
        if host.is_empty() {
            return Err(HttpError::Url(format!("URL has no host: {authority}")));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| HttpError::Url(format!("Invalid port: {authority}")))?;
        (host.to_string(), port)
    } else if authority.contains(':') {
        return Err(HttpError::Url(format!(
            "IPv6 addresses need brackets: {authority}"
        )));
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() || !host.is_ascii() || port == 0 {
        return Err(HttpError::Url(format!("Invalid host or port: {authority}")));
    }
    Ok(Url {
        scheme,
        host,
        port,
        path,
    })
}

/** @brief GET 요청을 짓기 시작한다. */
pub fn get(url: &str) -> Req {
    Req::new("GET", url)
}

/** @brief POST 요청을 짓기 시작한다. */
pub fn post(url: &str) -> Req {
    Req::new("POST", url)
}

/** @brief 보낼 요청. */
pub struct Req {
    /** @brief 요청 방식. */
    method: &'static str,
    /** @brief 요청할 주소. */
    url: String,
    /** @brief 붙일 헤더들. */
    headers: Vec<(String, String)>,
    /** @brief 보낼 본문. */
    body: Vec<u8>,
    /** @brief 요청 전체의 데드라인. */
    timeout: Duration,
    /** @brief 받아들일 응답 크기 상한. */
    max_response: u64,
    /** @brief 내부망을 가리키는 대상을 거부할지. */
    deny_private_targets: bool,
    /** @brief 이름을 풀 방법. 없으면 이름으로 요청할 수 없다. */
    resolver: Option<HostResolver>,
}

impl Req {
    /** @brief 기본값으로 요청을 만든다. */
    fn new(method: &'static str, url: &str) -> Self {
        Req {
            method,
            url: url.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(30),
            max_response: MAX_RESPONSE,
            deny_private_targets: false,
            resolver: None,
        }
    }

    /** @brief 헤더를 붙인다. */
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    /** @brief 요청 전체의 데드라인. */
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    /** @brief 받아들일 응답 크기 상한. */
    pub fn max_response(mut self, bytes: u64) -> Self {
        self.max_response = bytes.max(1);
        self
    }

    /**
     * @brief 내부망을 가리키는 대상을 거부한다.
     * @warning 밖에서 온 주소로 요청할 때 켠다. 켜지 않으면 그 주소로 이 서버의 내부망을
     *          훑게 된다.
     */
    pub fn deny_private_targets(mut self) -> Self {
        self.deny_private_targets = true;
        self
    }

    /** @brief 이름을 풀 방법을 지정한다. */
    pub fn resolver(mut self, resolver: HostResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /** @brief 본문을 문자열로 넣는다. */
    pub fn body_string(mut self, s: &str) -> Self {
        self.body = s.as_bytes().to_vec();
        self
    }

    /** @brief 본문을 바이트로 넣는다. */
    pub fn body_bytes(mut self, b: Vec<u8>) -> Self {
        self.body = b;
        self
    }

    /**
     * @brief 요청을 보내고 응답을 받는다. 넘김은 상한까지 따라간다.
     * @note 다른 곳으로 넘어가면 붙인 헤더를 그대로 전달하지 않는다. 인증 정보가
     *       엉뚱한 서버로 넘어간다.
     */
    pub fn call(mut self) -> Result<Resp, HttpError> {
        let deadline = Instant::now() + self.timeout;
        for _ in 0..MAX_REDIRECTS {
            let resp = send_one(&self, deadline)?;
            if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = resp.header("location") {
                    let next = resolve_redirect(&self.url, &loc)?;
                    let current_url = parse_url(&self.url)?;
                    let next_url = parse_url(&next)?;
                    if matches!(current_url.scheme, Scheme::Https)
                        && matches!(next_url.scheme, Scheme::Http)
                    {
                        return Err(HttpError::Protocol(
                            "A redirect from HTTPS to an unencrypted HTTP URL is not allowed"
                                .to_string(),
                        ));
                    }
                    if !same_origin(&current_url, &next_url) {
                        self.headers.retain(|(name, _)| {
                            !name.eq_ignore_ascii_case("authorization")
                                && !name.eq_ignore_ascii_case("proxy-authorization")
                                && !name.eq_ignore_ascii_case("cookie")
                        });
                    }
                    self.url = next;
                    if resp.status == 303
                        || (matches!(resp.status, 301 | 302) && self.method == "POST")
                    {
                        self.method = "GET";
                        self.body.clear();
                    }
                    continue;
                }
            }
            return Ok(resp);
        }
        Err(HttpError::TooManyRedirects)
    }
}

/** @brief 받은 응답. */
pub struct Resp {
    /** @brief 응답 상태. */
    pub status: u16,
    /** @brief 응답 헤더들. */
    pub headers: Vec<(String, String)>,
    /** @brief 응답 본문. */
    pub body: Vec<u8>,
}

impl Resp {
    /** @brief 이 헤더의 값. 대소문자를 가리지 않는다. */
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    /** @brief 본문을 문자열로. */
    pub fn into_string(self) -> Result<String, HttpError> {
        String::from_utf8(self.body)
            .map_err(|e| HttpError::Protocol(format!("Body is not UTF-8: {e}")))
    }
}

/** @brief 넘김 없이 요청 하나를 주고받는다. */
fn send_one(req: &Req, deadline: Instant) -> Result<Resp, HttpError> {
    let url = parse_url(&req.url)?;
    let tcp = connect(
        &url.host,
        url.port,
        deadline,
        req.deny_private_targets,
        req.resolver.as_ref(),
    )?;
    let request = build_request(req, &url)?;
    let raw = match url.scheme {
        Scheme::Http => send_plain(tcp, &request, req.max_response)?,
        Scheme::Https => send_tls(&url.host, tcp, &request, req.max_response)?,
    };
    parse_response(&raw)
}

/**
 * @brief 접속한다.
 * @warning 이름은 넘겨받은 방법으로만 푼다. 운영체제에 맡기면 자기 자신에게 물어
 *          순환이 된다.
 */
fn connect(
    host: &str,
    port: u16,
    deadline: Instant,
    deny_private_targets: bool,
    resolver: Option<&HostResolver>,
) -> Result<DeadlineTcp, HttpError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            HttpError::Connect(format!("{host}: the request took longer than allowed"))
        })?;
    let lookup_host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = if let Ok(ip) = lookup_host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else if lookup_host.eq_ignore_ascii_case("localhost") {
        vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)]
    } else if let Some(resolve) = resolver {
        resolve(lookup_host, remaining.min(Duration::from_secs(8)))
            .map_err(|error| HttpError::Connect(format!("{host}: {error}")))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    } else {
        return Err(HttpError::Connect(format!(
            "{host}: requesting by host name needs a separate DNS server for lookups; this prevents a loop that calls the operating system DNS again"
        )));
    };
    if addrs.is_empty() {
        return Err(HttpError::Connect(format!("Could not resolve {host}")));
    }
    if deny_private_targets && addrs.iter().any(|addr| blocked_target(addr.ip())) {
        return Err(HttpError::Connect(format!(
            "Refusing a private, loopback, or special-purpose address: {host}"
        )));
    }
    let mut last = None;
    for addr in addrs {
        if onetdns_core::tcp::time_left(deadline).is_err() {
            break;
        }
        match DeadlineTcp::connect(addr, deadline) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(e),
        }
    }
    Err(HttpError::Connect(
        last.map(|e| e.to_string())
            .unwrap_or_else(|| format!("Could not connect to {host}")),
    ))
}

/**
 * @brief 이 주소로 접속하면 안 되는지.
 * @details 내부망, 루프백, 특수 목적 대역을 막는다. IPv4를 담은 IPv6 표기는 먼저 펴서
 *          본다. 펴지 않으면 같은 주소를 다른 표기로 적어 통과한다.
 */
fn blocked_target(ip: std::net::IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0)
                || (a == 192 && b == 2)
                || (a == 198 && (18..=19).contains(&b))
                || (a == 198 && b == 51)
                || (a == 203 && b == 0 && c == 113)
                || a >= 240
        }
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || octets[..4] == [0x20, 0x01, 0x0d, 0xb8]
        }
    }
}

/** @brief 요청에 담을 대상 표기. 기본 포트면 포트를 적지 않는다. */
fn host_header(url: &Url) -> String {
    let default = matches!(url.scheme, Scheme::Http if url.port == 80)
        || matches!(url.scheme, Scheme::Https if url.port == 443);
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    if default {
        host
    } else {
        format!("{host}:{}", url.port)
    }
}

/**
 * @brief 헤더 이름으로 써도 되는 글자만 들었는지.
 * @warning 줄바꿈이 든 이름을 그대로 실으면 이 서버가 보내는 요청에 남이 헤더를 끼워 넣는다.
 */
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/**
 * @brief 헤더 구간의 줄바꿈이 짝을 이루는지.
 * @warning 홀로 선 줄바꿈을 허용하면 이 서버와 중간 장치가 응답 경계를 다르게 읽는다.
 */
fn validate_http_head(head: &[u8]) -> Result<(), HttpError> {
    for (index, byte) in head.iter().copied().enumerate() {
        let paired = match byte {
            b'\r' => head.get(index + 1) == Some(&b'\n'),
            b'\n' => index > 0 && head.get(index - 1) == Some(&b'\r'),
            _ => true,
        };
        if !paired {
            return Err(HttpError::Protocol(
                "HTTP response header lines must end with CRLF".into(),
            ));
        }
    }
    Ok(())
}

/** @brief 헤더 한 줄을 이름과 값으로. */
fn parse_header_line(line: &[u8]) -> Result<(&str, &str), HttpError> {
    let line = trim_cr(line);
    if line
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        return Err(HttpError::Protocol(
            "Folded multi-line HTTP headers are not allowed".into(),
        ));
    }
    let index = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or_else(|| HttpError::Protocol("Malformed HTTP header".into()))?;
    let name = std::str::from_utf8(&line[..index])
        .map_err(|_| HttpError::Protocol("Header name encoding".into()))?;
    if !valid_header_name(name) {
        return Err(HttpError::Protocol("Invalid HTTP header name".into()));
    }
    let value = &line[index + 1..];
    if value
        .iter()
        .any(|&byte| byte != b'\t' && (byte < b' ' || byte == 0x7f))
    {
        return Err(HttpError::Protocol(
            "HTTP header value contains a character that is not allowed".into(),
        ));
    }
    let value = std::str::from_utf8(value)
        .map_err(|_| HttpError::Protocol("Header value encoding".into()))?
        .trim_matches([' ', '\t']);
    Ok((name, value))
}

/** @brief 두 주소가 같은 곳인지. 넘어갈 때 헤더를 들고 갈지 정한다. */
fn same_origin(left: &Url, right: &Url) -> bool {
    matches!(
        (&left.scheme, &right.scheme),
        (Scheme::Http, Scheme::Http) | (Scheme::Https, Scheme::Https)
    ) && left.host.eq_ignore_ascii_case(&right.host)
        && left.port == right.port
}

/** @brief 보낼 요청 바이트를 만든다. */
fn build_request(req: &Req, url: &Url) -> Result<Vec<u8>, HttpError> {
    let mut s = format!("{} {} HTTP/1.1\r\n", req.method, url.path);
    s.push_str(&format!("Host: {}\r\n", host_header(url)));
    s.push_str(&format!("User-Agent: {}/0.0\r\n", crate::PRODUCT_NAME));
    s.push_str("Accept: */*\r\n");
    s.push_str("Connection: close\r\n");
    for (k, v) in &req.headers {
        if !valid_header_name(k)
            || v.contains('\r')
            || v.contains('\n')
            || matches!(
                k.to_ascii_lowercase().as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            )
        {
            return Err(HttpError::Protocol(format!(
                "Request header not allowed: {k}"
            )));
        }
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    if !req.body.is_empty() {
        s.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    s.push_str("\r\n");
    let mut bytes = s.into_bytes();
    bytes.extend_from_slice(&req.body);
    Ok(bytes)
}

/** @brief 평문으로 주고받는다. */
fn send_plain(
    mut tcp: DeadlineTcp,
    request: &[u8],
    max_response: u64,
) -> Result<Vec<u8>, HttpError> {
    tcp.write_all(request)
        .map_err(|e| HttpError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut completion = ResponseCompletion::default();
    loop {
        let read = tcp
            .read(&mut chunk)
            .map_err(|e| HttpError::Io(e.to_string()))?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        ensure_response_limit(&buf, max_response)?;
        if completion.is_complete(&buf, max_response)? {
            break;
        }
    }
    Ok(buf)
}

/** @brief 이 기계의 신뢰 루트 목록. */
fn system_roots() -> &'static TrustStore {
    /** @brief 한 번만 읽어 둔다. */
    static ROOTS: OnceLock<TrustStore> = OnceLock::new();
    ROOTS.get_or_init(TrustStore::system)
}

/** @brief TLS 위에서 주고받는다. */
fn send_tls(
    host: &str,
    mut tcp: DeadlineTcp,
    request: &[u8],
    max_response: u64,
) -> Result<Vec<u8>, HttpError> {
    let cfg = ClientConfig {
        server_name: host.to_string(),
        verify_name: true,
        roots: Some(system_roots().clone()),
        alpn: vec![b"http/1.1".to_vec()],
        ..Default::default()
    };
    let mut conn = client_handshake(&mut tcp, &cfg).map_err(|e| HttpError::Tls(e.to_string()))?;
    conn.write_app(&mut tcp, request)
        .map_err(|e| HttpError::Tls(e.to_string()))?;
    let mut buf = Vec::new();
    let mut completion = ResponseCompletion::default();

    loop {
        let chunk = match conn.read_app(&mut tcp) {
            Ok(chunk) => chunk,
            Err(TlsError::CloseNotify) if !buf.is_empty() => break,
            Err(TlsError::Io)
                if !buf.is_empty() && completion.is_complete(&buf, max_response)? =>
            {
                break
            }
            Err(TlsError::Io) => return Err(HttpError::Tls(
                "The connection closed without TLS close_notify, so the response may be incomplete"
                    .into(),
            )),
            Err(e) => {
                return Err(HttpError::Tls(format!(
                    "Could not receive the TLS response: {e}"
                )))
            }
        };
        if chunk.is_empty() {
            break;
        }
        buf.extend_from_slice(&chunk);
        ensure_response_limit(&buf, max_response)?;
        if completion.is_complete(&buf, max_response)? {
            break;
        }
    }
    Ok(buf)
}

/** @brief 받은 양이 상한을 넘지 않았는지. */
fn ensure_response_limit(raw: &[u8], max_response: u64) -> Result<(), HttpError> {
    if raw.len() as u64 > max_response {
        Err(HttpError::Protocol(format!(
            "Response exceeds the size limit of {} MiB",
            max_response / 1024 / 1024
        )))
    } else {
        Ok(())
    }
}

/** @brief 본 응답 앞에 올 수 있는 중간 응답 수. */
const MAX_INTERIM_RESPONSES: usize = 8;

/**
 * @brief 중간 응답들을 건너뛴 본 응답의 시작 위치.
 * @warning 중간 응답에는 본문 구획 헤더가 올 수 없다. 허용하면 그것을 본문 경계로
 *          읽어 응답 하나가 둘로 쪼개진다.
 * @return 본 응답의 시작. 아직 헤더가 다 안 왔으면 없다.
 */
fn final_response_start(raw: &[u8]) -> Result<Option<usize>, HttpError> {
    let mut start = 0usize;
    for _ in 0..=MAX_INTERIM_RESPONSES {
        let Some(relative_sep) = find(&raw[start..], b"\r\n\r\n") else {
            if raw.len().saturating_sub(start) > MAX_HEADER_BYTES {
                return Err(HttpError::Protocol(
                    "Response headers exceed the size limit".into(),
                ));
            }
            return Ok(None);
        };
        if relative_sep > MAX_HEADER_BYTES {
            return Err(HttpError::Protocol(
                "Response headers exceed the size limit".into(),
            ));
        }
        let sep = start
            .checked_add(relative_sep)
            .ok_or_else(|| HttpError::Protocol("Response offset calculation overflowed".into()))?;
        let head = &raw[start..sep];
        validate_http_head(head)?;
        let status_line = head
            .split(|&byte| byte == b'\n')
            .next()
            .ok_or_else(|| HttpError::Protocol("HTTP status line is missing".into()))?;
        let status = parse_status(trim_cr(status_line))?;
        if status == 101 {
            return Err(HttpError::Protocol(
                "HTTP protocol switch responses are not supported".into(),
            ));
        }
        if (100..200).contains(&status) {
            let mut header_count = 0usize;
            for line in head.split(|&byte| byte == b'\n').skip(1) {
                header_count = header_count.saturating_add(1);
                if header_count > MAX_HEADER_COUNT || line.len() > MAX_HEADER_LINE {
                    return Err(HttpError::Protocol(
                        "Informational response has too many headers or too long a line".into(),
                    ));
                }
                let (name, _) = parse_header_line(line)?;
                if name.eq_ignore_ascii_case("content-length")
                    || name.eq_ignore_ascii_case("transfer-encoding")
                {
                    return Err(HttpError::Protocol(
                        "Informational responses cannot use body framing headers".into(),
                    ));
                }
            }
            start = sep.checked_add(4).ok_or_else(|| {
                HttpError::Protocol("Response offset calculation overflowed".into())
            })?;
            continue;
        }
        return Ok(Some(start));
    }
    Err(HttpError::Protocol(
        "Too many chained HTTP 1xx responses".into(),
    ))
}

#[derive(Clone, Copy)]
/** @brief 본문 경계를 정하는 방식. */
enum ResponseFraming {
    /** @brief 본문이 없다. */
    Bodyless,
    /** @brief 길이로 경계를 정한다. */
    ContentLength { body_start: usize, length: usize },
    /** @brief 조각으로 나눠 보낸다. */
    Chunked { body_start: usize },
    /** @brief 연결이 닫힐 때까지가 본문이다. */
    CloseDelimited,
}

#[derive(Default)]
/** @brief 응답을 다 받았는지 판단하는 상태. */
struct ResponseCompletion {
    /** @brief 알아낸 경계 방식. 아직 헤더가 안 왔으면 없다. */
    framing: Option<ResponseFraming>,
    /** @brief 조각을 어디까지 확인했는지. 매번 처음부터 보지 않으려는 것이다. */
    chunk_position: usize,
}

impl ResponseCompletion {
    /**
     * @brief 지금까지 받은 것으로 응답이 끝났는지.
     * @note 조각 전송은 이미 확인한 위치부터 이어 본다. 매번 처음부터 훑으면 조각이
     *       늘수록 확인 비용이 제곱으로 는다.
     */
    fn is_complete(&mut self, raw: &[u8], max_response: u64) -> Result<bool, HttpError> {
        if self.framing.is_none() {
            self.framing = response_framing(raw, max_response)?;
        }
        match self.framing {
            None | Some(ResponseFraming::CloseDelimited) => Ok(false),
            Some(ResponseFraming::Bodyless) => Ok(true),
            Some(ResponseFraming::ContentLength { body_start, length }) => Ok(raw
                .len()
                .checked_sub(body_start)
                .is_some_and(|actual| actual >= length)),
            Some(ResponseFraming::Chunked { body_start }) => {
                let body = raw.get(body_start..).ok_or_else(|| {
                    HttpError::Protocol("HTTP body offset is outside the response".into())
                })?;
                Ok(chunked_wire_len_from(body, &mut self.chunk_position)?.is_some())
            }
        }
    }
}

/**
 * @brief 헤더에서 본문 경계 방식을 읽는다.
 * @warning 길이와 조각 전송이 함께 오거나 길이가 겹쳐 오면 거부한다. 어느 쪽을 믿느냐가
 *          장치마다 달라 응답 하나를 서로 다르게 쪼갠다.
 */
fn response_framing(raw: &[u8], max_response: u64) -> Result<Option<ResponseFraming>, HttpError> {
    let Some(start) = final_response_start(raw)? else {
        return Ok(None);
    };
    let final_raw = &raw[start..];
    let Some(sep) = find(final_raw, b"\r\n\r\n") else {
        if final_raw.len() > MAX_HEADER_BYTES {
            return Err(HttpError::Protocol(
                "Response headers exceed the size limit".into(),
            ));
        }
        return Ok(None);
    };
    if sep > MAX_HEADER_BYTES {
        return Err(HttpError::Protocol(
            "Response headers exceed the size limit".into(),
        ));
    }

    let head = &final_raw[..sep];
    let mut lines = head.split(|&byte| byte == b'\n');
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::Protocol("HTTP status line is missing".into()))?;
    let status = parse_status(trim_cr(status_line))?;
    let mut content_length = None::<usize>;
    let mut chunked = false;
    let mut transfer_encoding_count = 0usize;
    let mut header_count = 0usize;

    for line in lines {
        header_count = header_count.saturating_add(1);
        if header_count > MAX_HEADER_COUNT || line.len() > MAX_HEADER_LINE {
            return Err(HttpError::Protocol(
                "Response has too many headers or too long a line".into(),
            ));
        }
        let (name, value) = parse_header_line(line)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding_count = transfer_encoding_count.saturating_add(1);
            if transfer_encoding_count > 1 || !value.eq_ignore_ascii_case("chunked") {
                return Err(HttpError::Protocol("Unsupported Transfer-Encoding".into()));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::Protocol("Duplicate Content-Length".into()));
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError::Protocol("Invalid Content-Length".into()));
            }
            let parsed = value
                .parse::<usize>()
                .map_err(|_| HttpError::Protocol("Invalid Content-Length".into()))?;
            if parsed as u64 > max_response {
                return Err(HttpError::Protocol(format!(
                    "Response exceeds the size limit: Content-Length={parsed}, limit={} MiB",
                    max_response / 1024 / 1024
                )));
            }
            content_length = Some(parsed);
        }
    }
    if chunked && content_length.is_some() {
        return Err(HttpError::Protocol(
            "Responses that use both Transfer-Encoding and Content-Length are not allowed".into(),
        ));
    }
    if status == 204 && (chunked || content_length.is_some()) {
        return Err(HttpError::Protocol(
            "A 204 response cannot use body framing headers".into(),
        ));
    }
    if matches!(status, 204 | 304) {
        return Ok(Some(ResponseFraming::Bodyless));
    }
    let body_start = start
        .checked_add(sep)
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| HttpError::Protocol("HTTP body offset calculation overflowed".into()))?;
    if chunked {
        return Ok(Some(ResponseFraming::Chunked { body_start }));
    }
    if let Some(expected) = content_length {
        return Ok(Some(ResponseFraming::ContentLength {
            body_start,
            length: expected,
        }));
    }
    Ok(Some(ResponseFraming::CloseDelimited))
}

#[cfg(test)]
/** @brief 한 번에 판단하는 테스트용 진입점. */
fn response_is_complete(raw: &[u8], max_response: u64) -> Result<bool, HttpError> {
    ResponseCompletion::default().is_complete(raw, max_response)
}

/** @brief 조각 전송 본문이 끝난 위치. 아직이면 없다. */
fn chunked_wire_len_from(
    data: &[u8],
    completed_position: &mut usize,
) -> Result<Option<usize>, HttpError> {
    let mut pos = *completed_position;
    if pos > data.len() {
        return Err(HttpError::Protocol(
            "Chunk position is outside the body".into(),
        ));
    }
    loop {
        let Some(relative_eol) = find(&data[pos..], b"\r\n") else {
            return Ok(None);
        };
        let eol = pos
            .checked_add(relative_eol)
            .ok_or_else(|| HttpError::Protocol("Chunk offset calculation overflowed".into()))?;
        let size = parse_chunk_size(&data[pos..eol])?;
        pos = eol
            .checked_add(2)
            .ok_or_else(|| HttpError::Protocol("Chunk offset calculation overflowed".into()))?;

        if size == 0 {
            if data.len() < pos.saturating_add(2) {
                return Ok(None);
            }
            if data.get(pos..pos + 2) == Some(&b"\r\n"[..]) {
                return Ok(Some(pos + 2));
            }
            let Some(trailer_end) = find(&data[pos..], b"\r\n\r\n") else {
                return Ok(None);
            };
            validate_chunk_trailers(&data[pos..pos + trailer_end])?;
            return pos
                .checked_add(trailer_end)
                .and_then(|value| value.checked_add(4))
                .map(Some)
                .ok_or_else(|| {
                    HttpError::Protocol("Chunk trailer offset calculation overflowed".into())
                });
        }

        let chunk_end = pos
            .checked_add(size)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| HttpError::Protocol("Chunk size calculation overflowed".into()))?;
        if data.len() < chunk_end {
            return Ok(None);
        }
        if data.get(chunk_end - 2..chunk_end) != Some(&b"\r\n"[..]) {
            return Err(HttpError::Protocol(
                "Chunk data is missing its trailing CRLF".into(),
            ));
        }
        pos = chunk_end;
        *completed_position = pos;
    }
}

/** @brief 받은 바이트를 응답으로. */
fn parse_response(raw: &[u8]) -> Result<Resp, HttpError> {
    let start = final_response_start(raw)?
        .ok_or_else(|| HttpError::Protocol("No final HTTP response".into()))?;
    let raw = &raw[start..];
    let sep = find(raw, b"\r\n\r\n")
        .ok_or_else(|| HttpError::Protocol("Could not find the end of the HTTP headers".into()))?;
    if sep > MAX_HEADER_BYTES {
        return Err(HttpError::Protocol(
            "Response headers exceed the size limit".into(),
        ));
    }
    let head = &raw[..sep];
    let body_raw = &raw[sep + 4..];

    let mut lines = head.split(|&b| b == b'\n');
    let status_line = lines
        .next()
        .ok_or_else(|| HttpError::Protocol("HTTP status line is missing".into()))?;
    let status = parse_status(trim_cr(status_line))?;

    let mut headers = Vec::new();
    let mut chunked = false;
    let mut has_transfer_encoding = false;
    let mut content_length: Option<usize> = None;
    let mut transfer_encoding_count = 0usize;
    let mut header_count = 0usize;
    for line in lines {
        header_count = header_count.saturating_add(1);
        if header_count > MAX_HEADER_COUNT || line.len() > MAX_HEADER_LINE {
            return Err(HttpError::Protocol(
                "Response has too many headers or too long a line".into(),
            ));
        }
        let (k, v) = parse_header_line(line)?;
        if k.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding_count = transfer_encoding_count.saturating_add(1);
            if transfer_encoding_count > 1 || !v.trim().eq_ignore_ascii_case("chunked") {
                return Err(HttpError::Protocol("Unsupported Transfer-Encoding".into()));
            }
            has_transfer_encoding = true;
            chunked = true;
        }
        if k.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::Protocol("Duplicate Content-Length".into()));
            }
            if v.is_empty() || !v.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpError::Protocol("Invalid Content-Length".into()));
            }
            let parsed = v
                .parse::<usize>()
                .map_err(|_| HttpError::Protocol("Invalid Content-Length".into()))?;
            content_length = Some(parsed);
        }
        headers.push((k.to_string(), v.to_string()));
    }
    if has_transfer_encoding && content_length.is_some() {
        return Err(HttpError::Protocol(
            "Responses that use both Transfer-Encoding and Content-Length are not allowed".into(),
        ));
    }
    if status == 204 && (chunked || content_length.is_some()) {
        return Err(HttpError::Protocol(
            "A 204 response cannot use body framing headers".into(),
        ));
    }

    let body = if matches!(status, 204 | 304) {
        if !body_raw.is_empty() {
            return Err(HttpError::Protocol(
                "An HTTP response that must have no body contains data".into(),
            ));
        }
        Vec::new()
    } else if chunked {
        decode_chunked(body_raw)?
    } else if let Some(expected) = content_length {
        if body_raw.len() != expected {
            return Err(HttpError::Protocol(format!(
                "Content-Length mismatch: expected {expected}, got {}",
                body_raw.len()
            )));
        }
        body_raw.to_vec()
    } else {
        body_raw.to_vec()
    };
    Ok(Resp {
        status,
        headers,
        body,
    })
}

/** @brief 상태 줄에서 상태 번호를. */
fn parse_status(line: &[u8]) -> Result<u16, HttpError> {
    let s = std::str::from_utf8(line)
        .map_err(|_| HttpError::Protocol("Status line encoding".into()))?;
    if s.bytes().any(|byte| byte < b' ' || byte == 0x7f) {
        return Err(HttpError::Protocol(
            "HTTP status line contains a character that is not allowed".into(),
        ));
    }
    let (version, rest) = s
        .split_once(' ')
        .ok_or_else(|| HttpError::Protocol("HTTP version or status code is missing".into()))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpError::Protocol(format!(
            "Unsupported HTTP version: {version}"
        )));
    }
    let code = rest.split_once(' ').map_or(rest, |(code, _)| code);
    let code = (code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| code.parse::<u16>().ok())
        .flatten()
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| HttpError::Protocol(format!("Could not parse the status code: {s}")))?;
    Ok(code)
}

/** @brief 조각 전송 본문을 이어 붙인다. */
fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    loop {
        let eol = find(data, b"\r\n")
            .ok_or_else(|| HttpError::Protocol("Chunk size line is missing".into()))?;
        let size = parse_chunk_size(&data[..eol])?;
        data = &data[eol + 2..];
        if size == 0 {
            if data == b"\r\n" {
                return Ok(out);
            }
            let end = find(data, b"\r\n\r\n").ok_or_else(|| {
                HttpError::Protocol("Could not find the end of the chunk trailer".into())
            })?;
            if end + 4 != data.len() {
                return Err(HttpError::Protocol(
                    "Extra data after the chunked body".into(),
                ));
            }
            validate_chunk_trailers(&data[..end])?;
            return Ok(out);
        }
        let chunk_end = size
            .checked_add(2)
            .ok_or_else(|| HttpError::Protocol("Chunk size calculation overflowed".into()))?;
        if data.len() < chunk_end {
            return Err(HttpError::Protocol("Chunk data is truncated".into()));
        }
        if &data[size..chunk_end] != b"\r\n" {
            return Err(HttpError::Protocol(
                "Chunk data is missing its trailing CRLF".into(),
            ));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[chunk_end..];
    }
}

/** @brief 조각 크기 줄을 읽는다. */
fn parse_chunk_size(line: &[u8]) -> Result<usize, HttpError> {
    if line.len() > MAX_HEADER_LINE {
        return Err(HttpError::Protocol("Chunk size line is too long".into()));
    }
    let hex_end = line
        .iter()
        .position(|&byte| byte == b';')
        .unwrap_or(line.len());
    let hex = &line[..hex_end];
    if hex.is_empty() || !hex.iter().all(u8::is_ascii_hexdigit) {
        return Err(HttpError::Protocol("Invalid chunk size".into()));
    }
    let extension = &line[hex_end..];
    if extension.iter().any(|&byte| byte < b'!' || byte == 0x7f) {
        return Err(HttpError::Protocol(
            "Chunk extension contains a character that is not allowed".into(),
        ));
    }
    let hex =
        std::str::from_utf8(hex).map_err(|_| HttpError::Protocol("Chunk size encoding".into()))?;
    usize::from_str_radix(hex, 16)
        .map_err(|_| HttpError::Protocol(format!("Could not parse the chunk size: {hex}")))
}

/** @brief 본문 뒤에 붙은 헤더가 형식에 맞는지. 여기도 검사해야 경계가 어긋나지 않는다. */
fn validate_chunk_trailers(trailers: &[u8]) -> Result<(), HttpError> {
    if trailers.len() > MAX_HEADER_BYTES {
        return Err(HttpError::Protocol(
            "Chunk trailer exceeds the size limit".into(),
        ));
    }
    validate_http_head(trailers)?;
    for (index, line) in trailers.split(|&byte| byte == b'\n').enumerate() {
        if index >= MAX_HEADER_COUNT || line.len() > MAX_HEADER_LINE {
            return Err(HttpError::Protocol(
                "Chunk trailer has too many fields or too long a line".into(),
            ));
        }
        let (name, _) = parse_header_line(line)?;
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(HttpError::Protocol(
                "Chunk trailers cannot contain framing fields".into(),
            ));
        }
    }
    Ok(())
}

/** @brief 넘어갈 주소를 지금 주소를 기준으로 푼다. */
fn resolve_redirect(current: &str, location: &str) -> Result<String, HttpError> {
    let location = location.trim();
    if location.is_empty() {
        return Err(HttpError::Protocol("Location header is empty".into()));
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let cur = parse_url(current)?;
    let scheme = match cur.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };

    if location.starts_with("//") {
        return Ok(format!("{scheme}:{location}"));
    }
    let host = host_header(&cur);
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{host}{}", normalize_path(location)));
    }
    let base_path = cur.path.split(['?', '#']).next().unwrap_or("/");
    if let Some(rest) = location.strip_prefix('?') {
        let _ = rest;
        return Ok(format!("{scheme}://{host}{base_path}{location}"));
    }
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    let merged = format!("{dir}{location}");
    Ok(format!("{scheme}://{host}{}", normalize_path(&merged)))
}

/** @brief 경로의 점 조각을 정리한다. */
fn normalize_path(path: &str) -> String {
    let (path_part, suffix) = match path.find(['?', '#']) {
        Some(i) => (&path[..i], &path[i..]),
        None => (path, ""),
    };
    let trailing_slash = path_part.ends_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path_part.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = String::from("/");
    result.push_str(&out.join("/"));
    if trailing_slash && !out.is_empty() {
        result.push('/');
    }
    result.push_str(suffix);
    result
}

/** @brief 바이트열에서 이 조각이 처음 나오는 위치. */
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/** @brief 줄 끝의 복귀 문자를 뗀다. */
fn trim_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(l) => l,
        None => line,
    }
}

#[cfg(test)]
/** @brief 주소 해석, 데드라인, 내부망 거부, 그리고 응답 경계를 애매하게 만드는 것들의 거부. */
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /** @brief 정해진 바이트를 돌려주는 테스트용 서버. */
    fn mock_server(response: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(response);
            }
        });
        format!("http://{addr}/x")
    }

    #[test]
    /** @brief 여러 형태의 주소가 제대로 쪼개지는지. */
    fn url_parse_variants() {
        let u = parse_url("http://127.0.0.1:8080/v1/stats").unwrap();
        assert!(matches!(u.scheme, Scheme::Http));
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/v1/stats");

        let u = parse_url("https://example.com/list.txt").unwrap();
        assert!(matches!(u.scheme, Scheme::Https));
        assert_eq!(u.port, 443);

        let u = parse_url("http://host").unwrap();
        assert_eq!(u.path, "/");
        assert_eq!(u.port, 80);

        assert!(parse_url("ftp://x").is_err());
    }

    #[test]
    /** @brief 길이로 경계를 정한 응답을 받는지. */
    fn get_plain_content_length() {
        let url =
            mock_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        let resp = get(&url).call().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.into_string().unwrap(), "hello");
    }

    #[test]
    /** @brief 한 바이트씩 흘려 보내는 상대가 데드라인을 늘리지 못하는지. */
    fn slow_drip_response_cannot_reset_request_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let result = get(&format!("http://{addr}/slow"))
            .timeout(Duration::from_millis(120))
            .call();
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief 넘겨준 해석 방법을 실제로 쓰는지. */
    fn custom_resolver_bypasses_system_dns() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let calls_for_resolver = calls.clone();
        let resolver: HostResolver = Arc::new(move |host, _| {
            assert_eq!(host, "updates.test");
            calls_for_resolver.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(vec!["127.0.0.1".parse().unwrap()])
        });
        let url = format!("http://updates.test:{}/list.txt", addr.port());
        let response = get(&url).resolver(resolver).call().unwrap();
        assert_eq!(response.into_string().unwrap(), "ok");
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    /** @brief 해석 방법이 없으면 운영체제 리졸버로 넘기지 않는지. 넘기면 순환이 된다. */
    fn hostname_never_falls_back_to_system_dns() {
        let error = match get("http://unconfigured.invalid/")
            .timeout(Duration::from_millis(50))
            .call()
        {
            Err(error) => error.to_string(),
            Ok(_) => panic!("resolver 없는 hostname 요청은 실패해야 함"),
        };
        assert!(error.contains("separate DNS server"), "{error}");
    }

    #[test]
    /** @brief 표기를 바꿔 적은 내부망 주소도 걸러지는지. */
    fn private_target_filter_normalizes_mapped_and_reserved_addresses() {
        for address in [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "2001:db8::1",
        ] {
            assert!(blocked_target(address.parse().unwrap()), "{address}");
        }
        assert!(!blocked_target("1.1.1.1".parse().unwrap()));
        assert!(!blocked_target("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    /** @brief 접속하기 전에 막는지. 접속한 뒤 막으면 이미 두드린 것이다. */
    fn private_target_filter_rejects_localhost_before_connecting() {
        let result = get("http://localhost/")
            .deny_private_targets()
            .timeout(Duration::from_millis(50))
            .call();
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("private localhost target must be rejected"),
        };
        assert!(error.contains("private, loopback"), "{error}");
    }

    #[test]
    /** @brief 조각 전송 본문이 이어 붙는지. */
    fn get_chunked_decodes() {
        let url = mock_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        );
        let resp = get(&url).call().unwrap();
        assert_eq!(resp.into_string().unwrap(), "Wikipedia");
    }

    #[test]
    /** @brief 본문과 헤더가 실려 가는지. */
    fn post_with_body_and_header() {
        let url =
            mock_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let resp = post(&url)
            .header("Content-Type", "application/json")
            .body_string("{\"domain\":\"x.test\"}")
            .call()
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.into_string().unwrap(), "ok");
    }

    #[test]
    #[ignore]
    /** @brief 실제 서버와의 왕복. */
    fn live_https_fetch() {
        let bootstrap = ["1.1.1.1".parse().unwrap()];
        let resolver: HostResolver = Arc::new(move |host, timeout| {
            onetdns_forward::resolve_via_bootstrap(host, &bootstrap, timeout)
                .map(|(ip, _ttl)| vec![ip])
                .ok_or_else(|| format!("bootstrap 해석 실패: {host}"))
        });
        let resp = get("https://example.com/")
            .resolver(resolver)
            .call()
            .expect("HTTPS 요청");
        assert_eq!(resp.status, 200);
        let body = resp.into_string().unwrap();
        assert!(
            body.to_ascii_lowercase().contains("example domain"),
            "본문: {}",
            &body[..body.len().min(200)]
        );
    }

    #[test]
    /** @brief 상태와 헤더가 읽히는지. */
    fn status_and_header_parsing() {
        let raw = b"HTTP/1.1 404 Not Found\r\nX-Foo: bar\r\nConnection: close\r\n\r\nnope";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.header("x-foo").as_deref(), Some("bar"));
        assert_eq!(r.into_string().unwrap(), "nope");
    }

    #[test]
    /** @brief 절대 주소와 루트 경로 넘김. */
    fn redirect_absolute_and_root() {
        assert_eq!(
            resolve_redirect("https://a.test/x", "https://b.test/y").unwrap(),
            "https://b.test/y"
        );
        assert_eq!(
            resolve_redirect("https://a.test/x/y", "/z").unwrap(),
            "https://a.test/z"
        );
    }

    #[test]
    /** @brief 형식만 물려받는 넘김. */
    fn redirect_scheme_relative() {
        assert_eq!(
            resolve_redirect("https://a.test/x", "//cdn.test/p").unwrap(),
            "https://cdn.test/p"
        );
    }

    #[test]
    /** @brief 상대 경로 넘김. */
    fn redirect_path_relative() {
        assert_eq!(
            resolve_redirect("https://a.test/dir/page", "next").unwrap(),
            "https://a.test/dir/next"
        );
        assert_eq!(
            resolve_redirect("https://a.test/dir/sub/page", "../other").unwrap(),
            "https://a.test/dir/other"
        );
        assert_eq!(
            resolve_redirect("https://a.test/dir/page", "./same").unwrap(),
            "https://a.test/dir/same"
        );
        assert_eq!(
            resolve_redirect("https://a.test/a/b/c", "../../top").unwrap(),
            "https://a.test/top"
        );
    }

    #[test]
    /** @brief 질의 문자열만 바뀌는 넘김. */
    fn redirect_query_only() {
        assert_eq!(
            resolve_redirect("https://a.test/search?old=1", "?new=2").unwrap(),
            "https://a.test/search?new=2"
        );
    }

    #[test]
    /** @brief 넘길 주소가 비면 오류인지. */
    fn redirect_empty_errors() {
        assert!(resolve_redirect("https://a.test/x", "   ").is_err());
    }

    #[test]
    /** @brief 점 조각이 정리되는지. */
    fn normalize_dot_segments() {
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("/a/./b/"), "/a/b/");
        assert_eq!(normalize_path("/../.."), "/");
        assert_eq!(normalize_path("/a/b/c?q=1"), "/a/b/c?q=1");
    }
    #[test]
    /** @brief 경계가 애매한 응답을 거부하는지. 받아들이면 응답 하나가 둘로 읽힌다. */
    fn rejects_ambiguous_or_malformed_framing() {
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(parse_response(b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n Folded: x\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc").is_err());
        for raw in [
            b"HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\nX-Test: value\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Test: ok\x01bad\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: +0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 2\r\nok\r\n0\r\n\r\n"
                .as_slice(),
        ] {
            assert!(response_is_complete(raw, 1024).is_err(), "{raw:?}");
            assert!(parse_response(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    /** @brief 헤더에 끼워 넣기와 잘못된 포트를 막는지. */
    fn rejects_request_header_injection_and_bad_ports() {
        assert!(parse_url("http://example.com:0/").is_err());
        let url = parse_url("https://example.com/").unwrap();
        let req = get("https://example.com/").header("X-Test", "ok\r\nInjected: yes");
        assert!(build_request(&req, &url).is_err());
        let req = get("https://example.com/").header("Content-Length", "3");
        assert!(build_request(&req, &url).is_err());
    }

    #[test]
    /** @brief 다 받았는지를 프로토콜이 정한 경계로 판단하는지. */
    fn response_completion_uses_http_framing() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(!response_is_complete(partial, 1024).unwrap());
        assert!(response_is_complete(complete, 1024).unwrap());

        let chunked_partial =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n";
        let chunked_complete =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
        assert!(!response_is_complete(chunked_partial, 1024).unwrap());
        assert!(response_is_complete(chunked_complete, 1024).unwrap());

        let early_hints_then_final = b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert!(response_is_complete(early_hints_then_final, 1024).unwrap());
        assert_eq!(parse_response(early_hints_then_final).unwrap().status, 200);
    }

    #[test]
    /** @brief 조각 확인이 앞서 본 위치부터 이어지는지. 처음부터 다시 보면 비용이 제곱으로 든다. */
    fn chunked_completion_resumes_after_the_last_complete_chunk() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let body_start = raw.len();
        let mut completion = ResponseCompletion::default();
        assert!(!completion.is_complete(&raw, 1024 * 1024).unwrap());

        for _ in 0..4096 {
            raw.extend_from_slice(b"1\r\nx\r\n");
            assert!(!completion.is_complete(&raw, 1024 * 1024).unwrap());
            assert_eq!(completion.chunk_position, raw.len() - body_start);
        }

        raw.extend_from_slice(b"0\r\n\r\n");
        assert!(completion.is_complete(&raw, 1024 * 1024).unwrap());
    }

    #[test]
    /** @brief 길이가 상한을 넘으면 다 받기 전에 끊는지. */
    fn response_completion_rejects_oversized_content_length_early() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n";
        assert!(response_is_complete(raw, 1024).is_err());
    }

    #[test]
    /** @brief 본문 없는 상태와 뒤따르는 헤더를 규격대로 다루는지. */
    fn bodyless_status_and_chunk_trailers_obey_http_framing() {
        let not_modified =
            parse_response(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n").unwrap();
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.body.is_empty());

        assert!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\nunexpected").is_err());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nContent-Length: 2\r\n\r\n"
        )
        .is_err());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Test: one\nX-Test: two\r\n\r\n"
        )
        .is_err());
    }
}
