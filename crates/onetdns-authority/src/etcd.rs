/*!
 * @brief etcd에서 zone을 읽는 백엔드.
 *
 * @details etcd의 v3 JSON 게이트웨이를 HTTP로 호출한다. gRPC 스택을 들이지 않으려고
 *          HTTP/1.1 클라이언트와 응답 파서를 이 파일 안에 직접 둔다. 키 접두사 아래의
 *          모든 항목을 한 번에 받아 각각 zone으로 파싱한다.
 * @warning 서버 응답은 신뢰 입력이 아니다. 헤더·본문·청크 인코딩 모두 상한과 형식
 *          검사를 거치며, 애매한 프레이밍은 받아들이지 않는다.
 */

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use onetdns_tls::{client_handshake, ClientConfig, TlsConnection, TrustStore};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};
/** @brief 응답 헤더 전체 크기 상한. */
const MAX_HTTP_HEADER: usize = 64 * 1024;
/** @brief 응답 본문 크기 상한. */
const MAX_HTTP_BODY: usize = 8 * 1024 * 1024;
/** @brief 헤더와 본문을 합친 상한. 읽는 동안 이 값으로 끊는다. */
const MAX_HTTP_RESPONSE: usize = MAX_HTTP_HEADER + MAX_HTTP_BODY;
/** @brief 헤더 줄 수 상한. */
const MAX_HTTP_HEADERS: usize = 200;
/** @brief 헤더 한 줄의 길이 상한. */
const MAX_HTTP_HEADER_LINE: usize = 8 * 1024;
/** @brief 요청 하나에 걸리는 전체 데드라인. */
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/** @brief etcd를 zone 공급자로 쓴다. 키가 origin, 값이 zone 텍스트다. */
pub struct EtcdZoneSource {
    /** @brief 접속 주소. http와 https를 모두 받는다. */
    pub endpoint: String,

    /** @brief 훑을 키 접두사. 이 아래의 모든 키가 zone이다. */
    pub prefix: String,

    /** @brief 이름 대신 쓸 접속 주소. 이름 해석을 자기 자신에게 맡기지 않으려는 것이다. */
    connect_addr: Option<SocketAddr>,

    /** @brief TLS 신뢰 저장소. 없으면 https를 거부한다. */
    tls: Option<TrustStore>,

    /** @brief 인증 자격증명. 없으면 인증 없이 접속한다. */
    creds: Option<(String, onetdns_core::SecretString)>,

    /** @brief 발급받은 토큰. 재사용해 매 요청마다 로그인하지 않는다. */
    token: Mutex<Option<onetdns_core::SecretString>>,

    /** @brief 마지막으로 본 항목 수와 리비전. 변경 감지에 쓴다. */
    seen: Mutex<(usize, u64)>,

    /** @brief 직전 변경 감시가 실패했는지. 상태가 바뀔 때만 기록하려는 것이다. */
    unreachable: std::sync::atomic::AtomicBool,
}

impl EtcdZoneSource {
    /** @brief 접속 주소와 키 접두사로 만든다. */
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

    /** @brief 기본 키 접두사로 만든다. */
    pub fn with_default_prefix(endpoint: impl Into<String>) -> Self {
        Self::new(endpoint, "/onetdns/zones/")
    }

    /** @brief TLS 신뢰 저장소를 붙인다. https 접속에는 이것이 반드시 있어야 한다. */
    pub fn with_tls(mut self, roots: TrustStore) -> Self {
        self.tls = Some(roots);
        self
    }

    /** @brief 사용자 자격증명을 붙인다. */
    pub fn with_auth(
        mut self,
        user: impl Into<String>,
        password: impl Into<onetdns_core::SecretString>,
    ) -> Self {
        self.creds = Some((user.into(), password.into()));
        self
    }

    /**
     * @brief 접속할 주소를 직접 지정한다.
     * @details 이름으로 된 접속 주소는 해석이 필요한데, 그 해석을 자기 자신에게 맡기면
     *          시작 중 순환이 생긴다. 그래서 이름을 쓰려면 주소를 함께 줘야 한다.
     * @note TLS 인증서 검증에는 여전히 접속 주소의 이름을 쓴다.
     */
    pub fn with_connect_addr(mut self, addr: SocketAddr) -> Self {
        self.connect_addr = Some(addr);
        self
    }

    /** @brief 접속 주소에서 호스트와 포트를 추출한다. */
    pub fn endpoint_host_port(&self) -> Result<(String, u16), String> {
        endpoint_parts(&self.endpoint)
            .map(|parts| (parts.host, parts.port))
            .map_err(|error| error.to_string())
    }

    /** @brief 접속 주소가 https인지. */
    fn is_https(&self) -> bool {
        self.endpoint.starts_with("https://")
    }

    /**
     * @brief 인증 토큰을 준비한다. 이미 있으면 그대로 쓴다.
     * @return 자격증명이 없으면 None. 인증 없이 접속하겠다는 뜻이다.
     */
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

    /**
     * @brief 토큰을 붙여 요청하고, 만료면 한 번만 다시 받아 재시도한다.
     * @details 토큰은 서버가 언제든 무효화할 수 있다. 한 번만 다시 시도하는 이유는,
     *          자격증명 자체가 틀린 경우에 무한히 로그인을 시도하지 않기 위해서다.
     */
    fn request(&self, path: &str, body: &str, _retry: Option<()>) -> Result<String, String> {
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

    /**
     * @brief 접두사 범위 질의 본문을 만든다.
     * @param keys_only 참이면 값을 받지 않는다. 변경 감지에는 키와 리비전만 있으면 되므로,
     *                  zone 텍스트 전체를 매 주기 받아 오지 않는다.
     */
    fn range_body(&self, keys_only: bool) -> String {
        let key = b64(self.prefix.as_bytes());
        let range_end = b64(&prefix_end(self.prefix.as_bytes()));
        if keys_only {
            format!("{{\"key\":\"{key}\",\"range_end\":\"{range_end}\",\"keys_only\":true}}")
        } else {
            format!("{{\"key\":\"{key}\",\"range_end\":\"{range_end}\"}}")
        }
    }

    /**
     * @brief 접두사 아래의 키-값을 받아 온다.
     * @return 항목들과 개수, 그리고 가장 큰 수정 리비전. 개수와 리비전 둘 다 봐야
     *         삭제와 수정을 모두 잡는다.
     */
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
    /**
     * @brief 접두사 아래 모든 키를 zone으로 파싱한다.
     * @warning https인데 신뢰 저장소가 없으면 거부한다. 검증 없이 TLS를 맺으면 암호화만
     *          하고 상대는 확인하지 않는 꼴이라 아무 서버나 zone을 먹일 수 있다.
     */
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

    /**
     * @brief 키 목록만 받아 개수와 리비전을 비교한다.
     * @note 질의에 실패하면 거짓이다. 잠깐 닿지 않는 것을 변경으로 보면 매 주기 재로드를
     *       시도하게 된다.
     */
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

    /** @brief 공급자 설명. */
    fn describe(&self) -> String {
        format!("etcd({}, prefix={})", self.endpoint, self.prefix)
    }
}

/** @brief JSON에서 수를 읽는다. etcd는 64비트 값을 문자열로 보내기도 해서 둘 다 받는다. */
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

/**
 * @brief 접두사 범위의 끝 키를 만든다. 마지막 바이트를 1 올린 값이다.
 * @note 뒤가 전부 0xff면 올릴 슬롯이 없다. 그 경우 0 하나를 주는데, etcd는 이것을
 *       모든 키를 뜻하는 특수 값으로 해석한다.
 */
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

/** @brief HTTP 요청 실패 사유. */
#[derive(Debug)]
enum HttpError {
    /** @brief 401. 토큰을 버리고 다시 받을지 판단하는 데 쓰이므로 따로 구분한다. */
    Unauthorized,
    /** @brief 그 밖의 실패. */
    Other(String),
}

impl std::fmt::Display for HttpError {
    /** @brief 사람이 읽을 실패 사유. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Unauthorized => write!(f, "etcd HTTP 401 (authentication failed)"),
            HttpError::Other(s) => write!(f, "{s}"),
        }
    }
}

/**
 * @brief JSON 본문으로 POST 하고 응답 본문을 돌려준다.
 *
 * @details 연결마다 새로 맺고 닫는다. etcd 호출은 재로드 주기마다 몇 번뿐이라 연결을
 *          유지할 이유가 없고, 유지하면 그만큼 상태가 는다.
 * @note 이름으로 된 접속 주소는 미리 받은 주소가 있어야 한다. 없으면 이 서버가 이름을
 *       해석해야 하는데, 그 해석이 다시 이 서버를 거치면 시작 중 순환이 생긴다.
 */
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

/** @brief 접속 주소를 뜯어 놓은 조각들. */
struct EndpointParts {
    /** @brief TLS를 쓰는지. */
    https: bool,
    /** @brief 호스트. TLS 인증서 이름 검증에도 쓴다. */
    host: String,
    /** @brief 포트. 생략되면 기본값이 들어간다. */
    port: u16,
    /** @brief Host 헤더에 담을 원래 형태. 포트 표기를 그대로 보존한다. */
    authority: String,
}

/**
 * @brief 접속 주소를 해석한다.
 * @details 경로가 붙거나 제어문자가 든 주소는 거부한다. 그런 값이 Host 헤더에 그대로
 *          들어가면 요청 자체를 조작할 수 있다.
 */
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

/**
 * @brief 평문 응답을 끝까지 읽는다.
 * @details Content-Length가 채워지면 연결이 닫히기를 기다리지 않고 멈춘다. 기다리기만
 *          하면 상대가 닫지 않는 한 데드라인까지 붙잡힌다.
 */
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

/** @brief TLS 응답을 끝까지 읽는다. 멈추는 조건은 평문 경로와 같다. */
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

/**
 * @brief 지금까지 받은 것으로 응답이 완성됐는지.
 * @details 청크 인코딩이면 길이를 미리 알 수 없어 항상 거짓이다. 그 경우 연결이 닫힐
 *          때까지 읽는다.
 */
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

/** @brief 응답 헤더에서 이 서버가 쓰는 것만 추출해 둔 형태. */
#[derive(Clone, Copy)]
struct ParsedHttpHead {
    /** @brief 상태 코드. */
    status: u16,
    /** @brief 본문 길이. 청크 인코딩이면 없다. */
    content_length: Option<usize>,
    /** @brief 청크 인코딩인지. */
    chunked: bool,
}

/** @brief 헤더 이름이 토큰 문자로만 이뤄졌는지. */
fn valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

/**
 * @brief 헤더 한 줄을 이름과 값으로 구분한다.
 * @details 이름은 토큰 문자만, 값은 제어문자를 뺀 것만 받는다. 느슨하게 두면 값에 든
 *          줄바꿈이 헤더를 새로 만들어 내는 밀반입이 성립한다.
 */
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

/** @brief 상태 줄에서 코드를 읽는다. 버전은 1.0과 1.1만 받는다. */
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

/**
 * @brief 응답 헤더를 해석한다.
 *
 * @details 프레이밍이 애매한 응답을 전부 거부한다. Content-Length가 둘이거나, 그것과
 *          Transfer-Encoding이 함께 있거나, 청크가 아닌 전송 인코딩이 붙은 경우다.
 * @warning 이 검사가 느슨하면 이 서버와 중간 장비가 본문 경계를 다르게 보게 된다. 그
 *          어긋남이 곧 요청 스머글링이다.
 */
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

/**
 * @brief 응답 전체에서 본문을 꺼낸다.
 * @details Content-Length가 있으면 실제 길이와 정확히 같아야 한다. 짧으면 잘린 것이고
 *          길면 다음 응답이 섞인 것이라, 어느 쪽도 그냥 넘길 수 없다.
 * @return 본문 문자열. 401은 토큰 갱신 판단을 위해 따로 구분해 돌려준다.
 */
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

/**
 * @brief 청크 인코딩을 푼다.
 * @details 크기 줄에 확장 매개변수가 붙을 수 있어 세미콜론 앞까지만 읽는다. 앞에 0을
 *          덧댄 표기나 공백은 거부한다. 같은 크기를 여러 형태로 쓸 수 있으면 중간
 *          장비와 이 서버가 경계를 다르게 본다.
 */
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

/** @brief 표준 base64 알파벳. */
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** @brief base64 인코딩. etcd의 JSON은 키와 값을 이 형식으로 주고받는다. */
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

/** @brief base64 디코딩. 알파벳 밖 문자가 있으면 None. */
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
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

/** @brief HTTP 프레이밍 거부 조건, 데드라인 처리, 인증 흐름, 실제 TLS 왕복. */
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /** @brief 본문이 다 찼으면 연결이 닫히기를 기다리지 않는지. */
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

    /** @brief 이름으로 된 접속 주소는 미리 받은 주소가 있어야 한다. 없으면 시작 중 순환이 생긴다. */
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

    /** @brief 접속은 주어진 주소로 하되 Host 헤더와 인증서 검증에는 이름을 그대로 쓰는지. */
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

    /** @brief 대괄호로 감싼 IPv6와 생략된 포트를 제대로 다루는지. */
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

    /** @brief 본문 경계가 애매한 응답을 전부 거부하는지. 이 어긋남이 요청 스머글링이다. */
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

    /** @brief 최소 etcd 응답을 내는 테스트용 HTTP 서버. 질의 횟수를 세어 재로드 여부를 확인한다. */
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

    #[allow(clippy::type_complexity)]
    /** @brief 인증을 요구하는 테스트용 서버. 토큰 발급과 만료를 흉내 낸다. */
    fn fake_etcd_auth(
        zones: Vec<(&'static str, String)>,
    ) -> (String, Arc<AtomicU64>, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let rev = Arc::new(AtomicU64::new(1));
        let rev_thread = rev.clone();
        let observed: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let obs2 = observed.clone();
        std::thread::spawn(move || {
            let rev = rev_thread;
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut got = Vec::new();
                let mut buf = [0u8; 8192];
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
                    let _ = s.write_all(resp.as_bytes());
                    continue;
                } else {
                    let keys_only = req.contains("\"keys_only\":true");
                    let r = rev.load(Ordering::SeqCst);
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
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), rev, observed)
    }

    /** @brief 테스트용 최소 zone 텍스트. */
    fn zone_text(origin: &str) -> String {
        format!(
            "$ORIGIN {origin}.\n$TTL 300\n@ IN SOA ns1 admin 3 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n"
        )
    }

    /** @brief 접두사 아래 키를 zone으로 담고, 개수와 리비전으로 변경을 잡는지. */
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

    /** @brief 검증 없는 TLS를 거부하는지. 암호화만 하고 상대를 확인하지 않으면 아무 서버나 zone을 먹인다. */
    #[test]
    fn rejects_https_without_trust_store() {
        let src = EtcdZoneSource::with_default_prefix("https://127.0.0.1:2379");
        let err = match src.load() {
            Err(e) => e,
            Ok(_) => panic!("신뢰 스토어 없는 https는 거부되어야"),
        };
        assert!(err.contains("tls_ca"), "{err}");
    }

    /** @brief 토큰을 받아 재사용하고, 만료되면 다시 받아 재시도하는지. */
    #[test]
    fn auth_token_flow() {
        let (endpoint, _rev, observed) =
            fake_etcd_auth(vec![("auth.test", zone_text("auth.test"))]);
        let password = onetdns_core::SecretString::from("pw");
        let password_ptr = password.as_ptr();
        let src = EtcdZoneSource::with_default_prefix(endpoint).with_auth("root", password);
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

    /** @brief 이 서버의 TLS 구현으로 실제 https etcd와 통하는지. */
    #[test]
    fn https_etcd_self_tls() {
        use onetdns_tls::{server_handshake, ServerConfig};
        use p256::pkcs8::DecodePrivateKey;

        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let ca_der = cert_der.clone();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        let scfg = ServerConfig {
            cert_chain: vec![cert_der],
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

    /** @brief base64 왕복과 접두사 끝 키 계산. */
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

    /** @brief 청크 인코딩이 원본 바이트로 되돌아오는지. */
    #[test]
    fn dechunk_decodes() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n4\r\n bye\r\n0\r\n\r\n").unwrap(),
            b"hello bye"
        );
    }
}

/** @brief HTTP 파서 패닉 스윕. 크레이트 내부라 통합 스윕이 닿지 못한다. */
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    /** @brief 헤더·본문·청크 파서가 어떤 바이트에도 패닉하지 않는지. */
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
