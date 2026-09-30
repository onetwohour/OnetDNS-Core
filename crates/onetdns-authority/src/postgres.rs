/*!
 * @brief PostgreSQL에서 zone을 읽는 백엔드.
 *
 * @details 라이브러리를 링크하지 않고 와이어 프로토콜을 직접 말한다. 인증은 SCRAM-SHA-256
 *          하나만 쓰고, 서버 서명까지 검증해 상호 인증을 마친다.
 * @warning 서버가 보내는 바이트는 신뢰 입력이 아니다. SCRAM 매개변수에는 모두 상한이
 *          있어야 하고, 파서는 어떤 바이트에도 패닉하지 않아야 한다.
 */

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime};

use hmac::{Mac, SimpleHmac};
use sha2::{Digest, Sha256};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};

/** @brief SCRAM 계산에 쓰는 HMAC. */
type HmacSha256 = SimpleHmac<Sha256>;

/** @brief 메시지 하나의 크기 상한. */
const MAX_PG_MESSAGE: usize = 64 * 1024 * 1024;
/** @brief 받아들일 행 수 상한. */
const MAX_ZONE_ROWS: usize = 100_000;
/** @brief 결과 전체의 누적 바이트 상한. */
const MAX_ZONE_RESULT_BYTES: usize = 512 * 1024 * 1024;
/** @brief 인증 단계에서 받아들일 메시지 수. 서버가 무한히 끌지 못하게 한다. */
const MAX_PG_AUTH_MESSAGES: usize = 1024;
/** @brief 질의 단계 메시지 수 상한. 행마다 하나에 앞뒤 여유를 더한다. */
const MAX_PG_QUERY_MESSAGES: usize = MAX_ZONE_ROWS + 4096;
/** @brief 인증 메시지 본문 상한. 인증 전이라 더 빡빡하게 잡는다. */
const MAX_PG_AUTH_PAYLOAD: usize = 64 * 1024;
/** @brief SCRAM 반복 하한. 이보다 낮으면 서버가 약한 값을 강요하는 것이다. */
const MIN_SCRAM_ITERATIONS: u32 = 4096;
/** @brief SCRAM 반복 상한. 서버가 큰 값을 불러 이 서버의 CPU를 태우는 것을 막는다. */
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

/**
 * @brief PostgreSQL 테이블에서 zone을 읽는 백엔드.
 * @details 라이브러리를 링크하지 않고 와이어 프로토콜을 직접 말한다. 인증은 SCRAM-SHA-256만
 *          쓴다.
 */
pub struct PostgresZoneSource {
    /** @brief 접속 호스트. 루프백만 허용한다. */
    pub host: String,
    /** @brief 접속 포트. */
    pub port: u16,
    /** @brief 사용자 이름. */
    pub user: String,
    /** @brief 비밀번호. */
    pub password: onetdns_core::SecretString,
    /** @brief 데이터베이스 이름. */
    pub database: String,
    /** @brief zone이 담긴 테이블 이름. */
    pub table: String,
}

impl PostgresZoneSource {
    /**
     * @brief 접속하지 않고 확인할 수 있는 조건을 본다.
     * @details 접속할 때 거절될 주소와 질의문에 넣을 수 없는 테이블 이름을 설정 단계에서
     *          알린다.
     */
    pub fn check(&self) -> Result<(), String> {
        crate::loopback_socket_addr(&self.host, self.port, "PostgreSQL")?;
        sanitize_table(&self.table).map(|_| ())
    }

    /**
     * @brief 접속 URL을 해석한다.
     * @note 비밀번호는 퍼센트 인코딩을 푼다. 특수문자가 든 비밀번호를 URL에 담으려면
     *       인코딩이 필요하기 때문이다.
     */
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

    /** @brief 접속·인증·질의를 한 번에 하고 행을 가져온다. */
    fn fetch_rows(&self) -> Result<Vec<(String, String)>, String> {
        let mut conn = PgConn::connect(&self.host, self.port, Duration::from_secs(10))?;
        conn.startup(&self.user, &self.database, &self.password)?;
        let sql = format!("SELECT origin, zone FROM {}", sanitize_table(&self.table)?);
        conn.simple_query(&sql)
    }
}

impl ZoneSource for PostgresZoneSource {
    /** @brief 행마다 zone을 파싱한다. 빈 origin은 루트로 본다. */
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

    /** @brief 항상 참. 변경 시각을 물을 싼 방법이 없어 매 주기 다시 읽는다. */
    fn changed_since(&self, _last: SystemTime) -> bool {
        true
    }

    /** @brief 공급자 설명. 비밀번호는 넣지 않는다. */
    fn describe(&self) -> String {
        format!("postgres({}:{}/{})", self.host, self.port, self.database)
    }
}

/** @brief 테이블 이름 검사. 식별자는 바인딩할 수 없어 질의문에 그대로 들어간다. */
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

/** @brief PostgreSQL 연결 하나. MySQL과 달리 순번이 없다. */
struct PgConn {
    /** @brief 데드라인이 걸린 TCP. */
    stream: DeadlineTcp,
}

impl PgConn {
    /**
     * @brief 서버에 접속한다.
     * @warning 루프백 주소만 허용한다. 원격으로 향하면 자격증명이 평문으로 흐른다.
     */
    fn connect(host: &str, port: u16, timeout: Duration) -> Result<PgConn, String> {
        let deadline = Instant::now() + timeout;
        let addr = crate::loopback_socket_addr(host, port, "PostgreSQL")?;
        let stream = DeadlineTcp::connect(addr, deadline).map_err(|e| e.to_string())?;
        Ok(PgConn { stream })
    }

    /**
     * @brief 메시지를 보낸다.
     * @param tag 메시지 종류. 0이면 태그 없는 시작 메시지다.
     * @note 길이 필드는 자기 자신 4바이트를 포함한다.
     */
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

    /**
     * @brief 메시지 하나를 읽는다.
     * @details 길이가 4 미만이면 본문 길이 계산이 음수가 되므로 하한도 함께 검사한다.
     */
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

    /**
     * @brief 시작 메시지를 보내고 인증을 마친다.
     *
     * @details 서버가 준비 완료를 알릴 때까지 메시지를 받아 처리한다. 메시지 수에 상한을
     *          두어 서버가 알림만 보내며 끄는 상황에서 빠져나온다.
     * @warning MD5 인증은 거부한다. 충돌이 현실적인 해시를 인증에 쓸 이유가 없다.
     */
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
                            let mut m = password.as_bytes().to_vec();
                            m.push(0);
                            self.send(b'p', &m)?;
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

    /**
     * @brief SCRAM-SHA-256 인증을 수행한다.
     *
     * @details 이 서버의 nonce를 무작위로 만들어 보내고, 서버가 돌려준 nonce가 그것으로 시작하는지
     *          확인한다. 이 확인이 재생 공격을 막는다. 마지막에는 서버 서명까지 검증한다.
     *          클라이언트만 인증하고 끝내면 중간자가 서버 행세를 할 수 있다.
     * @warning 서버가 주는 salt·nonce·반복 횟수에 모두 상한이 있다. 상한이 없으면 서버
     *          하나가 이 서버의 CPU와 메모리를 마음대로 쓴다.
     */
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

    /**
     * @brief 단순 질의를 보내고 두 열을 가져온다.
     * @note 행 수와 누적 바이트, 메시지 수를 모두 센다. 셋 중 하나만으로는 메모리와
     *       시간을 함께 묶지 못한다.
     */
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

/**
 * @brief DataRow 메시지를 열 값들로 나눈다.
 * @note 길이가 부호 있는 32비트다. 음수는 NULL 표시이므로 그대로 부호 있는 값으로 읽어야
 *       한다. 부호 없이 읽으면 NULL이 거대한 길이로 둔갑한다.
 */
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

/** @brief 오류 메시지에서 사람이 읽을 본문 필드만 추출한다. */
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

/**
 * @brief SCRAM 서버 첫 응답에서 nonce, salt, 반복 횟수를 추출한다.
 * @details 반복 횟수는 여기서 상하한을 검사한다. 너무 작으면 서버가 약한 값을 강요하는
 *          것이고, 너무 크면 이 서버의 CPU를 태우는 것이다.
 */
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

/**
 * @brief 사용자 이름에서 SCRAM 구분자와 겹치는 문자를 이스케이프한다.
 * @note 치환 순서가 중요하다. 쉼표를 먼저 바꾸면 그 결과에 든 등호가 다시 치환돼 값이
 *       망가진다.
 */
fn saslprep(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

/** @brief SHA-256 한 번. */
fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.finalize().into()
}

/** @brief HMAC-SHA-256. */
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("The HMAC key length matches the algorithm requirement");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/**
 * @brief PBKDF2-HMAC-SHA-256, 출력 블록 하나.
 * @note SCRAM은 해시 길이만큼만 쓰므로 블록 하나면 충분하다. 반복 횟수는 호출 전에
 *       범위를 확인해 둔다.
 */
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

/** @brief 표준 base64 알파벳. */
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** @brief base64 인코딩. SCRAM 값은 이 형식으로 오간다. */
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

/** @brief URL의 퍼센트 인코딩을 푼다. 비밀번호에 특수문자가 들어갈 수 있다. */
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

/** @brief URL 해석, DataRow 읽기, SCRAM 계산을 공표된 벡터에 맞춰 고정한다. */
#[cfg(test)]
mod tests {
    use super::*;

    /** @brief 자격증명 유무와 포트 생략을 모두 처리하는지. */
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

    /** @brief 길이 -1이 NULL로 읽히는지. 부호 없이 읽으면 거대한 길이가 된다. */
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

    /** @brief SCRAM 계산 전체를 RFC 7677의 공표 벡터에 대조한다. 증명과 서버 서명을 모두 본다. */
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

    /** @brief 서버 첫 응답의 세 값이 제대로 갈리는지. */
    #[test]
    fn server_first_parse() {
        let (r, s, i) = parse_server_first("r=abc123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096").unwrap();
        assert_eq!(r, "abc123");
        assert_eq!(s, "W22ZaJ0SNY7soEsUEjb6gQ==");
        assert_eq!(i, 4096);
    }

    /** @brief 질의문에 그대로 들어가는 식별자가 걸러지는지. */
    #[test]
    fn table_sanitize() {
        assert!(sanitize_table("zones").is_ok());
        assert!(sanitize_table("schema.zones").is_ok());
        assert!(sanitize_table("zones; DROP TABLE x").is_err());
    }
}

/** @brief 와이어 파서 패닉 스윕. 크레이트 내부라 통합 스윕이 닿지 못한다. */
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    /** @brief DataRow와 SCRAM 파서가 어떤 바이트에도 패닉하지 않는지. */
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
