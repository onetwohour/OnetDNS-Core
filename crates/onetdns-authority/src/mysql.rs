/*!
 * @brief MySQL/MariaDB에서 zone을 읽는 백엔드.
 *
 * @details 클라이언트 라이브러리를 링크하지 않고 와이어 프로토콜을 직접 말한다. 이 서버에게
 *          필요한 것은 접속·인증·단순 질의뿐이라, 프로토콜 전체를 구현하지 않는다.
 * @warning 서버가 보내는 바이트는 신뢰 입력이 아니다. 인증 전에 닿는 핸드셰이크 파서와
 *          행 파서 모두 어떤 바이트에도 패닉하지 않아야 한다.
 */

use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime};

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::source::ZoneSource;
use crate::{parse_zone, DeadlineTcp, ZoneStore};

/** @brief 패킷 하나의 본문 크기 상한. 프로토콜 자체의 한계와 같다. */
const MAX_MYSQL_PACKET: usize = 16 * 1024 * 1024;
/** @brief 결과 집합의 열 수 상한. 이 서버의 질의는 두 열만 쓴다. */
const MAX_MYSQL_COLUMNS: usize = 64;
/** @brief 받아들일 행 수 상한. */
const MAX_MYSQL_ROWS: usize = 100_000;
/** @brief 결과 전체의 누적 바이트 상한. 행 수만으로는 메모리를 묶지 못한다. */
const MAX_MYSQL_RESULT_BYTES: usize = 512 * 1024 * 1024;
/** @brief 인증 왕복 상한. 서버가 인증 전환을 무한히 요구하는 것을 막는다. */
const MAX_AUTH_ROUNDS: usize = 16;

/** @brief 긴 비밀번호 지원. */
const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
/** @brief 4.1 프로토콜. 현대 서버의 기본이다. */
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
/** @brief 보안 연결 방식 인증. */
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
/** @brief 인증 플러그인 협상. */
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
/** @brief 접속과 동시에 데이터베이스 선택. */
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;

/**
 * @brief MySQL/MariaDB 테이블에서 zone을 읽는 백엔드.
 * @details 클라이언트 라이브러리를 링크하지 않고 와이어 프로토콜을 직접 말한다.
 *          origin과 zone 두 열만 읽으면 되므로 필요한 부분만 구현한다.
 */
pub struct MysqlZoneSource {
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

impl MysqlZoneSource {
    /**
     * @brief 접속하지 않고 확인할 수 있는 조건을 본다.
     * @details 접속할 때 거절될 주소와 질의문에 넣을 수 없는 테이블 이름을 설정 단계에서
     *          알린다.
     */
    pub fn check(&self) -> Result<(), String> {
        crate::loopback_socket_addr(&self.host, self.port, "MySQL")?;
        sanitize_table(&self.table).map(|_| ())
    }

    /**
     * @brief 접속 URL을 해석한다. 자격증명이 없으면 root로 본다.
     * @return 형식이 어긋나면 None.
     */
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

    /** @brief 접속·인증·질의를 한 번에 하고 행을 가져온다. 연결은 매번 새로 연다. */
    fn fetch_rows(&self) -> Result<Vec<(String, String)>, String> {
        let mut conn = MyConn::connect(&self.host, self.port, Duration::from_secs(10))?;
        conn.handshake(&self.user, &self.password, &self.database)?;
        let sql = format!("SELECT origin, zone FROM {}", sanitize_table(&self.table)?);
        conn.query(&sql)
    }
}

impl ZoneSource for MysqlZoneSource {
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
            let z = parse_zone(&text, o).map_err(|e| format!("mysql[{origin}]: {e}"))?;
            store.add(z);
        }
        if missing_origin > 0 {
            onetdns_core::warn!(event = "authority.mysql_origin_missing", table = %self.table, rows = missing_origin, "Read a row with an empty origin as the root zone; check the table if this is unintended");
        }
        Ok(store)
    }

    /**
     * @brief 항상 참.
     * @details 서버에 변경 시각을 물을 싼 방법이 없다. 매 주기 다시 읽는 쪽이 갱신을
     *          놓치는 것보다 낫다.
     */
    fn changed_since(&self, _last: SystemTime) -> bool {
        true
    }

    /** @brief 공급자 설명. 비밀번호는 넣지 않는다. */
    fn describe(&self) -> String {
        format!("mysql({}:{}/{})", self.host, self.port, self.database)
    }
}

/**
 * @brief 테이블 이름을 검사한다.
 * @details 식별자는 자리표시자로 바인딩할 수 없어 질의문에 그대로 들어간다. 영숫자와
 *          밑줄, 점만 허용해 SQL 주입을 막는다.
 */
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

/** @brief MySQL 연결 하나. 패킷 순번을 함께 가지고 있어야 프로토콜이 맞물린다. */
struct MyConn {
    /** @brief 데드라인이 걸린 TCP. 응답이 오지 않아도 영원히 기다리지 않는다. */
    stream: DeadlineTcp,
    /** @brief 다음 패킷의 순번. 명령마다 0으로 되돌린다. */
    seq: u8,
}

impl MyConn {
    /**
     * @brief 서버에 접속한다.
     * @warning 루프백 주소만 허용한다. 원격 DB로 향하면 자격증명이 평문으로 흐른다.
     */
    fn connect(host: &str, port: u16, timeout: Duration) -> Result<MyConn, String> {
        let deadline = Instant::now() + timeout;
        let addr = crate::loopback_socket_addr(host, port, "MySQL")?;
        let stream = DeadlineTcp::connect(addr, deadline).map_err(|e| e.to_string())?;
        Ok(MyConn { stream, seq: 0 })
    }

    /**
     * @brief 패킷 하나를 읽는다.
     * @details 길이를 상한과 견주고 순번도 확인한다. 순번이 어긋나면 프로토콜이 이미
     *          엇나간 것이라, 그대로 진행하면 엉뚱한 바이트를 결과로 읽는다.
     */
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

    /** @brief 3바이트 길이와 순번을 앞에 붙여 패킷을 보낸다. */
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

    /**
     * @brief 인증을 마친다.
     *
     * @details 서버가 인증 방식 전환을 요구할 수 있어 왕복이 여러 번일 수 있다. 횟수에
     *          상한을 두어 서버가 전환만 반복시키는 상황에서 빠져나온다.
     * @note caching_sha2의 전체 인증은 거부한다. 그 경로는 비밀번호를 평문에 가깝게
     *       보내므로 TLS 없이는 쓰면 안 된다.
     */
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

    /**
     * @brief 질의를 보내고 텍스트 결과의 두 열을 가져온다.
     *
     * @details 응답은 열 개수, 열 정의, 선택적 EOF, 행들, 그리고 마지막 EOF 순서다.
     *          서버 판마다 중간 EOF가 있고 없고 해서 그 슬롯을 봐 가며 건너뛴다.
     * @note 행 수와 누적 바이트를 모두 센다. 행 수만 세면 거대한 행 몇 개로 메모리를
     *       채울 수 있다.
     */
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

/**
 * @brief 서버의 최초 핸드셰이크에서 스크램블과 인증 플러그인 이름을 추출한다.
 * @details 스크램블은 앞 8바이트와 뒤쪽 조각이 떨어져 있어 이어 붙여야 한다. 모든
 *          오프셋 계산을 넘침 검사와 함께 한다. 이 바이트는 아직 인증되지 않았다.
 * @return 스크램블과 플러그인 이름.
 */
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

/** @brief 뒤쪽 0바이트를 떼어 낸다. 스크램블 조각에 채움용 0이 붙어 온다. */
fn trim_nul(b: &[u8]) -> Vec<u8> {
    let mut e = b.len();
    while e > 0 && b[e - 1] == 0 {
        e -= 1;
    }
    b[..e].to_vec()
}

/**
 * @brief 플러그인에 맞는 인증 응답을 만든다.
 * @note 비밀번호가 비면 빈 응답이다. 빈 비밀번호를 해시하면 서버가 인증 실패로 본다.
 */
fn compute_auth(plugin: &str, password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    match plugin {
        "caching_sha2_password" => scramble_sha256(password, scramble),
        _ => scramble_native(password, scramble),
    }
}

/**
 * @brief mysql_native_password 응답.
 * @details SHA1(비밀번호)를 SHA1(스크램블 ‖ SHA1(SHA1(비밀번호)))와 XOR한다. 서버는
 *          SHA1(SHA1(비밀번호))만 저장하므로 비밀번호 자체는 오가지 않는다.
 */
fn scramble_native(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    let h1 = sha1(password);
    let h2 = sha1(&h1);
    let mut cat = scramble.to_vec();
    cat.extend_from_slice(&h2);
    let h3 = sha1(&cat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/**
 * @brief caching_sha2_password의 빠른 경로 응답.
 * @note 이어 붙이는 순서가 native와 반대다. 서버 캐시가 비어 있으면 전체 인증으로
 *       넘어가는데, 그쪽은 이 서버가 거부한다.
 */
fn scramble_sha256(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    let h1 = sha256(password);
    let h2 = sha256(&h1);
    let mut cat = h2.to_vec();
    cat.extend_from_slice(scramble);
    let h3 = sha256(&cat);
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

/**
 * @brief 클라이언트 핸드셰이크 응답을 만든다.
 * @details 이 서버가 실제로 쓰는 기능만 요청한다. 압축이나 다중 문장 같은 것을 켜면 그
 *          응답 형식까지 다뤄야 한다.
 */
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

/** @brief 오류 패킷에서 사람이 읽을 메시지를 추출한다. SQL 상태가 붙어 있으면 건너뛴다. */
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

/**
 * @brief 길이 인코딩 정수를 읽는다.
 * @details 첫 바이트가 형식을 정한다. 0xfb는 NULL 표시라 값 0으로 취급하고, 나머지는
 *          뒤따르는 2·3·8바이트를 읽는다.
 * @return 값과 그 다음 위치. 바이트가 모자라면 None.
 */
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

/**
 * @brief 텍스트 프로토콜의 행 하나를 열 값들로 나눈다.
 * @details 길이 계산에 넘침 검사를 붙인다. 조작된 길이가 위치를 되감으면 같은 바이트를
 *          되풀이해 읽거나 범위를 벗어난다.
 * @return 열 값들. NULL은 None이다.
 */
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

/** @brief SHA-1 한 번. 인증 방식이 정한 것이라 선택지가 없다. */
fn sha1(d: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(d);
    h.finalize().into()
}

/** @brief SHA-256 한 번. */
fn sha256(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(d);
    h.finalize().into()
}

/** @brief URL 해석, 와이어 형식 읽기, 인증 계산의 정합성. */
#[cfg(test)]
mod tests {
    use super::*;

    /** @brief 자격증명 유무와 포트 생략을 모두 처리하는지. */
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

    /** @brief 길이 인코딩 정수의 세 형식이 값과 다음 위치를 맞게 주는지. */
    #[test]
    fn lenenc_variants() {
        assert_eq!(lenenc_int(&[0x05], 0), Some((5, 1)));
        assert_eq!(lenenc_int(&[0xfc, 0x10, 0x01], 0), Some((0x0110, 3)));
        assert_eq!(
            lenenc_int(&[0xfd, 0x01, 0x02, 0x03], 0),
            Some((0x030201, 4))
        );
    }

    /** @brief NULL 열을 빈 문자열과 구분하는지. 둘을 섞으면 origin이 루트로 둔갑한다. */
    #[test]
    fn text_row_parse_with_null() {
        let mut b = vec![6];
        b.extend_from_slice(b"ex.com");
        b.push(0xfb);
        let cols = parse_text_row(&b, 2).unwrap();
        assert_eq!(cols[0].as_deref(), Some("ex.com"));
        assert_eq!(cols[1], None);
    }

    /** @brief native 인증 계산을 식대로 되짚어 확인한다. 빈 비밀번호는 빈 응답이어야 한다. */
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

    /** @brief caching_sha2 응답 길이가 해시 길이와 같은지. */
    #[test]
    fn sha256_scramble_shape() {
        let scramble: Vec<u8> = (0u8..20).collect();
        let r = scramble_sha256(b"secret", &scramble);
        assert_eq!(r.len(), 32);
    }

    /** @brief 떨어져 있는 스크램블 두 조각이 하나로 이어지고 플러그인 이름이 읽히는지. */
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

/**
 * @brief 와이어 파서 패닉 스윕.
 * @details 이 파서들은 크레이트 내부라 통합 스윕이 닿지 못한다. 그래서 여기서 직접 흔든다.
 */
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::fuzzutil::{havoc, Rng};

    /** @brief 핸드셰이크와 행 파서가 어떤 바이트에도 패닉하지 않는지. */
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
