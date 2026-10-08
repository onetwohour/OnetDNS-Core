/*!
 * @brief QPACK 헤더 압축.
 *
 * @details HPACK과 달리 스트림 순서가 보장되지 않는다. 그래서 동적 테이블 갱신이 별도
 *          단방향 스트림으로 오가고, 아직 상대가 못 본 항목은 참조할 수 없다.
 * @warning 압축은 그 자체로 증폭 경로다. 작은 입력이 큰 헤더 목록으로 부풀 수 있으므로
 *          펼친 크기에 상한이 있어야 한다.
 * @note 이 구현은 DoH3에 필요한 만큼만 한다. 일반 목적 QPACK이 아니다.
 */

/** @brief 정적 테이블. 흔한 헤더를 번호 하나로 줄인다. */
pub static STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/** @brief 번호로 정적 테이블 항목을 찾는다. */
fn static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    STATIC.get(usize::try_from(idx).ok()?).copied()
}

/**
 * @brief 접두사 있는 정수를 읽는다.
 * @details 앞 몇 비트가 값의 일부이고, 다 차면 뒤에 이어서 온다. 이어지는 바이트 수에
 *          상한을 두어 값이 무한정 커지지 못하게 한다.
 */
fn read_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> Option<u64> {
    if !(1..=8).contains(&prefix_bits) {
        return None;
    }
    let mask = (1u64 << prefix_bits) - 1;
    let first = *buf.get(*pos)? as u64;
    *pos += 1;
    let mut val = first & mask;
    if val < mask {
        return Some(val);
    }
    let mut m = 0u32;
    loop {
        let b = *buf.get(*pos)? as u64;
        *pos += 1;
        let low = b & 0x7f;
        if m >= 64 || low > (u64::MAX >> m) {
            return None;
        }
        val = val.checked_add(low << m)?;
        if b & 0x80 == 0 {
            break;
        }
        m += 7;
        if m > 62 {
            return None;
        }
    }
    Some(val)
}

/** @brief 길이 접두사 있는 문자열을 읽는다. 허프만 부호일 수 있다. */
fn read_string(buf: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let huff = buf.get(*pos)? & 0x80 != 0;
    let len = usize::try_from(read_int(buf, pos, 7)?).ok()?;
    let end = pos.checked_add(len)?;
    let bytes = buf.get(*pos..end)?.to_vec();
    *pos = end;
    if huff {
        onetdns_http2::huffman::decode(&bytes)
    } else {
        Some(bytes)
    }
}

/**
 * @brief 스트림에서 읽은 결과.
 * @note 데이터가 모자란 것과 형식이 틀린 것을 구분한다. 스트림은 조각나서 오므로,
 *       모자란 것을 오류로 보면 정상 통신이 끊긴다.
 */
enum StreamParse<T> {
    /** @brief 다 읽었다. */
    Done(T),
    /** @brief 아직 바이트가 모자란다. */
    Incomplete,
    /** @brief 형식이 어긋난다. */
    Invalid,
}

/** @brief 스트림에서 정수를 읽는다. 모자라면 실패가 아니라 대기다. */
fn read_stream_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> StreamParse<u64> {
    if !(1..=8).contains(&prefix_bits) {
        return StreamParse::Invalid;
    }
    let mask = (1u64 << prefix_bits) - 1;
    let Some(first) = buf.get(*pos).copied() else {
        return StreamParse::Incomplete;
    };
    *pos += 1;
    let mut val = u64::from(first) & mask;
    if val < mask {
        return StreamParse::Done(val);
    }
    let mut m = 0u32;
    loop {
        let Some(b) = buf.get(*pos).copied().map(u64::from) else {
            return StreamParse::Incomplete;
        };
        *pos += 1;
        let low = b & 0x7f;
        if m >= 64 || low > (u64::MAX >> m) {
            return StreamParse::Invalid;
        }
        let Some(next) = val.checked_add(low << m) else {
            return StreamParse::Invalid;
        };
        val = next;
        if b & 0x80 == 0 {
            return StreamParse::Done(val);
        }
        m += 7;
        if m > 62 {
            return StreamParse::Invalid;
        }
    }
}

/** @brief 스트림에서 문자열을 읽는다. 모자라면 대기다. */
fn read_stream_string(buf: &[u8], pos: &mut usize) -> StreamParse<Vec<u8>> {
    let Some(first) = buf.get(*pos).copied() else {
        return StreamParse::Incomplete;
    };
    let huff = first & 0x80 != 0;
    let len = match read_stream_int(buf, pos, 7) {
        StreamParse::Done(len) => match usize::try_from(len) {
            Ok(len) => len,
            Err(_) => return StreamParse::Invalid,
        },
        StreamParse::Incomplete => return StreamParse::Incomplete,
        StreamParse::Invalid => return StreamParse::Invalid,
    };
    let Some(end) = pos.checked_add(len) else {
        return StreamParse::Invalid;
    };
    let Some(bytes) = buf.get(*pos..end) else {
        return StreamParse::Incomplete;
    };
    *pos = end;
    if huff {
        match onetdns_http2::huffman::decode(bytes) {
            Some(value) => StreamParse::Done(value),
            None => StreamParse::Invalid,
        }
    } else {
        StreamParse::Done(bytes.to_vec())
    }
}

/**
 * @brief 동적 테이블 없이 헤더 목록을 푼다.
 * @note 정적 테이블과 문자열만 다룬다. 동적 참조가 오면 거부한다. 이 경로는 테이블 상태를 갖지 않는다.
 */
pub fn decode_field_section(buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut pos = 0usize;

    let ric = read_int(buf, &mut pos, 8)?;
    if ric != 0 {
        return None;
    }
    let _delta_base = read_int(buf, &mut pos, 7)?;

    let mut out = Vec::new();
    let mut decoded_size = 0usize;
    let mut add = |name: Vec<u8>, value: Vec<u8>| -> Option<()> {
        decoded_size = decoded_size.checked_add(name.len() + value.len() + ENTRY_OVERHEAD)?;
        if decoded_size > 32 * 1024 || out.len() >= 128 {
            return None;
        }
        out.push((name, value));
        Some(())
    };
    while pos < buf.len() {
        let b = buf[pos];
        if b & 0x80 != 0 {
            let is_static = b & 0x40 != 0;
            let idx = read_int(buf, &mut pos, 6)?;
            if !is_static {
                return None;
            }
            let (n, v) = static_entry(idx)?;
            add(n.as_bytes().to_vec(), v.as_bytes().to_vec())?;
        } else if b & 0x40 != 0 {
            let is_static = b & 0x10 != 0;
            let idx = read_int(buf, &mut pos, 4)?;
            let value = read_string(buf, &mut pos)?;
            if !is_static {
                return None;
            }
            let (n, _) = static_entry(idx)?;
            add(n.as_bytes().to_vec(), value)?;
        } else if b & 0x20 != 0 {
            let huff = b & 0x08 != 0;
            let nlen = usize::try_from(read_int(buf, &mut pos, 3)?).ok()?;
            let end = pos.checked_add(nlen)?;
            let nbytes = buf.get(pos..end)?.to_vec();
            pos = end;
            let name = if huff {
                onetdns_http2::huffman::decode(&nbytes)?
            } else {
                nbytes
            };
            let value = read_string(buf, &mut pos)?;
            add(name, value)?;
        } else {
            return None;
        }
    }
    Some(out)
}

/** @brief 접두사 있는 정수를 쓴다. */
fn push_int(out: &mut Vec<u8>, mut val: u64, prefix_bits: u32, flags: u8) {
    let mask = (1u64 << prefix_bits) - 1;
    if val < mask {
        out.push(flags | val as u8);
        return;
    }
    out.push(flags | mask as u8);
    val -= mask;
    while val >= 128 {
        out.push((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

/** @brief 길이 접두사 있는 문자열을 쓴다. */
fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    push_int(out, s.len() as u64, 7, 0x00);
    out.extend_from_slice(s);
}

/** @brief 헤더 블록 프리픽스를 쓴다. 테이블 참조 기준점이 여기 들어간다. */
fn prefix(out: &mut Vec<u8>) {
    out.push(0x00);
    out.push(0x00);
}

/** @brief DoH3 응답 헤더. 형태가 고정이라 미리 만들어 둔다. */
pub fn doh_response_headers() -> Vec<u8> {
    let mut out = Vec::new();
    prefix(&mut out);
    out.push(0xC0 | 25);
    out.push(0xC0 | 44);
    out
}

/** @brief DoH3 요청 헤더. */
pub fn doh_post_request_headers(authority: &str, path: &str, content_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    prefix(&mut out);
    out.push(0xC0 | 20);
    out.push(0xC0 | 23);
    out.push(0x50);
    push_string(&mut out, authority.as_bytes());
    out.push(0x51);
    push_string(&mut out, path.as_bytes());
    out.push(0xC0 | 44);
    out.push(0x54);
    push_string(&mut out, content_len.to_string().as_bytes());
    out
}

/** @brief 항목 하나의 고정 부대 비용. 규격이 정한 값으로, 테이블 크기 계산에 더한다. */
const ENTRY_OVERHEAD: usize = 32;

#[derive(Default)]
/**
 * @brief 동적 테이블. 최근에 쓴 헤더를 번호로 줄인다.
 * @details 크기가 상한을 넘으면 오래된 것부터 버린다. 절대 번호는 계속 늘어나므로,
 *          버려진 항목을 가리키는 참조는 거부해야 한다.
 */
pub struct DynamicTable {
    /** @brief 테이블에 담긴 헤더들. */
    entries: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
    /** @brief 지금까지 넣은 항목 수. 상대와 맞춰 보는 기준이다. */
    insert_count: u64,
    /** @brief 테이블에 담을 수 있는 크기. */
    capacity: usize,
    /** @brief 지금 담긴 크기. */
    size: usize,
}

impl DynamicTable {
    /** @brief 동적 테이블의 예약 슬롯과 이름·값 버퍼가 실제로 보유한 바이트. */
    fn retained_payload_bytes(&self) -> usize {
        self.entries
            .capacity()
            .saturating_mul(std::mem::size_of::<(Vec<u8>, Vec<u8>)>())
            .saturating_add(self.entries.iter().fold(0usize, |total, (name, value)| {
                total
                    .saturating_add(name.capacity())
                    .saturating_add(value.capacity())
            }))
    }

    /** @brief 항목 하나가 차지하는 크기. 부대 비용을 더한 값이다. */
    fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len() + value.len() + ENTRY_OVERHEAD
    }

    /** @brief 테이블 크기를 바꾼다. 줄이면 넘치는 만큼 버린다. */
    fn set_capacity(&mut self, cap: usize) {
        self.capacity = cap;
        while self.size > self.capacity {
            self.evict_oldest();
        }
    }

    /** @brief 가장 오래된 항목을 버린다. */
    fn evict_oldest(&mut self) {
        if let Some((n, v)) = self.entries.pop_front() {
            self.size -= Self::entry_size(&n, &v);
        }
    }

    /** @brief 항목을 넣는다. 슬롯이 모자라면 오래된 것을 버려 가며 넣는다. */
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> bool {
        let es = Self::entry_size(&name, &value);
        if es > self.capacity {
            return false;
        }
        while self.size.checked_add(es).is_none_or(|n| n > self.capacity) {
            self.evict_oldest();
            if self.entries.is_empty()
                && self.size.checked_add(es).is_none_or(|n| n > self.capacity)
            {
                return false;
            }
        }
        self.size += es;
        self.entries.push_back((name, value));
        self.insert_count += 1;
        true
    }

    /**
     * @brief 버리지 않고 넣는다. 슬롯이 없으면 넣지 않는다.
     * @details 아직 상대가 참조 중일 수 있는 항목을 버리면 상대가 그 번호를 풀지 못한다.
     */
    fn insert_no_evict(&mut self, name: Vec<u8>, value: Vec<u8>) -> bool {
        let es = Self::entry_size(&name, &value);
        if self.size.checked_add(es).is_none_or(|n| n > self.capacity) {
            return false;
        }
        self.size += es;
        self.entries.push_back((name, value));
        self.insert_count += 1;
        true
    }

    /** @brief 절대 번호로 항목을 찾는다. 이미 버려졌으면 없다. */
    fn get_abs(&self, abs: u64) -> Option<(&[u8], &[u8])> {
        let oldest = self.insert_count - self.entries.len() as u64;
        if abs < oldest || abs >= self.insert_count {
            return None;
        }
        self.entries
            .get((abs - oldest) as usize)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /** @brief 같은 이름과 값을 가진 항목의 절대 번호. */
    fn find(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        let oldest = self.insert_count - self.entries.len() as u64;
        self.entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (n, v))| n == name && v == value)
            .map(|(i, _)| oldest + i as u64)
    }

    /** @brief 지금까지 넣은 항목 수. 절대 번호의 기준이다. */
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }
}

/** @brief 정적 테이블에서 이름과 값이 모두 맞는 항목. */
fn static_find(name: &[u8], value: &[u8]) -> Option<u64> {
    STATIC
        .iter()
        .position(|(n, v)| n.as_bytes() == name && v.as_bytes() == value)
        .map(|i| i as u64)
}

/** @brief 정적 테이블에서 이름만 맞는 항목. 값은 문자열로 붙인다. */
fn static_find_name(name: &[u8]) -> Option<u64> {
    STATIC
        .iter()
        .position(|(n, _)| n.as_bytes() == name)
        .map(|i| i as u64)
}

#[derive(Debug, PartialEq, Eq)]
/**
 * @brief 헤더 구역을 푼 결과.
 * @note 아직 못 푸는 경우가 있다. 참조하는 동적 항목이 아직 도착하지 않았을 때다. 그것은
 *       오류가 아니라 대기다.
 */
pub enum DecodeResult {
    /** @brief 다 읽었다. */
    Done(Vec<(Vec<u8>, Vec<u8>)>),

    /** @brief 테이블이 아직 따라오지 못했다. */
    Blocked,

    /** @brief 형식이 어긋난다. */
    Error,
}

/** @brief QPACK 디코더. 동적 테이블과 대기 중인 구역을 가지고 있다. */
pub struct Decoder {
    /** @brief 이쪽이 읽는 쪽 테이블. */
    table: DynamicTable,

    /** @brief 이 테이블에 허락한 최대 크기. */
    max_capacity: usize,

    /** @brief 상대의 적는 쪽에서 온 바이트. */
    enc_buf: Vec<u8>,

    /** @brief 상대에게 내보낼 바이트. */
    out: Vec<u8>,
}

impl Decoder {
    /** @brief 테이블 크기 상한을 정해 만든다. */
    pub fn new(max_capacity: usize) -> Self {
        Decoder {
            table: DynamicTable::default(),
            max_capacity,
            enc_buf: Vec::new(),
            out: Vec::new(),
        }
    }

    /** @brief 디코더 테이블과 입출력 조각이 보유한 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.table
            .retained_payload_bytes()
            .saturating_add(self.enc_buf.capacity())
            .saturating_add(self.out.capacity())
    }

    /**
     * @brief 상대의 테이블 갱신 지시를 처리한다.
     * @details 조각나서 올 수 있으므로, 다 읽지 못한 지시는 남겨 두고 다음 데이터를 기다린다.
     * @warning 테이블 크기 요청이 이쪽 상한을 넘으면 거부한다. 상대가 정하는 대로 두면 연결
     *          하나로 이쪽 메모리를 정할 수 있다.
     */
    pub fn on_encoder_stream(&mut self, data: &[u8]) -> Result<(), ()> {
        /** @brief 적는 쪽 버퍼 상한. */
        const MAX_ENCODER_BUFFER: usize = 64 * 1024;
        if self.enc_buf.len().saturating_add(data.len()) > MAX_ENCODER_BUFFER {
            self.enc_buf.clear();
            return Err(());
        }
        let insert_count_before = self.table.insert_count;
        self.enc_buf.extend_from_slice(data);
        let buf = std::mem::take(&mut self.enc_buf);
        let mut consumed = 0usize;
        loop {
            let mut pos = consumed;
            if pos == buf.len() {
                break;
            }
            let b = buf[pos];
            let res: Result<Option<()>, ()> = (|| {
                macro_rules! stream_value {
                    ($value:expr) => {
                        match $value {
                            StreamParse::Done(value) => value,
                            StreamParse::Incomplete => return Ok(None),
                            StreamParse::Invalid => return Err(()),
                        }
                    };
                }
                if b & 0x80 != 0 {
                    let is_static = b & 0x40 != 0;
                    let idx = stream_value!(read_stream_int(&buf, &mut pos, 6));
                    let value = stream_value!(read_stream_string(&buf, &mut pos));
                    let name = if is_static {
                        static_entry(idx).ok_or(())?.0.as_bytes().to_vec()
                    } else {
                        let abs = self.table.insert_count.checked_sub(1 + idx).ok_or(())?;
                        self.table.get_abs(abs).ok_or(())?.0.to_vec()
                    };
                    if !self.table.insert(name, value) {
                        return Err(());
                    }
                    Ok(Some(()))
                } else if b & 0x40 != 0 {
                    let huff = b & 0x20 != 0;
                    let nlen = usize::try_from(stream_value!(read_stream_int(&buf, &mut pos, 5)))
                        .map_err(|_| ())?;
                    let end = pos.checked_add(nlen).ok_or(())?;
                    let Some(nbytes) = buf.get(pos..end) else {
                        return Ok(None);
                    };
                    pos = end;
                    let name = if huff {
                        onetdns_http2::huffman::decode(nbytes).ok_or(())?
                    } else {
                        nbytes.to_vec()
                    };
                    let value = stream_value!(read_stream_string(&buf, &mut pos));
                    if !self.table.insert(name, value) {
                        return Err(());
                    }
                    Ok(Some(()))
                } else if b & 0x20 != 0 {
                    let cap = usize::try_from(stream_value!(read_stream_int(&buf, &mut pos, 5)))
                        .map_err(|_| ())?;
                    if cap > self.max_capacity {
                        return Err(());
                    }
                    self.table.set_capacity(cap);
                    Ok(Some(()))
                } else {
                    let idx = stream_value!(read_stream_int(&buf, &mut pos, 5));
                    let abs = self.table.insert_count.checked_sub(1 + idx).ok_or(())?;
                    let (n, v) = {
                        let (n, v) = self.table.get_abs(abs).ok_or(())?;
                        (n.to_vec(), v.to_vec())
                    };
                    if !self.table.insert(n, v) {
                        return Err(());
                    }
                    Ok(Some(()))
                }
            })();
            match res {
                Ok(Some(())) => {
                    consumed = pos;
                    if consumed == buf.len() {
                        break;
                    }
                }
                Ok(None) => {
                    self.enc_buf = buf[consumed..].to_vec();
                    break;
                }
                Err(()) => return Err(()),
            }
        }
        let inserted = self.table.insert_count - insert_count_before;
        if inserted > 0 {
            push_int(&mut self.out, inserted, 6, 0x00);
        }
        Ok(())
    }

    /**
     * @brief 헤더 구역 접두부에서 Required Insert Count 를 읽는다.
     * @return 접두부가 어긋나면 None 이다.
     */
    fn required_insert_count(&self, buf: &[u8], pos: &mut usize) -> Option<u64> {
        let enc_ric = read_int(buf, pos, 8)?;
        if enc_ric == 0 {
            return Some(0);
        }
        let max_entries = (self.max_capacity / ENTRY_OVERHEAD) as u64;
        if max_entries == 0 {
            return None;
        }
        let full_range = 2 * max_entries;
        if enc_ric > full_range {
            return None;
        }
        let max_value = self.table.insert_count + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + enc_ric - 1;
        if ric > max_value {
            if ric <= full_range {
                return None;
            }
            ric -= full_range;
        }
        (ric != 0).then_some(ric)
    }

    /**
     * @brief 이 헤더 구역이 아직 오지 않은 테이블 항목을 기다려야 하는지.
     * @details 상태를 바꾸지 않는다. 한 스트림에 헤더 구역이 여럿이면 하나라도 기다릴 때 어느
     *          구역도 풀지 않아야 한다. 먼저 푼 구역의 확인 지시가 나간 뒤 다시 시도하면 같은
     *          구역의 확인 지시가 또 나가고, 상대는 그것을 QPACK_DECODER_STREAM_ERROR 로 본다.
     *          접두부가 어긋난 구역은 기다리지 않는다고 답하며, 실제로 풀 때 오류가 된다.
     */
    pub fn is_blocked(&self, buf: &[u8]) -> bool {
        self.required_insert_count(buf, &mut 0)
            .is_some_and(|ric| ric > self.table.insert_count)
    }

    /**
     * @brief 헤더 구역을 푼다.
     * @return 아직 도착하지 않은 동적 항목을 참조하면 대기 상태를 돌려준다. 그 경우 테이블이
     *         채워진 뒤 다시 시도한다.
     */
    pub fn decode_field_section(&mut self, stream_id: u64, buf: &[u8]) -> DecodeResult {
        let mut pos = 0usize;

        let Some(ric) = self.required_insert_count(buf, &mut pos) else {
            return DecodeResult::Error;
        };
        if ric > self.table.insert_count {
            return DecodeResult::Blocked;
        }

        let Some(sb) = buf.get(pos).copied() else {
            return DecodeResult::Error;
        };
        let sign = sb & 0x80 != 0;
        let Some(delta) = read_int(buf, &mut pos, 7) else {
            return DecodeResult::Error;
        };
        let base = if sign {
            match ric.checked_sub(delta + 1) {
                Some(b) => b,
                None => return DecodeResult::Error,
            }
        } else {
            match ric.checked_add(delta) {
                Some(v) => v,
                None => return DecodeResult::Error,
            }
        };

        let mut out = Vec::new();
        let mut decoded_size = 0usize;
        while pos < buf.len() {
            let b = buf[pos];
            let field: Option<(Vec<u8>, Vec<u8>)> = (|| {
                if b & 0x80 != 0 {
                    let is_static = b & 0x40 != 0;
                    let idx = read_int(buf, &mut pos, 6)?;
                    if is_static {
                        let (n, v) = static_entry(idx)?;
                        Some((n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                    } else {
                        let abs = base.checked_sub(1 + idx)?;
                        let (n, v) = self.table.get_abs(abs)?;
                        Some((n.to_vec(), v.to_vec()))
                    }
                } else if b & 0x40 != 0 {
                    let is_static = b & 0x10 != 0;
                    let idx = read_int(buf, &mut pos, 4)?;
                    let value = read_string(buf, &mut pos)?;
                    if is_static {
                        let (n, _) = static_entry(idx)?;
                        Some((n.as_bytes().to_vec(), value))
                    } else {
                        let abs = base.checked_sub(1 + idx)?;
                        let (n, _) = self.table.get_abs(abs)?;
                        Some((n.to_vec(), value))
                    }
                } else if b & 0x20 != 0 {
                    let huff = b & 0x08 != 0;
                    let nlen = usize::try_from(read_int(buf, &mut pos, 3)?).ok()?;
                    let end = pos.checked_add(nlen)?;
                    let nbytes = buf.get(pos..end)?.to_vec();
                    pos = end;
                    let name = if huff {
                        onetdns_http2::huffman::decode(&nbytes)?
                    } else {
                        nbytes
                    };
                    let value = read_string(buf, &mut pos)?;
                    Some((name, value))
                } else if b & 0x10 != 0 {
                    let idx = read_int(buf, &mut pos, 4)?;
                    let abs = base.checked_add(idx)?;
                    let (n, v) = self.table.get_abs(abs)?;
                    Some((n.to_vec(), v.to_vec()))
                } else {
                    let idx = read_int(buf, &mut pos, 3)?;
                    let value = read_string(buf, &mut pos)?;
                    let abs = base.checked_add(idx)?;
                    let (n, _) = self.table.get_abs(abs)?;
                    Some((n.to_vec(), value))
                }
            })();
            match field {
                Some(f) => {
                    decoded_size = match decoded_size.checked_add(f.0.len() + f.1.len() + 32) {
                        Some(n) if n <= 32 * 1024 && out.len() < 128 => n,
                        _ => return DecodeResult::Error,
                    };
                    out.push(f)
                }
                None => return DecodeResult::Error,
            }
        }

        if ric > 0 {
            push_int(&mut self.out, stream_id, 7, 0x80);
        }
        DecodeResult::Done(out)
    }

    /** @brief 상대에게 보낼 확인 지시를 꺼낸다. */
    pub fn take_decoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /** @brief 보내지 못한 확인 지시를 되돌린다. 순서를 지켜 앞에 붙인다. */
    pub(crate) fn restore_decoder_stream(&mut self, mut data: Vec<u8>) {
        data.append(&mut self.out);
        self.out = data;
    }

    /** @brief 지금까지 테이블에 넣은 항목 수. */
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count
    }
}

/** @brief QPACK 인코더. */
pub struct Encoder {
    /** @brief 이쪽이 적는 쪽 테이블. */
    table: DynamicTable,

    /** @brief 상대가 허락한 테이블 크기. */
    peer_max_capacity: usize,

    /** @brief 쓸 크기를 상대에게 알렸는지. */
    capacity_sent: bool,

    /** @brief 상대가 여기까지는 받았음을 확인한 항목 수. */
    known_received: u64,

    /** @brief 상대에게 내보낼 바이트. */
    out: Vec<u8>,

    /** @brief 상대의 읽는 쪽에서 온 바이트. */
    dec_buf: Vec<u8>,
}

/** @brief 이쪽이 쓰겠다고 정한 테이블 크기 상한. */
const OUR_MAX_CAPACITY: usize = 4096;

impl Encoder {
    /** @brief 인코더를 만든다. */
    pub fn new() -> Self {
        Encoder {
            table: DynamicTable::default(),
            peer_max_capacity: 0,
            capacity_sent: false,
            known_received: 0,
            out: Vec::new(),
            dec_buf: Vec::new(),
        }
    }

    /** @brief 인코더 테이블과 입출력 조각이 보유한 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.table
            .retained_payload_bytes()
            .saturating_add(self.out.capacity())
            .saturating_add(self.dec_buf.capacity())
    }

    /** @brief 상대가 허용한 테이블 크기를 반영한다. 이쪽 상한과 작은 쪽을 쓴다. */
    pub fn set_peer_max_capacity(&mut self, cap: usize) {
        self.peer_max_capacity = cap;
        let ours = cap.min(OUR_MAX_CAPACITY);
        if ours > 0 && !self.capacity_sent {
            push_int(&mut self.out, ours as u64, 5, 0x20);
            self.table.set_capacity(ours);
            self.capacity_sent = true;
        }
    }

    /** @brief 상대의 확인 지시를 처리한다. 어디까지 참조해도 되는지가 여기서 정해진다. */
    pub fn on_decoder_stream(&mut self, data: &[u8]) -> Result<(), ()> {
        /** @brief 읽는 쪽 버퍼 상한. */
        const MAX_DECODER_BUFFER: usize = 64 * 1024;
        if self.dec_buf.len().saturating_add(data.len()) > MAX_DECODER_BUFFER {
            self.dec_buf.clear();
            return Err(());
        }
        self.dec_buf.extend_from_slice(data);
        let mut pos = 0usize;
        while pos < self.dec_buf.len() {
            let instruction_start = pos;
            let b = self.dec_buf[pos];
            macro_rules! decoder_int {
                ($bits:expr) => {
                    match read_stream_int(&self.dec_buf, &mut pos, $bits) {
                        StreamParse::Done(value) => value,
                        StreamParse::Incomplete => {
                            self.dec_buf.drain(..instruction_start);
                            return Ok(());
                        }
                        StreamParse::Invalid => {
                            self.dec_buf.clear();
                            return Err(());
                        }
                    }
                };
            }
            if b & 0x80 != 0 {
                decoder_int!(7);
            } else if b & 0x40 != 0 {
                decoder_int!(6);
            } else {
                let inc = decoder_int!(6);
                let Some(received) = self.known_received.checked_add(inc) else {
                    return Err(());
                };
                if inc == 0 || received > self.table.insert_count {
                    return Err(());
                }
                self.known_received = received;
            }
        }
        self.dec_buf.clear();
        Ok(())
    }

    /**
     * @brief 헤더 목록을 인코딩한다.
     * @details 정적 테이블, 이미 확인된 동적 항목, 그리고 문자열 순으로 고른다. 확인되지 않은
     *          동적 항목을 참조하면 상대가 그 번호를 풀지 못해 스트림이 멈춘다.
     * @return 헤더 구역과 테이블 갱신 지시. 지시는 별도 스트림으로 보낸다.
     */
    pub fn encode_field_section(&mut self, headers: &[(&[u8], &[u8])]) -> (Vec<u8>, Vec<u8>) {
        let mut plan: Vec<FieldPlan> = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            if let Some(idx) = static_find(name, value) {
                plan.push(FieldPlan::Static(idx));
                continue;
            }
            if self.table.capacity > 0 {
                if let Some(abs) = self.table.find(name, value) {
                    if abs < self.known_received {
                        plan.push(FieldPlan::Dynamic(abs));
                    } else if let Some(nidx) = static_find_name(name) {
                        plan.push(FieldPlan::LiteralNameRef(nidx, value.to_vec()));
                    } else {
                        plan.push(FieldPlan::Literal(name.to_vec(), value.to_vec()));
                    }
                    continue;
                }

                if self.table.insert_no_evict(name.to_vec(), value.to_vec()) {
                    if let Some(nidx) = static_find_name(name) {
                        push_int(&mut self.out, nidx, 6, 0xC0);
                    } else {
                        push_int(&mut self.out, name.len() as u64, 5, 0x40);
                        self.out.extend_from_slice(name);
                    }
                    push_string(&mut self.out, value);
                }
            }

            match static_find_name(name) {
                Some(nidx) => plan.push(FieldPlan::LiteralNameRef(nidx, value.to_vec())),
                None => plan.push(FieldPlan::Literal(name.to_vec(), value.to_vec())),
            }
        }

        let base = self.table.insert_count;
        let ric = plan
            .iter()
            .filter_map(|f| match f {
                FieldPlan::Dynamic(abs) => Some(abs + 1),
                _ => None,
            })
            .max()
            .unwrap_or(0);

        let mut sec = Vec::new();

        let max_entries = (self.peer_max_capacity / ENTRY_OVERHEAD) as u64;
        let enc_ric = if ric == 0 {
            0
        } else {
            (ric % (2 * max_entries)) + 1
        };
        push_int(&mut sec, enc_ric, 8, 0x00);
        if base >= ric {
            push_int(&mut sec, base - ric, 7, 0x00);
        } else {
            push_int(&mut sec, ric - base - 1, 7, 0x80);
        }
        for f in &plan {
            match f {
                FieldPlan::Static(idx) => push_int(&mut sec, *idx, 6, 0xC0),
                FieldPlan::Dynamic(abs) => {
                    push_int(&mut sec, base - 1 - abs, 6, 0x80);
                }
                FieldPlan::LiteralNameRef(nidx, value) => {
                    push_int(&mut sec, *nidx, 4, 0x50);
                    push_string(&mut sec, value);
                }
                FieldPlan::Literal(name, value) => {
                    push_int(&mut sec, name.len() as u64, 3, 0x20);
                    sec.extend_from_slice(name);
                    push_string(&mut sec, value);
                }
            }
        }
        (sec, std::mem::take(&mut self.out))
    }

    /** @brief 보내지 못한 테이블 갱신 지시를 되돌린다. */
    pub(crate) fn restore_encoder_stream(&mut self, mut data: Vec<u8>) {
        data.append(&mut self.out);
        self.out = data;
    }

    /** @brief 상대가 확인한 항목 수. 여기까지만 참조할 수 있다. */
    pub fn known_received(&self) -> u64 {
        self.known_received
    }

    /** @brief 지금까지 테이블에 넣은 항목 수. */
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count
    }
}

impl Default for Encoder {
    /** @brief 기본 인코더. */
    fn default() -> Self {
        Self::new()
    }
}

/** @brief 헤더 하나를 어떻게 인코딩할지 정한 결과. */
enum FieldPlan {
    /** @brief 고정 테이블에서 그대로 가리킨다. */
    Static(u64),
    /** @brief 이쪽 테이블에서 가리킨다. */
    Dynamic(u64),
    /** @brief 이름만 가리키고 값은 그대로 적는다. */
    LiteralNameRef(u64, Vec<u8>),
    /** @brief 이름과 값을 모두 그대로 적는다. */
    Literal(Vec<u8>, Vec<u8>),
}

#[cfg(test)]
/** @brief 테이블 참조 규칙, 조각난 스트림 처리, 그리고 상한 적용. */
mod tests {
    use super::*;

    /** @brief 푼 헤더 목록에서 이름으로 값을 찾는다. */
    fn find<'a>(h: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
        h.iter()
            .find(|(n, _)| n == name.as_bytes())
            .map(|(_, v)| v.as_slice())
    }

    #[test]
    /** @brief 파싱 뒤 clear한 QPACK 조각도 allocator가 놓지 않은 capacity만큼 세는지. */
    fn retained_memory_counts_qpack_capacity_after_clear() {
        let mut decoder = Decoder::new(4096);
        let baseline = decoder.retained_payload_bytes();
        decoder.enc_buf = vec![0; 4 * 1024];
        let retained = decoder.retained_payload_bytes();
        assert!(retained >= baseline.saturating_add(4 * 1024));

        decoder.enc_buf.clear();
        assert_eq!(decoder.retained_payload_bytes(), retained);
    }

    #[test]
    /** @brief 정적 테이블의 주요 항목이 규격과 맞는지. */
    fn static_table_key_entries() {
        assert_eq!(STATIC[20], (":method", "POST"));
        assert_eq!(STATIC[25], (":status", "200"));
        assert_eq!(STATIC[44], ("content-type", "application/dns-message"));
        assert_eq!(STATIC.len(), 99);
    }

    #[test]
    /** @brief 요청 헤더 왕복. */
    fn request_headers_roundtrip() {
        let enc = doh_post_request_headers("dns.example", "/dns-query", 33);
        let h = decode_field_section(&enc).unwrap();
        assert_eq!(find(&h, ":method"), Some(b"POST".as_slice()));
        assert_eq!(find(&h, ":scheme"), Some(b"https".as_slice()));
        assert_eq!(find(&h, ":authority"), Some(b"dns.example".as_slice()));
        assert_eq!(find(&h, ":path"), Some(b"/dns-query".as_slice()));
        assert_eq!(
            find(&h, "content-type"),
            Some(b"application/dns-message".as_slice())
        );
        assert_eq!(find(&h, "content-length"), Some(b"33".as_slice()));
    }

    #[test]
    /** @brief 응답 헤더 왕복. */
    fn response_headers_roundtrip() {
        let enc = doh_response_headers();
        let h = decode_field_section(&enc).unwrap();
        assert_eq!(find(&h, ":status"), Some(b"200".as_slice()));
        assert_eq!(
            find(&h, "content-type"),
            Some(b"application/dns-message".as_slice())
        );
    }

    #[test]
    /** @brief 허프만 부호로 온 값이 풀리는지. */
    fn literal_name_huffman_value_decodes() {
        let mut enc = Vec::new();
        prefix(&mut enc);
        enc.push(0x51);
        let huff = onetdns_http2::huffman::encode(b"/dns-query");
        push_int(&mut enc, huff.len() as u64, 7, 0x80);
        enc.extend_from_slice(&huff);
        let h = decode_field_section(&enc).unwrap();
        assert_eq!(find(&h, ":path"), Some(b"/dns-query".as_slice()));
    }

    #[test]
    /** @brief 테이블 없는 경로가 동적 참조를 거부하는지. */
    fn dynamic_table_reference_rejected() {
        let buf = [0x01u8, 0x00];
        assert!(decode_field_section(&buf).is_none());
    }

    #[test]
    /** @brief 펼친 헤더 크기에 상한이 걸리는지. 압축은 증폭 경로다. */
    fn static_decoder_bounds_expanded_header_lists() {
        let mut buf = vec![0, 0];
        buf.extend(std::iter::repeat_n(0xc0 | 20, 1024));
        assert!(decode_field_section(&buf).is_none());
    }

    /** @brief 동적 테이블을 써서 인코딩하고 디코딩한다. */
    fn roundtrip_dyn(
        enc: &mut Encoder,
        dec: &mut Decoder,
        sid: u64,
        headers: &[(&[u8], &[u8])],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let (sec, enc_stream) = enc.encode_field_section(headers);
        dec.on_encoder_stream(&enc_stream).unwrap();
        enc.on_decoder_stream(&dec.take_decoder_stream()).unwrap();
        match dec.decode_field_section(sid, &sec) {
            DecodeResult::Done(h) => {
                enc.on_decoder_stream(&dec.take_decoder_stream()).unwrap();
                h
            }
            other => panic!("디코딩하지 못했습니다: {other:?}"),
        }
    }

    #[test]
    /** @brief 테이블에 넣은 항목을 번호로 참조하는 왕복. */
    fn dynamic_insert_and_reference_roundtrip() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new(4096);
        enc.set_peer_max_capacity(4096);

        let headers: Vec<(&[u8], &[u8])> = vec![
            (b":method", b"POST"),
            (b":authority", b"dns.upstream.example"),
            (b"x-custom-key", b"abc123"),
        ];
        let h1 = roundtrip_dyn(&mut enc, &mut dec, 0, &headers);
        assert_eq!(h1.len(), 3);
        assert_eq!(h1[1].1, b"dns.upstream.example");
        assert_eq!(enc.insert_count(), 2, "두 헤더가 동적 테이블에 삽입");
        assert_eq!(dec.insert_count(), 2, "디코더 테이블 동기화");
        assert_eq!(enc.known_received(), 2, "Insert Count Increment로 확인");

        let (sec_static, _) = Encoder::new().encode_field_section(&headers);
        let (sec2, enc_stream2) = enc.encode_field_section(&headers);
        assert!(enc_stream2.is_empty(), "재사용: 새 삽입 없음");
        assert!(sec2.len() < sec_static.len(), "동적 참조로 섹션이 짧아져야");
        dec.on_encoder_stream(&enc_stream2).unwrap();
        let DecodeResult::Done(h2) = dec.decode_field_section(4, &sec2) else {
            panic!("두 번째 섹션 디코드")
        };
        assert_eq!(h2, h1);
    }

    #[test]
    /** @brief 확인 전 항목을 참조하지 않는지. 참조하면 상대가 풀지 못해 멈춘다. */
    fn new_dynamic_entries_are_not_referenced_until_acknowledged() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new(4096);
        enc.set_peer_max_capacity(4096);

        let headers: Vec<(&[u8], &[u8])> = vec![(b":authority", b"blocked.example")];
        let (first, enc_stream) = enc.encode_field_section(&headers);
        let DecodeResult::Done(first_headers) = dec.decode_field_section(0, &first) else {
            panic!("신규 insert보다 field section이 먼저 도착해도 차단되면 안 됨")
        };
        assert_eq!(first_headers[0].1, b"blocked.example");

        dec.on_encoder_stream(&enc_stream).unwrap();
        enc.on_decoder_stream(&dec.take_decoder_stream()).unwrap();
        assert_eq!(enc.known_received(), 1);

        let (second, second_enc_stream) = enc.encode_field_section(&headers);
        assert!(second_enc_stream.is_empty());
        assert!(second.len() < first.len());
        let DecodeResult::Done(h) = dec.decode_field_section(4, &second) else {
            panic!("확인된 동적 참조 디코드")
        };
        assert_eq!(h[0].1, b"blocked.example");
    }

    #[test]
    /** @brief 조각나서 온 지시가 이어 붙고, 잘못된 증가는 거부되는지. */
    fn decoder_stream_instructions_survive_fragmentation_and_validate_increment() {
        let mut enc = Encoder::new();
        enc.set_peer_max_capacity(4096);
        for index in 0..64 {
            let name = format!("x-{index}");
            enc.encode_field_section(&[(name.as_bytes(), b"v")]);
        }
        assert_eq!(enc.insert_count(), 64);

        let mut increment = Vec::new();
        push_int(&mut increment, 64, 6, 0x00);
        assert!(increment.len() > 1);
        enc.on_decoder_stream(&increment[..1]).unwrap();
        assert_eq!(enc.known_received(), 0);
        enc.on_decoder_stream(&increment[1..]).unwrap();
        assert_eq!(enc.known_received(), 64);

        assert_eq!(enc.on_decoder_stream(&[0]), Err(()));
        assert_eq!(enc.on_decoder_stream(&[1]), Err(()));
    }

    #[test]
    /** @brief 데이터가 모자란 것과 형식이 틀린 것을 구분하는지. 합치면 정상 통신이 끊긴다. */
    fn encoder_stream_distinguishes_fragmentation_from_invalid_instructions() {
        let mut dec = Decoder::new(128);
        let mut capacity = Vec::new();
        push_int(&mut capacity, 128, 5, 0x20);
        assert!(capacity.len() > 1);

        dec.on_encoder_stream(&capacity[..1]).unwrap();
        assert_eq!(dec.table.capacity, 0);
        dec.on_encoder_stream(&capacity[1..]).unwrap();
        assert_eq!(dec.table.capacity, 128);

        let mut excessive_capacity = Vec::new();
        push_int(&mut excessive_capacity, 129, 5, 0x20);
        assert_eq!(dec.on_encoder_stream(&excessive_capacity), Err(()));
        assert!(dec.enc_buf.is_empty());

        let mut invalid_static_name = Vec::new();
        push_int(&mut invalid_static_name, 999, 6, 0xc0);
        push_string(&mut invalid_static_name, b"");
        assert_eq!(dec.on_encoder_stream(&invalid_static_name), Err(()));
        assert!(dec.enc_buf.is_empty());
    }

    #[test]
    /** @brief 넘치는 정수를 버퍼가 차기 전에 거부하는지. */
    fn qpack_streams_reject_overflowing_integers_before_buffer_limit() {
        let mut malformed = vec![0x3f];
        malformed.extend(std::iter::repeat_n(0xff, 10));

        let mut dec = Decoder::new(4096);
        assert_eq!(dec.on_encoder_stream(&malformed), Err(()));
        assert!(dec.enc_buf.is_empty());

        let mut enc = Encoder::new();
        assert_eq!(enc.on_decoder_stream(&malformed), Err(()));
        assert!(enc.dec_buf.is_empty());
    }

    #[test]
    /** @brief 테이블 크기 변경이 여러 번 와도 처리되는지. */
    fn many_capacity_updates_are_processed() {
        let updates = vec![0x20; 32 * 1024];
        let mut dec = Decoder::new(4096);
        dec.on_encoder_stream(&updates).unwrap();
        assert!(dec.enc_buf.is_empty());
    }

    #[test]
    /** @brief 상대가 테이블을 안 쓰겠다고 하면 정적 테이블만 쓰는지. */
    fn peer_capacity_zero_means_static_only() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new(0);
        let headers: Vec<(&[u8], &[u8])> = vec![(b":authority", b"nodyn.example")];
        let (sec, enc_stream) = enc.encode_field_section(&headers);
        assert!(enc_stream.is_empty(), "동적 미사용: 인코더 명령 없음");
        assert_eq!(enc.insert_count(), 0);
        let DecodeResult::Done(h) = dec.decode_field_section(0, &sec) else {
            panic!("정적 폴백 디코드")
        };
        assert_eq!(h[0].1, b"nodyn.example");

        assert!(super::decode_field_section(&sec).is_some());
    }

    #[test]
    /** @brief 테이블이 넘치면 오래된 항목이 버려지는지. */
    fn decoder_evicts_when_capacity_exceeded() {
        let mut dec = Decoder::new(128);
        let mut stream = Vec::new();
        push_int(&mut stream, 128, 5, 0x20);

        for i in 0..3u8 {
            let name = format!("k-{i}-key");
            let value = b"v23456";
            push_int(&mut stream, name.len() as u64, 5, 0x40);
            stream.extend_from_slice(name.as_bytes());
            push_string(&mut stream, value);
        }
        dec.on_encoder_stream(&stream).unwrap();
        assert_eq!(dec.insert_count(), 3);

        assert!(dec.table.get_abs(0).is_none(), "축출됨");
        assert!(dec.table.get_abs(1).is_some());
        assert!(dec.table.get_abs(2).is_some());
    }

    #[test]
    /** @brief 테이블이 꽉 차면 문자열로 전환하는지. */
    fn encoder_full_table_falls_back_to_literal() {
        let mut enc = Encoder::new();

        enc.set_peer_max_capacity(80);
        let mut dec80 = Decoder::new(80);
        let headers: Vec<(&[u8], &[u8])> =
            vec![(b"x-first", b"0123456789"), (b"x-second", b"9876543210")];
        let (sec, enc_stream) = enc.encode_field_section(&headers);
        assert_eq!(enc.insert_count(), 1, "한 개만 삽입");
        dec80.on_encoder_stream(&enc_stream).unwrap();
        let DecodeResult::Done(h) = dec80.decode_field_section(0, &sec) else {
            panic!("디코드")
        };
        assert_eq!(h.len(), 2);
        assert_eq!(h[1].0, b"x-second");
        assert_eq!(h[1].1, b"9876543210");
    }
}
