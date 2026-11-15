//! QPACK header compression. Streams arrive in no fixed order, so dynamic table updates travel on
//! separate unidirectional streams, and an entry the peer has not acknowledged is never referenced.
//!
//! Compression amplifies: a small input can expand into a large header list, so the expanded size
//! is capped. This implements what DoH3 needs, not general-purpose QPACK.

/// RFC 9204 static table.
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

fn static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    STATIC.get(usize::try_from(idx).ok()?).copied()
}

/// Caps the continuation bytes so the value cannot grow without bound.
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

/// Tells missing bytes from malformed ones. Stream data arrives in pieces, so treating a short read
/// as an error would cut off normal traffic.
enum StreamParse<T> {
    Done(T),
    Incomplete,
    Invalid,
}

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

/// Static table and literals only; a dynamic reference is rejected.
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

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    push_int(out, s.len() as u64, 7, 0x00);
    out.extend_from_slice(s);
}

/// No dynamic references: Required Insert Count 0 and Base 0.
fn prefix(out: &mut Vec<u8>) {
    out.push(0x00);
    out.push(0x00);
}

/// Static references only, so it needs no encoder state.
pub fn doh_response_headers() -> Vec<u8> {
    let mut out = Vec::new();
    prefix(&mut out);
    out.push(0xC0 | 25);
    out.push(0xC0 | 44);
    out
}

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

/// Per-entry overhead from RFC 9204, added in table size accounting.
const ENTRY_OVERHEAD: usize = 32;

#[derive(Default)]
/// Evicts the oldest entries when over capacity. Absolute indices keep growing, so a reference to
/// an evicted entry is rejected.
pub struct DynamicTable {
    entries: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Entries ever inserted; absolute indices count from it.
    insert_count: u64,
    capacity: usize,
    size: usize,
}

impl DynamicTable {
    /// Includes the spare capacity of the deque and of the name and value buffers.
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

    fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len() + value.len() + ENTRY_OVERHEAD
    }

    /// Shrinking evicts what no longer fits.
    fn set_capacity(&mut self, cap: usize) {
        self.capacity = cap;
        while self.size > self.capacity {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some((n, v)) = self.entries.pop_front() {
            self.size -= Self::entry_size(&n, &v);
        }
    }

    /// Evicts the oldest entries to make room.
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

    /// Fails rather than evict: the peer may still reference the oldest entry and could not decode
    /// it.
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

    /// None once evicted.
    fn get_abs(&self, abs: u64) -> Option<(&[u8], &[u8])> {
        let oldest = self.insert_count - self.entries.len() as u64;
        if abs < oldest || abs >= self.insert_count {
            return None;
        }
        self.entries
            .get((abs - oldest) as usize)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    fn find(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        let oldest = self.insert_count - self.entries.len() as u64;
        self.entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, (n, v))| n == name && v == value)
            .map(|(i, _)| oldest + i as u64)
    }

    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }
}

fn static_find(name: &[u8], value: &[u8]) -> Option<u64> {
    STATIC
        .iter()
        .position(|(n, v)| n.as_bytes() == name && v.as_bytes() == value)
        .map(|i| i as u64)
}

fn static_find_name(name: &[u8]) -> Option<u64> {
    STATIC
        .iter()
        .position(|(n, _)| n.as_bytes() == name)
        .map(|i| i as u64)
}

#[derive(Debug, PartialEq, Eq)]
/// A section that references a dynamic entry not yet received is Blocked, not an error.
pub enum DecodeResult {
    Done(Vec<(Vec<u8>, Vec<u8>)>),

    Blocked,

    Error,
}

pub struct Decoder {
    table: DynamicTable,

    max_capacity: usize,

    /// Unparsed bytes from the peer's encoder stream.
    enc_buf: Vec<u8>,

    /// Instructions for the decoder stream.
    out: Vec<u8>,
}

impl Decoder {
    pub fn new(max_capacity: usize) -> Self {
        Decoder {
            table: DynamicTable::default(),
            max_capacity,
            enc_buf: Vec::new(),
            out: Vec::new(),
        }
    }

    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.table
            .retained_payload_bytes()
            .saturating_add(self.enc_buf.capacity())
            .saturating_add(self.out.capacity())
    }

    /// A partial instruction stays buffered until more data arrives. A capacity request above this
    /// side's limit is rejected; otherwise the peer would decide this side's memory.
    pub fn on_encoder_stream(&mut self, data: &[u8]) -> Result<(), ()> {
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

    /// Does not change state. When a stream carries several field sections, none is decoded while
    /// any one is blocked: retrying after an earlier one was decoded would send its acknowledgment
    /// twice, which the peer treats as QPACK_DECODER_STREAM_ERROR. A malformed prefix reports not
    /// blocked and fails at decode.
    pub fn is_blocked(&self, buf: &[u8]) -> bool {
        self.required_insert_count(buf, &mut 0)
            .is_some_and(|ric| ric > self.table.insert_count)
    }

    /// Blocked when a referenced entry has not arrived yet; retry once the table catches up.
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

    /// Sends Stream Cancellation from RFC 9204, for a reset or abandoned stream. The encoder cannot
    /// evict entries that unacknowledged sections reference, so without this they stay pinned until
    /// the connection ends.
    pub fn cancel_stream(&mut self, stream_id: u64) {
        push_int(&mut self.out, stream_id, 6, 0x40);
    }

    pub fn take_decoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Puts unsent instructions back in front, keeping their order.
    pub(crate) fn restore_decoder_stream(&mut self, mut data: Vec<u8>) {
        data.append(&mut self.out);
        self.out = data;
    }

    pub fn insert_count(&self) -> u64 {
        self.table.insert_count
    }
}

pub struct Encoder {
    table: DynamicTable,

    peer_max_capacity: usize,

    capacity_sent: bool,

    /// Entries the peer has acknowledged.
    known_received: u64,

    /// Instructions for the encoder stream.
    out: Vec<u8>,

    /// Unparsed bytes from the peer's decoder stream.
    dec_buf: Vec<u8>,
}

const OUR_MAX_CAPACITY: usize = 4096;

impl Encoder {
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

    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.table
            .retained_payload_bytes()
            .saturating_add(self.out.capacity())
            .saturating_add(self.dec_buf.capacity())
    }

    /// Uses the smaller of the peer's limit and this side's.
    pub fn set_peer_max_capacity(&mut self, cap: usize) {
        self.peer_max_capacity = cap;
        let ours = cap.min(OUR_MAX_CAPACITY);
        if ours > 0 && !self.capacity_sent {
            push_int(&mut self.out, ours as u64, 5, 0x20);
            self.table.set_capacity(ours);
            self.capacity_sent = true;
        }
    }

    /// Acknowledgments set how far references may go.
    pub fn on_decoder_stream(&mut self, data: &[u8]) -> Result<(), ()> {
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

    /// Prefers the static table, then acknowledged dynamic entries, then literals; referencing an
    /// unacknowledged entry would block the peer's stream.
    ///
    /// Returns the field section and the encoder stream instructions, which go on a separate
    /// stream.
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

    /// Puts unsent instructions back in front, keeping their order.
    pub(crate) fn restore_encoder_stream(&mut self, mut data: Vec<u8>) {
        data.append(&mut self.out);
        self.out = data;
    }

    /// Only entries up to here may be referenced.
    pub fn known_received(&self) -> u64 {
        self.known_received
    }

    pub fn insert_count(&self) -> u64 {
        self.table.insert_count
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

enum FieldPlan {
    Static(u64),
    Dynamic(u64),
    LiteralNameRef(u64, Vec<u8>),
    Literal(Vec<u8>, Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(h: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
        h.iter()
            .find(|(n, _)| n == name.as_bytes())
            .map(|(_, v)| v.as_slice())
    }

    #[test]
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
    fn static_table_key_entries() {
        assert_eq!(STATIC[20], (":method", "POST"));
        assert_eq!(STATIC[25], (":status", "200"));
        assert_eq!(STATIC[44], ("content-type", "application/dns-message"));
        assert_eq!(STATIC.len(), 99);
    }

    #[test]
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
    fn dynamic_table_reference_rejected() {
        let buf = [0x01u8, 0x00];
        assert!(decode_field_section(&buf).is_none());
    }

    #[test]
    fn static_decoder_bounds_expanded_header_lists() {
        let mut buf = vec![0, 0];
        buf.extend(std::iter::repeat_n(0xc0 | 20, 1024));
        assert!(decode_field_section(&buf).is_none());
    }

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
    /// Mixing it up with the 7-bit prefix of acknowledgments would misread stream IDs of 63 and
    /// above.
    fn stream_cancellation_uses_a_six_bit_prefix() {
        let mut dec = Decoder::new(4096);
        dec.cancel_stream(4);
        dec.cancel_stream(100);
        let instructions = dec.take_decoder_stream();
        assert_eq!(instructions, vec![0x44, 0x7f, 0x25]);
        assert_eq!(Encoder::new().on_decoder_stream(&instructions), Ok(()));
    }

    #[test]
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
    fn many_capacity_updates_are_processed() {
        let updates = vec![0x20; 32 * 1024];
        let mut dec = Decoder::new(4096);
        dec.on_encoder_stream(&updates).unwrap();
        assert!(dec.enc_buf.is_empty());
    }

    #[test]
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
