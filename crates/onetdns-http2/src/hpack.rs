//! HPACK header compression (RFC 7541). The dynamic table is compression context shared for the
//! whole connection: one wrong table update desyncs every later header, so errors are connection
//! errors, not stream errors.

use std::collections::VecDeque;

use crate::huffman;

/// HPACK allows compression bombs: a few bytes that keep referencing a dynamic table entry build a
/// huge header list, so the decoded total itself is capped.
const MAX_DECODED_HEADER_LIST: usize = 32 * 1024;

/// The RFC 7541 static table; indexes start at 1.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Reads an HPACK integer whose first byte holds `prefix_bits` bits of the value. Returns the value
/// and the bytes consumed; `None` when it would overflow, since continuation bytes could otherwise
/// go on forever.
pub fn decode_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if !(1..=8).contains(&prefix_bits) {
        return None;
    }
    let mask = (1u16 << prefix_bits) as u64 - 1;
    let first = *buf.first()? as u64;
    let mut value = first & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut m = 0u32;
    let mut i = 1usize;
    loop {
        let b = *buf.get(i)? as u64;
        i += 1;
        let low = b & 0x7f;
        if m >= 64 || low > (u64::MAX >> m) {
            return None;
        }
        value = value.checked_add(low << m)?;
        m += 7;
        if b & 0x80 == 0 {
            break;
        }
        if m > 63 {
            return None;
        }
    }
    Some((value, i))
}

/// `first_high` holds the indicator bits above the prefix in the first byte.
pub fn encode_int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, first_high: u8) {
    let mask = (1u16 << prefix_bits) as u64 - 1;
    if value < mask {
        out.push(first_high | value as u8);
        return;
    }
    out.push(first_high | mask as u8);
    let mut v = value - mask;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A set high bit means Huffman encoding.
fn decode_string(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let huff = buf.first()? & 0x80 != 0;
    let (len, n) = decode_int(buf, 7)?;
    let end = n.checked_add(usize::try_from(len).ok()?)?;
    let raw = buf.get(n..end)?;
    let s = if huff {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Some((s, end))
}

/// Huffman is used only when it comes out shorter.
fn encode_string(out: &mut Vec<u8>, s: &[u8], use_huffman: bool) {
    let huff = use_huffman && s.iter().all(|&b| b < 128);
    if huff {
        let enc = huffman::encode(s);
        if enc.len() < s.len() {
            encode_int(out, enc.len() as u64, 7, 0x80);
            out.extend_from_slice(&enc);
            return;
        }
    }
    encode_int(out, s.len() as u64, 7, 0x0);
    out.extend_from_slice(s);
}

/// Keeps the dynamic table for the whole connection. `max_size <= allowed_max_size`, so the peer
/// cannot grow the table past what this side advertised.
pub struct Decoder {
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    /// Current limit, set by table size updates.
    max_size: usize,
    /// Limit advertised to the peer; a larger table size update is refused.
    allowed_max_size: usize,
}

/// The 32 is the per-entry overhead the protocol defines.
fn entry_size(n: &[u8], v: &[u8]) -> usize {
    n.len() + v.len() + 32
}

impl Decoder {
    /// `max_size` is the table size advertised to the peer.
    pub fn new(max_size: usize) -> Self {
        Decoder {
            dynamic: VecDeque::new(),
            size: 0,
            max_size,
            allowed_max_size: max_size,
        }
    }

    /// Static entries come first, then dynamic ones, newest first. Index 0 is invalid.
    fn lookup(&self, index: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return None;
        }
        let i = usize::try_from(index).ok()?;
        if i <= STATIC.len() {
            let (n, v) = STATIC[i - 1];
            Some((n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        } else {
            self.dynamic.get(i - STATIC.len() - 1).cloned()
        }
    }

    /// Inserts at the front of the dynamic table, evicting the oldest entries on overflow.
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let es = entry_size(&name, &value);
        self.dynamic.push_front((name, value));
        self.size += es;
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            if let Some((n, v)) = self.dynamic.pop_back() {
                self.size -= entry_size(&n, &v);
            } else {
                break;
            }
        }
    }

    /// Refuses a size above the advertised limit; accepting it would let the peer decide this
    /// side's memory use.
    fn set_max(&mut self, m: usize) -> bool {
        if m > self.allowed_max_size {
            return false;
        }
        self.max_size = m;
        self.evict();
        true
    }

    /// Stops at the cap on total decoded size, which defends against compression bombs. Table size
    /// updates are allowed only at the start of a block; elsewhere, implementations would disagree
    /// on the table state and later headers would desync.
    ///
    /// `None` on any violation; the caller treats it as a connection error.
    pub fn decode(&mut self, mut buf: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut decoded_size = 0usize;
        let mut size_updates = 0u8;
        let mut first_size_update = None;
        let mut account = |name: &[u8], value: &[u8]| -> Option<()> {
            decoded_size = decoded_size.checked_add(name.len() + value.len() + 32)?;
            (decoded_size <= MAX_DECODED_HEADER_LIST).then_some(())
        };
        while let Some(&first) = buf.first() {
            if first & 0x80 != 0 {
                let (idx, n) = decode_int(buf, 7)?;
                let (name, value) = self.lookup(idx)?;
                account(&name, &value)?;
                out.push((name, value));
                buf = &buf[n..];
            } else if first & 0x40 != 0 {
                let (name, value, consumed) = self.read_literal(buf, 6)?;
                account(&name, &value)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
                buf = &buf[consumed..];
            } else if first & 0x20 != 0 {
                let (new_size, n) = decode_int(buf, 5)?;
                let new_size = usize::try_from(new_size).ok()?;
                if !out.is_empty()
                    || size_updates >= 2
                    || first_size_update.is_some_and(|first| new_size < first)
                    || !self.set_max(new_size)
                {
                    return None;
                }
                size_updates += 1;
                first_size_update.get_or_insert(new_size);
                buf = &buf[n..];
            } else {
                let (name, value, consumed) = self.read_literal(buf, 4)?;
                account(&name, &value)?;
                out.push((name, value));
                buf = &buf[consumed..];
            }
        }
        Some(out)
    }

    /// The name comes as an index or a string.
    fn read_literal(&self, buf: &[u8], prefix_bits: u8) -> Option<(Vec<u8>, Vec<u8>, usize)> {
        let (name_idx, mut pos) = decode_int(buf, prefix_bits)?;
        let name = if name_idx == 0 {
            let (n, used) = decode_string(&buf[pos..])?;
            pos += used;
            n
        } else {
            let (n, _) = self.lookup(name_idx)?;
            n
        };
        let (value, used) = decode_string(&buf[pos..])?;
        pos += used;
        Some((name, value, pos))
    }
}

/// Emits only literals without indexing and never touches the dynamic table. DoH responses carry a
/// few headers, so compression gains little, and having no encoder table state is simpler.
pub fn encode_response(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, value) in headers {
        if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
            encode_int(&mut out, (i + 1) as u64, 7, 0x80);
            continue;
        }

        if let Some(i) = STATIC.iter().position(|&(n, _)| n == name) {
            encode_int(&mut out, (i + 1) as u64, 4, 0x00);
            encode_string(&mut out, value.as_bytes(), true);
        } else {
            out.push(0x00);
            encode_string(&mut out, name.as_bytes(), true);
            encode_string(&mut out, value.as_bytes(), true);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[u8]) -> String {
        String::from_utf8(v.to_vec()).unwrap()
    }

    #[test]
    fn integer_rfc_examples() {
        let mut o = Vec::new();
        encode_int(&mut o, 10, 5, 0);
        assert_eq!(o, vec![0x0a]);
        assert_eq!(decode_int(&[0x0a], 5).unwrap(), (10, 1));

        let mut o = Vec::new();
        encode_int(&mut o, 1337, 5, 0);
        assert_eq!(o, vec![0x1f, 0x9a, 0x0a]);
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 5).unwrap(), (1337, 3));
    }

    #[test]
    fn decode_indexed_static() {
        let mut d = Decoder::new(4096);
        let hs = d.decode(&[0x82]).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(s(&hs[0].0), ":method");
        assert_eq!(s(&hs[0].1), "GET");
    }

    #[test]
    fn rfc_c31_request_with_huffman_and_indexing() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut d = Decoder::new(4096);
        let hs = d.decode(&block).unwrap();
        assert_eq!(hs.len(), 4);
        assert_eq!((s(&hs[0].0), s(&hs[0].1)), (":method".into(), "GET".into()));
        assert_eq!(
            (s(&hs[1].0), s(&hs[1].1)),
            (":scheme".into(), "http".into())
        );
        assert_eq!((s(&hs[2].0), s(&hs[2].1)), (":path".into(), "/".into()));
        assert_eq!(
            (s(&hs[3].0), s(&hs[3].1)),
            (":authority".into(), "www.example.com".into())
        );
    }

    #[test]
    fn encode_then_decode_response() {
        let block = encode_response(&[
            (":status", "200"),
            ("content-type", "application/dns-message"),
            ("content-length", "42"),
        ]);
        let mut d = Decoder::new(4096);
        let hs = d.decode(&block).unwrap();
        assert_eq!(hs.len(), 3);
        assert_eq!(
            (s(&hs[0].0).as_str(), s(&hs[0].1).as_str()),
            (":status", "200")
        );
        assert_eq!(s(&hs[1].0), "content-type");
        assert_eq!(s(&hs[1].1), "application/dns-message");
        assert_eq!(s(&hs[2].1), "42");
    }

    #[test]
    fn literal_with_incremental_indexing_roundtrips_dynamic() {
        let mut d = Decoder::new(4096);

        let mut block = vec![0x40];
        encode_string(&mut block, b"x-custom", false);
        encode_string(&mut block, b"hello", false);
        let hs = d.decode(&block).unwrap();
        assert_eq!(s(&hs[0].0), "x-custom");
        assert_eq!(s(&hs[0].1), "hello");

        let hs2 = d.decode(&[0xbe]).unwrap();
        assert_eq!(s(&hs2[0].0), "x-custom");
        assert_eq!(s(&hs2[0].1), "hello");
    }

    #[test]
    /// Allowing them mid-block desyncs the two tables.
    fn table_size_updates_are_limited_to_the_start_of_a_header_block() {
        let mut after_header = vec![0x82];
        encode_int(&mut after_header, 0, 5, 0x20);
        assert!(Decoder::new(4096).decode(&after_header).is_none());

        let three_updates = [0x20, 0x20, 0x20, 0x82];
        assert!(Decoder::new(4096).decode(&three_updates).is_none());
    }

    #[test]
    fn decoded_header_list_is_bounded_at_the_advertised_limit() {
        let block = vec![0x82; 1024];
        assert!(Decoder::new(4096).decode(&block).is_none());
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn rejects_lengths_indexes_and_table_sizes_wider_than_usize() {
        let wider = u64::from(u32::MAX) + 1;

        let mut string = Vec::new();
        encode_int(&mut string, wider, 7, 0);
        assert!(decode_string(&string).is_none());

        let mut indexed = Vec::new();
        encode_int(&mut indexed, wider + 2, 7, 0x80);
        assert!(Decoder::new(4096).decode(&indexed).is_none());

        let mut table_update = Vec::new();
        encode_int(&mut table_update, wider, 5, 0x20);
        assert!(Decoder::new(4096).decode(&table_update).is_none());
    }
}
