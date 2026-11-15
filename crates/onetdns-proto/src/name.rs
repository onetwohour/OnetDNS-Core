//! DNS names: label storage, parsing, and compressed encoding. A name is stored as its wire-format
//! label octets, not as a String: labels need not be UTF-8, and a round trip through a string would
//! corrupt octets like 0xFF and make different names look equal. Case is ignored only when
//! comparing.

use std::borrow::Cow;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher};
use std::sync::{Arc, LazyLock};

use crate::wire::{Reader, Writer};
use crate::ProtoError;

/// Compression pointers one name may follow. Without a cap, pointers aiming at each other loop
/// forever; even with backward-only pointers, the chain length must be bounded to bound expansion
/// cost.
const MAX_JUMPS: usize = 20;

/// Including length octets and the root label (RFC 1035).
const MAX_NAME_LEN: usize = 255;

/// Entries NameMap::clear keeps for reuse. Compression state is discarded per message; keeping the
/// capacity left by one pathological message would tie up that memory for the worker's lifetime, so
/// everything is dropped past this.
const MAX_RETAINED_NAME_ENTRIES: usize = 64;

/// Every root Name shares this, so the root never allocates.
static ROOT_WIRE: LazyLock<Arc<[u8]>> = LazyLock::new(|| Arc::from([0u8]));

/// Walks labels from either end without copying. `front` and `back` are byte offsets into the wire.
/// Labels are length-prefixed, so stepping back one label means scanning from the front again,
/// which is why next_back is linear.
///
/// `back` excludes the root label's 0 octet.
#[derive(Debug, Clone, Copy)]
pub struct Labels<'a> {
    wire: &'a [u8],
    front: usize,
    back: usize,
}

impl<'a> Labels<'a> {
    pub fn iter(&self) -> Self {
        *self
    }

    pub fn first(&self) -> Option<&'a [u8]> {
        let mut labels = *self;
        labels.next()
    }

    /// Counts in O(labels): the storage is a chain of length prefixes.
    pub fn len(&self) -> usize {
        let mut count = 0;
        let mut cursor = self.front;
        while cursor < self.back {
            let Some(&len) = self.wire.get(cursor) else {
                break;
            };
            cursor += usize::from(len) + 1;
            count += 1;
        }
        count
    }

    pub fn is_empty(&self) -> bool {
        self.front >= self.back
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let len = usize::from(*self.wire.get(self.front)?);
        let start = self.front + 1;
        let end = start.checked_add(len)?;
        if end > self.back {
            return None;
        }
        let label = self.wire.get(start..end)?;
        self.front = end;
        Some(label)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.back.saturating_sub(self.front) / 2))
    }
}

impl PartialEq for Labels<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Labels<'_> {}

impl<'a> DoubleEndedIterator for Labels<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front >= self.back {
            return None;
        }
        let mut last = self.front;
        let mut cursor = self.front;
        while cursor < self.back {
            last = cursor;
            cursor += usize::from(*self.wire.get(cursor)?) + 1;
        }
        let len = usize::from(*self.wire.get(last)?);
        self.back = last;
        self.wire.get(last + 1..last + 1 + len)
    }
}

/// Uncompressed wire form in shared ownership. `Arc<[u8]>` makes a clone a reference count
/// increment; names are cloned constantly in response assembly and cache keys, so this removes
/// hot-path allocations.
///
/// The derived PartialEq is case-sensitive; use eq_ignore_case for DNS comparison. Hash and Ord see
/// the same bytes, so as hash map keys, names differing in case are different entries.
///
/// `wire` always ends in a 0 octet and is at most MAX_NAME_LEN long.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name {
    wire: Arc<[u8]>,
}

impl Default for Name {
    fn default() -> Self {
        Self::root()
    }
}

impl Name {
    /// Shares the global wire, so it does not allocate.
    pub fn root() -> Self {
        Self {
            wire: Arc::clone(&ROOT_WIRE),
        }
    }

    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// Excludes the trailing root label.
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            wire: &self.wire,
            front: 0,
            back: self.wire.len().saturating_sub(1),
        }
    }

    /// 0 for the root.
    pub fn num_labels(&self) -> usize {
        self.labels().len()
    }

    /// Parses presentation format, decoding RFC 1035 escapes: a backslash and three decimal digits
    /// is one octet of that value, and a backslash before any other character removes its special
    /// meaning. An escaped dot is a byte inside the label, not a separator.
    ///
    /// Without decoding them, names in zone files written by other servers change silently: a label
    /// containing a dot becomes two labels, and a decimal escape stays four characters.
    ///
    /// One trailing unescaped dot marks the root. Empty labels, labels over 63 octets, and names
    /// over 255 octets are refused.
    pub fn from_str(s: &str) -> Result<Self, ProtoError> {
        let bytes = s.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut index = 0usize;
        let mut ended_with_separator = false;

        while index < bytes.len() {
            match bytes[index] {
                b'\\' => {
                    let digits = bytes
                        .get(index + 1..index + 4)
                        .filter(|triple| triple.iter().all(|byte| byte.is_ascii_digit()));
                    if let Some(triple) = digits {
                        let value = triple
                            .iter()
                            .fold(0u16, |acc, byte| acc * 10 + u16::from(byte - b'0'));
                        if value > 255 {
                            return Err(ProtoError::Name("Decimal escape exceeds 255".into()));
                        }
                        current.push(value as u8);
                        index += 4;
                    } else if let Some(byte) = bytes.get(index + 1) {
                        current.push(*byte);
                        index += 2;
                    } else {
                        return Err(ProtoError::Name("Unterminated escape".into()));
                    }
                    ended_with_separator = false;
                }
                b'.' => {
                    labels.push(std::mem::take(&mut current));
                    index += 1;
                    ended_with_separator = true;
                }
                byte => {
                    current.push(byte);
                    index += 1;
                    ended_with_separator = false;
                }
            }
        }
        if !ended_with_separator {
            labels.push(current);
        }

        if labels.is_empty() || (labels.len() == 1 && labels[0].is_empty()) {
            return Ok(Self::root());
        }
        if labels.iter().any(Vec::is_empty) {
            return Err(ProtoError::Name("Root label appears more than once".into()));
        }
        Self::from_labels(labels)
    }

    /// Lowercase form for zone files, escaping bytes with special meaning. to_ascii_lower is
    /// display-only and cannot round-trip a label containing a dot or space; any string read back
    /// must come from here, or writing a zone to a file and reading it back changes names. No
    /// trailing dot; the caller decides on absolute notation.
    pub fn to_master_lower(&self) -> String {
        let mut out = String::with_capacity(self.wire.len());
        for (index, label) in self.labels().enumerate() {
            if index != 0 {
                out.push('.');
            }
            for &byte in label {
                match byte {
                    b'.' | b'\\' | b'"' | b'(' | b')' | b';' | b'@' | b'$' => {
                        out.push('\\');
                        out.push(byte as char);
                    }
                    0x21..=0x7e => out.push(byte.to_ascii_lowercase() as char),
                    other => out.push_str(&format!("\\{other:03}")),
                }
            }
        }
        out
    }

    /// Labels need not be UTF-8; each must be 1 to 63 octets, and the total is checked for overflow
    /// too.
    pub fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, ProtoError> {
        let mut total = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(ProtoError::Name("Invalid label length".into()));
            }
            total = total
                .checked_add(label.len() + 1)
                .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
        }
        if total > MAX_NAME_LEN {
            return Err(ProtoError::Name("Name too long".into()));
        }
        let mut wire = Vec::with_capacity(total);
        for label in labels {
            wire.push(label.len() as u8);
            wire.extend_from_slice(&label);
        }
        wire.push(0);
        Ok(Self { wire: wire.into() })
    }

    /// Lowercased wire form, for cache and map keys. Length prefixes stay: joining with dots would
    /// make a.b+c and a+b.c the same key. Allocates; hot paths use canonical_key_into.
    pub fn canonical_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire.len());
        for label in self.labels() {
            out.push(label.len() as u8);
            out.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        out.push(0);
        out
    }

    /// Writes the canonical key into `out` without allocating; usually a [u8; 255] stack array.
    /// `None` when `out` is too small.
    pub fn canonical_key_into<'a>(&self, out: &'a mut [u8]) -> Option<&'a [u8]> {
        self.write_canonical_from(0, out)
    }

    /// Canonical key of the rightmost `label_count` labels, without building the suffix name. QNAME
    /// minimization and zone selection use it to walk several suffixes of one name. A count above
    /// the actual one gives the whole name.
    pub fn canonical_suffix_key_into<'a>(
        &self,
        label_count: usize,
        out: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let total = self.num_labels();
        let skip = total.saturating_sub(label_count.min(total));
        let mut start = 0;
        for _ in 0..skip {
            start += usize::from(*self.wire.get(start)?) + 1;
        }
        self.write_canonical_from(start, out)
    }

    /// `start` must be a label boundary; anywhere else yields a broken name.
    fn write_canonical_from<'a>(&self, start: usize, out: &'a mut [u8]) -> Option<&'a [u8]> {
        let needed = self.wire.len().checked_sub(start)?;
        if needed > out.len() {
            return None;
        }
        let mut offset = 0;
        let labels = Labels {
            wire: &self.wire,
            front: start,
            back: self.wire.len().checked_sub(1)?,
        };
        for label in labels {
            out[offset] = label.len() as u8;
            offset += 1;
            for &byte in label {
                out[offset] = byte.to_ascii_lowercase();
                offset += 1;
            }
        }
        out[offset] = 0;
        Some(&out[..needed])
    }

    /// Lowercase dotted form without a trailing dot. Non-UTF-8 labels convert lossily to
    /// replacement characters; display and logs only, never parse it back.
    pub fn to_ascii_lower(&self) -> String {
        let mut out = String::with_capacity(self.wire.len().saturating_sub(1));
        for (index, label) in self.labels().enumerate() {
            if index != 0 {
                out.push('.');
            }
            out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        }
        out
    }

    /// The derived PartialEq and Hash are case-sensitive, so names collected as hash map keys must
    /// go through this, or one name splits into several. An already lowercase name is borrowed
    /// without touching even the reference count; aggregation then only bumps a counter.
    ///
    /// Length octets in an uncompressed wire are 1..=63 and the end is 0, which never overlaps
    /// ASCII uppercase (65..=90), so lowering the whole wire is safe.
    pub fn to_ascii_lower_name(&self) -> Cow<'_, Name> {
        if !self.wire.iter().any(|byte| byte.is_ascii_uppercase()) {
            return Cow::Borrowed(self);
        }
        let lowered: Vec<u8> = self.wire.iter().map(|b| b.to_ascii_lowercase()).collect();
        Cow::Owned(Self {
            wire: Arc::from(lowered),
        })
    }

    /// Ancestor made of the rightmost `n` labels; an `n` above the actual count gives a copy of the
    /// name.
    pub fn suffix(&self, n: usize) -> Name {
        let total = self.num_labels();
        let mut skip = total.saturating_sub(n.min(total));
        let mut start = 0;
        while skip != 0 {
            start += usize::from(self.wire[start]) + 1;
            skip -= 1;
        }
        Name {
            wire: Arc::from(&self.wire[start..]),
        }
    }

    /// DNS name comparison: label octets compared ASCII case-insensitively.
    pub fn eq_ignore_case(&self, other: &Name) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }

    /// Whether `suffix` is this name or an ancestor of it. Matches only at label boundaries: x.test
    /// is under test, attest is not. Bailiwick and zone membership checks rely on this.
    pub fn ends_with_ignore_case(&self, suffix: &Name) -> bool {
        let own_labels = self.num_labels();
        let suffix_labels = suffix.num_labels();
        if own_labels < suffix_labels {
            return false;
        }
        let mut start = 0;
        for _ in 0..own_labels - suffix_labels {
            start += usize::from(self.wire[start]) + 1;
        }
        self.wire[start..].eq_ignore_ascii_case(&suffix.wire)
    }

    /// Accepts uncompressed wire bytes whose label chain ends in a 0 octet exactly at the slice
    /// end. Trailing bytes and compression pointers are refused: a name read from storage has no
    /// message to resolve pointers against.
    pub fn from_uncompressed_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
            return None;
        }
        let mut pos = 0usize;
        loop {
            let len = *bytes.get(pos)? as usize;
            if len == 0 {
                return (pos + 1 == bytes.len()).then(|| {
                    if bytes.len() == 1 {
                        Self::root()
                    } else {
                        Self {
                            wire: Arc::from(bytes),
                        }
                    }
                });
            }
            if len & 0xC0 != 0 {
                return None;
            }
            pos = pos.checked_add(1)?.checked_add(len)?;
        }
    }

    pub fn as_uncompressed_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Follows compression pointers while reading a name. Pointers may only point backward (ptr >=
    /// pos is refused), the first defense against loops; MAX_JUMPS bounds the chain as the second.
    /// The expanded result is checked against 255 octets at every label, so a short message cannot
    /// inflate into a huge name.
    ///
    /// The cursor ends after the first pointer, not where the pointers led, so the fields that
    /// follow are read in place.
    ///
    /// Loops, reserved bits, overlong names, and out-of-range pointers are all errors.
    pub fn parse(r: &mut Reader) -> Result<Self, ProtoError> {
        let buf = r.buf;
        let mut wire = [0u8; MAX_NAME_LEN];
        let mut wire_len = 0usize;
        let mut pos = r.pos;
        let mut jumped = false;
        let mut jumps = 0usize;
        let mut end = r.pos;
        let mut total = 1usize;

        loop {
            if !jumped && pos >= r.limit {
                return Err(ProtoError::Eof);
            }
            let len = *buf.get(pos).ok_or(ProtoError::Eof)? as usize;
            match len & 0xC0 {
                0x00 => {
                    if len == 0 {
                        if !jumped {
                            end = pos + 1;
                        }
                        break;
                    }
                    let start = pos.checked_add(1).ok_or(ProtoError::Eof)?;
                    let label_end = start.checked_add(len).ok_or(ProtoError::Eof)?;
                    if !jumped && label_end > r.limit {
                        return Err(ProtoError::Eof);
                    }
                    let lab = buf.get(start..label_end).ok_or(ProtoError::Eof)?;
                    total = total
                        .checked_add(len + 1)
                        .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
                    if total > MAX_NAME_LEN {
                        return Err(ProtoError::Name("Name too long".into()));
                    }
                    wire[wire_len] = len as u8;
                    wire_len += 1;
                    let wire_end = wire_len + len;
                    wire[wire_len..wire_end].copy_from_slice(lab);
                    wire_len = wire_end;
                    pos = label_end;
                }
                0xC0 => {
                    if !jumped && pos.checked_add(2).ok_or(ProtoError::Eof)? > r.limit {
                        return Err(ProtoError::Eof);
                    }
                    let b2 = *buf.get(pos + 1).ok_or(ProtoError::Eof)? as usize;
                    if !jumped {
                        end = pos + 2;
                    }
                    jumped = true;
                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(ProtoError::Name("Compression pointer loop".into()));
                    }
                    let ptr = ((len & 0x3F) << 8) | b2;
                    if ptr >= pos {
                        return Err(ProtoError::Name("Invalid compression pointer".into()));
                    }
                    pos = ptr;
                }
                _ => return Err(ProtoError::Name("Reserved label length bits".into())),
            }
        }
        r.pos = end;
        if wire_len == 0 {
            return Ok(Self::root());
        }
        wire[wire_len] = 0;
        Ok(Self {
            wire: Arc::from(&wire[..=wire_len]),
        })
    }

    /// DNSSEC canonical form and some RDATA forbid pointers; a set 0xC0 bit is refused without
    /// following it.
    pub(crate) fn parse_uncompressed(r: &mut Reader) -> Result<Self, ProtoError> {
        let mut wire = [0u8; MAX_NAME_LEN];
        let mut wire_len = 0usize;
        let mut total = 1usize;
        loop {
            let len = r.u8()? as usize;
            if len == 0 {
                if wire_len == 0 {
                    return Ok(Self::root());
                }
                wire[wire_len] = 0;
                return Ok(Self {
                    wire: Arc::from(&wire[..=wire_len]),
                });
            }
            if len & 0xc0 != 0 || len > 63 {
                return Err(ProtoError::Name(
                    "Invalid label in a DNS name that cannot be compressed".into(),
                ));
            }
            total = total
                .checked_add(len + 1)
                .ok_or_else(|| ProtoError::Name("Name too long".into()))?;
            if total > MAX_NAME_LEN {
                return Err(ProtoError::Name("Name too long".into()));
            }
            wire[wire_len] = len as u8;
            wire_len += 1;
            let wire_end = wire_len + len;
            wire[wire_len..wire_end].copy_from_slice(r.bytes(len)?);
            wire_len = wire_end;
        }
    }

    /// Replaces a known suffix with a compression pointer, looking up the canonical key of the
    /// remaining suffix at every label boundary so suffixes differing only in case still compress.
    /// Pointer offsets have 14 bits, so positions from 0x4000 on are not recorded; an offset that
    /// cannot be expressed would later produce a wrong pointer.
    pub fn encode(&self, w: &mut Writer) {
        let mut key_buf = [0u8; MAX_NAME_LEN];
        let Some(key) = self.canonical_key_into(&mut key_buf) else {
            w.fail("Canonical DNS name key exceeds 255 bytes");
            return;
        };
        let mut key_offset = 0;
        for label in self.labels() {
            let key = &key[key_offset..];
            if let Some(off) = w.names.get(key) {
                w.push_u16(0xC000 | off);
                return;
            }
            if !w.is_failed() && w.buf.len() < 0x4000 {
                w.names.insert(key, w.buf.len() as u16);
            }
            w.push_u8(label.len() as u8);
            w.push_bytes(label);
            key_offset += label.len() + 1;
        }
        w.push_u8(0);
    }

    /// For the canonical form under signatures, and for RDATA where compression could break on
    /// reserialization.
    pub(crate) fn encode_uncompressed(&self, w: &mut Writer) {
        w.push_bytes(&self.wire);
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for l in self.labels() {
            write!(f, "{}.", String::from_utf8_lossy(l))?;
        }
        Ok(())
    }
}

/// Compression offset table of the message being encoded. Entries pile up in the `entries` arena
/// and `heads` maps a hash to the head of its chain. `active` is the logical length, so clear
/// reuses the entry allocations; a new table per message would add an allocation to every response.
///
/// Offsets are always below 0x4000, expressible in 14 bits; callers guarantee this.
#[derive(Default)]
pub(crate) struct NameMap {
    heads: HashMap<u64, usize, BuildHasherDefault<IdentityHasher>>,
    entries: Vec<NameMapEntry>,
    active: usize,
    hash_builder: RandomState,
}

/// `next` is the next arena index in the hash collision chain.
struct NameMapEntry {
    key: Vec<u8>,
    offset: u16,
    next: Option<usize>,
}

/// Passes an already hashed value through. hash_builder, randomly seeded, hashes each key once and
/// the map uses that u64 without rehashing; the random seed keeps resistance to collision attacks.
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut value = 0u64;
        for (shift, byte) in bytes.iter().take(8).enumerate() {
            value |= u64::from(*byte) << (shift * 8);
        }
        self.0 = value;
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

impl NameMap {
    fn hash(&self, key: &[u8]) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        hasher.write(key);
        hasher.finish()
    }

    /// Compares the whole key even when hashes match: one collision turning into a wrong pointer
    /// would put the wrong name in the response.
    pub(crate) fn get(&self, key: &[u8]) -> Option<u16> {
        let mut current = self.heads.get(&self.hash(key)).copied();
        while let Some(index) = current {
            let entry = self.entries.get(index)?;
            if entry.key == key {
                return Some(entry.offset);
            }
            current = entry.next;
        }
        None
    }

    /// Reuses the Vec of a used arena slot instead of allocating.
    pub(crate) fn insert(&mut self, key: &[u8], offset: u16) {
        let hash = self.hash(key);
        let next = self.heads.insert(hash, self.active);
        if let Some(entry) = self.entries.get_mut(self.active) {
            entry.key.clear();
            entry.key.extend_from_slice(key);
            entry.offset = offset;
            entry.next = next;
        } else {
            self.entries.push(NameMapEntry {
                key: key.to_vec(),
                offset,
                next,
            });
        }
        self.active += 1;
    }

    /// Usually only the index is cleared so the arena is reused; a pathologically grown table is
    /// dropped entirely, so the worker does not hold that memory forever.
    pub(crate) fn clear(&mut self) {
        if self.entries.len() > MAX_RETAINED_NAME_ENTRIES {
            self.entries = Vec::new();
            self.heads = HashMap::default();
        } else {
            self.heads.clear();
        }
        self.active = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.active == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Without decoding, names in zone files from other servers change silently: a label containing
    /// a dot becomes two, and a decimal escape stays four characters. The writer must match too, so
    /// exporting to a file and reading back does not change names.
    fn escapes_in_names_are_decoded_and_written_back() {
        // \X removes the character's special meaning: one label containing a dot.
        let dotted = Name::from_str(r"a\.b.example").unwrap();
        let labels: Vec<&[u8]> = dotted.labels().collect();
        assert_eq!(labels, vec![b"a.b".as_slice(), b"example".as_slice()]);

        // \DDD is the octet the decimal number names; 065 is A.
        let decimal = Name::from_str(r"esc\065ape.example").unwrap();
        let labels: Vec<&[u8]> = decimal.labels().collect();
        assert_eq!(labels[0], b"escAape".as_slice());

        // A space is written as a decimal escape too.
        let spaced = Name::from_str(r"sp\032ace.example").unwrap();
        assert_eq!(spaced.labels().next().unwrap(), b"sp ace".as_slice());

        // The writer must escape again for a round trip.
        for name in [r"a\.b.example", r"esc\065ape.example", r"sp\032ace.example"] {
            let parsed = Name::from_str(name).unwrap();
            let written = parsed.to_master_lower();
            let again = Name::from_str(&written).unwrap();
            // The writer lowercases, so compare case-insensitively; in DNS these are the same name.
            assert!(
                parsed.eq_ignore_case(&again),
                "{name} 이 왕복하지 않습니다: {written}"
            );
            assert_eq!(
                parsed.num_labels(),
                again.num_labels(),
                "{name} 의 라벨 경계가 달라졌습니다: {written}"
            );
        }

        // Only an unescaped trailing dot marks the root.
        assert_eq!(
            Name::from_str("example.").unwrap(),
            Name::from_str("example").unwrap()
        );
        assert!(Name::from_str("a..b").is_err(), "빈 라벨은 거부한다");
        assert!(
            Name::from_str(r"a\").is_err(),
            "끝나지 않은 이스케이프는 거부한다"
        );
        assert!(
            Name::from_str(r"a\999").is_err(),
            "255를 넘는 십진값은 거부한다"
        );

        // Plain names come out unchanged.
        assert_eq!(
            Name::from_str("www.example.com").unwrap().to_master_lower(),
            "www.example.com"
        );
    }

    #[test]
    fn roundtrip_simple() {
        let n = Name::from_str("www.example.com").unwrap();
        let mut w = Writer::new();
        n.encode(&mut w);

        assert_eq!(w.buf.len(), 17);
        let mut r = Reader::new(&w.buf);
        let back = Name::parse(&mut r).unwrap();
        assert!(n.eq_ignore_case(&back));
        assert_eq!(back.to_ascii_lower(), "www.example.com");
    }

    #[test]
    /// Copying every time would allocate per name.
    fn clone_shares_immutable_label_storage() {
        let name = Name::from_str("www.example.com").unwrap();
        let cloned = name.clone();

        assert!(Arc::ptr_eq(&name.wire, &cloned.wire));
        assert_eq!(name, cloned);
    }

    #[test]
    fn contiguous_wire_preserves_label_views_and_reverse_iteration() {
        let name = Name::from_labels(vec![b"WwW".to_vec(), vec![0xff], b"TEST".to_vec()]).unwrap();

        assert_eq!(&*name.wire, b"\x03WwW\x01\xff\x04TEST\0");
        assert!(name
            .labels()
            .eq([b"WwW".as_slice(), [0xff].as_slice(), b"TEST".as_slice()]));
        assert!(name
            .labels()
            .rev()
            .eq([b"TEST".as_slice(), [0xff].as_slice(), b"WwW".as_slice()]));
        let mut alternating = name.labels();
        assert_eq!(alternating.next(), Some(b"WwW".as_slice()));
        assert_eq!(alternating.next_back(), Some(b"TEST".as_slice()));
        assert_eq!(alternating.next(), Some([0xff].as_slice()));
        assert_eq!(alternating.next_back(), None);
        assert!(name.ends_with_ignore_case(&Name::from_str("test").unwrap()));
        assert!(!name.ends_with_ignore_case(&Name::from_str("x.test").unwrap()));
    }

    #[test]
    fn compression_pointer() {
        let base = Name::from_str("example.com").unwrap();
        let sub = Name::from_str("www.example.com").unwrap();
        let mut w = Writer::new();
        base.encode(&mut w);
        let after_base = w.buf.len();
        sub.encode(&mut w);

        assert_eq!(w.buf.len() - after_base, 6);

        let mut r = Reader::new(&w.buf);
        let _ = Name::parse(&mut r).unwrap();
        let parsed_sub = Name::parse(&mut r).unwrap();
        assert_eq!(parsed_sub.to_ascii_lower(), "www.example.com");
    }

    #[test]
    /// Allowing it would let a loop spin forever.
    fn rejects_forward_pointer_loop() {
        let buf = [0xC0u8, 0x00];
        let mut r = Reader::new(&buf);
        assert!(Name::parse(&mut r).is_err());
    }

    #[test]
    fn root_name() {
        let n = Name::root();
        let mut w = Writer::new();
        n.encode(&mut w);
        assert_eq!(w.buf, vec![0]);
    }

    #[test]
    fn parsed_root_names_share_the_global_storage() {
        let mut compressed_reader = Reader::new(&[0]);
        let compressed = Name::parse(&mut compressed_reader).unwrap();
        assert!(Arc::ptr_eq(&compressed.wire, &ROOT_WIRE));

        let mut uncompressed_reader = Reader::new(&[0]);
        let uncompressed = Name::parse_uncompressed(&mut uncompressed_reader).unwrap();
        assert!(Arc::ptr_eq(&uncompressed.wire, &ROOT_WIRE));

        let borrowed = Name::from_uncompressed_wire(&[0]).unwrap();
        assert!(Arc::ptr_eq(&borrowed.wire, &ROOT_WIRE));
    }

    #[test]
    fn canonical_key_preserves_label_boundaries_and_raw_octets() {
        let a = Name::from_labels(vec![b"a.b".to_vec(), b"c".to_vec()]).unwrap();
        let b = Name::from_labels(vec![b"a".to_vec(), b"b.c".to_vec()]).unwrap();
        assert_ne!(a.canonical_key(), b.canonical_key());

        let raw1 = Name::from_labels(vec![vec![0xff]]).unwrap();
        let raw2 = Name::from_labels(vec![vec![0xfe]]).unwrap();
        assert_ne!(raw1.canonical_key(), raw2.canonical_key());
    }

    #[test]
    fn borrowed_canonical_keys_match_owned_keys() {
        let name = Name::from_labels(vec![b"WWW".to_vec(), vec![0xff], b"TEST".to_vec()]).unwrap();
        let mut key = [0u8; 255];
        assert_eq!(
            name.canonical_key_into(&mut key).unwrap(),
            name.canonical_key()
        );

        let mut suffix = [0u8; 255];
        assert_eq!(
            name.canonical_suffix_key_into(2, &mut suffix).unwrap(),
            name.suffix(2).canonical_key()
        );
    }

    fn backward_pointer_chain(count: usize) -> (Vec<u8>, usize) {
        let mut wire = vec![0u8];
        for index in 0..count {
            let target = if index == 0 {
                0usize
            } else {
                1 + 2 * (index - 1)
            };
            wire.push(0xC0 | ((target >> 8) as u8 & 0x3F));
            wire.push(target as u8);
        }
        let last = 1 + 2 * (count - 1);
        (wire, last)
    }

    #[test]
    /// Without a cap, a short packet keeps the parser busy.
    fn wire_parse_bounds_pointer_jumps() {
        for count in [1usize, 20] {
            let (wire, last) = backward_pointer_chain(count);
            let mut reader = Reader::new(&wire);
            reader.pos = last;
            assert!(
                Name::parse(&mut reader).is_ok(),
                "점프 {count}회는 예산 안이다"
            );
        }
        let (wire, last) = backward_pointer_chain(21);
        let mut reader = Reader::new(&wire);
        reader.pos = last;
        let error = Name::parse(&mut reader).expect_err("점프 21회는 예산을 넘는다");
        assert!(
            error.to_string().contains("Compression pointer loop"),
            "{error}"
        );
    }

    #[test]
    fn wire_parse_bounds_expanded_name_length() {
        let mut wire = Vec::new();

        let mut previous = usize::MAX;
        let mut starts = Vec::new();
        for _ in 0..4 {
            let start = wire.len();
            wire.push(63);
            wire.extend(std::iter::repeat_n(b'a', 63));
            if previous == usize::MAX {
                wire.push(0);
            } else {
                wire.push(0xC0 | ((previous >> 8) as u8 & 0x3F));
                wire.push(previous as u8);
            }
            starts.push(start);
            previous = start;
        }
        let last = *starts.last().expect("라벨을 넣었다");
        let mut reader = Reader::new(&wire);
        reader.pos = last;
        let error = Name::parse(&mut reader).expect_err("확장 후 255바이트를 넘는다");
        assert!(error.to_string().contains("Name too long"), "{error}");
    }

    #[test]
    fn from_labels_enforces_wire_limits() {
        assert!(Name::from_labels(vec![vec![]]).is_err());
        assert!(Name::from_labels(vec![vec![b'a'; 64]]).is_err());
        assert!(Name::from_labels(vec![vec![b'a'; 63]; 5]).is_err());
    }

    #[test]
    fn from_str_rejects_multiple_trailing_root_labels() {
        assert!(Name::from_str("example..").is_err());
        assert!(Name::from_str("..").is_err());
        assert_eq!(
            Name::from_str("example.").unwrap().to_ascii_lower(),
            "example"
        );
        assert!(Name::from_str(".").unwrap().is_root());
    }

    #[test]
    fn to_ascii_lower_name_folds_case_and_shares_when_already_lower() {
        use std::collections::HashSet;

        let mixed = Name::from_str("WWW.Example.COM").unwrap();
        let lower = Name::from_str("www.example.com").unwrap();
        assert_eq!(mixed.to_ascii_lower_name().as_ref(), &lower);
        assert_eq!(
            mixed.to_ascii_lower_name().as_uncompressed_wire(),
            lower.as_uncompressed_wire()
        );

        let folded: HashSet<Name> = ["WWW.Example.COM", "www.EXAMPLE.com", "www.example.com"]
            .iter()
            .map(|s| {
                Name::from_str(s)
                    .unwrap()
                    .to_ascii_lower_name()
                    .into_owned()
            })
            .collect();
        assert_eq!(folded.len(), 1, "소문자로 바꾼 뒤에는 키가 하나여야 합니다");

        // Borrowed when already lowercase, so aggregation does not touch even the reference count
        // per query.
        assert!(matches!(lower.to_ascii_lower_name(), Cow::Borrowed(_)));
        assert!(matches!(mixed.to_ascii_lower_name(), Cow::Owned(_)));

        // A label length of 65 cannot be built to test that length octets never overlap uppercase,
        // so check the maximum, 63.
        let long = Name::from_labels(vec![vec![b'A'; 63]]).unwrap();
        assert_eq!(long.to_ascii_lower_name().to_ascii_lower(), "a".repeat(63));
        assert_eq!(long.to_ascii_lower_name().num_labels(), 1);
    }

    #[test]
    fn name_map_clear_discards_pathological_retained_state() {
        let mut names = NameMap::default();
        for index in 0..1024u16 {
            let mut key = vec![63];
            key.extend(std::iter::repeat_n((index & 0xff) as u8, 63));
            key.extend_from_slice(&index.to_be_bytes());
            names.insert(&key, index);
        }
        assert_eq!(names.entries.len(), 1024);

        names.clear();

        assert!(names.entries.is_empty());
        assert!(names.entries.capacity() <= 64);
        assert!(names.heads.capacity() < 1024);
    }
}
