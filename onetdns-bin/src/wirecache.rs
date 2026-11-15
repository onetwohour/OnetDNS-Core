//! Storage form for the UDP fast path. A cache hit neither parses the query nor rebuilds the
//! response: the stored response bytes go out with only the query ID, the name's case, and the
//! remaining TTLs patched.
//!
//! Usable only when the response does not depend on the request, client, or time; a feature that
//! makes it depend must add itself to the fast-path conditions. The scan accepts only queries whose
//! answer can be reused as is; any room for a different answer sends the query to the normal path.

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use onetdns_proto::{Message, Writer};

/// Longest cache key the wire lane handles without allocating; the same as the structured cache's
/// inline key. Longer valid queries take the structured path.
const INLINE_KEY_CAPACITY: usize = 64;
const OPT_TYPE: u16 = 41;
/// Carries no content, so it does not change the response.
const EDNS_PADDING: u16 = 12;

pub struct ScannedQuery<'a> {
    /// Echoed in the response.
    pub id: [u8; 2],

    /// As received, for echoing the original case.
    pub qname: &'a [u8],
    pub qtype: u16,
    pub edns: Option<ScannedEdns>,
    key: KeyBuf,
}

#[derive(Clone, Copy)]
/// From the query's OPT, to decide whether the fast path may take the query. Options or DO mean the
/// response has something to carry, so the structured path must take it.
pub struct ScannedEdns {
    pub udp_payload: u16,
    pub dnssec_ok: bool,
    pub has_options: bool,
}

/// Fixed-size, so building a key does not allocate.
struct KeyBuf {
    bytes: [u8; INLINE_KEY_CAPACITY],
    len: usize,
}

impl KeyBuf {
    fn new() -> Self {
        Self {
            bytes: [0; INLINE_KEY_CAPACITY],
            len: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, value: u8) {
        debug_assert!(self.len < INLINE_KEY_CAPACITY);
        self.bytes[self.len] = value;
        self.len += 1;
    }

    /// Takes the length as a const so the copy unrolls; a slice length is known only at run time,
    /// and even two bytes would cost a memcpy call.
    #[inline(always)]
    fn push_array<const N: usize>(&mut self, value: [u8; N]) {
        let end = self.len + N;
        debug_assert!(end <= INLINE_KEY_CAPACITY);
        self.bytes[self.len..end].copy_from_slice(&value);
        self.len = end;
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl ScannedQuery<'_> {
    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Lowercased.
    pub fn canonical_qname(&self) -> &[u8] {
        &self.key.as_slice()[3..3 + self.qname.len()]
    }
}

/// Builds the key from the query packet without parsing. The name goes into the key lowercased, and
/// the original spelling is kept to echo back; every flag that can change the response goes into
/// the key.
///
/// Rejects anything that leaves room for a different response: several questions, special types,
/// EDNS options with content, trailing bytes. Missing one would give one query another's answer.
///
/// Never accepts a query the structured cache makes no key for; otherwise this path would serve a
/// stored answer to a query the normal path resolves without the cache. Accepting less is fine,
/// since those queries just take the normal path. None when this path cannot answer the query.
pub fn scan_query(packet: &[u8]) -> Option<ScannedQuery<'_>> {
    if packet.len() < 12 + 1 + 4 {
        return None;
    }
    let flags2 = packet[2];
    let flags3 = packet[3];

    if flags2 & 0x80 != 0 || (flags2 >> 3) & 0x0F != 0 || flags2 & 0x06 != 0 {
        return None;
    }

    // RA and RCODE mean nothing in a query, but the structured key rejects them, so this does too.
    if flags3 & 0x80 != 0 || flags3 & 0x40 != 0 || flags3 & 0x0F != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    if qdcount != 1 || ancount != 0 || nscount != 0 || arcount > 1 {
        return None;
    }

    // The name is written lowercased straight into the key, without a scratch array; copying
    // through one would zero a 255-byte array and move the name again on every query. The key's
    // prefix (version, semantic flags) is fixed before the name, so the order can change.
    let rd = flags2 & 0x01 != 0;
    let ad = flags3 & 0x20 != 0;
    let cd = flags3 & 0x10 != 0;
    let semantic_flags = (u16::from(rd) << 8) | (u16::from(ad) << 5) | (u16::from(cd) << 4);
    let mut key = KeyBuf::new();
    key.push(1);
    key.push_array(semantic_flags.to_be_bytes());
    let name_start = key.len;
    // After QTYPE and QCLASS come the EDNS tag and, with EDNS, payload, DO, and option count.
    // Reserving that tail and the root label before writing the name keeps the pushes below in
    // bounds in release builds too.
    let key_suffix_len = if arcount == 1 { 11 } else { 5 };

    let mut pos = 12usize;
    loop {
        let len = *packet.get(pos)? as usize;
        if len == 0 {
            if key.len + 1 + key_suffix_len > INLINE_KEY_CAPACITY {
                return None;
            }
            pos += 1;
            key.push(0);
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let start = pos + 1;
        let end = start.checked_add(len)?;
        let label = packet.get(start..end)?;
        if key.len - name_start + len + 2 > 255 {
            return None;
        }
        if key.len + 1 + len + 1 + key_suffix_len > INLINE_KEY_CAPACITY {
            return None;
        }
        key.push(len as u8);
        for &byte in label {
            key.push(byte.to_ascii_lowercase());
        }
        pos = end;
    }
    let qname_end = pos;
    let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(pos + 2)?, *packet.get(pos + 3)?]);
    pos += 4;

    if qclass != 1 || matches!(qtype, 0 | 41 | 250 | 251 | 252 | 253 | 254 | 255) {
        return None;
    }

    let mut edns: Option<(u16, bool, bool)> = None;
    if arcount == 1 {
        if *packet.get(pos)? != 0 {
            return None;
        }
        let rtype = u16::from_be_bytes([*packet.get(pos + 1)?, *packet.get(pos + 2)?]);
        if rtype != OPT_TYPE {
            return None;
        }
        let udp_payload = u16::from_be_bytes([*packet.get(pos + 3)?, *packet.get(pos + 4)?]);
        let ext = packet.get(pos + 5..pos + 9)?;

        // The first byte is the upper 8 bits of RCODE. The parser merges it into the header RCODE,
        // so the structured key rejects it when nonzero.
        if ext[0] != 0 || ext[1] != 0 {
            return None;
        }
        let do_bit = ext[2] & 0x80 != 0;
        let rdlen = u16::from_be_bytes([*packet.get(pos + 9)?, *packet.get(pos + 10)?]) as usize;
        let rdata_start = pos + 11;
        let rdata_end = rdata_start.checked_add(rdlen)?;
        let rdata = packet.get(rdata_start..rdata_end)?;

        let mut opt_pos = 0usize;
        let mut has_options = false;
        while opt_pos < rdata.len() {
            let header = rdata.get(opt_pos..opt_pos + 4)?;
            let code = u16::from_be_bytes([header[0], header[1]]);
            let len = u16::from_be_bytes([header[2], header[3]]) as usize;
            opt_pos = opt_pos.checked_add(4)?.checked_add(len)?;
            if opt_pos > rdata.len() {
                return None;
            }
            if code != EDNS_PADDING {
                return None;
            }
            has_options = true;
        }
        pos = rdata_end;
        edns = Some((udp_payload, do_bit, has_options));
    }
    if pos != packet.len() {
        return None;
    }

    key.push_array(qtype.to_be_bytes());
    key.push_array(qclass.to_be_bytes());
    match edns {
        Some((payload, do_bit, _)) => {
            // Must match the structured cache key byte for byte; otherwise promotion would never
            // find the slot, so queries of that shape would never take this lane and would do the
            // work twice going in and out. Only version 0 passes above, and neither side counts
            // padding as a meaningful option, so the option count is always 0.
            key.push(1);
            key.push_array(payload.to_be_bytes());
            key.push(0);
            key.push(u8::from(do_bit));
            key.push_array(0u16.to_be_bytes());
        }
        None => key.push(0),
    }

    Some(ScannedQuery {
        id: [packet[0], packet[1]],
        qname: &packet[12..qname_end],
        qtype,
        edns: edns.map(|(udp_payload, dnssec_ok, has_options)| ScannedEdns {
            udp_payload,
            dnssec_ok,
            has_options,
        }),
        key,
    })
}

#[repr(C)]
/// Header of one block holding the response bytes, TTL table, and log summary together, so a cache
/// entry is one allocation.
struct WireAllocation {
    /// Nanoseconds since the process epoch.
    inserted_nanos: i64,

    /// Filter and config generation at storage.
    filter_tag: usize,

    refs: AtomicU32,
    /// Length of what follows the header.
    storage_len: u32,

    lifetime_secs: u32,

    wire_len: u16,

    ttl_count: u16,
}

/// Owner of a block. Counted by hand instead of Arc: with no weak owners one counter is enough, and
/// the header and contents share one allocation.
pub(crate) struct WireEntry(NonNull<WireAllocation>);

// SAFETY: Contents never change after construction, and the count is atomic.
unsafe impl Send for WireEntry {}

// SAFETY: Contents never change after construction, and the count is atomic.
unsafe impl Sync for WireEntry {}

impl Clone for WireEntry {
    /// Aborts if the count grows near overflow; wrapping would free a live block and corrupt
    /// memory.
    fn clone(&self) -> Self {
        const MAX_REFCOUNT: u32 = i32::MAX as u32;
        let previous = self.header().refs.fetch_add(1, Ordering::Relaxed);
        if previous > MAX_REFCOUNT {
            std::process::abort();
        }
        Self(self.0)
    }
}

impl Drop for WireEntry {
    /// Release on each decrement and an Acquire fence on the last, so every other owner's accesses
    /// happen before the free.
    fn drop(&mut self) {
        if self.header().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        let storage_len = self.header().storage_len as usize;
        let layout = wire_allocation_layout(storage_len)
            .expect("The wire cache allocation layout was validated when it was created");

        // SAFETY: The last owner is gone, so nothing else reaches the block, and `layout` is the
        // one it was allocated with.
        unsafe {
            std::ptr::drop_in_place(self.0.as_ptr());
            dealloc(self.0.as_ptr().cast(), layout);
        }
    }
}

impl WireEntry {
    fn allocate_with(
        storage_len: usize,
        inserted: Instant,
        filter_tag: usize,
        lifetime_secs: u32,
        wire_len: u16,
        ttl_count: u16,
        fill: impl FnOnce(&mut [u8]),
    ) -> Option<Self> {
        let storage_len_u32 = u32::try_from(storage_len).ok()?;
        let layout = wire_allocation_layout(storage_len)?;

        // SAFETY: `layout` is never zero-sized, since it includes the header.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(pointer) = NonNull::new(raw.cast::<WireAllocation>()) else {
            handle_alloc_error(layout);
        };

        // SAFETY: `pointer` is a fresh allocation sized and aligned for the header.
        unsafe {
            pointer.as_ptr().write(WireAllocation {
                inserted_nanos: wire_timestamp_nanos(inserted),
                filter_tag,
                refs: AtomicU32::new(1),
                storage_len: storage_len_u32,
                lifetime_secs,
                wire_len,
                ttl_count,
            });
        }
        let mut entry = Self(pointer);
        fill(entry.storage_mut_unique());
        Some(entry)
    }

    fn header(&self) -> &WireAllocation {
        // SAFETY: The block stays allocated while any owner, `self` included, lives.
        unsafe { self.0.as_ref() }
    }

    fn storage(&self) -> &[u8] {
        let len = self.header().storage_len as usize;

        // SAFETY: `len` bytes follow the header inside the same allocation, zeroed when allocated.
        unsafe { std::slice::from_raw_parts(self.storage_ptr(), len) }
    }

    /// Only with a single owner: changing a shared block would change it under another thread's
    /// read. Asserts the count is 1.
    fn storage_mut_unique(&mut self) -> &mut [u8] {
        assert_eq!(
            self.header().refs.load(Ordering::Acquire),
            1,
            "A shared wire cache allocation cannot be modified"
        );
        let len = self.header().storage_len as usize;

        // SAFETY: As in `storage`; the count of 1 checked above makes this borrow unique.
        unsafe { std::slice::from_raw_parts_mut(self.storage_ptr(), len) }
    }

    fn storage_ptr(&self) -> *mut u8 {
        // SAFETY: The storage starts right after the header, inside the same allocation.
        unsafe {
            self.0
                .as_ptr()
                .cast::<u8>()
                .add(std::mem::size_of::<WireAllocation>())
        }
    }

    pub(crate) fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.0 == right.0
    }

    fn wire(&self) -> &[u8] {
        &self.storage()[..self.header().wire_len as usize]
    }

    fn ttl_metadata_end(&self) -> usize {
        self.header().wire_len as usize + usize::from(self.header().ttl_count) * 8
    }

    /// Where each TTL sits in the response bytes.
    fn ttl_metadata(&self) -> &[u8] {
        &self.storage()[self.header().wire_len as usize..self.ttl_metadata_end()]
    }

    /// For the query log.
    pub(crate) fn answers_summary(&self) -> &str {
        std::str::from_utf8(&self.storage()[self.ttl_metadata_end()..])
            .expect("A wire cache answer summary copied from a String is UTF-8")
    }

    pub(crate) fn elapsed_secs(&self, now: Instant) -> u32 {
        u32::try_from(wire_elapsed_secs(self.header().inserted_nanos, now)).unwrap_or(u32::MAX)
    }

    pub(crate) fn is_expired_at(&self, elapsed_secs: u32) -> bool {
        elapsed_secs >= self.header().lifetime_secs
    }

    /// None once expired.
    pub(crate) fn remaining_lifetime(&self, now: Instant) -> Option<u32> {
        let header = self.header();
        let elapsed = self.elapsed_secs(now);
        let remaining = header.lifetime_secs.saturating_sub(elapsed);
        (remaining > 0).then_some(remaining)
    }

    /// A stored answer from another generation is not used: after a blocklist update, serving the
    /// old generation's allowed answers would delay every new block.
    pub(crate) fn matches_filter(&self, filter_tag: usize) -> bool {
        self.header().filter_tag == filter_tag
    }

    /// Never below 1: a client given 0 does not cache, and its next query comes right back.
    fn age_ttls(&self, elapsed: u32, wire: &mut [u8]) {
        if elapsed == 0 {
            return;
        }
        for pair in self.ttl_metadata().chunks_exact(8) {
            let offset = u32::from_ne_bytes([pair[0], pair[1], pair[2], pair[3]]) as usize;
            let original = u32::from_ne_bytes([pair[4], pair[5], pair[6], pair[7]]);
            let remaining = original.saturating_sub(elapsed).max(1);
            wire[offset..offset + 4].copy_from_slice(&remaining.to_be_bytes());
        }
    }

    pub(crate) fn parse_aged_at(&self, elapsed_secs: u32) -> Option<Message> {
        let mut wire = self.wire().to_vec();
        self.age_ttls(elapsed_secs, &mut wire);
        Message::parse(&wire).ok()
    }

    /// Patches only the query ID, the name's original spelling, and the TTLs. Names are not
    /// recompressed, so the length stays the same.
    pub(crate) fn emit_at_age(
        &self,
        query: &ScannedQuery<'_>,
        elapsed_secs: u32,
        out: &mut Writer,
    ) {
        out.clear();
        out.buf.extend_from_slice(self.wire());
        out.buf[0] = query.id[0];
        out.buf[1] = query.id[1];

        let qname_len = query.qname.len();
        debug_assert_eq!(
            skip_name(self.wire(), 12).map(|end| end - 12),
            Some(qname_len)
        );
        out.buf[12..12 + qname_len].copy_from_slice(query.qname);
        self.age_ttls(elapsed_secs, &mut out.buf);
    }
}

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// Signed, so a time before the epoch still fits when an entry is made before the first call fixes
/// the epoch.
fn wire_timestamp_nanos(now: Instant) -> i64 {
    /// The first time the process asked; all timestamps count from it.
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(|| now);
    if now >= epoch {
        duration_nanos(now.saturating_duration_since(epoch))
    } else {
        -duration_nanos(epoch.saturating_duration_since(now))
    }
}

/// Saturates on overflow.
fn duration_nanos(duration: std::time::Duration) -> i64 {
    let secs = duration.as_secs();
    if secs > i64::MAX as u64 / NANOS_PER_SEC as u64 {
        return i64::MAX;
    }
    let nanos = secs * NANOS_PER_SEC as u64 + u64::from(duration.subsec_nanos());
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

/// Either side at the saturated maximum counts as expired; computing with an overflowed value would
/// keep an expired entry alive forever.
fn wire_elapsed_secs_at(inserted_nanos: i64, now_nanos: i64) -> u64 {
    if inserted_nanos.unsigned_abs() == i64::MAX as u64
        || now_nanos.unsigned_abs() == i64::MAX as u64
    {
        return u64::MAX;
    }
    now_nanos.saturating_sub(inserted_nanos).max(0) as u64 / NANOS_PER_SEC as u64
}

fn wire_elapsed_secs(inserted_nanos: i64, now: Instant) -> u64 {
    wire_elapsed_secs_at(inserted_nanos, wire_timestamp_nanos(now))
}

fn wire_allocation_layout(storage_len: usize) -> Option<Layout> {
    let size = std::mem::size_of::<WireAllocation>().checked_add(storage_len)?;
    Layout::from_size_align(size, std::mem::align_of::<WireAllocation>()).ok()
}

#[derive(Clone, Copy)]
pub struct WireEntryFactory {
    /// A nonzero floor disables this path.
    min_ttl: u32,
    max_ttl: u32,
}

impl WireEntryFactory {
    pub fn new(min_ttl: u32, max_ttl: u32) -> Self {
        Self { min_ttl, max_ttl }
    }

    /// Records each TTL position and original value in a table, so emitting patches only those
    /// positions without parsing.
    ///
    /// Truncated, error, and zero-TTL responses are not stored. A configured TTL floor disables
    /// this path entirely, since raising TTLs changes the response.
    pub(crate) fn prepare(
        &self,
        response_wire: &[u8],
        filter_tag: usize,
        answers_summary: String,
        now: Instant,
        lifetime_cap: u32,
    ) -> Option<WireEntry> {
        if self.min_ttl != 0 {
            return None;
        }

        if response_wire.len() < 12 || response_wire[2] & 0x02 != 0 {
            return None;
        }
        if response_wire[3] & 0x0F != 0 {
            return None;
        }
        let (mut ttl_offsets, min_ttl) = walk_response(response_wire)?;
        if min_ttl == 0 {
            return None;
        }
        let lifetime = min_ttl.min(self.max_ttl).min(lifetime_cap);
        if lifetime == 0 {
            return None;
        }
        let record_ttl_cap = self.max_ttl.min(lifetime_cap);
        let wire_len = u16::try_from(response_wire.len()).ok()?;
        let ttl_count = u16::try_from(ttl_offsets.len()).ok()?;
        let metadata_len = ttl_offsets.len().checked_mul(8)?;
        let storage_len = response_wire
            .len()
            .checked_add(metadata_len)?
            .checked_add(answers_summary.len())?;
        WireEntry::allocate_with(
            storage_len,
            now,
            filter_tag,
            lifetime,
            wire_len,
            ttl_count,
            |storage| {
                storage[..response_wire.len()].copy_from_slice(response_wire);
                let mut metadata_at = response_wire.len();
                for (offset, original) in &mut ttl_offsets {
                    *original = (*original).min(record_ttl_cap);
                    let offset_usize = *offset as usize;
                    storage[offset_usize..offset_usize + 4]
                        .copy_from_slice(&original.to_be_bytes());
                    storage[metadata_at..metadata_at + 4].copy_from_slice(&offset.to_ne_bytes());
                    storage[metadata_at + 4..metadata_at + 8]
                        .copy_from_slice(&original.to_ne_bytes());
                    metadata_at += 8;
                }
                storage[metadata_at..].copy_from_slice(answers_summary.as_bytes());
                debug_assert_eq!(metadata_at + answers_summary.len(), storage_len);
            },
        )
    }

    /// For fixed configured addresses, whose TTL does not age, so there is no TTL table.
    pub(crate) fn prepare_fixed(
        &self,
        response_wire: &[u8],
        filter_tag: usize,
        answers_summary: String,
        now: Instant,
    ) -> Option<WireEntry> {
        if response_wire.len() < 12
            || response_wire[2] & 0x02 != 0
            || response_wire[3] & 0x0f != 0
            || u16::from_be_bytes([response_wire[4], response_wire[5]]) != 1
        {
            return None;
        }
        let question_end = skip_name(response_wire, 12)?.checked_add(4)?;
        if question_end > response_wire.len() {
            return None;
        }
        let wire_len = u16::try_from(response_wire.len()).ok()?;
        let storage_len = response_wire.len().checked_add(answers_summary.len())?;
        WireEntry::allocate_with(
            storage_len,
            now,
            filter_tag,
            u32::MAX,
            wire_len,
            0,
            |storage| {
                storage[..response_wire.len()].copy_from_slice(response_wire);
                storage[response_wire.len()..].copy_from_slice(answers_summary.as_bytes());
            },
        )
    }
}

/// The entry lives only as long as its shortest TTL, since no expired record may go out. Returns
/// the TTL positions with their original values, and the shortest TTL; None on malformed input.
fn walk_response(wire: &[u8]) -> Option<(Vec<(u32, u32)>, u32)> {
    let qdcount = u16::from_be_bytes([*wire.get(4)?, *wire.get(5)?]);
    let ancount = u16::from_be_bytes([*wire.get(6)?, *wire.get(7)?]);
    let nscount = u16::from_be_bytes([*wire.get(8)?, *wire.get(9)?]);
    let arcount = u16::from_be_bytes([*wire.get(10)?, *wire.get(11)?]);
    if qdcount != 1 || ancount == 0 {
        return None;
    }

    let mut pos = 12usize;
    pos = skip_name(wire, pos)?;
    pos = pos.checked_add(4)?;

    let records = usize::from(ancount) + usize::from(nscount) + usize::from(arcount);
    let mut ttl_offsets = Vec::with_capacity(records);
    let mut min_ttl = u32::MAX;
    for _ in 0..records {
        pos = skip_name(wire, pos)?;
        let rtype = u16::from_be_bytes([*wire.get(pos)?, *wire.get(pos + 1)?]);
        let ttl_at = pos + 4;
        let ttl = u32::from_be_bytes([
            *wire.get(ttl_at)?,
            *wire.get(ttl_at + 1)?,
            *wire.get(ttl_at + 2)?,
            *wire.get(ttl_at + 3)?,
        ]);
        let rdlen = u16::from_be_bytes([*wire.get(pos + 8)?, *wire.get(pos + 9)?]) as usize;
        pos = pos.checked_add(10)?.checked_add(rdlen)?;
        if pos > wire.len() {
            return None;
        }

        if rtype == OPT_TYPE {
            continue;
        }
        ttl_offsets.push((ttl_at as u32, ttl));
        min_ttl = min_ttl.min(ttl);
    }
    if pos != wire.len() || ttl_offsets.is_empty() {
        return None;
    }
    Some((ttl_offsets, min_ttl))
}

/// Must differ per process; fixed keys would let chosen names pile into one shard and contend on
/// its lock.
pub(crate) fn random_shard_hash_keys() -> [u64; 2] {
    let seed = onetdns_core::random_array::<16>();
    [
        u64::from_le_bytes(seed[..8].try_into().expect("Fixed seed length")),
        u64::from_le_bytes(seed[8..].try_into().expect("Fixed seed length")),
    ]
}

pub(crate) fn shard_hash(key: &[u8], keys: [u64; 2]) -> u64 {
    const M: u64 = 0x9ddf_ea08_eb38_2d69;
    let mut hash = M.wrapping_mul((key.len() as u64).wrapping_add(1) ^ keys[0]);
    let mut chunks = key.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        hash = (hash ^ word).wrapping_mul(M);
        hash ^= keys[1];
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut tail = 0u64;
        for &byte in rem {
            tail = (tail << 8) | u64::from(byte);
        }
        hash = (hash ^ tail).wrapping_mul(M);
    }

    hash ^= keys[1].rotate_left(17);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(M);
    hash ^ (hash >> 32)
}

/// Stops after a compression pointer.
fn skip_name(wire: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *wire.get(pos)? as usize;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some(pos + 1);
                }
                pos = pos.checked_add(1)?.checked_add(len)?;
            }
            0xC0 => {
                wire.get(pos + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Message, Name, RData, Record, RecordType};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    /// A larger fixed cost means fewer entries fit in the same memory.
    fn wire_entry_fixed_overhead_stays_small() {
        assert_eq!(
            std::mem::size_of::<WireEntry>(),
            std::mem::size_of::<usize>(),
            "WireEntry owner는 LRU 값을 넓히지 않는 thin pointer여야 합니다"
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            std::mem::size_of::<WireAllocation>(),
            32,
            "wire 단일 할당 header가 커졌습니다"
        );
        assert_eq!(
            wire_allocation_layout(62).unwrap().size(),
            std::mem::size_of::<WireAllocation>() + 62
        );
    }

    #[test]
    /// The compact timestamp keeps expiry boundaries and leans toward expired on overflow.
    fn compact_timestamp_preserves_ttl_boundaries_and_fails_closed() {
        let inserted = 123_456_789;
        assert_eq!(
            wire_elapsed_secs_at(inserted, inserted + 5 * NANOS_PER_SEC - 1),
            4,
            "TTL 경계 직전에는 아직 다음 초로 넘어가면 안 됩니다"
        );
        assert_eq!(
            wire_elapsed_secs_at(inserted, inserted + 5 * NANOS_PER_SEC),
            5,
            "정확한 TTL 경계에서는 만료 초에 도달해야 합니다"
        );
        assert_eq!(
            wire_elapsed_secs_at(inserted, inserted - 1),
            0,
            "호출자가 더 이른 Instant를 넘겨도 수명을 늘리지 않습니다"
        );
        assert_eq!(
            wire_elapsed_secs_at(inserted, i64::MAX),
            u64::MAX,
            "단조시계 표현 범위를 넘기면 캐시를 보수적으로 만료합니다"
        );
        assert_eq!(
            wire_elapsed_secs_at(-i64::MAX, -i64::MAX),
            u64::MAX,
            "기준점보다 이른 방향의 범위 초과도 보수적으로 만료합니다"
        );
    }

    fn query_wire(name: &str, qtype: RecordType, edns: bool) -> Vec<u8> {
        let mut message = Message::query(0x1234, Name::from_str(name).unwrap(), qtype);
        if edns {
            message.additionals.push(
                Edns {
                    udp_payload: 1232,
                    ..Default::default()
                }
                .try_to_record()
                .unwrap(),
            );
        }
        message.try_encode().unwrap()
    }

    fn response_wire(request: &Message, ttl: u32) -> Vec<u8> {
        let mut response = request.clone();
        response.header.response = true;
        response.header.recursion_available = true;
        response.answers.push(Record::new(
            request.questions[0].name.clone(),
            ttl,
            RData::A(std::net::Ipv4Addr::new(192, 0, 2, 7)),
        ));
        response.try_encode().unwrap()
    }

    #[test]
    fn scan_accepts_plain_and_edns_queries() {
        let plain = query_wire("host.example", RecordType::A, false);
        let scanned = scan_query(&plain).expect("일반 질의 스캔");
        assert_eq!(scanned.qtype, RecordType::A.0);
        assert_eq!(scanned.id, [0x12, 0x34]);

        let edns = query_wire("host.example", RecordType::A, true);
        let scanned_edns = scan_query(&edns).expect("EDNS 질의 스캔");
        assert_ne!(
            scanned.key(),
            scanned_edns.key(),
            "EDNS 유무는 키를 구분한다"
        );
    }

    #[test]
    fn scan_normalizes_case_but_preserves_original_span() {
        let lower = query_wire("host.example", RecordType::A, false);
        let upper = query_wire("HOST.EXAMPLE", RecordType::A, false);
        let a = scan_query(&lower).unwrap();
        let b = scan_query(&upper).unwrap();
        assert_eq!(a.key(), b.key(), "케이스는 키에서 정규화");
        assert_ne!(a.qname, b.qname, "원본 케이스는 패치용으로 유지");
    }

    #[test]
    fn scan_inline_key_boundary_falls_back_without_rejecting_dns() {
        let plain_edge = "a".repeat(54);
        let plain_edge_wire = query_wire(&plain_edge, RecordType::A, false);
        let plain = scan_query(&plain_edge_wire).expect("64바이트 일반 키");
        assert_eq!(plain.key().len(), INLINE_KEY_CAPACITY);

        let plain_long_wire = query_wire(&"a".repeat(55), RecordType::A, false);
        assert!(Message::parse(&plain_long_wire).is_ok(), "정상 DNS 질의");
        assert!(
            scan_query(&plain_long_wire).is_none(),
            "인라인 상한을 넘으면 구조화 경로"
        );

        let edns_edge_wire = query_wire(&"a".repeat(48), RecordType::A, true);
        let edns = scan_query(&edns_edge_wire).expect("64바이트 EDNS 키");
        assert_eq!(edns.key().len(), INLINE_KEY_CAPACITY);

        let edns_long_wire = query_wire(&"a".repeat(49), RecordType::A, true);
        assert!(Message::parse(&edns_long_wire).is_ok(), "정상 EDNS 질의");
        assert!(
            scan_query(&edns_long_wire).is_none(),
            "EDNS 뒷부분까지 포함해 구조화 경로"
        );
    }

    #[test]
    /// Accepting them would give one query another's answer.
    fn scan_rejects_semantic_edns_and_multi_question() {
        let mut message = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        let mut edns = Edns::default();
        edns.options.push((10, vec![1, 2, 3, 4, 5, 6, 7, 8]));
        message.additionals.push(edns.try_to_record().unwrap());
        assert!(
            scan_query(&message.try_encode().unwrap()).is_none(),
            "쿠키 옵션은 슬로우패스"
        );

        let mut multi = Message::query(2, Name::from_str("x.test").unwrap(), RecordType::A);
        multi.questions.push(multi.questions[0].clone());
        assert!(
            scan_query(&multi.try_encode().unwrap()).is_none(),
            "다중 질의는 슬로우패스"
        );

        let any = query_wire("x.test", RecordType(255), false);
        assert!(scan_query(&any).is_none(), "ANY는 슬로우패스");
    }

    #[test]
    /// Accepting them would let this path serve a stored answer to a query the normal path resolves
    /// without the cache.
    fn scan_rejects_ra_and_extended_rcode() {
        let mut message = Message::query(1, Name::from_str("x.test").unwrap(), RecordType::A);
        message
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        let packet = message.try_encode().unwrap();
        assert!(
            scan_query(&packet).is_some(),
            "대조군이 무효입니다: 평범한 EDNS 질의"
        );

        let mut with_ra = packet.clone();
        with_ra[3] |= 0x80;
        assert!(scan_query(&with_ra).is_none(), "RA 를 켠 질의를 받았습니다");

        // OPT is the query's last record. Its TTL follows the root name (1), type (2), and UDP size
        // (2), and the TTL's first byte is the upper 8 bits of RCODE.
        let ttl = packet.len() - (4 + 2);
        assert_eq!(
            &packet[ttl - 4..ttl - 2],
            &[0, 41],
            "대조군이 무효입니다: OPT 위치"
        );
        let mut with_extended_rcode = packet;
        with_extended_rcode[ttl] = 1;
        assert!(
            scan_query(&with_extended_rcode).is_none(),
            "확장 RCODE 가 0 이 아닌 질의를 받았습니다"
        );
    }

    #[test]
    fn store_and_emit_patch_id_case_and_ttl() {
        let request = Message::query(7, Name::from_str("host.example").unwrap(), RecordType::A);
        let request_wire = request.try_encode().unwrap();
        let scanned = scan_query(&request_wire).unwrap();
        let wire = response_wire(&request, 300);

        let t0 = Instant::now();
        let entry = WireEntryFactory::new(0, 86_400)
            .prepare(&wire, 1, "A 192.0.2.7".into(), t0, u32::MAX)
            .expect("저장 가능한 wire 응답");
        assert_eq!(entry.answers_summary(), "A 192.0.2.7");

        let request2 = Message::query(9, Name::from_str("HOST.EXAMPLE").unwrap(), RecordType::A);
        let request2_wire = request2.try_encode().unwrap();
        let scanned2 = scan_query(&request2_wire).unwrap();
        assert_eq!(scanned.key(), scanned2.key());

        let mut out = Writer::with_limit(1232);
        entry.emit_at_age(
            &scanned2,
            entry.elapsed_secs(t0 + Duration::from_secs(10)),
            &mut out,
        );
        let parsed = Message::parse(&out.buf).expect("패치된 응답 파싱");
        assert_eq!(parsed.header.id, 9);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].ttl, 290, "TTL은 경과 시간만큼 감소");
        assert_eq!(
            parsed.questions[0].name.to_ascii_lower(),
            "host.example",
            "응답 질의 이름은 요청 케이스 구간을 그대로 반영"
        );

        assert_eq!(&out.buf[12..12 + scanned2.qname.len()], scanned2.qname);
    }

    #[test]
    /// One allocation is freed exactly once however threads share it.
    fn wire_entry_clone_drop_keeps_single_allocation_alive_across_threads() {
        let request = Message::query(7, Name::from_str("clone.example").unwrap(), RecordType::A);
        let wire = response_wire(&request, 300);
        let entry = WireEntryFactory::new(0, 86_400)
            .prepare(&wire, 7, "A 192.0.2.7".into(), Instant::now(), u32::MAX)
            .unwrap();
        let survivor = entry.clone();
        assert!(WireEntry::ptr_eq(&entry, &survivor));
        drop(entry);
        assert_eq!(survivor.answers_summary(), "A 192.0.2.7");

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let owner = survivor.clone();
                scope.spawn(move || {
                    for _ in 0..10_000 {
                        let clone = owner.clone();
                        assert!(WireEntry::ptr_eq(&owner, &clone));
                        assert!(clone.matches_filter(7));
                    }
                });
            }
        });
        assert_eq!(survivor.answers_summary(), "A 192.0.2.7");
    }

    #[test]
    fn zero_max_ttl_disables_wire_storage() {
        let request = Message::query(7, Name::from_str("host.example").unwrap(), RecordType::A);
        let wire = response_wire(&request, 300);
        let now = Instant::now();

        assert!(
            WireEntryFactory::new(0, 0)
                .prepare(&wire, 0, String::new(), now, u32::MAX)
                .is_none(),
            "max_ttl=0이면 wire 캐시를 사용하지 않아야 함"
        );
    }

    #[test]
    fn wire_entry_caps_ttl_visible_to_clients() {
        let request = Message::query(7, Name::from_str("host.example").unwrap(), RecordType::A);
        let request_wire = request.try_encode().unwrap();
        let scanned = scan_query(&request_wire).unwrap();
        let wire = response_wire(&request, 300);
        let now = Instant::now();
        let entry = WireEntryFactory::new(0, 5)
            .prepare(&wire, 0, String::new(), now, u32::MAX)
            .expect("wire 항목 생성");
        let mut output = Writer::with_limit(1232);

        entry.emit_at_age(&scanned, entry.elapsed_secs(now), &mut output);

        let response = Message::parse(&output.buf).unwrap();
        assert_eq!(response.answers[0].ttl, 5);
    }

    #[test]
    /// Otherwise the two paths would give different answers.
    fn structured_cache_lifetime_caps_shared_wire_entry() {
        let request = Message::query(7, Name::from_str("signed.example").unwrap(), RecordType::A);
        let request_wire = request.try_encode().unwrap();
        let scanned = scan_query(&request_wire).unwrap();
        let wire = response_wire(&request, 300);
        let now = Instant::now();
        let entry = WireEntryFactory::new(0, 86_400)
            .prepare(&wire, 0, String::new(), now, 5)
            .expect("구조화 캐시 수명으로 제한된 wire 항목");

        let mut out = Writer::with_limit(1232);
        entry.emit_at_age(&scanned, entry.elapsed_secs(now), &mut out);
        assert_eq!(Message::parse(&out.buf).unwrap().answers[0].ttl, 5);
        entry.emit_at_age(
            &scanned,
            entry.elapsed_secs(now + Duration::from_secs(4)),
            &mut out,
        );
        assert_eq!(Message::parse(&out.buf).unwrap().answers[0].ttl, 1);

        assert!(
            entry.is_expired_at(entry.elapsed_secs(now + Duration::from_secs(5))),
            "wire TTL이 길어도 DNSSEC 등을 반영한 구조화 캐시 수명을 넘으면 안 됩니다"
        );
    }

    #[test]
    fn expiry_and_filter_generation_invalidate() {
        let request = Message::query(3, Name::from_str("ttl.example").unwrap(), RecordType::A);
        let wire = response_wire(&request, 5);

        let t0 = Instant::now();
        let entry = WireEntryFactory::new(0, 86_400)
            .prepare(&wire, 1, String::new(), t0, u32::MAX)
            .unwrap();
        assert!(entry.matches_filter(1));
        assert!(
            entry.is_expired_at(entry.elapsed_secs(t0 + Duration::from_secs(5))),
            "최소 TTL 경과 후 만료"
        );
    }

    #[test]
    fn truncated_or_negative_responses_are_not_stored() {
        let request = Message::query(4, Name::from_str("neg.example").unwrap(), RecordType::A);

        let mut negative = request.clone();
        negative.header.response = true;
        negative.header.rcode = 3;
        let factory = WireEntryFactory::new(0, 86_400);
        let t0 = Instant::now();
        assert!(
            factory
                .prepare(
                    &negative.try_encode().unwrap(),
                    1,
                    String::new(),
                    t0,
                    u32::MAX,
                )
                .is_none(),
            "NXDOMAIN은 저장 안 함"
        );

        let mut truncated = response_wire(&request, 300);
        truncated[2] |= 0x02;
        assert!(
            factory
                .prepare(&truncated, 1, String::new(), t0, u32::MAX)
                .is_none(),
            "TC 응답은 저장 안 함"
        );

        let zero_ttl = response_wire(&request, 0);
        assert!(
            factory
                .prepare(&zero_ttl, 1, String::new(), t0, u32::MAX)
                .is_none(),
            "TTL 0은 저장 안 함"
        );
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release -- --ignored --nocapture"]
    fn bench_wire_fast_path_hit() {
        use std::time::Instant;

        let request = Message::query(
            0x1234,
            Name::from_str("www.example.com").unwrap(),
            RecordType::A,
        );
        let request_wire = request.try_encode().unwrap();
        let scanned = scan_query(&request_wire).unwrap();
        let response = response_wire(&request, 300);
        let now = Instant::now();
        struct Noop;
        impl crate::native::Resolver for Noop {
            fn resolve(&self, _request: &Message) -> Option<Message> {
                None
            }
        }
        let cache_layer = crate::cache::CacheLayer::new(Arc::new(Noop), 1024, 8, 0, 3600, 0, 3600);
        let cache = cache_layer.handle();
        let response_message = Message::parse(&response).unwrap();
        cache.store(cache.epoch(), &request, &response_message);
        let candidate = cache.wire_candidate(scanned.key(), now).unwrap();
        let entry = WireEntryFactory::new(0, 3600)
            .prepare(
                &response,
                1,
                "A 192.0.2.7".into(),
                now,
                candidate.lifetime_secs(),
            )
            .unwrap();
        assert!(cache.promote_wire(cache.epoch(), scanned.key(), &candidate, entry));

        use std::hint::black_box;
        let mut out = Writer::with_limit(1232);
        let warmup = 100_000u128;
        for _ in 0..warmup {
            let s = scan_query(&request_wire).unwrap();
            if let Some((entry, elapsed_secs)) = cache.wire_get(s.key(), 1, now) {
                entry.emit_at_age(&s, elapsed_secs, &mut out);
            }
        }

        let iters = 3_000_000u128;
        let mut sink = 0u64;

        let t = Instant::now();
        for _ in 0..iters {
            let s = scan_query(black_box(&request_wire)).unwrap();
            if let Some((entry, elapsed_secs)) = cache.wire_get(s.key(), 1, now) {
                entry.emit_at_age(&s, elapsed_secs, &mut out);
                sink = sink.wrapping_add(out.buf.len() as u64);
            }
        }
        let full = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            let s = scan_query(black_box(&request_wire)).unwrap();
            sink = sink.wrapping_add(black_box(s.key().len()) as u64);
        }
        let scan = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            let s = scan_query(black_box(&request_wire)).unwrap();
            let (e, _) = cache.wire_get(s.key(), 1, now).unwrap();
            sink = sink.wrapping_add(black_box(e.answers_summary().len()) as u64);
        }
        let scan_get = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            sink =
                sink.wrapping_add(black_box(Instant::now()).duration_since(now).as_nanos() as u64);
        }
        let clock = t.elapsed().as_nanos() as f64 / iters as f64;

        println!(
            "wire hit: full={full:.1}ns scan={scan:.1}ns get={:.1}ns emit={:.1}ns clock={clock:.1}ns ({:.1} Mops/s) sink={sink}",
            scan_get - scan,
            full - scan_get,
            1000.0 / full,
        );
    }

    #[test]
    fn scan_and_store_never_panic_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let query_seed = query_wire("host.example", RecordType::A, true);
        let response_seed = {
            let req = Message::query(1, Name::from_str("host.example").unwrap(), RecordType::A);
            response_wire(&req, 300)
        };
        let factory = WireEntryFactory::new(0, 3600);
        let now = Instant::now();
        let mut rng = Rng::new(0x0BAD_F00D_1234_5678);
        for i in 0..20_000u32 {
            let b = match i % 3 {
                0 => rng.rand_bytes(64),
                1 => havoc(&mut rng, &query_seed),
                _ => havoc(&mut rng, &response_seed),
            };
            if let Some(q) = scan_query(&b) {
                let _ = q.key();
            }
            let _ = factory.prepare(&b, 1, String::new(), now, u32::MAX);
        }
    }

    #[test]
    fn shard_selector_distributes_evenly() {
        let nshards = 16usize;
        let hash_keys = random_shard_hash_keys();
        let mut counts = vec![0usize; nshards];
        let n = 40_000usize;
        for i in 0..n {
            let name = format!("host{i}.zone{}.example{}.com", i % 251, i % 97);
            let wire = query_wire(&name, RecordType::A, i % 2 == 0);
            let scanned = scan_query(&wire).expect("정규 질의");
            counts[(shard_hash(scanned.key(), hash_keys) as usize) & (nshards - 1)] += 1;
        }
        let avg = n / nshards;
        for (shard, &count) in counts.iter().enumerate() {
            assert!(
                count > avg / 2 && count < avg * 2,
                "샤드 {shard} 편중: {count} (평균 {avg}): 분배 회귀"
            );
        }
    }

    #[test]
    /// Identical keys would let someone pile names into one shard.
    fn shard_selector_changes_with_process_secret() {
        let first = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let second = [0x1357_9bdf_2468_ace0, 0x0eca_8642_fdb9_7531];
        let mut changed = 0usize;
        for i in 0..1024 {
            let key = format!("host{i}.zone{}.example", i % 97);
            if shard_hash(key.as_bytes(), first) & 15 != shard_hash(key.as_bytes(), second) & 15 {
                changed += 1;
            }
        }
        assert!(
            changed > 512,
            "프로세스 비밀이 바뀌어도 샤드 배치가 충분히 달라지지 않았습니다: {changed}"
        );
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release -- --ignored --nocapture"]
    fn bench_shard_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::hint::black_box;
        use std::time::Instant;

        let wire = query_wire("www.example.com", RecordType::A, true);
        let key = scan_query(&wire).unwrap().key().to_vec();
        let hash_keys = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let iters = 20_000_000u128;
        let mut sink = 0u64;

        let t = Instant::now();
        for _ in 0..iters {
            let mut hasher = DefaultHasher::new();
            black_box(key.as_slice()).hash(&mut hasher);
            sink = sink.wrapping_add(hasher.finish());
        }
        let sip_hash = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            let mut hasher = DefaultHasher::new();
            hasher.write(black_box(key.as_slice()));
            sink = sink.wrapping_add(hasher.finish());
        }
        let sip_write = t.elapsed().as_nanos() as f64 / iters as f64;

        let t = Instant::now();
        for _ in 0..iters {
            sink = sink.wrapping_add(shard_hash(black_box(key.as_slice()), hash_keys));
        }
        let word = t.elapsed().as_nanos() as f64 / iters as f64;

        println!(
            "shard hash over {}B key: siphash(.hash)={sip_hash:.2}ns siphash(.write)={sip_write:.2}ns word-mul={word:.2}ns saved={:.2}ns/get (sink={sink})",
            key.len(),
            sip_hash - word,
        );
    }
}
