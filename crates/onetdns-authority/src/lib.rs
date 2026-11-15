//! Authoritative answers for zones this server owns. Storage is laid out so the query path does not
//! allocate: records sit in one arena, the owner index holds only 8-byte ranges, and common queries
//! such as A and AAAA are written straight to the wire without assembling a response.
//!
//! Every load path ends in Zone::from_flat_records, so zone data from any source gets the same
//! validation.

#[cfg(test)]
mod fuzzutil;
mod parse;

use std::cmp::Ordering;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use onetdns_proto::{DnsClass, Message, Name, ProtoError, RData, Record, RecordType, Soa, Writer};

pub use parse::parse_zone;

pub mod source;
pub use source::{DirZoneSource, FileZoneSource, MemoryZoneSource, ZoneSource};
pub mod sqlite;
pub use sqlite::SqliteZoneSource;
pub mod etcd;
pub use etcd::EtcdZoneSource;
pub mod postgres;
pub use postgres::PostgresZoneSource;
pub mod mysql;
pub use mysql::MysqlZoneSource;
pub mod lmdb;
pub use lmdb::LmdbZoneSource;

const MAX_ZONE_RECORDS: usize = 1_000_000;
const MAX_OWNER_RECORDS: usize = 4_096;
/// Bytes per zone transfer message, kept under the TCP message limit.
pub const XFR_CHUNK_BUDGET: usize = 60_000;

const NAME_EXISTS: u8 = 1;
const NAME_HAS_WILDCARD: u8 = 2;
const NAME_HAS_DNAME: u8 = 4;

/// Drops the first label; None at the root.
fn parent_canonical_key(key: &[u8]) -> Option<&[u8]> {
    let label_len = usize::from(*key.first()?);
    if label_len == 0 {
        return None;
    }
    key.get(label_len.checked_add(1)?..)
}

/// Handles bracketed IPv6 first, and takes a port only when there is exactly one colon, so colons
/// inside an address are not read as a port separator. None for port 0 or an empty host.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = bracketed[..end].to_string();
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        return (port != 0).then_some((host, port));
    }
    if authority.matches(':').count() == 1 {
        let (host, port) = authority.rsplit_once(':')?;
        let port = port.parse().ok()?;
        return (!host.is_empty() && port != 0).then_some((host.to_string(), port));
    }
    (!authority.is_empty()).then_some((authority.to_string(), default_port))
}

/// Accepts only localhost or an IP literal: resolving a name needs DNS, which could be this server,
/// a loop at startup. Rejects anything but loopback: the mysql and postgres backends speak without
/// TLS, so a remote target would carry credentials and zone data in the clear.
fn loopback_socket_addr(host: &str, port: u16, backend: &str) -> Result<SocketAddr, String> {
    let ip = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<IpAddr>().map_err(|_| {
            format!(
                "Host names cannot be used for an unencrypted connection to the {backend} authoritative DNS store; use `localhost` or a loopback IP address"
            )
        })?
    };
    if !ip.is_loopback() {
        return Err(format!(
            "The {backend} authoritative DNS store can be reached unencrypted only on the local machine; configure a TLS proxy to use a remote database"
        ));
    }
    Ok(SocketAddr::new(ip, port))
}

pub(crate) use onetdns_core::tcp::DeadlineTcp;

/// Immutable after load. Records live in one arena and the index points at ranges in it, so queries
/// walk the structure without allocating.
#[derive(Clone)]
pub struct Zone {
    origin: Name,
    soa: Soa,
    soa_ttl: u32,

    records: OwnerIndex,
    record_arena: Box<[StoredRecord]>,
    /// Kept apart to shrink the stored record variant.
    aaaa_arena: Box<[std::net::Ipv6Addr]>,
    /// Records other than A and AAAA; the stored form holds only an index.
    other_arena: Box<[Record]>,

    /// Existence, wildcard, and DNAME flags per name, empty non-terminals included.
    name_flags: HashMap<Vec<u8>, u8>,
    /// When false, queries skip the delegation search.
    has_delegations: bool,
    /// No delegation, DNAME, or wildcard: the precondition of the allocation-free path.
    simple_nxdomain: bool,
    denial_index: HashMap<RecordType, Vec<RecordLocation>>,

    /// Built once on first request.
    axfr_wire: Arc<OnceLock<Result<Box<[Box<[u8]>]>, ProtoError>>>,
    /// Digest of the file this content was read from or written to; None when it did not come from
    /// a file.
    source: Option<source::SourceDigest>,
}

#[derive(Clone)]
struct RecordLocation {
    owner: Vec<u8>,
    /// Index among that owner's records.
    offset: usize,
}

/// Transfers send the same bytes many times, so each message is encoded once as a template and only
/// the transaction ID is overwritten on send. Only the first message keeps the question section.
fn encode_axfr_template(
    origin: &Name,
    answers: Vec<Record>,
    first: bool,
) -> Result<Box<[u8]>, ProtoError> {
    let mut message = Message::query(0, origin.clone(), RecordType(252));
    message.header.response = true;
    message.header.authoritative = true;
    message.header.recursion_desired = false;
    message.header.recursion_available = true;
    if !first {
        message.questions.clear();
    }
    message.answers = answers;
    Ok(message.try_encode()?.into_boxed_slice())
}

/// One owner's records, contiguous in the arena.
#[derive(Clone, Copy)]
struct RecordRange {
    start: u32,
    len: u16,
}

/// 8 bytes, so several fit in a cache line. The key is not stored here: the tag filters most
/// mismatches, and only survivors fetch the key from metadata for comparison.
#[derive(Clone, Copy)]
struct OwnerSlot {
    /// Upper hash bits with the low bit set, since 0 marks an empty slot.
    tag: u32,
    metadata_start: u32,
    record_start: u32,
}

/// Open-addressing table from owner name to record range, chosen over std's map for layout: small
/// slots share cache lines, and keys are packed into one arena, so owners need no allocation each.
#[derive(Clone)]
struct OwnerIndex {
    /// Length is always a power of two, so the modulo is a mask.
    slots: Box<[OwnerSlot]>,

    /// Key length, record count, and key bytes, back to back.
    metadata: Vec<u8>,
    hash_builder: RandomState,
}

impl OwnerIndex {
    /// At least 1.25 slots per owner: the table never grows after load, and a high load factor
    /// makes linear probes long.
    fn new(owner_count: usize, metadata_len: usize) -> Result<Self, String> {
        let minimum_slots = owner_count
            .checked_mul(5)
            .and_then(|value| value.checked_add(3))
            .map(|value| value / 4)
            .ok_or_else(|| "Zone owner index size overflowed".to_string())?;
        let slot_count = minimum_slots
            .max(2)
            .checked_next_power_of_two()
            .ok_or_else(|| "Zone owner index size overflowed".to_string())?;
        Ok(Self {
            slots: vec![
                OwnerSlot {
                    tag: 0,
                    metadata_start: 0,
                    record_start: 0,
                };
                slot_count
            ]
            .into_boxed_slice(),
            metadata: Vec::with_capacity(metadata_len),
            hash_builder: RandomState::new(),
        })
    }

    fn tag_of(hash: u64) -> u32 {
        ((hash >> 32) as u32) | 1
    }

    /// Never returns 0.
    fn hash(&self, key: &[u8]) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        hasher.write(key);
        hasher.finish().max(1)
    }

    /// Load time only, called once per owner. Appends key length, record count, and key bytes to
    /// metadata and stores the start in the slot, probing to the next slot on collision.
    fn insert(&mut self, key: &[u8], range: RecordRange) -> Result<(), String> {
        let key_len = u8::try_from(key.len())
            .map_err(|_| "Zone owner wire key exceeds 255 bytes".to_string())?;
        let metadata_start = u32::try_from(self.metadata.len())
            .map_err(|_| "Zone owner key arena offset exceeds 32 bits".to_string())?;
        self.metadata.push(key_len);
        self.metadata.extend_from_slice(&range.len.to_le_bytes());
        self.metadata.extend_from_slice(key);

        let hash = self.hash(key);
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        loop {
            let slot = &mut self.slots[index];
            if slot.tag == 0 {
                *slot = OwnerSlot {
                    tag: Self::tag_of(hash),
                    metadata_start,
                    record_start: range.start,
                };
                return Ok(());
            }
            index = (index + 1) & mask;
        }
    }

    /// Skips the 3-byte header in metadata.
    fn key_for_slot(&self, slot: &OwnerSlot) -> Option<&[u8]> {
        let start = slot.metadata_start as usize;
        let key_len = usize::from(*self.metadata.get(start)?);
        let key_start = start.checked_add(3)?;
        self.metadata
            .get(key_start..key_start.checked_add(key_len)?)
    }

    /// The count comes from metadata, the start from the slot.
    fn range_for_slot(&self, slot: &OwnerSlot) -> Option<RecordRange> {
        let start = slot.metadata_start as usize;
        let len = u16::from_le_bytes([
            *self.metadata.get(start.checked_add(1)?)?,
            *self.metadata.get(start.checked_add(2)?)?,
        ]);
        Some(RecordRange {
            start: slot.record_start,
            len,
        })
    }

    /// The query path's hottest lookup. Tags are compared first and only matching slots compare
    /// keys, so most collisions never touch metadata.
    fn get(&self, key: &[u8]) -> Option<RecordRange> {
        let hash = self.hash(key);
        let tag = Self::tag_of(hash);
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        loop {
            let slot = &self.slots[index];
            if slot.tag == 0 {
                return None;
            }
            if slot.tag == tag && self.key_for_slot(slot)? == key {
                return self.range_for_slot(slot);
            }
            index = (index + 1) & mask;
        }
    }

    fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// In slot order, not sorted.
    fn keys(&self) -> impl Iterator<Item = &[u8]> {
        self.slots
            .iter()
            .filter(|slot| slot.tag != 0)
            .filter_map(|slot| self.key_for_slot(slot))
    }
}

/// Arena form of a record. A and AAAA dominate most zones, so they hold only their value, and other
/// types point into an arena. The variant stays a few words instead of the largest RData, so the
/// arena fits in cache far better.
///
/// The owner name lives in the index and is attached again when building a response.
#[derive(Clone)]
struct StoredRecord {
    /// Top 2 bits are the kind, the rest the TTL. For Other, the TTL field holds the record type
    /// instead, and the TTL lives in the full record in the arena.
    tagged: u32,
    /// The address for A, an AAAA arena index for AAAA, a record arena index otherwise.
    payload: u32,
}

const STORED_TAG_SHIFT: u32 = 30;
const STORED_TAG_A: u32 = 0;
const STORED_TAG_AAAA: u32 = 1;
const STORED_TAG_OTHER: u32 = 2;
const STORED_VALUE_MASK: u32 = (1 << STORED_TAG_SHIFT) - 1;

/// About 34 years. RFC 2181 treats TTLs with the top bit set as 0, leaving 31 usable bits, and the
/// kind takes one more. Longer TTLs are clamped at load.
const STORED_TTL_MAX: u32 = STORED_VALUE_MASK;

/// What the allocation-free path can conclude for a missing name or type. Fallback means it cannot
/// answer, and the caller takes the structured path.
enum SimpleAbsent<'a> {
    NxDomain,
    NoData,
    Wildcard(&'a [StoredRecord]),
    Dname(&'a Record),
    Fallback,
}

impl StoredRecord {
    /// Moves addresses and full records into their arenas.
    fn from_record(
        record: Record,
        aaaa_arena: &mut Vec<std::net::Ipv6Addr>,
        other_arena: &mut Vec<Record>,
    ) -> Result<Self, String> {
        let ttl = record.ttl.min(STORED_TTL_MAX);
        match &record.rdata {
            RData::A(address) => Ok(Self {
                tagged: (STORED_TAG_A << STORED_TAG_SHIFT) | ttl,
                payload: u32::from(*address),
            }),
            RData::Aaaa(address) => {
                let address_index = u32::try_from(aaaa_arena.len())
                    .map_err(|_| "AAAA address arena offset exceeds 32 bits".to_string())?;
                aaaa_arena.push(*address);
                Ok(Self {
                    tagged: (STORED_TAG_AAAA << STORED_TAG_SHIFT) | ttl,
                    payload: address_index,
                })
            }
            _ => {
                let index = u32::try_from(other_arena.len())
                    .map_err(|_| "Record arena offset exceeds 32 bits".to_string())?;
                let rtype = u32::from(record.rtype.0);
                other_arena.push(record);
                Ok(Self {
                    tagged: (STORED_TAG_OTHER << STORED_TAG_SHIFT) | rtype,
                    payload: index,
                })
            }
        }
    }

    fn tag(&self) -> u32 {
        self.tagged >> STORED_TAG_SHIFT
    }

    /// Meaningful only for A and AAAA.
    fn ttl(&self) -> u32 {
        self.tagged & STORED_VALUE_MASK
    }

    /// Other keeps its type in the TTL field, so this never reads the arena.
    fn rtype(&self) -> RecordType {
        match self.tag() {
            STORED_TAG_A => RecordType::A,
            STORED_TAG_AAAA => RecordType::AAAA,
            _ => RecordType((self.tagged & STORED_VALUE_MASK) as u16),
        }
    }

    /// None for compact variants.
    fn full<'a>(&self, other_arena: &'a [Record]) -> Option<&'a Record> {
        (self.tag() == STORED_TAG_OTHER).then(|| other_arena.get(self.payload as usize))?
    }

    /// Attaches the owner name to rebuild a full record. Clones the name, so only response assembly
    /// calls it; the allocation-free path does not.
    fn materialize(
        &self,
        owner: &Name,
        aaaa_arena: &[std::net::Ipv6Addr],
        other_arena: &[Record],
    ) -> Option<Record> {
        match self.tag() {
            STORED_TAG_A => Some(Record::new(
                owner.clone(),
                self.ttl(),
                RData::A(Ipv4Addr::from(self.payload)),
            )),
            STORED_TAG_AAAA => Some(Record::new(
                owner.clone(),
                self.ttl(),
                RData::Aaaa(*aaaa_arena.get(self.payload as usize)?),
            )),
            _ => Some(other_arena.get(self.payload as usize)?.clone()),
        }
    }
}

/// Borrows one RRset from an owner's records, which are sorted by type. A single-type owner, the
/// common case, is returned whole after checking the first and last; only mixed owners binary
/// search, so large A/AAAA RRsets are not walked twice.
///
/// Relies on from_flat_records sorting each owner's records by type number.
fn stored_rrset(records: &[StoredRecord], rtype: RecordType) -> &[StoredRecord] {
    let Some(first) = records.first() else {
        return records;
    };
    if first.rtype() == rtype
        && (records.len() == 1 || records.last().is_some_and(|last| last.rtype() == rtype))
    {
        return records;
    }

    let start = records.partition_point(|record| record.rtype().0 < rtype.0);
    let Some(tail) = records.get(start..) else {
        return &[];
    };
    let len = tail.partition_point(|record| record.rtype() == rtype);
    &tail[..len]
}

/// Records must be in canonical order.
fn owner_group_end(records: &[Record], start: usize) -> usize {
    let owner = &records[start].name;
    let mut end = start + 1;
    while end < records.len() && records[end].name.eq_ignore_case(owner) {
        end += 1;
    }
    end
}

/// Where an in-zone CNAME chase stopped. Each ending answers differently: RFC 6604 sets the rcode
/// from the last step of the chain, so absence and NODATA cannot merge, and both need a negative
/// SOA to be cached.
enum ChaseEnd {
    /// Found the requested type, with records for the additional section.
    Answered(Vec<Record>),
    NoSuchName,
    NoData,
    Delegated(Name),
    /// The client continues resolution.
    OutOfZone,
}

/// Keeps one of each set of records with equal owner, type, class, and data. RFC 2181 says such
/// duplicates are meaningless and servers should suppress them; kept, they inflate answers, and in
/// signed zones the set the signature covers differs from the set sent, breaking validation.
/// `records` must be sorted by owner; returns the number removed.
fn drop_duplicate_records(records: &mut Vec<Record>) -> usize {
    let mut seen: HashSet<(u16, u16, Vec<u8>)> = HashSet::new();
    let mut keep = vec![true; records.len()];
    let mut dropped = 0usize;
    let mut start = 0usize;
    while start < records.len() {
        let end = owner_group_end(records, start);
        if end - start > 1 {
            seen.clear();
            for (index, record) in records[start..end].iter().enumerate() {
                let mut writer = onetdns_proto::Writer::new();
                record.rdata.encode(&mut writer);
                if writer.error().is_some() {
                    continue;
                }
                if !seen.insert((record.rtype.0, record.class.0, writer.buf)) {
                    keep[start + index] = false;
                    dropped += 1;
                }
            }
        }
        start = end;
    }
    if dropped > 0 {
        let mut index = 0usize;
        records.retain(|_| {
            let wanted = keep[index];
            index += 1;
            wanted
        });
    }
    dropped
}

/// Makes each RRset's TTLs equal at load, as RFC 2181 requires. Doing it once here gives
/// structured answers, compact storage, the wire fast path, and transfer templates the same value.
fn normalize_owner_group_ttls(records: &mut [Record]) {
    let mut start = 0usize;
    while start < records.len() {
        let end = owner_group_end(records, start);
        onetdns_proto::normalize_ttls(&mut records[start..end]);
        start = end;
    }
}

/// Two passes: count owners and metadata length to allocate exactly, then fill. Growing while
/// filling would reallocate and copy repeatedly during load.
fn build_owner_index(records: &[Record]) -> Result<OwnerIndex, String> {
    let mut owner_count = 0usize;
    let mut metadata_len = 0usize;
    let mut start = 0usize;
    while start < records.len() {
        let end = owner_group_end(records, start);
        if end - start > MAX_OWNER_RECORDS {
            return Err(format!(
                "One name has more records than allowed ({MAX_OWNER_RECORDS})"
            ));
        }
        let mut key = [0u8; 255];
        let key = records[start]
            .name
            .canonical_key_into(&mut key)
            .ok_or_else(|| "DNS owner name exceeds the maximum wire length".to_string())?;
        metadata_len = metadata_len
            .checked_add(
                key.len()
                    .checked_add(3)
                    .ok_or_else(|| "Zone owner key arena size overflowed".to_string())?,
            )
            .ok_or_else(|| "Zone owner key arena size overflowed".to_string())?;
        owner_count += 1;
        start = end;
    }

    let mut index = OwnerIndex::new(owner_count, metadata_len)?;
    let mut start = 0usize;
    while start < records.len() {
        let end = owner_group_end(records, start);
        let mut key = [0u8; 255];
        let key = records[start]
            .name
            .canonical_key_into(&mut key)
            .ok_or_else(|| "DNS owner name exceeds the maximum wire length".to_string())?;
        index.insert(
            key,
            RecordRange {
                start: u32::try_from(start)
                    .map_err(|_| "Zone record arena offset exceeds 32 bits".to_string())?,
                len: u16::try_from(end - start)
                    .map_err(|_| "Owner record count exceeds 16 bits".to_string())?,
            },
        )?;
        start = end;
    }
    Ok(index)
}

/// Load-time lookup over the original records, before conversion to stored form.
fn full_records_for_key<'a>(
    records: &'a [Record],
    index: &OwnerIndex,
    key: &[u8],
) -> Option<&'a [Record]> {
    let range = index.get(key)?;
    let start = range.start as usize;
    records.get(start..start.checked_add(range.len as usize)?)
}

/// Load-time walk over the original records grouped by owner.
fn full_record_groups<'a>(
    records: &'a [Record],
    index: &'a OwnerIndex,
) -> impl Iterator<Item = (&'a [u8], &'a [Record])> + 'a {
    index.keys().filter_map(move |key| {
        full_records_for_key(records, index, key).map(|owner_records| (key, owner_records))
    })
}

/// The layer above turns this into a DNS message.
#[derive(Debug, Default, PartialEq)]
pub struct Response {
    pub rcode: u8,

    /// Off for referrals.
    pub authoritative: bool,
    pub answers: Vec<Record>,
    /// SOA for negative answers, NS for referrals.
    pub authority: Vec<Record>,
    /// Glue addresses.
    pub additional: Vec<Record>,
}

impl Zone {
    /// Checks that each map key matches its records' owner name; an index built over a mismatch
    /// would answer with the wrong records.
    pub fn new(
        origin: Name,
        soa: Soa,
        soa_ttl: u32,
        records: HashMap<String, Vec<Record>>,
    ) -> Result<Self, String> {
        if records.iter().any(|(key, owner_records)| {
            owner_records.is_empty()
                || owner_records.iter().any(|record| {
                    key != &record.name.to_ascii_lower()
                        || !is_subdomain_or_eq(&record.name, &origin)
                })
        }) {
            return Err("Owner outside the zone, or the owner index does not match".to_string());
        }
        let mut canonical_records = HashMap::with_capacity(records.len());
        for owner_records in records.into_values() {
            let owner = owner_records[0].name.canonical_key();
            let mut exact = Vec::with_capacity(owner_records.len());
            exact.extend(owner_records);
            canonical_records.insert(owner, exact);
        }
        Self::from_canonical_records(origin, soa, soa_ttl, canonical_records)
    }

    fn from_canonical_records(
        origin: Name,
        soa: Soa,
        soa_ttl: u32,
        canonical_records: HashMap<Vec<u8>, Vec<Record>>,
    ) -> Result<Self, String> {
        let Some(total_records) = canonical_records
            .values()
            .try_fold(0usize, |total, owner| total.checked_add(owner.len()))
        else {
            return Err(format!(
                "The zone has more records than allowed ({MAX_ZONE_RECORDS})"
            ));
        };
        if total_records > MAX_ZONE_RECORDS {
            return Err(format!(
                "The zone has more records than allowed ({MAX_ZONE_RECORDS})"
            ));
        }
        let mut records = Vec::with_capacity(total_records);
        for owner_records in canonical_records.into_values() {
            records.extend(owner_records);
        }
        Self::from_flat_records(origin, soa, soa_ttl, records)
    }

    /// Every load path ends here. Fails when the apex has no NS or an owner lies outside the zone.
    /// The result is immutable; queries only read it.
    fn from_flat_records(
        origin: Name,
        soa: Soa,
        soa_ttl: u32,
        mut full_records: Vec<Record>,
    ) -> Result<Self, String> {
        if full_records.len() > MAX_ZONE_RECORDS {
            return Err(format!(
                "The zone has more records than allowed ({MAX_ZONE_RECORDS})"
            ));
        }
        if full_records
            .iter()
            .any(|record| !is_subdomain_or_eq(&record.name, &origin))
        {
            return Err("Owner outside the zone, or the owner index does not match".to_string());
        }
        full_records.sort_unstable_by(|left, right| {
            dnssec_name_cmp(&left.name, &right.name).then_with(|| left.rtype.0.cmp(&right.rtype.0))
        });
        // TTLs first: only after RFC 2181 makes an RRset's TTLs equal are records that match in
        // everything else true duplicates.
        normalize_owner_group_ttls(&mut full_records);
        let duplicates = drop_duplicate_records(&mut full_records);
        if duplicates > 0 {
            onetdns_core::info!(
                event = "zone.duplicate_records_dropped",
                zone = %origin.to_ascii_lower(),
                count = duplicates,
                "Kept only one of several identical records"
            );
        }
        let soa_ttl = if soa_ttl > onetdns_proto::MAX_TTL {
            0
        } else {
            soa_ttl
        };
        let records = build_owner_index(&full_records)?;
        let mut origin_storage = [0u8; 255];
        let origin_key = origin
            .canonical_key_into(&mut origin_storage)
            .ok_or_else(|| "DNS zone origin exceeds the maximum wire length".to_string())?;
        if !full_records_for_key(&full_records, &records, origin_key)
            .is_some_and(|apex| apex.iter().any(|record| record.rtype == RecordType::NS))
        {
            return Err("The zone apex has no NS record".to_string());
        }
        validate_zone_records(&origin, &full_records, &records)?;
        let mut name_flags = HashMap::new();
        for (_, owner_records) in full_record_groups(&full_records, &records) {
            let owner = &owner_records[0].name;
            for labels in origin.num_labels()..=owner.num_labels() {
                let mut storage = [0u8; 255];
                let Some(key) = owner.suffix(labels).canonical_key_into(&mut storage) else {
                    return Err("DNS owner name exceeds the maximum wire length".to_string());
                };
                if !records.contains_key(key) {
                    *name_flags.entry(key.to_vec()).or_default() |= NAME_EXISTS;
                }
            }
        }
        let has_delegations =
            full_record_groups(&full_records, &records).any(|(owner, owner_records)| {
                owner != origin_key
                    && owner_records
                        .iter()
                        .any(|record| record.rtype == RecordType::NS)
            });
        for (owner, owner_records) in full_record_groups(&full_records, &records) {
            if owner.starts_with(&[1, b'*']) {
                let parent = parent_canonical_key(owner)
                    .ok_or_else(|| "A wildcard owner has no parent name".to_string())?;
                *name_flags.entry(parent.to_vec()).or_default() |= NAME_HAS_WILDCARD;
            }
            if owner_records
                .iter()
                .any(|record| record.rtype == RecordType::DNAME)
            {
                *name_flags.entry(owner.to_vec()).or_default() |= NAME_HAS_DNAME;
            }
        }
        let simple_nxdomain = !has_delegations && name_flags.is_empty();
        let mut denial_index: HashMap<RecordType, Vec<RecordLocation>> = HashMap::new();
        for (owner, owner_records) in full_record_groups(&full_records, &records) {
            for (offset, record) in owner_records.iter().enumerate() {
                if matches!(record.rtype, RecordType::NSEC | RecordType::NSEC3) {
                    denial_index
                        .entry(record.rtype)
                        .or_default()
                        .push(RecordLocation {
                            owner: owner.to_vec(),
                            offset,
                        });
                }
            }
        }
        for locations in denial_index.values_mut() {
            locations.sort_by(|left, right| {
                let left = full_records_for_key(&full_records, &records, &left.owner)
                    .and_then(|owner| owner.get(left.offset));
                let right = full_records_for_key(&full_records, &records, &right.owner)
                    .and_then(|owner| owner.get(right.offset));
                match (left, right) {
                    (Some(left), Some(right)) => dnssec_name_cmp(&left.name, &right.name),
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => Ordering::Equal,
                }
            });
        }
        let aaaa_count = full_records
            .iter()
            .filter(|record| record.rtype == RecordType::AAAA)
            .count();
        let mut aaaa_arena = Vec::with_capacity(aaaa_count);
        let mut other_arena = Vec::new();
        let mut record_arena = Vec::with_capacity(full_records.len());
        for record in full_records {
            record_arena.push(StoredRecord::from_record(
                record,
                &mut aaaa_arena,
                &mut other_arena,
            )?);
        }
        Ok(Zone {
            origin,
            soa,
            soa_ttl,
            records,
            record_arena: record_arena.into_boxed_slice(),
            aaaa_arena: aaaa_arena.into_boxed_slice(),
            other_arena: other_arena.into_boxed_slice(),
            name_flags,
            has_delegations,
            simple_nxdomain,
            denial_index,
            axfr_wire: Arc::new(OnceLock::new()),
            source: None,
        })
    }

    pub fn source_digest(&self) -> Option<source::SourceDigest> {
        self.source
    }

    /// A writer compares the file's current digest with this before writing; a difference means the
    /// file changed without this server knowing.
    pub fn with_source_digest(mut self, digest: source::SourceDigest) -> Self {
        self.source = Some(digest);
        self
    }

    /// Builds a zone from transferred records. A transfer starts and ends with SOA, so the two must
    /// match and one is dropped; a mismatch means the zone changed mid-transfer. Any owner outside
    /// the zone is rejected, so a peer cannot slip foreign names into its zone.
    pub fn from_records(mut records: Vec<Record>) -> Result<Zone, String> {
        if records.len() > MAX_ZONE_RECORDS {
            return Err(format!(
                "The zone has more records than allowed ({MAX_ZONE_RECORDS})"
            ));
        }
        let soa_records: Vec<&Record> = records
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .collect();
        let soa_rec = *soa_records
            .first()
            .ok_or_else(|| "AXFR response has no SOA record".to_string())?;
        let RData::Soa(soa) = &soa_rec.rdata else {
            return Err("Malformed SOA RDATA".to_string());
        };
        let origin = soa_rec.name.clone();

        if soa_records.len() > 2
            || soa_records
                .iter()
                .any(|record| !record.name.eq_ignore_case(&origin) || record.rdata != soa_rec.rdata)
        {
            return Err("AXFR contains differing or too many SOA records".to_string());
        }
        if records
            .iter()
            .any(|record| !is_subdomain_or_eq(&record.name, &origin))
        {
            return Err("AXFR contains an owner outside the zone".to_string());
        }
        if !records
            .iter()
            .any(|record| record.name.eq_ignore_case(&origin) && record.rtype == RecordType::NS)
        {
            return Err("The zone apex has no NS record".to_string());
        }

        let soa_ttl = soa_rec.ttl;
        let soa = soa.as_ref().clone();
        let mut kept_soa = false;
        records.retain(|record| {
            if record.rtype == RecordType::SOA {
                if kept_soa {
                    return false;
                }
                kept_soa = true;
            }
            true
        });
        Self::from_flat_records(origin, soa, soa_ttl, records)
    }

    pub fn origin(&self) -> &Name {
        &self.origin
    }

    pub fn soa(&self) -> &Soa {
        &self.soa
    }

    /// In index order.
    pub fn all_records(&self) -> impl Iterator<Item = Record> + '_ {
        self.records.keys().flat_map(move |owner_key| {
            let owner = Name::from_uncompressed_wire(owner_key);
            let records = self.records_for_key(owner_key).unwrap_or_default();
            records.iter().filter_map(move |record| {
                owner
                    .as_ref()
                    .and_then(|name| record.materialize(name, &self.aaaa_arena, &self.other_arena))
            })
        })
    }

    pub fn axfr_records(&self) -> Vec<Record> {
        self.axfr_records_iter().collect()
    }

    /// Starts and ends with SOA, as transfers require.
    pub fn axfr_records_iter(&self) -> impl Iterator<Item = Record> + '_ {
        let soa = self.soa_record();
        std::iter::once(soa.clone())
            .chain(
                self.all_records()
                    .filter(|record| record.rtype != RecordType::SOA),
            )
            .chain(std::iter::once(soa))
    }

    /// Built once on first request. A failure is remembered too: retrying on every transfer of a
    /// zone that cannot be encoded gives the same result.
    pub fn axfr_wire_templates(&self) -> Result<&[Box<[u8]>], ProtoError> {
        match self
            .axfr_wire
            .get_or_init(|| self.build_axfr_wire_templates())
        {
            Ok(templates) => Ok(templates),
            Err(error) => Err(error.clone()),
        }
    }

    /// Splits transfer records into messages within the budget, measuring each record with a trial
    /// encoding. Name compression only makes the real size smaller, so the estimate never exceeds
    /// the message limit.
    fn build_axfr_wire_templates(&self) -> Result<Box<[Box<[u8]>]>, ProtoError> {
        let mut templates = Vec::new();
        let mut chunk = Vec::new();
        let mut estimated = 0usize;
        let mut estimate_writer = Writer::new();
        for record in self.axfr_records_iter() {
            estimate_writer.clear();
            record.encode(&mut estimate_writer);
            let record_estimate = estimate_writer.buf.len();
            if estimated + record_estimate > XFR_CHUNK_BUDGET && !chunk.is_empty() {
                templates.push(encode_axfr_template(
                    &self.origin,
                    std::mem::take(&mut chunk),
                    templates.is_empty(),
                )?);
                estimated = 0;
            }
            estimated += record_estimate;
            chunk.push(record);
        }
        templates.push(encode_axfr_template(
            &self.origin,
            chunk,
            templates.is_empty(),
        )?);
        Ok(templates.into_boxed_slice())
    }

    /// For signing and diagnostics.
    pub fn records_of_type(&self, rtype: RecordType) -> Vec<Record> {
        self.records
            .keys()
            .flat_map(|owner_key| {
                let owner = Name::from_uncompressed_wire(owner_key);
                let records = self.records_for_key(owner_key).unwrap_or_default();
                records.iter().filter_map(move |record| {
                    (record.rtype() == rtype)
                        .then(|| {
                            owner.as_ref().and_then(|name| {
                                record.materialize(name, &self.aaaa_arena, &self.other_arena)
                            })
                        })
                        .flatten()
                })
            })
            .collect()
    }

    /// Tells NSEC zones from NSEC3 zones.
    pub fn has_denial_records(&self, rtype: RecordType) -> bool {
        self.denial_index
            .get(&rtype)
            .is_some_and(|records| !records.is_empty())
    }

    /// For wrapping around the chain.
    pub fn first_denial_record(&self, rtype: RecordType) -> Option<&Record> {
        self.denial_index
            .get(&rtype)?
            .first()
            .and_then(|location| self.record_at(location))
    }

    /// Binary search; the index is in canonical order.
    pub fn exact_denial_record(&self, rtype: RecordType, name: &Name) -> Option<&Record> {
        let locations = self.denial_index.get(&rtype)?;
        let index = locations
            .binary_search_by(|location| {
                self.record_at(location)
                    .map_or(Ordering::Less, |record| dnssec_name_cmp(&record.name, name))
            })
            .ok()?;
        self.record_at(&locations[index])
    }

    /// Wraps to the last record when the name sorts before the first: the chain is circular, so the
    /// zone's last record covers that gap.
    pub fn preceding_denial_record(&self, rtype: RecordType, name: &Name) -> Option<&Record> {
        let locations = self.denial_index.get(&rtype)?;
        if locations.is_empty() {
            return None;
        }
        let index = match locations.binary_search_by(|location| {
            self.record_at(location)
                .map_or(Ordering::Less, |record| dnssec_name_cmp(&record.name, name))
        }) {
            Ok(index) | Err(index) => index.checked_sub(1).unwrap_or(locations.len() - 1),
        };
        self.record_at(&locations[index])
    }

    /// Writes the zone as master file text, for persisting dynamic updates. Names are sorted, so
    /// the same zone always gives the same text and a file comparison shows whether it changed.
    pub fn to_master_file(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("$ORIGIN {}.\n", self.origin.to_ascii_lower()));
        out.push_str(";; File in which OnetDNS saves dynamic DNS updates. Keep the format when editing it by hand.\n");
        let soa = self.soa_record();
        out.push_str(&record_to_master_line(&soa));
        let mut names: Vec<&[u8]> = self.records.keys().collect();
        names.sort();
        for n in names {
            let Some(owner) = Name::from_uncompressed_wire(n) else {
                continue;
            };
            for r in self.records_for_key(n).unwrap_or_default() {
                if r.rtype() != RecordType::SOA {
                    if let Some(record) = r.materialize(&owner, &self.aaaa_arena, &self.other_arena)
                    {
                        out.push_str(&record_to_master_line(&record));
                    }
                }
            }
        }
        out
    }

    /// Builds the key in a stack buffer, without allocating.
    fn owner(&self, name: &Name) -> Option<&[StoredRecord]> {
        let mut key = [0u8; 255];
        self.records_for_key(name.canonical_key_into(&mut key)?)
    }

    fn records_for_key(&self, key: &[u8]) -> Option<&[StoredRecord]> {
        let range = self.records.get(key)?;
        let start = range.start as usize;
        let end = start.checked_add(range.len as usize)?;
        self.record_arena.get(start..end)
    }

    /// Denial records are always stored in full, never compact.
    fn record_at(&self, location: &RecordLocation) -> Option<&Record> {
        self.records_for_key(&location.owner)
            .and_then(|records| records.get(location.offset))
            .and_then(|record| record.full(&self.other_arena))
    }

    fn of_type(&self, recs: &[StoredRecord], qtype: RecordType, owner: &Name) -> Vec<Record> {
        stored_rrset(recs, qtype)
            .iter()
            .filter_map(|record| record.materialize(owner, &self.aaaa_arena, &self.other_arena))
            .collect()
    }

    /// With its own TTL.
    fn soa_record(&self) -> Record {
        Record::new(
            self.origin.clone(),
            self.soa_ttl,
            RData::soa(self.soa.clone()),
        )
    }

    /// The TTL is the smaller of the SOA's TTL and its minimum field, which sets how long the
    /// negative answer is cached; it must not be cached longer.
    fn negative_soa_record(&self) -> Record {
        Record::new(
            self.origin.clone(),
            self.soa_ttl.min(self.soa.minimum),
            RData::soa(self.soa.clone()),
        )
    }

    pub fn contains(&self, qname: &Name) -> bool {
        is_subdomain_or_eq(qname, &self.origin)
    }

    /// Checks in order: delegation, exact owner, DNAME, wildcard, then absence. Checking delegation
    /// later would make this server answer names in a child zone itself. Referrals have the
    /// authoritative bit off.
    pub fn query(&self, qname: &Name, qtype: RecordType) -> Response {
        if let Some(deleg) = self.delegation_for(qname) {
            if qname.eq_ignore_case(&deleg)
                && matches!(
                    qtype,
                    RecordType::DS | RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                )
            {
                let recs = self.owner(&deleg).unwrap_or_default();
                return self.answer_at(qname, qtype, recs);
            }
            return self.referral(deleg);
        }

        if let Some(recs) = self.owner(qname) {
            return self.answer_at(qname, qtype, recs);
        }

        if let Some(resp) = self.dname(qname, qtype) {
            return resp;
        }

        if self.node_exists(qname) {
            return Response {
                rcode: 0,
                authoritative: true,
                authority: vec![self.negative_soa_record()],
                ..Default::default()
            };
        }

        if let Some(resp) = self.wildcard(qname, qtype) {
            return resp;
        }

        Response {
            rcode: 3,
            authoritative: true,
            authority: vec![self.negative_soa_record()],
            ..Default::default()
        }
    }

    /// Deepest delegation point above the name, looking only below the apex, whose NS belongs to
    /// the zone itself. The deepest one is the right child in multi-level delegation.
    fn delegation_for(&self, qname: &Name) -> Option<Name> {
        if !self.has_delegations {
            return None;
        }
        let on = self.origin.num_labels();
        let qn = qname.num_labels();
        let mut storage = [0u8; 255];
        let mut key = qname.canonical_key_into(&mut storage)?;
        let mut labels = qn;
        let mut delegation = None;

        while labels > on {
            if self
                .records_for_key(key)
                .is_some_and(|records| records.iter().any(|r| r.rtype() == RecordType::NS))
            {
                delegation = Some(labels);
            }
            key = parent_canonical_key(key)?;
            labels -= 1;
        }
        delegation.map(|labels| qname.suffix(labels))
    }

    /// Authoritative bit off: the data belongs to the child zone, not this server. DS goes along
    /// when present, so the client can validate the child's signatures.
    fn referral(&self, deleg: Name) -> Response {
        let recs = self.owner(&deleg).unwrap_or_default();
        let ns = self.of_type(recs, RecordType::NS, &deleg);
        let ds = self.of_type(recs, RecordType::DS, &deleg);
        let mut additional = Vec::new();
        for r in &ns {
            if let RData::Ns(target) = &r.rdata {
                additional.extend(self.glue(target));
            }
        }
        let mut authority = ns;
        authority.extend(ds);
        Response {
            rcode: 0,
            authoritative: false,
            authority,
            additional,
            ..Default::default()
        }
    }

    /// Response for an existing name: the exact type if present; otherwise a CNAME, unless the
    /// query is for CNAME, where the CNAME itself is the answer; otherwise NODATA, never NXDOMAIN,
    /// since the name exists.
    fn answer_at(&self, qname: &Name, qtype: RecordType, recs: &[StoredRecord]) -> Response {
        if qtype == RecordType::ANY {
            return Response {
                rcode: 0,
                authoritative: true,
                answers: recs
                    .iter()
                    .filter_map(|record| {
                        record.materialize(qname, &self.aaaa_arena, &self.other_arena)
                    })
                    .collect(),
                ..Default::default()
            };
        }
        let exact = self.of_type(recs, qtype, qname);
        if !exact.is_empty() {
            let additional = self.target_glue(&exact);
            return Response {
                rcode: 0,
                authoritative: true,
                answers: exact,
                additional,
                ..Default::default()
            };
        }

        if qtype != RecordType::CNAME {
            let cnames = self.of_type(recs, RecordType::CNAME, qname);
            if let Some(cn) = cnames.first() {
                if let RData::Cname(target) = &cn.rdata {
                    let mut answers = vec![cn.clone()];
                    let end = self.chase_cname(target, qtype, &mut answers);
                    return self.cname_response(answers, end);
                }
            }
        }

        Response {
            rcode: 0,
            authoritative: true,
            authority: vec![self.negative_soa_record()],
            ..Default::default()
        }
    }

    /// Follows a CNAME chain within the zone. RFC 1034 restarts resolution at the new name on a
    /// CNAME, so empty non-terminals and wildcards follow the same rules as real names. The step
    /// count is capped: two CNAMEs pointing at each other would loop forever. Each step is appended
    /// to `answers`; the caller sets rcode and authority from the returned end.
    fn chase_cname(&self, target: &Name, qtype: RecordType, answers: &mut Vec<Record>) -> ChaseEnd {
        let mut cur = target.clone();
        for _ in 0..8 {
            if !self.contains(&cur) {
                return ChaseEnd::OutOfZone;
            }
            if let Some(deleg) = self.delegation_for(&cur) {
                return ChaseEnd::Delegated(deleg);
            }
            let recs = match self.owner(&cur) {
                Some(recs) => recs,
                None if self.node_exists(&cur) => return ChaseEnd::NoData,
                None => match self.wildcard_records(&cur) {
                    Some(recs) => recs,
                    None => return ChaseEnd::NoSuchName,
                },
            };
            let exact = self.of_type(recs, qtype, &cur);
            if !exact.is_empty() {
                let additional = self.target_glue(&exact);
                answers.extend(exact);
                return ChaseEnd::Answered(additional);
            }
            let cnames = self.of_type(recs, RecordType::CNAME, &cur);
            match cnames.first().map(|r| &r.rdata) {
                Some(RData::Cname(next)) => {
                    answers.push(cnames[0].clone());
                    cur = next.clone();
                }
                _ => return ChaseEnd::NoData,
            }
        }
        ChaseEnd::OutOfZone
    }

    /// Records of the wildcard owner covering the name, unmodified; the caller stamps the query
    /// name as owner.
    fn wildcard_records(&self, qname: &Name) -> Option<&[StoredRecord]> {
        let closest = self.closest_encloser(qname)?;
        if closest.eq_ignore_case(qname) {
            return None;
        }
        let source = prepend_wildcard(&closest);
        let mut key = [0u8; 255];
        self.records_for_key(source.canonical_key_into(&mut key)?)
    }

    /// RFC 6604 requires the rcode to come from the final query cycle, so CNAMEs already in
    /// `answers` stay and only the last cycle's outcome sets rcode and authority.
    fn cname_response(&self, answers: Vec<Record>, end: ChaseEnd) -> Response {
        let (rcode, authority, additional) = match end {
            ChaseEnd::Answered(additional) => (0, Vec::new(), additional),
            ChaseEnd::NoSuchName => (3, vec![self.negative_soa_record()], Vec::new()),
            ChaseEnd::NoData => (0, vec![self.negative_soa_record()], Vec::new()),
            ChaseEnd::Delegated(deleg) => {
                let referral = self.referral(deleg);
                (0, referral.authority, referral.additional)
            }
            ChaseEnd::OutOfZone => (0, Vec::new(), Vec::new()),
        };
        Response {
            rcode,
            authoritative: true,
            answers,
            authority,
            additional,
        }
    }

    /// Answers through a DNAME at an ancestor: keeps the query name's leading labels, replaces the
    /// rest with the target, and sends the synthesized CNAME along. A synthesized name over 255
    /// octets is YXDOMAIN; truncating it would send the client on to the wrong name.
    fn dname(&self, qname: &Name, qtype: RecordType) -> Option<Response> {
        let origin_labels = self.origin.num_labels();
        let mut labels = qname.num_labels();
        let mut storage = [0u8; 255];
        let mut key = qname.canonical_key_into(&mut storage)?;
        while labels > origin_labels {
            key = parent_canonical_key(key)?;
            labels -= 1;
            let Some(owner_records) = self.records_for_key(key) else {
                continue;
            };
            let Some(record) = owner_records.iter().find_map(|record| {
                (record.rtype() == RecordType::DNAME)
                    .then(|| record.full(&self.other_arena))
                    .flatten()
            }) else {
                continue;
            };
            let RData::Dname(target_suffix) = &record.rdata else {
                continue;
            };
            let prefix_len = qname.num_labels() - labels;
            let mut target_labels: Vec<Vec<u8>> = qname
                .labels()
                .take(prefix_len)
                .map(<[u8]>::to_vec)
                .collect();
            target_labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
            let Ok(target) = Name::from_labels(target_labels) else {
                return Some(Response {
                    rcode: 6,
                    authoritative: true,
                    answers: vec![record.clone()],
                    ..Default::default()
                });
            };
            let cname = Record::new(qname.clone(), record.ttl, RData::Cname(target.clone()));
            let mut answers = vec![record.clone(), cname];
            if qtype == RecordType::CNAME {
                return Some(Response {
                    rcode: 0,
                    authoritative: true,
                    answers,
                    ..Default::default()
                });
            }
            let end = self.chase_cname(&target, qtype, &mut answers);
            return Some(self.cname_response(answers, end));
        }
        None
    }

    /// No wildcard applies when the closest encloser is the query name itself: that name exists and
    /// wins over the wildcard. Synthesized records get the query name as owner, not the asterisk.
    fn wildcard(&self, qname: &Name, qtype: RecordType) -> Option<Response> {
        let closest = self.closest_encloser(qname)?;
        if closest.eq_ignore_case(qname) {
            return None;
        }
        let source = prepend_wildcard(&closest);
        let mut key = [0u8; 255];
        let recs = self.records_for_key(source.canonical_key_into(&mut key)?)?;
        let resp = self.answer_at(qname, qtype, recs);
        Some(synthesize_owner(resp, qname, &source))
    }

    /// Longest ancestor that exists in the zone, counting empty non-terminals: a name with children
    /// exists.
    fn closest_encloser(&self, qname: &Name) -> Option<Name> {
        let origin_labels = self.origin.num_labels();
        let mut labels = qname.num_labels();
        let mut storage = [0u8; 255];
        let mut key = qname.canonical_key_into(&mut storage)?;
        loop {
            if self.records.contains_key(key)
                || self
                    .name_flags
                    .get(key)
                    .is_some_and(|flags| flags & NAME_EXISTS != 0)
            {
                return Some(qname.suffix(labels));
            }
            if labels == origin_labels {
                break;
            }
            key = parent_canonical_key(key)?;
            labels -= 1;
        }
        None
    }

    /// Empty non-terminals count as existing.
    fn node_exists(&self, name: &Name) -> bool {
        let mut key = [0u8; 255];
        name.canonical_key_into(&mut key).is_some_and(|key| {
            self.records.contains_key(key)
                || self
                    .name_flags
                    .get(key)
                    .is_some_and(|flags| flags & NAME_EXISTS != 0)
        })
    }

    /// Absence check for the allocation-free path. A flat zone is NXDOMAIN at once; otherwise it
    /// walks ancestors for DNAME and wildcard branches, DNAME first, since a DNAME match makes
    /// wildcards irrelevant. No wildcard branch means a definite NXDOMAIN. The wildcard name is
    /// built in a stack buffer, since the asterisk label is always 2 bytes. Fallback when it cannot
    /// decide.
    fn simple_absent_for_key(&self, canonical_qname: &[u8]) -> SimpleAbsent<'_> {
        if self.simple_nxdomain {
            return SimpleAbsent::NxDomain;
        }

        let qname_flags = self
            .name_flags
            .get(canonical_qname)
            .copied()
            .unwrap_or_default();
        if qname_flags & NAME_HAS_DNAME != 0 {
            return SimpleAbsent::Fallback;
        }
        if qname_flags & NAME_EXISTS != 0 {
            return SimpleAbsent::NoData;
        }

        let Some(mut key) = parent_canonical_key(canonical_qname) else {
            return SimpleAbsent::Fallback;
        };
        let origin_len = self.origin.as_uncompressed_wire().len();
        let mut has_wildcard_branch = false;
        loop {
            if let Some(flags) = self.name_flags.get(key).copied() {
                if flags & NAME_HAS_DNAME != 0 {
                    let Some(record) = self.records_for_key(key).and_then(|records| {
                        records.iter().find_map(|record| {
                            (record.rtype() == RecordType::DNAME)
                                .then(|| record.full(&self.other_arena))
                                .flatten()
                        })
                    }) else {
                        return SimpleAbsent::Fallback;
                    };
                    return SimpleAbsent::Dname(record);
                }
                has_wildcard_branch |= flags & NAME_HAS_WILDCARD != 0;
            }
            if key.len() <= origin_len {
                break;
            }
            let Some(parent) = parent_canonical_key(key) else {
                break;
            };
            key = parent;
        }

        if !has_wildcard_branch {
            return SimpleAbsent::NxDomain;
        }

        let mut key = canonical_qname;
        let closest_encloser = loop {
            if self.records.contains_key(key)
                || self
                    .name_flags
                    .get(key)
                    .is_some_and(|flags| flags & NAME_EXISTS != 0)
            {
                break key;
            }
            let Some(parent) = parent_canonical_key(key) else {
                return SimpleAbsent::Fallback;
            };
            key = parent;
        };
        let Some(wildcard_len) = closest_encloser
            .len()
            .checked_add(2)
            .filter(|len| *len <= 255)
        else {
            return SimpleAbsent::Fallback;
        };
        let mut wildcard = [0u8; 255];
        wildcard[0] = 1;
        wildcard[1] = b'*';
        wildcard[2..wildcard_len].copy_from_slice(closest_encloser);
        match self.records_for_key(&wildcard[..wildcard_len]) {
            Some(records) => SimpleAbsent::Wildcard(records),
            None => SimpleAbsent::NxDomain,
        }
    }

    /// Addresses of names the answer points at (NS, MX, SRV, SVCB, HTTPS) go in the additional
    /// section, each target once. A root SVCB target means the record's own owner name.
    fn target_glue(&self, recs: &[Record]) -> Vec<Record> {
        let mut out = Vec::new();
        let mut seen_targets = std::collections::HashSet::new();
        for r in recs {
            let (target, binding_type) = match &r.rdata {
                RData::Ns(n) | RData::Mx { exchange: n, .. } => (Some(n), None),
                RData::Srv { target, .. } => (Some(target), None),
                RData::Svcb { target, .. } | RData::Https { target, .. } => (
                    Some(if target.is_root() { &r.name } else { target }),
                    Some(r.rtype),
                ),
                _ => (None, None),
            };
            if let Some(t) = target {
                let target_key = (t.canonical_key(), binding_type.map(|rtype| rtype.0));
                if !seen_targets.insert(target_key) {
                    continue;
                }
                if self.delegation_for(t).is_none() {
                    out.extend(self.glue(t));
                    if !t.eq_ignore_case(&r.name) {
                        if let Some(records) = self.owner(t) {
                            if let Some(rtype) = binding_type {
                                out.extend(self.of_type(records, rtype, t));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Only for names in this zone.
    fn glue(&self, name: &Name) -> Vec<Record> {
        let mut out = Vec::new();
        if let Some(recs) = self.owner(name) {
            out.extend(self.of_type(recs, RecordType::A, name));
            out.extend(self.of_type(recs, RecordType::AAAA, name));
        }
        out
    }
}

/// Finds the zone with the longest matching suffix.
#[derive(Default)]
pub struct ZoneStore {
    zones: Vec<Zone>,
    index: HashMap<Vec<u8>, usize>,
}

impl ZoneStore {
    pub fn new() -> Self {
        ZoneStore {
            zones: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Replaces a zone with the same origin.
    pub fn add(&mut self, zone: Zone) {
        let key = zone.origin.canonical_key();
        if let Some(index) = self.index.get(&key).copied() {
            self.zones[index] = zone;
        } else {
            self.index.insert(key, self.zones.len());
            self.zones.push(zone);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn zones(&self) -> &[Zone] {
        &self.zones
    }

    /// For paths that name the apex, such as transfer requests.
    pub fn zone_exact(&self, origin: &Name) -> Option<&Zone> {
        let mut storage = [0u8; 255];
        let key = origin.canonical_key_into(&mut storage)?;
        self.index.get(key).and_then(|index| self.zones.get(*index))
    }

    /// Deepest zone containing the name.
    pub fn zone_for(&self, qname: &Name) -> Option<&Zone> {
        let mut storage = [0u8; 255];
        self.zone_for_key(qname.canonical_key_into(&mut storage)?)
    }

    /// Longest suffix wins; picking a shorter one would let the parent answer names of a child
    /// zone.
    fn zone_for_key(&self, mut key: &[u8]) -> Option<&Zone> {
        loop {
            if let Some(index) = self.index.get(key) {
                return self.zones.get(*index);
            }
            key = parent_canonical_key(key)?;
        }
    }

    pub fn query(&self, qname: &Name, qtype: RecordType) -> Option<Response> {
        self.zone_for(qname).map(|z| z.query(qname, qtype))
    }

    /// Writes the answer straight to the wire without assembling a response. Only A and AAAA
    /// answers and absence answers from flat zones take this path; anything else returns false for
    /// the structured path.
    ///
    /// Must fail closed: EDNS options, additional records, delegation, DNSSEC, or any feature that
    /// changes the answer must keep a query off this path. These checks and the caller's fast-path
    /// gate hold that line together. Returns true only when it wrote a response; on false the
    /// buffer is untouched.
    pub fn write_simple_response(
        &self,
        canonical_qname: &[u8],
        request: &SimpleRequest<'_>,
        out: &mut Writer,
    ) -> bool {
        if !out.buf.is_empty()
            || out.is_failed()
            || !matches!(request.qtype, RecordType::A | RecordType::AAAA)
        {
            return false;
        }
        let Some(zone) = self.zone_for_key(canonical_qname) else {
            return false;
        };
        if zone.has_delegations {
            return false;
        }
        let Some(records) = zone.records_for_key(canonical_qname) else {
            return match zone.simple_absent_for_key(canonical_qname) {
                SimpleAbsent::NxDomain => Self::write_negative_response(zone, request, 3, out),
                SimpleAbsent::NoData => Self::write_negative_response(zone, request, 0, out),
                SimpleAbsent::Wildcard(records) => {
                    Self::write_address_response(zone, records, request, out)
                }
                SimpleAbsent::Dname(record) => {
                    Self::write_external_dname_response(zone, record, canonical_qname, request, out)
                }
                SimpleAbsent::Fallback => false,
            };
        };
        Self::write_address_response(zone, records, request, out)
    }

    /// RFC 6891 requires an OPT in the response when the request had one. Queries on this path
    /// carry no options and DO is off, so only the UDP size goes in, and it is this server's value,
    /// not the request's. The caller must have set ARCOUNT to 1, or parsers reject the message.
    fn push_empty_opt(out: &mut Writer, udp_payload: u16) {
        out.push_u8(0);
        out.push_u16(RecordType::OPT.0);
        out.push_u16(udp_payload);
        out.push_u32(0);
        out.push_u16(0);
    }

    /// Echoes the question name as received, not normalized: changing case makes clients using 0x20
    /// encoding drop the answer.
    fn write_question_prologue(
        out: &mut Writer,
        request: &SimpleRequest<'_>,
        flags: u16,
        answer_count: u16,
        authority_count: u16,
    ) {
        let qname_end = 12 + request.original_qname.len();
        let Some(prologue) = out.reserve_block(qname_end + 4) else {
            return;
        };
        prologue[0..2].copy_from_slice(&request.id.to_be_bytes());
        prologue[2..4].copy_from_slice(&flags.to_be_bytes());
        prologue[4..6].copy_from_slice(&1u16.to_be_bytes());
        prologue[6..8].copy_from_slice(&answer_count.to_be_bytes());
        prologue[8..10].copy_from_slice(&authority_count.to_be_bytes());
        prologue[10..12].copy_from_slice(&u16::from(request.edns.is_some()).to_be_bytes());
        prologue[12..qname_end].copy_from_slice(request.original_qname);
        prologue[qname_end..qname_end + 2].copy_from_slice(&request.qtype.0.to_be_bytes());
        prologue[qname_end + 2..qname_end + 4].copy_from_slice(&DnsClass::IN.0.to_be_bytes());
    }

    /// Writes an A or AAAA answer to the wire. The owner is one compression pointer to the
    /// question, which always sits at offset 12. On failure it clears the buffer and returns false;
    /// a half-written answer must not remain.
    fn write_address_response(
        zone: &Zone,
        records: &[StoredRecord],
        request: &SimpleRequest<'_>,
        out: &mut Writer,
    ) -> bool {
        let qtype = request.qtype;
        let records = stored_rrset(records, qtype);
        let Ok(answer_count) = u16::try_from(records.len()) else {
            return false;
        };
        if answer_count == 0 {
            return false;
        }

        let flags = 0x8000 | 0x0400 | (request.request_flags & 0x0190);
        Self::write_question_prologue(out, request, flags, answer_count, 0);

        // Every answer in one RRset has the same length, owner, type, class, and rdlength.
        // Reserving once and writing fixed-size records removes a small memcpy call per record;
        // matching on qtype makes the length a compile-time constant.
        let written = match qtype {
            RecordType::A => Self::fill_address_block::<{ 12 + 4 }>(
                out,
                records,
                answer_count,
                qtype,
                4,
                |record, answer| {
                    debug_assert_eq!(record.tag(), STORED_TAG_A);
                    answer[12..16].copy_from_slice(&record.payload.to_be_bytes());
                    true
                },
            ),
            RecordType::AAAA => Self::fill_address_block::<{ 12 + 16 }>(
                out,
                records,
                answer_count,
                qtype,
                16,
                |record, answer| {
                    debug_assert_eq!(record.tag(), STORED_TAG_AAAA);
                    let Some(address) = zone.aaaa_arena.get(record.payload as usize) else {
                        return false;
                    };
                    answer[12..28].copy_from_slice(&address.octets());
                    true
                },
            ),
            _ => false,
        };
        if let Some(udp_payload) = request.edns {
            Self::push_empty_opt(out, udp_payload);
        }
        if !written || out.is_failed() {
            out.clear();
            return false;
        }
        true
    }

    /// Writes equal-size answer records into reserved space. Only TTL and rdata vary per record, so
    /// the rest of the header is built once outside the loop. `LEN` is one record's wire length and
    /// must be a constant so the writes unroll; `fill` writes each rdata and returns false when a
    /// record cannot be written. Returns true when all were written; on false the caller must clear
    /// the buffer.
    ///
    /// LEN must equal 12 plus rdata_len; otherwise rdlength silently disagrees with the rdata.
    fn fill_address_block<const LEN: usize>(
        out: &mut Writer,
        records: &[StoredRecord],
        answer_count: u16,
        qtype: RecordType,
        rdata_len: u16,
        fill: impl Fn(&StoredRecord, &mut [u8; LEN]) -> bool,
    ) -> bool {
        debug_assert_eq!(LEN, 12 + usize::from(rdata_len));
        let Some(block) = usize::from(answer_count).checked_mul(LEN) else {
            return false;
        };
        let mut answer = [0u8; LEN];
        answer[0..2].copy_from_slice(&0xc00cu16.to_be_bytes());
        answer[2..4].copy_from_slice(&qtype.0.to_be_bytes());
        answer[4..6].copy_from_slice(&DnsClass::IN.0.to_be_bytes());
        answer[10..12].copy_from_slice(&rdata_len.to_be_bytes());
        let Some(destination) = out.reserve_block(block) else {
            return false;
        };
        let mut offset = 0usize;
        for record in records {
            answer[6..10].copy_from_slice(&record.ttl().to_be_bytes());
            if !fill(record, &mut answer) {
                return false;
            }
            let Some(slot) = destination.get_mut(offset..offset + LEN) else {
                return false;
            };
            slot.copy_from_slice(&answer);
            offset += LEN;
        }
        offset == block
    }

    /// Writes NXDOMAIN or NODATA with the SOA in the authority section. Names are written
    /// uncompressed; this path builds no compression table.
    fn write_negative_response(
        zone: &Zone,
        request: &SimpleRequest<'_>,
        rcode: u16,
        out: &mut Writer,
    ) -> bool {
        let flags = 0x8000 | 0x0400 | (request.request_flags & 0x0190) | rcode;
        Self::write_question_prologue(out, request, flags, 0, 1);
        out.push_bytes(zone.origin.as_uncompressed_wire());
        out.push_u16(RecordType::SOA.0);
        out.push_u16(DnsClass::IN.0);
        out.push_u32(zone.soa_ttl.min(zone.soa.minimum));
        let rdlen = out.placeholder_u16();
        out.push_bytes(zone.soa.mname.as_uncompressed_wire());
        out.push_bytes(zone.soa.rname.as_uncompressed_wire());
        out.push_u32(zone.soa.serial);
        out.push_u32(zone.soa.refresh);
        out.push_u32(zone.soa.retry);
        out.push_u32(zone.soa.expire);
        out.push_u32(zone.soa.minimum);
        out.backpatch_len(rdlen);
        if let Some(udp_payload) = request.edns {
            Self::push_empty_opt(out, udp_payload);
        }
        if out.is_failed() {
            out.clear();
            return false;
        }
        true
    }

    /// Writes a DNAME answer whose target lies outside the zone. The synthesized CNAME target is
    /// the query name's leading labels plus the DNAME target; the leading part is already in the
    /// question, so a compression pointer covers it and only the rest is written.
    ///
    /// Not used when the target is in the zone, which needs further chasing on the structured path,
    /// or when the query name's case differs, since the pointed-to bytes are the original name and
    /// would change the result.
    #[allow(clippy::too_many_arguments)]
    fn write_external_dname_response(
        zone: &Zone,
        record: &Record,
        canonical_qname: &[u8],
        request: &SimpleRequest<'_>,
        out: &mut Writer,
    ) -> bool {
        let original_qname = request.original_qname;
        let RData::Dname(target) = &record.rdata else {
            return false;
        };
        if zone.contains(target) || canonical_qname.len() != original_qname.len() {
            return false;
        }
        let mut owner_storage = [0u8; 255];
        let Some(owner_key) = record.name.canonical_key_into(&mut owner_storage) else {
            return false;
        };
        let Some(prefix_len) = canonical_qname.len().checked_sub(owner_key.len()) else {
            return false;
        };
        if canonical_qname.get(prefix_len..) != Some(owner_key) {
            return false;
        }
        let target_wire = target.as_uncompressed_wire();
        if prefix_len
            .checked_add(target_wire.len())
            .is_none_or(|len| len > 255)
        {
            return false;
        }
        let Some(owner_offset) = 12usize
            .checked_add(prefix_len)
            .filter(|offset| *offset <= 0x3fff)
        else {
            return false;
        };

        out.push_u16(request.id);
        out.push_u16(0x8000 | 0x0400 | (request.request_flags & 0x0190));
        out.push_u16(1);
        out.push_u16(2);
        out.push_u16(0);
        out.push_u16(u16::from(request.edns.is_some()));
        out.push_bytes(original_qname);
        out.push_u16(request.qtype.0);
        out.push_u16(DnsClass::IN.0);

        out.push_u16(0xc000 | owner_offset as u16);
        out.push_u16(RecordType::DNAME.0);
        out.push_u16(DnsClass::IN.0);
        out.push_u32(record.ttl);
        let dname_len = out.placeholder_u16();
        out.push_bytes(target_wire);
        out.backpatch_len(dname_len);

        out.push_u16(0xc00c);
        out.push_u16(RecordType::CNAME.0);
        out.push_u16(DnsClass::IN.0);
        out.push_u32(record.ttl);
        let cname_len = out.placeholder_u16();
        out.push_bytes(&original_qname[..prefix_len]);
        out.push_bytes(target_wire);
        out.backpatch_len(cname_len);
        if let Some(udp_payload) = request.edns {
            Self::push_empty_opt(out, udp_payload);
        }
        if out.is_failed() {
            out.clear();
            return false;
        }
        true
    }
}

/// Request values the fast path needs to build a response. The five always travel together; as
/// separate arguments, dropping one would still compile and silently send an answer that does not
/// match the query.
pub struct SimpleRequest<'a> {
    /// As received, to echo its case.
    pub original_qname: &'a [u8],
    pub qtype: RecordType,
    pub id: u16,
    pub request_flags: u16,
    /// UDP size for the response OPT; None means no OPT.
    pub edns: Option<u16>,
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parameters are written by number, not name, so keys this server does not interpret survive the
/// round trip.
fn svcb_text(priority: u16, target: &Name, params: &[(u16, Box<[u8]>)]) -> String {
    let mut s = format!("{priority} {}.", target.to_ascii_lower());
    for (key, val) in params {
        s.push(' ');
        s.push_str(&svcb_param_text(*key, val));
    }
    s
}

/// One SvcParam in RFC 9460 presentation format, matching what the parser reads: dynamic update
/// results are written to a file and read back. Values with unknown meaning are written as keyNNNNN
/// with a character-string, preserving the original bytes.
fn svcb_param_text(key: u16, wire: &[u8]) -> String {
    fn prefixed_list(wire: &[u8]) -> Option<String> {
        let mut items = Vec::new();
        let mut i = 0;
        while i < wire.len() {
            let len = *wire.get(i)? as usize;
            let end = i.checked_add(1)?.checked_add(len)?;
            let item = wire.get(i + 1..end)?;
            items.push(
                String::from_utf8(item.to_vec())
                    .ok()?
                    .replace('\\', "\\\\")
                    .replace(',', "\\,"),
            );
            i = end;
        }
        (!items.is_empty()).then(|| items.join(","))
    }
    fn addresses(wire: &[u8], width: usize, render: impl Fn(&[u8]) -> String) -> Option<String> {
        if wire.is_empty() || wire.len() % width != 0 {
            return None;
        }
        Some(wire.chunks(width).map(render).collect::<Vec<_>>().join(","))
    }

    let rendered = match key {
        0 if wire.len() % 2 == 0 && !wire.is_empty() => Some(
            wire.chunks(2)
                .map(|pair| svcb_key_name(u16::from_be_bytes([pair[0], pair[1]])))
                .collect::<Vec<_>>()
                .join(","),
        ),
        1 => prefixed_list(wire),
        2 if wire.is_empty() => return "no-default-alpn".to_string(),
        3 if wire.len() == 2 => Some(u16::from_be_bytes([wire[0], wire[1]]).to_string()),
        4 => addresses(wire, 4, |o| {
            std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string()
        }),
        5 if !wire.is_empty() => Some(base64_encode(wire)),
        6 => addresses(wire, 16, |o| {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(o);
            std::net::Ipv6Addr::from(octets).to_string()
        }),
        _ => None,
    };
    match rendered {
        Some(text) => format!("{}={}", svcb_key_name(key), text),
        None if wire.is_empty() => svcb_key_name(key),
        None => format!("{}={}", svcb_key_name(key), escape_char_string(wire)),
    }
}

/// keyNNNNN for keys not in the registry.
fn svcb_key_name(key: u16) -> String {
    match key {
        0 => "mandatory".to_string(),
        1 => "alpn".to_string(),
        2 => "no-default-alpn".to_string(),
        3 => "port".to_string(),
        4 => "ipv4hint".to_string(),
        5 => "ech".to_string(),
        6 => "ipv6hint".to_string(),
        other => format!("key{other}"),
    }
}

/// The ech value uses this form.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Quotes and escapes for master files: backslash before quotes and backslashes, three-digit
/// decimal escapes for other non-printing bytes and comment or parenthesis characters. Left as is,
/// they would split tokens when read back.
pub(crate) fn escape_char_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 2);
    s.push('"');
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(b as char);
            }
            0x21..=0x7e if b != b';' && b != b'(' && b != b')' => s.push(b as char),
            _ => {
                s.push('\\');
                let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:03}"));
            }
        }
    }
    s.push('"');
    s
}

/// Owner and name fields are absolute names ending in a dot; relative names would read back as
/// different names depending on the origin. Types this server does not interpret are written in
/// generic form, so the round trip is lossless.
pub fn record_to_master_line(r: &Record) -> String {
    let owner = format!("{}.", r.name.to_master_lower());
    let (ty, rd) = match &r.rdata {
        RData::A(ip) => ("A".to_string(), ip.to_string()),
        RData::Aaaa(ip) => ("AAAA".to_string(), ip.to_string()),
        RData::Ns(n) => ("NS".to_string(), format!("{}.", n.to_ascii_lower())),
        RData::Cname(n) => ("CNAME".to_string(), format!("{}.", n.to_ascii_lower())),
        RData::Dname(n) => ("DNAME".to_string(), format!("{}.", n.to_ascii_lower())),
        RData::Ptr(n) => ("PTR".to_string(), format!("{}.", n.to_ascii_lower())),
        RData::Mx {
            preference,
            exchange,
        } => (
            "MX".to_string(),
            format!("{preference} {}.", exchange.to_ascii_lower()),
        ),
        RData::Txt(parts) => (
            "TXT".to_string(),
            parts
                .iter()
                .map(|p| escape_char_string(p))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        RData::Soa(s) => (
            "SOA".to_string(),
            format!(
                "{}. {}. {} {} {} {} {}",
                s.mname.to_ascii_lower(),
                s.rname.to_ascii_lower(),
                s.serial,
                s.refresh,
                s.retry,
                s.expire,
                s.minimum
            ),
        ),
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => (
            "SRV".to_string(),
            format!("{priority} {weight} {port} {}.", target.to_ascii_lower()),
        ),
        RData::Caa { flags, tag, value } => (
            "CAA".to_string(),
            format!(
                "{flags} {} {}",
                escape_char_string(tag),
                escape_char_string(value)
            ),
        ),
        RData::Tlsa {
            usage,
            selector,
            matching,
            data,
        } => (
            "TLSA".to_string(),
            format!("{usage} {selector} {matching} {}", hex_str(data)),
        ),
        RData::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        } => (
            "SSHFP".to_string(),
            format!("{algorithm} {fp_type} {}", hex_str(fingerprint)),
        ),
        RData::Naptr(naptr) => (
            "NAPTR".to_string(),
            format!(
                "{} {} {} {} {} {}.",
                naptr.order,
                naptr.preference,
                escape_char_string(&naptr.flags),
                escape_char_string(&naptr.services),
                escape_char_string(&naptr.regexp),
                naptr.replacement.to_ascii_lower()
            ),
        ),
        RData::Uri {
            priority,
            weight,
            target,
        } => (
            "URI".to_string(),
            format!("{priority} {weight} {}", escape_char_string(target)),
        ),
        RData::Svcb {
            priority,
            target,
            params,
        } => ("SVCB".to_string(), svcb_text(*priority, target, params)),
        RData::Https {
            priority,
            target,
            params,
        } => ("HTTPS".to_string(), svcb_text(*priority, target, params)),
        RData::Unknown(t, raw) => (
            format!("TYPE{t}"),
            format!("\\# {} {}", raw.len(), hex_str(raw)),
        ),
    };
    format!("{owner} {} IN {} {}\n", r.ttl, ty, rd)
}

/// Catches violations across the whole zone at load, so the query path never has to handle them:
/// CNAME beside other data leaves the answer undefined, two DNAMEs send one name two ways, and
/// mixed NSEC3 parameters make validators reject denial proofs. Any violation fails the load, so a
/// partly broken zone is never served.
fn validate_zone_records(
    origin: &Name,
    records: &[Record],
    index: &OwnerIndex,
) -> Result<(), String> {
    let mut nsec3_parameters: Option<(u8, u16, Vec<u8>)> = None;
    for (_, owner_records) in full_record_groups(records, index) {
        if owner_records
            .iter()
            .any(|record| record.class != DnsClass::IN)
        {
            return Err(
                "Authoritative records in classes other than IN are not supported".to_string(),
            );
        }

        let cnames: Vec<&Record> = owner_records
            .iter()
            .filter(|record| record.rtype == RecordType::CNAME)
            .collect();
        if let Some(first) = cnames.first() {
            if cnames
                .iter()
                .any(|record| record.rdata != first.rdata || record.ttl != first.ttl)
            {
                return Err(format!(
                    "Conflicting CNAME targets: {}",
                    first.name.to_ascii_lower()
                ));
            }
            if owner_records.iter().any(|record| {
                !matches!(
                    record.rtype,
                    RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
                )
            }) {
                return Err(format!(
                    "CNAME coexists with other data: {}",
                    first.name.to_ascii_lower()
                ));
            }
        }

        let dnames: Vec<&Record> = owner_records
            .iter()
            .filter(|record| record.rtype == RecordType::DNAME)
            .collect();
        if let Some(first) = dnames.first() {
            if dnames.len() != 1 {
                return Err(format!(
                    "Multiple DNAME records: {}",
                    first.name.to_ascii_lower()
                ));
            }
            if !first.name.eq_ignore_case(origin)
                && owner_records
                    .iter()
                    .any(|record| record.rtype == RecordType::NS)
            {
                return Err(format!(
                    "Non-apex DNAME coexists with NS: {}",
                    first.name.to_ascii_lower()
                ));
            }
        }

        for record in owner_records
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
        {
            let metadata = parse_nsec3_metadata(record)?;
            if metadata.hash_algorithm != 1 {
                return Err(format!(
                    "Unsupported NSEC3 hash algorithm {}: {}",
                    metadata.hash_algorithm,
                    record.name.to_ascii_lower()
                ));
            }
            if metadata.flags & !1 != 0 {
                return Err(format!(
                    "Invalid NSEC3 flags: {}",
                    record.name.to_ascii_lower()
                ));
            }
            if metadata.iterations != 0 {
                return Err(format!(
                    "NSEC3 iterations must be 0 per RFC 9276: {}",
                    record.name.to_ascii_lower()
                ));
            }
            if record.name.num_labels() != origin.num_labels() + 1
                || !record
                    .name
                    .suffix(origin.num_labels())
                    .eq_ignore_case(origin)
                || !record
                    .name
                    .labels()
                    .first()
                    .is_some_and(is_sha1_nsec3_owner)
            {
                return Err(format!(
                    "Invalid NSEC3 owner name: {}",
                    record.name.to_ascii_lower()
                ));
            }

            let parameters = (
                metadata.hash_algorithm,
                metadata.iterations,
                metadata.salt.to_vec(),
            );
            if nsec3_parameters
                .as_ref()
                .is_some_and(|expected| expected != &parameters)
            {
                return Err(
                    "NSEC3 hash algorithm, iterations, or salt differ within one zone".to_string(),
                );
            }
            nsec3_parameters.get_or_insert(parameters);
        }
    }

    let dname_owners: HashSet<Vec<u8>> = full_record_groups(records, index)
        .filter(|(_, owner_records)| {
            owner_records
                .iter()
                .any(|record| record.rtype == RecordType::DNAME)
        })
        .map(|(_, owner_records)| owner_records[0].name.canonical_key())
        .collect();
    for (_, owner_records) in full_record_groups(records, index) {
        let owner = &owner_records[0].name;
        for labels in origin.num_labels()..owner.num_labels() {
            let ancestor = owner.suffix(labels);
            if dname_owners.contains(&ancestor.canonical_key()) {
                return Err(format!(
                    "Data exists below a DNAME: {}",
                    owner.to_ascii_lower()
                ));
            }
        }
    }

    let mut cname_states = HashMap::<Vec<u8>, u8>::new();
    for (owner, owner_records) in full_record_groups(records, index) {
        if !owner_records
            .iter()
            .any(|record| record.rtype == RecordType::CNAME)
        {
            continue;
        }
        if cname_states.get(owner).copied() == Some(2) {
            continue;
        }

        let mut current = owner.to_vec();
        let mut path = Vec::new();
        loop {
            match cname_states.get(&current).copied() {
                Some(1) => {
                    let owner = full_records_for_key(records, index, &current)
                        .and_then(|owner_records| owner_records.first())
                        .map(|record| record.name.to_ascii_lower())
                        .unwrap_or_else(|| "<binary-name>".to_string());
                    return Err(format!("CNAME loop: {owner}"));
                }
                Some(2) => break,
                _ => {}
            }

            cname_states.insert(current.clone(), 1);
            path.push(current.clone());
            let Some(next_records) = full_records_for_key(records, index, &current) else {
                break;
            };
            let Some(RData::Cname(next)) = next_records
                .iter()
                .find_map(|record| (record.rtype == RecordType::CNAME).then_some(&record.rdata))
            else {
                break;
            };
            current = next.canonical_key();
        }

        for name in path {
            cname_states.insert(name, 2);
        }
    }
    Ok(())
}

/// The NSEC3 parameters validation needs.
struct Nsec3Metadata<'a> {
    hash_algorithm: u8,
    /// Only the opt-out bit may be set.
    flags: u8,
    iterations: u16,
    salt: &'a [u8],
}

/// Follows each length field with bounds checks. A next-hash length other than SHA-1's 20 is not a
/// form this server handles.
fn parse_nsec3_metadata(record: &Record) -> Result<Nsec3Metadata<'_>, String> {
    let RData::Unknown(50, raw) = &record.rdata else {
        return Err(format!(
            "Malformed NSEC3 RDATA: {}",
            record.name.to_ascii_lower()
        ));
    };
    if raw.len() < 6 {
        return Err(format!(
            "Truncated NSEC3 RDATA: {}",
            record.name.to_ascii_lower()
        ));
    }

    let salt_len = usize::from(raw[4]);
    let hash_len_offset = 5usize
        .checked_add(salt_len)
        .filter(|offset| *offset < raw.len())
        .ok_or_else(|| format!("Truncated NSEC3 salt: {}", record.name.to_ascii_lower()))?;
    let hash_len = usize::from(raw[hash_len_offset]);
    if hash_len != 20 {
        return Err(format!(
            "NSEC3 SHA-1 next hash length must be 20: {}",
            record.name.to_ascii_lower()
        ));
    }
    let bitmap_offset = hash_len_offset
        .checked_add(1 + hash_len)
        .filter(|offset| *offset <= raw.len())
        .ok_or_else(|| {
            format!(
                "Truncated NSEC3 next hash: {}",
                record.name.to_ascii_lower()
            )
        })?;
    if !valid_type_bitmaps(&raw[bitmap_offset..]) {
        return Err(format!(
            "Invalid NSEC3 type bitmap: {}",
            record.name.to_ascii_lower()
        ));
    }

    Ok(Nsec3Metadata {
        hash_algorithm: raw[0],
        flags: raw[1],
        iterations: u16::from_be_bytes([raw[2], raw[3]]),
        salt: &raw[5..hash_len_offset],
    })
}

/// Canonical form only: strictly increasing window numbers, block lengths in 1..=32, and a nonzero
/// last octet. If one type set had several encodings, signature validation would disagree.
fn valid_type_bitmaps(raw: &[u8]) -> bool {
    let mut offset = 0;
    let mut previous_window = None;
    while offset < raw.len() {
        if raw.len() - offset < 2 {
            return false;
        }
        let window = raw[offset];
        let len = usize::from(raw[offset + 1]);
        offset += 2;
        if !(1..=32).contains(&len)
            || raw.len() - offset < len
            || previous_window.is_some_and(|previous| window <= previous)
            || raw[offset + len - 1] == 0
        {
            return false;
        }
        previous_window = Some(window);
        offset += len;
    }
    true
}

/// 32 base32hex characters.
fn is_sha1_nsec3_owner(label: &[u8]) -> bool {
    label.len() == 32
        && label
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte.to_ascii_uppercase(), b'A'..=b'V'))
}

fn is_subdomain_or_eq(name: &Name, zone: &Name) -> bool {
    if name.num_labels() < zone.num_labels() {
        return false;
    }
    name.suffix(zone.num_labels()).eq_ignore_case(zone)
}

/// Canonical name order, comparing labels from the right. This order puts siblings under one parent
/// next to each other, which both the denial chain and owner grouping rely on.
fn dnssec_name_cmp(left: &Name, right: &Name) -> Ordering {
    for (left_label, right_label) in left.labels().iter().rev().zip(right.labels().iter().rev()) {
        let order = left_label
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(right_label.iter().map(u8::to_ascii_lowercase));
        if order != Ordering::Equal {
            return order;
        }
    }
    left.num_labels().cmp(&right.num_labels())
}

/// Cannot exceed the length limit, since the parent is already a name in the zone.
fn prepend_wildcard(parent: &Name) -> Name {
    let mut labels = Vec::with_capacity(parent.labels().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend(parent.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).expect("The wildcard name is valid")
}

/// Rewrites only the answer section; records of other names added while chasing a CNAME stay as
/// they are.
fn synthesize_owner(mut resp: Response, qname: &Name, wildcard_source: &Name) -> Response {
    for record in &mut resp.answers {
        if record.name.eq_ignore_case(wildcard_source) {
            record.name = qname.clone();
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[test]
    /// Kept duplicates inflate answers, and in signed zones the signed set differs from the sent
    /// set. Records differing only in TTL are not duplicates but get their TTLs aligned, so they
    /// are checked too.
    fn a_loaded_zone_keeps_only_one_of_two_identical_records() {
        let zone = crate::parse::parse_zone(
            concat!(
                "$TTL 3600\n",
                "@ IN SOA ns.dup.test. hostmaster.dup.test. 1 7200 3600 1209600 300\n",
                "@ IN NS ns.dup.test.\n",
                "same IN A 192.0.2.77\n",
                "same IN A 192.0.2.77\n",
                "same IN A 192.0.2.78\n",
                "ttl 100 IN A 192.0.2.79\n",
                "ttl 900 IN A 192.0.2.79\n",
                "txt IN TXT \"one\"\n",
                "txt IN TXT \"one\"\n",
            ),
            "dup.test",
        )
        .expect("영역 로드");

        let rdata = |name: &str, rtype: RecordType| -> Vec<RData> {
            zone.query(&Name::from_str(name).unwrap(), rtype)
                .answers
                .iter()
                .map(|record| record.rdata.clone())
                .collect()
        };

        assert_eq!(
            rdata("same.dup.test", RecordType::A).len(),
            2,
            "완전히 같은 A를 둘 다 내보냈습니다"
        );
        assert_eq!(
            rdata("txt.dup.test", RecordType::TXT).len(),
            1,
            "완전히 같은 TXT를 둘 다 내보냈습니다"
        );
        assert_eq!(
            rdata("ttl.dup.test", RecordType::A).len(),
            1,
            "수명만 달랐던 같은 A는 5.2로 수명이 맞춰진 뒤 하나가 됩니다"
        );
    }

    #[test]
    /// Checked with both A and TXT, since the rule must hold for any type.
    fn a_loaded_zone_obeys_the_ttl_rules() {
        let zone = crate::parse::parse_zone(
            concat!(
                "$TTL 3600\n",
                "@ IN SOA ns.conf.test. hostmaster.conf.test. 1 7200 3600 1209600 300\n",
                "@ IN NS ns.conf.test.\n",
                "mixed 100 IN A 192.0.2.10\n",
                "mixed 900 IN A 192.0.2.11\n",
                "biga 2147483648 IN A 192.0.2.20\n",
                "bigtxt 2147483648 IN TXT \"x\"\n",
            ),
            "conf.test",
        )
        .expect("영역 로드");

        let ttls = |name: &str, rtype: RecordType| -> Vec<u32> {
            zone.query(&Name::from_str(name).unwrap(), rtype)
                .answers
                .iter()
                .map(|record| record.ttl)
                .collect()
        };

        assert_eq!(
            ttls("mixed.conf.test", RecordType::A),
            vec![100, 100],
            "한 RRSet은 가장 작은 수명 하나로 나간다"
        );
        assert_eq!(
            ttls("biga.conf.test", RecordType::A),
            vec![0],
            "상한을 넘는 수명은 0이다"
        );
        assert_eq!(
            ttls("bigtxt.conf.test", RecordType::TXT),
            vec![0],
            "타입이 달라도 같은 규칙을 쓴다"
        );
    }

    /// A larger layout costs memory and cache efficiency for every zone.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn authoritative_storage_layout_stays_compact() {
        assert_eq!(std::mem::size_of::<StoredRecord>(), 8);
        assert_eq!(std::mem::size_of::<RecordRange>(), 8);
        assert_eq!(std::mem::size_of::<OwnerSlot>(), 12);
    }

    #[test]
    /// Over-limit TTLs are clamped, and other types must report their type without reading the
    /// arena.
    fn stored_record_packs_tag_and_value_without_losing_either() {
        let mut aaaa = Vec::new();
        let mut other = Vec::new();
        let owner = Name::from_str("h.bench.test.").unwrap();

        let a = StoredRecord::from_record(
            Record::new(owner.clone(), 3600, RData::A(Ipv4Addr::new(192, 0, 2, 7))),
            &mut aaaa,
            &mut other,
        )
        .unwrap();
        assert_eq!(a.rtype(), RecordType::A);
        assert_eq!(a.ttl(), 3600);
        assert_eq!(
            a.materialize(&owner, &aaaa, &other).unwrap().rdata,
            RData::A(Ipv4Addr::new(192, 0, 2, 7))
        );

        let clamped = StoredRecord::from_record(
            Record::new(owner.clone(), u32::MAX, RData::A(Ipv4Addr::LOCALHOST)),
            &mut aaaa,
            &mut other,
        )
        .unwrap();
        assert_eq!(clamped.ttl(), STORED_TTL_MAX, "상한을 넘는 TTL은 깎는다");
        assert_eq!(clamped.rtype(), RecordType::A);

        let ns = StoredRecord::from_record(
            Record::new(owner.clone(), 300, RData::Ns(owner.clone())),
            &mut aaaa,
            &mut other,
        )
        .unwrap();
        assert_eq!(ns.rtype(), RecordType::NS, "아레나 없이 타입이 나와야 한다");
        assert_eq!(
            ns.full(&other).unwrap().ttl,
            300,
            "TTL은 아레나가 가지고 있다"
        );
        assert!(a.full(&other).is_none(), "압축 변형은 온전한 레코드가 없다");
    }

    #[test]
    /// An RRset slice must not include neighboring types.
    fn owner_records_are_type_sorted_for_single_pass_rrset_writes() {
        let zone = parse_zone(
            concat!(
                "$ORIGIN order.test.\n",
                "$TTL 300\n",
                "@ IN SOA ns admin 1 300 60 3600 60\n",
                "@ IN NS ns\n",
                "ns IN A 192.0.2.53\n",
                "mixed IN TXT \"tail\"\n",
                "mixed IN AAAA 2001:db8::2\n",
                "mixed IN A 192.0.2.2\n",
                "mixed IN AAAA 2001:db8::1\n",
                "mixed IN A 192.0.2.1\n",
            ),
            "order.test",
        )
        .unwrap();
        let owner = n("mixed.order.test");
        let records = zone.owner(&owner).unwrap();
        let types: Vec<u16> = records.iter().map(|record| record.rtype().0).collect();
        assert!(types.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(stored_rrset(records, RecordType::A).len(), 2);
        assert_eq!(stored_rrset(records, RecordType::AAAA).len(), 2);
        assert_eq!(stored_rrset(records, RecordType::TXT).len(), 1);
        assert!(stored_rrset(records, RecordType::MX).is_empty());
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-authority --release bench_sorted_rrset_slice -- --ignored --nocapture"]
    /// Measures two filtering passes against one pass over the type slice.
    fn bench_sorted_rrset_slice() {
        use std::hint::black_box;

        let mut text = String::from(
            "$ORIGIN rrset.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n",
        );
        for index in 1..=254 {
            use std::fmt::Write as _;
            writeln!(text, "many IN A 192.0.2.{index}").unwrap();
        }
        let zone = parse_zone(&text, "rrset.test").unwrap();
        let owner = n("many.rrset.test");
        let records = zone.owner(&owner).unwrap();
        assert_eq!(records.len(), 254);

        const ITERATIONS: usize = 1_000_000;
        for round in 0..6 {
            let run_old = || {
                let started = Instant::now();
                for _ in 0..ITERATIONS {
                    let records = black_box(records);
                    let count = records
                        .iter()
                        .filter(|record| record.rtype() == RecordType::A)
                        .count();
                    let checksum = records
                        .iter()
                        .filter(|record| record.rtype() == RecordType::A)
                        .fold(0u32, |sum, record| sum.wrapping_add(record.payload));
                    black_box((count, checksum));
                }
                started.elapsed()
            };
            let run_new = || {
                let started = Instant::now();
                for _ in 0..ITERATIONS {
                    let rrset = stored_rrset(black_box(records), RecordType::A);
                    let checksum = rrset
                        .iter()
                        .fold(0u32, |sum, record| sum.wrapping_add(record.payload));
                    black_box((rrset.len(), checksum));
                }
                started.elapsed()
            };
            let (old, new) = if round % 2 == 0 {
                (run_old(), run_new())
            } else {
                let new = run_new();
                (run_old(), new)
            };
            println!(
                "rrset-scan round={} old={:.2} ns/query new={:.2} ns/query ratio={:.2}x",
                round + 1,
                old.as_nanos() as f64 / ITERATIONS as f64,
                new.as_nanos() as f64 / ITERATIONS as f64,
                old.as_nanos() as f64 / new.as_nanos() as f64,
            );
        }
    }

    #[test]
    /// Reserving the header at once must keep the bytes and limit failures exact.
    fn question_prologue_is_byte_exact_and_fails_atomically() {
        let qname = [
            3, b'W', b'W', b'W', 4, b'f', b'a', b's', b't', 4, b't', b'e', b's', b't', 0,
        ];
        let request = SimpleRequest {
            original_qname: &qname,
            qtype: RecordType::AAAA,
            id: 0x1234,
            request_flags: 0,
            edns: Some(1232),
        };
        let flags = 0x8590;
        let total = 12 + qname.len() + 4;
        let mut writer = Writer::with_limit(total);
        ZoneStore::write_question_prologue(&mut writer, &request, flags, 2, 3);

        let mut expected = vec![0x12, 0x34, 0x85, 0x90, 0, 1, 0, 2, 0, 3, 0, 1];
        expected.extend_from_slice(&qname);
        expected.extend_from_slice(&RecordType::AAAA.0.to_be_bytes());
        expected.extend_from_slice(&DnsClass::IN.0.to_be_bytes());
        assert_eq!(writer.buf, expected);
        assert!(!writer.is_failed());

        let mut too_small = Writer::with_limit(total - 1);
        ZoneStore::write_question_prologue(&mut too_small, &request, flags, 2, 3);
        assert!(too_small.is_failed());
        assert!(too_small.buf.is_empty(), "부분 질문 헤더가 남으면 안 된다");
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-authority --release bench_question_prologue_single_reserve -- --ignored --nocapture"]
    /// Measures three appends against one reserve for the question header.
    fn bench_question_prologue_single_reserve() {
        use std::hint::black_box;

        fn old_prologue(
            out: &mut Writer,
            request: &SimpleRequest<'_>,
            flags: u16,
            answer_count: u16,
            authority_count: u16,
        ) {
            let mut header = [0u8; 12];
            header[0..2].copy_from_slice(&request.id.to_be_bytes());
            header[2..4].copy_from_slice(&flags.to_be_bytes());
            header[4..6].copy_from_slice(&1u16.to_be_bytes());
            header[6..8].copy_from_slice(&answer_count.to_be_bytes());
            header[8..10].copy_from_slice(&authority_count.to_be_bytes());
            header[10..12].copy_from_slice(&u16::from(request.edns.is_some()).to_be_bytes());
            out.push_bytes(&header);
            out.push_bytes(request.original_qname);
            let mut tail = [0u8; 4];
            tail[0..2].copy_from_slice(&request.qtype.0.to_be_bytes());
            tail[2..4].copy_from_slice(&DnsClass::IN.0.to_be_bytes());
            out.push_bytes(&tail);
        }

        fn run(request: &SimpleRequest<'_>, iterations: usize, candidate: bool) -> Duration {
            let mut out = Writer::with_limit(1232);
            out.buf.reserve(64);
            let started = Instant::now();
            for _ in 0..iterations {
                out.buf.clear();
                if candidate {
                    ZoneStore::write_question_prologue(&mut out, request, 0x8500, 16, 0);
                } else {
                    old_prologue(&mut out, request, 0x8500, 16, 0);
                }
                black_box(out.buf.as_slice());
            }
            started.elapsed()
        }

        let qname = [
            3, b'w', b'w', b'w', 4, b'f', b'a', b's', b't', 4, b't', b'e', b's', b't', 0,
        ];
        let request = SimpleRequest {
            original_qname: &qname,
            qtype: RecordType::A,
            id: 0x1234,
            request_flags: 0,
            edns: None,
        };
        const ITERATIONS: usize = 4_000_000;
        black_box(run(&request, 100_000, false));
        black_box(run(&request, 100_000, true));
        for round in 0..6 {
            let (old, new) = if round % 2 == 0 {
                (
                    run(&request, ITERATIONS, false),
                    run(&request, ITERATIONS, true),
                )
            } else {
                let new = run(&request, ITERATIONS, true);
                (run(&request, ITERATIONS, false), new)
            };
            println!(
                "question-prologue round={} old={:.2} ns/query new={:.2} ns/query ratio={:.2}x",
                round + 1,
                old.as_nanos() as f64 / ITERATIONS as f64,
                new.as_nanos() as f64 / ITERATIONS as f64,
                old.as_nanos() as f64 / new.as_nanos() as f64,
            );
        }
    }

    /// The hash seed must be cloned too.
    #[test]
    fn cloned_owner_index_preserves_exact_and_missing_lookups() {
        let zone = parse_zone(
            "$ORIGIN clone.test.\n$TTL 300\n@ IN SOA ns hostmaster 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nhost IN A 192.0.2.1\n",
            "clone.test",
        )
        .unwrap()
        .clone();
        let exact = Name::from_str("HOST.CLONE.TEST").unwrap();
        let missing = Name::from_str("missing.clone.test").unwrap();
        assert_eq!(zone.query(&exact, RecordType::A).answers.len(), 1);
        assert_eq!(zone.query(&missing, RecordType::A).rcode, 3);
    }

    #[test]
    fn root_zone_refers_below_tld_delegation() {
        let root_text = "$TTL 3600\n. IN SOA ns.root. host.root. 1 3600 900 604800 3600\n. IN NS ns.root.\nns.root. IN A 127.0.1.1\ntest. IN NS ns.test.\nns.test. IN A 127.0.2.1\n";
        let zone = parse_zone(root_text, ".").unwrap();
        let mut store = ZoneStore::new();
        store.add(zone);
        let r = store.query(&n("a00.z0007.test"), RecordType::A).unwrap();
        assert_eq!(r.rcode, 0, "위임 아래 이름은 SERVFAIL이 아니라 리퍼럴");
        assert!(!r.authoritative, "리퍼럴 AA=0");
        assert!(
            r.authority
                .iter()
                .any(|a| matches!(&a.rdata, RData::Ns(t) if t.eq_ignore_case(&n("ns.test")))),
            "test. NS 리퍼럴"
        );
    }

    #[test]
    fn tld_zone_refers_below_second_level_delegation() {
        let tld_text = "$TTL 3600\ntest. IN SOA ns.test. host.test. 1 3600 900 604800 3600\ntest. IN NS ns.test.\nns.test. IN A 127.0.2.1\nz0007.test. IN NS ns-leaf.test.\nns-leaf.test. IN A 127.0.3.1\n";
        let zone = parse_zone(tld_text, "test").unwrap();
        let mut store = ZoneStore::new();
        store.add(zone);
        let r = store.query(&n("a00.z0007.test"), RecordType::A).unwrap();
        assert_eq!(r.rcode, 0, "위임 아래 이름은 리퍼럴");
        assert!(!r.authoritative);
        assert!(
            r.additional
                .iter()
                .any(|a| matches!(a.rdata, RData::A(ip) if ip == Ipv4Addr::new(127, 0, 3, 1))),
            "ns-leaf 글루"
        );
    }

    #[test]
    fn wildcard_owner_preserves_raw_parent_octets() {
        let parent = Name::from_labels(vec![vec![0xff], b"test".to_vec()]).unwrap();
        let wildcard = prepend_wildcard(&parent);
        let labels: Vec<&[u8]> = wildcard.labels().collect();
        assert_eq!(labels[0], b"*");
        assert_eq!(labels[1], [0xff]);
        assert_eq!(labels[2], b"test");
    }

    const ZONE: &str = r#"
$ORIGIN example.com.
$TTL 3600
@        IN SOA ns1.example.com. admin.example.com. (
                2024010101 7200 3600 1209600 3600 )
@        IN NS   ns1.example.com.
@        IN NS   ns2.example.com.
@        IN A    192.0.2.1
ns1      IN A    192.0.2.10
ns2      IN A    192.0.2.11
www      IN A    192.0.2.2
www      IN AAAA 2001:db8::2
ftp      IN CNAME www
mail     IN MX   10 mailhost
mailhost IN A    192.0.2.3
*.wild   IN A    192.0.2.99
sub      IN NS   ns1.sub.example.com.
sub      IN TYPE43 \# 4 000d0200
ns1.sub  IN A    192.0.2.20
aliascut IN CNAME ns1.sub.example.com.
old      IN DNAME target.example.net.
"#;

    /// Has a delegation, a wildcard, and a DNAME, for comparing the two paths.
    fn zone() -> Zone {
        parse_zone(ZONE, "example.com").unwrap()
    }

    /// A mismatch would make the answer depend on which path a query took.
    #[test]
    fn simple_wire_matches_structured_answers_and_shaped_responses() {
        let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.1\nwww IN A 192.0.2.2\nwww IN AAAA 2001:db8::1\n";
        let mut store = ZoneStore::new();
        store.add(parse_zone(zone_text, "fast.test").unwrap());
        let qname = n("www.fast.test");
        let canonical = qname.canonical_key();
        let original = [
            3, b'W', b'W', b'W', 4, b'f', b'a', b's', b't', 4, b't', b'e', b's', b't', 0,
        ];
        let mut writer = Writer::with_limit(1232);
        assert!(store.write_simple_response(
            &canonical,
            &SimpleRequest {
                original_qname: &original,
                qtype: RecordType::A,
                id: 0x1234,
                request_flags: 0x0100,
                edns: None,
            },
            &mut writer,
        ));
        let direct = onetdns_proto::Message::parse(&writer.buf).unwrap();
        let structured = store.query(&qname, RecordType::A).unwrap();
        assert_eq!(direct.header.id, 0x1234);
        assert!(direct.header.authoritative);
        assert!(direct.header.recursion_desired);
        assert!(!direct.header.recursion_available);
        assert_eq!(direct.answers.len(), structured.answers.len());
        for (direct, structured) in direct.answers.iter().zip(&structured.answers) {
            assert_eq!(direct.rtype, structured.rtype);
            assert_eq!(direct.class, structured.class);
            assert_eq!(direct.ttl, structured.ttl);
            assert_eq!(direct.rdata, structured.rdata);
        }
        assert_eq!(direct.questions[0].name.to_ascii_lower(), "www.fast.test");

        let missing = n("Missing.fast.test");
        writer.clear();
        assert!(store.write_simple_response(
            &missing.canonical_key(),
            &SimpleRequest {
                original_qname: missing.as_uncompressed_wire(),
                qtype: RecordType::A,
                id: 0x2345,
                request_flags: 0x0190,
                edns: None,
            },
            &mut writer,
        ));
        let direct = onetdns_proto::Message::parse(&writer.buf).unwrap();
        let structured = store.query(&missing, RecordType::A).unwrap();
        assert_eq!(direct.header.rcode, 3);
        assert!(direct.header.authoritative);
        assert!(direct.header.recursion_desired);
        assert!(direct.header.recursion_available);
        assert!(direct.header.checking_disabled);
        assert!(direct.answers.is_empty());
        assert_eq!(direct.authorities.len(), 1);
        assert!(direct.authorities[0]
            .name
            .eq_ignore_case(&structured.authority[0].name));
        assert_eq!(direct.authorities[0].rtype, RecordType::SOA);
        assert_eq!(direct.authorities[0].ttl, structured.authority[0].ttl);
        assert_eq!(direct.authorities[0].rdata, structured.authority[0].rdata);

        let mut too_small = Writer::with_limit(40);
        assert!(!store.write_simple_response(
            &missing.canonical_key(),
            &SimpleRequest {
                original_qname: missing.as_uncompressed_wire(),
                qtype: RecordType::A,
                id: 1,
                request_flags: 0,
                edns: None,
            },
            &mut too_small,
        ));
        assert!(too_small.buf.is_empty());

        writer.clear();
        assert!(!store.write_simple_response(
            &canonical,
            &SimpleRequest {
                original_qname: &original,
                qtype: RecordType::MX,
                id: 1,
                request_flags: 0x0080,
                edns: None,
            },
            &mut writer,
        ));
        assert!(writer.buf.is_empty());

        // A large RRset over the limit must roll back fully instead of leaving a half-written
        // answer. The answer block reserves its space at once, so this is decided before the first
        // record is written.
        let mut wide = ZoneStore::new();
        let mut wide_text =
            String::from("$ORIGIN wide.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n");
        for index in 0..64 {
            use std::fmt::Write as _;
            writeln!(wide_text, "many IN A 192.0.2.{}", index + 1).unwrap();
        }
        wide.add(parse_zone(&wide_text, "wide.test").unwrap());
        let wide_name = n("many.wide.test");
        let mut roomy = Writer::with_limit(1232);
        assert!(wide.write_simple_response(
            &wide_name.canonical_key(),
            &SimpleRequest {
                original_qname: wide_name.as_uncompressed_wire(),
                qtype: RecordType::A,
                id: 7,
                request_flags: 0,
                edns: None,
            },
            &mut roomy,
        ));
        let parsed = onetdns_proto::Message::parse(&roomy.buf).unwrap();
        assert_eq!(parsed.answers.len(), 64);
        let structured = wide.query(&wide_name, RecordType::A).unwrap();
        for (direct, structured) in parsed.answers.iter().zip(&structured.answers) {
            assert_eq!(direct.ttl, structured.ttl);
            assert_eq!(direct.rdata, structured.rdata);
        }

        let mut cramped = Writer::with_limit(512);
        assert!(!wide.write_simple_response(
            &wide_name.canonical_key(),
            &SimpleRequest {
                original_qname: wide_name.as_uncompressed_wire(),
                qtype: RecordType::A,
                id: 8,
                request_flags: 0,
                edns: None,
            },
            &mut cramped,
        ));
        assert!(cramped.buf.is_empty());

        let mut delegated = ZoneStore::new();
        delegated.add(zone());
        let delegated_name = n("www.example.com");
        assert!(!delegated.write_simple_response(
            &delegated_name.canonical_key(),
            &SimpleRequest {
                original_qname: &delegated_name.canonical_key(),
                qtype: RecordType::A,
                id: 1,
                request_flags: 0x0080,
                edns: None,
            },
            &mut writer,
        ));
        assert!(writer.buf.is_empty());

        let shaped_zones = [
            (
                "$ORIGIN wild.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n*.branch IN A 192.0.2.1\n",
                "wild.test",
                "missing.branch.wild.test",
            ),
            (
                "$ORIGIN dname.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nold IN DNAME target.example.\n",
                "dname.test",
                "missing.old.dname.test",
            ),
            (
                "$ORIGIN ent.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nleaf.branch IN A 192.0.2.1\n",
                "ent.test",
                "branch.ent.test",
            ),
        ];
        for (zone_text, origin, query) in shaped_zones {
            let mut shaped = ZoneStore::new();
            shaped.add(parse_zone(zone_text, origin).unwrap());
            let query = n(query);
            writer.clear();
            assert!(shaped.write_simple_response(
                &query.canonical_key(),
                &SimpleRequest {
                    original_qname: query.as_uncompressed_wire(),
                    qtype: RecordType::A,
                    id: 1,
                    request_flags: 0,
                    edns: None,
                },
                &mut writer,
            ));
            let direct = Message::parse(&writer.buf).unwrap();
            let structured = shaped.query(&query, RecordType::A).unwrap();
            assert_eq!(direct.header.rcode, u16::from(structured.rcode));
            assert_eq!(direct.answers, structured.answers);
            assert_eq!(direct.authorities, structured.authority);
        }
    }

    /// The fast path must not change zone state; queries must not affect each other.
    #[test]
    fn shaped_zone_direct_wire_is_query_local() {
        let zone_text = "$ORIGIN mixed.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n*.wild IN A 192.0.2.1\nleaf.empty IN A 192.0.2.2\nold IN DNAME target.example.\n";
        let mut store = ZoneStore::new();
        store.add(parse_zone(zone_text, "mixed.test").unwrap());

        for query in ["OuTsIdE.mixed.test", "missing.empty.mixed.test"] {
            let qname = n(query);
            let mut writer = Writer::with_limit(1232);
            assert!(store.write_simple_response(
                &qname.canonical_key(),
                &SimpleRequest {
                    original_qname: qname.as_uncompressed_wire(),
                    qtype: RecordType::A,
                    id: 0x3456,
                    request_flags: 0x0190,
                    edns: None,
                },
                &mut writer,
            ));
            let direct = Message::parse(&writer.buf).unwrap();
            let structured = store.query(&qname, RecordType::A).unwrap();
            assert_eq!(direct.header.rcode, 3, "{query}");
            assert_eq!(direct.header.rcode, u16::from(structured.rcode), "{query}");
            assert_eq!(direct.answers, structured.answers, "{query}");
            assert_eq!(direct.authorities.len(), 1, "{query}");
            assert_eq!(direct.authorities[0], structured.authority[0], "{query}");
            assert_eq!(direct.authorities[0].ttl, 60, "{query}");
        }

        for query in [
            "hit.wild.mixed.test",
            "empty.mixed.test",
            "BeLoW.old.mixed.test",
        ] {
            let qname = n(query);
            let mut writer = Writer::with_limit(1232);
            assert!(store.write_simple_response(
                &qname.canonical_key(),
                &SimpleRequest {
                    original_qname: qname.as_uncompressed_wire(),
                    qtype: RecordType::A,
                    id: 1,
                    request_flags: 0,
                    edns: None,
                },
                &mut writer,
            ));
            let direct = Message::parse(&writer.buf).unwrap();
            let structured = store.query(&qname, RecordType::A).unwrap();
            assert_eq!(direct.header.rcode, u16::from(structured.rcode), "{query}");
            assert_eq!(direct.answers, structured.answers, "{query}");
            assert_eq!(direct.authorities, structured.authority, "{query}");
            if direct.answers.is_empty() {
                assert_eq!(direct.authorities[0].ttl, 60, "{query}");
            } else {
                assert!(direct.answers.iter().all(|record| record.ttl == 300));
            }
        }

        for (zone_text, query) in [
            (
                "$ORIGIN mixed.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n*.alias IN CNAME outside.example.\n",
                "hit.alias.mixed.test",
            ),
            (
                "$ORIGIN mixed.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nold IN DNAME target.mixed.test.\nhost.target IN A 192.0.2.9\n",
                "host.old.mixed.test",
            ),
        ] {
            let mut store = ZoneStore::new();
            store.add(parse_zone(zone_text, "mixed.test").unwrap());
            let qname = n(query);
            let mut writer = Writer::with_limit(1232);
            assert!(!store.write_simple_response(
            &qname.canonical_key(),
            &SimpleRequest {
                original_qname: qname.as_uncompressed_wire(),
                qtype: RecordType::A,
                id: 1,
                request_flags: 0,
                edns: None,
            },
            &mut writer,
        ));
            assert!(writer.buf.is_empty(), "{query}");
        }
    }

    #[test]
    fn master_file_roundtrip() {
        let z = zone();
        let text = z.to_master_file();
        let z2 = parse_zone(&text, "example.com").expect("재파싱");
        assert_eq!(z.soa(), z2.soa(), "SOA 보존");
        assert_eq!(
            z.axfr_records().len(),
            z2.axfr_records().len(),
            "레코드 수 보존"
        );
        for q in [
            "www.example.com",
            "ftp.example.com",
            "mail.example.com",
            "a.wild.example.com",
        ] {
            let r1 = z.query(&n(q), RecordType::A);
            let r2 = z2.query(&n(q), RecordType::A);
            assert_eq!(r1.rcode, r2.rcode, "{q} rcode");
            assert_eq!(r1.answers.len(), r2.answers.len(), "{q} answers");
        }

        let extra = format!("{text}x.example.com. 60 IN TYPE99 \\# 3 abcdef\n");
        let z3 = parse_zone(&extra, "example.com").expect("RFC3597 파싱");
        let r = z3.query(&n("x.example.com"), RecordType(99));
        assert_eq!(r.answers.len(), 1);
        assert_eq!(
            r.answers[0].rdata,
            RData::Unknown(99, vec![0xab, 0xcd, 0xef])
        );

        let z4 = parse_zone(&z3.to_master_file(), "example.com").expect("재직렬화 파싱");
        assert_eq!(
            z4.query(&n("x.example.com"), RecordType(99)).answers.len(),
            1
        );
    }

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /// Every address differs: repeated values would be removed by RFC 2181 duplicate suppression
    /// first, never reach the limit, and the test would measure nothing.
    #[test]
    fn rejects_owner_rrsets_that_cannot_fit_a_dns_message() {
        let mut records = zone().axfr_records();
        let owner = n("oversized.example.com");
        for index in 0..=MAX_OWNER_RECORDS {
            let octets = (index as u32).to_be_bytes();
            records.push(Record::new(
                owner.clone(),
                60,
                RData::A(Ipv4Addr::new(10, octets[1], octets[2], octets[3])),
            ));
        }
        assert!(Zone::from_records(records).is_err());
    }

    #[test]
    fn char_string_roundtrip_is_byte_exact_and_injection_safe() {
        let nasty: Vec<u8> = vec![
            b'a', b'"', b'\\', b'\n', b';', b'(', b')', b' ', 0x00, 0xff, 0x80, b'b',
        ];
        let mut records = zone().axfr_records();
        records.push(Record::new(
            n("evil.example.com"),
            60,
            RData::Txt(vec![nasty.clone(), b"second".to_vec()]),
        ));
        let z = Zone::from_records(records).unwrap();
        let text = z.to_master_file();

        assert!(!text.contains("a\"\\\n"), "원시 개행이 그대로 새면 안 됨");

        let z2 = parse_zone(&text, "example.com").expect("nasty TXT 재파싱");
        let ans = z2.query(&n("evil.example.com"), RecordType::TXT).answers;
        assert_eq!(ans.len(), 1);
        match &ans[0].rdata {
            RData::Txt(parts) => {
                assert_eq!(parts.len(), 2);
                assert_eq!(parts[0], nasty, "첫 character-string 바이트 정확 복원");
                assert_eq!(parts[1], b"second");
            }
            other => panic!("TXT 기대, {other:?}"),
        }
    }

    #[test]
    fn parses_and_roundtrips_caa() {
        let src = "\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
@ IN NS ns1.example.com.
@ IN CAA 0 issue \"letsencrypt.org\"
@ IN CAA 128 iodef \"mailto:sec@example.com\"
";
        let z = parse_zone(src, "example.com").expect("CAA 영역 파싱");
        let r = z.query(&n("example.com"), RecordType::CAA);
        assert_eq!(r.rcode, 0);
        assert_eq!(r.answers.len(), 2);
        let issue = r
            .answers
            .iter()
            .find_map(|a| match &a.rdata {
                RData::Caa { flags, tag, value } if tag.as_ref() == b"issue" => {
                    Some((*flags, value.as_ref()))
                }
                RData::Caa { .. } => None,
                _ => panic!("CAA 기대"),
            })
            .expect("issue 태그 레코드");
        assert_eq!(issue, (0u8, b"letsencrypt.org".as_slice()));

        let z2 = parse_zone(&z.to_master_file(), "example.com").expect("CAA 재파싱");
        assert_eq!(
            z2.query(&n("example.com"), RecordType::CAA).answers.len(),
            2
        );
    }

    #[test]
    fn parses_soa_and_records() {
        let z = zone();
        assert!(z.origin.eq_ignore_case(&n("example.com")));
        assert_eq!(z.soa.serial, 2024010101);
        assert_eq!(z.soa.refresh, 7200);
    }

    #[test]
    fn exact_a_answer_is_authoritative() {
        let r = zone().query(&n("www.example.com"), RecordType::A);
        assert_eq!(r.rcode, 0);
        assert!(r.authoritative);
        assert_eq!(r.answers.len(), 1);
        assert!(matches!(r.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 2)));
    }

    #[test]
    fn nodata_returns_soa_no_answer() {
        let r = zone().query(&n("www.example.com"), RecordType::MX);
        assert_eq!(r.rcode, 0);
        assert!(r.answers.is_empty());
        assert_eq!(r.authority.len(), 1);
        assert!(matches!(r.authority[0].rdata, RData::Soa(_)));
    }

    /// Its TTL sets the negative cache time.
    #[test]
    fn nxdomain_returns_soa() {
        let r = zone().query(&n("nope.example.com"), RecordType::A);
        assert_eq!(r.rcode, 3);
        assert!(r.authoritative);
        assert!(matches!(r.authority[0].rdata, RData::Soa(_)));
    }

    #[test]
    fn cname_is_chased_in_zone() {
        let r = zone().query(&n("ftp.example.com"), RecordType::A);
        assert_eq!(r.rcode, 0);

        assert!(
            matches!(&r.answers[0].rdata, RData::Cname(t) if t.eq_ignore_case(&n("www.example.com")))
        );
        assert!(r
            .answers
            .iter()
            .any(|a| matches!(a.rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,2))));
    }

    #[test]
    /// Merging the endings would send absence as NOERROR and drop the negative SOA, so nothing is
    /// cached negatively and the same query repeats.
    fn a_cname_chain_reports_where_it_stopped() {
        let zone = crate::parse::parse_zone(
            concat!(
                "$TTL 3600
",
                "@ IN SOA ns.chase.test. h.chase.test. 1 7200 3600 1209600 300
",
                "@ IN NS ns.chase.test.
",
                "ns IN A 127.0.0.1
",
                "*.wild IN A 192.0.2.9
",
                "deleg IN NS ns.deleg.chase.test.
",
                "ns.deleg IN A 192.0.2.60
",
                "hastxt IN TXT \"only text\"
",
                "gone IN CNAME nowhere.chase.test.
",
                "notype IN CNAME hastxt.chase.test.
",
                "away IN CNAME outside.example.net.
",
                "below IN CNAME under.deleg.chase.test.
",
                "star IN CNAME deep.wild.chase.test.
",
            ),
            "chase.test",
        )
        .expect("영역 로드");

        let soa_count = |r: &Response| {
            r.authority
                .iter()
                .filter(|record| record.rtype == RecordType::SOA)
                .count()
        };

        let gone = zone.query(&n("gone.chase.test"), RecordType::A);
        assert_eq!(gone.rcode, 3, "대상이 없으면 NXDOMAIN이다");
        assert_eq!(gone.answers.len(), 1, "이미 담은 CNAME은 그대로 둔다");
        assert_eq!(soa_count(&gone), 1, "부정 캐시하려면 SOA가 있어야 한다");

        let notype = zone.query(&n("notype.chase.test"), RecordType::A);
        assert_eq!(notype.rcode, 0, "이름이 있으면 NODATA다");
        assert_eq!(notype.answers.len(), 1);
        assert_eq!(soa_count(&notype), 1, "NODATA도 SOA가 있어야 한다");

        let away = zone.query(&n("away.chase.test"), RecordType::A);
        assert_eq!(away.rcode, 0);
        assert!(
            away.authority.is_empty(),
            "zone 밖은 이 서버가 부재를 증언할 수 없다"
        );

        let below = zone.query(&n("below.chase.test"), RecordType::A);
        assert_eq!(below.rcode, 0);
        assert_eq!(soa_count(&below), 0, "위임은 부정 응답이 아니다");
        assert!(
            below
                .authority
                .iter()
                .any(|record| record.rtype == RecordType::NS),
            "질의자가 이어 갈 위임을 담아야 한다"
        );

        let star = zone.query(&n("star.chase.test"), RecordType::A);
        assert_eq!(star.rcode, 0);
        assert_eq!(star.answers.len(), 2, "와일드카드가 덮으면 답이 나온다");
        assert!(
            star.answers[1]
                .name
                .eq_ignore_case(&n("deep.wild.chase.test")),
            "합성한 답의 소유자는 대상 이름이다"
        );
    }

    #[test]
    /// Dynamic update results are written to a file and read back in this form; a writer and reader
    /// that disagree would change values across one restart.
    fn service_binding_parameters_survive_a_text_round_trip() {
        let source = concat!(
            "$ORIGIN rt.test.
",
            "@ 60 IN SOA ns.rt.test. h.rt.test. 1 60 60 3600 60
",
            "@ 60 IN NS ns.rt.test.
",
            "ns 60 IN A 192.0.2.1
",
            "svc 60 IN HTTPS 1 t.rt.test. mandatory=alpn alpn=h2,h3 no-default-alpn ",
            "port=8443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 ech=AQIDBA== ",
            "key65000=hello
",
            "t 60 IN A 192.0.2.9
",
        );
        let first = parse_zone(source, "rt.test").expect("첫 로드");
        let text = first.to_master_file();
        let second = parse_zone(&text, "rt.test").expect("적어 둔 것을 다시 읽기");

        let params = |zone: &Zone| {
            let answer = zone.query(&n("svc.rt.test"), RecordType::HTTPS);
            match &answer.answers[0].rdata {
                RData::Https { params, .. } => params
                    .iter()
                    .map(|(key, value)| (*key, value.to_vec()))
                    .collect::<Vec<_>>(),
                other => panic!("HTTPS 기대: {other:?}"),
            }
        };
        let before = params(&first);
        assert_eq!(before.len(), 8, "여덟 매개변수가 모두 남아야 합니다");
        assert_eq!(before, params(&second), "왕복하고도 같아야 합니다");
        assert!(
            text.contains("alpn=h2,h3") && text.contains("port=8443"),
            "등록된 키는 이름으로 적어야 합니다: {text}"
        );
    }

    #[test]
    fn wildcard_synthesizes_owner() {
        let r = zone().query(&n("anything.wild.example.com"), RecordType::A);
        assert_eq!(r.rcode, 0);
        assert_eq!(r.answers.len(), 1);
        assert!(
            r.answers[0]
                .name
                .eq_ignore_case(&n("anything.wild.example.com")),
            "owner는 qname으로 합성"
        );
        assert!(matches!(r.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,99)));
    }

    #[test]
    fn empty_nonterminal_is_nodata_and_blocks_parent_wildcard() {
        let source = r#"
$ORIGIN example.
@ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60
@ 60 IN NS ns.example.
ns 60 IN A 192.0.2.1
* 60 IN A 192.0.2.99
leaf.empty 60 IN A 192.0.2.2
"#;
        let zone = parse_zone(source, "example").unwrap();
        let empty = zone.query(&n("empty.example"), RecordType::A);
        assert_eq!(empty.rcode, 0);
        assert!(empty.answers.is_empty());
        assert!(matches!(empty.authority[0].rdata, RData::Soa(_)));

        let wildcard = zone.query(&n("other.example"), RecordType::A);
        assert_eq!(wildcard.answers.len(), 1);
        assert!(
            matches!(wildcard.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 99))
        );
    }

    #[test]
    fn delegation_returns_referral_with_glue() {
        let r = zone().query(&n("host.sub.example.com"), RecordType::A);
        assert_eq!(r.rcode, 0);
        assert!(!r.authoritative, "위임 리퍼럴은 AA=0");
        assert!(r.answers.is_empty());
        assert!(r.authority.iter().any(
            |a| matches!(&a.rdata, RData::Ns(t) if t.eq_ignore_case(&n("ns1.sub.example.com")))
        ));
        assert!(r
            .authority
            .iter()
            .any(|record| record.rtype == RecordType::DS));
        assert!(
            r.additional
                .iter()
                .any(|a| matches!(a.rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,20))),
            "글루 A"
        );
    }

    /// The DS at a cut belongs to the parent.
    #[test]
    fn delegation_cut_serves_parent_ds_authoritatively() {
        let r = zone().query(&n("sub.example.com"), RecordType::DS);
        assert_eq!(r.rcode, 0);
        assert!(r.authoritative);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].rtype, RecordType::DS);
    }

    /// Glue below a delegation is child zone data.
    #[test]
    fn cname_chase_never_promotes_glue_below_delegation_to_answer() {
        let response = zone().query(&n("aliascut.example.com"), RecordType::A);
        assert_eq!(response.rcode, 0);
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(response.answers[0].rdata, RData::Cname(_)));
        assert!(!response
            .answers
            .iter()
            .any(|record| matches!(record.rdata, RData::A(_))));
    }

    #[test]
    fn dname_rewrites_descendants_but_not_the_owner() {
        let z = zone();
        let response = z.query(&n("www.old.example.com"), RecordType::A);
        assert_eq!(response.rcode, 0);
        assert!(response.authoritative);
        assert!(response.answers.iter().any(|record| {
            record.name.eq_ignore_case(&n("old.example.com"))
                && matches!(&record.rdata, RData::Dname(target) if target.eq_ignore_case(&n("target.example.net")))
        }));
        assert!(response.answers.iter().any(|record| {
            record.name.eq_ignore_case(&n("www.old.example.com"))
                && matches!(&record.rdata, RData::Cname(target) if target.eq_ignore_case(&n("www.target.example.net")))
        }));

        let owner = z.query(&n("old.example.com"), RecordType::A);
        assert_eq!(owner.rcode, 0);
        assert!(owner.answers.is_empty());
        assert!(matches!(owner.authority[0].rdata, RData::Soa(_)));
    }

    #[test]
    fn dname_chases_an_in_zone_terminal_rrset() {
        let source = "$ORIGIN example.\n\
            @ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n\
            @ 60 IN NS ns.example.\n\
            ns 60 IN A 192.0.2.1\n\
            old 60 IN DNAME target.example.\n\
            www.target 60 IN A 192.0.2.80\n";
        let zone = parse_zone(source, "example").unwrap();
        let response = zone.query(&n("www.old.example"), RecordType::A);

        assert_eq!(response.rcode, 0);
        assert_eq!(response.answers.len(), 3);
        assert_eq!(response.answers[0].rtype, RecordType::DNAME);
        assert_eq!(response.answers[1].rtype, RecordType::CNAME);
        assert!(matches!(
            response.answers[2].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 80)
        ));
    }

    #[test]
    fn cname_terminal_rrset_contributes_additional_records() {
        let source = "$ORIGIN example.\n\
            @ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n\
            @ 60 IN NS ns.example.\n\
            ns 60 IN A 192.0.2.1\n\
            alias 60 IN CNAME mail.example.\n\
            mail 60 IN MX 10 mx.example.\n\
            mx 60 IN A 192.0.2.25\n";
        let zone = parse_zone(source, "example").unwrap();
        let response = zone.query(&n("alias.example"), RecordType::MX);

        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].rtype, RecordType::CNAME);
        assert_eq!(response.answers[1].rtype, RecordType::MX);
        assert_eq!(response.additional.len(), 1);
        assert!(matches!(
            response.additional[0].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 25)
        ));
    }

    #[test]
    fn zone_rejects_alias_conflicts_and_cycles() {
        let base = |body: &str| {
            format!(
                "$ORIGIN example.\n@ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n@ 60 IN NS ns.example.\nns 60 IN A 192.0.2.1\n{body}"
            )
        };
        assert!(parse_zone(
            &base("bad 60 IN CNAME one.example.\nbad 60 IN A 192.0.2.2\n"),
            "example"
        )
        .is_err());
        assert!(parse_zone(
            &base("bad 60 IN CNAME one.example.\nbad 60 IN CNAME two.example.\n"),
            "example"
        )
        .is_err());
        assert!(parse_zone(
            &base("a 60 IN CNAME b.example.\nb 60 IN CNAME a.example.\n"),
            "example"
        )
        .is_err());
        assert!(parse_zone(
            &base("bad 60 IN DNAME one.example.\nbad 60 IN DNAME two.example.\n"),
            "example"
        )
        .is_err());
        assert!(parse_zone(
            &base("alias 60 IN DNAME target.example.net.\nchild.alias 60 IN A 192.0.2.2\n"),
            "example"
        )
        .is_err());
        assert!(parse_zone(
            &base("cut 60 IN NS ns.example.\ncut 60 IN DNAME target.example.net.\n"),
            "example"
        )
        .is_err());

        let apex_dname = "$ORIGIN example.\n@ 60 IN SOA ns.example.net. hostmaster.example. 1 60 60 3600 60\n@ 60 IN NS ns.example.net.\n@ 60 IN DNAME target.example.net.\n";
        assert!(parse_zone(apex_dname, "example").is_ok());
    }

    #[test]
    fn zone_validates_long_cname_chains_and_cycles() {
        const CHAIN_LEN: usize = 10_000;
        let header = "$ORIGIN example.\n@ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n@ 60 IN NS ns.example.\nns 60 IN A 192.0.2.1\n";
        let mut chain = String::from(header);
        for index in 0..CHAIN_LEN {
            chain.push_str(&format!("n{index} 60 IN CNAME n{}.example.\n", index + 1));
        }
        chain.push_str(&format!("n{CHAIN_LEN} 60 IN A 192.0.2.2\n"));
        assert!(parse_zone(&chain, "example").is_ok());

        let mut cycle = String::from(header);
        for index in 0..CHAIN_LEN {
            let target = if index + 1 == CHAIN_LEN { 0 } else { index + 1 };
            cycle.push_str(&format!("n{index} 60 IN CNAME n{target}.example.\n"));
        }
        let error = match parse_zone(&cycle, "example") {
            Ok(_) => panic!("CNAME 순환이 허용됨"),
            Err(error) => error,
        };
        assert!(error.contains("CNAME loop"), "{error}");
    }

    #[test]
    fn apex_soa_and_ns() {
        let z = zone();
        let soa = z.query(&n("example.com"), RecordType::SOA);
        assert_eq!(soa.answers.len(), 1);
        assert!(matches!(soa.answers[0].rdata, RData::Soa(_)));
        let ns = z.query(&n("example.com"), RecordType::NS);
        assert_eq!(ns.answers.len(), 2);
    }

    #[test]
    fn mx_includes_target_glue() {
        let r = zone().query(&n("mail.example.com"), RecordType::MX);
        assert_eq!(r.answers.len(), 1);
        assert!(
            r.additional
                .iter()
                .any(|a| matches!(a.rdata, RData::A(ip) if ip == Ipv4Addr::new(192,0,2,3))),
            "mailhost 글루"
        );
    }

    #[test]
    /// Without them the client has to ask again.
    fn service_binding_includes_in_zone_target_records_and_addresses() {
        let source = "$ORIGIN example.\n\
            @ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n\
            @ 60 IN NS ns.example.\n\
            ns 60 IN A 192.0.2.1\n\
            web 60 IN HTTPS 0 svc.example.\n\
            svc 60 IN HTTPS 1 . port=443\n\
            svc 60 IN A 192.0.2.80\n\
            svc 60 IN AAAA 2001:db8::80\n";
        let zone = parse_zone(source, "example").unwrap();

        let alias = zone.query(&n("web.example"), RecordType::HTTPS);
        assert_eq!(alias.answers.len(), 1);
        assert!(alias.additional.iter().any(|record| {
            record.name.eq_ignore_case(&n("svc.example")) && record.rtype == RecordType::HTTPS
        }));
        assert!(alias
            .additional
            .iter()
            .any(|record| record.rtype == RecordType::A));
        assert!(alias
            .additional
            .iter()
            .any(|record| record.rtype == RecordType::AAAA));

        let service = zone.query(&n("svc.example"), RecordType::HTTPS);
        assert_eq!(
            service
                .additional
                .iter()
                .filter(|record| record.rtype == RecordType::HTTPS)
                .count(),
            0,
            "TargetName '.'에서 answer RRset을 Additional에 중복하지 않음"
        );
        assert_eq!(service.additional.len(), 2, "A와 AAAA 주소 힌트 포함");
    }

    #[test]
    fn repeated_service_binding_target_does_not_amplify_additional_rrsets() {
        let mut source = "$ORIGIN example.\n\
            @ 60 IN SOA ns.example. hostmaster.example. 1 60 60 3600 60\n\
            @ 60 IN NS ns.example.\n\
            ns 60 IN A 192.0.2.1\n\
            svc 60 IN HTTPS 1 . port=443\n\
            svc 60 IN A 192.0.2.80\n"
            .to_string();
        for priority in 1..=1024 {
            source.push_str(&format!(
                "web 60 IN HTTPS {priority} svc.example. port=443\n"
            ));
        }
        let zone = parse_zone(&source, "example").unwrap();
        let response = zone.query(&n("web.example"), RecordType::HTTPS);

        assert_eq!(response.answers.len(), 1024);
        assert_eq!(response.additional.len(), 2, "target RRset은 한 번만 포함");
        assert_eq!(
            response
                .additional
                .iter()
                .filter(|record| record.rtype == RecordType::A)
                .count(),
            1
        );
        assert_eq!(
            response
                .additional
                .iter()
                .filter(|record| record.rtype == RecordType::HTTPS)
                .count(),
            1
        );
    }

    #[test]
    fn from_records_roundtrips_axfr() {
        let axfr = zone().axfr_records();
        let z2 = Zone::from_records(axfr).unwrap();
        assert!(z2.origin().eq_ignore_case(&n("example.com")));
        assert_eq!(
            z2.query(&n("www.example.com"), RecordType::A).answers.len(),
            1
        );

        assert_eq!(
            z2.query(&n("example.com"), RecordType::SOA).answers.len(),
            1
        );
    }

    fn nsec3_record(owner: &str, iterations: u16, salt: &[u8]) -> Record {
        let mut raw = vec![1, 0];
        raw.extend_from_slice(&iterations.to_be_bytes());
        raw.push(salt.len() as u8);
        raw.extend_from_slice(salt);
        raw.push(20);
        raw.extend_from_slice(&[0x11; 20]);
        raw.extend_from_slice(&[0, 1, 0x40]);
        Record::new(n(owner), 60, RData::Unknown(50, raw))
    }

    #[test]
    /// Inconsistent parameters would break denial proofs.
    fn presigned_zone_rejects_unsafe_or_inconsistent_nsec3() {
        let valid = nsec3_record("00000000000000000000000000000000.example.com", 0, b"salt");
        let mut records = zone().axfr_records();
        records.push(valid.clone());
        assert!(Zone::from_records(records).is_ok());

        let mut records = zone().axfr_records();
        let mut expensive = valid.clone();
        if let RData::Unknown(_, raw) = &mut expensive.rdata {
            raw[2..4].copy_from_slice(&1u16.to_be_bytes());
        }
        records.push(expensive);
        let error = match Zone::from_records(records) {
            Ok(_) => panic!("반복 NSEC3가 허용됨"),
            Err(error) => error,
        };
        assert!(error.contains("iterations"));

        let mut records = zone().axfr_records();
        records.push(valid.clone());
        records.push(nsec3_record(
            "11111111111111111111111111111111.example.com",
            0,
            b"other",
        ));
        let error = match Zone::from_records(records) {
            Ok(_) => panic!("혼합 NSEC3 파라미터가 허용됨"),
            Err(error) => error,
        };
        assert!(error.contains("differ within one zone"));

        let mut records = zone().axfr_records();
        records.push(nsec3_record(
            "00000000000000000000000000000000.extra.example.com",
            0,
            b"salt",
        ));
        let error = match Zone::from_records(records) {
            Ok(_) => panic!("잘못된 NSEC3 owner가 허용됨"),
            Err(error) => error,
        };
        assert!(error.contains("owner name"));

        let mut records = zone().axfr_records();
        let mut malformed = valid;
        if let RData::Unknown(_, raw) = &mut malformed.rdata {
            raw[9] = 19;
        }
        records.push(malformed);
        assert!(Zone::from_records(records).is_err());
    }

    #[test]
    /// A collision would serve another name's answer.
    fn binary_owner_names_do_not_collide_through_lossy_utf8() {
        let first =
            Name::from_labels(vec![vec![0xff], b"example".to_vec(), b"com".to_vec()]).unwrap();
        let second =
            Name::from_labels(vec![vec![0xfe], b"example".to_vec(), b"com".to_vec()]).unwrap();
        assert_eq!(first.to_ascii_lower(), second.to_ascii_lower());

        let mut records = zone().axfr_records();
        records.push(Record::new(
            first.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 101)),
        ));
        records.push(Record::new(
            second.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 102)),
        ));
        let zone = Zone::from_records(records).unwrap();

        let first_answer = zone.query(&first, RecordType::A);
        let second_answer = zone.query(&second, RecordType::A);
        assert_eq!(first_answer.answers.len(), 1);
        assert_eq!(second_answer.answers.len(), 1);
        assert!(matches!(
            first_answer.answers[0].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 101)
        ));
        assert!(matches!(
            second_answer.answers[0].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 102)
        ));
    }

    #[test]
    fn store_matches_most_specific_zone() {
        let mut store = ZoneStore::new();
        store.add(zone());
        store.add(
            parse_zone(
                "$ORIGIN sub.example.com.\n@ 60 IN SOA ns hostmaster 1 60 60 3600 60\n@ 60 IN NS ns\nns 60 IN A 192.0.2.1\n",
                "sub.example.com",
            )
            .unwrap(),
        );
        assert!(store.zone_for(&n("www.example.com")).is_some());
        assert!(store
            .zone_for(&n("host.deep.sub.example.com"))
            .unwrap()
            .origin()
            .eq_ignore_case(&n("sub.example.com")));
        assert!(store.zone_for(&n("other.test")).is_none());
        assert!(store.query(&n("www.example.com"), RecordType::A).is_some());
        assert!(store
            .zone_exact(&n("SUB.Example.COM"))
            .unwrap()
            .origin()
            .eq_ignore_case(&n("sub.example.com")));
        assert!(store.zone_exact(&n("host.sub.example.com")).is_none());
        assert_eq!(store.index.len(), store.zones.len());
    }

    #[test]
    fn store_replaces_duplicate_zone_origin() {
        let make = |address: &str| {
            parse_zone(
                &format!(
                    "$ORIGIN duplicate.test.\n@ 60 IN SOA ns hostmaster 1 60 60 3600 60\n@ 60 IN NS ns\nns 60 IN A 192.0.2.1\nwww 60 IN A {address}\n"
                ),
                "duplicate.test",
            )
            .unwrap()
        };
        let mut store = ZoneStore::new();
        store.add(make("192.0.2.2"));
        store.add(make("192.0.2.3"));
        assert_eq!(store.zones().len(), 1);
        let response = store
            .query(&n("www.duplicate.test"), RecordType::A)
            .unwrap();
        assert!(matches!(
            response.answers[0].rdata,
            RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 3)
        ));
    }

    #[test]
    /// Resolving it would loop at startup.
    fn plaintext_sql_endpoint_never_uses_hostname_dns() {
        assert_eq!(
            loopback_socket_addr("localhost", 3306, "SQL").unwrap(),
            "127.0.0.1:3306".parse().unwrap()
        );
        assert_eq!(
            loopback_socket_addr("::1", 5432, "SQL").unwrap(),
            "[::1]:5432".parse().unwrap()
        );
        assert!(loopback_socket_addr("db.example", 5432, "SQL").is_err());
        assert!(loopback_socket_addr("192.0.2.10", 5432, "SQL").is_err());
    }

    #[test]
    fn sql_authority_parser_handles_bracketed_ipv6() {
        assert_eq!(
            split_host_port("[::1]:6543", 5432),
            Some(("::1".to_string(), 6543))
        );
        assert_eq!(
            split_host_port("[::1]", 5432),
            Some(("::1".to_string(), 5432))
        );
        assert!(split_host_port("[::1]junk", 5432).is_none());
        assert!(split_host_port("localhost:0", 5432).is_none());
    }
}
