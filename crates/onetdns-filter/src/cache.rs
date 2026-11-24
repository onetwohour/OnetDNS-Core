//! Stores compiled filter sets on disk and reads them back. Reparsing the lists takes tens of
//! seconds; keeping the built sets makes restarts that much faster. Each list's parsed names are
//! kept as well, so a build after one list changed parses only that list.
//!
//! The file is untrusted input. The header's input fingerprint and payload hash reject tampering,
//! and the parsers behind them must still not panic on any bytes.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Seek, SeekFrom, Write};

use onetdns_core::{BlockResponse, FilterVerdict, RewriteTarget};
use onetdns_proto::{Name, RData, Reader as DnsReader, RecordType, Writer as DnsWriter};
use sha2::{Digest, Sha256};

use crate::engine::{
    ClientCond, ClientRule, DomainSet, EngineParts, FilterLoadReport, LocalZoneAction,
    LocalZoneSet, RewriteSet, RpzIpRule, RpzNameRule, StaticZone,
};
use crate::loader::{Kind, ListSet, ParsedList, Slot};
use crate::table::KeyRun;

/// File identifier.
const MAGIC: &[u8; 8] = b"ONETFST\0";

/// Describes the stored layout. Change it whenever the layout changes; there is no version number
/// to bump. Its hash is written in the header and compared on read, so editing this text along with
/// the layout makes older files get rejected and rebuilt. The cache can always be rebuilt, so there
/// is no reason to migrate it.
const LAYOUT: &str = "domain_sets:block,allow,block_important,allow_important,refuse,nodata,no_response|regex_sets:block,allow,block_important,allow_important,refuse,nodata,no_response|verdicts:allow,block,rewrite,drop|states:blocks(header,labels,edges(target,output,tail))|tails|sources";

/// A parsed list file: one list's domain entries and the rest of its rules as text.
const LIST_MAGIC: &[u8; 8] = b"ONETLST\0";

/// Plays the part of [`LAYOUT`] for parsed list files.
const LIST_LAYOUT: &str = "report|other_lines|sets:slot(plain:kind|typed:type|typed_except:types),exact,suffix|names:count,bytes,(shared_suffix,head_len,head)*";

fn tag_of(layout: &str) -> [u8; 4] {
    let digest: [u8; 32] = Sha256::digest(layout.as_bytes()).into();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn seal(
    magic: &[u8; 8],
    layout: &str,
    fingerprint: [u8; 32],
    payload_len: usize,
    payload_digest: [u8; 32],
) -> [u8; HEADER_BYTES] {
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(magic);
    header[8..12].copy_from_slice(&tag_of(layout));
    header[12..44].copy_from_slice(&fingerprint);
    header[44..52].copy_from_slice(&(payload_len as u64).to_le_bytes());
    header[52..].copy_from_slice(&payload_digest);
    header
}

/// Checks the header against what the caller expects and the payload against its hash, and returns
/// the payload.
fn unseal<'a>(
    encoded: &'a [u8],
    magic: &[u8; 8],
    layout: &str,
    expected_fingerprint: [u8; 32],
) -> Result<&'a [u8], CacheError> {
    if encoded.len() < HEADER_BYTES || encoded.len() > MAX_CACHE_BYTES {
        return Err(CacheError::new(
            "Compiled filter cache file size is invalid",
        ));
    }
    if encoded.get(..8) != Some(magic.as_slice()) {
        return Err(CacheError::new(
            "Compiled filter cache file magic does not match",
        ));
    }
    if encoded[8..12] != tag_of(layout) {
        return Err(CacheError::new(
            "Compiled filter cache layout differs from the current layout",
        ));
    }
    if encoded[12..44] != expected_fingerprint {
        return Err(CacheError::new(
            "Compiled filter cache input fingerprint does not match",
        ));
    }
    let payload_len = u64::from_le_bytes(
        encoded[44..52]
            .try_into()
            .map_err(|_| CacheError::new("Invalid compiled filter cache header"))?,
    );
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        CacheError::new("Compiled filter cache declares a data size that cannot be handled")
    })?;
    if HEADER_BYTES.checked_add(payload_len) != Some(encoded.len()) {
        return Err(CacheError::new(
            "Compiled filter cache data length does not match the file size",
        ));
    }
    let payload = &encoded[HEADER_BYTES..];
    let actual_digest: [u8; 32] = Sha256::digest(payload).into();
    if encoded[52..84] != actual_digest {
        return Err(CacheError::new(
            "Compiled filter cache integrity check failed",
        ));
    }
    Ok(payload)
}

/// Magic, layout tag, fingerprint, length, and hash.
const HEADER_BYTES: usize = 8 + 4 + 32 + 8 + 32;
const MAX_ITEMS: usize = 5_000_000;
const MAX_STRING_BYTES: usize = 64 * 1024 * 1024;

pub const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The reason is for diagnostics; the whole file is discarded either way.
pub struct CacheError(&'static str);

impl CacheError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CacheError {}

#[derive(Debug)]
pub enum CacheWriteError {
    Cache(CacheError),
    Io(std::io::Error),
}

impl fmt::Display for CacheWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CacheWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cache(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<CacheError> for CacheWriteError {
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<std::io::Error> for CacheWriteError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn encode_engine_cache(
    parts: &mut EngineParts,
    input_fingerprint: [u8; 32],
) -> Result<Vec<u8>, CacheError> {
    parts.finalize_domain_sets();

    let mut payload = Encoder::default();
    payload.bytes.extend_from_slice(&[0u8; HEADER_BYTES]);
    encode_parts(&mut payload, parts)?;
    let mut output = payload.bytes;
    let payload_len = output.len() - HEADER_BYTES;
    if payload_len > MAX_CACHE_BYTES.saturating_sub(HEADER_BYTES) {
        return Err(CacheError::new("Compiled filter cache is too large"));
    }
    let payload_digest: [u8; 32] = Sha256::digest(&output[HEADER_BYTES..]).into();
    output[..HEADER_BYTES].copy_from_slice(&seal(
        MAGIC,
        LAYOUT,
        input_fingerprint,
        payload_len,
        payload_digest,
    ));
    Ok(output)
}

/// Streams instead of building the whole file in memory: the filter sets can be hundreds of
/// megabytes, and building them all would double memory use at the moment of saving.
pub fn write_engine_cache(
    parts: &mut EngineParts,
    input_fingerprint: [u8; 32],
    output: &mut (impl Write + Seek),
) -> Result<(), CacheWriteError> {
    parts.finalize_domain_sets();
    output.write_all(&[0u8; HEADER_BYTES])?;

    let mut payload = PayloadStream::new(output);
    encode_domain_sets_streaming(&mut payload, parts)?;
    let mut write_chunk = |bytes: &[u8]| payload.write(bytes);
    encode_parts_tail(&mut Encoder::streaming(&mut write_chunk), parts)?;
    let (payload_len, payload_digest) = payload.finish()?;
    let header = seal(
        MAGIC,
        LAYOUT,
        input_fingerprint,
        payload_len,
        payload_digest,
    );
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header)?;
    output.seek(SeekFrom::End(0))?;
    Ok(())
}

/// Streams one parsed list under `key`, which must name the rules it was parsed from.
pub fn write_parsed_list(
    list: &ParsedList,
    key: [u8; 32],
    output: &mut (impl Write + Seek),
) -> Result<(), CacheWriteError> {
    output.write_all(&[0u8; HEADER_BYTES])?;
    let mut payload = PayloadStream::new(output);
    {
        let mut write_chunk = |bytes: &[u8]| payload.write(bytes);
        encode_parsed_list(&mut Encoder::streaming(&mut write_chunk), list)?;
    }
    let (payload_len, payload_digest) = payload.finish()?;
    let header = seal(LIST_MAGIC, LIST_LAYOUT, key, payload_len, payload_digest);
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header)?;
    output.seek(SeekFrom::End(0))?;
    Ok(())
}

/// Checked like [`decode_engine_cache`]. The names must also come in the order the automaton is
/// built in, each once, so a sealed file with bad content is still rejected rather than built.
pub fn decode_parsed_list(encoded: &[u8], key: [u8; 32]) -> Result<ParsedList, CacheError> {
    let payload = unseal(encoded, LIST_MAGIC, LIST_LAYOUT, key)?;
    let mut decoder = Decoder::new(payload);
    let list = decode_list_payload(&mut decoder)?;
    if !decoder.input.is_empty() {
        return Err(CacheError::new(
            "Unexpected trailing data in compiled filter cache",
        ));
    }
    Ok(list)
}

const STREAM_BUFFER_BYTES: usize = 64 * 1024;

struct PayloadStream<'a, W> {
    output: &'a mut W,
    digest: Sha256,
    buffer: Vec<u8>,
    len: usize,
    error: Option<std::io::Error>,
    overflowed: bool,
}

impl<'a, W: Write> PayloadStream<'a, W> {
    fn new(output: &'a mut W) -> Self {
        Self {
            output,
            digest: Sha256::new(),
            buffer: Vec::with_capacity(STREAM_BUFFER_BYTES),
            len: 0,
            error: None,
            overflowed: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.error.is_some() || self.overflowed {
            return;
        }
        let Some(next_len) = self.len.checked_add(bytes.len()) else {
            self.overflowed = true;
            return;
        };
        if next_len > MAX_CACHE_BYTES - HEADER_BYTES {
            self.overflowed = true;
            return;
        }
        self.len = next_len;

        if bytes.len() >= STREAM_BUFFER_BYTES {
            self.flush();
            self.write_direct(bytes);
            return;
        }
        if self.buffer.len() + bytes.len() > STREAM_BUFFER_BYTES {
            self.flush();
        }
        if self.error.is_none() {
            self.buffer.extend_from_slice(bytes);
        }
    }

    /// Large chunks skip the buffer.
    fn write_direct(&mut self, bytes: &[u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(error) = self.output.write_all(bytes) {
            self.error = Some(error);
            return;
        }
        self.digest.update(bytes);
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() || self.error.is_some() {
            return;
        }
        if let Err(error) = self.output.write_all(&self.buffer) {
            self.error = Some(error);
            self.buffer.clear();
            return;
        }
        self.digest.update(&self.buffer);
        self.buffer.clear();
    }

    fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn len(&mut self, value: usize, max: usize) -> Result<(), CacheError> {
        if value > max {
            return Err(CacheError::new(
                "Compiled filter cache has too many entries",
            ));
        }
        let value = u32::try_from(value)
            .map_err(|_| CacheError::new("Compiled filter cache has too many entries"))?;
        self.write(&value.to_le_bytes());
        Ok(())
    }

    fn finish(mut self) -> Result<(usize, [u8; 32]), CacheWriteError> {
        if self.overflowed {
            return Err(CacheError::new("Compiled filter cache is too large").into());
        }
        self.flush();
        if let Some(error) = self.error {
            return Err(error.into());
        }
        Ok((self.len, self.digest.finalize().into()))
    }
}

/// The header fingerprint must match the current input and the payload hash must match too. If
/// either does not, the file is discarded and the lists are parsed again.
pub fn decode_engine_cache(
    encoded: &[u8],
    expected_fingerprint: [u8; 32],
) -> Result<EngineParts, CacheError> {
    let payload = unseal(encoded, MAGIC, LAYOUT, expected_fingerprint)?;
    let mut decoder = Decoder::new(payload);
    let parts = decode_parts(&mut decoder)?;
    if !decoder.input.is_empty() {
        return Err(CacheError::new(
            "Unexpected trailing data in compiled filter cache",
        ));
    }
    Ok(parts)
}

#[derive(Default)]
struct Encoder<'a> {
    bytes: Vec<u8>,
    chunks: Option<&'a mut dyn FnMut(&[u8])>,
}

impl<'a> Encoder<'a> {
    fn streaming(chunks: &'a mut dyn FnMut(&[u8])) -> Self {
        Self {
            bytes: Vec::new(),
            chunks: Some(chunks),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if let Some(chunks) = &mut self.chunks {
            chunks(bytes);
        } else {
            self.bytes.extend_from_slice(bytes);
        }
    }

    fn u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn len(&mut self, value: usize, max: usize) -> Result<(), CacheError> {
        if value > max {
            return Err(CacheError::new(
                "Compiled filter cache has too many entries",
            ));
        }
        self.u32(
            u32::try_from(value)
                .map_err(|_| CacheError::new("Compiled filter cache has too many entries"))?,
        );
        Ok(())
    }

    fn blob(&mut self, value: &[u8], max: usize) -> Result<(), CacheError> {
        self.len(value.len(), max)?;
        self.write(value);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), CacheError> {
        self.blob(value.as_bytes(), MAX_STRING_BYTES)
    }

    fn varint(&mut self, mut value: u32) {
        let mut bytes = [0u8; 5];
        let mut len = 0;
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                bytes[len] = low;
                len += 1;
                break;
            }
            bytes[len] = low | 0x80;
            len += 1;
        }
        self.write(&bytes[..len]);
    }
}

/// Every read is bounds-checked.
struct Decoder<'a> {
    input: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// Fails when too short.
    fn take(&mut self, count: usize) -> Result<&'a [u8], CacheError> {
        let (head, tail) = self
            .input
            .split_at_checked(count)
            .ok_or_else(|| CacheError::new("Compiled filter cache is truncated"))?;
        self.input = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CacheError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CacheError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(
            |_| CacheError::new("Could not read a 16-bit integer from the compiled filter cache"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, CacheError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| CacheError::new("Could not read a 32-bit integer from the compiled filter cache"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, CacheError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| CacheError::new("Could not read a 64-bit integer from the compiled filter cache"),
        )?))
    }

    fn len(&mut self, max: usize) -> Result<usize, CacheError> {
        let value = self.u32()? as usize;
        if value > max {
            return Err(CacheError::new(
                "Compiled filter cache has too many entries",
            ));
        }
        Ok(value)
    }

    fn blob(&mut self, max: usize) -> Result<&'a [u8], CacheError> {
        let len = self.len(max)?;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, CacheError> {
        let bytes = self.blob(MAX_STRING_BYTES)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| CacheError::new("Invalid string in compiled filter cache"))?;
        Ok(value.to_owned())
    }

    fn varint(&mut self) -> Result<u32, CacheError> {
        let mut value = 0u64;
        for shift in [0, 7, 14, 21, 28] {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return u32::try_from(value)
                    .map_err(|_| CacheError::new("Oversized number in compiled filter cache"));
            }
        }
        Err(CacheError::new("Oversized number in compiled filter cache"))
    }

    /// Values other than 0 and 1 are errors.
    fn boolean(&mut self) -> Result<bool, CacheError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CacheError::new("Invalid boolean in compiled filter cache")),
        }
    }
}

fn encode_parts(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    encode_domain_sets(w, parts)?;
    encode_parts_tail(w, parts)
}

fn encode_domain_sets(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    for set in [
        &parts.block,
        &parts.allow,
        &parts.block_important,
        &parts.allow_important,
        &parts.refuse,
        &parts.nodata,
        &parts.no_response,
    ] {
        set.encode_compact(&mut w.bytes).map_err(CacheError::new)?;
    }
    encode_vec(w, &parts.typed_block, |w, (rtype, set)| {
        w.u16(rtype.0);
        set.encode_compact(&mut w.bytes).map_err(CacheError::new)
    })?;
    encode_vec(w, &parts.typed_block_except, |w, (types, set)| {
        encode_record_types(w, types)?;
        set.encode_compact(&mut w.bytes).map_err(CacheError::new)
    })?;
    Ok(())
}

/// The largest part, so it is not buffered in memory.
fn encode_domain_sets_streaming<W: Write>(
    w: &mut PayloadStream<'_, W>,
    parts: &EngineParts,
) -> Result<(), CacheError> {
    for set in [
        &parts.block,
        &parts.allow,
        &parts.block_important,
        &parts.allow_important,
        &parts.refuse,
        &parts.nodata,
        &parts.no_response,
    ] {
        set.encode_compact_chunks(&mut |bytes| w.write(bytes))
            .map_err(CacheError::new)?;
    }
    w.len(parts.typed_block.len(), MAX_ITEMS)?;
    for (rtype, set) in &parts.typed_block {
        w.u16(rtype.0);
        set.encode_compact_chunks(&mut |bytes| w.write(bytes))
            .map_err(CacheError::new)?;
    }
    w.len(parts.typed_block_except.len(), MAX_ITEMS)?;
    for (types, set) in &parts.typed_block_except {
        w.len(types.len(), MAX_ITEMS)?;
        for rtype in types {
            w.u16(rtype.0);
        }
        set.encode_compact_chunks(&mut |bytes| w.write(bytes))
            .map_err(CacheError::new)?;
    }
    Ok(())
}

fn encode_parts_tail(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    for strings in [
        &parts.regex_block,
        &parts.regex_allow,
        &parts.regex_block_important,
        &parts.regex_allow_important,
        &parts.regex_refuse,
        &parts.regex_nodata,
        &parts.regex_no_response,
    ] {
        encode_strings(w, strings)?;
    }
    encode_vec(w, &parts.regex_rewrites, |w, (pattern, target)| {
        w.string(pattern)?;
        encode_rewrite_target(w, target)
    })?;
    encode_vec(w, &parts.regex_typed_block, |w, (rtype, pattern)| {
        w.u16(rtype.0);
        w.string(pattern)
    })?;
    encode_vec(w, &parts.regex_typed_block_except, |w, (types, pattern)| {
        encode_record_types(w, types)?;
        w.string(pattern)
    })?;
    encode_rewrite_set(w, &parts.rewrites)?;
    encode_local_zones(w, &parts.local_zones)?;
    encode_vec(w, &parts.client_rules, encode_client_rule)?;
    for rules in [&parts.rpz_client_ip, &parts.rpz_ip, &parts.rpz_nsip] {
        encode_vec(w, rules, encode_rpz_ip)?;
    }
    encode_vec(w, &parts.rpz_nsdname, |w, rule| {
        encode_name(w, &rule.suffix)?;
        encode_verdict(w, &rule.verdict)
    })?;
    encode_report(w, &parts.report)?;
    encode_strings(w, &parts.sources)
}

fn decode_parts(r: &mut Decoder<'_>) -> Result<EngineParts, CacheError> {
    let block = decode_domain_set(r)?;
    let allow = decode_domain_set(r)?;
    let block_important = decode_domain_set(r)?;
    let allow_important = decode_domain_set(r)?;
    let refuse = decode_domain_set(r)?;
    let nodata = decode_domain_set(r)?;
    let no_response = decode_domain_set(r)?;
    let typed_block = decode_vec(r, |r| Ok((RecordType(r.u16()?), decode_domain_set(r)?)))?;
    let typed_block_except =
        decode_vec(r, |r| Ok((decode_record_types(r)?, decode_domain_set(r)?)))?;
    let regex_block = decode_strings(r)?;
    let regex_allow = decode_strings(r)?;
    let regex_block_important = decode_strings(r)?;
    let regex_allow_important = decode_strings(r)?;
    let regex_refuse = decode_strings(r)?;
    let regex_nodata = decode_strings(r)?;
    let regex_no_response = decode_strings(r)?;
    let regex_rewrites = decode_vec(r, |r| Ok((r.string()?, decode_rewrite_target(r)?)))?;
    let regex_typed_block = decode_vec(r, |r| Ok((RecordType(r.u16()?), r.string()?)))?;
    let regex_typed_block_except = decode_vec(r, |r| Ok((decode_record_types(r)?, r.string()?)))?;
    let rewrites = decode_rewrite_set(r)?;
    let local_zones = decode_local_zones(r)?;
    let client_rules = decode_vec(r, decode_client_rule)?;
    let rpz_client_ip = decode_vec(r, decode_rpz_ip)?;
    let rpz_ip = decode_vec(r, decode_rpz_ip)?;
    let rpz_nsip = decode_vec(r, decode_rpz_ip)?;
    let rpz_nsdname = decode_vec(r, |r| {
        let name = decode_name(r)?;
        let verdict = decode_verdict(r)?;
        Ok(RpzNameRule {
            suffix: name,
            verdict,
        })
    })?;
    let report = decode_report(r)?;
    let sources = decode_strings(r)?;
    Ok(EngineParts {
        block,
        allow,
        block_important,
        allow_important,
        refuse,
        nodata,
        no_response,
        typed_block,
        typed_block_except,
        regex_block,
        regex_allow,
        regex_block_important,
        regex_allow_important,
        regex_refuse,
        regex_nodata,
        regex_no_response,
        regex_rewrites,
        regex_typed_block,
        regex_typed_block_except,
        rewrites,
        local_zones,
        client_rules,
        rpz_client_ip,
        rpz_ip,
        rpz_nsdname,
        rpz_nsip,
        report,
        sources,
    })
}

fn encode_parsed_list(w: &mut Encoder<'_>, list: &ParsedList) -> Result<(), CacheError> {
    encode_report(w, &list.report)?;
    encode_strings(w, &list.other_lines)?;
    w.len(list.sets.len(), MAX_ITEMS)?;
    let mut budget = MAX_CACHE_BYTES;
    for (slot, set) in &list.sets {
        encode_slot(w, slot)?;
        encode_names(w, &set.exact, &mut budget)?;
        encode_names(w, &set.suffix, &mut budget)?;
    }
    Ok(())
}

fn decode_list_payload(r: &mut Decoder<'_>) -> Result<ParsedList, CacheError> {
    let report = decode_report(r)?;
    let other_lines = decode_strings(r)?;
    let set_count = r.len(MAX_ITEMS)?;
    let mut sets: Vec<(Slot, ListSet)> = Vec::new();
    let mut budget = MAX_CACHE_BYTES;
    for _ in 0..set_count {
        let slot = decode_slot(r)?;
        if sets.iter().any(|(known, _)| *known == slot) {
            return Err(CacheError::new(
                "Compiled filter cache has a duplicate domain set",
            ));
        }
        let exact = decode_names(r, &mut budget)?;
        let suffix = decode_names(r, &mut budget)?;
        sets.push((slot, ListSet { exact, suffix }));
    }
    Ok(ParsedList {
        sets,
        other_lines,
        report,
    })
}

const SLOT_TYPED: u8 = 7;
const SLOT_TYPED_EXCEPT: u8 = 8;

fn encode_slot(w: &mut Encoder<'_>, slot: &Slot) -> Result<(), CacheError> {
    match slot {
        Slot::Plain(kind) => w.u8(*kind as u8),
        Slot::Typed(rtype) => {
            w.u8(SLOT_TYPED);
            w.u16(rtype.0);
        }
        Slot::TypedExcept(types) => {
            w.u8(SLOT_TYPED_EXCEPT);
            encode_record_types(w, types)?;
        }
    }
    Ok(())
}

fn decode_slot(r: &mut Decoder<'_>) -> Result<Slot, CacheError> {
    let tag = r.u8()?;
    if let Some(kind) = Kind::ALL.get(usize::from(tag)) {
        return Ok(Slot::Plain(*kind));
    }
    match tag {
        SLOT_TYPED => Ok(Slot::Typed(RecordType(r.u16()?))),
        SLOT_TYPED_EXCEPT => {
            let types = decode_record_types(r)?;
            if types.is_empty() || !types.windows(2).all(|pair| pair[0].0 < pair[1].0) {
                return Err(CacheError::new(
                    "Invalid record type set in compiled filter cache",
                ));
            }
            Ok(Slot::TypedExcept(types))
        }
        _ => Err(CacheError::new(
            "Invalid domain set kind in compiled filter cache",
        )),
    }
}

/// Each name is stored as the length of the suffix it shares with the previous one and the bytes
/// in front of it; sorted by reversed bytes, neighbors share most of their suffix. `budget` bounds
/// the bytes of every name in the file together.
fn encode_names(w: &mut Encoder<'_>, run: &KeyRun, budget: &mut usize) -> Result<(), CacheError> {
    let bytes: usize = run.names().map(str::len).sum();
    *budget = budget
        .checked_sub(bytes)
        .ok_or(CacheError::new("Compiled filter cache is too large"))?;
    w.len(run.len(), u32::MAX as usize)?;
    w.len(bytes, u32::MAX as usize)?;
    let mut previous: &[u8] = &[];
    for name in run.names() {
        let name = name.as_bytes();
        let shared = previous
            .iter()
            .rev()
            .zip(name.iter().rev())
            .take_while(|(left, right)| left == right)
            .count();
        let head = &name[..name.len() - shared];
        w.varint(shared as u32);
        w.varint(head.len() as u32);
        w.write(head);
        previous = name;
    }
    Ok(())
}

fn decode_names(r: &mut Decoder<'_>, budget: &mut usize) -> Result<KeyRun, CacheError> {
    let count = r.len(u32::MAX as usize)?;
    let bytes = r.len(u32::MAX as usize)?;
    *budget = budget
        .checked_sub(bytes)
        .ok_or(CacheError::new("Compiled filter cache is too large"))?;
    // Every name takes at least two bytes, so a count the input cannot hold is rejected before
    // anything is reserved for it.
    if count > r.input.len() / 2 {
        return Err(CacheError::new("Compiled filter cache is truncated"));
    }
    let mut names: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    names
        .try_reserve_exact(bytes)
        .and_then(|()| offsets.try_reserve_exact(count + 1))
        .map_err(|_| CacheError::new("Out of memory loading compiled filter cache entries"))?;
    offsets.push(0);
    let mut previous = 0..0;
    for index in 0..count {
        let shared = r.varint()? as usize;
        let head_len = r.varint()? as usize;
        let head = r.take(head_len)?;
        if shared > previous.len() || names.len() + head.len() + shared > bytes {
            return Err(CacheError::new("Invalid name in compiled filter cache"));
        }
        let start = names.len();
        names.extend_from_slice(head);
        names.extend_from_within(previous.end - shared..previous.end);
        let name = start..names.len();
        let ordered = index == 0
            || names[previous]
                .iter()
                .rev()
                .lt(names[name.clone()].iter().rev());
        if !ordered {
            return Err(CacheError::new(
                "Compiled filter cache names are out of order",
            ));
        }
        offsets.push(names.len() as u32);
        previous = name;
    }
    if names.len() != bytes {
        return Err(CacheError::new("Invalid name in compiled filter cache"));
    }
    let names = String::from_utf8(names)
        .map_err(|_| CacheError::new("Invalid string in compiled filter cache"))?;
    if !offsets
        .iter()
        .all(|offset| names.is_char_boundary(*offset as usize))
    {
        return Err(CacheError::new("Invalid string in compiled filter cache"));
    }
    Ok(KeyRun::Stored { names, offsets })
}

fn encode_vec<T>(
    w: &mut Encoder<'_>,
    values: &[T],
    mut encode: impl FnMut(&mut Encoder<'_>, &T) -> Result<(), CacheError>,
) -> Result<(), CacheError> {
    w.len(values.len(), MAX_ITEMS)?;
    for value in values {
        encode(w, value)?;
    }
    Ok(())
}

fn decode_vec<T>(
    r: &mut Decoder<'_>,
    mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T, CacheError>,
) -> Result<Vec<T>, CacheError> {
    let count = r.len(MAX_ITEMS)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| CacheError::new("Out of memory loading compiled filter cache entries"))?;
    for _ in 0..count {
        values.push(decode(r)?);
    }
    Ok(values)
}

fn decode_domain_set(r: &mut Decoder<'_>) -> Result<DomainSet, CacheError> {
    DomainSet::decode_compact(&mut r.input).map_err(CacheError::new)
}

fn encode_strings(w: &mut Encoder<'_>, values: &[String]) -> Result<(), CacheError> {
    encode_vec(w, values, |w, value| w.string(value))
}

fn decode_strings(r: &mut Decoder<'_>) -> Result<Vec<String>, CacheError> {
    decode_vec(r, |r| r.string())
}

fn encode_record_types(w: &mut Encoder<'_>, types: &[RecordType]) -> Result<(), CacheError> {
    w.len(types.len(), MAX_ITEMS)?;
    for rtype in types {
        w.u16(rtype.0);
    }
    Ok(())
}

fn decode_record_types(r: &mut Decoder<'_>) -> Result<Vec<RecordType>, CacheError> {
    decode_vec(r, |r| Ok(RecordType(r.u16()?)))
}

fn encode_rewrite_set(w: &mut Encoder<'_>, set: &RewriteSet) -> Result<(), CacheError> {
    encode_rewrite_map(w, &set.exact)?;
    encode_rewrite_map(w, &set.suffix)
}

fn encode_rewrite_map(
    w: &mut Encoder<'_>,
    map: &HashMap<Box<str>, RewriteTarget>,
) -> Result<(), CacheError> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    w.len(entries.len(), MAX_ITEMS)?;
    for (domain, target) in entries {
        w.string(domain)?;
        encode_rewrite_target(w, target)?;
    }
    Ok(())
}

fn decode_rewrite_set(r: &mut Decoder<'_>) -> Result<RewriteSet, CacheError> {
    Ok(RewriteSet {
        exact: decode_rewrite_map(r)?,
        suffix: decode_rewrite_map(r)?,
    })
}

fn decode_rewrite_map(r: &mut Decoder<'_>) -> Result<HashMap<Box<str>, RewriteTarget>, CacheError> {
    let entries: Vec<(Box<str>, RewriteTarget)> = decode_vec(r, |r| {
        Ok((r.string()?.into_boxed_str(), decode_rewrite_target(r)?))
    })?;
    let count = entries.len();
    let map: HashMap<_, _> = entries.into_iter().collect();
    if map.len() != count {
        return Err(CacheError::new(
            "Compiled filter cache has a duplicate rewrite entry",
        ));
    }
    Ok(map)
}

/// Sorted by name, so the same config gives the same bytes.
fn encode_local_zones(w: &mut Encoder<'_>, set: &LocalZoneSet) -> Result<(), CacheError> {
    let mut entries: Vec<_> = set.iter().collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    w.len(entries.len(), MAX_ITEMS)?;
    for (zone, action) in entries {
        w.string(zone)?;
        match action {
            LocalZoneAction::Deny => w.u8(0),
            LocalZoneAction::Refuse => w.u8(1),
            LocalZoneAction::Rewrite(target) => {
                w.u8(2);
                encode_rewrite_target(w, target)?;
            }
            LocalZoneAction::Transparent => w.u8(3),
            LocalZoneAction::Static(data) => {
                w.u8(4);
                let mut names: Vec<_> = data.iter().collect();
                names.sort_unstable_by(|left, right| left.0.cmp(right.0));
                w.len(names.len(), MAX_ITEMS)?;
                for (name, target) in names {
                    w.string(name)?;
                    encode_rewrite_target(w, target)?;
                }
            }
        }
    }
    Ok(())
}

fn decode_local_zones(r: &mut Decoder<'_>) -> Result<LocalZoneSet, CacheError> {
    let entries = decode_vec(r, |r| {
        let zone = r.string()?;
        let action = match r.u8()? {
            0 => LocalZoneAction::Deny,
            1 => LocalZoneAction::Refuse,
            2 => LocalZoneAction::Rewrite(decode_rewrite_target(r)?),
            3 => LocalZoneAction::Transparent,
            4 => {
                let names = decode_vec(r, |r| Ok((r.string()?, decode_rewrite_target(r)?)))?;
                let mut data = StaticZone::new(&zone);
                for (name, target) in names {
                    data.insert(&name, target).map_err(|_| {
                        CacheError::new(
                            "Compiled filter cache static zone has an out-of-zone or overlapping name",
                        )
                    })?;
                }
                LocalZoneAction::Static(data)
            }
            _ => {
                return Err(CacheError::new(
                    "Invalid local zone type in compiled filter cache",
                ))
            }
        };
        Ok((zone, action))
    })?;
    let mut set = LocalZoneSet::default();
    for (zone, action) in entries {
        set.insert(&zone, action)
            .map_err(|_| CacheError::new("Compiled filter cache has a duplicate local zone"))?;
    }
    Ok(set)
}

fn encode_client_rule(w: &mut Encoder<'_>, rule: &ClientRule) -> Result<(), CacheError> {
    w.string(&rule.domain)?;
    encode_option(w, rule.regex.as_ref(), |w, value| w.string(value))?;
    w.u8(u8::from(rule.allow));
    encode_vec(w, &rule.clients, |w, condition| match condition {
        ClientCond::Net { negated, net } => {
            w.u8(0);
            w.u8(u8::from(*negated));
            w.string(&net.to_string())
        }
        ClientCond::Id { negated, id } => {
            w.u8(1);
            w.u8(u8::from(*negated));
            w.string(id)
        }
    })?;
    encode_vec(w, &rule.ctags, |w, (negated, tag)| {
        w.u8(u8::from(*negated));
        w.string(tag)
    })?;
    encode_strings(w, &rule.denyallow)
}

fn decode_client_rule(r: &mut Decoder<'_>) -> Result<ClientRule, CacheError> {
    let domain = r.string()?;
    let regex = decode_option(r, |r| r.string())?;
    let allow = r.boolean()?;
    let clients = decode_vec(r, |r| {
        let tag = r.u8()?;
        let negated = r.boolean()?;
        match tag {
            0 => Ok(ClientCond::Net {
                negated,
                net: r
                    .string()?
                    .parse()
                    .map_err(|_| CacheError::new("Invalid client CIDR in compiled filter cache"))?,
            }),
            1 => Ok(ClientCond::Id {
                negated,
                id: r.string()?,
            }),
            _ => Err(CacheError::new(
                "Invalid client condition type in compiled filter cache",
            )),
        }
    })?;
    let ctags = decode_vec(r, |r| Ok((r.boolean()?, r.string()?)))?;
    let denyallow = decode_strings(r)?;
    Ok(ClientRule {
        domain,
        regex,
        allow,
        clients,
        ctags,
        denyallow,
    })
}

fn encode_rpz_ip(w: &mut Encoder<'_>, rule: &RpzIpRule) -> Result<(), CacheError> {
    w.string(&rule.net.to_string())?;
    w.string(&rule.display)?;
    encode_verdict(w, &rule.verdict)
}

fn decode_rpz_ip(r: &mut Decoder<'_>) -> Result<RpzIpRule, CacheError> {
    let net = r
        .string()?
        .parse()
        .map_err(|_| CacheError::new("Invalid RPZ CIDR in compiled filter cache"))?;
    let display = r.string()?.into_boxed_str();
    let verdict = decode_verdict(r)?;
    Ok(RpzIpRule {
        net,
        verdict,
        display,
    })
}

fn encode_report(w: &mut Encoder<'_>, report: &FilterLoadReport) -> Result<(), CacheError> {
    for value in [
        report.rules_total,
        report.rules_skipped,
        report.invalid_regex,
        report.invalid_pattern,
        report.not_applicable,
    ] {
        w.u64(value);
    }
    w.len(report.unsupported_modifier.len(), MAX_ITEMS)?;
    for (modifier, count) in &report.unsupported_modifier {
        w.string(modifier)?;
        w.u64(*count);
    }
    Ok(())
}

fn decode_report(r: &mut Decoder<'_>) -> Result<FilterLoadReport, CacheError> {
    let rules_total = r.u64()?;
    let rules_skipped = r.u64()?;
    let invalid_regex = r.u64()?;
    let invalid_pattern = r.u64()?;
    let not_applicable = r.u64()?;
    let entries: Vec<(String, u64)> = decode_vec(r, |r| Ok((r.string()?, r.u64()?)))?;
    let count = entries.len();
    let unsupported_modifier: BTreeMap<_, _> = entries.into_iter().collect();
    if unsupported_modifier.len() != count {
        return Err(CacheError::new(
            "Compiled filter cache has a duplicate report entry",
        ));
    }
    Ok(FilterLoadReport {
        rules_total,
        rules_skipped,
        unsupported_modifier,
        invalid_regex,
        invalid_pattern,
        not_applicable,
    })
}

fn encode_verdict(w: &mut Encoder<'_>, verdict: &FilterVerdict) -> Result<(), CacheError> {
    match verdict {
        FilterVerdict::Allow => w.u8(0),
        FilterVerdict::Block(response) => {
            w.u8(1);
            encode_block_response(w, response);
        }
        FilterVerdict::Rewrite(target) => {
            w.u8(2);
            encode_rewrite_target(w, target)?;
        }
        FilterVerdict::Drop => w.u8(3),
    }
    Ok(())
}

fn decode_verdict(r: &mut Decoder<'_>) -> Result<FilterVerdict, CacheError> {
    match r.u8()? {
        0 => Ok(FilterVerdict::Allow),
        1 => Ok(FilterVerdict::Block(decode_block_response(r)?)),
        2 => Ok(FilterVerdict::Rewrite(decode_rewrite_target(r)?)),
        3 => Ok(FilterVerdict::Drop),
        _ => Err(CacheError::new(
            "Invalid verdict type in compiled filter cache",
        )),
    }
}

fn encode_block_response(w: &mut Encoder<'_>, response: &BlockResponse) {
    match response {
        BlockResponse::NxDomain => w.u8(0),
        BlockResponse::ZeroIp => w.u8(1),
        BlockResponse::Refused => w.u8(2),
        BlockResponse::NoData => w.u8(3),
        BlockResponse::Custom { v4, v6 } => {
            w.u8(4);
            w.u8(u8::from(v4.is_some()));
            if let Some(ip) = v4 {
                w.write(&ip.octets());
            }
            w.u8(u8::from(v6.is_some()));
            if let Some(ip) = v6 {
                w.write(&ip.octets());
            }
        }
    }
}

fn decode_block_response(r: &mut Decoder<'_>) -> Result<BlockResponse, CacheError> {
    match r.u8()? {
        0 => Ok(BlockResponse::NxDomain),
        1 => Ok(BlockResponse::ZeroIp),
        2 => Ok(BlockResponse::Refused),
        3 => Ok(BlockResponse::NoData),
        4 => {
            let v4 = if r.boolean()? {
                Some(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(r.take(4)?).map_err(|_| {
                        CacheError::new("Invalid IPv4 address in compiled filter cache")
                    })?,
                ))
            } else {
                None
            };
            let v6 = if r.boolean()? {
                Some(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(r.take(16)?).map_err(|_| {
                        CacheError::new("Invalid IPv6 address in compiled filter cache")
                    })?,
                ))
            } else {
                None
            };
            Ok(BlockResponse::Custom { v4, v6 })
        }
        _ => Err(CacheError::new(
            "Invalid block response type in compiled filter cache",
        )),
    }
}

fn encode_rewrite_target(w: &mut Encoder<'_>, target: &RewriteTarget) -> Result<(), CacheError> {
    match target {
        RewriteTarget::Records(records) => {
            w.u8(0);
            encode_vec(w, records, encode_rdata)
        }
        RewriteTarget::Cname(name) => {
            w.u8(1);
            encode_name(w, name)
        }
    }
}

fn decode_rewrite_target(r: &mut Decoder<'_>) -> Result<RewriteTarget, CacheError> {
    match r.u8()? {
        0 => Ok(RewriteTarget::Records(decode_vec(r, decode_rdata)?)),
        1 => Ok(RewriteTarget::Cname(decode_name(r)?)),
        _ => Err(CacheError::new(
            "Invalid rewrite type in compiled filter cache",
        )),
    }
}

fn encode_name(w: &mut Encoder<'_>, name: &Name) -> Result<(), CacheError> {
    let mut wire = DnsWriter::new();
    name.encode(&mut wire);
    if wire.is_failed() {
        return Err(CacheError::new(
            "Could not encode a DNS name for the filter cache",
        ));
    }
    w.blob(&wire.buf, 255)
}

fn decode_name(r: &mut Decoder<'_>) -> Result<Name, CacheError> {
    let bytes = r.blob(255)?;
    let mut wire = DnsReader::new(bytes);
    let name = Name::parse(&mut wire)
        .map_err(|_| CacheError::new("Invalid DNS name in compiled filter cache"))?;
    if wire.remaining() != 0 {
        return Err(CacheError::new(
            "Invalid DNS name length in compiled filter cache",
        ));
    }
    Ok(name)
}

fn encode_rdata(w: &mut Encoder<'_>, rdata: &RData) -> Result<(), CacheError> {
    let mut wire = DnsWriter::new();
    rdata.encode(&mut wire);
    if wire.is_failed() {
        return Err(CacheError::new(
            "Could not encode record data for the filter cache",
        ));
    }
    w.u16(rdata.record_type().0);
    w.blob(&wire.buf, u16::MAX as usize)
}

fn decode_rdata(r: &mut Decoder<'_>) -> Result<RData, CacheError> {
    let rtype = RecordType(r.u16()?);
    let bytes = r.blob(u16::MAX as usize)?;
    let mut wire = DnsReader::new(bytes);
    let rdata = RData::parse(rtype, &mut wire, bytes.len())
        .map_err(|_| CacheError::new("Invalid record data in compiled filter cache"))?;
    if wire.remaining() != 0 || rdata.record_type() != rtype {
        return Err(CacheError::new(
            "Invalid record data length or format in compiled filter cache",
        ));
    }
    Ok(rdata)
}

/// Prefixed with a presence flag.
fn encode_option<T>(
    w: &mut Encoder<'_>,
    value: Option<&T>,
    encode: impl FnOnce(&mut Encoder<'_>, &T) -> Result<(), CacheError>,
) -> Result<(), CacheError> {
    match value {
        Some(value) => {
            w.u8(1);
            encode(w, value)
        }
        None => {
            w.u8(0);
            Ok(())
        }
    }
}

fn decode_option<T>(
    r: &mut Decoder<'_>,
    decode: impl FnOnce(&mut Decoder<'_>) -> Result<T, CacheError>,
) -> Result<Option<T>, CacheError> {
    match r.u8()? {
        0 => Ok(None),
        1 => decode(r).map(Some),
        _ => Err(CacheError::new(
            "Invalid option tag in compiled filter cache",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_core::{ClientInfo, FilterEngine, Transport};

    fn client() -> ClientInfo {
        ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    fn verdict(parts: EngineParts, name: &str, rtype: RecordType) -> String {
        let engine = crate::BlockEngine::new(parts, BlockResponse::NxDomain);
        let name = Name::from_str(name).unwrap();
        format!("{:?}", engine.verdict(&name, rtype, &client()))
    }

    #[test]
    fn engine_cache_roundtrip_preserves_domain_and_typed_verdicts() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix_src("blocked.example", 0);
        parts.allow.add_exact_src("ok.blocked.example", 1);
        let mut typed = DomainSet::default();
        typed.add_suffix("typed.example");
        parts.typed_block.push((RecordType::AAAA, typed));
        parts.regex_allow.push("^safe\\.".into());
        parts.sources = vec!["block.txt".into(), "allow.txt".into()];
        parts.report.rules_total = 3;

        let fingerprint = [7; 32];
        let encoded = encode_engine_cache(&mut parts, fingerprint).unwrap();
        assert_eq!(&encoded[8..12], &tag_of(LAYOUT));
        let restored = decode_engine_cache(&encoded, fingerprint).unwrap();
        assert_eq!(
            verdict(restored, "typed.example", RecordType::AAAA),
            "Block(NxDomain)"
        );

        let restored = decode_engine_cache(&encoded, fingerprint).unwrap();
        assert_eq!(
            verdict(restored, "ok.blocked.example", RecordType::A),
            "Allow"
        );
    }

    #[test]
    /// If they were dropped or read into another set, a restarted server would answer names it was
    /// told not to answer.
    fn engine_cache_roundtrip_keeps_noresponse_rules() {
        let mut parts = EngineParts::default();
        parts.no_response.add_suffix_src("quiet.example", 0);
        parts.regex_no_response.push("^scan[0-9]+\\.".into());
        parts.rpz_ip.push(RpzIpRule::new(
            "192.0.2.0/24".parse().unwrap(),
            FilterVerdict::Drop,
        ));
        parts.sources = vec!["quiet.txt".into()];

        let encoded = encode_engine_cache(&mut parts, [4; 32]).unwrap();
        let restored = decode_engine_cache(&encoded, [4; 32]).unwrap();
        assert!(
            matches!(
                restored.rpz_ip.first().map(|rule| &rule.verdict),
                Some(FilterVerdict::Drop)
            ),
            "무응답 판정이 왕복에서 바뀌었습니다"
        );
        let engine = crate::BlockEngine::new(restored, BlockResponse::NxDomain);
        let ask = |q: &str| engine.explain(&Name::from_str(q).unwrap(), RecordType::A, &client());
        let quiet = ask("www.quiet.example");
        assert!(matches!(quiet.verdict, FilterVerdict::Drop), "{quiet:?}");
        assert_eq!(quiet.source.as_deref(), Some("quiet.txt"));
        assert!(matches!(ask("scan9.example").verdict, FilterVerdict::Drop));
        assert!(
            matches!(ask("other.example").verdict, FilterVerdict::Allow),
            "대조군이 무효입니다: 규칙에 없는 이름이 막혔습니다"
        );
    }

    #[test]
    /// Moving one would misread files written earlier.
    fn encoded_header_fields_sit_at_pinned_offsets() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");
        let fingerprint = [0x5a; 32];
        let encoded = encode_engine_cache(&mut parts, fingerprint).unwrap();

        assert_eq!(&encoded[..8], MAGIC.as_slice());
        assert_eq!(&encoded[8..12], &tag_of(LAYOUT));
        assert_eq!(&encoded[12..44], &fingerprint);
        let payload_len = u64::from_le_bytes(encoded[44..52].try_into().unwrap()) as usize;
        assert_eq!(payload_len, encoded.len() - HEADER_BYTES);
        let digest: [u8; 32] = Sha256::digest(&encoded[HEADER_BYTES..]).into();
        assert_eq!(&encoded[52..HEADER_BYTES], &digest);
    }

    #[test]
    /// With a different layout the same bytes would be read as different arrays, so the cache is
    /// rejected and rebuilt instead.
    fn cache_written_with_another_layout_is_rejected() {
        let fingerprint = [0x5a; 32];
        let encoded = encode_engine_cache(&mut EngineParts::default(), fingerprint).unwrap();
        let mut tampered = encoded.clone();
        tampered[8] ^= 0xff;
        assert!(
            decode_engine_cache(&tampered, fingerprint).is_err(),
            "다른 배치로 적힌 캐시를 받아들였습니다"
        );
        assert!(decode_engine_cache(&encoded, fingerprint).is_ok());
    }

    #[test]
    /// Otherwise the hash would not match.
    fn streaming_cache_is_byte_identical_to_the_in_memory_encoder() {
        fn parts() -> EngineParts {
            let mut parts = EngineParts::default();
            parts.block.add_suffix_src("blocked.example", 7);
            parts.allow.add_exact_src("safe.blocked.example", 3);
            let mut typed = DomainSet::default();
            typed.add_suffix("typed.example");
            parts.typed_block.push((RecordType::AAAA, typed));
            let mut typed_except = DomainSet::default();
            typed_except.add_exact("except.example");
            parts
                .typed_block_except
                .push((vec![RecordType::A, RecordType::AAAA], typed_except));
            parts.regex_block.push("^ads[0-9]+\\.".into());
            parts.no_response.add_suffix_src("quiet.example", 7);
            parts.regex_no_response.push("^scan[0-9]+\\.".into());
            parts.rpz_ip.push(RpzIpRule::new(
                "192.0.2.0/24".parse().unwrap(),
                FilterVerdict::Block(BlockResponse::Custom {
                    v4: Some("192.0.2.1".parse().unwrap()),
                    v6: Some("2001:db8::1".parse().unwrap()),
                }),
            ));
            parts.sources = vec!["block.txt".into(), "allow.txt".into()];
            parts
        }

        let fingerprint = [0x3c; 32];
        let expected = encode_engine_cache(&mut parts(), fingerprint).unwrap();
        let mut streamed = std::io::Cursor::new(Vec::new());
        write_engine_cache(&mut parts(), fingerprint, &mut streamed).unwrap();
        assert_eq!(streamed.into_inner(), expected);
    }

    #[test]
    /// Swallowing it would leave a broken file.
    fn streaming_cache_propagates_output_failure() {
        struct FailingWriter {
            inner: std::io::Cursor<Vec<u8>>,
            remaining: usize,
        }

        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "injected cache write failure",
                    ));
                }
                let count = bytes.len().min(self.remaining);
                self.remaining -= count;
                self.inner.write(&bytes[..count])
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        impl Seek for FailingWriter {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                self.inner.seek(position)
            }
        }

        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");
        let mut output = FailingWriter {
            inner: std::io::Cursor::new(Vec::new()),
            remaining: HEADER_BYTES + 8,
        };
        assert!(matches!(
            write_engine_cache(&mut parts, [7; 32], &mut output),
            Err(CacheWriteError::Io(_))
        ));
    }

    #[test]
    fn engine_cache_rejects_wrong_input_truncation_and_every_single_byte_corruption() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");
        let fingerprint = [3; 32];
        let encoded = encode_engine_cache(&mut parts, fingerprint).unwrap();
        assert!(decode_engine_cache(&encoded, [4; 32]).is_err());
        for end in 0..encoded.len() {
            assert!(decode_engine_cache(&encoded[..end], fingerprint).is_err());
        }
        for index in 0..encoded.len() {
            let mut damaged = encoded.clone();
            damaged[index] ^= 0x5a;
            assert!(decode_engine_cache(&damaged, fingerprint).is_err());
        }
    }

    #[test]
    fn engine_cache_rejects_over_limit_content_at_encode_time() {
        let mut parts = EngineParts::default();
        parts.sources = vec!["x".repeat(MAX_STRING_BYTES + 1)];
        assert!(encode_engine_cache(&mut parts, [1; 32]).is_err());

        let mut parts = EngineParts::default();
        parts.regex_block = vec![String::new(); MAX_ITEMS + 1];
        assert!(encode_engine_cache(&mut parts, [1; 32]).is_err());

        let mut parts = EngineParts::default();
        parts.sources = vec!["x".repeat(MAX_STRING_BYTES)];
        let encoded = encode_engine_cache(&mut parts, [1; 32]).unwrap();
        assert!(decode_engine_cache(&encoded, [1; 32]).is_ok());
    }

    #[test]
    fn engine_cache_roundtrips_rewrites_clients_rpz_and_report() {
        let mut parts = EngineParts::default();
        parts.rewrites.add_exact(
            "rewrite.example",
            RewriteTarget::ip("192.0.2.1".parse::<std::net::IpAddr>().unwrap()),
        );
        parts.regex_rewrites.push((
            "^alias\\.".into(),
            RewriteTarget::Cname(Name::from_str("target.example").unwrap()),
        ));
        parts.client_rules.push(ClientRule {
            domain: "clients.example".into(),
            allow: true,
            clients: vec![ClientCond::Net {
                negated: false,
                net: "127.0.0.0/8".parse().unwrap(),
            }],
            ctags: vec![(false, "trusted".into())],
            denyallow: vec!["deny.clients.example".into()],
            ..ClientRule::default()
        });
        parts.rpz_client_ip.push(RpzIpRule::new(
            "127.0.0.0/8".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::Refused),
        ));
        parts
            .rpz_nsdname
            .push(RpzNameRule::new("ns.example", FilterVerdict::Allow).unwrap());
        parts.report.unsupported_modifier.insert("foo".into(), 2);
        for (zone, action) in [
            ("corp.example", LocalZoneAction::Deny),
            ("api.corp.example", LocalZoneAction::Transparent),
            ("lan", LocalZoneAction::Refuse),
            (
                "static.example",
                LocalZoneAction::Rewrite(RewriteTarget::Cname(
                    Name::from_str("target.example").unwrap(),
                )),
            ),
        ] {
            parts.local_zones.insert(zone, action).unwrap();
        }
        let mut listed = StaticZone::new("hosts.example");
        listed
            .insert(
                "www.hosts.example",
                RewriteTarget::Records(vec![RData::A("192.0.2.7".parse().unwrap())]),
            )
            .unwrap();
        listed
            .insert(
                "mail.dept.hosts.example",
                RewriteTarget::Cname(Name::from_str("www.hosts.example").unwrap()),
            )
            .unwrap();
        parts
            .local_zones
            .insert("hosts.example", LocalZoneAction::Static(listed))
            .unwrap();

        let encoded = encode_engine_cache(&mut parts, [9; 32]).unwrap();
        let restored = decode_engine_cache(&encoded, [9; 32]).unwrap();
        assert_eq!(restored.rewrites.len(), 1);
        assert_eq!(restored.regex_rewrites.len(), 1);
        assert_eq!(restored.client_rules.len(), 1);
        assert_eq!(restored.rpz_client_ip.len(), 1);
        assert_eq!(restored.rpz_nsdname.len(), 1);
        assert_eq!(restored.report.unsupported_modifier.get("foo"), Some(&2));
        // Static zones are a hash map, so Debug order varies; compare sorted by name.
        let canonical = |set: &LocalZoneSet| {
            let mut out: Vec<_> = set
                .iter()
                .map(|(zone, action)| {
                    let text = match action {
                        LocalZoneAction::Static(data) => {
                            let mut names: Vec<_> = data
                                .iter()
                                .map(|(name, target)| format!("{name}={target:?}"))
                                .collect();
                            names.sort();
                            format!("Static{names:?}")
                        }
                        other => format!("{other:?}"),
                    };
                    (zone.to_string(), text)
                })
                .collect();
            out.sort();
            out
        };
        let zones = canonical(&restored.local_zones);
        assert_eq!(zones, canonical(&parts.local_zones));
        assert_eq!(zones.len(), 5);
        let Some((_, LocalZoneAction::Static(data))) = restored
            .local_zones
            .iter()
            .find(|(zone, _)| *zone == "hosts.example")
        else {
            panic!("static 영역이 복원되지 않았습니다");
        };
        assert!(matches!(
            data.answer("dept.hosts.example"),
            crate::engine::StaticAnswer::NoData
        ));
    }

    #[test]
    /// The header hash would stop a plain mutation before the payload parser, so each mutation is
    /// resealed to reach the real parser. The acceptance rate is also checked to be nonzero, so
    /// mutations that are too strict cannot silently disarm the test.
    fn cache_decoder_never_panics_on_resealed_mutations() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix_src("blocked.example", 0);
        parts.block.add_exact_src("exact.blocked.example", 1);
        parts.allow.add_exact_src("ok.blocked.example", 1);
        parts.regex_block.push("^ad[0-9]+\\.".into());
        parts.regex_allow.push("^safe\\.".into());
        let mut typed = DomainSet::default();
        typed.add_suffix("typed.example");
        parts.typed_block.push((RecordType::AAAA, typed));
        parts.rewrites.add_exact(
            "rewrite.example",
            RewriteTarget::ip("192.0.2.1".parse::<std::net::IpAddr>().unwrap()),
        );
        parts.regex_rewrites.push((
            "^alias\\.".into(),
            RewriteTarget::Cname(Name::from_str("target.example").unwrap()),
        ));
        parts.client_rules.push(ClientRule {
            domain: "clients.example".into(),
            allow: true,
            clients: vec![ClientCond::Net {
                negated: false,
                net: "127.0.0.0/8".parse().unwrap(),
            }],
            ctags: vec![(false, "trusted".into())],
            denyallow: vec!["deny.clients.example".into()],
            ..ClientRule::default()
        });
        parts.rpz_client_ip.push(RpzIpRule::new(
            "127.0.0.0/8".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::Refused),
        ));
        parts
            .rpz_nsdname
            .push(RpzNameRule::new("ns.example", FilterVerdict::Allow).unwrap());
        parts.sources = vec!["block.txt".into(), "allow.txt".into()];
        parts.report.rules_total = 9;
        parts.report.unsupported_modifier.insert("foo".into(), 2);

        let fingerprint = [0x33; 32];
        let seed = encode_engine_cache(&mut parts, fingerprint).expect("시드 캐시 인코딩");

        let reseal = |body: &[u8]| -> Vec<u8> {
            let mut out = Vec::with_capacity(HEADER_BYTES + body.len());
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&tag_of(LAYOUT));
            out.extend_from_slice(&fingerprint);
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            out.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(body)));
            out.extend_from_slice(body);
            out
        };

        let iters = std::env::var("ONETDNS_SWEEP_ITERS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| (value / 200).clamp(1, 20_000))
            .unwrap_or(200);

        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0u64;
        for _ in 0..iters {
            let mut body = seed[HEADER_BYTES..].to_vec();

            let index = (next() % body.len() as u64) as usize;
            match next() % 10 {
                0..=4 => body[index] = (next() & 0xff) as u8,
                5..=7 => body[index] ^= 1 << (next() % 8),
                8 => body.insert(index, (next() & 0xff) as u8),
                _ => body.truncate(index),
            }
            let encoded = reseal(&body);
            if let Ok(restored) = decode_engine_cache(&encoded, fingerprint) {
                accepted += 1;
                let engine = crate::BlockEngine::new(restored, BlockResponse::NxDomain);
                for name in [
                    "blocked.example",
                    "deep.sub.blocked.example",
                    "ok.blocked.example",
                    "ad12.example",
                    "typed.example",
                    "rewrite.example",
                    "alias.example",
                    "clients.example",
                ] {
                    let Ok(name) = Name::from_str(name) else {
                        continue;
                    };
                    let _ = engine.verdict(&name, RecordType::A, &client());
                    let _ = engine.verdict(&name, RecordType::AAAA, &client());
                }
            }

            let mut header_damaged = seed.clone();
            let index = (next() % HEADER_BYTES as u64) as usize;
            header_damaged[index] ^= 1 << (next() % 8);
            assert!(decode_engine_cache(&header_damaged, fingerprint).is_err());
        }

        assert!(
            accepted > 0,
            "재봉인한 변형 {iters}건 중 {accepted}건 복원: 본문 파서 노출 확인"
        );
    }

    const PARSED_RULES: &str = "\
||ads.example^
||tracker.ads.example^
0.0.0.0 é.example ©.example
||typed.example^$dnstype=AAAA
||except.example^$dnstype=~A
@@||allowed.example^
||rewrite.example^$dnsrewrite=192.0.2.1
||cancel.example^$badfilter
||weird.example^$app=org.example
";

    fn parsed(text: &str) -> ParsedList {
        ParsedList::parse(false, |on_line| {
            text.lines().for_each(on_line);
            Ok(())
        })
        .unwrap()
    }

    fn encode_list(list: &ParsedList, key: [u8; 32]) -> Vec<u8> {
        let mut file = std::io::Cursor::new(Vec::new());
        write_parsed_list(list, key, &mut file).unwrap();
        file.into_inner()
    }

    fn describe_list(list: &ParsedList) -> String {
        let sets: Vec<String> = list
            .sets
            .iter()
            .map(|(slot, set)| {
                let names = |run: &KeyRun| run.names().map(str::to_owned).collect::<Vec<_>>();
                format!(
                    "{:?} {:?} {:?}",
                    encode_slot_bytes(slot),
                    names(&set.exact),
                    names(&set.suffix)
                )
            })
            .collect();
        format!(
            "{sets:?} {:?} {}",
            list.other_lines,
            crate::engine::FilterLoadReport::to_json(&list.report)
        )
    }

    fn encode_slot_bytes(slot: &Slot) -> Vec<u8> {
        let mut w = Encoder::default();
        encode_slot(&mut w, slot).unwrap();
        w.bytes
    }

    #[test]
    fn parsed_list_roundtrips_names_slots_lines_and_report() {
        let list = parsed(PARSED_RULES);
        assert!(list.sets.len() >= 4);
        assert_eq!(list.other_lines.len(), 2);
        let encoded = encode_list(&list, [7; 32]);
        let restored = decode_parsed_list(&encoded, [7; 32]).unwrap();
        assert!(matches!(restored.sets[0].1.suffix, KeyRun::Stored { .. }));
        assert_eq!(describe_list(&restored), describe_list(&list));
    }

    #[test]
    fn parsed_list_rejects_wrong_key_truncation_and_every_single_byte_corruption() {
        let encoded = encode_list(&parsed(PARSED_RULES), [7; 32]);
        assert!(decode_parsed_list(&encoded, [8; 32]).is_err());
        let mut engine_magic = encoded.clone();
        engine_magic[..8].copy_from_slice(MAGIC);
        assert!(decode_parsed_list(&engine_magic, [7; 32]).is_err());
        for end in 0..encoded.len() {
            assert!(decode_parsed_list(&encoded[..end], [7; 32]).is_err());
        }
        for index in 0..encoded.len() {
            let mut damaged = encoded.clone();
            damaged[index] ^= 0x5a;
            assert!(decode_parsed_list(&damaged, [7; 32]).is_err());
        }
    }

    #[test]
    /// The automaton builder trusts its input order, so a sealed file must not get past it.
    fn sealed_parsed_list_with_names_out_of_order_is_rejected() {
        let mut list = parsed("||b.example^\n||a.example^\n");
        let (_, set) = &mut list.sets[0];
        let mut names: Vec<String> = set.suffix.names().map(str::to_owned).collect();
        names.reverse();
        let mut joined = String::new();
        let mut offsets = vec![0];
        for name in &names {
            joined.push_str(name);
            offsets.push(joined.len() as u32);
        }
        set.suffix = KeyRun::Stored {
            names: joined,
            offsets,
        };
        let encoded = encode_list(&list, [1; 32]);
        assert!(decode_parsed_list(&encoded, [1; 32]).is_err());
    }

    #[test]
    fn parsed_list_decoder_never_panics_on_resealed_mutations() {
        let key = [0x44; 32];
        let seed = encode_list(&parsed(PARSED_RULES), key);
        let reseal = |body: &[u8]| -> Vec<u8> {
            let mut out = seal(
                LIST_MAGIC,
                LIST_LAYOUT,
                key,
                body.len(),
                Sha256::digest(body).into(),
            )
            .to_vec();
            out.extend_from_slice(body);
            out
        };
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut accepted = 0u64;
        for _ in 0..2000 {
            let mut body = seed[HEADER_BYTES..].to_vec();
            let index = (next() % body.len() as u64) as usize;
            match next() % 10 {
                0..=4 => body[index] = (next() & 0xff) as u8,
                5..=7 => body[index] ^= 1 << (next() % 8),
                8 => body.insert(index, (next() & 0xff) as u8),
                _ => body.truncate(index),
            }
            if let Ok(restored) = decode_parsed_list(&reseal(&body), key) {
                accepted += 1;
                for (_, set) in &restored.sets {
                    for run in [&set.exact, &set.suffix] {
                        let names: Vec<&str> = run.names().collect();
                        assert!(names
                            .windows(2)
                            .all(|pair| crate::compact::reverse_cmp(pair[0], pair[1]).is_lt()));
                    }
                }
            }
        }
        assert!(accepted > 0, "{accepted} of the mutations decoded");
    }
}
