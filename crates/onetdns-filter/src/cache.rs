/*!
 * @brief 컴파일된 필터 집합을 디스크에 담고 되읽는다.
 *
 * @details 목록을 다시 파싱하는 데는 수십 초가 걸린다. 한 번 만든 집합을 그대로 담아
 *          두면 재시작이 그만큼 빨라진다.
 * @warning 이 파일은 신뢰 입력이 아니다. 헤더에 입력 지문과 본문 해시가 있어 조작을
 *          걸러 내지만, 그 안쪽 파서도 어떤 바이트에도 패닉하지 않아야 한다.
 * @note 되읽을 때 무엇을 확인하느냐가 곧 안전성이다. 엣지 순서, 도달 가능성, 순환,
 *       부분 순위와 오토마톤에서 재구성한 모든 이름을 전부 본다.
 */

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

/** @brief 파일 식별자. */
const MAGIC: &[u8; 8] = b"ONETFST\0";

/**
 * @brief 저장 배치를 적은 글. 배열 구성이 바뀌면 이 글도 함께 바꾼다.
 * @details 올려야 하는 번호를 두지 않는다. 이 글의 해시를 헤더에 적고 읽을 때 대조하므로,
 *          배치를 바꾸면서 이 글을 고치면 예전에 만든 파일은 저절로 거부되고 다시 만들어진다.
 *          캐시는 언제든 다시 만들 수 있는 파생물이라 옮겨 읽을 이유가 없다.
 */
const LAYOUT: &str = "states:edge_starts+terminal_bits|edges:labels,targets,outputs|sources";

/** @brief 저장 배치를 가리키는 값. LAYOUT 해시의 앞 네 바이트다. */
fn layout_tag() -> [u8; 4] {
    let digest: [u8; 32] = Sha256::digest(LAYOUT.as_bytes()).into();
    [digest[0], digest[1], digest[2], digest[3]]
}

/** @brief 헤더 크기. 식별자, 배치 표시, 지문, 길이, 해시를 담는다. */
const HEADER_BYTES: usize = 8 + 4 + 32 + 8 + 32;
/** @brief 목록 하나의 항목 수 상한. */
const MAX_ITEMS: usize = 5_000_000;
/** @brief 문자열 하나의 길이 상한. */
const MAX_STRING_BYTES: usize = 64 * 1024 * 1024;

/** @brief 캐시 파일 전체 크기 상한. */
pub const MAX_CACHE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 캐시 해석 실패. 사유는 진단용이며 파일은 전체를 버린다. */
pub struct CacheError(&'static str);

impl CacheError {
    /** @brief 오류를 만든다. */
    fn new(message: &'static str) -> Self {
        Self(message)
    }
}

impl fmt::Display for CacheError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CacheError {}

#[derive(Debug)]
/** @brief 캐시 쓰기 실패. */
pub enum CacheWriteError {
    /** @brief 저장 형식이 어긋났다. */
    Cache(CacheError),
    /** @brief 파일을 읽고 쓰지 못했다. */
    Io(std::io::Error),
}

impl fmt::Display for CacheWriteError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cache(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CacheWriteError {
    /** @brief 이 오류를 일으킨 원래 오류. */
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cache(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<CacheError> for CacheWriteError {
    /** @brief 저장 오류를 감싼다. */
    fn from(error: CacheError) -> Self {
        Self::Cache(error)
    }
}

impl From<std::io::Error> for CacheWriteError {
    /** @brief 입출력 오류를 감싼다. */
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/** @brief 엔진을 메모리 안에서 전부 인코딩한다. */
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
    output[..8].copy_from_slice(MAGIC);
    output[8..12].copy_from_slice(&layout_tag());
    output[12..44].copy_from_slice(&input_fingerprint);
    output[44..52].copy_from_slice(&(payload_len as u64).to_le_bytes());
    output[52..HEADER_BYTES].copy_from_slice(&payload_digest);
    Ok(output)
}

/**
 * @brief 엔진을 스트림으로 흘려 쓴다.
 * @details 전체를 메모리에 담지 않는다. 필터 집합이 수백 메가일 수 있어, 전부 만들면
 *          저장하는 순간 메모리 사용이 두 배가 된다.
 */
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

    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&layout_tag());
    header[12..44].copy_from_slice(&input_fingerprint);
    header[44..52].copy_from_slice(&(payload_len as u64).to_le_bytes());
    header[52..].copy_from_slice(&payload_digest);
    output.seek(SeekFrom::Start(0))?;
    output.write_all(&header)?;
    output.seek(SeekFrom::End(0))?;
    Ok(())
}

/** @brief 흘려 쓸 때 쓰는 버퍼 크기. */
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/** @brief 본문을 흘려 쓰며 해시를 함께 계산하는 것. */
struct PayloadStream<'a, W> {
    /** @brief 실제로 쓸 곳. */
    output: &'a mut W,
    /** @brief 흘려보내며 함께 계산하는 요약값. */
    digest: Sha256,
    /** @brief 모아 두었다 한꺼번에 쓰는 버퍼. */
    buffer: Vec<u8>,
    /** @brief 지금까지 흘려보낸 바이트. */
    len: usize,
    /** @brief 쓰다 난 오류. 한 번 나면 이후는 버린다. */
    error: Option<std::io::Error>,
    /** @brief 담을 수 있는 크기를 넘겼는지. */
    overflowed: bool,
}

impl<'a, W: Write> PayloadStream<'a, W> {
    /** @brief 출력 대상으로 만든다. */
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

    /** @brief 버퍼를 거쳐 쓴다. */
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

    /** @brief 큰 청크는 버퍼를 거치지 않고 바로 쓴다. */
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

    /** @brief 버퍼를 비운다. */
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

    /** @brief 16비트 값을 쓴다. */
    fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    /** @brief 길이를 쓴다. 상한을 넘으면 실패다. */
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

    /** @brief 남은 것을 비우고 총 길이와 해시를 돌려준다. */
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

/**
 * @brief 캐시 파일을 되읽는다.
 * @warning 헤더의 지문이 지금 입력과 맞고 본문 해시도 맞아야 한다. 어느 하나라도 어긋나면
 *          파일을 버리고 목록을 다시 파싱한다.
 */
pub fn decode_engine_cache(
    encoded: &[u8],
    expected_fingerprint: [u8; 32],
) -> Result<EngineParts, CacheError> {
    if encoded.len() < HEADER_BYTES || encoded.len() > MAX_CACHE_BYTES {
        return Err(CacheError::new(
            "Compiled filter cache file size is invalid",
        ));
    }
    if encoded.get(..8) != Some(MAGIC.as_slice()) {
        return Err(CacheError::new(
            "Compiled filter cache file magic does not match",
        ));
    }
    if encoded[8..12] != layout_tag() {
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
/** @brief 값들을 와이어 형태로 쓰는 것. */
struct Encoder<'a> {
    /** @brief 적어 넣을 바이트. */
    bytes: Vec<u8>,
    /** @brief 전부 잡지 않고 조각마다 넘길 곳. */
    chunks: Option<&'a mut dyn FnMut(&[u8])>,
}

impl<'a> Encoder<'a> {
    /** @brief 청크를 넘겨받는 함수로 스트리밍하는 인코더. */
    fn streaming(chunks: &'a mut dyn FnMut(&[u8])) -> Self {
        Self {
            bytes: Vec::new(),
            chunks: Some(chunks),
        }
    }

    /** @brief 바이트를 쓴다. */
    fn write(&mut self, bytes: &[u8]) {
        if let Some(chunks) = &mut self.chunks {
            chunks(bytes);
        } else {
            self.bytes.extend_from_slice(bytes);
        }
    }

    /** @brief 8비트 값. */
    fn u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    /** @brief 16비트 값. */
    fn u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    /** @brief 32비트 값. */
    fn u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    /** @brief 64비트 값. */
    fn u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    /** @brief 길이. 상한을 넘으면 실패다. */
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

    /** @brief 길이 접두사 있는 바이트열. */
    fn blob(&mut self, value: &[u8], max: usize) -> Result<(), CacheError> {
        self.len(value.len(), max)?;
        self.write(value);
        Ok(())
    }

    /** @brief 길이 접두사 있는 문자열. */
    fn string(&mut self, value: &str) -> Result<(), CacheError> {
        self.blob(value.as_bytes(), MAX_STRING_BYTES)
    }
}

/** @brief 와이어 형태를 값으로 읽는 것. 모든 읽기가 경계를 검사한다. */
struct Decoder<'a> {
    /** @brief 읽어 들일 바이트. */
    input: &'a [u8],
}

impl<'a> Decoder<'a> {
    /** @brief 바이트열로 디코더를 만든다. */
    fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /** @brief 정해진 길이만큼 가져온다. 모자라면 오류다. */
    fn take(&mut self, count: usize) -> Result<&'a [u8], CacheError> {
        let (head, tail) = self
            .input
            .split_at_checked(count)
            .ok_or_else(|| CacheError::new("Compiled filter cache is truncated"))?;
        self.input = tail;
        Ok(head)
    }

    /** @brief 8비트 값. */
    fn u8(&mut self) -> Result<u8, CacheError> {
        Ok(self.take(1)?[0])
    }

    /** @brief 16비트 값. */
    fn u16(&mut self) -> Result<u16, CacheError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(
            |_| CacheError::new("Could not read a 16-bit integer from the compiled filter cache"),
        )?))
    }

    /** @brief 32비트 값. */
    fn u32(&mut self) -> Result<u32, CacheError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| CacheError::new("Could not read a 32-bit integer from the compiled filter cache"),
        )?))
    }

    /** @brief 64비트 값. */
    fn u64(&mut self) -> Result<u64, CacheError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| CacheError::new("Could not read a 64-bit integer from the compiled filter cache"),
        )?))
    }

    /** @brief 길이. 상한을 넘으면 오류다. */
    fn len(&mut self, max: usize) -> Result<usize, CacheError> {
        let value = self.u32()? as usize;
        if value > max {
            return Err(CacheError::new(
                "Compiled filter cache has too many entries",
            ));
        }
        Ok(value)
    }

    /** @brief 바이트열. */
    fn blob(&mut self, max: usize) -> Result<&'a [u8], CacheError> {
        let len = self.len(max)?;
        self.take(len)
    }

    /** @brief 문자열. UTF-8이 아니면 오류다. */
    fn string(&mut self) -> Result<String, CacheError> {
        let bytes = self.blob(MAX_STRING_BYTES)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| CacheError::new("Invalid string in compiled filter cache"))?;
        Ok(value.to_owned())
    }

    /** @brief 참거짓. 0과 1 외의 값은 오류다. */
    fn boolean(&mut self) -> Result<bool, CacheError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CacheError::new("Invalid boolean in compiled filter cache")),
        }
    }
}

/** @brief 엔진 구성 전체를 쓴다. */
fn encode_parts(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    encode_domain_sets(w, parts)?;
    encode_parts_tail(w, parts)
}

/** @brief 도메인 집합들을 쓴다. */
fn encode_domain_sets(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    for set in [
        &parts.block,
        &parts.allow,
        &parts.block_important,
        &parts.allow_important,
        &parts.refuse,
        &parts.nodata,
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

/** @brief 도메인 집합들을 흘려 쓴다. 가장 큰 부분이라 메모리에 담지 않는다. */
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

/** @brief 도메인 집합을 뺀 나머지를 쓴다. */
fn encode_parts_tail(w: &mut Encoder<'_>, parts: &EngineParts) -> Result<(), CacheError> {
    for strings in [
        &parts.regex_block,
        &parts.regex_allow,
        &parts.regex_block_important,
        &parts.regex_allow_important,
        &parts.regex_refuse,
        &parts.regex_nodata,
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

/** @brief 엔진 구성 전체를 읽는다. */
fn decode_parts(r: &mut Decoder<'_>) -> Result<EngineParts, CacheError> {
    let block = decode_domain_set(r)?;
    let allow = decode_domain_set(r)?;
    let block_important = decode_domain_set(r)?;
    let allow_important = decode_domain_set(r)?;
    let refuse = decode_domain_set(r)?;
    let nodata = decode_domain_set(r)?;
    let typed_block = decode_vec(r, |r| Ok((RecordType(r.u16()?), decode_domain_set(r)?)))?;
    let typed_block_except =
        decode_vec(r, |r| Ok((decode_record_types(r)?, decode_domain_set(r)?)))?;
    let regex_block = decode_strings(r)?;
    let regex_allow = decode_strings(r)?;
    let regex_block_important = decode_strings(r)?;
    let regex_allow_important = decode_strings(r)?;
    let regex_refuse = decode_strings(r)?;
    let regex_nodata = decode_strings(r)?;
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
        typed_block,
        typed_block_except,
        regex_block,
        regex_allow,
        regex_block_important,
        regex_allow_important,
        regex_refuse,
        regex_nodata,
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

/** @brief 목록 하나를 쓴다. */
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

/** @brief 목록 하나를 읽는다. */
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

/** @brief 도메인 집합 하나를 읽는다. */
fn decode_domain_set(r: &mut Decoder<'_>) -> Result<DomainSet, CacheError> {
    DomainSet::decode_compact(&mut r.input).map_err(CacheError::new)
}

/** @brief 문자열 목록을 쓴다. */
fn encode_strings(w: &mut Encoder<'_>, values: &[String]) -> Result<(), CacheError> {
    encode_vec(w, values, |w, value| w.string(value))
}

/** @brief 문자열 목록을 읽는다. */
fn decode_strings(r: &mut Decoder<'_>) -> Result<Vec<String>, CacheError> {
    decode_vec(r, |r| r.string())
}

/** @brief 레코드 타입 목록을 쓴다. */
fn encode_record_types(w: &mut Encoder<'_>, types: &[RecordType]) -> Result<(), CacheError> {
    w.len(types.len(), MAX_ITEMS)?;
    for rtype in types {
        w.u16(rtype.0);
    }
    Ok(())
}

/** @brief 레코드 타입 목록을 읽는다. */
fn decode_record_types(r: &mut Decoder<'_>) -> Result<Vec<RecordType>, CacheError> {
    decode_vec(r, |r| Ok(RecordType(r.u16()?)))
}

/** @brief 재작성 집합을 쓴다. */
fn encode_rewrite_set(w: &mut Encoder<'_>, set: &RewriteSet) -> Result<(), CacheError> {
    encode_rewrite_map(w, &set.exact)?;
    encode_rewrite_map(w, &set.suffix)
}

/** @brief 재작성 맵을 쓴다. */
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

/** @brief 재작성 집합을 읽는다. */
fn decode_rewrite_set(r: &mut Decoder<'_>) -> Result<RewriteSet, CacheError> {
    Ok(RewriteSet {
        exact: decode_rewrite_map(r)?,
        suffix: decode_rewrite_map(r)?,
    })
}

/** @brief 재작성 맵을 읽는다. */
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

/** @brief 로컬 영역을 이름 순으로 쓴다. 같은 설정이면 같은 바이트가 나와야 한다. */
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

/** @brief 로컬 영역을 읽는다. */
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

/** @brief 클라이언트 규칙 하나를 쓴다. */
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

/** @brief 클라이언트 규칙 하나를 읽는다. */
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

/** @brief RPZ 주소 규칙을 쓴다. */
fn encode_rpz_ip(w: &mut Encoder<'_>, rule: &RpzIpRule) -> Result<(), CacheError> {
    w.string(&rule.net.to_string())?;
    w.string(&rule.display)?;
    encode_verdict(w, &rule.verdict)
}

/** @brief RPZ 주소 규칙을 읽는다. */
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

/** @brief 로드 보고를 쓴다. */
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

/** @brief 로드 보고를 읽는다. */
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

/** @brief 판정을 쓴다. */
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
    }
    Ok(())
}

/** @brief 판정을 읽는다. 모르는 종류면 오류다. */
fn decode_verdict(r: &mut Decoder<'_>) -> Result<FilterVerdict, CacheError> {
    match r.u8()? {
        0 => Ok(FilterVerdict::Allow),
        1 => Ok(FilterVerdict::Block(decode_block_response(r)?)),
        2 => Ok(FilterVerdict::Rewrite(decode_rewrite_target(r)?)),
        _ => Err(CacheError::new(
            "Invalid verdict type in compiled filter cache",
        )),
    }
}

/** @brief 차단 응답 방식을 쓴다. */
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

/** @brief 차단 응답 방식을 읽는다. */
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

/** @brief 재작성 대상을 쓴다. */
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

/** @brief 재작성 대상을 읽는다. */
fn decode_rewrite_target(r: &mut Decoder<'_>) -> Result<RewriteTarget, CacheError> {
    match r.u8()? {
        0 => Ok(RewriteTarget::Records(decode_vec(r, decode_rdata)?)),
        1 => Ok(RewriteTarget::Cname(decode_name(r)?)),
        _ => Err(CacheError::new(
            "Invalid rewrite type in compiled filter cache",
        )),
    }
}

/** @brief 이름을 쓴다. 와이어 형태 그대로다. */
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

/** @brief 이름을 읽는다. 형식이 어긋나면 오류다. */
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

/** @brief RDATA를 쓴다. */
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

/** @brief RDATA를 읽는다. */
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

/** @brief 선택 값을 쓴다. 있는지 여부를 앞에 붙인다. */
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

/** @brief 선택 값을 읽는다. */
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
/** @brief 왕복 정확성, 헤더 배치, 그리고 조작된 파일 거부. */
mod tests {
    use super::*;
    use onetdns_core::{ClientInfo, FilterEngine, Transport};

    /** @brief 판정에 쓸 테스트용 클라이언트 정보. */
    fn client() -> ClientInfo {
        ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    /** @brief 되읽은 엔진으로 판정해 결과를 문자열로 얻는다. */
    fn verdict(parts: EngineParts, name: &str, rtype: RecordType) -> String {
        let engine = crate::BlockEngine::new(parts, BlockResponse::NxDomain);
        let name = Name::from_str(name).unwrap();
        format!("{:?}", engine.verdict(&name, rtype, &client()))
    }

    #[test]
    /** @brief 도메인과 타입별 판정이 왕복에서 보존되는지. */
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
        assert_eq!(&encoded[8..12], &layout_tag());
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
    /** @brief 헤더 필드가 정해진 곳에 있는지. 옮기면 이전 파일 판정이 어긋난다. */
    fn encoded_header_fields_sit_at_pinned_offsets() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");
        let fingerprint = [0x5a; 32];
        let encoded = encode_engine_cache(&mut parts, fingerprint).unwrap();

        assert_eq!(&encoded[..8], MAGIC.as_slice());
        assert_eq!(&encoded[8..12], &layout_tag());
        assert_eq!(&encoded[12..44], &fingerprint);
        let payload_len = u64::from_le_bytes(encoded[44..52].try_into().unwrap()) as usize;
        assert_eq!(payload_len, encoded.len() - HEADER_BYTES);
        let digest: [u8; 32] = Sha256::digest(&encoded[HEADER_BYTES..]).into();
        assert_eq!(&encoded[52..HEADER_BYTES], &digest);
    }

    #[test]
    /**
     * @brief 저장 배치가 다른 캐시를 옮겨 읽지 않고 거부하는지.
     * @details 배치가 다르면 같은 바이트가 다른 배열로 해석된다. 옮겨 읽으려 들면 엉뚱한
     *          자리를 상태로 읽는다. 캐시는 다시 만들 수 있으니 거부하고 새로 만든다.
     */
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
    /** @brief 흘려 쓴 결과가 메모리 인코딩과 바이트까지 같은지. 다르면 해시가 어긋난다. */
    fn streaming_cache_is_byte_identical_to_the_in_memory_encoder() {
        /** @brief 테스트용 엔진 부품. */
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
    /** @brief 쓰다 실패하면 그것이 위로 전해지는지. 삼키면 깨진 파일이 남는다. */
    fn streaming_cache_propagates_output_failure() {
        /** @brief 정해진 지점에서 실패하는 테스트용 대상. */
        struct FailingWriter {
            /** @brief 실제로 담을 곳. */
            inner: std::io::Cursor<Vec<u8>>,
            /** @brief 이만큼 쓰고 나면 실패한다. */
            remaining: usize,
        }

        impl Write for FailingWriter {
            /** @brief 정해진 지점에서 실패한다. */
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

            /** @brief 비운다. */
            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        impl Seek for FailingWriter {
            /** @brief 곳을 옮긴다. */
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
    /** @brief 입력 불일치, 잘림, 그리고 한 바이트 변조를 모두 거부하는지. */
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
    /** @brief 상한을 넘는 내용을 쓰는 시점에 거부하는지. */
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
    /** @brief 재작성, 클라이언트 규칙, RPZ, 보고가 모두 왕복하는지. */
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
        /* static 영역은 해시 표라 Debug 순서가 매번 다르다. 이름 순으로 펴서 비교한다. */
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
    /**
     * @brief 헤더를 다시 봉한 변조 입력에도 디코더가 패닉하지 않는지.
     * @details 헤더이 해시로 막혀 있어 그냥 변조하면 본문 파서까지 닿지 않는다. 그래서
     *          변조 후 다시 봉해야 실제 파서를 테스트할 수 있다. 수락률이 0이 아닌지도
     *          함께 확인해, 지나치게 엄격한 변이가 테스트를 조용히 무력화하지 않게 한다.
     */
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
            out.extend_from_slice(&layout_tag());
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
}
