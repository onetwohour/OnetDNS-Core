/*!
 * @brief UDP 고속 경로가 쓰는 저장 형태.
 *
 * @details 캐시가 맞았을 때 질의를 파싱하지도, 응답을 다시 조립하지도 않는다. 저장해 둔
 *          응답 바이트를 그대로 내보내고 질의 번호와 이름 대소문자, 남은 수명만 고쳐 쓴다.
 * @warning 이 경로는 응답이 요청·클라이언트·시각에 따라 달라지지 않을 때만 쓸 수 있다.
 *          달라지게 하는 기능을 새로 넣으면 그 기능도 고속 경로 조건에 스스로를 넣어야 한다.
 * @note 훑기는 이 서버가 답을 그대로 재사용할 수 있는 질의만 받아들인다. 조금이라도 다르게
 *       답해야 할 여지가 있으면 거부하고 보통 경로로 보낸다.
 */

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{fence, AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use onetdns_proto::{Message, Writer};

/**
 * @brief 할당 없이 wire 레인이 맡을 캐시 키 길이 상한.
 * @details 구조화 캐시의 인라인 키와 같은 크기다. 긴 정상 질의는 구조화 경로가 맡는다.
 */
const INLINE_KEY_CAPACITY: usize = 64;
/** @brief EDNS 유사 레코드 종류. */
const OPT_TYPE: u16 = 41;
/** @brief 채우기 옵션. 내용이 없어 응답을 바꾸지 않는다. */
const EDNS_PADDING: u16 = 12;

/** @brief 파싱 없이 훑어낸 질의. */
pub struct ScannedQuery<'a> {
    /** @brief 질의 번호. 응답에 그대로 되비춘다. */
    pub id: [u8; 2],

    /** @brief 받은 그대로의 이름 바이트. 대소문자를 되돌려줄 때 쓴다. */
    pub qname: &'a [u8],
    /** @brief 질의 종류. */
    pub qtype: u16,
    /** @brief 질의에 붙은 OPT. 없으면 없다. */
    pub edns: Option<ScannedEdns>,
    /** @brief 이 질의의 캐시 키. */
    key: KeyBuf,
}

#[derive(Clone, Copy)]
/**
 * @brief 질의에 붙은 OPT에서 읽은 것들.
 * @details 빠른 경로가 이 질의를 맡아도 되는지 판단하는 데 쓴다. 옵션이 있거나 DO가 켜져
 *          있으면 응답에 담을 것이 생기므로 구조적 경로가 맡아야 한다.
 */
pub struct ScannedEdns {
    /** @brief 상대가 받아들이겠다고 알린 UDP 크기. */
    pub udp_payload: u16,
    /** @brief 서명을 함께 달라는 요구. */
    pub dnssec_ok: bool,
    /** @brief 옵션이 하나라도 실려 있는지. */
    pub has_options: bool,
}

/** @brief 키를 담는 고정 크기 버퍼. 할당을 하지 않으려는 것이다. */
struct KeyBuf {
    /** @brief 키 바이트. */
    bytes: [u8; INLINE_KEY_CAPACITY],
    /** @brief 지금까지 담긴 길이. */
    len: usize,
}

impl KeyBuf {
    /** @brief 빈 버퍼. */
    fn new() -> Self {
        Self {
            bytes: [0; INLINE_KEY_CAPACITY],
            len: 0,
        }
    }

    /** @brief 한 바이트 붙인다. */
    #[inline(always)]
    fn push(&mut self, value: u8) {
        debug_assert!(self.len < INLINE_KEY_CAPACITY);
        self.bytes[self.len] = value;
        self.len += 1;
    }

    /**
     * @brief 고정 길이 바이트를 붙인다.
     * @details 길이를 컴파일 시점 상수로 받아야 이동이 펼쳐진다. 슬라이스로 받으면
     *          길이가 실행 시점에 정해져 두 바이트를 옮기는 데도 memcpy 호출이 난다.
     */
    #[inline(always)]
    fn push_array<const N: usize>(&mut self, value: [u8; N]) {
        let end = self.len + N;
        debug_assert!(end <= INLINE_KEY_CAPACITY);
        self.bytes[self.len..end].copy_from_slice(&value);
        self.len = end;
    }

    /** @brief 지금까지 담긴 바이트. */
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl ScannedQuery<'_> {
    /** @brief 이 질의의 캐시 키. */
    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    /** @brief 대소문자를 맞춘 질의 이름. */
    pub fn canonical_qname(&self) -> &[u8] {
        &self.key.as_slice()[3..3 + self.qname.len()]
    }
}

/**
 * @brief 질의 패킷을 파싱하지 않고 훑어 키를 만든다.
 * @details 이름은 대소문자를 맞춰 키에 넣고, 원래 철자는 그대로 두었다가 응답에
 *          되비춘다. 응답을 바꿀 수 있는 표시는 전부 키에 들어간다.
 * @warning 응답을 달리 만들 여지가 있는 것은 모두 거부한다. 여러 질문, 특수한 종류,
 *          내용 있는 EDNS 옵션, 남는 바이트가 그렇다. 하나라도 놓치면 다른 질의에
 *          같은 답을 준다.
 * @return 훑은 결과. 이 경로로 답할 수 없는 질의면 없다.
 */
pub fn scan_query(packet: &[u8]) -> Option<ScannedQuery<'_>> {
    if packet.len() < 12 + 1 + 4 {
        return None;
    }
    let flags2 = packet[2];
    let flags3 = packet[3];

    if flags2 & 0x80 != 0 || (flags2 >> 3) & 0x0F != 0 || flags2 & 0x06 != 0 {
        return None;
    }

    if flags3 & 0x0F != 0 || flags3 & 0x40 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let nscount = u16::from_be_bytes([packet[8], packet[9]]);
    let arcount = u16::from_be_bytes([packet[10], packet[11]]);
    if qdcount != 1 || ancount != 0 || nscount != 0 || arcount > 1 {
        return None;
    }

    /*
     * 이름은 중간 배열을 거치지 않고 키에 곧장 소문자로 쓴다. 따로 담았다가 옮기면
     * 255바이트 배열을 0으로 채우고 이름을 한 번 더 옮기는 값을 질의마다 치른다.
     * 키 앞부분(버전, 의미 플래그)는 이름보다 먼저 정해지므로 순서를 바꿔도 된다.
     */
    let rd = flags2 & 0x01 != 0;
    let ad = flags3 & 0x20 != 0;
    let cd = flags3 & 0x10 != 0;
    let semantic_flags = (u16::from(rd) << 8) | (u16::from(ad) << 5) | (u16::from(cd) << 4);
    let mut key = KeyBuf::new();
    key.push(1);
    key.push_array(semantic_flags.to_be_bytes());
    let name_start = key.len;
    /*
     * QTYPE/QCLASS 뒤에는 EDNS 유무 태그와, 있으면 payload/DO/옵션 수가 붙는다. 이름을
     * 쓰기 전에 그 뒷부분과 루트 라벨 공간까지 남겨 두면 아래 push는 release에서도 안전하다.
     */
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

        if ext[1] != 0 {
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
            /*
             * 구조적 캐시의 키와 바이트까지 같아야 한다. 어긋나면 승격할 슬롯을 찾지
             * 못해 그 모양의 질의는 영원히 이 레인을 못 타고, 레인에 들어갔다 나오느라 일을
             * 두 번 한다. 버전 번호는 위에서 0만 통과시켰고, 패딩은 양쪽 다 의미 있는 옵션으로
             * 세지 않으므로 옵션 수는 언제나 0이다.
             */
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
/**
 * @brief 응답 바이트와 부가 정보를 한 블록에 담는 헤더.
 * @details 응답 바이트, TTL 테이블, 기록용 요약을 따로 할당하지 않고 이어 붙인다. 캐시
 *          항목 하나가 할당 하나다.
 */
struct WireAllocation {
    /** @brief 담은 시각. 기준 시점에서 흐른 나노초. */
    inserted_nanos: i64,

    /** @brief 담을 때의 필터·설정 세대. */
    filter_tag: usize,

    /** @brief 이 블록을 가리키는 소유자 수. */
    refs: AtomicU32,
    /** @brief 헤더 뒤에 이어진 내용의 길이. */
    storage_len: u32,

    /** @brief 이 항목의 수명. */
    lifetime_secs: u32,

    /** @brief 응답 바이트의 길이. */
    wire_len: u16,

    /** @brief TTL 테이블의 항목 수. */
    ttl_count: u16,
}

/**
 * @brief 위 블록을 가리키는 소유자.
 * @details 표준 공유 포인터 대신 직접 센다. 약한 소유자가 없어 카운터 하나면 되고,
 *          헤더와 내용이 한 할당에 붙어 있다.
 */
pub(crate) struct WireEntry(NonNull<WireAllocation>);

/** @safety 내용은 만든 뒤 바뀌지 않고 카운터는 원자적이다. */
unsafe impl Send for WireEntry {}

/** @safety 내용은 만든 뒤 바뀌지 않고 카운터는 원자적이다. */
unsafe impl Sync for WireEntry {}

impl Clone for WireEntry {
    /**
     * @brief 소유자를 하나 늘린다.
     * @warning 카운터가 넘칠 만큼 늘어나면 그대로 죽는다. 한 바퀴 돌면 살아 있는 것을
     *          해제해 메모리를 짓밟는다.
     */
    fn clone(&self) -> Self {
        /** @brief 이 이상 늘면 넘칠 위험이 있다고 본다. */
        const MAX_REFCOUNT: u32 = i32::MAX as u32;
        let previous = self.header().refs.fetch_add(1, Ordering::Relaxed);
        if previous > MAX_REFCOUNT {
            std::process::abort();
        }
        Self(self.0)
    }
}

impl Drop for WireEntry {
    /**
     * @brief 소유자를 하나 줄이고 마지막이면 해제한다.
     * @safety 줄일 때는 방출, 마지막에 획득 울타리를 둔다. 그래야 다른 스레드가 쓴
     *         내용이 해제 전에 모두 보인다.
     */
    fn drop(&mut self) {
        if self.header().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        let storage_len = self.header().storage_len as usize;
        let layout = wire_allocation_layout(storage_len)
            .expect("The wire cache allocation layout was validated when it was created");

        unsafe {
            std::ptr::drop_in_place(self.0.as_ptr());
            dealloc(self.0.as_ptr().cast(), layout);
        }
    }
}

impl WireEntry {
    /** @brief 블록을 할당하고 내용을 채운다. */
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

        let raw = unsafe { alloc_zeroed(layout) };
        let Some(pointer) = NonNull::new(raw.cast::<WireAllocation>()) else {
            handle_alloc_error(layout);
        };

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

    /** @brief 블록 헤더. */
    fn header(&self) -> &WireAllocation {
        unsafe { self.0.as_ref() }
    }

    /** @brief 헤더 뒤에 이어 붙은 내용 전체. */
    fn storage(&self) -> &[u8] {
        let len = self.header().storage_len as usize;

        unsafe { std::slice::from_raw_parts(self.storage_ptr(), len) }
    }

    /**
     * @brief 내용을 고칠 수 있게 빌린다.
     * @warning 소유자가 하나일 때만 부를 수 있다. 공유된 것을 고치면 다른 스레드가 읽는
     *          도중에 바뀐다.
     */
    fn storage_mut_unique(&mut self) -> &mut [u8] {
        assert_eq!(
            self.header().refs.load(Ordering::Acquire),
            1,
            "A shared wire cache allocation cannot be modified"
        );
        let len = self.header().storage_len as usize;

        unsafe { std::slice::from_raw_parts_mut(self.storage_ptr(), len) }
    }

    /** @brief 내용이 시작하는 위치. */
    fn storage_ptr(&self) -> *mut u8 {
        unsafe {
            self.0
                .as_ptr()
                .cast::<u8>()
                .add(std::mem::size_of::<WireAllocation>())
        }
    }

    /** @brief 같은 블록을 가리키는지. */
    pub(crate) fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.0 == right.0
    }

    /** @brief 저장된 응답 바이트. */
    fn wire(&self) -> &[u8] {
        &self.storage()[..self.header().wire_len as usize]
    }

    /** @brief TTL 테이블가 끝나는 위치. */
    fn ttl_metadata_end(&self) -> usize {
        self.header().wire_len as usize + usize::from(self.header().ttl_count) * 8
    }

    /** @brief 수명 값이 응답 바이트 어디에 있는지 적어 둔 테이블. */
    fn ttl_metadata(&self) -> &[u8] {
        &self.storage()[self.header().wire_len as usize..self.ttl_metadata_end()]
    }

    /** @brief 질의 기록에 남길 답변 요약. */
    pub(crate) fn answers_summary(&self) -> &str {
        std::str::from_utf8(&self.storage()[self.ttl_metadata_end()..])
            .expect("A wire cache answer summary copied from a String is UTF-8")
    }

    /** @brief 저장한 뒤 흐른 초. */
    pub(crate) fn elapsed_secs(&self, now: Instant) -> u32 {
        u32::try_from(wire_elapsed_secs(self.header().inserted_nanos, now)).unwrap_or(u32::MAX)
    }

    /** @brief 이만큼 흘렀으면 만료인지. */
    pub(crate) fn is_expired_at(&self, elapsed_secs: u32) -> bool {
        elapsed_secs >= self.header().lifetime_secs
    }

    /** @brief 남은 수명. 만료면 없다. */
    pub(crate) fn remaining_lifetime(&self, now: Instant) -> Option<u32> {
        let header = self.header();
        let elapsed = self.elapsed_secs(now);
        let remaining = header.lifetime_secs.saturating_sub(elapsed);
        (remaining > 0).then_some(remaining)
    }

    /**
     * @brief 저장할 때의 필터·설정 세대가 지금과 같은지.
     * @warning 다르면 쓰지 않는다. 차단 목록을 갱신했는데 이전 세대의 허용 응답을 계속
     *          내보내면 차단이 전부 늦어진다.
     */
    pub(crate) fn matches_filter(&self, filter_tag: usize) -> bool {
        self.header().filter_tag == filter_tag
    }

    /**
     * @brief 흐른 시간만큼 수명을 깎아 적는다.
     * @note 0까지 깎지 않고 최소 1을 남긴다. 0을 받은 클라이언트는 캐시하지 않아 다음
     *       질의가 곧바로 다시 온다.
     */
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

    /** @brief 수명을 깎은 응답을 메시지로 되읽는다. */
    pub(crate) fn parse_aged_at(&self, elapsed_secs: u32) -> Option<Message> {
        let mut wire = self.wire().to_vec();
        self.age_ttls(elapsed_secs, &mut wire);
        Message::parse(&wire).ok()
    }

    /**
     * @brief 저장된 응답을 이 질의에 맞춰 내보낸다.
     * @details 고치는 것은 질의 번호, 이름의 원래 철자, 수명뿐이다. 이름 압축을 다시
     *          하지 않으므로 길이는 그대로다.
     */
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

/** @brief 1초의 나노초. */
const NANOS_PER_SEC: i64 = 1_000_000_000;

/**
 * @brief 프로세스 기준 시점에서 흐른 나노초.
 * @note 부호 있는 값이다. 기준 시점보다 이른 시각도 담을 수 있어야 첫 항목이 기준을
 *       정하기 전에 만들어져도 어긋나지 않는다.
 */
fn wire_timestamp_nanos(now: Instant) -> i64 {
    /** @brief 프로세스가 처음 시각을 물은 순간. 이후 모든 시각이 여기서 측정한다. */
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(|| now);
    if now >= epoch {
        duration_nanos(now.saturating_duration_since(epoch))
    } else {
        -duration_nanos(epoch.saturating_duration_since(now))
    }
}

/** @brief 시간 간격을 나노초로. 넘치면 최대값으로 붙든다. */
fn duration_nanos(duration: std::time::Duration) -> i64 {
    let secs = duration.as_secs();
    if secs > i64::MAX as u64 / NANOS_PER_SEC as u64 {
        return i64::MAX;
    }
    let nanos = secs * NANOS_PER_SEC as u64 + u64::from(duration.subsec_nanos());
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

/**
 * @brief 두 시점 사이에 흐른 초.
 * @warning 어느 쪽이든 붙들린 최대값이면 만료로 본다. 넘친 값으로 계산하면 만료된
 *          항목이 영원히 살아남는다.
 */
fn wire_elapsed_secs_at(inserted_nanos: i64, now_nanos: i64) -> u64 {
    if inserted_nanos.unsigned_abs() == i64::MAX as u64
        || now_nanos.unsigned_abs() == i64::MAX as u64
    {
        return u64::MAX;
    }
    now_nanos.saturating_sub(inserted_nanos).max(0) as u64 / NANOS_PER_SEC as u64
}

/** @brief 저장 시점에서 지금까지 흐른 초. */
fn wire_elapsed_secs(inserted_nanos: i64, now: Instant) -> u64 {
    wire_elapsed_secs_at(inserted_nanos, wire_timestamp_nanos(now))
}

/** @brief 헤더와 내용을 합친 블록의 배치. */
fn wire_allocation_layout(storage_len: usize) -> Option<Layout> {
    let size = std::mem::size_of::<WireAllocation>().checked_add(storage_len)?;
    Layout::from_size_align(size, std::mem::align_of::<WireAllocation>()).ok()
}

#[derive(Clone, Copy)]
/** @brief 저장 항목을 만드는 것. 수명 상하한을 잡고 있다. */
pub struct WireEntryFactory {
    /** @brief 담을 때 걸 수명 하한. 0이 아니면 이 경로를 쓰지 않는다. */
    min_ttl: u32,
    /** @brief 담을 때 걸 수명 상한. */
    max_ttl: u32,
}

impl WireEntryFactory {
    /** @brief 수명 상하한으로 만든다. */
    pub fn new(min_ttl: u32, max_ttl: u32) -> Self {
        Self { min_ttl, max_ttl }
    }

    /**
     * @brief 응답 바이트로 저장 항목을 만든다.
     * @details 각 TTL 위치와 원래 값을 테이블로 적어 둔다. 그래야 내보낼 때 파싱 없이
     *          그 위치만 고쳐 쓴다.
     * @warning 잘렸거나 오류인 응답, 수명이 0인 응답은 저장하지 않는다. 최소 수명 설정이
     *          걸려 있으면 이 경로 자체를 쓰지 않는다. 수명을 늘려 적는 것은 응답을
     *          바꾸는 일이다.
     */
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

    /**
     * @brief 수명이 변하지 않는 응답으로 저장 항목을 만든다.
     * @details 설정에 고정해 둔 주소를 답할 때 쓴다. 시간이 지나도 수명을 깎지 않으므로
     *          TTL 테이블가 필요 없다.
     */
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

/**
 * @brief 응답을 훑어 TTL 위치와 그중 가장 짧은 값을 찾는다.
 * @details 항목 수명이 아니라 가장 짧은 수명이 이 항목의 수명이다. 하나라도 만료된
 *          레코드를 내보내면 안 된다.
 * @return TTL 위치와 원래 값의 목록, 그리고 가장 짧은 수명. 형식이 어긋나면 없다.
 */
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

/**
 * @brief 이 프로세스의 조각 나누기 비밀값.
 * @warning 프로세스마다 달라야 한다. 고정하면 한 조각에 몰리도록 고른 이름들로 잠금
 *          경합을 일으킬 수 있다.
 */
pub(crate) fn random_shard_hash_keys() -> [u64; 2] {
    let seed = onetdns_core::random_array::<16>();
    [
        u64::from_le_bytes(seed[..8].try_into().expect("Fixed seed length")),
        u64::from_le_bytes(seed[8..].try_into().expect("Fixed seed length")),
    ]
}

/** @brief 키를 해시해 샤드 번호를 고른다. */
pub(crate) fn shard_hash(key: &[u8], keys: [u64; 2]) -> u64 {
    /** @brief 섞기에 쓰는 곱셈 상수. */
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

/** @brief 이름 하나를 건너뛴 곳. 압축 지시자를 만나면 거기서 끝난다. */
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
/** @brief 훑기가 받아들이고 거부하는 범위, 저장 항목의 수명·세대 처리, 그리고 소유권. */
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Message, Name, RData, Record, RecordType};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    /** @brief 항목 하나의 고정 비용이 커지지 않았는지. 커지면 같은 메모리에 담기는 항목이 준다. */
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
    /** @brief 줄여 담은 시각이 만료 경계를 그대로 지키고, 넘치면 만료 쪽으로 기우는지. */
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

    /** @brief 테스트용 질의 바이트. */
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

    /** @brief 테스트용 응답 바이트. */
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
    /** @brief 평범한 질의와 EDNS 질의를 받아들이는지. */
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
    /** @brief 키는 대소문자를 맞추되 원래 철자를 되돌려줄 수 있는지. */
    fn scan_normalizes_case_but_preserves_original_span() {
        let lower = query_wire("host.example", RecordType::A, false);
        let upper = query_wire("HOST.EXAMPLE", RecordType::A, false);
        let a = scan_query(&lower).unwrap();
        let b = scan_query(&upper).unwrap();
        assert_eq!(a.key(), b.key(), "케이스는 키에서 정규화");
        assert_ne!(a.qname, b.qname, "원본 케이스는 패치용으로 유지");
    }

    #[test]
    /** @brief 인라인 키 경계까지 맡고 더 긴 정상 질의는 안전하게 구조화 경로로 보내는지. */
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
    /** @brief 응답을 바꿀 수 있는 질의를 거부하는지. 받아들이면 다른 질의에 같은 답을 준다. */
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
    /** @brief 내보낼 때 번호·철자·수명만 고쳐지는지. */
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
    /** @brief 여러 스레드가 나눠 가져도 할당 하나가 정확히 한 번 해제되는지. */
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
    /** @brief 수명 상한이 0이면 저장하지 않는지. */
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
    /** @brief 설정한 상한보다 긴 수명을 내보내지 않는지. */
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
    /** @brief 응답 캐시의 수명이 이 항목의 수명을 넘지 못하는지. 넘으면 두 경로가 다른 답을 준다. */
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
    /** @brief 만료됐거나 세대가 다르면 쓰지 않는지. */
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
    /** @brief 잘렸거나 오류인 응답을 저장하지 않는지. */
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
    /** @brief 고속 경로 적중 비용. */
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
        /** @brief 아무것도 하지 않는 리졸버. */
        struct Noop;
        impl crate::native::Resolver for Noop {
            /** @brief 항상 답하지 않는다. */
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
    /** @brief 어떤 바이트열이 와도 훑기와 저장이 패닉하지 않는지. */
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
    /** @brief 조각이 고르게 나뉘는지. */
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
    /** @brief 비밀값이 다르면 나뉘는 모양도 달라지는지. 같으면 한 조각에 몰리게 만들 수 있다. */
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
    /** @brief 조각 나누기 비용. */
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
