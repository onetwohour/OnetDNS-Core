/*!
 * @brief 권한 DNS 서빙.
 *
 * @details 이 서버가 소유한 zone에 대해 직접 답한다. 저장 구조는 질의 경로가 할당 없이
 *          돌도록 짜여 있다. 레코드는 단일 아레나에, 소유자 인덱스는 8바이트 범위만
 *          담는다. A/AAAA 같은 흔한 질의는 응답을 조립하지 않고 곧장 와이어로 쓴다.
 * @note zone 데이터는 여러 공급자에서 오지만 전부 parse_zone을 거친다. 어느 경로로
 *       들어오든 같은 검증을 받는다.
 */

#[cfg(test)]
/** @brief 파서 훑기 테스트 도구. */
mod fuzzutil;
/** @brief 영역 파일 읽기. */
mod parse;

use std::cmp::Ordering;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use onetdns_proto::{DnsClass, Message, Name, ProtoError, RData, Record, RecordType, Soa, Writer};

pub use parse::parse_zone;

/** @brief zone 공급자 추상과 파일·디렉터리·메모리 구현. */
pub mod source;
pub use source::{DirZoneSource, FileZoneSource, MemoryZoneSource, ZoneSource};
/** @brief SQLite 파일 백엔드. */
pub mod sqlite;
pub use sqlite::SqliteZoneSource;
/** @brief etcd 백엔드. */
pub mod etcd;
pub use etcd::EtcdZoneSource;
/** @brief PostgreSQL 백엔드. */
pub mod postgres;
pub use postgres::PostgresZoneSource;
/** @brief MySQL/MariaDB 백엔드. */
pub mod mysql;
pub use mysql::MysqlZoneSource;
/** @brief LMDB 파일 백엔드. */
pub mod lmdb;
pub use lmdb::LmdbZoneSource;

/** @brief zone 하나가 가질 수 있는 레코드 수 상한. */
const MAX_ZONE_RECORDS: usize = 1_000_000;
/** @brief 소유자 이름 하나에 붙을 수 있는 레코드 수 상한. */
const MAX_OWNER_RECORDS: usize = 4_096;
/** @brief zone 전송 메시지 하나에 담을 바이트 예산. TCP 메시지 크기를 넘지 않게 끊는다. */
pub const XFR_CHUNK_BUDGET: usize = 60_000;

/** @brief 이 이름이 zone에 존재한다. */
const NAME_EXISTS: u8 = 1;
/** @brief 이 이름 아래에 와일드카드 자식이 있다. */
const NAME_HAS_WILDCARD: u8 = 2;
/** @brief 이 이름 아래에 DNAME이 있다. */
const NAME_HAS_DNAME: u8 = 4;

/**
 * @brief 정규 키에서 부모의 키를 얻는다. 첫 라벨을 떼어 낸 나머지다.
 * @return 이미 루트면 None.
 */
fn parent_canonical_key(key: &[u8]) -> Option<&[u8]> {
    let label_len = usize::from(*key.first()?);
    if label_len == 0 {
        return None;
    }
    key.get(label_len.checked_add(1)?..)
}

/**
 * @brief 접속 주소를 호스트와 포트로 구분한다.
 * @details 대괄호로 감싼 IPv6를 먼저 처리한다. 그러지 않으면 주소 안의 콜론을 포트
 *          구분자로 잘못 본다. 콜론이 정확히 하나일 때만 포트로 해석하는 것도 같은 이유다.
 * @return 포트가 0이거나 호스트가 비면 None.
 */
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

/**
 * @brief DB 접속 주소가 루프백인지 확인하고 소켓 주소로 만든다.
 *
 * @details 이름은 localhost만 받고 나머지는 IP 문자열이어야 한다. 이름을 해석하려면
 *          DNS가 필요한데, 그 DNS가 자기 자신이면 시작 중 순환이 생긴다.
 * @warning 루프백이 아니면 거부한다. mysql과 postgres 백엔드는 TLS 없이 말하므로,
 *          원격으로 향하면 자격증명과 zone 데이터가 평문으로 흐른다.
 */
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

/**
 * @brief zone 하나. 로드 후에는 바뀌지 않는다.
 * @details 레코드를 아레나 하나에 몰아넣고 인덱스는 그 안의 범위만 가리킨다. 질의마다
 *          자료구조를 타고 다니며 할당하지 않으려는 배치다.
 */
#[derive(Clone)]
pub struct Zone {
    /** @brief zone apex. */
    origin: Name,
    /** @brief apex의 SOA. 부정 응답과 전송에 쓴다. */
    soa: Soa,
    /** @brief SOA 레코드의 TTL. */
    soa_ttl: u32,

    /** @brief 소유자 이름에서 아레나 범위로 가는 인덱스. */
    records: OwnerIndex,
    /** @brief 모든 레코드를 담은 단일 아레나. */
    record_arena: Box<[StoredRecord]>,
    /** @brief AAAA 주소만 따로 모은 아레나. 레코드 변형 크기를 줄인다. */
    aaaa_arena: Box<[std::net::Ipv6Addr]>,
    /** @brief A·AAAA가 아닌 레코드를 담은 아레나. 저장 형태는 인덱스만 가지고 있다. */
    other_arena: Box<[Record]>,

    /** @brief 이름별 존재·와일드카드·DNAME 표시. 빈 비단말도 여기 들어간다. */
    name_flags: HashMap<Vec<u8>, u8>,
    /** @brief 위임이 하나라도 있는지. 없으면 질의마다 위임을 찾지 않는다. */
    has_delegations: bool,
    /** @brief 위임도 DNAME도 와일드카드도 없는 평탄한 zone인지. 무할당 경로의 전제다. */
    simple_nxdomain: bool,
    /** @brief 부재 증명 레코드의 위치 인덱스. */
    denial_index: HashMap<RecordType, Vec<RecordLocation>>,

    /** @brief 전송용 와이어 템플릿. 처음 요청될 때 한 번만 만든다. */
    axfr_wire: Arc<OnceLock<Result<Box<[Box<[u8]>]>, ProtoError>>>,
    /** @brief 이 내용을 읽어 오거나 써 넣은 파일의 지문. 파일에서 오지 않았으면 없다. */
    source: Option<source::SourceDigest>,
}

/** @brief 아레나 안 레코드 하나의 위치. 소유자 키와 그 안에서의 곳이다. */
#[derive(Clone)]
struct RecordLocation {
    /** @brief 소유자 이름의 정규 키. */
    owner: Vec<u8>,
    /** @brief 그 소유자의 레코드들 중 몇 번째인지. */
    offset: usize,
}

/**
 * @brief 전송 응답 메시지 하나를 미리 인코딩해 둔다.
 * @details 전송은 같은 바이트를 여러 번 보내므로, 매번 조립하지 않고 템플릿으로 만들어
 *          둔다. 보낼 때는 트랜잭션 ID만 덮어쓴다.
 * @param first 첫 메시지만 질문 절을 남긴다. 이후 메시지는 질문 없이 보낸다.
 */
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

/** @brief 아레나 안의 연속 구간. 소유자 하나의 레코드들이 여기 모여 있다. */
#[derive(Clone, Copy)]
struct RecordRange {
    /** @brief 아레나에서의 시작 위치. */
    start: u32,
    /** @brief 레코드 개수. */
    len: u16,
}

/**
 * @brief 인덱스 슬롯 하나. 8바이트에 맞춰 두어 한 캐시 줄에 여럿이 들어가게 한다.
 * @note 키 자체는 여기 두지 않는다. 태그로 대부분을 걸러 내고, 통과한 것만 메타데이터에서
 *       키를 꺼내 비교한다.
 */
#[derive(Clone, Copy)]
struct OwnerSlot {
    /** @brief 해시 상위 비트. 0은 빈 슬롯을 뜻하므로 최하위 비트를 설정해 0을 피한다. */
    tag: u32,
    /** @brief 메타데이터 아레나에서 이 항목의 시작 위치. */
    metadata_start: u32,
    /** @brief 레코드 아레나에서의 시작 위치. */
    record_start: u32,
}

/**
 * @brief 소유자 이름에서 레코드 범위로 가는 열린 주소 지정 해시 테이블.
 * @details 표준 해시맵 대신 쓰는 이유는 배치 때문이다. 슬롯이 작아 캐시 줄 하나에 여럿이
 *          들어가고, 키는 별도 아레나에 이어 붙여 두어 소유자마다 할당이 생기지 않는다.
 */
#[derive(Clone)]
struct OwnerIndex {
    /** @brief 슬롯 배열. 길이는 항상 2의 거듭제곱이라 나머지 연산이 비트 마스크가 된다. */
    slots: Box<[OwnerSlot]>,

    /** @brief 키 길이, 레코드 개수, 키 바이트를 이어 붙인 아레나. */
    metadata: Vec<u8>,
    /** @brief 해시 시드. 프로세스마다 달라 충돌을 노린 입력을 막는다. */
    hash_builder: RandomState,
}

impl OwnerIndex {
    /**
     * @brief 예상 크기에 맞춰 인덱스를 만든다.
     * @details 슬롯을 소유자 수의 1.25배 이상으로 잡는다. 적재율이 높으면 선형 탐색이
     *          길어지고, 이 테이블은 로드 후 늘어나지 않으므로 처음에 여유를 둔다.
     */
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

    /** @brief 해시 상위 절반에서 태그를 만든다. 최하위 비트를 설정해 빈 슬롯 표시와 겹치지 않게 한다. */
    fn tag_of(hash: u64) -> u32 {
        ((hash >> 32) as u32) | 1
    }

    /** @brief 키 해시. 0은 쓰지 않는다. */
    fn hash(&self, key: &[u8]) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        hasher.write(key);
        hasher.finish().max(1)
    }

    /**
     * @brief 소유자를 넣는다. 로드 시점에만 호출한다.
     * @details 메타데이터에 키 길이, 레코드 개수, 키 바이트를 이어 붙이고 슬롯에는 그
     *          시작 위치만 둔다. 충돌하면 다음 슬롯으로 밀어 넣는다.
     * @note 같은 키를 두 번 넣는 경우는 없다. 호출자가 소유자별로 묶어 한 번씩 부른다.
     */
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

    /** @brief 슬롯이 가리키는 키 바이트. 메타데이터의 앞 3바이트를 건너뛴다. */
    fn key_for_slot(&self, slot: &OwnerSlot) -> Option<&[u8]> {
        let start = slot.metadata_start as usize;
        let key_len = usize::from(*self.metadata.get(start)?);
        let key_start = start.checked_add(3)?;
        self.metadata
            .get(key_start..key_start.checked_add(key_len)?)
    }

    /** @brief 슬롯이 가리키는 레코드 범위. 개수는 메타데이터에, 시작은 슬롯에 있다. */
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

    /**
     * @brief 소유자 키로 레코드 범위를 찾는다. 질의 경로에서 가장 자주 불린다.
     * @details 태그를 먼저 견주고 통과한 것만 키를 실제로 비교한다. 대부분의 충돌이
     *          메타데이터를 건드리지 않고 걸러져 캐시 미스가 줄어든다.
     */
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

    /** @brief 이 소유자가 있는지. */
    fn contains_key(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /** @brief 모든 소유자 키. 순서는 슬롯 배치를 따르므로 정렬돼 있지 않다. */
    fn keys(&self) -> impl Iterator<Item = &[u8]> {
        self.slots
            .iter()
            .filter(|slot| slot.tag != 0)
            .filter_map(|slot| self.key_for_slot(slot))
    }
}

/**
 * @brief 아레나에 저장하는 레코드 형태.
 *
 * @details 대부분의 zone은 A와 AAAA가 압도적으로 많다. 그 둘은 소유자 이름 없이 값만
 *          담고, 나머지는 상자에 넣어 참조로 둔다. 이렇게 하면 이 변형의 크기가 가장 큰
 *          RData가 아니라 몇 워드로 고정돼, 아레나 전체가 캐시에 훨씬 잘 들어간다.
 * @note 소유자 이름은 인덱스가 갖고 있으므로 여기 두지 않는다. 응답을 만들 때 다시 붙인다.
 */
#[derive(Clone)]
struct StoredRecord {
    /**
     * @brief 상위 2비트가 종류, 나머지가 TTL.
     * @details 종류가 Other일 때는 TTL 필드에 레코드 타입을 담는다. 그 레코드의 TTL은
     *          아레나 안 온전한 레코드가 가지고 있으므로 여기서는 비어 있다.
     */
    tagged: u32,
    /** @brief A면 주소, AAAA면 주소 아레나 인덱스, 그 밖이면 레코드 아레나 인덱스. */
    payload: u32,
}

/** @brief 종류 필드의 시작 비트. */
const STORED_TAG_SHIFT: u32 = 30;
/** @brief A 레코드. */
const STORED_TAG_A: u32 = 0;
/** @brief AAAA 레코드. */
const STORED_TAG_AAAA: u32 = 1;
/** @brief 그 밖의 타입. */
const STORED_TAG_OTHER: u32 = 2;
/** @brief 종류 비트를 뺀 나머지. */
const STORED_VALUE_MASK: u32 = (1 << STORED_TAG_SHIFT) - 1;

/**
 * @brief 담을 수 있는 TTL 상한. 약 34년이다.
 *
 * @details RFC 2181은 최상위 비트가 선 TTL을 0으로 다루라고 하므로 원래 쓸 수 있는 폭이
 *          31비트다. 타입을 합쳐 넣느라 한 비트를 더 줄였다. 이보다 긴 TTL은 로드할 때
 *          여기로 깎는다. DNS에서 34년을 넘는 수명은 실질적으로 쓰이지 않는다.
 */
const STORED_TTL_MAX: u32 = STORED_VALUE_MASK;

/**
 * @brief 이름이 없거나 타입이 없을 때 무할당 경로가 내릴 수 있는 판정.
 * @details Fallback은 이 경로로 답할 수 없다는 뜻이다. 그 경우 호출자가 구조화된 경로로
 *          넘어간다.
 */
enum SimpleAbsent<'a> {
    /** @brief 이름 자체가 없다. */
    NxDomain,
    /** @brief 이름은 있으나 그 타입이 없다. */
    NoData,
    /** @brief 와일드카드가 답한다. 그 레코드들을 함께 준다. */
    Wildcard(&'a [StoredRecord]),
    /** @brief DNAME이 걸린다. */
    Dname(&'a Record),
    /** @brief 이 경로로 판정할 수 없다. 구조화된 경로로 넘긴다. */
    Fallback,
}

impl StoredRecord {
    /** @brief 레코드를 저장 형태로 바꾼다. 주소와 온전한 레코드는 각각 아레나로 옮긴다. */
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

    /** @brief 담긴 종류. */
    fn tag(&self) -> u32 {
        self.tagged >> STORED_TAG_SHIFT
    }

    /** @brief A·AAAA의 TTL. 그 밖의 타입에는 뜻이 없다. */
    fn ttl(&self) -> u32 {
        self.tagged & STORED_VALUE_MASK
    }

    /**
     * @brief 레코드 타입.
     * @note 그 밖의 타입도 TTL 필드에 타입을 담아 두므로 아레나를 보지 않는다.
     */
    fn rtype(&self) -> RecordType {
        match self.tag() {
            STORED_TAG_A => RecordType::A,
            STORED_TAG_AAAA => RecordType::AAAA,
            _ => RecordType((self.tagged & STORED_VALUE_MASK) as u16),
        }
    }

    /** @brief 온전한 레코드가 그대로 있으면 빌려 준다. 압축 변형은 None이다. */
    fn full<'a>(&self, other_arena: &'a [Record]) -> Option<&'a Record> {
        (self.tag() == STORED_TAG_OTHER).then(|| other_arena.get(self.payload as usize))?
    }

    /**
     * @brief 소유자 이름을 붙여 온전한 레코드로 되살린다.
     * @note 여기서 이름을 복제한다. 응답을 조립하는 경로에서만 부르고, 무할당 경로는
     *       이 함수를 거치지 않는다.
     */
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

/**
 * @brief 타입순으로 붙어 있는 소유자 레코드에서 한 RRset만 빌린다.
 * @details 흔한 단일 타입 owner는 첫·끝 확인만 하고 전부 돌려준다. 혼합 owner만
 *          이진 탐색하므로 큰 A/AAAA RRset을 세고 다시 쓰는 이중 순회가 없다.
 * @invariant from_flat_records가 같은 owner 안을 타입 번호 오름차순으로 정렬한다.
 */
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

/** @brief 같은 소유자 이름이 이어지는 구간의 끝. 레코드가 정규 순서로 정렬돼 있어야 한다. */
fn owner_group_end(records: &[Record], start: usize) -> usize {
    let owner = &records[start].name;
    let mut end = start + 1;
    while end < records.len() && records[end].name.eq_ignore_case(owner) {
        end += 1;
    }
    end
}

/**
 * @brief CNAME 체인을 zone 안에서 따라가다 멈춘 위치.
 *
 * @details 다섯을 구분하는 이유는 응답이 서로 다르기 때문이다. RFC 6604는 rcode를 체인의
 *          마지막 질의 주기로 정하라고 하므로 부재와 NODATA를 하나로 합치면 안 되고, 둘 다 부정
 *          SOA가 있어야 부정 캐시가 된다.
 */
enum ChaseEnd {
    /** @brief 물어본 종류를 찾았다. 추가부에 담을 것이 따라온다. */
    Answered(Vec<Record>),
    /** @brief 대상 이름이 이 zone에 없다. */
    NoSuchName,
    /** @brief 이름은 있으나 물어본 종류가 없다. */
    NoData,
    /** @brief 대상이 위임 아래다. 그 위임으로 넘긴다. */
    Delegated(Name),
    /** @brief 대상이 이 zone 밖이다. 질의자가 이어서 푼다. */
    OutOfZone,
}

/**
 * @brief 로드하면서 RRset마다 수명을 RFC 2181대로 고른다.
 *
 * @details 5.2항은 한 RRSet의 수명이 모두 같아야 한다고 정하고 서버가 다른 값을 담아
 *          보내는 것을 아예 금지한다. 8항은 상한을 넘는 수명을 0으로 본다. 로드 곳에서
 *          한 번 고르면 구조적 응답, 압축 저장, 무할당 wire 경로, 영역 전송 template이
 *          모두 같은 값을 쓴다.
 * @param records 소유자 이름으로 정렬된 목록. 제자리에서 고친다.
 */
/**
 * @brief 소유자·종류·부류·데이터가 모두 같은 레코드를 하나만 남긴다.
 *
 * @details RFC 2181은 넷이 모두 같은 레코드가 둘 있는 것은 뜻이 없으므로 서버가
 *          억제해야 한다고 한다. 남겨 두면 응답이 그만큼 불어나고, 서명 영역에서는
 *          서명이 덮는 집합과 내보내는 집합이 달라져 검증이 깨진다.
 * @param records 소유자 이름으로 정렬된 목록. 제자리에서 줄인다.
 * @return 덜어 낸 레코드 수.
 */
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

fn normalize_owner_group_ttls(records: &mut [Record]) {
    let mut start = 0usize;
    while start < records.len() {
        let end = owner_group_end(records, start);
        onetdns_proto::normalize_ttls(&mut records[start..end]);
        start = end;
    }
}

/**
 * @brief 정렬된 레코드 목록에서 소유자 인덱스를 만든다.
 * @details 두 번 훑는다. 먼저 소유자 수와 메타데이터 길이를 세어 정확한 크기로 잡고,
 *          그다음 채운다. 늘려 가며 채우면 로드 중 재할당과 복사가 반복된다.
 */
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

/** @brief 로드 중 쓰는 조회. 아직 저장 형태로 바꾸기 전의 원본 레코드를 본다. */
fn full_records_for_key<'a>(
    records: &'a [Record],
    index: &OwnerIndex,
    key: &[u8],
) -> Option<&'a [Record]> {
    let range = index.get(key)?;
    let start = range.start as usize;
    records.get(start..start.checked_add(range.len as usize)?)
}

/** @brief 로드 중 쓰는 순회. 소유자별로 묶인 원본 레코드를 준다. */
fn full_record_groups<'a>(
    records: &'a [Record],
    index: &'a OwnerIndex,
) -> impl Iterator<Item = (&'a [u8], &'a [Record])> + 'a {
    index.keys().filter_map(move |key| {
        full_records_for_key(records, index, key).map(|owner_records| (key, owner_records))
    })
}

/** @brief 권한 응답 하나. 상위 계층이 이것을 DNS 메시지로 옮긴다. */
#[derive(Debug, Default, PartialEq)]
pub struct Response {
    /** @brief 응답 코드. */
    pub rcode: u8,

    /** @brief 권한 비트. 위임을 넘긴 참조 응답에서는 꺼진다. */
    pub authoritative: bool,
    /** @brief 답변 절. */
    pub answers: Vec<Record>,
    /** @brief 권한 절. 부정 응답의 SOA나 참조의 NS가 들어간다. */
    pub authority: Vec<Record>,
    /** @brief 추가 절. glue 주소가 들어간다. */
    pub additional: Vec<Record>,
}

impl Zone {
    /**
     * @brief 소유자별로 묶인 레코드 맵에서 zone을 만든다.
     * @details 맵의 키와 레코드의 소유자 이름이 일치하는지 확인한다. 어긋난 채로 인덱스를
     *          만들면 조회가 엉뚱한 레코드를 준다.
     */
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

    /** @brief 정규 키로 묶인 맵을 평탄한 목록으로 펼친 뒤 zone을 만든다. */
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

    /**
     * @brief 평탄한 레코드 목록에서 zone을 완성한다. 모든 로드 경로가 여기로 모인다.
     *
     * @details 순서가 정해져 있다. 정규 순서로 정렬해 같은 소유자를 붙여 놓고, 인덱스를
     *          만들고, apex NS 유무를 확인하고, 레코드 전체를 검증한 뒤, 빈 비단말을
     *          포함한 이름 표시를 채운다. 마지막으로 무할당 경로를 쓸 수 있는 zone인지
     *          판정한다.
     * @return apex에 NS가 없거나 zone 밖 소유자가 섞여 있으면 오류.
     * @invariant 여기서 만들어진 zone은 이후 바뀌지 않는다. 질의 경로는 읽기만 한다.
     */
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
        // TTL 을 먼저 맞춰야 한다. RFC 2181로 같은 RRset 의 TTL 이 같아진 뒤라야
        // 나머지가 모두 같은 레코드가 정말 같은 레코드다.
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

    /** @brief 이 내용이 어느 파일 내용에서 왔는지. 파일에서 오지 않았으면 없다. */
    pub fn source_digest(&self) -> Option<source::SourceDigest> {
        self.source
    }

    /**
     * @brief 이 내용을 읽어 오거나 써 넣은 파일의 지문을 붙인다.
     * @details 파일을 고쳐 쓰는 쪽은 쓰기 전에 지금 파일의 지문이 이 값과 같은지 확인한다.
     *          다르면 이 서버가 모르는 사이에 파일이 바뀐 것이다.
     */
    pub fn with_source_digest(mut self, digest: source::SourceDigest) -> Self {
        self.source = Some(digest);
        self
    }

    /**
     * @brief 전송으로 받은 레코드 목록에서 zone을 만든다.
     *
     * @details 전송 응답은 SOA로 시작해 SOA로 끝나므로 SOA가 둘 나온다. 그 둘이 같은지
     *          확인하고 하나만 남긴다. 다르면 전송 도중 zone이 바뀐 것이라 받아들일 수 없다.
     * @warning zone 밖 소유자가 하나라도 섞이면 거부한다. 상대가 자기 zone 응답에
     *          남의 이름을 끼워 넣는 것을 막는 검사다.
     */
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

    /** @brief zone apex. */
    pub fn origin(&self) -> &Name {
        &self.origin
    }

    /** @brief apex의 SOA. */
    pub fn soa(&self) -> &Soa {
        &self.soa
    }

    /** @brief 모든 레코드를 되살려 훑는다. 순서는 인덱스 배치를 따른다. */
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

    /** @brief 전송용 레코드 전부를 모아 돌려준다. */
    pub fn axfr_records(&self) -> Vec<Record> {
        self.axfr_records_iter().collect()
    }

    /** @brief 전송 순서대로 훑는다. SOA로 시작해 SOA로 끝나는 것이 규격이다. */
    pub fn axfr_records_iter(&self) -> impl Iterator<Item = Record> + '_ {
        let soa = self.soa_record();
        std::iter::once(soa.clone())
            .chain(
                self.all_records()
                    .filter(|record| record.rtype != RecordType::SOA),
            )
            .chain(std::iter::once(soa))
    }

    /**
     * @brief 미리 인코딩해 둔 전송 메시지들. 처음 요청될 때 한 번만 만든다.
     * @note 실패도 기억한다. 인코딩할 수 없는 zone에 전송이 올 때마다 다시 시도해 봐야
     *       같은 결과다.
     */
    pub fn axfr_wire_templates(&self) -> Result<&[Box<[u8]>], ProtoError> {
        match self
            .axfr_wire
            .get_or_init(|| self.build_axfr_wire_templates())
        {
            Ok(templates) => Ok(templates),
            Err(error) => Err(error.clone()),
        }
    }

    /**
     * @brief 전송 레코드를 예산에 맞춰 메시지 단위로 끊고 각각 인코딩한다.
     * @details 레코드 하나를 테스트 인코딩해 크기를 재고 예산을 넘기 전에 끊는다. 이름
     *          압축 때문에 실제 크기는 이보다 작거나 같으므로, 이 추정으로 끊으면 메시지
     *          한도를 넘지 않는다.
     */
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

    /** @brief zone 전체에서 이 타입의 레코드를 모은다. 서명이나 진단에 쓴다. */
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

    /** @brief 이 타입의 부재 증명 레코드가 있는지. NSEC 방식인지 NSEC3 방식인지 가리는 데 쓴다. */
    pub fn has_denial_records(&self, rtype: RecordType) -> bool {
        self.denial_index
            .get(&rtype)
            .is_some_and(|records| !records.is_empty())
    }

    /** @brief 정규 순서상 첫 부재 증명 레코드. 되감기는 구간을 찾을 때 쓴다. */
    pub fn first_denial_record(&self, rtype: RecordType) -> Option<&Record> {
        self.denial_index
            .get(&rtype)?
            .first()
            .and_then(|location| self.record_at(location))
    }

    /** @brief 이 이름과 정확히 일치하는 부재 증명 레코드. 인덱스가 정규 순서로 정렬돼 있어 이분 탐색한다. */
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

    /**
     * @brief 정규 순서상 이 이름 바로 앞의 부재 증명 레코드.
     * @note 이름이 첫 레코드보다 앞이면 마지막으로 되감는다. 체인이 순환 구조라
     *       zone 끝의 레코드가 그 앞을 덮는다.
     */
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

    /**
     * @brief zone을 파일 형식 텍스트로 내보낸다.
     * @details 동적 갱신 결과를 디스크에 남길 때 쓴다. 이름을 정렬해 내보내므로 같은
     *          zone은 같은 텍스트가 되고, 그래야 변경 여부를 파일 비교로 알 수 있다.
     */
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

    /** @brief 이름으로 그 소유자의 레코드들을 찾는다. 키는 스택 버퍼에 만들어 할당하지 않는다. */
    fn owner(&self, name: &Name) -> Option<&[StoredRecord]> {
        let mut key = [0u8; 255];
        self.records_for_key(name.canonical_key_into(&mut key)?)
    }

    /** @brief 정규 키로 아레나 구간을 얻는다. */
    fn records_for_key(&self, key: &[u8]) -> Option<&[StoredRecord]> {
        let range = self.records.get(key)?;
        let start = range.start as usize;
        let end = start.checked_add(range.len as usize)?;
        self.record_arena.get(start..end)
    }

    /** @brief 위치로 레코드를 꺼낸다. 부재 증명 레코드는 압축 변형이 아니라 항상 온전한 형태다. */
    fn record_at(&self, location: &RecordLocation) -> Option<&Record> {
        self.records_for_key(&location.owner)
            .and_then(|records| records.get(location.offset))
            .and_then(|record| record.full(&self.other_arena))
    }

    /** @brief 이 소유자의 레코드 중 타입이 맞는 것만 되살린다. */
    fn of_type(&self, recs: &[StoredRecord], qtype: RecordType, owner: &Name) -> Vec<Record> {
        stored_rrset(recs, qtype)
            .iter()
            .filter_map(|record| record.materialize(owner, &self.aaaa_arena, &self.other_arena))
            .collect()
    }

    /** @brief apex의 SOA 레코드. 원래 TTL을 그대로 쓴다. */
    fn soa_record(&self) -> Record {
        Record::new(
            self.origin.clone(),
            self.soa_ttl,
            RData::soa(self.soa.clone()),
        )
    }

    /**
     * @brief 부정 응답에 담을 SOA.
     * @details TTL을 SOA의 minimum과 비교해 작은 쪽을 쓴다. 부정 응답의 캐시 기간은 그
     *          필드가 정하므로, 더 오래 캐시되게 두면 안 된다.
     */
    fn negative_soa_record(&self) -> Record {
        Record::new(
            self.origin.clone(),
            self.soa_ttl.min(self.soa.minimum),
            RData::soa(self.soa.clone()),
        )
    }

    /** @brief 이 이름이 zone 범위 안인지. */
    pub fn contains(&self, qname: &Name) -> bool {
        is_subdomain_or_eq(qname, &self.origin)
    }

    /**
     * @brief 질의에 답한다.
     *
     * @details 판정 순서가 정해져 있다. 위임을 먼저 보고, 정확한 소유자, DNAME, 그다음
     *          와일드카드, 마지막이 부재 판정이다. 위임을 뒤로 미루면 자식 zone의
     *          이름에 이 서버가 직접 답하게 된다.
     * @return 응답. 위임을 넘긴 경우 권한 비트가 꺼진다.
     */
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

    /**
     * @brief 이 이름 위쪽에서 가장 깊은 위임 지점을 찾는다.
     * @details apex보다 아래에서만 본다. apex의 NS는 zone 자신의 것이지 위임이 아니다.
     *          가장 깊은 것을 골라야 다단 위임에서 올바른 자식으로 넘긴다.
     * @return 위임이 없거나 zone에 위임 자체가 없으면 None.
     */
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

    /**
     * @brief 위임 참조 응답을 만든다.
     * @note 권한 비트를 끈다. 이 데이터는 자식 zone의 것이고 이 서버가 보증하는 것이 아니다.
     *       DS가 있으면 함께 담아야 질의자가 자식의 서명을 검증할 수 있다.
     */
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

    /**
     * @brief 이름은 존재할 때의 응답을 만든다.
     * @details 타입이 정확히 맞으면 그것으로 끝이다. 없으면 CNAME을 보는데, 질의 타입이
     *          CNAME일 때는 보지 않는다. 그 경우 CNAME이 곧 답이라 따라갈 이유가 없다.
     *          둘 다 없으면 NODATA다. 이름은 있으니 NXDOMAIN이 아니다.
     */
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

    /**
     * @brief CNAME 체인을 zone 안에서 따라간다.
     *
     * @details RFC 1034는 CNAME을 만나면 이름을 바꿔 처음부터 다시 풀라고 한다.
     *          그래서 실재하는 이름뿐 아니라 빈 비단말과 와일드카드까지 같은 규칙으로 본다.
     * @details 횟수에 상한을 둔다. 서로를 가리키는 CNAME 두 개면 무한 반복이 된다.
     * @param answers 여기에 체인의 각 단계를 쌓는다.
     * @return 멈춘 위치. 호출자가 이것으로 rcode와 권한부를 정한다.
     */
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

    /**
     * @brief 이 이름을 덮는 와일드카드 소유자의 레코드.
     * @details 소유자 이름은 호출자가 질의 이름으로 찍으므로 여기서는 원본만 돌려준다.
     * @return 덮는 와일드카드가 없으면 None.
     */
    fn wildcard_records(&self, qname: &Name) -> Option<&[StoredRecord]> {
        let closest = self.closest_encloser(qname)?;
        if closest.eq_ignore_case(qname) {
            return None;
        }
        let source = prepend_wildcard(&closest);
        let mut key = [0u8; 255];
        self.records_for_key(source.canonical_key_into(&mut key)?)
    }

    /**
     * @brief CNAME 체인이 멈춘 위치에 맞는 응답을 만든다.
     *
     * @details RFC 6604는 "The RCODE in the ultimate DNS response MUST BE set based on
     *          the final query cycle"이라고 정한다. 이미 담은 CNAME은 그대로 두고 마지막
     *          주기의 판정만 rcode와 권한부에 반영한다.
     * @param answers 체인의 각 단계. 첫 CNAME이 이미 들어 있다.
     */
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

    /**
     * @brief 조상에 걸린 DNAME으로 응답을 만든다.
     *
     * @details DNAME은 이름의 뒷부분을 전부 바꾼다. 질의 이름의 앞 라벨들을 그대로 두고
     *          뒤를 대상 이름으로 교체한 CNAME을 합성해 함께 보낸다.
     * @note 합성한 이름이 255옥텟 상한을 넘으면 YXDOMAIN이다. 잘라서 보내면 질의자가
     *       엉뚱한 이름으로 이어 간다.
     */
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

    /**
     * @brief 와일드카드로 응답을 합성한다.
     * @details closest encloser가 질의 이름 자신이면 와일드카드가 끼어들 슬롯이 없다.
     *          그 이름은 실재하므로 와일드카드보다 우선한다.
     * @note 합성한 레코드의 소유자는 별표가 아니라 질의 이름으로 바꿔 준다.
     */
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

    /**
     * @brief 이 이름의 조상 중 zone에 실재하는 가장 긴 것.
     * @note 레코드가 있는 이름뿐 아니라 빈 비단말도 존재로 친다. 트리 구조상 자식이
     *       있으면 그 이름은 존재하는 것이다.
     */
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

    /** @brief 이 이름이 zone에 존재하는지. 빈 비단말도 존재로 친다. */
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

    /**
     * @brief 무할당 경로에서 부재를 판정한다.
     *
     * @details 평탄한 zone이면 곧장 NXDOMAIN이다. 아니면 조상을 거슬러 올라가며 DNAME과
     *          와일드카드 가지를 찾는다. DNAME이 먼저다. 그것이 걸리면 와일드카드는
     *          볼 필요가 없다. 와일드카드 가지가 없으면 확실한 NXDOMAIN이다.
     * @note 와일드카드 이름은 스택 버퍼에 조립한다. 별표 라벨은 항상 2바이트라 크기가
     *       미리 정해진다.
     * @return 판정할 수 없으면 Fallback. 호출자는 구조화된 경로로 넘어간다.
     */
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

    /**
     * @brief 답변이 가리키는 이름들의 주소를 추가 절에 담는다.
     * @details NS, MX, SRV, SVCB, HTTPS가 대상이다. SVCB 계열은 대상이 루트면 자기
     *          소유자 이름을 뜻하므로 그쪽을 본다. 같은 대상을 두 번 넣지 않는다.
     */
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

    /** @brief 이 이름의 A와 AAAA. zone 안에 있을 때만 나온다. */
    fn glue(&self, name: &Name) -> Vec<Record> {
        let mut out = Vec::new();
        if let Some(recs) = self.owner(name) {
            out.extend(self.of_type(recs, RecordType::A, name));
            out.extend(self.of_type(recs, RecordType::AAAA, name));
        }
        out
    }
}

/** @brief 여러 zone을 담고 이름으로 가장 긴 접미사 zone을 찾는다. */
#[derive(Default)]
pub struct ZoneStore {
    /** @brief 담고 있는 zone들. */
    zones: Vec<Zone>,
    /** @brief origin 정규 키에서 zone 위치로 가는 인덱스. */
    index: HashMap<Vec<u8>, usize>,
}

impl ZoneStore {
    /** @brief 빈 저장소. */
    pub fn new() -> Self {
        ZoneStore {
            zones: Vec::new(),
            index: HashMap::new(),
        }
    }

    /** @brief zone을 넣는다. 같은 origin이 이미 있으면 덮어쓴다. */
    pub fn add(&mut self, zone: Zone) {
        let key = zone.origin.canonical_key();
        if let Some(index) = self.index.get(&key).copied() {
            self.zones[index] = zone;
        } else {
            self.index.insert(key, self.zones.len());
            self.zones.push(zone);
        }
    }

    /** @brief zone이 하나도 없는지. */
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /** @brief 담고 있는 zone 전부. */
    pub fn zones(&self) -> &[Zone] {
        &self.zones
    }

    /** @brief origin이 정확히 이 이름인 zone. 전송 요청처럼 apex를 지목하는 경로에 쓴다. */
    pub fn zone_exact(&self, origin: &Name) -> Option<&Zone> {
        let mut storage = [0u8; 255];
        let key = origin.canonical_key_into(&mut storage)?;
        self.index.get(key).and_then(|index| self.zones.get(*index))
    }

    /** @brief 이 이름을 담는 zone 중 가장 깊은 것. */
    pub fn zone_for(&self, qname: &Name) -> Option<&Zone> {
        let mut storage = [0u8; 255];
        self.zone_for_key(qname.canonical_key_into(&mut storage)?)
    }

    /**
     * @brief 정규 키에서 조상으로 거슬러 올라가며 zone을 찾는다.
     * @note 가장 긴 접미사가 이긴다. 짧은 쪽을 고르면 자식 zone의 이름을 부모가 답하게 된다.
     */
    fn zone_for_key(&self, mut key: &[u8]) -> Option<&Zone> {
        loop {
            if let Some(index) = self.index.get(key) {
                return self.zones.get(*index);
            }
            key = parent_canonical_key(key)?;
        }
    }

    /** @brief 이름을 담는 zone에 질의한다. 담는 zone이 없으면 None. */
    pub fn query(&self, qname: &Name, qtype: RecordType) -> Option<Response> {
        self.zone_for(qname).map(|z| z.query(qname, qtype))
    }

    /**
     * @brief 응답을 조립하지 않고 곧장 와이어로 쓴다.
     *
     * @details A와 AAAA 질의, 그리고 평탄한 zone의 부재 응답만 이 경로로 간다. 그 밖에는
     *          거짓을 돌려 구조화된 경로로 넘긴다.
     * @warning fail-closed여야 한다. EDNS, 추가 절, 위임, DNSSEC, 그리고 응답을 바꾸는
     *          어떤 기능이라도 걸리면 이 경로를 쓰면 안 된다. 여기서 거르는 조건과 main의
     *          바깥 게이트가 함께 그 분리를 지킨다.
     * @return 실제로 응답을 썼으면 참. 거짓이면 버퍼는 건드리지 않은 상태다.
     */
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

    /**
     * @brief 빈 OPT 레코드를 추가 절에 쓴다.
     *
     * @details RFC 6891은 요청에 OPT가 있으면 응답에도 넣으라고 정한다. 이 경로가 맡는 질의는
     *          옵션이 없고 DO가 꺼진 것뿐이므로 담을 것도 없다. 알릴 UDP 크기만 담는다.
     * @param udp_payload 이 서버가 받아들이겠다고 알릴 크기. 요청 값이 아니라 이 서버의 값이다.
     * @invariant 호출자가 헤더의 ARCOUNT를 1로 적어 두어야 한다. 어긋나면 파서가 거부한다.
     */
    fn push_empty_opt(out: &mut Writer, udp_payload: u16) {
        out.push_u8(0);
        out.push_u16(RecordType::OPT.0);
        out.push_u16(udp_payload);
        out.push_u32(0);
        out.push_u16(0);
    }

    /**
     * @brief 헤더와 질문 절을 쓴다.
     * @note 질문의 이름은 정규화한 것이 아니라 받은 그대로 되비춘다. 대소문자를 바꾸면
     *       0x20 인코딩을 쓰는 질의자가 응답을 버린다.
     */
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

    /**
     * @brief A 또는 AAAA 답변을 곧장 와이어로 쓴다.
     * @details 소유자 이름은 질문을 가리키는 압축 포인터 하나로 끝난다. 질문은 항상
     *          오프셋 12에 있으므로 값이 고정이다.
     * @return 도중에 실패하면 버퍼를 비우고 거짓을 준다. 반쯤 쓴 응답을 남기면 안 된다.
     */
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

        // 같은 RRset의 답변은 전부 길이가 같고 소유자·타입·클래스·rdlength까지 같다.
        // 공간을 한 번 확보해 두고 고정 크기로 직접 써서, 레코드마다 생기던 작은 memcpy
        // 호출을 없앤다. qtype으로 루프를 구분해야 쓰는 길이가 컴파일 시점에 정해진다.
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

    /**
     * @brief 크기가 같은 답변 레코드들을 미리 잡은 구간에 이어 쓴다.
     *
     * @details 소유자는 질문을 가리키는 압축 포인터 하나로 끝난다. 질문은 항상 오프셋
     *          12에 있으므로 값이 고정이다. 레코드마다 달라지는 것은 TTL과 rdata뿐이라
     *          나머지 헤더는 루프 밖에서 한 번만 만든다.
     * @param LEN 레코드 하나의 와이어 길이. 컴파일 시점 상수여야 쓰기가 호출 없이 펼쳐진다.
     * @param rdata_len rdlength 곳에 적을 값.
     * @param fill 레코드별 rdata를 채운다. 거짓이면 그 레코드를 쓸 수 없다는 뜻이다.
     * @return 전부 썼으면 참. 거짓이면 호출자가 버퍼를 비워야 한다.
     * @invariant LEN은 헤더 12바이트에 rdata_len을 더한 값이다. 둘이 어긋나면 rdlength가
     *            실제 rdata 길이와 다른 응답이 조용히 나가므로 호출 시점에 못 고정한다.
     */
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

    /**
     * @brief NXDOMAIN 또는 NODATA 응답을 곧장 와이어로 쓴다.
     * @details 권한 절에 SOA를 담는다. 이름은 압축하지 않고 그대로 쓴다. 압축 테이블을
     *          만들지 않는 것이 이 경로의 전제다.
     */
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

    /**
     * @brief zone 밖을 가리키는 DNAME 응답을 곧장 와이어로 쓴다.
     *
     * @details 합성한 CNAME의 대상은 질의 이름의 앞부분과 DNAME 대상을 이은 것이다.
     *          앞부분은 질문 절에 이미 있으므로 압축 포인터로 가리키고 뒤만 새로 쓴다.
     * @note 대상이 zone 안이면 이 경로를 쓰지 않는다. 그때는 체인을 더 따라가야 해서
     *       구조화된 경로가 필요하다. 질의 이름의 대소문자가 바뀐 경우도 제외한다.
     *       포인터로 가리킨 바이트가 원래 이름이라 합성 결과가 달라진다.
     */
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

/**
 * @brief 빠른 경로가 응답을 만들 때 보는 요청 쪽 값들.
 *
 * @details 이 다섯은 언제나 함께 다닌다. 인자로 흩어 놓으면 하나를 빠뜨려도 컴파일은 되고
 *          질의와 어긋난 응답만 조용히 나간다.
 */
pub struct SimpleRequest<'a> {
    /** @brief 받은 그대로의 질문 이름. 대소문자를 되돌려줄 때 쓴다. */
    pub original_qname: &'a [u8],
    /** @brief 질의 종류. */
    pub qtype: RecordType,
    /** @brief 질의 번호. 응답에 그대로 되비춘다. */
    pub id: u16,
    /** @brief 되비출 요청 플래그. */
    pub request_flags: u16,
    /** @brief 응답 OPT에 알릴 UDP 크기. 없으면 OPT를 넣지 않는다. */
    pub edns: Option<u16>,
}

/** @brief 바이트를 소문자 16진 문자열로. */
fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/**
 * @brief SVCB 계열 RDATA를 텍스트로.
 * @note 매개변수는 이름 대신 번호로 적는다. 이 서버가 해석하지 않는 키도 그대로 되살릴 수
 *       있어야 하기 때문이다.
 */
fn svcb_text(priority: u16, target: &Name, params: &[(u16, Box<[u8]>)]) -> String {
    let mut s = format!("{priority} {}.", target.to_ascii_lower());
    for (key, val) in params {
        s.push(' ');
        s.push_str(&svcb_param_text(*key, val));
    }
    s
}

/**
 * @brief SvcParam 하나를 RFC 9460 표시 형식으로 적는다.
 *
 * @details 파서가 읽는 것과 같은 형식이어야 한다. 동적 갱신 결과를 파일에 적고 다시 읽는
 *          경로가 이 형식을 왕복하기 때문이다. 뜻을 모르는 값은 keyNNNNN에 character-string
 *          으로 적어 원래 바이트를 그대로 보존한다.
 */
fn svcb_param_text(key: u16, wire: &[u8]) -> String {
    /** @brief 길이 프리픽스가 붙은 이름 목록을 쉼표로 잇는다. */
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
    /** @brief 고정 길이 주소를 쉼표로 잇는다. */
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

/** @brief SvcParamKey 번호를 표시 이름으로. 등록부에 없으면 keyNNNNN이다. */
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

/** @brief base64로 적는다. ech 값이 이 형식을 쓴다. */
fn base64_encode(data: &[u8]) -> String {
    /** @brief 표준 base64 알파벳. */
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

/**
 * @brief 문자열을 zone 파일 형식으로 이스케이프해 따옴표로 감싼다.
 * @details 따옴표와 역슬래시는 역슬래시로, 그 밖의 비출력 문자와 주석·괄호 문자는 세 곳
 *          십진 이스케이프로 바꾼다. 그대로 두면 다시 읽을 때 토큰이 갈라진다.
 */
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

/**
 * @brief 레코드를 zone 파일 한 줄로 만든다.
 * @details 소유자와 이름 인자는 모두 점으로 끝나는 절대 이름으로 쓴다. 상대 이름으로
 *          내보내면 다시 읽을 때 origin에 따라 다른 이름이 된다.
 * @note 이 서버가 해석하지 않는 타입은 형식으로 적는다. 그래야 왕복이 손실 없이 된다.
 */
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

/**
 * @brief 로드 시점에 zone 전체의 규격 위반을 잡는다.
 *
 * @details 여기서 걸러 두면 질의 경로가 이런 경우를 다루지 않아도 된다. CNAME과 다른
 *          데이터가 한 이름에 공존하면 어느 쪽으로 답할지 정해지지 않고, DNAME이 둘이면
 *          같은 이름이 두 곳으로 향한다. NSEC3 매개변수가 zone 안에서 섞이면 검증기가
 *          부재 증명을 받아들이지 않는다.
 * @return 위반이 하나라도 있으면 오류. 로드 자체가 실패해야 반쯤 잘못된 zone이 서빙되지
 *         않는다.
 */
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

/** @brief NSEC3 RDATA에서 검증에 필요한 매개변수만 추출해 둔 형태. */
struct Nsec3Metadata<'a> {
    /** @brief 해시 알고리즘. */
    hash_algorithm: u8,
    /** @brief 플래그. opt-out 비트 외에는 켜져 있으면 안 된다. */
    flags: u8,
    /** @brief 추가 해시 반복 횟수. */
    iterations: u16,
    /** @brief salt. 복사하지 않고 원본을 빌린다. */
    salt: &'a [u8],
}

/**
 * @brief NSEC3 RDATA를 검사하며 매개변수를 추출한다.
 * @details 길이 필드를 하나씩 따라가며 경계를 확인한다. 다음 해시 길이가 SHA-1의 20이
 *          아니면 이 서버가 다루는 형태가 아니다.
 */
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

/**
 * @brief 타입 비트맵이 정규형인지.
 * @details 윈도우 번호가 엄격히 증가하고, 블록 길이가 1..=32이며, 마지막 옥텟이 0이 아니어야
 *          한다. 같은 타입 집합을 여러 바이트열로 쓸 수 있으면 서명 검증이 어긋난다.
 */
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

/** @brief 라벨이 SHA-1 해시를 base32hex로 적은 형태인지. 길이 32에 알파벳 안 문자만 온다. */
fn is_sha1_nsec3_owner(label: &[u8]) -> bool {
    label.len() == 32
        && label
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte.to_ascii_uppercase(), b'A'..=b'V'))
}

/** @brief 이름이 zone 안인지. 자기 자신도 포함이다. */
fn is_subdomain_or_eq(name: &Name, zone: &Name) -> bool {
    if name.num_labels() < zone.num_labels() {
        return false;
    }
    name.suffix(zone.num_labels()).eq_ignore_case(zone)
}

/**
 * @brief 정규 이름 순서 비교. 라벨을 뒤에서부터 본다.
 * @details 이 순서로 정렬해야 같은 부모 아래 형제가 인접하고, 부재 증명 체인과 소유자
 *          그룹화가 함께 성립한다.
 */
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

/**
 * @brief 부모 앞에 별표 라벨을 붙인다.
 * @note 부모가 이미 zone 안의 이름이라 길이 상한을 넘지 않는다. 그래서 실패를 가정하지 않는다.
 */
fn prepend_wildcard(parent: &Name) -> Name {
    let mut labels = Vec::with_capacity(parent.labels().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend(parent.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).expect("The wildcard name is valid")
}

/**
 * @brief 와일드카드로 합성한 답변의 소유자를 질의 이름으로 바꾼다.
 * @note 답변 절만 바꾼다. CNAME을 따라가며 붙은 다른 이름의 레코드는 그대로 둬야 한다.
 */
fn synthesize_owner(mut resp: Response, qname: &Name, wildcard_source: &Name) -> Response {
    for record in &mut resp.answers {
        if record.name.eq_ignore_case(wildcard_source) {
            record.name = qname.clone();
        }
    }
    resp
}

/** @brief 질의 판정 순서, 위임 경계, 무할당 경로와 구조화 경로의 동치성. */
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[test]
    /**
     * @brief 넷이 모두 같은 레코드를 하나만 남기는지.
     * @details RFC 2181은 label, class, type, data가 모두 같은 레코드가 둘 있는 것은
     *          뜻이 없으므로 서버가 억제해야 한다고 한다. 남겨 두면 응답이 그만큼 커지고,
     *          서명 영역에서는 서명이 덮는 집합과 내보내는 집합이 달라진다. 수명만 다른
     *          것은 중복이 아니라 5.2가 맞춰 주는 대상이므로 함께 본다.
     */
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
    /**
     * @brief 로드한 영역이 RFC 2181의 수명 규칙을 지키는지.
     * @details 5.2항은 한 RRSet의 수명이 모두 같아야 한다 정하고 서버가 다른 값을 담아
     *          보내는 것을 금지한다. 8항은 상한을 넘는 수명을 0으로 본다. 어느 타입으로
     *          들어와도 같아야 하므로 A와 TXT를 함께 본다.
     */
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

    /** @brief 저장 구조가 커지지 않았는지. 이 배치가 커지면 zone 하나의 메모리와 캐시 효율이 함께 나빠진다. */
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn authoritative_storage_layout_stays_compact() {
        assert_eq!(std::mem::size_of::<StoredRecord>(), 8);
        assert_eq!(std::mem::size_of::<RecordRange>(), 8);
        assert_eq!(std::mem::size_of::<OwnerSlot>(), 12);
    }

    #[test]
    /**
     * @brief 타입을 TTL 필드에 합쳐 넣어도 값이 온전히 돌아오는지.
     * @details 상한을 넘는 TTL은 깎이고, 그 밖의 타입은 TTL 필드에 타입을 담으므로
     *          아레나를 보지 않고도 타입이 나와야 한다.
     */
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
    /** @brief 같은 owner의 타입이 정렬되고 RRset slice가 이웃 타입을 섞지 않는지. */
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
    /** @brief 종전 두 번 필터와 타입 slice 한 번 순회의 격리 비용을 비교한다. */
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
    /** @brief 질문 헤더를 한 번에 잡아도 바이트와 한도 실패가 정확한지. */
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
    /** @brief 세 번 append하던 질문 헤더와 한 번 reserve한 후보의 격리 비용을 비교한다. */
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

    /** @brief 인덱스를 복제해도 조회 결과가 같은지. 해시 시드가 함께 복제돼야 한다. */
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

    /** @brief 루트 zone이 TLD 아래 이름을 직접 답하지 않고 참조로 넘기는지. */
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

    /** @brief TLD zone이 위임 아래 이름을 참조로 넘기는지. */
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

    /** @brief 와일드카드 이름을 만들 때 부모의 라벨 바이트가 그대로 보존되는지. */
    #[test]
    fn wildcard_owner_preserves_raw_parent_octets() {
        let parent = Name::from_labels(vec![vec![0xff], b"test".to_vec()]).unwrap();
        let wildcard = prepend_wildcard(&parent);
        let labels: Vec<&[u8]> = wildcard.labels().collect();
        assert_eq!(labels[0], b"*");
        assert_eq!(labels[1], [0xff]);
        assert_eq!(labels[2], b"test");
    }

    /** @brief 테스트용 영역 글. */
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

    /** @brief 테스트용 zone 하나. 위임·와일드카드·DNAME을 갖춰 두 경로 대조에 쓴다. */
    fn zone() -> Zone {
        parse_zone(ZONE, "example.com").unwrap()
    }

    /** @brief 무할당 경로와 구조화된 경로가 같은 답을 내는지. 어긋나면 어느 경로로 갔느냐에 따라 응답이 달라진다. */
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

        // 큰 RRset이 상한을 넘으면 반쯤 쓴 응답을 남기지 않고 전부 되돌려야 한다.
        // 답변 블록은 공간을 한 번에 확보하므로 이 판정이 첫 레코드를 쓰기 전에 난다.
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

    /** @brief 무할당 경로가 zone 상태를 바꾸지 않는지. 질의끼리 서로 영향을 주면 안 된다. */
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

    /** @brief zone을 파일로 내보내고 다시 읽어도 같은지. */
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

    /** @brief 이름 문자열을 Name으로. */
    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /**
     * @brief 메시지 하나에 담을 수 없는 RRset을 로드 시점에 거부하는지.
     * @details 주소는 전부 달라야 한다. 같은 값을 되풀이하면 RFC 2181의 중복 억제가
     *          먼저 걷어 내 상한에 닿지 않고, 테스트가 재려던 것을 측정하지 못한다.
     */
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

    /** @brief 문자열이 바이트 그대로 왕복하고, 이스케이프가 토큰을 갈라 놓지 않는지. */
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

    /** @brief CAA의 태그와 값이 왕복에서 보존되는지. */
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

    /** @brief 기본 zone 파싱. */
    #[test]
    fn parses_soa_and_records() {
        let z = zone();
        assert!(z.origin.eq_ignore_case(&n("example.com")));
        assert_eq!(z.soa.serial, 2024010101);
        assert_eq!(z.soa.refresh, 7200);
    }

    /** @brief 정확히 일치하는 이름의 답변에 권한 비트가 서는지. */
    #[test]
    fn exact_a_answer_is_authoritative() {
        let r = zone().query(&n("www.example.com"), RecordType::A);
        assert_eq!(r.rcode, 0);
        assert!(r.authoritative);
        assert_eq!(r.answers.len(), 1);
        assert!(matches!(r.answers[0].rdata, RData::A(ip) if ip == Ipv4Addr::new(192, 0, 2, 2)));
    }

    /** @brief NODATA는 답변 없이 SOA만 담는지. */
    #[test]
    fn nodata_returns_soa_no_answer() {
        let r = zone().query(&n("www.example.com"), RecordType::MX);
        assert_eq!(r.rcode, 0);
        assert!(r.answers.is_empty());
        assert_eq!(r.authority.len(), 1);
        assert!(matches!(r.authority[0].rdata, RData::Soa(_)));
    }

    /** @brief NXDOMAIN도 SOA를 담는지. 그 TTL이 부정 캐시 기간을 정한다. */
    #[test]
    fn nxdomain_returns_soa() {
        let r = zone().query(&n("nope.example.com"), RecordType::A);
        assert_eq!(r.rcode, 3);
        assert!(r.authoritative);
        assert!(matches!(r.authority[0].rdata, RData::Soa(_)));
    }

    /** @brief zone 안의 CNAME은 이 서버가 끝까지 따라가는지. */
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
    /**
     * @brief CNAME 체인이 멈추는 다섯 곳이 각각 맞는 응답을 내는지.
     *
     * @details RFC 6604는 rcode를 체인의 마지막 질의 주기로 정하라고 한다. 다섯을
     *          하나로 합치면 부재가 NOERROR로 나가고, 부정 SOA가 빠져 부정 캐시도 되지 않아
     *          같은 질의가 되풀이된다.
     */
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
    /**
     * @brief SVCB 매개변수가 텍스트를 왕복해도 그대로인지.
     *
     * @details 동적 갱신 결과를 파일로 적고 다시 읽는 경로가 이 형식을 지난다. 적는 쪽과
     *          읽는 쪽이 어긋나면 재시작 한 번에 값이 달라진다.
     */
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

    /** @brief 와일드카드 답변의 소유자가 질의 이름으로 바뀌는지. */
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

    /** @brief 빈 비단말은 존재하므로 NODATA이고, 부모 와일드카드가 끼어들지 못하는지. */
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

    /** @brief 위임 참조에 NS와 glue가 함께 담기는지. */
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

    /** @brief 위임 지점의 DS는 부모 것이므로 권한 있게 답하는지. */
    #[test]
    fn delegation_cut_serves_parent_ds_authoritatively() {
        let r = zone().query(&n("sub.example.com"), RecordType::DS);
        assert_eq!(r.rcode, 0);
        assert!(r.authoritative);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].rtype, RecordType::DS);
    }

    /** @brief 위임 아래 glue를 답변으로 끌어올리지 않는지. 그것은 자식 zone의 데이터다. */
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

    /** @brief DNAME은 자손만 바꾸고 자기 이름은 건드리지 않는지. */
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

    /** @brief DNAME 대상이 zone 안이면 그 답까지 함께 담는지. */
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

    /** @brief 체인 끝의 답변이 가리키는 이름의 주소가 추가 절에 담기는지. */
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

    /** @brief CNAME과 다른 데이터의 공존, 그리고 순환을 로드 시점에 거부하는지. */
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

    /** @brief 긴 체인과 순환이 질의 경로를 붙잡지 않는지. */
    #[test]
    fn zone_validates_long_cname_chains_and_cycles() {
        /** @brief 테스트에 쓸 체인 길이. */
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

    /** @brief apex의 SOA와 NS가 제대로 답해지는지. */
    #[test]
    fn apex_soa_and_ns() {
        let z = zone();
        let soa = z.query(&n("example.com"), RecordType::SOA);
        assert_eq!(soa.answers.len(), 1);
        assert!(matches!(soa.answers[0].rdata, RData::Soa(_)));
        let ns = z.query(&n("example.com"), RecordType::NS);
        assert_eq!(ns.answers.len(), 2);
    }

    /** @brief MX가 가리키는 이름의 주소가 추가 절에 담기는지. */
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
    /** @brief 서비스 기록과 함께 그 대상의 주소도 담아 보내는지. 안 실으면 클라이언트가 한 번 더 묻는다. */
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
    /** @brief 같은 대상이 여럿이어도 딸린 기록이 늘어나지 않는지. */
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
    /** @brief 영역 전송으로 받은 기록이 다시 영역이 되는지. */
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

    /** @brief 이름을 감춘 형태의 테스트용 증명 기록. */
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
    /** @brief 미리 서명된 영역의 증명 설정이 어긋나면 거부하는지. 섞이면 없는 것을 있다고 한다. */
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
    /** @brief 글자로 바꿀 수 없는 이름이 서로 겹치지 않는지. 겹치면 남의 답을 준다. */
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
    /** @brief 가장 좁게 맞는 영역이 이기는지. */
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
    /** @brief 같은 이름의 영역을 두 번 올리면 교체하는지. */
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
    /** @brief 데이터베이스 주소를 이름으로 풀지 않는지. 풀면 시작 중 순환이 된다. */
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
    /** @brief 대괄호로 감싼 IPv6 주소가 읽히는지. */
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
