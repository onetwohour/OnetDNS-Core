/*!
 * @brief 레코드 타입과 RDATA: 타입별 파싱, 검사, 인코딩.
 *
 * @details 모르는 타입은 RData::Unknown으로 원시 바이트를 보존해 그대로 중계한다.
 *          단, 압축 이름을 품을 수 있는 이전 타입은 예외로 거부한다. 원시 바이트를 다시
 *          쓰면 이전 메시지 기준의 포인터가 새 메시지에서 엉뚱한 곳을 가리키기 때문이다.
 */

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::name::Name;
use crate::wire::{Reader, Writer};
use crate::ProtoError;

/**
 * @brief DNS 레코드 타입 코드.
 *
 * @details 열거형이 아닌 newtype이라 미지의 타입도 값으로 담아 전달한다. 새 타입이 등록될
 *          때마다 코드를 고치지 않아도 캐시와 중계가 동작하게 하려는 설계다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordType(pub u16);

#[allow(non_upper_case_globals)]
impl RecordType {
    /** @brief IPv4 주소. */
    pub const A: RecordType = RecordType(1);
    /** @brief 이름 서버. */
    pub const NS: RecordType = RecordType(2);
    /** @brief 별칭. */
    pub const CNAME: RecordType = RecordType(5);
    /** @brief 영역의 권한 정보. */
    pub const SOA: RecordType = RecordType(6);
    /** @brief 주소에서 이름으로. */
    pub const PTR: RecordType = RecordType(12);
    /** @brief 메일 서버. */
    pub const MX: RecordType = RecordType(15);
    /** @brief 임의의 글. */
    pub const TXT: RecordType = RecordType(16);
    /** @brief IPv6 주소. */
    pub const AAAA: RecordType = RecordType(28);
    /** @brief 규칙으로 다른 이름을 이끌어 낸다. */
    pub const NAPTR: RecordType = RecordType(35);
    /** @brief 이름 아래를 전부 옮긴다. */
    pub const DNAME: RecordType = RecordType(39);
    /** @brief 서비스가 있는 곳과 포트. */
    pub const SRV: RecordType = RecordType(33);
    /** @brief 원격 접속 키 지문. */
    pub const SSHFP: RecordType = RecordType(44);
    /** @brief 이 이름이 쓸 인증서를 못 고정한다. */
    pub const TLSA: RecordType = RecordType(52);
    /** @brief 주소 하나. */
    pub const URI: RecordType = RecordType(256);
    /** @brief 확장 옵션을 담는 유사 기록. */
    pub const OPT: RecordType = RecordType(41);
    /** @brief 아래 영역의 키 지문. */
    pub const DS: RecordType = RecordType(43);
    /** @brief 서명. */
    pub const RRSIG: RecordType = RecordType(46);
    /** @brief 이름 사이에 아무것도 없다는 증명. */
    pub const NSEC: RecordType = RecordType(47);
    /** @brief 서명에 쓰는 공개 키. */
    pub const DNSKEY: RecordType = RecordType(48);
    /** @brief 이름을 감춘 형태의 부재 증명. */
    pub const NSEC3: RecordType = RecordType(50);
    /** @brief 위 영역에 올릴 키 지문. */
    pub const CDS: RecordType = RecordType(59);
    /** @brief 위 영역에 올릴 공개 키. */
    pub const CDNSKEY: RecordType = RecordType(60);
    /** @brief 서비스가 있는 곳과 그 성질. */
    pub const SVCB: RecordType = RecordType(64);
    /** @brief 웹 서비스가 있는 곳과 그 성질. */
    pub const HTTPS: RecordType = RecordType(65);
    /** @brief 이 이름의 인증서를 낼 수 있는 기관. */
    pub const CAA: RecordType = RecordType(257);
    /** @brief 모든 종류를 묻는 질의 전용. */
    pub const ANY: RecordType = RecordType(255);

    /**
     * @brief 표시용 타입 이름.
     * @return 이름을 아는 타입의 약칭, 모르면 "UNKNOWN". 로그·대시보드 전용이며
     *         이 문자열을 파싱해 되돌리는 용도로 쓰지 않는다.
     */
    pub fn name(self) -> &'static str {
        match self.0 {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            39 => "DNAME",
            41 => "OPT",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            50 => "NSEC3",
            59 => "CDS",
            60 => "CDNSKEY",
            64 => "SVCB",
            65 => "HTTPS",
            257 => "CAA",
            255 => "ANY",
            _ => "UNKNOWN",
        }
    }
}

/**
 * @brief DNS 클래스 코드.
 * @note OPT 레코드는 이 필드를 클래스가 아니라 UDP 페이로드 크기로 쓴다.
 *       UPDATE(RFC 2136)도 254/255를 연산 부호로 전용한다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsClass(pub u16);

#[allow(non_upper_case_globals)]
impl DnsClass {
    /** @brief 인터넷 클래스. 실질적으로 유일하게 쓰이는 값이다. */
    pub const IN: DnsClass = DnsClass(1);
}

/**
 * @brief 타입별로 해석된 레코드 데이터.
 *
 * @details 크기가 캐시 비용을 직접 좌우한다. 가장 큰 변형이 모든 캐시 레코드의
 *          비용을 정하므로, 드물고 큰 변형은 Box로 간접화한다(SOA, NAPTR).
 *          typed_rdata_tests의 레이아웃 단언이 이 크기를 고정해 두는 감시 장치다.
 * @invariant record_type()이 돌려주는 타입은 이 변형과 항상 일치한다. 메시지 인코더가
 *            레코드의 TYPE 필드와 이 값을 대조해 어긋나면 인코딩을 거부한다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum RData {
    /** @brief IPv4 주소. */
    A(Ipv4Addr),
    /** @brief IPv6 주소. */
    Aaaa(Ipv6Addr),
    /** @brief 이 영역의 이름 서버. */
    Ns(Name),
    /** @brief 이 이름의 별칭. */
    Cname(Name),
    /** @brief 이 이름 아래를 전부 옮긴다. */
    Dname(Name),
    /** @brief 주소에서 이름으로. */
    Ptr(Name),
    /** @brief 메일 서버. */
    Mx { preference: u16, exchange: Name },
    /** @brief 임의의 글. */
    Txt(Vec<Vec<u8>>),

    /** @brief 영역의 권한 정보. */
    Soa(Box<Soa>),
    /** @brief 서비스가 있는 곳과 포트. */
    Srv {
        /** @brief 먼저 볼 순서. 작을수록 먼저다. */
        priority: u16,
        /** @brief 같은 순서 안에서 나눠 가질 몫. */
        weight: u16,
        /** @brief 붙을 포트. */
        port: u16,
        /** @brief 붙을 이름. */
        target: Name,
    },

    /** @brief 인증서를 낼 수 있는 기관. */
    Caa {
        /** @brief 이 항목을 반드시 이해해야 하는지 나타내는 표시. */
        flags: u8,
        /** @brief 무엇을 제한하는지. */
        tag: Box<[u8]>,
        /** @brief 그 값. */
        value: Box<[u8]>,
    },

    /** @brief 이 이름이 쓸 인증서를 못 고정한다. */
    Tlsa {
        /** @brief 이 기록을 어떻게 쓸지. */
        usage: u8,
        /** @brief 인증서의 어느 부분을 가리키는지. */
        selector: u8,
        /** @brief 그 부분을 어떻게 맞춰 볼지. */
        matching: u8,
        /** @brief 맞춰 볼 값. */
        data: Vec<u8>,
    },

    /** @brief 원격 접속 키 지문. */
    Sshfp {
        /** @brief 키 알고리즘. */
        algorithm: u8,
        /** @brief 지문을 만든 방식. */
        fp_type: u8,
        /** @brief 지문. */
        fingerprint: Vec<u8>,
    },

    /** @brief 규칙으로 다른 이름을 이끌어 낸다. */
    Naptr(Box<Naptr>),

    /** @brief 주소 하나. */
    Uri {
        /** @brief 먼저 볼 순서. */
        priority: u16,
        /** @brief 같은 순서 안에서 나눠 가질 몫. */
        weight: u16,
        /** @brief 가리키는 주소. */
        target: Vec<u8>,
    },

    /** @brief 서비스가 있는 곳과 그 성질. */
    Svcb {
        /** @brief 먼저 볼 순서. 0이면 다른 이름으로 넘긴다는 뜻이다. */
        priority: u16,
        /** @brief 붙을 이름. */
        target: Name,
        /** @brief 이 서비스의 성질들. */
        params: Box<[(u16, Box<[u8]>)]>,
    },

    /** @brief 웹 서비스가 있는 곳과 그 성질. */
    Https {
        /** @brief 먼저 볼 순서. 0이면 다른 이름으로 넘긴다는 뜻이다. */
        priority: u16,
        /** @brief 붙을 이름. */
        target: Name,
        /** @brief 이 서비스의 성질들. */
        params: Box<[(u16, Box<[u8]>)]>,
    },

    /** @brief 이 서버가 뜻을 모르는 종류. 바이트를 그대로 전달한다. */
    Unknown(u16, Vec<u8>),
}

/** @brief NAPTR RDATA(RFC 3403). 크기가 커서 RData에서 Box로 간접 참조한다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naptr {
    /** @brief 먼저 볼 순서. */
    pub order: u16,
    /** @brief 같은 순서 안에서의 우선순위. */
    pub preference: u16,
    /** @brief 이 기록을 어떻게 쓸지 나타내는 글자. */
    pub flags: Vec<u8>,
    /** @brief 어떤 서비스에 쓰는지. */
    pub services: Vec<u8>,
    /** @brief 이름을 바꾸는 규칙. */
    pub regexp: Vec<u8>,
    /** @brief 규칙 대신 쓸 이름. */
    pub replacement: Name,
}

/**
 * @brief SOA RDATA. zone의 권한 정보와 2차 서버 타이머를 담는다.
 * @note serial은 RFC 1982 순환 산술로 비교한다. 단순 크기 비교를 하면 되감긴 직렬번호가
 *       영원히 최신으로 남는다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    /** @brief 이 영역의 주 서버. */
    pub mname: Name,
    /** @brief 관리자 주소를 이름으로 적은 것. */
    pub rname: Name,
    /** @brief 시리얼. 바뀌면 하위 서버가 다시 받아 간다. */
    pub serial: u32,
    /** @brief 하위 서버가 다시 물어볼 간격. */
    pub refresh: u32,
    /** @brief 실패했을 때 다시 물어볼 간격. */
    pub retry: u32,
    /** @brief 이 시간이 지나면 하위 서버가 잡은 영역을 버린다. */
    pub expire: u32,
    /** @brief 부정 응답을 담아 둘 기간. */
    pub minimum: u32,
}

/** @brief 길이 접두사가 붙은 character-string(최대 255옥텟)을 읽는다. */
fn read_char_string(r: &mut Reader) -> Result<Vec<u8>, ProtoError> {
    let n = r.u8()? as usize;
    Ok(r.bytes(n)?.to_vec())
}

/** @brief character-string을 쓴다. 255옥텟을 넘으면 자르지 않고 인코딩을 실패시킨다. */
fn write_char_string(w: &mut Writer, s: &[u8]) {
    let Ok(n) = u8::try_from(s.len()) else {
        w.fail("DNS character string exceeds 255 bytes");
        return;
    };
    w.push_u8(n);
    w.push_bytes(s);
}

/**
 * @brief RDATA에 압축 이름을 품을 수 있는데 이 서버가 해석하지 않는 이전 타입인지.
 *
 * @details MD/MF/MB/MG/MR/MINFO/RP/AFSDB/RT/SIG/PX/NXT 계열이다. 미해석 바이트로 보관한 뒤
 *          다른 메시지에 그대로 다시 쓰면, 원본 메시지 기준의 압축 포인터가 새 메시지의
 *          엉뚱한 위치를 가리켜 이름이 조작된다. 파싱 단계에서 아예 거부하는 이유다.
 */
fn is_unsupported_name_bearing(rtype: RecordType) -> bool {
    matches!(
        rtype.0,
        3 | 4 | 7 | 8 | 9 | 14 | 17 | 18 | 21 | 23 | 26 | 30 | 36
    )
}

/**
 * @brief SVCB/HTTPS 매개변수 목록의 문법을 검사한다(RFC 9460).
 *
 * @details 키는 엄격한 오름차순이어야 하고 65535는 예약이다. 정렬 강제는 mandatory
 *          자기참조 검사가 이진 탐색을 쓸 수 있게 하는 전제이기도 하다.
 * @param priority 0이면 AliasMode다. 이때는 매개변수 의미가 정의되지 않아 순서 검사만 한다.
 * @return 키 순서, mandatory 자기일관성, alpn 길이 표기, port·ipv4hint·ipv6hint 길이 중
 *         하나라도 어긋나면 오류.
 */
fn validate_svcb_params(priority: u16, params: &[(u16, Box<[u8]>)]) -> Result<(), ProtoError> {
    if params.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(ProtoError::Message(
            "SVCB parameter keys are not strictly increasing".into(),
        ));
    }
    if params.last().is_some_and(|(key, _)| *key == u16::MAX) {
        return Err(ProtoError::Message(
            "SVCB parameter key 65535 is reserved".into(),
        ));
    }

    if priority == 0 {
        return Ok(());
    }

    let has = |key| params.binary_search_by_key(&key, |(key, _)| *key).is_ok();
    for (key, value) in params {
        match *key {
            0 => {
                if value.is_empty() || value.len() % 2 != 0 {
                    return Err(ProtoError::Message(
                        "SVCB mandatory value must be a non-empty list of u16 keys".into(),
                    ));
                }
                let mut previous = None;
                for bytes in value.chunks_exact(2) {
                    let listed = u16::from_be_bytes([bytes[0], bytes[1]]);
                    if listed == 0
                        || previous.is_some_and(|previous| listed <= previous)
                        || !has(listed)
                    {
                        return Err(ProtoError::Message(
                            "SVCB mandatory key list is not self-consistent".into(),
                        ));
                    }
                    previous = Some(listed);
                }
            }
            1 => {
                let mut position = 0usize;
                while position < value.len() {
                    let len = usize::from(value[position]);
                    position += 1;
                    if len == 0 || position.saturating_add(len) > value.len() {
                        return Err(ProtoError::Message(
                            "Invalid length prefix in SVCB alpn value".into(),
                        ));
                    }
                    position += len;
                }
                if position == 0 {
                    return Err(ProtoError::Message("SVCB alpn value is empty".into()));
                }
            }
            2 if !value.is_empty() || !has(1) => {
                return Err(ProtoError::Message(
                    "SVCB no-default-alpn must be empty and requires alpn".into(),
                ));
            }
            3 if value.len() != 2 => {
                return Err(ProtoError::Message(
                    "SVCB port value must be exactly 2 bytes".into(),
                ));
            }
            4 if value.is_empty() || value.len() % 4 != 0 => {
                return Err(ProtoError::Message("Invalid SVCB ipv4hint length".into()));
            }
            6 if value.is_empty() || value.len() % 16 != 0 => {
                return Err(ProtoError::Message("Invalid SVCB ipv6hint length".into()));
            }
            _ => {}
        }
    }
    Ok(())
}

impl RData {
    /** @brief SOA를 박싱해 변형으로 감싼다. */
    pub fn soa(soa: Soa) -> Self {
        Self::Soa(Box::new(soa))
    }

    /** @brief 이 변형이 나타내는 레코드 타입. 인코더가 TYPE 필드와 대조하는 값이다. */
    pub fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::Aaaa(_) => RecordType::AAAA,
            RData::Ns(_) => RecordType::NS,
            RData::Cname(_) => RecordType::CNAME,
            RData::Dname(_) => RecordType::DNAME,
            RData::Ptr(_) => RecordType::PTR,
            RData::Mx { .. } => RecordType::MX,
            RData::Txt(_) => RecordType::TXT,
            RData::Soa(_) => RecordType::SOA,
            RData::Srv { .. } => RecordType::SRV,
            RData::Caa { .. } => RecordType::CAA,
            RData::Tlsa { .. } => RecordType::TLSA,
            RData::Sshfp { .. } => RecordType::SSHFP,
            RData::Naptr(_) => RecordType::NAPTR,
            RData::Uri { .. } => RecordType::URI,
            RData::Svcb { .. } => RecordType::SVCB,
            RData::Https { .. } => RecordType::HTTPS,
            RData::Unknown(t, _) => RecordType(*t),
        }
    }

    /**
     * @brief 인코딩 전 RDATA 내부 제약을 검사한다.
     * @details 지금은 SVCB/HTTPS만 대상이다. 직접 조립한 값이 파서가 거부할 형태로
     *          나가지 않게 막는 대칭 장치다.
     */
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            RData::Svcb {
                priority, params, ..
            }
            | RData::Https {
                priority, params, ..
            } => validate_svcb_params(*priority, params),
            _ => Ok(()),
        }
    }

    /**
     * @brief 타입에 맞춰 RDATA를 해석한다.
     *
     * @param rdlen 선언된 RDATA 길이. 가변 길이 뒷부분(CAA 값, TLSA 데이터 등)의 길이를 여기서
     *              역산하므로, 고정 헤더보다 작으면 checked_sub가 오류로 잡는다.
     * @note 호출자(Record::parse_inner)가 이미 Reader::limit을 RDATA 끝으로 좁혀 두었다.
     *       이름 파싱이 자기 레코드 밖을 넘겨다보지 못하게 하는 장치다.
     * @return 이름을 품는 미지원 이전 타입은 오류, 그 밖의 미지 타입은 Unknown으로 보존.
     */
    pub fn parse(rtype: RecordType, r: &mut Reader, rdlen: usize) -> Result<RData, ProtoError> {
        Ok(match rtype {
            RecordType::A => {
                let b = r.bytes(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RecordType::AAAA => {
                let b = r.bytes(16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            RecordType::NS => RData::Ns(Name::parse(r)?),
            RecordType::CNAME => RData::Cname(Name::parse(r)?),
            RecordType::DNAME => RData::Dname(Name::parse(r)?),
            RecordType::PTR => RData::Ptr(Name::parse(r)?),
            RecordType::MX => RData::Mx {
                preference: r.u16()?,
                exchange: Name::parse(r)?,
            },
            RecordType::TXT => {
                let end = r.pos + rdlen;
                let mut chunks = vec![];
                while r.pos < end {
                    let n = r.u8()? as usize;
                    chunks.push(r.bytes(n)?.to_vec());
                }
                RData::Txt(chunks)
            }
            RecordType::SOA => RData::Soa(Box::new(Soa {
                mname: Name::parse(r)?,
                rname: Name::parse(r)?,
                serial: r.u32()?,
                refresh: r.u32()?,
                retry: r.u32()?,
                expire: r.u32()?,
                minimum: r.u32()?,
            })),
            RecordType::SRV => RData::Srv {
                priority: r.u16()?,
                weight: r.u16()?,
                port: r.u16()?,
                target: Name::parse(r)?,
            },
            RecordType::CAA => {
                let flags = r.u8()?;
                let tag_len = r.u8()? as usize;
                let tag = Box::from(r.bytes(tag_len)?);
                let vlen = rdlen.checked_sub(2 + tag_len).ok_or(ProtoError::Eof)?;
                let value = Box::from(r.bytes(vlen)?);
                RData::Caa { flags, tag, value }
            }
            RecordType::TLSA => {
                let usage = r.u8()?;
                let selector = r.u8()?;
                let matching = r.u8()?;
                let dlen = rdlen.checked_sub(3).ok_or(ProtoError::Eof)?;
                RData::Tlsa {
                    usage,
                    selector,
                    matching,
                    data: r.bytes(dlen)?.to_vec(),
                }
            }
            RecordType::SSHFP => {
                let algorithm = r.u8()?;
                let fp_type = r.u8()?;
                let flen = rdlen.checked_sub(2).ok_or(ProtoError::Eof)?;
                RData::Sshfp {
                    algorithm,
                    fp_type,
                    fingerprint: r.bytes(flen)?.to_vec(),
                }
            }
            RecordType::NAPTR => {
                let order = r.u16()?;
                let preference = r.u16()?;
                let flags = read_char_string(r)?;
                let services = read_char_string(r)?;
                let regexp = read_char_string(r)?;
                let replacement = Name::parse(r)?;
                RData::Naptr(Box::new(Naptr {
                    order,
                    preference,
                    flags,
                    services,
                    regexp,
                    replacement,
                }))
            }
            RecordType::URI => {
                let priority = r.u16()?;
                let weight = r.u16()?;
                let tlen = rdlen.checked_sub(4).ok_or(ProtoError::Eof)?;
                RData::Uri {
                    priority,
                    weight,
                    target: r.bytes(tlen)?.to_vec(),
                }
            }
            RecordType::SVCB | RecordType::HTTPS => {
                let end = r.pos + rdlen;
                let priority = r.u16()?;
                let target = Name::parse_uncompressed(r)?;
                let mut params = Vec::new();
                while r.pos < end {
                    let key = r.u16()?;
                    let plen = r.u16()? as usize;
                    params.push((key, Box::from(r.bytes(plen)?)));
                }
                validate_svcb_params(priority, &params)?;
                if rtype == RecordType::SVCB {
                    RData::Svcb {
                        priority,
                        target,
                        params: params.into_boxed_slice(),
                    }
                } else {
                    RData::Https {
                        priority,
                        target,
                        params: params.into_boxed_slice(),
                    }
                }
            }
            other if is_unsupported_name_bearing(other) => {
                return Err(ProtoError::Message(format!(
                    "Unsupported RDATA type {} that may contain compressed names",
                    other.0
                )))
            }
            other => RData::Unknown(other.0, r.bytes(rdlen)?.to_vec()),
        })
    }

    /**
     * @brief RDATA 본문을 쓴다. 길이 접두사는 호출자가 백패치한다.
     *
     * @note RDATA 안 이름을 압축해도 되는 것은 RFC 1035 가 정의한 종류뿐이다. RFC 3597이
     *       그 밖의 종류를 금하는 까닭은, 압축 포인터가 그 메시지 안에서만 뜻이 있어서
     *       RDATA 를 전부 옮겨 담는 쪽이 엉뚱한 위치를 가리키는 이름을 만들기 때문이다.
     *       SRV, NAPTR, DNAME, SVCB, HTTPS 가 여기 해당한다.
     */
    pub fn encode(&self, w: &mut Writer) {
        match self {
            RData::A(ip) => w.push_bytes(&ip.octets()),
            RData::Aaaa(ip) => w.push_bytes(&ip.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.encode(w),
            RData::Dname(n) => n.encode_uncompressed(w),
            RData::Mx {
                preference,
                exchange,
            } => {
                w.push_u16(*preference);
                exchange.encode(w);
            }
            RData::Txt(chunks) => {
                for c in chunks {
                    let Ok(len) = u8::try_from(c.len()) else {
                        w.fail("TXT string exceeds 255 bytes");
                        return;
                    };
                    w.push_u8(len);
                    w.push_bytes(c);
                }
            }
            RData::Soa(s) => {
                s.mname.encode(w);
                s.rname.encode(w);
                w.push_u32(s.serial);
                w.push_u32(s.refresh);
                w.push_u32(s.retry);
                w.push_u32(s.expire);
                w.push_u32(s.minimum);
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                w.push_u16(*priority);
                w.push_u16(*weight);
                w.push_u16(*port);
                target.encode_uncompressed(w);
            }
            RData::Caa { flags, tag, value } => {
                w.push_u8(*flags);
                let Ok(tag_len) = u8::try_from(tag.len()) else {
                    w.fail("CAA tag exceeds 255 bytes");
                    return;
                };
                w.push_u8(tag_len);
                w.push_bytes(tag);
                w.push_bytes(value);
            }
            RData::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => {
                w.push_u8(*usage);
                w.push_u8(*selector);
                w.push_u8(*matching);
                w.push_bytes(data);
            }
            RData::Sshfp {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                w.push_u8(*algorithm);
                w.push_u8(*fp_type);
                w.push_bytes(fingerprint);
            }
            RData::Naptr(naptr) => {
                w.push_u16(naptr.order);
                w.push_u16(naptr.preference);
                write_char_string(w, &naptr.flags);
                write_char_string(w, &naptr.services);
                write_char_string(w, &naptr.regexp);
                naptr.replacement.encode_uncompressed(w);
            }
            RData::Uri {
                priority,
                weight,
                target,
            } => {
                w.push_u16(*priority);
                w.push_u16(*weight);
                w.push_bytes(target);
            }
            RData::Svcb {
                priority,
                target,
                params,
            }
            | RData::Https {
                priority,
                target,
                params,
            } => {
                if let Err(error) = validate_svcb_params(*priority, params) {
                    w.fail(error.to_string());
                    return;
                }
                w.push_u16(*priority);
                target.encode_uncompressed(w);
                for (key, val) in params {
                    w.push_u16(*key);
                    let Ok(len) = u16::try_from(val.len()) else {
                        w.fail("SVCB parameter exceeds 65,535 bytes");
                        return;
                    };
                    w.push_u16(len);
                    w.push_bytes(val);
                }
            }
            RData::Unknown(_, bytes) => w.push_bytes(bytes),
        }
    }
}

/**
 * @brief 자원 레코드 하나: owner 이름, 타입, 클래스, TTL, 데이터.
 * @invariant rtype은 rdata.record_type()과 같아야 한다. 메시지 인코더가 이 불변식을
 *            검사해 어긋난 레코드를 내보내지 않는다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /** @brief 이 기록의 이름. */
    pub name: Name,
    /** @brief 기록 종류. */
    pub rtype: RecordType,
    /** @brief 기록 부류. */
    pub class: DnsClass,
    /** @brief 이 기록의 수명. */
    pub ttl: u32,
    /** @brief 기록 내용. */
    pub rdata: RData,
}

impl Record {
    /** @brief IN 클래스 레코드를 만든다. 타입은 RDATA에서 끌어와 불일치를 원천 차단한다. */
    pub fn new(name: Name, ttl: u32, rdata: RData) -> Self {
        Self {
            rtype: rdata.record_type(),
            name,
            class: DnsClass::IN,
            ttl,
            rdata,
        }
    }

    /** @brief 일반 레코드를 읽는다. 빈 RDATA는 타입 규칙대로만 허용된다. */
    pub fn parse(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, None)
    }

    /**
     * @brief UPDATE 선결 조건 섹션의 레코드를 읽는다.
     * @details 클래스 NONE(254)/ANY(255)는 "이 이름이 있는가/없는가"만 묻는 곳이라
     *          타입별 RDATA 없이 빈 본문이 정상이다.
     */
    pub(crate) fn parse_update_empty(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, Some(&[254, 255]))
    }

    /**
     * @brief UPDATE 갱신 섹션의 레코드를 읽는다.
     * @details 클래스 ANY(255)는 삭제 연산이라 빈 RDATA가 정상이다. NONE은 지울 대상
     *          데이터를 담아야 하므로 여기서는 허용하지 않는다.
     */
    pub(crate) fn parse_update_operation(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, Some(&[255]))
    }

    /**
     * @brief 레코드 헤더와 RDATA를 읽는 공통 구현.
     *
     * @details RDATA를 읽는 동안 Reader::limit을 선언된 끝으로 좁혔다가 되돌린다. 이름
     *          파싱이 자기 레코드 경계를 넘어 읽는 것을 막는 핵심 장치다. 다 읽은 뒤 커서가
     *          정확히 그 끝에 있는지 확인해, 선언한 길이와 실제 소비량이 어긋난 레코드를
     *          거부한다.
     * @param empty_rdata_classes 빈 RDATA를 허용할 클래스 목록. UPDATE 섹션에만 준다.
     */
    fn parse_inner(
        r: &mut Reader,
        empty_rdata_classes: Option<&[u16]>,
    ) -> Result<Record, ProtoError> {
        let name = Name::parse(r)?;
        let rtype = RecordType(r.u16()?);
        let class = DnsClass(r.u16()?);
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let end = start.checked_add(rdlen).ok_or(ProtoError::Eof)?;
        if end > r.limit {
            return Err(ProtoError::Eof);
        }
        let previous_limit = r.limit;
        r.limit = end;
        let parsed = if rdlen == 0
            && empty_rdata_classes.is_some_and(|classes| classes.contains(&class.0))
        {
            Ok(RData::Unknown(rtype.0, Vec::new()))
        } else {
            RData::parse(rtype, r, rdlen)
        };
        r.limit = previous_limit;
        let rdata = parsed?;
        if r.pos != end {
            return Err(ProtoError::Name("RDATA length does not match".into()));
        }
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    /** @brief 레코드 전체를 쓴다. */
    pub fn encode(&self, w: &mut Writer) {
        self.encode_with_ttl(w, self.ttl);
    }

    /**
     * @brief TTL 필드에 다른 값을 넣어 레코드를 쓴다.
     * @details OPT 전용 경로다. OPT는 TTL 필드에 확장 rcode·버전·DO 비트를 싣기 때문에,
     *          헤더에서 합쳐 둔 확장 rcode를 다시 이 필드로 돌려놓아야 한다.
     */
    pub(crate) fn encode_with_ttl(&self, w: &mut Writer, ttl: u32) {
        self.name.encode(w);
        w.push_u16(self.rtype.0);
        w.push_u16(self.class.0);
        w.push_u32(ttl);
        let at = w.placeholder_u16();
        self.rdata.encode(w);
        w.backpatch_len(at);
    }
}

/** @brief RFC 2181이 정한 TTL 상한. 이보다 큰 값은 0으로 본다. */
pub const MAX_TTL: u32 = 0x7fff_ffff;

/**
 * @brief TTL 필드가 수명이 아니라 다른 뜻인 메타 타입인지.
 * @details OPT는 확장 rcode와 DO 비트를, TSIG와 TKEY는 규격이 0으로 고정한 곳을 쓴다.
 */
fn ttl_field_is_not_a_lifetime(rtype: RecordType) -> bool {
    matches!(rtype.0, 41 | 249 | 250)
}

/**
 * @brief 같은 RRSet인지 구분하는 키.
 * @details 소유자 이름은 대소문자를 무시하고 비교한다. RRSIG는 covered type이 다르면 서로 다른
 *          RRSet이고 각자 덮는 RRSet과 수명이 같아야 하므로 앞 2바이트까지 키에 넣는다.
 */
fn rrset_key(record: &Record) -> (Vec<u8>, u16, u16, u16) {
    let covered = if record.rtype == RecordType::RRSIG {
        match &record.rdata {
            RData::Unknown(_, raw) if raw.len() >= 2 => u16::from_be_bytes([raw[0], raw[1]]),
            _ => 0,
        }
    } else {
        0
    };
    (
        record.name.canonical_key(),
        record.rtype.0,
        record.class.0,
        covered,
    )
}

/**
 * @brief 한 구간의 수명을 RFC 2181대로 고른다.
 *
 * @details 8항은 최상위 비트가 선 수명을 받으면 값 전체를 0으로 보라고 한다. 5.2항은 한
 *          RRSet의 수명이 모두 같아야 한다고 정하고 서버가 다른 값을 담아 보내는 것을
 *          금지하므로, 같은 RRset은 가장 작은 값으로 맞춘다. 낮추기만 하므로 업스트림이 정한
 *          것보다 오래 가지고 있으라고 말하게 되지 않는다.
 * @param records 한 구간의 레코드. 제자리에서 고친다.
 * @note 구간이 다르면 서로 다른 RRset으로 본다. 호출자가 구간마다 부른다.
 */
pub fn normalize_ttls(records: &mut [Record]) {
    for record in records.iter_mut() {
        if !ttl_field_is_not_a_lifetime(record.rtype) && record.ttl > MAX_TTL {
            record.ttl = 0;
        }
    }

    let mut lowest: HashMap<(Vec<u8>, u16, u16, u16), u32> = HashMap::new();
    for record in records.iter() {
        if ttl_field_is_not_a_lifetime(record.rtype) {
            continue;
        }
        lowest
            .entry(rrset_key(record))
            .and_modify(|ttl| *ttl = (*ttl).min(record.ttl))
            .or_insert(record.ttl);
    }
    if lowest.len() == records.len() {
        return;
    }
    for record in records.iter_mut() {
        if ttl_field_is_not_a_lifetime(record.rtype) {
            continue;
        }
        if let Some(ttl) = lowest.get(&rrset_key(record)) {
            record.ttl = *ttl;
        }
    }
}

#[cfg(test)]
/** @brief 기록 종류별 내용이 바이트로 오갔다 와도 그대로인지. */
mod typed_rdata_tests {
    use super::*;

    /** @brief 적었다 읽는다. */
    fn roundtrip(rd: RData) -> RData {
        let rec = Record::new(Name::from_str("svc.example.com").unwrap(), 300, rd);
        let mut w = Writer::new();
        rec.encode(&mut w);
        let mut r = Reader::new(&w.buf);
        Record::parse(&mut r).unwrap().rdata
    }

    /** @brief 테스트용 매개변수 목록. */
    fn boxed_params(params: Vec<(u16, Vec<u8>)>) -> Box<[(u16, Box<[u8]>)]> {
        params
            .into_iter()
            .map(|(key, value)| (key, value.into_boxed_slice()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    /** @brief 내용 하나의 크기가 커지지 않았는지. 가장 큰 변형이 모든 기록의 비용을 정한다. */
    fn rdata_layout_stays_cache_compact() {
        assert_eq!(
            std::mem::size_of::<RData>(),
            48,
            "RData grew. Check that a new variant was added inline, and Box rare large variants"
        );
        assert_eq!(std::mem::size_of::<Record>(), 72);
        assert_eq!(std::mem::size_of::<(u16, Box<[u8]>)>(), 24);
    }

    #[test]
    /** @brief 종류별 내용의 왕복. */
    fn typed_rdata_wire_roundtrip() {
        let tlsa = RData::Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: vec![0xab, 0xcd, 0xef],
        };
        assert_eq!(roundtrip(tlsa.clone()), tlsa);
        assert_eq!(tlsa.record_type(), RecordType::TLSA);

        let sshfp = RData::Sshfp {
            algorithm: 4,
            fp_type: 2,
            fingerprint: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(roundtrip(sshfp.clone()), sshfp);
        assert_eq!(sshfp.record_type(), RecordType::SSHFP);

        let naptr = RData::Naptr(Box::new(Naptr {
            order: 100,
            preference: 10,
            flags: b"U".to_vec(),
            services: b"E2U+sip".to_vec(),
            regexp: b"!^.*$!sip:info@example.com!".to_vec(),
            replacement: Name::root(),
        }));
        assert_eq!(roundtrip(naptr.clone()), naptr);
        assert_eq!(naptr.record_type(), RecordType::NAPTR);

        let uri = RData::Uri {
            priority: 10,
            weight: 1,
            target: b"https://example.com/".to_vec(),
        };
        assert_eq!(roundtrip(uri.clone()), uri);
        assert_eq!(uri.record_type(), RecordType::URI);

        let svcb = RData::Svcb {
            priority: 1,
            target: Name::from_str("svc.example.net").unwrap(),
            params: boxed_params(vec![(1, vec![2, b'h', b'2']), (3, vec![0x01, 0xbb])]),
        };
        assert_eq!(roundtrip(svcb.clone()), svcb);
        assert_eq!(svcb.record_type(), RecordType::SVCB);

        let https = RData::Https {
            priority: 0,
            target: Name::from_str("svc.example.net").unwrap(),
            params: Box::default(),
        };
        assert_eq!(roundtrip(https.clone()), https);
        assert_eq!(https.record_type(), RecordType::HTTPS);

        let dname = RData::Dname(Name::from_str("target.example.net").unwrap());
        assert_eq!(roundtrip(dname.clone()), dname);
        assert_eq!(dname.record_type(), RecordType::DNAME);
    }

    #[test]
    /** @brief 이름이 든 이전 기록을 거부하는지. 그대로 다시 적으면 안에 든 압축 지시자가 깨진다. */
    fn rejects_unknown_name_bearing_rdata() {
        /** @brief 이름이 든 이전 기록 종류들. */
        const NAME_BEARING: [u16; 13] = [3, 4, 7, 8, 9, 14, 17, 18, 21, 23, 26, 30, 36];
        for rtype in NAME_BEARING {
            let [high, low] = rtype.to_be_bytes();
            let wire = [0, high, low, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 0x00];
            let mut reader = Reader::new(&wire);
            let Err(error) = Record::parse(&mut reader) else {
                panic!("type {rtype} must be rejected. Rewriting RDATA that contains compressed names as raw bytes corrupts the response");
            };
            assert!(
                error.to_string().contains("Unsupported RDATA type"),
                "type {rtype}: {error}"
            );
        }
    }

    #[test]
    /** @brief 압축된 대상 이름과 순서가 어긋난 매개변수를 거부하는지. */
    fn svcb_wire_rejects_compressed_target_and_non_increasing_keys() {
        let compressed = [0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 4, 0, 1, 0xc0, 0x00];
        assert!(Record::parse(&mut Reader::new(&compressed)).is_err());

        let mut reversed = vec![0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 15, 0, 1, 0];
        reversed.extend_from_slice(&[0, 3, 0, 2, 1, 187]);
        reversed.extend_from_slice(&[0, 1, 0, 2, 1, b'h']);
        assert!(Record::parse(&mut Reader::new(&reversed)).is_err());
    }

    #[test]
    /**
     * @brief RFC 1035 밖의 종류가 RDATA 안 이름을 압축하지 않는지.
     *
     * @details RFC 3597은 압축을 RFC 1035 가 정의한 종류로만 한정한다. 포인터는 그
     *          메시지 안에서만 뜻이 있어서, RDATA 를 전부 옮겨 담는 쪽이 엉뚱한 위치를
     *          가리키는 이름을 만든다. 소유자 이름을 먼저 적어 같은 접미사가 이미 메시지에
     *          있는 상태로 만들어야 압축이 일어날 곳이 생긴다.
     * @note 같은 메시지의 MX 는 RFC 1035 종류라 압축해야 한다. 압축을 전부 끄는 것으로
     *       고치면 응답이 커지므로 양쪽을 함께 붙든다.
     */
    fn rdata_names_outside_rfc1035_are_never_compressed() {
        /**
         * @brief RDATA 안 이름 필드를 훑으며 압축 포인터를 만나는지.
         * @details 포인터는 이름의 첫 바이트가 아니라 리터럴 라벨 몇 개 뒤에 온다. 버퍼
         *          전체에서 0xC0 비트를 찾으면 포트나 TTL 같은 평범한 값도 걸린다.
         */
        fn name_is_compressed(rdata: &[u8], mut at: usize) -> bool {
            while at < rdata.len() {
                let len = rdata[at];
                if len & 0xC0 == 0xC0 {
                    return true;
                }
                if len == 0 {
                    return false;
                }
                at += 1 + usize::from(len);
            }
            false
        }

        let apex = Name::from_str("wire.test").unwrap();
        let target = Name::from_str("t.wire.test").unwrap();
        // NAPTR 의 이름 필드는 order 2, preference 2, 그리고 문자열 셋 뒤인 15 다.
        let cases: Vec<(&str, RData, usize, bool)> = vec![
            (
                "SRV",
                RData::Srv {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: target.clone(),
                },
                6,
                false,
            ),
            ("DNAME", RData::Dname(target.clone()), 0, false),
            (
                "NAPTR",
                RData::Naptr(Box::new(Naptr {
                    order: 1,
                    preference: 2,
                    flags: b"u".to_vec(),
                    services: b"E2U+sip".to_vec(),
                    regexp: Vec::new(),
                    replacement: target.clone(),
                })),
                15,
                false,
            ),
            (
                "SVCB",
                RData::Svcb {
                    priority: 1,
                    target: target.clone(),
                    params: Box::default(),
                },
                2,
                false,
            ),
            (
                "MX",
                RData::Mx {
                    preference: 10,
                    exchange: target.clone(),
                },
                2,
                true,
            ),
            ("CNAME", RData::Cname(target.clone()), 0, true),
            ("NS", RData::Ns(target.clone()), 0, true),
        ];

        for (label, rdata, name_at, compressible) in cases {
            let mut writer = Writer::new();
            // 같은 접미사를 메시지에 미리 두어야 압축이 일어날 곳이 생긴다.
            apex.encode(&mut writer);
            let start = writer.buf.len();
            rdata.encode(&mut writer);
            assert!(writer.error().is_none(), "Encoding {label} failed");
            let body = &writer.buf[start..];
            assert_eq!(
                name_is_compressed(body, name_at),
                compressible,
                "{label} compression does not match the spec: {body:02x?}"
            );
        }
    }

    #[test]
    /** @brief 대상 이름을 압축하지 않고 적는지. */
    fn svcb_encoder_never_compresses_target_name() {
        let name = Name::from_str("svc.example").unwrap();
        let record = Record::new(
            name.clone(),
            60,
            RData::Svcb {
                priority: 1,
                target: name,
                params: Box::default(),
            },
        );
        let mut writer = Writer::new();
        record.encode(&mut writer);
        assert!(writer.error().is_none());
        assert_eq!(writer.buf[25], 3, "First TargetName label is not a pointer");
        assert_eq!(&writer.buf[25..], b"\x03svc\x07example\x00");
    }

    #[test]
    /** @brief 아는 매개변수의 형식을 엄격히 보는지. */
    fn svcb_known_parameter_formats_are_strict() {
        let invalid = [
            vec![(3, vec![0, 53]), (3, vec![0, 54])],
            vec![(3, vec![0])],
            vec![(1, vec![])],
            vec![(2, vec![])],
            vec![(4, vec![])],
            vec![(6, vec![0; 15])],
            vec![(u16::MAX, vec![])],
        ];
        for params in invalid {
            let rdata = RData::Https {
                priority: 1,
                target: Name::root(),
                params: boxed_params(params),
            };
            assert!(rdata.validate().is_err(), "{rdata:?}");
        }

        let valid = RData::Https {
            priority: 1,
            target: Name::root(),
            params: boxed_params(vec![
                (0, vec![0, 1, 0, 3]),
                (1, vec![2, b'h', b'2']),
                (2, vec![]),
                (3, 443u16.to_be_bytes().to_vec()),
            ]),
        };
        assert!(valid.validate().is_ok());
    }
}

#[cfg(test)]
/** @brief RFC 2181이 정한 수명 규칙. */
mod ttl_normalization_tests {
    use super::*;

    /** @brief 주어진 수명의 A 레코드. */
    fn a(name: &str, ttl: u32, last: u8) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, last)),
        )
    }

    #[test]
    /** @brief 최상위 비트가 선 수명은 값 전체가 0이 된다. RFC 2181. */
    fn a_ttl_above_the_ceiling_becomes_zero() {
        let mut records = vec![
            a("x.example.com", 0x8000_0000, 1),
            a("y.example.com", 300, 2),
        ];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, 0);
        assert_eq!(records[1].ttl, 300, "Values below the cap are unchanged");

        let mut edge = vec![a("z.example.com", MAX_TTL, 3)];
        normalize_ttls(&mut edge);
        assert_eq!(edge[0].ttl, MAX_TTL, "The cap itself is a valid value");
    }

    #[test]
    /** @brief 한 RRSet의 수명은 가장 작은 값으로 고른다. RFC 2181. */
    fn one_rrset_leaves_with_one_ttl() {
        let mut records = vec![
            a("host.example.com", 900, 10),
            a("host.example.com", 100, 11),
            a("other.example.com", 700, 12),
        ];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, 100);
        assert_eq!(records[1].ttl, 100);
        assert_eq!(records[2].ttl, 700, "Other names are not grouped");
    }

    #[test]
    /** @brief 소유자 이름의 대소문자는 같은 RRset으로 본다. RFC 4343. */
    fn case_does_not_split_an_rrset() {
        let mut records = vec![
            a("Host.Example.COM", 900, 10),
            a("host.example.com", 100, 11),
        ];
        normalize_ttls(&mut records);
        assert_eq!((records[0].ttl, records[1].ttl), (100, 100));
    }

    #[test]
    /** @brief 상한을 넘겨 0이 된 값이 같은 RRset 전체를 0으로 끌어내린다. */
    fn the_ceiling_rule_runs_before_the_rrset_rule() {
        let mut records = vec![
            a("host.example.com", 0x8000_0000, 10),
            a("host.example.com", 300, 11),
        ];
        normalize_ttls(&mut records);
        assert_eq!((records[0].ttl, records[1].ttl), (0, 0));
    }

    #[test]
    /** @brief OPT의 TTL 필드는 수명이 아니라 확장 rcode와 DO 비트라 건드리지 않는다. */
    fn the_opt_pseudo_record_is_left_alone() {
        let flags = 0x8000_0000u32;
        let mut records = vec![Record {
            name: Name::root(),
            rtype: RecordType::OPT,
            class: DnsClass(1232),
            ttl: flags,
            rdata: RData::Unknown(RecordType::OPT.0, Vec::new()),
        }];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, flags);
    }

    #[test]
    /** @brief covered type이 다른 RRSIG는 서로 다른 RRSet이라 함께 깎이지 않는다. */
    fn signatures_over_different_types_are_different_rrsets() {
        let sig = |covered: u16, ttl: u32| {
            let mut raw = covered.to_be_bytes().to_vec();
            raw.extend_from_slice(&[13, 2, 0, 0, 0, 0, 0]);
            Record {
                name: Name::from_str("host.example.com").unwrap(),
                rtype: RecordType::RRSIG,
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(RecordType::RRSIG.0, raw),
            }
        };
        let mut records = vec![sig(1, 900), sig(28, 100), sig(1, 500)];
        normalize_ttls(&mut records);
        assert_eq!(
            records[0].ttl, 500,
            "Only signatures covering A are grouped"
        );
        assert_eq!(
            records[1].ttl, 100,
            "Signatures covering AAAA are unchanged"
        );
        assert_eq!(records[2].ttl, 500);
    }
}
