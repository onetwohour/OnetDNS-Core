/*!
 * @brief DHCPv4 서버.
 *
 * @details 주소를 나눠 주면서 이 서버를 DNS로 함께 알리고, 네트워크 부팅에 필요한 값도 담아
 *          보낸다. 임대와 고정 할당은 파일에 남겨 재시작해도 이어진다.
 * @warning 인증이 없는 프로토콜이다. 남의 임대를 가로채지 못하도록 요청한 주소의 임자와
 *          서버 식별자를 확인하고, 이 서버가 내주지 않은 주소는 확정하지 않는다.
 */

use std::collections::HashMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

/** @brief 옵션 구간의 시작을 알리는 고정 바이트. */
const MAGIC: [u8; 4] = [99, 130, 83, 99];

/** @brief 옵션 앞 고정 구간의 길이. */
const FIXED_LEN: usize = 236;
/** @brief IPv4 전체 길이에서 최소 IP/UDP 헤더를 뺀 표준 UDP payload 상한. */
const MAX_STANDARD_IPV4_UDP_PAYLOAD: usize = u16::MAX as usize - 20 - 8;
/** @brief 표준 상한을 넘긴 데이터그램을 절단 prefix와 구별하는 수신 크기. */
const DHCP4_RECV_CAPACITY: usize = MAX_STANDARD_IPV4_UDP_PAYLOAD + 1;
const BROADCAST_FLAG: u16 = 0x8000;
/** @brief BOOTP 고정 헤더의 서버 이름 필드. */
const SNAME_RANGE: std::ops::Range<usize> = 44..108;
/** @brief BOOTP 고정 헤더의 부트 파일 필드. */
const FILE_RANGE: std::ops::Range<usize> = 108..236;
/** @brief 읽어들일 저장 파일 크기 상한. */
const MAX_PERSIST_FILE: u64 = 16 * 1024 * 1024;
/** @brief 메모리와 저장 파일에 담을 상태 항목 수 상한. */
const MAX_STATE_ENTRIES: usize = 100_000;
/** @brief 임대 파일의 첫 줄. 형식이 다르면 읽지 않는다. */
const LEASE_HEADER: &str = "ONETDNS-DHCP4-LEASES-V1\n";
/** @brief 고정 할당 파일의 첫 줄. */
const RESERVATION_HEADER: &str = "ONETDNS-DHCP4-RESERVATIONS-V1\n";

/** @brief wire의 infinity 임대를 내부에서도 만료되지 않는 시각으로 보존한다. */
fn lease_expiry(now: u64, lease: u32) -> u64 {
    if lease == u32::MAX {
        u64::MAX
    } else {
        now.saturating_add(u64::from(lease))
    }
}

/** @brief 크기 상한을 걸어 저장 파일을 읽는다. 못 읽으면 빈 상태로 시작한다. */
fn read_persist_text(path: &std::path::Path) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp4.restore_open_failed",
                path = %path.display(),
                %error,
                "저장된 DHCP 정보를 열지 못해 빈 상태로 시작합니다"
            );
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_PERSIST_FILE + 1).read_to_end(&mut bytes) {
        onetdns_core::warn!(
            event = "dhcp4.restore_read_failed",
            path = %path.display(),
            %error,
            "저장된 DHCP 정보를 읽지 못해 빈 상태로 시작합니다"
        );
        return None;
    }
    if bytes.len() as u64 > MAX_PERSIST_FILE {
        onetdns_core::warn!(
            event = "dhcp4.restore_too_large",
            path = %path.display(),
            bytes = bytes.len(),
            limit = MAX_PERSIST_FILE,
            "저장된 DHCP 파일이 허용 크기를 넘어 복원하지 않습니다"
        );
        return None;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp4.restore_invalid_utf8",
                path = %path.display(),
                %error,
                "저장된 DHCP 파일의 문자 인코딩이 올바르지 않아 복원하지 않습니다"
            );
            None
        }
    }
}

/** @brief 서버를 찾는 요청. */
pub const DISCOVER: u8 = 1;
/** @brief 서버가 주소를 제안하는 응답. */
pub const OFFER: u8 = 2;
/** @brief 주소를 확정해 달라는 요청. */
pub const REQUEST: u8 = 3;
/** @brief 받은 주소가 이미 쓰이고 있다는 통지. */
pub const DECLINE: u8 = 4;
/** @brief 확정 응답. */
pub const ACK: u8 = 5;
/** @brief 거절 응답. */
pub const NAK: u8 = 6;
/** @brief 주소를 돌려주는 통지. */
pub const RELEASE: u8 = 7;

/** @brief 서브넷 마스크 옵션. */
pub const OPT_SUBNET_MASK: u8 = 1;
/** @brief 기본 경로 옵션. */
pub const OPT_ROUTER: u8 = 3;
/** @brief DNS 서버 목록 옵션. */
pub const OPT_DNS: u8 = 6;
/** @brief 클라이언트가 원하는 주소 옵션. */
pub const OPT_REQUESTED_IP: u8 = 50;
/** @brief 클라이언트 이름 옵션. */
pub const OPT_HOSTNAME: u8 = 12;
/** @brief 임대 기간 옵션. */
pub const OPT_LEASE_TIME: u8 = 51;
/** @brief file/sname 필드도 옵션으로 쓰는지 알리는 옵션. */
const OPT_OVERLOAD: u8 = 52;
/** @brief 메시지 종류 옵션. */
pub const OPT_MSG_TYPE: u8 = 53;
/** @brief 서버 식별 옵션. */
pub const OPT_SERVER_ID: u8 = 54;
/** @brief 클라이언트가 선택한 불투명 식별자 옵션. */
pub const OPT_CLIENT_ID: u8 = 61;
/** @brief 클라이언트가 짧은 이름 뒤에 붙일 도메인 옵션. */
pub const OPT_DOMAIN_NAME: u8 = 15;
/** @brief 네트워크 부팅 서버 이름 옵션. */
pub const OPT_TFTP_SERVER_NAME: u8 = 66;
/** @brief 부트 이미지 이름 옵션. */
pub const OPT_BOOTFILE: u8 = 67;
/** @brief 옵션 구간의 끝. */
pub const OPT_END: u8 = 255;

/** @brief 받은 길이가 표준 IPv4 UDP payload 안인지 판정한다. */
fn standard_dhcp4_datagram_len(received: usize) -> Option<usize> {
    (received <= MAX_STANDARD_IPV4_UDP_PAYLOAD).then_some(received)
}

/** @brief 이 서버가 실제 소유해 처리하는 옵션의 연결 후 최대 길이. */
fn retained_option_limit(code: u8) -> Option<usize> {
    match code {
        OPT_OVERLOAD | OPT_MSG_TYPE => Some(1),
        OPT_REQUESTED_IP | OPT_SERVER_ID => Some(4),
        OPT_HOSTNAME | OPT_CLIENT_ID => Some(255),
        _ => None,
    }
}

/** @brief RFC 3396 조각 하나를 코드별 단일 소유 버퍼에 이어 붙인다. */
fn append_option_fragment(
    options: &mut Vec<(u8, Vec<u8>)>,
    code: u8,
    value: &[u8],
    limit: usize,
) -> Option<()> {
    if let Some((_, aggregate)) = options.iter_mut().find(|(stored, _)| *stored == code) {
        let new_len = aggregate.len().checked_add(value.len())?;
        if new_len > limit {
            return None;
        }
        aggregate.extend_from_slice(value);
    } else {
        if value.len() > limit {
            return None;
        }
        options.push((code, value.to_vec()));
    }
    Some(())
}

/** @brief 옵션 필드 하나를 끝까지 검사하고 지원 값만 RFC 3396 순서로 소유한다. */
fn scan_option_field(
    field: &[u8],
    allow_overload: bool,
    options: &mut Vec<(u8, Vec<u8>)>,
) -> Option<()> {
    let mut offset = 0usize;
    while offset < field.len() {
        let code = field[offset];
        if code == OPT_END {
            return field[offset + 1..]
                .iter()
                .all(|byte| *byte == 0)
                .then_some(());
        }
        if code == 0 {
            offset += 1;
            continue;
        }
        let len = usize::from(*field.get(offset + 1)?);
        let end = offset.checked_add(2)?.checked_add(len)?;
        let value = field.get(offset + 2..end)?;
        if code == OPT_OVERLOAD && !allow_overload {
            return None;
        }
        if let Some(limit) = retained_option_limit(code) {
            append_option_fragment(options, code, value, limit)?;
        }
        offset = end;
    }
    None
}

/** @brief 연결을 끝낸 뒤 각 지원 옵션의 RFC 길이를 검증한다. */
fn retained_options_are_valid(options: &[(u8, Vec<u8>)]) -> bool {
    options.iter().all(|(code, value)| match *code {
        OPT_REQUESTED_IP | OPT_SERVER_ID => value.len() == 4,
        OPT_HOSTNAME => !value.is_empty(),
        OPT_CLIENT_ID => (2..=255).contains(&value.len()),
        OPT_OVERLOAD => value.len() == 1 && matches!(value[0], 1..=3),
        OPT_MSG_TYPE => value.len() == 1,
        _ => false,
    })
}

#[derive(Debug, Clone)]
/** @brief 주고받는 메시지 하나. */
pub struct DhcpMessage {
    /** @brief 요청인지 응답인지. */
    pub op: u8,
    /** @brief 거래 번호. 요청과 응답을 짝짓는다. */
    pub xid: u32,
    /** @brief 방송으로 답해 달라는 등의 표시. */
    pub flags: u16,
    /** @brief 클라이언트가 이미 잡은 주소. */
    pub ciaddr: Ipv4Addr,
    /** @brief 이 서버가 주는 주소. */
    pub yiaddr: Ipv4Addr,
    /** @brief 다음에 접속할 서버 주소. 네트워크 부팅에 쓴다. */
    pub siaddr: Ipv4Addr,
    /** @brief 거쳐 온 중계 장치 주소. */
    pub giaddr: Ipv4Addr,

    /** @brief 클라이언트 하드웨어 주소. */
    pub chaddr: [u8; 6],
    /** @brief option 61의 불투명 클라이언트 식별자. 없으면 chaddr가 식별자다. */
    client_identifier: Option<std::sync::Arc<[u8]>>,
    /** @brief 담긴 옵션들. */
    pub options: Vec<(u8, Vec<u8>)>,
}

impl DhcpMessage {
    /**
     * @brief 바이트열을 메시지로.
     * @warning 옵션 길이가 남은 바이트를 넘으면 전체를 거부한다. 거기까지만 받아들이면
     *          잘린 요청이 온전한 요청처럼 처리된다.
     */
    pub fn parse(buf: &[u8]) -> Option<DhcpMessage> {
        if buf.len() < FIXED_LEN + 4
            || buf.len() > MAX_STANDARD_IPV4_UDP_PAYLOAD
            || !matches!(buf[0], 1 | 2)
            || buf[1] != 1
            || buf[2] != 6
            || buf[FIXED_LEN..FIXED_LEN + 4] != MAGIC
        {
            return None;
        }
        let v4 = |o: usize| Ipv4Addr::new(buf[o], buf[o + 1], buf[o + 2], buf[o + 3]);
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&buf[28..34]);
        let op = buf[0];
        let mut options = Vec::with_capacity(4);
        scan_option_field(&buf[FIXED_LEN + 4..], true, &mut options)?;

        let overload = options
            .iter()
            .find(|(code, _)| *code == OPT_OVERLOAD)
            .and_then(|(_, value)| (value.len() == 1).then_some(value[0]))
            .unwrap_or(0);
        if overload & 1 != 0 {
            scan_option_field(&buf[FILE_RANGE], false, &mut options)?;
        }
        if overload & 2 != 0 {
            scan_option_field(&buf[SNAME_RANGE], false, &mut options)?;
        }
        if !retained_options_are_valid(&options)
            || !options.iter().any(|(code, _)| *code == OPT_MSG_TYPE)
        {
            return None;
        }
        options.retain(|(code, _)| *code != OPT_OVERLOAD);
        let client_identifier = options
            .iter()
            .position(|(code, _)| *code == OPT_CLIENT_ID)
            .map(|index| std::sync::Arc::from(options.remove(index).1));
        Some(DhcpMessage {
            op,
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: v4(12),
            yiaddr: v4(16),
            siaddr: v4(20),
            giaddr: v4(24),
            chaddr,
            client_identifier,
            options,
        })
    }

    /** @brief 메시지를 바이트열로. */
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; FIXED_LEN];
        b[0] = self.op;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        b[10..12].copy_from_slice(&self.flags.to_be_bytes());
        b[12..16].copy_from_slice(&self.ciaddr.octets());
        b[16..20].copy_from_slice(&self.yiaddr.octets());
        b[20..24].copy_from_slice(&self.siaddr.octets());
        b[24..28].copy_from_slice(&self.giaddr.octets());
        b[28..34].copy_from_slice(&self.chaddr);
        b.extend_from_slice(&MAGIC);
        if let Some(client_identifier) = &self.client_identifier {
            b.push(OPT_CLIENT_ID);
            b.push(u8::try_from(client_identifier.len()).expect("파서가 DHCP 옵션 길이를 검증함"));
            b.extend_from_slice(client_identifier);
        }
        for (code, val) in &self.options {
            let Ok(len) = u8::try_from(val.len()) else {
                continue;
            };
            b.push(*code);
            b.push(len);
            b.extend_from_slice(val);
        }
        b.push(OPT_END);
        b
    }

    /** @brief 이 옵션의 내용. */
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        if code == OPT_CLIENT_ID {
            return self.client_identifier.as_deref();
        }
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    /** @brief 메시지 종류. */
    pub fn msg_type(&self) -> Option<u8> {
        let value = self.option(OPT_MSG_TYPE)?;
        (value.len() == 1).then_some(value[0])
    }

    /** @brief 클라이언트가 알린 이름. */
    pub fn hostname(&self) -> Option<String> {
        let raw = self.option(OPT_HOSTNAME)?;
        let s: String = std::str::from_utf8(raw)
            .ok()?
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace())
            .collect();
        (!s.is_empty()).then_some(s)
    }

    /** @brief option 61이 있으면 그것, 없으면 chaddr로 정한 단일 소유권 키. */
    fn client_identity(&self) -> ClientIdentity {
        match &self.client_identifier {
            Some(value) => ClientIdentity::Opaque(value.clone()),
            None => ClientIdentity::Hardware(self.chaddr),
        }
    }
}

/** @brief 서버 수신 경로에서는 BOOTREQUEST만 TLV 파서로 넘긴다. */
fn parse_client_request(buf: &[u8]) -> Option<DhcpMessage> {
    if buf.first().copied() != Some(1) {
        return None;
    }
    DhcpMessage::parse(buf)
}

/** @brief 옵션 내용을 주소 하나로. 길이가 맞아야 한다. */
fn opt_ipv4(v: &[u8]) -> Option<Ipv4Addr> {
    (v.len() == 4).then(|| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
}

/** @brief 공백 구분 영속 형식에 안전한 DHCP hostname인지. */
pub fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/** @brief DHCPv4 바인딩의 유일한 소유권 키. */
pub enum ClientIdentity {
    /** @brief option 61이 없을 때 쓰는 Ethernet chaddr. */
    Hardware([u8; 6]),
    /** @brief option 61 전체를 해석하지 않고 보존한 값. */
    Opaque(std::sync::Arc<[u8]>),
}

impl ClientIdentity {
    /** @brief 저장·HA·관리 API가 공유하는 손실 없는 식별자 표기. */
    pub fn to_text(&self) -> String {
        match self {
            Self::Hardware(mac) => format!("mac:{}", mac_hex(mac)),
            Self::Opaque(value) => format!("id:{}", bytes_hex(value)),
        }
    }

    /** @brief 저장·HA·관리 API의 식별자 표기를 읽는다. */
    pub fn from_text(text: &str) -> Option<Self> {
        if let Some(value) = text.strip_prefix("mac:") {
            return mac_from_hex(value).map(Self::Hardware);
        }
        let value = text.strip_prefix("id:")?;
        let bytes = bytes_from_hex(value)?;
        (2..=255)
            .contains(&bytes.len())
            .then(|| Self::Opaque(std::sync::Arc::from(bytes)))
    }

    /** @brief MAC fallback 식별자라면 그 MAC. */
    pub fn hardware(&self) -> Option<[u8; 6]> {
        match self {
            Self::Hardware(mac) => Some(*mac),
            Self::Opaque(_) => None,
        }
    }
}

#[derive(Clone)]
/** @brief 임대 하나. */
struct Lease {
    /** @brief 마지막으로 관측한 전송용 하드웨어 주소. */
    mac: [u8; 6],
    /** @brief 빌려준 주소. */
    ip: u32,
    /** @brief 이 임대가 끝나는 시각. */
    expiry: u64,
    /** @brief 클라이언트가 알린 이름. */
    hostname: Option<String>,
}

/** @brief 밖에 내보이는 임대 하나. */
pub struct LeaseInfo {
    /** @brief 임대 소유권을 정하는 option 61 또는 MAC fallback. */
    pub identity: ClientIdentity,
    /** @brief 클라이언트 하드웨어 주소. */
    pub mac: [u8; 6],
    /** @brief 빌려준 주소. */
    pub ip: Ipv4Addr,
    /** @brief 이 임대가 끝나는 시각. */
    pub expiry_unix: u64,
    /** @brief 클라이언트가 알린 이름. */
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
/** @brief 나눠 줄 범위와 함께 알릴 값들. */
pub struct DhcpConfig {
    /** @brief 이 서버의 주소. 응답에 서버 식별자로 담는다. */
    pub server_ip: Ipv4Addr,
    /** @brief 나눠 줄 범위의 시작. */
    pub range_start: Ipv4Addr,
    /** @brief 나눠 줄 범위의 끝. */
    pub range_end: Ipv4Addr,
    /** @brief 함께 알릴 서브넷 마스크. */
    pub subnet_mask: Ipv4Addr,
    /** @brief 함께 알릴 기본 경로. */
    pub router: Ipv4Addr,
    /** @brief 함께 알릴 DNS 서버. */
    pub dns: Vec<Ipv4Addr>,
    /** @brief 임대 기간. */
    pub lease_secs: u32,

    /** @brief 네트워크 부팅 서버 주소. */
    pub tftp_server: Option<Ipv4Addr>,

    /** @brief 네트워크 부팅에 받아 갈 파일 이름. */
    pub boot_file: Option<String>,

    /** @brief 클라이언트에 알릴 로컬 도메인. */
    pub domain_name: Option<String>,

    /** @brief 임대 기록을 담아 둘 파일. */
    pub lease_file: Option<PathBuf>,

    /** @brief 고정 할당을 담아 둘 파일. */
    pub static_file: Option<PathBuf>,
}

/** @brief 고정 할당 하나. */
pub struct ReservationInfo {
    /** @brief 고정 할당을 적용할 클라이언트 식별자. */
    pub identity: ClientIdentity,
    /** @brief 고정한 주소. */
    pub ip: Ipv4Addr,
    /** @brief 함께 적어 둔 이름. */
    pub hostname: Option<String>,
}

/**
 * @brief 임대 기록.
 * @details 확정된 임대 말고도 제안해 둔 것과 거절당한 주소를 따로 잡는다. 제안만 하고
 *          아직 확정되지 않은 주소를 다른 클라이언트에 또 주면 안 된다.
 */
pub struct LeasePool {
    /** @brief 나눠 줄 범위의 시작. */
    start: u32,
    /** @brief 나눠 줄 범위의 끝. */
    end: u32,
    /** @brief 임대 기간. */
    lease_secs: u32,
    /** @brief 확정된 임대들. */
    leases: HashMap<ClientIdentity, Lease>,
    /** @brief 임대 기록을 담아 둘 파일. */
    persist: Option<PathBuf>,

    /** @brief 제안만 하고 아직 확정되지 않은 주소들. */
    offers: HashMap<ClientIdentity, (u32, u32, u64)>,

    /** @brief 이미 쓰이고 있다고 통지받아 잠시 뺀 주소들. */
    declined: HashMap<u32, u64>,

    /** @brief 고정 할당들. */
    reservations: HashMap<ClientIdentity, (u32, Option<String>)>,
    /** @brief 주소별 임대·제안·거절·고정 할당 참조 수. 새 주소 선택이 기록을 복사하지 않게 한다. */
    address_use: HashMap<u32, u32>,
    /** @brief 고정 할당을 담아 둘 파일. */
    static_persist: Option<PathBuf>,

    /** @brief 이 서버의 서브넷 마스크. 고정 할당을 검사하는 데 쓴다. */
    subnet_mask: u32,
    /** @brief 이 서버의 주소. */
    server_ip: u32,
    /** @brief 관문 주소. */
    router: u32,
    /** @brief 범위가 바닥났다고 이미 알렸는지. 요청마다 같은 경고를 되풀이하지 않으려는 것이다. */
    exhausted: bool,
    /** @brief 동적 상태 상한 도달을 이미 알렸는지. */
    dynamic_limited: bool,
    /** @brief 고정 할당 상한 도달을 이미 알렸는지. */
    reservations_limited: bool,
    /** @brief 다음 새 주소 검색을 시작할 위치. */
    allocation_cursor: u32,
    /** @brief 임대·제안·거절 주소 중 가장 이른 만료 시각. */
    next_expiry: u64,
}

impl LeasePool {
    /**
     * @brief 저장된 임대와 고정 할당을 읽어 기록을 만든다.
     * @note 읽은 것을 지금 설정으로 다시 검사한다. 설정을 바꾼 뒤 이전 주소를 계속 내주면
     *       그 주소는 어디에도 닿지 않는다.
     */
    pub fn new(cfg: &DhcpConfig) -> Self {
        let leases = cfg
            .lease_file
            .as_deref()
            .map(load_leases)
            .unwrap_or_default();
        let mut static_persist = cfg.static_file.clone();
        let reservations = match cfg.static_file.as_deref().map(read_reservations) {
            Some(Ok(reservations)) => reservations,
            Some(Err(error)) => {
                onetdns_core::warn!(event = "dhcp4.reservations_restore_invalid", error = %error, "DHCP 고정 할당 파일을 읽지 못했습니다. 운영자 파일을 덮어쓰지 않도록 고정 할당을 저장하지 않고 시작합니다");
                static_persist = None;
                HashMap::new()
            }
            None => HashMap::new(),
        };
        let mut pool = LeasePool {
            start: u32::from(cfg.range_start),
            end: u32::from(cfg.range_end),
            lease_secs: cfg.lease_secs,
            leases,
            persist: cfg.lease_file.clone(),
            offers: HashMap::new(),
            declined: HashMap::new(),
            reservations,
            address_use: HashMap::new(),
            static_persist,
            subnet_mask: u32::from(cfg.subnet_mask),
            server_ip: u32::from(cfg.server_ip),
            router: u32::from(cfg.router),
            exhausted: false,
            dynamic_limited: false,
            reservations_limited: false,
            allocation_cursor: u32::from(cfg.range_start),
            next_expiry: u64::MAX,
        };
        pool.revalidate_loaded_state();
        pool.rebuild_address_use();

        pool.save_static();
        pool.save();
        pool
    }

    /**
     * @brief 서비스를 재시작할 때 기록을 버리지 않고 새 설정에 맞춘다.
     * @details 새 기록을 만들면 이미 나간 주소를 다른 기기에 또 준다. 새 고정 할당 파일이
     *          있으면 읽고, 없으면 지금 고정 할당을 그 파일에 적는다.
     * @return 새 고정 할당 파일을 읽지 못하면 실패. 이때 기록은 바뀌지 않는다.
     */
    pub fn reconfigure(&mut self, cfg: &DhcpConfig) -> Result<(), String> {
        if cfg.static_file != self.static_persist {
            if let Some(path) = cfg.static_file.as_deref() {
                if path.exists() {
                    self.reservations = read_reservations(path)?;
                }
            }
            self.static_persist = cfg.static_file.clone();
        }
        self.start = u32::from(cfg.range_start);
        self.end = u32::from(cfg.range_end);
        self.lease_secs = cfg.lease_secs;
        self.persist = cfg.lease_file.clone();
        self.subnet_mask = u32::from(cfg.subnet_mask);
        self.server_ip = u32::from(cfg.server_ip);
        self.router = u32::from(cfg.router);
        self.offers.clear();
        self.exhausted = false;
        self.allocation_cursor = self.start;
        self.revalidate_loaded_state();
        self.rebuild_address_use();
        self.save_static();
        self.save();
        Ok(())
    }

    /** @brief 입력 크기의 상태가 상한을 넘지 않게 하고 도달·회복을 한 번씩 알린다. */
    fn admit_state(limited: &mut bool, kind: &'static str, entries: usize) -> bool {
        if entries < MAX_STATE_ENTRIES {
            if std::mem::replace(limited, false) {
                onetdns_core::info!(
                    event = "dhcp4.state_available",
                    kind = kind,
                    entries,
                    limit = MAX_STATE_ENTRIES,
                    "DHCPv4 상태 상한 아래에 다시 빈자리가 생겼습니다"
                );
            }
            true
        } else {
            if !std::mem::replace(limited, true) {
                onetdns_core::warn!(
                    event = "dhcp4.state_limit",
                    kind = kind,
                    entries,
                    limit = MAX_STATE_ENTRIES,
                    "DHCPv4 상태 상한에 닿아 새 항목을 받지 않습니다"
                );
            }
            false
        }
    }

    /** @brief 임대·제안·거절 주소가 공유하는 원격 입력 예산의 현재 사용량. */
    fn dynamic_entries(&self) -> usize {
        self.leases
            .len()
            .saturating_add(self.offers.len())
            .saturating_add(self.declined.len())
    }

    /** @brief 전이에서 먼저 사라질 항목을 제외한 뒤 동적 상태 한 슬롯을 예약한다. */
    fn admit_dynamic_after_removing(&mut self, removing: usize) -> bool {
        let entries = self.dynamic_entries().saturating_sub(removing);
        Self::admit_state(&mut self.dynamic_limited, "dynamic", entries)
    }

    /** @brief 주소 참조를 하나 늘린다. */
    fn occupy_in(address_use: &mut HashMap<u32, u32>, ip: u32) {
        let count = address_use.entry(ip).or_insert(0);
        *count = count.saturating_add(1);
    }

    /** @brief 주소 참조를 하나 줄이고 마지막 참조면 인덱스에서 지운다. */
    fn vacate_in(address_use: &mut HashMap<u32, u32>, ip: u32) {
        let Some(count) = address_use.get_mut(&ip) else {
            return;
        };
        if *count <= 1 {
            address_use.remove(&ip);
        } else {
            *count -= 1;
        }
    }

    /** @brief 같은 식별자가 이 주소를 가리키는 임대·제안·고정 할당 참조 수. */
    fn own_address_references(&self, identity: &ClientIdentity, ip: u32) -> u32 {
        u32::from(
            self.leases
                .get(identity)
                .is_some_and(|lease| lease.ip == ip),
        )
        .saturating_add(u32::from(
            self.offers
                .get(identity)
                .is_some_and(|(offered, _, _)| *offered == ip),
        ))
        .saturating_add(u32::from(
            self.reservations
                .get(identity)
                .is_some_and(|(reserved, _)| *reserved == ip),
        ))
    }

    /** @brief 호출자가 만료 정리를 끝낸 상태에서 같은 식별자 이외의 참조가 남는지. */
    fn address_used_by_other_inner(&self, identity: &ClientIdentity, ip: u32) -> bool {
        self.address_use.get(&ip).copied().unwrap_or(0) > self.own_address_references(identity, ip)
    }

    /** @brief 만료 상태를 치운 뒤 이 클라이언트의 임대 기록이 남아 있는지. */
    fn has_record(&mut self, identity: &ClientIdentity) -> bool {
        self.cleanup_expired(crate::unix_now());
        self.leases.contains_key(identity)
    }

    /** @brief 만료 상태를 치운 뒤 같은 식별자 이외의 주소 참조가 남는지. */
    fn address_used_by_other(&mut self, identity: &ClientIdentity, ip: u32) -> bool {
        self.cleanup_expired(crate::unix_now());
        self.address_used_by_other_inner(identity, ip)
    }

    /** @brief 대량 만료·해제 뒤 희소해진 맵의 고수위 버킷을 기하급수적으로 줄인다. */
    fn shrink_map_if_sparse<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
        let len = map.len();
        if len == 0 {
            *map = HashMap::new();
        } else if map.capacity() > len.saturating_mul(4).max(16) {
            map.shrink_to(len.saturating_mul(2));
        }
    }

    /** @brief 현재 기록과 서비스 주소로 점유 인덱스와 다음 만료 시각을 다시 만든다. */
    fn rebuild_address_use(&mut self) {
        let mut address_use = HashMap::with_capacity(
            self.dynamic_entries()
                .saturating_add(self.reservations.len())
                .saturating_add(4),
        );
        let net = self.server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        for ip in [self.server_ip, self.router, net, bcast] {
            if ip >= self.start && ip <= self.end {
                Self::occupy_in(&mut address_use, ip);
            }
        }
        for lease in self.leases.values() {
            Self::occupy_in(&mut address_use, lease.ip);
        }
        for (ip, _, _) in self.offers.values() {
            Self::occupy_in(&mut address_use, *ip);
        }
        for ip in self.declined.keys() {
            Self::occupy_in(&mut address_use, *ip);
        }
        for (ip, _) in self.reservations.values() {
            Self::occupy_in(&mut address_use, *ip);
        }
        self.address_use = address_use;
        self.next_expiry = self
            .leases
            .values()
            .map(|lease| lease.expiry)
            .chain(self.offers.values().map(|(_, _, expiry)| *expiry))
            .chain(self.declined.values().copied())
            .min()
            .unwrap_or(u64::MAX);
    }

    /** @brief 가장 이른 만료 전에는 O(1), 도달했을 때만 만료 상태를 한 번 걷어 낸다. */
    fn cleanup_expired(&mut self, now: u64) {
        if now < self.next_expiry {
            return;
        }
        let mut next_expiry = u64::MAX;
        let address_use = &mut self.address_use;
        self.leases.retain(|_, lease| {
            if lease.expiry <= now {
                Self::vacate_in(address_use, lease.ip);
                false
            } else {
                next_expiry = next_expiry.min(lease.expiry);
                true
            }
        });
        self.offers.retain(|_, (ip, _, expiry)| {
            if *expiry <= now {
                Self::vacate_in(address_use, *ip);
                false
            } else {
                next_expiry = next_expiry.min(*expiry);
                true
            }
        });
        self.declined.retain(|ip, expiry| {
            if *expiry <= now {
                Self::vacate_in(address_use, *ip);
                false
            } else {
                next_expiry = next_expiry.min(*expiry);
                true
            }
        });
        self.next_expiry = next_expiry;
        Self::shrink_map_if_sparse(&mut self.leases);
        Self::shrink_map_if_sparse(&mut self.offers);
        Self::shrink_map_if_sparse(&mut self.declined);
        Self::shrink_map_if_sparse(&mut self.address_use);
    }

    /** @brief 점유 인덱스와 순환 커서만 보고 새 주소를 고른다. */
    fn pick_available(&mut self) -> Option<u32> {
        if self.start > self.end {
            return None;
        }
        let span = u64::from(self.end) - u64::from(self.start) + 1;
        let probes = span.min(self.address_use.len().saturating_add(1) as u64);
        let mut candidate =
            if self.allocation_cursor >= self.start && self.allocation_cursor <= self.end {
                self.allocation_cursor
            } else {
                self.start
            };
        for _ in 0..probes {
            let next = if candidate == self.end {
                self.start
            } else {
                candidate + 1
            };
            if !self.address_use.contains_key(&candidate) {
                self.allocation_cursor = next;
                return Some(candidate);
            }
            candidate = next;
        }
        self.allocation_cursor = candidate;
        None
    }

    /**
     * @brief 이 주소를 고정 할당해도 되는지.
     * @warning 서브넷 밖, 망 주소, 방송 주소, 서버와 관문 주소는 막는다. 내주면 그
     *          클라이언트는 통신을 못 하거나 망 전체를 흔든다.
     */
    fn validate_reservation_ip(&self, ip: u32) -> Result<(), String> {
        let net = self.server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        if (ip & self.subnet_mask) != net {
            return Err(format!("{} 는 서버 서브넷 밖", Ipv4Addr::from(ip)));
        }
        if ip == net || ip == bcast {
            return Err(format!(
                "{} 는 네트워크/브로드캐스트 주소",
                Ipv4Addr::from(ip)
            ));
        }
        if ip == self.server_ip || ip == self.router {
            return Err(format!("{} 는 서버/게이트웨이 주소", Ipv4Addr::from(ip)));
        }
        Ok(())
    }

    /**
     * @brief 읽어들인 기록을 지금 설정으로 다시 거른다.
     * @details 겹치는 고정 할당, 범위 밖 임대, 남의 고정 주소를 잡은 임대를 버린다.
     */
    fn revalidate_loaded_state(&mut self) {
        let now = crate::unix_now();
        let mut seen = std::collections::HashSet::new();
        let invalid_reservations: Vec<ClientIdentity> = self
            .reservations
            .iter()
            .filter_map(|(identity, (ip, _))| {
                let invalid = self.validate_reservation_ip(*ip).is_err() || !seen.insert(*ip);
                invalid.then(|| identity.clone())
            })
            .collect();
        for identity in invalid_reservations {
            self.reservations.remove(&identity);
            onetdns_core::warn!(event = "dhcp4.static_entry_invalid", identity = %identity.to_text(), "유효하지 않은 DHCP 고정 할당 항목을 제외했습니다");
        }
        let reservation_owners: std::collections::HashMap<u32, ClientIdentity> = self
            .reservations
            .iter()
            .map(|(identity, (ip, _))| (*ip, identity.clone()))
            .collect();
        let reservations = &self.reservations;
        let start = self.start;
        let end = self.end;
        let server_ip = self.server_ip;
        let router = self.router;
        let net = server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        let mut lease_ips = std::collections::HashSet::new();
        self.leases.retain(|identity, lease| {
            let reserved_by_other = reservation_owners
                .get(&lease.ip)
                .is_some_and(|owner| owner != identity);
            let address_allowed = match reservations.get(identity) {
                Some((reserved, _)) => *reserved == lease.ip,
                None => {
                    lease.ip >= start
                        && lease.ip <= end
                        && lease.ip != server_ip
                        && lease.ip != router
                        && lease.ip != net
                        && lease.ip != bcast
                }
            };
            let valid = lease.expiry > now
                && address_allowed
                && !reserved_by_other
                && lease_ips.insert(lease.ip);
            if !valid {
                onetdns_core::warn!(event = "dhcp4.stale_lease_dropped", identity = %identity.to_text(), ip = %Ipv4Addr::from(lease.ip), "현재 DHCP 주소 범위에 맞지 않는 저장된 임대 정보를 삭제했습니다");
            }
            valid
        });
    }

    /** @brief 제안한 주소를 잠시 잡아 둔다. */
    pub fn hold_offer(&mut self, identity: &ClientIdentity, xid: u32, ip: u32) -> bool {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if !self.offers.contains_key(identity) && !self.admit_dynamic_after_removing(0) {
            return false;
        }
        let expiry = now.saturating_add(60);
        match self.offers.insert(identity.clone(), (ip, xid, expiry)) {
            Some((old_ip, _, _)) if old_ip != ip => {
                Self::vacate_in(&mut self.address_use, old_ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry);
        true
    }

    /**
     * @brief 이 확정 요청이 이 서버가 제안한 것과 맞는지 보고 잡아 둔 것을 푼다.
     * @warning 거래 번호와 주소가 모두 맞아야 한다. 맞추지 않으면 다른 서버가 제안한
     *          주소를 이 서버가 확정해 준다.
     */
    fn consume_offer(&mut self, identity: &ClientIdentity, xid: u32, ip: u32) -> bool {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let valid = matches!(
            self.offers.get(identity),
            Some((held, held_xid, expiry)) if *held == ip && *held_xid == xid && *expiry > now
        );
        if valid {
            if let Some((removed_ip, _, _)) = self.offers.remove(identity) {
                Self::vacate_in(&mut self.address_use, removed_ip);
            }
        }
        valid
    }

    /**
     * @brief 이미 쓰이고 있다는 통지를 받아 그 주소를 잠시 뺀다.
     * @warning 그 주소의 임자만 통지할 수 있다. 아무나 받아 주면 통지 몇 번으로 범위
     *          전체를 비워 버릴 수 있다.
     */
    pub fn decline(&mut self, identity: &ClientIdentity, ip: u32) {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let owns = self
            .offers
            .get(identity)
            .map(|(oip, ..)| *oip == ip)
            .unwrap_or(false)
            || self
                .leases
                .get(identity)
                .is_some_and(|lease| lease.ip == ip && lease.expiry > now);
        if owns && !self.declined.contains_key(&ip) {
            let removing = usize::from(self.leases.contains_key(identity))
                .saturating_add(usize::from(self.offers.contains_key(identity)));
            if !self.admit_dynamic_after_removing(removing) {
                return;
            }
        }
        if let Some(lease) = self.leases.remove(identity) {
            Self::vacate_in(&mut self.address_use, lease.ip);
            self.save();
        }
        if let Some((removed_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, removed_ip);
        }
        if owns && ip >= self.start && ip <= self.end {
            let expiry = now.saturating_add(600);
            if self.declined.insert(ip, expiry).is_none() {
                Self::occupy_in(&mut self.address_use, ip);
            }
            self.next_expiry = self.next_expiry.min(expiry);
        }
    }

    /**
     * @brief 이 클라이언트에 줄 주소를 고른다.
     * @details 고정 할당이 있으면 그것, 없으면 이미 잡은 것, 그것도 없으면 비어 있는
     *          첫 주소. 제안 중이거나 거절당한 주소는 쓰지 않는다.
     */
    pub fn allocate(&mut self, identity: &ClientIdentity) -> Option<u32> {
        if let Some((ip, _)) = self.reservations.get(identity) {
            return Some(*ip);
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if let Some((ip, _, expiry)) = self.offers.get(identity) {
            if *expiry > now {
                return Some(*ip);
            }
        }
        if let Some(l) = self.leases.get(identity) {
            if l.expiry > now {
                return Some(l.ip);
            }
        }
        if !self.admit_dynamic_after_removing(0) {
            return None;
        }

        let picked = self.pick_available();
        match (picked, self.exhausted) {
            (None, false) => {
                self.exhausted = true;
                onetdns_core::warn!(event = "dhcp4.pool_exhausted", range_start = %Ipv4Addr::from(self.start), range_end = %Ipv4Addr::from(self.end), indexed_addresses = self.address_use.len(), "DHCP 주소 범위가 모두 차서 새 기기에 주소를 주지 못합니다");
            }
            (Some(_), true) => {
                self.exhausted = false;
                onetdns_core::info!(event = "dhcp4.pool_available", range_start = %Ipv4Addr::from(self.start), range_end = %Ipv4Addr::from(self.end), "DHCP 주소 범위에 다시 빈자리가 생겼습니다");
            }
            _ => {}
        }
        picked
    }

    /** @brief 이 클라이언트에 고정된 주소. */
    pub fn reservation_ip(&self, identity: &ClientIdentity) -> Option<u32> {
        self.reservations.get(identity).map(|(ip, _)| *ip)
    }

    /** @brief 이 주소가 다른 클라이언트에 고정돼 있는지. */
    pub fn is_reserved_by_other(&self, ip: u32, identity: &ClientIdentity) -> bool {
        self.reservations
            .iter()
            .any(|(owner, (reserved, _))| *reserved == ip && owner != identity)
    }

    /**
     * @brief 고정 할당을 넣는다.
     * @details 그 주소를 임시로 잡고 있던 다른 클라이언트의 임대는 걷는다. 걷지 않으면
     *          같은 주소를 둘이 쓴다.
     */
    pub fn add_reservation(
        &mut self,
        identity: ClientIdentity,
        ip: u32,
        hostname: Option<String>,
    ) -> Result<(), String> {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return Err(
                "hostname 값은 1~255바이트이며 공백이나 제어문자를 포함할 수 없습니다".to_string(),
            );
        }
        self.validate_reservation_ip(ip)?;
        if self.is_reserved_by_other(ip, &identity) {
            return Err(format!(
                "IP {} 는 이미 다른 클라이언트 식별자에 예약됨",
                Ipv4Addr::from(ip)
            ));
        }
        if !self.reservations.contains_key(&identity)
            && !Self::admit_state(
                &mut self.reservations_limited,
                "reservations",
                self.reservations.len(),
            )
        {
            return Err(format!(
                "DHCPv4 고정 할당은 최대 {MAX_STATE_ENTRIES}개입니다"
            ));
        }
        let now = crate::unix_now();
        let stale: Vec<ClientIdentity> = self
            .leases
            .iter()
            .filter(|(owner, lease)| lease.ip == ip && lease.expiry > now && *owner != &identity)
            .map(|(owner, _)| owner.clone())
            .collect();
        let freed = !stale.is_empty();
        for owner in stale {
            if let Some(lease) = self.leases.remove(&owner) {
                Self::vacate_in(&mut self.address_use, lease.ip);
            }
        }
        match self.reservations.insert(identity, (ip, hostname)) {
            Some((old_ip, _)) if old_ip != ip => {
                Self::vacate_in(&mut self.address_use, old_ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.save_static();
        if freed {
            Self::shrink_map_if_sparse(&mut self.leases);
            self.save();
        }
        Ok(())
    }

    /** @brief 고정 할당을 지운다. */
    pub fn remove_reservation(&mut self, identity: &ClientIdentity) -> bool {
        if let Some((ip, _)) = self.reservations.remove(identity) {
            Self::vacate_in(&mut self.address_use, ip);
            Self::shrink_map_if_sparse(&mut self.reservations);
            Self::shrink_map_if_sparse(&mut self.address_use);
            self.save_static();
            true
        } else {
            false
        }
    }

    /** @brief 고정 할당 목록. */
    pub fn reservations(&self) -> Vec<ReservationInfo> {
        let mut out: Vec<ReservationInfo> = self
            .reservations
            .iter()
            .map(|(identity, (ip, h))| ReservationInfo {
                identity: identity.clone(),
                ip: Ipv4Addr::from(*ip),
                hostname: h.clone(),
            })
            .collect();
        out.sort_by_key(|r| u32::from(r.ip));
        out
    }

    /** @brief 확정한 임대를 기록에 적고 저장한다. */
    pub fn commit(
        &mut self,
        identity: &ClientIdentity,
        mac: [u8; 6],
        ip: u32,
        hostname: Option<String>,
    ) -> bool {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return false;
        }
        let hostname = self
            .reservations
            .get(identity)
            .and_then(|(_, reserved)| reserved.clone())
            .or(hostname)
            .or_else(|| {
                self.leases
                    .get(identity)
                    .and_then(|lease| lease.hostname.clone())
            });
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if !self.leases.contains_key(identity) {
            let removing = usize::from(self.offers.contains_key(identity));
            if !self.admit_dynamic_after_removing(removing) {
                return false;
            }
        }
        let expiry = lease_expiry(now, self.lease_secs);
        if let Some((offer_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, offer_ip);
        }
        match self.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry,
                hostname,
            },
        ) {
            Some(old) if old.ip != ip => {
                Self::vacate_in(&mut self.address_use, old.ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry);
        self.save();
        true
    }

    /** @brief HA에서 받은 주소가 이 식별자에 안전하게 귀속될 수 있는지 검사한다. */
    fn validate_synced_lease_inner(
        &self,
        identity: &ClientIdentity,
        ip: u32,
    ) -> Result<(), String> {
        match self.reservations.get(identity) {
            Some((reserved, _)) if *reserved != ip => {
                return Err(format!(
                    "클라이언트 {} 는 IP {} 에 고정되어 있습니다",
                    identity.to_text(),
                    Ipv4Addr::from(*reserved)
                ));
            }
            None if ip < self.start || ip > self.end => {
                return Err(format!(
                    "IP {} 는 DHCP 동적 범위 밖입니다",
                    Ipv4Addr::from(ip)
                ));
            }
            _ => {}
        }

        if self.address_used_by_other_inner(identity, ip) {
            return Err(format!(
                "IP {} 는 이미 다른 DHCP 상태가 사용 중입니다",
                Ipv4Addr::from(ip)
            ));
        }
        Ok(())
    }

    /** @brief HA 배치의 주소 소유권과 순서별 상태 예산을 반영 전에 검사한다. */
    pub fn validate_synced_batch(
        &mut self,
        entries: impl IntoIterator<Item = (ClientIdentity, u32, u64)>,
    ) -> Result<(), String> {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let mut projected = self.dynamic_entries();
        for (identity, ip, expiry) in entries {
            if expiry <= now {
                return Err(format!(
                    "클라이언트 {} 의 임대 만료 시각이 이미 지났습니다",
                    identity.to_text()
                ));
            }
            self.validate_synced_lease_inner(&identity, ip)?;

            let lease = self.leases.get(&identity);
            if lease.is_some_and(|existing| existing.ip == ip && existing.expiry >= expiry) {
                continue;
            }
            if lease.is_some() {
                projected =
                    projected.saturating_sub(usize::from(self.offers.contains_key(&identity)));
            } else if !self.offers.contains_key(&identity) {
                if projected >= MAX_STATE_ENTRIES {
                    return Err(format!(
                        "DHCPv4 동적 상태는 최대 {MAX_STATE_ENTRIES}개입니다"
                    ));
                }
                projected += 1;
            }
        }
        Ok(())
    }

    /** @brief 밖에서 받은 임대를 넣는다. 이미 더 새 것이 있으면 넣지 않는다. */
    pub fn insert(
        &mut self,
        identity: &ClientIdentity,
        mac: [u8; 6],
        ip: u32,
        expiry_unix: u64,
        hostname: Option<String>,
    ) -> bool {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return false;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if expiry_unix <= now {
            return false;
        }
        if self.validate_synced_lease_inner(identity, ip).is_err() {
            return false;
        }
        if let Some(existing) = self.leases.get(identity) {
            if existing.expiry >= expiry_unix && existing.ip == ip {
                return false;
            }
        }
        if !self.leases.contains_key(identity) {
            let removing = usize::from(self.offers.contains_key(identity));
            if !self.admit_dynamic_after_removing(removing) {
                return false;
            }
        }
        if let Some((offer_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, offer_ip);
        }
        match self.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry: expiry_unix,
                hostname,
            },
        ) {
            Some(old) if old.ip != ip => {
                Self::vacate_in(&mut self.address_use, old.ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry_unix);
        true
    }

    /** @brief 클라이언트가 실제로 잡은 주소만 기록에서 지운다. */
    pub fn release(&mut self, identity: &ClientIdentity, ip: u32) {
        if self
            .leases
            .get(identity)
            .is_some_and(|lease| lease.ip == ip)
        {
            if let Some(lease) = self.leases.remove(identity) {
                Self::vacate_in(&mut self.address_use, lease.ip);
                Self::shrink_map_if_sparse(&mut self.leases);
                Self::shrink_map_if_sparse(&mut self.address_use);
                self.save();
            }
        }
    }

    /** @brief 살아 있는 임대 수. */
    pub fn active(&self) -> usize {
        let now = crate::unix_now();
        self.leases.values().filter(|l| l.expiry > now).count()
    }

    /** @brief 살아 있는 임대 목록. 대시보드가 쓴다. */
    pub fn snapshot(&self) -> Vec<LeaseInfo> {
        let now = crate::unix_now();
        let mut out: Vec<LeaseInfo> = self
            .leases
            .iter()
            .filter(|(_, l)| l.expiry > now)
            .map(|(identity, l)| LeaseInfo {
                identity: identity.clone(),
                mac: l.mac,
                ip: Ipv4Addr::from(l.ip),
                expiry_unix: l.expiry,
                hostname: l.hostname.clone(),
            })
            .collect();
        out.sort_by_key(|i| u32::from(i.ip));
        out
    }

    /** @brief 임대 기록을 원자적으로 교체해 저장한다. */
    pub fn save(&self) {
        let Some(path) = &self.persist else { return };
        let now = crate::unix_now();
        let mut text = String::from(LEASE_HEADER);
        for (identity, l) in self.leases.iter().filter(|(_, l)| l.expiry > now) {
            text.push_str(&format!(
                "{} {} {} {}",
                identity.to_text(),
                mac_hex(&l.mac),
                Ipv4Addr::from(l.ip),
                l.expiry
            ));
            if let Some(h) = &l.hostname {
                text.push(' ');
                text.push_str(h);
            }
            text.push('\n');
        }
        if let Err(e) = crate::atomic_file::atomic_write(path, text.as_bytes()) {
            onetdns_core::warn!(event = "dhcp4.lease_save_failed", path = ?path, error = %e, "DHCP 임대 정보를 파일에 저장하지 못했습니다");
        }
    }

    /** @brief 고정 할당을 원자적으로 교체해 저장한다. */
    fn save_static(&self) {
        let Some(path) = &self.static_persist else {
            return;
        };
        let mut text = String::from(RESERVATION_HEADER);
        for (identity, (ip, h)) in &self.reservations {
            text.push_str(&format!("{} {}", identity.to_text(), Ipv4Addr::from(*ip)));
            if let Some(h) = h {
                text.push(' ');
                text.push_str(h);
            }
            text.push('\n');
        }
        if let Err(e) = crate::atomic_file::atomic_write(path, text.as_bytes()) {
            onetdns_core::warn!(event = "dhcp4.static_save_failed", path = ?path, error = %e, "DHCP 고정 할당 정보를 저장하지 못했습니다");
        }
    }
}

/**
 * @brief 고정 할당 파일을 읽는다.
 * @warning 운영자가 고치는 파일이라 어긋나면 읽지 않고 실패한다. 빈 기록으로 덮어쓰면
 *          운영자의 할당이 사라진다.
 * @return 파일이 없으면 빈 목록. 열거나 읽지 못하거나 형식이 어긋나면 그 이유.
 */
pub fn read_reservations(
    path: &std::path::Path,
) -> Result<HashMap<ClientIdentity, (u32, Option<String>)>, String> {
    let shown = path.display();
    let bytes = match std::fs::File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(MAX_PERSIST_FILE + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    format!("DHCP 고정 할당 파일을 읽지 못했습니다({shown}): {error}")
                })?;
            bytes
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(format!(
                "DHCP 고정 할당 파일을 열지 못했습니다({shown}): {error}"
            ));
        }
    };
    if bytes.len() as u64 > MAX_PERSIST_FILE {
        return Err(format!(
            "DHCP 고정 할당 파일이 허용 크기 {MAX_PERSIST_FILE}바이트를 넘습니다({shown})"
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("DHCP 고정 할당 파일이 UTF-8 텍스트가 아닙니다({shown})"))?;
    let body = text.strip_prefix(RESERVATION_HEADER).ok_or_else(|| {
        format!(
            "DHCP 고정 할당 파일({shown})의 첫 줄은 {}이어야 합니다",
            RESERVATION_HEADER.trim_end()
        )
    })?;
    let mut out = HashMap::new();
    for (index, line) in body.lines().enumerate() {
        let line_no = index + 2;
        if out.len() >= MAX_STATE_ENTRIES {
            return Err(format!(
                "DHCP 고정 할당 파일({shown})의 항목이 상한 {MAX_STATE_ENTRIES}개를 넘습니다"
            ));
        }
        let bad =
            || format!("DHCP 고정 할당 파일({shown}) {line_no}번째 줄의 형식이 올바르지 않습니다");
        let mut toks = line.split_whitespace();
        let (Some(identity_s), Some(ip_s)) = (toks.next(), toks.next()) else {
            return Err(bad());
        };
        let (Some(identity), Ok(ip)) = (
            ClientIdentity::from_text(identity_s),
            ip_s.parse::<Ipv4Addr>(),
        ) else {
            return Err(bad());
        };
        let hostname = toks.next().map(|s| s.to_string());
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
            || toks.next().is_some()
        {
            return Err(bad());
        }
        if out.insert(identity, (u32::from(ip), hostname)).is_some() {
            return Err(format!(
                "DHCP 고정 할당 파일({shown}) {line_no}번째 줄의 클라이언트가 앞에서 이미 나왔습니다"
            ));
        }
    }
    Ok(out)
}

/** @brief 하드웨어 주소를 16진 문자열로. */
fn mac_hex(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

/** @brief 16진 문자열을 하드웨어 주소로. */
fn mac_from_hex(s: &str) -> Option<[u8; 6]> {
    if s.len() != 12 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/** @brief 임의 바이트열을 손실 없는 소문자 16진수로. */
fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/** @brief 최대 option 61 크기의 짝수 길이 16진수를 바이트열로. */
fn bytes_from_hex(text: &str) -> Option<Vec<u8>> {
    if !(4..=510).contains(&text.len())
        || text.len() % 2 != 0
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[index..index + 2], 16).ok()?);
    }
    Some(out)
}

/**
 * @brief 저장된 임대를 읽는다.
 * @warning 한 줄이라도 형식이 어긋나면 전체를 버린다. 반쯤 읽어 들이면 어떤 주소가
 *          이미 나갔는지 알 수 없어 같은 주소를 둘에게 준다.
 */
fn load_leases(path: &std::path::Path) -> HashMap<ClientIdentity, Lease> {
    let mut out = HashMap::new();
    let mut seen_ips = std::collections::HashSet::new();
    let Some(text) = read_persist_text(path) else {
        return out;
    };
    let Some(text) = text.strip_prefix(LEASE_HEADER) else {
        onetdns_core::warn!(event = "dhcp4.leases_restore_invalid", path = %path.display(), "DHCP 임대 파일이 현재 형식과 일치하지 않아 빈 상태로 시작합니다");
        return out;
    };
    let now = crate::unix_now();
    let mut malformed = 0u64;
    for line in text.lines() {
        if out.len() >= MAX_STATE_ENTRIES {
            malformed = malformed.saturating_add(1);
            continue;
        }
        let mut toks = line.split_whitespace();
        let (Some(identity_s), Some(mac_s), Some(ip_s), Some(exp_s)) =
            (toks.next(), toks.next(), toks.next(), toks.next())
        else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let (Some(identity), Some(mac), Ok(ip), Ok(expiry)) = (
            ClientIdentity::from_text(identity_s),
            mac_from_hex(mac_s),
            ip_s.parse::<Ipv4Addr>(),
            exp_s.parse::<u64>(),
        ) else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let hostname = toks.next().map(|s| s.to_string());
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
            || toks.next().is_some()
        {
            malformed = malformed.saturating_add(1);
            continue;
        }
        if expiry <= now {
            continue;
        }
        let ip = u32::from(ip);
        if identity
            .hardware()
            .is_some_and(|identity_mac| identity_mac != mac)
            || out.contains_key(&identity)
            || !seen_ips.insert(ip)
        {
            malformed = malformed.saturating_add(1);
            continue;
        }
        out.insert(
            identity,
            Lease {
                mac,
                ip,
                expiry,
                hostname,
            },
        );
    }
    if malformed > 0 {
        onetdns_core::warn!(
            event = "dhcp4.leases_restore_invalid",
            path = %path.display(),
            malformed,
            "DHCP 임대 파일이 손상되어 빈 상태로 시작합니다"
        );
        return HashMap::new();
    }
    out
}

/** @brief 상태 변경 전에 확정한 DHCPv4 클라이언트 동작. */
enum ClientAction {
    Discover,
    Request { target: Ipv4Addr, selecting: bool },
    Decline { target: Ipv4Addr },
    Release { target: Ipv4Addr },
}

/** @brief 없거나 정확히 4바이트인 IPv4 옵션만 구분한다. */
fn optional_ipv4_option(req: &DhcpMessage, code: u8) -> Option<Option<Ipv4Addr>> {
    match req.option(code) {
        Some(raw) => Some(Some(opt_ipv4(raw)?)),
        None => Some(None),
    }
}

/** @brief RFC 2131의 상태별 필드 조합을 상태 변경 전에 검증한다. */
fn classify_client_action(req: &DhcpMessage, server_ip: Ipv4Addr) -> Option<ClientAction> {
    if req.flags & !BROADCAST_FLAG != 0
        || req.yiaddr != Ipv4Addr::UNSPECIFIED
        || req.siaddr != Ipv4Addr::UNSPECIFIED
    {
        return None;
    }
    let requested = optional_ipv4_option(req, OPT_REQUESTED_IP)?;
    let server = optional_ipv4_option(req, OPT_SERVER_ID)?;

    match req.msg_type()? {
        DISCOVER if req.ciaddr == Ipv4Addr::UNSPECIFIED && server.is_none() => {
            Some(ClientAction::Discover)
        }
        REQUEST => match (server, requested, req.ciaddr) {
            (Some(selected), Some(target), ciaddr)
                if selected == server_ip && ciaddr == Ipv4Addr::UNSPECIFIED =>
            {
                Some(ClientAction::Request {
                    target,
                    selecting: true,
                })
            }
            (None, Some(target), ciaddr) if ciaddr == Ipv4Addr::UNSPECIFIED => {
                Some(ClientAction::Request {
                    target,
                    selecting: false,
                })
            }
            (None, None, ciaddr) if ciaddr != Ipv4Addr::UNSPECIFIED => {
                Some(ClientAction::Request {
                    target: ciaddr,
                    selecting: false,
                })
            }
            _ => None,
        },
        DECLINE
            if req.flags == 0
                && req.ciaddr == Ipv4Addr::UNSPECIFIED
                && server == Some(server_ip) =>
        {
            Some(ClientAction::Decline { target: requested? })
        }
        RELEASE
            if req.flags == 0
                && req.ciaddr != Ipv4Addr::UNSPECIFIED
                && requested.is_none()
                && server == Some(server_ip) =>
        {
            Some(ClientAction::Release { target: req.ciaddr })
        }
        _ => None,
    }
}

/**
 * @brief 요청 하나를 처리해 응답을 만든다.
 * @warning 서버 식별자가 이 서버의 것이 아니면 끼어들지 않는다. 그리고 남이 잡은 주소나 남에게
 *          고정된 주소는 거절한다. 확정해 주면 같은 주소를 둘이 쓴다.
 */
pub fn handle(req: &DhcpMessage, pool: &mut LeasePool, cfg: &DhcpConfig) -> Option<DhcpMessage> {
    let identity = req.client_identity();
    match classify_client_action(req, cfg.server_ip)? {
        ClientAction::Discover => {
            let ip = pool.allocate(&identity)?;
            if !pool.hold_offer(&identity, req.xid, ip) {
                return None;
            }
            Some(build_reply(req, OFFER, Ipv4Addr::from(ip), cfg))
        }
        ClientAction::Request { target, selecting } => {
            let want_u = u32::from(target);
            if selecting && !pool.consume_offer(&identity, req.xid, want_u) {
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = "no_matching_offer", "이 서버가 제안한 적 없는 주소를 확정해 달라는 요청이라 거절했습니다");
                return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
            }
            if let Some(rip) = pool.reservation_ip(&identity) {
                if rip != want_u {
                    onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reserved = %Ipv4Addr::from(rip), reason = "reserved_address_mismatch", "고정 할당과 다른 주소를 요청해 거절했습니다");
                    return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
                }
                if !pool.address_used_by_other(&identity, rip)
                    && pool.commit(&identity, req.chaddr, rip, req.hostname())
                {
                    return Some(build_reply(req, ACK, Ipv4Addr::from(rip), cfg));
                }
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %Ipv4Addr::from(rip), reason = "reserved_address_unavailable", "고정 할당 주소를 안전하게 확정할 수 없어 거절했습니다");
                return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
            }
            let used_by_other = pool.address_used_by_other(&identity, want_u);
            if want_u >= pool.start && want_u <= pool.end && !used_by_other {
                if pool.commit(&identity, req.chaddr, want_u, req.hostname()) {
                    Some(build_reply(req, ACK, target, cfg))
                } else {
                    onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = "lease_state_limit", "임대 기록 상한 때문에 새 주소를 확정하지 않습니다");
                    Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg))
                }
            } else {
                /*
                 * 이 서버에 기록이 없는 클라이언트가 같은 망에서 이 서버의 범위 밖 주소를 요청하면
                 * 같은 망의 다른 서버가 준 주소다. RFC 2131 은 기록이 없는 클라이언트에게 답하지
                 * 말라고 정한다. NAK 를 보내면 그 기기가 쓰던 주소를 버린다. 이 서버 범위의 주소는
                 * 이 서버가 맡으므로 NAK 로 거절하고, 망 밖의 주소는 잘못된 망이라는 뜻이므로 NAK 로
                 * 알린다.
                 */
                let outside_pool = want_u < pool.start || want_u > pool.end;
                if !selecting
                    && outside_pool
                    && in_served_subnet(target, cfg)
                    && !pool.has_record(&identity)
                {
                    onetdns_core::debug!(event = "dhcp4.request_ignored", identity = %identity.to_text(), requested = %target, reason = "unknown_client", "기록이 없는 클라이언트의 같은 망 주소 요청이라 답하지 않습니다");
                    return None;
                }
                let reason = if want_u < pool.start || want_u > pool.end {
                    "out_of_range"
                } else {
                    "used_by_other"
                };
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = reason, "요청한 주소를 줄 수 없어 거절했습니다");
                Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg))
            }
        }
        ClientAction::Release { target } => {
            pool.release(&identity, u32::from(target));
            None
        }
        ClientAction::Decline { target } => {
            pool.decline(&identity, u32::from(target));
            None
        }
    }
}

/** @brief 이 서버가 맡은 서브넷의 주소인지. */
fn in_served_subnet(ip: Ipv4Addr, cfg: &DhcpConfig) -> bool {
    let mask = u32::from(cfg.subnet_mask);
    u32::from(ip) & mask == u32::from(cfg.server_ip) & mask
}

/** @brief 응답 메시지를 만든다. 거절에는 설정 값을 담지 않는다. */
fn build_reply(req: &DhcpMessage, mtype: u8, yiaddr: Ipv4Addr, cfg: &DhcpConfig) -> DhcpMessage {
    let mut options = vec![
        (OPT_MSG_TYPE, vec![mtype]),
        (OPT_SERVER_ID, cfg.server_ip.octets().to_vec()),
    ];
    if mtype != NAK {
        options.push((OPT_LEASE_TIME, cfg.lease_secs.to_be_bytes().to_vec()));
        options.push((OPT_SUBNET_MASK, cfg.subnet_mask.octets().to_vec()));
        options.push((OPT_ROUTER, cfg.router.octets().to_vec()));
        let dns: Vec<u8> = cfg.dns.iter().flat_map(|d| d.octets()).collect();
        if !dns.is_empty() {
            options.push((OPT_DNS, dns));
        }

        if let Some(domain) = &cfg.domain_name {
            options.push((OPT_DOMAIN_NAME, domain.as_bytes().to_vec()));
        }
        if let Some(tftp) = cfg.tftp_server {
            options.push((OPT_TFTP_SERVER_NAME, tftp.to_string().into_bytes()));
        }
        if let Some(bf) = &cfg.boot_file {
            options.push((OPT_BOOTFILE, bf.as_bytes().to_vec()));
        }
    }
    DhcpMessage {
        op: 2,
        xid: req.xid,
        flags: if mtype == NAK && req.giaddr != Ipv4Addr::UNSPECIFIED {
            req.flags | BROADCAST_FLAG
        } else {
            req.flags
        },
        ciaddr: if mtype == ACK {
            req.ciaddr
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        yiaddr,

        siaddr: if mtype != NAK {
            cfg.tftp_server.unwrap_or(cfg.server_ip)
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        giaddr: req.giaddr,
        chaddr: req.chaddr,
        client_identifier: None,
        options,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief DHCP 응답이 일반 UDP 경로인지 초기 클라이언트 L2 직접 경로인지. */
enum ReplyTarget {
    /** @brief 커널 IP 계층으로 보내도 되는 목적지. */
    Udp(std::net::SocketAddr),
    /** @brief IP가 아직 없는 클라이언트의 yiaddr와 Ethernet 목적지. */
    InitialUnicast { ip: Ipv4Addr, mac: [u8; 6] },
}

/** @brief Ethernet unicast 목적지로 쓸 수 있는 MAC인지. */
fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/** @brief 요청과 응답 엔벨로프를 보고 RFC 2131의 IP·L2 목적지를 함께 고른다. */
fn reply_target(req: &DhcpMessage, reply: &DhcpMessage) -> ReplyTarget {
    if req.giaddr != Ipv4Addr::UNSPECIFIED {
        ReplyTarget::Udp(std::net::SocketAddr::from((req.giaddr, 67)))
    } else if reply.msg_type() == Some(NAK) {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    } else if req.ciaddr != Ipv4Addr::UNSPECIFIED {
        ReplyTarget::Udp(std::net::SocketAddr::from((req.ciaddr, 68)))
    } else if req.flags & BROADCAST_FLAG != 0 {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    } else if unicast_mac(req.chaddr) {
        ReplyTarget::InitialUnicast {
            ip: reply.yiaddr,
            mac: req.chaddr,
        }
    } else {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    }
}

/** @brief 초기 L2 유니캐스트가 불가능하면 RFC 2131이 허용한 방송으로 반드시 한 번 더 보낸다. */
fn send_initial_with_fallback<U, B>(unicast: U, broadcast: B) -> std::io::Result<bool>
where
    U: FnOnce() -> std::io::Result<()>,
    B: FnOnce() -> std::io::Result<()>,
{
    if unicast().is_ok() {
        Ok(true)
    } else {
        broadcast()?;
        Ok(false)
    }
}

/**
 * @brief 이 서버가 맡은 망에서 온 요청인지.
 * @details 중계된 요청은 중계기가 서버 주소로 직접 보내므로 들어온 인터페이스와 무관하다.
 *          들어온 인터페이스나 서버 인터페이스를 알 수 없으면 받는다.
 */
fn from_served_link(giaddr: Ipv4Addr, arrival: Option<u32>, served: Option<u32>) -> bool {
    if giaddr != Ipv4Addr::UNSPECIFIED {
        return true;
    }
    match (arrival, served) {
        (Some(arrival), Some(served)) => arrival == served,
        _ => true,
    }
}

/** @brief DHCP 서버를 시작한다. */
pub fn spawn_dhcp(
    cfg: DhcpConfig,
    port: u16,
    pool: std::sync::Arc<std::sync::Mutex<LeasePool>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use onetdns_core::MutexExt;
    let sock = crate::dhcp_l2::bind_server_socket(cfg.server_ip, port)?;
    sock.set_broadcast(true)?;
    let wait = onetdns_core::udp::RecvWait::new(Duration::from_millis(500));
    wait.install(&sock)?;
    std::thread::Builder::new().name("dhcp".into()).spawn(move || {
        let mut buf = vec![0u8; DHCP4_RECV_CAPACITY];
        let mut served = crate::dhcp_l2::served_interface(cfg.server_ip);
        while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            let (n, arrival) = match crate::dhcp_l2::recv_request(&sock, wait, &mut buf) {
                Ok(received) => received,
                Err(error) => {
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) {
                        onetdns_core::warn!(event = "dhcp4.recv_failed", %error, "DHCP 요청을 받지 못했습니다");
                    }
                    continue;
                }
            };
            let Some(n) = standard_dhcp4_datagram_len(n) else {
                continue;
            };
            let Some(req) = parse_client_request(&buf[..n]) else { continue };
            if !from_served_link(req.giaddr, arrival, served) {
                /* 인터페이스 번호는 인터페이스를 다시 만들면 바뀌므로 버리기 전에 한 번 다시 찾는다. */
                served = crate::dhcp_l2::served_interface(cfg.server_ip);
                if !from_served_link(req.giaddr, arrival, served) {
                    continue;
                }
            }
            let reply = handle(&req, &mut pool.lock_recover(), &cfg);
            if let Some(reply) = reply {
                if reply.msg_type() == Some(ACK) {
                    onetdns_core::debug!(event = "dhcp4.lease_issued", ip = %reply.yiaddr, active = pool.lock_recover().active(), "DHCP 임대 주소를 발급했습니다");
                }
                let wire = reply.encode();
                let target = reply_target(&req, &reply);
                let sent = match target {
                    ReplyTarget::Udp(destination) if destination.ip() == std::net::IpAddr::V4(Ipv4Addr::BROADCAST) => {
                        crate::dhcp_l2::send_broadcast(&sock, cfg.server_ip, destination.port(), &wire).map(|_| true)
                    }
                    ReplyTarget::Udp(destination) => {
                        sock.send_to(&wire, destination).map(|_| true)
                    }
                    ReplyTarget::InitialUnicast { ip, mac } => send_initial_with_fallback(
                        || {
                            crate::dhcp_l2::send_initial_unicast(
                                &sock,
                                cfg.server_ip,
                                port,
                                ip,
                                mac,
                                &wire,
                            )
                            .map_err(|error| {
                                onetdns_core::warn!(event = "dhcp4.initial_unicast_fallback", ip = %ip, mac = %mac_hex(&mac), %error, "초기 클라이언트에 L2 유니캐스트를 보낼 수 없어 방송으로 다시 보냅니다");
                                error
                            })
                        },
                        || crate::dhcp_l2::send_broadcast(&sock, cfg.server_ip, 68, &wire),
                    ),
                };
                if let Err(error) = sent {
                    onetdns_core::warn!(event = "dhcp4.send_failed", target = ?target, mac = %mac_hex(&req.chaddr), %error, "DHCP 응답을 보내지 못해 이 기기는 주소를 받지 못합니다");
                }
            }
        }
    })
}

#[cfg(test)]
/** @brief 임대 가로채기 방어, 고정 할당 규칙, 인코딩 왕복과 저장. */
mod tests {
    use super::*;

    /** @brief 테스트용 설정. */
    fn cfg() -> DhcpConfig {
        DhcpConfig {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 102),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        }
    }

    #[test]
    /** @brief DHCPv4 infinity 임대가 내부에서 유한한 만료 시각으로 바뀌지 않는지. */
    fn infinite_lease_stays_infinite_in_the_pool() {
        let mut c = cfg();
        c.lease_secs = u32::MAX;
        let mut pool = LeasePool::new(&c);
        let mac = [1, 2, 3, 4, 5, 6];
        let identity = ClientIdentity::Hardware(mac);
        assert!(pool.commit(&identity, mac, u32::from(c.range_start), None));
        assert_eq!(pool.leases.get(&identity).unwrap().expiry, u64::MAX);
    }

    /** @brief 큰 상태 상한 테스트에서 겹치지 않는 MAC을 만든다. */
    fn mac_for(index: usize) -> [u8; 6] {
        let bytes = (index as u64).to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    /** @brief option 61이 없는 테스트 클라이언트의 소유권 키. */
    fn identity_for(index: usize) -> ClientIdentity {
        ClientIdentity::Hardware(mac_for(index))
    }

    #[test]
    /** @brief 네트워크 부팅에 필요한 값이 확정 응답에 담기는지. */
    fn pxe_boot_options_in_ack() {
        let mut c = cfg();
        c.tftp_server = Some(Ipv4Addr::new(192, 168, 1, 5));
        c.boot_file = Some("pxelinux.0".to_string());
        let mut pool = LeasePool::new(&c);
        let mut req = discover([1, 2, 3, 4, 5, 6]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, [192, 168, 1, 100].to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));

        assert_eq!(ack.siaddr, Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(ack.option(OPT_BOOTFILE), Some(b"pxelinux.0".as_slice()));
    }

    #[test]
    /** @brief 만료된 임대가 슬롯을 계속 차지하지 않는지. */
    fn allocate_prunes_expired_leases() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let expired_mac = [1, 2, 3, 4, 5, 6];
        pool.leases.insert(
            ClientIdentity::Hardware(expired_mac),
            Lease {
                mac: expired_mac,
                ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)),
                expiry: crate::unix_now(),
                hostname: None,
            },
        );
        pool.rebuild_address_use();

        assert!(pool
            .allocate(&ClientIdentity::Hardware([6, 5, 4, 3, 2, 1]))
            .is_some());
        assert!(pool.leases.is_empty());
    }

    #[test]
    /** @brief 잘못 넓게 잡은 범위에서도 서버와 게이트웨이 주소를 내주지 않는지. */
    fn allocation_never_uses_server_or_router_address() {
        let mut c = cfg();
        c.range_start = Ipv4Addr::new(192, 168, 1, 1);
        c.range_end = Ipv4Addr::new(192, 168, 1, 3);
        c.router = Ipv4Addr::new(192, 168, 1, 2);
        let mut pool = LeasePool::new(&c);

        assert_eq!(
            pool.allocate(&ClientIdentity::Hardware([1, 2, 3, 4, 5, 6])),
            Some(u32::from(Ipv4Addr::new(192, 168, 1, 3)))
        );
    }

    #[test]
    /** @brief 만료 뒤 점유 인덱스의 공격 고수위 capacity까지 반환하는지. */
    fn address_index_releases_high_water_capacity_after_expiry() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let now = crate::unix_now();
        for index in 0..20_000 {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: u32::try_from(index).unwrap(),
                    expiry: now,
                    hostname: None,
                },
            );
        }
        pool.rebuild_address_use();
        assert!(pool.address_use.capacity() >= 20_000);

        pool.cleanup_expired(now);
        assert!(pool.leases.is_empty());
        assert_eq!(
            pool.leases.capacity(),
            0,
            "만료된 공격 임대의 기록 버킷도 함께 반환해야 합니다"
        );
        assert_eq!(pool.address_use.len(), 0);
        assert_eq!(
            pool.address_use.capacity(),
            0,
            "만료된 공격 상태의 점유 인덱스 버킷을 프로세스 수명 동안 붙들면 안 됩니다"
        );
    }

    #[test]
    /** @brief 위조 식별자 수만큼 제안 상태가 상한 없이 늘지 않는지. */
    fn runtime_offer_state_has_a_hard_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.offers.reserve(MAX_STATE_ENTRIES);
        for index in 0..MAX_STATE_ENTRIES {
            pool.offers.insert(
                identity_for(index),
                (u32::try_from(index).unwrap(), 1, u64::MAX),
            );
        }
        pool.rebuild_address_use();

        assert!(!pool.hold_offer(
            &identity_for(MAX_STATE_ENTRIES),
            2,
            u32::try_from(MAX_STATE_ENTRIES).unwrap(),
        ));
        assert_eq!(
            pool.offers.len(),
            MAX_STATE_ENTRIES,
            "공격자가 고른 식별자 수만큼 DHCPv4 제안 상태가 계속 자라면 안 됩니다"
        );
        assert!(pool.hold_offer(&identity_for(0), 3, 7));
        assert_eq!(pool.offers.len(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.offers.get(&identity_for(0)).map(|offer| offer.1),
            Some(3)
        );
    }

    #[test]
    /** @brief 세 동적 맵이 상한 하나를 공유하고 기존 상태 전이는 계속되는지. */
    fn runtime_dynamic_state_has_one_shared_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let lease_count = MAX_STATE_ENTRIES / 2;
        pool.leases.reserve(lease_count);
        for index in 0..lease_count {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: if index == 0 {
                        u32::from(Ipv4Addr::new(192, 168, 1, 100))
                    } else {
                        u32::try_from(index).unwrap()
                    },
                    expiry: u64::MAX,
                    hostname: None,
                },
            );
        }
        pool.offers.reserve(MAX_STATE_ENTRIES - lease_count);
        for index in lease_count..MAX_STATE_ENTRIES {
            pool.offers.insert(
                identity_for(index),
                (u32::try_from(index).unwrap(), 1, u64::MAX),
            );
        }
        pool.rebuild_address_use();

        let mut renewal = discover(mac_for(0));
        renewal.flags = 0;
        renewal.ciaddr = Ipv4Addr::new(192, 168, 1, 100);
        renewal.options = vec![(OPT_MSG_TYPE, vec![REQUEST])];
        let renewal_ack = handle(&renewal, &mut pool, &c).unwrap();
        assert_eq!(renewal_ack.msg_type(), Some(ACK));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);

        let extra = mac_for(MAX_STATE_ENTRIES);
        let nak = handle(&request(extra, [192, 168, 1, 101], None), &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert!(!pool.insert(&ClientIdentity::Hardware(extra), extra, 1, u64::MAX, None,));

        assert!(pool.commit(&identity_for(0), mac_for(0), 7, Some("renewed".into())));
        assert!(pool.commit(
            &identity_for(lease_count),
            mac_for(lease_count),
            8,
            Some("offered".into()),
        ));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.leases.get(&identity_for(0)).map(|lease| lease.ip),
            Some(7)
        );
    }

    #[test]
    /** @brief 관리 API도 식별자 수만큼 고정 할당을 무제한 보관하지 않는지. */
    fn runtime_reservation_state_has_a_hard_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.reservations.reserve(MAX_STATE_ENTRIES);
        for index in 0..MAX_STATE_ENTRIES {
            pool.reservations.insert(
                identity_for(index),
                (u32::from(Ipv4Addr::new(10, 0, 0, 1)), None),
            );
        }
        pool.rebuild_address_use();

        let valid_ip = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        assert!(pool
            .add_reservation(identity_for(MAX_STATE_ENTRIES), valid_ip, None)
            .is_err());
        assert_eq!(pool.reservations.len(), MAX_STATE_ENTRIES);

        assert!(pool
            .add_reservation(identity_for(0), valid_ip, Some("updated".into()))
            .is_ok());
        assert_eq!(pool.reservations.len(), MAX_STATE_ENTRIES);
    }

    #[test]
    /** @brief 꽉 찬 동적 예산에서도 임대에서 거절 주소로 안전하게 전이하는지. */
    fn decline_transition_stays_inside_shared_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.declined.reserve(MAX_STATE_ENTRIES - 1);
        for index in 0..MAX_STATE_ENTRIES - 1 {
            pool.declined
                .insert(u32::try_from(index).unwrap(), u64::MAX);
        }
        let mac = mac_for(MAX_STATE_ENTRIES);
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        pool.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry: u64::MAX,
                hostname: None,
            },
        );
        pool.rebuild_address_use();

        pool.decline(&identity, ip);
        assert_eq!(pool.declined.len(), MAX_STATE_ENTRIES);
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert!(!pool.leases.contains_key(&identity));
        assert_eq!(pool.allocate(&identity_for(MAX_STATE_ENTRIES + 1)), None);
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_new_client_allocation_scaling -- --ignored --nocapture"]
    /** @brief 새 클라이언트 주소 선택 비용이 기존 상태 크기에 비례하는지 측정한다. */
    fn bench_dhcp4_new_client_allocation_scaling() {
        const OPS: usize = 256;
        const ROUNDS: usize = 6;

        for preload in [1_000usize, 20_000] {
            for round in 0..ROUNDS {
                let mut c = cfg();
                c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
                c.range_start = Ipv4Addr::new(10, 0, 0, 10);
                c.range_end = Ipv4Addr::new(10, 255, 255, 254);
                c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
                c.router = c.server_ip;
                c.dns = vec![c.server_ip];
                let mut pool = LeasePool::new(&c);
                pool.leases.reserve(preload);
                let first = u32::from(c.range_start);
                for index in 0..preload {
                    assert!(pool.commit(
                        &identity_for(index),
                        mac_for(index),
                        first + u32::try_from(index).unwrap(),
                        None,
                    ));
                }
                let address_slots = pool.address_use.capacity();

                let started = std::time::Instant::now();
                for index in preload..preload + OPS {
                    let mac = mac_for(index);
                    let identity = ClientIdentity::Hardware(mac);
                    let ip = std::hint::black_box(pool.allocate(&identity).unwrap());
                    assert!(pool.hold_offer(&identity, u32::try_from(index).unwrap(), ip));
                }
                let ns_per_op = started.elapsed().as_nanos() / OPS as u128;
                println!(
                    "dhcp4_allocate preload={preload} round={} ns_per_op={ns_per_op} address_slots={address_slots}",
                    round + 1
                );
            }
        }
    }

    /** @brief 테스트용 탐색 요청. */
    fn discover(mac: [u8; 6]) -> DhcpMessage {
        DhcpMessage {
            op: 1,
            xid: 0x1234,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            client_identifier: None,
            options: vec![(OPT_MSG_TYPE, vec![DISCOVER])],
        }
    }

    /** @brief 테스트용 확정 요청. */
    fn request(mac: [u8; 6], ip: [u8; 4], server_id: Option<[u8; 4]>) -> DhcpMessage {
        let mut opts = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, ip.to_vec()),
        ];
        if let Some(sid) = server_id {
            opts.push((OPT_SERVER_ID, sid.to_vec()));
        }
        let mut m = discover(mac);
        m.options = opts;
        m
    }

    /** @brief 실제 wire 파서를 거쳐 option 61을 요청에 담는다. */
    fn with_client_id(mut req: DhcpMessage, client_id: &[u8]) -> DhcpMessage {
        req.options.push((OPT_CLIENT_ID, client_id.to_vec()));
        DhcpMessage::parse(&req.encode()).expect("유효한 client identifier 요청")
    }

    #[test]
    /** @brief RFC 2132 최소 길이보다 짧은 option 61을 무시하지 않고 거부하는지. */
    fn client_identifier_requires_type_and_value() {
        let mut req = discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]);
        req.options.push((OPT_CLIENT_ID, vec![1]));
        assert!(DhcpMessage::parse(&req.encode()).is_none());

        let valid = with_client_id(discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]), &[7; 255]);
        assert_eq!(valid.option(OPT_CLIENT_ID).map(<[u8]>::len), Some(255));

        let mut too_long = discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]);
        too_long.options.push((OPT_CLIENT_ID, vec![7; 128]));
        too_long.options.push((OPT_CLIENT_ID, vec![8; 128]));
        assert!(DhcpMessage::parse(&too_long.encode()).is_none());
    }

    #[test]
    /** @brief 같은 MAC이어도 서로 다른 option 61은 서로 다른 바인딩인지. */
    fn distinct_client_identifiers_on_one_mac_get_distinct_bindings() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let first_id = [0, b'f', b'i', b'r', b's', b't'];
        let second_id = [0, b's', b'e', b'c', b'o', b'n', b'd'];

        let first_discover = with_client_id(discover(mac), &first_id);
        let first_offer = handle(&first_discover, &mut pool, &c).unwrap();
        assert!(first_offer.option(OPT_CLIENT_ID).is_none());
        let first_request = with_client_id(
            request(mac, first_offer.yiaddr.octets(), Some(c.server_ip.octets())),
            &first_id,
        );
        let first_ack = handle(&first_request, &mut pool, &c).unwrap();
        assert_eq!(first_ack.msg_type(), Some(ACK));
        assert!(first_ack.option(OPT_CLIENT_ID).is_none());

        let second_offer = handle(&with_client_id(discover(mac), &second_id), &mut pool, &c)
            .expect("두 번째 식별자에도 주소를 제안해야");
        assert_ne!(second_offer.yiaddr, first_offer.yiaddr);
    }

    #[test]
    /** @brief 같은 option 61은 chaddr가 바뀌어도 같은 바인딩을 찾는지. */
    fn one_client_identifier_across_macs_keeps_one_binding() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let client_id = [0, b's', b't', b'a', b'b', b'l', b'e'];
        let first_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let second_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2];

        let first_discover = with_client_id(discover(first_mac), &client_id);
        let first_offer = handle(&first_discover, &mut pool, &c).unwrap();
        let first_request = with_client_id(
            request(
                first_mac,
                first_offer.yiaddr.octets(),
                Some(c.server_ip.octets()),
            ),
            &client_id,
        );
        assert_eq!(
            handle(&first_request, &mut pool, &c).unwrap().msg_type(),
            Some(ACK)
        );

        let moved_offer = handle(
            &with_client_id(discover(second_mac), &client_id),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(moved_offer.yiaddr, first_offer.yiaddr);
    }

    #[test]
    /** @brief 같은 MAC이라도 다른 option 61이 기존 임대를 RELEASE하지 못하는지. */
    fn release_uses_client_identifier_instead_of_mac() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let owner = [0, b'o', b'w', b'n', b'e', b'r'];
        let other = [0, b'o', b't', b'h', b'e', b'r'];
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        let owner_discover = with_client_id(discover(mac), &owner);
        let offer = handle(&owner_discover, &mut pool, &c).unwrap();
        let owner_request = with_client_id(
            request(mac, offer.yiaddr.octets(), Some(c.server_ip.octets())),
            &owner,
        );
        assert_eq!(
            handle(&owner_request, &mut pool, &c).unwrap().msg_type(),
            Some(ACK)
        );

        let mut release = discover(mac);
        release.options[0].1[0] = RELEASE;
        release
            .options
            .push((OPT_SERVER_ID, c.server_ip.octets().to_vec()));
        release.ciaddr = ip;
        let release = with_client_id(release, &other);
        assert!(handle(&release, &mut pool, &c).is_none());
        assert_eq!(
            pool.active(),
            1,
            "다른 식별자가 기존 임대를 지우면 안 됩니다"
        );

        let renew = with_client_id(request(mac, ip.octets(), None), &owner);
        assert_eq!(handle(&renew, &mut pool, &c).unwrap().msg_type(), Some(ACK));
    }

    #[test]
    /** @brief 서로 모순되는 DHCPREQUEST 상태 필드가 임대 기록을 바꾸지 않는지. */
    fn contradictory_client_state_fields_are_silently_discarded() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut cases = Vec::new();

        let mut discover_with_ciaddr = discover(mac);
        discover_with_ciaddr.ciaddr = ip;
        cases.push(discover_with_ciaddr);

        let mut request_with_both = request(mac, ip.octets(), None);
        request_with_both.ciaddr = ip;
        cases.push(request_with_both);

        let mut request_with_neither = discover(mac);
        request_with_neither.options = vec![(OPT_MSG_TYPE, vec![REQUEST])];
        cases.push(request_with_neither);

        let mut selecting_with_ciaddr = request(mac, ip.octets(), Some(c.server_ip.octets()));
        selecting_with_ciaddr.ciaddr = ip;
        cases.push(selecting_with_ciaddr);

        let mut reserved_flag = discover(mac);
        reserved_flag.flags |= 1;
        cases.push(reserved_flag);

        let mut nonzero_yiaddr = discover(mac);
        nonzero_yiaddr.yiaddr = ip;
        cases.push(nonzero_yiaddr);

        for req in cases {
            let mut pool = LeasePool::new(&c);
            assert!(handle(&req, &mut pool, &c).is_none());
            assert!(pool.leases.is_empty());
            assert!(pool.offers.is_empty());
            assert!(pool.declined.is_empty());
        }
    }

    #[test]
    /** @brief RELEASE가 이 서버의 server-id와 실제 임대 주소를 모두 증명해야만 임대를 지우는지. */
    fn release_requires_our_server_and_the_owned_client_address() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);

        let mut release = discover(mac);
        release.flags = 0;
        release.ciaddr = ip;
        release.options = vec![(OPT_MSG_TYPE, vec![RELEASE])];
        assert!(pool.commit(&identity, mac, u32::from(ip), None));
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(pool.leases.contains_key(&identity));

        release
            .options
            .push((OPT_SERVER_ID, c.server_ip.octets().to_vec()));
        release.ciaddr = Ipv4Addr::new(192, 168, 1, 101);
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(pool.leases.contains_key(&identity));

        release.ciaddr = ip;
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(!pool.leases.contains_key(&identity));
    }

    #[test]
    /** @brief DECLINE이 선택한 서버와 제안 주소를 모두 가리킬 때만 격리되는지. */
    fn decline_requires_our_server_and_the_owned_requested_address() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);
        assert!(pool.hold_offer(&identity, 7, ip));

        let mut decline = discover(mac);
        decline.flags = 0;
        decline.options = vec![
            (OPT_MSG_TYPE, vec![DECLINE]),
            (OPT_REQUESTED_IP, Ipv4Addr::from(ip).octets().to_vec()),
        ];
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(pool.offers.contains_key(&identity));
        assert!(!pool.declined.contains_key(&ip));

        decline.options.push((
            OPT_SERVER_ID,
            Ipv4Addr::new(192, 168, 1, 2).octets().to_vec(),
        ));
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(pool.offers.contains_key(&identity));

        decline.options.last_mut().unwrap().1 = c.server_ip.octets().to_vec();
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(!pool.offers.contains_key(&identity));
        assert!(pool.declined.contains_key(&ip));
    }

    #[test]
    /** @brief 고정 할당 클라이언트도 다른 주소를 요청하면 그 주소를 ACK하지 않는지. */
    fn reservation_does_not_override_a_conflicting_request_target() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let reserved = Ipv4Addr::new(192, 168, 1, 100);
        let requested = Ipv4Addr::new(192, 168, 1, 101);
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);
        pool.add_reservation(identity.clone(), u32::from(reserved), None)
            .unwrap();

        let reply = handle(&request(mac, requested.octets(), None), &mut pool, &c).unwrap();
        assert_eq!(reply.msg_type(), Some(NAK));
        assert_eq!(reply.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert!(!pool.leases.contains_key(&identity));
    }

    #[test]
    /** @brief 기존 임대가 있어도 SELECTING REQUEST는 같은 xid의 OFFER를 대신할 수 없는지. */
    fn selecting_request_cannot_substitute_an_existing_lease_for_its_offer() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut pool = LeasePool::new(&c);
        assert!(pool.commit(&ClientIdentity::Hardware(mac), mac, u32::from(ip), None,));

        let reply = handle(
            &request(mac, ip.octets(), Some(c.server_ip.octets())),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(reply.msg_type(), Some(NAK));
    }

    #[test]
    /** @brief RFC 2131의 relay, ciaddr, broadcast bit, yiaddr, NAK 목적지를 모두 고정한다. */
    fn reply_ip_destination_follows_the_rfc_matrix() {
        let c = cfg();
        let mut req = discover([0x02, 2, 3, 4, 5, 6]);
        let mut reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);

        req.giaddr = Ipv4Addr::new(192, 168, 2, 1);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((req.giaddr, 67)))
        );

        req.giaddr = Ipv4Addr::UNSPECIFIED;
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 42);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((req.ciaddr, 68)))
        );

        req.ciaddr = Ipv4Addr::UNSPECIFIED;
        req.flags = BROADCAST_FLAG;
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
        );

        req.flags = 0;
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::InitialUnicast {
                ip: reply.yiaddr,
                mac: req.chaddr,
            }
        );

        req.ciaddr = Ipv4Addr::new(192, 168, 1, 42);
        reply = build_reply(&req, NAK, Ipv4Addr::UNSPECIFIED, &c);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
        );
    }

    #[test]
    /** @brief 주소가 없는 초기 클라이언트의 clear broadcast bit를 일반 IP 유니캐스트로 낮추지 않는지. */
    fn initial_client_reply_requires_link_layer_delivery() {
        let c = cfg();
        let mac = [0x02, 0, 0, 0, 0, 1];
        let mut req = discover(mac);
        req.flags = 0;
        let reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);

        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::InitialUnicast {
                ip: reply.yiaddr,
                mac,
            }
        );
    }

    #[test]
    /** @brief L2 고정 또는 유니캐스트 전송이 실패하면 초기 클라이언트에 방송으로 답하는지. */
    fn initial_unicast_failure_falls_back_to_broadcast() {
        let attempts = std::cell::RefCell::new(Vec::new());
        let used_unicast = send_initial_with_fallback(
            || {
                attempts.borrow_mut().push("unicast");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "neighbor pin denied",
                ))
            },
            || {
                attempts.borrow_mut().push("broadcast");
                Ok(())
            },
        )
        .unwrap();

        assert!(!used_unicast);
        assert_eq!(*attempts.borrow(), ["unicast", "broadcast"]);
    }

    #[test]
    /** @brief L2 목적지로 쓸 수 없는 0·multicast MAC이면 곧장 방송 경로를 고르는지. */
    fn invalid_initial_client_mac_uses_broadcast() {
        let c = cfg();
        for mac in [[0; 6], [0x01, 0, 0, 0, 0, 1], [0xff; 6]] {
            let mut req = discover(mac);
            req.flags = 0;
            let reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);
            assert_eq!(
                reply_target(&req, &reply),
                ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
            );
        }
    }

    #[test]
    /** @brief 갱신 ACK와 relay NAK가 RFC 2131의 고정 필드 계약을 보존하는지. */
    fn reply_envelope_preserves_ack_address_and_hardens_relay_nak() {
        let c = cfg();
        let mut req = request([1, 2, 3, 4, 5, 6], [192, 168, 1, 100], None);
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 100);

        let ack = build_reply(&req, ACK, req.ciaddr, &c);
        assert_eq!(ack.ciaddr, req.ciaddr);

        req.giaddr = Ipv4Addr::new(192, 168, 2, 1);
        req.flags = 0;
        let nak = build_reply(&req, NAK, Ipv4Addr::UNSPECIFIED, &c);
        assert_eq!(nak.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(nak.siaddr, Ipv4Addr::UNSPECIFIED);
        assert_ne!(nak.flags & BROADCAST_FLAG, 0);
    }

    #[test]
    /** @brief 같은 망의 다른 서버가 준 주소에는 답하지 않고, 망 밖의 주소와 기록이 있는 클라이언트에는 거절을 알리는지. */
    fn unknown_client_on_same_subnet_outside_pool_gets_no_reply() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let stranger = [3, 3, 3, 3, 3, 3];
        assert!(
            handle(&request(stranger, [192, 168, 1, 50], None), &mut pool, &c).is_none(),
            "같은 망의 다른 서버가 준 주소에 NAK를 보내면 그 기기가 주소를 버립니다"
        );
        let wrong_network = handle(&request(stranger, [172, 30, 1, 6], None), &mut pool, &c)
            .expect("망 밖의 주소는 잘못된 망이라고 알려야 합니다");
        assert_eq!(wrong_network.msg_type(), Some(NAK));

        let known = [4, 4, 4, 4, 4, 4];
        let ack = handle(&request(known, [192, 168, 1, 100], None), &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        let moved = handle(&request(known, [192, 168, 1, 50], None), &mut pool, &c)
            .expect("기록이 있는 클라이언트에게는 거절을 알려야 합니다");
        assert_eq!(moved.msg_type(), Some(NAK));
    }

    #[test]
    /** @brief 중계되지 않은 요청은 서버 인터페이스로 들어온 것만 받는지. */
    fn requests_from_other_links_are_dropped() {
        let direct = Ipv4Addr::UNSPECIFIED;
        let relay = Ipv4Addr::new(10, 0, 0, 1);
        assert!(from_served_link(direct, Some(3), Some(3)));
        assert!(!from_served_link(direct, Some(2), Some(3)));
        assert!(from_served_link(relay, Some(2), Some(3)));
        assert!(from_served_link(direct, None, Some(3)));
        assert!(from_served_link(direct, Some(2), None));
    }

    #[test]
    /** @brief 남이 잡은 주소를 달라면 거절하는지. 주면 같은 주소를 둘이 쓴다. */
    fn request_for_ip_leased_to_other_mac_is_nak() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let a = [1, 1, 1, 1, 1, 1];
        let b = [2, 2, 2, 2, 2, 2];
        let ip = [192, 168, 1, 100];
        let ack_a = handle(&request(a, ip, None), &mut pool, &c).unwrap();
        assert_eq!(ack_a.msg_type(), Some(ACK));
        let reply_b = handle(&request(b, ip, None), &mut pool, &c).unwrap();
        assert_eq!(reply_b.msg_type(), Some(NAK));
    }

    #[test]
    /** @brief 남의 제안 주소와 거절된 주소를 제안 없는 REQUEST가 가로채지 못하는지. */
    fn request_rejects_other_offer_and_declined_address() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let offer_owner = [1, 1, 1, 1, 1, 1];
        let decline_owner = [3, 3, 3, 3, 3, 3];
        let intruder = [2, 2, 2, 2, 2, 2];
        let offered = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let declined = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        let offer_identity = ClientIdentity::Hardware(offer_owner);
        let decline_identity = ClientIdentity::Hardware(decline_owner);
        assert!(pool.hold_offer(&offer_identity, 1, offered));
        assert!(pool.hold_offer(&decline_identity, 2, declined));
        pool.decline(&decline_identity, declined);

        let offered_reply = handle(
            &request(intruder, Ipv4Addr::from(offered).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(offered_reply.msg_type(), Some(NAK));

        let declined_reply = handle(
            &request(intruder, Ipv4Addr::from(declined).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(declined_reply.msg_type(), Some(NAK));

        let reserved_client = [4, 4, 4, 4, 4, 4];
        let conflict_owner = [5, 5, 5, 5, 5, 5];
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 102));
        pool.add_reservation(ClientIdentity::Hardware(reserved_client), reserved, None)
            .unwrap();
        let conflict_identity = ClientIdentity::Hardware(conflict_owner);
        assert!(pool.hold_offer(&conflict_identity, 3, reserved));
        pool.decline(&conflict_identity, reserved);
        let reserved_reply = handle(
            &request(reserved_client, Ipv4Addr::from(reserved).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(reserved_reply.msg_type(), Some(NAK));
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_init_reboot_request_scaling -- --ignored --nocapture"]
    /** @brief 제안 없는 REQUEST 주소 판정 비용이 전체 임대·고정 할당 수에 비례하는지 측정한다. */
    fn bench_dhcp4_init_reboot_request_scaling() {
        const OPS: usize = 256;
        const ROUNDS: usize = 6;

        for preload in [1_000usize, 20_000] {
            for round in 0..ROUNDS {
                let mut c = cfg();
                c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
                c.range_start = Ipv4Addr::new(10, 0, 0, 10);
                c.range_end = Ipv4Addr::new(10, 127, 255, 254);
                c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
                c.router = c.server_ip;
                c.dns = vec![c.server_ip];
                let mut pool = LeasePool::new(&c);
                let first = u32::from(c.range_start);
                let reserved_first = u32::from(Ipv4Addr::new(10, 200, 0, 1));
                let expiry = crate::unix_now() + 3_600;
                for index in 0..preload {
                    let lease_mac = mac_for(index);
                    pool.leases.insert(
                        ClientIdentity::Hardware(lease_mac),
                        Lease {
                            mac: lease_mac,
                            ip: first + u32::try_from(index).unwrap(),
                            expiry,
                            hostname: None,
                        },
                    );
                    pool.reservations.insert(
                        identity_for(preload + index),
                        (reserved_first + u32::try_from(index).unwrap(), None),
                    );
                }
                pool.rebuild_address_use();
                let target_first = first + u32::try_from(preload).unwrap();

                let started = std::time::Instant::now();
                for index in 0..OPS {
                    let ip = Ipv4Addr::from(target_first + u32::try_from(index).unwrap());
                    let reply = std::hint::black_box(handle(
                        &request(mac_for(preload * 2 + index), ip.octets(), None),
                        &mut pool,
                        &c,
                    ))
                    .unwrap();
                    assert_eq!(reply.msg_type(), Some(ACK));
                }
                let ns_per_op = started.elapsed().as_nanos() / OPS as u128;
                println!(
                    "dhcp4_request preload={preload} round={} ns_per_op={ns_per_op}",
                    round + 1
                );
            }
        }
    }

    #[test]
    /** @brief 다른 서버에 보낸 요청에 끼어들지 않는지. */
    fn request_with_foreign_server_id_is_ignored() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [3, 3, 3, 3, 3, 3];

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        let offered = offer.yiaddr.octets();

        let foreign = handle(&request(mac, offered, Some([10, 0, 0, 9])), &mut pool, &c);
        assert!(foreign.is_none());

        let mine = handle(
            &request(mac, offered, Some([192, 168, 1, 1])),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(mine.msg_type(), Some(ACK));
    }

    #[test]
    /** @brief 서브넷 밖과 특수 주소를 고정 할당하지 못하는지. */
    fn static_reservation_rejects_out_of_subnet_and_special() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [9, 9, 9, 9, 9, 9];
        let identity = ClientIdentity::Hardware(mac);
        for bad in [
            [10, 0, 0, 5],
            [192, 168, 1, 0],
            [192, 168, 1, 255],
            [192, 168, 1, 1],
        ] {
            assert!(
                pool.add_reservation(identity.clone(), u32::from(Ipv4Addr::from(bad)), None)
                    .is_err(),
                "{bad:?} 예약은 거부되어야 함"
            );
        }

        assert!(pool
            .add_reservation(identity, u32::from(Ipv4Addr::new(192, 168, 1, 50)), None,)
            .is_ok());
    }

    #[test]
    /** @brief 인코딩하고 되읽으면 같은지. */
    fn wire_roundtrip() {
        let m = discover([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let back = DhcpMessage::parse(&m.encode()).unwrap();
        assert_eq!(back.xid, 0x1234);
        assert_eq!(back.chaddr, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(back.msg_type(), Some(DISCOVER));
    }

    #[test]
    /** @brief 1,500바이트 뒤 옵션과 END가 잘린 prefix만으로 상태를 바꾸지 않는지. */
    fn receive_capacity_covers_tail_option_validation() {
        assert_eq!(MAX_STANDARD_IPV4_UDP_PAYLOAD, 65_507);
        assert_eq!(DHCP4_RECV_CAPACITY, 65_508);
        assert_eq!(standard_dhcp4_datagram_len(65_507), Some(65_507));
        assert_eq!(standard_dhcp4_datagram_len(65_508), None);

        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        wire.extend_from_slice(&[200, 1, 0]);
        while wire.len() < 1_500 {
            wire.extend_from_slice(&[200, 0]);
        }
        assert_eq!(wire.len(), 1_500);

        wire.extend_from_slice(&[OPT_MSG_TYPE, 1, REQUEST, OPT_END]);
        assert!(DhcpMessage::parse(&wire[..1_500]).is_none());
        assert!(DhcpMessage::parse(&wire).is_none());
    }

    #[test]
    /** @brief 64KiB unknown 옵션이 파서의 소유 엔트리 수를 증폭하지 않는지. */
    fn unknown_option_flood_is_ignored_without_storage_amplification() {
        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        while wire.len() + 3 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.extend_from_slice(&[200, 1, 0]);
        }
        while wire.len() + 1 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.push(0);
        }
        wire.push(OPT_END);
        assert_eq!(wire.len(), MAX_STANDARD_IPV4_UDP_PAYLOAD);

        let parsed = DhcpMessage::parse(&wire).unwrap();
        assert_eq!(parsed.options.len(), 1);
        assert_eq!(parsed.msg_type(), Some(DISCOVER));

        wire.push(0);
        assert!(DhcpMessage::parse(&wire).is_none());
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_unknown_option_flood_parse -- --ignored --nocapture"]
    /** @brief 64KiB unknown 옵션을 소유하지 않고 전체 검증하는 비용을 측정한다. */
    fn bench_dhcp4_unknown_option_flood_parse() {
        const OPS: usize = 64;
        const ROUNDS: usize = 12;
        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        while wire.len() + 3 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.extend_from_slice(&[200, 1, 0]);
        }
        while wire.len() + 1 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.push(0);
        }
        wire.push(OPT_END);

        for round in 0..ROUNDS {
            let started = std::time::Instant::now();
            for _ in 0..OPS {
                let parsed = DhcpMessage::parse(std::hint::black_box(&wire)).unwrap();
                assert_eq!(parsed.options.len(), 1);
                std::hint::black_box(parsed);
            }
            let ns_per_parse = started.elapsed().as_nanos() / OPS as u128;
            println!(
                "dhcp4_unknown_flood round={} ns_per_parse={ns_per_parse}",
                round + 1
            );
        }
    }

    #[test]
    /** @brief RFC 3396 조각을 options, file, sname 순서로 한 값으로 읽는지. */
    fn split_options_are_concatenated_in_aggregate_buffer_order() {
        const OPT_OVERLOAD_CODE: u8 = 52;

        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        wire.extend_from_slice(&[OPT_HOSTNAME, 5]);
        wire.extend_from_slice(b"alpha");
        wire.extend_from_slice(&[OPT_OVERLOAD_CODE, 1, 3, OPT_END]);

        wire[108..113].copy_from_slice(&[OPT_HOSTNAME, 1, b'-', OPT_END, 0]);
        wire[44..51].copy_from_slice(&[OPT_HOSTNAME, 4, b'h', b'o', b's', b't', OPT_END]);

        let parsed = DhcpMessage::parse(&wire).unwrap();
        assert_eq!(parsed.hostname().as_deref(), Some("alpha-host"));
        assert_eq!(parsed.options.len(), 2);

        let mut split_controls = discover([1, 2, 3, 4, 5, 6]);
        split_controls.options = vec![
            (OPT_MSG_TYPE, Vec::new()),
            (OPT_MSG_TYPE, vec![DISCOVER]),
            (OPT_REQUESTED_IP, vec![192, 168]),
            (OPT_REQUESTED_IP, vec![1, 100]),
        ];
        let parsed = DhcpMessage::parse(&split_controls.encode()).unwrap();
        assert_eq!(parsed.msg_type(), Some(DISCOVER));
        assert_eq!(
            parsed.option(OPT_REQUESTED_IP).and_then(opt_ipv4),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(parsed.options.len(), 2);
    }

    #[test]
    /** @brief 고정 길이 옵션과 hostname의 최종 연결 길이를 엄격히 검사하는지. */
    fn consumed_option_lengths_are_validated_after_concatenation() {
        for options in [
            vec![(OPT_MSG_TYPE, vec![DISCOVER, REQUEST])],
            vec![
                (OPT_MSG_TYPE, vec![REQUEST]),
                (OPT_REQUESTED_IP, vec![192, 168, 1, 100, 0]),
            ],
            vec![
                (OPT_MSG_TYPE, vec![REQUEST]),
                (OPT_SERVER_ID, vec![192, 168, 1, 1, 0]),
            ],
            vec![(OPT_MSG_TYPE, vec![DISCOVER]), (OPT_HOSTNAME, Vec::new())],
        ] {
            let mut message = discover([1, 2, 3, 4, 5, 6]);
            message.options = options;
            assert!(DhcpMessage::parse(&message.encode()).is_none());
        }

        let mut split_type = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(split_type.pop(), Some(OPT_END));
        split_type.extend_from_slice(&[OPT_MSG_TYPE, 1, REQUEST, OPT_END]);
        assert!(DhcpMessage::parse(&split_type).is_none());
    }

    #[test]
    /** @brief END와 서버가 실제 지원하는 Ethernet 주소 형식이 필수인지. */
    fn request_header_and_end_marker_are_required() {
        let mut no_end = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(no_end.pop(), Some(OPT_END));
        assert!(DhcpMessage::parse(&no_end).is_none());

        let mut wrong_htype = discover([1, 2, 3, 4, 5, 6]).encode();
        wrong_htype[1] = 2;
        assert!(DhcpMessage::parse(&wrong_htype).is_none());

        let mut wrong_hlen = discover([1, 2, 3, 4, 5, 6]).encode();
        wrong_hlen[2] = 5;
        assert!(DhcpMessage::parse(&wrong_hlen).is_none());

        let mut reply = discover([1, 2, 3, 4, 5, 6]);
        reply.op = 2;
        let reply = reply.encode();
        assert!(DhcpMessage::parse(&reply).is_some());
        assert!(parse_client_request(&reply).is_none());

        let mut data_after_end = discover([1, 2, 3, 4, 5, 6]).encode();
        data_after_end.extend_from_slice(&[200, 0]);
        assert!(DhcpMessage::parse(&data_after_end).is_none());

        let mut missing_overload_end = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(missing_overload_end.pop(), Some(OPT_END));
        missing_overload_end.extend_from_slice(&[OPT_OVERLOAD, 1, 1, OPT_END]);
        missing_overload_end[108..111].copy_from_slice(&[OPT_HOSTNAME, 1, b'a']);
        assert!(DhcpMessage::parse(&missing_overload_end).is_none());
    }

    #[test]
    /** @brief 어긋난 옵션이 전체를 거부되는지. 앞부분만 받아들이면 잘린 요청이 통과한다. */
    fn malformed_option_is_rejected_instead_of_partially_applied() {
        let mut truncated = discover([1, 2, 3, 4, 5, 6]).encode();
        truncated.truncate(truncated.len() - 2);
        assert!(DhcpMessage::parse(&truncated).is_none());

        let mut missing_length = discover([1, 2, 3, 4, 5, 6]).encode();
        let last = missing_length.len() - 1;
        missing_length[last] = OPT_MSG_TYPE;
        assert!(DhcpMessage::parse(&missing_length).is_none());
    }

    #[test]
    /** @brief 탐색에는 제안으로, 확정 요청에는 확정으로 답하는지. */
    fn discover_offers_request_acks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [1, 2, 3, 4, 5, 6];

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(offer.option(OPT_ROUTER), Some([192, 168, 1, 1].as_slice()));

        let mut req = discover(mac);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, offer.yiaddr.octets().to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(pool.active(), 1);
    }

    #[test]
    /** @brief 제안과 어긋난 요청이 잡아 둔 주소를 풀지 못하는지. */
    fn mismatched_request_does_not_consume_offer() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [4, 3, 2, 1, 0, 9];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.hold_offer(&identity, 0x1234, ip));

        assert!(!pool.consume_offer(&identity, 0x9999, ip));
        assert!(pool.consume_offer(&identity, 0x1234, ip));
        assert!(!pool.consume_offer(&identity, 0x1234, ip));
    }

    #[test]
    /** @brief 서로 다른 주소를 주고, 다 쓰면 못 준다고 하는지. */
    fn pool_distinct_ips_and_exhaustion() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let first_mac = [0, 0, 0, 0, 0, 1];
        let second_mac = [0, 0, 0, 0, 0, 2];
        let third_mac = [0, 0, 0, 0, 0, 3];
        let first = ClientIdentity::Hardware(first_mac);
        let second = ClientIdentity::Hardware(second_mac);
        let third = ClientIdentity::Hardware(third_mac);
        let a = pool.allocate(&first).unwrap();
        assert!(pool.commit(&first, first_mac, a, None));
        let b = pool.allocate(&second).unwrap();
        assert!(pool.commit(&second, second_mac, b, None));
        let cc = pool.allocate(&third).unwrap();
        assert!(pool.commit(&third, third_mac, cc, None));
        assert_ne!(a, b);
        assert_ne!(b, cc);

        assert!(pool
            .allocate(&ClientIdentity::Hardware([0, 0, 0, 0, 0, 4]))
            .is_none());

        assert_eq!(pool.allocate(&first), Some(a));
    }

    #[test]
    /** @brief 범위 밖 주소 요청을 거절하는지. */
    fn out_of_range_request_naks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mut req = discover([9, 9, 9, 9, 9, 9]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (
                OPT_REQUESTED_IP,
                Ipv4Addr::new(10, 0, 0, 5).octets().to_vec(),
            ),
        ];
        let nak = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
    }

    #[test]
    /** @brief 클라이언트 이름이 읽히는지. */
    fn hostname_option_parsed() {
        let mut req = discover([1, 2, 3, 4, 5, 6]);
        req.options.push((OPT_HOSTNAME, b"my-laptop".to_vec()));
        assert_eq!(req.hostname().as_deref(), Some("my-laptop"));

        let mut req2 = discover([1, 2, 3, 4, 5, 6]);
        req2.options.push((OPT_HOSTNAME, vec![0u8]));
        assert!(req2.hostname().is_none());

        let mut invalid = discover([1, 2, 3, 4, 5, 6]);
        invalid.options.push((OPT_HOSTNAME, vec![0xff]));
        assert!(
            invalid.hostname().is_none(),
            "invalid UTF-8 is not repaired"
        );
    }

    #[test]
    /** @brief 저장했다 읽으면 같은 기록이 되는지. */
    fn persistence_roundtrip_and_snapshot() {
        let path =
            std::env::temp_dir().join(format!("onetdns-lease-persist-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.lease_file = Some(path.clone());
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let identity = ClientIdentity::Hardware(mac);
        {
            let mut pool = LeasePool::new(&c);
            let ip = pool.allocate(&identity).unwrap();
            assert!(pool.commit(&identity, mac, ip, Some("host1".to_string())));
            let snap = pool.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].identity, identity);
            assert_eq!(snap[0].mac, mac);
            assert_eq!(snap[0].ip, Ipv4Addr::new(192, 168, 1, 100));
            assert_eq!(snap[0].hostname.as_deref(), Some("host1"));
        }

        let pool2 = LeasePool::new(&c);
        let snap = pool2.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(snap[0].hostname.as_deref(), Some("host1"));

        std::fs::write(
            &path,
            format!(
                "aabbccddeeff 192.168.1.100 {} host1\n",
                crate::unix_now() + 60
            ),
        )
        .unwrap();
        assert!(LeasePool::new(&c).snapshot().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    /** @brief 하드웨어 주소 변환 왕복. */
    fn mac_hex_roundtrip() {
        let mac = [0x00, 0x1a, 0x2b, 0xff, 0xcc, 0x01];
        assert_eq!(mac_hex(&mac), "001a2bffcc01");
        assert_eq!(mac_from_hex("001a2bffcc01"), Some(mac));
        assert!(mac_from_hex("zz").is_none());
    }

    #[test]
    /** @brief 관리·저장 식별자 표기가 손실 없이 왕복하고 MAC과 opaque ID가 섞이지 않는지. */
    fn client_identity_text_roundtrip_and_namespaces_are_distinct() {
        let hardware = ClientIdentity::from_text("mac:001a2bffcc01").unwrap();
        let opaque = ClientIdentity::from_text("id:001a2bffcc01").unwrap();
        assert_eq!(hardware.to_text(), "mac:001a2bffcc01");
        assert_eq!(opaque.to_text(), "id:001a2bffcc01");
        assert_ne!(hardware, opaque);
        assert!(ClientIdentity::from_text("id:01").is_none());
        assert!(ClientIdentity::from_text("id:xyz0").is_none());
        assert!(ClientIdentity::from_text("mac:00:1a:2b:ff:cc:01").is_none());
    }

    #[test]
    /** @brief opaque option 61 소유권과 마지막 chaddr가 임대 파일에서 함께 복원되는지. */
    fn opaque_client_identity_persistence_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-client-id-persist-{}-{}.txt",
            std::process::id(),
            crate::unix_now()
        ));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.lease_file = Some(path.clone());
        let identity = ClientIdentity::from_text("id:0102030405").unwrap();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ip = u32::from(c.range_start);
        {
            let mut pool = LeasePool::new(&c);
            assert!(pool.insert(
                &identity,
                mac,
                ip,
                crate::unix_now() + 3_600,
                Some("opaque".into()),
            ));
            pool.save();
        }

        let snapshot = LeasePool::new(&c).snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].identity, identity);
        assert_eq!(snapshot[0].mac, mac);
        assert_eq!(snapshot[0].hostname.as_deref(), Some("opaque"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    /** @brief 더 오래된 임대가 새 것을 덮지 않는지. */
    fn insert_takes_newer_only() {
        let mut pool = LeasePool::new(&cfg());
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let now = crate::unix_now();

        assert!(pool.insert(&identity, mac, ip, now + 1000, Some("peer".into())));
        let s = pool.snapshot();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ip, Ipv4Addr::new(192, 168, 1, 100));

        assert!(
            !pool.insert(&identity, mac, ip, now + 10, None),
            "같은 주소의 더 이른 만료는 무시한다"
        );
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("peer"));

        assert!(pool.insert(&identity, mac, ip, now + 5000, Some("newer".into())));
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("newer"));

        let moved = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        assert!(pool.insert(&identity, mac, moved, now + 20, None));
        assert_eq!(pool.snapshot()[0].ip, Ipv4Addr::new(192, 168, 1, 101));
    }

    #[test]
    /** @brief HA 임대가 동적 범위와 기존 주소 소유권을 우회하지 못하는지. */
    fn synced_lease_rejects_out_of_range_and_duplicate_ip() {
        let mut pool = LeasePool::new(&cfg());
        let now = crate::unix_now();
        let first = [0xaa, 0, 0, 0, 0, 1];
        let second = [0xbb, 0, 0, 0, 0, 2];
        let first_identity = ClientIdentity::Hardware(first);
        let second_identity = ClientIdentity::Hardware(second);
        let in_range = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let out_of_range = u32::from(Ipv4Addr::new(192, 168, 1, 99));

        assert!(!pool.insert(&first_identity, first, out_of_range, now + 3_600, None));
        assert!(pool.insert(&first_identity, first, in_range, now + 3_600, None));
        assert!(!pool.insert(&second_identity, second, in_range, now + 3_600, None));
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        pool.add_reservation(first_identity.clone(), reserved, None)
            .unwrap();
        assert!(!pool.insert(&second_identity, second, reserved, now + 3_600, None));
        assert_eq!(pool.snapshot().len(), 1);
        assert_eq!(
            pool.leases.get(&first_identity).map(|lease| lease.ip),
            Some(in_range)
        );
    }

    #[test]
    /** @brief HA 배치가 상태 상한에서 앞 항목만 적용할 수 없도록 미리 거부하는지. */
    fn synced_batch_preflights_the_whole_state_budget() {
        let mut c = cfg();
        c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
        c.range_start = Ipv4Addr::new(10, 0, 0, 10);
        c.range_end = Ipv4Addr::new(10, 255, 255, 254);
        c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
        c.router = c.server_ip;
        let mut pool = LeasePool::new(&c);
        let now = crate::unix_now();
        let first = u32::from(c.range_start);
        for index in 0..MAX_STATE_ENTRIES {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: first + u32::try_from(index).unwrap(),
                    expiry: now + 3_600,
                    hostname: None,
                },
            );
        }
        pool.rebuild_address_use();

        assert!(pool
            .validate_synced_batch([
                (identity_for(0), first, now + 7_200),
                (
                    identity_for(MAX_STATE_ENTRIES),
                    first + u32::try_from(MAX_STATE_ENTRIES).unwrap(),
                    now + 7_200,
                ),
            ])
            .is_err());
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.leases.get(&identity_for(0)).unwrap().expiry,
            now + 3_600
        );
    }

    #[test]
    /** @brief 동적 범위 밖의 정상 고정 할당 임대는 재검사 뒤에도 유지되는지. */
    fn reserved_lease_outside_dynamic_range_survives_revalidation() {
        let mut pool = LeasePool::new(&cfg());
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let identity = ClientIdentity::Hardware(mac);
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        pool.add_reservation(identity.clone(), reserved, None)
            .unwrap();
        assert!(pool.insert(&identity, mac, reserved, crate::unix_now() + 3_600, None,));

        pool.revalidate_loaded_state();

        assert_eq!(pool.snapshot().len(), 1);
        assert_eq!(
            pool.leases.get(&identity).map(|lease| lease.ip),
            Some(reserved)
        );
    }

    #[test]
    /** @brief 손상된 저장 파일에서 같은 IP를 두 식별자에 복원하지 않는지. */
    fn persisted_duplicate_ip_rejects_the_whole_lease_file() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-duplicate-lease-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let expiry = crate::unix_now() + 3_600;
        std::fs::write(
            &path,
            format!(
                "{LEASE_HEADER}mac:aabbccddee01 aabbccddee01 192.168.1.100 {expiry}\n\
                 mac:aabbccddee02 aabbccddee02 192.168.1.100 {expiry}\n"
            ),
        )
        .unwrap();

        assert!(load_leases(&path).is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    /** @brief 고정 할당이 제안과 확정 모두에서 지켜지는지. */
    fn reservation_honored_in_offer_and_request() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0, 0, 0, 0, 0x10];
        let identity = ClientIdentity::Hardware(mac);

        let pinned = u32::from(Ipv4Addr::new(192, 168, 1, 200));
        pool.add_reservation(identity, pinned, Some("printer".into()))
            .unwrap();

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 200));

        let mut req = discover(mac);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, offer.yiaddr.octets().to_vec()),
            (OPT_SERVER_ID, c.server_ip.octets().to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 1, 200));
    }

    #[test]
    /** @brief 고정된 주소를 다른 클라이언트에 주지 않는지. */
    fn dynamic_client_skips_reserved_ip() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        pool.add_reservation(
            ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]),
            reserved,
            None,
        )
        .unwrap();

        let got = pool
            .allocate(&ClientIdentity::Hardware([0xbb, 0, 0, 0, 0, 2]))
            .unwrap();
        assert_ne!(got, reserved);
        assert!(got >= u32::from(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    /** @brief 남에게 고정된 주소를 달라면 거절하는지. */
    fn other_client_requesting_reserved_ip_naks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.add_reservation(
            ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]),
            u32::from(Ipv4Addr::new(192, 168, 1, 101)),
            None,
        )
        .unwrap();
        let mut req = discover([0xbb, 0, 0, 0, 0, 2]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, [192, 168, 1, 101].to_vec()),
        ];
        let nak = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
    }

    #[test]
    /** @brief 고정 할당을 넣을 때 겹치는 임대를 걷는지. */
    fn add_reservation_reclaims_conflicting_dynamic_lease() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let dynamic_mac = [0xbb, 0, 0, 0, 0, 2];
        assert!(pool.commit(
            &ClientIdentity::Hardware(dynamic_mac),
            dynamic_mac,
            ip,
            None,
        ));
        assert_eq!(pool.active(), 1);

        pool.add_reservation(ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]), ip, None)
            .unwrap();
        assert_eq!(pool.active(), 0);

        assert!(pool
            .add_reservation(ClientIdentity::Hardware([0xcc, 0, 0, 0, 0, 3]), ip, None)
            .is_err());
    }

    #[test]
    /** @brief 고정 할당이 저장됐다 읽히는지. */
    fn reservation_persistence_roundtrip() {
        let path = std::env::temp_dir().join(format!("onetdns-static-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.static_file = Some(path.clone());
        let identity = ClientIdentity::from_text("id:deadbeef0001").unwrap();
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 250));
        {
            let mut pool = LeasePool::new(&c);
            pool.add_reservation(identity.clone(), ip, Some("nas".into()))
                .unwrap();
            assert_eq!(pool.reservations().len(), 1);
        }
        let pool2 = LeasePool::new(&c);
        let r = pool2.reservations();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].identity, identity);
        assert_eq!(r[0].ip, Ipv4Addr::new(192, 168, 1, 250));
        assert_eq!(r[0].hostname.as_deref(), Some("nas"));

        {
            let mut pool = LeasePool::new(&c);
            assert!(pool.remove_reservation(&identity));
            assert!(!pool.remove_reservation(&identity));
        }
        assert!(LeasePool::new(&c).reservations().is_empty());

        let operator_text = "deadbeef0001 192.168.1.250 nas\n";
        std::fs::write(&path, operator_text).unwrap();
        assert!(read_reservations(&path).is_err());
        assert!(LeasePool::new(&c).reservations().is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), operator_text);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    /**
     * @brief 서비스를 재시작해도 이미 나간 주소를 다른 기기에 주지 않는지.
     * @details 임대 파일이 없는 설정에서 기록을 새로 만들면 첫 기기가 쓰는 주소가 다음 기기에
     *          또 나간다.
     */
    fn reconfigure_keeps_issued_leases_without_a_lease_file() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let first = [0xaa, 0, 0, 0, 0, 1];
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.commit(&ClientIdentity::Hardware(first), first, ip, None));

        let mut changed = c.clone();
        changed.dns = vec![Ipv4Addr::new(192, 168, 1, 9)];
        changed.lease_secs = 600;
        pool.reconfigure(&changed).unwrap();

        let second = ClientIdentity::Hardware([0xbb, 0, 0, 0, 0, 2]);
        assert_ne!(pool.allocate(&second), Some(ip));
        assert_eq!(pool.active(), 1);
    }

    #[test]
    /** @brief 고정 할당 파일을 바꾸면 그 파일의 할당을 읽고, 틀린 파일이면 기록을 두는지. */
    fn reconfigure_reads_the_new_reservation_file() {
        let path =
            std::env::temp_dir().join(format!("onetdns-static-switch-{}.txt", std::process::id()));
        let identity = ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 7]);
        std::fs::write(
            &path,
            format!(
                "{RESERVATION_HEADER}{} 192.168.1.50 printer\n",
                identity.to_text()
            ),
        )
        .unwrap();
        let mut pool = LeasePool::new(&cfg());
        let mut changed = cfg();
        changed.static_file = Some(path.clone());
        pool.reconfigure(&changed).unwrap();
        assert_eq!(
            pool.reservation_ip(&identity),
            Some(u32::from(Ipv4Addr::new(192, 168, 1, 50)))
        );

        let broken =
            std::env::temp_dir().join(format!("onetdns-static-broken-{}.txt", std::process::id()));
        std::fs::write(&broken, format!("{RESERVATION_HEADER}not-an-entry\n")).unwrap();
        let mut bad = cfg();
        bad.static_file = Some(broken.clone());
        assert!(pool.reconfigure(&bad).is_err());
        assert!(pool.reservation_ip(&identity).is_some());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&broken);
    }

    #[test]
    /** @brief 갱신 요청에 이름이 빠져도 이름을 잃지 않고, 고정 할당의 이름이 앞서는지. */
    fn commit_keeps_hostname_and_prefers_the_reserved_one() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.commit(&identity, mac, ip, Some("alpha".into())));
        assert!(pool.commit(&identity, mac, ip, None));
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("alpha"));

        let reserved_mac = [0xcc, 0, 0, 0, 0, 3];
        let reserved = ClientIdentity::Hardware(reserved_mac);
        let reserved_ip = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        pool.add_reservation(reserved.clone(), reserved_ip, Some("printer".into()))
            .unwrap();
        assert!(pool.commit(&reserved, reserved_mac, reserved_ip, Some("npi1234".into())));
        let names: Vec<_> = pool
            .snapshot()
            .into_iter()
            .filter(|lease| lease.identity == reserved)
            .map(|lease| lease.hostname)
            .collect();
        assert_eq!(names, vec![Some("printer".to_string())]);
    }

    #[test]
    /** @brief 로컬 도메인과 네트워크 부팅 서버가 옵션 15와 66으로 담기는지. */
    fn ack_carries_domain_and_tftp_server_name() {
        let mut c = cfg();
        c.domain_name = Some("lan".into());
        c.tftp_server = Some(Ipv4Addr::new(192, 168, 1, 5));
        let mut pool = LeasePool::new(&c);
        let offer = handle(&discover([1, 2, 3, 4, 5, 6]), &mut pool, &c).unwrap();
        assert_eq!(offer.option(OPT_DOMAIN_NAME), Some(b"lan".as_slice()));
        assert_eq!(
            offer.option(OPT_TFTP_SERVER_NAME),
            Some(b"192.168.1.5".as_slice())
        );
    }

    #[test]
    /** @brief 어떤 바이트열이 와도 파서가 패닉하지 않는지. */
    fn parse_never_panics_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let seed = discover([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).encode();
        let mut rng = Rng::new(0xD11C_0DE5_1234_5678);
        for i in 0..20_000u32 {
            let bytes = if i % 3 == 0 {
                rng.rand_bytes(300)
            } else {
                havoc(&mut rng, &seed)
            };
            let _ = DhcpMessage::parse(&bytes);
        }
    }
}
