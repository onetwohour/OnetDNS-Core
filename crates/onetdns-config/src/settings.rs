/*!
 * @brief 설정 구조와 검증.
 *
 * @details 키 하나를 더하려면 다섯 곳을 함께 고쳐야 한다. 알려진 키 목록, 구조체 필드와
 *          기본값과 디코딩, 스키마의 두 테이블, 검증, 그리고 도구의 개수 확인이다. 테스트가
 *          그 일치를 강제한다.
 * @warning 검증은 실패 시 막는 쪽이다. 위험한 조합은 시작을 거부하고, 운영자가 명시적으로
 *          감수하겠다고 밝힌 경우에만 열어 준다.
 * @note 모르는 키는 무시하지 않고 거부한다. 오타 하나가 의도한 설정을 조용히 없애는
 *       것을 막는다. 없앤 키도 같은 이유로 거부된다.
 */

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use onetdns_core::{HttpsOrigin, IpNet, SecretString};

use crate::mode::Mode;

/** @brief 읽어 들일 설정 파일 크기 상한. */
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/** @brief 리졸버 하나에 붙일 업스트림 수 상한. 많으면 질의당 작업이 그만큼 는다. */
const MAX_UPSTREAMS_PER_RESOLVER: usize = 256;
/** @brief 동적 레코드 하나의 값 수 상한. */
const MAX_DYNAMIC_RECORD_VALUES: usize = 64;
/** @brief 검증기가 받아들일 수 있는 NSEC3 반복 횟수 보안 하드 상한. */
const MAX_VALIDATOR_NSEC3_ITERATIONS: u16 = 150;
/**
 * @brief 업스트림을 적지 않았을 때 쓰는 DNS-over-HTTP/3 서버.
 * @details 평문 UDP 53번은 ISP 나 공유기가 가로채 자기 리졸버로 대신 답하는 망이 있어, 적은
 *          업스트림이 아닌 서버의 답을 받게 된다. 443번 포트의 암호화 전송은 가로챌 수 없고 인증서로
 *          상대를 확인한다. 주소를 IP 로 적고 인증서 이름을
 *          함께 주므로 업스트림 이름을 풀기 위한 bootstrap 이 필요 없다.
 */
const DEFAULT_UPSTREAM_URLS: [&str; 2] = [
    "h3://1.1.1.1/dns-query#cloudflare-dns.com",
    "h3://1.0.0.1/dns-query#cloudflare-dns.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 해석 방식. 전달, 재귀, 또는 이름별로 나누는 분할이다. */
pub enum BackendKind {
    #[default]
    /** @brief 업스트림 서버로 전달한다. */
    Forward,

    /** @brief 루트부터 직접 따라간다. */
    Recurse,

    /** @brief 이름에 따라 전달과 재귀를 나눈다. */
    Split,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 분할에서 이 이름을 어디로 보낼지. */
pub enum SplitTarget {
    #[default]
    /** @brief 전달로 보낸다. */
    Forward,
    /** @brief 재귀로 보낸다. */
    Recurse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief WASM 정책 플러그인 하나의 설정. */
pub struct WasmPluginConfig {
    /** @brief 플러그인 파일 경로. */
    pub path: PathBuf,
    /** @brief 로그와 대시보드에 보일 이름. */
    pub name: Option<String>,
    /** @brief 이 플러그인이 실패했을 때의 처분. 전체 설정을 덮는다. */
    pub fail_mode: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 클라이언트 그룹 하나의 설정. */
pub struct ClientConfig {
    /** @brief 이 클라이언트 그룹의 이름. */
    pub name: String,

    /** @brief 이 그룹에 드는 주소 대역. */
    pub ids: Vec<IpNet>,

    /** @brief 이 그룹에 드는 클라이언트 식별자. */
    pub client_ids: Vec<String>,

    /** @brief 이 그룹에 드는 하드웨어 주소. */
    pub mac: Vec<String>,

    /** @brief 분류에 쓰는 태그. */
    pub tags: Vec<String>,

    /** @brief 이 그룹에만 적용할 차단 규칙. */
    pub block: Vec<String>,

    /** @brief 이 그룹에만 적용할 허용 규칙. */
    pub allow: Vec<String>,

    /** @brief 이 그룹은 차단을 하지 않는다. */
    pub disable_filtering: bool,

    /** @brief 안전 검색 여부. 없으면 전체 설정을 따른다. */
    pub safe_search: Option<bool>,

    /** @brief 이 그룹에서 차단할 서비스. */
    pub blocked_services: Vec<String>,

    /** @brief 이 그룹만 쓸 업스트림 서버. */
    pub upstreams: Vec<String>,

    /** @brief 이 그룹의 질의는 기록하지 않는다. */
    pub ignore_querylog: bool,

    /** @brief 이 그룹의 질의는 통계에 넣지 않는다. */
    pub ignore_stats: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 클라이언트에 따라 다른 답을 주는 뷰 설정. */
pub struct ViewConfig {
    /** @brief 이 뷰의 이름. */
    pub name: String,
    /** @brief 이 뷰에 드는 클라이언트. */
    pub clients: Vec<String>,
    /** @brief 이 뷰에만 답할 IPv4 주소. */
    pub local_a: Vec<(String, Ipv4Addr)>,
    /** @brief 이 뷰에만 답할 IPv6 주소. */
    pub local_aaaa: Vec<(String, Ipv6Addr)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 대시보드 사용자 하나. */
pub struct UserConfig {
    /** @brief 로그인 이름. */
    pub name: String,
    /** @brief 암호 해시. 원문은 저장하지 않는다. */
    pub password_hash: SecretString,
    /** @brief 권한. 읽기 전용과 관리자를 구분한다. */
    pub role: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 차단할 때 어떻게 답할지. */
pub enum BlockResponseKind {
    #[default]
    /** @brief 없다고 답한다. */
    Nxdomain,
    /** @brief 0 주소로 답한다. */
    ZeroIp,
    /** @brief 거절로 답한다. */
    Refused,

    /** @brief 지정한 주소로 답한다. */
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief DNS 쿠키 사용 방식. */
pub enum CookieMode {
    /** @brief 쿠키를 쓰지 않는다. */
    Off,

    #[default]
    /** @brief 쿠키가 없어도 받는다. */
    Lenient,

    /** @brief 쿠키가 없거나 맞지 않으면 거절한다. */
    Strict,
}

impl CookieMode {
    /** @brief 쿠키를 쓰는지. */
    pub fn is_enabled(self) -> bool {
        !matches!(self, CookieMode::Off)
    }
    /** @brief 쿠키 없는 질의를 거부하는지. */
    pub fn is_strict(self) -> bool {
        matches!(self, CookieMode::Strict)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 업스트림을 여럿 둘 때 고르는 방식. */
pub enum UpstreamStrategy {
    #[default]
    /** @brief 성적이 좋은 업스트림을 고른다. */
    QueryStatistics,

    /** @brief 적은 순서대로 쓴다. */
    UserOrder,

    /** @brief 돌아가며 쓴다. */
    RoundRobin,

    /** @brief 여럿에 동시에 묻고 먼저 온 답을 쓴다. */
    Parallel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 클라이언트 대역 정보를 업스트림에 넘길지. */
pub enum EcsMode {
    #[default]
    /** @brief 클라이언트 대역 정보를 건드리지 않는다. */
    Off,

    /** @brief 붙어 온 대역 정보를 뗀다. */
    Strip,

    /** @brief 대역 정보를 붙여 보낸다. */
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/** @brief 로컬 영역을 어떻게 처리할지. */
pub enum LocalZoneKind {
    #[default]
    /** @brief REFUSED로 답한다. */
    Refuse,

    /** @brief 설정한 차단 응답으로 답한다. 일반 허용 규칙이 이긴다. */
    Deny,

    /** @brief 이름별로 적어 둔 답만 있고 영역 안의 나머지 이름은 없는 이름으로 답한다. */
    Static,

    /** @brief 영역과 그 아래 모든 이름에 같은 답을 준다. */
    Redirect,

    /** @brief 언제나 0 주소로 답한다. */
    AlwaysNull,

    /** @brief 이 이름은 그냥 통과시킨다. */
    Transparent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 밖으로 새면 안 되는 이름들의 처분. */
pub struct LocalZone {
    /** @brief 이 규칙이 걸릴 이름. */
    pub name: String,
    /** @brief 이 이름을 어떻게 다룰지. */
    pub kind: LocalZoneKind,

    /**
     * @brief 직접 답할 값들.
     * @details redirect는 IP 주소나 DNS 이름을 값만 적는다. static은 "이름 값"으로 적어
     *          이름마다 답을 따로 둔다.
     */
    pub records: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 로컬 영역의 이름 하나가 돌려줄 답. */
pub enum LocalAnswer {
    /** @brief A와 AAAA로 답할 주소들. */
    Addresses(Vec<IpAddr>),
    /** @brief 이 이름으로 CNAME을 건다. 정규화한 이름이다. */
    Alias(String),
}

impl LocalZone {
    /**
     * @brief records를 이름별 답으로 묶는다.
     * @details 설정 검증과 실행이 같은 해석을 쓰도록 이 함수 하나에 둔다. 두 곳에서 따로
     *          읽으면 검증을 통과한 값이 실행할 때 거절되거나 그 반대가 된다. 한 이름에 주소와
     *          CNAME을 섞거나 CNAME을 둘 두면 어느 답을 줄지 정할 수 없어 거절한다.
     * @return 정규화한 이름과 그 답. static과 redirect가 아니면 빈 목록이다.
     * @retval Err records 안에서 문제가 된 위치와 이유. 앞에 설정 경로를 붙여 쓴다.
     */
    pub fn answers(&self) -> Result<Vec<(String, LocalAnswer)>, String> {
        let per_name = match self.kind {
            LocalZoneKind::Static => true,
            LocalZoneKind::Redirect => false,
            _ => return Ok(Vec::new()),
        };
        let zone = if self.name.trim() == "." {
            String::new()
        } else {
            normalized_dns_name(&self.name)
                .ok_or_else(|| "name is not a valid DNS name".to_string())?
        };
        let mut grouped: Vec<(String, Vec<IpAddr>, Option<String>)> = Vec::new();
        for (item, raw) in self.records.iter().enumerate() {
            let mut fields = raw.split_whitespace();
            let (owner, value) = if per_name {
                let (Some(owner), Some(value), None) =
                    (fields.next(), fields.next(), fields.next())
                else {
                    return Err(format!(
                        "records[{item}] must be 'name value' for static zones, for example \"www.corp.example 192.0.2.10\""
                    ));
                };
                let owner = normalized_dns_name(owner).ok_or_else(|| {
                    format!("records[{item}] name '{owner}' is not a valid DNS name")
                })?;
                let inside = zone.is_empty()
                    || owner == zone
                    || owner
                        .strip_suffix(zone.as_str())
                        .is_some_and(|head| head.ends_with('.'));
                if !inside {
                    return Err(format!(
                        "records[{item}] name '{owner}' is outside zone '{zone}'"
                    ));
                }
                (owner, value)
            } else {
                let (Some(value), None) = (fields.next(), fields.next()) else {
                    return Err(format!(
                        "For redirect, records[{item}] holds a single IP address or DNS name; to give each name a different answer, use kind static"
                    ));
                };
                (zone.clone(), value)
            };
            let index = match grouped.iter().position(|entry| entry.0 == owner) {
                Some(index) => index,
                None => {
                    grouped.push((owner, Vec::new(), None));
                    grouped.len() - 1
                }
            };
            let entry = &mut grouped[index];
            if let Ok(ip) = value.parse::<IpAddr>() {
                entry.1.push(ip);
            } else {
                let target = normalized_dns_name(value).ok_or_else(|| {
                    format!("records[{item}] needs a valid IP address or DNS name: '{value}'")
                })?;
                if entry.2.replace(target).is_some() {
                    return Err(format!(
                        "In records, '{}' can have only one CNAME target",
                        entry.0
                    ));
                }
            }
            if !entry.1.is_empty() && entry.2.is_some() {
                return Err(format!(
                    "In records, '{}' cannot have both IP addresses and a CNAME target",
                    entry.0
                ));
            }
        }
        if grouped.is_empty() {
            return Err("records needs at least one answer value".to_string());
        }
        Ok(grouped
            .into_iter()
            .map(|(owner, addresses, alias)| {
                let answer = match alias {
                    Some(target) => LocalAnswer::Alias(target),
                    None => LocalAnswer::Addresses(addresses),
                };
                (owner, answer)
            })
            .collect())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 이름 재작성 규칙 하나. */
pub struct Rewrite {
    /** @brief 바꿀 이름. */
    pub domain: String,

    /** @brief 대신 답할 값. */
    pub answer: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 상태를 살펴 답을 바꾸는 레코드. */
pub struct DynamicRecord {
    /** @brief 이 기록의 이름. */
    pub name: String,
    /** @brief 기록 종류. */
    pub qtype: String,
    /** @brief 여러 값 중 무엇을 답할지 고르는 방식. */
    pub mode: String,
    /** @brief 답할 후보 값들. */
    pub values: Vec<String>,
    /** @brief 답에 담을 수명. */
    pub ttl: u32,
    /** @brief 살아 있는지 확인할 포트. 0이면 확인하지 않는다. */
    pub probe_port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 특정 접미사를 지정한 서버로 보내는 설정. */
pub struct StubZone {
    /** @brief 이 접미사에 걸린다. */
    pub suffix: String,

    /** @brief 이 접미사를 보낼 서버들. */
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 이 서버가 권한을 갖는 zone 하나. */
pub struct ZoneConfig {
    /** @brief 이 영역의 꼭대기 이름. */
    pub origin: String,

    /** @brief 영역 파일 경로. */
    pub file: Option<PathBuf>,

    /** @brief 이 영역에 서명할지. */
    pub dnssec_sign: bool,

    /**
     * @brief 서명 알고리즘 이름. 비면 ecdsap256(알고리즘 13)이다.
     *
     * @details ed25519(알고리즘 15, RFC 8080)는 서명 1회가 훨씬 싸다. 다만 알고리즘 15를
     *          모르는 검증기는 이 영역을 bogus가 아니라 insecure로 떨어뜨리므로 기본값을
     *          바꾸지 않는다.
     */
    pub dnssec_algorithm: String,

    /** @brief 서명에 쓸 키. */
    pub dnssec_key: Option<PathBuf>,

    /** @brief 키에 서명하는 키. 나눠 쓸 때만 있다. */
    pub dnssec_ksk: Option<PathBuf>,

    /** @brief 교체 중에 미리 알릴 다음 키. */
    pub dnssec_key_next: Option<PathBuf>,

    /** @brief 부재 증명에 이름을 감출지. */
    pub dnssec_nsec3: bool,

    /** @brief 감추기 반복 횟수. 크면 검증하는 쪽의 부담이 는다. */
    pub dnssec_nsec3_iterations: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 다른 서버에서 전송받아 서빙하는 zone. */
pub struct SecondaryZone {
    /** @brief 이 영역의 꼭대기 이름. */
    pub origin: String,

    /** @brief 받아 온 영역을 담아 둘 파일. */
    pub file: Option<PathBuf>,

    /** @brief 받아 올 업스트림 서버. */
    pub primary: Option<IpAddr>,

    /** @brief 업스트림 서버 포트. */
    pub primary_port: Option<u16>,

    /** @brief 전송에 쓸 공유 키 이름. */
    pub tsig_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief zone이 바뀌면 알릴 대상. */
pub struct NotifyTarget {
    /** @brief 알림을 보낼 주소. */
    pub address: SocketAddr,

    /** @brief 알림에 쓸 공유 키 이름. */
    pub tsig_key: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 전송 인증에 쓸 TSIG 키. */
pub struct TsigKeyConfig {
    /** @brief 키 이름. 요청에 이 이름이 담긴다. */
    pub name: String,

    /** @brief 키 값. */
    pub secret: SecretString,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 규칙이 적용되는 시간 구간. */
pub struct ScheduleWindow {
    /** @brief 적용할 요일. */
    pub days: Vec<String>,

    /** @brief 시작 시각. */
    pub start: String,
    /** @brief 끝 시각. */
    pub end: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/** @brief 질의 정책 규칙 하나. */
pub struct PolicyRule {
    /** @brief 맞았을 때 할 일. */
    pub action: String,
    /** @brief 이 클라이언트들에만 건다. */
    pub clients: Vec<String>,
    /** @brief 이 이름들에만 건다. */
    pub suffixes: Vec<String>,

    /** @brief 이 질의 종류에만 건다. */
    pub qtypes: Vec<String>,

    /** @brief 바꿀 답. 재작성일 때만 쓴다. */
    pub rewrite: Option<String>,

    /** @brief 적용할 요일. */
    pub days: Vec<String>,
    /** @brief 시작 시각. */
    pub start: Option<String>,
    /** @brief 끝 시각. */
    pub end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 동적 갱신 허용 규칙 하나. */
pub struct UpdatePolicyRule {
    /** @brief 허용할지 거절할지. */
    pub action: String,
    /** @brief 이 키로 서명한 요청에만 걸린다. */
    pub identity: String,
    /** @brief 이 이름 범위에만 걸린다. */
    pub name: String,
    /** @brief 이 기록 종류에만 걸린다. 비면 전부. */
    pub types: Vec<String>,
}

#[derive(Debug, Clone)]
/**
 * @brief 설정 전체.
 * @note 필드를 더하면 기본값, 디코딩, 알려진 키 목록, 스키마, 검증을 함께 고쳐야 한다.
 *       테스트가 그 일치를 강제하므로 하나만 빠뜨려도 걸린다.
 */
pub struct Config {
    /** @brief 운영 모드. */
    pub mode: Mode,
    /** @brief 질의 처리 방식. */
    pub backend: BackendKind,

    /** @brief 일반 DNS 수신 주소. */
    pub listen: Vec<SocketAddr>,

    /** @brief 일반 DNS 업스트림 서버. */
    pub upstreams: Vec<IpAddr>,

    /** @brief 차단 목록 파일. */
    pub blocklists: Vec<PathBuf>,

    /** @brief 허용 목록 파일. */
    pub allowlists: Vec<PathBuf>,

    /** @brief 차단 목록 다운로드 주소. */
    pub blocklist_urls: Vec<String>,

    /** @brief 차단 목록 표시 이름. */
    pub blocklist_titles: Vec<String>,

    /** @brief 사용하지 않을 차단 목록. */
    pub disabled_blocklist_urls: Vec<String>,

    /** @brief 사용자 차단 규칙. */
    pub block_rules: Vec<String>,

    /** @brief 사용자 허용 규칙. */
    pub allow_rules: Vec<String>,

    /** @brief 목록 자동 갱신 주기. */
    pub list_refresh_secs: u64,

    /** @brief 차단할 서비스. */
    pub blocked_services: Vec<String>,

    /** @brief 안전 검색 강제. */
    pub safe_search: bool,

    /** @brief 클라이언트별 설정. */
    pub clients: Vec<ClientConfig>,

    /** @brief 웹 관리 사용자. */
    pub users: Vec<UserConfig>,

    /** @brief 클라이언트별 DNS 보기. */
    pub views: Vec<ViewConfig>,

    /** @brief 선언형 질의 정책. */
    pub policy: Vec<PolicyRule>,

    /** @brief WASM 정책 파일. */
    pub wasm_policy: Option<PathBuf>,

    /** @brief WASM 정책 플러그인. */
    pub wasm_plugins: Vec<WasmPluginConfig>,

    /** @brief WASM 오류 처리 방식. */
    pub wasm_fail_mode: String,

    /** @brief 차단 응답 방식. */
    pub block_response: BlockResponseKind,

    /** @brief 응답 캐시 항목 수. */
    pub cache_size: u64,

    /** @brief 최소 캐시 TTL. */
    pub min_ttl: u64,
    /** @brief 최대 캐시 TTL. */
    pub max_ttl: u64,

    /** @brief 업스트림 DNS 응답 대기 시간. */
    pub query_timeout_secs: u64,

    /** @brief 최대 동시 질의 수. */
    pub max_inflight: usize,

    /** @brief 만료 응답 제공 기간. */
    pub serve_stale_secs: u64,

    /** @brief 만료 응답의 TTL. */
    pub serve_expired_reply_ttl: u32,

    /** @brief 만료 응답 TTL 재설정. */
    pub serve_expired_ttl_reset: bool,

    /** @brief 만료 응답 전환 대기 시간. */
    pub serve_expired_client_timeout_ms: u64,

    /** @brief 만료 응답 제공 후 즉시 갱신. */
    pub serve_stale_refresh: bool,

    /** @brief PROXY 프로토콜 적용 포트. */
    pub proxy_protocol_ports: Vec<u16>,

    /** @brief 신뢰할 PROXY 송신자. */
    pub proxy_protocol_trusted: Vec<IpNet>,

    /** @brief DNS64 IPv6 접두사. */
    pub dns64_prefix: Option<String>,

    /** @brief DNS 리바인딩 차단. */
    pub rebind_protection: bool,

    /** @brief 만료 전 사전 갱신. */
    pub prefetch: bool,

    /** @brief 일반 DNS 작업 스레드 수. */
    pub workers: usize,

    /** @brief 일반 DNS UDP 사용. */
    pub do_udp: bool,

    /** @brief 일반 DNS TCP 사용. */
    pub do_tcp: bool,

    /** @brief DNSSEC 검증. */
    pub dnssec: bool,

    /** @brief DNSSEC 엄격 검증. */
    pub dnssec_strict: bool,

    /** @brief DNSSEC 오류 응답 허용. */
    pub val_permissive_mode: bool,

    /** @brief 만료된 DNSSEC 서명 허용. */
    pub dnssec_accept_expired: bool,

    /** @brief 클라이언트 CD 비트 무시. */
    pub ignore_cd_flag: bool,

    /** @brief RFC 5011 신뢰 앵커 자동 갱신. */
    pub dnssec_rfc5011: bool,

    /** @brief DNSSEC 루트 신뢰 앵커 파일. */
    pub dnssec_anchor_file: Option<PathBuf>,

    /** @brief DNSSEC ZSK 교체 주기. */
    pub dnssec_roll_interval_secs: u64,

    /** @brief 루트 키 센티널 지원. */
    pub root_key_sentinel: bool,

    /** @brief 신뢰 앵커 신호 전송. */
    pub trust_anchor_signaling: bool,

    /** @brief 최대 위임 추적 횟수. */
    pub recursion_limit: u8,

    /** @brief 최대 CNAME 추적 횟수. */
    pub cname_limit: u8,

    /** @brief 최대 DNAME 치환 횟수. */
    pub dname_limit: u8,

    /** @brief 재귀 질의에 IPv4 사용. */
    pub do_ip4: bool,
    /** @brief 재귀 질의에 IPv6 사용. */
    pub do_ip6: bool,
    /** @brief 재귀 질의에서 IPv4 우선. */
    pub prefer_ip4: bool,
    /** @brief 재귀 질의에서 IPv6 우선. */
    pub prefer_ip6: bool,

    /** @brief 엄격한 QNAME 최소화. */
    pub qname_minimisation_strict: bool,

    /** @brief 위임 경로 추가 검증. */
    pub harden_referral_path: bool,

    /** @brief 질의 이름 대소문자 무작위화. */
    pub use_caps_for_id: bool,

    /** @brief 송신 질의 이름 소문자화. */
    pub lowercase_outgoing: bool,

    /** @brief 크기가 큰 질의를 처리 전에 거부함. */
    pub harden_large_queries: bool,

    /** @brief DNSSEC 검증 제외 도메인. */
    pub domain_insecure: Vec<String>,

    /** @brief 분할 처리 기본 경로. */
    pub split_default: SplitTarget,

    /** @brief 직접 재귀로 처리할 도메인. */
    pub split_recurse: Vec<String>,

    /** @brief 업스트림 서버로 전달할 도메인. */
    pub split_forward: Vec<String>,

    /** @brief 로컬 IPv4 레코드. */
    pub local_a: Vec<(String, Ipv4Addr)>,

    /** @brief 로컬 IPv6 레코드. */
    pub local_aaaa: Vec<(String, Ipv6Addr)>,

    /** @brief 허용할 클라이언트 대역. */
    pub acl_allow: Vec<IpNet>,

    /** @brief 차단할 클라이언트 대역. */
    pub acl_deny: Vec<IpNet>,

    /** @brief 클라이언트당 초당 질의 한도. */
    pub rate_limit_per_sec: u32,

    /** @brief 클라이언트당 순간 질의 허용량. */
    pub rate_limit_burst: u32,

    /** @brief 실행 권한을 낮출 사용자. */
    pub run_as_user: Option<String>,
    /** @brief 실행 권한을 낮출 그룹. */
    pub run_as_group: Option<String>,

    /** @brief DNS 쿠키 처리 방식. */
    pub cookies: CookieMode,

    /** @brief 서브넷당 초당 응답 한도. */
    pub subnet_rrl_per_sec: u32,
    /** @brief 서브넷당 순간 응답 허용량. */
    pub subnet_rrl_burst: u32,

    /** @brief DoT 수신 주소. */
    pub listen_dot: Vec<SocketAddr>,

    /** @brief DoH 수신 주소. */
    pub listen_doh: Vec<SocketAddr>,

    /** @brief DoQ 수신 주소. */
    pub listen_doq: Vec<SocketAddr>,

    /** @brief DoH3 수신 주소. */
    pub listen_doh3: Vec<SocketAddr>,

    /** @brief DNSCrypt UDP 수신 주소. */
    pub listen_dnscrypt: Vec<SocketAddr>,

    /** @brief DNSCrypt 공급자 이름. */
    pub dnscrypt_provider_name: String,

    /** @brief DoH 요청 경로. */
    pub doh_path: String,

    /**
     * @brief DDR로 알릴 이 리졸버의 인증 이름(RFC 9462).
     *
     * @details 비어 있으면 DDR을 답하지 않는다. 값이 있으면 _dns.resolver.arpa SVCB 질의에
     *          설정된 암호화 수신 주소들을 알려, 클라이언트가 Do53에서 DoH·DoT·DoQ로
     *          스스로 올라오게 한다. 클라이언트는 이 이름으로 TLS 인증서를 검증하므로
     *          인증서가 이 이름을 담고 있어야 한다.
     */
    pub ddr_name: String,

    /** @brief TLS 인증서 파일. */
    pub tls_cert: Option<PathBuf>,
    /** @brief TLS 개인 키 파일. */
    pub tls_key: Option<PathBuf>,

    /** @brief 자체 서명 인증서 호스트명. */
    pub tls_self_signed_host: Option<String>,

    /** @brief 클라이언트 인증용 CA 파일. */
    pub tls_client_ca: Option<PathBuf>,

    /** @brief 인증서 폐기 확인 방식. */
    pub tls_revocation: String,

    /** @brief 폐기 확인 실패 허용. */
    pub tls_revocation_softfail: bool,

    /** @brief ACME 서버 주소. */
    pub acme_directory_url: Option<String>,
    /** @brief ACME 연락처 이메일. */
    pub acme_contact_email: Option<String>,
    /** @brief 인증서를 발급할 도메인. */
    pub acme_domains: Vec<String>,

    /** @brief ACME 소유권 확인 방식. */
    pub acme_challenge: String,
    /** @brief ACME 계정 키 파일. */
    pub acme_account_key_file: Option<String>,
    /** @brief ACME 인증서 저장 파일. */
    pub acme_cert_file: Option<String>,
    /** @brief ACME 개인 키 저장 파일. */
    pub acme_key_file: Option<String>,

    /** @brief 관리 화면 및 API 수신 주소. */
    pub control_listen: Option<SocketAddr>,

    /** @brief 관리자 API 토큰. */
    pub control_token: SecretString,

    /** @brief 추가 관리자 API 토큰. */
    pub control_admin_tokens: Vec<SecretString>,

    /** @brief 읽기 전용 API 토큰. */
    pub control_readonly_tokens: Vec<SecretString>,

    /**
     * @brief 관리 화면 앞에 둔 리버스 프록시의 주소 대역.
     * @details 이 대역에서 온 요청만 control_public_origins의 Host로 들어올 수 있고, 그때만
     *          X-Forwarded-For에서 실제 클라이언트 주소를 읽는다.
     */
    pub control_trusted_proxies: Vec<IpNet>,

    /** @brief 리버스 프록시가 관리 화면을 내보이는 HTTPS 출처. */
    pub control_public_origins: Vec<HttpsOrigin>,

    /** @brief 사용자 지정 차단 IPv4. */
    pub block_ipv4: Option<Ipv4Addr>,

    /** @brief 사용자 지정 차단 IPv6. */
    pub block_ipv6: Option<Ipv6Addr>,

    /** @brief 차단 응답 TTL. */
    pub blocked_response_ttl: u32,

    /** @brief IPv6 주소 응답 차단. */
    pub block_aaaa: bool,

    /** @brief NXDOMAIN으로 바꿀 주소. */
    pub bogus_nxdomain: Vec<IpNet>,

    /** @brief 점 없는 이름 전달 금지. */
    pub domain_needed: bool,

    /** @brief 사설 주소 역방향 질의 차단. */
    pub bogus_priv: bool,

    /** @brief 특수 용도 역방향 영역 처리. */
    pub empty_zones: bool,

    /** @brief 로컬 응답 TTL. */
    pub local_ttl: u32,

    /** @brief DNS 응답 변경 규칙. */
    pub rewrites: Vec<Rewrite>,

    /** @brief 동적 DNS 레코드. */
    pub dynamic_records: Vec<DynamicRecord>,

    /** @brief 로컬 DNS 영역. */
    pub local_zones: Vec<LocalZone>,

    /** @brief REFUSED로 답할 도메인 접미사. */
    pub refused_domains: Vec<String>,

    /** @brief RPZ 파일. */
    pub rpz_files: Vec<PathBuf>,

    /** @brief RPZ 다운로드 주소. */
    pub rpz_urls: Vec<String>,

    /** @brief 위험 사이트 차단. */
    pub safe_browsing: bool,

    /** @brief 성인 콘텐츠 차단. */
    pub parental_control: bool,

    /** @brief 서비스 차단 일정. */
    pub service_schedule: Vec<ScheduleWindow>,

    /** @brief 암호화 업스트림 DNS 서버. */
    pub upstream_urls: Vec<String>,

    /** @brief 호스트명 확인용 DNS 서버. */
    pub bootstrap: Vec<IpAddr>,

    /** @brief 재귀 해석 루트 서버. */
    pub root_hints: Vec<IpAddr>,

    /** @brief 대체 업스트림 DNS 서버. */
    pub fallback_upstreams: Vec<String>,

    /** @brief 업스트림 DNS 서버 선택 방식. */
    pub upstream_strategy: UpstreamStrategy,

    /** @brief 동시 업스트림 질의 수. */
    pub upstream_concurrency: usize,

    /** @brief 업스트림 질의 송신 IPv4. */
    pub query_source: Option<Ipv4Addr>,

    /** @brief 업스트림 질의 송신 IPv6. */
    pub query_source_v6: Option<Ipv6Addr>,

    /** @brief 스텁 DNS 영역. */
    pub stub_zones: Vec<StubZone>,

    /** @brief 권한 DNS 영역. */
    pub zones: Vec<ZoneConfig>,

    /** @brief 보조 DNS 영역. */
    pub secondary: Vec<SecondaryZone>,

    /** @brief 영역 파일 디렉터리. */
    pub zones_dir: Option<PathBuf>,

    /** @brief 영역 SQLite 데이터베이스. */
    pub zones_db: Option<PathBuf>,

    /** @brief 영역 SQLite 테이블. */
    pub zones_db_table: String,

    /** @brief PostgreSQL 연결 문자열. */
    pub zones_postgres: Option<SecretString>,
    /** @brief MySQL 연결 문자열. */
    pub zones_mysql: Option<SecretString>,
    /** @brief LMDB 데이터 경로. */
    pub zones_lmdb: Option<PathBuf>,
    /** @brief SQL 영역 테이블. */
    pub zones_sql_table: String,

    /** @brief etcd 서버 주소. */
    pub zones_etcd: Option<String>,

    /** @brief etcd 키 접두사. */
    pub zones_etcd_prefix: String,

    /** @brief etcd TLS CA 파일. */
    pub zones_etcd_ca: Option<PathBuf>,

    /** @brief etcd 사용자 이름. */
    pub zones_etcd_user: Option<String>,

    /** @brief etcd 비밀번호. */
    pub zones_etcd_password: Option<SecretString>,

    /** @brief 카탈로그 영역 구독. */
    pub catalog: Vec<SecondaryZone>,

    /** @brief 제공할 카탈로그 영역. */
    pub catalog_serve: Option<String>,

    /** @brief 영역 전송 허용 대역. */
    pub xfr_allow: Vec<IpNet>,

    /** @brief NOTIFY 전송 대상. */
    pub notify: Vec<NotifyTarget>,

    /** @brief TSIG 공유 키. */
    pub tsig_keys: Vec<TsigKeyConfig>,

    /** @brief 영역 전송에 TSIG 요구. */
    pub xfr_tsig_required: bool,

    /** @brief ZONEMD 검증. */
    pub zonemd_check: bool,

    /** @brief ZONEMD 레코드가 없는 영역을 허용하지 않음. */
    pub zonemd_reject_absence: bool,

    /** @brief 동적 DNS 갱신 허용 대역. */
    pub update_allow: Vec<IpNet>,

    /** @brief 동적 DNS 갱신 정책. */
    pub update_policy: Vec<UpdatePolicyRule>,

    /** @brief 동적 DNS 갱신에 TSIG 요구. */
    pub update_tsig_required: bool,

    /** @brief EDNS 클라이언트 서브넷 처리. */
    pub ecs_mode: EcsMode,

    /** @brief 고정 ECS 주소. */
    pub ecs_custom_ip: Option<IpAddr>,

    /** @brief 부정 응답 최소 TTL. */
    pub neg_min_ttl: u64,
    /** @brief 부정 응답 최대 TTL. */
    pub neg_max_ttl: u64,

    /** @brief EDNS UDP 버퍼 크기. */
    pub edns_buffer_size: u16,

    /** @brief ANY 형식의 질의를 허용하지 않음. */
    pub deny_any: bool,

    /** @brief 최소 응답 사용. */
    pub minimal_responses: bool,

    /** @brief EDNS 패딩 단위. */
    pub edns_padding_block: usize,

    /** @brief EDNS TCP 연결 유지 시간. */
    pub edns_tcp_keepalive_secs: u64,

    /** @brief 응답 캐시 사용. */
    pub cache_enabled: bool,

    /** @brief 분할 캐시 사용. */
    pub sharded_cache: bool,

    /** @brief 캐시 분할 수. */
    pub cache_shards: usize,

    /** @brief 사전 갱신 점검 주기. */
    pub prefetch_interval_secs: u64,

    /** @brief 사전 갱신 최소 적중 횟수. */
    pub prefetch_min_hits: u32,

    /** @brief 사전 갱신 시작 시점. */
    pub prefetch_ttl_pct: u32,

    /** @brief 모든 A 응답에 DNS64 적용. */
    pub dns64_synthall: bool,

    /** @brief 응답 레코드 순서 순환. */
    pub rrset_roundrobin: bool,

    /** @brief 규칙별 적중 횟수 기록. */
    pub track_rule_hits: bool,

    /** @brief NSEC 부재 응답 재사용. */
    pub aggressive_nsec: bool,

    /** @brief 이름별 초당 질의 한도. */
    pub name_ratelimit_per_sec: u32,

    /** @brief 이름별 제한에 사용할 라벨 수. */
    pub name_ratelimit_labels: usize,

    /** @brief NXDOMAIN 하위 이름 재사용. */
    pub harden_below_nxdomain: bool,

    /** @brief DHCPv4 서버 사용. */
    pub dhcp_enable: bool,

    /** @brief DHCPv4 서버 주소. */
    pub dhcp_server_ip: Option<String>,

    /** @brief DHCPv4 할당 시작 주소. */
    pub dhcp_range_start: Option<String>,
    /** @brief DHCPv4 할당 끝 주소. */
    pub dhcp_range_end: Option<String>,

    /** @brief DHCPv4 서브넷 마스크. */
    pub dhcp_subnet_mask: Option<String>,
    /** @brief DHCPv4 기본 게이트웨이. */
    pub dhcp_router: Option<String>,

    /** @brief DHCPv4에서 안내할 DNS 서버. */
    pub dhcp_dns: Vec<String>,

    /** @brief DHCPv4 임대 시간. */
    pub dhcp_lease_secs: u64,

    /** @brief DHCP 호스트의 로컬 도메인. */
    pub dhcp_local_domain: String,

    /** @brief DHCP에서 안내할 TFTP 서버. */
    pub dhcp_tftp_server: Option<String>,

    /** @brief DHCP 부팅 파일 이름. */
    pub dhcp_boot_file: Option<String>,

    /** @brief TFTP 서버 사용. */
    pub tftp_enable: bool,

    /** @brief TFTP 파일 루트. */
    pub tftp_root: Option<String>,

    /** @brief TFTP 수신 주소. */
    pub tftp_listen: SocketAddr,

    /** @brief TFTP 파일 업로드 허용. */
    pub tftp_writable: bool,

    /** @brief TFTP 업로드 허용 대역. */
    pub tftp_write_allow: Vec<IpNet>,

    /** @brief TFTP 기존 파일 덮어쓰기 허용. */
    pub tftp_allow_overwrite: bool,

    /** @brief IPv6 라우터 광고 사용. */
    pub ra_enable: bool,

    /** @brief 라우터 광고 IPv6 접두사. */
    pub ra_prefix: Option<String>,

    /** @brief 라우터 광고 관리 주소 플래그. */
    pub ra_managed: bool,

    /** @brief 라우터 광고 기타 설정 플래그. */
    pub ra_other: bool,

    /** @brief 라우터 광고 기본 경로 수명. */
    pub ra_router_lifetime: u16,

    /** @brief 라우터 광고 전송 주기. */
    pub ra_interval: u64,

    /** @brief 라우터 광고 MTU. */
    pub ra_mtu: u32,

    /** @brief 라우터 광고 네트워크 인터페이스. */
    pub ra_interface_index: u32,

    /** @brief DHCPv6 서버 사용. */
    pub dhcp6_enable: bool,

    /** @brief DHCPv6 할당 시작 주소. */
    pub dhcp6_range_start: Option<String>,
    /** @brief DHCPv6 할당 끝 주소. */
    pub dhcp6_range_end: Option<String>,

    /** @brief DHCPv6에서 안내할 DNS 서버. */
    pub dhcp6_dns: Vec<String>,

    /** @brief DHCPv6 multicast를 받을 네트워크 인터페이스. 0은 운영체제 기본. */
    pub dhcp6_interface_index: u32,

    /** @brief DHCPv4 임대 정보 파일. */
    pub dhcp_lease_file: Option<String>,

    /** @brief DHCPv4 고정 할당 파일. */
    pub dhcp_static_file: Option<String>,

    /** @brief DHCPv6 임대 정보 파일. */
    pub dhcp6_lease_file: Option<String>,

    /** @brief MAC 제조사 데이터베이스. */
    pub mac_vendor_db: Option<String>,

    /** @brief IPv4 ipset 이름. */
    pub ipset_name_v4: Option<String>,
    /** @brief IPv6 ipset 이름. */
    pub ipset_name_v6: Option<String>,
    /** @brief ipset에 넣을 도메인. */
    pub ipset_domains: Vec<String>,

    /** @brief 외부 Redis 캐시 서버. */
    pub cachedb_redis_host: Option<String>,
    /** @brief 외부 Redis 캐시 포트. */
    pub cachedb_redis_port: u16,
    /** @brief 외부 Redis 캐시 만료 시간. */
    pub cachedb_redis_expire_secs: u64,
    /** @brief 외부 Redis 캐시에 담는 값을 인증하는 공용 비밀 키. */
    pub cachedb_redis_secret: SecretString,
    /** @brief 외부 Redis 캐시 사용자 이름. */
    pub cachedb_redis_username: Option<String>,
    /** @brief 외부 Redis 캐시 비밀번호. */
    pub cachedb_redis_password: Option<SecretString>,
    /** @brief 외부 Redis 캐시에 TLS로 접속할지. */
    pub cachedb_redis_tls: bool,
    /** @brief 외부 Redis 캐시의 TLS 인증서를 검증할 CA 파일. 없으면 시스템 신뢰 저장소를 쓴다. */
    pub cachedb_redis_tls_ca: Option<PathBuf>,

    /** @brief 상대 클러스터 노드. */
    pub cluster_peers: Vec<String>,

    /** @brief Raft 클러스터 사용. */
    pub cluster_raft: bool,
    /** @brief 이 노드의 Raft ID. */
    pub cluster_node_id: u64,
    /** @brief Raft 통신 수신 주소. */
    pub cluster_raft_listen: Option<String>,
    /** @brief Raft 클러스터 노드. */
    pub cluster_raft_peers: Vec<String>,
    /** @brief Raft 노드 공용 인증 키. */
    pub cluster_raft_secret: SecretString,

    /** @brief 이 노드의 Raft 서명 키. */
    pub cluster_raft_node_key: SecretString,

    /** @brief 리바인딩 차단 예외 도메인. */
    pub rebind_allow: Vec<String>,

    /** @brief 재귀 질의에서 제외할 서버. */
    pub recurse_deny_server: Vec<IpNet>,

    /** @brief 재귀 질의에 허용할 서버. */
    pub recurse_allow_server: Vec<IpNet>,

    /** @brief 네임서버 주소 추적 한도. */
    pub ns_recursion_limit: u8,

    /** @brief 재귀 상태 캐시 항목 수. */
    pub ns_cache_size: usize,

    /** @brief 거부할 재귀 응답 주소. */
    pub recurse_deny_answers: Vec<IpNet>,
    /** @brief 허용할 재귀 응답 주소. */
    pub recurse_allow_answers: Vec<IpNet>,

    /** @brief 허용할 NSEC3 최대 반복 횟수. */
    pub val_nsec3_max_iterations: u16,

    /** @brief 속도 제한 예외 대역. */
    pub rate_limit_allow: Vec<IpNet>,

    /** @brief 허용할 클라이언트 ID. */
    pub acl_allow_ids: Vec<String>,
    /** @brief 차단할 클라이언트 ID. */
    pub acl_deny_ids: Vec<String>,

    /** @brief 서버 식별자 숨김. */
    pub hide_identity: bool,

    /** @brief 서버 버전 숨김. */
    pub hide_version: bool,

    /** @brief EDNS NSID 값. */
    pub nsid: Option<String>,

    /** @brief CHAOS 서버 식별자. */
    pub identity: Option<String>,

    /** @brief CHAOS 서버 버전 문자열. */
    pub version: Option<String>,

    /** @brief 시스템 로그 상세 수준. */
    pub log_level: Option<String>,

    /** @brief 질의 로그 기록. */
    pub querylog: bool,

    /** @brief 메모리에 보관할 질의 로그 수. */
    pub querylog_size: usize,

    /** @brief 질의 로그 보관 시간. */
    pub querylog_retention_secs: u64,

    /** @brief 질의 로그의 클라이언트 IP 익명화. */
    pub anonymize_client_ip: bool,

    /** @brief 기록하지 않을 도메인. */
    pub querylog_ignored: Vec<String>,

    /** @brief 시계열 통계 보관 시간. */
    pub stats_retention_secs: u64,

    /** @brief 질의 로그 저장 파일. */
    pub querylog_file: Option<PathBuf>,

    /** @brief 누적 통계 저장 파일. */
    pub stats_file: Option<PathBuf>,

    /** @brief 로그와 통계 저장 주기. */
    pub persist_flush_secs: u64,

    /** @brief dnstap 출력 파일. */
    pub dnstap_file: Option<PathBuf>,

    /** @brief dnstap 서버 식별자. */
    pub dnstap_identity: String,

    /**
     * @brief 새 릴리스를 주기적으로 확인하는지.
     * @details 끄면 주기 확인만 멈춘다. 관리자가 직접 확인하고 적용하는 것은 막지 않는다.
     */
    pub release_check: bool,
}

impl Default for Config {
    /** @brief 안전한 기본값. 아무것도 적지 않아도 이 값으로 돈다. */
    fn default() -> Self {
        Self {
            mode: Mode::Personal,
            backend: BackendKind::Forward,

            listen: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],

            upstreams: vec![],
            blocklists: vec![],
            allowlists: vec![],
            blocklist_urls: vec![],
            blocklist_titles: vec![],
            disabled_blocklist_urls: vec![],
            block_rules: vec![],
            allow_rules: vec![],
            list_refresh_secs: 0,
            blocked_services: vec![],
            safe_search: false,
            clients: vec![],
            users: vec![],
            views: vec![],
            policy: vec![],
            wasm_policy: None,
            wasm_plugins: vec![],
            wasm_fail_mode: "closed-refuse".to_string(),
            block_response: BlockResponseKind::Nxdomain,
            cache_size: 4096,
            min_ttl: 0,
            max_ttl: 86_400,
            query_timeout_secs: 5,
            max_inflight: 0,
            serve_stale_secs: 0,
            serve_expired_reply_ttl: 30,
            serve_expired_ttl_reset: false,
            serve_expired_client_timeout_ms: 0,
            serve_stale_refresh: false,
            proxy_protocol_ports: vec![],
            proxy_protocol_trusted: vec![],
            dns64_prefix: None,
            rebind_protection: false,
            prefetch: false,
            workers: 0,
            do_udp: true,
            do_tcp: true,
            dnssec: false,
            dnssec_strict: true,
            val_permissive_mode: false,
            dnssec_accept_expired: false,
            ignore_cd_flag: true,
            dnssec_rfc5011: false,
            dnssec_anchor_file: None,
            dnssec_roll_interval_secs: 0,
            root_key_sentinel: true,
            trust_anchor_signaling: true,
            recursion_limit: 0,
            cname_limit: 8,
            dname_limit: 8,
            do_ip4: true,
            do_ip6: true,
            prefer_ip4: false,
            prefer_ip6: false,
            qname_minimisation_strict: false,
            harden_referral_path: false,
            use_caps_for_id: true,
            lowercase_outgoing: false,
            harden_large_queries: false,
            domain_insecure: vec![],
            split_default: SplitTarget::Forward,
            split_recurse: vec![],
            split_forward: vec![],
            local_a: vec![],
            local_aaaa: vec![],
            acl_allow: Mode::Personal.preset_acl_allow(),
            acl_deny: vec![],
            rate_limit_per_sec: 0,
            rate_limit_burst: 0,
            run_as_user: None,
            run_as_group: None,
            cookies: CookieMode::Lenient,
            subnet_rrl_per_sec: 0,
            subnet_rrl_burst: 0,
            listen_dot: vec![],
            listen_doh: vec![],
            listen_doq: vec![],
            listen_doh3: vec![],
            listen_dnscrypt: vec![],
            dnscrypt_provider_name: "2.dnscrypt-cert.onetdns".to_string(),
            doh_path: "/dns-query".to_string(),
            ddr_name: String::new(),
            tls_cert: None,
            tls_key: None,
            tls_self_signed_host: None,
            tls_client_ca: None,
            tls_revocation: "off".to_string(),
            tls_revocation_softfail: true,
            acme_directory_url: None,
            acme_contact_email: None,
            acme_domains: vec![],
            acme_challenge: "http01".to_string(),
            acme_account_key_file: None,
            acme_cert_file: None,
            acme_key_file: None,
            control_listen: None,
            control_token: SecretString::default(),
            control_admin_tokens: vec![],
            control_readonly_tokens: vec![],
            control_trusted_proxies: vec![],
            control_public_origins: vec![],

            block_ipv4: None,
            block_ipv6: None,
            blocked_response_ttl: 10,
            block_aaaa: false,
            bogus_nxdomain: vec![],
            domain_needed: false,
            bogus_priv: false,
            empty_zones: false,
            local_ttl: 300,
            rewrites: vec![],
            dynamic_records: vec![],
            local_zones: vec![],
            refused_domains: vec![],
            rpz_files: vec![],
            rpz_urls: vec![],
            safe_browsing: false,
            parental_control: false,
            service_schedule: vec![],
            upstream_urls: DEFAULT_UPSTREAM_URLS
                .iter()
                .map(|url| (*url).to_string())
                .collect(),
            bootstrap: vec![],
            root_hints: vec![],
            fallback_upstreams: vec![],
            upstream_strategy: UpstreamStrategy::QueryStatistics,
            upstream_concurrency: 0,
            query_source: None,
            query_source_v6: None,
            stub_zones: vec![],
            zones: vec![],
            secondary: vec![],
            catalog: vec![],
            catalog_serve: None,
            zones_dir: None,
            zones_db: None,
            zones_db_table: "zones".to_string(),
            zones_postgres: None,
            zones_mysql: None,
            zones_lmdb: None,
            zones_sql_table: "zones".to_string(),
            zones_etcd: None,
            zones_etcd_prefix: "/onetdns/zones/".to_string(),
            zones_etcd_ca: None,
            zones_etcd_user: None,
            zones_etcd_password: None,
            xfr_allow: vec![],
            notify: vec![],
            tsig_keys: vec![],
            xfr_tsig_required: false,
            zonemd_check: false,
            zonemd_reject_absence: false,
            update_allow: vec![],
            update_policy: vec![],
            update_tsig_required: false,
            ecs_mode: EcsMode::Off,
            ecs_custom_ip: None,
            neg_min_ttl: 0,
            neg_max_ttl: 86_400,
            edns_buffer_size: 1232,
            deny_any: true,
            minimal_responses: false,
            edns_padding_block: 0,
            edns_tcp_keepalive_secs: 0,
            cache_enabled: true,
            sharded_cache: false,
            cache_shards: 16,
            prefetch_interval_secs: 10,
            prefetch_min_hits: 0,
            prefetch_ttl_pct: 90,
            dns64_synthall: false,
            rrset_roundrobin: false,
            track_rule_hits: false,
            aggressive_nsec: false,
            name_ratelimit_per_sec: 0,
            name_ratelimit_labels: 2,
            harden_below_nxdomain: false,
            dhcp_enable: false,
            dhcp_server_ip: None,
            dhcp_range_start: None,
            dhcp_range_end: None,
            dhcp_subnet_mask: None,
            dhcp_router: None,
            dhcp_dns: vec![],
            dhcp_lease_secs: 86_400,
            dhcp_local_domain: "lan".to_string(),
            dhcp_tftp_server: None,
            dhcp_boot_file: None,
            tftp_enable: false,
            tftp_root: None,
            tftp_listen: "127.0.0.1:69"
                .parse()
                .expect("The default TFTP listening address must be valid"),
            tftp_writable: false,
            tftp_write_allow: vec![],
            tftp_allow_overwrite: false,
            ra_enable: false,
            ra_prefix: None,
            ra_managed: false,
            ra_other: false,
            ra_router_lifetime: 1800,
            ra_interval: 600,
            ra_mtu: 0,
            ra_interface_index: 0,
            dhcp6_enable: false,
            dhcp6_range_start: None,
            dhcp6_range_end: None,
            dhcp6_dns: vec![],
            dhcp6_interface_index: 0,
            dhcp_lease_file: None,
            dhcp_static_file: None,
            dhcp6_lease_file: None,
            mac_vendor_db: None,
            ipset_name_v4: None,
            ipset_name_v6: None,
            ipset_domains: vec![],
            cachedb_redis_host: None,
            cachedb_redis_port: 6379,
            cachedb_redis_expire_secs: 0,
            cachedb_redis_secret: String::new().into(),
            cachedb_redis_username: None,
            cachedb_redis_password: None,
            cachedb_redis_tls: false,
            cachedb_redis_tls_ca: None,
            cluster_peers: vec![],
            cluster_raft: false,
            cluster_node_id: 0,
            cluster_raft_listen: None,
            cluster_raft_peers: vec![],
            cluster_raft_secret: String::new().into(),
            cluster_raft_node_key: String::new().into(),
            rebind_allow: vec![],
            recurse_deny_server: vec![],
            recurse_allow_server: vec![],
            ns_recursion_limit: 0,
            ns_cache_size: 0,
            recurse_deny_answers: vec![],
            recurse_allow_answers: vec![],
            val_nsec3_max_iterations: 150,
            rate_limit_allow: vec![],
            acl_allow_ids: vec![],
            acl_deny_ids: vec![],
            hide_identity: false,
            hide_version: false,
            nsid: None,
            identity: None,
            version: None,
            log_level: None,
            querylog: true,
            querylog_size: 200,
            querylog_retention_secs: 0,
            anonymize_client_ip: false,
            querylog_ignored: vec![],
            stats_retention_secs: 0,
            querylog_file: None,
            stats_file: None,
            persist_flush_secs: 30,
            dnstap_file: None,
            dnstap_identity: String::new(),
            release_check: true,
        }
    }
}

/**
 * @brief URL에서 자격증명만 가린다.
 * @note 주소는 남긴다. 어디로 가는지는 진단에 필요하고, 위험한 것은 사용자 이름과 비밀번호다.
 */
pub fn redact_url_credentials(input: &str) -> String {
    let Some(scheme_end) = input.find("://") else {
        return "<redacted-url>".to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = input[authority_start..]
        .find(['/', '?', '#'])
        .map_or(input.len(), |offset| authority_start + offset);
    let authority = &input[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return input.to_string();
    };
    let userinfo = &authority[..at];
    let Some(colon) = userinfo.find(':') else {
        return input.to_string();
    };

    let mut out = String::with_capacity(input.len().min(256));
    out.push_str(&input[..authority_start]);
    out.push_str(&userinfo[..colon]);
    out.push_str(":***@");
    out.push_str(&authority[at + 1..]);
    out.push_str(&input[authority_end..]);
    out
}

impl Config {
    /** @brief TOML 문자열에서 설정을 읽는다. 모르는 키는 거부한다. */
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        if s.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(
                "The configuration file exceeds the size limit".into(),
            ));
        }
        let value = crate::toml::parse(s).map_err(ConfigError::Parse)?;
        let cfg = decode_config(&value)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /** @brief 두 설정 텍스트의 차이를 항목 단위로 낸다. 대시보드가 적용 전에 보여 준다. */
    pub fn diff_toml(
        current: &str,
        proposed: &str,
    ) -> Result<(Vec<String>, Vec<String>, Vec<String>), ConfigError> {
        Self::from_toml_str(proposed)?;
        let cur = crate::toml::parse(current)
            .unwrap_or(crate::toml::Value::Table(std::collections::BTreeMap::new()));
        let new = crate::toml::parse(proposed).map_err(ConfigError::Parse)?;
        let empty = std::collections::BTreeMap::new();
        let ct = cur.as_table().unwrap_or(&empty);
        let nt = new.as_table().unwrap_or(&empty);
        let mut added = vec![];
        let mut removed = vec![];
        let mut changed = vec![];
        for k in nt.keys() {
            match ct.get(k) {
                None => added.push(k.clone()),
                Some(v) if v != &nt[k] => changed.push(k.clone()),
                _ => {}
            }
        }
        for k in ct.keys() {
            if !nt.contains_key(k) {
                removed.push(k.clone());
            }
        }
        Ok((added, removed, changed))
    }

    /** @brief 파일에서 읽거나, 없으면 기본값을 쓴다. */
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        match path {
            Some(p) => {
                let text = SecretString::from(Self::read_text(p)?);
                Self::from_toml_str(&text)
            }
            None => {
                let cfg = Self::default();
                cfg.validate()?;
                Ok(cfg)
            }
        }
    }

    /** @brief 설정 파일을 읽는다. 크기 상한을 파싱 전에 확인한다. */
    pub fn read_text(path: &std::path::Path) -> Result<String, ConfigError> {
        let file = std::fs::File::open(path)
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?;
        let len = file
            .metadata()
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?
            .len();
        if len > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(
                "The configuration file exceeds the size limit".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(len as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(
                "The configuration file exceeds the size limit".into(),
            ));
        }
        String::from_utf8(bytes)
            .map_err(|_| ConfigError::Parse("The configuration file is not valid UTF-8".into()))
    }

    /**
     * @brief 설정 전체의 일관성을 확인한다.
     *
     * @details 개별 항목의 형식은 파싱에서 이미 봤다. 여기서는 항목끼리의 관계를 본다.
     *          컨트롤 플레인이 루프백인지, 업스트림이 자기 자신을 가리키지 않는지, 공개 모드에
     *          속도 제한이 있는지 같은 것들이다.
     * @warning 실패하면 시작하지 않는다. 위험한 설정으로 실행되는 것보다 시작하지 않는 쪽이 낫다.
     */
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.check(&mut Vec::new())
    }

    /**
     * @brief 권한 서버 저장소와 TSIG 값 가운데 저장은 되지만 쓰일 수 없는 모양을 거른다.
     * @details 테이블 이름은 질의문에 그대로 들어가므로 저장소가 쓰는 규칙과 같은 문자만
     *          받는다. 규칙이 다르면 검증을 통과한 값이 영역을 불러올 때마다 실패한다.
     */
    fn check_authority_values(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| Err(ConfigError::Invalid(message));
        for (key, table) in [
            ("zones_db_table", &self.zones_db_table),
            ("zones_sql_table", &self.zones_sql_table),
        ] {
            if table.is_empty()
                || !table
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
            {
                return invalid(format!(
                    "{key} needs a table name made of letters, digits, underscores, and dots: {table:?}"
                ));
            }
        }
        if self.zones_etcd_prefix.is_empty() {
            return invalid(
                "zones_etcd_prefix cannot be empty; an empty prefix would read every etcd key as a zone"
                    .into(),
            );
        }
        if self
            .zones_lmdb
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return invalid("zones_lmdb cannot be an empty path".into());
        }
        if self.zones_etcd_user.is_some() != self.zones_etcd_password.is_some() {
            return invalid("Set both zones_etcd_user and zones_etcd_password, or neither".into());
        }
        if let Some(name) = &self.catalog_serve {
            if !valid_dns_name(name) {
                return invalid(format!("catalog_serve needs a valid DNS name: {name:?}"));
            }
        }
        let mut key_names = std::collections::HashSet::new();
        for key in &self.tsig_keys {
            let name = key.name.trim().trim_end_matches('.').to_ascii_lowercase();
            if !key_names.insert(name.clone()) {
                return invalid(format!("The same TSIG key name is set twice: {name}"));
            }
        }
        for (index, rule) in self.update_policy.iter().enumerate() {
            let identity = rule.identity.trim_end_matches('.').to_ascii_lowercase();
            if identity != "*" && !key_names.contains(&identity) {
                return invalid(format!(
                    "update_policy[{index}] identity '{}' is not in [[tsig_keys]]",
                    rule.identity
                ));
            }
        }
        if self.zonemd_reject_absence && !self.zonemd_check {
            return invalid(
                "zonemd_reject_absence can be turned on only while zonemd_check is on; turn on zonemd_check first"
                    .into(),
            );
        }
        Ok(())
    }

    /**
     * @brief 전달, 수신, ACME 값 가운데 저장은 되지만 쓰일 수 없는 모양을 거른다.
     * @details 여기서 막지 않으면 값은 설정에 남는데 동작은 기본값으로 돌거나, 켜는 순간에야
     *          발급이나 수신이 실패한다.
     */
    fn check_protocol_values(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| Err(ConfigError::Invalid(message));
        if self.edns_tcp_keepalive_secs > 6_553 {
            return invalid(
                "edns_tcp_keepalive_secs must be at most 6553 seconds; the EDNS TCP keepalive option is a 16-bit value in units of 100 ms"
                    .into(),
            );
        }
        if self.ecs_mode == EcsMode::Send && self.ecs_custom_ip.is_none() {
            return invalid(
                "When ecs_mode is send, set the subnet to send upstream in ecs_custom_ip".into(),
            );
        }
        if !valid_doh_path(&self.doh_path) {
            return invalid(format!(
                "doh_path must start with / and contain no spaces, ?, or #: {:?}",
                self.doh_path
            ));
        }
        if !valid_dns_name(&self.dnscrypt_provider_name) {
            return invalid(format!(
                "dnscrypt_provider_name needs a valid DNS name such as 2.dnscrypt-cert.example.com: {:?}",
                self.dnscrypt_provider_name
            ));
        }
        validate_acme_request(
            self.acme_directory_url.as_deref(),
            &self.acme_domains,
            self.acme_contact_email.as_deref(),
            &self.acme_challenge,
        )
        .map_err(ConfigError::Invalid)?;
        for (key, path) in [
            ("acme_account_key_file", &self.acme_account_key_file),
            ("acme_cert_file", &self.acme_cert_file),
            ("acme_key_file", &self.acme_key_file),
        ] {
            if path.as_deref().is_some_and(|p| p.trim().is_empty()) {
                return invalid(format!(
                    "{key} cannot be an empty path; remove the setting if you do not use it"
                ));
            }
        }
        if self.acme_cert_file.is_some() != self.acme_key_file.is_some() {
            return invalid("Set both acme_cert_file and acme_key_file, or neither".into());
        }
        Ok(())
    }

    /**
     * @brief DHCP, DHCPv6, 라우터 광고 값 하나하나가 쓸 수 있는 모양인지.
     * @details 서비스가 꺼져 있어도 검사한다. 켜는 순간에야 드러나면 서버가 뜨지 않는다.
     *          여러 값을 함께 보는 서브넷과 범위 검사는 서비스를 시작하는 쪽이 맡는다.
     */
    fn check_edge_service_values(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| Err(ConfigError::Invalid(message));
        if !self.dhcp_local_domain.is_empty() && !valid_dns_name(&self.dhcp_local_domain) {
            return invalid(format!(
                "dhcp_local_domain needs a valid DNS name: {}",
                self.dhcp_local_domain
            ));
        }
        if let Some(server) = &self.dhcp_tftp_server {
            if server.parse::<std::net::Ipv4Addr>().is_err() {
                return invalid(format!("dhcp_tftp_server needs an IPv4 address: {server}"));
            }
        }
        if let Some(file) = &self.dhcp_boot_file {
            if file.is_empty() || file.len() > 255 || file.bytes().any(|b| b == 0) {
                return invalid(
                    "dhcp_boot_file must be a 1 to 255 byte name that fits in one DHCP option"
                        .into(),
                );
            }
        }
        for server in &self.dhcp6_dns {
            if server.parse::<std::net::Ipv6Addr>().is_err() {
                return invalid(format!(
                    "dhcp6_dns entries must be IPv6 addresses: {server}"
                ));
            }
        }
        if let Some(prefix) = &self.ra_prefix {
            let parsed = prefix.split_once('/').and_then(|(address, length)| {
                let address = address.trim().parse::<std::net::Ipv6Addr>().ok()?;
                let length = length.trim().parse::<u8>().ok().filter(|l| *l <= 128)?;
                Some((address, length))
            });
            let Some((address, length)) = parsed else {
                return invalid(format!(
                    "ra_prefix needs an IPv6 address and prefix length, such as fd00:1::/64: {prefix}"
                ));
            };
            let host_bits = u128::from(address)
                .checked_shl(u32::from(length))
                .unwrap_or(0);
            if address.is_unspecified() || host_bits != 0 {
                return invalid(format!(
                    "ra_prefix must be a network address with every bit after the prefix length set to 0: {prefix}"
                ));
            }
        }
        if !(4..=1_800).contains(&self.ra_interval) {
            return invalid(
                "ra_interval must be within the RFC 4861 router advertisement range of 4 to 1800 seconds".into(),
            );
        }
        let lifetime = u64::from(self.ra_router_lifetime);
        if lifetime != 0 && !(self.ra_interval..=9_000).contains(&lifetime) {
            return invalid(
                "ra_router_lifetime must be 0, or at least ra_interval and at most 9000 seconds; if it is shorter than the advertisement interval, the default route disappears before the next advertisement"
                    .into(),
            );
        }
        if self.ra_mtu != 0 && self.ra_mtu < 1_280 {
            return invalid("ra_mtu must be 0 or at least 1280, the IPv6 minimum MTU".into());
        }
        Ok(())
    }

    /**
     * @brief 설정을 막지는 않지만 알려야 하는 것들.
     *
     * @details 조건이 맞지 않아 동작하지 않을 항목, 그리고 위험을 감수하는 선택을 모은다.
     *          설정을 못 하게 막지 않는다. 무엇을 켤지는 운영자가 정한다.
     * @return 사람이 읽을 문장들. 시작 로그와 대시보드에 그대로 뜬다.
     */
    pub fn advisories(&self) -> Vec<String> {
        let mut out = Vec::new();
        let _ = self.check(&mut out);
        out
    }

    /**
     * @brief DNSSEC 서명을 이 서버가 실제로 검증하는지.
     *
     * @details 재귀 방식은 위임을 걸으며 검증하고, 전달 방식은 업스트림에 DNSKEY와 DS를 따로
     *          물어 체인을 구성한다. 어느 쪽이든 업스트림이 설정한 AD 비트는 믿지 않는다.
     * @warning 켜졌다고 말하는 곳은 전부 이 판정을 써야 한다. 설정값만 보고 알리면
     *          운영자는 검증되지 않는 답을 검증됐다고 믿는다.
     */
    pub fn dnssec_validation_active(&self) -> bool {
        self.dnssec
    }

    /**
     * @brief 값 자체가 틀린 것만 거절하고, 조건이 안 맞는 것은 경고로 모은다.
     * @param soft 조건이 안 맞아 동작하지 않을 항목을 담을 곳.
     */
    fn check(&self, soft: &mut Vec<String>) -> Result<(), ConfigError> {
        if matches!(self.backend, BackendKind::Forward | BackendKind::Split)
            && self.upstreams.is_empty()
            && self.upstream_urls.is_empty()
        {
            return Err(ConfigError::Invalid(
                "Queries are set to be forwarded to upstream DNS servers, but no server address is set; add at least one to `upstreams` or `upstream_urls`".into(),
            ));
        }
        if !matches!(self.backend, BackendKind::Split)
            && (!self.local_a.is_empty()
                || !self.local_aaaa.is_empty()
                || !self.split_recurse.is_empty()
                || !self.split_forward.is_empty())
        {
            soft.push("`local_a`, `local_aaaa`, `split_recurse`, and `split_forward` work only with the split backend; set `backend = \"split\"` or remove those settings".into(),);
        }
        match (self.run_as_user.as_deref(), self.run_as_group.as_deref()) {
            (None, Some(_)) => {
                soft.push("`run_as_group` also needs `run_as_user`".into());
            }
            (Some(user), group) => {
                let user = user.trim();
                if user.is_empty() {
                    return Err(ConfigError::Invalid(
                        "Set `run_as_user` to the user that should run the server".into(),
                    ));
                }
                if user.eq_ignore_ascii_case("root") || user.parse::<u32>() == Ok(0) {
                    return Err(ConfigError::Invalid(
                        "Set `run_as_user` to a user other than root".into(),
                    ));
                }
                if let Some(group) = group {
                    let group = group.trim();
                    if group.is_empty() {
                        return Err(ConfigError::Invalid(
                            "Set `run_as_group` to the group that should run the server".into(),
                        ));
                    }
                    if group.eq_ignore_ascii_case("root") || group.parse::<u32>() == Ok(0) {
                        return Err(ConfigError::Invalid(
                            "Set `run_as_group` to a group other than root".into(),
                        ));
                    }
                }
                if !cfg!(target_os = "linux") {
                    soft.push("`run_as_user` and `run_as_group` work only on Linux; on this operating system the server keeps running as the current account".into());
                }
            }
            (None, None) => {}
        }
        if !self.recurse_allow_answers.is_empty() && self.recurse_deny_answers.is_empty() {
            soft.push("`recurse_allow_answers` lists exceptions to `recurse_deny_answers`; the deny list is empty, so it has no effect".into());
        }
        let ipset_named = self.ipset_name_v4.is_some() || self.ipset_name_v6.is_some();
        if ipset_named == self.ipset_domains.is_empty() {
            soft.push(
                "ipset needs `ipset_name_v4` or `ipset_name_v6` together with `ipset_domains`"
                    .into(),
            );
        } else if ipset_named && !cfg!(target_os = "linux") {
            soft.push("ipset works only on Linux; on this operating system answer addresses are not added to address sets".into());
        }
        if self.min_ttl > self.max_ttl {
            return Err(ConfigError::Invalid(
                "The minimum TTL cannot be greater than the maximum TTL".into(),
            ));
        }
        if self.val_nsec3_max_iterations > MAX_VALIDATOR_NSEC3_ITERATIONS {
            return Err(ConfigError::Invalid(format!(
                "`val_nsec3_max_iterations` must be at most {MAX_VALIDATOR_NSEC3_ITERATIONS} to prevent CPU exhaustion"
            )));
        }
        if [
            self.min_ttl,
            self.max_ttl,
            self.neg_min_ttl,
            self.neg_max_ttl,
        ]
        .into_iter()
        .any(|ttl| ttl > u64::from(u32::MAX))
        {
            return Err(ConfigError::Invalid(
                "DNS TTL values cannot exceed the u32 range".into(),
            ));
        }
        if !(1..=u64::from(u32::MAX)).contains(&self.dhcp_lease_secs) {
            return Err(ConfigError::Invalid(
                "`dhcp_lease_secs` must be within 1..=4294967295 seconds, the range the DHCP wire format can carry"
                    .into(),
            ));
        }
        self.check_edge_service_values()?;
        self.check_protocol_values()?;
        self.check_authority_values()?;
        if !(1..=3_600).contains(&self.query_timeout_secs) {
            return Err(ConfigError::Invalid(
                "Set `query_timeout_secs` between 1 and 3,600 seconds".into(),
            ));
        }
        if self.serve_stale_secs > 31_536_000 {
            return Err(ConfigError::Invalid(
                "Set `serve_stale_secs` to at most 31,536,000 seconds (1 year)".into(),
            ));
        }
        if self.serve_expired_client_timeout_ms > 3_600_000 {
            return Err(ConfigError::Invalid(
                "Set `serve_expired_client_timeout_ms` to at most 3,600,000 milliseconds (1 hour)"
                    .into(),
            ));
        }
        if self.prefetch && !(1..=3_600).contains(&self.prefetch_interval_secs) {
            return Err(ConfigError::Invalid(
                "With prefetch on, set `prefetch_interval_secs` between 1 and 3,600 seconds".into(),
            ));
        }
        let response_cache_available =
            self.cache_enabled && self.max_ttl > 0 && self.cache_size > 0;
        if self.prefetch && !response_cache_available {
            soft.push("`prefetch` needs an enabled response cache with a TTL above 0".into());
        }
        if self.serve_stale_secs > 0 && !response_cache_available {
            soft.push(
                "`serve_stale_secs` needs an enabled response cache with a TTL above 0".into(),
            );
        }
        if !(10..=99).contains(&self.prefetch_ttl_pct) {
            return Err(ConfigError::Invalid(
                "Set `prefetch_ttl_pct` between 10 and 99".into(),
            ));
        }
        if (self.aggressive_nsec || self.harden_below_nxdomain)
            && !(self.dnssec && self.backend != BackendKind::Forward)
        {
            soft.push(
                "`aggressive_nsec` and `harden_below_nxdomain` work only with recursive or split resolution using local DNSSEC validation; they have no effect with the current settings"
                    .into(),
            );
        }

        if self.dnssec
            && self.backend == BackendKind::Forward
            && self.val_nsec3_max_iterations != 150
        {
            soft.push(
                "`val_nsec3_max_iterations` works only with recursive or split resolution; validation in forwarding mode uses a limit of 150 iterations"
                    .into(),
            );
        }

        if self.mixes_plain_and_encrypted_upstreams() {
            soft.push(
                "Both encrypted and plain upstream DNS servers are set. Upstreams are chosen by round-trip time, so the plain ones almost always win and most queries actually leave unencrypted. To use encryption only, empty `upstreams`"
                    .into(),
            );
        }

        if self.dnssec_anchor_file.is_some() && !self.dnssec_validation_active() {
            soft.push(
                "`dnssec_anchor_file` needs `dnssec` turned on; it has no effect with the current settings"
                    .into(),
            );
        }

        let reject_upstream_count = |label: &str, count: usize| -> Result<(), ConfigError> {
            if count > MAX_UPSTREAMS_PER_RESOLVER {
                return Err(ConfigError::Invalid(format!(
                    "{label} can have at most {MAX_UPSTREAMS_PER_RESOLVER} upstream DNS servers; {count} are set"
                )));
            }
            Ok(())
        };
        reject_upstream_count(
            "default forwarding path",
            self.upstreams
                .len()
                .saturating_add(self.upstream_urls.len()),
        )?;
        reject_upstream_count(
            "fallback forwarding path used when the default path fails",
            self.fallback_upstreams.len(),
        )?;
        reject_upstream_count(
            "address lookup path for encrypted DNS servers",
            self.bootstrap.len(),
        )?;
        reject_upstream_count("root DNS server list", self.root_hints.len())?;
        for zone in &self.stub_zones {
            reject_upstream_count(&format!("stub zone '{}'", zone.suffix), zone.servers.len())?;
        }
        for client in &self.clients {
            reject_upstream_count(
                &format!("dedicated forwarding path of client '{}'", client.name),
                client.upstreams.len(),
            )?;
        }
        if let Some(record) = self
            .dynamic_records
            .iter()
            .find(|record| record.values.len() > MAX_DYNAMIC_RECORD_VALUES)
        {
            return Err(ConfigError::Invalid(format!(
                "Dynamic record '{}' can have at most {MAX_DYNAMIC_RECORD_VALUES} values; {} are set",
                record.name,
                record.values.len()
            )));
        }
        for (index, rule) in self.update_policy.iter().enumerate() {
            validate_update_policy_values(
                index,
                &rule.action,
                &rule.identity,
                &rule.name,
                rule.types.iter().map(String::as_str),
            )?;
        }
        if self.neg_min_ttl > self.neg_max_ttl {
            return Err(ConfigError::Invalid(
                "The minimum negative-response TTL cannot be greater than the maximum negative-response TTL".into(),
            ));
        }

        if self.block_response == BlockResponseKind::Custom
            && self.block_ipv4.is_none()
            && self.block_ipv6.is_none()
        {
            soft.push("With the custom block response, set `block_ipv4` or `block_ipv6`; until then blocked names are answered with NXDOMAIN".into(),);
        }

        if let Some(z) = self.stub_zones.iter().find(|z| z.servers.is_empty()) {
            return Err(ConfigError::Invalid(format!(
                "Add at least one DNS server to the `servers` list of stub zone '{}'",
                z.suffix
            )));
        }

        if let Some(c) = self.clients.iter().find(|c| {
            !c.upstreams.is_empty()
                && c.ids.is_empty()
                && c.client_ids.is_empty()
                && c.mac.is_empty()
        }) {
            return Err(ConfigError::Invalid(format!(
                "Client '{}' has dedicated upstream DNS servers but nothing to match it by; set at least one of `ids`, `client_ids`, or `mac`",
                c.name
            )));
        }
        if self.listen.is_empty()
            && self.listen_dot.is_empty()
            && self.listen_doh.is_empty()
            && self.listen_doq.is_empty()
            && self.listen_doh3.is_empty()
            && self.listen_dnscrypt.is_empty()
        {
            soft.push("There are no listening addresses, so no queries are received".into());
        }

        if !self.ddr_name.is_empty() {
            // 알릴 것이 없는데 알리면 클라이언트가 닿지 못하는 곳으로 올라가려 한다.
            if !self.tls_enabled() {
                return Err(ConfigError::Invalid(
                    "ddr_name is set but there is no encrypted listening address to announce; open at least one of listen_dot, listen_doh, listen_doq, or listen_doh3".into(),
                ));
            }
            if !valid_dns_name(&self.ddr_name) {
                return Err(ConfigError::Invalid(format!(
                    "ddr_name '{}' is not a valid DNS name",
                    self.ddr_name
                )));
            }
        }

        for name in &self.domain_insecure {
            let trimmed = name.trim();
            if trimmed != "." && !valid_dns_name(trimmed) {
                return Err(ConfigError::Invalid(format!(
                    "'{name}' in domain_insecure is not a valid DNS name"
                )));
            }
        }
        for name in &self.rebind_allow {
            let trimmed = name.trim();
            if !valid_dns_name(trimmed.strip_prefix("*.").unwrap_or(trimmed)) {
                return Err(ConfigError::Invalid(format!(
                    "'{name}' in rebind_allow is not a valid DNS name"
                )));
            }
        }
        for (key, value) in [
            ("nsid", &self.nsid),
            ("identity", &self.identity),
            ("version", &self.version),
        ] {
            if value.as_ref().is_some_and(|text| text.len() > 255) {
                return Err(ConfigError::Invalid(format!(
                    "{key} cannot exceed 255 bytes; the server name and version are sent in a single TXT string"
                )));
            }
        }
        if !(1..=127).contains(&self.name_ratelimit_labels) {
            return Err(ConfigError::Invalid(
                "name_ratelimit_labels must be between 1 and 127".into(),
            ));
        }
        for (key, urls) in [
            ("blocklist_urls", &self.blocklist_urls),
            ("rpz_urls", &self.rpz_urls),
        ] {
            if let Some(url) = urls.iter().find(|url| !valid_http_url(url)) {
                return Err(ConfigError::Invalid(format!(
                    "'{url}' in {key} must be an http:// or https:// URL"
                )));
            }
        }
        if !self.do_ip4 && !self.do_ip6 {
            return Err(ConfigError::Invalid(
                "With both do_ip4 and do_ip6 off, there is no address to send recursive queries from".into(),
            ));
        }
        if self.prefer_ip4 && self.prefer_ip6 {
            return Err(ConfigError::Invalid(
                "prefer_ip4 and prefer_ip6 cannot both be on".into(),
            ));
        }
        let mut split_names = std::collections::HashSet::new();
        for (key, names) in [
            ("split_recurse", &self.split_recurse),
            ("split_forward", &self.split_forward),
        ] {
            for name in names {
                let Some(normalized) = normalized_dns_name(name) else {
                    return Err(ConfigError::Invalid(format!(
                        "'{name}' in {key} is not a valid DNS name"
                    )));
                };
                if key == "split_recurse" {
                    split_names.insert(normalized);
                } else if split_names.contains(&normalized) {
                    return Err(ConfigError::Invalid(format!(
                        "'{name}' cannot be in both split_recurse and split_forward"
                    )));
                }
            }
        }
        let mut local_names: Vec<(String, Vec<&String>)> = vec![
            (
                "local_a".into(),
                self.local_a.iter().map(|(name, _)| name).collect(),
            ),
            (
                "local_aaaa".into(),
                self.local_aaaa.iter().map(|(name, _)| name).collect(),
            ),
        ];
        for (index, view) in self.views.iter().enumerate() {
            local_names.push((
                format!("views[{index}].local_a"),
                view.local_a.iter().map(|(name, _)| name).collect(),
            ));
            local_names.push((
                format!("views[{index}].local_aaaa"),
                view.local_aaaa.iter().map(|(name, _)| name).collect(),
            ));
        }
        let mut zone_names = std::collections::HashSet::new();
        for (index, zone) in self.local_zones.iter().enumerate() {
            let normalized = if zone.name.trim() == "." {
                Some(String::new())
            } else {
                normalized_dns_name(&zone.name)
            };
            let Some(normalized) = normalized else {
                return Err(ConfigError::Invalid(format!(
                    "local_zones[{index}].name '{}' is not a valid DNS name",
                    zone.name
                )));
            };
            if !zone_names.insert(normalized) {
                return Err(ConfigError::Invalid(format!(
                    "Zone '{}' appears twice in local_zones; a zone can have only one kind",
                    zone.name
                )));
            }
            if !zone.records.is_empty()
                && !matches!(zone.kind, LocalZoneKind::Static | LocalZoneKind::Redirect)
            {
                return Err(ConfigError::Invalid(format!(
                    "local_zones[{index}].records is used only when kind is static or redirect"
                )));
            }
            zone.answers()
                .map_err(|error| ConfigError::Invalid(format!("local_zones[{index}].{error}")))?;
        }
        for (key, names) in local_names {
            let mut seen = std::collections::HashSet::new();
            for name in names {
                let Some(normalized) = normalized_dns_name(name) else {
                    return Err(ConfigError::Invalid(format!(
                        "'{name}' in {key} is not a valid DNS name"
                    )));
                };
                if !seen.insert(normalized) {
                    return Err(ConfigError::Invalid(format!(
                        "'{name}' appears twice in {key}"
                    )));
                }
            }
        }
        if self.cachedb_redis_port == 0 {
            return Err(ConfigError::Invalid(
                "cachedb_redis_port must be between 1 and 65535".into(),
            ));
        }
        if self.cachedb_redis_host.is_some() && self.cachedb_redis_secret.len() < 32 {
            return Err(ConfigError::Invalid(
                "With a shared Redis cache, set `cachedb_redis_secret` to at least 32 bytes".into(),
            ));
        }
        if self.cachedb_redis_username.is_some() && self.cachedb_redis_password.is_none() {
            return Err(ConfigError::Invalid(
                "Set `cachedb_redis_password` together with `cachedb_redis_username`".into(),
            ));
        }
        if self.cachedb_redis_tls_ca.is_some() && !self.cachedb_redis_tls {
            return Err(ConfigError::Invalid(
                "Set `cachedb_redis_tls = true` to use `cachedb_redis_tls_ca`".into(),
            ));
        }
        for (index, rewrite) in self.rewrites.iter().enumerate() {
            let answer = rewrite.answer.trim();
            if answer.parse::<IpAddr>().is_err() && !valid_dns_name(answer) {
                return Err(ConfigError::Invalid(format!(
                    "rewrites[{index}].answer needs an IP address or DNS name: '{answer}'"
                )));
            }
        }

        let listeners: Vec<SocketAddr> = self
            .listen
            .iter()
            .chain(self.listen_dot.iter())
            .chain(self.listen_doh.iter())
            .chain(self.listen_doq.iter())
            .chain(self.listen_doh3.iter())
            .chain(self.listen_dnscrypt.iter())
            .copied()
            .collect();
        let reject_loop = |label: &str, target: SocketAddr| -> Result<(), ConfigError> {
            if listener_conflicts(&listeners, target) {
                return Err(ConfigError::Invalid(format!(
                    "{label}={target} points back to this server's own DNS listening address, which would create a query loop"
                )));
            }
            Ok(())
        };
        for ip in &self.upstreams {
            reject_loop("default upstream DNS server", SocketAddr::new(*ip, 53))?;
        }
        for ip in &self.bootstrap {
            reject_loop(
                "address lookup server for encrypted DNS",
                SocketAddr::new(*ip, 53),
            )?;
        }
        for ip in &self.root_hints {
            reject_loop("root DNS server", SocketAddr::new(*ip, 53))?;
        }
        for raw in &self.fallback_upstreams {
            if let Some(target) = numeric_upstream_endpoint(raw) {
                reject_loop("fallback upstream DNS server", target)?;
            }
        }
        for raw in &self.upstream_urls {
            if let Some(target) = numeric_upstream_endpoint(raw) {
                reject_loop("encrypted upstream DNS server", target)?;
            }
        }
        for zone in &self.stub_zones {
            for raw in &zone.servers {
                if let Some(target) = numeric_upstream_endpoint(raw) {
                    reject_loop(&format!("stub zone '{}'", zone.suffix), target)?;
                }
            }
        }
        for client in &self.clients {
            for raw in &client.upstreams {
                if let Some(target) = numeric_upstream_endpoint(raw) {
                    reject_loop(
                        &format!("dedicated upstream DNS server of client '{}'", client.name),
                        target,
                    )?;
                }
            }
        }
        let configured_tsig_keys: std::collections::HashSet<String> = self
            .tsig_keys
            .iter()
            .map(|key| key.name.trim().trim_end_matches('.').to_ascii_lowercase())
            .collect();
        let mut notify_addresses = std::collections::HashSet::new();
        for target in &self.notify {
            if target.address.port() == 0 {
                return Err(ConfigError::Invalid(
                    "A notify target port cannot be 0".into(),
                ));
            }
            reject_loop("NOTIFY target", target.address)?;
            if !notify_addresses.insert(target.address) {
                return Err(ConfigError::Invalid(format!(
                    "The same NOTIFY target is set twice: {}",
                    target.address
                )));
            }
            if let Some(key) = &target.tsig_key {
                let key = key.trim().trim_end_matches('.').to_ascii_lowercase();
                if !configured_tsig_keys.contains(&key) {
                    return Err(ConfigError::Invalid(format!(
                        "TSIG key '{key}' given for NOTIFY target '{}' is not in `[[tsig_keys]]`",
                        target.address
                    )));
                }
            }
        }
        let mut zone_origins = std::collections::HashMap::<String, &'static str>::new();
        let normalize_origin = |origin: &str| {
            let normalized = origin.trim().trim_end_matches('.').to_ascii_lowercase();
            if normalized.is_empty() {
                ".".to_string()
            } else {
                normalized
            }
        };
        let mut zone_files = std::collections::HashMap::<PathBuf, String>::new();
        for zone in &self.zones {
            if zone.origin.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "Enter the DNS zone name (`origin`) in the `zones` entry".into(),
                ));
            }
            if !zone.dnssec_algorithm.is_empty()
                && !matches!(zone.dnssec_algorithm.as_str(), "ecdsap256" | "ed25519")
            {
                return Err(ConfigError::Invalid(format!(
                    "`dnssec_algorithm` for DNS zone '{}' must be `ecdsap256` or `ed25519`; got: {}",
                    zone.origin, zone.dnssec_algorithm
                )));
            }
            if zone.dnssec_nsec3_iterations != 0 {
                soft.push(format!(
                    "Set `dnssec_nsec3_iterations` for DNS zone '{}' to 0 per RFC 9276",
                    zone.origin
                ));
            }
            let origin = normalize_origin(&zone.origin);
            if let Some(path) = &zone.file {
                if let Some(previous) = zone_files.insert(path.clone(), origin.clone()) {
                    return Err(ConfigError::Invalid(format!(
                        "Zones {previous} and {origin} use the same file: {}",
                        path.display()
                    )));
                }
            }
            if zone_origins.insert(origin.clone(), "zones").is_some() {
                return Err(ConfigError::Invalid(format!(
                    "The same authoritative DNS zone is set twice: {origin}"
                )));
            }
        }
        for (kind, zones) in [("secondary", &self.secondary), ("catalog", &self.catalog)] {
            for zone in zones {
                if zone.origin.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "Enter the zone name (`origin`) in the {kind} zone entry"
                    )));
                }
                let origin = normalize_origin(&zone.origin);
                if kind == "catalog" && zone.file.is_some() {
                    return Err(ConfigError::Invalid(
                        "Catalog zones cannot use the secondary zone file cache".into(),
                    ));
                }
                if let Some(path) = &zone.file {
                    if let Some(previous) = zone_files.insert(path.clone(), origin.clone()) {
                        return Err(ConfigError::Invalid(format!(
                            "Zones {previous} and {origin} use the same file: {}",
                            path.display()
                        )));
                    }
                }
                if let Some(previous) = zone_origins.insert(origin.clone(), kind) {
                    return Err(ConfigError::Invalid(format!(
                        "Zone {origin} is set both in {previous} and in {kind}"
                    )));
                }
                let primary = zone.primary.ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "Set the primary DNS server (`primary`) for {kind} zone '{origin}'"
                    ))
                })?;
                let port = zone.primary_port.unwrap_or(53);
                if port == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "The primary DNS server port (`primary_port`) of {kind} zone '{origin}' cannot be 0"
                    )));
                }
                reject_loop(
                    &format!("{kind} '{origin}' primary"),
                    SocketAddr::new(primary, port),
                )?;
                if let Some(key) = &zone.tsig_key {
                    let key = key.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !configured_tsig_keys.contains(&key) {
                        return Err(ConfigError::Invalid(format!(
                            "TSIG key '{key}' given for {kind} zone '{origin}' is not in `[[tsig_keys]]`"
                        )));
                    }
                }
            }
        }

        let mut tcp_addrs: Vec<(SocketAddr, &str)> = Vec::new();
        let mut udp_addrs: Vec<(SocketAddr, &str)> = Vec::new();
        if self.do_tcp {
            tcp_addrs.extend(self.listen.iter().map(|a| (*a, "listen(TCP)")));
        }
        if self.do_udp {
            udp_addrs.extend(self.listen.iter().map(|a| (*a, "listen(UDP)")));
        }
        tcp_addrs.extend(self.listen_dot.iter().map(|a| (*a, "listen_dot")));
        tcp_addrs.extend(self.listen_doh.iter().map(|a| (*a, "listen_doh")));
        udp_addrs.extend(self.listen_doq.iter().map(|a| (*a, "listen_doq")));
        udp_addrs.extend(self.listen_doh3.iter().map(|a| (*a, "listen_doh3")));
        // DNSCrypt 는 같은 주소를 UDP 와 TCP 둘 다로 연다. 한쪽만 비교하면 설정 검사를
        // 통과한 설정이 시작 때 주소를 못 열어 리스너 하나가 조용히 빠진다.
        udp_addrs.extend(self.listen_dnscrypt.iter().map(|a| (*a, "listen_dnscrypt")));
        tcp_addrs.extend(self.listen_dnscrypt.iter().map(|a| (*a, "listen_dnscrypt")));
        if let Some(addr) = self.control_listen {
            tcp_addrs.push((addr, "control_listen"));
        }
        for (addr, label) in tcp_addrs.iter().chain(udp_addrs.iter()) {
            if addr.port() == 0 {
                return Err(ConfigError::Invalid(format!(
                    "{label} listening addresses cannot use port 0: {addr}"
                )));
            }
        }
        if let Some(msg) =
            first_bind_conflict(&tcp_addrs).or_else(|| first_bind_conflict(&udp_addrs))
        {
            return Err(ConfigError::Invalid(msg));
        }

        if !self.proxy_protocol_ports.is_empty() && self.proxy_protocol_trusted.is_empty() {
            soft.push("With PROXY protocol ports set, also set the trusted proxy address ranges in `proxy_protocol_trusted`".into(),);
        }
        if self.workers > 256 {
            return Err(ConfigError::Invalid("Set `workers` to at most 256".into()));
        }
        if self.max_inflight > 1_000_000 {
            return Err(ConfigError::Invalid(
                "Set `max_inflight` to at most 1,000,000".into(),
            ));
        }
        if self.cache_size > 10_000_000 {
            return Err(ConfigError::Invalid(
                "Set `cache_size` to at most 10,000,000".into(),
            ));
        }

        if self.ns_cache_size > 1_000_000 {
            return Err(ConfigError::Invalid(
                "Set `ns_cache_size` to at most 1,000,000".into(),
            ));
        }
        if self.use_caps_for_id && self.lowercase_outgoing {
            return Err(ConfigError::Invalid(
                "`use_caps_for_id` and `lowercase_outgoing` cannot both be on; turn off `use_caps_for_id` to send lowercase names".into(),
            ));
        }
        if self.cache_shards > 4096 {
            return Err(ConfigError::Invalid(
                "Set `cache_shards` to at most 4,096".into(),
            ));
        }
        if self.upstream_concurrency > MAX_UPSTREAMS_PER_RESOLVER {
            return Err(ConfigError::Invalid(format!(
                "Set `upstream_concurrency` to at most {MAX_UPSTREAMS_PER_RESOLVER}"
            )));
        }

        if self.rate_limit_burst != 0 && self.rate_limit_burst < self.rate_limit_per_sec {
            return Err(ConfigError::Invalid(
                "The burst allowance cannot be smaller than the per-second rate".into(),
            ));
        }

        if self.tls_enabled() && !self.has_cert_source() {
            soft.push("DoT or DoH listening addresses need tls_cert and tls_key, or a self-signed certificate from tls_self_signed_host".into(),);
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            soft.push("tls_cert and tls_key must be set together".into());
        }

        if self.tls_client_ca.is_some() && !self.tls_enabled() {
            soft.push(
                "tls_client_ca (mTLS) needs at least one DoT, DoH, DoQ, or DoH3 listening address"
                    .into(),
            );
        }

        let mut admin_tokens = std::collections::HashSet::new();
        let mut readonly_tokens = std::collections::HashSet::new();
        for (field, tokens, readonly) in [
            (
                "control_token",
                std::slice::from_ref(&self.control_token),
                false,
            ),
            (
                "control_admin_tokens",
                self.control_admin_tokens.as_slice(),
                false,
            ),
            (
                "control_readonly_tokens",
                self.control_readonly_tokens.as_slice(),
                true,
            ),
        ] {
            for token in tokens.iter().filter(|token| !token.is_empty()) {
                if token.chars().count() < 24 {
                    soft.push(format!(
                        "Set the control token (`{field}`) to at least 24 characters"
                    ));
                }
                if readonly {
                    readonly_tokens.insert(token.as_str());
                } else {
                    admin_tokens.insert(token.as_str());
                }
            }
        }
        if admin_tokens.intersection(&readonly_tokens).next().is_some() {
            soft.push("The same token cannot have both administrator and read-only access".into());
        }
        if let Some(addr) = self.control_listen {
            if !addr.ip().is_loopback() {
                return Err(ConfigError::Invalid(format!(
                    "The built-in management server has no TLS, so it can listen only on a local address: {addr}"
                )));
            }
        }
        validate_control_proxy(&self.control_trusted_proxies, &self.control_public_origins)?;

        if self.tftp_enable
            && self.tftp_writable
            && !self.tftp_listen.ip().is_loopback()
            && self.tftp_write_allow.is_empty()
        {
            soft.push("To allow TFTP writes from outside addresses, set the allowed source CIDRs in tftp_write_allow".into(),);
        }

        if let Some(raw) = &self.dns64_prefix {
            validate_dns64_prefix(raw)?;
        }

        for peer in &self.cluster_peers {
            validate_cluster_peer_url(peer)?;
        }

        if self.cluster_raft {
            if self.cluster_node_id == 0 {
                return Err(ConfigError::Invalid(
                    "With Raft, set `cluster_node_id` to a nonzero node number".into(),
                ));
            }
            if self
                .cluster_raft_listen
                .as_deref()
                .and_then(|address| address.trim().parse::<SocketAddr>().ok())
                .is_none()
            {
                return Err(ConfigError::Invalid(
                    "Set `cluster_raft_listen` to a numeric IP address and port that need no operating system DNS lookup"
                        .into(),
                ));
            }
            if self.cluster_raft_secret.len() < 32 {
                return Err(ConfigError::Invalid(
                    "With Raft, set `cluster_raft_secret` to at least 32 bytes".into(),
                ));
            }
            if !is_hex_len(&self.cluster_raft_node_key, 64) {
                return Err(ConfigError::Invalid(
                    "cluster_raft needs a 64-digit hex Ed25519 seed in cluster_raft_node_key"
                        .into(),
                ));
            }
            let mut peer_ids = std::collections::HashSet::new();
            let mut peer_pubkeys = std::collections::HashSet::new();
            for peer in &self.cluster_raft_peers {
                let Some((id, rest)) = peer.split_once('@') else {
                    return Err(ConfigError::Invalid(format!(
                        "Write each `cluster_raft_peers` entry as `node-number@IP-address:port#public-key`: '{peer}'"
                    )));
                };
                let Some((addr, pubkey)) = rest.split_once('#') else {
                    return Err(ConfigError::Invalid(format!(
                        "Each cluster_raft_peers entry needs a 64-digit hex public key for node authentication: '{peer}'"
                    )));
                };
                let Ok(id) = id.trim().parse::<u64>() else {
                    return Err(ConfigError::Invalid(format!(
                        "Invalid node ID in cluster_raft_peers: '{peer}'"
                    )));
                };
                if id == 0
                    || id == self.cluster_node_id
                    || addr.trim().parse::<SocketAddr>().is_err()
                {
                    return Err(ConfigError::Invalid(format!(
                        "Write `cluster_raft_peers` entries as `node-number@numeric-IP:port#public-key`, which needs no operating system DNS lookup: '{peer}'"
                    )));
                }
                if !is_hex_len(pubkey.trim(), 64) {
                    return Err(ConfigError::Invalid(format!(
                        "The public key in `cluster_raft_peers` must be a 64-digit hex Ed25519 public key: '{peer}'"
                    )));
                }
                if !peer_ids.insert(id) {
                    return Err(ConfigError::Invalid(format!(
                        "The same node ID appears twice in cluster_raft_peers: {id}"
                    )));
                }

                if !peer_pubkeys.insert(pubkey.trim().to_ascii_lowercase()) {
                    return Err(ConfigError::Invalid(format!(
                        "Several nodes in cluster_raft_peers use the same public key: '{peer}'"
                    )));
                }
            }
        }

        for u in &self.users {
            if u.name.is_empty() {
                return Err(ConfigError::Invalid(
                    "A [[users]] entry needs a name".into(),
                ));
            }
            if u.password_hash.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "User '{}' needs a password_hash",
                    u.name
                )));
            }
            if !matches!(u.role.as_str(), "admin" | "readonly") {
                return Err(ConfigError::Invalid(format!(
                    "The role of user '{}' must be admin or readonly; got: '{}'",
                    u.name, u.role
                )));
            }
        }
        if self.users.iter().any(|u| !u.name.is_empty()) {
            let mut names: Vec<&str> = self.users.iter().map(|u| u.name.as_str()).collect();
            names.sort_unstable();
            if names.windows(2).any(|w| w[0] == w[1]) {
                return Err(ConfigError::Invalid(
                    "The same user name appears twice in [[users]]".into(),
                ));
            }
        }

        if let Some(ep) = &self.zones_etcd {
            if !ep.starts_with("http://") && !ep.starts_with("https://") {
                return Err(ConfigError::Invalid(
                    "zones_etcd must be an http:// or https:// endpoint".into(),
                ));
            }
            if ep.starts_with("https://") && self.zones_etcd_ca.is_none() {
                return Err(ConfigError::Invalid(
                    "An https zones_etcd needs a CA PEM file in zones_etcd_ca; etcd connections do not use the system trust store".into(),
                ));
            }
        }

        if self.xfr_tsig_required && self.tsig_keys.is_empty() {
            soft.push(
                "xfr_tsig_required is on but there are no [[tsig_keys]], so every zone transfer request is refused; set at least one [[tsig_keys]] entry to allow transfers"
                    .into(),
            );
        }
        if self.update_tsig_required && self.tsig_keys.is_empty() {
            soft.push(
                "update_tsig_required is on but there are no [[tsig_keys]], so every dynamic update request is refused; set at least one [[tsig_keys]] entry to allow updates"
                    .into(),
            );
        }
        for k in &self.tsig_keys {
            if k.name.trim().is_empty() || !valid_base64_secret(&k.secret, 16) {
                return Err(ConfigError::Invalid(
                    "A [[tsig_keys]] entry needs a name and a valid Base64 secret of at least 16 bytes"
                        .into(),
                ));
            }
        }

        Ok(())
    }

    /** @brief 허용 목록이 비어 기본 허용으로 도는지. */
    pub fn acl_default_allow(&self) -> bool {
        self.acl_allow.is_empty() && self.acl_allow_ids.is_empty()
    }

    /**
     * @brief 이 서버의 질의 수신 주소 가운데 다른 호스트에서 닿을 수 있는 것이 있는지.
     * @details 루프백에만 묶여 있으면 이 기계 밖에서는 질의를 보낼 수 없다. 증폭이나 반사
     *          같은 위험은 그 경우 성립하지 않는다.
     */
    pub fn reachable_from_other_hosts(&self) -> bool {
        [
            &self.listen,
            &self.listen_dot,
            &self.listen_doh,
            &self.listen_doq,
            &self.listen_doh3,
            &self.listen_dnscrypt,
        ]
        .into_iter()
        .flatten()
        .any(|addr| !addr.ip().is_loopback())
    }

    /**
     * @brief 열린 리졸버로 동작할 위험을 알리는 경고들.
     * @note 속도 제한을 걸지 말지는 운영자가 정하므로 시작은 막지 않는다. 대신 이 경고를
     *       시작할 때마다 로그에 남긴다.
     */
    pub fn open_resolver_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.mode == Mode::Public && self.reachable_from_other_hosts() {
            if self.rate_limit_per_sec == 0 || self.rate_limit_burst == 0 {
                out.push(
                    "Public mode has no per-client query rate limit. This server could be abused for DNS amplification and reflection attacks; set rate_limit_per_sec and rate_limit_burst.".into(),
                );
            }
            if self.acl_default_allow() {
                out.push(
                    "Public mode accepts requests from every source address. Set acl_allow to only the address ranges you actually serve.".into(),
                );
            }
        }
        out
    }

    /**
     * @brief 암호화 업스트림과 평문 업스트림을 함께 쓰고 있는지.
     *
     * @details 고르는 기준이 왕복 시간이라 평문이 거의 언제나 이긴다. 둘을 섞으면
     *          암호화를 적어 두고도 실제로는 대부분 평문으로 나간다.
     * @return 섞여 있으면 참.
     */
    pub fn mixes_plain_and_encrypted_upstreams(&self) -> bool {
        self.backend != BackendKind::Recurse
            && !self.upstreams.is_empty()
            && !self.upstream_urls.is_empty()
    }

    /** @brief 암호화 전송이 하나라도 켜져 있는지. */
    pub fn tls_enabled(&self) -> bool {
        !self.listen_dot.is_empty()
            || !self.listen_doh.is_empty()
            || !self.listen_doq.is_empty()
            || !self.listen_doh3.is_empty()
    }

    /** @brief 인증서를 어디서든 얻을 수 있는지. */
    pub fn has_cert_source(&self) -> bool {
        (self.tls_cert.is_some() && self.tls_key.is_some()) || self.tls_self_signed_host.is_some()
    }

    /** @brief 클라이언트 인증이 켜져 있는지. */
    pub fn tls_authenticated(&self) -> bool {
        self.tls_client_ca.is_some()
    }

    /** @brief 지금 적용된 설정을 JSON으로. 비밀 항목은 가린다. */
    pub fn effective_json(&self) -> String {
        /** @brief 문자열을 JSON 값으로. */
        fn js(s: &str) -> String {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        /** @brief 목록을 JSON 배열로. */
        fn sarr<T: std::fmt::Display>(v: &[T]) -> String {
            let items: Vec<String> = v.iter().map(|x| js(&x.to_string())).collect();
            format!("[{}]", items.join(","))
        }
        /** @brief 경로 목록을 JSON 배열로. */
        fn parr(v: &[PathBuf]) -> String {
            let items: Vec<String> = v.iter().map(|p| js(&p.display().to_string())).collect();
            format!("[{}]", items.join(","))
        }
        /** @brief 있을 수도 없을 수도 있는 문자열을 JSON 값으로. */
        fn opt_s(v: &Option<String>) -> String {
            v.as_ref().map_or("null".to_string(), |s| js(s))
        }
        /** @brief 암호가 섞인 주소를 가려서 JSON 값으로. */
        fn opt_redacted_url(v: &Option<SecretString>) -> String {
            v.as_ref().map_or("null".to_string(), |s| {
                js(&redact_url_credentials(s.as_str()))
            })
        }
        /** @brief 있을 수도 없을 수도 있는 경로를 JSON 값으로. */
        fn opt_p(v: &Option<PathBuf>) -> String {
            v.as_ref()
                .map_or("null".to_string(), |p| js(&p.display().to_string()))
        }
        /** @brief 값을 소문자 이름으로. */
        fn lower_dbg<T: std::fmt::Debug>(v: &T) -> String {
            js(&format!("{v:?}").to_ascii_lowercase())
        }

        let mut o: Vec<String> = Vec::with_capacity(96);
        let mut kv = |k: &str, v: String| o.push(format!("{}:{}", js(k), v));

        kv("mode", lower_dbg(&self.mode));
        kv("backend", lower_dbg(&self.backend));
        kv("listen", sarr(&self.listen));
        kv("upstreams", sarr(&self.upstreams));
        kv("upstream_urls", sarr(&self.upstream_urls));
        kv("bootstrap", sarr(&self.bootstrap));
        kv("root_hints", sarr(&self.root_hints));
        kv("fallback_upstreams", sarr(&self.fallback_upstreams));
        kv("upstream_strategy", lower_dbg(&self.upstream_strategy));
        kv(
            "upstream_concurrency",
            self.upstream_concurrency.to_string(),
        );
        kv(
            "query_source",
            opt_s(&self.query_source.map(|a| a.to_string())),
        );
        kv(
            "query_source_v6",
            opt_s(&self.query_source_v6.map(|a| a.to_string())),
        );

        kv("blocklists", parr(&self.blocklists));
        kv("allowlists", parr(&self.allowlists));
        kv("blocklist_urls", sarr(&self.blocklist_urls));
        kv("blocklist_titles", sarr(&self.blocklist_titles));
        kv(
            "disabled_blocklist_urls",
            sarr(&self.disabled_blocklist_urls),
        );
        kv("block_rules", sarr(&self.block_rules));
        kv("allow_rules", sarr(&self.allow_rules));
        kv("list_refresh_secs", self.list_refresh_secs.to_string());
        kv("blocked_services", sarr(&self.blocked_services));
        kv("safe_search", self.safe_search.to_string());
        kv("safe_browsing", self.safe_browsing.to_string());
        kv("parental_control", self.parental_control.to_string());
        kv("refused_domains", sarr(&self.refused_domains));
        kv("rpz_files", parr(&self.rpz_files));
        kv("rpz_urls", sarr(&self.rpz_urls));
        kv("rewrites", self.rewrites.len().to_string());
        kv("dynamic_records", self.dynamic_records.len().to_string());
        kv("local_zones", self.local_zones.len().to_string());
        kv("clients", self.clients.len().to_string());
        kv("users", self.users.len().to_string());
        kv("views", self.views.len().to_string());
        kv("policy", self.policy.len().to_string());
        kv("wasm_policy", opt_p(&self.wasm_policy));
        {
            let items: Vec<String> = self
                .wasm_plugins
                .iter()
                .map(|p| {
                    let mut obj = format!("{{\"path\":{}", js(&p.path.display().to_string()));
                    if let Some(name) = &p.name {
                        obj.push_str(&format!(",\"name\":{}", js(name)));
                    }
                    if let Some(mode) = &p.fail_mode {
                        obj.push_str(&format!(",\"fail_mode\":{}", js(mode)));
                    }
                    obj.push('}');
                    obj
                })
                .collect();
            kv("wasm_plugins", format!("[{}]", items.join(",")));
        }
        kv("wasm_fail_mode", js(&self.wasm_fail_mode));

        kv("block_response", lower_dbg(&self.block_response));
        kv(
            "block_ipv4",
            self.block_ipv4
                .map_or("null".into(), |v| js(&v.to_string())),
        );
        kv(
            "block_ipv6",
            self.block_ipv6
                .map_or("null".into(), |v| js(&v.to_string())),
        );
        kv(
            "blocked_response_ttl",
            self.blocked_response_ttl.to_string(),
        );
        kv("block_aaaa", self.block_aaaa.to_string());
        kv("bogus_nxdomain", sarr(&self.bogus_nxdomain));
        kv("domain_needed", self.domain_needed.to_string());
        kv("bogus_priv", self.bogus_priv.to_string());
        kv("empty_zones", self.empty_zones.to_string());
        kv("local_ttl", self.local_ttl.to_string());

        kv("cache_size", self.cache_size.to_string());
        kv("min_ttl", self.min_ttl.to_string());
        kv("max_ttl", self.max_ttl.to_string());
        kv("neg_min_ttl", self.neg_min_ttl.to_string());
        kv("neg_max_ttl", self.neg_max_ttl.to_string());
        kv("query_timeout_secs", self.query_timeout_secs.to_string());
        kv("max_inflight", self.max_inflight.to_string());
        kv("workers", self.workers.to_string());
        kv("do_udp", self.do_udp.to_string());
        kv("do_tcp", self.do_tcp.to_string());
        kv("serve_stale_secs", self.serve_stale_secs.to_string());
        kv(
            "serve_expired_reply_ttl",
            self.serve_expired_reply_ttl.to_string(),
        );
        kv(
            "serve_expired_ttl_reset",
            self.serve_expired_ttl_reset.to_string(),
        );
        kv(
            "serve_expired_client_timeout_ms",
            self.serve_expired_client_timeout_ms.to_string(),
        );
        kv("serve_stale_refresh", self.serve_stale_refresh.to_string());
        kv(
            "proxy_protocol_ports",
            format!(
                "[{}]",
                self.proxy_protocol_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
        kv(
            "proxy_protocol_trusted",
            sarr(
                &self
                    .proxy_protocol_trusted
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
        );
        kv("edns_buffer_size", self.edns_buffer_size.to_string());
        kv("deny_any", self.deny_any.to_string());
        kv("minimal_responses", self.minimal_responses.to_string());
        kv("edns_padding_block", self.edns_padding_block.to_string());
        kv(
            "edns_tcp_keepalive_secs",
            self.edns_tcp_keepalive_secs.to_string(),
        );
        kv("cache_enabled", self.cache_enabled.to_string());
        kv("sharded_cache", self.sharded_cache.to_string());
        kv("cache_shards", self.cache_shards.to_string());
        kv("prefetch", self.prefetch.to_string());
        kv("prefetch_min_hits", self.prefetch_min_hits.to_string());
        kv("prefetch_ttl_pct", self.prefetch_ttl_pct.to_string());
        kv(
            "prefetch_interval_secs",
            self.prefetch_interval_secs.to_string(),
        );
        kv("dns64_prefix", opt_s(&self.dns64_prefix));
        kv("dns64_synthall", self.dns64_synthall.to_string());
        kv("rrset_roundrobin", self.rrset_roundrobin.to_string());
        kv("track_rule_hits", self.track_rule_hits.to_string());
        kv("aggressive_nsec", self.aggressive_nsec.to_string());
        kv(
            "name_ratelimit_per_sec",
            self.name_ratelimit_per_sec.to_string(),
        );
        kv(
            "name_ratelimit_labels",
            self.name_ratelimit_labels.to_string(),
        );
        kv(
            "harden_below_nxdomain",
            self.harden_below_nxdomain.to_string(),
        );
        kv("dhcp_enable", self.dhcp_enable.to_string());
        kv("dhcp_server_ip", opt_s(&self.dhcp_server_ip));
        kv("dhcp_range_start", opt_s(&self.dhcp_range_start));
        kv("dhcp_range_end", opt_s(&self.dhcp_range_end));
        kv("dhcp_subnet_mask", opt_s(&self.dhcp_subnet_mask));
        kv("dhcp_router", opt_s(&self.dhcp_router));
        kv("dhcp_dns", sarr(&self.dhcp_dns));
        kv("dhcp_lease_secs", self.dhcp_lease_secs.to_string());
        kv("dhcp_local_domain", js(&self.dhcp_local_domain));
        kv("dhcp_tftp_server", opt_s(&self.dhcp_tftp_server));
        kv("dhcp_boot_file", opt_s(&self.dhcp_boot_file));
        kv("tftp_enable", self.tftp_enable.to_string());
        kv("tftp_root", opt_s(&self.tftp_root));
        kv("tftp_listen", js(&self.tftp_listen.to_string()));
        kv("tftp_writable", self.tftp_writable.to_string());
        kv("tftp_write_allow", sarr(&self.tftp_write_allow));
        kv(
            "tftp_allow_overwrite",
            self.tftp_allow_overwrite.to_string(),
        );
        kv("ra_enable", self.ra_enable.to_string());
        kv("ra_prefix", opt_s(&self.ra_prefix));
        kv("ra_managed", self.ra_managed.to_string());
        kv("ra_other", self.ra_other.to_string());
        kv("ra_router_lifetime", self.ra_router_lifetime.to_string());
        kv("ra_interval", self.ra_interval.to_string());
        kv("ra_mtu", self.ra_mtu.to_string());
        kv("ra_interface_index", self.ra_interface_index.to_string());
        kv("dhcp6_enable", self.dhcp6_enable.to_string());
        kv("dhcp6_range_start", opt_s(&self.dhcp6_range_start));
        kv("dhcp6_range_end", opt_s(&self.dhcp6_range_end));
        kv("dhcp6_dns", sarr(&self.dhcp6_dns));
        kv(
            "dhcp6_interface_index",
            self.dhcp6_interface_index.to_string(),
        );
        kv("dhcp_lease_file", opt_s(&self.dhcp_lease_file));
        kv("dhcp_static_file", opt_s(&self.dhcp_static_file));
        kv("dhcp6_lease_file", opt_s(&self.dhcp6_lease_file));
        kv("mac_vendor_db", opt_s(&self.mac_vendor_db));
        kv("ipset_name_v4", opt_s(&self.ipset_name_v4));
        kv("ipset_name_v6", opt_s(&self.ipset_name_v6));
        kv("ipset_domains", sarr(&self.ipset_domains));
        kv("cachedb_redis_host", opt_s(&self.cachedb_redis_host));
        kv("cachedb_redis_port", self.cachedb_redis_port.to_string());
        kv(
            "cachedb_redis_expire_secs",
            self.cachedb_redis_expire_secs.to_string(),
        );
        kv(
            "cachedb_redis_secret_set",
            (!self.cachedb_redis_secret.is_empty()).to_string(),
        );
        kv(
            "cachedb_redis_username",
            opt_s(&self.cachedb_redis_username),
        );
        kv(
            "cachedb_redis_password_set",
            self.cachedb_redis_password.is_some().to_string(),
        );
        kv("cachedb_redis_tls", self.cachedb_redis_tls.to_string());
        kv("cachedb_redis_tls_ca", opt_p(&self.cachedb_redis_tls_ca));
        kv("cluster_peers", sarr(&self.cluster_peers));
        kv("cluster_raft", self.cluster_raft.to_string());
        kv("cluster_node_id", self.cluster_node_id.to_string());
        kv("cluster_raft_listen", opt_s(&self.cluster_raft_listen));
        kv("cluster_raft_peers", sarr(&self.cluster_raft_peers));
        kv(
            "cluster_raft_secret_set",
            (!self.cluster_raft_secret.is_empty()).to_string(),
        );
        kv(
            "cluster_raft_node_key_set",
            (!self.cluster_raft_node_key.is_empty()).to_string(),
        );
        kv("rebind_protection", self.rebind_protection.to_string());
        kv("rebind_allow", sarr(&self.rebind_allow));

        kv("dnssec", self.dnssec.to_string());
        kv("dnssec_strict", self.dnssec_strict.to_string());
        kv("val_permissive_mode", self.val_permissive_mode.to_string());
        kv(
            "dnssec_accept_expired",
            self.dnssec_accept_expired.to_string(),
        );
        kv("ignore_cd_flag", self.ignore_cd_flag.to_string());
        kv("dnssec_rfc5011", self.dnssec_rfc5011.to_string());
        kv("dnssec_anchor_file", opt_p(&self.dnssec_anchor_file));
        kv(
            "dnssec_roll_interval_secs",
            self.dnssec_roll_interval_secs.to_string(),
        );
        kv("root_key_sentinel", self.root_key_sentinel.to_string());
        kv(
            "trust_anchor_signaling",
            self.trust_anchor_signaling.to_string(),
        );
        kv("recursion_limit", self.recursion_limit.to_string());
        kv("cname_limit", self.cname_limit.to_string());
        kv("dname_limit", self.dname_limit.to_string());
        kv("do_ip4", self.do_ip4.to_string());
        kv("do_ip6", self.do_ip6.to_string());
        kv("prefer_ip4", self.prefer_ip4.to_string());
        kv("prefer_ip6", self.prefer_ip6.to_string());
        kv(
            "qname_minimisation_strict",
            self.qname_minimisation_strict.to_string(),
        );
        kv(
            "harden_referral_path",
            self.harden_referral_path.to_string(),
        );
        kv("use_caps_for_id", self.use_caps_for_id.to_string());
        kv("lowercase_outgoing", self.lowercase_outgoing.to_string());
        kv(
            "harden_large_queries",
            self.harden_large_queries.to_string(),
        );
        kv("domain_insecure", sarr(&self.domain_insecure));
        kv("ns_recursion_limit", self.ns_recursion_limit.to_string());
        kv("ns_cache_size", self.ns_cache_size.to_string());
        kv("recurse_deny_server", sarr(&self.recurse_deny_server));
        kv("recurse_allow_server", sarr(&self.recurse_allow_server));
        kv("recurse_deny_answers", sarr(&self.recurse_deny_answers));
        kv("recurse_allow_answers", sarr(&self.recurse_allow_answers));
        kv(
            "val_nsec3_max_iterations",
            self.val_nsec3_max_iterations.to_string(),
        );

        kv("split_default", lower_dbg(&self.split_default));
        kv("split_recurse", sarr(&self.split_recurse));
        kv("split_forward", sarr(&self.split_forward));
        kv("local_a", self.local_a.len().to_string());
        kv("local_aaaa", self.local_aaaa.len().to_string());
        kv("stub_zones", self.stub_zones.len().to_string());

        kv("acl_allow", sarr(&self.acl_allow));
        kv("acl_deny", sarr(&self.acl_deny));
        kv("acl_allow_ids", sarr(&self.acl_allow_ids));
        kv("acl_deny_ids", sarr(&self.acl_deny_ids));
        kv("rate_limit_per_sec", self.rate_limit_per_sec.to_string());
        kv("rate_limit_burst", self.rate_limit_burst.to_string());
        kv("run_as_user", opt_s(&self.run_as_user));
        kv("run_as_group", opt_s(&self.run_as_group));
        kv("rate_limit_allow", sarr(&self.rate_limit_allow));
        kv("cookies", lower_dbg(&self.cookies));
        kv("subnet_rrl_per_sec", self.subnet_rrl_per_sec.to_string());
        kv("subnet_rrl_burst", self.subnet_rrl_burst.to_string());

        kv("listen_dot", sarr(&self.listen_dot));
        kv("listen_doh", sarr(&self.listen_doh));
        kv("listen_doq", sarr(&self.listen_doq));
        kv("listen_doh3", sarr(&self.listen_doh3));
        kv("listen_dnscrypt", sarr(&self.listen_dnscrypt));
        kv("dnscrypt_provider_name", js(&self.dnscrypt_provider_name));
        kv("doh_path", js(&self.doh_path));
        kv("ddr_name", js(&self.ddr_name));
        kv("tls_cert", opt_p(&self.tls_cert));
        kv("tls_key", opt_p(&self.tls_key));
        kv("tls_self_signed_host", opt_s(&self.tls_self_signed_host));
        kv("tls_client_ca", opt_p(&self.tls_client_ca));
        kv("tls_revocation", js(&self.tls_revocation));
        kv(
            "tls_revocation_softfail",
            self.tls_revocation_softfail.to_string(),
        );
        kv("acme_directory_url", opt_s(&self.acme_directory_url));
        kv("acme_contact_email", opt_s(&self.acme_contact_email));
        kv("acme_domains", sarr(&self.acme_domains));
        kv("acme_challenge", js(&self.acme_challenge));
        kv("acme_account_key_file", opt_s(&self.acme_account_key_file));
        kv("acme_cert_file", opt_s(&self.acme_cert_file));
        kv("acme_key_file", opt_s(&self.acme_key_file));
        kv("mtls_enforced", self.tls_authenticated().to_string());

        let zone_origins: Vec<String> = self.zones.iter().map(|z| z.origin.clone()).collect();
        kv("zones", sarr(&zone_origins));
        kv("zones_dir", opt_p(&self.zones_dir));
        kv("zones_db", opt_p(&self.zones_db));
        kv("zones_db_table", js(&self.zones_db_table));
        kv("zones_postgres", opt_redacted_url(&self.zones_postgres));
        kv("zones_mysql", opt_redacted_url(&self.zones_mysql));
        kv("zones_lmdb", opt_p(&self.zones_lmdb));
        kv("zones_sql_table", js(&self.zones_sql_table));
        kv("catalog_serve", opt_s(&self.catalog_serve));
        kv("zones_etcd", opt_s(&self.zones_etcd));
        kv("zones_etcd_prefix", js(&self.zones_etcd_prefix));
        kv("zones_etcd_ca", opt_p(&self.zones_etcd_ca));
        kv("zones_etcd_user", opt_s(&self.zones_etcd_user));
        kv(
            "zones_etcd_auth",
            self.zones_etcd_password.is_some().to_string(),
        );
        let sec_origins: Vec<String> = self.secondary.iter().map(|s| s.origin.clone()).collect();
        kv("secondary", sarr(&sec_origins));
        let cat_origins: Vec<String> = self.catalog.iter().map(|s| s.origin.clone()).collect();
        kv("catalog", sarr(&cat_origins));
        kv("xfr_allow", sarr(&self.xfr_allow));
        kv("xfr_tsig_required", self.xfr_tsig_required.to_string());
        kv("zonemd_check", self.zonemd_check.to_string());
        kv(
            "zonemd_reject_absence",
            self.zonemd_reject_absence.to_string(),
        );
        let notify_addresses: Vec<SocketAddr> =
            self.notify.iter().map(|target| target.address).collect();
        kv("notify", sarr(&notify_addresses));

        let tsig_names: Vec<String> = self.tsig_keys.iter().map(|k| k.name.clone()).collect();
        kv("tsig_keys", sarr(&tsig_names));
        kv("update_allow", sarr(&self.update_allow));
        kv("update_policy", self.update_policy.len().to_string());
        kv(
            "update_tsig_required",
            self.update_tsig_required.to_string(),
        );
        kv("ecs_mode", lower_dbg(&self.ecs_mode));
        kv(
            "ecs_custom_ip",
            self.ecs_custom_ip
                .map_or("null".into(), |v| js(&v.to_string())),
        );

        kv(
            "control_listen",
            self.control_listen
                .map_or("null".into(), |v| js(&v.to_string())),
        );
        let admin_n = self.control_admin_tokens.len() + usize::from(!self.control_token.is_empty());
        kv("control_admin_tokens", admin_n.to_string());
        kv(
            "control_readonly_tokens",
            self.control_readonly_tokens.len().to_string(),
        );
        kv(
            "control_trusted_proxies",
            sarr(&self.control_trusted_proxies),
        );
        kv("control_public_origins", sarr(&self.control_public_origins));
        kv("hide_identity", self.hide_identity.to_string());
        kv("hide_version", self.hide_version.to_string());
        kv("nsid", opt_s(&self.nsid));
        kv("identity", opt_s(&self.identity));
        kv("version", opt_s(&self.version));
        kv("log_level", opt_s(&self.log_level));
        kv("querylog", self.querylog.to_string());
        kv("querylog_size", self.querylog_size.to_string());
        kv(
            "querylog_retention_secs",
            self.querylog_retention_secs.to_string(),
        );
        kv("anonymize_client_ip", self.anonymize_client_ip.to_string());
        kv("querylog_ignored", sarr(&self.querylog_ignored));
        kv(
            "stats_retention_secs",
            self.stats_retention_secs.to_string(),
        );
        kv("querylog_file", opt_p(&self.querylog_file));
        kv("stats_file", opt_p(&self.stats_file));
        kv("persist_flush_secs", self.persist_flush_secs.to_string());
        kv("dnstap_file", opt_p(&self.dnstap_file));
        kv("dnstap_identity", js(&self.dnstap_identity));
        kv("release_check", self.release_check.to_string());

        format!("{{{}}}", o.join(","))
    }
}

/** @brief 업스트림 주소 표기가 이 서버가 아는 형식인지. */
fn valid_upstream_spec(raw: &str, allow_plain_ip: bool) -> bool {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return false;
    }
    if allow_plain_ip && (raw.parse::<IpAddr>().is_ok() || raw.parse::<SocketAddr>().is_ok()) {
        return true;
    }

    let Some((scheme, rest)) = raw.split_once("://") else {
        return false;
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "udp" | "tcp" | "tls" | "https" | "quic" | "h3"
    ) {
        return false;
    }
    if rest.is_empty() || rest.matches('#').count() > 1 {
        return false;
    }

    let (endpoint, sni) = match rest.split_once('#') {
        Some((endpoint, sni)) if !sni.trim().is_empty() => (endpoint, Some(sni)),
        Some(_) => return false,
        None => (rest, None),
    };
    if sni.is_some_and(|value| value.chars().any(char::is_whitespace)) {
        return false;
    }

    let authority = endpoint.split('/').next().unwrap_or_default().trim();
    if authority.is_empty() {
        return false;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        if bracketed[..close].parse::<IpAddr>().is_err() {
            return false;
        }
        let tail = &bracketed[close + 1..];
        return tail.is_empty()
            || tail
                .strip_prefix(':')
                .and_then(|value| value.parse::<u16>().ok())
                .is_some_and(|port| port != 0);
    }

    if authority.matches(':').count() == 1 {
        let Some((host, value)) = authority.rsplit_once(':') else {
            return false;
        };
        return !host.trim().is_empty() && value.parse::<u16>().ok().is_some_and(|port| port != 0);
    }

    !authority.chars().any(char::is_whitespace)
}

/** @brief 이 주소가 이 서버의 리스너 중 하나와 겹치는지. */
fn listener_conflicts(listeners: &[SocketAddr], target: SocketAddr) -> bool {
    listeners
        .iter()
        .any(|listener| dns_endpoint_conflicts(*listener, target))
}

/**
 * @brief 이 업스트림이 자기 자신을 가리키는지.
 * @warning 가리키면 질의가 무한히 돌아온다. 어느 대역에 묶였는지에 따라 판정이 갈리므로
 *          주소를 정규화해 비교한다.
 */
pub fn dns_endpoint_conflicts(listener: SocketAddr, target: SocketAddr) -> bool {
    if listener.port() != target.port() {
        return false;
    }
    let listener_ip = normalized_ip(listener.ip());
    let target_ip = normalized_ip(target.ip());
    listener_ip == target_ip
        || listener_ip.is_unspecified()
            && (target_ip.is_loopback() || target_ip.is_unspecified())
            && (listener_ip.is_ipv6() || listener_ip.is_ipv4() == target_ip.is_ipv4())
}

/** @brief 주소를 비교 가능한 형태로. IPv6에 감싼 IPv4를 펴 준다. */
fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

/** @brief 같은 주소에 두 번 묶으려는 곳을 찾는다. */
fn first_bind_conflict(addrs: &[(SocketAddr, &str)]) -> Option<String> {
    for i in 0..addrs.len() {
        for j in (i + 1)..addrs.len() {
            let (a, la) = addrs[i];
            let (b, lb) = addrs[j];
            if a.port() != b.port() {
                continue;
            }
            let a_ip = normalized_ip(a.ip());
            let b_ip = normalized_ip(b.ip());
            let same_family = a_ip.is_ipv4() == b_ip.is_ipv4();
            let dual_stack_wildcard =
                a_ip.is_ipv6() && a_ip.is_unspecified() || b_ip.is_ipv6() && b_ip.is_unspecified();
            let overlap = a_ip == b_ip
                || (a_ip.is_unspecified() || b_ip.is_unspecified())
                    && (same_family || dual_stack_wildcard);
            if overlap {
                return Some(format!(
                    "DNS listening address conflict: {la}={a} and {lb}={b}"
                ));
            }
        }
    }
    None
}

/** @brief 업스트림 표기에서 주소를 추출한다. 이름이면 없다. */
fn numeric_upstream_endpoint(raw: &str) -> Option<SocketAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (scheme, rest) = raw
        .split_once("://")
        .map(|(scheme, rest)| (scheme.to_ascii_lowercase(), rest))
        .unwrap_or_else(|| ("udp".to_string(), raw));
    let default_port = match scheme.as_str() {
        "udp" | "tcp" => 53,
        "tls" | "quic" => 853,
        "https" | "h3" => 443,
        _ => return None,
    };
    let authority = rest
        .split('#')
        .next()
        .unwrap_or(rest)
        .split('/')
        .next()
        .unwrap_or(rest)
        .trim();
    if authority.eq_ignore_ascii_case("localhost") {
        return Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            default_port,
        ));
    }
    if let Some((host, value)) = authority.rsplit_once(':') {
        if host.eq_ignore_ascii_case("localhost") {
            let port = value.parse::<u16>().ok().filter(|port| *port != 0)?;
            return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        }
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let ip = bracketed[..close].parse::<IpAddr>().ok()?;
        let tail = &bracketed[close + 1..];
        let port = if tail.is_empty() {
            default_port
        } else {
            tail.strip_prefix(':')?
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)?
        };
        return Some(SocketAddr::new(ip, port));
    }
    if let Ok(ip) = authority.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    let ip = host.parse::<IpAddr>().ok()?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    Some(SocketAddr::new(ip, port))
}

#[derive(Debug)]
/** @brief 설정 실패 사유. 사람이 읽고 고칠 수 있어야 한다. */
pub enum ConfigError {
    /** @brief 설정 텍스트를 읽지 못했다. */
    Parse(String),
    /** @brief 값이 규칙에 맞지 않는다. */
    Invalid(String),
    /** @brief 파일을 읽고 쓰지 못했다. */
    Io(String),
}

impl std::fmt::Display for ConfigError {
    /** @brief 사람이 읽을 실패 사유. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Parse(s) => write!(f, "Could not parse the configuration: {s}"),
            ConfigError::Invalid(s) => write!(f, "Invalid configuration value: {s}"),
            ConfigError::Io(s) => write!(f, "Could not read the configuration file: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {}

use crate::toml::Value;
use std::str::FromStr;

/** @brief 문자열 항목을 읽는다. */
fn gstr(r: &Value, k: &str) -> Option<String> {
    r.get(k).and_then(|v| v.as_str()).map(String::from)
}
/** @brief 참거짓 항목을 읽는다. 없으면 기본값. */
fn gbool(r: &Value, k: &str, d: bool) -> bool {
    r.get(k).and_then(|v| v.as_bool()).unwrap_or(d)
}
/** @brief 부호 있는 정수 항목을 읽는다. */
fn gi64(r: &Value, k: &str) -> Option<i64> {
    r.get(k).and_then(|v| v.as_int())
}
/** @brief 부호 없는 정수 항목을 읽는다. */
fn gu64(r: &Value, k: &str, d: u64) -> u64 {
    gi64(r, k).map(|i| i as u64).unwrap_or(d)
}
/** @brief 크기 항목을 읽는다. */
fn gusize(r: &Value, k: &str, d: usize) -> usize {
    gi64(r, k).map(|i| i as usize).unwrap_or(d)
}
/** @brief 배열 항목을 읽는다. */
fn garr<'a>(r: &'a Value, k: &str) -> &'a [Value] {
    r.get(k).and_then(|v| v.as_array()).unwrap_or_default()
}
/** @brief 문자열 배열을 읽는다. */
fn gstrvec(r: &Value, k: &str) -> Vec<String> {
    garr(r, k)
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}
/** @brief 파싱 가능한 값들의 배열을 읽는다. */
fn gparsevec<T: FromStr>(r: &Value, k: &str) -> Vec<T> {
    garr(r, k)
        .iter()
        .filter_map(|v| v.as_str()?.parse::<T>().ok())
        .collect()
}
/** @brief 경로 배열을 읽는다. */
fn gpathvec(r: &Value, k: &str) -> Vec<PathBuf> {
    gstrvec(r, k).into_iter().map(PathBuf::from).collect()
}

/** @brief 플러그인 설정을 읽는다. 경로만 적은 형태와 테이블 형태를 모두 받는다. */
fn dec_wasm_plugins(root: &Value) -> Vec<WasmPluginConfig> {
    let Some(values) = root.get("wasm_plugins").and_then(Value::as_array) else {
        return vec![];
    };
    values
        .iter()
        .filter_map(|value| match value {
            Value::String(path) => Some(WasmPluginConfig {
                path: PathBuf::from(path.as_str()),
                name: None,
                fail_mode: None,
            }),
            Value::Table(table) => Some(WasmPluginConfig {
                path: PathBuf::from(table.get("path")?.as_str()?),
                name: table.get("name").and_then(Value::as_str).map(String::from),
                fail_mode: table
                    .get("fail_mode")
                    .and_then(Value::as_str)
                    .map(String::from),
            }),
            _ => None,
        })
        .collect()
}
/** @brief 선택 항목을 파싱해 읽는다. */
fn gopt_parse<T: FromStr>(r: &Value, k: &str) -> Option<T> {
    gstr(r, k).and_then(|s| s.parse::<T>().ok())
}
/** @brief 이름과 주소의 짝 배열을 읽는다. */
fn gnamed_ip<T: FromStr>(r: &Value, k: &str) -> Vec<(String, T)> {
    garr(r, k)
        .iter()
        .filter_map(|pair| {
            let a = pair.as_array()?;
            let name = a.first()?.as_str()?.to_string();
            let ip = a.get(1)?.as_str()?.parse::<T>().ok()?;
            Some((name, ip))
        })
        .collect()
}

/**
 * @brief 모르는 키와 형이 어긋난 값을 거부한다.
 * @warning 무시하지 않는다. 오타 하나가 의도한 설정을 조용히 없애면, 운영자는 그것이
 *          켜져 있다고 믿은 채로 돈다.
 */
fn strict_check(root: &Value) -> Result<(), ConfigError> {
    reject_negative_ints(root, "")?;

    for key in [
        "aggressive_nsec",
        "anonymize_client_ip",
        "block_aaaa",
        "bogus_priv",
        "cache_enabled",
        "cachedb_redis_tls",
        "cluster_raft",
        "deny_any",
        "dhcp6_enable",
        "dhcp_enable",
        "dns64_synthall",
        "dnssec",
        "dnssec_accept_expired",
        "dnssec_rfc5011",
        "dnssec_strict",
        "do_ip4",
        "do_ip6",
        "do_tcp",
        "do_udp",
        "domain_needed",
        "empty_zones",
        "harden_below_nxdomain",
        "harden_large_queries",
        "harden_referral_path",
        "hide_identity",
        "hide_version",
        "ignore_cd_flag",
        "lowercase_outgoing",
        "minimal_responses",
        "parental_control",
        "prefer_ip4",
        "prefer_ip6",
        "prefetch",
        "querylog",
        "qname_minimisation_strict",
        "ra_enable",
        "ra_managed",
        "ra_other",
        "rebind_protection",
        "release_check",
        "root_key_sentinel",
        "rrset_roundrobin",
        "safe_browsing",
        "safe_search",
        "serve_expired_ttl_reset",
        "serve_stale_refresh",
        "sharded_cache",
        "tftp_allow_overwrite",
        "tftp_enable",
        "tftp_writable",
        "tls_revocation_softfail",
        "track_rule_hits",
        "trust_anchor_signaling",
        "update_tsig_required",
        "use_caps_for_id",
        "val_permissive_mode",
        "xfr_tsig_required",
        "zonemd_check",
        "zonemd_reject_absence",
    ] {
        check_kind(root, key, "bool", Value::as_bool)?;
    }
    for key in [
        "acme_account_key_file",
        "acme_cert_file",
        "acme_challenge",
        "acme_contact_email",
        "acme_directory_url",
        "acme_key_file",
        "backend",
        "block_response",
        "block_ipv4",
        "block_ipv6",
        "cachedb_redis_host",
        "cachedb_redis_password",
        "cachedb_redis_secret",
        "cachedb_redis_tls_ca",
        "cachedb_redis_username",
        "catalog_serve",
        "cluster_raft_listen",
        "cluster_raft_secret",
        "cluster_raft_node_key",
        "control_listen",
        "control_token",
        "cookies",
        "ddr_name",
        "dhcp6_lease_file",
        "dhcp6_range_end",
        "dhcp6_range_start",
        "dhcp_boot_file",
        "dhcp_lease_file",
        "dhcp_local_domain",
        "dhcp_range_end",
        "dhcp_range_start",
        "dhcp_router",
        "dhcp_server_ip",
        "dhcp_static_file",
        "dhcp_subnet_mask",
        "dhcp_tftp_server",
        "dns64_prefix",
        "dnscrypt_provider_name",
        "dnssec_anchor_file",
        "dnstap_file",
        "dnstap_identity",
        "doh_path",
        "ecs_custom_ip",
        "ecs_mode",
        "identity",
        "ipset_name_v4",
        "ipset_name_v6",
        "log_level",
        "mac_vendor_db",
        "mode",
        "nsid",
        "query_source",
        "query_source_v6",
        "querylog_file",
        "ra_prefix",
        "run_as_user",
        "run_as_group",
        "split_default",
        "stats_file",
        "tftp_root",
        "tftp_listen",
        "tls_cert",
        "tls_client_ca",
        "tls_key",
        "tls_revocation",
        "tls_self_signed_host",
        "upstream_strategy",
        "version",
        "wasm_fail_mode",
        "wasm_policy",
        "zones_db",
        "zones_db_table",
        "zones_dir",
        "zones_etcd",
        "zones_etcd_ca",
        "zones_etcd_password",
        "zones_etcd_prefix",
        "zones_etcd_user",
        "zones_lmdb",
        "zones_mysql",
        "zones_postgres",
        "zones_sql_table",
    ] {
        check_kind(root, key, "string", Value::as_str)?;
    }
    for key in [
        "acl_allow_ids",
        "acl_deny_ids",
        "acme_domains",
        "allow_rules",
        "allowlists",
        "block_rules",
        "blocklists",
        "refused_domains",
        "blocked_services",
        "blocklist_titles",
        "blocklist_urls",
        "cluster_peers",
        "cluster_raft_peers",
        "control_admin_tokens",
        "control_readonly_tokens",
        "control_public_origins",
        "control_trusted_proxies",
        "dhcp6_dns",
        "dhcp_dns",
        "disabled_blocklist_urls",
        "domain_insecure",
        "fallback_upstreams",
        "ipset_domains",
        "querylog_ignored",
        "rebind_allow",
        "rpz_files",
        "rpz_urls",
        "split_forward",
        "split_recurse",
        "upstream_urls",
        "proxy_protocol_trusted",
    ] {
        check_string_array(root, key)?;
    }
    check_wasm_plugins(root)?;

    check_enum(root, "mode", &["personal", "public"])?;
    check_enum(root, "backend", &["forward", "recurse", "split"])?;
    check_enum(
        root,
        "block_response",
        &["nxdomain", "zero_ip", "refused", "custom"],
    )?;
    check_enum(root, "cookies", &["off", "lenient", "strict"])?;
    check_enum(root, "split_default", &["forward", "recurse"])?;
    check_enum(
        root,
        "upstream_strategy",
        &["query_statistics", "user_order", "round_robin", "parallel"],
    )?;
    check_enum(root, "ecs_mode", &["off", "strip", "send"])?;
    check_enum(root, "wasm_fail_mode", &WASM_FAIL_MODE_VALUES)?;
    check_enum(root, "tls_revocation", &["off", "crl", "ocsp", "both"])?;
    check_enum(root, "acme_challenge", &["http01", "dns01"])?;
    check_enum(
        root,
        "log_level",
        &["trace", "debug", "info", "warn", "error"],
    )?;

    for key in [
        "clients",
        "dynamic_records",
        "local_zones",
        "policy",
        "rewrites",
        "secondary",
        "notify",
        "service_schedule",
        "stub_zones",
        "tsig_keys",
        "update_policy",
        "users",
        "views",
        "zones",
        "catalog",
    ] {
        check_table_array(root, key)?;
    }

    validate_nested_config(root)?;
    check_named_ip_array::<Ipv4Addr>(root, "local_a", "IPv4")?;
    check_named_ip_array::<Ipv6Addr>(root, "local_aaaa", "IPv6")?;
    check_optional_parse::<SocketAddr>(root, "control_listen", "address:port")?;
    check_optional_parse::<Ipv4Addr>(root, "block_ipv4", "IPv4 address")?;
    check_optional_parse::<Ipv6Addr>(root, "block_ipv6", "IPv6 address")?;
    check_optional_parse::<IpAddr>(root, "ecs_custom_ip", "IP address")?;
    check_optional_parse::<Ipv4Addr>(root, "query_source", "IPv4 address")?;
    check_optional_parse::<Ipv6Addr>(root, "query_source_v6", "IPv6 address")?;

    for key in [
        "recursion_limit",
        "cname_limit",
        "dname_limit",
        "ns_recursion_limit",
    ] {
        check_int_range::<u8>(root, key)?;
    }
    for key in [
        "cachedb_redis_port",
        "edns_buffer_size",
        "edns_padding_block",
        "ra_router_lifetime",
        "val_nsec3_max_iterations",
    ] {
        check_int_range::<u16>(root, key)?;
    }
    for key in [
        "serve_expired_reply_ttl",
        "min_ttl",
        "max_ttl",
        "neg_min_ttl",
        "neg_max_ttl",
        "prefetch_min_hits",
        "prefetch_ttl_pct",
        "rate_limit_per_sec",
        "rate_limit_burst",
        "subnet_rrl_per_sec",
        "subnet_rrl_burst",
        "blocked_response_ttl",
        "local_ttl",
        "name_ratelimit_per_sec",
        "ra_mtu",
        "ra_interface_index",
        "dhcp6_interface_index",
    ] {
        check_int_range::<u32>(root, key)?;
    }
    for key in [
        "cachedb_redis_expire_secs",
        "cluster_node_id",
        "dhcp_lease_secs",
        "dnssec_roll_interval_secs",
        "edns_tcp_keepalive_secs",
        "list_refresh_secs",
        "persist_flush_secs",
        "prefetch_interval_secs",
        "query_timeout_secs",
        "querylog_retention_secs",
        "ra_interval",
        "serve_expired_client_timeout_ms",
        "serve_stale_secs",
        "stats_retention_secs",
    ] {
        check_int_range::<u64>(root, key)?;
    }
    for key in [
        "cache_size",
        "max_inflight",
        "workers",
        "upstream_concurrency",
        "cache_shards",
        "name_ratelimit_labels",
        "ns_cache_size",
        "querylog_size",
    ] {
        check_int_range::<usize>(root, key)?;
    }
    check_int_array_range::<u16>(root, "proxy_protocol_ports")?;
    check_typed_array::<IpNet>(
        root,
        "proxy_protocol_trusted",
        "CIDR (for example 127.0.0.1/32)",
    )?;
    check_typed_array::<IpNet>(
        root,
        "control_trusted_proxies",
        "CIDR (for example 127.0.0.1/32)",
    )?;
    for value in gstrvec(root, "control_public_origins") {
        if HttpsOrigin::parse(&value).is_none() {
            return Err(ConfigError::Invalid(format!(
                "control_public_origins: expected an HTTPS address with no path, like https://admin.example.com: {value}"
            )));
        }
    }
    if let Some(value) = root.get("tftp_listen") {
        let valid = value
            .as_str()
            .and_then(|s| s.parse::<SocketAddr>().ok())
            .is_some();
        if !valid {
            return Err(ConfigError::Invalid(
                "tftp_listen: expected address:port".into(),
            ));
        }
    }
    check_nested_int_range::<u32>(root, "dynamic_records", "ttl")?;
    check_nested_int_range::<u16>(root, "dynamic_records", "probe_port")?;
    check_nested_int_range::<u16>(root, "zones", "dnssec_nsec3_iterations")?;
    check_nested_int_range::<u16>(root, "secondary", "primary_port")?;
    check_nested_int_range::<u16>(root, "catalog", "primary_port")?;

    check_typed_array::<IpNet>(root, "acl_allow", "CIDR (for example 192.168.0.0/24)")?;
    check_typed_array::<IpNet>(root, "acl_deny", "CIDR (for example 192.168.0.0/24)")?;
    check_typed_array::<IpNet>(
        root,
        "tftp_write_allow",
        "CIDR (for example 192.168.0.0/24)",
    )?;
    check_typed_array::<IpNet>(
        root,
        "rate_limit_allow",
        "CIDR (for example 192.168.0.0/24)",
    )?;
    check_typed_array::<IpNet>(root, "bogus_nxdomain", "CIDR (for example 10.10.10.10/32)")?;
    check_typed_array::<IpNet>(root, "recurse_deny_server", "CIDR")?;
    check_typed_array::<IpNet>(root, "recurse_allow_server", "CIDR")?;
    check_typed_array::<IpNet>(root, "recurse_deny_answers", "CIDR")?;
    check_typed_array::<IpNet>(root, "recurse_allow_answers", "CIDR")?;
    check_typed_array::<IpNet>(root, "xfr_allow", "CIDR")?;
    check_typed_array::<IpNet>(root, "update_allow", "CIDR")?;
    check_typed_array::<IpAddr>(root, "upstreams", "IP address (for example 1.1.1.1)")?;
    check_typed_array::<IpAddr>(root, "bootstrap", "IP address")?;
    check_typed_array::<IpAddr>(root, "root_hints", "IP address")?;
    for k in [
        "listen",
        "listen_dot",
        "listen_doh",
        "listen_doq",
        "listen_doh3",
        "listen_dnscrypt",
    ] {
        check_typed_array::<SocketAddr>(root, k, "address:port (for example 0.0.0.0:53)")?;
    }

    for (i, v) in garr(root, "fallback_upstreams").iter().enumerate() {
        let Some(raw) = v.as_str() else {
            return Err(invalid_elem(
                "fallback_upstreams",
                i,
                v,
                "an IP or a supported scheme://host[:port]",
            ));
        };
        if !valid_upstream_spec(raw, true) {
            return Err(invalid_elem(
                "fallback_upstreams",
                i,
                v,
                "an IP or udp|tcp|tls|https|quic|h3://host[:port]",
            ));
        }
    }

    for (i, v) in garr(root, "upstream_urls").iter().enumerate() {
        let Some(raw) = v.as_str() else {
            return Err(invalid_elem(
                "upstream_urls",
                i,
                v,
                "a supported scheme://host[:port]",
            ));
        };
        if !valid_upstream_spec(raw, false) {
            return Err(invalid_elem(
                "upstream_urls",
                i,
                v,
                "udp|tcp|tls|https|quic|h3://host[:port]",
            ));
        }
    }
    Ok(())
}

/** @brief 테이블 배열 안쪽 항목들도 같은 엄격함으로 본다. */
fn validate_nested_config(root: &Value) -> Result<(), ConfigError> {
    /** @brief 테이블 배열마다 허용되는 필드 이름들. */
    const NESTED_FIELDS: &[(&str, &[&str])] = &[
        (
            "clients",
            &[
                "name",
                "ids",
                "client_ids",
                "mac",
                "tags",
                "block",
                "allow",
                "disable_filtering",
                "safe_search",
                "blocked_services",
                "upstreams",
                "ignore_querylog",
                "ignore_stats",
            ],
        ),
        (
            "dynamic_records",
            &["name", "qtype", "mode", "values", "ttl", "probe_port"],
        ),
        ("local_zones", &["name", "kind", "records"]),
        (
            "policy",
            &[
                "action", "clients", "suffixes", "qtypes", "rewrite", "days", "start", "end",
            ],
        ),
        ("rewrites", &["domain", "answer"]),
        (
            "secondary",
            &["origin", "file", "primary", "primary_port", "tsig_key"],
        ),
        ("notify", &["address", "tsig_key"]),
        ("service_schedule", &["days", "start", "end"]),
        ("stub_zones", &["suffix", "servers"]),
        ("tsig_keys", &["name", "secret"]),
        ("update_policy", &["action", "identity", "name", "types"]),
        ("users", &["name", "password_hash", "role"]),
        ("views", &["name", "clients", "local_a", "local_aaaa"]),
        (
            "zones",
            &[
                "origin",
                "file",
                "dnssec_sign",
                "dnssec_algorithm",
                "dnssec_key",
                "dnssec_ksk",
                "dnssec_key_next",
                "dnssec_nsec3",
                "dnssec_nsec3_iterations",
            ],
        ),
        (
            "catalog",
            &["origin", "file", "primary", "primary_port", "tsig_key"],
        ),
    ];
    for (array, fields) in NESTED_FIELDS {
        for (index, table) in garr(root, array).iter().enumerate() {
            check_nested_fields(table, array, index, fields)?;
        }
    }

    for (index, table) in garr(root, "clients").iter().enumerate() {
        required_nested_str(table, "clients", index, "name")?;
        check_nested_string_array(table, "clients", index, "client_ids", false)?;
        check_nested_string_array(table, "clients", index, "mac", false)?;
        check_nested_string_array(table, "clients", index, "tags", false)?;
        check_nested_string_array(table, "clients", index, "block", false)?;
        check_nested_string_array(table, "clients", index, "allow", false)?;
        check_nested_string_array(table, "clients", index, "blocked_services", false)?;
        check_nested_string_array(table, "clients", index, "upstreams", false)?;
        check_nested_typed_array::<IpNet>(
            table,
            "clients",
            index,
            "ids",
            "CIDR (for example 192.168.0.0/24)",
            false,
        )?;
        for field in [
            "disable_filtering",
            "safe_search",
            "ignore_querylog",
            "ignore_stats",
        ] {
            check_nested_bool(table, "clients", index, field)?;
        }
        if let Some(upstreams) = nested_array(table, "clients", index, "upstreams", false)? {
            for (item, value) in upstreams.iter().enumerate() {
                let Some(raw) = value.as_str() else {
                    continue;
                };
                if !valid_upstream_spec(raw, true) {
                    return Err(ConfigError::Invalid(format!(
                        "clients[{index}].upstreams[{item}]: expected an IP or udp|tcp|tls|https|quic|h3://host[:port]"
                    )));
                }
            }
        }
    }

    for (index, table) in garr(root, "policy").iter().enumerate() {
        let action = required_nested_str(table, "policy", index, "action")?;
        if !matches!(action, "block" | "allow" | "refuse" | "rewrite") {
            return Err(ConfigError::Invalid(format!(
                "Set `policy[{index}].action` to one of `block`, `allow`, `refuse`, or `rewrite`"
            )));
        }
        if action == "rewrite" {
            let raw = required_nested_str(table, "policy", index, "rewrite")?;
            if raw.parse::<Ipv4Addr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "Set `policy[{index}].rewrite` to a valid IPv4 address"
                )));
            }
        }
        check_nested_typed_array::<IpNet>(table, "policy", index, "clients", "CIDR", true)?;
        check_nested_string_array(table, "policy", index, "suffixes", true)?;
        if let Some(values) = nested_array(table, "policy", index, "qtypes", true)? {
            for (item, value) in values.iter().enumerate() {
                let Some(raw) = value.as_str() else {
                    return Err(ConfigError::Invalid(format!(
                        "`policy[{index}].qtypes[{item}]` must be a DNS record type written as a string"
                    )));
                };
                if !valid_qtype(raw) {
                    return Err(ConfigError::Invalid(format!(
                        "`policy[{index}].qtypes[{item}]` has an unknown DNS record type: '{raw}'"
                    )));
                }
            }
        }
        if let Some(values) = nested_array(table, "policy", index, "days", true)? {
            for (item, value) in values.iter().enumerate() {
                let Some(raw) = value.as_str() else {
                    return Err(ConfigError::Invalid(format!(
                        "`policy[{index}].days[{item}]` must be a day of the week written as a string"
                    )));
                };
                if !valid_day(raw) {
                    return Err(ConfigError::Invalid(format!(
                        "`policy[{index}].days[{item}]` has an unknown day of the week: '{raw}'"
                    )));
                }
            }
        }
        validate_optional_time_pair(table, "policy", index)?;
    }

    for (index, table) in garr(root, "update_policy").iter().enumerate() {
        let action = required_nested_str(table, "update_policy", index, "action")?;
        let identity = required_nested_str(table, "update_policy", index, "identity")?;
        let name = required_nested_str(table, "update_policy", index, "name")?;
        let types = nested_array(table, "update_policy", index, "types", true)?
            .map(|values| {
                values
                    .iter()
                    .enumerate()
                    .map(|(item, value)| {
                        value.as_str().ok_or_else(|| {
                            ConfigError::Invalid(format!(
                                "`update_policy[{index}].types[{item}]` must be a DNS record type written as a string"
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        validate_update_policy_values(index, action, identity, name, types)?;
    }

    for (index, table) in garr(root, "users").iter().enumerate() {
        required_nested_str(table, "users", index, "name")?;
        required_nested_str(table, "users", index, "password_hash")?;
        let role = required_nested_str(table, "users", index, "role")?;
        if !matches!(role, "admin" | "readonly") {
            return Err(ConfigError::Invalid(format!(
                "Set users[{index}].role to exactly `admin` or `readonly`"
            )));
        }
    }

    for (index, table) in garr(root, "views").iter().enumerate() {
        required_nested_str(table, "views", index, "name")?;
        let Some(_) = nested_array(table, "views", index, "clients", true)? else {
            return Err(ConfigError::Invalid(format!(
                "views[{index}].clients needs at least one target"
            )));
        };
        check_nested_string_array(table, "views", index, "clients", true)?;
        check_nested_named_ip_array::<Ipv4Addr>(table, "views", index, "local_a", "IPv4")?;
        check_nested_named_ip_array::<Ipv6Addr>(table, "views", index, "local_aaaa", "IPv6")?;
    }

    for (index, table) in garr(root, "rewrites").iter().enumerate() {
        required_nested_str(table, "rewrites", index, "domain")?;
        required_nested_str(table, "rewrites", index, "answer")?;
    }

    for (index, table) in garr(root, "local_zones").iter().enumerate() {
        required_nested_str(table, "local_zones", index, "name")?;
        check_nested_str(table, "local_zones", index, "kind")?;
        let kind = table
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("refuse");
        if !matches!(
            kind,
            "deny" | "refuse" | "static" | "redirect" | "always_null" | "transparent"
        ) {
            return Err(ConfigError::Invalid(format!(
                "local_zones[{index}].kind has an unknown value: '{kind}'"
            )));
        }
        let records_required = matches!(kind, "static" | "redirect");
        check_nested_string_array(table, "local_zones", index, "records", records_required)?;
        if records_required && table.get("records").is_none() {
            return Err(ConfigError::Invalid(format!(
                "local_zones[{index}].records needs at least one answer value"
            )));
        }
    }

    for (index, table) in garr(root, "stub_zones").iter().enumerate() {
        required_nested_str(table, "stub_zones", index, "suffix")?;
        let Some(servers) = nested_array(table, "stub_zones", index, "servers", true)? else {
            return Err(ConfigError::Invalid(format!(
                "stub_zones[{index}].servers needs at least one upstream DNS server"
            )));
        };
        for (item, value) in servers.iter().enumerate() {
            let raw = value.as_str().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "stub_zones[{index}].servers[{item}]: must be a string"
                ))
            })?;
            if !valid_upstream_spec(raw, true) {
                return Err(ConfigError::Invalid(format!(
                    "stub_zones[{index}].servers[{item}]: expected an IP or udp|tcp|tls|https|quic|h3://host[:port]"
                )));
            }
        }
    }

    for (index, table) in garr(root, "tsig_keys").iter().enumerate() {
        required_nested_str(table, "tsig_keys", index, "name")?;
        required_nested_str(table, "tsig_keys", index, "secret")?;
    }

    for (index, table) in garr(root, "notify").iter().enumerate() {
        let address = required_nested_str(table, "notify", index, "address")?;
        if address.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(format!(
                "notify[{index}].address must be address:port"
            )));
        }
        check_nested_str(table, "notify", index, "tsig_key")?;
    }

    for (index, table) in garr(root, "zones").iter().enumerate() {
        required_nested_str(table, "zones", index, "origin")?;
        for field in [
            "file",
            "dnssec_key",
            "dnssec_ksk",
            "dnssec_key_next",
            "dnssec_algorithm",
        ] {
            check_nested_str(table, "zones", index, field)?;
        }
        for field in ["dnssec_sign", "dnssec_nsec3"] {
            check_nested_bool(table, "zones", index, field)?;
        }
    }

    for array in ["secondary", "catalog"] {
        for (index, table) in garr(root, array).iter().enumerate() {
            required_nested_str(table, array, index, "origin")?;
            let primary = required_nested_str(table, array, index, "primary")?;
            if primary.parse::<IpAddr>().is_err() {
                return Err(ConfigError::Invalid(format!(
                    "{array}[{index}].primary must be a numeric IP address"
                )));
            }
            for field in ["file", "tsig_key"] {
                check_nested_str(table, array, index, field)?;
            }
        }
    }

    for (index, table) in garr(root, "service_schedule").iter().enumerate() {
        let Some(days) = nested_array(table, "service_schedule", index, "days", true)? else {
            return Err(ConfigError::Invalid(format!(
                "service_schedule[{index}].days needs at least one day"
            )));
        };
        for (item, value) in days.iter().enumerate() {
            let Some(raw) = value.as_str() else {
                return Err(ConfigError::Invalid(format!(
                    "service_schedule[{index}].days[{item}]: must be a string"
                )));
            };
            if !valid_day(raw) && raw != "all" {
                return Err(ConfigError::Invalid(format!(
                    "service_schedule[{index}].days[{item}]: unknown day '{raw}'"
                )));
            }
        }
        let start = required_nested_str(table, "service_schedule", index, "start")?;
        let end = required_nested_str(table, "service_schedule", index, "end")?;
        let start_min = parse_hhmm_checked(start).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "service_schedule[{index}].start: expected HH:MM (00:00..23:59)"
            ))
        })?;
        let end_min = parse_hhmm_checked(end).ok_or_else(|| {
            ConfigError::Invalid(format!(
                "service_schedule[{index}].end: expected HH:MM (00:00..23:59)"
            ))
        })?;
        if start_min == end_min {
            return Err(ConfigError::Invalid(format!(
                "service_schedule[{index}] start and end must differ"
            )));
        }
    }

    for (index, table) in garr(root, "dynamic_records").iter().enumerate() {
        required_nested_str(table, "dynamic_records", index, "name")?;
        check_nested_str(table, "dynamic_records", index, "qtype")?;
        check_nested_str(table, "dynamic_records", index, "mode")?;
        let qtype = table.get("qtype").and_then(Value::as_str).unwrap_or("A");
        if !matches!(qtype, "A" | "AAAA") {
            return Err(ConfigError::Invalid(format!(
                "dynamic_records[{index}].qtype: only A or AAAA is allowed"
            )));
        }
        let mode = table
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("random");
        if !matches!(mode, "random" | "weighted" | "round_robin" | "failover") {
            return Err(ConfigError::Invalid(format!(
                "dynamic_records[{index}].mode: unknown value '{mode}'"
            )));
        }
        let Some(values) = nested_array(table, "dynamic_records", index, "values", true)? else {
            return Err(ConfigError::Invalid(format!(
                "dynamic_records[{index}].values needs at least one value"
            )));
        };
        for (item, value) in values.iter().enumerate() {
            let raw = value.as_str().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "dynamic_records[{index}].values[{item}]: must be a string"
                ))
            })?;
            let (ip_raw, weight_raw) = raw
                .split_once('|')
                .map_or((raw, None), |(ip, weight)| (ip, Some(weight)));
            let ip: IpAddr = ip_raw.trim().parse().map_err(|_| {
                ConfigError::Invalid(format!(
                    "dynamic_records[{index}].values[{item}] needs a valid IP address"
                ))
            })?;
            if (qtype == "A" && !ip.is_ipv4()) || (qtype == "AAAA" && !ip.is_ipv6()) {
                return Err(ConfigError::Invalid(format!(
                    "dynamic_records[{index}].values[{item}]: IP family does not match qtype"
                )));
            }
            if let Some(weight) = weight_raw {
                if mode != "weighted" || weight.trim().parse::<u32>().is_err() {
                    return Err(ConfigError::Invalid(format!(
                        "dynamic_records[{index}].values[{item}].weight is malformed"
                    )));
                }
            }
        }
    }

    Ok(())
}

/** @brief 테이블 안에 모르는 필드가 없는지. */
fn check_nested_fields(
    table: &Value,
    array: &str,
    index: usize,
    allowed: &[&str],
) -> Result<(), ConfigError> {
    let fields = table
        .as_table()
        .ok_or_else(|| ConfigError::Invalid(format!("{array}[{index}]: must be a table")))?;
    for field in fields.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}]: unknown key '{field}'"
            )));
        }
    }
    Ok(())
}

/** @brief 동적 갱신 규칙의 값들을 검사한다. */
fn validate_update_policy_values<'a>(
    index: usize,
    action: &str,
    identity: &str,
    name: &str,
    types: impl IntoIterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    if !matches!(action, "grant" | "deny") {
        return Err(ConfigError::Invalid(format!(
            "Set `update_policy[{index}].action` to exactly `grant` or `deny`"
        )));
    }
    if identity.is_empty()
        || identity != identity.trim()
        || (identity != "*" && identity.contains('*'))
    {
        return Err(ConfigError::Invalid(format!(
            "Set `update_policy[{index}].identity` to an exact TSIG name or `*`"
        )));
    }
    let name_valid = if name == "*" {
        true
    } else if let Some(suffix) = name.strip_prefix("*.") {
        !suffix.is_empty() && !suffix.starts_with('.') && !suffix.contains('*')
    } else {
        !name.starts_with('.') && !name.contains('*')
    };
    if name.is_empty() || name != name.trim() || !name_valid {
        return Err(ConfigError::Invalid(format!(
            "Set `update_policy[{index}].name` to an exact DNS name, `*.subdomain`, or `*`"
        )));
    }
    for (item, rtype) in types.into_iter().enumerate() {
        if parse_update_rtype(rtype).is_none() {
            return Err(ConfigError::Invalid(format!(
                "`update_policy[{index}].types[{item}]` has a DNS record type that is not allowed: '{rtype}'"
            )));
        }
    }
    Ok(())
}

/** @brief 테이블에서 반드시 있어야 하는 문자열 필드. */
fn required_nested_str<'a>(
    table: &'a Value,
    array: &str,
    index: usize,
    field: &str,
) -> Result<&'a str, ConfigError> {
    table
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ConfigError::Invalid(format!("{array}[{index}].{field} needs a non-empty string"))
        })
}

/** @brief 테이블의 문자열 필드를 검사한다. */
fn check_nested_str(
    table: &Value,
    array: &str,
    index: usize,
    field: &str,
) -> Result<(), ConfigError> {
    if let Some(value) = table.get(field) {
        if value.as_str().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}].{field}: must be a string"
            )));
        }
    }
    Ok(())
}

/** @brief 테이블의 참거짓 필드를 검사한다. */
fn check_nested_bool(
    table: &Value,
    array: &str,
    index: usize,
    field: &str,
) -> Result<(), ConfigError> {
    if let Some(value) = table.get(field) {
        if value.as_bool().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}].{field}: must be true or false"
            )));
        }
    }
    Ok(())
}

/** @brief 테이블의 이름-주소 배열을 검사한다. */
fn check_nested_named_ip_array<T: FromStr>(
    table: &Value,
    array: &str,
    index: usize,
    field: &str,
    address_kind: &str,
) -> Result<(), ConfigError> {
    let Some(values) = nested_array(table, array, index, field, false)? else {
        return Ok(());
    };
    for (item, value) in values.iter().enumerate() {
        let pair = value.as_array().ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{array}[{index}].{field}[{item}]: must be a [name, address] array"
            ))
        })?;
        let valid = pair.len() == 2
            && pair[0].as_str().is_some_and(|name| !name.trim().is_empty())
            && pair[1]
                .as_str()
                .is_some_and(|address| address.parse::<T>().is_ok());
        if !valid {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}].{field}[{item}]: expected [DNS name, {address_kind} address]"
            )));
        }
    }
    Ok(())
}

/** @brief 테이블에서 배열 필드를 꺼낸다. */
fn nested_array<'a>(
    table: &'a Value,
    array: &str,
    index: usize,
    field: &str,
    reject_empty: bool,
) -> Result<Option<&'a [Value]>, ConfigError> {
    let Some(raw) = table.get(field) else {
        return Ok(None);
    };
    let values = raw.as_array().ok_or_else(|| {
        ConfigError::Invalid(format!("{array}[{index}].{field}: must be an array"))
    })?;
    if reject_empty && values.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{array}[{index}].{field}: an empty array could be mistaken for matching everything; remove the field or give at least one value"
        )));
    }
    Ok(Some(values))
}

/** @brief 테이블의 문자열 배열을 검사한다. */
fn check_nested_string_array(
    table: &Value,
    array: &str,
    index: usize,
    field: &str,
    reject_empty: bool,
) -> Result<(), ConfigError> {
    let Some(values) = nested_array(table, array, index, field, reject_empty)? else {
        return Ok(());
    };
    for (item, value) in values.iter().enumerate() {
        if value.as_str().is_none_or(|raw| raw.trim().is_empty()) {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}].{field}[{item}]: must be a non-empty string"
            )));
        }
    }
    Ok(())
}

/** @brief 테이블의 파싱 가능한 값 배열을 검사한다. */
fn check_nested_typed_array<T: FromStr>(
    table: &Value,
    array: &str,
    index: usize,
    field: &str,
    hint: &str,
    reject_empty: bool,
) -> Result<(), ConfigError> {
    let Some(values) = nested_array(table, array, index, field, reject_empty)? else {
        return Ok(());
    };
    for (item, value) in values.iter().enumerate() {
        let valid = value.as_str().is_some_and(|raw| raw.parse::<T>().is_ok());
        if !valid {
            return Err(ConfigError::Invalid(format!(
                "{array}[{index}].{field}[{item}]: expected {hint}"
            )));
        }
    }
    Ok(())
}

/** @brief 레코드 타입 이름이 이 서버가 아는 것인지. */
fn valid_qtype(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_uppercase().as_str(),
        "A" | "NS"
            | "CNAME"
            | "SOA"
            | "PTR"
            | "MX"
            | "TXT"
            | "AAAA"
            | "SRV"
            | "SVCB"
            | "HTTPS"
            | "ANY"
    ) || raw.trim().parse::<u16>().is_ok()
}

/**
 * @brief 리스너가 요청 경로와 맞춰 볼 수 있는 DoH 경로인지.
 * @details 요청 줄에서 공백은 경로를 끊고, ?와 #은 질의와 조각을 연다. 이런 문자가 들어간
 *          경로는 어떤 요청과도 맞지 않는다.
 */
fn valid_doh_path(path: &str) -> bool {
    path.starts_with('/')
        && !path
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'?' || b == b'#')
}

/**
 * @brief ACME 발급에 넘길 값들이 발급을 시작할 수 있는 모양인지.
 * @details 설정 검사와 관리 API의 발급 요청이 같은 규칙을 쓴다. RFC 8555는 디렉터리를
 *          HTTPS로 받게 하므로 http는 같은 기계의 테스트용 CA에만 허용한다. 와일드카드
 *          이름은 DNS-01로만 소유를 증명할 수 있다.
 */
pub fn validate_acme_request(
    directory_url: Option<&str>,
    domains: &[String],
    contact_email: Option<&str>,
    challenge: &str,
) -> Result<(), String> {
    if !matches!(challenge, "http01" | "dns01") {
        return Err(format!(
            "acme_challenge must be http01 or dns01: {challenge:?}"
        ));
    }
    if let Some(url) = directory_url {
        if !valid_acme_directory_url(url) {
            return Err(format!(
                "acme_directory_url must be an https:// URL; http:// is allowed only for localhost and loopback addresses: {url:?}"
            ));
        }
    }
    for domain in domains {
        let (wildcard, name) = match domain.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, domain.as_str()),
        };
        if !valid_dns_name(name) || name.contains('_') {
            return Err(format!(
                "acme_domains needs host names to put in the certificate: {domain:?}"
            ));
        }
        if wildcard && challenge != "dns01" {
            return Err(format!(
                "Wildcard names can be issued only with dns01: {domain}"
            ));
        }
    }
    if let Some(email) = contact_email {
        let valid = email.split_once('@').is_some_and(|(local, host)| {
            !local.is_empty()
                && !local
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'@')
                && valid_dns_name(host)
                && host.contains('.')
        });
        if !valid {
            return Err(format!(
                "acme_contact_email needs an email address such as ops@example.com: {email:?}"
            ));
        }
    }
    Ok(())
}

/** @brief ACME 디렉터리로 쓸 수 있는 주소인지. */
fn valid_acme_directory_url(url: &str) -> bool {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || rest
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((inner, port)) = bracketed.split_once(']') else {
            return false;
        };
        if !port.is_empty()
            && port
                .strip_prefix(':')
                .is_none_or(|p| p.parse::<u16>().is_err())
        {
            return false;
        }
        inner
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.parse::<u16>().is_err() {
                    return false;
                }
                host
            }
            None => authority,
        }
    };
    let ip = host.parse::<IpAddr>().ok();
    if ip.is_none() && !valid_dns_name(host) {
        return false;
    }
    secure || host.eq_ignore_ascii_case("localhost") || ip.is_some_and(|ip| ip.is_loopback())
}

/**
 * @brief 표기법 DNS 이름으로 쓸 수 있는지.
 * @details 끝점 하나는 받아들인다. 라벨은 63옥텟, 전체는 255옥텟을 넘지 못한다.
 */
fn valid_dns_name(raw: &str) -> bool {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return false;
    }
    trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/**
 * @brief 비교에 쓸 DNS 이름. 끝점과 대소문자를 없앤다.
 * @return 올바른 이름이 아니면 없다.
 */
fn normalized_dns_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    valid_dns_name(trimmed).then(|| trimmed.trim_end_matches('.').to_ascii_lowercase())
}

/**
 * @brief 목록을 내려받을 수 있는 HTTP 주소인지.
 * @details 내려받는 쪽은 http와 https만 안다. 다른 주소는 저장돼도 갱신할 때마다 실패만 남긴다.
 */
fn valid_http_url(raw: &str) -> bool {
    let rest = raw
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw.trim().strip_prefix("http://"));
    rest.and_then(|rest| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

/** @brief 요일 이름이 이 서버가 아는 것인지. */
fn valid_day(raw: &str) -> bool {
    matches!(raw, "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun")
}

/** @brief 갱신 규칙의 타입 이름을 번호로. */
pub fn parse_update_rtype(raw: &str) -> Option<u16> {
    let code = match raw {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "SSHFP" => 44,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "URI" => 256,
        "CAA" => 257,
        "ANY" => 255,
        numeric => {
            let code = numeric.parse::<u16>().ok()?;
            if code.to_string() != numeric {
                return None;
            }
            code
        }
    };
    (!matches!(code, 0 | 41 | 249..=254)).then_some(code)
}

/** @brief 시각 표기를 분 단위로. 범위를 벗어나면 없다. */
fn parse_hhmm_checked(raw: &str) -> Option<u16> {
    let (hour, minute) = raw.split_once(':')?;
    let hour: u16 = hour.trim().parse().ok()?;
    let minute: u16 = minute.trim().parse().ok()?;
    (hour < 24 && minute < 60).then_some(hour * 60 + minute)
}

/** @brief 시작과 끝 시각이 둘 다 있거나 둘 다 없는지. */
fn validate_optional_time_pair(
    table: &Value,
    array: &str,
    index: usize,
) -> Result<(), ConfigError> {
    let start = table.get("start");
    let end = table.get("end");
    match (start, end) {
        (None, None) => Ok(()),
        (Some(start), Some(end)) => {
            let start = start.as_str().and_then(parse_hhmm_checked).ok_or_else(|| {
                ConfigError::Invalid(format!("{array}[{index}].start must be HH:MM"))
            })?;
            let end = end.as_str().and_then(parse_hhmm_checked).ok_or_else(|| {
                ConfigError::Invalid(format!("{array}[{index}].end must be HH:MM"))
            })?;
            if start == end {
                return Err(ConfigError::Invalid(format!(
                    "{array}[{index}] start and end must differ"
                )));
            }
            Ok(())
        }
        _ => Err(ConfigError::Invalid(format!(
            "{array}[{index}]: start and end must be set together"
        ))),
    }
}

/** @brief 값의 형이 기대한 것인지. */
fn check_kind<'a, T>(
    root: &'a Value,
    key: &str,
    expected: &str,
    extract: impl Fn(&'a Value) -> Option<T>,
) -> Result<(), ConfigError> {
    if let Some(value) = root.get(key) {
        if extract(value).is_none() {
            return Err(ConfigError::Invalid(format!("{key}: must be a {expected}")));
        }
    }
    Ok(())
}

/** @brief 플러그인 실패 시 처분들. 열어 주기와 막기 둘로 갈린다. */
const WASM_FAIL_MODE_VALUES: [&str; 3] = ["open", "closed-block", "closed-refuse"];

/** @brief 플러그인 설정을 검사한다. */
fn check_wasm_plugins(root: &Value) -> Result<(), ConfigError> {
    let Some(value) = root.get("wasm_plugins") else {
        return Ok(());
    };
    let Some(values) = value.as_array() else {
        return Err(ConfigError::Invalid(
            "wasm_plugins: must be an array".into(),
        ));
    };
    for (idx, entry) in values.iter().enumerate() {
        match entry {
            Value::String(path) => {
                if path.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "wasm_plugins[{idx}]: empty path"
                    )));
                }
            }
            Value::Table(table) => {
                for key in table.keys() {
                    if !matches!(key.as_str(), "path" | "name" | "fail_mode") {
                        return Err(ConfigError::Invalid(format!(
                            "wasm_plugins[{idx}]: unknown key '{key}'"
                        )));
                    }
                }
                let path_ok = table
                    .get("path")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty());
                if !path_ok {
                    return Err(ConfigError::Invalid(format!(
                        "wasm_plugins[{idx}].path needs a non-empty file path"
                    )));
                }
                if let Some(name) = table.get("name") {
                    if name.as_str().is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "wasm_plugins[{idx}]: name must be a string"
                        )));
                    }
                }
                if let Some(mode) = table.get("fail_mode") {
                    let valid = mode
                        .as_str()
                        .is_some_and(|s| WASM_FAIL_MODE_VALUES.contains(&s));
                    if !valid {
                        return Err(ConfigError::Invalid(format!(
                            "wasm_plugins[{idx}].fail_mode must be one of: {WASM_FAIL_MODE_VALUES:?}"
                        )));
                    }
                }
            }
            _ => {
                return Err(ConfigError::Invalid(format!(
                    "wasm_plugins[{idx}] must be a file path string or a table of the form {{ path, name, fail_mode }}"
                )));
            }
        }
    }
    Ok(())
}

/** @brief 문자열 배열 항목을 검사한다. */
fn check_string_array(root: &Value, key: &str) -> Result<(), ConfigError> {
    let Some(value) = root.get(key) else {
        return Ok(());
    };
    let Some(values) = value.as_array() else {
        return Err(ConfigError::Invalid(format!("{key}: must be an array")));
    };
    for (idx, value) in values.iter().enumerate() {
        if value.as_str().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{key}[{idx}]: must be a string"
            )));
        }
    }
    Ok(())
}

/** @brief 열거 항목이 허용된 값인지. */
fn check_enum(root: &Value, key: &str, allowed: &[&str]) -> Result<(), ConfigError> {
    let Some(value) = root.get(key) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(ConfigError::Invalid(format!("{key}: must be a string")));
    };
    if !allowed.contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{key}: unknown value '{value}'; allowed values: {}",
            allowed.join("|")
        )));
    }
    Ok(())
}

/**
 * @brief 정수 항목이 그 형의 범위 안인지.
 * @warning 넘치면 거부한다. 잘라 담으면 운영자가 적은 값과 실제로 적용된 값이 달라진다.
 */
fn check_int_range<T>(root: &Value, key: &str) -> Result<(), ConfigError>
where
    T: TryFrom<i64>,
{
    let Some(value) = root.get(key) else {
        return Ok(());
    };
    let i = value
        .as_int()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be an integer")))?;
    T::try_from(i)
        .map_err(|_| ConfigError::Invalid(format!("{key}: integer out of range (={i})")))?;
    Ok(())
}

/** @brief 정수 배열의 모든 항목이 범위 안인지. */
fn check_int_array_range<T>(root: &Value, key: &str) -> Result<(), ConfigError>
where
    T: TryFrom<i64>,
{
    let Some(raw) = root.get(key) else {
        return Ok(());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be an array")))?;
    for (idx, value) in values.iter().enumerate() {
        let i = value
            .as_int()
            .ok_or_else(|| ConfigError::Invalid(format!("{key}[{idx}] must be an integer")))?;
        T::try_from(i).map_err(|_| {
            ConfigError::Invalid(format!("{key}[{idx}]: integer out of range (={i})"))
        })?;
    }
    Ok(())
}

/** @brief 테이블 안 정수 필드가 범위 안인지. */
fn check_nested_int_range<T>(root: &Value, array_key: &str, field: &str) -> Result<(), ConfigError>
where
    T: TryFrom<i64>,
{
    let Some(raw) = root.get(array_key) else {
        return Ok(());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ConfigError::Invalid(format!("{array_key}: must be an array")))?;
    for (idx, value) in values.iter().enumerate() {
        if value.as_table().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{array_key}[{idx}]: must be a table"
            )));
        }
        if let Some(raw_field) = value.get(field) {
            let i = raw_field.as_int().ok_or_else(|| {
                ConfigError::Invalid(format!("{array_key}[{idx}].{field}: must be an integer"))
            })?;
            T::try_from(i).map_err(|_| {
                ConfigError::Invalid(format!(
                    "{array_key}[{idx}].{field}: integer out of range (={i})"
                ))
            })?;
        }
    }
    Ok(())
}

/** @brief 부호 없는 슬롯에 음수가 오면 거부한다. */
fn reject_negative_ints(v: &Value, path: &str) -> Result<(), ConfigError> {
    match v {
        Value::Int(i) if *i < 0 => Err(ConfigError::Invalid(format!(
            "{} must be a non-negative integer; got: {i}",
            if path.is_empty() { "<root>" } else { path }
        ))),
        Value::Array(a) => {
            for (idx, e) in a.iter().enumerate() {
                reject_negative_ints(e, &format!("{path}[{idx}]"))?;
            }
            Ok(())
        }
        Value::Table(t) => {
            for (k, e) in t {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                reject_negative_ints(e, &p)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/** @brief 테이블 배열이어야 하는 항목인지. */
fn check_table_array(root: &Value, key: &str) -> Result<(), ConfigError> {
    let Some(raw) = root.get(key) else {
        return Ok(());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be an array of tables")))?;
    for (index, value) in values.iter().enumerate() {
        if value.as_table().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{key}[{index}]: must be a table"
            )));
        }
    }
    Ok(())
}

/** @brief 선택 항목이 파싱되는 값인지. */
fn check_optional_parse<T: FromStr>(
    root: &Value,
    key: &str,
    hint: &str,
) -> Result<(), ConfigError> {
    let Some(raw) = root.get(key) else {
        return Ok(());
    };
    let value = raw
        .as_str()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be a string")))?;
    value
        .parse::<T>()
        .map(|_| ())
        .map_err(|_| ConfigError::Invalid(format!("{key}: expected {hint}")))
}

/** @brief 이름-주소 배열을 검사한다. */
fn check_named_ip_array<T: FromStr>(
    root: &Value,
    key: &str,
    hint: &str,
) -> Result<(), ConfigError> {
    let Some(raw) = root.get(key) else {
        return Ok(());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be an array")))?;
    for (index, value) in values.iter().enumerate() {
        let pair = value.as_array().ok_or_else(|| {
            ConfigError::Invalid(format!("{key}[{index}]: must be a [name, address] array"))
        })?;
        if pair.len() != 2 || pair[0].as_str().is_none() {
            return Err(ConfigError::Invalid(format!(
                "{key}[{index}]: expected [name, address]"
            )));
        }
        let address = pair[1]
            .as_str()
            .ok_or_else(|| ConfigError::Invalid(format!("{key}[{index}][1]: must be a string")))?;
        if address.parse::<T>().is_err() {
            return Err(ConfigError::Invalid(format!(
                "{key}[{index}][1]: expected {hint}"
            )));
        }
    }
    Ok(())
}

/** @brief 파싱 가능한 값 배열을 검사한다. */
/**
 * @brief 관리 화면 리버스 프록시 설정을 검증한다.
 * @details 두 키는 함께 쓴다. 한쪽만 있으면 아무 동작도 하지 않는다. 관리 서버는 루프백에서만
 *          받으므로 프록시도 루프백에서 접속한다.
 */
fn validate_control_proxy(proxies: &[IpNet], origins: &[HttpsOrigin]) -> Result<(), ConfigError> {
    if proxies.is_empty() != origins.is_empty() {
        return Err(ConfigError::Invalid(
            "Set control_trusted_proxies and control_public_origins together: the reverse proxy's address and the HTTPS address it serves the dashboard on".into(),
        ));
    }
    for net in proxies {
        let loopback = net.network().is_loopback()
            && match net.network() {
                IpAddr::V4(_) => net.prefix_len() >= 8,
                IpAddr::V6(_) => net.prefix_len() == 128,
            };
        if !loopback {
            return Err(ConfigError::Invalid(format!(
                "control_trusted_proxies can hold only local addresses, because the management server listens only on a local address: {net}"
            )));
        }
    }
    Ok(())
}

fn check_typed_array<T: FromStr>(root: &Value, key: &str, hint: &str) -> Result<(), ConfigError> {
    let Some(raw) = root.get(key) else {
        return Ok(());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| ConfigError::Invalid(format!("{key}: must be an array")))?;
    for (i, v) in values.iter().enumerate() {
        let ok = v.as_str().map(|s| s.parse::<T>().is_ok()).unwrap_or(false);
        if !ok {
            return Err(invalid_elem(key, i, v, hint));
        }
    }
    Ok(())
}

/** @brief 배열 항목 오류를 만든다. 몇 번째가 왜 틀렸는지 담는다. */
fn invalid_elem(key: &str, idx: usize, v: &Value, hint: &str) -> ConfigError {
    let shown = v
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| "<not a string>".to_string());
    ConfigError::Invalid(format!(
        "Invalid value for {key}[{idx}]: \"{shown}\". {hint}"
    ))
}

/** @brief 16진 문자열이 정확히 그 길이인지. */
fn is_hex_len(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/** @brief 클러스터 동료 주소가 형식에 맞는지. */
fn validate_cluster_peer_url(raw: &str) -> Result<(), ConfigError> {
    let peer = raw.trim();
    let Some(host_port) = peer
        .strip_prefix("https://")
        .or_else(|| peer.strip_prefix("http://"))
    else {
        return Err(ConfigError::Invalid(format!(
            "`cluster_peers` entries must be `https://host[:port]`: '{raw}'"
        )));
    };
    let authority = host_port.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    if host.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "A `cluster_peers` entry has no host: '{raw}'"
        )));
    }
    if peer.starts_with("http://") {
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !loopback {
            return Err(ConfigError::Invalid(format!(
                "`cluster_peers` receive the control plane token, so use `https://` for peers that are not on loopback: '{raw}'"
            )));
        }
    }
    Ok(())
}

/** @brief DNS64 접두사가 규격이 허용한 길이인지. */
fn validate_dns64_prefix(raw: &str) -> Result<(), ConfigError> {
    let (address, prefix) = raw.split_once('/').ok_or_else(|| {
        ConfigError::Invalid("dns64_prefix must be IPv6/prefix (for example 64:ff9b::/96)".into())
    })?;
    address.parse::<Ipv6Addr>().map_err(|_| {
        ConfigError::Invalid(format!("Invalid IPv6 address in dns64_prefix: '{address}'"))
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ConfigError::Invalid(format!("Invalid dns64_prefix length: '{prefix}'")))?;
    if prefix != 96 {
        return Err(ConfigError::Invalid(format!(
            "The DNS64 synthesizer supports only the RFC 6052 /96 prefix (got /{prefix})"
        )));
    }
    Ok(())
}

/** @brief 비밀이 base64이고 최소 길이를 넘는지. */
fn valid_base64_secret(raw: &str, min_decoded: usize) -> bool {
    let value = raw.trim();
    if value.is_empty() || value.len() % 4 != 0 {
        return false;
    }
    let mut padding = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        let is_padding = byte == b'=';
        if is_padding {
            padding += 1;
            if index < value.len().saturating_sub(2) || padding > 2 {
                return false;
            }
        } else if padding != 0 || !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')) {
            return false;
        }
    }
    value.len() / 4 * 3 - padding >= min_decoded
}

/** @brief 모드 이름을 값으로. */
fn dec_mode(s: &str) -> Mode {
    match s {
        "public" => Mode::Public,
        _ => Mode::Personal,
    }
}
/** @brief 해석 방식 이름을 값으로. */
fn dec_backend(s: &str) -> BackendKind {
    match s {
        "recurse" => BackendKind::Recurse,
        "split" => BackendKind::Split,
        _ => BackendKind::Forward,
    }
}
/** @brief 차단 응답 방식 이름을 값으로. */
fn dec_block(s: &str) -> BlockResponseKind {
    match s {
        "zero_ip" => BlockResponseKind::ZeroIp,
        "refused" => BlockResponseKind::Refused,
        "custom" => BlockResponseKind::Custom,
        _ => BlockResponseKind::Nxdomain,
    }
}
/** @brief 쿠키 방식 이름을 값으로. */
fn dec_cookies(s: &str) -> CookieMode {
    match s {
        "lenient" => CookieMode::Lenient,
        "strict" => CookieMode::Strict,
        _ => CookieMode::Off,
    }
}
/** @brief 분할 대상 이름을 값으로. */
fn dec_split(s: &str) -> SplitTarget {
    match s {
        "recurse" => SplitTarget::Recurse,
        _ => SplitTarget::Forward,
    }
}
/** @brief 업스트림 선택 방식 이름을 값으로. */
fn dec_strategy(s: &str) -> UpstreamStrategy {
    match s {
        "user_order" => UpstreamStrategy::UserOrder,
        "round_robin" => UpstreamStrategy::RoundRobin,
        "parallel" => UpstreamStrategy::Parallel,
        _ => UpstreamStrategy::QueryStatistics,
    }
}
/** @brief 대역 정보 방식 이름을 값으로. */
fn dec_ecs(s: &str) -> EcsMode {
    match s {
        "strip" => EcsMode::Strip,
        "send" => EcsMode::Send,
        _ => EcsMode::Off,
    }
}
/** @brief 지역 zone 처분 이름을 값으로. */
fn dec_lzkind(s: &str) -> LocalZoneKind {
    match s {
        "deny" => LocalZoneKind::Deny,
        "static" => LocalZoneKind::Static,
        "redirect" => LocalZoneKind::Redirect,
        "always_null" => LocalZoneKind::AlwaysNull,
        "transparent" => LocalZoneKind::Transparent,
        _ => LocalZoneKind::Refuse,
    }
}

/** @brief 정책 규칙 하나를 읽는다. */
fn decode_policy(t: &Value) -> PolicyRule {
    PolicyRule {
        action: gstr(t, "action").unwrap_or_default(),
        clients: gstrvec(t, "clients"),
        suffixes: gstrvec(t, "suffixes"),
        qtypes: gstrvec(t, "qtypes"),
        rewrite: gstr(t, "rewrite"),
        days: gstrvec(t, "days"),
        start: gstr(t, "start"),
        end: gstr(t, "end"),
    }
}

/** @brief 갱신 규칙 하나를 읽는다. */
fn decode_update_policy(t: &Value) -> UpdatePolicyRule {
    UpdatePolicyRule {
        action: gstr(t, "action").unwrap_or_default(),
        identity: gstr(t, "identity").unwrap_or_default(),
        name: gstr(t, "name").unwrap_or_default(),
        types: gstrvec(t, "types"),
    }
}

/** @brief 클라이언트 그룹 하나를 읽는다. */
fn decode_client(t: &Value) -> ClientConfig {
    ClientConfig {
        name: gstr(t, "name").unwrap_or_default(),
        ids: gparsevec(t, "ids"),
        client_ids: gstrvec(t, "client_ids"),
        mac: gstrvec(t, "mac"),
        tags: gstrvec(t, "tags"),
        block: gstrvec(t, "block"),
        allow: gstrvec(t, "allow"),
        disable_filtering: gbool(t, "disable_filtering", false),
        safe_search: t.get("safe_search").and_then(|v| v.as_bool()),
        blocked_services: gstrvec(t, "blocked_services"),
        upstreams: gstrvec(t, "upstreams"),
        ignore_querylog: gbool(t, "ignore_querylog", false),
        ignore_stats: gbool(t, "ignore_stats", false),
    }
}

/** @brief 사용자 하나를 읽는다. */
fn decode_user(t: &Value) -> UserConfig {
    UserConfig {
        name: gstr(t, "name").unwrap_or_default(),
        password_hash: gstr(t, "password_hash").unwrap_or_default().into(),
        role: gstr(t, "role").unwrap_or_default(),
    }
}

/** @brief 뷰 하나를 읽는다. */
fn decode_view(t: &Value) -> ViewConfig {
    ViewConfig {
        name: gstr(t, "name").unwrap_or_default(),
        clients: gstrvec(t, "clients"),
        local_a: gnamed_ip(t, "local_a"),
        local_aaaa: gnamed_ip(t, "local_aaaa"),
    }
}

/**
 * @brief 이 서버가 아는 설정 키 전부.
 * @warning 여기 없는 키는 거부된다. 없앤 키도 마찬가지라, 이전 설정을 그대로 쓰면 무엇이
 *          사라졌는지 바로 드러난다.
 */
const KNOWN_KEYS: &[&str] = &[
    "mode",
    "backend",
    "listen",
    "upstreams",
    "blocklists",
    "allowlists",
    "blocklist_urls",
    "blocklist_titles",
    "disabled_blocklist_urls",
    "block_rules",
    "allow_rules",
    "list_refresh_secs",
    "blocked_services",
    "safe_search",
    "clients",
    "users",
    "views",
    "policy",
    "wasm_policy",
    "wasm_plugins",
    "wasm_fail_mode",
    "block_response",
    "cache_size",
    "min_ttl",
    "max_ttl",
    "query_timeout_secs",
    "max_inflight",
    "workers",
    "do_udp",
    "do_tcp",
    "serve_stale_secs",
    "serve_expired_reply_ttl",
    "serve_expired_ttl_reset",
    "serve_expired_client_timeout_ms",
    "serve_stale_refresh",
    "proxy_protocol_ports",
    "proxy_protocol_trusted",
    "dns64_prefix",
    "rebind_protection",
    "prefetch",
    "prefetch_min_hits",
    "prefetch_ttl_pct",
    "dnssec",
    "dnssec_strict",
    "val_permissive_mode",
    "dnssec_accept_expired",
    "ignore_cd_flag",
    "dnssec_rfc5011",
    "dnssec_anchor_file",
    "dnssec_roll_interval_secs",
    "root_key_sentinel",
    "trust_anchor_signaling",
    "recursion_limit",
    "cname_limit",
    "dname_limit",
    "do_ip4",
    "do_ip6",
    "prefer_ip4",
    "prefer_ip6",
    "qname_minimisation_strict",
    "harden_referral_path",
    "use_caps_for_id",
    "lowercase_outgoing",
    "harden_large_queries",
    "domain_insecure",
    "split_default",
    "split_recurse",
    "split_forward",
    "local_a",
    "local_aaaa",
    "acl_allow",
    "acl_deny",
    "rate_limit_per_sec",
    "rate_limit_burst",
    "run_as_user",
    "run_as_group",
    "cookies",
    "subnet_rrl_per_sec",
    "subnet_rrl_burst",
    "listen_dot",
    "listen_doh",
    "listen_doq",
    "listen_doh3",
    "listen_dnscrypt",
    "dnscrypt_provider_name",
    "doh_path",
    "ddr_name",
    "tls_cert",
    "tls_key",
    "tls_self_signed_host",
    "tls_client_ca",
    "tls_revocation",
    "tls_revocation_softfail",
    "acme_directory_url",
    "acme_contact_email",
    "acme_domains",
    "acme_challenge",
    "acme_account_key_file",
    "acme_cert_file",
    "acme_key_file",
    "control_listen",
    "control_token",
    "control_admin_tokens",
    "control_readonly_tokens",
    "control_trusted_proxies",
    "control_public_origins",
    "block_ipv4",
    "block_ipv6",
    "blocked_response_ttl",
    "block_aaaa",
    "bogus_nxdomain",
    "domain_needed",
    "bogus_priv",
    "empty_zones",
    "local_ttl",
    "rewrites",
    "dynamic_records",
    "local_zones",
    "refused_domains",
    "rpz_files",
    "rpz_urls",
    "safe_browsing",
    "parental_control",
    "service_schedule",
    "upstream_urls",
    "bootstrap",
    "root_hints",
    "fallback_upstreams",
    "upstream_strategy",
    "upstream_concurrency",
    "query_source",
    "query_source_v6",
    "stub_zones",
    "zones",
    "zones_dir",
    "zones_db",
    "zones_db_table",
    "zones_postgres",
    "zones_mysql",
    "zones_lmdb",
    "zones_sql_table",
    "zones_etcd",
    "zones_etcd_prefix",
    "zones_etcd_ca",
    "zones_etcd_user",
    "zones_etcd_password",
    "secondary",
    "catalog",
    "catalog_serve",
    "xfr_allow",
    "notify",
    "tsig_keys",
    "xfr_tsig_required",
    "zonemd_check",
    "zonemd_reject_absence",
    "update_allow",
    "update_policy",
    "update_tsig_required",
    "ecs_mode",
    "ecs_custom_ip",
    "neg_min_ttl",
    "neg_max_ttl",
    "edns_buffer_size",
    "deny_any",
    "minimal_responses",
    "edns_padding_block",
    "edns_tcp_keepalive_secs",
    "cache_enabled",
    "sharded_cache",
    "cache_shards",
    "prefetch_interval_secs",
    "dns64_synthall",
    "rrset_roundrobin",
    "track_rule_hits",
    "aggressive_nsec",
    "name_ratelimit_per_sec",
    "name_ratelimit_labels",
    "harden_below_nxdomain",
    "dhcp_enable",
    "dhcp_server_ip",
    "dhcp_range_start",
    "dhcp_range_end",
    "dhcp_subnet_mask",
    "dhcp_router",
    "dhcp_dns",
    "dhcp_lease_secs",
    "dhcp_local_domain",
    "dhcp_tftp_server",
    "dhcp_boot_file",
    "tftp_enable",
    "tftp_root",
    "tftp_listen",
    "tftp_writable",
    "tftp_write_allow",
    "tftp_allow_overwrite",
    "ra_enable",
    "ra_prefix",
    "ra_managed",
    "ra_other",
    "ra_router_lifetime",
    "ra_interval",
    "ra_mtu",
    "ra_interface_index",
    "dhcp6_enable",
    "dhcp6_range_start",
    "dhcp6_range_end",
    "dhcp6_dns",
    "dhcp6_interface_index",
    "dhcp_lease_file",
    "dhcp_static_file",
    "dhcp6_lease_file",
    "mac_vendor_db",
    "ipset_name_v4",
    "ipset_name_v6",
    "ipset_domains",
    "cachedb_redis_host",
    "cachedb_redis_port",
    "cachedb_redis_expire_secs",
    "cachedb_redis_secret",
    "cachedb_redis_username",
    "cachedb_redis_password",
    "cachedb_redis_tls",
    "cachedb_redis_tls_ca",
    "cluster_peers",
    "cluster_raft",
    "cluster_node_id",
    "cluster_raft_listen",
    "cluster_raft_peers",
    "cluster_raft_secret",
    "cluster_raft_node_key",
    "rebind_allow",
    "recurse_deny_server",
    "recurse_allow_server",
    "ns_recursion_limit",
    "ns_cache_size",
    "recurse_deny_answers",
    "recurse_allow_answers",
    "val_nsec3_max_iterations",
    "rate_limit_allow",
    "acl_allow_ids",
    "acl_deny_ids",
    "hide_identity",
    "hide_version",
    "nsid",
    "identity",
    "version",
    "log_level",
    "querylog",
    "querylog_size",
    "querylog_retention_secs",
    "anonymize_client_ip",
    "querylog_ignored",
    "stats_retention_secs",
    "querylog_file",
    "stats_file",
    "persist_flush_secs",
    "dnstap_file",
    "dnstap_identity",
    "release_check",
];

/** @brief 알려진 키 목록. 스키마 테스트가 이것과 대조한다. */
pub fn known_keys() -> &'static [&'static str] {
    KNOWN_KEYS
}

/** @brief 파싱된 문서에서 설정을 만든다. */
pub fn decode_config(root: &Value) -> Result<Config, ConfigError> {
    strict_check(root)?;
    let table = root.as_table().ok_or_else(|| {
        ConfigError::Parse(
            "The top-level value of the configuration document must be a TOML table".into(),
        )
    })?;
    for k in table.keys() {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "Unknown configuration key: {k}"
            )));
        }
    }
    let d = Config::default();
    let mut c = Config::default();

    if let Some(s) = gstr(root, "mode") {
        c.mode = dec_mode(&s);
    }
    if let Some(s) = gstr(root, "backend") {
        c.backend = dec_backend(&s);
    }
    if root.get("listen").is_some() {
        c.listen = gparsevec(root, "listen");
    }
    // 업스트림 기본값은 upstream_urls 의 암호화 서버다. 평문 upstreams 만 적은 사람에게
    // 기본 암호화 서버를 남기면, 적은 적 없는 서버로 질의가 나가고 평문과 섞였다는 경고까지
    // 받는다. 적지 않은 것은 고른 것이 아니므로 한쪽을 적으면 다른 쪽 기본값을 물린다.
    let urls_written = root.get("upstream_urls").is_some();
    if urls_written {
        c.upstream_urls = gstrvec(root, "upstream_urls");
    }
    if root.get("upstreams").is_some() {
        c.upstreams = gparsevec(root, "upstreams");
        if !urls_written {
            c.upstream_urls.clear();
        }
    }
    c.blocklists = gpathvec(root, "blocklists");
    c.allowlists = gpathvec(root, "allowlists");
    c.blocklist_urls = gstrvec(root, "blocklist_urls");
    c.blocklist_titles = gstrvec(root, "blocklist_titles");
    c.disabled_blocklist_urls = gstrvec(root, "disabled_blocklist_urls");
    c.block_rules = gstrvec(root, "block_rules");
    c.allow_rules = gstrvec(root, "allow_rules");
    c.list_refresh_secs = gu64(root, "list_refresh_secs", d.list_refresh_secs);
    c.blocked_services = gstrvec(root, "blocked_services");
    c.safe_search = gbool(root, "safe_search", d.safe_search);
    c.clients = garr(root, "clients").iter().map(decode_client).collect();
    c.policy = garr(root, "policy").iter().map(decode_policy).collect();
    c.users = garr(root, "users").iter().map(decode_user).collect();
    c.views = garr(root, "views").iter().map(decode_view).collect();
    c.wasm_policy = gstr(root, "wasm_policy").map(PathBuf::from);
    c.wasm_plugins = dec_wasm_plugins(root);
    c.wasm_fail_mode = gstr(root, "wasm_fail_mode").unwrap_or_else(|| d.wasm_fail_mode.clone());
    if let Some(s) = gstr(root, "block_response") {
        c.block_response = dec_block(&s);
    }
    c.cache_size = gu64(root, "cache_size", d.cache_size);
    c.min_ttl = gu64(root, "min_ttl", d.min_ttl);
    c.max_ttl = gu64(root, "max_ttl", d.max_ttl);
    c.query_timeout_secs = gu64(root, "query_timeout_secs", d.query_timeout_secs);
    c.max_inflight = gusize(root, "max_inflight", d.max_inflight);
    c.workers = gusize(root, "workers", d.workers);
    c.do_udp = gbool(root, "do_udp", d.do_udp);
    c.do_tcp = gbool(root, "do_tcp", d.do_tcp);
    c.serve_stale_secs = gu64(root, "serve_stale_secs", d.serve_stale_secs);
    c.serve_expired_reply_ttl = gu64(
        root,
        "serve_expired_reply_ttl",
        d.serve_expired_reply_ttl as u64,
    ) as u32;
    c.serve_expired_ttl_reset = gbool(root, "serve_expired_ttl_reset", d.serve_expired_ttl_reset);
    c.serve_expired_client_timeout_ms = gu64(
        root,
        "serve_expired_client_timeout_ms",
        d.serve_expired_client_timeout_ms,
    );
    c.serve_stale_refresh = gbool(root, "serve_stale_refresh", d.serve_stale_refresh);
    c.proxy_protocol_ports = garr(root, "proxy_protocol_ports")
        .iter()
        .filter_map(|v| v.as_int().map(|i| i as u16))
        .collect();
    c.proxy_protocol_trusted = gparsevec(root, "proxy_protocol_trusted");
    c.dns64_prefix = gstr(root, "dns64_prefix");
    c.rebind_protection = gbool(root, "rebind_protection", d.rebind_protection);
    c.prefetch = gbool(root, "prefetch", d.prefetch);
    c.prefetch_min_hits = gi64(root, "prefetch_min_hits")
        .filter(|v| *v >= 0)
        .map(|v| v as u32)
        .unwrap_or(d.prefetch_min_hits);
    c.prefetch_ttl_pct = gi64(root, "prefetch_ttl_pct")
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(d.prefetch_ttl_pct);
    c.dnssec = gbool(root, "dnssec", d.dnssec);
    c.dnssec_strict = gbool(root, "dnssec_strict", d.dnssec_strict);
    c.val_permissive_mode = gbool(root, "val_permissive_mode", d.val_permissive_mode);
    c.dnssec_accept_expired = gbool(root, "dnssec_accept_expired", d.dnssec_accept_expired);
    c.ignore_cd_flag = gbool(root, "ignore_cd_flag", d.ignore_cd_flag);
    c.dnssec_rfc5011 = gbool(root, "dnssec_rfc5011", d.dnssec_rfc5011);
    c.dnssec_anchor_file = gstr(root, "dnssec_anchor_file").map(PathBuf::from);
    c.dnssec_roll_interval_secs = gu64(
        root,
        "dnssec_roll_interval_secs",
        d.dnssec_roll_interval_secs,
    );
    c.root_key_sentinel = gbool(root, "root_key_sentinel", d.root_key_sentinel);
    c.trust_anchor_signaling = gbool(root, "trust_anchor_signaling", d.trust_anchor_signaling);
    c.recursion_limit = gi64(root, "recursion_limit")
        .map(|i| i as u8)
        .unwrap_or(d.recursion_limit);
    c.cname_limit = gi64(root, "cname_limit")
        .map(|i| i as u8)
        .unwrap_or(d.cname_limit);
    c.dname_limit = gi64(root, "dname_limit")
        .map(|i| i as u8)
        .unwrap_or(d.dname_limit);
    c.do_ip4 = gbool(root, "do_ip4", d.do_ip4);
    c.do_ip6 = gbool(root, "do_ip6", d.do_ip6);
    c.prefer_ip4 = gbool(root, "prefer_ip4", d.prefer_ip4);
    c.prefer_ip6 = gbool(root, "prefer_ip6", d.prefer_ip6);
    c.qname_minimisation_strict = gbool(
        root,
        "qname_minimisation_strict",
        d.qname_minimisation_strict,
    );
    c.harden_referral_path = gbool(root, "harden_referral_path", d.harden_referral_path);
    c.use_caps_for_id = gbool(root, "use_caps_for_id", d.use_caps_for_id);
    c.lowercase_outgoing = gbool(root, "lowercase_outgoing", d.lowercase_outgoing);
    c.harden_large_queries = gbool(root, "harden_large_queries", d.harden_large_queries);
    c.domain_insecure = gstrvec(root, "domain_insecure");
    if let Some(s) = gstr(root, "split_default") {
        c.split_default = dec_split(&s);
    }
    c.split_recurse = gstrvec(root, "split_recurse");
    c.split_forward = gstrvec(root, "split_forward");
    c.local_a = gnamed_ip(root, "local_a");
    c.local_aaaa = gnamed_ip(root, "local_aaaa");
    c.acl_allow = if root.get("acl_allow").is_some() {
        gparsevec(root, "acl_allow")
    } else {
        match c.mode {
            Mode::Public => Vec::new(),
            Mode::Personal => c.mode.preset_acl_allow(),
        }
    };
    c.acl_deny = gparsevec(root, "acl_deny");
    c.rate_limit_per_sec = gi64(root, "rate_limit_per_sec")
        .map(|i| i as u32)
        .unwrap_or(d.rate_limit_per_sec);
    c.rate_limit_burst = gi64(root, "rate_limit_burst")
        .map(|i| i as u32)
        .unwrap_or(d.rate_limit_burst);
    c.run_as_user = gstr(root, "run_as_user");
    c.run_as_group = gstr(root, "run_as_group");
    if let Some(s) = gstr(root, "cookies") {
        c.cookies = dec_cookies(&s);
    }
    c.subnet_rrl_per_sec = gi64(root, "subnet_rrl_per_sec")
        .map(|i| i as u32)
        .unwrap_or(d.subnet_rrl_per_sec);
    c.subnet_rrl_burst = gi64(root, "subnet_rrl_burst")
        .map(|i| i as u32)
        .unwrap_or(d.subnet_rrl_burst);
    c.listen_dot = gparsevec(root, "listen_dot");
    c.listen_doh = gparsevec(root, "listen_doh");
    c.listen_doq = gparsevec(root, "listen_doq");
    c.listen_doh3 = gparsevec(root, "listen_doh3");
    c.listen_dnscrypt = gparsevec(root, "listen_dnscrypt");
    c.dnscrypt_provider_name =
        gstr(root, "dnscrypt_provider_name").unwrap_or(d.dnscrypt_provider_name);
    c.doh_path = gstr(root, "doh_path").unwrap_or(d.doh_path);
    c.ddr_name = gstr(root, "ddr_name").unwrap_or(d.ddr_name);
    c.tls_cert = gstr(root, "tls_cert").map(PathBuf::from);
    c.tls_key = gstr(root, "tls_key").map(PathBuf::from);
    c.tls_self_signed_host = gstr(root, "tls_self_signed_host");
    c.tls_client_ca = gstr(root, "tls_client_ca").map(PathBuf::from);
    c.tls_revocation = gstr(root, "tls_revocation").unwrap_or(d.tls_revocation);
    c.tls_revocation_softfail = gbool(root, "tls_revocation_softfail", d.tls_revocation_softfail);
    c.acme_directory_url = gstr(root, "acme_directory_url");
    c.acme_contact_email = gstr(root, "acme_contact_email");
    c.acme_domains = gstrvec(root, "acme_domains");
    c.acme_challenge = gstr(root, "acme_challenge").unwrap_or(d.acme_challenge);
    c.acme_account_key_file = gstr(root, "acme_account_key_file");
    c.acme_cert_file = gstr(root, "acme_cert_file");
    c.acme_key_file = gstr(root, "acme_key_file");
    c.control_listen = gopt_parse(root, "control_listen");
    c.control_token = gstr(root, "control_token")
        .map(SecretString::from)
        .unwrap_or(d.control_token);
    c.control_admin_tokens = gstrvec(root, "control_admin_tokens")
        .into_iter()
        .map(SecretString::from)
        .collect();
    c.control_readonly_tokens = gstrvec(root, "control_readonly_tokens")
        .into_iter()
        .map(SecretString::from)
        .collect();
    c.control_trusted_proxies = gparsevec(root, "control_trusted_proxies");
    c.control_public_origins = gstrvec(root, "control_public_origins")
        .iter()
        .filter_map(|value| HttpsOrigin::parse(value))
        .collect();
    c.block_ipv4 = gopt_parse(root, "block_ipv4");
    c.block_ipv6 = gopt_parse(root, "block_ipv6");
    c.blocked_response_ttl = gi64(root, "blocked_response_ttl")
        .map(|i| i as u32)
        .unwrap_or(d.blocked_response_ttl);
    c.block_aaaa = gbool(root, "block_aaaa", d.block_aaaa);
    c.bogus_nxdomain = gparsevec(root, "bogus_nxdomain");
    c.domain_needed = gbool(root, "domain_needed", d.domain_needed);
    c.bogus_priv = gbool(root, "bogus_priv", d.bogus_priv);
    c.empty_zones = gbool(root, "empty_zones", d.empty_zones);
    c.local_ttl = gu64(root, "local_ttl", d.local_ttl as u64) as u32;
    c.rewrites = garr(root, "rewrites")
        .iter()
        .map(|t| Rewrite {
            domain: gstr(t, "domain").unwrap_or_default(),
            answer: gstr(t, "answer").unwrap_or_default(),
        })
        .collect();
    c.dynamic_records = garr(root, "dynamic_records")
        .iter()
        .map(|t| DynamicRecord {
            name: gstr(t, "name").unwrap_or_default(),
            qtype: gstr(t, "qtype").unwrap_or_else(|| "A".to_string()),
            mode: gstr(t, "mode").unwrap_or_else(|| "random".to_string()),
            values: gstrvec(t, "values"),
            ttl: gi64(t, "ttl")
                .map(|v| v.clamp(0, u32::MAX as i64) as u32)
                .unwrap_or(60),
            probe_port: gi64(t, "probe_port")
                .map(|v| v.clamp(0, u16::MAX as i64) as u16)
                .unwrap_or(0),
        })
        .collect();
    c.local_zones = garr(root, "local_zones")
        .iter()
        .map(|t| LocalZone {
            name: gstr(t, "name").unwrap_or_default(),
            kind: dec_lzkind(gstr(t, "kind").as_deref().unwrap_or("refuse")),
            records: gstrvec(t, "records"),
        })
        .collect();
    c.refused_domains = gstrvec(root, "refused_domains");
    c.rpz_files = gpathvec(root, "rpz_files");
    c.rpz_urls = gstrvec(root, "rpz_urls");
    c.safe_browsing = gbool(root, "safe_browsing", d.safe_browsing);
    c.parental_control = gbool(root, "parental_control", d.parental_control);
    c.service_schedule = garr(root, "service_schedule")
        .iter()
        .map(|t| ScheduleWindow {
            days: gstrvec(t, "days"),
            start: gstr(t, "start").unwrap_or_default(),
            end: gstr(t, "end").unwrap_or_default(),
        })
        .collect();
    c.bootstrap = gparsevec(root, "bootstrap");
    c.root_hints = gparsevec(root, "root_hints");
    c.fallback_upstreams = gstrvec(root, "fallback_upstreams");
    if let Some(s) = gstr(root, "upstream_strategy") {
        c.upstream_strategy = dec_strategy(&s);
    }
    c.upstream_concurrency = gusize(root, "upstream_concurrency", d.upstream_concurrency);
    c.query_source = gstr(root, "query_source").and_then(|s| s.parse().ok());
    c.query_source_v6 = gstr(root, "query_source_v6").and_then(|s| s.parse().ok());
    c.stub_zones = garr(root, "stub_zones")
        .iter()
        .map(|t| StubZone {
            suffix: gstr(t, "suffix").unwrap_or_default(),
            servers: gstrvec(t, "servers"),
        })
        .collect();
    c.zones = garr(root, "zones")
        .iter()
        .map(|t| ZoneConfig {
            origin: gstr(t, "origin").unwrap_or_default(),
            file: gstr(t, "file").map(PathBuf::from),
            dnssec_sign: gbool(t, "dnssec_sign", false),
            dnssec_algorithm: gstr(t, "dnssec_algorithm").unwrap_or_default(),
            dnssec_key: gstr(t, "dnssec_key").map(PathBuf::from),
            dnssec_ksk: gstr(t, "dnssec_ksk").map(PathBuf::from),
            dnssec_key_next: gstr(t, "dnssec_key_next").map(PathBuf::from),
            dnssec_nsec3: gbool(t, "dnssec_nsec3", false),
            dnssec_nsec3_iterations: gi64(t, "dnssec_nsec3_iterations").unwrap_or(0) as u16,
        })
        .collect();
    let dec_secondary = |key: &str| -> Vec<SecondaryZone> {
        garr(root, key)
            .iter()
            .map(|t| SecondaryZone {
                origin: gstr(t, "origin").unwrap_or_default(),
                file: gstr(t, "file").map(PathBuf::from),
                primary: gopt_parse(t, "primary"),
                primary_port: gi64(t, "primary_port").map(|i| i as u16),
                tsig_key: gstr(t, "tsig_key"),
            })
            .collect()
    };
    c.secondary = dec_secondary("secondary");
    c.catalog = dec_secondary("catalog");
    c.catalog_serve = gstr(root, "catalog_serve");
    c.zones_dir = gstr(root, "zones_dir").map(PathBuf::from);
    c.zones_db = gstr(root, "zones_db").map(PathBuf::from);
    if let Some(t) = gstr(root, "zones_db_table") {
        c.zones_db_table = t;
    }
    c.zones_postgres = gstr(root, "zones_postgres").map(SecretString::from);
    c.zones_mysql = gstr(root, "zones_mysql").map(SecretString::from);
    c.zones_lmdb = gstr(root, "zones_lmdb").map(PathBuf::from);
    if let Some(t) = gstr(root, "zones_sql_table") {
        c.zones_sql_table = t;
    }
    c.zones_etcd = gstr(root, "zones_etcd");
    if let Some(pf) = gstr(root, "zones_etcd_prefix") {
        c.zones_etcd_prefix = pf;
    }
    c.zones_etcd_ca = gstr(root, "zones_etcd_ca").map(PathBuf::from);
    c.zones_etcd_user = gstr(root, "zones_etcd_user");
    c.zones_etcd_password = gstr(root, "zones_etcd_password").map(SecretString::from);
    c.xfr_allow = gparsevec(root, "xfr_allow");
    c.notify = garr(root, "notify")
        .iter()
        .filter_map(|table| {
            Some(NotifyTarget {
                address: gopt_parse(table, "address")?,
                tsig_key: gstr(table, "tsig_key"),
            })
        })
        .collect();
    c.tsig_keys = garr(root, "tsig_keys")
        .iter()
        .map(|t| TsigKeyConfig {
            name: gstr(t, "name").unwrap_or_default(),
            secret: gstr(t, "secret").unwrap_or_default().into(),
        })
        .collect();
    c.xfr_tsig_required = gbool(root, "xfr_tsig_required", d.xfr_tsig_required);
    c.zonemd_check = gbool(root, "zonemd_check", d.zonemd_check);
    c.zonemd_reject_absence = gbool(root, "zonemd_reject_absence", d.zonemd_reject_absence);
    c.update_allow = gparsevec(root, "update_allow");
    c.update_policy = garr(root, "update_policy")
        .iter()
        .map(decode_update_policy)
        .collect();
    c.update_tsig_required = gbool(root, "update_tsig_required", d.update_tsig_required);
    if let Some(s) = gstr(root, "ecs_mode") {
        c.ecs_mode = dec_ecs(&s);
    }
    c.ecs_custom_ip = gopt_parse(root, "ecs_custom_ip");
    c.neg_min_ttl = gu64(root, "neg_min_ttl", d.neg_min_ttl);
    c.neg_max_ttl = gu64(root, "neg_max_ttl", d.neg_max_ttl);
    c.edns_buffer_size = match gi64(root, "edns_buffer_size") {
        Some(i) if (512..=4096).contains(&i) => i as u16,
        Some(i) => {
            return Err(ConfigError::Invalid(format!(
                "edns_buffer_size must be within 512..=4096 (got {i})"
            )));
        }
        None => d.edns_buffer_size,
    };
    c.deny_any = gbool(root, "deny_any", d.deny_any);
    c.minimal_responses = gbool(root, "minimal_responses", d.minimal_responses);
    c.edns_padding_block = gusize(root, "edns_padding_block", d.edns_padding_block);
    c.edns_tcp_keepalive_secs = gu64(root, "edns_tcp_keepalive_secs", d.edns_tcp_keepalive_secs);
    c.cache_enabled = gbool(root, "cache_enabled", d.cache_enabled);
    c.sharded_cache = gbool(root, "sharded_cache", d.sharded_cache);
    c.cache_shards = gusize(root, "cache_shards", d.cache_shards);
    c.prefetch_interval_secs = gu64(root, "prefetch_interval_secs", d.prefetch_interval_secs);
    c.dns64_synthall = gbool(root, "dns64_synthall", d.dns64_synthall);
    c.rrset_roundrobin = gbool(root, "rrset_roundrobin", d.rrset_roundrobin);
    c.track_rule_hits = gbool(root, "track_rule_hits", d.track_rule_hits);
    c.aggressive_nsec = gbool(root, "aggressive_nsec", d.aggressive_nsec);
    c.name_ratelimit_per_sec = gu64(
        root,
        "name_ratelimit_per_sec",
        d.name_ratelimit_per_sec as u64,
    ) as u32;
    c.name_ratelimit_labels = gusize(root, "name_ratelimit_labels", d.name_ratelimit_labels);
    c.harden_below_nxdomain = gbool(root, "harden_below_nxdomain", d.harden_below_nxdomain);
    c.dhcp_enable = gbool(root, "dhcp_enable", d.dhcp_enable);
    c.dhcp_server_ip = gstr(root, "dhcp_server_ip");
    c.dhcp_range_start = gstr(root, "dhcp_range_start");
    c.dhcp_range_end = gstr(root, "dhcp_range_end");
    c.dhcp_subnet_mask = gstr(root, "dhcp_subnet_mask");
    c.dhcp_router = gstr(root, "dhcp_router");
    c.dhcp_dns = gstrvec(root, "dhcp_dns");
    c.dhcp_lease_secs = gu64(root, "dhcp_lease_secs", d.dhcp_lease_secs);
    c.dhcp_local_domain = gstr(root, "dhcp_local_domain").unwrap_or(d.dhcp_local_domain);
    c.dhcp_tftp_server = gstr(root, "dhcp_tftp_server");
    c.dhcp_boot_file = gstr(root, "dhcp_boot_file");
    c.tftp_enable = gbool(root, "tftp_enable", d.tftp_enable);
    c.tftp_root = gstr(root, "tftp_root");
    c.tftp_listen = gopt_parse(root, "tftp_listen").unwrap_or(d.tftp_listen);
    c.tftp_writable = gbool(root, "tftp_writable", d.tftp_writable);
    c.tftp_write_allow = gparsevec(root, "tftp_write_allow");
    c.tftp_allow_overwrite = gbool(root, "tftp_allow_overwrite", d.tftp_allow_overwrite);
    c.ra_enable = gbool(root, "ra_enable", d.ra_enable);
    c.ra_prefix = gstr(root, "ra_prefix");
    c.ra_managed = gbool(root, "ra_managed", d.ra_managed);
    c.ra_other = gbool(root, "ra_other", d.ra_other);
    c.ra_router_lifetime = gi64(root, "ra_router_lifetime")
        .filter(|v| (0..=u16::MAX as i64).contains(v))
        .map(|v| v as u16)
        .unwrap_or(d.ra_router_lifetime);
    c.ra_interval = gu64(root, "ra_interval", d.ra_interval);
    c.ra_mtu = gi64(root, "ra_mtu").unwrap_or(0).max(0) as u32;
    c.ra_interface_index = gi64(root, "ra_interface_index").unwrap_or(0).max(0) as u32;
    c.dhcp6_enable = gbool(root, "dhcp6_enable", d.dhcp6_enable);
    c.dhcp6_range_start = gstr(root, "dhcp6_range_start");
    c.dhcp6_range_end = gstr(root, "dhcp6_range_end");
    c.dhcp6_dns = gstrvec(root, "dhcp6_dns");
    c.dhcp6_interface_index = gi64(root, "dhcp6_interface_index")
        .filter(|value| (0..=u32::MAX as i64).contains(value))
        .map(|value| value as u32)
        .unwrap_or(d.dhcp6_interface_index);
    c.dhcp_lease_file = gstr(root, "dhcp_lease_file");
    c.dhcp_static_file = gstr(root, "dhcp_static_file");
    c.dhcp6_lease_file = gstr(root, "dhcp6_lease_file");
    c.mac_vendor_db = gstr(root, "mac_vendor_db");
    c.ipset_name_v4 = gstr(root, "ipset_name_v4");
    c.ipset_name_v6 = gstr(root, "ipset_name_v6");
    c.ipset_domains = gstrvec(root, "ipset_domains");
    c.cachedb_redis_host = gstr(root, "cachedb_redis_host");
    c.cachedb_redis_port = gi64(root, "cachedb_redis_port")
        .map(|i| i as u16)
        .unwrap_or(d.cachedb_redis_port);
    c.cachedb_redis_expire_secs = gu64(
        root,
        "cachedb_redis_expire_secs",
        d.cachedb_redis_expire_secs,
    );
    c.cachedb_redis_secret = gstr(root, "cachedb_redis_secret")
        .unwrap_or_default()
        .into();
    c.cachedb_redis_username = gstr(root, "cachedb_redis_username");
    c.cachedb_redis_password = gstr(root, "cachedb_redis_password").map(SecretString::from);
    c.cachedb_redis_tls = gbool(root, "cachedb_redis_tls", d.cachedb_redis_tls);
    c.cachedb_redis_tls_ca = gstr(root, "cachedb_redis_tls_ca").map(PathBuf::from);
    c.cluster_raft = gbool(root, "cluster_raft", d.cluster_raft);
    c.cluster_node_id = gi64(root, "cluster_node_id")
        .map(|i| i.max(0) as u64)
        .unwrap_or(d.cluster_node_id);
    c.cluster_raft_listen = gstr(root, "cluster_raft_listen");
    c.cluster_peers = gstrvec(root, "cluster_peers");
    c.cluster_raft_peers = gstrvec(root, "cluster_raft_peers");
    c.cluster_raft_secret = gstr(root, "cluster_raft_secret").unwrap_or_default().into();
    c.cluster_raft_node_key = gstr(root, "cluster_raft_node_key")
        .unwrap_or_default()
        .into();
    c.rebind_allow = gstrvec(root, "rebind_allow");
    c.recurse_deny_server = gparsevec(root, "recurse_deny_server");
    c.recurse_allow_server = gparsevec(root, "recurse_allow_server");
    c.ns_recursion_limit = gi64(root, "ns_recursion_limit")
        .map(|i| i as u8)
        .unwrap_or(d.ns_recursion_limit);
    c.ns_cache_size = gusize(root, "ns_cache_size", d.ns_cache_size);
    c.recurse_deny_answers = gparsevec(root, "recurse_deny_answers");
    c.recurse_allow_answers = gparsevec(root, "recurse_allow_answers");
    c.val_nsec3_max_iterations = gi64(root, "val_nsec3_max_iterations")
        .map(|i| i.clamp(0, u16::MAX as i64) as u16)
        .unwrap_or(d.val_nsec3_max_iterations);
    c.rate_limit_allow = gparsevec(root, "rate_limit_allow");
    c.acl_allow_ids = gstrvec(root, "acl_allow_ids");
    c.acl_deny_ids = gstrvec(root, "acl_deny_ids");
    c.hide_identity = gbool(root, "hide_identity", d.hide_identity);
    c.hide_version = gbool(root, "hide_version", d.hide_version);
    c.nsid = gstr(root, "nsid");
    c.identity = gstr(root, "identity");
    c.version = gstr(root, "version");
    c.log_level = gstr(root, "log_level");
    c.querylog = gbool(root, "querylog", d.querylog);
    c.querylog_size = gusize(root, "querylog_size", d.querylog_size);
    c.querylog_retention_secs = gu64(root, "querylog_retention_secs", d.querylog_retention_secs);
    c.anonymize_client_ip = gbool(root, "anonymize_client_ip", d.anonymize_client_ip);
    c.querylog_ignored = gstrvec(root, "querylog_ignored");
    c.stats_retention_secs = gu64(root, "stats_retention_secs", d.stats_retention_secs);
    c.querylog_file = gstr(root, "querylog_file").map(PathBuf::from);
    c.stats_file = gstr(root, "stats_file").map(PathBuf::from);
    c.persist_flush_secs = gu64(root, "persist_flush_secs", d.persist_flush_secs);
    c.dnstap_file = gstr(root, "dnstap_file").map(PathBuf::from);
    c.dnstap_identity = gstr(root, "dnstap_identity").unwrap_or(d.dnstap_identity);
    c.release_check = gbool(root, "release_check", d.release_check);

    Ok(c)
}

#[cfg(test)]
/** @brief 위험한 조합의 거부, 모드별 기본값, 그리고 모르는 키와 없앤 키의 거부. */
mod tests {
    use super::*;

    /**
     * @brief 설정은 저장되고 경고만 뜨는지.
     *
     * @details 조건이 맞지 않는 항목은 막지 않는다. 무엇을 켤지는 운영자가 정하고, 이 서버는
     *          지금 동작하지 않는다는 것만 알린다.
     */
    fn saved_with_advisory(toml: &str) -> bool {
        Config::from_toml_str(toml)
            .map(|cfg| !cfg.advisories().is_empty())
            .unwrap_or(false)
    }

    #[test]
    /** @brief 기본값만으로 검증을 통과하는지. 아무것도 적지 않아도 돌아야 한다. */
    fn defaults_validate() {
        let config = Config::default();
        config.validate().unwrap();
        assert!(config.dnssec_strict, "DNSSEC 활성화 시 기본은 fail-closed");
        assert_eq!(
            config.cookies,
            CookieMode::Lenient,
            "쿠키를 모르는 클라이언트는 허용하되 지원하는 클라이언트에는 기본으로 발급"
        );
    }

    #[test]
    /** @brief DHCPv6 multicast 인터페이스가 독립 설정으로 읽히고 범위를 벗어나지 않는지. */
    fn dhcp6_interface_index_is_bounded_and_visible() {
        let config = Config::from_toml_str("dhcp6_interface_index = 17\n").unwrap();
        assert_eq!(config.dhcp6_interface_index, 17);
        assert!(config
            .effective_json()
            .contains("\"dhcp6_interface_index\":17"));
        assert!(Config::from_toml_str("dhcp6_interface_index = 4294967296\n").is_err());
    }

    #[test]
    /** @brief DHCP 임대 수명이 wire에서 조용히 잘리거나 즉시 만료되지 않는지. */
    fn dhcp_lease_lifetime_must_fit_the_wire() {
        assert!(Config::from_toml_str("dhcp_lease_secs = 0\n").is_err());
        assert!(Config::from_toml_str("dhcp_lease_secs = 4294967296\n").is_err());
        assert_eq!(
            Config::from_toml_str("dhcp_lease_secs = 4294967295\n")
                .unwrap()
                .dhcp_lease_secs,
            u64::from(u32::MAX)
        );
    }

    #[test]
    /** @brief DNS 쿠키 기본값을 명시적으로 끄거나 엄격하게 바꿀 수 있는지. */
    fn cookie_default_and_explicit_modes_are_distinct() {
        assert_eq!(
            Config::from_toml_str("").unwrap().cookies,
            CookieMode::Lenient
        );
        assert_eq!(
            Config::from_toml_str("cookies = \"off\"\n")
                .unwrap()
                .cookies,
            CookieMode::Off
        );
        assert_eq!(
            Config::from_toml_str("cookies = \"strict\"\n")
                .unwrap()
                .cookies,
            CookieMode::Strict
        );
    }

    #[test]
    /** @brief 제거한 UDP 중첩 키를 호환 별칭으로 받아들이지 않는지. */
    fn removed_udp_worker_overlap_is_rejected() {
        let error = Config::from_toml_str("udp_worker_overlap = 2\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Unknown configuration key: udp_worker_overlap"));
        assert!(!known_keys().contains(&"udp_worker_overlap"));
    }

    #[test]
    /** @brief 설정 복제가 TSIG 비밀값을 복제하거나 디버그 출력으로 드러내지 않는지. */
    fn tsig_secret_is_shared_and_redacted() {
        let secret = "MDEyMzQ1Njc4OWFiY2RlZg==";
        let config = Config::from_toml_str(&format!(
            "[[tsig_keys]]\nname = \"transfer.example\"\nsecret = \"{secret}\"\n"
        ))
        .unwrap();
        let cloned = config.clone();
        assert_eq!(
            config.tsig_keys[0].secret.as_ptr(),
            cloned.tsig_keys[0].secret.as_ptr()
        );
        assert!(!format!("{:?}", config.tsig_keys[0]).contains(secret));
    }

    #[test]
    /** @brief Raft 공유키와 노드 개인키도 설정 복제에서 원문 버퍼를 늘리지 않는지. */
    fn raft_secrets_are_shared_and_redacted() {
        let shared: SecretString = "cluster-shared-secret-32-bytes!!".to_string().into();
        let node: SecretString = "0123456789abcdef0123456789abcdef".to_string().into();
        let shared_clone = shared.clone();
        let node_clone = node.clone();

        assert_eq!(shared.as_ptr(), shared_clone.as_ptr());
        assert_eq!(node.as_ptr(), node_clone.as_ptr());
        assert_eq!(format!("{shared:?}"), "<redacted>");
        assert_eq!(format!("{node:?}"), "<redacted>");
    }

    #[test]
    /** @brief 관리 자격증명이 설정 복제에서 공유되고 디버그 출력에서 가려지는지. */
    fn management_credentials_are_shared_and_redacted() {
        let config = Config::from_toml_str(
            "control_token = \"primary-token-secret\"\n\
             control_admin_tokens = [\"admin-token-secret\"]\n\
             control_readonly_tokens = [\"readonly-token-secret\"]\n\
             zones_etcd_user = \"dns\"\n\
             zones_etcd_password = \"etcd-password-secret\"\n\
             zones_postgres = \"postgres://dns:postgres-password-secret@127.0.0.1/zones\"\n\
             zones_mysql = \"mysql://dns:mysql-password-secret@127.0.0.1/zones\"\n\
             [[users]]\n\
             name = \"admin\"\n\
             password_hash = \"password-hash-secret\"\n\
             role = \"admin\"\n",
        )
        .unwrap();
        let cloned = config.clone();

        assert_eq!(config.control_token.as_ptr(), cloned.control_token.as_ptr());
        assert_eq!(
            config.control_admin_tokens[0].as_ptr(),
            cloned.control_admin_tokens[0].as_ptr()
        );
        assert_eq!(
            config.control_readonly_tokens[0].as_ptr(),
            cloned.control_readonly_tokens[0].as_ptr()
        );
        assert_eq!(
            config.users[0].password_hash.as_ptr(),
            cloned.users[0].password_hash.as_ptr()
        );
        assert_eq!(
            config.zones_etcd_password.as_ref().unwrap().as_ptr(),
            cloned.zones_etcd_password.as_ref().unwrap().as_ptr()
        );
        assert_eq!(
            config.zones_postgres.as_ref().unwrap().as_ptr(),
            cloned.zones_postgres.as_ref().unwrap().as_ptr()
        );
        assert_eq!(
            config.zones_mysql.as_ref().unwrap().as_ptr(),
            cloned.zones_mysql.as_ref().unwrap().as_ptr()
        );
        let debug = format!("{config:?}");
        for secret in [
            "primary-token-secret",
            "admin-token-secret",
            "readonly-token-secret",
            "password-hash-secret",
            "etcd-password-secret",
            "postgres-password-secret",
            "mysql-password-secret",
        ] {
            assert!(
                !debug.contains(secret),
                "디버그 출력에서 비밀값 가림: {secret}"
            );
        }
    }

    #[test]
    /** @brief 플러그인을 경로만 적은 형태와 테이블 형태로 모두 쓸 수 있는지. */
    fn wasm_plugins_accepts_paths_and_tables() {
        let cfg = Config::from_toml_str(
            "upstreams = [\"1.1.1.1\"]\n\
             wasm_plugins = [\n\
               \"a.wasm\",\n\
               { path = \"b.wasm\", name = \"guard\", fail_mode = \"open\" },\n\
             ]\n",
        )
        .unwrap();
        assert_eq!(cfg.wasm_plugins.len(), 2);
        assert_eq!(cfg.wasm_plugins[0].path, PathBuf::from("a.wasm"));
        assert_eq!(cfg.wasm_plugins[0].fail_mode, None);
        assert_eq!(cfg.wasm_plugins[1].name.as_deref(), Some("guard"));
        assert_eq!(cfg.wasm_plugins[1].fail_mode.as_deref(), Some("open"));
    }

    #[test]
    /** @brief 형식이 어긋난 플러그인 설정을 거부하는지. */
    fn wasm_plugins_invalid_entries_rejected() {
        for text in [
            "wasm_plugins = [1]\n",
            "wasm_plugins = [\"\"]\n",
            "wasm_plugins = [{ name = \"x\" }]\n",
            "wasm_plugins = [{ path = \"a.wasm\", oops = 1 }]\n",
            "wasm_plugins = [{ path = \"a.wasm\", fail_mode = \"whatever\" }]\n",
        ] {
            assert!(
                Config::from_toml_str(&format!("upstreams = [\"1.1.1.1\"]\n{text}")).is_err(),
                "거부해야 함: {text:?}"
            );
        }
    }

    #[test]
    /**
     * @brief 실행 중에 조용히 버려지거나 시작을 막는 값을 검증에서 거절하는지.
     * @details rebind_allow의 잘못된 이름은 실행할 때 걸러져 예외가 사라지고,
     *          domain_insecure의 잘못된 이름은 리졸버 구성을 실패시킨다. 서버 이름은 TXT 문자열
     *          하나에 담기므로 255바이트를 넘으면 답을 만들지 못한다.
     */
    fn values_dropped_or_fatal_at_runtime_are_rejected() {
        for text in [
            "rebind_allow = [\"bad name\"]\n",
            "domain_insecure = [\"a..b\"]\n",
            "name_ratelimit_labels = 0\n",
            "name_ratelimit_labels = 128\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        let long = format!("identity = \"{}\"\n", "x".repeat(256));
        assert!(Config::from_toml_str(&long).is_err());
        let long = format!("nsid = \"{}\"\n", "x".repeat(256));
        assert!(Config::from_toml_str(&long).is_err());
        Config::from_toml_str(
            "rebind_allow = [\"*.corp.example\", \"lan.\"]\ndomain_insecure = [\"test.example\"]\nidentity = \"ns1\"\n",
        )
        .expect("올바른 이름은 받아들인다");
    }

    #[test]
    /**
     * @brief DHCP와 라우터 광고에 담을 수 없는 값을 검증에서 거절하는지.
     * @details 이런 값은 저장된 뒤 서비스를 시작할 때에야 실패하거나, 라우터 광고처럼 경고
     *          없이 꺼진다.
     */
    fn unsendable_edge_service_values_are_rejected() {
        for text in [
            "dhcp_local_domain = \"bad domain\"\n",
            "dhcp_tftp_server = \"bogus\"\n",
            "dhcp_tftp_server = \"fd00::1\"\n",
            "dhcp6_dns = [\"10.0.0.1\"]\n",
            "ra_prefix = \"fd31:e5e5::\"\n",
            "ra_prefix = \"fd31:e5e5::/129\"\n",
            "ra_prefix = \"fd31:e5e5::1/64\"\n",
            "ra_prefix = \"10.0.0.0/8\"\n",
            "ra_interval = 0\n",
            "ra_interval = 100000\n",
            "ra_router_lifetime = 65535\n",
            "ra_interval = 600\nra_router_lifetime = 300\n",
            "ra_mtu = 100\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        let long = format!("dhcp_boot_file = \"{}\"\n", "b".repeat(256));
        assert!(Config::from_toml_str(&long).is_err());
        Config::from_toml_str(
            "dhcp_local_domain = \"home.arpa\"\ndhcp_tftp_server = \"10.0.0.2\"\ndhcp6_dns = [\"fd00::53\"]\nra_prefix = \"fd31:e5e5::/64\"\nra_interval = 30\nra_router_lifetime = 0\nra_mtu = 1500\n",
        )
        .expect("쓸 수 있는 값은 받아들인다");
    }

    #[test]
    /**
     * @brief 저장은 되지만 쓰일 수 없는 권한 저장소와 TSIG 값을 거절하는지.
     * @details 이런 값은 검증을 통과해도 영역을 불러올 때마다 실패하거나, 어느 요청에도 맞지
     *          않는 규칙으로 남는다.
     */
    fn unusable_authority_values_are_rejected() {
        for text in [
            "zones_db_table = \"\"\n",
            "zones_sql_table = \"bad;drop\"\n",
            "zones_etcd_prefix = \"\"\n",
            "zones_lmdb = \"\"\n",
            "zones_etcd = \"http://127.0.0.1:2379\"\nzones_etcd_user = \"u\"\n",
            "zones_etcd = \"http://127.0.0.1:2379\"\nzones_etcd_password = \"p\"\n",
            "catalog_serve = \"bad..name\"\n",
            "zones_etcd = \"https://127.0.0.1:2379\"\n",
            "zonemd_reject_absence = true\n",
            "[[tsig_keys]]\nname = \"k1.\"\nsecret = \"c2VjcmV0LXNlY3JldC1zZWNyZXQtMzItYnl0ZXMhIQ==\"\n[[tsig_keys]]\nname = \"K1\"\nsecret = \"c2VjcmV0LXNlY3JldC1zZWNyZXQtMzItYnl0ZXMhIQ==\"\n",
            "[[update_policy]]\naction = \"grant\"\nidentity = \"nokey.\"\nname = \"*\"\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        Config::from_toml_str(
            "zones_sql_table = \"dns.zones\"\ncatalog_serve = \"catalog.example\"\n[[tsig_keys]]\nname = \"k1.\"\nsecret = \"c2VjcmV0LXNlY3JldC1zZWNyZXQtMzItYnl0ZXMhIQ==\"\n[[update_policy]]\naction = \"grant\"\nidentity = \"K1\"\nname = \"*\"\n",
        )
        .expect("쓸 수 있는 값은 받아들인다");
    }

    #[test]
    /**
     * @brief 저장은 되지만 동작에 쓰일 수 없는 전달, 수신, ACME 값을 거절하는지.
     * @details 해석에 실패한 출발 주소가 없음으로 바뀌거나 알 수 없는 ACME 방식이 다른 방식으로
     *          돌면, 설정에 남은 값과 실제 동작이 어긋난다.
     */
    fn unusable_protocol_values_are_rejected() {
        for text in [
            "query_source = \"not-an-ip\"\n",
            "query_source = \"::1\"\n",
            "query_source_v6 = \"127.0.0.1\"\n",
            "edns_padding_block = 70000\n",
            "edns_tcp_keepalive_secs = 100000\n",
            "ecs_mode = \"send\"\n",
            "doh_path = \"\"\n",
            "doh_path = \"no-slash\"\n",
            "doh_path = \"/a b\"\n",
            "dnscrypt_provider_name = \"\"\n",
            "dnscrypt_provider_name = \"not a name!\"\n",
            "acme_challenge = \"tls-alpn-01\"\n",
            "acme_directory_url = \"not a url\"\n",
            "acme_directory_url = \"http://ca.example/dir\"\n",
            "acme_contact_email = \"not-an-email\"\n",
            "acme_domains = [\"bad name!\"]\n",
            "acme_domains = [\"*.example.com\"]\n",
            "acme_cert_file = \"\"\n",
            "acme_cert_file = \"cert.pem\"\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        Config::from_toml_str("acme_directory_url = \"http://127.0.0.1:14000/dir\"\nacme_challenge = \"dns01\"\nacme_domains = [\"*.example.com\", \"dns.example.com\"]\nacme_contact_email = \"ops@example.com\"\nacme_cert_file = \"c.pem\"\nacme_key_file = \"k.pem\"\necs_mode = \"send\"\necs_custom_ip = \"203.0.113.0\"\nquery_source = \"127.0.0.1\"\nedns_tcp_keepalive_secs = 6553\n")
            .expect("쓸 수 있는 값은 받아들인다");
    }

    #[test]
    /**
     * @brief 시작하면 리졸버 구성이 실패할 값을 검증에서 거절하는지.
     * @details 이런 값은 검증을 통과해도 저장한 뒤 서버가 뜨지 않는다.
     */
    fn split_and_family_contradictions_are_rejected() {
        for text in [
            "do_ip4 = false\ndo_ip6 = false\n",
            "prefer_ip4 = true\nprefer_ip6 = true\n",
            "backend = \"split\"\nsplit_recurse = [\"bad name\"]\n",
            "backend = \"split\"\nsplit_recurse = [\"corp.example\"]\nsplit_forward = [\"Corp.Example.\"]\n",
            "backend = \"split\"\nlocal_a = [[\"host.lan\", \"192.0.2.1\"], [\"HOST.lan.\", \"192.0.2.2\"]]\n",
            "views = [{ name = \"lo\", clients = [\"127.0.0.1/32\"], local_a = [[\"bad..name\", \"192.0.2.1\"]] }]\n",
            "views = [{ name = \"lo\", clients = [\"127.0.0.1/32\"], local_aaaa = [[\"a b.lan\", \"2001:db8::1\"]] }]\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        Config::from_toml_str(
            "views = [{ name = \"lo\", clients = [\"127.0.0.1/32\"], local_a = [[\"host.lan\", \"192.0.2.1\"]] }]\n",
        )
        .expect("올바른 이름을 가진 뷰는 받아들인다");
    }

    #[test]
    /**
     * @brief 처분을 정할 수 없거나 쓰이지 않을 로컬 영역을 거절하는지.
     * @details 같은 영역이 두 번이면 어느 처분이 이길지 정할 수 없고, static과 redirect가
     *          아닌 영역의 records는 아무 데도 쓰이지 않는다.
     */
    fn ambiguous_or_unused_local_zone_values_are_rejected() {
        for text in [
            "local_zones = [{ name = \"corp.example\", kind = \"deny\" }, { name = \"Corp.Example.\", kind = \"transparent\" }]\n",
            "local_zones = [{ name = \"corp.example\", kind = \"deny\", records = [\"192.0.2.1\"] }]\n",
            "local_zones = [{ name = \"a.corp.example\", kind = \"transparent\", records = [\"192.0.2.1\"] }]\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        Config::from_toml_str(
            "local_zones = [{ name = \"corp.example\", kind = \"deny\" }, { name = \"api.corp.example\", kind = \"transparent\" }, { name = \".\", kind = \"refuse\" }]\n",
        )
        .expect("겹치는 영역과 루트 영역은 받아들인다");
        Config::from_toml_str(
            "backend = \"split\"\nsplit_recurse = [\"corp.example\"]\nsplit_forward = [\"public.example\"]\n",
        )
        .expect("겹치지 않는 분할 이름은 받아들인다");
    }

    #[test]
    /**
     * @brief static은 이름별 답을, redirect는 값 하나씩을 받는지.
     * @details static에 값만 적거나 영역 밖 이름을 적으면 그 답을 줄 이름이 없다. redirect에
     *          이름을 붙이면 적은 사람은 이름별 답을 기대하지만 영역 전체가 같은 답을 받는다.
     */
    fn static_and_redirect_records_follow_their_kind() {
        for text in [
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"192.0.2.1\"] }]
",
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"www.other.example 192.0.2.1\"] }]
",
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"xcorp.example 192.0.2.1\"] }]
",
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"www.corp.example 192.0.2.1\", \"www.corp.example alias.example\"] }]
",
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"www.corp.example a.example\", \"www.corp.example b.example\"] }]
",
            "local_zones = [{ name = \"corp.example\", kind = \"redirect\", records = [\"www.corp.example 192.0.2.1\"] }]
",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        let cfg = Config::from_toml_str(
            "local_zones = [{ name = \"corp.example\", kind = \"static\", records = [\"corp.example 192.0.2.1\", \"WWW.corp.example. 192.0.2.2\", \"www.corp.example 2001:db8::2\", \"mail.corp.example www.corp.example\"] }]
",
        )
        .unwrap();
        assert_eq!(
            cfg.local_zones[0].answers().unwrap(),
            vec![
                (
                    "corp.example".to_string(),
                    LocalAnswer::Addresses(vec!["192.0.2.1".parse().unwrap()])
                ),
                (
                    "www.corp.example".to_string(),
                    LocalAnswer::Addresses(vec![
                        "192.0.2.2".parse().unwrap(),
                        "2001:db8::2".parse().unwrap()
                    ])
                ),
                (
                    "mail.corp.example".to_string(),
                    LocalAnswer::Alias("www.corp.example".to_string())
                ),
            ]
        );
        let root = Config::from_toml_str(
            "local_zones = [{ name = \".\", kind = \"static\", records = [\"router.lan 192.0.2.9\"] }]
",
        )
        .unwrap();
        assert_eq!(root.local_zones[0].answers().unwrap()[0].0, "router.lan");
    }

    #[test]
    /**
     * @brief 저장은 되지만 쓸 수 없는 값을 검증에서 거절하는지.
     * @details 내려받을 수 없는 주소, 0번 포트, 이름이 아닌 재작성 답은 시작한 뒤 실패 로그나
     *          깨진 응답으로만 드러난다.
     */
    fn unusable_urls_ports_and_rewrite_answers_are_rejected() {
        for text in [
            "blocklist_urls = [\"ftp://x/y\"]
",
            "rpz_urls = [\"notaurl\"]
",
            "rpz_urls = [\"https:///path\"]
",
            "cachedb_redis_port = 0
",
            "[[rewrites]]
domain = \"rw.example\"
answer = \"not valid answer!!\"
",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text:?}");
        }
        Config::from_toml_str(
            "blocklist_urls = [\"https://lists.example/a.txt\"]
rpz_urls = [\"http://rpz.example\"]
[[rewrites]]
domain = \"rw.example\"
answer = \"target.example\"
",
        )
        .expect("쓸 수 있는 값은 받아들인다");
    }

    #[test]
    /** @brief 권한을 내려놓을 대상이 실제로 낮은 권한인지. root로 내려놓으면 의미가 없다. */
    fn privilege_drop_configuration_requires_non_root_user_and_group() {
        // 값 자체가 틀린 것은 그대로 거절한다. 빈 이름이나 root는 넘겨받을 대상이 아니다.
        for text in [
            "run_as_user = \"\"\n",
            "run_as_user = \"root\"\n",
            "run_as_user = \"00\"\n",
            "run_as_user = \"dns\"\nrun_as_group = \"\"\n",
            "run_as_user = \"dns\"\nrun_as_group = \"root\"\n",
            "run_as_user = \"dns\"\nrun_as_group = \"0\"\n",
        ] {
            assert!(
                Config::from_toml_str(text).is_err(),
                "값이 틀렸으면 거절: {text:?}"
            );
        }
        // 짝이 없는 것은 막지 않고 알린다.
        assert!(saved_with_advisory("run_as_group = \"dns\"\n"));
        Config::from_toml_str("run_as_user = \"dns\"\nrun_as_group = \"dns\"\n")
            .expect("비-root 사용자/그룹은 허용");
        Config::from_toml_str("run_as_user = \"65534\"\nrun_as_group = \"65534\"\n")
            .expect("비-root 숫자 UID/GID는 허용");
        assert_eq!(
            saved_with_advisory("run_as_user = \"dns\"\n"),
            !cfg!(target_os = "linux"),
            "권한 낮추기가 없는 운영체제에서는 그대로 실행된다는 것을 알려야 한다"
        );
    }

    #[test]
    /** @brief 클러스터 주소가 이름 해석을 요구하지 않는지. 요구하면 시작 중 순환이 생긴다. */
    fn raft_addresses_never_require_os_dns() {
        let pubkey = "b".repeat(64);
        let mut config = Config {
            cluster_raft: true,
            cluster_node_id: 1,
            cluster_raft_listen: Some("127.0.0.1:7001".into()),
            cluster_raft_peers: vec![format!("2@[::1]:7002#{pubkey}")],
            cluster_raft_secret: "x".repeat(32).into(),
            cluster_raft_node_key: "a".repeat(64).into(),
            ..Config::default()
        };
        assert!(config.validate().is_ok());

        config.cluster_raft_listen = Some("localhost:7001".into());
        assert!(config.validate().is_err());

        config.cluster_raft_listen = Some("127.0.0.1:7001".into());
        config.cluster_raft_peers = vec![format!("2@raft-peer.example:7002#{pubkey}")];
        assert!(config.validate().is_err());
    }

    #[test]
    /**
     * @brief 클러스터에 인증 재료가 갖춰져 있는지. 없으면 아무나 합의에 끼어든다.
     * @details 경고로만 두면 검사는 통과하는데 서버는 뜨지 않는다. 공개키 없는 노드는 실행
     *          중에 빠지므로, 그렇게 설정한 노드마다 혼자 리더가 되어 합의가 갈라진다.
     */
    fn raft_requires_node_key_and_peer_pubkeys() {
        let pubkey = "b".repeat(64);
        let base = Config {
            cluster_raft: true,
            cluster_node_id: 1,
            cluster_raft_listen: Some("127.0.0.1:7001".into()),
            cluster_raft_peers: vec![format!("2@127.0.0.1:7002#{pubkey}")],
            cluster_raft_secret: "x".repeat(32).into(),
            cluster_raft_node_key: "a".repeat(64).into(),
            ..Config::default()
        };
        assert!(base.validate().is_ok());

        let mut no_key = base.clone();
        no_key.cluster_raft_node_key = String::new().into();
        assert!(no_key.validate().is_err());

        let mut short_secret = base.clone();
        short_secret.cluster_raft_secret = "x".repeat(31).into();
        assert!(short_secret.validate().is_err());

        let mut no_peer_key = base.clone();
        no_peer_key.cluster_raft_peers = vec!["2@127.0.0.1:7002".into()];
        assert!(no_peer_key.validate().is_err());

        let mut dup_pubkey = base.clone();
        dup_pubkey.cluster_raft_peers = vec![
            format!("2@127.0.0.1:7002#{pubkey}"),
            format!("3@127.0.0.1:7003#{}", pubkey.to_uppercase()),
        ];
        assert!(dup_pubkey.validate().is_err(), "중복 peer 공개키는 거부");
    }

    #[test]
    /**
     * @brief 공유 캐시 설정이 함께 있어야 할 값을 요구하고, 비밀 키와 비밀번호를 가리는지.
     * @details 비밀 키가 없으면 Redis에 쓸 수 있는 누구나 이 서버가 내보낼 답을 만들어 넣을 수 있다.
     */
    fn shared_cache_requires_secret_and_masks_credentials() {
        let base = Config {
            cachedb_redis_host: Some("127.0.0.1".into()),
            cachedb_redis_secret: "s".repeat(32).into(),
            ..Config::default()
        };
        assert!(base.validate().is_ok());

        let mut short_secret = base.clone();
        short_secret.cachedb_redis_secret = "s".repeat(31).into();
        assert!(short_secret.validate().is_err());

        let mut without_cache = short_secret.clone();
        without_cache.cachedb_redis_host = None;
        assert!(without_cache.validate().is_ok(), "공유 캐시를 쓸 때만 요구");

        let mut username_only = base.clone();
        username_only.cachedb_redis_username = Some("dns".into());
        assert!(username_only.validate().is_err());

        let mut ca_without_tls = base.clone();
        ca_without_tls.cachedb_redis_tls_ca = Some("redis-ca.pem".into());
        assert!(ca_without_tls.validate().is_err());

        let toml = concat!(
            "cachedb_redis_host = \"127.0.0.1\"\n",
            "cachedb_redis_secret = \"shared-cache-secret-0123456789abcdef\"\n",
            "cachedb_redis_username = \"dns\"\n",
            "cachedb_redis_password = \"redis-password-secret\"\n",
            "cachedb_redis_tls = true\n",
            "cachedb_redis_tls_ca = \"redis-ca.pem\"\n",
        );
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.cachedb_redis_username.as_deref(), Some("dns"));
        assert!(cfg.cachedb_redis_tls);
        assert_eq!(
            cfg.cachedb_redis_tls_ca.as_deref(),
            Some(std::path::Path::new("redis-ca.pem"))
        );
        let json = cfg.effective_json();
        assert!(!json.contains("shared-cache-secret"), "비밀 키 마스킹");
        assert!(!json.contains("redis-password-secret"), "비밀번호 마스킹");
        assert!(json.contains("\"cachedb_redis_secret_set\":true"));
        assert!(json.contains("\"cachedb_redis_password_set\":true"));
    }

    #[test]
    /**
     * @brief 관리 화면 리버스 프록시 설정을 검증하는지.
     * @details 두 키는 함께 있어야 하고, 프록시는 로컬 주소, 출처는 경로 없는 HTTPS여야 한다.
     *          출처는 브라우저가 Origin에 싣는 형태로 정규화된다.
     */
    fn dashboard_reverse_proxy_settings_are_validated() {
        let parsed = Config::from_toml_str(
            "control_trusted_proxies = [\"127.0.0.1/32\"]\n\
             control_public_origins = [\"HTTPS://Admin.Example.com:443\"]\n",
        )
        .expect("정상 설정이 거부됨");
        assert_eq!(
            parsed.control_public_origins[0].to_string(),
            "https://admin.example.com"
        );
        assert!(parsed.validate().is_ok());

        for (proxies, origins) in [
            ("[\"127.0.0.1/32\"]", "[\"http://admin.example.com\"]"),
            ("[\"127.0.0.1/32\"]", "[\"https://admin.example.com/ui\"]"),
            ("[\"192.168.0.10/32\"]", "[\"https://admin.example.com\"]"),
            ("[\"::/0\"]", "[\"https://admin.example.com\"]"),
            ("[\"127.0.0.1/32\"]", "[]"),
            ("[]", "[\"https://admin.example.com\"]"),
        ] {
            let text = format!(
                "control_trusted_proxies = {proxies}\ncontrol_public_origins = {origins}\n"
            );
            assert!(
                Config::from_toml_str(&text)
                    .and_then(|cfg| cfg.validate())
                    .is_err(),
                "{text}"
            );
        }
    }

    #[test]
    /**
     * @brief 관리 토큰 없이 컨트롤 플레인을 여는 설정에 경고가 붙지 않는지.
     *
     * @details 계정이 없으면 첫 관리자 만들기가, 계정이 있으면 로그인이 컨트롤 플레인을 연다.
     *          토큰은 여러 인증 수단 중 하나일 뿐이라, 없다고 알리면 멀쩡한 설정을
     *          고장 난 것처럼 보이게 만든다.
     */
    fn control_listen_without_token_is_not_an_advisory() {
        let cfg = Config {
            control_listen: Some("127.0.0.1:8553".parse().unwrap()),
            ..Config::default()
        };
        assert!(cfg.validate().is_ok());
        assert!(cfg.advisories().is_empty(), "{:?}", cfg.advisories());
    }

    #[test]
    /** @brief 너무 짧은 관리 토큰을 거부하는지. */
    fn control_token_below_min_length_rejected() {
        let mut cfg = Config {
            control_listen: Some("127.0.0.1:8553".parse().unwrap()),
            control_token: "short".into(),
            ..Config::default()
        };
        assert!(!cfg.advisories().is_empty(), "24자 미만 토큰은 알린다");
        cfg.control_token = "x".repeat(24).into();
        assert!(cfg.validate().is_ok(), "24자 이상 토큰은 허용");
    }

    #[test]
    /** @brief 추가 토큰도 길이와 중복 조건을 지키는지. */
    fn auxiliary_control_tokens_require_minimum_length_and_uniqueness() {
        let mut cfg = Config {
            control_admin_tokens: vec!["x".into()],
            ..Config::default()
        };
        assert!(
            !cfg.advisories().is_empty(),
            "짧은 보조 관리자 토큰은 알린다"
        );

        let duplicate = "a".repeat(24);
        cfg.control_admin_tokens = vec![duplicate.clone().into()];
        cfg.control_readonly_tokens = vec![duplicate.into()];
        assert!(
            !cfg.advisories().is_empty(),
            "권한 목록 간 중복 토큰은 알린다"
        );

        cfg.control_admin_tokens = vec!["a".repeat(24).into(), String::new().into()];
        cfg.control_readonly_tokens = vec!["b".repeat(24).into()];
        assert!(cfg.validate().is_ok(), "서로 다른 강한 보조 토큰 허용");

        cfg.control_token = "a".repeat(24).into();
        assert!(
            cfg.validate().is_ok(),
            "같은 역할(admin) 안의 중복 기재는 허용"
        );
    }

    #[test]
    /** @brief 재귀 캐시에 상한이 없는 설정을 거부하는지. */
    fn rejects_unbounded_recursive_state_cache() {
        let mut config = Config::default();
        config.ns_cache_size = 1_000_001;
        assert!(config.validate().is_err());
    }

    #[test]
    /** @brief 0x20이 기본으로 켜져 있고 소문자화와 함께 켤 수 없는지. 둘은 서로를 무력화한다. */
    fn recursive_case_randomization_is_secure_by_default_and_exclusive() {
        let default = Config::default();
        assert!(default.use_caps_for_id);

        let conflicting = Config {
            lowercase_outgoing: true,
            ..default.clone()
        };
        assert!(conflicting.validate().is_err());

        let lowercase_only = Config {
            use_caps_for_id: false,
            lowercase_outgoing: true,
            ..default
        };
        assert!(lowercase_only.validate().is_ok());
    }

    #[test]
    /** @brief 0이거나 넘치는 데드라인 값을 거부하는지. */
    fn rejects_zero_or_overflow_prone_query_timeout() {
        let mut config = Config::default();
        config.query_timeout_secs = 0;
        assert!(config.validate().is_err());

        config.query_timeout_secs = u64::MAX;
        assert!(config.validate().is_err());
    }

    #[test]
    /** @brief TTL 값이 실행 시간이나 와이어 범위를 넘치지 않는지. */
    fn rejects_cache_time_values_that_overflow_runtime_or_wire_ranges() {
        let mut config = Config::default();
        config.max_ttl = u64::from(u32::MAX) + 1;
        assert!(config.validate().is_err());

        config = Config::default();
        config.serve_stale_secs = 31_536_001;
        assert!(config.validate().is_err());

        config = Config::default();
        config.serve_expired_client_timeout_ms = 3_600_001;
        assert!(config.validate().is_err());

        config = Config::default();
        config.prefetch = true;
        config.prefetch_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    /** @brief 부재 합성이 이 서버의 검증 위에서만 켜지는지. 검증 없이 합성하면 위조된 부재를 퍼뜨린다. */
    fn aggressive_denial_cache_requires_local_dnssec_validation() {
        for harden_below in [false, true] {
            let mut config = Config::default();
            config.aggressive_nsec = !harden_below;
            config.harden_below_nxdomain = harden_below;
            assert!(
                !config.advisories().is_empty(),
                "forward 백엔드는 AD를 신뢰하지 않으므로 효과가 없다고 알려야 함"
            );

            config.backend = BackendKind::Recurse;
            config.dnssec = false;
            assert!(
                !config.advisories().is_empty(),
                "DNSSEC 검증 없이는 합성이 동작하지 않는다고 알려야 함"
            );

            config.dnssec = true;
            assert!(config.validate().is_ok(), "검증 재귀 경로에서는 허용");
            assert!(
                config.advisories().is_empty(),
                "동작하는 조합에서는 알릴 것이 없어야 함"
            );
        }
    }

    #[test]
    /** @brief 질의당 작업을 폭증시키는 업스트림 구성을 거부하는지. */
    fn rejects_upstream_sets_that_amplify_per_query_work() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let mut primary = Config::default();
        primary.upstreams = vec![ip; MAX_UPSTREAMS_PER_RESOLVER + 1];
        assert!(primary.validate().is_err());

        let mut fallback = Config::default();
        fallback.fallback_upstreams = vec!["192.0.2.1".into(); MAX_UPSTREAMS_PER_RESOLVER + 1];
        assert!(fallback.validate().is_err());

        let mut stub = Config::default();
        stub.stub_zones.push(StubZone {
            suffix: "internal.example".into(),
            servers: vec!["192.0.2.1".into(); MAX_UPSTREAMS_PER_RESOLVER + 1],
        });
        assert!(stub.validate().is_err());

        let mut client = Config::default();
        client.clients.push(ClientConfig {
            name: "bounded-client".into(),
            client_ids: vec!["client-id".into()],
            upstreams: vec!["192.0.2.1".into(); MAX_UPSTREAMS_PER_RESOLVER + 1],
            ..Default::default()
        });
        assert!(client.validate().is_err());

        let mut concurrency = Config::default();
        concurrency.upstream_concurrency = MAX_UPSTREAMS_PER_RESOLVER + 1;
        assert!(concurrency.validate().is_err());

        let mut dynamic = Config::default();
        dynamic.dynamic_records.push(DynamicRecord {
            name: "pool.example".into(),
            qtype: "A".into(),
            mode: "failover".into(),
            values: vec!["192.0.2.1".into(); MAX_DYNAMIC_RECORD_VALUES + 1],
            ttl: 60,
            probe_port: 443,
        });
        assert!(dynamic.validate().is_err());
    }

    #[test]
    /** @brief 포트 0인 리스너를 거부하는지. */
    fn rejects_port_zero_listener() {
        assert!(Config::from_toml_str("listen = [\"127.0.0.1:0\"]\n").is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nlisten_dot = [\"0.0.0.0:0\"]\n"
        )
        .is_err());
    }

    #[test]
    /** @brief 전송 설정의 순환, 중복, 모르는 키를 거부하는지. */
    fn secondary_configuration_rejects_loops_duplicates_and_unknown_tsig() {
        let mut looped = Config::default();
        let listener = looped.listen[0];
        looped.secondary.push(SecondaryZone {
            origin: "loop.test".into(),
            file: None,
            primary: Some(listener.ip()),
            primary_port: Some(listener.port()),
            tsig_key: None,
        });
        assert!(looped.validate().is_err());

        let mut duplicate = Config::default();
        duplicate.secondary.extend([
            SecondaryZone {
                origin: "duplicate.test.".into(),
                file: None,
                primary: Some("192.0.2.1".parse().unwrap()),
                primary_port: Some(53),
                tsig_key: None,
            },
            SecondaryZone {
                origin: "DUPLICATE.TEST".into(),
                file: None,
                primary: Some("192.0.2.2".parse().unwrap()),
                primary_port: Some(53),
                tsig_key: None,
            },
        ]);
        assert!(duplicate.validate().is_err());

        let mut unknown_key = Config::default();
        unknown_key.secondary.push(SecondaryZone {
            origin: "signed.test".into(),
            file: None,
            primary: Some("192.0.2.1".parse().unwrap()),
            primary_port: Some(53),
            tsig_key: Some("missing-key".into()),
        });
        assert!(unknown_key.validate().is_err());

        let cached = Config::from_toml_str(
            "secondary = [{ origin = \"cached.test\", primary = \"192.0.2.1\", file = \"cached.test.zone\" }]\n",
        )
        .unwrap();
        assert_eq!(
            cached.secondary[0].file.as_deref(),
            Some(std::path::Path::new("cached.test.zone"))
        );
    }

    #[test]
    /** @brief 알림 대상에 주소와 아는 키가 있어야 하는지. */
    fn notify_targets_require_explicit_endpoint_and_known_tsig_identity() {
        let configured = Config::from_toml_str(concat!(
            "notify = [{ address = \"127.0.0.1:5353\", tsig_key = \"notify-key\" }]\n",
            "[[tsig_keys]]\n",
            "name = \"notify-key\"\n",
            "secret = \"MDEyMzQ1Njc4OWFiY2RlZg==\"\n",
        ))
        .expect("NOTIFY endpoint와 TSIG identity");
        assert_eq!(configured.notify.len(), 1);
        assert_eq!(
            configured.notify[0].address,
            "127.0.0.1:5353".parse().unwrap()
        );
        assert_eq!(configured.notify[0].tsig_key.as_deref(), Some("notify-key"));

        assert!(Config::from_toml_str("notify = [{ address = \"127.0.0.1:0\" }]\n").is_err());
        assert!(Config::from_toml_str(
            "notify = [{ address = \"127.0.0.1:5353\", tsig_key = \"missing\" }]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:5353\"]\nnotify = [{ address = \"127.0.0.1:5353\" }]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "notify = [{ address = \"192.0.2.1:53\" }, { address = \"192.0.2.1:53\" }]\n"
        )
        .is_err());
        assert!(
            Config::from_toml_str("notify = [\"127.0.0.1\"]\n").is_err(),
            "배포 전 설정이므로 주소-only 레거시 문법은 제거"
        );
    }

    #[test]
    /** @brief 같은 전송이 같은 주소에 두 번 묶이는 것을 거부하는지. */
    fn rejects_same_transport_listener_conflict() {
        assert!(Config::from_toml_str("listen = [\"0.0.0.0:53\", \"0.0.0.0:53\"]\n").is_err());

        assert!(Config::from_toml_str("listen = [\"0.0.0.0:53\", \"127.0.0.1:53\"]\n").is_err());

        assert!(
            Config::from_toml_str("listen = [\"127.0.0.1:53\", \"192.168.1.1:5353\"]\n").is_ok()
        );

        assert!(Config::from_toml_str("listen = [\"[::]:53\", \"0.0.0.0:53\"]\n").is_err());
    }

    #[test]
    /**
     * @brief DNSCrypt 주소를 TCP 쪽과도 견주는지.
     *
     * @details DNSCrypt 는 같은 주소를 UDP 와 TCP 둘 다로 연다. UDP 목록에만 넣어 두면
     *          DoT·DoH 와 포트가 겹친 설정이 검사를 통과한 뒤 시작 때 주소를 못 열어
     *          리스너 하나가 조용히 빠진다.
     */
    fn dnscrypt_address_conflicts_with_tcp_listeners_too() {
        let doh = "listen_doh = [\"127.0.0.1:8443\"]\nlisten_dnscrypt = [\"127.0.0.1:8443\"]\n";
        assert!(
            Config::from_toml_str(doh).is_err(),
            "DoH 와 포트가 겹치면 거부해야 합니다"
        );

        let dot = "listen_dot = [\"127.0.0.1:853\"]\nlisten_dnscrypt = [\"127.0.0.1:853\"]\n";
        assert!(
            Config::from_toml_str(dot).is_err(),
            "DoT 와 포트가 겹치면 거부해야 합니다"
        );

        let apart = "listen_doh = [\"127.0.0.1:8443\"]\nlisten_dnscrypt = [\"127.0.0.1:8444\"]\n";
        assert!(
            Config::from_toml_str(apart).is_ok(),
            "포트가 다르면 함께 열 수 있습니다"
        );
    }

    #[test]
    /**
     * @brief 속도 제한 없는 공개 모드를 받아들이되 위험을 알리는지.
     * @details 열린 리졸버는 증폭 공격의 발판이 된다. 그래도 제한을 걸지는 운영자가 정한다.
     */
    fn public_mode_without_rate_limit_is_accepted_with_warning() {
        let e = Config::from_toml_str(
            "mode = \"public\"\nlisten = [\"0.0.0.0:53\"]\nrate_limit_per_sec = 0\nrate_limit_burst = 0\n",
        );
        let cfg = e.expect("속도 제한을 걸지 말지는 운영자가 정한다");
        assert!(
            cfg.open_resolver_warnings()
                .iter()
                .any(|line| line.contains("amplification")),
            "막지는 않되 위험은 반드시 알려야 합니다"
        );
    }

    #[test]
    /**
     * @brief 루프백에만 묶인 공개 모드가 열린 리졸버 경고를 내지 않는지.
     * @details 다른 호스트가 닿을 수 없으면 증폭 공격의 발판이 되지 않는다. 그런데도 경고를
     *          내면 실제 위험과 구분되지 않아 경고 자체가 무시된다.
     */
    fn public_mode_bound_to_loopback_only_warns_about_nothing() {
        let cfg = Config::from_toml_str(
            "mode = \"public\"
listen = [\"127.0.0.1:53\"]
rate_limit_per_sec = 0
rate_limit_burst = 0
",
        )
        .expect("루프백에 묶인 공개 모드도 설정으로는 유효합니다");
        assert!(
            cfg.open_resolver_warnings().is_empty(),
            "밖에서 닿지 못하는 서버에 열린 리졸버 경고를 내면 안 됩니다"
        );
    }

    #[test]
    /** @brief 없어진 열린 리졸버 허용 스위치를 모르는 키로 거절하는지. */
    fn removed_open_resolver_switch_is_unknown() {
        assert!(Config::from_toml_str("allow_open_resolver = true\n").is_err());
    }

    #[test]
    /** @brief 속도 제한이 있으면 넓은 허용 목록이 정상인지. 그것이 공개 모드의 목적이다. */
    fn public_mode_rate_limited_open_acl_is_ok() {
        Config::from_toml_str(
            "mode = \"public\"\nlisten = [\"0.0.0.0:53\"]\nrate_limit_per_sec = 100\nrate_limit_burst = 200\n",
        )
        .expect("레이트리밋 있는 공개 리졸버는 허용");
    }

    #[test]
    /** @brief 공개 모드에서 허용 목록을 강제로 채우지 않는지. */
    fn public_mode_without_acl_stays_default_allow_not_forced() {
        let cfg = Config::from_toml_str(
            "mode = \"public\"\nlisten = [\"0.0.0.0:53\"]\nacl_deny = [\"192.0.2.0/24\"]\nrate_limit_per_sec = 100\nrate_limit_burst = 200\n",
        )
        .unwrap();
        assert!(cfg.acl_allow.is_empty(), "acl_allow를 강제로 채우지 않음");
        assert!(cfg.acl_default_allow());
    }

    #[test]
    /** @brief 쓰기 가능한 파일 전송을 밖으로 열려면 명시적 허용이 필요한지. */
    fn tftp_writable_non_loopback_without_allow_rejected() {
        let e = Config::from_toml_str(
            "tftp_enable = true\ntftp_root = \"/srv/tftp\"\ntftp_listen = \"0.0.0.0:69\"\ntftp_writable = true\n",
        );
        let cfg = e.expect("쓰기 허용 여부는 운영자가 정한다");
        assert!(
            cfg.advisories()
                .iter()
                .any(|line| line.contains("tftp_write_allow")),
            "비-loopback writable TFTP는 write_allow 없으면 알린다"
        );
    }

    #[test]
    /** @brief 명시적으로 허용하면 열리는지. */
    fn tftp_writable_non_loopback_with_allow_ok() {
        let cfg = Config::from_toml_str(
            "tftp_enable = true\ntftp_root = \"/srv/tftp\"\ntftp_listen = \"0.0.0.0:69\"\ntftp_writable = true\ntftp_write_allow = [\"192.168.0.0/16\"]\n",
        )
        .expect("write_allow를 명시하면 시작 허용");
        assert_eq!(cfg.tftp_write_allow.len(), 1);
    }

    #[test]
    /** @brief 루프백에서는 추가 허용 없이 되는지. */
    fn tftp_writable_loopback_without_allow_ok() {
        Config::from_toml_str(
            "tftp_enable = true\ntftp_root = \"/srv/tftp\"\ntftp_listen = \"127.0.0.1:69\"\ntftp_writable = true\n",
        )
        .expect("loopback writable TFTP는 write_allow 없이도 허용");
    }

    #[test]
    /** @brief 개인 모드에서 허용 목록이 사설 대역으로 채워지는지. */
    fn personal_mode_without_acl_materializes_trusted_networks() {
        let cfg =
            Config::from_toml_str("mode = \"personal\"\nlisten = [\"127.0.0.1:53\"]\n").unwrap();
        assert_eq!(cfg.acl_allow, Mode::Personal.preset_acl_allow());
        assert!(!cfg.acl_default_allow());
    }

    #[test]
    /** @brief 빈 목록을 명시하면 그대로 두는지. 채워 넣으면 운영자 의도를 뒤집는다. */
    fn explicit_empty_acl_remains_unrestricted() {
        let cfg = Config::from_toml_str("mode = \"personal\"\nacl_allow = []\n").unwrap();
        assert!(cfg.acl_allow.is_empty());
        assert!(cfg.acl_default_allow());
    }

    #[test]
    /** @brief 허용 목록이 있으면 그 밖은 막히는지. */
    fn public_mode_nonempty_allow_list_is_closed_to_unlisted_clients() {
        let cfg = Config::from_toml_str(
            "mode = \"public\"\nlisten = [\"0.0.0.0:53\"]\nacl_allow = [\"203.0.113.0/24\"]\nrate_limit_per_sec = 100\nrate_limit_burst = 200\n",
        )
        .unwrap();
        assert!(!cfg.acl_default_allow());
    }

    #[test]
    /** @brief 대체 업스트림이 이 서버가 아는 형식만 받는지. */
    fn fallback_upstreams_accept_supported_urls_without_defaults() {
        let cfg = Config::from_toml_str(
            "fallback_upstreams = [\"1.1.1.1:5353\", \"https://1.1.1.1/dns-query#cloudflare-dns.com\", \"tls://9.9.9.9:853#dns.quad9.net\", \"quic://1.0.0.1:853#cloudflare-dns.com\"]\n",
        )
        .unwrap();
        assert_eq!(cfg.fallback_upstreams.len(), 4);

        assert!(Config::from_toml_str("fallback_upstreams = [\"ftp://1.1.1.1\"]\n").is_err());
    }

    #[test]
    /** @brief 업스트림 표기가 정해진 이름만 받는지. */
    fn upstream_schemes_accept_only_canonical_names() {
        for scheme in ["udp", "tcp", "tls", "https", "quic", "h3"] {
            let text = format!("upstream_urls = [\"{scheme}://192.0.2.1\"]\n");
            assert!(Config::from_toml_str(&text).is_ok(), "{scheme}");
        }
        for removed_alias in ["dot", "doh", "h2", "doq", "doh3"] {
            let text = format!("upstream_urls = [\"{removed_alias}://192.0.2.1\"]\n");
            assert!(Config::from_toml_str(&text).is_err(), "{removed_alias}");
        }
    }

    #[test]
    /** @brief 플러그인 실패 처분이 지금 이름만 받는지. */
    fn wasm_failure_modes_accept_only_current_spellings() {
        for mode in ["open", "closed-block", "closed-refuse"] {
            let text = format!("wasm_fail_mode = \"{mode}\"\n");
            assert!(Config::from_toml_str(&text).is_ok(), "mode={mode}");
        }
        for mode in ["closed", "closed_block", "closed_refuse", "block", "refuse"] {
            let text = format!("wasm_fail_mode = \"{mode}\"\n");
            assert!(Config::from_toml_str(&text).is_err(), "mode={mode}");
        }
    }

    #[test]
    /** @brief 없앤 키가 거부되는지. 무시하면 켜져 있다고 믿은 채 돈다. */
    fn removed_recursive_auto_switch_keys_are_rejected() {
        for removed in [
            "recursive_auto_fallback = true\n",
            "recursive_probe_interval_secs = 30\n",
            "recursive_probe_max_backoff_secs = 300\n",
        ] {
            assert!(Config::from_toml_str(removed).is_err(), "removed={removed}");
        }
    }

    #[test]
    /** @brief 지정 주소로 답하는 차단에 주소가 있어야 하는지. */
    fn custom_block_requires_ip() {
        let toml = r#"block_response = "custom""#;
        assert!(saved_with_advisory(toml));
        let toml = "block_response = \"custom\"\nblock_ipv4 = \"0.0.0.0\"\n";
        assert!(Config::from_toml_str(toml).is_ok());
    }

    #[test]
    /** @brief 부정 캐시 시간의 최소와 최대가 뒤바뀌지 않았는지. */
    fn neg_ttl_order_checked() {
        let toml = "neg_min_ttl = 100\nneg_max_ttl = 10\n";
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    /** @brief 잘못된 미리 가져오기 비율을 무시하지 않고 거부하는지. */
    fn invalid_prefetch_ttl_percentage_is_rejected_instead_of_ignored() {
        assert!(Config::from_toml_str("prefetch_ttl_pct = 9\n").is_err());
        assert!(Config::from_toml_str("prefetch_ttl_pct = 100\n").is_err());
        assert_eq!(
            Config::from_toml_str("prefetch_ttl_pct = 10\n")
                .unwrap()
                .prefetch_ttl_pct,
            10
        );
    }

    #[test]
    /** @brief 미리 가져오기가 캐시 위에서만 켜지는지. 캐시가 없으면 할 일이 없다. */
    fn prefetch_requires_an_enabled_nonzero_response_cache() {
        let mut disabled = Config {
            prefetch: true,
            cache_enabled: false,
            ..Config::default()
        };
        assert!(!disabled.advisories().is_empty());

        disabled.cache_enabled = true;
        disabled.min_ttl = 0;
        disabled.max_ttl = 0;
        assert!(!disabled.advisories().is_empty());

        disabled.max_ttl = 60;
        disabled.cache_size = 0;
        assert!(!disabled.advisories().is_empty());

        disabled.cache_size = 16;
        assert!(disabled.validate().is_ok());
    }

    #[test]
    /**
     * @brief 켰다고 말하는 곳과 실제로 검증하는 곳이 어긋나지 않는지.
     * @details 전달 경로도 이 서버가 검증하므로 세 방식 모두 켜졌다고 말한다. 어느 체인에 검증
     *          계층을 얹는지는 resolver_chain 의 테스트가 확인한다.
     */
    fn dnssec_is_not_claimed_active_where_nothing_validates() {
        let forwarding = Config {
            dnssec: true,
            backend: BackendKind::Forward,
            upstreams: vec!["1.1.1.1".parse().unwrap()],
            ..Config::default()
        };
        assert!(
            forwarding.dnssec_validation_active(),
            "전달 경로도 이 서버가 검증합니다"
        );
        assert!(
            !forwarding
                .advisories()
                .iter()
                .any(|line| line.contains("전달 처리 방식에서는 서명을 검증하지 않습니다")),
            "검증하는데 검증하지 않는다고 알렸습니다"
        );

        for backend in [BackendKind::Recurse, BackendKind::Split] {
            let validating = Config {
                dnssec: true,
                backend,
                upstreams: vec!["1.1.1.1".parse().unwrap()],
                ..Config::default()
            };
            assert!(
                validating.dnssec_validation_active(),
                "{backend:?}에서는 검증합니다"
            );
        }

        let off = Config {
            dnssec: false,
            backend: BackendKind::Forward,
            upstreams: vec!["1.1.1.1".parse().unwrap()],
            ..Config::default()
        };
        assert!(
            !off.advisories().iter().any(|line| line.contains("dnssec")),
            "끈 설정에까지 알릴 것은 없습니다"
        );
    }

    #[test]
    /**
     * @brief 업스트림을 적지 않으면 암호화 기본값만 쓰고, 한쪽을 적으면 다른 쪽 기본값이
     *        물러나는지.
     *
     * @details 업스트림을 고르는 기준이 왕복 시간이라 평문이 언제나 이긴다. 기본값이 섞여
     *          남으면 한쪽만 적은 사람의 질의가 적은 적 없는 서버로 나간다.
     */
    fn naming_one_upstream_list_drops_the_other_default() {
        let defaults = Config::from_toml_str("").unwrap();
        assert!(
            defaults.upstreams.is_empty(),
            "기본값에 평문 업스트림이 있습니다"
        );
        assert_eq!(
            defaults.upstream_urls,
            DEFAULT_UPSTREAM_URLS.map(str::to_string).to_vec(),
            "기본값은 Cloudflare DNS-over-HTTP/3 입니다"
        );
        assert!(DEFAULT_UPSTREAM_URLS
            .iter()
            .all(|url| url.starts_with("h3://1.") && url.ends_with("#cloudflare-dns.com")));

        let plain_only = Config::from_toml_str("upstreams = [\"9.9.9.9\"]\n").unwrap();
        assert!(
            plain_only.upstream_urls.is_empty(),
            "평문만 적었는데 기본 암호화 업스트림이 남았습니다: {:?}",
            plain_only.upstream_urls
        );
        assert!(!plain_only.mixes_plain_and_encrypted_upstreams());

        let encrypted_only =
            Config::from_toml_str("upstream_urls = [\"tls://1.1.1.1:853#cloudflare-dns.com\"]\n")
                .unwrap();
        assert!(
            encrypted_only.upstreams.is_empty(),
            "암호화만 적었는데 평문 업스트림이 생겼습니다: {:?}",
            encrypted_only.upstreams
        );
        assert_eq!(
            encrypted_only.upstream_urls.len(),
            1,
            "적은 것만 남아야 합니다"
        );
        assert!(!encrypted_only.mixes_plain_and_encrypted_upstreams());
        assert!(
            !encrypted_only
                .advisories()
                .iter()
                .any(|line| line.contains("plain upstream")),
            "섞이지 않았는데 섞였다고 알렸습니다"
        );

        // 대조군. 적어 놓은 평문은 그대로 두고, 섞였다는 것을 알린다.
        let mixed = Config::from_toml_str(
            "upstreams = [\"9.9.9.9\"]\nupstream_urls = [\"tls://1.1.1.1:853#cloudflare-dns.com\"]\n",
        )
        .unwrap();
        assert_eq!(mixed.upstreams.len(), 1, "적어 놓은 평문은 남아야 합니다");
        assert!(mixed.mixes_plain_and_encrypted_upstreams());
        assert!(
            mixed
                .advisories()
                .iter()
                .any(|line| line.contains("plain upstream")),
            "섞였다는 것을 알리지 않았습니다"
        );
    }

    #[test]
    /** @brief 만료 응답 제공이 캐시 위에서만 켜지는지. */
    fn serve_stale_requires_an_enabled_nonzero_response_cache() {
        let mut disabled = Config {
            serve_stale_secs: 60,
            cache_enabled: false,
            ..Config::default()
        };
        assert!(!disabled.advisories().is_empty());

        disabled.cache_enabled = true;
        disabled.min_ttl = 0;
        disabled.max_ttl = 0;
        assert!(!disabled.advisories().is_empty());

        disabled.max_ttl = 60;
        disabled.cache_size = 0;
        assert!(!disabled.advisories().is_empty());

        disabled.cache_size = 16;
        assert!(disabled.validate().is_ok());
    }

    #[test]
    /** @brief 접미사 전달에 서버가 지정돼 있어야 하는지. */
    fn stub_zone_requires_servers() {
        let toml = "[[stub_zones]]\nsuffix = \"corp.internal\"\nservers = []\n";
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    /** @brief 클라이언트별 업스트림에 대상 지정이 있어야 하는지. */
    fn client_upstreams_require_matcher() {
        let toml = "[[clients]]\nname = \"orphan\"\nupstreams = [\"1.1.1.1\"]\n";
        assert!(Config::from_toml_str(toml).is_err());
    }

    #[test]
    /** @brief 최근에 더한 항목들이 읽히는지. */
    fn new_fields_parse() {
        let toml = r#"
upstream_urls = ["tls://1.1.1.1#cloudflare-dns.com"]
upstream_strategy = "round_robin"
ecs_mode = "strip"
safe_browsing = true
refused_domains = ["tracking.example"]
rewrites = [{ domain = "router.lan", answer = "192.168.1.1" }]
local_zones = [{ name = "lan", kind = "static", records = ["lan 10.0.0.1"] }]
stub_zones = [{ suffix = "corp.internal", servers = ["10.0.0.53"] }]
[[clients]]
name = "kid"
ids = ["192.168.1.50/32"]
tags = ["child"]
safe_search = true
blocked_services = ["youtube"]
"#;
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(cfg.upstream_urls.len(), 1);
        assert_eq!(cfg.upstream_strategy, UpstreamStrategy::RoundRobin);
        assert_eq!(cfg.ecs_mode, EcsMode::Strip);
        assert!(cfg.safe_browsing);
        assert_eq!(cfg.clients[0].tags, vec!["child".to_string()]);
    }

    #[test]
    /** @brief split 전용 항목이 다른 백엔드에서 조용히 무시되지 않는지. */
    fn split_only_keys_are_rejected_outside_split_backend() {
        let err = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nlocal_a = [[\"router.lan\", \"192.168.1.1\"]]\n",
        )
        .expect("split에서만 쓰이는 항목이라도 저장은 할 수 있어야 합니다");
        assert!(err.advisories().iter().any(|line| line.contains("split")));

        assert!(saved_with_advisory(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nsplit_forward = [\"corp.example\"]\n",
        ));

        assert!(Config::from_toml_str(
            "backend = \"split\"\nupstreams = [\"1.1.1.1\"]\nlocal_a = [[\"router.lan\", \"192.168.1.1\"]]\n",
        )
        .is_ok());
    }

    #[test]
    /** @brief 부호 없는 슬롯의 음수를 거부하는지. */
    fn strict_rejects_negative_unsigned() {
        assert!(Config::from_toml_str("cache_size = -1\n").is_err());
        assert!(Config::from_toml_str("rate_limit_per_sec = -100\n").is_err());

        assert!(Config::from_toml_str("cache_size = 0\n").is_ok());
        assert!(Config::from_toml_str("cache_size = 100000\n").is_ok());
    }

    #[test]
    /** @brief 존 서명 알고리즘이 아는 이름만 받는지. */
    fn zone_signing_algorithm_accepts_only_known_names() {
        let zone = |extra: &str| {
            format!("zones = [{{ origin = \"example.test\", dnssec_sign = true{extra} }}]\n")
        };
        assert!(Config::from_toml_str(&zone("")).is_ok(), "비우면 기본값");
        assert!(Config::from_toml_str(&zone(", dnssec_algorithm = \"ecdsap256\"")).is_ok());
        assert!(Config::from_toml_str(&zone(", dnssec_algorithm = \"ed25519\"")).is_ok());
        assert!(
            Config::from_toml_str(&zone(", dnssec_algorithm = \"rsasha256\"")).is_err(),
            "지원하지 않는 알고리즘은 거부해야 합니다"
        );
        assert!(
            Config::from_toml_str(&zone(", dnssec_algorithm = 13")).is_err(),
            "문자열이 아니면 거부해야 합니다"
        );
    }

    #[test]
    /** @brief DDR이 알릴 것이 없거나 이름이 틀리면 거부하는지. */
    fn ddr_name_requires_a_reachable_encrypted_listener() {
        // 알릴 암호화 수신 주소가 없으면 클라이언트를 닿지 못하는 곳으로 보내게 된다.
        assert!(Config::from_toml_str("ddr_name = \"dns.example.net\"\n").is_err());
        assert!(Config::from_toml_str(
            "ddr_name = \"dns.example.net\"\nlisten_dnscrypt = [\"127.0.0.1:5443\"]\n"
        )
        .is_err());

        // 암호화 수신 주소는 인증서 출처를 요구하므로 함께 준다.
        const CERT: &str = "tls_self_signed_host = \"dns.example.net\"\n";
        for key in ["listen_dot", "listen_doh", "listen_doq", "listen_doh3"] {
            let toml =
                format!("ddr_name = \"dns.example.net\"\n{key} = [\"127.0.0.1:8853\"]\n{CERT}");
            assert!(
                Config::from_toml_str(&toml).is_ok(),
                "{key}만 열려 있어도 알릴 것이 있습니다"
            );
        }

        let with_dot =
            |name: &str| format!("ddr_name = \"{name}\"\nlisten_dot = [\"127.0.0.1:853\"]\n{CERT}");
        assert!(Config::from_toml_str(&with_dot("dns.example.net.")).is_ok());
        assert!(Config::from_toml_str(&with_dot("dns..example")).is_err());
        assert!(Config::from_toml_str(&with_dot("dns example")).is_err());
        assert!(Config::from_toml_str(&with_dot(&"a".repeat(64))).is_err());

        // 비어 있으면 아무것도 요구하지 않는다. 기본값이다.
        assert!(Config::from_toml_str("ddr_name = \"\"\n").is_ok());
    }

    #[test]
    /** @brief 없앤 캐시 크기 키를 거부하는지. */
    fn removed_response_cache_size_is_rejected() {
        assert!(Config::from_toml_str("response_cache_size = 16\n").is_err());
    }

    #[test]
    /** @brief 루프백 밖 클러스터 동료에 암호화를 요구하는지. */
    fn cluster_peers_requires_https_off_loopback() {
        assert!(Config::from_toml_str("cluster_peers = [\"http://127.0.0.1:8553\"]\n").is_ok());
        assert!(Config::from_toml_str("cluster_peers = [\"http://localhost:8553\"]\n").is_ok());
        assert!(Config::from_toml_str("cluster_peers = [\"http://[::1]:8553\"]\n").is_ok());
        assert!(
            Config::from_toml_str("cluster_peers = [\"https://node2.example:8553\"]\n").is_ok()
        );

        assert!(
            Config::from_toml_str("cluster_peers = [\"http://node2.example:8553\"]\n").is_err()
        );
        assert!(Config::from_toml_str("cluster_peers = [\"http://10.0.0.2\"]\n").is_err());
        assert!(Config::from_toml_str("cluster_peers = [\"node2.example\"]\n").is_err());
        assert!(Config::from_toml_str("cluster_peers = [\"https://\"]\n").is_err());
    }

    #[test]
    /** @brief 갱신 규칙이 실수로 열리는 형태를 거부하는지. */
    fn update_policy_rejects_fail_open_inputs() {
        let canonical = r#"
[[tsig_keys]]
name = "dhcp-key"
secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtMzItYnl0ZXMhIQ=="

[[update_policy]]
action = "grant"
identity = "dhcp-key"
name = "*.dyn.example"
types = ["A", "AAAA", "CAA", "257"]
"#;
        assert!(Config::from_toml_str(canonical).is_ok());

        for invalid in [
            "action = \"grnat\"\nidentity = \"*\"\nname = \"*\"",
            "action = \"Grant\"\nidentity = \"*\"\nname = \"*\"",
            "identity = \"*\"\nname = \"*\"",
            "action = \"grant\"\nname = \"*\"",
            "action = \"grant\"\nidentity = \"*\"",
            "action = \"grant\"\nidentity = \"*\"\nname = \".dyn.example\"",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\ntypes = []",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\ntypes = [\"*\"]",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\ntypes = [\"a\"]",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\ntypes = [\"BOGUS\"]",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\ntypes = [\"41\"]",
            "action = \"grant\"\nidentity = \"*\"\nname = \"*\"\noops = true",
        ] {
            let text = format!("[[update_policy]]\n{invalid}\n");
            assert!(Config::from_toml_str(&text).is_err(), "{invalid}");
        }

        let mut programmatic = Config::default();
        programmatic.update_policy.push(UpdatePolicyRule {
            action: "grant".to_string(),
            identity: String::new(),
            name: "*".to_string(),
            types: vec!["A".to_string()],
        });
        assert!(programmatic.validate().is_err());
    }

    #[test]
    /** @brief 모든 테이블 배열이 모르는 필드를 거부하는지. */
    fn every_nested_config_table_rejects_unknown_fields() {
        for array in [
            "clients",
            "dynamic_records",
            "local_zones",
            "policy",
            "rewrites",
            "service_schedule",
            "stub_zones",
            "tsig_keys",
            "update_policy",
            "users",
            "views",
            "zones",
            "secondary",
            "catalog",
        ] {
            let text = format!("{array} = [{{ oops = true }}]\n");
            let error = Config::from_toml_str(&text).unwrap_err().to_string();
            assert!(
                error.contains("unknown key 'oops'"),
                "{array}가 내부 오타를 명시적으로 거부해야 함: {error}"
            );
        }
    }

    #[test]
    /** @brief 전송과 목록 설정이 테이블 배열 형태여야 하는지. */
    fn secondary_and_catalog_require_table_arrays() {
        for array in ["secondary", "catalog"] {
            let text = format!("{array} = \"not-a-table-array\"\n");
            assert!(Config::from_toml_str(&text).is_err(), "{array}");
        }
    }

    #[test]
    /** @brief 보안 관련 필드가 형이 틀리거나 암묵적으로 관리자가 되는 것을 거부하는지. */
    fn nested_security_fields_reject_wrong_types_and_implicit_admin() {
        for text in [
            "clients = [{ name = \"phone\", disable_filtering = \"true\" }]\n",
            "clients = [{ ids = [\"192.0.2.1/32\"] }]\n",
            "users = [{ name = \"ops\", password_hash = \"hash\", role = 1 }]\n",
            "users = [{ name = \"ops\", password_hash = \"hash\" }]\n",
            "views = [{ name = \"office\", clients = [\"192.0.2.0/24\"], local_a = [\"bad\"] }]\n",
            "rewrites = [{ domain = \"router.example\", answer = 1 }]\n",
            "dynamic_records = [{ values = [\"192.0.2.1\"] }]\n",
            "local_zones = [{ name = \"local\", kind = 1 }]\n",
            "stub_zones = [{ suffix = 1, servers = [\"192.0.2.53\"] }]\n",
            "zones = [{ origin = \"example\", dnssec_sign = \"true\" }]\n",
            "secondary = [{ origin = \"example\", primary = 1 }]\n",
            "policy = [{ action = \"Block\" }]\n",
            "service_schedule = [{ days = [\"Mon\"], start = \"08:00\", end = \"09:00\" }]\n",
            "dynamic_records = [{ name = \"pool.example\", qtype = \"a\", values = [\"192.0.2.1\"] }]\n",
        ] {
            assert!(Config::from_toml_str(text).is_err(), "{text}");
        }
    }

    #[test]
    /** @brief 동적 레코드 방식이 정해진 이름만 받는지. */
    fn dynamic_record_modes_accept_only_canonical_names() {
        for mode in ["random", "weighted", "round_robin", "failover"] {
            let value = if mode == "weighted" {
                "192.0.2.1|1"
            } else {
                "192.0.2.1"
            };
            let text = format!(
                "dynamic_records = [{{ name = \"pool.example\", mode = \"{mode}\", values = [\"{value}\"] }}]\n"
            );
            assert!(Config::from_toml_str(&text).is_ok(), "{mode}");
        }
        for removed_alias in ["roundrobin", "ifportup"] {
            let text = format!(
                "dynamic_records = [{{ name = \"pool.example\", mode = \"{removed_alias}\", values = [\"192.0.2.1\"] }}]\n"
            );
            assert!(Config::from_toml_str(&text).is_err(), "{removed_alias}");
        }
    }

    #[test]
    /** @brief 요일 이름이 정해진 것만 받는지. */
    fn service_schedule_days_accept_only_canonical_names() {
        for day in ["sun", "mon", "tue", "wed", "thu", "fri", "sat", "all"] {
            let text = format!(
                "service_schedule = [{{ days = [\"{day}\"], start = \"08:00\", end = \"09:00\" }}]\n"
            );
            assert!(Config::from_toml_str(&text).is_ok(), "{day}");
        }
        for removed_alias in ["sunday", "monday", "daily", "everyday"] {
            let text = format!(
                "service_schedule = [{{ days = [\"{removed_alias}\"], start = \"08:00\", end = \"09:00\" }}]\n"
            );
            assert!(Config::from_toml_str(&text).is_err(), "{removed_alias}");
        }
    }

    #[test]
    /** @brief 좁은 정수형에 넘치는 값을 거부하는지. 잘라 담으면 적은 값과 실제로 적용된 값이 달라진다. */
    fn strict_rejects_narrow_integer_overflow() {
        assert!(Config::from_toml_str("recursion_limit = 256\n").is_err());
        assert!(Config::from_toml_str("cachedb_redis_port = 70000\n").is_err());
        assert!(Config::from_toml_str("rate_limit_per_sec = 4294967296\n").is_err());
        assert!(Config::from_toml_str("proxy_protocol_ports = [53, 70000]\n").is_err());
        assert!(Config::from_toml_str(
            "zones = [{ origin = \"example.\", dnssec_nsec3_iterations = 70000 }]\n"
        )
        .is_err());
        assert!(Config::from_toml_str("recursion_limit = 255\n").is_ok());
        assert!(Config::from_toml_str("cachedb_redis_port = 65535\n").is_ok());
    }

    #[test]
    /** @brief 이 서버가 서명하는 zone의 NSEC3 반복이 0인지. 크면 검증기 CPU를 태운다. */
    fn authoritative_nsec3_iterations_must_be_zero() {
        assert!(saved_with_advisory(
            "zones = [{ origin = \"example.\", dnssec_nsec3 = true, dnssec_nsec3_iterations = 1 }]\n"
        ));
        assert!(Config::from_toml_str(
            "zones = [{ origin = \"example.\", dnssec_nsec3 = true, dnssec_nsec3_iterations = 0 }]\n"
        )
        .is_ok());
    }

    #[test]
    /** @brief 검증 NSEC3 반복 상한을 설정으로 해제하지 못하는지. */
    fn validator_nsec3_iterations_cannot_exceed_the_hard_limit() {
        assert!(Config::from_toml_str("val_nsec3_max_iterations = 150\n").is_ok());
        let error = Config::from_toml_str("val_nsec3_max_iterations = 151\n").unwrap_err();
        assert!(format!("{error}").contains("at most 150"));
    }

    #[test]
    /** @brief 배열 항목 하나가 틀려도 거부하는지. */
    fn strict_rejects_invalid_array_elements() {
        let e = Config::from_toml_str("acl_allow = [\"192.168.0.0/24\", \"not-a-cidr\"]\n");
        assert!(e.is_err());
        assert!(format!("{}", e.unwrap_err()).contains("acl_allow[1]"));

        assert!(Config::from_toml_str("listen = [\"127.0.0.1:53\", \"bad-addr\"]\n").is_err());

        assert!(Config::from_toml_str("upstreams = [\"1.1.1.1\", \"1.1.1.1:53\"]\n").is_err());

        assert!(Config::from_toml_str("upstream_urls = [\"no-scheme-here\"]\n").is_err());

        assert!(Config::from_toml_str("rate_limit_allow = [\"oops\"]\n").is_err());

        assert!(Config::from_toml_str(
            "acl_allow = [\"10.0.0.0/8\"]\nlisten = [\"0.0.0.0:53\"]\nupstreams = [\"1.1.1.1\"]\n"
        )
        .is_ok());
    }

    #[test]
    /** @brief 지나치게 큰 설정 파일을 파싱 전에 거부하는지. */
    fn rejects_oversized_config_before_parsing() {
        let oversized = " ".repeat(MAX_CONFIG_BYTES as usize + 1);
        assert!(Config::from_toml_str(&oversized).is_err());
    }

    #[test]
    /** @brief 클라이언트 인증이 암호화 리스너 위에서만 켜지는지. */
    fn mtls_requires_tls_listener() {
        let toml = "tls_client_ca = \"ca.pem\"\n";
        assert!(saved_with_advisory(toml));
        assert!(!Config::default().tls_authenticated());

        let toml = concat!(
            "listen_dot = [\"127.0.0.1:853\"]\n",
            "tls_self_signed_host = \"dns.test\"\n",
            "tls_client_ca = \"ca.pem\"\n",
        );
        let cfg = Config::from_toml_str(toml).unwrap();
        assert!(cfg.tls_authenticated());
    }

    #[test]
    /** @brief 앵커 파일이 고정 방식과 자동 갱신 방식 모두에 쓰이는지. */
    fn anchor_file_supports_static_or_rfc5011_managed_trust() {
        let toml = "dnssec_anchor_file = \"anchors.txt\"\n";
        assert!(
            saved_with_advisory(toml),
            "저장은 되되 효과가 없다고 알려야 함"
        );

        let toml = concat!(
            "backend = \"recurse\"\n",
            "dnssec = true\n",
            "dnssec_anchor_file = \"anchors.txt\"\n",
        );
        assert!(Config::from_toml_str(toml).is_ok());

        let toml = concat!(
            "backend = \"recurse\"\n",
            "dnssec_rfc5011 = true\n",
            "dnssec_anchor_file = \"anchors.txt\"\n",
        );
        assert!(
            saved_with_advisory(toml),
            "저장은 되되 효과가 없다고 알려야 함"
        );

        let toml = concat!(
            "backend = \"recurse\"\n",
            "dnssec = true\n",
            "dnssec_rfc5011 = true\n",
            "dnssec_anchor_file = \"anchors.txt\"\n",
        );
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(
            cfg.dnssec_anchor_file.as_deref(),
            Some(std::path::Path::new("anchors.txt"))
        );

        // 전달 방식도 이 앵커로 체인을 세우므로 더 이상 효과가 없는 설정이 아니다.
        let toml = concat!(
            "backend = \"forward\"\n",
            "upstreams = [\"1.1.1.1\"]\n",
            "dnssec = true\n",
            "dnssec_rfc5011 = true\n",
            "dnssec_anchor_file = \"anchors.txt\"\n",
        );
        assert!(
            !saved_with_advisory(toml),
            "전달 방식도 이 앵커를 쓰는데 효과가 없다고 알렸습니다"
        );

        // 대조군. 꺼 두면 그때는 정말 쓰이지 않으므로 알려야 한다.
        let toml = concat!(
            "backend = \"forward\"\n",
            "upstreams = [\"1.1.1.1\"]\n",
            "dnssec = false\n",
            "dnssec_anchor_file = \"anchors.txt\"\n",
        );
        assert!(
            saved_with_advisory(toml),
            "꺼 두었는데 효과가 없다고 알리지 않았습니다"
        );
    }

    #[test]
    /** @brief zone 백엔드 설정이 읽히고 검증되는지. */
    fn zone_backend_keys_parse_and_validate() {
        let toml = concat!(
            "zones_db = \"zones.db\"
",
            "zones_db_table = \"my_zones\"
",
            "zones_etcd = \"http://127.0.0.1:2379\"
",
            "zones_etcd_prefix = \"/dns/zones/\"
",
        );
        let cfg = Config::from_toml_str(toml).unwrap();
        assert_eq!(
            cfg.zones_db.as_deref(),
            Some(std::path::Path::new("zones.db"))
        );
        assert_eq!(cfg.zones_db_table, "my_zones");
        assert_eq!(cfg.zones_etcd.as_deref(), Some("http://127.0.0.1:2379"));
        assert_eq!(cfg.zones_etcd_prefix, "/dns/zones/");

        let d = Config::default();
        assert_eq!(d.zones_db_table, "zones");
        assert_eq!(d.zones_etcd_prefix, "/onetdns/zones/");

        let https = concat!(
            "zones_etcd = \"https://etcd.example:2379\"
",
            "zones_etcd_ca = \"etcd-ca.pem\"
",
            "zones_etcd_user = \"root\"
",
            "zones_etcd_password = \"hunter2\"
",
        );
        let c = Config::from_toml_str(https).unwrap();
        assert_eq!(
            c.zones_etcd_ca.as_deref(),
            Some(std::path::Path::new("etcd-ca.pem"))
        );
        assert_eq!(c.zones_etcd_user.as_deref(), Some("root"));

        let ej = c.effective_json();
        assert!(!ej.contains("hunter2"), "etcd 비밀번호 마스킹");
        assert!(ej.contains("\"zones_etcd_auth\":true"));
        assert!(Config::from_toml_str("zones_etcd = \"https://x:2379\"\n").is_err());
    }

    #[test]
    /** @brief 적용 설정 JSON이 유효하고 비밀을 가리는지. */
    fn effective_json_is_valid_and_masks_secrets() {
        let toml = concat!(
            "control_listen = \"127.0.0.1:8080\"
",
            "control_token = \"super-secret-token-0123456789\"
",
            "zones_postgres = \"postgres://dns:pg-secret@127.0.0.1/zones\"\n",
            "zones_mysql = \"mysql://dns:mysql-secret@127.0.0.1/zones\"\n",
            "[[tsig_keys]]
",
            "name = \"xfer-key\"
",
            "secret = \"MDEyMzQ1Njc4OWFiY2RlZg==\"
",
        );
        let cfg = Config::from_toml_str(toml).unwrap();
        let j = cfg.effective_json();

        let parsed = onetdns_core::json::parse(&j).expect("유효한 JSON이어야");

        assert_eq!(
            parsed.get("cache_size").and_then(|v| v.as_num()),
            Some(4096.0),
            "기본 cache_size 노출"
        );
        assert_eq!(
            parsed
                .get("mode")
                .and_then(|v| v.as_str().map(String::from)),
            Some("personal".to_string())
        );

        assert!(!j.contains("super-secret-token"), "control_token 마스킹");
        assert!(!j.contains("c2VjcmV0"), "TSIG secret 마스킹");
        assert!(!j.contains("pg-secret"), "PostgreSQL 비밀번호 마스킹");
        assert!(!j.contains("mysql-secret"), "MySQL 비밀번호 마스킹");
        assert!(j.contains("postgres://dns:***@127.0.0.1/zones"));
        assert!(j.contains("mysql://dns:***@127.0.0.1/zones"));

        assert!(j.contains("xfer-key"));

        assert_eq!(
            parsed.get("control_admin_tokens").and_then(|v| v.as_num()),
            Some(1.0)
        );
    }

    #[test]
    /** @brief 자격증명만 가리고 주소는 남기는지. 주소는 진단에 필요하다. */
    fn url_credentials_are_redacted_without_hiding_endpoint() {
        assert_eq!(
            redact_url_credentials("postgres://alice:p%40ss@127.0.0.1:5432/zones?sslmode=disable"),
            "postgres://alice:***@127.0.0.1:5432/zones?sslmode=disable"
        );
        assert_eq!(
            redact_url_credentials("mysql://127.0.0.1/zones"),
            "mysql://127.0.0.1/zones"
        );
        assert_eq!(redact_url_credentials("not-a-url"), "<redacted-url>");
    }

    #[test]
    /** @brief 업스트림 선택 방식 값들이 읽히는지. */
    fn upstream_strategy_values() {
        assert_eq!(dec_strategy("parallel"), UpstreamStrategy::Parallel);
        assert_eq!(dec_strategy("user_order"), UpstreamStrategy::UserOrder);
        assert_eq!(dec_strategy("round_robin"), UpstreamStrategy::RoundRobin);
        assert_eq!(
            dec_strategy("query_statistics"),
            UpstreamStrategy::QueryStatistics
        );
        assert_eq!(dec_strategy("???"), UpstreamStrategy::QueryStatistics);
    }

    #[test]
    /** @brief 업스트림이 자기 자신을 가리키면 거부하는지. 질의가 무한히 돌아온다. */
    fn rejects_direct_dns_self_reference() {
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nupstreams = [\"127.0.0.1\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"0.0.0.0:53\"]\nupstream_urls = [\"udp://127.0.0.1:53\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nfallback_upstreams = [\"127.0.0.1\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nupstream_urls = [\"tls://127.0.0.1:853\"]\n"
        )
        .is_ok());
        assert!(
            Config::from_toml_str("listen = [\"[::]:53\"]\nupstreams = [\"127.0.0.1\"]\n").is_err()
        );
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nupstream_urls = [\"udp://[::ffff:127.0.0.1]:53\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nbootstrap = [\"127.0.0.1\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\nroot_hints = [\"::ffff:127.0.0.1\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\n[[stub_zones]]\nsuffix = \"corp.test\"\nservers = [\"localhost\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen = [\"127.0.0.1:53\"]\n[[clients]]\nname = \"local\"\nids = [\"127.0.0.1/32\"]\nupstreams = [\"localhost\"]\n"
        )
        .is_err());
        assert!(Config::from_toml_str(
            "listen_doh = [\"127.0.0.1:443\"]\nupstream_urls = [\"https://localhost/dns-query\"]\n"
        )
        .is_err());
    }

    #[test]
    /** @brief 순환 검사를 위해 업스트림 주소를 추출하는지. */
    fn parses_numeric_upstream_endpoints_for_loop_checks() {
        assert_eq!(
            numeric_upstream_endpoint("udp://127.0.0.1"),
            Some("127.0.0.1:53".parse().unwrap())
        );
        assert_eq!(
            numeric_upstream_endpoint("https://[::1]:444/dns-query"),
            Some("[::1]:444".parse().unwrap())
        );
        assert_eq!(
            numeric_upstream_endpoint("udp://localhost:5300"),
            Some("127.0.0.1:5300".parse().unwrap())
        );
        assert!(numeric_upstream_endpoint("https://dns.example/dns-query").is_none());
    }
}
