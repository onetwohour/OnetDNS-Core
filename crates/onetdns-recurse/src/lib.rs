/*!
 * @brief 반복 질의 재귀 해석.
 *
 * @details 루트에서 시작해 위임을 따라 내려가며 스스로 답을 찾는다. 업스트림에 맡기지 않으므로
 *          어느 서버를 믿을지 이 서버가 직접 판단해야 하고, 그 판단이 이 크레이트의 대부분이다.
 * @warning bailiwick이 핵심 안전 속성이다. 참조는 질의 이름 쪽으로 더 가까워지고 현재
 *          zone 안일 때만 따라간다. 이 검사가 느슨하면 어떤 서버든 남의 zone을 가로챌 수 있다.
 * @note 예산 상한이 여럿이다. 참조·CNAME·DNAME·부수 질의 횟수가 각각 묶여 있어야 질의
 *       한 건이 이 서버를 무한정 붙잡지 못한다.
 */

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use onetdns_core::{IpNet, LruMap, MutexExt};
use onetdns_proto::{
    ede_code, DnsClass, Edns, Header, Message, Name, Question, RData, Record, RecordType,
    ResponseCode,
};

/** @brief 진단 추적이 켜졌는지. 환경 변수를 한 번만 읽어 기억한다. */
fn recurse_trace_enabled() -> bool {
    /** @brief 한 번만 읽어 둔 판정. */
    static E: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *E.get_or_init(|| std::env::var_os("ONETDNS_RECURSE_TRACE").is_some())
}
macro_rules! rtrace {
    ($($arg:tt)*) => {
        if recurse_trace_enabled() {
            eprintln!("[recurse] {}", format_args!($($arg)*));
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 재귀 해석 실패 사유. */
pub enum RecurseError {
    /** @brief 루트 서버 목록이 비어 있다. */
    NoRoots,

    /** @brief 아무 서버도 답하지 않았다. */
    NoResponse,

    /** @brief 참조 예산을 다 썼다. 위임 순환에 걸렸을 수 있다. */
    TooManyReferrals,

    /** @brief CNAME 체인이 예산을 넘었다. */
    TooManyCnames,

    /** @brief DNAME 체인이 예산을 넘었다. */
    TooManyDnames,

    /** @brief 네임서버 주소를 푸는 부수 질의가 예산을 넘었다. */
    TooManyQueries,

    /** @brief 위임된 서버가 전부 응답하지 않거나 권한이 없다. 이 실패는 질의자에게 그대로 전한다. */
    NoReachableNs,

    /** @brief DNSSEC 검증이 깨졌다. 응답을 내보내면 안 된다. */
    Bogus,
}

impl std::fmt::Display for RecurseError {
    /** @brief 사람이 읽을 실패 사유. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RecurseError::NoRoots => "No root server hints",
            RecurseError::NoResponse => "The queried server did not respond",
            RecurseError::TooManyReferrals => "Followed too many delegations",
            RecurseError::TooManyQueries => "Query needs too many upstream queries",
            RecurseError::TooManyCnames => "Followed too many CNAMEs",
            RecurseError::TooManyDnames => "Followed too many DNAMEs",
            RecurseError::NoReachableNs => "No reachable name server",
            RecurseError::Bogus => "DNSSEC validation failed",
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for RecurseError {}

thread_local! {

    /** @brief 클라이언트가 검증을 끄라고 했는지. 질의마다 설정한다. */
    static HONOR_CD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/**
 * @brief 지금 이 스레드가 CD 비트를 존중하는 중인지.
 * @details 질의자가 CD를 설정하면 검증을 건너뛰고 답을 그대로 준다. 이 상태를 인자로
 *          모든 함수에 흘리는 대신 스레드 지역 값으로 둔다.
 */
fn honor_cd_active() -> bool {
    HONOR_CD.with(|h| h.get())
}

/** @brief CD 존중 상태를 잠시 바꿨다가 되돌리는 범위 보호자. */
struct HonorCdScope {
    /** @brief 이곳에 들어오기 전의 값. 나갈 때 되돌린다. */
    previous: bool,
}

impl HonorCdScope {
    /** @brief 상태를 바꾸고 이전 값을 기억한다. */
    fn enter(honor: bool) -> Self {
        Self {
            previous: HONOR_CD.with(|state| state.replace(honor)),
        }
    }
}

impl Drop for HonorCdScope {
    /** @brief 이전 값으로 되돌린다. 중첩 호출에서도 상태가 새지 않는다. */
    fn drop(&mut self) {
        HONOR_CD.with(|state| state.set(self.previous));
    }
}

/** @brief 주어진 CD 존중 상태로 클로저를 실행한다. */
fn with_honor_cd<T>(honor: bool, f: impl FnOnce() -> T) -> T {
    let _scope = HonorCdScope::enter(honor);
    f()
}

/**
 * @brief 재귀 리졸버 하나. 캐시와 설정을 함께 가지고 있다.
 * @details 여러 스레드가 같은 인스턴스를 공유한다. 모든 캐시가 뮤텍스 뒤에 있고, 질의
 *          경로는 잠금을 짧게 잡았다 바로 놓는다.
 */
pub struct Recursor {
    /** @brief 루트 서버 주소들. 여기서 모든 해석이 시작된다. */
    roots: Vec<SocketAddr>,
    /** @brief 질의 하나의 전체 데드라인. 개별 왕복이 아니라 해석 전체에 걸린다. */
    timeout: Duration,

    /** @brief 업스트림에 접속할 포트. 테스트에서만 53이 아닌 값을 쓴다. */
    port: u16,
    /** @brief 따라갈 참조 수 상한. */
    max_referrals: usize,
    /** @brief 따라갈 CNAME 수 상한. */
    max_cnames: usize,
    /** @brief 따라갈 DNAME 수 상한. */
    max_dnames: usize,

    /** @brief 네임서버 주소를 푸는 부수 질의 수 상한. 이것이 없으면 위임 체인 하나가 질의를 폭증시킨다. */
    max_ns_resolves: usize,

    /** @brief 루트 신뢰 앵커. 자동 갱신이 켜지면 밖에서 바뀌므로 원자 교체로 둔다. */
    trust_anchors: std::sync::Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,

    /** @brief 참이면 검증 실패를 전부 Bogus로 본다. */
    strict: bool,

    /** @brief 참이면 검증 실패를 알리되 응답은 준다. 진단용이며 운영에서는 쓰지 않는다. */
    permissive: bool,

    /** @brief 0x20 인코딩. 질의 이름의 대소문자를 섞어 응답 위조 난도를 올린다. */
    caps_for_id: bool,

    /**
     * @brief 참이면 권한 서버에 TCP로만 묻는다.
     * @details UDP 53번이 중간에서 가로채이는지는 인스턴스가 아니라 호스트 망의 성질이다.
     *          설정을 다시 읽어 인스턴스를 새로 만들어도 판정이 이어지도록, 판정하는 쪽이
     *          가진 값을 공유한다.
     */
    authority_tcp: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /** @brief 나가는 질의 이름을 소문자로 내린다. 캐시 적중률을 올리지만 0x20과는 함께 쓸 수 없다. */
    lowercase_outgoing: bool,

    /** @brief 참이면 질의자의 CD 비트를 무시하고 항상 검증한다. */
    ignore_cd: bool,

    /** @brief 질의하지 않을 업스트림 주소 대역. */
    deny_servers: Vec<IpNet>,

    /** @brief 비어 있지 않으면 이 대역만 질의한다. */
    allow_servers: Vec<IpNet>,

    /** @brief IPv4 업스트림을 쓸지. */
    do_ip4: bool,
    /** @brief IPv6 업스트림을 쓸지. */
    do_ip6: bool,
    /** @brief IPv6를 먼저 시도할지. */
    prefer_ip6: bool,
    /** @brief IPv4를 먼저 시도할지. */
    prefer_ip4: bool,

    /** @brief 이름 최소화를 엄격히 할지. 느슨하면 일부 서버와의 호환을 위해 전체 이름으로 전환한다. */
    qname_min_strict: bool,

    /** @brief 참조 경로를 더 엄격히 본다. 업스트림 zone이 내려 준 네임서버만 인정한다. */
    harden_referral_path: bool,

    /** @brief 검증에서 뺄 도메인들. 운영자가 명시적으로 지정한 것만 들어간다. */
    domain_insecure: Vec<Name>,

    /** @brief 루트 키 센티널 질의에 답할지. 어떤 앵커를 쓰는지 밖에서 확인할 수 있게 한다. */
    root_key_sentinel: bool,

    /** @brief 받아들일 NSEC3 반복 상한. 이것을 넘는 zone은 검증하지 않는다. */
    nsec3_max_iterations: u16,

    /** @brief 캐시에 담을 TTL 상한. */
    recursive_cache_ttl_max: u32,

    /**
     * @brief 서버와 zone 쌍마다의 실패 기록. 어느 서버를 먼저 물을지 정하는 근거다.
     * @note 무응답과 lame 응답은 서버가 그 zone을 제대로 맡고 있는지의 문제라 zone마다 따로 본다.
     */
    infra: std::sync::Mutex<LruMap<InfraKey, InfraStat>>,

    /**
     * @brief 주소마다의 평활 왕복 시간.
     * @note 왕복 시간은 그 주소까지의 경로가 정하므로 zone과 무관하다. zone마다 따로 재면 한
     *       zone에서 느리다고 잰 서버를 같은 서버가 맡은 부모 zone에서는 처음 보는 서버로 보고
     *       가장 먼저 묻는다.
     */
    rtt: std::sync::Mutex<LruMap<IpAddr, u32>>,

    /** @brief 네임서버 이름에서 주소로 가는 캐시. 부수 질의를 크게 줄인다. */
    ns_addr_cache: std::sync::Mutex<LruMap<Vec<u8>, NsAddrEntry>>,

    /** @brief zone별 위임 서버 캐시. 루트부터 다시 내려가지 않게 해 준다. */
    deleg_cache: std::sync::Mutex<LruMap<Vec<u8>, DelegationEntry>>,

    /** @brief zone별 DNSKEY 응답 캐시. */
    dnskey_cache: std::sync::Mutex<LruMap<Vec<u8>, DnskeyEntry>>,
    /** @brief 검증까지 끝난 키 캐시. 체인 전체를 매번 다시 걷지 않게 한다. */
    validated_keys: std::sync::Mutex<LruMap<Vec<u8>, ValidatedKeyEntry>>,

    /** @brief 뒤에서 마저 해석 중인 질의. 같은 질의를 두 번 돌리지 않는다. */
    background: std::sync::Mutex<HashSet<(Vec<u8>, RecordType)>>,
}

/**
 * @brief 뒤에서 동시에 마저 해석할 질의 수 상한.
 * @note 끝내지 못한 질의가 이보다 많이 쌓이면 권한 서버 쪽 망이 막힌 것이라, 더 돌려도 채울
 *       캐시 없이 스레드와 질의만 쓴다.
 */
const MAX_BACKGROUND_COMPLETIONS: usize = 16;

/**
 * @brief 뒤에서 마저 해석할 만한 결과인지.
 * @details 아무 서버도 답하지 않았거나, 해석 예산의 데드라인을 넘겨 실패한 경우다. 데드라인을
 *          넘긴 해석은 검증에 쓸 키를 받지 못해 SERVFAIL 응답으로 끝나기도 한다.
 */
fn unfinished(result: &Result<(Message, NsContext), RecurseError>, deadline: Instant) -> bool {
    match result {
        Err(RecurseError::NoResponse) => true,
        Err(_) => Instant::now() >= deadline,
        Ok((message, _)) => {
            message.header.rcode == ResponseCode::ServFail.0 && Instant::now() >= deadline
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/** @brief 서버 통계의 키. 같은 주소라도 zone마다 응답성이 다르므로 둘을 함께 쓴다. */
struct InfraKey {
    /** @brief 서버 주소. */
    ip: IpAddr,
    /** @brief 그 서버가 맡은 zone의 정규 키. */
    zone: Vec<u8>,
}

impl InfraKey {
    /** @brief 주소와 zone으로 키를 만든다. */
    fn new(ip: IpAddr, zone: &Name) -> Self {
        Self {
            ip,
            zone: zone.canonical_key(),
        }
    }
}

#[derive(Default)]
/** @brief 서버와 zone 쌍 하나의 실패 기록. */
struct InfraStat {
    /** @brief 마지막 실패 시각. 잠깐 뒤로 미루는 데 쓴다. */
    last_fail: Option<Instant>,

    /** @brief 마지막 프로토콜 오류 시각. 응답은 왔지만 쓸 수 없던 경우다. */
    last_protocol_error: Option<Instant>,
}

/** @brief 재 본 적 없는 서버에 매길 왕복 시간. 새 서버가 무조건 뒤로 밀리지 않게 한다. */
const DEFAULT_RTT_MS: u32 = 50;

/**
 * @brief 처음 보는 서버의 답을 기다렸다가 다음 서버에도 물을 때까지의 시간.
 * @note 대부분의 권한 서버는 UDP로 이 안에 답한다. 더 짧으면 처음 보는 서버마다 질의가 두
 *       배로 나가고, 더 길면 답하지 않는 서버 하나에 그만큼씩 시간을 쓴다.
 */
const UNKNOWN_SERVER_PATIENCE: Duration = Duration::from_millis(400);

/**
 * @brief 질의 하나가 동시에 답을 기다리는 교환 수 상한.
 * @details 느린 서버 하나의 답을 기다리면서 다음 서버에 묻는 데는 둘이면 된다. 더 늘리면
 *          워커 하나가 동시에 걸어 두는 질의가 늘어, 응답을 한꺼번에 몰아오게 하는
 *          DNSBomb류 공격에 쓸 폭이 넓어진다.
 */
const MAX_EXCHANGES_PER_QUERY: usize = 2;

/**
 * @brief 잰 왕복 시간이 아무리 짧아도 다음 서버에 묻기 전에 기다리는 시간.
 * @note 가까운 서버는 스케줄링 지연만으로 왕복 시간의 세 배를 넘길 수 있다. 그때마다 질의를
 *       두 번 보내지 않게 한다.
 */
const MIN_SERVER_PATIENCE: Duration = Duration::from_millis(100);

/** @brief 실패한 서버를 뒤로 미룰 기간. 지나면 다시 정상 순위로 돌아온다. */
const INFRA_FAIL_COOLDOWN: Duration = Duration::from_secs(30);

/** @brief 최근 실패한 서버에 더할 가상 지연. 순위를 크게 낮추되 완전히 배제하지는 않는다. */
const INFRA_FAIL_PENALTY_MS: u64 = 100_000;
/** @brief 프로토콜 오류를 낸 서버에 더할 가상 지연. 무응답보다는 가볍게 본다. */
const INFRA_PROTOCOL_PENALTY_MS: u64 = 10_000;

/** @brief 서버 통계 캐시 크기. */
const MAX_INFRA: usize = 50_000;
/** @brief 설정으로 지정할 수 있는 네임서버 캐시 크기 상한. */
const MAX_NS_CACHE_CONFIGURED: usize = 1_000_000;

#[derive(Clone, Copy)]
/**
 * @brief 캐시 항목의 만료 시각.
 * @details 시스템 시계가 아니라 프로세스 단조 시계의 밀리초를 쓴다. 시계를 되돌려도
 *          만료가 뒤틀리지 않는다.
 */
struct TtlLifetime {
    /** @brief 단조 시계 기준 만료 시각. */
    expires_at_millis: u64,
}

impl TtlLifetime {
    /** @brief TTL 초에서 만료 시각을 만든다. */
    fn new(ttl_secs: u32) -> Self {
        Self {
            expires_at_millis: cache_now_millis()
                .saturating_add(u64::from(ttl_secs).saturating_mul(1_000)),
        }
    }

    #[cfg(test)]
    /** @brief 남은 시간. 이미 지났으면 없다. */
    fn remaining(self, now_millis: u64) -> Option<Duration> {
        let millis = self.expires_at_millis.checked_sub(now_millis)?;
        (millis > 0).then(|| Duration::from_millis(millis))
    }

    /** @brief 남은 초. 응답 TTL로 내보낼 때 쓰며 올림한다. 내림하면 0초짜리 답이 나간다. */
    fn remaining_secs(self, now_millis: u64) -> Option<u32> {
        let millis = self.expires_at_millis.checked_sub(now_millis)?;
        (millis > 0).then(|| millis.div_ceil(1_000).min(u64::from(u32::MAX)) as u32)
    }

    /** @brief 아직 살아 있는지. */
    fn is_live(self, now_millis: u64) -> bool {
        self.expires_at_millis > now_millis
    }

    #[cfg(test)]
    /** @brief 이미 만료된 값. 테스트에서 만료 경로를 태울 때 쓴다. */
    fn expired() -> Self {
        Self {
            expires_at_millis: 0,
        }
    }
}

/**
 * @brief 프로세스 시작 기준 경과 밀리초.
 * @note 시작 시각을 한 번만 잡아 두고 그 뒤로는 경과만 측정한다. 시스템 시계 변경에 영향받지 않는다.
 */
fn cache_now_millis() -> u64 {
    /** @brief 기준 시각. 시스템 시계가 바뀌어도 흔들리지 않게 한다. */
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/** @brief 네임서버 주소 캐시 항목. */
struct NsAddrEntry {
    /** @brief 그 이름의 주소들. */
    addrs: Vec<IpAddr>,
    /** @brief 이 항목의 만료 시각. */
    lifetime: TtlLifetime,
}

/** @brief 네임서버 주소 캐시 크기. */
const NS_ADDR_CACHE_MAX: usize = 4_096;

/** @brief 이름 하나에 담을 주소 수 상한. 주소를 잔뜩 담은 응답으로 캐시를 채우지 못하게 한다. */
const MAX_CACHED_NS_ADDRS: usize = 64;

/** @brief 위임 캐시 항목. */
struct DelegationEntry {
    /** @brief 그 zone을 맡은 서버 주소들. */
    servers: Vec<SocketAddr>,
    /** @brief 이 항목의 만료 시각. */
    lifetime: TtlLifetime,
}

/** @brief 위임 캐시 크기. */
const DELEGATION_CACHE_MAX: usize = 4_096;

/** @brief DNSKEY 응답 캐시 항목. 검증 전 상태다. */
struct DnskeyEntry {
    /** @brief DNSKEY 레코드들. */
    records: Vec<Record>,
    /** @brief 그 RRset을 덮는 서명들. */
    signatures: Vec<onetdns_dnssec::Rrsig>,
    /** @brief 이 항목의 만료 시각. */
    lifetime: TtlLifetime,
}

/** @brief DNSKEY 캐시 크기. */
const DNSKEY_CACHE_MAX: usize = 4_096;

/**
 * @brief 검증까지 끝난 키 캐시 항목.
 * @note 그때 쓴 앵커를 함께 담는다. 앵커가 바뀌면 이 항목은 더 이상 유효하지 않다.
 */
struct ValidatedKeyEntry {
    /** @brief 체인을 검증해 얻은 이 zone의 신뢰 상태. */
    trust: ZoneTrust,
    /** @brief 검증에 쓴 앵커. 이것이 달라지면 캐시를 버려야 한다. */
    anchors: std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
    /** @brief 이 항목의 만료 시각. */
    lifetime: TtlLifetime,
}

#[derive(Clone)]
/**
 * @brief 앵커에서 체인을 끝까지 검증해 얻은 zone의 신뢰 상태.
 * @details 서명되지 않은 영역이라는 판정도 담는다. 담지 않으면 그런 영역은 캐시된 위임에서
 *          시작할 수 없어 질의마다 루트부터 다시 걷는다.
 */
enum ZoneTrust {
    /** @brief 앵커에서 이어진 서명으로 확인한 zone 키. */
    Secure(std::sync::Arc<[onetdns_dnssec::Dnskey]>),
    /** @brief 상위 zone이 서명으로 DS 부재를 증명해 서명을 검증하지 않는 영역. */
    Insecure,
}

/** @brief 검증된 키 캐시 크기. */
const VALIDATED_KEY_CACHE_MAX: usize = 4_096;

/**
 * @brief 검증 결과를 얼마나 캐시할 수 있는지.
 * @details 체인에 든 레코드의 TTL과 서명 만료까지 남은 시간 중 가장 짧은 것을 쓴다.
 *          서명이 만료된 뒤에도 검증 결과를 쓰면 폐기된 키를 계속 믿게 된다.
 * @note 만료 비교는 순환 산술이다. 이미 지난 서명은 0으로 바꾼다.
 */
fn chain_validity_ttl(links: &[onetdns_dnssec::ChainLink], now: u32) -> u32 {
    let remaining = |expiration: u32| {
        let left = expiration.wrapping_sub(now);
        if left < 0x8000_0000 {
            left
        } else {
            0
        }
    };
    let mut ttl = u32::MAX;
    for link in links {
        for record in link
            .dnskeys
            .iter()
            .chain(&link.ds_records)
            .chain(&link.ds_nsec_records)
            .chain(&link.ds_nsec3_records)
        {
            ttl = ttl.min(record.ttl);
        }
        for signature in link
            .dnskey_rrsigs
            .iter()
            .chain(&link.ds_rrsigs)
            .chain(&link.ds_nsec_rrsigs)
            .chain(&link.ds_nsec3_rrsigs)
        {
            ttl = ttl.min(remaining(signature.expiration));
        }
    }
    if ttl == u32::MAX {
        0
    } else {
        ttl
    }
}

/**
 * @brief 부재 증명에서 받아들일 NSEC3 해시 반복 횟수 상한.
 *
 * @details 반복 횟수는 응답을 만든 zone이 정하고, 검증기는 그 횟수만큼 해시를 돌려야 한다.
 *          상한이 없으면 질의 한 건으로 임의의 해시 연산을 강제할 수 있다
 *          (CVE-2023-50868·CVE-2026-1519 계열).
 * @note    초과하는 NSEC3는 증명에서 제외되어 인증된 부재로 인정되지 않는다.
 */
const DEFAULT_NSEC3_MAX_ITERATIONS: u16 = onetdns_dnssec::MAX_NSEC3_ITERATIONS;

/**
 * @brief 클라이언트 질의 하나가 유발할 수 있는 총 발신 질의 수.
 *
 * @details 위임 추적과 NS 주소 해석이 서로를 부르며 넓어지는 것을 막는 절대 카운터다
 *          (NXNSAttack 계열). BIND의 max-recursion-queries와 같은 목적이다.
 * @note    정상 최악(별칭 8홉 × 위임 5단계 × 위임당 referral 1 + NS 주소 A/AAAA 2)이
 *          대략 120이므로 두 배 여유를 둔다.
 * @warning ns_resolves와 달리 되돌리지 않는다. 되돌리면 상한의 의미가 사라진다.
 */
const MAX_TOTAL_QUERIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * @brief 응답의 DNSSEC 상태.
 * @note 셋을 합치면 안 된다. Insecure는 서명 없는 정상 zone이라 응답을 주고, Bogus는
 *       서명이 깨진 것이라 SERVFAIL로 막는다.
 */
enum SecurityStatus {
    /** @brief 검증됐다. */
    Secure,

    /** @brief 서명이 없는 구간이다. */
    Insecure,

    /**
     * @brief 검증을 통과하지 못했다. 값은 클라이언트에 알릴 EDE 사유다.
     * @details 서명이 맞지 않는 경우뿐 아니라, 검증에 쓸 키를 받지 못해 서명되지 않았다는
     *          증명도 할 수 없는 경우도 여기에 든다. 둘 다 답을 내보낼 수 없지만 사유는 다르다.
     */
    Bogus(u16),
}

impl SecurityStatus {
    /**
     * @brief 두 상태를 합친다. 나쁜 쪽이 이긴다.
     * @details 한 응답에 여러 RRset이 들어오면 그중 하나만 깨져도 응답 전체를 믿을 수 없다.
     */
    fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bogus(code), _) => Self::Bogus(code),
            (_, Self::Bogus(code)) => Self::Bogus(code),
            (Self::Insecure, _) | (_, Self::Insecure) => Self::Insecure,
            _ => Self::Secure,
        }
    }
}

/**
 * @brief 클라이언트 질의 하나가 쓸 수 있는 해석 자원.
 *
 * @details 중첩 해석(글루 없는 NS의 A/AAAA 조회 등)에 &mut로 그대로 전달되므로, 재귀
 *          트리 전체가 이 하나를 나눠 쓴다. 호출 깊이마다 새로 만들면 상한이 무의미해진다.
 * @invariant queries는 감소만 한다.
 */
struct Budget {
    /**
     * @brief NS 이름 해석에 쓸 토큰. 이름 하나마다 하나씩 쓴다.
     * @warning 캐시된 위임에서 시작한 시도가 실패하면 오탐 SERVFAIL을 막으려고 되돌린다.
     *          그래서 절대 상한이 아니며, queries가 그 역할을 맡는다.
     */
    ns_resolves: usize,
    /** @brief 남은 총 발신 질의 수. 되돌리지 않는다. */
    queries: usize,
    /** @brief 이 해석의 벽시계 데드라인. 중첩 해석도 같은 데드라인을 공유한다. */
    deadline: Instant,
}

/** @brief 위임을 따라 내려가는 중의 현재 위치. */
struct IterationState {
    /** @brief 지금 물어보고 있는 zone. */
    zone: Name,

    /** @brief 그 zone을 맡은 서버 주소들. */
    servers: Vec<SocketAddr>,

    /** @brief 지금까지 확정한 라벨 수. 이름 최소화의 진행 정도다. */
    depth: usize,

    /** @brief 이름 최소화를 계속할지. 상대가 받아 주지 않으면 꺼서 전체 이름으로 전환한다. */
    minimize: bool,

    /** @brief 루트부터 여기까지의 단계들. DNSSEC 체인을 만들 재료가 된다. */
    chain: Vec<ZoneStep>,

    /**
     * @brief 지금 영역의 네임서버 가운데 주소를 아직 풀지 않은 이름들.
     * @details 주소는 쓸 수 있는 것이 하나 생기면 그만 푼다. 그 주소들이 모두 답하지 않을 때만
     *          여기서 하나씩 더 푼다.
     */
    unresolved_ns: Vec<Name>,
}

/** @brief 다음에 보낼 질의의 모양. */
struct NextQuery {
    /** @brief 물어볼 라벨 수. */
    target: usize,
    /** @brief 전체 이름을 묻는 마지막 단계인지. */
    is_final: bool,
    /** @brief 실제로 보낼 이름. 최소화 중이면 접미사만이다. */
    mname: Name,
    /** @brief 보낼 타입. 최소화 중에는 NS를 묻는다. */
    mtype: RecordType,
}

/** @brief 반복 내내 바뀌지 않는 질의 정보. */
struct IterationContext<'a> {
    /** @brief 최종 목표 이름. */
    qname: &'a Name,
    /** @brief 최종 목표 타입. */
    qtype: RecordType,
    /** @brief 목표 이름의 라벨 수. */
    total: usize,
    /**
     * @brief 업스트림에 DNSSEC 레코드를 함께 달라고 할지.
     *
     * @details 언제나 참이다. 검증하지 않더라도 DO=1로 묻는 질의자에게 줄 서명을 이 서버가
     *          가지고 있어야 한다. 검증기를 끈 채로 DO를 설정하지 않으면 서명을 애초에 받아
     *          오지 못해, 이 서버의 뒤에 선 검증하는 스텁이 아무것도 확인하지 못한다.
     * @note 서명은 담아 두고, DO를 설정하지 않은 질의자에게 나갈 때 걷어낸다.
     */
    do_bit: bool,
    /**
     * @brief 위임마다 DS 증거를 모을지.
     *
     * @details 신뢰 체인을 구성할 때만 쓴다. 검증하지 않으면 모아 봐야 쓰지 않으므로
     *          위임마다 붙는 복제를 하지 않는다.
     */
    collect_ds: bool,
}

/**
 * @brief 주소를 아직 모르는 네임서버가 있어 잠시 멈춘 참조.
 * @details glue가 없는 위임에서 생긴다. 네임서버 주소를 따로 풀어 온 뒤 이어 간다.
 */
struct PendingReferral {
    /** @brief 이 위임이 가리키는 영역. */
    zone: Name,
    /** @brief 참조를 담고 있던 원본 응답. */
    resp: Message,
    /** @brief 그 zone의 네임서버 이름들. */
    ns_names: Vec<Name>,

    /** @brief glue로 이미 알아낸 주소들. */
    addrs: Vec<SocketAddr>,
    /** @brief 그 주소들의 TTL. 캐시에 담을 때 쓴다. */
    address_ttl: Option<u32>,
    /**
     * @brief 부모에게 따로 물어 받은 DS와 그 부재 증명. 답변 절로 드러난 경계에만 있다.
     * @details 참조라면 DS 증거가 권한 절에 함께 오지만, 권한 있는 답으로 드러난 경계에는 오지
     *          않는다. 증거 없이 체인에 넣으면 서명된 영역이 증명 없이 Insecure로 내려간다.
     */
    ds_evidence: Option<Vec<Record>>,
    /** @brief 주소를 풀지 않고 남긴 네임서버 이름들. 내려간 뒤 반복 상태로 옮긴다. */
    unresolved: Vec<Name>,
}

/** @brief 한 단계를 밟은 결과. */
enum StepOutcome {
    /** @brief 최종 응답을 얻었다. */
    Done(Message),

    /** @brief 한 단계 더 내려간다. */
    Continue,

    /** @brief 네임서버 주소를 먼저 풀어야 한다. */
    NeedNsAddrs {
        /** @brief 주소를 모르는 이름들. */
        missing: Vec<Name>,
        /** @brief 주소를 얻은 뒤 이어 갈 참조 상태. */
        pending: Box<PendingReferral>,
    },

    /** @brief 답변 절로 드러난 경계라 부모에게 DS를 먼저 물어야 한다. 검증할 때만 생긴다. */
    NeedDs {
        /** @brief glue가 없어 주소를 모르는 네임서버 이름들. */
        missing: Vec<Name>,
        /** @brief DS를 받은 뒤 이어 갈 참조 상태. */
        pending: Box<PendingReferral>,
    },

    /** @brief 더 진행할 수 없다. */
    Failed(RecurseError),
}

impl IterationState {
    /** @brief 시작 zone과 서버로 반복을 시작한다. 체인의 첫 단계도 함께 만든다. */
    fn start(zone: Name, servers: Vec<SocketAddr>) -> Self {
        let depth = zone.num_labels();
        let chain = vec![ZoneStep {
            zone: zone.clone(),
            servers: servers.clone(),
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        Self {
            zone,
            servers,
            depth,
            minimize: true,
            chain,
            unresolved_ns: Vec::new(),
        }
    }

    /**
     * @brief 다음 질의의 이름과 타입을 정한다.
     * @details 최소화 중이면 라벨을 하나씩 늘려 가며 NS를 묻는다. 전체 이름을 처음부터
     *          보내면 경로상의 모든 서버가 질의자의 관심사를 알게 된다.
     */
    fn next_query(&self, ctx: &IterationContext<'_>) -> NextQuery {
        let target = if self.minimize {
            (self.depth + 1).min(ctx.total)
        } else {
            ctx.total
        };
        let is_final = target >= ctx.total;
        NextQuery {
            target,
            is_final,
            mname: ctx.qname.suffix(target),
            mtype: if is_final { ctx.qtype } else { RecordType::NS },
        }
    }
}

/** @brief 체인의 한 단계. zone 하나와 그 위임 증거를 담는다. */
struct ZoneStep {
    /** @brief 이 단계에서 물어볼 영역. */
    zone: Name,
    /** @brief 그 영역의 서버 주소들. */
    servers: Vec<SocketAddr>,

    /** @brief 주소를 아직 모르는 서버 이름들. */
    ns_names: Vec<Name>,
    /** @brief 그 zone의 DS RRset. */
    ds_records: Vec<Record>,
    /** @brief DS RRset의 서명들. */
    ds_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /** @brief DS 부재를 NSEC으로 증명하는 레코드들. */
    ds_nsec_records: Vec<Record>,
    /** @brief 위 NSEC들의 서명. */
    ds_nsec_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /** @brief DS 부재를 NSEC3으로 증명하는 레코드들. */
    ds_nsec3_records: Vec<Record>,
    /** @brief 위 NSEC3들의 서명. */
    ds_nsec3_rrsigs: Vec<onetdns_dnssec::Rrsig>,
    /** @brief 파싱한 DS. 다음 단계의 신뢰 기준이 된다. */
    ds: Vec<onetdns_dnssec::Ds>,
}

#[derive(Debug, Default, Clone)]
/** @brief 이 해석에 관여한 네임서버들. 응답과 함께 업스트림 계층에 전한다. */
pub struct NsContext {
    /** @brief 거쳐 온 네임서버 이름들. */
    pub names: Vec<Name>,
    /** @brief 실제로 물어본 주소들. */
    pub ips: Vec<std::net::IpAddr>,
}

impl NsContext {
    /** @brief 체인 전체에서 이름과 주소를 중복 없이 모은다. */
    fn from_chain(chain: &[ZoneStep]) -> Self {
        let mut names: Vec<Name> = Vec::new();
        let mut ips: Vec<std::net::IpAddr> = Vec::new();
        for step in chain {
            for n in &step.ns_names {
                if !names.iter().any(|x| x.eq_ignore_case(n)) {
                    names.push(n.clone());
                }
            }
            for s in &step.servers {
                let ip = s.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        NsContext { names, ips }
    }
}

impl Recursor {
    /** @brief 루트 목록과 데드라인으로 리졸버를 만든다. 나머지 설정은 with_ 계열로 얹는다. */
    pub fn new(roots: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self {
            roots,
            timeout,
            port: 53,
            max_referrals: 16,
            max_cnames: 8,
            max_dnames: 8,

            max_ns_resolves: 64,
            trust_anchors: std::sync::Arc::new(onetdns_core::ArcSwap::new(std::sync::Arc::new(
                Vec::new(),
            ))),
            strict: false,
            permissive: false,
            caps_for_id: true,
            authority_tcp: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            lowercase_outgoing: false,
            ignore_cd: true,
            deny_servers: Vec::new(),
            allow_servers: Vec::new(),
            do_ip4: true,
            do_ip6: true,
            prefer_ip6: false,
            prefer_ip4: false,
            qname_min_strict: false,
            harden_referral_path: false,
            domain_insecure: Vec::new(),
            root_key_sentinel: true,
            nsec3_max_iterations: DEFAULT_NSEC3_MAX_ITERATIONS,
            recursive_cache_ttl_max: u32::MAX,
            infra: std::sync::Mutex::new(LruMap::new(MAX_INFRA)),
            rtt: std::sync::Mutex::new(LruMap::new(MAX_INFRA)),
            ns_addr_cache: std::sync::Mutex::new(LruMap::new(NS_ADDR_CACHE_MAX)),
            deleg_cache: std::sync::Mutex::new(LruMap::new(DELEGATION_CACHE_MAX)),
            dnskey_cache: std::sync::Mutex::new(LruMap::new(DNSKEY_CACHE_MAX)),
            validated_keys: std::sync::Mutex::new(LruMap::new(VALIDATED_KEY_CACHE_MAX)),
            background: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /** @brief 권한 서버에 TCP로만 물을지를 이 값으로 정한다. 값은 부른 쪽이 바꾼다. */
    pub fn with_authority_tcp(
        mut self,
        switch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.authority_tcp = switch;
        self
    }

    /** @brief 지금 권한 서버에 TCP로만 묻고 있는지. */
    pub fn authority_over_tcp(&self) -> bool {
        self.authority_tcp
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /** @brief NSEC3 반복 상한을 바꾼다. 보안 하드 상한 150보다 높게는 설정되지 않는다. */
    pub fn with_nsec3_max_iterations(mut self, max: u16) -> Self {
        self.nsec3_max_iterations = max.min(onetdns_dnssec::MAX_NSEC3_ITERATIONS);
        self
    }

    /** @brief 모든 캐시의 크기를 한꺼번에 바꾼다. 0이면 기본값을 유지한다. */
    pub fn with_ns_cache_max(mut self, max: usize) -> Self {
        if max > 0 {
            let max = max.min(MAX_NS_CACHE_CONFIGURED);
            self.infra = std::sync::Mutex::new(LruMap::new(max));
            self.rtt = std::sync::Mutex::new(LruMap::new(max));
            self.ns_addr_cache = std::sync::Mutex::new(LruMap::new(max));
            self.deleg_cache = std::sync::Mutex::new(LruMap::new(max));
            self.dnskey_cache = std::sync::Mutex::new(LruMap::new(max));
            self.validated_keys = std::sync::Mutex::new(LruMap::new(max));
        }
        self
    }

    /** @brief 캐시에 담을 TTL 상한을 바꾼다. */
    pub fn with_recursive_cache_ttl_max(mut self, max: u32) -> Self {
        self.recursive_cache_ttl_max = max;
        self
    }

    /** @brief 부수 질의 예산을 바꾼다. */
    pub fn with_ns_side_query_limit(mut self, limit: usize) -> Self {
        if limit > 0 {
            self.max_ns_resolves = limit;
        }
        self
    }

    /** @brief 루트 키 센티널 응답을 켜고 끈다. */
    pub fn with_root_key_sentinel(mut self, on: bool) -> Self {
        self.root_key_sentinel = on;
        self
    }

    /**
     * @brief 루트 키 센티널 질의면 응답을 바꿔 이 서버가 아는 앵커를 알린다.
     * @details 이름 앞 라벨이 특정 형태이고 그 tag를 이 서버가 신뢰하는지에 따라 정상 응답과
     *          SERVFAIL로 갈린다. 질의자는 두 이름의 응답 차이로 이 서버의 앵커 상태를 알아낸다.
     * @note 검증된 응답에만 적용한다. 검증되지 않은 답으로 신호를 보내면 의미가 없다.
     */
    fn apply_sentinel(&self, qname: &Name, qtype: RecordType, out: &mut Message) {
        if !self.root_key_sentinel || !out.header.authentic_data {
            return;
        }
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return;
        }
        let Some(first) = qname.labels().first() else {
            return;
        };
        let Some(sentinel) = onetdns_dnssec::RootKeySentinel::parse(first) else {
            return;
        };
        if sentinel.fails(&self.trust_anchors.load()) {
            out.answers.clear();
            out.authorities.clear();
            out.additionals.clear();
            out.header.rcode = ResponseCode::ServFail.0;
            out.header.authentic_data = false;
        }
    }

    /** @brief 쓸 주소 계열과 선호를 정한다. */
    pub fn with_ip_family(mut self, do_ip4: bool, do_ip6: bool, prefer: Option<bool>) -> Self {
        self.do_ip4 = do_ip4;
        self.do_ip6 = do_ip6;
        match prefer {
            Some(true) => self.prefer_ip6 = true,
            Some(false) => self.prefer_ip4 = true,
            None => {}
        }
        self
    }

    /** @brief 이름 최소화를 엄격히 할지. */
    pub fn with_qname_min_strict(mut self, strict: bool) -> Self {
        self.qname_min_strict = strict;
        self
    }

    /**
     * @brief 내보낼 질의 이름의 대소문자를 설정대로 바꾼다.
     * @details 동기 경로와 리액터 레인이 모두 이것을 부른다. 한쪽만 따르면 레인이 켜진 설치에서
     *          설정이 효과를 잃는다.
     */
    pub(crate) fn apply_outgoing_case(&self, query: &mut Message) {
        for question in &mut query.questions {
            if self.caps_for_id {
                question.name = randomize_name_case(&question.name);
            } else if self.lowercase_outgoing {
                question.name = lowercase_name(&question.name);
            }
        }
    }

    /** @brief 참조 경로 강화를 켜고 끈다. */
    pub fn with_harden_referral_path(mut self, on: bool) -> Self {
        self.harden_referral_path = on;
        self
    }

    /** @brief 검증에서 뺄 도메인을 지정한다. 운영자가 명시한 것만 들어간다. */
    pub fn with_domain_insecure(mut self, domains: Vec<Name>) -> Self {
        self.domain_insecure = domains;
        self
    }

    /** @brief 이 이름이 검증 제외 목록 안인지. */
    fn is_domain_insecure(&self, name: &Name) -> bool {
        self.domain_insecure.iter().any(|d| is_within(name, d))
    }

    /** @brief 이 주소 계열을 쓰도록 설정돼 있는지. */
    fn family_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.do_ip4,
            IpAddr::V6(_) => self.do_ip6,
        }
    }

    /** @brief 선호 계열이면 0, 아니면 1. 서버 정렬의 첫 기준이다. */
    fn family_rank(&self, ip: IpAddr) -> u8 {
        let is_v6 = ip.is_ipv6();
        if self.prefer_ip6 && is_v6 || self.prefer_ip4 && !is_v6 {
            0
        } else {
            1
        }
    }

    /** @brief 내장 루트 목록으로 리졸버를 만든다. */
    pub fn with_default_roots(timeout: Duration) -> Self {
        Self::new(default_roots(), timeout)
    }

    /** @brief 업스트림 포트를 바꾼다. 테스트용이다. */
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    #[cfg(test)]
    /** @brief 루프백을 질의 대상으로 허용한다. 테스트 전용이며 운영에서는 열리지 않는다. */
    fn with_test_loopback(mut self) -> Self {
        self.allow_servers.push("127.0.0.0/8".parse().unwrap());
        self.allow_servers.push("::1/128".parse().unwrap());
        self
    }

    /** @brief 신뢰 앵커를 넣는다. 넣으면 검증이 켜진다. */
    pub fn with_trust_anchors(self, anchors: Vec<onetdns_dnssec::Ds>) -> Self {
        self.trust_anchors.store(std::sync::Arc::new(anchors));
        self
    }

    /** @brief 앵커 저장소 핸들. 자동 갱신이 이것으로 앵커를 바꾼다. */
    pub fn anchors_handle(&self) -> std::sync::Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>> {
        self.trust_anchors.clone()
    }

    /** @brief zone의 DNSKEY를 직접 가져온다. 앵커 갱신이 쓴다. */
    pub fn fetch_zone_dnskey(&self, zone: &Name) -> Result<Vec<Record>, RecurseError> {
        let mut budget = Budget {
            ns_resolves: self.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: self.query_deadline(),
        };
        let (resp, _) = self.iterate(zone, RecordType::DNSKEY, &mut budget, self.validating())?;
        Ok(resp.answers)
    }

    /** @brief 엄격 모드를 켜고 끈다. */
    pub fn with_dnssec_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /** @brief 관대 모드를 켜고 끈다. 진단용이며 운영에서는 쓰지 않는다. */
    pub fn with_dnssec_permissive(mut self, permissive: bool) -> Self {
        self.permissive = permissive;
        self
    }

    /** @brief 0x20 인코딩을 켜고 끈다. */
    pub fn with_caps_for_id(mut self, on: bool) -> Self {
        self.caps_for_id = on;
        self
    }

    /** @brief 나가는 이름의 소문자화를 켜고 끈다. */
    pub fn with_lowercase_outgoing(mut self, on: bool) -> Self {
        self.lowercase_outgoing = on;
        self
    }

    /** @brief 질의할 업스트림 대역을 제한한다. */
    pub fn with_server_acl(mut self, deny: Vec<IpNet>, allow: Vec<IpNet>) -> Self {
        self.deny_servers = deny;
        self.allow_servers = allow;
        self
    }

    /** @brief 이 주소에 질의해도 되는지. 계열과 대역을 함께 본다. */
    fn server_eligible(&self, ip: IpAddr) -> bool {
        self.family_allowed(ip) && self.is_queryable(ip)
    }

    /**
     * @brief 이 주소가 질의 대상으로 허용되는지.
     * @details 허용 목록이 먼저고 그다음이 거부 목록, 마지막이 전역 라우팅 가능 여부다.
     * @warning 기본은 전역 주소만이다. 내부망 주소로 질의하게 두면 위임을 조작해 이 서버를
     *          내부망 탐색에 쓰는 SSRF가 성립한다.
     */
    fn is_queryable(&self, ip: IpAddr) -> bool {
        if self.allow_servers.iter().any(|n| n.contains(&ip)) {
            return true;
        }
        if self.deny_servers.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        is_globally_routable(ip)
    }

    /** @brief 내장 루트 앵커로 검증을 켠다. */
    pub fn with_dnssec(self) -> Self {
        self.with_trust_anchors(onetdns_dnssec::root_trust_anchors())
    }

    /** @brief 참조 예산을 바꾼다. 0은 무시한다. */
    pub fn with_recursion_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_referrals = limit as usize;
        }
        self
    }

    /** @brief CNAME 예산을 바꾼다. 0은 무시한다. */
    pub fn with_cname_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_cnames = limit as usize;
        }
        self
    }

    /** @brief DNAME 예산을 바꾼다. 0은 무시한다. */
    pub fn with_dname_limit(mut self, limit: u8) -> Self {
        if limit > 0 {
            self.max_dnames = limit as usize;
        }
        self
    }

    /** @brief 지금 검증해야 하는지. 앵커가 있고 CD 존중 상태가 아닐 때다. */
    fn validating(&self) -> bool {
        !self.trust_anchors.load().is_empty()
    }

    #[cfg(any(unix, test))]
    /** @brief 이 리졸버가 검증하도록 설정돼 있는지. */
    pub fn is_validating(&self) -> bool {
        self.validating()
    }

    /** @brief 이 질의의 데드라인 시각. 중첩 해석도 이 데드라인을 나눠 쓴다. */
    fn query_deadline(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(self.timeout).unwrap_or(now)
    }

    /** @brief 이름과 타입을 해석한다. 가장 바깥 진입점이다. */
    pub fn resolve(&self, qname: &Name, qtype: RecordType) -> Result<Message, RecurseError> {
        self.resolve_collect(qname, qtype).map(|(m, _)| m)
    }

    /** @brief 질의자의 CD 비트를 무시할지. */
    pub fn with_ignore_cd(mut self, ignore: bool) -> Self {
        self.ignore_cd = ignore;
        self
    }

    /**
     * @brief CD 비트를 지정해 해석하고 거쳐 온 네임서버도 함께 돌려준다.
     * @details 끝내지 못한 해석은 뒤에서 마저 돌린다(complete_in_background). 클라이언트는
     *          곧 다시 묻는데, 그때 남은 단계만 진행하면 되도록 이 재귀기의 캐시를 채워 둔다.
     */
    pub fn resolve_with_ns_cd(
        self: &std::sync::Arc<Self>,
        qname: &Name,
        qtype: RecordType,
        cd: bool,
    ) -> Result<(Message, NsContext), RecurseError> {
        let deadline = self.query_deadline();
        let result = self.resolve_once_cd(qname, qtype, cd);
        if unfinished(&result, deadline) {
            self.complete_in_background(qname.clone(), qtype, cd);
        }
        result
    }

    /** @brief CD 비트를 지정해 한 번 해석한다. 끝내지 못해도 뒤에서 이어 가지 않는다. */
    fn resolve_once_cd(
        &self,
        qname: &Name,
        qtype: RecordType,
        cd: bool,
    ) -> Result<(Message, NsContext), RecurseError> {
        let honor = cd && !self.ignore_cd;
        with_honor_cd(honor, || self.resolve_collect(qname, qtype))
    }

    /**
     * @brief 끝내지 못한 해석을 다른 스레드에서 한 번 더 돌린다. 결과는 버리고 캐시만 남는다.
     * @details 같은 질의는 한 번만 돌리고, 동시에 돌리는 수는 MAX_BACKGROUND_COMPLETIONS를
     *          넘지 않는다. 뒤에서 돌리는 해석이 실패해도 다시 뒤로 넘기지 않는다.
     */
    pub fn complete_in_background(
        self: &std::sync::Arc<Self>,
        qname: Name,
        qtype: RecordType,
        cd: bool,
    ) {
        let key = (qname.canonical_key(), qtype);
        {
            let mut running = self.background.lock_recover();
            if running.len() >= MAX_BACKGROUND_COMPLETIONS || !running.insert(key.clone()) {
                return;
            }
        }
        let this = std::sync::Arc::clone(self);
        let task_key = key.clone();
        let spawned = std::thread::Builder::new()
            .name("recurse-complete".into())
            .spawn(move || {
                rtrace!(
                    "Finishing an unfinished recursion in the background: name={}, type={:?}",
                    qname.to_ascii_lower(),
                    qtype
                );
                let _ = this.resolve_once_cd(&qname, qtype, cd);
                this.background.lock_recover().remove(&task_key);
            });
        if spawned.is_err() {
            self.background.lock_recover().remove(&key);
        }
    }

    /** @brief 해석하고 거쳐 온 네임서버도 함께 돌려준다. */
    pub fn resolve_with_ns(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        self.resolve_collect(qname, qtype)
    }

    /** @brief 해석 본체. 예산을 새로 잡고 체인 정보를 모아 돌려준다. */
    fn resolve_collect(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        let (mut out, ns) = self.iterate_to_answer(qname, qtype)?;

        out.header.authoritative = false;
        Ok((out, ns))
    }

    /**
     * @brief 반복 해석을 돌리고 최종 응답을 다듬는다.
     *
     * @details 반복이 끝나면 셋 중 하나다. DNAME이 이름 길이를 넘긴 경우, 별칭 없이 끝난
     *          경우, 별칭을 따라가야 하는 경우. 각각 검증과 정리 방식이 다르다.
     * @warning 응답을 내보내기 전에 AD 비트를 반드시 먼저 꺼야 한다. 업스트림이 설정한 비트를
     *          그대로 흘리면 검증하지 않은 답이 검증된 것처럼 나간다.
     */
    fn iterate_to_answer(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(Message, NsContext), RecurseError> {
        if self.roots.is_empty() {
            return Err(RecurseError::NoRoots);
        }
        let mut budget = Budget {
            ns_resolves: self.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: self.query_deadline(),
        };
        rtrace!(
            "Starting recursion: name={}, type={:?}, dnssec={}",
            qname.to_ascii_lower(),
            qtype,
            self.validating()
        );
        let (resp, chain) = self.iterate(qname, qtype, &mut budget, self.validating())?;

        let ns = NsContext::from_chain(&chain);

        if is_dname_yxdomain(&resp, qname) {
            let mut out = resp;
            out.header.authentic_data = false;
            out.answers.retain(|record| {
                record.class == DnsClass::IN
                    && (matches!(record.rdata, RData::Dname(_))
                        || onetdns_dnssec::Rrsig::from_record(record)
                            .is_some_and(|sig| sig.type_covered == RecordType::DNAME.0))
            });
            out.authorities.clear();
            out.additionals.clear();
            out.header.response = true;
            out.header.recursion_available = true;
            return Ok((out, ns));
        }

        let alias = alias_hop(&resp, qname, qtype);
        rtrace!(
            "Finished recursion: rcode={}, answers={}, cname_response={}, cname_target={:?}, delegation_steps={}",
            resp.header.rcode,
            resp.answers.len(),
            alias.is_some(),
            alias.as_ref().map(|hop| hop.target.to_ascii_lower()),
            chain.len()
        );

        if alias.is_none() {
            let mut out = resp;

            out.header.authentic_data = false;
            let positive = out.header.rcode == ResponseCode::NoError.0
                && has_direct_qtype_answer(&out, qname, qtype);
            if self.validating() {
                if positive {
                    let status =
                        self.validate_answer_status(qname, qtype, &out, &chain, budget.deadline);
                    rtrace!(
                        "DNSSEC response validation: name={}, status={:?}",
                        qname.to_ascii_lower(),
                        status
                    );
                    match status {
                        SecurityStatus::Secure => out.header.authentic_data = true,

                        SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                            rtrace!(
                                "DNSSEC validation failed; returning SERVFAIL: name={}",
                                qname.to_ascii_lower()
                            );
                            out = bogus_servfail(&out, code)
                        }

                        _ => {}
                    }
                } else {
                    let status =
                        self.validate_denial_status(qname, qtype, &out, &chain, budget.deadline);
                    rtrace!(
                        "DNSSEC denial proof validation: name={}, status={:?}",
                        qname.to_ascii_lower(),
                        status
                    );
                    match status {
                        SecurityStatus::Secure => out.header.authentic_data = true,

                        SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                            rtrace!(
                                "DNSSEC denial proof failed; returning SERVFAIL: name={}",
                                qname.to_ascii_lower()
                            );
                            out = bogus_servfail(&out, code)
                        }

                        _ => {}
                    }
                }
            }
            sanitize_terminal_response(
                &mut out,
                qname,
                qtype,
                positive,
                chain.last().map(|step| &step.zone),
            );
            self.apply_sentinel(qname, qtype, &mut out);
            out.header.response = true;
            out.header.recursion_available = true;
            return Ok((out, ns));
        }

        let AliasHop {
            target,
            owner: alias_owner,
            atype: alias_type,
            records: mut merged,
        } = alias.expect("Returned in the alias.is_none() branch");
        let (cname_depth, dname_depth) = if alias_type == RecordType::DNAME {
            (0, 1)
        } else {
            (1, 0)
        };
        let alias_status = if self.validating() {
            self.validate_answer_status(&alias_owner, alias_type, &resp, &chain, budget.deadline)
        } else {
            SecurityStatus::Insecure
        };
        let (mut tail, tail_status) =
            self.resolve_inner(&target, qtype, cname_depth, dname_depth, &mut budget, true)?;
        merged.append(&mut tail.answers);
        tail.answers = merged;
        tail.questions = resp.questions.clone();

        let mut out = tail;

        out.header.authentic_data = false;
        let status = alias_status.combine(tail_status);
        if self.validating() {
            match status {
                SecurityStatus::Secure => out.header.authentic_data = true,
                SecurityStatus::Bogus(code) if !self.permissive && !honor_cd_active() => {
                    out = bogus_servfail(&out, code)
                }
                _ => {}
            }
        }
        out.header.response = true;
        out.header.recursion_available = true;
        Ok((out, ns))
    }

    /**
     * @brief 별칭을 따라가며 재귀적으로 해석한다.
     * @details 체인 깊이를 인자로 물려받아 예산을 이어 쓴다. 깊이를 새로 세면 별칭이
     *          별칭을 부르는 체인에서 상한이 무의미해진다.
     * @param validate 거짓이면 DS를 모으지도 검증하지도 않고 Insecure로 돌려준다. 결과를 판정에
     *                 쓰지 않는 네임서버 주소 풀기만 끈다.
     */
    fn resolve_inner(
        &self,
        qname: &Name,
        qtype: RecordType,
        cname_depth: usize,
        dname_depth: usize,
        budget: &mut Budget,
        validate: bool,
    ) -> Result<(Message, SecurityStatus), RecurseError> {
        if cname_depth > self.max_cnames {
            return Err(RecurseError::TooManyCnames);
        }
        if dname_depth > self.max_dnames {
            return Err(RecurseError::TooManyDnames);
        }
        let validate = validate && self.validating();
        let (mut resp, chain) = self.iterate(qname, qtype, budget, validate)?;

        if let Some((dname_record, target, synthetic_cname)) = dname_rewrite(&resp, qname) {
            let dname_status = if validate {
                self.validate_answer_status(
                    &dname_record.name,
                    RecordType::DNAME,
                    &resp,
                    &chain,
                    budget.deadline,
                )
            } else {
                SecurityStatus::Insecure
            };
            let (mut tail, tail_status) = self.resolve_inner(
                &target,
                qtype,
                cname_depth,
                dname_depth + 1,
                budget,
                validate,
            )?;
            let mut merged = alias_rrset_records(&resp, &dname_record.name, RecordType::DNAME);
            merged.push(synthetic_cname);
            merged.append(&mut tail.answers);
            tail.answers = merged;
            tail.questions = resp.questions.clone();
            return Ok((tail, dname_status.combine(tail_status)));
        }

        if has_direct_qtype_answer(&resp, qname, qtype) {
            let status = if validate {
                self.validate_answer_status(qname, qtype, &resp, &chain, budget.deadline)
            } else {
                SecurityStatus::Insecure
            };
            sanitize_terminal_response(&mut resp, qname, qtype, true, None);
            return Ok((resp, status));
        }
        if resp.header.rcode == ResponseCode::NXDomain.0 {
            let status = if validate {
                self.validate_denial_status(qname, qtype, &resp, &chain, budget.deadline)
            } else {
                SecurityStatus::Insecure
            };
            sanitize_terminal_response(
                &mut resp,
                qname,
                qtype,
                false,
                chain.last().map(|step| &step.zone),
            );
            return Ok((resp, status));
        }
        if let Some(target) = cname_target(&resp, qname) {
            let cname_status = if validate {
                self.validate_answer_status(
                    qname,
                    RecordType::CNAME,
                    &resp,
                    &chain,
                    budget.deadline,
                )
            } else {
                SecurityStatus::Insecure
            };
            let (mut tail, tail_status) = self.resolve_inner(
                &target,
                qtype,
                cname_depth + 1,
                dname_depth,
                budget,
                validate,
            )?;
            let mut merged = alias_rrset_records(&resp, qname, RecordType::CNAME);
            merged.append(&mut tail.answers);
            tail.answers = merged;
            tail.questions = resp.questions.clone();
            return Ok((tail, cname_status.combine(tail_status)));
        }

        let status = if validate {
            self.validate_denial_status(qname, qtype, &resp, &chain, budget.deadline)
        } else {
            SecurityStatus::Insecure
        };
        sanitize_terminal_response(
            &mut resp,
            qname,
            qtype,
            false,
            chain.last().map(|step| &step.zone),
        );
        Ok((resp, status))
    }

    /**
     * @brief 긍정 응답의 DNSSEC 상태를 판정한다.
     * @details 키가 없어도 알 수 있는 경우를 먼저 걸러 낸다. 그다음 체인을 검증해 키를
     *          얻고, 그 키로 답변 RRset을 본다.
     */
    fn validate_answer_status(
        &self,
        qname: &Name,
        qtype: RecordType,
        answer_msg: &Message,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> SecurityStatus {
        if let Some(status) = self.answer_status_without_keys(qname, qtype) {
            return status;
        }
        let keys = match self.validated_chain_keys(chain, deadline) {
            Ok(keys) => keys,
            Err(status) => return status,
        };
        self.validate_answer_with_keys(qname, qtype, answer_msg, chain, &keys)
    }

    /**
     * @brief 키를 얻기 전에 정해지는 상태가 있으면 돌려준다.
     * @note RRSIG를 직접 물은 경우는 Insecure다. 서명을 서명으로 감싸지 않기 때문이다.
     */
    fn answer_status_without_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Option<SecurityStatus> {
        if self.is_domain_insecure(qname) {
            return Some(SecurityStatus::Insecure);
        }

        if qtype == RecordType::RRSIG {
            return Some(SecurityStatus::Insecure);
        }
        None
    }

    /**
     * @brief 확정된 키로 답변 RRset의 서명을 검증한다.
     *
     * @details 서명자가 체인의 리프 zone인 것만 본다. 그리고 서명의 labels가 실제 이름보다
     *          짧으면 와일드카드 확장이므로, 그 확장이 정당한지까지 증명돼야 한다.
     * @warning 와일드카드 확장 증명을 빼면 실재하는 더 구체적인 이름을 숨기고 와일드카드
     *          답으로 교체할 수 있다.
     */
    fn validate_answer_with_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
        answer_msg: &Message,
        chain: &[ZoneStep],
        keys: &[onetdns_dnssec::Dnskey],
    ) -> SecurityStatus {
        let now = now_secs();
        let rrset: Vec<Record> = answer_msg
            .answers
            .iter()
            .filter(|r| r.class == DnsClass::IN && r.rtype == qtype && r.name.eq_ignore_case(qname))
            .cloned()
            .collect();
        if rrset.is_empty() {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }
        let answer_rrsigs = extract_rrsigs(&answer_msg.answers, qtype.0, qname);
        if answer_rrsigs.is_empty() {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }

        let Some(apex) = chain.last().map(|step| &step.zone) else {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        };
        let mut verification_budget = onetdns_dnssec::VerificationBudget::new();
        if onetdns_dnssec::validate_rrset_in_zone_with_budget_and(
            &rrset,
            &answer_rrsigs,
            keys,
            apex,
            now,
            &mut verification_budget,
            |signature, budget| {
                let labels = usize::from(signature.labels);
                labels == qname.num_labels()
                    || validated_wildcard_expansion(
                        answer_msg,
                        qname,
                        labels,
                        WildcardValidation {
                            keys,
                            apex,
                            now,
                            nsec3_max_iterations: self.nsec3_max_iterations,
                            verification_budget: budget,
                        },
                    )
            },
        )
        .is_ok()
        {
            return SecurityStatus::Secure;
        }
        SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS)
    }

    /**
     * @brief 반복으로 모은 단계들을 검증용 체인으로 옮긴다.
     * @details 각 단계의 DNSKEY는 그 zone에 직접 물어 가져오고, DS는 자식 단계에 담겨
     *          있던 것을 끌어온다. DS는 부모가 준 것이라 자식 단계에 기록돼 있다.
     */
    fn build_chain_links(
        &self,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> Result<Vec<onetdns_dnssec::ChainLink>, RecurseError> {
        let mut links = Vec::with_capacity(chain.len());
        for (i, step) in chain.iter().enumerate() {
            let (dnskeys, dnskey_rrsigs) =
                self.fetch_dnskey(&step.zone, &step.servers, deadline)?;
            let (
                ds_records,
                ds_rrsigs,
                ds_nsec_records,
                ds_nsec_rrsigs,
                ds_nsec3_records,
                ds_nsec3_rrsigs,
                ds,
            ) = if i + 1 < chain.len() {
                (
                    chain[i + 1].ds_records.clone(),
                    chain[i + 1].ds_rrsigs.clone(),
                    chain[i + 1].ds_nsec_records.clone(),
                    chain[i + 1].ds_nsec_rrsigs.clone(),
                    chain[i + 1].ds_nsec3_records.clone(),
                    chain[i + 1].ds_nsec3_rrsigs.clone(),
                    chain[i + 1].ds.clone(),
                )
            } else {
                (vec![], vec![], vec![], vec![], vec![], vec![], vec![])
            };
            links.push(onetdns_dnssec::ChainLink {
                zone: step.zone.clone(),
                dnskeys,
                dnskey_rrsigs,
                ds_records,
                ds_rrsigs,
                ds_nsec_records,
                ds_nsec_rrsigs,
                ds_nsec3_records,
                ds_nsec3_rrsigs,
                ds,
            });
        }
        Ok(links)
    }

    /** @brief 체인 어딘가에 이 서버의 상한을 넘는 NSEC3 반복이 있는지. 있으면 검증하지 않는다. */
    fn chain_has_excessive_nsec3(&self, links: &[onetdns_dnssec::ChainLink]) -> bool {
        links.iter().any(|link| {
            onetdns_dnssec::nsec3_max_iterations(&link.ds_nsec3_records) > self.nsec3_max_iterations
        })
    }

    /** @brief 부정 응답의 DNSSEC 상태를 판정한다. */
    fn validate_denial_status(
        &self,
        qname: &Name,
        qtype: RecordType,
        out: &Message,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> SecurityStatus {
        if self.is_domain_insecure(qname) {
            return SecurityStatus::Insecure;
        }
        let keys = match self.validated_chain_keys(chain, deadline) {
            Ok(keys) => keys,
            Err(status) => return status,
        };
        self.validate_denial_with_keys(qname, qtype, out, chain, &keys)
    }

    /**
     * @brief 확정된 키로 부재 증명을 검증한다.
     *
     * @details SOA를 먼저 검증한다. 그것이 이 부정 응답이 어느 zone에서 왔는지를 정한다.
     *          그다음 NSEC이나 NSEC3으로 실제 부재를 증명한다.
     * @warning 먼저 구문상 최소 증명을 고르고 그 RRset만 검증한다. 순서를 뒤집으면 응답을
     *          무관한 서명 레코드로 채워 공개키 연산을 강요할 수 있다.
     */
    fn validate_denial_with_keys(
        &self,
        qname: &Name,
        qtype: RecordType,
        out: &Message,
        chain: &[ZoneStep],
        keys: &[onetdns_dnssec::Dnskey],
    ) -> SecurityStatus {
        let now = now_secs();
        let Some(apex) = chain.last().map(|step| &step.zone) else {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        };

        let soa: Vec<Record> = out
            .authorities
            .iter()
            .filter(|record| {
                record.class == DnsClass::IN
                    && record.rtype == RecordType::SOA
                    && record.name.eq_ignore_case(apex)
            })
            .cloned()
            .collect();
        if soa.len() != 1 {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }
        let mut verification_budget = onetdns_dnssec::VerificationBudget::new();
        let soa_sigs = extract_rrsigs(&out.authorities, RecordType::SOA.0, apex);
        if onetdns_dnssec::validate_rrset_in_zone_with_budget(
            &soa,
            &soa_sigs,
            keys,
            apex,
            now,
            &mut verification_budget,
        )
        .is_err()
        {
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }

        let denial_records = |rtype| {
            out.authorities
                .iter()
                .filter(|record| record.class == DnsClass::IN && record.rtype == rtype)
                .cloned()
                .collect::<Vec<_>>()
        };
        let nsec = denial_records(RecordType::NSEC);
        let nsec3 = denial_records(RecordType::NSEC3);
        let nsec3_allowed =
            onetdns_dnssec::nsec3_max_iterations(&nsec3) <= self.nsec3_max_iterations;
        // 부재 증명이 NSEC3 뿐인데 그 반복이 상한을 넘으면, 증명을 볼 수 없어서 실패한
        // 것이다. RFC 9276이 이 경우의 사유 코드를 따로 정한다.
        let excessive_nsec3_only = !nsec3_allowed && nsec.is_empty() && !nsec3.is_empty();
        let denial_bogus = if excessive_nsec3_only {
            SecurityStatus::Bogus(ede_code::UNSUPPORTED_NSEC3_ITERATIONS)
        } else {
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS)
        };

        if out.header.rcode == ResponseCode::NXDomain.0 {
            if let Some(proof) = onetdns_dnssec::nsec_name_nonexistent_proof(&nsec, qname) {
                if validate_denial_proof(
                    &proof,
                    &out.authorities,
                    keys,
                    apex,
                    now,
                    &mut verification_budget,
                ) {
                    return SecurityStatus::Secure;
                }
            }
            if nsec3_allowed {
                if let Some((proof, relies_on_opt_out)) =
                    onetdns_dnssec::nsec3_name_nonexistent_proof_status(&nsec3, qname)
                {
                    if validate_denial_proof(
                        &proof,
                        &out.authorities,
                        keys,
                        apex,
                        now,
                        &mut verification_budget,
                    ) {
                        return if relies_on_opt_out {
                            SecurityStatus::Insecure
                        } else {
                            SecurityStatus::Secure
                        };
                    }
                }
            }
            return SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS);
        }

        if let Some(proof) = onetdns_dnssec::nsec_nodata_proof(&nsec, qname, qtype.0) {
            if validate_denial_proof(
                &proof,
                &out.authorities,
                keys,
                apex,
                now,
                &mut verification_budget,
            ) {
                return SecurityStatus::Secure;
            }
        }
        if nsec3_allowed {
            if let Some(proof) = onetdns_dnssec::nsec3_nodata_proof(&nsec3, qname, qtype.0) {
                if validate_denial_proof(
                    &proof,
                    &out.authorities,
                    keys,
                    apex,
                    now,
                    &mut verification_budget,
                ) {
                    return SecurityStatus::Secure;
                }
            }
        }
        denial_bogus
    }

    /**
     * @brief zone의 DNSKEY를 가져온다. 캐시에 있으면 그것을 쓴다.
     * @details 그 zone의 서버에 직접 묻는다. 루트부터 다시 내려가면 체인 검증마다 전체
     *          해석이 한 벌씩 더 붙는다.
     */
    fn fetch_dnskey(
        &self,
        zone: &Name,
        servers: &[SocketAddr],
        deadline: Instant,
    ) -> Result<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>), RecurseError> {
        let key = zone.canonical_key();
        if let Some(cached) = self.dnskey_cached(&key) {
            return Ok(cached);
        }
        let resp = self.query_any(
            servers,
            &make_query(zone, RecordType::DNSKEY, true),
            zone,
            deadline,
        )?;
        Ok(self.absorb_dnskey_response(zone, &resp))
    }

    /**
     * @brief DNSKEY 응답에서 키와 서명을 뽑고 캐시에 담는다.
     * @note 캐시 기간은 레코드 TTL과 서명 만료까지 남은 시간 중 짧은 쪽이다. 만료된 서명을
     *       계속 가지고 있으면 폐기된 키를 믿게 된다.
     */
    fn absorb_dnskey_response(
        &self,
        zone: &Name,
        resp: &Message,
    ) -> (Vec<Record>, Vec<onetdns_dnssec::Rrsig>) {
        let key = zone.canonical_key();
        let keys: Vec<Record> = resp
            .answers
            .iter()
            .filter(|r| {
                r.class == DnsClass::IN
                    && r.rtype == RecordType::DNSKEY
                    && r.name.eq_ignore_case(zone)
            })
            .cloned()
            .collect();
        let sigs = extract_rrsigs(&resp.answers, RecordType::DNSKEY.0, zone);
        let ttl = resp
            .answers
            .iter()
            .filter(|record| {
                record.class == DnsClass::IN
                    && record.name.eq_ignore_case(zone)
                    && (record.rtype == RecordType::DNSKEY
                        || record.rtype == RecordType::RRSIG
                            && onetdns_dnssec::Rrsig::from_record(record).is_some_and(
                                |signature| signature.type_covered == RecordType::DNSKEY.0,
                            ))
            })
            .map(|record| record.ttl)
            .min();
        if !keys.is_empty() && !sigs.is_empty() {
            if let Some(ttl) = ttl {
                let now = now_secs();
                let signature_ttl = sigs
                    .iter()
                    .map(|signature| {
                        let remaining = signature.expiration.wrapping_sub(now);
                        if remaining < 0x8000_0000 {
                            remaining
                        } else {
                            0
                        }
                    })
                    .min()
                    .unwrap_or(0);
                self.dnskey_store(key, keys.clone(), sigs.clone(), ttl.min(signature_ttl));
            }
        }
        (keys, sigs)
    }

    /**
     * @brief 캐시된 DNSKEY. 만료된 항목은 꺼내면서 버린다.
     * @note 돌려주는 레코드의 TTL을 남은 시간으로 낮춘다. 저장 당시 TTL을 그대로 주면
     *       질의자가 실제보다 오래 캐시한다.
     */
    fn dnskey_cached(&self, key: &[u8]) -> Option<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>)> {
        let mut cache = self.dnskey_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => {
                let remaining = entry
                    .lifetime
                    .remaining_secs(now)
                    .expect("A live TTL must have time remaining");
                let mut records = entry.records.clone();
                for record in &mut records {
                    record.ttl = record.ttl.min(remaining);
                }
                Some((records, entry.signatures.clone()))
            }
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    /** @brief DNSKEY를 캐시에 담는다. TTL이 0이 되면 담지 않는다. */
    fn dnskey_store(
        &self,
        key: Vec<u8>,
        records: Vec<Record>,
        signatures: Vec<onetdns_dnssec::Rrsig>,
        ttl_secs: u32,
    ) {
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.dnskey_cache.lock_recover().put(
            key,
            DnskeyEntry {
                records,
                signatures,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /**
     * @brief 검증까지 끝난 zone의 신뢰 상태를 캐시에서 꺼낸다.
     * @warning 저장 당시의 앵커와 지금 앵커가 같은 객체일 때만 쓴다. 앵커가 바뀌었는데
     *          이전 결과를 쓰면 더 이상 신뢰하지 않는 키로 검증하게 된다.
     */
    fn validated_keys_cached(
        &self,
        zone_key: &[u8],
        anchors: &std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
    ) -> Option<ZoneTrust> {
        let mut cache = self.validated_keys.lock_recover();
        let now = cache_now_millis();
        match cache.get(zone_key) {
            Some(entry)
                if entry.lifetime.is_live(now)
                    && std::sync::Arc::ptr_eq(&entry.anchors, anchors) =>
            {
                Some(entry.trust.clone())
            }
            Some(_) => {
                cache.pop(zone_key);
                None
            }
            None => None,
        }
    }

    /** @brief 검증한 신뢰 상태를 그때 쓴 앵커와 함께 캐시에 담는다. */
    fn validated_keys_store(
        &self,
        zone_key: Vec<u8>,
        trust: ZoneTrust,
        anchors: std::sync::Arc<Vec<onetdns_dnssec::Ds>>,
        ttl_secs: u32,
    ) {
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.validated_keys.lock_recover().put(
            zone_key,
            ValidatedKeyEntry {
                trust,
                anchors,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /** @brief 체인 리프 zone의 신뢰 상태가 캐시에 있으면 꺼낸다. */
    fn cached_chain_trust(&self, chain: &[ZoneStep]) -> Option<ZoneTrust> {
        let leaf = chain.last()?;
        let anchors = self.trust_anchors.load();
        self.validated_keys_cached(&leaf.zone.canonical_key(), &anchors)
    }

    #[cfg(unix)]
    /** @brief 체인에서 DNSKEY가 캐시에 없는 첫 zone. 어느 zone을 먼저 받아 와야 할지 정한다. */
    fn first_chain_zone_missing_dnskey(
        &self,
        chain: &[ZoneStep],
        skip: &[Vec<u8>],
    ) -> Option<(Name, Vec<SocketAddr>)> {
        chain
            .iter()
            .map(|step| (step.zone.canonical_key(), step))
            .find(|(key, _)| !skip.contains(key) && self.dnskey_cached(key).is_none())
            .map(|(_, step)| (step.zone.clone(), step.servers.clone()))
    }

    #[cfg(unix)]
    /**
     * @brief 새로 질의하지 않고 검증할 수 있으면 검증한다.
     * @details 이벤트 구동 경로가 쓴다. 그 경로는 여기서 다시 동기 질의를 낼 수 없으므로,
     *          필요한 것이 전부 캐시에 있을 때만 판정하고 아니면 판정을 미룬다.
     * @return 판정할 수 없으면 None. 호출자가 필요한 DNSKEY를 먼저 받아 온다.
     */
    fn validate_terminal_without_fetch(
        &self,
        qname: &Name,
        qtype: RecordType,
        msg: &Message,
        chain: &[ZoneStep],
        positive: bool,
    ) -> Option<SecurityStatus> {
        if positive {
            if let Some(status) = self.answer_status_without_keys(qname, qtype) {
                return Some(status);
            }
        } else if self.is_domain_insecure(qname) {
            return Some(SecurityStatus::Insecure);
        }
        if self.cached_chain_trust(chain).is_none() {
            if !chain.first().is_some_and(|step| step.zone.is_root()) {
                return None;
            }
            if self.first_chain_zone_missing_dnskey(chain, &[]).is_some() {
                return None;
            }
        }

        let keys = match self.validated_chain_keys(chain, Instant::now()) {
            Ok(keys) => keys,
            Err(status) => return Some(status),
        };
        Some(if positive {
            self.validate_answer_with_keys(qname, qtype, msg, chain, &keys)
        } else {
            self.validate_denial_with_keys(qname, qtype, msg, chain, &keys)
        })
    }

    /**
     * @brief 이 zone에서 시작해도 검증이 성립하는지.
     * @details 검증하지 않는 설정이면 언제나 참이다. 검증한다면 그 zone의 키가 이미
     *          확정돼 있어야 한다. 중간에서 시작하면 그 위 체인을 걷지 않기 때문이다.
     */
    fn validated_start_ok(&self, zone: &Name) -> bool {
        !self.validating() || {
            let anchors = self.trust_anchors.load();
            self.validated_keys_cached(&zone.canonical_key(), &anchors)
                .is_some()
        }
    }

    /**
     * @brief 체인을 검증해 리프 zone의 신뢰된 키를 얻는다.
     *
     * @details 캐시에 있으면 그것을 쓴다. 없으면 각 단계의 DNSKEY를 받아 와 체인을 만들고
     *          앵커부터 검증한다.
     * @warning 체인이 루트에서 시작하지 않으면 Bogus다. 중간에서 시작한 체인은 그 위의
     *          위임을 확인하지 않은 것이라 신뢰의 근거가 없다.
     */
    fn validated_chain_keys(
        &self,
        chain: &[ZoneStep],
        deadline: Instant,
    ) -> Result<std::sync::Arc<[onetdns_dnssec::Dnskey]>, SecurityStatus> {
        match self.cached_chain_trust(chain) {
            Some(ZoneTrust::Secure(keys)) => return Ok(keys),
            Some(ZoneTrust::Insecure) => return Err(SecurityStatus::Insecure),
            None => {}
        }
        let Some(leaf) = chain.last() else {
            return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS));
        };
        let zone_key = leaf.zone.canonical_key();
        let anchors = self.trust_anchors.load();

        if !chain.first().is_some_and(|step| step.zone.is_root()) {
            return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS));
        }
        let links = match self.build_chain_links(chain, deadline) {
            Ok(l) => l,

            Err(error) => {
                onetdns_core::debug!(event = "dnssec.chain_build_failed", zone = %leaf.zone.to_ascii_lower(), error = ?error, "Could not fetch the keys for the chain of trust; answering SERVFAIL");
                // 체인을 만들지 못하는 것은 DNSKEY 를 받지 못했을 때뿐이다. 서명이 깨졌는지는
                // 알 수 없으므로, 서명이 깨졌다고 알리면 운영자가 엉뚱한 영역을 살핀다.
                return Err(SecurityStatus::Bogus(match error {
                    RecurseError::NoResponse | RecurseError::NoReachableNs => {
                        ede_code::NO_REACHABLE_AUTHORITY
                    }
                    _ => ede_code::DNSSEC_BOGUS,
                }));
            }
        };
        if self.chain_has_excessive_nsec3(&links) {
            onetdns_core::debug!(event = "dnssec.chain_nsec3_excessive", zone = %leaf.zone.to_ascii_lower(), "NSEC3 iterations exceed the budget; treating as bogus");
            // RFC 9276: 이 서버가 계산을 거부한 것이지 서명이 깨진 것이 아니다. 사유를
            // 갈라 알려야 운영자가 영역 매개변수를 고쳐야 한다는 것을 안다.
            return Err(SecurityStatus::Bogus(
                ede_code::UNSUPPORTED_NSEC3_ITERATIONS,
            ));
        }
        let now = now_secs();
        let keys = match onetdns_dnssec::validate_chain_status_with_options(
            &anchors,
            &links,
            now,
            self.strict,
        ) {
            onetdns_dnssec::ChainStatus::Secure(keys) => keys,
            onetdns_dnssec::ChainStatus::Insecure => {
                self.validated_keys_store(
                    zone_key,
                    ZoneTrust::Insecure,
                    anchors,
                    chain_validity_ttl(&links, now),
                );
                return Err(SecurityStatus::Insecure);
            }
            onetdns_dnssec::ChainStatus::Bogus => {
                return Err(SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS))
            }
        };
        let keys: std::sync::Arc<[onetdns_dnssec::Dnskey]> = keys.into();
        self.validated_keys_store(
            zone_key,
            ZoneTrust::Secure(keys.clone()),
            anchors,
            chain_validity_ttl(&links, now),
        );
        Ok(keys)
    }

    /**
     * @brief 캐시된 위임에서 시작하고, 실패하면 루트부터 다시 걷는다.
     *
     * @details 매번 루트부터 내려가면 질의가 몇 배로 는다. 대신 캐시된 위임에서 출발한
     *          시도가 실패하면 그 경로를 지우고 루트부터 다시 한다.
     * @note 다시 시도할 때 부수 질의 예산을 되돌린다. 되돌리지 않으면 캐시가 오래된 것뿐인데
     *       예산 부족으로 SERVFAIL이 나간다.
     * @param validate 거짓이면 DS를 모으지 않고, 캐시된 위임에서 시작할 때 검증된 키를 요구하지
     *                 않는다.
     */
    fn iterate(
        &self,
        qname: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        validate: bool,
    ) -> Result<(Message, Vec<ZoneStep>), RecurseError> {
        let validated_start_ok = |zone: &Name| !validate || self.validated_start_ok(zone);
        {
            if let Some((zone, servers)) = self
                .deepest_cached_delegation(qname)
                .filter(|(zone, _)| validated_start_ok(zone))
            {
                rtrace!(
                    "Starting {} from cached delegation {} ({} servers)",
                    zone.to_ascii_lower(),
                    servers.len(),
                    qname.to_ascii_lower()
                );
                let saved = budget.ns_resolves;
                match self.iterate_from(qname, qtype, budget, zone.clone(), servers, validate) {
                    Ok(v) if validated_start_ok(v.1.last().map_or(&zone, |s| &s.zone)) => {
                        return Ok(v)
                    }
                    Ok(_) => {
                        rtrace!("No cached validated key for the partial chain leaf; walking again from the root");
                        budget.ns_resolves = saved;
                    }
                    Err(e) => {
                        rtrace!(
                            "Query from cached delegation {} failed ({:?}); dropping that path and retrying from the root",
                            zone.to_ascii_lower(),
                            e
                        );
                        self.deleg_evict_path(qname);
                        budget.ns_resolves = saved;
                    }
                }
            }
        }
        self.iterate_from(
            qname,
            qtype,
            budget,
            Name::root(),
            self.roots.clone(),
            validate,
        )
    }

    /**
     * @brief 주어진 zone에서 시작해 위임을 따라 내려간다. 반복의 본체다.
     *
     * @details 한 바퀴마다 질의를 하나 보내고 결과에 따라 한 단계 나아가거나, 네임서버
     *          주소를 먼저 풀거나, 끝낸다. 바퀴 수에 상한이 있어 참조가 순환해도 멈춘다.
     * @note 이름 최소화 때문에 바퀴 수는 참조 예산에 라벨 수를 더한 만큼 필요하다. 그래서
     *       바퀴 수와 따로, 실제로 따라간 위임 횟수를 세어 참조 예산에 맞춘다.
     */
    fn iterate_from(
        &self,
        qname: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        start_zone: Name,
        start_servers: Vec<SocketAddr>,
        validate: bool,
    ) -> Result<(Message, Vec<ZoneStep>), RecurseError> {
        let ctx = IterationContext {
            qname,
            qtype,
            total: qname.num_labels(),
            do_bit: true,
            collect_ds: validate,
        };
        let mut state = IterationState::start(start_zone, start_servers);
        let mut referrals = 0usize;

        for _ in 0..(self.max_referrals + ctx.total + 2) {
            let plan = state.next_query(&ctx);
            let zone_depth = state.zone.num_labels();

            if budget.queries == 0 {
                rtrace!(
                    "Used up the total outgoing query budget: name={}",
                    qname.to_ascii_lower()
                );
                return Err(RecurseError::TooManyQueries);
            }
            budget.queries -= 1;

            let resp = loop {
                let error = match self.query_any_reserving(
                    &state.servers,
                    &make_query(&plan.mname, plan.mtype, ctx.do_bit),
                    &state.zone,
                    budget.deadline,
                    state.unresolved_ns.len(),
                ) {
                    Ok(r) => break r,
                    Err(e) => e,
                };
                // 이 영역의 서버가 모두 답하지 않았다. 남겨 둔 네임서버 이름이 있으면 그 주소로
                // 다시 묻는다.
                if budget.queries > 0 && self.resolve_more_ns_addrs(&mut state, budget) {
                    budget.queries -= 1;
                    continue;
                }
                rtrace!(
                    "Recursive query failed: name={}, type={:?}, final_step={}, error={:?}, nameservers={}, zone={}",
                    plan.mname.to_ascii_lower(),
                    plan.mtype,
                    plan.is_final,
                    error,
                    state.servers.len(),
                    state.zone.to_ascii_lower()
                );
                return Err(error);
            };

            let mut outcome = self.advance(&mut state, resp, &plan, &ctx);

            if let StepOutcome::NeedDs { missing, pending } = outcome {
                let mut pending = *pending;
                pending.ds_evidence = Some(self.fetch_ds_evidence(
                    &pending.zone,
                    &state.zone,
                    &state.servers,
                    budget,
                )?);
                outcome = self.descend(&mut state, &ctx, pending, missing);
            }
            if let StepOutcome::NeedNsAddrs { missing, pending } = outcome {
                let mut pending = *pending;
                match self.resolve_ns_addrs(&missing, budget) {
                    Ok((extra, side_ttl, rest)) => {
                        pending.addrs.extend(extra);
                        pending.address_ttl = min_optional_ttl(pending.address_ttl, side_ttl);
                        pending.unresolved = rest;
                        outcome = self.finish_referral(&mut state, &ctx, pending);
                    }
                    Err(e) => {
                        rtrace!(
                            "  nameserver address lookup failed for zone {}: {:?}",
                            e,
                            pending.zone.to_ascii_lower()
                        );
                        return Err(e);
                    }
                }
            }
            match outcome {
                StepOutcome::Done(resp) => return Ok((resp, state.chain)),
                StepOutcome::Failed(e) => return Err(e),
                StepOutcome::Continue => {
                    if state.zone.num_labels() > zone_depth {
                        referrals += 1;
                        if referrals > self.max_referrals {
                            break;
                        }
                    }
                }

                StepOutcome::NeedNsAddrs { .. } | StepOutcome::NeedDs { .. } => unreachable!(),
            }
        }
        rtrace!("Delegation limit exceeded: name={}", qname.to_ascii_lower());
        Err(RecurseError::TooManyReferrals)
    }

    /**
     * @brief 응답 하나를 보고 다음에 무엇을 할지 정한다.
     *
     * @details 순서가 안전성을 만든다. 최종 단계면 이 서버가 물은 것에 대한 답인지 먼저 보고,
     *          NXDOMAIN이면 그 서버가 그 이름에 대해 권한이 있는지 확인한다. 참조는
     *          현재 zone보다 가깝고 질의 이름을 포함할 때만 따라간다.
     * @warning bailiwick 검사가 여기 있다. 두 조건 중 하나라도 빠지면 아무 서버나 남의
     *          zone으로 이 서버를 끌고 갈 수 있다.
     * @note 이름 최소화 중에 받은 NXDOMAIN은 그대로 믿지 않고 전체 이름으로 다시 묻는다.
     *       빈 비단말을 NXDOMAIN으로 답하는 서버가 있기 때문이다.
     * @note 권한 서버가 위임 없이 빈 답을 주면 그 이름은 지금 영역 안에 있다. 빈 비단말이
     *       그렇다. 참조 경로 강화는 받아들일 수 없는 위임이나 권한 없는 답처럼 경로가
     *       의심스러울 때만 멈춘다.
     */
    fn advance(
        &self,
        state: &mut IterationState,
        mut resp: Message,
        plan: &NextQuery,
        ctx: &IterationContext<'_>,
    ) -> StepOutcome {
        rtrace!(
            "Got recursive response: name={}, type={:?}, final_step={}, rcode={}, answers={}, authority={}, additional={}, nameservers={}, zone={}",
            plan.mname.to_ascii_lower(),
            plan.mtype,
            plan.is_final,
            resp.header.rcode,
            resp.answers.len(),
            resp.authorities.len(),
            resp.additionals.len(),
            state.servers.len(),
            state.zone.to_ascii_lower()
        );

        if plan.is_final {
            strip_out_of_bailiwick_dnames(&mut resp, &state.zone);
            if is_relevant_positive(&resp, ctx.qname, ctx.qtype) {
                rtrace!("Got final response: name={}", ctx.qname.to_ascii_lower());
                return StepOutcome::Done(resp);
            }
        }

        if is_dname_yxdomain(&resp, ctx.qname) {
            return StepOutcome::Done(resp);
        }

        if resp.header.rcode == ResponseCode::NXDomain.0 {
            if !is_authoritative_negative(&resp, &plan.mname, &state.zone) {
                rtrace!(
                    "Rejected an NXDOMAIN that is unrelated to the current zone or not authoritative: zone={}",
                    state.zone.to_ascii_lower()
                );
                return StepOutcome::Failed(RecurseError::NoReachableNs);
            }
            if plan.is_final {
                return StepOutcome::Done(resp);
            }

            if self.qname_min_strict {
                return StepOutcome::Done(resp);
            }
            rtrace!(
                "Got NXDOMAIN during QNAME minimization; querying the full name: name={}",
                plan.mname.to_ascii_lower()
            );
            state.minimize = false;
            return StepOutcome::Continue;
        }

        if let Some(ns_names) = answer_zone_cut(&resp, plan, &state.zone) {
            rtrace!(
                "Found a zone cut in an authoritative NS answer: zone={}",
                plan.mname.to_ascii_lower()
            );
            let (addrs, missing, address_ttl) = self.glue_addrs(&resp, &ns_names, &state.zone);
            let pending = PendingReferral {
                zone: plan.mname.clone(),
                resp,
                ns_names,
                addrs,
                address_ttl,
                ds_evidence: None,
                unresolved: Vec::new(),
            };
            if ctx.collect_ds {
                return StepOutcome::NeedDs {
                    missing,
                    pending: Box::new(pending),
                };
            }
            return self.descend(state, ctx, pending, missing);
        }

        let (referral_zone, ns_names) = extract_referral(&resp, ctx.qname);
        rtrace!(
            "Checked delegation: zone={:?}, ns_names={}, closer_than_current={}, contains_qname={}",
            referral_zone.as_ref().map(|z| z.to_ascii_lower()),
            ns_names.len(),
            referral_zone
                .as_ref()
                .map(|nz| is_closer(nz, &state.zone))
                .unwrap_or(false),
            referral_zone
                .as_ref()
                .map(|nz| is_within(ctx.qname, nz))
                .unwrap_or(false)
        );
        match referral_zone {
            Some(nz) if is_closer(&nz, &state.zone) && is_within(ctx.qname, &nz) => {
                let (addrs, missing_ns, address_ttl) =
                    self.glue_addrs(&resp, &ns_names, &state.zone);
                let pending = PendingReferral {
                    zone: nz,
                    resp,
                    ns_names,
                    addrs,
                    address_ttl,
                    ds_evidence: None,
                    unresolved: Vec::new(),
                };
                self.descend(state, ctx, pending, missing_ns)
            }
            rejected_referral => {
                if plan.is_final {
                    if is_terminal_response(&resp, ctx.qname, &state.zone) {
                        rtrace!(
                            "Got a final response with no answers: name={}",
                            ctx.qname.to_ascii_lower()
                        );
                        return StepOutcome::Done(resp);
                    }

                    rtrace!(
                        "Final response is unusable; treating as unreachable nameservers: name={}",
                        ctx.qname.to_ascii_lower()
                    );
                    return StepOutcome::Failed(RecurseError::NoReachableNs);
                }
                if self.harden_referral_path
                    && (rejected_referral.is_some() || !resp.header.authoritative)
                {
                    rtrace!("Found no safe delegation path; treating as unreachable nameservers");
                    return StepOutcome::Failed(RecurseError::NoReachableNs);
                }
                rtrace!(
                    "No usable delegation; reducing QNAME minimization depth: depth={}",
                    plan.target
                );
                state.depth = plan.target;
                StepOutcome::Continue
            }
        }
    }

    /**
     * @brief 받아들인 경계로 내려간다. 주소를 모르는 네임서버만 있으면 주소부터 풀게 한다.
     * @param missing glue가 없어 주소를 모르는 네임서버 이름들.
     */
    fn descend(
        &self,
        state: &mut IterationState,
        ctx: &IterationContext<'_>,
        mut pending: PendingReferral,
        missing: Vec<Name>,
    ) -> StepOutcome {
        // 부모가 준 주소가 하나라도 있으면 그것으로 내려간다. 주소를 이미 쥐고도
        // 남은 네임서버 이름을 먼저 풀러 가면, 그 하나하나가 다시 루트부터 걷는
        // 해석이 되어 예산을 전부 소진한다. iana.org가 그랬다. 주소 2개를 손에
        // 잡은 채 이름 3개를 풀다가 시간이 끝나 SERVFAIL이 나갔다.
        if !missing.is_empty() && pending.addrs.is_empty() {
            rtrace!(
                "Looking up addresses of nameservers without glue: need_address={}, have_address={}",
                missing.len(),
                pending.addrs.len()
            );

            return StepOutcome::NeedNsAddrs {
                missing,
                pending: Box::new(pending),
            };
        }
        if !missing.is_empty() {
            rtrace!(
                "Leaving {} glueless nameservers and descending with the {} addresses already known",
                missing.len(),
                pending.addrs.len()
            );
            pending.unresolved = missing;
        }
        self.finish_referral(state, ctx, pending)
    }

    /**
     * @brief 답변 절로 드러난 경계의 DS와 그 부재 증명을 부모 영역의 서버에 묻는다.
     * @details 자식 영역도 같은 서버가 맡지만 DS는 부모 영역의 데이터이므로 서버가 부모 쪽에서
     *          답한다. 받은 증거는 참조의 권한 절처럼 체인 검증이 서명으로 확인한다.
     * @return 답변 절과 권한 절의 레코드. 체인 단계의 DS 증거로 쓴다.
     */
    fn fetch_ds_evidence(
        &self,
        zone: &Name,
        parent: &Name,
        servers: &[SocketAddr],
        budget: &mut Budget,
    ) -> Result<Vec<Record>, RecurseError> {
        if budget.queries == 0 {
            return Err(RecurseError::TooManyQueries);
        }
        budget.queries -= 1;
        let resp = self.query_any(
            servers,
            &make_query(zone, RecordType::DS, true),
            parent,
            budget.deadline,
        )?;
        Ok(resp.answers.into_iter().chain(resp.authorities).collect())
    }

    /**
     * @brief 주소가 모인 참조로 실제 이동한다.
     * @details 주소를 정렬해 중복을 없애고 개수를 자른다. 자르지 않으면 주소를 잔뜩 담은
     *          위임 하나가 캐시와 시도 횟수를 함께 부풀린다.
     * @return 쓸 수 있는 주소가 하나도 없으면 실패다.
     */
    fn finish_referral(
        &self,
        state: &mut IterationState,
        ctx: &IterationContext<'_>,
        pending: PendingReferral,
    ) -> StepOutcome {
        let PendingReferral {
            zone: nz,
            resp,
            ns_names,
            mut addrs,
            address_ttl,
            ds_evidence,
            unresolved,
        } = pending;
        addrs.sort_unstable();
        addrs.dedup();
        addrs.truncate(MAX_CACHED_NS_ADDRS);
        if addrs.is_empty() {
            rtrace!("  no reachable nameserver for {}", nz.to_ascii_lower());
            return StepOutcome::Failed(RecurseError::NoReachableNs);
        }
        rtrace!(
            "  following delegation {} ({} nameserver addresses)",
            nz.to_ascii_lower(),
            addrs.len()
        );
        state.servers = addrs;

        if let Some(ttl) = min_ns_ttl(&resp, &nz) {
            self.deleg_store(&nz, &state.servers, address_ttl.map_or(ttl, |a| a.min(ttl)));
        }

        let (
            ds_records,
            ds_rrsigs,
            ds_nsec_records,
            ds_nsec_rrsigs,
            ds_nsec3_records,
            ds_nsec3_rrsigs,
            ds,
        ) = if ctx.collect_ds {
            extract_ds(ds_evidence.as_deref().unwrap_or(&resp.authorities), &nz)
        } else {
            (vec![], vec![], vec![], vec![], vec![], vec![], vec![])
        };
        state.chain.push(ZoneStep {
            zone: nz.clone(),
            servers: state.servers.clone(),
            ns_names,
            ds_records,
            ds_rrsigs,
            ds_nsec_records,
            ds_nsec_rrsigs,
            ds_nsec3_records,
            ds_nsec3_rrsigs,
            ds,
        });
        state.depth = nz.num_labels();
        state.zone = nz;
        state.unresolved_ns = unresolved;
        StepOutcome::Continue
    }

    /**
     * @brief 응답의 추가 절에서 네임서버 주소를 추출한다.
     *
     * @details glue는 부모가 준 것이라 자식 zone 데이터만큼 믿을 수 없다. 그래서 현재
     *          zone 안의 이름에 대한 것만 받아들인다.
     * @warning bailiwick 밖 glue를 받으면 위임 하나로 임의의 이름에 임의의 주소를 심을 수 있다.
     * @return 얻은 주소들, 주소를 모르는 이름들, 그리고 그 주소들의 최소 TTL.
     */
    fn glue_addrs(
        &self,
        resp: &Message,
        ns_names: &[Name],
        zone: &Name,
    ) -> (Vec<SocketAddr>, Vec<Name>, Option<u32>) {
        let mut out = Vec::new();
        let mut covered = Vec::<Name>::new();
        let mut min_ttl = None;
        for r in &resp.additionals {
            if r.class != DnsClass::IN {
                continue;
            }
            let Some(ns_name) = ns_names.iter().find(|n| n.eq_ignore_case(&r.name)) else {
                continue;
            };
            if !is_within(&r.name, zone) {
                continue;
            }
            let addr = match &r.rdata {
                RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), self.port)),
                RData::Aaaa(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), self.port)),
                _ => None,
            };
            if let Some(addr) =
                addr.filter(|addr| self.family_allowed(addr.ip()) && self.is_queryable(addr.ip()))
            {
                out.push(addr);
                min_ttl = min_optional_ttl(min_ttl, Some(r.ttl));
                if !covered.iter().any(|name| name.eq_ignore_case(ns_name)) {
                    covered.push(ns_name.clone());
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        let missing = ns_names
            .iter()
            .filter(|name| !covered.iter().any(|covered| covered.eq_ignore_case(name)))
            .cloned()
            .collect();
        (out, missing, min_ttl)
    }

    /**
     * @brief glue가 없는 네임서버의 주소를 앞에서부터 풀되, 쓸 수 있는 주소가 생기면 멈춘다.
     * @details 이 부수 해석도 같은 예산과 데드라인을 나눠 쓴다. 새로 잡으면 위임 체인 하나가
     *          질의를 기하급수로 늘린다. 이름을 전부 풀면 느린 서버 하나가 남은 시간을 모두
     *          가져가, 주소를 쥐고도 정작 그 영역에는 묻지 못한다. 남은 이름은 돌려주고, 받은
     *          주소들이 모두 답하지 않을 때만 더 푼다.
     * @note 주소는 어디로 보낼지만 정한다. 답은 체인으로 따로 검증하므로 이 해석은 검증하지
     *       않는다. 위조된 주소는 틀린 서버로 보낼 뿐이고, 그 서버의 답은 검증에서 걸러진다.
     * @return 얻은 주소들, 그 최소 TTL, 풀지 않고 남긴 이름들.
     */
    fn resolve_ns_addrs(
        &self,
        ns_names: &[Name],
        budget: &mut Budget,
    ) -> Result<(Vec<SocketAddr>, Option<u32>, Vec<Name>), RecurseError> {
        let mut all: Vec<SocketAddr> = Vec::new();
        let mut all_ttl = None;
        let mut rest = ns_names.iter();
        let ask_aaaa = self.do_ip6 && ipv6_route_available();
        for ns in rest.by_ref() {
            let key = ns.canonical_key();

            if let Some((addrs, ttl)) = self.ns_addr_cached_with_ttl(&key) {
                all.extend(addrs.into_iter().map(|ip| SocketAddr::new(ip, self.port)));
                all_ttl = min_optional_ttl(all_ttl, Some(ttl));
            } else {
                if budget.ns_resolves == 0 {
                    break;
                }
                budget.ns_resolves -= 1;
                let mut resolved: Vec<IpAddr> = Vec::new();
                let mut min_ttl = u32::MAX;
                let families = [(self.do_ip4, RecordType::A), (ask_aaaa, RecordType::AAAA)];
                for (wanted, rtype) in families {
                    if !wanted {
                        continue;
                    }
                    let Ok((m, _)) = self.resolve_inner(ns, rtype, 0, 0, budget, false) else {
                        continue;
                    };
                    for r in m.answers.iter().filter(|r| r.class == DnsClass::IN) {
                        let ip = match &r.rdata {
                            RData::A(ip) => IpAddr::V4(*ip),
                            RData::Aaaa(ip) => IpAddr::V6(*ip),
                            _ => continue,
                        };
                        resolved.push(ip);
                        min_ttl = min_ttl.min(r.ttl);
                    }
                }
                if !resolved.is_empty() {
                    resolved.sort_unstable();
                    resolved.dedup();
                    resolved.truncate(MAX_CACHED_NS_ADDRS);
                    self.ns_addr_store(key, resolved.clone(), min_ttl);
                    all_ttl = min_optional_ttl(all_ttl, Some(min_ttl));
                }
                all.extend(
                    resolved
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, self.port)),
                );
            }
            if all.iter().any(|s| self.usable_server(s.ip())) {
                break;
            }
        }
        all.retain(|s| self.server_eligible(s.ip()));
        all.sort_unstable();
        all.dedup();
        Ok((all, all_ttl, rest.cloned().collect()))
    }

    /**
     * @brief 지금 이 호스트에서 실제로 보낼 수 있는 서버 주소인지.
     * @details 허용 여부에 더해, IPv6 경로가 없는 호스트의 IPv6 주소는 쓸 수 없는 것으로 본다.
     *          그런 주소만 쥐고 네임서버 풀기를 멈추면 보낼 곳이 없다.
     */
    fn usable_server(&self, ip: IpAddr) -> bool {
        self.server_eligible(ip) && (ip.is_ipv4() || ipv6_route_available())
    }

    /**
     * @brief 지금 영역의 서버가 모두 답하지 않을 때 남겨 둔 네임서버 이름의 주소를 더 푼다.
     * @return 새 주소를 얻어 서버 목록을 바꿨으면 참.
     */
    fn resolve_more_ns_addrs(&self, state: &mut IterationState, budget: &mut Budget) -> bool {
        while !state.unresolved_ns.is_empty() {
            let names = std::mem::take(&mut state.unresolved_ns);
            let Ok((addrs, _, rest)) = self.resolve_ns_addrs(&names, budget) else {
                return false;
            };
            state.unresolved_ns = rest;
            let fresh: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|addr| !state.servers.contains(addr))
                .collect();
            if fresh.is_empty() {
                continue;
            }
            rtrace!(
                "Nameservers of {} did not answer; resolved {} more addresses ({} names left)",
                state.zone.to_ascii_lower(),
                fresh.len(),
                state.unresolved_ns.len()
            );
            if let Some(step) = state.chain.last_mut() {
                step.servers.extend(fresh.iter().copied());
            }
            state.servers = fresh;
            return true;
        }
        false
    }

    #[cfg(test)]
    /** @brief 캐시된 네임서버 주소. */
    fn ns_addr_cached(&self, key: &[u8]) -> Option<Vec<IpAddr>> {
        self.ns_addr_cached_with_ttl(key).map(|(addrs, _)| addrs)
    }

    /** @brief 캐시된 네임서버 주소와 남은 TTL. 만료된 항목은 꺼내면서 버린다. */
    fn ns_addr_cached_with_ttl(&self, key: &[u8]) -> Option<(Vec<IpAddr>, u32)> {
        let mut cache = self.ns_addr_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => {
                let remaining = entry
                    .lifetime
                    .remaining_secs(now)
                    .expect("A live TTL must have time remaining");
                Some((entry.addrs.clone(), remaining))
            }
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    /** @brief 네임서버 주소를 캐시에 담는다. */
    fn ns_addr_store(&self, key: Vec<u8>, addrs: Vec<IpAddr>, ttl_secs: u32) {
        let mut addrs = addrs;
        addrs.sort_unstable();
        addrs.dedup();
        addrs.truncate(MAX_CACHED_NS_ADDRS);
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        self.ns_addr_cache.lock_recover().put(
            key,
            NsAddrEntry {
                addrs,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /**
     * @brief 이 이름에 대해 캐시된 위임 중 가장 깊은 것.
     * @details 깊을수록 남은 단계가 적다. 얕은 것을 고르면 캐시를 쓰는 의미가 줄어든다.
     */
    fn deepest_cached_delegation(&self, qname: &Name) -> Option<(Name, Vec<SocketAddr>)> {
        let total = qname.num_labels();
        let now = cache_now_millis();
        let mut key = [0u8; 255];
        let mut cache = self.deleg_cache.lock_recover();
        for k in (1..=total).rev() {
            let key = qname.canonical_suffix_key_into(k, &mut key)?;
            match cache.get(key) {
                Some(entry) if entry.lifetime.is_live(now) => {
                    return Some((qname.suffix(k), entry.servers.clone()));
                }
                Some(_) => {
                    cache.pop(key);
                }
                None => {}
            }
        }
        None
    }

    #[cfg(test)]
    /** @brief zone의 캐시된 위임 서버들. 만료된 항목은 꺼내면서 버린다. */
    fn deleg_cached(&self, zone: &Name) -> Option<Vec<SocketAddr>> {
        let mut key = [0u8; 255];
        let key = zone.canonical_key_into(&mut key)?;
        let mut cache = self.deleg_cache.lock_recover();
        let now = cache_now_millis();
        match cache.get(key) {
            Some(entry) if entry.lifetime.is_live(now) => Some(entry.servers.clone()),
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    /** @brief 위임 서버를 캐시에 담는다. */
    fn deleg_store(&self, zone: &Name, servers: &[SocketAddr], ttl_secs: u32) {
        if servers.is_empty() {
            return;
        }
        let mut servers = servers.to_vec();
        servers.sort_unstable();
        servers.dedup();
        servers.truncate(MAX_CACHED_NS_ADDRS);
        let ttl = ttl_secs.min(self.recursive_cache_ttl_max);
        if ttl == 0 {
            return;
        }
        let key = zone.canonical_key();
        self.deleg_cache.lock_recover().put(
            key,
            DelegationEntry {
                servers,
                lifetime: TtlLifetime::new(ttl),
            },
        );
    }

    /**
     * @brief 이 이름으로 가는 경로의 위임 캐시를 전부 지운다.
     * @details 캐시된 위임에서 시작한 시도가 실패했을 때 부른다. 어느 단계가 오래됐는지
     *          알 수 없으므로 경로 전체를 버리고 루트부터 다시 걷는다.
     */
    fn deleg_evict_path(&self, qname: &Name) {
        let total = qname.num_labels();
        let mut cache = self.deleg_cache.lock_recover();
        let mut key = [0u8; 255];
        for k in 1..=total {
            if let Some(key) = qname.canonical_suffix_key_into(k, &mut key) {
                cache.pop(key);
            }
        }
    }

    /**
     * @brief 서버들을 순서대로 시도해 쓸 만한 응답 하나를 얻는다.
     *
     * @details 응답성이 좋은 서버부터 물어본다. 응답이 왔어도 이 서버의 질의와 맞지 않으면
     *          쓰지 않고 다음 서버로 넘어가되, 마지막 수단으로 남겨 둔다.
     * @warning 0x20 인코딩을 켰으면 응답의 질문 이름이 보낸 것과 대소문자까지 같아야 한다.
     *          이 검사가 위조 응답을 걸러 내는 실체다.
     * @note 서버당 시간을 나눠 준다. 첫 서버가 데드라인을 다 쓰면 나머지를 시도조차 못 한다.
     */
    fn query_any(
        &self,
        servers: &[SocketAddr],
        q: &Message,
        zone: &Name,
        deadline: Instant,
    ) -> Result<Message, RecurseError> {
        self.query_any_reserving(servers, q, zone, deadline, 0)
    }

    /**
     * @brief query_any와 같되, 아직 주소를 풀지 않은 서버 몫의 시간을 남겨 둔다.
     * @param reserve 이 목록이 모두 실패하면 이어서 풀어 물어볼 네임서버 이름 수.
     * @details 서버마다 답을 기다릴 시간(server_patience)이 지나면 앞 서버의 답을 기다리는
     *          채로 다음 서버에도 묻고, 먼저 온 쓸 만한 답을 쓴다. 앞 서버를 버리고 넘어가면
     *          조금 느린 서버의 답을 받기 직전에 버리게 되고, 끝까지 기다리면 느린 서버 하나가
     *          남은 시간을 다 쓴다.
     * @note 네임서버 주소는 쓸 수 있는 것이 생기면 그만 풀므로 목록이 짧다. 그 몇 개로 시간을
     *       나누면 죽은 서버 하나가 데드라인을 다 써서 남은 이름으로 넘어가지 못한다.
     */
    fn query_any_reserving(
        &self,
        servers: &[SocketAddr],
        q: &Message,
        zone: &Name,
        deadline: Instant,
        reserve: usize,
    ) -> Result<Message, RecurseError> {
        let mut fallback: Option<Message> = None;

        let mut sent = q.clone();
        self.apply_outgoing_case(&mut sent);

        let ordered: Vec<SocketAddr> = self
            .order_by_infra(servers, zone)
            .into_iter()
            .filter(|server| self.server_eligible(server.ip()))
            .collect();
        if ordered.is_empty() {
            return Err(RecurseError::NoReachableNs);
        }

        let per_exchange_deadline = Instant::now().checked_add(self.timeout).unwrap_or(deadline);
        let deadline = deadline.min(per_exchange_deadline);
        let divisor = (ordered.len() + reserve).clamp(1, 4) as u32;
        let per_server = (self.timeout / divisor).max(Duration::from_millis(300));
        let request = std::sync::Arc::new(sent);
        let (tx, rx) = std::sync::mpsc::channel();
        let mut started: Vec<Option<Instant>> = vec![None; ordered.len()];
        let mut next = 0;
        let mut in_flight = 0usize;
        let mut ask_next_at = Instant::now();

        // 교환마다 제한 시간을 데드라인 안에 잡으므로, 이 상한은 교환이 제 시간을 넘기는
        // 이상한 경우에만 쓰인다.
        let settled_by = deadline + per_server;
        loop {
            let now = Instant::now();
            let asking = now < deadline;
            if !asking && (in_flight == 0 || now >= settled_by) {
                if next < ordered.len() {
                    rtrace!(
                        "Ran out of time before asking some of the {} servers: name={}",
                        servers.len(),
                        request
                            .questions
                            .first()
                            .map(|q| q.name.to_ascii_lower())
                            .unwrap_or_default()
                    );
                }
                break;
            }
            if asking
                && next < ordered.len()
                && (in_flight == 0 || (now >= ask_next_at && in_flight < MAX_EXCHANGES_PER_QUERY))
            {
                let server = ordered[next];
                let attempt_timeout = per_server.min(deadline - now);
                self.spawn_attempt(server, &request, attempt_timeout, next, &tx);
                started[next] = Some(now);
                next += 1;
                in_flight += 1;
                ask_next_at = now + self.server_patience(server.ip()).min(per_server);
                continue;
            }
            if in_flight == 0 {
                break;
            }
            // 데드라인이 지나면 새로 묻지 않고, 이미 보낸 교환이 끝나 결과를 보낼 때까지만
            // 기다린다. 끝나기 전에 돌아가면 그 교환이 아직 진행 중으로 남아, 곧 같은 질의를 다시
            // 보내는 쪽이 끝나 가는 교환에 합쳐져 함께 시간 초과로 끝난다.
            let wake = if !asking {
                settled_by
            } else if next < ordered.len() && in_flight < MAX_EXCHANGES_PER_QUERY {
                ask_next_at.min(deadline)
            } else {
                deadline
            };
            let Ok((idx, result)) = rx.recv_timeout(wake.saturating_duration_since(now)) else {
                continue;
            };
            in_flight -= 1;
            let s = ordered[idx];
            let elapsed = started[idx]
                .take()
                .map_or(Duration::ZERO, |at| at.elapsed());
            match result {
                Ok(r) => {
                    if self.caps_for_id && !questions_case_exact(&r.questions, &request.questions) {
                        rtrace!(
                            "{} did not echo the query name case; dropping: sent={}, got={}",
                            s,
                            request
                                .questions
                                .first()
                                .map(|q| q.name.to_string())
                                .unwrap_or_default(),
                            r.questions
                                .first()
                                .map(|q| q.name.to_string())
                                .unwrap_or_default()
                        );
                        self.infra_fail(s.ip(), zone);
                        ask_next_at = Instant::now();
                        continue;
                    }
                    if response_usable_for_iteration(&r, &request, zone) {
                        self.infra_success(s.ip(), zone, elapsed);
                        self.record_unanswered(&ordered, &started);
                        return Ok(r);
                    }

                    self.infra_protocol_error(s.ip(), zone);
                    fallback = Some(r);
                    ask_next_at = Instant::now();
                }
                Err(error) => {
                    rtrace!(
                        "Asked {} but got no answer: name={}, type={:?}, error={:?}",
                        s,
                        request
                            .questions
                            .first()
                            .map(|q| q.name.to_ascii_lower())
                            .unwrap_or_default(),
                        request.questions.first().map(|q| q.qtype),
                        error
                    );
                    self.infra_fail(s.ip(), zone);
                    ask_next_at = Instant::now();
                }
            }
        }
        self.record_unanswered(&ordered, &started);
        fallback.ok_or(RecurseError::NoResponse)
    }

    /**
     * @brief 서버 하나에 묻는 교환을 따로 돌리고 결과를 채널로 보낸다.
     * @details 부른 쪽은 이 교환을 기다리는 동안 다른 서버에도 물을 수 있어야 한다. 부른 쪽이
     *          먼저 끝나 채널을 닫아도 교환은 자기 제한 시간 안에 끝나고 결과만 버려진다.
     *          스레드를 만들지 못하면 이 자리에서 직접 묻는다.
     * @note 전송은 교환마다 새로 고른다. UDP 53번 가로채기 판정은 해석 도중에도 켜지며, 켜진
     *       뒤에 UDP로 보낸 질의는 답을 받지 못한다.
     */
    fn spawn_attempt(
        &self,
        server: SocketAddr,
        request: &std::sync::Arc<Message>,
        timeout: Duration,
        idx: usize,
        tx: &std::sync::mpsc::Sender<(usize, Result<Message, onetdns_forward::ForwardError>)>,
    ) {
        let merge_case = self.caps_for_id;
        let transport = if self.authority_over_tcp() {
            onetdns_forward::AuthorityTransport::Tcp
        } else {
            onetdns_forward::AuthorityTransport::Udp
        };
        let attempt = {
            let request = request.clone();
            let tx = tx.clone();
            move || {
                let result = onetdns_forward::query_server_over(
                    server, &request, timeout, transport, merge_case,
                );
                let _ = tx.send((idx, result));
            }
        };
        if std::thread::Builder::new()
            .name("recurse-exchange".into())
            .spawn(attempt)
            .is_err()
        {
            let result =
                onetdns_forward::query_server_over(server, request, timeout, transport, merge_case);
            let _ = tx.send((idx, result));
        }
    }

    /**
     * @brief 답을 받기 전에 그만 기다린 서버들의 왕복 시간을 기다린 시간 이상으로 기록한다.
     * @param started 서버마다 아직 답을 기다리던 교환의 시작 시각.
     */
    fn record_unanswered(&self, ordered: &[SocketAddr], started: &[Option<Instant>]) {
        for (server, at) in ordered.iter().zip(started) {
            if let Some(at) = at {
                self.record_rtt_at_least(server.ip(), at.elapsed());
            }
        }
    }

    /**
     * @brief 이 서버의 답을 기다렸다가 다음 서버에도 물을 때까지의 시간.
     * @details 잰 왕복 시간이 있으면 그 세 배다. RFC 6298이 첫 측정 뒤에 잡는 재전송 시간과
     *          같은 값으로, 평소의 흔들림으로는 넘지 않는다.
     */
    fn server_patience(&self, ip: IpAddr) -> Duration {
        match self.srtt(ip) {
            Some(ms) => Duration::from_millis(u64::from(ms) * 3).max(MIN_SERVER_PATIENCE),
            None => UNKNOWN_SERVER_PATIENCE,
        }
    }

    /**
     * @brief 응답성 통계로 서버 순서를 정한다.
     * @details 선호 계열, 점수, 그리고 냉각 중인지로 정렬한다. 냉각 중인 서버도 목록
     *          뒤에는 남긴다. 전부 냉각 중이면 아무 데도 못 묻게 되기 때문이다.
     */
    fn order_by_infra(&self, servers: &[SocketAddr], zone: &Name) -> Vec<SocketAddr> {
        let infra = self.infra.lock_recover();
        let rtt = self.rtt.lock_recover();
        let now = Instant::now();

        let eligible: Vec<SocketAddr> = servers
            .iter()
            .copied()
            .filter(|server| self.family_allowed(server.ip()))
            .collect();
        let score = |server: &SocketAddr| {
            let key = InfraKey::new(server.ip(), zone);
            (
                self.family_rank(server.ip()),
                infra_score(infra.peek(&key), rtt.peek(&server.ip()).copied(), now),
                *server,
            )
        };
        let mut ready: Vec<(u8, u64, SocketAddr)> = eligible
            .iter()
            .filter(|server| {
                let key = InfraKey::new(server.ip(), zone);
                !infra_is_cooling(&infra, &key, now)
            })
            .map(score)
            .collect();

        if ready.is_empty() {
            if let Some(server) = eligible.iter().min_by_key(|server| {
                let key = InfraKey::new(server.ip(), zone);
                infra
                    .peek(&key)
                    .and_then(|state| state.last_fail)
                    .unwrap_or_else(Instant::now)
            }) {
                ready.push(score(server));
            }
        }
        drop(rtt);
        drop(infra);
        ready.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        ready.into_iter().map(|(_, _, server)| server).collect()
    }

    /** @brief 이 주소가 재 본 적 있는 왕복 시간. 처음 보는 주소면 없다. */
    fn srtt(&self, ip: IpAddr) -> Option<u32> {
        self.rtt.lock_recover().peek(&ip).copied()
    }

    /**
     * @brief 왕복 시간 측정 하나를 반영한다.
     * @note 지수 평활이라 새 측정이 8분의 1만 반영된다. 한 번 느렸다고 순위가 뒤집히지 않는다.
     */
    fn record_rtt(&self, ip: IpAddr, sample: Duration) {
        let ms = sample.as_millis().min(u128::from(u32::MAX)) as u32;
        let mut rtt = self.rtt.lock_recover();
        let smoothed = match rtt.peek(&ip) {
            Some(&old) => ((u64::from(old) * 7 + u64::from(ms)) / 8) as u32,
            None => ms,
        };
        rtt.put(ip, smoothed);
    }

    /**
     * @brief 답을 기다리던 중에 다른 서버의 답을 받아 그만 기다린 서버를 기록한다.
     * @details 이 서버의 왕복 시간은 적어도 기다린 시간만큼이다. 이것을 남기지 않으면 처음 보는
     *          서버로 남아 다음 질의에서도 가장 먼저 물어진다.
     */
    fn record_rtt_at_least(&self, ip: IpAddr, waited: Duration) {
        if self
            .srtt(ip)
            .is_none_or(|known| u128::from(known) < waited.as_millis())
        {
            self.record_rtt(ip, waited);
        }
    }

    /** @brief 성공을 기록한다. 왕복 시간을 갱신하고 이 zone에서의 실패 기록을 지운다. */
    fn infra_success(&self, ip: IpAddr, zone: &Name, rtt: Duration) {
        self.record_rtt(ip, rtt);
        self.infra.lock_recover().pop(&InfraKey::new(ip, zone));
    }

    /** @brief 프로토콜 오류를 기록한다. 응답은 왔으므로 전송 실패와는 다르게 센다. */
    fn infra_protocol_error(&self, ip: IpAddr, zone: &Name) {
        let key = InfraKey::new(ip, zone);
        let mut infra = self.infra.lock_recover();
        let mut state = infra.pop(&key).unwrap_or_default();
        state.last_protocol_error = Some(Instant::now());
        infra.put(key, state);
    }

    /** @brief 전송 실패를 기록한다. 잠시 뒤로 밀린다. */
    fn infra_fail(&self, ip: IpAddr, zone: &Name) {
        let key = InfraKey::new(ip, zone);
        let mut infra = self.infra.lock_recover();
        let mut state = infra.pop(&key).unwrap_or_default();
        state.last_fail = Some(Instant::now());
        infra.put(key, state);
    }
}

/** @brief 이 서버가 아직 실패 냉각 중인지. */
fn infra_is_cooling(infra: &LruMap<InfraKey, InfraStat>, key: &InfraKey, now: Instant) -> bool {
    infra
        .peek(key)
        .and_then(|state| state.last_fail)
        .is_some_and(|failed_at| now.saturating_duration_since(failed_at) < INFRA_FAIL_COOLDOWN)
}

/**
 * @brief 서버 점수. 낮을수록 먼저 시도한다.
 * @details 왕복 시간에 실패 벌점을 더한다. 벌점을 크게 잡아 실패한 서버가 뒤로 가지만,
 *          완전히 배제하지는 않아 냉각이 끝나면 자연히 돌아온다.
 * @param state 이 서버와 zone 쌍의 실패 기록.
 * @param srtt_ms 이 주소의 평활 왕복 시간. 재 본 적 없으면 없다.
 */
fn infra_score(state: Option<&InfraStat>, srtt_ms: Option<u32>, now: Instant) -> u64 {
    let base = u64::from(srtt_ms.unwrap_or(DEFAULT_RTT_MS));
    let Some(state) = state else {
        return base;
    };
    let recent = |at: Option<Instant>| {
        at.is_some_and(|at| now.saturating_duration_since(at) < INFRA_FAIL_COOLDOWN)
    };
    let transport_penalty = if recent(state.last_fail) {
        INFRA_FAIL_PENALTY_MS
    } else {
        0
    };
    let protocol_penalty = if recent(state.last_protocol_error) {
        INFRA_PROTOCOL_PENALTY_MS
    } else {
        0
    };
    base + transport_penalty + protocol_penalty
}

/**
 * @brief 이 주소가 전역에서 라우팅되는 정상 주소인지.
 *
 * @details 루프백, 사설, 링크 로컬, 문서화용, 그리고 IPv6에 IPv4를 포함한 형태까지 전부
 *          거른다. 포함한 형태를 놓치면 IPv6 주소로 감싼 내부 IPv4로 우회할 수 있다.
 * @warning 이것이 SSRF 방어의 핵심이다. 위임을 조작해 내부망 주소를 네임서버로 심으면
 *          이 서버가 대신 내부망을 두드리게 된다.
 */
fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => !is_special_v4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = embedded_v4(address) {
                return !is_special_v4(mapped);
            }
            let octets = address.octets();
            let segments = address.segments();
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0
                || (segments[0] & 0xfe00) == 0xfc00
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
                || octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]
                || (octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x00
                    && octets[3] == 0x02)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001))
        }
    }
}

/** @brief IPv6 주소 안에 든 IPv4를 꺼낸다. 매핑, 6to4, NAT64 형태를 모두 본다. */
fn embedded_v4(address: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let segments = address.segments();
    let octets = address.octets();

    if segments[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(
            octets[2], octets[3], octets[4], octets[5],
        ));
    }

    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6] == [0, 0, 0, 0] {
        return Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(std::net::Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    None
}

/** @brief 이 IPv4가 특수 용도 대역인지. 루프백·사설·링크로컬·문서화용 등을 모두 포함한다. */
fn is_special_v4(address: std::net::Ipv4Addr) -> bool {
    let value = u32::from(address);
    let in_net = |network: [u8; 4], prefix: u8| {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        value & mask == u32::from(std::net::Ipv4Addr::from(network)) & mask
    };

    in_net([0, 0, 0, 0], 8)
        || in_net([10, 0, 0, 0], 8)
        || in_net([100, 64, 0, 0], 10)
        || in_net([127, 0, 0, 0], 8)
        || in_net([169, 254, 0, 0], 16)
        || in_net([172, 16, 0, 0], 12)
        || in_net([192, 0, 0, 0], 24)
        || in_net([192, 0, 2, 0], 24)
        || in_net([192, 88, 99, 0], 24)
        || in_net([192, 168, 0, 0], 16)
        || in_net([198, 18, 0, 0], 15)
        || in_net([198, 51, 100, 0], 24)
        || in_net([203, 0, 113, 0], 24)
        || in_net([224, 0, 0, 0], 4)
        || in_net([240, 0, 0, 0], 4)
}

/** @brief 검증 실패로 막은 응답 수. 지표로 내보낸다. */
pub static VALIDATION_BOGUS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
std::thread_local! {
    /** @brief 병렬 테스트의 전역 계수 간섭 없이 현재 스레드의 증가만 관찰한다. */
    static TEST_THREAD_VALIDATION_BOGUS_TOTAL: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

/** @brief 지금까지의 검증 실패 수. */
pub fn validation_bogus_total() -> u64 {
    VALIDATION_BOGUS_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/** @brief 검증 실패를 전역 관측성 계수에 한 번 기록한다. */
fn record_validation_bogus() {
    VALIDATION_BOGUS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    TEST_THREAD_VALIDATION_BOGUS_TOTAL.with(|total| {
        total.set(total.get().saturating_add(1));
    });
}

#[cfg(test)]
/** @brief 현재 테스트 스레드가 기록한 검증 실패 수. */
fn test_thread_validation_bogus_total() -> u64 {
    TEST_THREAD_VALIDATION_BOGUS_TOTAL.with(std::cell::Cell::get)
}

/**
 * @brief EDE 사유 코드에 붙일 설명 문구.
 * @details 사유마다 다른 문구를 주어야 운영자가 무엇을 고쳐야 할지 알 수 있다. 서명이
 *          깨진 것과 이 서버가 계산을 거부한 것은 대응이 다르다.
 */
fn ede_text_for(code: u16) -> &'static str {
    match code {
        ede_code::UNSUPPORTED_NSEC3_ITERATIONS => "NSEC3 iterations above local limit",
        ede_code::NO_REACHABLE_AUTHORITY => "Could not fetch the DNSSEC keys from the authority",
        _ => "DNSSEC validation failed",
    }
}

/**
 * @brief 검증에 실패한 응답을 SERVFAIL로 바꾼다.
 * @note 질문만 남기고 레코드를 전부 버린다. 깨진 답을 조금이라도 남기면 질의자가 그것을
 *       쓸 수 있다.
 */
fn bogus_servfail(template: &Message, ede: u16) -> Message {
    // 키를 받지 못한 것은 권한 서버에 닿지 못한 것이지 검증이 실패한 것이 아니다. 검증 실패
    // 지표에 섞으면 망 장애가 서명 문제로 보인다.
    if ede != ede_code::NO_REACHABLE_AUTHORITY {
        record_validation_bogus();
    }
    let mut sf = Message::default();
    sf.header.id = template.header.id;
    sf.header.rcode = ResponseCode::ServFail.0;
    sf.questions = template.questions.clone();
    let mut e = Edns::default();
    e.push_ede(ede, ede_text_for(ede));
    sf.additionals.push(e.try_to_record().unwrap());
    sf
}

/** @brief 업스트림에 보낼 질의 메시지를 만든다. 재귀 요청 비트는 설정하지 않는다. */
fn make_query(qname: &Name, qtype: RecordType, do_bit: bool) -> Message {
    let mut m = Message {
        header: Header {
            id: 0,
            recursion_desired: false,
            ..Default::default()
        },
        questions: vec![Question {
            name: qname.clone(),
            qtype,
            qclass: DnsClass::IN,
        }],
        ..Default::default()
    };
    m.additionals.push(
        Edns {
            udp_payload: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: do_bit,
            options: vec![],
        }
        .try_to_record()
        .unwrap(),
    );
    m
}

/**
 * @brief 이름의 대소문자를 무작위로 섞는다.
 * @details 응답에 그대로 되비쳐 오므로, 맞히려면 트랜잭션 ID와 포트 외에 이 패턴까지
 *          맞혀야 한다. 위조 난도를 크게 올린다.
 */
fn randomize_name_case(name: &Name) -> Name {
    let mut bits = onetdns_core::ephemeral_random_array::<32>();
    let mut idx = 0usize;
    let labels: Vec<Vec<u8>> = name
        .labels()
        .iter()
        .map(|l| {
            l.iter()
                .map(|&b| {
                    if b.is_ascii_alphabetic() {
                        if idx >= bits.len() * 8 {
                            bits = onetdns_core::ephemeral_random_array::<32>();
                            idx = 0;
                        }
                        let bit = (bits[idx / 8] >> (idx % 8)) & 1;
                        idx += 1;
                        if bit == 1 {
                            b.to_ascii_uppercase()
                        } else {
                            b.to_ascii_lowercase()
                        }
                    } else {
                        b
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels).unwrap_or_else(|_| name.clone())
}

/** @brief 이름을 소문자로 내린다. 업스트림 캐시 적중률을 올린다. */
fn lowercase_name(name: &Name) -> Name {
    Name::from_labels(
        name.labels()
            .iter()
            .map(|l| l.to_ascii_lowercase())
            .collect(),
    )
    .unwrap_or_else(|_| name.clone())
}

/**
 * @brief 응답의 질문이 보낸 것과 대소문자까지 같은지.
 * @warning 0x20 인코딩의 검사 지점이다. 대소문자를 무시하면 이 방어가 전부 사라진다.
 */
fn questions_case_exact(resp: &[Question], sent: &[Question]) -> bool {
    if resp.len() != sent.len() {
        return false;
    }
    resp.iter().zip(sent).all(|(a, b)| {
        a.qtype == b.qtype
            && a.qclass == b.qclass
            && a.name.labels().len() == b.name.labels().len()
            && a.name
                .labels()
                .iter()
                .zip(b.name.labels())
                .all(|(x, y)| x == y)
    })
}

/**
 * @brief DS와 그 부재 증명, 서명을 추출한다. 체인 단계에 기록된다.
 * @param records 참조 응답의 권한 절, 또는 부모에게 따로 물은 DS 응답의 레코드.
 */
fn extract_ds(
    records: &[Record],
    child_zone: &Name,
) -> (
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<Record>,
    Vec<onetdns_dnssec::Rrsig>,
    Vec<onetdns_dnssec::Ds>,
) {
    let mut recs = Vec::new();
    let mut ds = Vec::new();
    let mut nsec = Vec::new();
    let mut nsec_sigs = Vec::new();
    let mut nsec3 = Vec::new();
    let mut nsec3_sigs = Vec::new();
    let mut ds_rrsig_ttl = None;
    let mut nsec_owners = HashSet::new();
    let mut nsec3_owners = HashSet::new();
    for r in records {
        if r.class != DnsClass::IN {
            continue;
        }
        if r.rtype == RecordType::DS && r.name.eq_ignore_case(child_zone) {
            recs.push(r.clone());
            if let Some(d) = onetdns_dnssec::Ds::from_record(r) {
                ds.push(d);
            }
        } else if r.rtype == RecordType::NSEC {
            nsec_owners.insert(r.name.canonical_key());
            nsec.push(r.clone());
        } else if r.rtype == RecordType::NSEC3 {
            nsec3_owners.insert(r.name.canonical_key());
            nsec3.push(r.clone());
        }
    }

    let mut sigs = Vec::new();
    for record in records {
        if record.class != DnsClass::IN || record.rtype != RecordType::RRSIG {
            continue;
        }
        let Some(signature) = onetdns_dnssec::Rrsig::from_record(record) else {
            continue;
        };
        match RecordType(signature.type_covered) {
            RecordType::DS if record.name.eq_ignore_case(child_zone) => {
                ds_rrsig_ttl = min_optional_ttl(ds_rrsig_ttl, Some(record.ttl));
                sigs.push(signature);
            }
            RecordType::NSEC if nsec_owners.contains(&record.name.canonical_key()) => {
                nsec_sigs.push(signature);
            }
            RecordType::NSEC3 if nsec3_owners.contains(&record.name.canonical_key()) => {
                nsec3_sigs.push(signature);
            }
            _ => {}
        }
    }

    if let Some(ttl) = ds_rrsig_ttl {
        for record in &mut recs {
            record.ttl = record.ttl.min(ttl);
        }
    }
    (recs, sigs, nsec, nsec_sigs, nsec3, nsec3_sigs, ds)
}

/**
 * @brief 이 호스트에 전역 IPv6 경로가 있는지.
 * @details UDP 소켓의 connect는 경로만 고르고 패킷을 보내지 않으므로, 경로가 없으면 네트워크
 *          도달 불가로 바로 실패한다. 경로가 없는 호스트에서 AAAA를 풀면 쓸 수 없는 주소를
 *          얻으려고 시간만 쓴다. 망은 바뀔 수 있으므로 판정은 30초만 쓴다.
 * @note 대상은 a.root-servers.net 의 IPv6 주소다. 전역 경로가 있는지만 보므로 응답은 필요 없다.
 */
fn ipv6_route_available() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    /** @brief 판정을 다시 할 간격(초). */
    const RECHECK_SECS: u64 = 30;
    /** @brief 마지막 판정 시각(Unix 초)을 위 비트에, 결과를 맨 아래 비트에 담는다. 0이면 판정 전이다. */
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last >> 1) < RECHECK_SECS {
        return last & 1 == 1;
    }
    let probe = SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30,
        )),
        53,
    );
    let available = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
        .and_then(|sock| sock.connect(probe))
        .is_ok();
    LAST.store((now << 1) | u64::from(available), Ordering::Relaxed);
    available
}

/** @brief 현재 Unix 초. 서명 유효 기간 판정에 쓴다. */
fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/** @brief 특정 소유자와 타입을 덮는 RRSIG만 골라낸다. */
fn extract_rrsigs(
    records: &[Record],
    type_covered: u16,
    owner: &Name,
) -> Vec<onetdns_dnssec::Rrsig> {
    records
        .iter()
        .filter(|r| {
            r.class == DnsClass::IN && r.rtype == RecordType::RRSIG && r.name.eq_ignore_case(owner)
        })
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|sig| sig.type_covered == type_covered)
        .collect()
}

/**
 * @brief 와일드카드 확장이 정당함을 증명했는지.
 * @details next closer가 존재하지 않는다는 서명된 NSEC이나 NSEC3이 있어야 한다. 없으면
 *          더 구체적인 이름을 숨긴 것일 수 있다.
 */
struct WildcardValidation<'a> {
    /** @brief 리프 zone의 검증된 키. */
    keys: &'a [onetdns_dnssec::Dnskey],
    /** @brief 서명자가 일치해야 하는 리프 apex. */
    apex: &'a Name,
    /** @brief 서명 시간 검사 기준. */
    now: u32,
    /** @brief 허용할 NSEC3 반복 상한. */
    nsec3_max_iterations: u16,
    /** @brief 답변 RRset부터 이어 받은 응답 전체 공개키 예산. */
    verification_budget: &'a mut onetdns_dnssec::VerificationBudget,
}

fn validated_wildcard_expansion(
    response: &Message,
    qname: &Name,
    closest_encloser_labels: usize,
    validation: WildcardValidation<'_>,
) -> bool {
    let denial_records = |rtype| {
        response
            .authorities
            .iter()
            .filter(|record| record.class == DnsClass::IN && record.rtype == rtype)
            .cloned()
            .collect::<Vec<_>>()
    };
    let nsecs = denial_records(RecordType::NSEC);
    if let Some(proof) =
        onetdns_dnssec::nsec_wildcard_expansion_proof(&nsecs, qname, closest_encloser_labels)
    {
        if validate_denial_proof(
            &proof,
            &response.authorities,
            validation.keys,
            validation.apex,
            validation.now,
            validation.verification_budget,
        ) {
            return true;
        }
    }
    let nsec3s = denial_records(RecordType::NSEC3);
    onetdns_dnssec::nsec3_max_iterations(&nsec3s) <= validation.nsec3_max_iterations
        && onetdns_dnssec::nsec3_wildcard_expansion_proof(&nsec3s, qname, closest_encloser_labels)
            .is_some_and(|proof| {
                validate_denial_proof(
                    &proof,
                    &response.authorities,
                    validation.keys,
                    validation.apex,
                    validation.now,
                    validation.verification_budget,
                )
            })
}

/** @brief 선택된 최소 NSEC/NSEC3 증명의 RRset 서명을 전부 확인한다. */
fn validate_denial_proof(
    proof: &[Record],
    response_records: &[Record],
    keys: &[onetdns_dnssec::Dnskey],
    apex: &Name,
    now: u32,
    verification_budget: &mut onetdns_dnssec::VerificationBudget,
) -> bool {
    !proof.is_empty()
        && proof.iter().all(|record| {
            let signatures = extract_rrsigs(response_records, record.rtype.0, &record.name);
            onetdns_dnssec::validate_rrset_in_zone_with_budget(
                std::slice::from_ref(record),
                &signatures,
                keys,
                apex,
                now,
                verification_budget,
            )
            .is_ok()
        })
}

/** @brief 이름이 zone 안인지. */
fn is_within(name: &Name, zone: &Name) -> bool {
    name.ends_with_ignore_case(zone)
}

/** @brief 현재 zone 밖 소유자의 DNAME을 응답에서 걷어낸다. 남기면 그것으로 이름을 가로챌 수 있다. */
fn strip_out_of_bailiwick_dnames(resp: &mut Message, zone: &Name) {
    resp.answers
        .retain(|r| !matches!(r.rdata, RData::Dname(_)) || is_within(&r.name, zone));
}

/** @brief 후보 zone이 현재보다 질의 이름에 더 가까운지. 참조를 따라가는 조건 중 하나다. */
fn is_closer(cand: &Name, cur: &Name) -> bool {
    cand.num_labels() > cur.num_labels() && is_within(cand, cur)
}

/** @brief 두 TTL 중 작은 쪽. 한쪽이 없으면 나머지. */
fn min_optional_ttl(left: Option<u32>, right: Option<u32>) -> Option<u32> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(ttl), None) | (None, Some(ttl)) => Some(ttl),
        (None, None) => None,
    }
}

/**
 * @brief 경계의 NS 레코드 중 최소 TTL. 위임 캐시 기간이 된다.
 * @note 참조면 권한 절에, 권한 있는 답으로 드러난 경계면 답변 절에 있다.
 */
fn min_ns_ttl(resp: &Message, zone: &Name) -> Option<u32> {
    resp.authorities
        .iter()
        .chain(&resp.answers)
        .filter(|r| {
            r.class == DnsClass::IN && r.rtype == RecordType::NS && r.name.eq_ignore_case(zone)
        })
        .map(|r| r.ttl)
        .min()
}

/**
 * @brief 응답에서 위임 zone과 네임서버 이름들을 추출한다.
 * @note 권한 절의 NS만 본다. 답변 절의 NS는 그 zone 자신에 대한 답이지 위임이 아니다.
 */
fn extract_referral(resp: &Message, qname: &Name) -> (Option<Name>, Vec<Name>) {
    if resp.header.rcode != ResponseCode::NoError.0
        || resp.header.authoritative
        || !resp.answers.is_empty()
    {
        return (None, vec![]);
    }
    let mut best: Option<Name> = None;
    for r in &resp.authorities {
        if r.class != DnsClass::IN {
            continue;
        }
        if let RData::Ns(_) = &r.rdata {
            if is_within(qname, &r.name)
                && best
                    .as_ref()
                    .is_none_or(|b| r.name.num_labels() > b.num_labels())
            {
                best = Some(r.name.clone());
            }
        }
    }
    let zone = match best {
        Some(z) => z,
        None => return (None, vec![]),
    };
    let ns: Vec<Name> = resp
        .authorities
        .iter()
        .filter_map(|r| match &r.rdata {
            RData::Ns(n) if r.class == DnsClass::IN && r.name.eq_ignore_case(&zone) => {
                Some(n.clone())
            }
            _ => None,
        })
        .collect();
    (Some(zone), ns)
}

/**
 * @brief 최소화 질의에 온 권한 있는 NS 답이 현재 영역 아래의 경계를 드러내는지.
 * @details 부모와 자식 영역을 같은 서버가 맡으면 서버는 자식 영역으로 답하므로, 경계의 NS가
 *          참조의 권한 절이 아니라 답변 절에 온다. RFC 9156은 이 답도 경계로 다룬다. 따라가지
 *          않으면 현재 영역을 부모로 잘못 알아, 자식 영역의 SOA가 붙은 부정 응답을 무관한
 *          것으로 버린다.
 * @note 물은 이름이 현재 영역보다 깊어야 한다. 현재 영역의 꼭대기 NS는 경계가 아니다.
 * @return 경계면 그 영역의 네임서버 이름들.
 */
fn answer_zone_cut(resp: &Message, plan: &NextQuery, zone: &Name) -> Option<Vec<Name>> {
    if plan.is_final
        || plan.mtype != RecordType::NS
        || resp.header.rcode != ResponseCode::NoError.0
        || !resp.header.authoritative
        || !is_closer(&plan.mname, zone)
    {
        return None;
    }
    let ns: Vec<Name> = resp
        .answers
        .iter()
        .filter_map(|record| match &record.rdata {
            RData::Ns(target)
                if record.class == DnsClass::IN && record.name.eq_ignore_case(&plan.mname) =>
            {
                Some(target.clone())
            }
            _ => None,
        })
        .collect();
    (!ns.is_empty()).then_some(ns)
}

/** @brief 이 서버가 물은 이름과 타입에 대한 답이 실제로 있는지. */
fn has_direct_qtype_answer(resp: &Message, qname: &Name, qtype: RecordType) -> bool {
    resp.answers.iter().any(|record| {
        record.class == DnsClass::IN
            && record.name.eq_ignore_case(qname)
            && (qtype == RecordType::ANY || record.rtype == qtype)
    })
}

/** @brief DNAME 합성 이름이 길이 상한을 넘어 YXDOMAIN이 된 경우인지. 이것도 최종 응답이다. */
fn is_dname_yxdomain(resp: &Message, qname: &Name) -> bool {
    resp.header.rcode == ResponseCode::YXDomain.0
        && resp.header.authoritative
        && resp.answers.iter().any(|record| {
            record.class == DnsClass::IN
                && matches!(record.rdata, RData::Dname(_))
                && record.name.num_labels() < qname.num_labels()
                && qname
                    .suffix(record.name.num_labels())
                    .eq_ignore_case(&record.name)
        })
}

/** @brief 이 zone에서 온 SOA가 권한 절에 있는지. 부정 응답의 근거가 된다. */
fn has_relevant_soa(resp: &Message, qname: &Name, zone: &Name) -> bool {
    is_within(qname, zone)
        && resp.authorities.iter().any(|record| {
            record.rtype == RecordType::SOA
                && record.class == DnsClass::IN
                && record.name.eq_ignore_case(zone)
        })
}

/** @brief 이 서버의 질의 이름에 대한 별칭이 답변에 있는지. */
fn has_relevant_alias(resp: &Message, qname: &Name) -> bool {
    cname_target(resp, qname).is_some() || dname_rewrite(resp, qname).is_some()
}

/** @brief 이 응답이 이 서버의 질의에 대한 쓸 만한 긍정 답인지. */
fn is_relevant_positive(resp: &Message, qname: &Name, qtype: RecordType) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && resp.header.authoritative
        && cname_owner_is_valid(resp, qname)
        && (has_direct_qtype_answer(resp, qname, qtype) || has_relevant_alias(resp, qname))
}

/**
 * @brief 이 NXDOMAIN을 믿어도 되는지.
 * @warning 권한 비트와 zone 관련성을 함께 본다. 무관한 서버의 NXDOMAIN을 그대로 받으면
 *          아무나 임의의 이름을 지울 수 있다.
 */
fn is_authoritative_negative(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.authoritative && has_relevant_soa(resp, qname, zone)
}

/**
 * @brief 권한 서버가 답도 SOA도 위임도 없이 비워 보낸 NOERROR인지.
 * @details RFC 2308은 이 모양도 NODATA의 한 형태로 열거한다. 지역 부하 분산용 권한 서버가
 *          A에만 별칭을 주고 다른 유형에는 이렇게 답하는 일이 흔해서, 받지 않으면 영역의 모든
 *          서버가 실패로 보여 SERVFAIL이 된다. SOA가 없으니 부정 캐시 기한이 없고, 담지 않는 일은
 *          캐시 계층이 맡는다. 서명된 영역이면 부재 증명 검증이 SOA를 요구하므로 bogus가 된다.
 */
fn is_bare_authoritative_nodata(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && resp.header.authoritative
        && is_within(qname, zone)
        && resp.answers.is_empty()
        && !resp
            .authorities
            .iter()
            .any(|record| matches!(record.rtype, RecordType::NS | RecordType::SOA))
}

/** @brief 이 응답 코드면 다른 서버에 다시 물어볼 만한지. */
fn retryable_rcode(rcode: u16) -> bool {
    matches!(
        rcode,
        code if code == ResponseCode::FormErr.0
            || code == ResponseCode::ServFail.0
            || code == ResponseCode::NotImp.0
            || code == ResponseCode::Refused.0
    )
}

/**
 * @brief 이 응답으로 반복을 이어 갈 수 있는지.
 * @details 트랜잭션 ID와 질문이 이 서버가 보낸 것과 맞아야 하고, 응답 코드도 쓸 수 있는
 *          것이어야 한다. 하나라도 어긋나면 다음 서버로 넘어간다.
 */
fn response_usable_for_iteration(resp: &Message, query: &Message, zone: &Name) -> bool {
    let Some(question) = query.questions.first() else {
        return false;
    };
    if retryable_rcode(resp.header.rcode) {
        return false;
    }
    match resp.header.rcode {
        code if code == ResponseCode::NoError.0 => {
            is_relevant_positive(resp, &question.name, question.qtype)
                || is_authoritative_negative(resp, &question.name, zone)
                || is_bare_authoritative_nodata(resp, &question.name, zone)
                || extract_referral(resp, &question.name)
                    .0
                    .is_some_and(|child| is_closer(&child, zone))
        }
        code if code == ResponseCode::NXDomain.0 => {
            is_authoritative_negative(resp, &question.name, zone)
        }

        code if code == ResponseCode::YXDomain.0 => is_dname_yxdomain(resp, &question.name),
        _ => false,
    }
}

/** @brief 답변은 없지만 이것으로 끝나는 응답인지. NODATA가 여기 해당한다. */
fn is_terminal_response(resp: &Message, qname: &Name, zone: &Name) -> bool {
    resp.header.rcode == ResponseCode::NoError.0
        && (is_authoritative_negative(resp, qname, zone)
            || is_bare_authoritative_nodata(resp, qname, zone))
}

/**
 * @brief 최종 응답에서 이 서버가 보증하지 않는 레코드를 걷어낸다.
 * @warning 업스트림이 끼워 넣은 무관한 레코드를 그대로 흘리면 캐시 오염이 된다. 질의 이름과
 *          zone에 관계있는 것만 남긴다.
 */
fn sanitize_terminal_response(
    response: &mut Message,
    qname: &Name,
    qtype: RecordType,
    positive: bool,
    proof_zone: Option<&Name>,
) {
    if positive {
        response.answers.retain(|record| {
            if record.class != DnsClass::IN || !record.name.eq_ignore_case(qname) {
                return false;
            }

            qtype == RecordType::ANY
                || record.rtype == qtype
                || record.rtype == RecordType::RRSIG
                    && onetdns_dnssec::Rrsig::from_record(record)
                        .is_some_and(|signature| signature.type_covered == qtype.0)
        });
        response.authorities.clear();
    } else {
        response.answers.clear();
        response.authorities.retain(|record| {
            if record.class != DnsClass::IN {
                return false;
            }
            let Some(zone) = proof_zone else {
                return false;
            };
            if !is_within(&record.name, zone) {
                return false;
            }
            match record.rtype {
                RecordType::SOA => record.name.eq_ignore_case(zone),
                RecordType::NSEC | RecordType::NSEC3 => true,
                RecordType::RRSIG => {
                    onetdns_dnssec::Rrsig::from_record(record).is_some_and(|signature| {
                        let covered = RecordType(signature.type_covered);
                        matches!(covered, RecordType::NSEC | RecordType::NSEC3)
                            || covered == RecordType::SOA && record.name.eq_ignore_case(zone)
                    })
                }
                _ => false,
            }
        });
    }
    response
        .additionals
        .retain(|record| record.rtype == RecordType::OPT);
}

/** @brief 별칭 한 걸음. 따라갈 대상과 그 근거 레코드를 담는다. */
struct AliasHop {
    /** @brief 이 별칭이 가리키는 곳. */
    target: Name,
    /** @brief 이 별칭이 걸린 이름. */
    owner: Name,
    /** @brief 별칭의 종류. */
    atype: RecordType,

    /** @brief 이 단계에서 얻은 기록들. */
    records: Vec<Record>,
}

/** @brief 응답에서 따라가야 할 별칭을 찾는다. DNAME이 CNAME보다 우선한다. */
fn alias_hop(resp: &Message, qname: &Name, qtype: RecordType) -> Option<AliasHop> {
    if resp.header.rcode == ResponseCode::NXDomain.0 {
        return None;
    }
    if let Some((dname_record, target, synthetic_cname)) = dname_rewrite(resp, qname) {
        let owner = dname_record.name.clone();
        let mut records = alias_rrset_records(resp, &owner, RecordType::DNAME);
        records.push(synthetic_cname);
        return Some(AliasHop {
            target,
            owner,
            atype: RecordType::DNAME,
            records,
        });
    }
    if has_direct_qtype_answer(resp, qname, qtype) {
        return None;
    }
    let target = cname_target(resp, qname)?;
    Some(AliasHop {
        target,
        owner: qname.clone(),
        atype: RecordType::CNAME,
        records: alias_rrset_records(resp, qname, RecordType::CNAME),
    })
}

/** @brief 별칭 RRset과 그 서명을 함께 모은다. 검증에 둘 다 필요하다. */
fn alias_rrset_records(response: &Message, owner: &Name, alias_type: RecordType) -> Vec<Record> {
    response
        .answers
        .iter()
        .filter(|record| {
            record.name.eq_ignore_case(owner)
                && record.class == DnsClass::IN
                && (record.rtype == alias_type
                    || record.rtype == RecordType::RRSIG
                        && onetdns_dnssec::Rrsig::from_record(record)
                            .is_some_and(|signature| signature.type_covered == alias_type.0))
        })
        .cloned()
        .collect()
}

/** @brief 이 서버의 질의 이름에 대한 CNAME 대상. 소유자가 올바를 때만 준다. */
fn cname_target(resp: &Message, qname: &Name) -> Option<Name> {
    if !cname_owner_is_valid(resp, qname) {
        return None;
    }
    let mut target: Option<Name> = None;
    for record in &resp.answers {
        let RData::Cname(candidate) = &record.rdata else {
            continue;
        };
        if record.class != DnsClass::IN || !record.name.eq_ignore_case(qname) {
            continue;
        }
        if target
            .as_ref()
            .is_some_and(|current| !current.eq_ignore_case(candidate))
        {
            return None;
        }
        target = Some(candidate.clone());
    }
    target
}

/**
 * @brief 이 CNAME 소유자를 받아들일 수 있는지.
 * @note 같은 소유자에 서로 다른 CNAME이 있으면 거부한다. 어느 쪽을 따라갈지 정해지지 않는다.
 */
fn cname_owner_is_valid(resp: &Message, owner: &Name) -> bool {
    let has_cname = resp.answers.iter().any(|record| {
        record.class == DnsClass::IN
            && record.rtype == RecordType::CNAME
            && record.name.eq_ignore_case(owner)
    });
    if !has_cname {
        return true;
    }
    resp.answers.iter().all(|record| {
        record.class != DnsClass::IN
            || !record.name.eq_ignore_case(owner)
            || matches!(
                record.rtype,
                RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
            )
    })
}

/**
 * @brief 응답의 DNAME으로 이름을 다시 쓴다.
 * @details 소유자가 여럿이면 가장 긴 것이 이긴다. 짧은 것을 고르면 더 구체적인 규칙을
 *          건너뛰게 된다.
 */
fn dname_rewrite(resp: &Message, qname: &Name) -> Option<(Record, Name, Record)> {
    let mut best: Option<&Record> = None;
    for record in &resp.answers {
        if record.class != DnsClass::IN {
            continue;
        }
        let RData::Dname(_) = &record.rdata else {
            continue;
        };
        let owner_labels = record.name.num_labels();
        if qname.num_labels() <= owner_labels
            || !qname.suffix(owner_labels).eq_ignore_case(&record.name)
        {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| current.name.num_labels() < owner_labels)
        {
            best = Some(record);
        }
    }
    let record = best?;
    let RData::Dname(target_suffix) = &record.rdata else {
        return None;
    };
    if resp.answers.iter().any(|candidate| {
        candidate.class == DnsClass::IN
            && candidate.name.eq_ignore_case(&record.name)
            && matches!(
                &candidate.rdata,
                RData::Dname(other) if !other.eq_ignore_case(target_suffix)
            )
    }) {
        return None;
    }
    let prefix_len = qname.num_labels() - record.name.num_labels();
    let mut labels: Vec<Vec<u8>> = qname
        .labels()
        .take(prefix_len)
        .map(<[u8]>::to_vec)
        .collect();
    labels.extend(target_suffix.labels().map(<[u8]>::to_vec));
    let target = Name::from_labels(labels).ok()?;
    let synthetic = Record::new(qname.clone(), record.ttl, RData::Cname(target.clone()));
    Some((record.clone(), target, synthetic))
}

/** @brief 내장 루트 서버 목록. */
pub fn default_roots() -> Vec<SocketAddr> {
    [
        [198, 41, 0, 4],
        [199, 9, 14, 201],
        [192, 33, 4, 12],
        [199, 7, 91, 13],
        [192, 203, 230, 10],
        [192, 5, 5, 241],
        [192, 112, 36, 4],
        [198, 97, 190, 53],
        [192, 36, 148, 17],
        [192, 58, 128, 30],
        [193, 0, 14, 129],
        [199, 7, 83, 42],
        [202, 12, 27, 33],
    ]
    .into_iter()
    .map(|octets| SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), 53))
    .collect()
}

#[cfg(unix)]
/** @brief 이벤트 구동 해석 레인. 동기 경로와 같은 판정을 내되 스레드를 붙잡지 않는다. */
pub mod reactor;

#[cfg(all(test, unix))]
#[path = "reactor_probe.rs"]
/** @brief 레인의 수명과 자원 사용을 측정하는 테스트 전용 프로브. */
mod reactor_probe;

#[cfg(all(test, target_os = "linux", target_env = "musl"))]
#[global_allocator]
/** @brief 프로브가 할당을 관찰할 수 있도록 테스트 빌드에서만 교체하는 전역 할당기. */
static PROBE_ALLOC: onetdns_core::talloc::ThreadCachedSystem =
    onetdns_core::talloc::ThreadCachedSystem;

#[cfg(test)]
/** @brief bailiwick 판정, 캐시 수명, DNSSEC 검증, 그리고 이벤트 레인과 동기 경로의 동치성. */
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::{Arc, Mutex};

    /** @brief 이름 문자열의 정규 키. */
    fn name_key(name: &str) -> Vec<u8> {
        Name::from_str(name).unwrap().canonical_key()
    }

    #[test]
    /** @brief 와일드카드 확장에 부재 증명이 없으면 Secure로 보지 않는다. 없으면 더 구체적인 이름을 숨길 수 있다. */
    fn wildcard_expansion_requires_authenticated_denial_proof() {
        use onetdns_dnssec::sign::{pick_denial_nsecs, sign_zone, ZoneSigner};

        let apex = Name::from_str("example.test").unwrap();
        let wildcard = Name::from_str("*.wild.example.test").unwrap();
        let qname = Name::from_str("host.wild.example.test").unwrap();
        let signer = ZoneSigner::generate(apex.clone(), [44u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(
            &[Record::new(
                wildcard,
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, 44)),
            )],
            &signer,
            now,
        );
        let nsecs: Vec<Record> = signed
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        let proof = pick_denial_nsecs(&nsecs, &qname, true);
        let mut response = Message::default();
        for nsec in proof {
            response.authorities.push(nsec.clone());
            response.authorities.extend(
                signed
                    .iter()
                    .filter(|record| {
                        record.rtype == RecordType::RRSIG
                            && record.name.eq_ignore_case(&nsec.name)
                            && onetdns_dnssec::Rrsig::from_record(record).is_some_and(|signature| {
                                signature.type_covered == RecordType::NSEC.0
                            })
                    })
                    .cloned(),
            );
        }

        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(validated_wildcard_expansion(
            &response,
            &qname,
            3,
            WildcardValidation {
                keys: &[signer.dnskey()],
                apex: &apex,
                now: now as u32,
                nsec3_max_iterations: 0,
                verification_budget: &mut budget,
            },
        ));

        let (signing_key, dnskey) = ecdsa_key(44);
        let proof_records: Vec<Record> = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .cloned()
            .collect();
        response
            .authorities
            .retain(|record| record.rtype != RecordType::RRSIG);
        for proof in proof_records {
            response.authorities.push(rrsig_rec(
                &signing_key,
                &dnskey,
                ".",
                RecordType::NSEC.0,
                std::slice::from_ref(&proof),
            ));
        }
        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(
            !validated_wildcard_expansion(
                &response,
                &qname,
                3,
                WildcardValidation {
                    keys: &[dnskey],
                    apex: &apex,
                    now: now as u32,
                    nsec3_max_iterations: 0,
                    verification_budget: &mut budget,
                },
            ),
            "유효한 키로 서명했어도 NSEC signer가 leaf apex와 다르면 거부"
        );

        response.authorities.clear();
        let mut budget = onetdns_dnssec::VerificationBudget::new();
        assert!(!validated_wildcard_expansion(
            &response,
            &qname,
            3,
            WildcardValidation {
                keys: &[signer.dnskey()],
                apex: &apex,
                now: now as u32,
                nsec3_max_iterations: 0,
                verification_budget: &mut budget,
            },
        ));
    }

    #[test]
    /** @brief 네임서버 주소가 만료 전까지 재사용되고 그 뒤에는 버려지는지. */
    fn ns_addr_cache_reuses_until_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));

        let active = name_key("ns1.azure-dns.net.");
        rec.ns_addr_store(active.clone(), vec![ip], 300);
        assert_eq!(rec.ns_addr_cached(&active), Some(vec![ip]));

        {
            let mut cache = rec.ns_addr_cache.lock_recover();
            cache.put(
                name_key("stale.azure-dns.net."),
                NsAddrEntry {
                    addrs: vec![ip],
                    lifetime: TtlLifetime::expired(),
                },
            );
        }
        let stale = name_key("stale.azure-dns.net.");
        assert_eq!(rec.ns_addr_cached(&stale), None);
        assert!(!rec.ns_addr_cache.lock_recover().contains_key(&stale));
    }

    #[test]
    /** @brief 캐시 키가 이름의 원본 옥텟을 보존하는지. 문자열로 왕복하면 비ASCII 라벨이 깨진다. */
    fn recursive_cache_keys_preserve_raw_name_octets() {
        let first = Name::from_labels(vec![vec![0xff]]).unwrap();
        let second = Name::from_labels(vec![vec![0xfe]]).unwrap();
        assert_ne!(first.canonical_key(), second.canonical_key());
        assert_eq!(
            Name::from_str("WWW.example").unwrap().canonical_key(),
            Name::from_str("www.EXAMPLE").unwrap().canonical_key()
        );

        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        rec.ns_addr_store(first.canonical_key(), vec![first_ip], 300);
        rec.ns_addr_store(second.canonical_key(), vec![second_ip], 300);
        assert_eq!(
            rec.ns_addr_cached(&first.canonical_key()),
            Some(vec![first_ip])
        );
        assert_eq!(
            rec.ns_addr_cached(&second.canonical_key()),
            Some(vec![second_ip])
        );

        rec.deleg_store(&first, &[SocketAddr::new(first_ip, 53)], 300);
        rec.deleg_store(&second, &[SocketAddr::new(second_ip, 53)], 300);
        assert_eq!(
            rec.deleg_cached(&first),
            Some(vec![SocketAddr::new(first_ip, 53)])
        );
        assert_eq!(
            rec.deleg_cached(&second),
            Some(vec![SocketAddr::new(second_ip, 53)])
        );
        assert_ne!(
            InfraKey::new(first_ip, &first),
            InfraKey::new(first_ip, &second)
        );
    }

    #[test]
    /** @brief TTL 0은 담지 않고, 거대한 항목은 개수 상한에 걸리는지. */
    fn zero_ttl_ns_state_is_not_cached_and_large_entries_are_bounded() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone = Name::from_str("example").unwrap();
        let addresses: Vec<IpAddr> = (0..100)
            .map(|n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
            .collect();
        let servers: Vec<SocketAddr> = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, 53))
            .collect();

        let zero = name_key("ns.zero.example");
        rec.ns_addr_store(zero.clone(), addresses.clone(), 0);
        rec.deleg_store(&zone, &servers, 0);
        assert!(rec.ns_addr_cached(&zero).is_none());
        assert!(rec.deleg_cached(&zone).is_none());

        let large = name_key("ns.large.example");
        rec.ns_addr_store(large.clone(), addresses, 300);
        rec.deleg_store(&zone, &servers, 300);
        assert_eq!(
            rec.ns_addr_cached(&large).unwrap().len(),
            MAX_CACHED_NS_ADDRS
        );
        assert_eq!(rec.deleg_cached(&zone).unwrap().len(), MAX_CACHED_NS_ADDRS);
    }

    #[test]
    /** @brief 캐시가 권한 서버가 준 TTL보다 오래 살지 않는지. */
    fn recursive_ns_state_never_outlives_authoritative_ttl() {
        assert_eq!(std::mem::size_of::<TtlLifetime>(), 8);
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone = Name::from_str("example").unwrap();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let key = name_key("ns.short.example");

        rec.ns_addr_store(key.clone(), vec![address], 1);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 1);

        let ns_remaining = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        let deleg_remaining = rec
            .deleg_cache
            .lock_recover()
            .peek(&zone.canonical_key())
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        assert!(ns_remaining <= Duration::from_secs(1), "{ns_remaining:?}");
        assert!(
            deleg_remaining <= Duration::from_secs(1),
            "{deleg_remaining:?}"
        );

        rec.ns_addr_store(key.clone(), vec![address], 86_400);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 86_400);
        let ns_remaining = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        let deleg_remaining = rec
            .deleg_cache
            .lock_recover()
            .peek(&zone.canonical_key())
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap();
        assert!(
            ns_remaining > Duration::from_secs(3_600)
                && ns_remaining <= Duration::from_secs(86_400),
            "{ns_remaining:?}"
        );
        assert!(
            deleg_remaining > Duration::from_secs(3_600)
                && deleg_remaining <= Duration::from_secs(86_400),
            "{deleg_remaining:?}"
        );

        rec.ns_addr_store(key.clone(), vec![address], u32::MAX);
        let full_dns_ttl = rec
            .ns_addr_cache
            .lock_recover()
            .peek(&key)
            .unwrap()
            .lifetime
            .remaining(cache_now_millis())
            .unwrap()
            .as_secs();
        assert!(
            full_dns_ttl >= u64::from(u32::MAX) - 1,
            "전체 u32 TTL 범위를 미래 Instant 덧셈 없이 보존해야 함: {full_dns_ttl}"
        );
    }

    #[test]
    /** @brief 설정한 TTL 상한이 모든 캐시에 함께 걸리는지. */
    fn configured_max_ttl_bounds_every_recursive_cache() {
        assert_eq!(
            Recursor::new(vec![], Duration::from_secs(1))
                .with_recursive_cache_ttl_max(0)
                .recursive_cache_ttl_max,
            0
        );
        assert_eq!(
            Recursor::new(vec![], Duration::from_secs(1))
                .with_recursive_cache_ttl_max(u32::MAX)
                .recursive_cache_ttl_max,
            u32::MAX
        );

        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_recursive_cache_ttl_max(5);
        let zone = Name::from_str("example").unwrap();
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let key = name_key("ns.configured.example");

        rec.ns_addr_store(key.clone(), vec![address], 300);
        rec.deleg_store(&zone, &[SocketAddr::new(address, 53)], 300);
        rec.dnskey_store(key.clone(), vec![], vec![], 300);

        let now = cache_now_millis();
        let configured_max = Duration::from_secs(5);
        assert!(
            rec.ns_addr_cache
                .lock_recover()
                .peek(&key)
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
        assert!(
            rec.deleg_cache
                .lock_recover()
                .peek(&zone.canonical_key())
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
        assert!(
            rec.dnskey_cache
                .lock_recover()
                .peek(&key)
                .unwrap()
                .lifetime
                .remaining(now)
                .unwrap()
                <= configured_max
        );
    }

    #[test]
    /** @brief 앵커가 바뀌면 검증된 키 캐시가 따라서 무효가 되는지. */
    fn validated_key_cache_expires_and_follows_anchor_rotation() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let key = name_key("example");
        let anchors = std::sync::Arc::new(Vec::new());

        rec.validated_keys_store(
            key.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            0,
        );
        assert!(rec.validated_keys_cached(&key, &anchors).is_none());

        rec.validated_keys_store(
            key.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&key, &anchors).is_some());

        let rotated = std::sync::Arc::new(Vec::new());
        assert!(rec.validated_keys_cached(&key, &rotated).is_none());

        assert!(rec.validated_keys_cached(&key, &anchors).is_none());
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 검증해 둔 키를 다시 쓰는 비용. */
    fn bench_validated_key_cache_hit() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let zone_key = name_key("bench.example");
        let anchors = rec.trust_anchors.load();
        let keys: Vec<onetdns_dnssec::Dnskey> = (0..2)
            .map(|seed| onetdns_dnssec::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![seed; 64],
            })
            .collect();
        rec.validated_keys_store(
            zone_key.clone(),
            ZoneTrust::Secure(keys.into()),
            anchors.clone(),
            300,
        );

        /** @brief 반복 횟수. */
        const HITS: u32 = 1_000_000;
        let started = Instant::now();
        for _ in 0..HITS {
            std::hint::black_box(
                rec.validated_keys_cached(&zone_key, &anchors)
                    .expect("cache hit"),
            );
        }
        let elapsed = started.elapsed();
        println!(
            "validated-key-cache-hit: {:.1} ns/hit ({HITS} hits in {elapsed:?})",
            elapsed.as_nanos() as f64 / f64::from(HITS)
        );
    }

    #[test]
    /** @brief DNSKEY 캐시가 TTL 0과 만료를 지키는지. */
    fn dnskey_cache_honors_zero_ttl_and_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let key = name_key("example");
        let records = vec![Record::new(
            Name::from_str("example").unwrap(),
            300,
            RData::Unknown(RecordType::DNSKEY.0, vec![1, 2, 3]),
        )];
        let signatures = vec![onetdns_dnssec::Rrsig {
            type_covered: RecordType::DNSKEY.0,
            algorithm: 13,
            labels: 1,
            original_ttl: 300,
            expiration: now_secs().wrapping_add(300),
            inception: now_secs().wrapping_sub(60),
            key_tag: 1,
            signer: Name::from_str("example").unwrap(),
            signature: vec![0; 64],
        }];

        rec.dnskey_store(key.clone(), records.clone(), signatures.clone(), 0);
        assert!(rec.dnskey_cached(&key).is_none());

        rec.dnskey_store(key.clone(), records, signatures, 300);
        assert!(rec.dnskey_cached(&key).is_some());
        rec.dnskey_cache.lock_recover().put(
            key.clone(),
            DnskeyEntry {
                records: vec![],
                signatures: vec![],
                lifetime: TtlLifetime::expired(),
            },
        );
        assert!(rec.dnskey_cached(&key).is_none());
    }

    #[test]
    /** @brief DS 서명 만료가 검증 결과의 캐시 기간을 묶는지. 만료 뒤에도 쓰면 폐기된 키를 믿게 된다. */
    fn ds_rrsig_ttl_bounds_validated_key_cache_lifetime() {
        let child = Name::from_str("child.example").unwrap();
        let ds = onetdns_dnssec::Ds {
            key_tag: 1234,
            algorithm: 13,
            digest_type: 2,
            digest: vec![7; 32],
        };
        let ds_record = Record::new(
            child.clone(),
            300,
            RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
        );
        let signature = onetdns_dnssec::Rrsig {
            type_covered: RecordType::DS.0,
            algorithm: 13,
            labels: child.num_labels() as u8,
            original_ttl: 300,
            expiration: now_secs().wrapping_add(300),
            inception: now_secs().wrapping_sub(1),
            key_tag: 5678,
            signer: Name::from_str("example").unwrap(),
            signature: vec![9; 64],
        };
        let signature_record = Record::new(
            child.clone(),
            7,
            RData::Unknown(RecordType::RRSIG.0, signature.rdata_bytes()),
        );
        let mut response = Message::default();
        response.authorities = vec![ds_record, signature_record];

        let (ds_records, ds_rrsigs, _, _, _, _, parsed_ds) =
            extract_ds(&response.authorities, &child);
        assert_eq!(ds_records[0].ttl, 7);
        assert_eq!(ds_rrsigs.len(), 1);
        assert_eq!(parsed_ds, vec![ds]);

        let link = onetdns_dnssec::ChainLink {
            zone: child,
            dnskeys: vec![],
            dnskey_rrsigs: vec![],
            ds_records,
            ds_rrsigs,
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: parsed_ds,
        };
        assert_eq!(chain_validity_ttl(&[link], now_secs()), 7);
    }

    #[test]
    /** @brief 참조의 부재 서명을 레코드마다 다시 훑고 중복 복제하지 않는지. */
    fn extract_ds_parses_each_denial_signature_once() {
        let (signing_key, key) = ecdsa_key(93);
        let child = Name::from_str("child.example").unwrap();
        let nsec = nsec_rec(
            "child.example",
            "z.example",
            &[RecordType::NS.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        let signature = rrsig_rec(
            &signing_key,
            &key,
            "example",
            RecordType::NSEC.0,
            std::slice::from_ref(&nsec),
        );
        let mut response = Message::default();
        response.authorities = vec![nsec.clone(), nsec, signature];

        let (_, _, nsecs, nsec_sigs, _, _, _) = extract_ds(&response.authorities, &child);
        assert_eq!(nsecs.len(), 2, "입력 RR은 손실 없이 보존한다");
        assert_eq!(
            nsec_sigs.len(),
            1,
            "같은 owner의 NSEC가 중복돼도 RRSIG 한 개를 제곱 복제하면 안 된다"
        );
    }

    #[test]
    /** @brief 가장 깊은 위임을 고르고, 경로 삭제와 만료가 제대로 도는지. */
    fn delegation_cache_deepest_evict_and_expiry() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let com = Name::from_str("com").unwrap();
        let ms = Name::from_str("microsoft.com").unwrap();
        let com_srv = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)),
            53,
        )];
        let ms_srv = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(13, 107, 222, 41)),
            53,
        )];
        rec.deleg_store(&com, &com_srv, 3600);
        rec.deleg_store(&ms, &ms_srv, 3600);

        let q = Name::from_str("eu-mobile.events.data.microsoft.com").unwrap();
        let (zone, servers) = rec
            .deepest_cached_delegation(&q)
            .expect("cached delegation");
        assert_eq!(zone.to_ascii_lower(), "microsoft.com");
        assert_eq!(servers, ms_srv);

        rec.deleg_evict_path(&q);
        assert!(rec.deepest_cached_delegation(&q).is_none());

        {
            let mut cache = rec.deleg_cache.lock_recover();
            cache.put(
                com.canonical_key(),
                DelegationEntry {
                    servers: com_srv.clone(),
                    lifetime: TtlLifetime::expired(),
                },
            );
        }
        assert!(rec.deleg_cached(&com).is_none());
    }

    #[test]
    /** @brief 캐시 크기가 설정대로 정확히 지켜지는지. */
    fn recursive_state_caches_enforce_exact_lru_capacity() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_ns_cache_max(2);

        let ns1 = name_key("ns1.test");
        let ns2 = name_key("ns2.test");
        rec.ns_addr_store(ns1.clone(), vec![ip1], 300);
        rec.ns_addr_store(ns2.clone(), vec![ip2], 300);
        assert_eq!(rec.ns_addr_cached(&ns1), Some(vec![ip1]));
        rec.ns_addr_store(name_key("ns3.test"), vec![ip1], 300);
        assert!(rec.ns_addr_cached(&ns2).is_none());
        assert_eq!(rec.ns_addr_cache.lock_recover().len(), 2);

        let a = Name::from_str("a.test").unwrap();
        let b = Name::from_str("b.test").unwrap();
        let c = Name::from_str("c.test").unwrap();
        let server = [SocketAddr::new(ip1, 53)];
        rec.deleg_store(&a, &server, 300);
        rec.deleg_store(&b, &server, 300);
        assert!(rec.deleg_cached(&a).is_some());
        rec.deleg_store(&c, &server, 300);
        assert!(rec.deleg_cached(&b).is_none());
        assert_eq!(rec.deleg_cache.lock_recover().len(), 2);

        rec.infra_fail(ip1, &a);
        rec.infra_fail(ip1, &b);
        rec.infra_protocol_error(ip1, &a);
        rec.infra_fail(ip1, &c);
        let infra = rec.infra.lock_recover();
        assert!(infra.peek(&InfraKey::new(ip1, &a)).is_some());
        assert!(infra.peek(&InfraKey::new(ip1, &b)).is_none());
        assert!(infra.peek(&InfraKey::new(ip1, &c)).is_some());
        assert_eq!(infra.len(), 2);
        drop(infra);

        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        rec.record_rtt(ip1, Duration::from_millis(10));
        rec.record_rtt(ip2, Duration::from_millis(10));
        rec.record_rtt(ip3, Duration::from_millis(10));
        assert!(rec.srtt(ip1).is_none());
        assert_eq!(rec.rtt.lock_recover().len(), 2);

        let key1 = name_key("key1.test");
        let key2 = name_key("key2.test");
        rec.dnskey_store(key1.clone(), vec![], vec![], 300);
        rec.dnskey_store(key2.clone(), vec![], vec![], 300);
        assert!(rec.dnskey_cached(&key1).is_some());
        rec.dnskey_store(name_key("key3.test"), vec![], vec![], 300);
        assert!(rec.dnskey_cached(&key2).is_none());
        assert_eq!(rec.dnskey_cache.lock_recover().len(), 2);

        let anchors = rec.trust_anchors.load();
        let validated1 = name_key("validated1.test");
        let validated2 = name_key("validated2.test");
        rec.validated_keys_store(
            validated1.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        rec.validated_keys_store(
            validated2.clone(),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&validated1, &anchors).is_some());
        rec.validated_keys_store(
            name_key("validated3.test"),
            ZoneTrust::Secure(Vec::new().into()),
            anchors.clone(),
            300,
        );
        assert!(rec.validated_keys_cached(&validated2, &anchors).is_none());
        assert_eq!(rec.validated_keys.lock_recover().len(), 2);
    }

    #[test]
    /** @brief IN 클래스가 아닌 레코드가 답변·참조·glue 어디에도 끼어들지 못하는지. */
    fn non_in_records_cannot_drive_answers_referrals_or_glue() {
        let qname = Name::from_str("host.test").unwrap();
        let mut response = Message::query(1, qname.clone(), RecordType::A);
        response.header.response = true;
        response.header.authoritative = true;

        let mut answer = Record::new(qname.clone(), 300, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
        answer.class = DnsClass(3);
        response.answers.push(answer);
        assert!(!has_direct_qtype_answer(&response, &qname, RecordType::A));

        response.answers.clear();
        response.header.authoritative = false;
        let zone = Name::from_str("test").unwrap();
        let ns = Name::from_str("ns.test").unwrap();
        let mut referral = Record::new(zone.clone(), 300, RData::Ns(ns.clone()));
        referral.class = DnsClass(3);
        response.authorities.push(referral);
        let mut glue = Record::new(ns.clone(), 300, RData::A(Ipv4Addr::new(192, 0, 2, 53)));
        glue.class = DnsClass(3);
        response.additionals.push(glue);
        assert!(extract_referral(&response, &qname).0.is_none());

        let rec = Recursor::new(vec![], Duration::from_secs(1));
        assert!(rec.glue_addrs(&response, &[ns], &zone).0.is_empty());
    }

    #[test]
    /** @brief ANY 질의에 온 보통의 RRset 응답을 받아들이는지. */
    fn any_query_accepts_normal_rrset_response() {
        let qname = Name::from_str("host.test").unwrap();
        let zone = Name::from_str("test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::ANY);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Aaaa("2001:db8::1".parse().unwrap()),
        ));

        assert!(
            has_direct_qtype_answer(&resp, &qname, RecordType::ANY),
            "A/AAAA를 가진 ANY 응답은 직접 답변이어야 한다"
        );
        assert!(is_relevant_positive(&resp, &qname, RecordType::ANY));
        let req = Message::query(1, qname.clone(), RecordType::ANY);
        assert!(response_usable_for_iteration(&resp, &req, &zone));

        let mut out = resp.clone();
        sanitize_terminal_response(&mut out, &qname, RecordType::ANY, true, None);
        assert_eq!(
            out.answers.len(),
            2,
            "ANY 응답의 A·AAAA RRset이 유지되어야 한다"
        );
    }

    #[test]
    /**
     * @brief 권한 서버가 SOA 없이 비워 보낸 NOERROR를 NODATA로 받는지.
     * @details 받지 않으면 다음 서버로 넘어가고, 모든 서버가 같은 답을 주는 영역은 SERVFAIL이
     *          된다. 권한 비트가 없거나, 위임이 있거나, 영역 밖 이름이거나, 답이 섞여 있으면
     *          NODATA가 아니다.
     */
    fn bare_authoritative_nodata_is_terminal_and_usable() {
        let qname = Name::from_str("host.gslb.test").unwrap();
        let zone = Name::from_str("gslb.test").unwrap();
        let query = Message::query(1, qname.clone(), RecordType::AAAA);
        let mut resp = query.clone();
        resp.header.response = true;
        resp.header.authoritative = true;

        assert!(response_usable_for_iteration(&resp, &query, &zone));
        assert!(is_terminal_response(&resp, &qname, &zone));

        let mut not_authoritative = resp.clone();
        not_authoritative.header.authoritative = false;
        assert!(!response_usable_for_iteration(
            &not_authoritative,
            &query,
            &zone
        ));
        assert!(!is_terminal_response(&not_authoritative, &qname, &zone));

        let mut delegation = resp.clone();
        delegation.authorities.push(Record::new(
            qname.clone(),
            300,
            RData::Ns(Name::from_str("ns.host.gslb.test").unwrap()),
        ));
        assert!(!is_bare_authoritative_nodata(&delegation, &qname, &zone));
        assert!(!is_terminal_response(&delegation, &qname, &zone));

        let other_zone = Name::from_str("other.test").unwrap();
        assert!(!is_bare_authoritative_nodata(&resp, &qname, &other_zone));
        assert!(!is_terminal_response(&resp, &qname, &other_zone));

        let mut unrelated_answer = resp.clone();
        unrelated_answer.answers.push(Record::new(
            Name::from_str("elsewhere.gslb.test").unwrap(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        assert!(!is_terminal_response(&unrelated_answer, &qname, &zone));
    }

    #[test]
    /** @brief DNAME 합성이 길이를 넘긴 경우도 최종 응답으로 다루는지. */
    fn dname_yxdomain_is_terminal_and_usable() {
        let owner = Name::from_str("sub.test").unwrap();
        let qname = Name::from_str("x.sub.test").unwrap();
        let zone = Name::from_str("test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::A);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.header.rcode = ResponseCode::YXDomain.0;
        resp.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("target.example").unwrap()),
        ));

        assert!(is_dname_yxdomain(&resp, &qname));
        let req = Message::query(1, qname.clone(), RecordType::A);
        assert!(
            response_usable_for_iteration(&resp, &req, &zone),
            "권한적 YXDOMAIN은 재시도 대상이 아니라 usable해야 한다"
        );

        assert!(!is_dname_yxdomain(&resp, &owner));
    }

    #[test]
    /** @brief 질의 이름을 덮는 DNAME이 합성 CNAME보다 우선하는지. */
    fn dname_covering_qname_wins_over_synthetic_cname() {
        let owner = Name::from_str("sub.test").unwrap();
        let qname = Name::from_str("a.sub.test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::CNAME);
        resp.header.response = true;
        resp.header.authoritative = true;
        resp.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("dst.example").unwrap()),
        ));
        resp.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Cname(Name::from_str("a.dst.example").unwrap()),
        ));

        assert!(has_direct_qtype_answer(&resp, &qname, RecordType::CNAME));
        assert!(
            dname_rewrite(&resp, &qname).is_some(),
            "DNAME이 qname을 덮으면 별칭 경로(합성 CNAME보다 우선)를 타야 한다"
        );
    }

    #[test]
    /** @brief RRSIG를 직접 물으면 Insecure다. 서명을 서명으로 감싸지 않으므로 Bogus가 아니다. */
    fn rrsig_query_is_insecure_not_bogus() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        let qname = Name::from_str("host.test").unwrap();
        let mut resp = Message::query(1, qname.clone(), RecordType::RRSIG);
        resp.header.response = true;
        let status = rec.validate_answer_status(
            &qname,
            RecordType::RRSIG,
            &resp,
            &[],
            Instant::now() + Duration::from_secs(1),
        );
        assert!(
            matches!(status, SecurityStatus::Insecure),
            "qtype=RRSIG는 Insecure여야 한다(Bogus 아님): {status:?}"
        );
    }

    #[test]
    /** @brief NAT64 지역 사용 접두사를 전역 주소로 보지 않는지. IPv6로 감싼 내부 주소 우회를 막는다. */
    fn nat64_local_use_prefix_is_not_globally_routable() {
        assert!(
            !is_globally_routable("64:ff9b:1::808:808".parse().unwrap()),
            "64:ff9b:1::/48은 비라우팅이어야 한다"
        );

        assert!(is_globally_routable("64:ff9b::808:808".parse().unwrap()));
        assert!(
            !is_globally_routable("64:ff9b::a9fe:a9fe".parse().unwrap()),
            "64:ff9b::169.254.169.254는 특수라 거부"
        );
    }

    #[test]
    /** @brief DNAME 소유자가 여럿이면 가장 긴 것이 이기는지. */
    fn dname_rewrite_uses_longest_matching_owner() {
        let qname = Name::from_str("www.deep.old.example").unwrap();
        let mut response = Message::default();
        response.answers.push(Record::new(
            Name::from_str("old.example").unwrap(),
            300,
            RData::Dname(Name::from_str("broad.example.net").unwrap()),
        ));
        response.answers.push(Record::new(
            Name::from_str("deep.old.example").unwrap(),
            120,
            RData::Dname(Name::from_str("specific.example.net").unwrap()),
        ));

        let (source, target, synthetic) = dname_rewrite(&response, &qname).expect("DNAME rewrite");
        assert_eq!(source.name.to_ascii_lower(), "deep.old.example");
        assert_eq!(target.to_ascii_lower(), "www.specific.example.net");
        assert_eq!(synthetic.ttl, 120);
        assert!(matches!(
            synthetic.rdata,
            RData::Cname(ref name) if name.to_ascii_lower() == "www.specific.example.net"
        ));
    }

    #[test]
    /** @brief 현재 zone 밖 DNAME이 응답에서 걷어내지는지. */
    fn out_of_bailiwick_dname_is_stripped() {
        let zone = Name::from_str("sub.example.com").unwrap();
        let mut resp = Message::default();
        resp.answers.push(Record::new(
            Name::from_str("sub.example.com").unwrap(),
            300,
            RData::Dname(Name::from_str("ok.example.net").unwrap()),
        ));
        resp.answers.push(Record::new(
            Name::from_str("example.com").unwrap(),
            300,
            RData::Dname(Name::from_str("evil.example.net").unwrap()),
        ));
        resp.answers.push(Record::new(
            Name::from_str("host.sub.example.com").unwrap(),
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));

        strip_out_of_bailiwick_dnames(&mut resp, &zone);

        assert_eq!(resp.answers.len(), 2, "bailiwick 밖 DNAME 1건 제거");
        assert!(
            resp.answers
                .iter()
                .all(|r| !matches!(&r.rdata, RData::Dname(_)) || is_within(&r.name, &zone)),
            "남은 DNAME은 zone 이내여야 함"
        );
        assert!(
            resp.answers.iter().any(|r| matches!(&r.rdata, RData::A(_))),
            "비-DNAME 레코드는 유지"
        );
    }

    #[test]
    /** @brief 같은 이름에 서로 다른 별칭이 오면 답으로 받아들이지 않는지. */
    fn conflicting_alias_data_is_not_accepted_as_an_answer() {
        let qname = Name::from_str("www.example").unwrap();
        let zone = Name::from_str("example").unwrap();
        let query = Message::query(1, qname.clone(), RecordType::A);
        let mut response = query.clone();
        response.header.response = true;
        response.header.authoritative = true;
        response.answers.push(Record::new(
            qname.clone(),
            300,
            RData::Cname(Name::from_str("target.example").unwrap()),
        ));
        response.answers.push(Record::new(
            qname.clone(),
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));

        assert!(cname_target(&response, &qname).is_none());
        assert!(!is_relevant_positive(&response, &qname, RecordType::A));
        assert!(!response_usable_for_iteration(&response, &query, &zone));

        response.answers.clear();
        let owner = Name::from_str("example").unwrap();
        response.answers.push(Record::new(
            owner.clone(),
            300,
            RData::Dname(Name::from_str("one.example.net").unwrap()),
        ));
        response.answers.push(Record::new(
            owner,
            300,
            RData::Dname(Name::from_str("two.example.net").unwrap()),
        ));
        assert!(dname_rewrite(&response, &qname).is_none());
    }

    #[test]
    /** @brief 빠른 서버가 먼저, 실패한 서버가 뒤로 가는지. */
    fn infra_orders_fast_first_failed_last() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let fast: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let slow: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let dead: SocketAddr = "1.0.0.1:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        r.infra_success(fast.ip(), &zone, Duration::from_millis(5));
        r.infra_success(slow.ip(), &zone, Duration::from_millis(200));
        r.infra_fail(dead.ip(), &zone);

        assert_eq!(
            r.order_by_infra(&[dead, slow, fast], &zone),
            vec![fast, slow]
        );
    }

    #[test]
    /** @brief 주소 계열 필터와 선호가 순서에 반영되는지. */
    fn ip_family_filter_and_prefer() {
        let v4: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let servers = [v4, v6];
        let zone = Name::from_str("example").unwrap();

        let r = Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(true, false, None);
        assert_eq!(r.order_by_infra(&servers, &zone), vec![v4]);

        let r = Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(false, true, None);
        assert_eq!(r.order_by_infra(&servers, &zone), vec![v6]);

        let r =
            Recursor::new(vec![], Duration::from_millis(50)).with_ip_family(true, true, Some(true));
        assert_eq!(r.order_by_infra(&servers, &zone).first(), Some(&v6));
    }

    #[test]
    /** @brief 센티널 질의가 이 서버가 신뢰하는 앵커 상태를 그대로 드러내는지. */
    fn root_key_sentinel_rfc8509() {
        let r = Recursor::with_default_roots(Duration::from_millis(50)).with_dnssec();
        let mk = |qname: &str| {
            let mut m = Message::query(1, Name::from_str(qname).unwrap(), RecordType::A);
            m.header.authentic_data = true;
            m.answers.push(Record::new(
                Name::from_str(qname).unwrap(),
                60,
                RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            m
        };
        let apply = |q: &str| {
            let mut m = mk(q);
            r.apply_sentinel(&Name::from_str(q).unwrap(), RecordType::A, &mut m);
            m
        };

        let m = apply("root-key-sentinel-is-ta-20326.example.com");
        assert_eq!(m.header.rcode, ResponseCode::NoError.0);
        assert!(!m.answers.is_empty());

        assert_eq!(
            apply("root-key-sentinel-is-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::ServFail.0
        );

        assert_eq!(
            apply("root-key-sentinel-not-ta-20326.example.com")
                .header
                .rcode,
            ResponseCode::ServFail.0
        );

        assert_eq!(
            apply("root-key-sentinel-not-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::NoError.0
        );

        assert_eq!(
            apply("kskroll-sentinel-is-ta-00001.example.com")
                .header
                .rcode,
            ResponseCode::NoError.0,
            "초안의 라벨은 RFC 8509 센티널이 아니다"
        );
        assert_eq!(
            apply("root-key-sentinel-is-ta-1.example.com").header.rcode,
            ResponseCode::NoError.0,
            "key tag는 다섯 자리여야 한다"
        );

        let mut m = mk("root-key-sentinel-is-ta-00001.example.com");
        m.header.authentic_data = false;
        r.apply_sentinel(
            &Name::from_str("root-key-sentinel-is-ta-00001.example.com").unwrap(),
            RecordType::A,
            &mut m,
        );
        assert_eq!(m.header.rcode, ResponseCode::NoError.0);
    }

    #[test]
    /** @brief 검증 제외가 접미사 단위로 걸리는지. */
    fn domain_insecure_suffix_match() {
        let r = Recursor::new(vec![], Duration::from_millis(50))
            .with_domain_insecure(vec![Name::from_str("internal.example").unwrap()]);
        assert!(r.is_domain_insecure(&Name::from_str("host.internal.example").unwrap()));
        assert!(r.is_domain_insecure(&Name::from_str("internal.example").unwrap()));
        assert!(!r.is_domain_insecure(&Name::from_str("host.example").unwrap()));
    }

    #[test]
    /** @brief 성공하면 실패 냉각이 즉시 풀리는지. */
    fn infra_success_clears_fail_cooldown() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let ip: IpAddr = "8.8.4.4".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        let key = InfraKey::new(ip, &zone);
        let score = |r: &Recursor| {
            infra_score(
                r.infra.lock_recover().peek(&key),
                r.srtt(ip),
                Instant::now(),
            )
        };
        r.infra_fail(ip, &zone);
        assert!(score(&r) >= INFRA_FAIL_PENALTY_MS, "실패는 큰 점수");

        r.infra_success(ip, &zone, Duration::from_millis(10));
        assert!(score(&r) < 100, "성공 후 작은 점수");
    }

    #[test]
    /** @brief 실패한 서버가 냉각 동안 뒤로 밀렸다가 돌아오는지. */
    fn failed_servers_are_excluded_until_cooldown_expires() {
        let r = Recursor::new(vec![], Duration::from_millis(100));
        let failed: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let healthy: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();
        let key = InfraKey::new(failed.ip(), &zone);
        r.infra_fail(failed.ip(), &zone);
        assert_eq!(r.order_by_infra(&[failed, healthy], &zone), vec![healthy]);

        {
            let mut infra = r.infra.lock_recover();
            infra.get_mut(&key).unwrap().last_fail =
                Instant::now().checked_sub(INFRA_FAIL_COOLDOWN + Duration::from_secs(1));
        }
        let ordered = r.order_by_infra(&[failed, healthy], &zone);
        assert!(ordered.contains(&failed) && ordered.contains(&healthy));
    }

    #[test]
    /** @brief 정책으로 거부한 것을 전송 실패로 세지 않는지. 그러면 멀쩡한 서버가 냉각된다. */
    fn recursion_policy_rejection_is_not_reported_as_transport_failure() {
        let recursor = Recursor::new(vec![], Duration::from_millis(10));
        let blocked: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let zone = Name::root();
        let query = make_query(&Name::from_str("example").unwrap(), RecordType::A, false);

        assert!(matches!(
            recursor.query_any(&[blocked], &query, &zone, recursor.query_deadline()),
            Err(RecurseError::NoReachableNs)
        ));
    }

    #[test]
    /** @brief 부수 질의도 같은 데드라인을 지키는지. 새로 잡으면 해석 하나가 데드라인을 넘긴다. */
    fn authority_exchange_obeys_the_shared_resolution_deadline() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = blackhole.local_addr().unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(2))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let zone = Name::root();
        let query = make_query(&Name::from_str("example").unwrap(), RecordType::A, false);
        let started = Instant::now();

        assert!(matches!(
            recursor.query_any(
                &[server],
                &query,
                &zone,
                Instant::now() + Duration::from_millis(80)
            ),
            Err(RecurseError::NoResponse)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "전체 해석 마감시각이 서버별 2초 timeout보다 우선해야 함"
        );
    }

    #[test]
    /** @brief 프로토콜 오류를 전송 실패와 구분하는지. 응답은 온 서버다. */
    fn dns_protocol_error_does_not_open_transport_cooldown() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let zone = Name::from_str("example").unwrap();

        recursor.infra_protocol_error(server.ip(), &zone);
        assert_eq!(
            recursor.order_by_infra(&[server], &zone),
            vec![server],
            "SERVFAIL/REFUSED/lame response must remain a DNS response, not transport outage"
        );
    }

    #[test]
    /**
     * @brief 한 zone에서 잰 왕복 시간을 다른 zone에서도 쓰는지.
     * @details 부모와 자식 zone을 같은 서버가 맡는 일이 흔하다. 자식 zone에서 느리다고 잰
     *          서버를 부모 zone에서 처음 보는 서버로 치면, 부모 zone의 DNSKEY를 물을 때 그
     *          느린 서버에 가장 먼저 묻는다.
     */
    fn round_trip_time_is_shared_across_zones() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let slow: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let fresh: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let child = Name::from_str("ris.example").unwrap();
        let parent = Name::from_str("example").unwrap();

        recursor.infra_success(slow.ip(), &child, Duration::from_millis(800));
        assert_eq!(
            recursor.order_by_infra(&[slow, fresh], &parent),
            vec![fresh, slow]
        );
    }

    #[test]
    /** @brief 한 zone에서의 실패가 다른 zone의 순위를 건드리지 않는지. */
    fn infra_failure_is_scoped_to_zone() {
        let recursor = Recursor::new(vec![], Duration::from_millis(100));
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let failed_zone = Name::from_str("example").unwrap();
        let other_zone = Name::from_str("net").unwrap();

        let healthy: SocketAddr = "1.1.1.1:53".parse().unwrap();
        recursor.infra_fail(server.ip(), &failed_zone);

        assert_eq!(
            recursor.order_by_infra(&[server, healthy], &failed_zone),
            vec![healthy]
        );

        let other = recursor.order_by_infra(&[server, healthy], &other_zone);
        assert!(other.contains(&server) && other.contains(&healthy));
    }

    #[test]
    /** @brief 앵커를 넣으면 검증이 켜지는지. */
    fn with_dnssec_activates_validation() {
        let plain = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(!plain.validating(), "기본은 검증 비활성");
        let secure = Recursor::with_default_roots(Duration::from_secs(1)).with_dnssec();
        assert!(secure.validating(), "with_dnssec → 루트 앵커로 검증 활성");
        assert_eq!(secure.trust_anchors.load()[0].key_tag, 20326);
    }

    #[test]
    /** @brief 기본 설정이 내부망 주소로의 질의를 막는지. 이것이 SSRF 방어의 기본선이다. */
    fn ssrf_default_denies_internal_servers() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(
            !r.is_queryable("169.254.169.254".parse().unwrap()),
            "클라우드 메타데이터 거부"
        );
        assert!(!r.is_queryable("127.0.0.1".parse().unwrap()), "루프백 거부");
        assert!(!r.is_queryable("10.0.0.5".parse().unwrap()), "사설 거부");
        assert!(!r.is_queryable("192.168.1.1".parse().unwrap()), "사설 거부");
        assert!(!r.is_queryable("::1".parse().unwrap()), "v6 루프백 거부");
        assert!(!r.is_queryable("fd00::1".parse().unwrap()), "v6 ULA 거부");

        assert!(
            !r.is_queryable("::ffff:127.0.0.1".parse().unwrap()),
            "IPv4-mapped 루프백 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b::7f00:1".parse().unwrap()),
            "NAT64 well-known 루프백 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b::a00:1".parse().unwrap()),
            "NAT64 사설 거부"
        );
        assert!(
            !r.is_queryable("64:ff9b:1::a9fe:a9fe".parse().unwrap()),
            "NAT64 local-use 메타데이터 거부"
        );
        assert!(
            !r.is_queryable("2002:7f00:1::".parse().unwrap()),
            "6to4 루프백 거부"
        );
        assert!(
            !r.is_queryable("2002:a00:1::".parse().unwrap()),
            "6to4 사설 거부"
        );
        assert!(
            !r.is_queryable("::127.0.0.1".parse().unwrap()),
            "IPv4-compatible 루프백 거부"
        );
        assert!(
            !r.is_queryable("fec0::1".parse().unwrap()),
            "deprecated site-local 거부"
        );

        assert!(
            r.is_queryable("64:ff9b::808:808".parse().unwrap()),
            "NAT64로 매핑된 전역 8.8.8.8 허용"
        );
        assert!(
            r.is_queryable("2002:808:808::".parse().unwrap()),
            "6to4로 매핑된 전역 8.8.8.8 허용"
        );

        let alternate_port = Recursor::with_default_roots(Duration::from_secs(1)).with_port(5353);
        assert!(
            !alternate_port.is_queryable("127.0.0.1".parse().unwrap()),
            "권한 포트 변경이 루프백/SSRF ACL을 암묵적으로 해제하면 안 됨"
        );

        assert!(r.is_queryable("8.8.8.8".parse().unwrap()), "전역 허용");
        assert!(
            r.is_queryable("2001:4860:4860::8888".parse().unwrap()),
            "전역 v6 허용"
        );

        let r2 = r.with_server_acl(vec![], vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(
            r2.is_queryable("10.0.0.5".parse().unwrap()),
            "allow 명시 → 사설 허용"
        );

        let r3 = Recursor::with_default_roots(Duration::from_secs(1))
            .with_server_acl(vec!["8.8.8.0/24".parse().unwrap()], vec![]);
        assert!(
            !r3.is_queryable("8.8.8.8".parse().unwrap()),
            "deny 명시 → 전역도 거부"
        );
    }

    #[test]
    /** @brief 엄격 플래그가 실제 판정까지 전달되는지. */
    fn dnssec_strict_flag_plumbs() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert!(!r.strict, "기본은 fail-closed 비활성(보수적)");
        let r = r.with_dnssec().with_dnssec_strict(true);
        assert!(r.strict && r.validating(), "strict + 검증 활성");
    }

    #[test]
    /** @brief 대소문자를 섞어도 이름 자체는 같은지. */
    fn caps_for_id_randomizes_but_preserves_name() {
        let n = Name::from_str("www.Example.com").unwrap();

        for _ in 0..50 {
            let r = randomize_name_case(&n);
            assert!(r.eq_ignore_case(&n), "0x20: 대소문자 무시 시 동일 이름");
            assert_eq!(r.to_ascii_lower(), "www.example.com");
        }

        let differs = (0..50).any(|_| {
            randomize_name_case(&n)
                .labels()
                .iter()
                .zip(n.labels())
                .any(|(a, b)| a != b)
        });
        assert!(differs, "0x20: 랜덤화로 바이트가 바뀌어야 함");
    }

    #[test]
    /** @brief 0x20이 기본으로 켜져 있고 끌 수 있는지. */
    fn caps_for_id_is_enabled_by_default_and_can_be_disabled() {
        assert!(Recursor::new(vec![], Duration::from_secs(1)).caps_for_id);
        assert!(
            !Recursor::new(vec![], Duration::from_secs(1))
                .with_caps_for_id(false)
                .caps_for_id
        );
    }

    #[test]
    /** @brief 패닉으로 풀려도 CD 상태가 되돌아오는지. 새면 다음 질의가 검증을 건너뛴다. */
    fn honor_cd_scope_restores_after_request_isolation_unwind() {
        HONOR_CD.with(|state| state.set(false));
        let result = onetdns_core::isolation::catch_request(|| {
            with_honor_cd(true, || {
                assert!(honor_cd_active());
                panic!("injected request panic");
            });
        });
        assert!(result.is_err());
        assert!(!honor_cd_active());
    }

    #[test]
    /** @brief 중첩된 범위에서도 부모 상태가 되돌아오는지. */
    fn honor_cd_scope_restores_nested_parent() {
        HONOR_CD.with(|state| state.set(false));
        with_honor_cd(true, || {
            assert!(honor_cd_active());
            with_honor_cd(false, || assert!(!honor_cd_active()));
            assert!(honor_cd_active());
        });
        assert!(!honor_cd_active());
    }

    #[test]
    /** @brief 소문자화 설정이 나가는 이름에 적용되는지. */
    fn lowercase_outgoing_normalizes_name() {
        let n = lowercase_name(&Name::from_str("WwW.Example.COM").unwrap());
        assert_eq!(n.to_ascii_lower(), "www.example.com");
        assert!(
            n.labels()
                .eq([b"www".as_slice(), b"example".as_slice(), b"com".as_slice()]),
            "라벨 바이트가 실제 소문자"
        );

        let mut query = make_query(
            &Name::from_str("WwW.Example.COM").unwrap(),
            RecordType::A,
            true,
        );
        Recursor::with_default_roots(Duration::from_secs(1))
            .with_caps_for_id(false)
            .with_lowercase_outgoing(true)
            .apply_outgoing_case(&mut query);
        assert!(
            query.questions[0].name.labels().eq([
                b"www".as_slice(),
                b"example".as_slice(),
                b"com".as_slice()
            ]),
            "리액터 레인도 쓰는 공통 경로가 설정을 따라야 한다"
        );
    }

    #[test]
    /** @brief 대소문자가 다른 응답을 거부하는지. 이 검사가 0x20 방어의 실체다. */
    fn caps_for_id_exact_match_rejects_case_mismatch() {
        let q = |s: &str| {
            vec![Question {
                name: Name::from_str(s).unwrap(),
                qtype: RecordType::A,
                qclass: DnsClass::IN,
            }]
        };
        assert!(questions_case_exact(
            &q("WwW.eXample.com"),
            &q("WwW.eXample.com")
        ));

        assert!(!questions_case_exact(
            &q("www.example.com"),
            &q("WWW.example.com")
        ));
    }

    #[test]
    /** @brief 와이어 단계까지 통틀어 대소문자 불일치를 거부하는지. */
    fn caps_for_id_rejects_wire_question_case_mismatch_end_to_end() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let Ok((size, peer)) = socket.recv_from(&mut buf) else {
                return;
            };
            let Ok(request) = Message::parse(&buf[..size]) else {
                return;
            };
            let mut response = base(&request);
            let original_name = request.questions[0].name.clone();
            let mut labels: Vec<Vec<u8>> = original_name.labels().map(<[u8]>::to_vec).collect();
            'outer: for label in &mut labels {
                for byte in label {
                    if byte.is_ascii_alphabetic() {
                        *byte = if byte.is_ascii_lowercase() {
                            byte.to_ascii_uppercase()
                        } else {
                            byte.to_ascii_lowercase()
                        };
                        break 'outer;
                    }
                }
            }
            response.questions[0].name = Name::from_labels(labels).unwrap();
            response.answers.push(Record::new(
                original_name,
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 80)),
            ));
            let _ = socket.send_to(&response.try_encode().unwrap(), peer);
        });

        let recursor = Recursor::new(vec![], Duration::from_millis(500))
            .with_caps_for_id(true)
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let zone = Name::root();
        let request = Message::query(
            7,
            Name::from_str("manyletters.example").unwrap(),
            RecordType::A,
        );
        assert!(matches!(
            recursor.query_any(&[server], &request, &zone, recursor.query_deadline()),
            Err(RecurseError::NoResponse)
        ));
    }

    #[test]
    /** @brief 참조 예산 설정이 기본값을 덮는지. */
    fn with_recursion_limit_overrides_default() {
        let r = Recursor::with_default_roots(Duration::from_secs(1));
        assert_eq!(r.max_referrals, 16, "기본 위임 추적 상한");
        let r = r.with_recursion_limit(4);
        assert_eq!(r.max_referrals, 4);

        let r = Recursor::with_default_roots(Duration::from_secs(1)).with_recursion_limit(0);
        assert_eq!(r.max_referrals, 16);
    }

    /** @brief 요청에 대응하는 빈 응답 뼈대. */
    fn base(req: &Message) -> Message {
        Message {
            header: Header {
                id: req.header.id,
                response: true,
                recursion_desired: req.header.recursion_desired,
                ..Default::default()
            },
            questions: req.questions.clone(),
            ..Default::default()
        }
    }

    /**
     * @brief 절단만 알리는 UDP와 온전히 답하는 TCP를 같은 주소에 시작한다.
     *
     * @details 실제 권한 서버가 큰 응답에 하는 일 그대로다. TCP로 다시 묻지 않으면
     *          질의자는 위임을 따라갈 수 없다.
     */
    fn spawn_truncating_server(
        bind_ip: &str,
        port: u16,
        respond: impl Fn(&Message) -> Message + Send + Sync + 'static,
    ) -> SocketAddr {
        let addr: SocketAddr = format!("{bind_ip}:{port}").parse().unwrap();

        let udp = UdpSocket::bind(addr).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                // UDP에는 절단 표시만 설정해 빈 응답을 보낸다.
                let mut m = base(&req);
                m.header.truncated = true;
                if let Ok(wire) = m.try_encode() {
                    let _ = udp.send_to(&wire, from);
                }
            }
        });

        spawn_tcp_server(addr, respond)
    }

    /** @brief 주어진 응답 규칙으로 답하는 테스트용 TCP DNS 서버를 시작한다. */
    fn spawn_tcp_server(
        addr: SocketAddr,
        respond: impl Fn(&Message) -> Message + Send + Sync + 'static,
    ) -> SocketAddr {
        use std::io::{Read, Write};
        let respond = std::sync::Arc::new(respond);
        let listener = std::net::TcpListener::bind(addr).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let respond = respond.clone();
                std::thread::spawn(move || {
                    let mut len = [0u8; 2];
                    while stream.read_exact(&mut len).is_ok() {
                        let want = u16::from_be_bytes(len) as usize;
                        let mut body = vec![0u8; want];
                        if stream.read_exact(&mut body).is_err() {
                            return;
                        }
                        let Ok(req) = Message::parse(&body) else {
                            return;
                        };
                        let Ok(wire) = respond(&req).try_encode() else {
                            return;
                        };
                        let framed = (wire.len() as u16).to_be_bytes();
                        if stream.write_all(&framed).is_err() || stream.write_all(&wire).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    /** @brief 주어진 응답 규칙으로 답하는 테스트용 DNS 서버를 시작한다. */
    fn spawn_server(
        bind_ip: &str,
        port: u16,
        respond: impl Fn(&Message) -> Message + Send + 'static,
    ) -> SocketAddr {
        let addr: SocketAddr = format!("{bind_ip}:{port}").parse().unwrap();
        let sock = UdpSocket::bind(addr).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if let Ok(req) = Message::parse(&buf[..n]) {
                    let _ = sock.send_to(&respond(&req).try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    #[test]
    /** @brief 끝없는 위임 체인이 총 질의 예산에 걸려 멈추는지. */
    fn endless_delegation_chain_is_bounded_by_total_query_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();

        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 15987;
        let addr = spawn_server("127.0.0.40", PORT, move |req| {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let mut m = base(req);
            m.header.authoritative = false;
            if let Some(q) = req.questions.first() {
                m.authorities.push(Record::new(
                    q.name.clone(),
                    172800,
                    RData::Ns(Name::from_str(&format!("ns{n}.chain.test.")).unwrap()),
                ));
            }
            m
        });

        let rec = Recursor::new(vec![addr], Duration::from_secs(5)).with_test_loopback();
        let name = Name::from_str("a.b.c.d.e.f.g.deep.test.").unwrap();

        let mut per_query = Vec::new();
        for _ in 0..3 {
            let before = seen.load(Ordering::Relaxed);
            assert!(
                rec.resolve(&name, RecordType::A).is_err(),
                "끝없는 위임이 성공으로 끝나면 안 된다"
            );
            per_query.push(seen.load(Ordering::Relaxed) - before);
        }
        let total = per_query.iter().copied().max().unwrap();

        assert!(total > 1, "공격 형태가 재현되지 않았다(발신 {total}회)");
        assert!(
            total <= MAX_TOTAL_QUERIES,
            "총 발신 질의 예산({MAX_TOTAL_QUERIES})을 넘겼다: {total}회"
        );
    }

    /** @brief NS와 glue를 담은 참조 응답. */
    fn referral(req: &Message, zone: &str, ns: &str, glue: Ipv4Addr) -> Message {
        let mut m = base(req);
        m.header.authoritative = false;
        m.authorities.push(Record::new(
            Name::from_str(zone).unwrap(),
            172800,
            RData::Ns(Name::from_str(ns).unwrap()),
        ));
        m.additionals.push(Record::new(
            Name::from_str(ns).unwrap(),
            172800,
            RData::A(glue),
        ));
        m
    }

    /** @brief A 답변 하나짜리 응답. */
    fn a_answer(req: &Message, ip: Ipv4Addr) -> Message {
        let mut m = base(req);
        m.header.authoritative = true;
        if let Some(q) = req.questions.first() {
            m.answers
                .push(Record::new(q.name.clone(), 300, RData::A(ip)));
        }
        m
    }

    /** @brief 시드로 고정한 P-256 키쌍과 그 DNSKEY. */
    fn ecdsa_key(seed: u8) -> (p256::ecdsa::SigningKey, onetdns_dnssec::Dnskey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let dnskey = onetdns_dnssec::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        (sk, dnskey)
    }

    /** @brief DNSKEY를 미해석 RDATA 레코드로 감싼다. */
    fn dnskey_rec(owner: &str, key: &onetdns_dnssec::Dnskey) -> Record {
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(48, key.rdata_bytes()),
        )
    }

    /** @brief NSEC 레코드를 손으로 만든다. */
    fn nsec_rec(owner: &str, next: &str, types: &[u16]) -> Record {
        let mut rdata = Vec::new();
        for label in next.trim_end_matches('.').split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let max = types.iter().copied().max().unwrap_or(0);
        let nbytes = (max / 8 + 1) as usize;
        let mut bm = vec![0u8; nbytes];
        for &t in types {
            bm[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        rdata.push(0);
        rdata.push(nbytes as u8);
        rdata.extend_from_slice(&bm);
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(47, rdata),
        )
    }

    /** @brief 주어진 RRset을 서명해 RRSIG 레코드를 만든다. */
    fn rrsig_rec(
        sk: &p256::ecdsa::SigningKey,
        key: &onetdns_dnssec::Dnskey,
        signer: &str,
        type_covered: u16,
        rrset: &[Record],
    ) -> Record {
        use p256::ecdsa::{signature::Signer, Signature};
        let owner = rrset[0].name.clone();
        let mut sig = onetdns_dnssec::Rrsig {
            type_covered,
            algorithm: 13,
            labels: owner.num_labels() as u8,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str(signer).unwrap(),
            signature: vec![],
        };
        let s: Signature = sk.sign(&onetdns_dnssec::signed_data(&sig, rrset));
        sig.signature = s.to_bytes().to_vec();
        Record::new(owner, 3600, RData::Unknown(46, sig.rdata_bytes()))
    }

    #[test]
    /** @brief 부재 증명이 체인 apex의 SOA를 쓰는지. 자손의 SOA를 쓰면 남의 zone이 부재를 주장할 수 있다. */
    fn terminal_denial_uses_chain_apex_not_descendant_soa() {
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let soa = onetdns_proto::Soa {
            mname: Name::from_str("ns.test").unwrap(),
            rname: Name::from_str("hostmaster.test").unwrap(),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: 300,
        };
        let mut response = Message::default();
        response.header.authoritative = true;
        response.header.rcode = ResponseCode::NXDomain.0;
        response
            .authorities
            .push(Record::new(qname.clone(), 3600, RData::soa(soa.clone())));

        assert!(
            !is_authoritative_negative(&response, &qname, &apex),
            "하위 owner의 SOA는 현재 zone의 최종 부재 응답이 아님"
        );

        let child = Name::from_str("sub.test").unwrap();
        let child_qname = Name::from_str("host.sub.test").unwrap();
        let mut lame = Message::default();
        lame.header.authoritative = true;
        lame.header.rcode = ResponseCode::NXDomain.0;
        lame.authorities
            .push(Record::new(apex.clone(), 3600, RData::soa(soa.clone())));
        assert!(
            !is_authoritative_negative(&lame, &child_qname, &child),
            "위임 지점보다 위의 SOA는 그 자식 zone의 부재 증명이 아님"
        );

        response
            .authorities
            .push(Record::new(apex.clone(), 3600, RData::soa(soa)));
        response
            .authorities
            .push(nsec_rec("host.test", "z.test", &[1, 46, 47]));
        sanitize_terminal_response(&mut response, &qname, RecordType::AAAA, false, Some(&apex));

        let retained_soa: Vec<&Record> = response
            .authorities
            .iter()
            .filter(|record| record.rtype == RecordType::SOA)
            .collect();
        assert_eq!(retained_soa.len(), 1);
        assert!(retained_soa[0].name.eq_ignore_case(&apex));
        assert!(response
            .authorities
            .iter()
            .any(|record| record.rtype == RecordType::NSEC));
    }

    #[test]
    /** @brief 부재 증명이 리프 apex의 서명을 요구하는지. */
    fn terminal_denial_requires_leaf_apex_signatures() {
        let (signing_key, key) = ecdsa_key(63);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let anchor = onetdns_dnssec::Ds::from_dnskey(&key, &apex, 2).unwrap();
        let rec = Recursor::new(vec![], Duration::from_secs(1)).with_trust_anchors(vec![anchor]);
        let anchors = rec.trust_anchors.load();
        rec.validated_keys_store(
            apex.canonical_key(),
            ZoneTrust::Secure(Arc::from(vec![key.clone()])),
            anchors,
            300,
        );
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        );
        let nsec = nsec_rec("host.test", "z.test", &[1, 46, 47]);
        let status = |signer: &str, soa_record: &Record, include_soa_sig: bool| {
            let mut response = Message::default();
            response.authorities.push(soa_record.clone());
            if include_soa_sig {
                response.authorities.push(soa_sig.clone());
            }
            response.authorities.push(nsec.clone());
            response.authorities.push(rrsig_rec(
                &signing_key,
                &key,
                signer,
                RecordType::NSEC.0,
                std::slice::from_ref(&nsec),
            ));
            rec.validate_denial_status(
                &qname,
                RecordType::AAAA,
                &response,
                &chain,
                Instant::now() + Duration::from_secs(1),
            )
        };

        assert_eq!(status("test", &soa, true), SecurityStatus::Secure);
        assert_eq!(
            status(".", &soa, true),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "암호학적으로 유효해도 업스트림 zone signer의 최종 NSEC는 거부"
        );
        assert_eq!(
            status("test", &soa, false),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "서명되지 않은 SOA를 포함한 부재 응답은 AD를 주장하면 안 됨"
        );
        let mut forged_soa = soa.clone();
        let RData::Soa(forged) = &mut forged_soa.rdata else {
            unreachable!()
        };
        forged.serial += 1;
        assert_eq!(
            status("test", &forged_soa, true),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "유효한 SOA 서명에 변조된 SOA를 붙여도 거부"
        );
    }

    #[test]
    /** @brief 서명된 무관 NSEC가 많아도 실제 최소 증명을 먼저 골라 검증하는지. */
    fn denial_validation_ignores_superfluous_signed_nsec_records() {
        let (signing_key, key) = ecdsa_key(64);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let mut response = Message::default();
        response.authorities.push(soa.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        ));

        for i in 0..32 {
            let record = nsec_rec(
                &format!("a{i:02}.test"),
                &format!("a{i:02}z.test"),
                &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
            );
            response.authorities.push(record.clone());
            response.authorities.push(rrsig_rec(
                &signing_key,
                &key,
                "test",
                RecordType::NSEC.0,
                std::slice::from_ref(&record),
            ));
        }
        let needed = nsec_rec(
            "host.test",
            "z.test",
            &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        response.authorities.push(needed.clone());
        response.authorities.push(rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&needed),
        ));

        assert_eq!(
            recursor
                .validate_denial_with_keys(&qname, RecordType::AAAA, &response, &chain, &[key],),
            SecurityStatus::Secure,
            "무관한 서명 RRset의 개수가 검증 순서나 판정을 좌우하면 안 된다"
        );
    }

    #[test]
    /** @brief 답변의 모든 RRSIG 후보가 RRset 하나의 8회 검증 예산을 공유하는지. */
    fn answer_rrsigs_share_one_verification_budget() {
        let (signing_key, key) = ecdsa_key(65);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let chain = [ZoneStep {
            zone: apex,
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let answer = Record::new(qname.clone(), 3600, RData::A(Ipv4Addr::new(192, 0, 2, 65)));
        let other = Record::new(qname.clone(), 3600, RData::A(Ipv4Addr::new(192, 0, 2, 66)));
        let invalid_for_answer = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::A.0,
            std::slice::from_ref(&other),
        );
        let valid = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::A.0,
            std::slice::from_ref(&answer),
        );
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let verdict = |invalid_count| {
            let mut response = Message::default();
            response.answers.push(answer.clone());
            response.answers.extend(std::iter::repeat_n(
                invalid_for_answer.clone(),
                invalid_count,
            ));
            response.answers.push(valid.clone());
            recursor.validate_answer_with_keys(
                &qname,
                RecordType::A,
                &response,
                &chain,
                std::slice::from_ref(&key),
            )
        };

        assert_eq!(
            verdict(7),
            SecurityStatus::Secure,
            "8회째의 정상 서명은 검증해야 한다"
        );
        assert_eq!(
            verdict(8),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "후보마다 예산을 초기화해 9회째를 검증하면 KeyTrap 상한이 무의미하다"
        );
    }

    #[test]
    /** @brief SOA와 NSEC가 응답 하나의 공개키 연산 예산을 공유하는지. */
    fn denial_rrsets_share_one_response_verification_budget() {
        let (signing_key, key) = ecdsa_key(66);
        let apex = Name::from_str("test").unwrap();
        let qname = Name::from_str("host.test").unwrap();
        let chain = [ZoneStep {
            zone: apex.clone(),
            servers: vec![],
            ns_names: vec![],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        }];
        let soa = Record::new(
            apex,
            3600,
            RData::soa(onetdns_proto::Soa {
                mname: Name::from_str("ns.test").unwrap(),
                rname: Name::from_str("hostmaster.test").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum: 300,
            }),
        );
        let mut other_soa = soa.clone();
        let RData::Soa(other) = &mut other_soa.rdata else {
            unreachable!()
        };
        other.serial = 2;
        let invalid_soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&other_soa),
        );
        let valid_soa_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::SOA.0,
            std::slice::from_ref(&soa),
        );
        let nsec = nsec_rec(
            "host.test",
            "z.test",
            &[RecordType::A.0, RecordType::RRSIG.0, RecordType::NSEC.0],
        );
        let nsec_sig = rrsig_rec(
            &signing_key,
            &key,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&nsec),
        );
        let recursor = Recursor::new(vec![], Duration::from_secs(1));
        let verdict = |invalid_count| {
            let mut response = Message::default();
            response.authorities.push(soa.clone());
            response
                .authorities
                .extend(std::iter::repeat_n(invalid_soa_sig.clone(), invalid_count));
            response.authorities.push(valid_soa_sig.clone());
            response.authorities.push(nsec.clone());
            response.authorities.push(nsec_sig.clone());
            recursor.validate_denial_with_keys(
                &qname,
                RecordType::AAAA,
                &response,
                &chain,
                std::slice::from_ref(&key),
            )
        };

        assert_eq!(
            verdict(6),
            SecurityStatus::Secure,
            "SOA 7회와 NSEC 1회는 응답 예산 안에서 검증해야 한다"
        );
        assert_eq!(
            verdict(7),
            SecurityStatus::Bogus(ede_code::DNSSEC_BOGUS),
            "SOA가 예산을 소진한 뒤 NSEC에서 새 예산을 만들면 응답 전체 상한이 아니다"
        );
    }

    #[cfg(unix)]
    /** @brief 루트부터 리프까지 서명된 테스트용 계층을 시작한다. 체인 검증 전체를 거친다. */
    fn spawn_signed_hierarchy(
        port: u16,
        root_ip: &str,
        child_ip: &str,
        forge_leaf_answer: bool,
    ) -> (SocketAddr, onetdns_dnssec::Ds) {
        let (sk_root, k_root) = ecdsa_key(21);
        let (sk_test, k_test) = ecdsa_key(22);
        let (sk_evil, k_evil) = ecdsa_key(23);

        let root_owner = Name::from_str(".").unwrap();
        let test_owner = Name::from_str("test").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let test_ds = onetdns_dnssec::Ds::from_dnskey(&k_test, &test_owner, 2).unwrap();
        let test_ds_rec = Record::new(test_owner, 3600, RData::Unknown(43, test_ds.rdata_bytes()));

        let child_glue: Ipv4Addr = child_ip.parse().unwrap();
        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = test_ds_rec.clone();
            spawn_server(root_ip, port, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.test").unwrap()),
                    ));
                    m.authorities.push(ds_rec.clone());
                    m.authorities.push(rrsig_rec(
                        &sk,
                        &k,
                        ".",
                        RecordType::DS.0,
                        &[ds_rec.clone()],
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.test").unwrap(),
                        3600,
                        RData::A(child_glue),
                    ));
                }
                m
            });
        }
        {
            let (sk, k) = (sk_test.clone(), k_test.clone());
            let (sk_bad, k_bad) = (sk_evil.clone(), k_evil.clone());
            spawn_server(child_ip, port, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "test" {
                    let dk = dnskey_rec("test", &k);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("host.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    );

                    let sig = if forge_leaf_answer {
                        rrsig_rec(&sk_bad, &k_bad, "test", RecordType::A.0, &[a.clone()])
                    } else {
                        rrsig_rec(&sk, &k, "test", RecordType::A.0, &[a.clone()])
                    };
                    m.answers.push(a);
                    m.answers.push(sig);
                }
                m
            });
        }
        let root_server = SocketAddr::new(IpAddr::V4(root_ip.parse().unwrap()), port);
        (root_server, root_anchor)
    }

    #[cfg(unix)]
    /** @brief 이벤트 레인을 끝까지 돌리고 결과를 얻는다. */
    fn drive_lane(
        reactor: &mut crate::reactor::Reactor,
        rec: &Recursor,
    ) -> Option<crate::reactor::Completion> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            if fds.is_empty() {
                return None;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(rec, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(rec, now, &mut out);
            if let Some(first) = out.into_iter().next() {
                return Some(first);
            }
        }
        None
    }

    #[cfg(unix)]
    #[test]
    /** @brief 이벤트 레인이 스레드를 막지 않고도 검증을 마치는지. */
    fn reactor_lane_validates_dnssec_without_blocking_fetch() {
        use crate::reactor::{Completion, Reactor, ReactorConfig, SubmitOutcome};

        let (root_server, anchor) = spawn_signed_hierarchy(5410, "127.0.0.40", "127.0.0.41", false);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(5410)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let qname = Name::from_str("host.test").unwrap();

        let mut cold = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            cold.submit(&rec, qname.clone(), RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        let Some(Completion::Answer(token, msg)) = drive_lane(&mut cold, &rec) else {
            panic!("레인이 DNSKEY를 스스로 모아 완결해야 한다");
        };
        assert_eq!(token, 1);
        assert_eq!(msg.header.rcode, ResponseCode::NoError.0);
        assert!(msg.header.authentic_data, "레인이 검증한 답은 AD=1");
        assert_eq!(
            msg.answers
                .iter()
                .filter(|r| r.rtype == RecordType::A)
                .count(),
            1
        );

        let sync = rec.resolve(&qname, RecordType::A).expect("동기 해석");
        assert_eq!(sync.header.authentic_data, msg.header.authentic_data);
        assert_eq!(sync.header.rcode, msg.header.rcode);
    }

    #[cfg(unix)]
    #[test]
    /** @brief 이벤트 레인도 위조 서명을 SERVFAIL로 막는지. 동기 경로와 판정이 같아야 한다. */
    fn reactor_lane_servfails_forged_signature() {
        use crate::reactor::{Completion, Reactor, ReactorConfig, SubmitOutcome};

        let (root_server, anchor) = spawn_signed_hierarchy(5411, "127.0.0.42", "127.0.0.43", true);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(5411)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let qname = Name::from_str("host.test").unwrap();

        let sync = rec.resolve(&qname, RecordType::A).expect("동기 해석 시도");
        assert_eq!(
            sync.header.rcode,
            ResponseCode::ServFail.0,
            "동기 경로: 위조 서명은 SERVFAIL"
        );

        let mut warm = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            warm.submit(&rec, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));

        match drive_lane(&mut warm, &rec) {
            Some(Completion::Answer(_, msg)) => {
                assert_eq!(
                    msg.header.rcode,
                    ResponseCode::ServFail.0,
                    "레인이 위조 서명을 통과시켰다: AD={}, answers={}",
                    msg.header.authentic_data,
                    msg.answers.len()
                );
                assert!(!msg.header.authentic_data);
            }
            Some(Completion::Retry(_)) => {
                panic!("레인이 판정하지 않고 넘겼다. 이 테스트가 검증 경로를 지나지 않는다")
            }
            Some(Completion::Fail(..)) => panic!("해석 자체가 실패했다"),
            None => panic!("완료 통지가 없다"),
        }
    }

    #[test]
    /**
     * @brief 쓸 수 있는 글루가 있으면 그것으로 내려가는지.
     *
     * @details 네임서버 이름은 여럿인데 부모가 준 주소는 일부뿐인 위임이 흔하다. 주소를
     *          이미 쥐고도 남은 이름을 먼저 풀러 가면 그 하나하나가 다시 루트부터 걷는
     *          해석이 되어 예산을 전부 소진한다. 실제로 iana.org, kernel.org, debian.org,
     *          bbc.co.uk가 찬 프로세스에서 전부 SERVFAIL이었다. 흔한 이름 10개 중 4개다.
     * @warning 글루 없는 네임서버는 답하지 않는 주소로 위임된다. 그것을 먼저 풀려 들면
     *          예산이 말라 이 테스트는 통과할 수 없다.
     */
    fn a_referral_with_partial_glue_uses_what_it_has() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5406;
        /** @brief 아무도 듣지 않는 주소. 여기로 위임하면 그 해석은 시간을 다 쓴다. */
        const BLACKHOLE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 40);

        spawn_server("127.0.0.38", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            let name = q.name.to_ascii_lower();
            if name.ends_with("slow.test") {
                // 글루 없는 네임서버들이 사는 곳. 답하지 않는 주소로 넘긴다.
                m.authorities.push(Record::new(
                    Name::from_str("slow.test").unwrap(),
                    3600,
                    RData::Ns(Name::from_str("ns.slow.test").unwrap()),
                ));
                m.additionals.push(Record::new(
                    Name::from_str("ns.slow.test").unwrap(),
                    3600,
                    RData::A(BLACKHOLE),
                ));
                return m;
            }
            for ns in ["ns1.partial", "ns2.slow.test", "ns3.slow.test"] {
                m.authorities.push(Record::new(
                    Name::from_str("partial").unwrap(),
                    3600,
                    RData::Ns(Name::from_str(ns).unwrap()),
                ));
            }
            m.additionals.push(Record::new(
                Name::from_str("ns1.partial").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 39)),
            ));
            m
        });

        spawn_server("127.0.0.39", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.partial" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.partial").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 38)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 38)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.partial").unwrap(), RecordType::A)
            .expect("받은 글루로 내려갈 수 있어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 38))
            ),
            "글루를 쥐고도 답하지 않는 네임서버를 풀러 갔습니다"
        );
    }

    #[test]
    /**
     * @brief 참조 경로 강화를 켜도 빈 비단말 아래 이름이 풀리고, 권한 없는 빈 답에서는 멈추는지.
     * @details 이름 최소화는 빈 비단말에서 위임 없는 빈 답을 받는다. 이것을 경로 실패로 보면
     *          강화를 켠 설치에서 그런 이름은 모두 SERVFAIL이 된다.
     */
    fn harden_referral_path_allows_empty_non_terminals() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5408;

        spawn_server("127.0.0.83", PORT, |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("test").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.test").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.test").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 84)),
            ));
            m
        });
        spawn_server("127.0.0.84", PORT, |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            let name = q.name.to_ascii_lower();
            m.header.authoritative = !name.ends_with("lame.test");
            if name == "host.ent.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    q.name.clone(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 84)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 83)), PORT);
        let recursor = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_harden_referral_path(true);
        let resp = recursor
            .resolve(&Name::from_str("host.ent.test").unwrap(), RecordType::A)
            .expect("빈 비단말 아래 이름은 풀려야 한다");
        assert!(resp.answers.iter().any(
            |record| matches!(record.rdata, RData::A(ip) if ip == Ipv4Addr::new(10, 0, 0, 84))
        ));
        assert!(
            recursor
                .resolve(&Name::from_str("host.lame.test").unwrap(), RecordType::A)
                .is_err(),
            "권한 없는 빈 답으로는 내려가지 않는다"
        );
    }

    #[test]
    /**
     * @brief recursion_limit이 실제로 따라간 위임 횟수를 막는지.
     * @details 바퀴 수 상한에는 이름 최소화 몫으로 라벨 수가 더해진다. 위임을 따로 세지 않으면
     *          상한을 1로 두어도 두 번 위임받는 이름이 그대로 풀린다.
     */
    fn recursion_limit_bounds_followed_delegations() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5407;

        /** @brief zone을 ns 이름과 주소로 넘기는 참조 응답. */
        fn referral(req: &Message, zone: &str, ns: &str, ip: Ipv4Addr) -> Message {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str(zone).unwrap(),
                3600,
                RData::Ns(Name::from_str(ns).unwrap()),
            ));
            m.additionals
                .push(Record::new(Name::from_str(ns).unwrap(), 3600, RData::A(ip)));
            m
        }

        spawn_server("127.0.0.80", PORT, |req| {
            referral(req, "test", "ns.test", Ipv4Addr::new(127, 0, 0, 81))
        });
        spawn_server("127.0.0.81", PORT, |req| {
            referral(req, "a.test", "ns.a.test", Ipv4Addr::new(127, 0, 0, 82))
        });
        spawn_server("127.0.0.82", PORT, |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.a.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    q.name.clone(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 80)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 80)), PORT);
        let recursor = |limit| {
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_recursion_limit(limit)
        };
        let name = Name::from_str("host.a.test").unwrap();
        assert!(
            recursor(2).resolve(&name, RecordType::A).is_ok(),
            "위임 두 번은 상한 2 안에 든다"
        );
        assert!(
            recursor(1).resolve(&name, RecordType::A).is_err(),
            "상한 1로는 두 번째 위임을 따라가지 않는다"
        );
    }

    #[test]
    /**
     * @brief 절단된 응답을 받으면 TCP로 다시 물어 마저 받아 오는지.
     *
     * @details UDP 한 장에 담기지 않는 응답은 절단 표시만 달려 온다. 다시 묻지 않으면
     *          위임을 따라갈 수 없어 그 이름은 아예 풀리지 않는다. 서명을 함께 요청하는
     *          지금은 위임 응답이 한 장을 넘는 일이 흔하다.
     * @note 다시 묻는 일은 재귀 리졸버가 아니라 그 아래 교환 계층이 한다. 재귀 경로로 그것을
     *       확인해 두지 않으면, 교환 계층에서 사라져도 여기서는 드러나지 않는다.
     * @warning UDP 쪽은 일부러 답을 비워 둔다. TCP로 다시 묻지 않으면 이 테스트는 통과할 수 없다.
     */
    fn a_truncated_referral_is_refetched_over_tcp() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5405;

        spawn_truncating_server("127.0.0.36", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("big").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.big").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.big").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 37)),
            ));
            let _ = q;
            m
        });

        spawn_server("127.0.0.37", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.big" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.big").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(10, 0, 0, 36)),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 36)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.big").unwrap(), RecordType::A)
            .expect("절단된 위임을 TCP로 다시 받아 따라갈 수 있어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 36))
            ),
            "최종 답을 얻지 못했습니다"
        );
    }

    #[test]
    /** @brief UDP가 가로채인 망에서 TCP 판정을 켜면 권한 서버의 진짜 답을 받는지. */
    fn authority_tcp_switch_bypasses_intercepted_udp() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5412;
        /** @brief 가로챈 쪽이 UDP로 돌려주는 주소. */
        const FORGED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
        /** @brief 권한 서버가 TCP로 돌려주는 주소. */
        const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 44);

        let answer = |req: &Message, ip: Ipv4Addr| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.qtype == RecordType::A {
                m.answers.push(Record::new(q.name, 300, RData::A(ip)));
            }
            m
        };
        let addr = spawn_server("127.0.0.44", PORT, move |req| answer(req, FORGED));
        spawn_tcp_server(addr, move |req| answer(req, REAL));

        let switch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rec = Recursor::new(vec![addr], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_authority_tcp(switch.clone());
        let resolve = |name: &str| {
            let resp = rec
                .resolve(&Name::from_str(name).unwrap(), RecordType::A)
                .expect("답을 받아야 합니다");
            resp.answers
                .iter()
                .find_map(|record| match record.rdata {
                    RData::A(ip) => Some(ip),
                    _ => None,
                })
                .expect("주소 답이 있어야 합니다")
        };

        assert_eq!(resolve("udp.intercept"), FORGED);
        switch.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(rec.authority_over_tcp());
        assert_eq!(
            resolve("tcp.intercept"),
            REAL,
            "판정을 켰는데도 UDP로 물어 가로챈 답을 받았습니다"
        );
    }

    #[test]
    /**
     * @brief 질의 하나가 동시에 기다리는 교환이 MAX_EXCHANGES_PER_QUERY를 넘지 않는지.
     * @details 앞의 두 서버는 답하지 않는다. 상한이 없으면 셋째 서버에도 다음 서버에 물을
     *          시각이 되자마자 묻고, 상한이 있으면 앞의 교환 하나가 시간을 넘긴 뒤에야 묻는다.
     */
    fn a_query_waits_on_at_most_two_exchanges_at_once() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5423;
        let silent = |ip: &str| {
            let sock = UdpSocket::bind(format!("{ip}:{PORT}")).unwrap();
            let addr = sock.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while sock.recv_from(&mut buf).is_ok() {}
            });
            addr
        };
        let first = silent("127.0.0.90");
        let second = silent("127.0.0.91");
        let third_sock = UdpSocket::bind(format!("127.0.0.92:{PORT}")).unwrap();
        let third = third_sock.local_addr().unwrap();
        let asked_third = Arc::new(Mutex::new(None::<Instant>));
        let record = asked_third.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while third_sock.recv_from(&mut buf).is_ok() {
                record.lock().unwrap().get_or_insert_with(Instant::now);
            }
        });

        let timeout = Duration::from_secs(4);
        let rec = Recursor::new(vec![], timeout).with_test_loopback();
        let zone = Name::from_str("cap.test").unwrap();
        let query = make_query(
            &Name::from_str("host.cap.test").unwrap(),
            RecordType::A,
            false,
        );
        let started = Instant::now();
        assert!(rec
            .query_any(&[first, second, third], &query, &zone, rec.query_deadline())
            .is_err());

        let per_server = timeout / 3;
        let asked = asked_third
            .lock()
            .unwrap()
            .map(|at| at.duration_since(started))
            .expect("앞의 교환이 끝나면 셋째 서버에도 물어야 합니다");
        assert!(
            asked >= per_server,
            "앞의 두 교환이 답을 기다리는 동안 셋째 서버에도 물었습니다: {asked:?}"
        );
    }

    #[test]
    /**
     * @brief 답을 기다리는 사이 TCP 판정이 켜지면 다음 서버에는 TCP로 묻는지.
     * @details 판정은 시작 직후의 점검이 끝날 때 켜지므로, 그 전에 시작한 해석의 도중에 바뀐다.
     *          서버 목록을 시작할 때 전송을 한 번만 고르면 나머지 서버에도 가로채이는 UDP로
     *          묻는다.
     */
    fn authority_tcp_switch_applies_to_servers_asked_after_it_turns_on() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5422;
        /** @brief 가로챈 쪽이 UDP로 돌려주는 주소. */
        const FORGED: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 88);
        /** @brief 권한 서버가 TCP로 돌려주는 주소. */
        const REAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 88);

        let switch = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let silent = UdpSocket::bind("127.0.0.88:5422").unwrap();
        let first = silent.local_addr().unwrap();
        let flip = switch.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while silent.recv_from(&mut buf).is_ok() {
                flip.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let answer = |req: &Message, ip: Ipv4Addr| {
            let mut m = base(req);
            m.header.authoritative = true;
            let q = req.questions.first().unwrap().clone();
            m.answers.push(Record::new(q.name, 300, RData::A(ip)));
            m
        };
        let second = spawn_server("127.0.0.89", PORT, move |req| answer(req, FORGED));
        spawn_tcp_server(second, move |req| answer(req, REAL));

        let rec = Recursor::new(vec![], Duration::from_secs(3))
            .with_test_loopback()
            .with_authority_tcp(switch);
        let zone = Name::from_str("switch.test").unwrap();
        let query = make_query(
            &Name::from_str("host.switch.test").unwrap(),
            RecordType::A,
            false,
        );
        let resp = rec
            .query_any(&[first, second], &query, &zone, rec.query_deadline())
            .expect("둘째 서버의 답을 받아야 합니다");
        assert!(
            matches!(resp.answers.first().map(|r| &r.rdata), Some(RData::A(ip)) if *ip == REAL),
            "판정이 켜진 뒤에도 UDP로 물어 가로챈 답을 받았습니다: {resp:?}"
        );
    }

    /** @brief 부모와 자식 영역 테스트에서 최종 이름이 가리키는 주소. */
    const COHOSTED_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);

    /**
     * @brief parent.test와 그 자식 l.parent.test를 한 서버가 맡는 구성을 시작한다.
     * @details 루트는 parent.test로 위임한다. 영역 서버는 자식 영역의 NS를 권한 있는 답으로
     *          주고, 빈 비단말 myaddr.l.parent.test를 NXDOMAIN으로 답한다. DS 질의에는 부모
     *          영역의 DS를 답변 절에 담아 주고, 받은 횟수를 센다.
     * @return 루트 서버 주소와 DS 질의 횟수.
     */
    fn spawn_cohosted_zones(
        root_ip: Ipv4Addr,
        zone_ip: Ipv4Addr,
        port: u16,
    ) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        /** @brief 테스트 이름을 만든다. */
        fn name(text: &str) -> Name {
            Name::from_str(text).unwrap()
        }
        /** @brief 이 영역의 부정 응답에 붙일 SOA. */
        fn soa(apex: &str) -> Record {
            Record::new(
                name(apex),
                300,
                RData::soa(onetdns_proto::Soa {
                    mname: name("ns.parent.test"),
                    rname: name("hostmaster.parent.test"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86_400,
                    minimum: 300,
                }),
            )
        }

        spawn_server(&root_ip.to_string(), port, move |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                name("parent.test"),
                3600,
                RData::Ns(name("ns.parent.test")),
            ));
            m.additionals
                .push(Record::new(name("ns.parent.test"), 3600, RData::A(zone_ip)));
            m
        });
        let ds_queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = ds_queries.clone();
        spawn_server(&zone_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let asked = q.name.to_ascii_lower();
            let mut m = base(req);
            m.header.authoritative = true;
            match (asked.as_str(), q.qtype) {
                ("l.parent.test", RecordType::NS) => {
                    m.answers.push(Record::new(
                        name("l.parent.test"),
                        3600,
                        RData::Ns(name("ns.parent.test")),
                    ));
                    m.additionals.push(Record::new(
                        name("ns.parent.test"),
                        3600,
                        RData::A(zone_ip),
                    ));
                }
                ("l.parent.test", RecordType::DS) => {
                    seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let ds = onetdns_dnssec::Ds {
                        key_tag: 4321,
                        algorithm: 13,
                        digest_type: 2,
                        digest: vec![5; 32],
                    };
                    m.answers.push(Record::new(
                        name("l.parent.test"),
                        300,
                        RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
                    ));
                }
                ("myaddr.l.parent.test", _) => {
                    m.header.rcode = ResponseCode::NXDomain.0;
                    m.authorities.push(soa("l.parent.test"));
                }
                ("o-o.myaddr.l.parent.test", RecordType::A) => {
                    m.answers
                        .push(Record::new(q.name, 60, RData::A(COHOSTED_TARGET)));
                }
                (other, _) if other.ends_with("l.parent.test") => {
                    m.authorities.push(soa("l.parent.test"));
                }
                _ => m.authorities.push(soa("parent.test")),
            }
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), ds_queries)
    }

    #[test]
    /**
     * @brief 부모와 자식 영역을 같은 서버가 맡을 때 답변 절의 NS를 영역 경계로 따라가는지.
     * @details 서버는 자식 영역으로 답하므로 최소화 질의에 대한 NS가 위임이 아니라 권한 있는
     *          답으로 온다. 경계를 놓치면 현재 영역을 부모로 알아, 자식 영역의 SOA가 붙은
     *          부정 응답을 무관한 것으로 버리고 SERVFAIL을 낸다. 경계를 따라가야 빈 비단말에
     *          대한 NXDOMAIN을 받아들이고 전체 이름으로 다시 물을 수 있다.
     */
    fn an_authoritative_ns_answer_is_followed_as_a_zone_cut() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5413;
        let (root, ds_queries) = spawn_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 50),
            Ipv4Addr::new(127, 0, 0, 51),
            PORT,
        );

        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(
                &Name::from_str("o-o.myaddr.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("같은 서버가 맡은 자식 영역으로 내려가 답을 받아야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers
                .iter()
                .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)),
            "최종 답을 얻지 못했습니다: {resp:?}"
        );
        assert_eq!(
            ds_queries.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "검증하지 않으면 DS를 따로 묻지 않는다"
        );
    }

    #[test]
    /**
     * @brief 검증할 때 답변 절로 드러난 경계의 DS를 부모에게 물어 체인에 넣는지.
     * @details 참조와 달리 이 경계에는 DS 증거가 함께 오지 않는다. 증거 없이 체인에 넣으면
     *          서명된 자식 영역이 증명 없이 Insecure로 내려가 검증이 무력화된다.
     */
    fn an_answer_zone_cut_fetches_its_ds_when_validating() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5414;
        let (root, ds_queries) = spawn_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 52),
            Ipv4Addr::new(127, 0, 0, 53),
            PORT,
        );

        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let mut budget = Budget {
            ns_resolves: rec.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: rec.query_deadline(),
        };
        let qname = Name::from_str("o-o.myaddr.l.parent.test").unwrap();
        let (resp, chain) = rec
            .iterate_from(
                &qname,
                RecordType::A,
                &mut budget,
                Name::root(),
                vec![root],
                true,
            )
            .expect("검증을 켜도 경계를 따라 내려가야 합니다");
        assert!(resp
            .answers
            .iter()
            .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)));
        assert_eq!(ds_queries.load(std::sync::atomic::Ordering::Relaxed), 1);
        let child = chain
            .iter()
            .find(|step| step.zone.to_ascii_lower() == "l.parent.test")
            .expect("자식 영역이 체인에 있어야 합니다");
        assert_eq!(
            child.ds.iter().map(|ds| ds.key_tag).collect::<Vec<_>>(),
            vec![4321],
            "부모에게 받은 DS가 체인에 기록돼야 합니다"
        );
    }

    /**
     * @brief 서명된 루트, parent.test, l.parent.test를 시작한다. 두 영역은 한 서버가 맡는다.
     * @details 영역마다 키가 다르다. 자식 영역의 NS는 권한 있는 답으로 주고, 그 DS는 부모 키로
     *          서명해 DS 질의에만 준다. child_ds_seed로 DS를 만들 키를 고른다. 자식 키와 다르면
     *          위조된 DS가 된다.
     * @return 루트 서버 주소와 루트 신뢰 앵커.
     */
    fn spawn_signed_cohosted_zones(
        root_ip: Ipv4Addr,
        zone_ip: Ipv4Addr,
        port: u16,
        child_ds_seed: u8,
    ) -> (SocketAddr, onetdns_dnssec::Ds) {
        /** @brief 테스트 이름을 만든다. */
        fn name(text: &str) -> Name {
            Name::from_str(text).unwrap()
        }
        /** @brief DS를 레코드로 감싼다. */
        fn ds_rec(owner: &str, key: &onetdns_dnssec::Dnskey) -> Record {
            let ds = onetdns_dnssec::Ds::from_dnskey(key, &name(owner), 2).unwrap();
            Record::new(
                name(owner),
                3600,
                RData::Unknown(RecordType::DS.0, ds.rdata_bytes()),
            )
        }

        let (root_sk, root_key) = ecdsa_key(71);
        let (parent_sk, parent_key) = ecdsa_key(72);
        let (child_sk, child_key) = ecdsa_key(73);
        let (_, ds_key) = ecdsa_key(child_ds_seed);
        let anchor = onetdns_dnssec::Ds::from_dnskey(&root_key, &Name::root(), 2).unwrap();

        let root_dnskey = vec![dnskey_rec(".", &root_key)];
        let root_dnskey_sig = rrsig_rec(&root_sk, &root_key, ".", 48, &root_dnskey);
        let parent_ds = vec![ds_rec("parent.test", &parent_key)];
        let parent_ds_sig = rrsig_rec(&root_sk, &root_key, ".", RecordType::DS.0, &parent_ds);
        spawn_server(&root_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                m.header.authoritative = true;
                m.answers.extend(root_dnskey.iter().cloned());
                m.answers.push(root_dnskey_sig.clone());
                return m;
            }
            m.authorities.push(Record::new(
                name("parent.test"),
                3600,
                RData::Ns(name("ns.parent.test")),
            ));
            m.authorities.extend(parent_ds.iter().cloned());
            m.authorities.push(parent_ds_sig.clone());
            m.additionals
                .push(Record::new(name("ns.parent.test"), 3600, RData::A(zone_ip)));
            m
        });

        let parent_dnskey = vec![dnskey_rec("parent.test", &parent_key)];
        let parent_dnskey_sig =
            rrsig_rec(&parent_sk, &parent_key, "parent.test", 48, &parent_dnskey);
        let child_dnskey = vec![dnskey_rec("l.parent.test", &child_key)];
        let child_dnskey_sig = rrsig_rec(&child_sk, &child_key, "l.parent.test", 48, &child_dnskey);
        let child_ns = vec![Record::new(
            name("l.parent.test"),
            3600,
            RData::Ns(name("ns.parent.test")),
        )];
        let child_ns_sig = rrsig_rec(
            &child_sk,
            &child_key,
            "l.parent.test",
            RecordType::NS.0,
            &child_ns,
        );
        let child_ds = vec![ds_rec("l.parent.test", &ds_key)];
        let child_ds_sig = rrsig_rec(
            &parent_sk,
            &parent_key,
            "parent.test",
            RecordType::DS.0,
            &child_ds,
        );
        let host = vec![Record::new(
            name("host.l.parent.test"),
            3600,
            RData::A(COHOSTED_TARGET),
        )];
        let host_sig = rrsig_rec(&child_sk, &child_key, "l.parent.test", 1, &host);
        spawn_server(&zone_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            let (records, signature): (&[Record], &Record) =
                match (q.name.to_ascii_lower().as_str(), q.qtype) {
                    ("parent.test", RecordType::DNSKEY) => (&parent_dnskey, &parent_dnskey_sig),
                    ("l.parent.test", RecordType::DNSKEY) => (&child_dnskey, &child_dnskey_sig),
                    ("l.parent.test", RecordType::NS) => {
                        m.additionals.push(Record::new(
                            name("ns.parent.test"),
                            3600,
                            RData::A(zone_ip),
                        ));
                        (&child_ns, &child_ns_sig)
                    }
                    ("l.parent.test", RecordType::DS) => (&child_ds, &child_ds_sig),
                    ("host.l.parent.test", RecordType::A) => (&host, &host_sig),
                    _ => return m,
                };
            m.answers.extend(records.iter().cloned());
            m.answers.push(signature.clone());
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), anchor)
    }

    #[test]
    /**
     * @brief 답변 절로 드러난 서명된 자식 영역의 답이 부모에게 받은 DS로 끝까지 검증되는지.
     * @details 루트, 부모, 자식 영역을 모두 실제 키로 서명한다. 자식 영역의 DS를 부모에게 따로
     *          물어 체인에 넣어야 자식 키를 믿을 수 있고, 그래야 답에 AD가 붙는다. DS 없이
     *          체인에 넣으면 자식 영역이 Insecure로 내려가 AD가 붙지 않는다.
     */
    fn a_signed_answer_zone_cut_validates_through_the_fetched_ds() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5415;
        let (root, anchor) = spawn_signed_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 54),
            Ipv4Addr::new(127, 0, 0, 55),
            PORT,
            73,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let resp = rec
            .resolve(
                &Name::from_str("host.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("서명된 자식 영역의 답을 받아야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0, "{resp:?}");
        assert!(
            resp.answers
                .iter()
                .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == COHOSTED_TARGET)),
            "최종 답을 얻지 못했습니다: {resp:?}"
        );
        assert!(
            resp.header.authentic_data,
            "부모에게 받은 DS로 자식 키를 확인해 Secure여야 합니다"
        );
    }

    #[test]
    /**
     * @brief 답변 절로 드러난 경계에서 부모가 준 DS가 자식 키와 맞지 않으면 SERVFAIL인지.
     * @details 부모의 서명은 유효하지만 DS가 다른 키를 가리킨다. 자식 영역의 DNSKEY를 믿을 수
     *          없으므로 Bogus이고, Insecure로 내려가 답을 그대로 주면 안 된다.
     */
    fn a_signed_answer_zone_cut_with_a_mismatched_ds_is_bogus() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5416;
        let (root, anchor) = spawn_signed_cohosted_zones(
            Ipv4Addr::new(127, 0, 0, 56),
            Ipv4Addr::new(127, 0, 0, 57),
            PORT,
            74,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let resp = rec
            .resolve(
                &Name::from_str("host.l.parent.test").unwrap(),
                RecordType::A,
            )
            .expect("검증 실패도 응답으로 돌아와야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0, "{resp:?}");
        assert!(!resp.header.authentic_data);
    }

    /** @brief glue 없는 위임 테스트에서 최종 이름이 가리키는 주소. */
    const GLUELESS_TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 58);

    /**
     * @brief glue 없이 네임서버 두 개로 위임하는 구성을 시작한다.
     * @details 루트는 target.test를 ns1.a.test와 ns2.b.test로 위임하되 주소를 주지 않고, 두
     *          이름의 주소는 스스로 권한 있게 답한다. 한 주소는 답하지 않는 서버, 다른 주소는
     *          답하는 서버다. 루트가 받은 질의는 이름과 타입으로 기록한다.
     * @param dead_first 참이면 ns1.a.test가 답하지 않는 서버를 가리킨다.
     * @return 루트 서버 주소와 루트가 받은 질의 기록.
     */
    fn spawn_glueless_delegation(
        ips: [Ipv4Addr; 3],
        port: u16,
        dead_first: bool,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<(String, RecordType)>>>,
    ) {
        let [root_ip, dead_ip, good_ip] = ips;
        let (first, second) = if dead_first {
            (dead_ip, good_ip)
        } else {
            (good_ip, dead_ip)
        };
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        spawn_server(&root_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let asked = q.name.to_ascii_lower();
            log.lock().unwrap().push((asked.clone(), q.qtype));
            let mut m = base(req);
            if asked.ends_with("target.test") {
                for ns in ["ns1.a.test", "ns2.b.test"] {
                    m.authorities.push(Record::new(
                        Name::from_str("target.test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str(ns).unwrap()),
                    ));
                }
                return m;
            }
            m.header.authoritative = true;
            let address = match (asked.as_str(), q.qtype) {
                ("ns1.a.test", RecordType::A) => Some(first),
                ("ns2.b.test", RecordType::A) => Some(second),
                _ => None,
            };
            if let Some(ip) = address {
                m.answers.push(Record::new(q.name, 3600, RData::A(ip)));
            }
            m
        });
        let silent = UdpSocket::bind(SocketAddr::new(IpAddr::V4(dead_ip), port)).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while silent.recv_from(&mut buf).is_ok() {}
        });
        spawn_server(&good_ip.to_string(), port, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.target.test" && q.qtype == RecordType::A {
                m.answers
                    .push(Record::new(q.name, 60, RData::A(GLUELESS_TARGET)));
            }
            m
        });
        (SocketAddr::new(IpAddr::V4(root_ip), port), seen)
    }

    /** @brief 응답에 이 테스트의 최종 주소가 있는지. */
    fn has_glueless_target(resp: &Message) -> bool {
        resp.answers
            .iter()
            .any(|record| matches!(&record.rdata, RData::A(ip) if *ip == GLUELESS_TARGET))
    }

    #[test]
    /**
     * @brief glue 없는 네임서버의 주소를 쓸 수 있는 것이 생기면 그만 푸는지.
     * @details 이름을 전부 풀면 느린 서버 하나가 남은 시간을 모두 가져가, 주소를 쥐고도 정작 그
     *          영역에는 묻지 못한다. 첫 이름이 답하는 서버를 가리키면 둘째 이름은 묻지 않아야 한다.
     */
    fn glueless_nameserver_lookup_stops_at_the_first_usable_address() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5417;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 58),
                Ipv4Addr::new(127, 0, 0, 59),
                Ipv4Addr::new(127, 0, 0, 61),
            ],
            PORT,
            false,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.target.test").unwrap(), RecordType::A)
            .expect("첫 네임서버로 답을 받아야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|(name, _)| name == "ns2.b.test"),
            "쓸 수 있는 주소가 있는데 다음 네임서버 이름까지 풀었습니다"
        );
    }

    #[test]
    /**
     * @brief 먼저 푼 네임서버가 답하지 않으면 남겨 둔 이름을 풀어 다시 묻는지.
     * @details 서버당 시간은 남겨 둔 이름 몫까지 나눈다. 받은 주소 하나로 시간을 다 쓰면 둘째
     *          이름으로 넘어갈 시간이 남지 않는다.
     */
    fn glueless_nameserver_lookup_resolves_the_next_name_when_the_first_is_dead() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5418;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 68),
                Ipv4Addr::new(127, 0, 0, 69),
                Ipv4Addr::new(127, 0, 0, 72),
            ],
            PORT,
            true,
        );
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback();
        let resp = rec
            .resolve(&Name::from_str("host.target.test").unwrap(), RecordType::A)
            .expect("둘째 네임서버로 넘어가 답을 받아야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert_eq!(
            seen.lock()
                .unwrap()
                .iter()
                .filter(|(name, qtype)| name == "ns2.b.test" && *qtype == RecordType::A)
                .count(),
            1
        );
    }

    #[test]
    /**
     * @brief 네임서버 주소를 풀 때는 검증하지 않는지.
     * @details 주소는 어디로 보낼지만 정하고 답은 체인으로 따로 검증한다. 이 해석을 검증하면
     *          결과는 쓰지 않으면서 DNSKEY를 가져오느라 시간만 쓴다. 최종 답은 검증하지 않고
     *          반복만 돌리므로, 루트가 DNSKEY 질의를 받았다면 주소 풀기가 보낸 것이다.
     */
    fn glueless_nameserver_lookup_does_not_validate() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5419;
        let (root, seen) = spawn_glueless_delegation(
            [
                Ipv4Addr::new(127, 0, 0, 75),
                Ipv4Addr::new(127, 0, 0, 76),
                Ipv4Addr::new(127, 0, 0, 77),
            ],
            PORT,
            false,
        );
        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_secs(3))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);
        let mut budget = Budget {
            ns_resolves: rec.max_ns_resolves,
            queries: MAX_TOTAL_QUERIES,
            deadline: rec.query_deadline(),
        };
        let qname = Name::from_str("host.target.test").unwrap();
        let (resp, _) = rec
            .iterate_from(
                &qname,
                RecordType::A,
                &mut budget,
                Name::root(),
                vec![root],
                true,
            )
            .expect("주소를 풀어 내려가야 합니다");
        assert!(has_glueless_target(&resp), "{resp:?}");
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|(_, qtype)| matches!(*qtype, RecordType::DNSKEY | RecordType::DS)),
            "네임서버 주소를 푸는 해석이 검증하려고 키를 물었습니다: {:?}",
            seen.lock().unwrap()
        );
    }

    #[test]
    /**
     * @brief 느린 서버의 답을 기다리는 동안 다음 서버에도 물어 먼저 온 답을 쓰는지.
     * @details 첫 서버는 처음 보는 서버라 UNKNOWN_SERVER_PATIENCE만큼 기다린 뒤 둘째 서버에도
     *          묻는다. 첫 서버를 끝까지 기다리면 그 서버의 지연만큼 늦고, 버리고 넘어가면 곧 올
     *          답을 잃는다. 늦은 서버는 기다린 시간 이상으로 왕복 시간이 기록되어 다음에는
     *          뒤로 간다.
     */
    fn a_slow_server_is_raced_by_the_next_one() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5420;
        /** @brief 느린 서버가 답을 미루는 시간. 서버당 제한 시간보다 짧아야 한다. */
        const SLOW_DELAY: Duration = Duration::from_millis(1500);
        let answer = |ip: Ipv4Addr| {
            move |req: &Message| {
                let mut m = base(req);
                m.header.authoritative = true;
                let q = req.questions.first().unwrap().clone();
                m.answers.push(Record::new(q.name, 60, RData::A(ip)));
                m
            }
        };
        let slow_ip = Ipv4Addr::new(127, 0, 0, 78);
        let fast_ip = Ipv4Addr::new(127, 0, 0, 79);
        let slow = spawn_server(&slow_ip.to_string(), PORT, {
            let respond = answer(slow_ip);
            move |req: &Message| {
                std::thread::sleep(SLOW_DELAY);
                respond(req)
            }
        });
        let fast = spawn_server(&fast_ip.to_string(), PORT, answer(fast_ip));

        let rec = Recursor::new(vec![], Duration::from_secs(4)).with_test_loopback();
        let zone = Name::from_str("race.test").unwrap();
        let query = make_query(
            &Name::from_str("host.race.test").unwrap(),
            RecordType::A,
            false,
        );
        let started = Instant::now();
        let resp = rec
            .query_any(&[slow, fast], &query, &zone, rec.query_deadline())
            .expect("둘째 서버의 답을 받아야 합니다");
        let elapsed = started.elapsed();

        assert!(
            matches!(resp.answers.first().map(|r| &r.rdata), Some(RData::A(ip)) if *ip == fast_ip),
            "{resp:?}"
        );
        assert!(
            elapsed >= UNKNOWN_SERVER_PATIENCE && elapsed < SLOW_DELAY,
            "둘째 서버에 물은 시점이 기대와 다릅니다: {elapsed:?}"
        );
        assert!(
            rec.srtt(slow.ip())
                .is_some_and(|ms| u128::from(ms) >= UNKNOWN_SERVER_PATIENCE.as_millis()),
            "답을 기다리다 만 서버의 왕복 시간이 기록되지 않았습니다"
        );
        assert_eq!(rec.order_by_infra(&[slow, fast], &zone), vec![fast, slow]);
    }

    #[test]
    /**
     * @brief 아무 서버도 답하지 않아 실패한 해석을 뒤에서 마저 돌려 캐시를 채우는지.
     * @details 루트는 첫 질의에만 답하지 않는다. 클라이언트에게는 실패가 나가지만, 뒤에서 다시
     *          돌린 해석이 자식 zone의 위임을 캐시에 남겨 다음 질의는 루트부터 걷지 않는다.
     */
    fn an_unanswered_resolution_is_finished_in_the_background() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5421;
        let root_ip = Ipv4Addr::new(127, 0, 0, 86);
        let child_ip = Ipv4Addr::new(127, 0, 0, 87);
        let root_sock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(root_ip), PORT)).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut first = true;
            while let Ok((n, from)) = root_sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                if std::mem::take(&mut first) {
                    continue;
                }
                let asked = req.questions.first().unwrap().name.to_ascii_lower();
                let resp = if asked.ends_with("bg.test") {
                    referral(&req, "bg.test", "ns.bg.test", child_ip)
                } else {
                    let mut m = base(&req);
                    m.header.authoritative = true;
                    m
                };
                let _ = root_sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        spawn_server(&child_ip.to_string(), PORT, move |req| {
            a_answer(req, Ipv4Addr::new(192, 0, 2, 86))
        });

        let rec = Arc::new(
            Recursor::new(
                vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
                Duration::from_millis(500),
            )
            .with_port(PORT)
            .with_test_loopback(),
        );
        let qname = Name::from_str("host.bg.test").unwrap();
        assert!(
            rec.resolve_with_ns_cd(&qname, RecordType::A, false)
                .is_err(),
            "루트가 첫 질의에 답하지 않았으니 이 해석은 실패해야 합니다"
        );

        let zone = Name::from_str("bg.test").unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while rec.deleg_cached(&zone).is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            rec.deleg_cached(&zone).is_some(),
            "뒤에서 마저 돌린 해석이 위임을 캐시에 남기지 않았습니다"
        );
    }

    #[test]
    /**
     * @brief 검증하지 않아도 DO=1로 묻는 질의자에게 서명을 줄 수 있는지.
     *
     * @details 업스트림에 DO를 설정하지 않으면 서명을 애초에 받아 오지 못한다. 그러면 이 서버의 뒤에
     *          선 검증하는 스텁이나, 이 서버를 업스트림으로 삼아 검증하는 전달기가 아무것도 확인하지
     *          못한다. 여기서 실행한 가짜 권한 서버는 DO가 켜졌을 때만 서명을 담는다.
     *          언제나 싣게 하면 이 서버가 DO를 세우는지 아닌지를 이 테스트가 구분하지 못한다.
     * @warning 트러스트 앵커가 없는 리졸버다. 검증은 하지 않고 서명만 전달한다.
     */
    fn a_non_validating_recursor_still_carries_signatures_for_do_clients() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5404;
        let (sk_root, k_root) = ecdsa_key(21);
        let (sk_zone, k_zone) = ecdsa_key(22);

        let zone_owner = Name::from_str("signed").unwrap();
        let zone_ds = onetdns_dnssec::Ds::from_dnskey(&k_zone, &zone_owner, 2).unwrap();
        let zone_ds_rec = Record::new(zone_owner, 3600, RData::Unknown(43, zone_ds.rdata_bytes()));

        /** @brief 이 질의가 DNSSEC 레코드를 함께 달라고 했는지. */
        fn asked_for_dnssec(request: &Message) -> bool {
            request
                .opt()
                .and_then(Edns::from_record)
                .is_some_and(|edns| edns.dnssec_ok)
        }

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = zone_ds_rec.clone();
            spawn_server("127.0.0.34", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let signed = asked_for_dnssec(req);
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    if signed {
                        let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                        m.answers.push(dk);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(dk);
                    }
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("signed").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.signed").unwrap()),
                    ));
                    if signed {
                        m.authorities.push(ds_rec.clone());
                        m.authorities.push(rrsig_rec(
                            &sk,
                            &k,
                            ".",
                            RecordType::DS.0,
                            &[ds_rec.clone()],
                        ));
                    }
                    m.additionals.push(Record::new(
                        Name::from_str("ns.signed").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 35)),
                    ));
                }
                m
            });
        }

        {
            let (sk, k) = (sk_zone.clone(), k_zone.clone());
            spawn_server("127.0.0.35", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let signed = asked_for_dnssec(req);
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "signed" {
                    let dk = dnskey_rec("signed", &k);
                    if signed {
                        let sig = rrsig_rec(&sk, &k, "signed", RecordType::DNSKEY.0, &[dk.clone()]);
                        m.answers.push(dk);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(dk);
                    }
                } else if q.name.to_ascii_lower() == "www.signed" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("www.signed").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 21)),
                    );
                    if signed {
                        let sig = rrsig_rec(&sk, &k, "signed", RecordType::A.0, &[a.clone()]);
                        m.answers.push(a);
                        m.answers.push(sig);
                    } else {
                        m.answers.push(a);
                    }
                }
                m
            });
        }

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 34)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback();
        assert!(
            !rec.is_validating(),
            "이 테스트는 검증하지 않는 리졸버를 전제로 합니다"
        );

        let resp = rec
            .resolve(&Name::from_str("www.signed").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(
            resp.answers.iter().any(
                |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 21))
            ),
            "답 자체가 없습니다"
        );
        assert!(
            resp.answers
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG),
            "검증하지 않는다는 이유로 업스트림에 DO를 설정하지 않아 서명을 받아 오지 못했습니다"
        );
        assert!(
            !resp.header.authentic_data,
            "검증하지 않았으므로 AD를 설정하면 안 됩니다"
        );
    }

    #[test]
    /** @brief 정상 체인은 AD를 설정하고 깨진 체인은 SERVFAIL이 되는지. */
    fn dnssec_secure_chain_sets_ad_and_bogus_servfails() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5400;
        let (sk_root, k_root) = ecdsa_key(11);
        let (sk_test, k_test) = ecdsa_key(12);

        let root_owner = Name::from_str(".").unwrap();
        let test_owner = Name::from_str("test").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let test_ds = onetdns_dnssec::Ds::from_dnskey(&k_test, &test_owner, 2).unwrap();
        let test_ds_rec = Record::new(test_owner, 3600, RData::Unknown(43, test_ds.rdata_bytes()));

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let ds_rec = test_ds_rec.clone();
            spawn_server("127.0.0.30", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.test").unwrap()),
                    ));
                    m.authorities.push(ds_rec.clone());
                    m.authorities.push(rrsig_rec(
                        &sk,
                        &k,
                        ".",
                        RecordType::DS.0,
                        &[ds_rec.clone()],
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 31)),
                    ));
                }
                m
            });
        }

        {
            let (sk, k) = (sk_test.clone(), k_test.clone());
            spawn_server("127.0.0.31", PORT, move |req| {
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                m.header.authoritative = true;
                if q.qtype == RecordType::DNSKEY && q.name.to_ascii_lower() == "test" {
                    let dk = dnskey_rec("test", &k);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" && q.qtype == RecordType::A {
                    let a = Record::new(
                        Name::from_str("host.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(10, 0, 0, 9)),
                    );
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::A.0, &[a.clone()]);
                    m.answers.push(a);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "alias.test" {
                    let cn = Record::new(
                        Name::from_str("alias.test").unwrap(),
                        3600,
                        RData::Cname(Name::from_str("host.test").unwrap()),
                    );
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::CNAME.0, &[cn.clone()]);
                    m.answers.push(cn);
                    m.answers.push(sig);
                } else if q.name.to_ascii_lower() == "host.test" {
                    let soa = Record::new(
                        Name::from_str("test").unwrap(),
                        3600,
                        RData::soa(onetdns_proto::Soa {
                            mname: Name::from_str("ns.test").unwrap(),
                            rname: Name::from_str("hostmaster.test").unwrap(),
                            serial: 1,
                            refresh: 3600,
                            retry: 600,
                            expire: 86_400,
                            minimum: 300,
                        }),
                    );
                    let soa_sig = rrsig_rec(&sk, &k, "test", RecordType::SOA.0, &[soa.clone()]);
                    let ns = nsec_rec("host.test", "z.test", &[1, 46, 47]);
                    let sig = rrsig_rec(&sk, &k, "test", RecordType::NSEC.0, &[ns.clone()]);
                    m.authorities.push(soa);
                    m.authorities.push(soa_sig);
                    m.authorities.push(ns);
                    m.authorities.push(sig);
                }
                m
            });
        }

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 30)), PORT);

        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor.clone()]);
        let resp = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
        assert!(resp.header.authentic_data, "검증된 답은 AD=1");
        assert_eq!(
            resp.answers
                .iter()
                .filter(|r| r.rtype == RecordType::A)
                .count(),
            1
        );

        let nodata = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("NODATA 해석");
        assert_eq!(nodata.header.rcode, ResponseCode::NoError.0);
        assert!(nodata.answers.is_empty());
        assert!(nodata.header.authentic_data, "보안 NODATA는 AD=1");

        let cname = rec
            .resolve(&Name::from_str("alias.test").unwrap(), RecordType::A)
            .expect("CNAME 체인 해석");
        assert_eq!(cname.header.rcode, ResponseCode::NoError.0);
        assert!(
            cname
                .answers
                .iter()
                .any(|r| matches!(r.rdata, RData::Cname(_))),
            "CNAME 레코드 포함"
        );
        assert!(
            cname
                .answers
                .iter()
                .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 9))),
            "최종 A 레코드 포함"
        );
        assert!(
            cname.header.authentic_data,
            "전부 secure한 CNAME 체인은 AD=1"
        );
        assert!(cname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("alias.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::CNAME.0)
        }));
        assert!(cname.answers.iter().any(|record| {
            record
                .name
                .eq_ignore_case(&Name::from_str("host.test").unwrap())
                && onetdns_dnssec::Rrsig::from_record(record)
                    .is_some_and(|signature| signature.type_covered == RecordType::A.0)
        }));

        let wrong_anchor =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_bad = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![wrong_anchor]);
        let resp2 = rec_bad
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("해석 시도");
        assert_eq!(
            resp2.header.rcode,
            ResponseCode::ServFail.0,
            "bogus는 SERVFAIL"
        );
        assert!(!resp2.header.authentic_data);

        let opt = resp2.opt().expect("bogus 응답에 OPT");
        let (code, _) = Edns::from_record(opt).unwrap().ede().expect("EDE");
        assert_eq!(code, ede_code::DNSSEC_BOGUS);

        let bogus_nodata = rec_bad
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("bogus NODATA도 DNS 응답으로 반환");
        assert_eq!(
            bogus_nodata.header.rcode,
            ResponseCode::ServFail.0,
            "DNSSEC 음성 증명 실패도 strict 플래그와 무관하게 fail-closed"
        );
        assert!(!bogus_nodata.header.authentic_data);

        let bad_anchor2 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_perm = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![bad_anchor2])
            .with_dnssec_permissive(true);
        let resp_perm = rec_perm
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("permissive 해석");
        assert_eq!(
            resp_perm.header.rcode,
            ResponseCode::NoError.0,
            "permissive: bogus여도 SERVFAIL 아님"
        );
        assert!(!resp_perm.header.authentic_data, "permissive: AD=0");
        assert!(
            resp_perm
                .answers
                .iter()
                .any(|r| matches!(r.rdata, RData::A(_))),
            "permissive: 데이터 반환"
        );
        let permissive_nodata = rec_perm
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::AAAA)
            .expect("permissive NODATA");
        assert_eq!(permissive_nodata.header.rcode, ResponseCode::NoError.0);
        assert!(!permissive_nodata.header.authentic_data);

        let bad3 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_cd = Arc::new(
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_trust_anchors(vec![bad3])
                .with_ignore_cd(false),
        );
        let n = Name::from_str("host.test").unwrap();

        let r_cd1 = rec_cd
            .resolve_with_ns_cd(&n, RecordType::A, true)
            .expect("cd 해석")
            .0;
        assert_eq!(
            r_cd1.header.rcode,
            ResponseCode::NoError.0,
            "CD honor: 데이터"
        );
        assert!(!r_cd1.header.authentic_data, "CD honor: AD=0");

        let r_cd0 = rec_cd
            .resolve_with_ns_cd(&n, RecordType::A, false)
            .expect("cd0 해석")
            .0;
        assert_eq!(
            r_cd0.header.rcode,
            ResponseCode::ServFail.0,
            "CD=0: bogus SERVFAIL"
        );

        let bad4 =
            onetdns_dnssec::Ds::from_dnskey(&k_test, &Name::from_str(".").unwrap(), 2).unwrap();
        let rec_ign = Arc::new(
            Recursor::new(vec![root_server], Duration::from_secs(2))
                .with_port(PORT)
                .with_test_loopback()
                .with_trust_anchors(vec![bad4]),
        );
        let r_ign = rec_ign
            .resolve_with_ns_cd(&n, RecordType::A, true)
            .expect("ign 해석")
            .0;
        assert_eq!(
            r_ign.header.rcode,
            ResponseCode::ServFail.0,
            "ignore_cd=true: CD 무시 SERVFAIL"
        );
    }

    #[test]
    /**
     * @brief 서명 없는 위임은 Insecure다. SERVFAIL로 만들면 서명하지 않은 정상 도메인이 전부 죽는다.
     * @details 그 판정은 캐시에 남아야 한다. 남지 않으면 같은 영역의 다음 질의가 캐시된
     *          위임에서 시작하지 못하고 매번 루트부터 다시 걷는다.
     */
    fn unsigned_delegation_is_insecure_not_servfail() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5402;
        let (sk_root, k_root) = ecdsa_key(21);
        let root_owner = Name::from_str(".").unwrap();
        let root_anchor = onetdns_dnssec::Ds::from_dnskey(&k_root, &root_owner, 2).unwrap();
        let root_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        {
            let (sk, k) = (sk_root.clone(), k_root.clone());
            let root_queries = root_queries.clone();
            spawn_server("127.0.0.40", PORT, move |req| {
                root_queries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let q = req.questions.first().unwrap().clone();
                let mut m = base(req);
                if q.qtype == RecordType::DNSKEY && q.name.is_root() {
                    m.header.authoritative = true;
                    let dk = dnskey_rec(".", &k);
                    let sig = rrsig_rec(&sk, &k, ".", RecordType::DNSKEY.0, &[dk.clone()]);
                    m.answers.push(dk);
                    m.answers.push(sig);
                } else {
                    m.authorities.push(Record::new(
                        Name::from_str("insecure.test").unwrap(),
                        3600,
                        RData::Ns(Name::from_str("ns.insecure.test").unwrap()),
                    ));
                    m.additionals.push(Record::new(
                        Name::from_str("ns.insecure.test").unwrap(),
                        3600,
                        RData::A(Ipv4Addr::new(127, 0, 0, 41)),
                    ));
                }
                m
            });
        }

        spawn_server("127.0.0.41", PORT, move |req| {
            let q = req.questions.first().unwrap().clone();
            let mut m = base(req);
            m.header.authoritative = true;
            if q.name.to_ascii_lower() == "host.insecure.test" && q.qtype == RecordType::A {
                m.answers.push(Record::new(
                    Name::from_str("host.insecure.test").unwrap(),
                    3600,
                    RData::A(Ipv4Addr::new(203, 0, 113, 5)),
                ));
            } else {
                m.authorities.push(Record::new(
                    Name::from_str("insecure.test").unwrap(),
                    300,
                    RData::soa(onetdns_proto::Soa {
                        mname: Name::from_str("ns.insecure.test").unwrap(),
                        rname: Name::from_str("hostmaster.insecure.test").unwrap(),
                        serial: 1,
                        refresh: 300,
                        retry: 60,
                        expire: 3600,
                        minimum: 60,
                    }),
                ));
            }
            m
        });

        let root_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 40)), PORT);
        let rec = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor.clone()]);
        let resp = rec
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::A,
            )
            .expect("비서명 영역도 해석 성공해야 함");
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "비서명 답은 SERVFAIL 아님"
        );
        assert!(!resp.header.authentic_data, "비서명 = AD=0");
        assert!(
            resp.answers
                .iter()
                .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(203, 0, 113, 5))),
            "비서명 A 답이 그대로 전달됨"
        );
        let insecure_zone = Name::from_str("insecure.test").unwrap();
        assert!(
            matches!(
                rec.validated_keys_cached(
                    &insecure_zone.canonical_key(),
                    &rec.trust_anchors.load()
                ),
                Some(ZoneTrust::Insecure)
            ),
            "서명 없는 영역이라는 판정이 캐시에 남아야 함"
        );
        assert!(rec.validated_start_ok(&insecure_zone));
        let root_before = root_queries.load(std::sync::atomic::Ordering::SeqCst);
        let nodata = rec
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::AAAA,
            )
            .expect("비서명 영역의 NODATA도 허용");
        assert_eq!(nodata.header.rcode, ResponseCode::NoError.0);
        assert!(!nodata.header.authentic_data);
        assert_eq!(
            root_queries.load(std::sync::atomic::Ordering::SeqCst),
            root_before,
            "같은 비서명 영역의 다음 질의는 루트로 다시 가지 않아야 함"
        );

        let strict = Recursor::new(vec![root_server], Duration::from_secs(2))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![root_anchor])
            .with_dnssec_strict(true);
        let stripped_ds = strict
            .resolve(
                &Name::from_str("host.insecure.test").unwrap(),
                RecordType::A,
            )
            .expect("DS 부재 증명 실패는 SERVFAIL 응답");
        assert_eq!(stripped_ds.header.rcode, ResponseCode::ServFail.0);
    }

    #[test]
    /** @brief 루트에서 TLD를 거쳐 권한 서버까지 실제로 걸어가는지. */
    fn iterative_walk_root_tld_auth() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5388;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);

        spawn_server("127.0.0.3", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });

        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });

        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    /** @brief 검증하지 않을 때 업스트림의 AD 비트를 걷어내는지. 흘리면 검증하지 않은 답이 검증된 것처럼 나간다. */
    fn non_validating_recursor_strips_upstream_ad_bit() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5399;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);

        spawn_server("127.0.0.3", PORT, move |req| {
            let mut m = a_answer(req, Ipv4Addr::new(6, 6, 6, 6));
            m.header.authentic_data = true;
            m
        });
        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        assert!(
            !resp.header.authentic_data,
            "비검증 recursor는 업스트림 AD=1을 제거해야 함"
        );
    }

    #[test]
    /** @brief 거쳐 온 네임서버가 함께 모이는지. */
    fn resolve_with_ns_collects_delegation() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5393;
        let root_ip = Ipv4Addr::new(127, 0, 0, 1);
        let com_ip = Ipv4Addr::new(127, 0, 0, 2);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 3);
        spawn_server("127.0.0.3", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });
        spawn_server("127.0.0.2", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.1", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let (resp, ns) = rec
            .resolve_with_ns(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);
        let names: Vec<String> = ns.names.iter().map(|n| n.to_ascii_lower()).collect();
        assert!(
            names.iter().any(|n| n == "ns.com"),
            "NS 이름에 ns.com: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "ns.example.com"),
            "NS 이름에 ns.example.com: {names:?}"
        );
        assert!(
            ns.ips.contains(&IpAddr::V4(com_ip)),
            "NS IP에 com 글루: {:?}",
            ns.ips
        );
        assert!(
            ns.ips.contains(&IpAddr::V4(auth_ip)),
            "NS IP에 auth 글루: {:?}",
            ns.ips
        );
    }

    #[test]
    /** @brief CNAME 체인을 끝까지 따라가는지. */
    fn follows_cname_chain() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5389;
        let auth_ip = Ipv4Addr::new(127, 0, 0, 5);

        spawn_server("127.0.0.5", PORT, move |req| {
            let mut m = base(req);
            m.header.authoritative = true;
            let q = req.questions.first().unwrap();
            let qn = q.name.to_ascii_lower();
            if qn == "alias.test" {
                m.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::Cname(Name::from_str("real.test").unwrap()),
                ));
            } else if qn == "real.test" {
                m.answers.push(Record::new(
                    q.name.clone(),
                    300,
                    RData::A(Ipv4Addr::new(10, 0, 0, 7)),
                ));
            }
            m
        });

        spawn_server("127.0.0.4", PORT, move |req| {
            referral(req, "test", "ns.test", auth_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)),
                PORT,
            )],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(&Name::from_str("alias.test").unwrap(), RecordType::A)
            .expect("CNAME 추적 성공");

        assert!(resp
            .answers
            .iter()
            .any(|r| matches!(r.rdata, RData::Cname(_))));
        assert!(resp
            .answers
            .iter()
            .any(|r| matches!(&r.rdata, RData::A(ip) if *ip == Ipv4Addr::new(10, 0, 0, 7))));
    }

    #[test]
    /** @brief 최소화가 경로상의 서버에게 전체 이름을 감추는지. */
    fn qname_minimization_hides_full_name() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5391;
        let com_ip = Ipv4Addr::new(127, 0, 0, 21);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 22);
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        spawn_server("127.0.0.22", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(5, 5, 5, 5))
        });

        spawn_server("127.0.0.21", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });

        let seen2 = seen.clone();
        spawn_server("127.0.0.20", PORT, move |req| {
            if let Some(q) = req.questions.first() {
                seen2.lock().unwrap().push(q.name.to_ascii_lower());
            }
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 20)),
                PORT,
            )],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();

        let resp = rec
            .resolve(
                &Name::from_str("secret.www.example.com").unwrap(),
                RecordType::A,
            )
            .expect("해석 성공");
        assert_eq!(resp.answers.len(), 1);

        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "루트가 적어도 한 번 질의받아야");
        for name in seen.iter() {
            assert_eq!(name, "com", "루트가 최소화된 이름만 봐야: {name}");
        }
    }

    #[test]
    /** @brief 루트 목록이 비면 오류가 나는지. */
    fn no_roots_errors() {
        let rec = Recursor::new(vec![], Duration::from_secs(1));
        assert!(matches!(
            rec.resolve(&Name::from_str("x.com").unwrap(), RecordType::A),
            Err(RecurseError::NoRoots)
        ));
    }

    #[test]
    /** @brief 부모 zone 안의 형제 glue는 받아들이는지. */
    fn parent_bailiwick_accepts_valid_sibling_glue() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5395;
        let root_ip = Ipv4Addr::new(127, 0, 0, 30);
        let com_ip = Ipv4Addr::new(127, 0, 0, 31);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 32);

        spawn_server("127.0.0.32", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(93, 184, 216, 34))
        });
        spawn_server("127.0.0.31", PORT, move |req| {
            referral(req, "example.com", "ns.example.com", auth_ip)
        });
        spawn_server("127.0.0.30", PORT, move |req| {
            referral(req, "com", "a.gtld.test", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(2),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("www.example.com").unwrap(), RecordType::A)
            .expect("sibling glue를 사용해 해석 성공");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(93, 184, 216, 34))
        ));
    }

    #[test]
    /** @brief zone 밖 glue를 거부하는지. 받으면 위임 하나로 임의의 주소를 심을 수 있다. */
    fn bailiwick_rejects_out_of_zone_glue() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5390;
        let com_ip = Ipv4Addr::new(127, 0, 0, 11);

        spawn_server("127.0.0.11", PORT, move |req| {
            let mut m = base(req);
            m.authorities.push(Record::new(
                Name::from_str("victim.com").unwrap(),
                172800,
                RData::Ns(Name::from_str("ns.evil.org").unwrap()),
            ));
            m.additionals.push(Record::new(
                Name::from_str("ns.evil.org").unwrap(),
                172800,
                RData::A(Ipv4Addr::new(127, 0, 0, 99)),
            ));
            m
        });

        spawn_server("127.0.0.10", PORT, move |req| {
            referral(req, "com", "ns.com", com_ip)
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)),
                PORT,
            )],
            Duration::from_millis(500),
        )
        .with_port(PORT)
        .with_test_loopback();

        let r = rec.resolve(&Name::from_str("www.victim.com").unwrap(), RecordType::A);
        assert!(
            matches!(r, Err(RecurseError::NoReachableNs)),
            "존 밖 글루 거부 → NoReachableNs, got {r:?}"
        );
    }

    #[test]
    /** @brief 부수 질의가 실제로 답에 이어진 주소만 캐시하는지. */
    fn ns_side_query_caches_only_reachable_answer_chain_addresses() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5403;
        let root_ip = Ipv4Addr::new(127, 0, 0, 70);
        let example_ip = Ipv4Addr::new(127, 0, 0, 71);
        let attacker_ip = Ipv4Addr::new(127, 0, 0, 73);
        let auth_ip = Ipv4Addr::new(127, 0, 0, 74);
        let attacker_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = attacker_hits.clone();

        spawn_server("127.0.0.73", PORT, move |req| {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(6, 6, 6, 6))
        });
        spawn_server("127.0.0.74", PORT, move |req| {
            a_answer(req, Ipv4Addr::new(1, 2, 3, 4))
        });
        spawn_server("127.0.0.71", PORT, move |req| {
            let question = req.questions.first().unwrap();
            let mut response = base(req);
            response.header.authoritative = true;
            if question
                .name
                .eq_ignore_case(&Name::from_str("ns.example").unwrap())
            {
                response.answers.push(Record::new(
                    question.name.clone(),
                    300,
                    RData::Cname(Name::from_str("real.example").unwrap()),
                ));
            } else {
                response
                    .answers
                    .push(Record::new(question.name.clone(), 300, RData::A(auth_ip)));
            }
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(attacker_ip),
            ));
            response
        });
        spawn_server("127.0.0.70", PORT, move |req| {
            let question = req.questions.first().unwrap();
            if question
                .name
                .eq_ignore_case(&Name::from_str("test").unwrap())
            {
                let mut response = base(req);
                response.header.authoritative = false;
                response.authorities.push(Record::new(
                    Name::from_str("test").unwrap(),
                    300,
                    RData::Ns(Name::from_str("ns.example").unwrap()),
                ));
                response
            } else {
                referral(req, "example", "ns.example", example_ip)
            }
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_secs(1),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim.test").unwrap(), RecordType::A)
            .expect("glue 없는 NS를 안전하게 side-resolve");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert_eq!(
            rec.ns_addr_cached(&name_key("ns.example")),
            Some(vec![IpAddr::V4(auth_ip)])
        );
        assert_eq!(
            attacker_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "NS side-query의 무관한 A로 연결하면 안 됨"
        );
    }

    #[test]
    /** @brief 무관한 긍정 응답을 최종 답으로 보지 않는지. */
    fn unrelated_positive_answer_is_not_terminal() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5396;
        let root_ip = Ipv4Addr::new(127, 0, 0, 60);
        spawn_server("127.0.0.60", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(127, 0, 0, 61)),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "무관한 A 레코드는 최종 답이 아니어야 함: {result:?}"
        );
    }

    #[test]
    /** @brief 최종 응답에서 무관한 절을 걷어내는지. 남기면 캐시 오염이 된다. */
    fn terminal_response_strips_unrelated_sections() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5399;
        let root_ip = Ipv4Addr::new(127, 0, 0, 65);
        spawn_server("127.0.0.65", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                req.questions[0].name.clone(),
                300,
                RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response.authorities.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                3600,
                RData::Ns(Name::from_str("ns.attacker.invalid").unwrap()),
            ));
            response.additionals.push(Record::new(
                Name::from_str("ns.attacker.invalid").unwrap(),
                3600,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim").unwrap(), RecordType::A)
            .expect("관련 A는 반환되어야 함");
        assert_eq!(response.answers.len(), 1);
        assert!(response.answers[0]
            .name
            .eq_ignore_case(&Name::from_str("victim").unwrap()));
        assert!(response.authorities.is_empty());
        assert!(response.additionals.is_empty());
    }

    #[test]
    /** @brief 망가진 응답을 받으면 다음 서버로 넘어가는지. */
    fn malformed_authority_response_fails_over_to_next_server() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5401;
        let bad_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let good_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let bad_count = bad_hits.clone();
        let good_count = good_hits.clone();
        let bad = spawn_server("127.0.0.66", PORT, move |req| {
            bad_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut response = base(req);
            response.header.authoritative = true;
            response.answers.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                300,
                RData::A(Ipv4Addr::new(6, 6, 6, 6)),
            ));
            response
        });
        let good = spawn_server("127.0.0.67", PORT, move |req| {
            good_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(1, 2, 3, 4))
        });

        let rec = Recursor::new(vec![bad, good], Duration::from_millis(600))
            .with_port(PORT)
            .with_test_loopback();
        let response = rec
            .resolve(&Name::from_str("victim").unwrap(), RecordType::A)
            .expect("두 번째 권한 서버로 failover");
        assert!(response.answers.iter().any(
            |record| matches!(&record.rdata, RData::A(ip) if *ip == Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert_eq!(bad_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(good_hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    /** @brief 무관한 SOA로 NXDOMAIN을 증명하지 못하는지. */
    fn unrelated_soa_cannot_prove_nxdomain() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5397;
        let root_ip = Ipv4Addr::new(127, 0, 0, 62);
        spawn_server("127.0.0.62", PORT, move |req| {
            let mut response = base(req);
            response.header.authoritative = true;
            response.header.rcode = ResponseCode::NXDomain.0;
            response.authorities.push(Record::new(
                Name::from_str("attacker.invalid").unwrap(),
                300,
                RData::soa(onetdns_proto::Soa {
                    mname: Name::from_str("ns.attacker.invalid").unwrap(),
                    rname: Name::from_str("hostmaster.attacker.invalid").unwrap(),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 3600,
                    minimum: 60,
                }),
            ));
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "무관한 SOA는 NXDOMAIN을 증명하지 못해야 함: {result:?}"
        );
    }

    #[test]
    /** @brief SERVFAIL 응답의 NS가 위임 캐시에 심어지지 못하는지. */
    fn servfail_authority_ns_cannot_seed_delegation_cache() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5398;
        let root_ip = Ipv4Addr::new(127, 0, 0, 63);
        let attacker_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = attacker_hits.clone();
        spawn_server("127.0.0.64", PORT, move |req| {
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            a_answer(req, Ipv4Addr::new(6, 6, 6, 6))
        });
        spawn_server("127.0.0.63", PORT, move |req| {
            let mut response = referral(req, "test", "ns.test", Ipv4Addr::new(127, 0, 0, 64));
            response.header.rcode = ResponseCode::ServFail.0;
            response
        });

        let rec = Recursor::new(
            vec![SocketAddr::new(IpAddr::V4(root_ip), PORT)],
            Duration::from_millis(300),
        )
        .with_port(PORT)
        .with_test_loopback();
        let result = rec.resolve(&Name::from_str("victim.test").unwrap(), RecordType::A);
        assert!(
            matches!(result, Err(RecurseError::NoReachableNs)),
            "SERVFAIL의 NS는 referral이 아니어야 함: {result:?}"
        );
        assert_eq!(
            attacker_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "공격자 NS로 질의하면 안 됨"
        );
        assert!(
            rec.deleg_cached(&Name::from_str("test").unwrap()).is_none(),
            "SERVFAIL referral은 위임 캐시에 들어가면 안 됨"
        );
    }

    #[test]
    /**
     * @brief NSEC3 반복이 상한을 넘어 거부할 때 그 사유로 알리는지.
     *
     * @details RFC 9276은 반복이 많은 NSEC3 때문에 insecure나 SERVFAIL을 낼 때 EDE 27을
     *          실으라고 한다. 서명이 깨진 것(EDE 6)과 이 서버가 계산을 거부한 것은 운영자가
     *          할 일이 다르다. 앞은 영역이 망가진 것이고 뒤는 매개변수를 낮춰야 하는 것이다.
     * @note 두 사유가 같은 SERVFAIL 로 합쳐지므로 rcode 만 보는 테스트로는 갈라지지 않는다.
     */
    fn excessive_nsec3_iterations_report_their_own_ede() {
        let plain = bogus_servfail(
            &make_query(
                &Name::from_str("bogus.example").unwrap(),
                RecordType::A,
                false,
            ),
            ede_code::DNSSEC_BOGUS,
        );
        let excessive = bogus_servfail(
            &make_query(
                &Name::from_str("bogus.example").unwrap(),
                RecordType::A,
                false,
            ),
            ede_code::UNSUPPORTED_NSEC3_ITERATIONS,
        );

        let ede_of = |msg: &Message| {
            Edns::from_record(msg.opt().expect("OPT"))
                .expect("EDNS")
                .ede()
                .expect("EDE")
        };
        assert_eq!(ede_of(&plain).0, ede_code::DNSSEC_BOGUS);
        assert_eq!(ede_of(&excessive).0, ede_code::UNSUPPORTED_NSEC3_ITERATIONS);
        assert_ne!(
            ede_of(&plain).1,
            ede_of(&excessive).1,
            "사유마다 다른 문구여야 운영자가 무엇을 고칠지 압니다"
        );
        assert_eq!(
            excessive.header.rcode,
            ResponseCode::ServFail.0,
            "rcode는 그대로 SERVFAIL입니다"
        );
    }

    #[test]
    /**
     * @brief 검증에 쓸 키를 받지 못한 SERVFAIL이 서명 문제가 아니라 권한 서버 문제로 알려지는지.
     * @details 루트는 주소 질의에는 답하고 DNSKEY 질의에는 답하지 않는다. 서명되지 않았다는
     *          증명도 없으므로 답은 여전히 SERVFAIL이지만, 사유는 EDE 22여야 하고 검증 실패
     *          지표에 잡히면 안 된다. EDE 6으로 알리면 운영자가 멀쩡한 서명을 살핀다.
     */
    fn unfetchable_keys_are_reported_as_an_unreachable_authority() {
        /** @brief 이 테스트가 쓰는 포트. 다른 테스트와 겹치면 서로 답을 가로챈다. */
        const PORT: u16 = 5424;
        let root = spawn_server("127.0.0.93", PORT, |req| {
            if req.questions.first().unwrap().qtype == RecordType::DNSKEY {
                // 답하지 않는 서버를 흉내 내려고, 이 서버가 버리는 ID를 가진 응답을 돌려준다.
                let mut m = base(req);
                m.header.id = req.header.id.wrapping_add(1);
                return m;
            }
            a_answer(req, Ipv4Addr::new(192, 0, 2, 93))
        });
        let anchor = onetdns_dnssec::Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![1; 32],
        };
        let rec = Recursor::new(vec![root], Duration::from_millis(800))
            .with_port(PORT)
            .with_test_loopback()
            .with_trust_anchors(vec![anchor]);

        let before = test_thread_validation_bogus_total();
        let resp = rec
            .resolve(&Name::from_str("host.test").unwrap(), RecordType::A)
            .expect("SERVFAIL 응답이어야 합니다");
        assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
        let (code, _) = Edns::from_record(resp.opt().expect("OPT"))
            .expect("EDNS")
            .ede()
            .expect("EDE");
        assert_eq!(code, ede_code::NO_REACHABLE_AUTHORITY);
        assert_eq!(
            test_thread_validation_bogus_total(),
            before,
            "키를 받지 못한 것을 검증 실패로 셌습니다"
        );
    }

    #[test]
    /** @brief 검증 실패가 지표에 잡히는지. */
    fn bogus_servfail_increments_observability_counter() {
        let global_before = validation_bogus_total();
        let before = test_thread_validation_bogus_total();
        let template = make_query(
            &Name::from_str("bogus.example").unwrap(),
            RecordType::A,
            false,
        );
        let concurrent = template.clone();
        let noise = std::thread::spawn(move || {
            for _ in 0..32 {
                let _ = bogus_servfail(&concurrent, ede_code::DNSSEC_BOGUS);
            }
        });
        let sf = bogus_servfail(&template, ede_code::DNSSEC_BOGUS);
        noise.join().unwrap();
        assert_eq!(sf.header.rcode, ResponseCode::ServFail.0);
        assert!(
            validation_bogus_total() >= global_before.saturating_add(33),
            "동시 요청까지 전역 관측 카운터에 모두 기록되어야 함"
        );
        assert_eq!(
            test_thread_validation_bogus_total(),
            before + 1,
            "검증 실패 SERVFAIL은 이 요청의 관측 카운터를 한 번 올려야 함"
        );
    }
}
