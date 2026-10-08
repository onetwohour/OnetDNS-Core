/*!
 * @brief 모든 전송이 모이는 질의 핸들러의 상태와 해석 백엔드.
 *
 * @details NativeServer 가 담는 설정, 기능 스왑, 백엔드 선택을 여기에 둔다. 접근 제어,
 *          속도 제한, 쿠키, 정책, 차단, 안전 검색, 클라이언트 대역 붙이기는 query 모듈이
 *          처리한 뒤 해석 체인으로 내려보낸다. 전송이 무엇이든 이 핸들러로 모인다.
 * @warning 차단은 이 위층에서 한다. 그래야 하위 캐시가 클라이언트별 정책을 건너뛰지
 *          못한다.
 * @note 빠른 경로가 둘 더 있다. 캐시가 맞은 UDP 질의를 파싱 없이 내보내는 경로와, 이 서버의
 *       권한 영역의 단순 질의를 조립 없이 내보내는 경로다. 응답을 달라지게 하는 기능이
 *       하나라도 켜지면 두 경로 모두 쓰지 않는다.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use onetdns_control::Recorder;
use onetdns_core::{
    AccessControl, ArcSwap, BlockResponse, ClientInfo, FilterVerdict, IpNet, LruMap, RateLimiter,
    RewriteTarget,
};
use onetdns_filter::SharedFilter;
use onetdns_forward::Forwarder;
use onetdns_proto::{
    Message, Name as ApName, RData as ApRData, Record as ApRecord, RecordType as ApRt,
};
use onetdns_recurse::Recursor;
use onetdns_security::CookieKeeper;

mod authority;
mod handler;
#[cfg(unix)]
mod lane;
mod observe;
mod query;
mod response;

use authority::AuthorityWirePath;
pub(crate) use authority::{NotifyKick, UpdateRule, ZoneJournal};
pub(crate) use response::{block_rcode, local_only_negative_response, rcode_str, rdata_brief};
use response::{block_resp, records_resp};

/** @brief 쿠키 옵션. */
const OPT_COOKIE: u16 = 10;

/**
 * @brief 설정이 너무 작을 때 쓰는 UDP 크기.
 * @details IPv6 최소 MTU에서 헤더를 뺀 값이라 경로 조각화를 피한다.
 */
const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/**
 * @brief 이 서버가 UDP로 내보내는 응답 크기 상한.
 * @details 상대가 이보다 작게 알리면 절단 사다리가 필요하므로 빠른 경로가 맡지 않는다.
 */
const SERVER_UDP_MAX: u16 = 1232;

/** @brief 옵션이 없는 OPT 레코드의 와이어 길이. 이름 1 + 종류 2 + 종류별 2 + TTL 4 + 길이 2. */
const EMPTY_OPT_WIRE_LEN: usize = 11;
/** @brief 서버 식별 옵션. */
const OPT_NSID: u16 = 3;

/** @brief DDR이 로컬에서 맡는 이름의 소문자 wire 표현. */
const DDR_OWNER_WIRE: &[u8] = b"\x04_dns\x08resolver\x04arpa\x00";

/** @brief 이름이 DDR의 로컬 소유 이름인지. 할당하지 않고 대소문자를 무시하고 비교한다. */
#[cfg_attr(not(unix), allow(dead_code))]
fn ddr_owner(name: &ApName) -> bool {
    name.as_uncompressed_wire()
        .eq_ignore_ascii_case(DDR_OWNER_WIRE)
}

/** @brief 이보다 큰 질의는 수상하게 본다. 정상 질의가 이만큼 클 일이 없다. */
const MAX_LARGE_QUERY_BYTES: usize = 1024;

#[derive(Clone, Default)]
/** @brief 쿠키를 쓸지, 그리고 없는 질의를 거절할지. */
pub struct CookiePolicy {
    /** @brief 쿠키를 만들고 확인하는 것. 없으면 쿠키를 쓰지 않는다. */
    pub keeper: Option<Arc<CookieKeeper>>,
    /** @brief 쿠키가 없거나 맞지 않으면 거절할지. */
    pub strict: bool,
}

#[derive(Debug, Clone, Copy)]
/** @brief 요일과 시각으로 정한 구간 하나. */
pub struct SchedWindow {
    /** @brief 적용할 요일 비트. */
    pub days: u8,
    /** @brief 시작 시각. 자정부터 흐른 분. */
    pub start_min: u32,
    /** @brief 끝 시각. 자정부터 흐른 분. */
    pub end_min: u32,
}

#[derive(Debug, Default)]
/** @brief 서비스 차단을 멈출 시간대. */
pub struct Schedule {
    /** @brief 서비스 차단을 멈출 구간들. */
    pub windows: Vec<SchedWindow>,
}

impl Schedule {
    /** @brief 지금이 그 시간대인지. 자정을 넘는 구간은 전날 요일로도 본다. */
    pub fn is_active(&self, now: SystemTime) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        let (dow, tod_min) = crate::localtime::local_weekday_minute(now);
        let tod_min = u32::from(tod_min);
        self.windows.iter().any(|w| {
            if w.start_min < w.end_min {
                (w.days & (1 << dow)) != 0 && tod_min >= w.start_min && tod_min < w.end_min
            } else {
                let previous_dow = (dow + 6) % 7;
                ((w.days & (1 << dow)) != 0 && tod_min >= w.start_min)
                    || ((w.days & (1 << previous_dow)) != 0 && tod_min < w.end_min)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/**
 * @brief 세 빠른 경로 각각을 지금 써도 되는지.
 * @details 설정과 설정 밖의 사실로 evaluate_lane_gates 가 정한다.
 */
pub(crate) struct LaneGates {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    pub(crate) wire: bool,
    /** @brief 권한 영역 단순 질의 빠른 경로. */
    pub(crate) authority: bool,
    /** @brief 재귀 콜드미스 리액터 레인. */
    pub(crate) reactor: bool,
}

impl Default for LaneGates {
    /**
     * @brief 세 경로를 모두 연다.
     * @details 설정으로 정하기 전의 핸들러가 쓰는 값이다. 실행 중 서버는 시작할 때와 설정을
     *          교체할 때 evaluate_lane_gates 의 결과를 넣는다.
     */
    fn default() -> Self {
        LaneGates {
            wire: true,
            authority: true,
            reactor: true,
        }
    }
}

#[derive(Clone, Default)]
/**
 * @brief 설정 하나로 정해지는 응답 기능들. 설정을 다시 읽으면 한꺼번에 교체한다.
 * @details 세대를 넘겨 이어 쓰는 상태는 여기 두지 않고 NativeServer 가 가진다. 처리 중 질의
 *          수, 지표 기록기, 안전 검색 스위치가 그렇다. 여기 두면 설정을 바꿀 때마다 옮겨 담아야
 *          하고, 빠뜨리면 그 상태가 처음으로 돌아간다.
 * @invariant 빠른 경로는 경로 조건, 체인 세대, wire 세대를 이 값 하나에서 읽는다. 체인
 *            세대만 먼저 바뀐 상태가 보이면 새 체인의 캐시에 이전 조건으로 만든 답이 담겨
 *            그 수명 동안 나간다.
 */
pub struct NativeFeatures {
    /** @brief IPv6 주소 답을 막는다. */
    pub block_aaaa: bool,
    /** @brief IPv4 답으로 IPv6 답을 지어낼 때 쓸 접두사. */
    pub dns64_prefix: Option<[u8; 16]>,
    /** @brief IPv6 답이 있어도 임의로 만든 답을 함께 준다. */
    pub dns64_synthall: bool,
    /** @brief 밖의 이름이 내부망 주소를 가리키면 막는다. */
    pub rebind_protection: bool,
    /** @brief 위 검사에서 뺄 이름들. */
    pub rebind_allow: Vec<ApName>,
    /** @brief 이 주소들로 답하면 없다고 바꾼다. */
    pub bogus_nxdomain: Vec<IpNet>,
    /** @brief 재귀 답에 이 주소가 있으면 막는다. */
    pub recurse_deny_answers: Vec<IpNet>,
    /** @brief 재귀 답에서 이 주소만 받아들인다. */
    pub recurse_allow_answers: Vec<IpNet>,
    /** @brief 같은 이름의 답 순서를 돌려 가며 낸다. */
    pub rrset_roundrobin: bool,
    /** @brief 응답에 담을 서버 식별값. */
    pub nsid: Option<Vec<u8>>,
    /** @brief 쿠키 정책. */
    pub cookies: CookiePolicy,

    /** @brief 동시에 처리할 질의 수 상한. */
    pub inflight_max: usize,

    /** @brief 질의 기록 파일. */
    pub dnstap: Option<Arc<onetdns_control::DnstapWriter>>,

    /** @brief 응답에 알릴 UDP 수신 크기. */
    pub edns_buffer: u16,

    /** @brief 서버 이름을 묻는 질의에 답하지 않는다. */
    pub hide_identity: bool,
    /** @brief 서버 버전을 묻는 질의에 답하지 않는다. */
    pub hide_version: bool,

    /** @brief 서버 이름을 물었을 때 답할 값. */
    pub server_identity: Vec<u8>,
    /** @brief 서버 버전을 물었을 때 답할 값. */
    pub server_version: Vec<u8>,

    /** @brief 모든 종류를 묻는 질의를 받아들일지. 큰 답을 끌어내는 증폭에 쓰인다. */
    pub allow_any: bool,
    /** @brief 꼭 필요한 것만 담아 응답을 줄인다. */
    pub minimal_responses: bool,
    /** @brief 응답 크기를 이 단위로 채운다. 크기로 내용을 짐작하지 못하게 한다. */
    pub padding_block: usize,
    /** @brief 연결을 유지할 시간. 없으면 알리지 않는다. */
    pub tcp_keepalive_100ms: Option<u16>,
    /** @brief 대역 정보를 쓰고 있어 클라이언트에게도 그 사실을 알려야 하는지. */
    pub ecs_in_use: bool,
    /** @brief 지나치게 큰 질의를 버린다. */
    pub harden_large_queries: bool,

    /** @brief DDR 특수 이름을 일반 해석 체인으로 보내야 하는지. */
    pub ddr_enabled: bool,

    /** @brief 지금 체인 세대의 캐시·재귀 리졸버. */
    pub(crate) lane_runtime: Option<Arc<LaneRuntime>>,
    /** @brief 세 빠른 경로 각각을 지금 써도 되는지. */
    pub(crate) lanes: LaneGates,
    /**
     * @brief wire 항목에 붙일 설정 세대.
     * @details 응답을 바꾸는 설정이 바뀌면 올린다. 이전 세대에 만든 항목은 태그가 달라 다시
     *          나가지 않는다.
     */
    pub(crate) wire_epoch: usize,
}

impl NativeFeatures {
    /**
     * @brief wire 항목의 태그. 차단 엔진과 설정 세대가 모두 같을 때만 같은 값이 나온다.
     * @param filter 응답을 거른 차단 엔진.
     */
    pub(crate) fn wire_tag(&self, filter: &Arc<onetdns_filter::BlockEngine>) -> usize {
        (Arc::as_ptr(filter) as usize).rotate_left(17) ^ self.wire_epoch
    }

    /**
     * @brief 빠른 경로를 새 체인 세대의 캐시와 재귀 리졸버로 옮긴다.
     * @param factory  wire 항목의 수명 정책.
     * @param cache    새 체인의 응답 캐시.
     * @param recursor 새 체인의 재귀 리졸버. 전달만 하는 체인이면 없다.
     */
    pub(crate) fn adopt_chain(
        &mut self,
        factory: crate::wirecache::WireEntryFactory,
        cache: crate::cache::CacheHandle,
        recursor: Option<Arc<Recursor>>,
    ) {
        self.lane_runtime = Some(Arc::new(LaneRuntime {
            factory: Some(factory),
            cache,
            recursor,
        }));
    }
}

/** @brief 기능 세트 전체를 교체하는 슬롯. */
pub struct NativeFeatureSwap {
    /** @brief 지금 기능 세트. */
    swap: ArcSwap<NativeFeatures>,
    /** @brief 테스트에서 질의당 snapshot 수를 고정한다. 출하 코드에는 없다. */
    #[cfg(test)]
    test_loads: AtomicUsize,
}

impl NativeFeatureSwap {
    /** @brief 값 하나로 만든다. */
    fn from_pointee(value: NativeFeatures) -> Self {
        Self {
            swap: ArcSwap::from_pointee(value),
            #[cfg(test)]
            test_loads: AtomicUsize::new(0),
        }
    }

    /** @brief 지금 기능 세트. */
    pub fn load(&self) -> Arc<NativeFeatures> {
        #[cfg(test)]
        self.test_loads.fetch_add(1, Ordering::Relaxed);
        self.swap.load()
    }

    /** @brief 직전 확인 뒤의 테스트용 snapshot 횟수를 돌려주고 0으로 만든다. */
    #[cfg(test)]
    fn take_test_loads(&self) -> usize {
        self.test_loads.swap(0, Ordering::Relaxed)
    }

    /** @brief 기능 세트를 교체한다. */
    pub fn store(&self, value: Arc<NativeFeatures>) {
        self.swap.store(value);
    }
}

/** @brief 처리 중인 질의 수를 세고 끝나면 되돌린다. */
struct InflightGuard<'a>(&'a AtomicUsize);
impl Drop for InflightGuard<'_> {
    /** @brief 처리 중 수를 하나 줄인다. */
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/** @brief 점이 없는 이름인지. */
pub(crate) fn is_single_label(name: &ApName) -> bool {
    name.num_labels() == 1
}

/** @brief 전송 종류를 정책이 쓰는 표현으로. */
pub(crate) fn policy_transport(t: onetdns_core::Transport) -> onetdns_policy::QueryTransport {
    use onetdns_core::Transport as T;
    use onetdns_policy::QueryTransport as Q;
    match t {
        T::Do53Udp => Q::Do53Udp,
        T::Do53Tcp => Q::Do53Tcp,
        T::DoT => Q::Dot,
        T::DoH => Q::Doh,
        T::DoH3 => Q::Doh3,
        T::DoQ => Q::Doq,
        T::DnsCrypt => Q::DnsCrypt,
    }
}

/** @brief 이름을 정책에 넘길 문자열로. 올바른 문자가 아니면 고치지 않고 없음으로 둔다. */
pub(crate) fn normalized_text_name(name: &ApName) -> Option<String> {
    let mut out = String::new();
    for (index, label) in name.labels().iter().enumerate() {
        let label = std::str::from_utf8(label).ok()?;
        if index > 0 {
            out.push('.');
        }
        out.extend(label.chars().map(|c| c.to_ascii_lowercase()));
    }
    Some(out)
}

/** @brief 내부망 주소를 거꾸로 적은 이름인지. */
pub(crate) fn is_private_reverse(name: &ApName) -> bool {
    let labels: Vec<String> = name
        .labels()
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect();
    let n = labels.len();
    if n < 3 {
        return false;
    }
    if labels[n - 2] == "in-addr" && labels[n - 1] == "arpa" {
        let octs: Vec<u8> = labels[..n - 2]
            .iter()
            .rev()
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        if octs.len() != n - 2 {
            return false;
        }
        return matches!(
            octs.as_slice(),
            [10, ..] | [127, ..] | [192, 168, ..] | [169, 254, ..]
        ) || matches!(octs.as_slice(), [172, b, ..] if (16u8..=31).contains(b));
    }
    if labels[n - 2] == "ip6" && labels[n - 1] == "arpa" {
        let nibs = &labels[..n - 2];
        let hi = nibs.last().map(String::as_str);
        let hi2 = (nibs.len() >= 2).then(|| nibs[nibs.len() - 2].as_str());
        if hi == Some("f") {
            if matches!(hi2, Some("c") | Some("d")) {
                return true;
            }
            if hi2 == Some("e") && nibs.len() >= 3 {
                return matches!(nibs[nibs.len() - 3].as_str(), "8" | "9" | "a" | "b");
            }
        }
        return false;
    }
    false
}

/** @brief 밖에 물으면 안 되는 이름인지. */
pub(crate) fn is_empty_zone(name: &ApName) -> bool {
    if is_private_reverse(name) {
        return true;
    }
    let s = name.to_ascii_lower();
    let s = s.trim_end_matches('.');
    /** @brief 밖에 새 나가면 안 되는 이름들. */
    const ZONES: &[&str] = &[
        "home.arpa",
        "empty.as112.arpa",
        "0.in-addr.arpa",
        "255.in-addr.arpa",
        "2.0.192.in-addr.arpa",
        "100.51.198.in-addr.arpa",
        "113.0.203.in-addr.arpa",
        "64.100.in-addr.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
    ];
    ZONES
        .iter()
        .any(|z| s == *z || s.ends_with(&format!(".{z}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/**
 * @brief 해석이 실패한 종류.
 * @warning 둘의 구분이 보조 경로로 넘어갈지를 정한다. 전송이 끊긴 것만 다시 물을 값어치가
 *          있고, 나머지는 다시 물어도 같다.
 */
pub enum ResolveFailure {
    /** @brief 닿지 못했다. 다른 경로로 다시 물어볼 값어치가 있다. */
    TransportExhausted,

    /** @brief 다시 물어도 같다. 값은 클라이언트에 알릴 사유 코드. */
    Permanent(Option<u16>),
}

/** @brief 해석 결과. */
pub enum ResolveOutcome {
    /** @brief 답을 얻었다. */
    Response(Message),
    /** @brief 얻지 못했다. */
    Failure(ResolveFailure),
}

/** @brief 해석 체인의 한 슬롯. */
pub trait Resolver: Send + Sync {
    /** @brief 해석한다. 답하지 못하면 없다. */
    fn resolve(&self, request: &Message) -> Option<Message>;

    /** @brief 실패 종류까지 알려 해석한다. 기본은 답하지 못한 것을 되돌릴 수 없는 실패로 본다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self.resolve(request) {
            Some(response) => ResolveOutcome::Response(response),
            None => ResolveOutcome::Failure(ResolveFailure::Permanent(None)),
        }
    }
}

/**
 * @brief 전달 설정으로 아직 만들어지지 않은 전달 리졸버.
 * @details 전달을 쓰지 않는 backend로 시작해도 전달 리졸버 슬롯은 미리 만들어 둔다.
 *          backend를 전달이나 분할로 바꾸면 설정 반영이 이 슬롯을 진짜 리졸버로 바꾼다.
 *          슬롯이 없으면 그 전환을 무중단으로 처리할 수 없다.
 */
pub struct UnbuiltForward;

impl Resolver for UnbuiltForward {
    /** @brief 전달할 곳이 아직 없으므로 답하지 않는다. */
    fn resolve(&self, _request: &Message) -> Option<Message> {
        None
    }
}

#[derive(Clone)]
/**
 * @brief 교체할 수 있는 리졸버 슬롯.
 * @details 설정을 다시 읽었을 때 체인을 전부 다시 만들지 않고 이 슬롯만 바꾼다. 이미 이 슬롯을
 *          잡은 채 처리 중인 질의는 이전 것으로 끝난다.
 */
pub struct ResolverSlot {
    /** @brief 지금 들어 있는 리졸버. */
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
}

impl ResolverSlot {
    /** @brief 리졸버 하나로 만든다. */
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(resolver)),
        }
    }

    /** @brief 지금 들어 있는 리졸버. */
    pub fn load(&self) -> Arc<dyn Resolver> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /** @brief 리졸버를 교체한다. 다음 질의부터 새 것으로 간다. */
    pub fn replace(&self, resolver: Arc<dyn Resolver>) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = resolver;
    }
}

impl Resolver for ResolverSlot {
    /** @brief 지금 들어 있는 리졸버로 넘긴다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        self.load().resolve(request)
    }

    /** @brief 지금 들어 있는 리졸버로 넘긴다. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        self.load().resolve_outcome(request)
    }
}

#[derive(Clone)]
/**
 * @brief 특정 클라이언트만 다른 업스트림으로 보내는 경로.
 * @warning 이 경로도 같은 안전·캐시 계층으로 감싼다. 감싸지 않으면 클라이언트를 맞추는
 *          것만으로 정책과 권한 영역을 건너뛴다.
 */
pub struct ClientUpstream {
    /** @brief 이 경로에 드는 주소 대역. */
    pub nets: Vec<IpNet>,
    /** @brief 이 경로에 드는 클라이언트 식별자. */
    pub ids: Vec<String>,
    /** @brief 이 경로가 쓸 해석 체인. */
    pub resolver: Arc<dyn Resolver>,
    /** @brief 이 경로가 묻는 업스트림. 공유 캐시에서 이 경로의 답을 구분한다. */
    upstreams: Vec<String>,
}

impl ClientUpstream {
    /** @brief 대상 대역과 식별자, 그리고 그 업스트림과 그 업스트림으로 만든 체인으로 만든다. */
    pub fn new(
        nets: Vec<IpNet>,
        ids: Vec<String>,
        upstreams: Vec<String>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        ClientUpstream {
            nets,
            ids,
            resolver,
            upstreams,
        }
    }

    /**
     * @brief 공유 캐시에서 이 경로의 답을 구분하는 이름.
     * @details 답을 정하는 것은 이 경로가 묻는 업스트림이다. 대상 클라이언트로 구분하면 같은
     *          대역에 다른 업스트림을 둔 서버끼리 답이 섞인다.
     */
    pub fn namespace_key(&self) -> String {
        let mut upstreams = self.upstreams.clone();
        upstreams.sort_unstable();
        upstreams.dedup();
        upstreams.join(",")
    }

    /** @brief 이 클라이언트가 이 경로에 드는지. */
    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        if let Some(id) = &client.client_id {
            if self.ids.iter().any(|x| x == id) {
                return true;
            }
        }
        false
    }
}

/** @brief 검증에 실패한 질의 수. 지표로 내보낸다. */
pub static DNSSEC_BOGUS_TOTAL: AtomicU64 = AtomicU64::new(0);

/** @brief 재귀 오류를 실패 종류로 옮긴다. */
fn recurse_failure(error: onetdns_recurse::RecurseError, qname: &ApName) -> ResolveFailure {
    use onetdns_recurse::RecurseError as E;
    match error {
        E::NoResponse => ResolveFailure::TransportExhausted,
        E::NoRoots | E::NoReachableNs => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY))
        }
        E::Bogus => {
            note_dnssec_bogus(qname);
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::DNSSEC_BOGUS))
        }

        E::TooManyReferrals | E::TooManyCnames | E::TooManyDnames | E::TooManyQueries => {
            ResolveFailure::Permanent(Some(onetdns_proto::ede_code::OTHER))
        }
    }
}

/** @brief 실패 사유를 클라이언트에 알릴 코드와 문구로. */
pub(crate) fn failure_diagnosis(
    failure: &ResolveFailure,
) -> (&'static str, &'static str, Option<u16>) {
    match failure {
        ResolveFailure::TransportExhausted => (
            "RESOLVER_TRANSPORT_EXHAUSTED",
            "transport_exhausted",
            Some(onetdns_proto::ede_code::NETWORK_ERROR),
        ),
        ResolveFailure::Permanent(ede) => ("RESOLVER_PERMANENT_FAILURE", "permanent", *ede),
    }
}

/** @brief 검증 실패를 세고 남긴다. */
fn note_dnssec_bogus(qname: &onetdns_proto::Name) {
    let count = DNSSEC_BOGUS_TOTAL
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if count.is_power_of_two() {
        onetdns_core::warn!(
            event = "dnssec.validation_bogus",
            qname = %qname,
            count = count,
            "Blocked a response that failed DNSSEC validation"
        );
    }
}

/** @brief 체인 맨 안쪽. 전달이거나 재귀다. */
pub enum NativeBackend {
    /** @brief 업스트림 서버로 전달한다. */
    Forward(Forwarder),

    /** @brief 루트부터 직접 따라간다. */
    Recurse {
        /** @brief 재귀 해석을 실행하는 것. */
        recursor: Arc<Recursor>,
        /** @brief 답에 담긴 이름 서버를 거를 규칙. 없으면 거르지 않는다. */
        ns_rpz: Option<Arc<SharedFilter>>,
        /** @brief 차단 답에 담을 수명. */
        block_ttl: Arc<AtomicU32>,
        /** @brief 고정해 둔 주소에 담을 수명. */
        local_ttl: Arc<AtomicU32>,
    },
}

impl Resolver for NativeBackend {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        match self.resolve_outcome(request) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /**
     * @brief 전달하거나 재귀한다.
     * @warning 전달일 때 업스트림이 설정한 검증 표시를 지운다. 이 서버가 검증하지 않은 것을 검증됐다며
     *          클라이언트에 넘기면 안 된다. 권한 표시도 같이 지운다. 업스트림이 권한이지 이 서버가
     *          아니다. 이 서버의 영역의 답에 그 표시를 설정하는 것은 위쪽 권한 계층이 한다.
     */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self {
            NativeBackend::Forward(forwarder) => match forwarder.resolve(request) {
                Ok(mut response) => {
                    response.header.authentic_data = false;
                    response.header.authoritative = false;
                    normalize_response_ttls(&mut response);
                    ResolveOutcome::Response(response)
                }
                Err(onetdns_forward::ForwardError::Timeout)
                | Err(onetdns_forward::ForwardError::Io(_))
                | Err(onetdns_forward::ForwardError::BadResponse) => {
                    ResolveOutcome::Failure(ResolveFailure::TransportExhausted)
                }
                Err(onetdns_forward::ForwardError::NoUpstream) => {
                    ResolveOutcome::Failure(ResolveFailure::Permanent(None))
                }
            },
            NativeBackend::Recurse {
                recursor,
                ns_rpz,
                block_ttl,
                local_ttl,
            } => {
                let Some(q) = request.questions.first() else {
                    return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
                };
                let (mut message, ns) = match recursor.resolve_with_ns_cd(
                    &q.name,
                    q.qtype,
                    request.header.checking_disabled,
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        return ResolveOutcome::Failure(recurse_failure(error, &q.name));
                    }
                };

                if let Some(filter) = ns_rpz {
                    if let Some(verdict) = filter.load().rpz_ns_verdict(&ns.names, &ns.ips) {
                        match verdict {
                            FilterVerdict::Allow => {}
                            FilterVerdict::Block(block) => {
                                return ResolveOutcome::Response(block_resp(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    block,
                                    block_ttl.load(Ordering::Acquire),
                                ));
                            }
                            FilterVerdict::Drop => {
                                /*
                                 * RPZ 트리거는 무응답 처분을 만들지 않는다. 해석 체인은 응답을
                                 * 거둘 수 없으므로, 그런 처분이 오더라도 rpz-drop 처럼 NXDOMAIN
                                 * 으로 답한다.
                                 */
                                return ResolveOutcome::Response(block_resp(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    BlockResponse::NxDomain,
                                    block_ttl.load(Ordering::Acquire),
                                ));
                            }
                            FilterVerdict::Rewrite(target) => {
                                return ResolveOutcome::Response(ns_rpz_rewrite(
                                    request,
                                    &q.name,
                                    q.qtype,
                                    &target,
                                    local_ttl.load(Ordering::Acquire),
                                ));
                            }
                        }
                    }
                }
                message.header.id = request.header.id;
                message.questions = request.questions.clone();
                strip_dnssec_unless_requested(request, &mut message);
                normalize_response_ttls(&mut message);
                ResolveOutcome::Response(message)
            }
        }
    }
}

/**
 * @brief 밖에서 들어온 응답의 수명을 RFC 2181대로 고른다.
 *
 * @details 업스트림이나 재귀가 준 응답이 캐시·wire 고속 경로·클라이언트로 갈라지기 전 위치다.
 *          여기서 한 번 고르면 이후 분기가 모두 같은 값을 쓴다. 나가는 곳에서 하면
 *          미리 만들어 둔 wire 바이트열을 내보내는 경로가 빠진다.
 * @param response 제자리에서 고친다.
 */
fn normalize_response_ttls(response: &mut Message) {
    onetdns_proto::normalize_ttls(&mut response.answers);
    onetdns_proto::normalize_ttls(&mut response.authorities);
    onetdns_proto::normalize_ttls(&mut response.additionals);
}

/** @brief 이름을 감춘 부재 증명의 매개변수. */
const NSEC3PARAM: ApRt = ApRt(51);

/** @brief 이 종류가 DO를 설정한 쪽에만 나가야 하는 것인지. */
fn is_dnssec_only_type(rtype: ApRt) -> bool {
    matches!(rtype, ApRt::RRSIG | ApRt::NSEC | ApRt::NSEC3 | NSEC3PARAM)
}

/**
 * @brief 이 요청이 DNSSEC 레코드를 함께 달라고 했는지.
 *
 * @details DO는 OPT TTL 필드의 상위 비트다. 질의마다 호출되는 함수라 옵션까지 파싱하지
 *          않는다. 파싱하면 그 값을 응답마다 낸다.
 */
pub(crate) fn wants_dnssec(request: &Message) -> bool {
    request
        .additionals
        .iter()
        .any(|record| record.rtype == ApRt::OPT && (record.ttl & 0x0000_8000) != 0)
}

/**
 * @brief DO를 설정하지 않은 질의자에게 나가는 응답에서 DNSSEC 레코드를 걷어낸다.
 *
 * @details 재귀 리졸버는 검증 여부와 무관하게 업스트림에 DO=1로 묻는다. 그래야 DO=1로 묻는
 *          질의자에게 줄 서명을 가지고 있을 수 있기 때문이다. 대신 묻지 않은 쪽에는
 *          보내지 않는다. 응답만 커지고 절단으로 이어진다.
 * @note DNSKEY와 DS는 질의자가 직접 물을 수 있는 종류라 걷어내지 않는다. 답이 곧
 *       그 종류일 때 지우면 물어본 것을 못 주게 된다.
 * @note 걷어낼 것이 하나도 없는 응답이 대부분이다. 먼저 훑어보고 있을 때만 옮긴다.
 *       retain은 지울 것이 없어도 원소를 하나씩 옮겨 쓴다.
 */
pub(crate) fn strip_dnssec_unless_requested(request: &Message, response: &mut Message) {
    let carries_dnssec = |section: &[ApRecord]| {
        section
            .iter()
            .any(|record| is_dnssec_only_type(record.rtype))
    };
    if !carries_dnssec(&response.answers)
        && !carries_dnssec(&response.authorities)
        && !carries_dnssec(&response.additionals)
    {
        return;
    }
    if wants_dnssec(request) {
        return;
    }
    let keep = |record: &ApRecord| !is_dnssec_only_type(record.rtype);
    response.answers.retain(keep);
    response.authorities.retain(keep);
    response.additionals.retain(keep);
}

/** @brief 응답에 담긴 이름 서버가 차단 대상이면 답을 바꾼다. */
fn ns_rpz_rewrite(
    request: &Message,
    qname: &ApName,
    qtype: ApRt,
    target: &RewriteTarget,
    ttl: u32,
) -> Message {
    match target {
        RewriteTarget::Records(rdatas) => {
            let recs: Vec<ApRecord> = rdatas
                .iter()
                .filter(|rd| rd.record_type() == qtype)
                .map(|rd| ApRecord::new(qname.clone(), ttl, rd.clone()))
                .collect();
            records_resp(request, recs)
        }
        RewriteTarget::Cname(t) => {
            let cname = ApRecord::new(qname.clone(), ttl, ApRData::Cname(t.clone()));
            records_resp(request, vec![cname])
        }
    }
}

/** @brief 이 값이 실제로 무언가를 하는지 스스로 답하는 것. */
pub trait GatePresence {
    /** @brief 지금 이 값이 하는 일이 있는지. */
    fn gate_present(&self) -> bool;
}

impl GatePresence for Vec<NativeView> {
    /** @brief 뷰가 하나라도 있는지. */
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

impl GatePresence for onetdns_policy::PolicyEngine {
    /** @brief 규칙이나 플러그인이 하나라도 있는지. */
    fn gate_present(&self) -> bool {
        !self.is_empty()
    }
}

/**
 * @brief 교체할 수 있으면서 비었는지를 값싸게 답하는 것.
 * @details 질의마다 내용을 복제해 비었는지 보면 그것이 비용이다. 비었는지만 원자 값으로
 *          따로 둔다.
 */
pub struct GatedSwap<T> {
    /** @brief 지금 값. */
    swap: ArcSwap<T>,
    /** @brief 지금 값이 하는 일이 있는지. 복제 없이 답하려고 따로 둔다. */
    present: AtomicBool,
}

impl<T: GatePresence> GatedSwap<T> {
    /** @brief 값 하나로 만든다. */
    pub fn from_pointee(value: T) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::from_pointee(value),
            present: AtomicBool::new(present),
        }
    }

    /** @brief 이미 공유된 값으로 만든다. */
    pub fn new(value: Arc<T>) -> Self {
        let present = value.gate_present();
        GatedSwap {
            swap: ArcSwap::new(value),
            present: AtomicBool::new(present),
        }
    }

    /** @brief 지금 값. */
    pub fn load(&self) -> Arc<T> {
        self.swap.load()
    }

    /** @brief 지금 값이 하는 일이 있는지. 복제 없이 답한다. */
    pub fn present(&self) -> bool {
        self.present.load(Ordering::Acquire)
    }

    /** @brief 값을 교체하고 요약 판정도 함께 맞춘다. */
    pub fn store(&self, value: Arc<T>) {
        let present = value.gate_present();
        if present {
            self.present.store(true, Ordering::Release);
            self.swap.store(value);
        } else {
            self.swap.store(value);
            self.present.store(false, Ordering::Release);
        }
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
/** @brief 재귀를 기다리는 동안 스레드를 붙잡지 않는 레인이 쓰는 것들. */
struct ReactorLaneShared {
    /** @brief 레인에 동시에 맡길 수 있는 질의 수. */
    inflight: usize,

    /** @brief 레인이 끝내지 못한 것을 마저 풀 체인. */
    chain: Arc<dyn Resolver>,
}

/** @brief 한 해석 체인 세대에 반드시 함께 속해야 하는 빠른 경로 자원. */
pub(crate) struct LaneRuntime {
    /** @brief wire 항목을 만들 수 있으면 그 수명 정책. */
    factory: Option<crate::wirecache::WireEntryFactory>,
    /** @brief wire 경로와 리액터 레인이 함께 보는 응답 캐시. */
    cache: crate::cache::CacheHandle,
    /** @brief 이 세대의 재귀 리졸버. 전달 전용 세대면 없다. */
    recursor: Option<Arc<Recursor>>,
}

impl LaneRuntime {
    /**
     * @brief 내보낸 응답을 빠른 경로가 다시 쓸 수 있게 담아 둔다. 담을 수 없는 응답이면 담지 않는다.
     * @param epoch 이 응답을 만든 해석이 시작되기 전에 잡은 캐시 세대.
     */
    pub(crate) fn store_wire_response(
        &self,
        epoch: crate::cache::CacheEpoch,
        key: &[u8],
        response_wire: &[u8],
        filter_tag: usize,
        answers_summary: String,
        now: std::time::Instant,
    ) {
        let Some(factory) = self.factory.as_ref() else {
            return;
        };
        let Some(candidate) = self.cache.wire_candidate(key, now) else {
            return;
        };
        let entry = if candidate.has_fixed_local_ttl() {
            factory.prepare_fixed(response_wire, filter_tag, answers_summary, now)
        } else {
            factory.prepare(
                response_wire,
                filter_tag,
                answers_summary,
                now,
                candidate.lifetime_secs(),
            )
        };
        let Some(entry) = entry else {
            return;
        };
        self.cache.promote_wire(epoch, key, &candidate, entry);
    }
}

/** @brief 질의 하나를 처음부터 끝까지 다루는 것. */
pub struct NativeServer {
    /** @brief 차단 엔진. 한꺼번에 교체한다. */
    pub filter: Arc<SharedFilter>,
    /** @brief 접근 제어. */
    pub acl: Arc<dyn AccessControl>,
    /** @brief 속도 제한들. */
    pub rate_limiters: Vec<Arc<dyn RateLimiter>>,

    /** @brief 해석 체인. */
    pub backend: Arc<dyn Resolver>,

    /** @brief 클라이언트별 업스트림 경로. */
    pub client_upstreams: Vec<ClientUpstream>,

    /** @brief 재귀 대기가 스레드를 붙잡지 않는 레인. 없으면 쓰지 않는다. */
    reactor_lane: Option<ReactorLaneShared>,
    /** @brief 차단 답에 담을 수명. */
    pub block_ttl: Arc<AtomicU32>,
    /** @brief 고정해 둔 주소에 담을 수명. */
    pub local_ttl: Arc<AtomicU32>,
    /** @brief 설정 하나로 정해지는 응답 기능들. */
    pub features: Arc<NativeFeatureSwap>,
    /** @brief 지표와 질의 기록을 보낼 곳. */
    recorder: Option<Recorder>,
    /** @brief 클라이언트 하드웨어 주소 조회. */
    mac_cache: Option<Arc<crate::mac::NeighborCache>>,
    /** @brief 안전 검색이 켜져 있는지. 시간대 작업과 설정 교체가 함께 바꾼다. */
    safe_search: Arc<AtomicBool>,
    /** @brief 지금 처리 중인 질의 수. */
    inflight: AtomicUsize,
    /** @brief 같은 이름의 답을 돌려 가며 낼 때의 지금 위치. */
    rotor: AtomicUsize,

    /** @brief 정책 엔진. */
    pub policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>,

    /** @brief 영역 전송으로 내줄 영역들. 없으면 전송을 하지 않는다. */
    pub xfr_store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,

    /** @brief 영역 전송·원격 업데이트·서명 설정. 한꺼번에 교체한다. */
    pub authority: Arc<ArcSwap<AuthoritySettings>>,

    /** @brief 이미 본 서명들. 가로챈 요청을 다시 쓰지 못하게 한다. */
    tsig_replay: std::sync::Mutex<LruMap<Vec<u8>, u64>>,

    /** @brief 영역이 고쳐졌을 때 부를 것. */
    pub update_notify: Option<Arc<dyn Fn(&ApName, u32) + Send + Sync>>,

    /** @brief 업스트림 서버가 알려 온 영역들. */
    pub notify_kick: Arc<NotifyKick>,

    /** @brief 영역별 최근 변경 기록. */
    pub journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,

    /** @brief 클라이언트별로 다르게 답할 뷰들. */
    pub views: Arc<GatedSwap<Vec<NativeView>>>,

    /** @brief 권한 영역 단순 질의의 빠른 경로. 없으면 쓰지 않는다. */
    authority_wire_path: Option<AuthorityWirePath>,
}

#[derive(Clone)]
/**
 * @brief 원격 업데이트를 받는 영역 하나.
 * @details 영역과 저장할 파일을 한 값으로 묶는다. 업데이트는 받는데 저장할 곳이 없는 영역은
 *          다시 읽을 때 변경이 사라지므로, 그런 상태를 만들 수 없게 한다. 파일이 아닌 원본에서
 *          온 영역은 그 원본에 쓰는 방법이 따로 있어야 하므로 여기 들어오지 않는다.
 */
pub struct UpdateTarget {
    /** @brief 영역 이름. */
    pub origin: ApName,
    /** @brief 고친 내용을 저장할 파일. */
    pub file: std::path::PathBuf,
}

#[derive(Clone, Default)]
/**
 * @brief 권한 영역을 다루는 설정 세트.
 *
 * @details 영역 목록이 바뀌면 전송 허용 대역·서명 키·고칠 수 있는 영역·저장 경로가
 *          함께 바뀐다. 하나씩 교체하면 그 사이에 서로 어긋난 상태로 요청을 받는다.
 */
pub struct AuthoritySettings {
    /** @brief 영역 전송을 허용할 대역. */
    pub xfr_allow: Vec<IpNet>,
    /** @brief 요청 서명에 쓸 공유 키들. */
    pub tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    /** @brief 영역 전송에 서명을 요구할지. */
    pub xfr_tsig_required: bool,
    /** @brief 원격 업데이트를 허용할 대역. */
    pub update_allow: Vec<IpNet>,
    /** @brief 누가 무엇을 고칠 수 있는지 정한 규칙. */
    pub update_policy: Vec<UpdateRule>,
    /** @brief 원격 업데이트에 서명을 요구할지. */
    pub update_tsig_required: bool,
    /** @brief 원격으로 고칠 수 있는 영역들과 고친 내용을 저장할 파일. */
    pub update_targets: Vec<UpdateTarget>,
    /** @brief NOTIFY를 받아들일 보조 영역과 그 주 서버, 기대하는 TSIG 키. */
    pub notify_secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
    /**
     * @brief 카탈로그를 받아 오는 주 서버와 기대하는 TSIG 키.
     * @details 카탈로그로 찾은 구성원 영역은 실행 중에 늘고 준다. 이 주 서버가 보낸 NOTIFY는
     *          영역 이름을 미리 알지 못해도 받아들이고, 갱신 작업이 모르는 영역은 버린다.
     */
    pub notify_catalog_primaries: Vec<(IpAddr, Option<ApName>)>,
    /** @brief 영역별 서명기. */
    pub zone_signers: Vec<(ApName, crate::zone_signing::ZoneSigningCtx)>,
}

#[derive(Clone, Default)]
/** @brief 특정 클라이언트에만 다르게 답할 이름들. */
pub struct NativeView {
    /** @brief 이 뷰에 드는 주소 대역. */
    pub nets: Vec<IpNet>,
    /** @brief 이 뷰에 드는 클라이언트 식별자. */
    pub ids: Vec<String>,

    /** @brief 이 뷰에만 답할 IPv4 주소. */
    pub local_a: Vec<(Vec<u8>, Ipv4Addr)>,
    /** @brief 이 뷰에만 답할 IPv6 주소. */
    pub local_aaaa: Vec<(Vec<u8>, Ipv6Addr)>,
}

impl NativeView {
    /** @brief 이 클라이언트가 이 뷰에 드는지. */
    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        client
            .client_id
            .as_ref()
            .is_some_and(|id| self.ids.iter().any(|x| x == id))
    }
}

impl NativeServer {
    /** @brief 차단·접근 제어·속도 제한과 해석 체인을 잡은 핸들러를 만든다. */
    pub fn new(
        filter: Arc<SharedFilter>,
        acl: Arc<dyn AccessControl>,
        rate_limiters: Vec<Arc<dyn RateLimiter>>,
        backend: Arc<dyn Resolver>,
        block_ttl: u32,
    ) -> Self {
        NativeServer {
            filter,
            acl,
            rate_limiters,
            backend,
            client_upstreams: Vec::new(),
            reactor_lane: None,
            block_ttl: Arc::new(AtomicU32::new(block_ttl)),
            local_ttl: Arc::new(AtomicU32::new(300)),
            features: Arc::new(NativeFeatureSwap::from_pointee(NativeFeatures::default())),
            recorder: None,
            mac_cache: None,
            safe_search: Arc::new(AtomicBool::new(false)),
            inflight: AtomicUsize::new(0),
            rotor: AtomicUsize::new(0),
            policy: Arc::new(GatedSwap::from_pointee(
                onetdns_policy::PolicyEngine::default(),
            )),
            xfr_store: None,
            authority: Arc::new(ArcSwap::from_pointee(AuthoritySettings::default())),
            tsig_replay: std::sync::Mutex::new(LruMap::new(4096)),
            update_notify: None,
            notify_kick: Arc::new(NotifyKick::default()),
            journal: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            views: Arc::new(GatedSwap::from_pointee(Vec::new())),
            authority_wire_path: None,
        }
    }

    /** @brief 재귀 대기가 스레드를 붙잡지 않는 레인을 붙인다. */
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn with_reactor_lane(
        self,
        recursor: Arc<Recursor>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        self.with_reactor_lane_runtime(Some(recursor), cache, inflight)
    }

    /** @brief 재귀 리졸버가 아직 없는 세대도 나중에 레인을 켤 수 있게 슬롯을 붙인다. */
    pub fn with_reactor_lane_runtime(
        mut self,
        recursor: Option<Arc<Recursor>>,
        cache: crate::cache::CacheHandle,
        inflight: usize,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let factory = features
            .lane_runtime
            .as_ref()
            .and_then(|runtime| runtime.factory);
        features.lane_runtime = Some(Arc::new(LaneRuntime {
            factory,
            cache,
            recursor,
        }));
        self.features.store(Arc::new(features));
        self.reactor_lane = Some(ReactorLaneShared {
            inflight,
            chain: self.backend.clone(),
        });
        self
    }

    /** @brief 차단과 고정해 둔 주소의 수명 출처를 붙인다. */
    pub fn with_ttl_sources(
        mut self,
        block_ttl: Arc<AtomicU32>,
        local_ttl: Arc<AtomicU32>,
    ) -> Self {
        self.block_ttl = block_ttl;
        self.local_ttl = local_ttl;
        self
    }

    /** @brief 캐시가 맞은 UDP 질의의 빠른 경로를 붙인다. */
    pub fn with_wire_fast_path(
        self,
        fast_path: Option<(
            crate::wirecache::WireEntryFactory,
            crate::cache::CacheHandle,
        )>,
    ) -> Self {
        let mut features = (*self.features.load()).clone();
        let previous = features.lane_runtime.clone();
        features.lane_runtime = match fast_path {
            Some((factory, cache)) => Some(Arc::new(LaneRuntime {
                factory: Some(factory),
                cache,
                recursor: previous.and_then(|runtime| runtime.recursor.clone()),
            })),
            None => previous.map(|runtime| {
                Arc::new(LaneRuntime {
                    factory: None,
                    cache: runtime.cache.clone(),
                    recursor: runtime.recursor.clone(),
                })
            }),
        };
        self.features.store(Arc::new(features));
        self
    }

    /** @brief 권한 영역 단순 질의의 빠른 경로를 붙인다. */
    pub fn with_authority_wire_path(
        mut self,
        store: Option<Arc<ArcSwap<onetdns_authority::ZoneStore>>>,
        recursion_available: bool,
    ) -> Self {
        self.authority_wire_path = store.map(|store| AuthorityWirePath {
            store,
            recursion_available,
        });
        self
    }

    /** @brief 클라이언트별로 다르게 답할 뷰를 붙인다. */
    pub fn with_views(mut self, views: Vec<NativeView>) -> Self {
        self.views = Arc::new(GatedSwap::from_pointee(views));
        self
    }

    /** @brief 변경 기록 기록을 붙인다. */
    pub fn with_journal(
        mut self,
        journal: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, ZoneJournal>>>,
    ) -> Self {
        self.journal = journal;
        self
    }

    /** @brief 업스트림 서버 알림을 받을 곳을 붙인다. */
    pub fn with_notify_kick(mut self, kick: Arc<NotifyKick>) -> Self {
        self.notify_kick = kick;
        self
    }

    #[cfg(test)]
    /** @brief 변경을 알릴 하위 서버 목록을 붙인다. */
    pub fn with_notify_secondaries(
        mut self,
        secondaries: Vec<(ApName, IpAddr, Option<ApName>)>,
        kick: Arc<NotifyKick>,
    ) -> Self {
        self.edit_authority(|a| a.notify_secondaries = secondaries);
        self.notify_kick = kick;
        self
    }

    /** @brief 기능 세트를 붙인다. */
    pub fn with_features(mut self, features: NativeFeatures) -> Self {
        self.features = Arc::new(NativeFeatureSwap::from_pointee(features));
        self
    }

    /** @brief 지표와 질의 기록을 보낼 곳을 붙인다. */
    pub fn with_recorder(mut self, recorder: Option<Recorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /** @brief 클라이언트 하드웨어 주소 조회를 붙인다. */
    pub fn with_mac_cache(mut self, mac_cache: Option<Arc<crate::mac::NeighborCache>>) -> Self {
        self.mac_cache = mac_cache;
        self
    }

    /** @brief 시간대 작업과 설정 교체가 함께 바꾸는 안전 검색 스위치를 붙인다. */
    pub fn with_safe_search(mut self, safe_search: Arc<AtomicBool>) -> Self {
        self.safe_search = safe_search;
        self
    }

    /**
     * @brief 질의마다 기록을 남길 곳.
     *
     * @details 기록기가 있어도 볼 곳이 없으면 없는 것으로 답한다. 그 자리에서 만드는 이름과
     *          시계 읽기가 질의마다 드는 비용이라, 만들어서 버릴 것이면 만들지 않아야 한다.
     * @return 볼 곳이 있을 때만 기록기.
     */
    pub fn events(&self) -> Option<&Recorder> {
        self.recorder.as_ref().filter(|r| r.collecting())
    }

    /** @brief 클라이언트별 업스트림 경로를 붙인다. */
    pub fn with_client_upstreams(mut self, client_upstreams: Vec<ClientUpstream>) -> Self {
        self.client_upstreams = client_upstreams;
        self
    }

    /**
     * @brief 정책 엔진 슬롯을 붙인다.
     * @details 관리 API의 시뮬레이션과 설명도 같은 슬롯을 읽는다. 따로 가지고 있으면 설정을
     *          바꾼 뒤에도 이전 정책으로 답한다.
     */
    pub fn with_policy(mut self, policy: Arc<GatedSwap<onetdns_policy::PolicyEngine>>) -> Self {
        self.policy = policy;
        self
    }

    /** @brief 권한 영역 설정 세트의 한 부분을 고쳐 넣는다. */
    fn edit_authority(&self, edit: impl FnOnce(&mut AuthoritySettings)) {
        let mut next = (*self.authority.load()).clone();
        edit(&mut next);
        self.authority.store(Arc::new(next));
    }

    /** @brief 권한 영역 설정을 전부 교체한다. */
    pub fn replace_authority(&self, settings: AuthoritySettings) {
        self.authority.store(Arc::new(settings));
    }

    /** @brief 영역 전송을 켠다. */
    pub fn with_xfr(
        mut self,
        store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
        allow: Vec<IpNet>,
    ) -> Self {
        self.xfr_store = Some(store);
        self.edit_authority(|a| a.xfr_allow = allow);
        self
    }

    #[cfg(test)]
    /** @brief 공유 키 목록을 붙인다. 요구로 두면 서명 없는 요청을 거절한다. */
    pub fn with_tsig(self, keys: Vec<onetdns_dnssec::tsig::TsigKey>, required: bool) -> Self {
        self.edit_authority(|a| {
            a.tsig_keys = keys;
            a.xfr_tsig_required = required;
        });
        self
    }

    #[cfg(test)]
    /** @brief 원격 영역 업데이트를 켠다. */
    pub fn with_ddns(
        self,
        allow: Vec<IpNet>,
        tsig_required: bool,
        targets: Vec<UpdateTarget>,
    ) -> Self {
        self.edit_authority(|a| {
            a.update_allow = allow;
            a.update_tsig_required = tsig_required;
            a.update_targets = targets;
        });
        self
    }

    /** @brief 영역이 고쳐졌을 때 부를 것을 붙인다. */
    pub fn with_update_notify(mut self, notify: Arc<dyn Fn(&ApName, u32) + Send + Sync>) -> Self {
        self.update_notify = Some(notify);
        self
    }

    /** @brief 이 클라이언트에 맞는 체인으로 해석한다. */
    fn resolve_for(&self, request: &Message, client: &ClientInfo) -> ResolveOutcome {
        if let Some(route) = self.client_upstreams.iter().find(|r| r.matches(client)) {
            return route.resolver.resolve_outcome(request);
        }
        self.backend.resolve_outcome(request)
    }

    /** @brief 이 클라이언트에 맞는 체인으로 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve_message_for(&self, request: &Message, client: &ClientInfo) -> Option<Message> {
        match self.resolve_for(request, client) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /** @brief 이 클라이언트가 어느 경로로 가는지. 기록에 남긴다. */
    fn resolver_mode(&self, client: &ClientInfo) -> &'static str {
        if self.client_upstreams.iter().any(|r| r.matches(client)) {
            "client_route"
        } else {
            "backend"
        }
    }
}

#[cfg(test)]
mod tests;
