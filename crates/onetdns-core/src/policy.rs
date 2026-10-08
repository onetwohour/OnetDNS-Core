/*!
 * @brief 데이터 평면과 정책 구현을 잇는 트레이트 경계.
 *
 * @details 서버는 어떤 필터·ACL·속도 제한이 꽂혀 있는지 모른다. 이 트레이트들만 안다.
 *          덕분에 정책 구현을 전부 교체해도 질의 경로가 바뀌지 않는다.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use onetdns_proto::{Name, RData, RecordType};

use crate::client::ClientInfo;

/** @brief 접근 제어 판정. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /** @brief 받아들인다. */
    Allow,
    /** @brief 막고, 막았다는 응답을 보낸다. */
    Deny,
    /** @brief 막고, 아무 응답도 보내지 않는다. 어느 규칙으로 버렸는지 함께 담는다. */
    Drop(DropReason),
}

/**
 * @brief 응답 없이 버린 까닭.
 * @details 버림은 클라이언트에게 아무것도 알리지 않으므로 운영자가 볼 수 있는 것은 로그뿐이다.
 *          목록 밖 버림은 인터넷 전체의 탐색 트래픽을 받아 버림 목록의 기록을 묻어 버리므로
 *          까닭을 가려 따로 센다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /** @brief 버림 목록에 든 주소다. */
    DropList,
    /** @brief 어느 규칙에도 걸리지 않았고, 그런 클라이언트는 버리도록 설정됐다. */
    Unlisted,
}

/** @brief 클라이언트 주소 기반 접근 제어. */
pub trait AccessControl: Send + Sync {
    /**
     * @brief 이 클라이언트를 받아들일지 판정한다.
     * @warning 질의마다 불리는 핫패스다. 여기서 잠금을 오래 잡으면 처리량 전체가 눌린다.
     */
    fn check(&self, client: &ClientInfo) -> AclDecision;

    /**
     * @brief 이 주소에서 온 것을 응답 없이 버려야 하는지와 그 까닭.
     * @details 주소만으로 정하므로 전송은 질의를 읽거나 핸드셰이크를 하기 전에 이 판정을 쓸 수
     *          있다. 값이 있으면 그 주소의 클라이언트가 어떤 ID 를 가져오든 check 도 같은 까닭의
     *          Drop 을 돌려줘야 한다. 클라이언트 ID 규칙이 없으면 두 판정은 정확히 같다.
     */
    fn drops(&self, ip: IpAddr) -> Option<DropReason>;

    /**
     * @brief 규칙이 없어 항상 허용인지.
     * @details wire 고속 경로가 이걸 보고 재검사를 건너뛴다. 규칙이 하나라도 있으면
     *          false여야 한다. 잘못 true를 돌려주면 ACL이 우회된다.
     */
    fn is_trivially_allow(&self) -> bool {
        false
    }
}

/** @brief 속도 제한 판정. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /** @brief 몫이 남았다. */
    Permit,
    /** @brief 몫이 떨어졌다. */
    Throttle,
}

/** @brief 클라이언트별 질의 속도 제한. */
pub trait RateLimiter: Send + Sync {
    /** @brief 이 질의를 통과시킬지 판정하고 카운터를 갱신한다. */
    fn check(&self, client: &ClientInfo) -> RateDecision;

    /**
     * @brief 실제로 제한이 걸려 있는지.
     * @note 속도 0은 비활성이다. Public 모드는 활성 제한기를 요구하므로 이 값이 설정
     *       검증에도 쓰인다. 제한 없는 개방 리졸버는 증폭 공격의 발판이 된다.
     */
    fn is_active(&self) -> bool {
        true
    }
}

/**
 * @brief 차단된 질의에 무엇을 돌려줄지.
 * @note 선택에 따라 클라이언트 체감이 다르다. NXDOMAIN은 빠르게 실패하고, 0.0.0.0은
 *       연결 시도 후 타임아웃이 나며, NODATA는 이름은 있으나 그 타입이 없다고 말한다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    /** @brief 이름이 없다고 답한다. 기본값이며 클라이언트가 가장 빨리 포기한다. */
    #[default]
    NxDomain,

    /** @brief 0.0.0.0 / :: 을 돌려준다. */
    ZeroIp,
    /** @brief REFUSED. 차단 사실이 가장 뚜렷하게 드러난다. */
    Refused,

    /** @brief 이름은 존재하되 해당 타입 레코드가 없다고 답한다. */
    NoData,

    /** @brief 운영자가 지정한 주소로 돌린다. 차단 안내 페이지를 시작할 때 쓴다. */
    Custom {
        /** @brief IPv4 질의에 답할 주소. */
        v4: Option<Ipv4Addr>,
        /** @brief IPv6 질의에 답할 주소. */
        v6: Option<Ipv6Addr>,
    },
}

/** @brief 재작성 규칙이 실제 응답 대신 넣을 내용. */
#[derive(Debug, Clone)]
pub enum RewriteTarget {
    /** @brief 완성된 레코드로 대체한다. */
    Records(Vec<RData>),

    /** @brief 다른 이름으로 CNAME을 건다. 뒤이은 해석은 정상 경로를 탄다. */
    Cname(Name),
}

impl RewriteTarget {
    /** @brief 주소 하나를 담은 대상. IP 종류에 맞춰 A 또는 AAAA가 된다. */
    pub fn ip(ip: std::net::IpAddr) -> Self {
        let rdata = match ip {
            std::net::IpAddr::V4(v4) => RData::A(v4),
            std::net::IpAddr::V6(v6) => RData::Aaaa(v6),
        };
        RewriteTarget::Records(vec![rdata])
    }
}

/** @brief 필터 판정 결과. */
#[derive(Debug, Clone)]
pub enum FilterVerdict {
    /** @brief 통과. wire 고속 경로에 저장될 수 있는 유일한 판정이다. */
    Allow,
    /** @brief 차단하고 지정된 형태로 응답한다. */
    Block(BlockResponse),

    /** @brief 다른 내용으로 응답을 바꾼다. */
    Rewrite(RewriteTarget),

    /**
     * @brief 차단하고 아무것도 답하지 않는다.
     * @details 운영자가 이름에 NORESPONSE 를 고른 규칙에서만 나온다. 응답의 형태가 아니라 응답을
     *          하지 않는 판정이라 BlockResponse 에 두지 않는다. 거기 두면 기본 차단 응답으로도 고를
     *          수 있게 되고, 차단 응답을 만드는 곳마다 만들 수 없는 경우를 떠안는다.
     */
    Drop,
}

/**
 * @brief 판정이 결정된 우선순위 단계.
 *
 * @details 나열 순서가 곧 우선순위다. 위에서 먼저 맞은 단계가 이긴다. 클라이언트별 정책이
 *          전역 규칙을 이기고, important 표시가 일반 규칙을 이기며, 허용이 같은 층의
 *          차단을 이긴다. 진단에서 "왜 이렇게 판정됐는가"를 답하는 값이다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStage {
    /** @brief 이 클라이언트는 필터링 자체를 끄도록 설정됐다. */
    ClientPolicyDisable,

    /** @brief 클라이언트별 허용 목록에 맞았다. */
    ClientPolicyAllow,
    /** @brief 클라이언트별 차단 목록에 맞았다. */
    ClientPolicyBlock,

    /** @brief RPZ의 클라이언트 IP 규칙에 맞았다. */
    RpzClientIp,

    /** @brief 클라이언트를 한정한 규칙의 허용. */
    ClientRuleAllow,
    /** @brief 클라이언트를 한정한 규칙의 차단. */
    ClientRuleBlock,

    /** @brief $important 허용. 일반 차단을 무력화한다. */
    ImportantAllow,

    /** @brief 아무것도 답하지 않는 규칙. 전역 규칙 가운데서는 important 허용만 이것을 이긴다. */
    NoResponse,

    /** @brief $important 차단. 일반 허용을 무력화한다. */
    ImportantBlock,

    /** @brief REFUSED로 응답하는 규칙. */
    Refuse,

    /** @brief NODATA로 응답하는 규칙. */
    NoData,

    /** @brief 재작성 규칙. */
    Rewrite,

    /** @brief 일반 허용 규칙(@@). */
    Allow,
    /** @brief 정규식 허용 규칙. */
    RegexAllow,

    /** @brief 일반 차단 규칙. */
    Block,
    /** @brief 정규식 차단 규칙. */
    RegexBlock,
    /** @brief 특정 레코드 타입만 겨냥한 차단. */
    TypedBlock,

    /** @brief 아무 규칙에도 맞지 않아 통과. */
    DefaultAllow,
}

impl MatchStage {
    /** @brief 로그·API에 나가는 안정된 식별 문자열. 대시보드가 이 값을 그대로 읽는다. */
    pub fn as_str(self) -> &'static str {
        match self {
            MatchStage::ClientPolicyDisable => "client-policy:disable-filtering",
            MatchStage::ClientPolicyAllow => "client-policy:allow",
            MatchStage::ClientPolicyBlock => "client-policy:block",
            MatchStage::RpzClientIp => "rpz-client-ip",
            MatchStage::ClientRuleAllow => "client-rule:allow",
            MatchStage::ClientRuleBlock => "client-rule:block",
            MatchStage::ImportantAllow => "important:allow",
            MatchStage::NoResponse => "noresponse",
            MatchStage::ImportantBlock => "important:block",
            MatchStage::Refuse => "refuse",
            MatchStage::NoData => "nodata",
            MatchStage::Rewrite => "rewrite",
            MatchStage::Allow => "allow",
            MatchStage::RegexAllow => "regex:allow",
            MatchStage::Block => "block",
            MatchStage::RegexBlock => "regex:block",
            MatchStage::TypedBlock => "typed-block",
            MatchStage::DefaultAllow => "default-allow",
        }
    }
}

/** @brief 판정과 그 근거. 질의 로그와 check 진단이 쓴다. */
#[derive(Debug, Clone)]
pub struct FilterExplanation {
    /** @brief 판정 결과. */
    pub verdict: FilterVerdict,
    /** @brief 어느 단계에서 갈렸는지. */
    pub stage: MatchStage,

    /** @brief 실제로 맞은 규칙 원문. 어느 목록의 어느 줄이 걸었는지 추적하는 값이다. */
    pub matched: Option<String>,
    /**
     * @brief 맞은 규칙이 들어 있던 목록의 이름.
     * @details 파일 목록은 경로, 구독 목록은 주소다. 직접 입력한 규칙처럼 목록에 속하지
     *          않으면 없다.
     */
    pub source: Option<String>,
}

/** @brief 도메인 차단 엔진. */
pub trait FilterEngine: Send + Sync {
    /**
     * @brief 이 질의를 어떻게 처리할지 판정한다.
     * @warning 질의마다 불리는 핫패스다. 구현은 할당 없이 끝나야 한다.
     */
    fn verdict(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterVerdict;

    /**
     * @brief 판정과 함께 근거를 돌려준다.
     * @details 기본 구현은 판정만 보고 단계를 되짚기 때문에 정확한 단계를 알지 못한다.
     *          정밀한 진단이 필요한 엔진은 반드시 재정의해야 한다.
     */
    fn explain(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterExplanation {
        let verdict = self.verdict(name, qtype, client);
        let stage = match &verdict {
            FilterVerdict::Allow => MatchStage::DefaultAllow,
            FilterVerdict::Block(_) => MatchStage::Block,
            FilterVerdict::Rewrite(_) => MatchStage::Rewrite,
            FilterVerdict::Drop => MatchStage::NoResponse,
        };
        FilterExplanation {
            verdict,
            stage,
            matched: None,
            source: None,
        }
    }
}
