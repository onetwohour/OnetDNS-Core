/*!
 * @brief 정책 엔진: 네이티브 규칙과 WASM 플러그인.
 *
 * @details 네이티브 규칙을 먼저 보고 그다음 플러그인을 순서대로 부른다. Continue가
 *          아닌 첫 결과가 이긴다. 플러그인은 WASM 인터프리터에서 연료 제한과
 *          메모리 상한 아래 돌아, 잘못 만든 플러그인이 서버를 멈추지 못한다.
 */

use std::net::{IpAddr, Ipv4Addr};

/** @brief 설정에 적는 규칙. */
mod rules;
/** @brief 플러그인을 올리고 부르는 부분. */
mod wasm;
/** @brief 플러그인을 실제로 돌리는 리졸버. */
mod wasmrt;

pub use rules::{Rule, RuleEngine, TimeWindow};
pub use wasm::{FailureMode, PluginMetricsSnapshot, WasmPolicy};

/**
 * @brief 정책에 노출되는 전송 종류.
 * @note 별도 타입인 이유는 code()가 WASM ABI의 일부이기 때문이다. 다른 전송 열거형의
 *       변형 순서가 바뀌어도 플러그인이 보는 값은 흔들리지 않아야 한다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryTransport {
    #[default]
    /** @brief 평문 UDP. */
    Do53Udp,
    /** @brief 평문 TCP. */
    Do53Tcp,
    /** @brief TLS 위. */
    Dot,
    /** @brief HTTP 위. */
    Doh,
    /** @brief HTTP/3 위. */
    Doh3,
    /** @brief QUIC 위. */
    Doq,
    /** @brief DNSCrypt. */
    DnsCrypt,
}

impl QueryTransport {
    /**
     * @brief WASM 문맥에 담기는 전송 코드.
     * @warning ABI 계약이다. 이미 배포된 플러그인이 이 숫자를 그대로 읽으므로 바꾸면 안 된다.
     */
    pub fn code(self) -> u8 {
        match self {
            QueryTransport::Do53Udp => 0,
            QueryTransport::Do53Tcp => 1,
            QueryTransport::Dot => 2,
            QueryTransport::Doh => 3,
            QueryTransport::Doh3 => 4,
            QueryTransport::Doq => 5,
            QueryTransport::DnsCrypt => 6,
        }
    }
}

/**
 * @brief 질의 시점에 정책이 보는 값.
 * @details 이 구조가 그대로 WASM 문맥으로 직렬화된다. 필드를 늘리면 ABI 버전을 올려야 한다.
 */
pub struct PolicyInput<'a> {
    /** @brief 질의를 보낸 곳. */
    pub client: IpAddr,

    /** @brief 물어본 이름. */
    pub qname: &'a str,
    /** @brief 질의 종류. */
    pub qtype: u16,

    /** @brief 요청 시각. 유닉스 기원부터 흐른 초. 이 값이 WASM 문맥에 담긴다. */
    pub unix_time: u64,

    /**
     * @brief 지역 시각으로 일요일 0시부터 흐른 분. 시간대 조건이 쓴다.
     * @details 시간대 조건은 절대 시각이 아니라 요일과 하루 중 시각만 보므로 지역 시각으로
     *          접은 값을 따로 받는다. WASM 문맥에는 담기지 않는다.
     */
    pub local_minute_of_week: u32,

    /** @brief 어느 전송으로 왔는지. */
    pub transport: QueryTransport,
    /** @brief 알아낸 클라이언트 식별자. */
    pub client_id: Option<&'a str>,
    /** @brief 인증된 연결로 왔는지. */
    pub authenticated: bool,
}

/**
 * @brief 응답 시점에 정책이 보는 값.
 * @details 응답에 담긴 주소를 보고 판정할 수 있게 한다. 이름이 아니라 결과 주소로
 *          걸러야 하는 규칙(재바인딩 방어 등)이 이 훅을 쓴다.
 */
pub struct ResponseInput<'a> {
    /** @brief 물어본 이름. */
    pub qname: &'a str,
    /** @brief 질의 종류. */
    pub qtype: u16,
    /** @brief 응답 코드. */
    pub rcode: u16,
    /** @brief 답에 담긴 주소들. */
    pub addrs: &'a [IpAddr],
}

/** @brief 응답 훅의 판정. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    /** @brief 그대로 내보낸다. */
    Pass,
    /** @brief 차단한다. */
    Block,
    /** @brief 거절로 답한다. */
    Refuse,
}

/** @brief 정책 판정. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /** @brief 이 정책은 판단하지 않는다. 다음 정책으로 넘어간다. */
    Continue,

    /**
     * @brief 명시적 허용.
     * @details 다음 정책도 계속 보되, 마지막까지 차단이 없으면 허용으로 확정된다.
     *          이후 정책이 차단하면 그쪽이 이긴다.
     */
    Allow,

    /** @brief 차단. 즉시 종결된다. */
    Block,

    /** @brief REFUSED로 거절. 즉시 종결된다. */
    Refuse,

    /** @brief 지정한 주소로 재작성. */
    Rewrite(Ipv4Addr),
}

impl Action {
    /**
     * @brief WASM 반환 코드를 판정으로 바꾼다.
     * @warning ABI 계약이다. 모르는 코드는 오류로 처리해 실패 모드 정책이 적용되게 한다.
     *          임의로 Continue에 매핑하면 플러그인 버그가 조용한 통과가 된다.
     */
    fn from_code(code: i32) -> Result<Action, String> {
        match code {
            0 => Ok(Action::Continue),
            1 => Ok(Action::Allow),
            2 => Ok(Action::Block),
            3 => Ok(Action::Refuse),
            other => Err(format!("Unknown policy return code: {other}")),
        }
    }
}

/** @brief 정책 로드·실행 오류. */
#[derive(Debug)]
pub enum PolicyError {
    /** @brief 플러그인 쪽에서 실패했다. */
    Wasm(String),
}

impl std::fmt::Display for PolicyError {
    /** @brief 사람이 읽을 문구. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Wasm(s) => write!(f, "WASM policy error: {s}"),
        }
    }
}
impl std::error::Error for PolicyError {}

/** @brief 네이티브 규칙과 WASM 플러그인을 묶은 정책 엔진. */
#[derive(Default)]
pub struct PolicyEngine {
    /** @brief 설정에 적은 규칙들. */
    rules: RuleEngine,
    /** @brief 올린 플러그인들. */
    plugins: Vec<WasmPolicy>,
}

impl PolicyEngine {
    /** @brief 규칙과 플러그인으로 엔진을 만든다. 플러그인은 주어진 순서대로 평가된다. */
    pub fn new(rules: RuleEngine, plugins: Vec<WasmPolicy>) -> Self {
        PolicyEngine { rules, plugins }
    }

    /** @brief 로드된 플러그인 수. */
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /** @brief 플러그인별 실행 통계. 대시보드가 연료 소진·트랩 빈도를 보여 준다. */
    pub fn plugin_metrics(&self) -> Vec<(String, PluginMetricsSnapshot)> {
        self.plugins
            .iter()
            .map(|p| (p.name().to_string(), p.metrics()))
            .collect()
    }

    /** @brief 아무 정책도 없는지. 비어 있으면 호출자가 평가 자체를 건너뛴다. */
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.plugins.is_empty()
    }

    /**
     * @brief 질의를 평가한다.
     * @details 네이티브 규칙 → 플러그인 순서로 보고, Continue가 아닌 첫 결과에서 멈춘다.
     *          Allow만 예외로 계속 진행한다. 뒤쪽 정책이 차단할 기회를 남기기 위해서다.
     * @return 아무도 판단하지 않았으면 Continue, 허용만 있었으면 Allow.
     */
    pub fn evaluate(&self, input: &PolicyInput) -> Action {
        let mut allow = false;
        match self.rules.evaluate(input) {
            Action::Continue => {}
            Action::Allow => allow = true,
            terminal => return terminal,
        }
        for p in &self.plugins {
            match p.evaluate(input) {
                Action::Continue => {}
                Action::Allow => allow = true,
                terminal => return terminal,
            }
        }
        if allow {
            Action::Allow
        } else {
            Action::Continue
        }
    }

    /** @brief 응답 훅을 가진 플러그인이 있는지. 없으면 응답 경로에서 아예 부르지 않는다. */
    pub fn has_response_hook(&self) -> bool {
        self.plugins.iter().any(WasmPolicy::has_response_hook)
    }

    /** @brief 응답을 평가한다. Pass가 아닌 첫 판정이 이긴다. */
    pub fn evaluate_response(&self, input: &ResponseInput) -> ResponseVerdict {
        for p in &self.plugins {
            match p.evaluate_response(input) {
                ResponseVerdict::Pass => {}
                terminal => return terminal,
            }
        }
        ResponseVerdict::Pass
    }
}
