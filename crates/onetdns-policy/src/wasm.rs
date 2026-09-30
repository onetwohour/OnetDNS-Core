use std::net::{IpAddr, Ipv4Addr};

use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::Mutex;

use crate::wasmrt::{Instance, InstanceState, Module, ValType, Value};
use crate::{Action, PolicyError, PolicyInput, ResponseInput, ResponseVerdict};

/**
 * @brief 플러그인 호출 하나가 쓸 수 있는 명령 예산.
 * @warning 이 상한이 없으면 무한 루프를 담은 플러그인 하나가 워커를 영구히 붙든다.
 *          소진되면 트랩이 나고 실패 모드 정책이 적용된다.
 * @note 대표 정책의 최장 테스트 분기는 62 fuel이다. 이 값은 800배 이상의 여유를 둔다.
 */
const FUEL_LIMIT: u64 = 50_000;

/** @brief 플러그인 선형 메모리 상한. 정책 문맥 처리에 충분한 2 MiB로 요청별 메모리를 묶는다. */
const MEM_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/** @brief 재사용을 위해 보관할 인스턴스 상태 수. */
const STATE_POOL_MAX: usize = 4;

/**
 * @brief 재사용 대상으로 남길 인스턴스 메모리의 상한.
 * @details 크게 자란 상태는 되돌려 받지 않고 버린다. 그러지 않으면 한 번의 큰 호출이
 *          키워 놓은 메모리를 플러그인 수명 내내 붙잡고 있게 된다.
 */
const STATE_POOL_RETAIN_MEM_MAX: usize = 2 * 1024 * 1024;

/**
 * @brief 플러그인이 실패했을 때의 처리 방식.
 * @details 기본은 거절(fail-closed)이다. 정책이 판단하지 못한 질의를 통과시키는 것은
 *          정책을 껐다는 뜻이므로, 운영자가 명시적으로 open을 고를 때만 통과시킨다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    /** @brief 실패를 무시하고 통과시킨다. 가용성을 정확성보다 앞세우는 선택이다. */
    Open,
    /** @brief 차단으로 처리한다. */
    ClosedBlock,
    /** @brief REFUSED로 처리한다. 기본값이다. */
    #[default]
    ClosedRefuse,
}

impl FailureMode {
    /** @brief 실패 시 적용할 질의 판정. */
    fn action(self) -> Action {
        match self {
            FailureMode::Open => Action::Continue,
            FailureMode::ClosedBlock => Action::Block,
            FailureMode::ClosedRefuse => Action::Refuse,
        }
    }

    /** @brief 실패 시 적용할 응답 판정. */
    fn response_verdict(self) -> ResponseVerdict {
        match self {
            FailureMode::Open => ResponseVerdict::Pass,
            FailureMode::ClosedBlock => ResponseVerdict::Block,
            FailureMode::ClosedRefuse => ResponseVerdict::Refuse,
        }
    }

    /** @brief 설정 문자열을 실패 모드로 바꾼다. 알 수 없는 값은 오류다. */
    pub fn parse(s: &str) -> Result<FailureMode, PolicyError> {
        let mode = match s {
            "closed-block" => FailureMode::ClosedBlock,
            "closed-refuse" => FailureMode::ClosedRefuse,
            "open" => FailureMode::Open,
            other => {
                return Err(PolicyError::Wasm(format!(
                    "Unknown WASM failure mode: {other}"
                )))
            }
        };
        Ok(mode)
    }
}

/** @brief 플러그인 실행 카운터. 잠금 없이 갱신되도록 전부 원자값이다. */
#[derive(Debug, Default)]
pub struct PluginMetrics {
    /** @brief 부른 횟수. */
    pub eval_total: AtomicU64,
    /** @brief 실패한 횟수. */
    pub error_total: AtomicU64,

    /** @brief 연료 소진으로 끝난 횟수. 예산이 모자란 플러그인을 찾아내는 지표다. */
    pub timeout_total: AtomicU64,
    /** @brief 막은 횟수. */
    pub block_total: AtomicU64,

    /** @brief 걸린 시간의 합. */
    pub latency_us_total: AtomicU64,
}

/** @brief 카운터를 한 시점에서 읽은 값. */
#[derive(Debug, Clone, Copy)]
pub struct PluginMetricsSnapshot {
    /** @brief 부른 횟수. */
    pub eval_total: u64,
    /** @brief 실패한 횟수. */
    pub error_total: u64,
    /** @brief 연료가 떨어진 횟수. */
    pub timeout_total: u64,
    /** @brief 막은 횟수. */
    pub block_total: u64,
    /** @brief 걸린 시간의 합. */
    pub latency_us_total: u64,
}

/**
 * @brief WASM 정책 플러그인 하나.
 * @details 모듈은 한 번 파싱해 두고 호출마다 인스턴스를 만든다. 인스턴스 상태를 풀에
 *          모아 두어 재사용하므로, 호출마다 메모리를 새로 잡지 않는다.
 */
pub struct WasmPolicy {
    /** @brief 올려 둔 플러그인. */
    module: Module,
    /** @brief 로그와 대시보드에 보일 이름. */
    name: String,
    /** @brief 실패했을 때의 처분. */
    fail_mode: FailureMode,
    /** @brief 이 플러그인의 지표. */
    metrics: PluginMetrics,
    /** @brief 다시 쓰려고 모아 둔 실행 상태들. */
    state_pool: Mutex<Vec<InstanceState>>,
    /** @brief 응답 쪽에도 걸리는 플러그인인지. */
    response_hook: bool,
}

impl WasmPolicy {
    /**
     * @brief WASM 바이트열을 파싱하고 ABI를 검사한다.
     *
     * @details 필수 내보내기(memory, alloc, evaluate)의 형식까지 대조한다.
     *          이름만 확인하면 형식이 다른 함수가 호출 시점에야 트랩을 내는데, 그때는
     *          이미 질의 처리 중이라 실패 모드로 떨어진다. 로드 시점에 걸러야 한다.
     * @note on_response는 선택이다. 있으면 형식을 검사하고, 없으면 응답 훅을 끈다.
     */
    pub fn from_wasm(bytes: &[u8]) -> Result<Self, PolicyError> {
        let module = Module::parse(bytes).map_err(PolicyError::Wasm)?;
        if !module.has_memory_export("memory") {
            return Err(PolicyError::Wasm(
                "memory export is missing or invalid".into(),
            ));
        }
        let require_signature =
            |name: &str, params: &[ValType], results: &[ValType]| -> Result<(), PolicyError> {
                match module.func_export_signature(name) {
                    Some((actual_params, actual_results))
                        if actual_params == params && actual_results == results =>
                    {
                        Ok(())
                    }
                    _ => Err(PolicyError::Wasm(format!(
                        "WASM function {name} does not match the current ABI"
                    ))),
                }
            };
        require_signature("alloc", &[ValType::I32], &[ValType::I32])?;
        require_signature("evaluate", &[ValType::I32, ValType::I32], &[ValType::I32])?;
        let response_hook = module.has_export("on_response");
        if response_hook {
            require_signature(
                "on_response",
                &[ValType::I32, ValType::I32],
                &[ValType::I32],
            )?;
        }
        Instance::instantiate_with(
            &module,
            FUEL_LIMIT,
            MEM_LIMIT_BYTES,
            InstanceState::default(),
        )
        .map_err(PolicyError::Wasm)?;
        Ok(WasmPolicy {
            module,
            name: "wasm".to_string(),
            fail_mode: FailureMode::ClosedRefuse,
            metrics: PluginMetrics::default(),
            state_pool: Mutex::new(Vec::new()),
            response_hook,
        })
    }

    /** @brief 응답 훅을 내보내는 플러그인인지. */
    pub fn has_response_hook(&self) -> bool {
        self.response_hook
    }

    /** @brief 로그·지표에 쓸 이름을 지정한다. */
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /** @brief 실패 모드를 지정한다. 기본은 거절이다. */
    pub fn with_failure_mode(mut self, mode: FailureMode) -> Self {
        self.fail_mode = mode;
        self
    }

    /** @brief 플러그인 이름. */
    pub fn name(&self) -> &str {
        &self.name
    }

    /** @brief 현재 카운터 값. */
    pub fn metrics(&self) -> PluginMetricsSnapshot {
        PluginMetricsSnapshot {
            eval_total: self.metrics.eval_total.load(Ordering::Relaxed),
            error_total: self.metrics.error_total.load(Ordering::Relaxed),
            timeout_total: self.metrics.timeout_total.load(Ordering::Relaxed),
            block_total: self.metrics.block_total.load(Ordering::Relaxed),
            latency_us_total: self.metrics.latency_us_total.load(Ordering::Relaxed),
        }
    }

    /**
     * @brief 질의를 평가하고 카운터를 갱신한다.
     * @details 실행 오류·트랩·연료 소진은 모두 실패 모드로 합쳐진다. 플러그인 결함이
     *          질의 처리 자체를 깨뜨리지 않게 하는 경계다.
     */
    pub fn evaluate(&self, input: &PolicyInput) -> Action {
        let start = std::time::Instant::now();
        self.metrics.eval_total.fetch_add(1, Ordering::Relaxed);
        let action = match self.try_eval(input) {
            Ok(a) => a,
            Err(error) => {
                let count = self.metrics.error_total.fetch_add(1, Ordering::Relaxed) + 1;
                let action = self.fail_mode.action();
                if count.is_power_of_two() {
                    onetdns_core::warn!(event = "policy.wasm_eval_failed", plugin = %self.name, count = count, fallback = ?action, %error, "Policy plugin could not evaluate the query; applied the failure mode");
                }
                action
            }
        };
        if matches!(action, Action::Block | Action::Refuse) {
            self.metrics.block_total.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics
            .latency_us_total
            .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        action
    }

    /**
     * @brief 인스턴스를 만들어 evaluate를 호출한다.
     * @note 남은 연료가 0인 채로 실패했으면 예산 소진으로 따로 센다. 다른 트랩과 구분해야
     *       예산이 모자란 플러그인을 찾을 수 있다.
     * @note 인스턴스 상태는 실패했더라도 풀에 되돌린다. 메모리는 다음 호출 시작에서
     *       어차피 초기화되므로 재사용해도 값이 새지 않는다.
     */
    fn try_eval(&self, input: &PolicyInput) -> Result<Action, String> {
        let state = {
            let mut pool = self.state_pool.lock().unwrap_or_else(|e| e.into_inner());
            pool.pop().unwrap_or_default()
        };
        let mut inst =
            Instance::instantiate_with(&self.module, FUEL_LIMIT, MEM_LIMIT_BYTES, state)?;
        let result = Self::eval_in(&mut inst, input);
        if result.is_err() && inst.fuel_remaining() == 0 {
            self.metrics.timeout_total.fetch_add(1, Ordering::Relaxed);
        }
        let state = inst.into_state();
        if state.memory_capacity() <= STATE_POOL_RETAIN_MEM_MAX {
            let mut pool = self.state_pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() < STATE_POOL_MAX {
                pool.push(state);
            }
        }
        result
    }

    /** @brief 응답을 평가한다. 훅이 없으면 곧바로 통과다. */
    pub fn evaluate_response(&self, input: &ResponseInput) -> ResponseVerdict {
        if !self.response_hook {
            return ResponseVerdict::Pass;
        }
        let start = std::time::Instant::now();
        self.metrics.eval_total.fetch_add(1, Ordering::Relaxed);
        let verdict = match self.try_eval_response(input) {
            Ok(v) => v,
            Err(error) => {
                let count = self.metrics.error_total.fetch_add(1, Ordering::Relaxed) + 1;
                let verdict = self.fail_mode.response_verdict();
                if count.is_power_of_two() {
                    onetdns_core::warn!(event = "policy.wasm_response_eval_failed", plugin = %self.name, count = count, fallback = ?verdict, %error, "Policy plugin could not evaluate the response; applied the failure mode");
                }
                verdict
            }
        };
        if matches!(verdict, ResponseVerdict::Block | ResponseVerdict::Refuse) {
            self.metrics.block_total.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics
            .latency_us_total
            .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        verdict
    }

    /** @brief 인스턴스를 만들어 on_response를 호출한다. */
    fn try_eval_response(&self, input: &ResponseInput) -> Result<ResponseVerdict, String> {
        let state = {
            let mut pool = self.state_pool.lock().unwrap_or_else(|e| e.into_inner());
            pool.pop().unwrap_or_default()
        };
        let mut inst =
            Instance::instantiate_with(&self.module, FUEL_LIMIT, MEM_LIMIT_BYTES, state)?;
        let result = Self::eval_response_in(&mut inst, input);
        if result.is_err() && inst.fuel_remaining() == 0 {
            self.metrics.timeout_total.fetch_add(1, Ordering::Relaxed);
        }
        let state = inst.into_state();
        if state.memory_capacity() <= STATE_POOL_RETAIN_MEM_MAX {
            let mut pool = self.state_pool.lock().unwrap_or_else(|e| e.into_inner());
            if pool.len() < STATE_POOL_MAX {
                pool.push(state);
            }
        }
        result
    }

    /** @brief 응답 문맥에 담을 주소 개수 상한. 문맥 크기를 유계로 만든다. */
    const RESP_CTX_MAX_ADDRS: usize = 16;

    /**
     * @brief 응답 문맥을 게스트 ABI 배치로 직렬화한다.
     * @details 전부 리틀엔디언이며, 이름과 주소 목록은 상한에서 잘린다. 상한이 없으면
     *          거대한 응답 하나가 그만큼의 문맥을 게스트 메모리에 밀어 넣는다.
     */
    fn encode_response_context(input: &ResponseInput) -> Vec<u8> {
        let qname = input.qname.as_bytes();
        let qname = &qname[..qname.len().min(255)];
        let addrs = &input.addrs[..input.addrs.len().min(Self::RESP_CTX_MAX_ADDRS)];
        let mut ctx = Vec::with_capacity(10 + qname.len() + addrs.len() * 17);
        ctx.extend_from_slice(&1u16.to_le_bytes());
        ctx.extend_from_slice(&input.qtype.to_le_bytes());
        ctx.extend_from_slice(&input.rcode.to_le_bytes());
        ctx.push(addrs.len() as u8);
        ctx.push(0);
        ctx.extend_from_slice(&(qname.len() as u16).to_le_bytes());
        ctx.extend_from_slice(qname);
        for addr in addrs {
            let mut bytes = [0u8; 16];
            let family: u8 = match addr {
                IpAddr::V4(a) => {
                    bytes[..4].copy_from_slice(&a.octets());
                    4
                }
                IpAddr::V6(a) => {
                    bytes.copy_from_slice(&a.octets());
                    6
                }
            };
            ctx.push(family);
            ctx.extend_from_slice(&bytes);
        }
        ctx
    }

    /**
     * @brief 게스트에 문맥을 써 넣고 on_response를 호출한다.
     * @details 게스트의 alloc으로 메모리를 받아야 한다. 임의의 주소에 쓰면 게스트가
     *          쓰고 있는 메모리를 덮는다.
     * @return 모르는 반환 코드는 오류다. 실패 모드 정책이 적용된다.
     */
    fn eval_response_in(
        inst: &mut Instance,
        input: &ResponseInput,
    ) -> Result<ResponseVerdict, String> {
        let ctx = Self::encode_response_context(input);
        let ptr = match inst
            .call_export("alloc", vec![Value::I32(ctx.len() as i32)])?
            .first()
        {
            Some(Value::I32(v)) => *v,
            _ => return Err("alloc must return i32".into()),
        };
        inst.write_mem(ptr as usize, &ctx)?;
        let code = match inst
            .call_export(
                "on_response",
                vec![Value::I32(ptr), Value::I32(ctx.len() as i32)],
            )?
            .first()
        {
            Some(Value::I32(v)) => *v,
            _ => return Err("on_response must return i32".into()),
        };
        match code {
            0 => Ok(ResponseVerdict::Pass),
            2 => Ok(ResponseVerdict::Block),
            3 => Ok(ResponseVerdict::Refuse),
            other => Err(format!("Unknown response verdict code: {other}")),
        }
    }

    /**
     * @brief 질의 문맥 ABI 버전.
     * @warning 배치를 바꾸면 반드시 함께 올린다. 협상 절차가 없으므로 게스트는 이 값으로만
     *          자기가 이해할 수 있는 문맥인지 판단한다.
     */
    const CTX_VERSION: u16 = 1;

    /** @brief 문맥 안에서 클라이언트 주소가 시작되는 오프셋. */
    const CTX_ADDR: usize = 8;

    /** @brief 가변 길이 뒷부분 앞까지의 고정 헤더 길이. */
    const CTX_HEADER_LEN: usize = 36;

    /**
     * @brief 질의 문맥을 게스트 ABI 배치로 직렬화한다.
     * @details 리틀엔디언 고정 헤더 뒤에 이름과 클라이언트 ID가 붙는다. 둘 다 255옥텟에서
     *          자른다.
     */
    fn encode_context(input: &PolicyInput) -> Vec<u8> {
        let qname = input.qname.as_bytes();
        let qname = &qname[..qname.len().min(255)];
        let client_id = input.client_id.map(str::as_bytes).unwrap_or_default();
        let client_id = &client_id[..client_id.len().min(255)];
        let mut ctx = Vec::with_capacity(Self::CTX_HEADER_LEN + qname.len() + client_id.len());
        ctx.extend_from_slice(&Self::CTX_VERSION.to_le_bytes());
        ctx.extend_from_slice(&input.qtype.to_le_bytes());
        ctx.push(input.transport.code());
        ctx.push(u8::from(input.authenticated));
        let mut addr = [0u8; 16];
        let family: u8 = match input.client {
            IpAddr::V4(a) => {
                addr[..4].copy_from_slice(&a.octets());
                4
            }
            IpAddr::V6(a) => {
                addr.copy_from_slice(&a.octets());
                6
            }
        };
        ctx.push(family);
        ctx.push(0);
        ctx.extend_from_slice(&addr);
        ctx.extend_from_slice(&input.unix_time.to_le_bytes());
        ctx.extend_from_slice(&(qname.len() as u16).to_le_bytes());
        ctx.extend_from_slice(&(client_id.len() as u16).to_le_bytes());
        ctx.extend_from_slice(qname);
        ctx.extend_from_slice(client_id);
        ctx
    }

    /**
     * @brief 게스트에 문맥을 써 넣고 evaluate를 호출한다.
     * @note 재작성(코드 4)은 게스트가 문맥 안의 클라이언트 주소 필드를 덮어써서 새 주소를
     *       전달한다. 반환값 하나로 주소를 담을 방법이 없어 택한 방식이다.
     */
    fn eval_in(inst: &mut Instance, input: &PolicyInput) -> Result<Action, String> {
        let call_i32 = |inst: &mut Instance, name: &str, args: Vec<Value>| -> Result<i32, String> {
            match inst.call_export(name, args)?.first() {
                Some(Value::I32(v)) => Ok(*v),
                _ => Err(format!("{name} must return i32")),
            }
        };

        let ctx = Self::encode_context(input);
        let ptr = call_i32(inst, "alloc", vec![Value::I32(ctx.len() as i32)])?;
        inst.write_mem(ptr as usize, &ctx)?;
        let code = call_i32(
            inst,
            "evaluate",
            vec![Value::I32(ptr), Value::I32(ctx.len() as i32)],
        )?;

        if code == 4 {
            let ip = inst.read_mem(ptr as usize + Self::CTX_ADDR, 4)?;
            return Ok(Action::Rewrite(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])));
        }
        Action::from_code(code)
    }
}

#[cfg(test)]
/** @brief 플러그인 인터페이스를 지키지 않는 것을 올리지 않고, 연료 상한이 걸리는지. */
mod tests {
    use super::*;

    /** @brief 테스트용 정책 플러그인. */
    const POLICY_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
            (if (result i32)
                (i32.eq
                  (i32.load16_u (i32.add (local.get $ptr) (i32.const 2)))
                  (i32.const 28))
              (then (i32.const 2))
              (else
                (if (result i32)
                    (i32.and
                      (i32.gt_u
                        (i32.load16_u (i32.add (local.get $ptr) (i32.const 32)))
                        (i32.const 0))
                      (i32.eq
                        (i32.load8_u (i32.add (local.get $ptr) (i32.const 36)))
                        (i32.const 120)))
                  (then (i32.const 2))
                  (else
                    (if (result i32)
                        (i32.eq
                          (i32.load8_u (i32.add (local.get $ptr) (i32.const 8)))
                          (i32.const 10))
                      (then
                        ;; 주소 슬롯에 192.168.0.1 기록 후 Rewrite(4) 반환.
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 8)) (i32.const 192))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 9)) (i32.const 168))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 10)) (i32.const 0))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 11)) (i32.const 1))
                        (i32.const 4))
                      (else (i32.const 0)))))))))
    "#;

    /** @brief 테스트용 입력. */
    fn input<'a>(qname: &'a str, qtype: u16) -> PolicyInput<'a> {
        PolicyInput {
            client: "1.2.3.4".parse().unwrap(),
            qname,
            qtype,
            unix_time: 0,
            local_minute_of_week: 0,
            transport: crate::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        }
    }
    /** @brief 클라이언트 주소가 붙은 테스트용 입력. */
    fn input_ip<'a>(qname: &'a str, qtype: u16, ip: &str) -> PolicyInput<'a> {
        PolicyInput {
            client: ip.parse().unwrap(),
            qname,
            qtype,
            unix_time: 0,
            local_minute_of_week: 0,
            transport: crate::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        }
    }

    #[test]
    /** @brief 플러그인이 질의 종류로 막을 수 있는지. */
    fn wasm_policy_blocks_by_qtype() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert_eq!(
            p.evaluate(&input("good.com", 28)),
            Action::Block,
            "AAAA 차단"
        );
        assert_eq!(
            p.evaluate(&input("good.com", 1)),
            Action::Continue,
            "A 통과"
        );
    }

    #[test]
    /** @brief 대표 정책의 모든 주요 분기가 작은 명령 예산 안에 머무는지. */
    fn representative_policy_fuel_usage_is_bounded() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        let inputs = [
            input("good.com", 28),
            input("xtracker.com", 1),
            input_ip("a.com", 1, "10.1.2.3"),
        ];
        let mut max_used = 0;
        for input in inputs {
            let mut inst = Instance::instantiate(&p.module, 1_000, MEM_LIMIT_BYTES).unwrap();
            WasmPolicy::eval_in(&mut inst, &input).unwrap();
            max_used = max_used.max(1_000 - inst.fuel_remaining());
        }
        assert!(max_used <= 256, "대표 정책 fuel 사용량: {max_used}");
    }

    #[test]
    #[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
    /** @brief 인스턴스 풀·문맥 복사·자체 실행기를 합친 대표 정책 종단 비용. */
    fn bench_representative_policy_evaluation() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let policy = WasmPolicy::from_wasm(&wasm).unwrap();
        let query = input("good.com", 1);
        assert_eq!(policy.evaluate(&query), Action::Continue);

        const ITERATIONS: u32 = 200_000;
        let start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(policy.evaluate(std::hint::black_box(&query)));
        }
        let elapsed = start.elapsed();
        eprintln!(
            "wasm policy evaluate: {:.1} ns/op ({} iterations, {:?})",
            elapsed.as_nanos() as f64 / f64::from(ITERATIONS),
            ITERATIONS,
            elapsed
        );
    }

    #[test]
    /** @brief 플러그인이 돌려준 주소를 읽는지. */
    fn wasm_rewrite_action_reads_ip_from_buffer() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert_eq!(
            p.evaluate(&input_ip("a.com", 1, "10.1.2.3")),
            Action::Rewrite(Ipv4Addr::new(192, 168, 0, 1)),
            "사설 클라 → rewrite"
        );
        assert_eq!(
            p.evaluate(&input_ip("a.com", 1, "8.8.8.8")),
            Action::Continue,
            "전역 클라 → 통과"
        );
    }

    #[test]
    /** @brief IPv6 클라이언트가 넘어가도 패닉하지 않는지. */
    fn wasm_ipv6_client_passed_without_panic() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert_eq!(
            p.evaluate(&input_ip("good.com", 28, "2001:db8::1")),
            Action::Block
        );
        assert_eq!(
            p.evaluate(&input_ip("good.com", 1, "2001:db8::1")),
            Action::Continue
        );
    }

    #[test]
    /** @brief 끝나지 않는 플러그인이 연료 상한에 걸리는지. 없으면 질의 하나가 영영 안 끝난다. */
    fn infinite_loop_plugin_is_bounded_by_fuel_and_refused_by_default() {
        /** @brief 끝나지 않는 테스트용 플러그인. */
        const LOOP_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32)
                (loop $l (br $l))
                (i32.const 2)))
        "#;
        let wasm = wat::parse_str(LOOP_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(
            p.evaluate(&input("x.com", 1)),
            Action::Refuse,
            "무한루프 → 기본 fail-closed Refuse"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "fuel 상한으로 빠르게 종료"
        );
        let m = p.metrics();
        assert_eq!(m.eval_total, 1);
        assert_eq!(m.error_total, 1, "fuel 소진은 error로 계수");
        assert_eq!(m.timeout_total, 1, "fuel 소진은 timeout으로도 구분 계수");

        let wasm2 = wat::parse_str(LOOP_WAT).unwrap();
        let pc = WasmPolicy::from_wasm(&wasm2)
            .unwrap()
            .with_name("loopguard")
            .with_failure_mode(FailureMode::ClosedBlock);
        assert_eq!(
            pc.evaluate(&input("x.com", 1)),
            Action::Block,
            "fail-closed → Block"
        );
        let mc = pc.metrics();
        assert_eq!(mc.error_total, 1);
        assert_eq!(mc.block_total, 1, "fail-closed Block은 block_total 계수");
    }

    #[test]
    /** @brief 실패 처분 표기를 읽는지. */
    fn failure_mode_parse() {
        assert_eq!(FailureMode::parse("open").unwrap(), FailureMode::Open);
        assert_eq!(
            FailureMode::parse("closed-block").unwrap(),
            FailureMode::ClosedBlock
        );
        assert_eq!(
            FailureMode::parse("closed-refuse").unwrap(),
            FailureMode::ClosedRefuse
        );
        for invalid in ["closed", "closed_block", "closed_refuse", "block", "refuse"] {
            assert!(FailureMode::parse(invalid).is_err(), "invalid={invalid}");
        }
        assert!(FailureMode::parse("garbage").is_err());
    }

    #[test]
    /** @brief 플러그인이 질의 이름을 읽는지. */
    fn wasm_policy_reads_qname_bytes() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert_eq!(
            p.evaluate(&input("xtracker.com", 1)),
            Action::Block,
            "qname 'x' 차단"
        );
        assert_eq!(p.evaluate(&input("ytracker.com", 1)), Action::Continue);
    }

    #[test]
    /** @brief 다시 부를 때 앞 질의의 상태가 남지 않는지. */
    fn wasm_eval_reuses_module_without_state_leak() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        for _ in 0..5 {
            assert_eq!(p.evaluate(&input("x.com", 1)), Action::Block);
            assert_eq!(p.evaluate(&input("y.com", 1)), Action::Continue);
        }
    }

    #[test]
    /** @brief 재사용할 때 메모리가 처음 상태로 돌아가는지. 남으면 남의 질의 자료가 보인다. */
    fn pooled_instance_reuse_resets_memory_and_data_segments() {
        /** @brief 상태를 남기는 테스트용 플러그인. */
        const STATEFUL_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 4096) "\ab")
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "evaluate") (param i32 i32) (result i32)
                (if (result i32) (i32.ne (i32.load8_u (i32.const 4096)) (i32.const 171))
                  (then (i32.const 2))
                  (else
                    (if (result i32) (i32.eqz (i32.load8_u (i32.const 2048)))
                      (then
                        (i32.store8 (i32.const 2048) (i32.const 7))
                        (i32.const 0))
                      (else (i32.const 2)))))))
        "#;
        let wasm = wat::parse_str(STATEFUL_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        for i in 0..4 {
            assert_eq!(
                p.evaluate(&input("a.com", 1)),
                Action::Continue,
                "{i}번째 평가에서 이전 평가 상태가 잔존"
            );
        }
    }

    /** @brief 맥락을 읽는 테스트용 플러그인. */
    const CONTEXT_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
            ;; transport(+4)가 DoH(3)면 Block
            (if (result i32)
                (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 4))) (i32.const 3))
              (then (i32.const 2))
              (else
                ;; authenticated(+5)면 Allow
                (if (result i32)
                    (i32.eq (i32.load8_u (i32.add (local.get $ptr) (i32.const 5))) (i32.const 1))
                  (then (i32.const 1))
                  (else
                    ;; client_id_len(+34) > 0 이면 rewrite: 주소 슬롯(+8)에 기록 후 4
                    (if (result i32)
                        (i32.gt_u
                          (i32.load16_u (i32.add (local.get $ptr) (i32.const 34)))
                          (i32.const 0))
                      (then
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 8)) (i32.const 192))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 9)) (i32.const 168))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 10)) (i32.const 0))
                        (i32.store8 (i32.add (local.get $ptr) (i32.const 11)) (i32.const 9))
                        (i32.const 4))
                      (else (i32.const 0)))))))))
    "#;

    #[test]
    /** @brief 전송·인증·식별자가 플러그인에 전해지는지. */
    fn evaluate_receives_transport_auth_and_client_id() {
        let wasm = wat::parse_str(CONTEXT_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();

        let mut doh = input("a.com", 1);
        doh.transport = crate::QueryTransport::Doh;
        assert_eq!(p.evaluate(&doh), Action::Block, "DoH 전송 → 차단");

        let mut authed = input("a.com", 1);
        authed.authenticated = true;
        assert_eq!(p.evaluate(&authed), Action::Allow, "인증 클라이언트 → 허용");

        let mut with_id = input("a.com", 1);
        with_id.client_id = Some("tv");
        assert_eq!(
            p.evaluate(&with_id),
            Action::Rewrite(Ipv4Addr::new(192, 168, 0, 9)),
            "client_id 존재 → 주소 슬롯 rewrite"
        );

        assert_eq!(p.evaluate(&input("a.com", 1)), Action::Continue);
    }

    #[test]
    /** @brief 인터페이스와 다른 형태의 플러그인을 올릴 때 거부하는지. 부를 때 알면 이미 늦다. */
    fn evaluate_bad_signature_is_rejected_on_load() {
        /** @brief 형태가 어긋난 테스트용 플러그인. */
        const BAD_SIGNATURE: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32) (result i32) (i32.const 0)))
        "#;
        let wasm = wat::parse_str(BAD_SIGNATURE).unwrap();
        assert!(WasmPolicy::from_wasm(&wasm).is_err());
    }

    #[test]
    /** @brief 모르는 반환값을 그냥 통과로 보지 않는지. */
    fn unknown_return_code_triggers_fail_mode_not_continue() {
        /** @brief 모르는 값을 돌려주는 테스트용 플러그인. */
        const BAD_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32)
                (i32.const 99)))
        "#;
        let wasm = wat::parse_str(BAD_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert_eq!(
            p.evaluate(&input("x.com", 1)),
            Action::Refuse,
            "미지정 코드는 Continue가 아니라 fail_mode"
        );
        assert_eq!(p.metrics().error_total, 1);

        let wasm2 = wat::parse_str(BAD_WAT).unwrap();
        let po = WasmPolicy::from_wasm(&wasm2)
            .unwrap()
            .with_failure_mode(FailureMode::Open);
        assert_eq!(
            po.evaluate(&input("x.com", 1)),
            Action::Continue,
            "fail-open 모드는 명시적 선택일 때만"
        );
    }

    #[test]
    /** @brief 시각이 플러그인에 전해지는지. */
    fn evaluate_context_receives_unix_time() {
        /** @brief 시각을 읽는 테스트용 플러그인. */
        const TIME_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param $ptr i32) (param $len i32) (result i32)
                (if (result i32)
                    (i64.eq
                      (i64.load (i32.add (local.get $ptr) (i32.const 24)))
                      (i64.const 12345))
                  (then (i32.const 2))
                  (else (i32.const 0)))))
        "#;
        let wasm = wat::parse_str(TIME_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        let mut at_noon = input("x.com", 1);
        at_noon.unix_time = 12345;
        assert_eq!(
            p.evaluate(&at_noon),
            Action::Block,
            "시간 전달 → 시간 기반 차단"
        );
        assert_eq!(
            p.evaluate(&input("x.com", 1)),
            Action::Continue,
            "다른 시각 → 통과"
        );
    }

    #[test]
    /** @brief 인자 수가 다른 함수를 거부하는지. */
    fn multi_argument_evaluate_signature_is_rejected() {
        /** @brief 인자 수가 다른 테스트용 플러그인. */
        const BADSIG_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32 i32 i32 i32 i32) (result i32)
                (i32.const 0)))
        "#;
        let wasm = wat::parse_str(BADSIG_WAT).unwrap();
        assert!(WasmPolicy::from_wasm(&wasm).is_err());
    }

    #[test]
    /** @brief 필요한 것을 다 갖추지 않은 플러그인을 거부하는지. */
    fn incomplete_module_is_rejected_on_load() {
        let wasm = wat::parse_str("(module (memory (export \"memory\") 1))").unwrap();
        assert!(WasmPolicy::from_wasm(&wasm).is_err());
    }

    #[test]
    /** @brief 첫 질의에서만 실패할 초기 메모리와 data 범위를 로드 시점에 거부하는지. */
    fn impossible_initial_instance_is_rejected_on_load() {
        const TOO_LARGE: &str = r#"
            (module
              (memory (export "memory") 33)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
        "#;
        const DATA_OUT_OF_BOUNDS: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0))
              (data (i32.const 65535) "xx"))
        "#;
        for wat in [TOO_LARGE, DATA_OUT_OF_BOUNDS] {
            assert!(WasmPolicy::from_wasm(&wat::parse_str(wat).unwrap()).is_err());
        }
    }

    #[test]
    /** @brief 보조 함수의 형태도 확인하는지. */
    fn invalid_alloc_and_response_signatures_are_rejected_on_load() {
        /** @brief 슬롯 잡기 함수가 어긋난 테스트용 플러그인. */
        const BAD_ALLOC: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i64) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
        "#;
        /** @brief 응답 쪽 함수가 어긋난 테스트용 플러그인. */
        const BAD_RESPONSE: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0))
              (func (export "on_response") (param i32) (result i32) (i32.const 0)))
        "#;

        for wat in [BAD_ALLOC, BAD_RESPONSE] {
            let wasm = wat::parse_str(wat).unwrap();
            assert!(WasmPolicy::from_wasm(&wasm).is_err());
        }
    }

    #[test]
    /** @brief 깨진 바이트열을 올릴 때 오류가 나는지. */
    fn invalid_wasm_bytes_error_on_load() {
        assert!(WasmPolicy::from_wasm(b"not wasm").is_err());
    }

    /** @brief 응답 쪽 테스트용 플러그인. */
    const RESP_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0))
          (func (export "on_response") (param $ptr i32) (param $len i32) (result i32)
            (local $count i32)
            (local $addr0 i32)
            ;; addr_count(+6)==0 → Pass
            (local.set $count (i32.load8_u (i32.add (local.get $ptr) (i32.const 6))))
            (if (result i32) (i32.eqz (local.get $count))
              (then (i32.const 0))
              (else
                ;; 첫 주소 항목 = ptr+10+qname_len, 주소 첫 바이트가 10이면 Block
                (local.set $addr0
                  (i32.add (i32.add (local.get $ptr) (i32.const 10))
                           (i32.load16_u (i32.add (local.get $ptr) (i32.const 8)))))
                (if (result i32)
                    (i32.eq (i32.load8_u (i32.add (local.get $addr0) (i32.const 1)))
                            (i32.const 10))
                  (then (i32.const 2))
                  (else (i32.const 0)))))))
    "#;

    #[test]
    /** @brief 응답 쪽 플러그인이 답을 막을 수 있는지. */
    fn response_hook_blocks_private_answers() {
        let wasm = wat::parse_str(RESP_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        assert!(p.has_response_hook());

        let private = [std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let public = [std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        let block = p.evaluate_response(&crate::ResponseInput {
            qname: "a.com",
            qtype: 1,
            rcode: 0,
            addrs: &private,
        });
        assert_eq!(block, crate::ResponseVerdict::Block, "사설 응답 → 차단");
        let pass = p.evaluate_response(&crate::ResponseInput {
            qname: "a.com",
            qtype: 1,
            rcode: 0,
            addrs: &public,
        });
        assert_eq!(pass, crate::ResponseVerdict::Pass);
        let empty = p.evaluate_response(&crate::ResponseInput {
            qname: "a.com",
            qtype: 1,
            rcode: 0,
            addrs: &[],
        });
        assert_eq!(empty, crate::ResponseVerdict::Pass);

        let plain = WasmPolicy::from_wasm(&wat::parse_str(POLICY_WAT).unwrap()).unwrap();
        assert!(!plain.has_response_hook());

        let engine = crate::PolicyEngine::new(crate::RuleEngine::new(vec![]), vec![p, plain]);
        assert!(engine.has_response_hook());
        assert_eq!(
            engine.evaluate_response(&crate::ResponseInput {
                qname: "a.com",
                qtype: 1,
                rcode: 0,
                addrs: &private,
            }),
            crate::ResponseVerdict::Block
        );
    }

    #[test]
    /** @brief 규칙이 허용해도 플러그인의 차단을 건너뛰지 않는지. */
    fn rule_allow_does_not_bypass_plugin_block() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let plugin = WasmPolicy::from_wasm(&wasm).unwrap();
        let engine = crate::PolicyEngine::new(
            crate::RuleEngine::new(vec![
                crate::Rule::new(Action::Allow).with_suffixes(&["x.com".to_string()])
            ]),
            vec![plugin],
        );
        assert_eq!(
            engine.evaluate(&input("x.com", 1)),
            Action::Block,
            "허용 규칙이 뒤의 보안 플러그인을 우회하지 못한다"
        );
        assert_eq!(
            engine.evaluate(&input("y.com", 1)),
            Action::Continue,
            "허용 규칙 미매칭 → Continue"
        );

        let wasm2 = wat::parse_str(POLICY_WAT).unwrap();
        let engine2 = crate::PolicyEngine::new(
            crate::RuleEngine::new(vec![
                crate::Rule::new(Action::Allow).with_suffixes(&["y.com".to_string()])
            ]),
            vec![WasmPolicy::from_wasm(&wasm2).unwrap()],
        );
        assert_eq!(
            engine2.evaluate(&input("y.com", 1)),
            Action::Allow,
            "차단이 없으면 Allow 유지(이후 필터 면제)"
        );
    }
}
