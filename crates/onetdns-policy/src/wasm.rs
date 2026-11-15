use std::net::{IpAddr, Ipv4Addr};

use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::Mutex;

use crate::wasmrt::{Instance, InstanceState, Module, ValType, Value};
use crate::{Action, PolicyError, PolicyInput, ResponseInput, ResponseVerdict};

/// Instruction budget for one plugin call; without it, a plugin that loops forever holds a worker
/// forever. Running out traps, and the failure mode applies.
const FUEL_LIMIT: u64 = 50_000;

/// Linear memory cap per call; enough for the policy context.
const MEM_LIMIT_BYTES: usize = 2 * 1024 * 1024;

const STATE_POOL_MAX: usize = 4;

/// States whose memory grew past this are dropped instead of pooled; otherwise one large call would
/// keep its memory for the plugin's lifetime.
const STATE_POOL_RETAIN_MEM_MAX: usize = 2 * 1024 * 1024;

/// What a plugin failure does. The default refuses (fail-closed): passing queries the policy could
/// not judge amounts to turning the policy off, so that happens only when the operator picks open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailureMode {
    /// Pass despite the failure, trading correctness for availability.
    Open,
    ClosedBlock,
    #[default]
    ClosedRefuse,
}

impl FailureMode {
    fn action(self) -> Action {
        match self {
            FailureMode::Open => Action::Continue,
            FailureMode::ClosedBlock => Action::Block,
            FailureMode::ClosedRefuse => Action::Refuse,
        }
    }

    fn response_verdict(self) -> ResponseVerdict {
        match self {
            FailureMode::Open => ResponseVerdict::Pass,
            FailureMode::ClosedBlock => ResponseVerdict::Block,
            FailureMode::ClosedRefuse => ResponseVerdict::Refuse,
        }
    }

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

#[derive(Debug, Default)]
pub struct PluginMetrics {
    pub eval_total: AtomicU64,
    pub error_total: AtomicU64,

    /// Calls that ran out of fuel; finds plugins whose budget is too small.
    pub timeout_total: AtomicU64,
    pub block_total: AtomicU64,

    pub latency_us_total: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct PluginMetricsSnapshot {
    pub eval_total: u64,
    pub error_total: u64,
    /// Calls that ran out of fuel.
    pub timeout_total: u64,
    pub block_total: u64,
    pub latency_us_total: u64,
}

/// One WASM policy plugin. The module is parsed once and instantiated per call; instance states are
/// pooled, so calls do not allocate memory afresh.
pub struct WasmPolicy {
    module: Module,
    /// Shown in logs and the dashboard.
    name: String,
    fail_mode: FailureMode,
    metrics: PluginMetrics,
    state_pool: Mutex<Vec<InstanceState>>,
    /// Whether the plugin exports on_response.
    response_hook: bool,
}

impl WasmPolicy {
    /// Parses the module and checks the ABI, including the signatures of the required exports
    /// (memory, alloc, evaluate). Checking names alone would let a mismatched function trap only
    /// when called, mid-query, where it falls to the failure mode; it must be caught at load.
    ///
    /// on_response is optional: checked when present, otherwise the response hook is off.
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

    pub fn has_response_hook(&self) -> bool {
        self.response_hook
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_failure_mode(mut self, mode: FailureMode) -> Self {
        self.fail_mode = mode;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn metrics(&self) -> PluginMetricsSnapshot {
        PluginMetricsSnapshot {
            eval_total: self.metrics.eval_total.load(Ordering::Relaxed),
            error_total: self.metrics.error_total.load(Ordering::Relaxed),
            timeout_total: self.metrics.timeout_total.load(Ordering::Relaxed),
            block_total: self.metrics.block_total.load(Ordering::Relaxed),
            latency_us_total: self.metrics.latency_us_total.load(Ordering::Relaxed),
        }
    }

    /// Execution errors, traps, and fuel exhaustion all map to the failure mode, so a plugin defect
    /// cannot break query handling.
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

    /// A failure with no fuel left counts as budget exhaustion, apart from other traps, so plugins
    /// with too small a budget can be found.
    ///
    /// The instance state goes back to the pool even after a failure: memory is reset when the next
    /// call starts, so nothing leaks between calls.
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

    /// Bounds the response context size.
    const RESP_CTX_MAX_ADDRS: usize = 16;

    /// Serializes the response context in the guest ABI layout, all little-endian. The name and
    /// address list are cut at their caps; without them, one huge response would push that much
    /// context into guest memory.
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

    /// Memory for the context must come from the guest's alloc; writing anywhere else would
    /// overwrite memory the guest is using. An unknown return code is an error, so the failure mode
    /// applies.
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

    /// Query context ABI version. Bump it with any layout change: there is no negotiation, so this
    /// is the only way a guest knows whether it understands the context.
    const CTX_VERSION: u16 = 1;

    /// Offset of the client address in the context.
    const CTX_ADDR: usize = 8;

    /// Fixed header length before the variable-length tail.
    const CTX_HEADER_LEN: usize = 36;

    /// Serializes the query context in the guest ABI layout: a little-endian fixed header, then the
    /// name and client ID, each cut at 255 octets.
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

    /// A rewrite (code 4) passes its address by overwriting the client address field in the
    /// context, since one return value cannot carry an address.
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
mod tests {
    use super::*;

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
    /// End-to-end cost of the representative policy: instance pool, context copy, and interpreter.
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
    /// Without the cap, one query never finishes.
    fn infinite_loop_plugin_is_bounded_by_fuel_and_refused_by_default() {
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
    fn wasm_eval_reuses_module_without_state_leak() {
        let wasm = wat::parse_str(POLICY_WAT).unwrap();
        let p = WasmPolicy::from_wasm(&wasm).unwrap();
        for _ in 0..5 {
            assert_eq!(p.evaluate(&input("x.com", 1)), Action::Block);
            assert_eq!(p.evaluate(&input("y.com", 1)), Action::Continue);
        }
    }

    #[test]
    /// Leftover memory would expose another query's data.
    fn pooled_instance_reuse_resets_memory_and_data_segments() {
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
    /// Finding out at call time is too late.
    fn evaluate_bad_signature_is_rejected_on_load() {
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
    fn unknown_return_code_triggers_fail_mode_not_continue() {
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
    fn evaluate_context_receives_unix_time() {
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
    fn multi_argument_evaluate_signature_is_rejected() {
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
    fn incomplete_module_is_rejected_on_load() {
        let wasm = wat::parse_str("(module (memory (export \"memory\") 1))").unwrap();
        assert!(WasmPolicy::from_wasm(&wasm).is_err());
    }

    #[test]
    /// Initial memory and data ranges that would fail only on the first query are refused at load.
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
    fn invalid_alloc_and_response_signatures_are_rejected_on_load() {
        const BAD_ALLOC: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i64) (result i32) (i32.const 0))
              (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0)))
        "#;
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
    fn invalid_wasm_bytes_error_on_load() {
        assert!(WasmPolicy::from_wasm(b"not wasm").is_err());
    }

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
