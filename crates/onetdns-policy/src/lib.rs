//! Policy engine: native rules and WASM plugins. Native rules run first, then plugins in order; the
//! first result other than Continue wins. Plugins run in a WASM interpreter under fuel and memory
//! limits, so a broken plugin cannot stall the server.

use std::net::{IpAddr, Ipv4Addr};

mod rules;
mod wasm;
mod wasmrt;

pub use rules::{Rule, RuleEngine, TimeWindow};
pub use wasm::{FailureMode, PluginMetricsSnapshot, WasmPolicy};

/// Transport as policies see it. It is a separate type because code() is part of the WASM ABI:
/// reordering another transport enum must not change the values plugins see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryTransport {
    #[default]
    Do53Udp,
    Do53Tcp,
    Dot,
    Doh,
    Doh3,
    Doq,
    DnsCrypt,
}

impl QueryTransport {
    /// ABI contract: deployed plugins read these numbers, so they never change.
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

/// What a policy sees at query time. Adding a field to the WASM context needs an ABI version bump.
pub struct PolicyInput<'a> {
    pub client: IpAddr,

    pub qname: &'a str,
    pub qtype: u16,

    /// Seconds since the Unix epoch; carried in the WASM context.
    pub unix_time: u64,

    /// Minutes since Sunday 00:00 local time, for time-window rules. Windows look only at weekday
    /// and time of day, so they take this folded local value. Not in the WASM context.
    pub local_minute_of_week: u32,

    pub transport: QueryTransport,
    pub client_id: Option<&'a str>,
    /// The connection was authenticated.
    pub authenticated: bool,
}

/// What a policy sees at response time, so rules that filter by resulting address rather than by
/// name (rebinding defense, for example) can use this hook.
pub struct ResponseInput<'a> {
    pub qname: &'a str,
    pub qtype: u16,
    pub rcode: u16,
    pub addrs: &'a [IpAddr],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    Pass,
    Block,
    Refuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// This policy has no opinion; ask the next one.
    Continue,

    /// Explicit allow. Later policies are still asked; if none blocks, the query is allowed.
    Allow,

    /// Ends evaluation.
    Block,

    /// Answers REFUSED; ends evaluation.
    Refuse,

    Rewrite(Ipv4Addr),
}

impl Action {
    /// ABI contract. An unknown code is an error so the failure mode applies; mapping it to
    /// Continue would turn a plugin bug into a silent pass.
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

#[derive(Debug)]
pub enum PolicyError {
    Wasm(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Wasm(s) => write!(f, "WASM policy error: {s}"),
        }
    }
}
impl std::error::Error for PolicyError {}

#[derive(Default)]
pub struct PolicyEngine {
    rules: RuleEngine,
    plugins: Vec<WasmPolicy>,
}

impl PolicyEngine {
    /// Plugins are evaluated in the given order.
    pub fn new(rules: RuleEngine, plugins: Vec<WasmPolicy>) -> Self {
        PolicyEngine { rules, plugins }
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub fn plugin_metrics(&self) -> Vec<(String, PluginMetricsSnapshot)> {
        self.plugins
            .iter()
            .map(|p| (p.name().to_string(), p.metrics()))
            .collect()
    }

    /// Callers skip evaluation entirely when empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.plugins.is_empty()
    }

    /// Native rules, then plugins, stopping at the first result other than Continue. Allow is the
    /// exception and keeps going, so later policies can still block. Returns Continue when nothing
    /// decided, Allow when only allows matched.
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

    /// Without one, the response path never calls the engine.
    pub fn has_response_hook(&self) -> bool {
        self.plugins.iter().any(WasmPolicy::has_response_hook)
    }

    /// The first verdict other than Pass wins.
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
