//! Records query results to metrics, dnstap, and the query log.

use std::net::IpAddr;

use onetdns_control::{Action, EventDiag, Recorder};
use onetdns_core::{ClientInfo, DropReason, MatchStage};
use onetdns_proto::{Message, Name as ApName, RecordType as ApRt, ResponseCode};

use crate::native::query::RuleMatch;
use crate::native::response::{answers_summary, rcode_str};
use crate::native::NativeServer;

/// The rule and list behind a filter verdict, held until recorded.
pub(crate) struct FilterRuleLabel {
    /// The verdict stage name when there is no rule text.
    rule: String,
    list: String,
}

impl FilterRuleLabel {
    pub(crate) fn new(stage: MatchStage, matched: Option<String>, source: Option<String>) -> Self {
        Self {
            rule: matched.unwrap_or_else(|| stage.as_str().to_string()),
            list: source.unwrap_or_default(),
        }
    }

    pub(crate) fn as_match(&self) -> RuleMatch<'_> {
        RuleMatch {
            rule: &self.rule,
            list: &self.list,
        }
    }
}

impl NativeServer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rec_failure(
        &self,
        client: &ClientInfo,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        reason: &'static str,
        stage: &'static str,
        detail: &str,
    ) {
        resolution_failed(reason, stage, name);
        if let Some(r) = self.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            r.record_detailed(
                client.transport,
                Action::ServFail,
                client.source_ip,
                name,
                qtype,
                log,
                stat,
                EventDiag {
                    rcode: "SERVFAIL",
                    reason,
                    stage,
                    detail,
                    ..Default::default()
                },
            );
        }
    }

    pub(crate) fn rec_final_answer(
        &self,
        client: &ClientInfo,
        qname: &ApName,
        qtype: ApRt,
        resp: &Message,
    ) {
        let source = onetdns_forward::take_response_source().unwrap_or_default();
        let Some(recorder) = self.events() else {
            return;
        };
        if resp.header.rcode == ResponseCode::ServFail.0 {
            let detail = format!(
                "The DNS handling path returned a server error response. backend={}",
                self.resolver_mode(client)
            );
            self.rec_failure(
                client,
                Some(qname),
                Some(qtype),
                "UPSTREAM_SERVFAIL",
                "upstream",
                &detail,
            );
            return;
        }
        let action = if resp.header.rcode == ResponseCode::Refused.0 {
            Action::Refused
        } else if resp.header.rcode != ResponseCode::NoError.0
            && resp.header.rcode != ResponseCode::NXDomain.0
        {
            Action::ServFail
        } else {
            Action::Resolved
        };
        // Only the query log uses the summary.
        let answers = if recorder.querylog_enabled() {
            answers_summary(&resp.answers)
        } else {
            String::new()
        };
        let (log, stat) = self.filter.load().client_log_stat(client);
        self.rec_rc_diag_with(
            recorder,
            client,
            action,
            Some(qname),
            Some(qtype),
            ResponseCode(resp.header.rcode),
            &answers,
            &source,
            "",
            log,
            stat,
            None,
        );
    }

    pub(crate) fn rec_latency(&self, client: &ClientInfo, qname: Option<&ApName>, elapsed_us: u64) {
        if let Some(r) = self.events() {
            let (_, stat) = self.filter.load().client_log_stat(client);
            r.record_latency_for(elapsed_us, stat, qname);
        }
    }

    pub(crate) fn rec(
        &self,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
    ) {
        note_rejection(action, client);
        if let Some(r) = self.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            r.record(
                client.transport,
                action,
                client.source_ip,
                name,
                qtype,
                log,
                stat,
            );
        }
    }

    pub(crate) fn rec_rc(
        &self,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
    ) {
        self.rec_rc_diag(client, action, name, qtype, rcode, "", "", "");
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rec_rc_diag<'r>(
        &self,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
        answers: &str,
        upstream: &str,
        rule: impl Into<RuleMatch<'r>>,
    ) {
        note_rejection(action, client);
        if let Some(recorder) = self.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            self.rec_rc_diag_with(
                recorder, client, action, name, qtype, rcode, answers, upstream, rule, log, stat,
                None,
            );
        }
    }

    /// Counted as Throttled like rate limiting, but the reason differs, and it tells the operator
    /// whether to look at the client or at server capacity.
    pub(crate) fn rec_overloaded(&self, client: &ClientInfo, name: &ApName, qtype: ApRt) {
        note_rejection(Action::Throttled, client);
        if let Some(recorder) = self.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            self.rec_rc_diag_with(
                recorder,
                client,
                Action::Throttled,
                Some(name),
                Some(qtype),
                ResponseCode::ServFail,
                "",
                "",
                "",
                log,
                stat,
                Some("MAX_INFLIGHT"),
            );
        }
    }

    /// Counted as blocked, with DROPPED where the rcode goes; logging the rcode of a response that
    /// never went out would tell the operator the client got it.
    pub(crate) fn rec_dropped<'r>(
        &self,
        client: &ClientInfo,
        name: &ApName,
        qtype: ApRt,
        rule: impl Into<RuleMatch<'r>>,
    ) {
        if let Some(recorder) = self.events() {
            let (log, stat) = self.filter.load().client_log_stat(client);
            let rule = rule.into();
            recorder.record_detailed(
                client.transport,
                Action::Blocked,
                client.source_ip,
                Some(name),
                Some(qtype),
                log,
                stat,
                EventDiag {
                    rcode: "DROPPED",
                    reason: "FILTER_BLOCKED",
                    rule: rule.rule,
                    list: rule.list,
                    ..Default::default()
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// `reason` is for when the action alone does not decide it; otherwise it comes from the
    /// action.
    pub(crate) fn rec_rc_diag_with<'r>(
        &self,
        recorder: &Recorder,
        client: &ClientInfo,
        action: Action,
        name: Option<&ApName>,
        qtype: Option<ApRt>,
        rcode: ResponseCode,
        answers: &str,
        upstream: &str,
        rule: impl Into<RuleMatch<'r>>,
        log: bool,
        stat: bool,
        reason: Option<&'static str>,
    ) {
        let reason = reason.unwrap_or(match action {
            Action::ServFail => "UNSPECIFIED_SERVFAIL",
            Action::Refused | Action::Denied => "POLICY_REFUSED",
            Action::Blocked => "FILTER_BLOCKED",
            Action::Throttled => "RATE_LIMITED",
            _ => "",
        });
        let rcode_name = rcode_str(rcode);
        let rule = rule.into();
        recorder.record_detailed(
            client.transport,
            action,
            client.source_ip,
            name,
            qtype,
            log,
            stat,
            EventDiag {
                rcode: &rcode_name,
                reason,
                answers,
                upstream,
                rule: rule.rule,
                list: rule.list,
                ..Default::default()
            },
        );
    }
}

/// Logs refused clients. Otherwise the verdicts reach only the stats recorder, and with it off
/// nothing shows why queries fail. Called per verdict, so only powers of two are logged per kind.
fn note_rejection(action: Action, client: &ClientInfo) {
    static DENIED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static THROTTLED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let (counter, denied) = match action {
        Action::Denied => (&DENIED, true),
        Action::Throttled => (&THROTTLED, false),
        _ => return,
    };
    let count = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    if denied {
        onetdns_core::warn!(event = "dns.client_rejected", reason = "acl", client = %client.source_ip, count = count, "Blocked a query from an address that is not allowed");
    } else {
        onetdns_core::warn!(event = "dns.client_rejected", reason = "rate_limit", client = %client.source_ip, count = count, "Blocked a rate-limited query");
    }
}

/// Logs silent ACL drops. A dropped query has no rcode and appears in neither the query log nor
/// stats, so this is the only trace. Called per packet and connection, so only powers of two are
/// logged per reason. Unlisted drops come from Internet-wide scanning; one shared counter would
/// bury the drop-list entries.
pub(super) fn note_dropped(source: IpAddr, reason: DropReason) {
    static LISTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static UNLISTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = match reason {
        DropReason::DropList => &LISTED,
        DropReason::Unlisted => &UNLISTED,
    };
    let count = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    match reason {
        DropReason::DropList => {
            onetdns_core::warn!(event = "dns.client_rejected", reason = "acl_drop", client = %source, count = count, "Dropped traffic from an address in acl_drop without responding");
        }
        DropReason::Unlisted => {
            onetdns_core::warn!(event = "dns.client_rejected", reason = "acl_unlisted", client = %source, count = count, "Dropped traffic from a client that matches no access rule without responding");
        }
    }
}

/// Logs a SERVFAIL for a query that could not be resolved. With stats off this is the only trace of
/// resolution failures. Called per query, so only powers of two are logged.
fn resolution_failed(reason: &'static str, stage: &'static str, name: Option<&ApName>) {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    let qname = name.map(|n| n.to_ascii_lower()).unwrap_or_default();
    onetdns_core::warn!(event = "dns.resolution_failed", reason = reason, stage = stage, qname = %qname, count = count, "Could not resolve the query; answered SERVFAIL");
}
