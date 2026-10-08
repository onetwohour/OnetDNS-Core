/*!
 * @brief 질의 결과를 지표, dnstap, 질의 로그에 기록한다.
 */

use onetdns_control::{Action, EventDiag, Recorder};
use onetdns_core::{ClientInfo, FilterEngine};
use onetdns_proto::{Message, Name as ApName, RecordType as ApRt, ResponseCode};

use crate::native::query::RuleMatch;
use crate::native::response::{answers_summary, rcode_str};
use crate::native::NativeServer;

/** @brief 필터 판정을 설명하는 규칙과 목록. 기록할 때까지 들고 있는 값이다. */
pub(crate) struct FilterRuleLabel {
    /** @brief 걸린 규칙. 규칙 원문이 없으면 판정 단계 이름이다. */
    rule: String,
    /** @brief 그 규칙이 들어 있던 목록. */
    list: String,
}

impl FilterRuleLabel {
    /** @brief 기록에 넘길 형태로 빌려 준다. */
    pub(crate) fn as_match(&self) -> RuleMatch<'_> {
        RuleMatch {
            rule: &self.rule,
            list: &self.list,
        }
    }
}

impl NativeServer {
    /** @brief 어느 규칙이 걸렸는지와 그 규칙이 들어 있던 목록. */
    pub(crate) fn filter_rule_label(
        &self,
        name: &ApName,
        qtype: ApRt,
        client: &ClientInfo,
    ) -> FilterRuleLabel {
        let exp = self.filter.load().explain(name, qtype, client);
        FilterRuleLabel {
            rule: exp
                .matched
                .unwrap_or_else(|| exp.stage.as_str().to_string()),
            list: exp.source.unwrap_or_default(),
        }
    }

    /** @brief 실패를 기록에 남긴다. */
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

    /** @brief 최종 답을 기록에 남긴다. */
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
        /* 요약은 질의 기록에만 담긴다. 꺼져 있으면 만들자마자 버려지므로 만들지 않는다. */
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

    /** @brief 처리에 걸린 시간을 남긴다. */
    pub(crate) fn rec_latency(&self, client: &ClientInfo, qname: Option<&ApName>, elapsed_us: u64) {
        if let Some(r) = self.events() {
            let (_, stat) = self.filter.load().client_log_stat(client);
            r.record_latency_for(elapsed_us, stat, qname);
        }
    }

    /** @brief 질의 하나를 기록에 남긴다. */
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

    /** @brief 응답 코드와 함께 남긴다. */
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
    /** @brief 응답 코드와 사유를 함께 남긴다. */
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

    /**
     * @brief 동시 처리 한도에 걸려 거절한 질의를 남긴다.
     * @details 속도 제한과 같은 Throttled 로 세지만 까닭은 다르다. 운영자는 까닭을 보고
     *          클라이언트를 볼지 서버 용량을 볼지 정한다.
     */
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

    #[allow(clippy::too_many_arguments)]
    /**
     * @brief 응답 코드와 사유, 답 요약을 함께 남긴다.
     * @param reason 동작만으로 까닭이 정해지지 않을 때 넘기는 까닭. 없으면 동작에서 고른다.
     */
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

/**
 * @brief 클라이언트를 막아 답하지 않았음을 알린다.
 * @details 접근 제한과 속도 제한 판정은 통계 기록기에만 남았다. 기록기를 끈 배포에서는
 *          "왜 아무것도 안 되는지"를 알 방법이 없다. 판정마다 호출되는 경로라 종류별로
 *          2의 거듭제곱 번째만 남긴다.
 */
fn note_rejection(action: Action, client: &ClientInfo) {
    /** @brief 접근 제한에 막힌 누적 수. */
    static DENIED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    /** @brief 속도 제한에 막힌 누적 수. */
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

/**
 * @brief 질의를 풀지 못해 SERVFAIL로 답했음을 알린다.
 * @details 통계 기록기를 끈 배포에서는 이 기록이 해석 실패를 알 수 있는 유일한 경로다.
 *          질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn resolution_failed(reason: &'static str, stage: &'static str, name: Option<&ApName>) {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if !count.is_power_of_two() {
        return;
    }
    let qname = name.map(|n| n.to_ascii_lower()).unwrap_or_default();
    onetdns_core::warn!(event = "dns.resolution_failed", reason = reason, stage = stage, qname = %qname, count = count, "Could not resolve the query; answered SERVFAIL");
}
