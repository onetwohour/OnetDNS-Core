/*!
 * @brief 일반 질의 처리. 접근 제어, 쿠키, 정책 판정, 해석, 응답 후처리를 이 순서로 거친다.
 */

use std::borrow::Cow;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

use onetdns_control::Action;
use onetdns_core::{
    AclDecision, ClientInfo, FilterEngine, FilterVerdict, RateDecision, RewriteTarget, Transport,
};
use onetdns_filter::BlockEngine;
use onetdns_proto::{
    DnsClass, Edns, Message, Name as ApName, RData as ApRData, Record as ApRecord,
    RecordType as ApRt, ResponseCode,
};
use onetdns_runtime::{RequestCtx, Transport as RtTransport};

use crate::native::authority::name_ends_with;
use crate::native::response::{
    base_response, block_rcode, block_resp, dns64_negative_ttl, ede_text, edns_error_resp,
    error_resp, finalize, has_alias_answer, has_negative_soa, is_delegation_referral,
    normalize_recursive_response, policy_negative_resp, rdata_in_nets, rdata_ip, records_resp,
    response_has_requested_answer, rfc8482_hinfo, strip_private_records, synthesize_dns64,
    with_ede,
};
use crate::native::{
    failure_diagnosis, normalized_text_name, policy_transport, wants_dnssec, InflightGuard,
    NativeFeatures, NativeServer, ResolveOutcome, DEFAULT_EDNS_PAYLOAD, MAX_LARGE_QUERY_BYTES,
    OPT_COOKIE, OPT_NSID,
};

impl NativeServer {
    /** @brief 이 뷰에 이 이름의 답이 있는지. */
    fn view_local_answer(
        &self,
        client: &ClientInfo,
        qname: &ApName,
        qtype: ApRt,
    ) -> Option<Vec<ApRecord>> {
        let views = self.views.load();
        if views.is_empty() {
            return None;
        }
        let mut key = [0u8; 255];
        let key = qname.canonical_key_into(&mut key)?;
        let ttl = self.local_ttl.load(Ordering::Acquire);
        for v in views.iter().filter(|v| v.matches(client)) {
            match qtype {
                ApRt::A => {
                    if let Some((_, ip)) = v.local_a.iter().find(|(n, _)| n.as_slice() == key) {
                        return Some(vec![ApRecord::new(qname.clone(), ttl, ApRData::A(*ip))]);
                    }
                }
                ApRt::AAAA => {
                    if let Some((_, ip)) = v.local_aaaa.iter().find(|(n, _)| n.as_slice() == key) {
                        return Some(vec![ApRecord::new(qname.clone(), ttl, ApRData::Aaaa(*ip))]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /** @brief 서버 이름과 버전을 묻는 질의에 답한다. 감추기로 했으면 답하지 않는다. */
    fn handle_chaos(&self, request: &Message, qname: &ApName) -> Option<Message> {
        let name = qname.to_ascii_lower();
        let f = self.features.load();
        let txt: Option<&[u8]> = match name.as_str() {
            "id.server" | "hostname.bind" => {
                if f.hide_identity {
                    return Some(error_resp(request, ResponseCode::Refused));
                }
                Some(&f.server_identity)
            }
            "version.server" | "version.bind" => {
                if f.hide_version {
                    return Some(error_resp(request, ResponseCode::Refused));
                }
                Some(&f.server_version)
            }
            _ => None,
        };
        let txt = txt?;
        let mut m = base_response(request);
        m.header.authoritative = true;
        m.answers.push(ApRecord {
            name: qname.clone(),
            rtype: ApRt::TXT,
            class: DnsClass(3),
            ttl: 0,
            rdata: ApRData::Txt(vec![txt.to_vec()]),
        });
        Some(m)
    }

    /** @brief 이 요청을 보낸 클라이언트를 알아본다. */
    pub(crate) fn identify(&self, ctx: &RequestCtx) -> ClientInfo {
        let transport = core_transport(ctx.transport);
        let mut client = ClientInfo {
            source_ip: canonical_source_ip(ctx.src.ip()),

            client_id: if ctx.authenticated {
                ctx.auth_identity.clone().or_else(|| ctx.client_id.clone())
            } else {
                None
            },
            transport,

            authenticated: ctx.authenticated,
        };
        if client.client_id.is_none() {
            if let Some(mc) = &self.mac_cache {
                client.client_id = mc.lookup(client.source_ip);
            }
        }
        client
    }

    /**
     * @brief 질의 하나를 실제로 처리한다.
     * @details 입장, 요청 정책, 해석, 답 완성, 응답 정책을 차례로 거친다. 어느 단계든 응답을
     *          확정하면 뒤 단계는 건너뛴다.
     */
    pub(crate) fn handle_inner(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let f = self.features.load();
        let policy = self.policy.load();
        let block_ttl = self.block_ttl.load(Ordering::Acquire);
        match self.run_pipeline(request, ctx, &f, &policy, block_ttl) {
            ControlFlow::Break(reply) | ControlFlow::Continue(reply) => reply,
        }
    }

    /** @brief handle_inner 의 단계를 순서대로 잇는다. */
    fn run_pipeline(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        f: &NativeFeatures,
        policy: &onetdns_policy::PolicyEngine,
        block_ttl: u32,
    ) -> Stage<Option<Message>> {
        let mut scope = self.admit(request, ctx, f, block_ttl)?;
        let filter = self.apply_request_policy(&mut scope, ctx, f, policy)?;
        let _permit = self.acquire_inflight(&mut scope, f)?;
        let resolved = self.resolve_query(&mut scope, &filter)?;
        let resolved = self.complete_answer(&mut scope, f, resolved)?;
        let mut response = self.apply_response_policy(&mut scope, f, policy, &filter, resolved)?;

        self.rec_final_answer(&scope.client, &scope.qname, scope.qtype, &response);
        normalize_recursive_response(&mut response, request);
        ControlFlow::Continue(Some(finalize(response, scope.resp_edns.take())))
    }

    /**
     * @brief 입장 단계. 메시지 형식, opcode, 접근 제어, EDNS, 쿠키, 속도 제한을 본다.
     * @details UPDATE 와 NOTIFY 는 여기서 권한 영역 처리로 넘기고 끝낸다. 통과하면 질문이
     *          정확히 하나인 일반 질의다.
     */
    fn admit<'r>(
        &self,
        request: &'r Message,
        ctx: &RequestCtx,
        f: &NativeFeatures,
        block_ttl: u32,
    ) -> Stage<QueryScope<'r>> {
        if request.header.response {
            return ControlFlow::Break(None);
        }

        if request.header.opcode == 4 || request.header.opcode == 5 {
            /*
             * UPDATE 는 ZCLASS 가 달라도 형식 오류가 아니다. RFC 2136은 그것을
             * 이 서버가 맡지 않은 영역으로 보고 NOTAUTH 로 답하게 하므로 handle_update 로 넘긴다.
             */
            let valid_zone_question = request.questions.len() == 1
                && request.questions[0].qtype == ApRt::SOA
                && (request.header.opcode == 5 || request.questions[0].qclass == DnsClass::IN);
            if !valid_zone_question {
                return ControlFlow::Break(Some(edns_error_resp(
                    request,
                    ResponseCode::FormErr,
                    f.edns_buffer,
                )));
            }
        }

        let client = self.identify(ctx);

        if request.header.opcode == 4 || request.header.opcode == 5 {
            if self.acl.check(&client) == AclDecision::Deny {
                self.rec(&client, Action::Denied, None, None);
                let edns = with_ede(
                    None,
                    request,
                    f.edns_buffer,
                    onetdns_proto::ede_code::PROHIBITED,
                    "access denied by ACL",
                );
                return ControlFlow::Break(Some(finalize(
                    error_resp(request, ResponseCode::Refused),
                    edns,
                )));
            }
            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    self.rec_rc(
                        &client,
                        Action::Throttled,
                        request.questions.first().map(|question| &question.name),
                        request.questions.first().map(|question| question.qtype),
                        ResponseCode::ServFail,
                    );
                    let edns = with_ede(
                        None,
                        request,
                        f.edns_buffer,
                        onetdns_proto::ede_code::PROHIBITED,
                        "query rate limit exceeded",
                    );
                    return ControlFlow::Break(Some(finalize(
                        error_resp(request, ResponseCode::ServFail),
                        edns,
                    )));
                }
            }
        }

        if request.header.opcode == 5 {
            return ControlFlow::Break(self.handle_update(request, ctx, &client));
        }

        if request.header.opcode == 4 {
            return ControlFlow::Break(self.handle_notify(request, ctx));
        }
        if request.header.opcode != 0 {
            return ControlFlow::Break(Some(edns_error_resp(
                request,
                ResponseCode::NotImp,
                f.edns_buffer,
            )));
        }
        let [question] = request.questions.as_slice() else {
            /*
             * RFC 9619는 opcode 0인 DNS 메시지가 QDCOUNT를 1보다 크게 담을 수 없다고 정한다. 응답도
             * opcode 0이므로 그대로 돌려주면 이 서버의 답이 같은 규칙을 어긴다. 질문부를 비운다.
             */
            let mut response = edns_error_resp(request, ResponseCode::FormErr, f.edns_buffer);
            response.questions.clear();
            return ControlFlow::Break(Some(response));
        };

        let mut scope = QueryScope {
            request,
            edns_buffer: f.edns_buffer,
            block_ttl,
            client,
            resp_edns: None,
            qname: question.name.clone(),
            qtype: question.qtype,
        };

        if self.acl.check(&scope.client) == AclDecision::Deny {
            self.rec(&scope.client, Action::Denied, None, None);
            return ControlFlow::Break(scope.reply(
                error_resp(request, ResponseCode::Refused),
                Some((onetdns_proto::ede_code::PROHIBITED, "access denied by ACL")),
            ));
        }

        if let Some(request_edns) = request.opt().and_then(Edns::from_record) {
            if request_edns.version != 0 {
                let mut response_edns = base_edns(request, f.edns_buffer);
                response_edns.extended_rcode = (ResponseCode::BadVers.0 >> 4) as u8;
                return ControlFlow::Break(Some(finalize(
                    error_resp(request, ResponseCode::BadVers),
                    Some(response_edns),
                )));
            }

            /*
             * RFC 6891: 요청에 OPT가 있으면 응답에도 반드시 넣는다. 빼면 상대는 이 서버가 EDNS를
             * 모르는 것으로 보고 512바이트로 전환하고, 쿠키·NSID·패딩·EDE를 담을 슬롯도 없다.
             * 이미 읽어 둔 요청 EDNS를 그대로 고쳐 쓴다. base_edns를 부르면 같은 OPT를 한 번
             * 더 파싱하며 곧 버릴 옵션들을 항목마다 복제한다.
             */
            let mut response_edns = request_edns;
            response_edns.udp_payload = advertised_udp_payload(f.edns_buffer);
            response_edns.extended_rcode = 0;
            response_edns.version = 0;
            response_edns.options.clear();
            scope.resp_edns = Some(response_edns);
        }
        if let Some(keeper) = &f.cookies.keeper {
            match read_cookie(request) {
                Some(bytes) => match keeper.parse_and_validate(&bytes, scope.client.source_ip) {
                    Some(check) => {
                        scope.resp_edns = Some(cookie_edns(
                            request,
                            keeper.response_cookie(&check.client, scope.client.source_ip),
                            f.edns_buffer,
                        ));
                        if f.cookies.strict
                            && scope.client.transport == Transport::Do53Udp
                            && !check.valid
                        {
                            return ControlFlow::Break(
                                scope.reply(error_resp(request, ResponseCode::BadCookie), None),
                            );
                        }
                    }
                    /*
                     * COOKIE는 OPT 안에만 있으므로 이 요청에는 반드시 OPT가 있었다. 위에서
                     * 만든 응답 OPT를 그대로 담아야 RFC 6891을 지킨다. 빼면 상대는
                     * 이 서버가 EDNS를 모르는 것으로 보고 512바이트로 전환한다.
                     */
                    None => {
                        return ControlFlow::Break(
                            scope.reply(error_resp(request, ResponseCode::FormErr), None),
                        )
                    }
                },
                None if f.cookies.strict && scope.client.transport == Transport::Do53Udp => {
                    return ControlFlow::Break(Some(finalize(
                        error_resp(request, ResponseCode::BadCookie),
                        Some(base_edns(request, f.edns_buffer)),
                    )));
                }
                None => {}
            }
        }

        let nsid_requested = request
            .opt()
            .and_then(Edns::from_record)
            .is_some_and(|edns| edns.options.iter().any(|(code, _)| *code == OPT_NSID));
        if nsid_requested {
            if let Some(nsid) = &f.nsid {
                let buf = f.edns_buffer;
                scope
                    .resp_edns
                    .get_or_insert_with(|| base_edns(request, buf))
                    .options
                    .push((OPT_NSID, nsid.clone()));
            }
        }

        for rl in &self.rate_limiters {
            if rl.check(&scope.client) == RateDecision::Throttle {
                self.rec_rc(
                    &scope.client,
                    Action::Throttled,
                    Some(&scope.qname),
                    Some(scope.qtype),
                    ResponseCode::ServFail,
                );
                return ControlFlow::Break(scope.reply(
                    error_resp(request, ResponseCode::ServFail),
                    Some((
                        onetdns_proto::ede_code::PROHIBITED,
                        "query rate limit exceeded",
                    )),
                ));
            }
        }

        ControlFlow::Continue(scope)
    }

    /**
     * @brief 요청 정책 단계. 해석 전에 답을 정할 수 있는 규칙을 본다.
     * @details 존 전송, CHAOS, 최소 ANY, 로컬 답, AAAA 차단, 정책 엔진, 필터 순서다. 통과하면
     *          이후 단계가 같은 필터 판본을 쓰도록 그 판본을 돌려준다.
     */
    fn apply_request_policy(
        &self,
        scope: &mut QueryScope<'_>,
        ctx: &RequestCtx,
        f: &NativeFeatures,
        policy: &onetdns_policy::PolicyEngine,
    ) -> Stage<Arc<BlockEngine>> {
        let request = scope.request;
        let qname = &scope.qname;
        let qtype = scope.qtype;

        if f.harden_large_queries && ctx.raw.is_some_and(|raw| raw.len() > MAX_LARGE_QUERY_BYTES) {
            self.rec(&scope.client, Action::Denied, Some(qname), Some(qtype));
            return ControlFlow::Break(None);
        }

        if qtype == ApRt(252) || qtype == ApRt(251) {
            let mut first = None;
            let _ = self.handle_axfr(request, ctx, qname, &scope.client, &mut |message| {
                first = Some(message);
                false
            });
            return ControlFlow::Break(first);
        }

        let qclass = request.questions[0].qclass;
        if qclass.0 == 3 && qtype == ApRt::TXT {
            if let Some(resp) = self.handle_chaos(request, qname) {
                self.rec(&scope.client, Action::Resolved, Some(qname), Some(qtype));
                return ControlFlow::Break(scope.reply(resp, None));
            }
        }

        if qclass != DnsClass::IN {
            self.rec(&scope.client, Action::Refused, Some(qname), Some(qtype));
            return ControlFlow::Break(
                scope.reply(error_resp(request, ResponseCode::Refused), None),
            );
        }

        /*
         * 이 서버가 맡은 영역 밖이면 이름이 있는지 알 수 없으므로 여기서 바로 합성한다. 안이면
         * 표준 알고리즘을 먼저 돌린 뒤 답 구간만 바꾼다. 없는 이름에 NOERROR를 주면 존재를
         * 알리는 셈이고 부정 캐시도 서지 않는다.
         */
        if scope.minimal_any(f) && !self.serves_zone_for(qname) {
            self.rec(&scope.client, Action::Resolved, Some(qname), Some(qtype));
            return ControlFlow::Break(
                scope.reply(records_resp(request, vec![rfc8482_hinfo(qname)]), None),
            );
        }

        if let Some(recs) = self.view_local_answer(&scope.client, qname, qtype) {
            self.rec(&scope.client, Action::Resolved, Some(qname), Some(qtype));
            return ControlFlow::Break(scope.reply(records_resp(request, recs), None));
        }

        if f.block_aaaa && qtype == ApRt::AAAA {
            self.rec_rc(
                &scope.client,
                Action::Blocked,
                Some(qname),
                Some(qtype),
                ResponseCode::NoError,
            );
            return ControlFlow::Break(scope.reply(
                policy_negative_resp(request, qname, ResponseCode::NoError, scope.block_ttl),
                Some((onetdns_proto::ede_code::FILTERED, "IPv6 disabled")),
            ));
        }

        let mut policy_allow = false;
        if !policy.is_empty() {
            if let Some(qn) = normalized_text_name(qname) {
                let now = SystemTime::now();
                let pin = onetdns_policy::PolicyInput {
                    client: scope.client.source_ip,
                    qname: &qn,
                    qtype: qtype.0,
                    unix_time: crate::localtime::unix_seconds(now),
                    local_minute_of_week: crate::localtime::local_minute_of_week(now),
                    transport: policy_transport(scope.client.transport),
                    client_id: scope.client.client_id.as_deref(),
                    authenticated: scope.client.authenticated,
                };
                match policy.evaluate(&pin) {
                    onetdns_policy::Action::Continue => {}
                    onetdns_policy::Action::Allow => policy_allow = true,
                    onetdns_policy::Action::Block => {
                        self.rec_rc(
                            &scope.client,
                            Action::Blocked,
                            Some(qname),
                            Some(qtype),
                            ResponseCode::NXDomain,
                        );
                        return ControlFlow::Break(scope.reply(
                            policy_negative_resp(
                                request,
                                qname,
                                ResponseCode::NXDomain,
                                scope.block_ttl,
                            ),
                            Some((onetdns_proto::ede_code::BLOCKED, "blocked by policy")),
                        ));
                    }
                    onetdns_policy::Action::Refuse => {
                        self.rec(&scope.client, Action::Refused, Some(qname), Some(qtype));
                        return ControlFlow::Break(scope.reply(
                            error_resp(request, ResponseCode::Refused),
                            Some((onetdns_proto::ede_code::PROHIBITED, "refused by policy")),
                        ));
                    }
                    onetdns_policy::Action::Rewrite(ip) => {
                        let response = self.rewrite_resp(
                            request,
                            qname,
                            qtype,
                            RewriteTarget::ip(ip.into()),
                            &scope.client,
                        );
                        self.rec_rewrite_response(&scope.client, qname, qtype, &response, "policy");
                        return ControlFlow::Break(scope.reply(response, None));
                    }
                }
            }
        }

        let filter = self.filter.load();
        if !policy_allow {
            match filter.verdict(qname, qtype, &scope.client) {
                FilterVerdict::Allow => {}
                FilterVerdict::Block(br) => {
                    let rule = self.filter_rule_label(qname, qtype, &scope.client);
                    self.rec_rc_diag(
                        &scope.client,
                        Action::Blocked,
                        Some(qname),
                        Some(qtype),
                        block_rcode(&br, qtype),
                        "",
                        "",
                        rule.as_match(),
                    );
                    return ControlFlow::Break(scope.reply(
                        block_resp(request, qname, qtype, br, scope.block_ttl),
                        Some((onetdns_proto::ede_code::BLOCKED, "blocked by filter")),
                    ));
                }
                FilterVerdict::Rewrite(target) => {
                    let rule = self.filter_rule_label(qname, qtype, &scope.client);
                    let response = self.rewrite_resp(request, qname, qtype, target, &scope.client);
                    self.rec_rewrite_response(
                        &scope.client,
                        qname,
                        qtype,
                        &response,
                        rule.as_match(),
                    );
                    return ControlFlow::Break(scope.reply(response, None));
                }
            }
        }

        ControlFlow::Continue(filter)
    }

    /**
     * @brief 동시에 해석 중인 질의 수를 한도 안에 묶는다.
     * @return 해석이 끝날 때까지 들고 있어야 하는 자리. 한도가 없으면 None 이다.
     */
    fn acquire_inflight(
        &self,
        scope: &mut QueryScope<'_>,
        f: &NativeFeatures,
    ) -> Stage<Option<InflightGuard<'_>>> {
        if f.inflight_max == 0 {
            return ControlFlow::Continue(None);
        }
        let n = self.inflight.fetch_add(1, Ordering::Relaxed);
        if n >= f.inflight_max {
            self.inflight.fetch_sub(1, Ordering::Relaxed);
            self.rec_overloaded(&scope.client, &scope.qname, scope.qtype);
            return ControlFlow::Break(
                scope.reply(error_resp(scope.request, ResponseCode::ServFail), None),
            );
        }
        ControlFlow::Continue(Some(InflightGuard(&self.inflight)))
    }

    /**
     * @brief 해석 단계. 안전 검색이 이름을 바꾸면 바뀐 이름으로 해석 체인에 묻는다.
     * @details 해석이 실패하면 사유를 기록하고 SERVFAIL 로 끝낸다.
     */
    fn resolve_query<'r>(
        &self,
        scope: &mut QueryScope<'r>,
        filter: &BlockEngine,
    ) -> Stage<Resolved<'r>> {
        let request = scope.request;
        let qname = &scope.qname;
        let qtype = scope.qtype;

        let ss = filter
            .client_safe_search(&scope.client)
            .unwrap_or_else(|| self.safe_search.load(Ordering::Relaxed));
        let mut resolve_name = qname.clone();
        let mut safe_cname: Option<ApRecord> = None;
        if ss {
            if let Some(target) = normalized_text_name(qname)
                .as_deref()
                .and_then(onetdns_filter::safesearch::safe_target)
            {
                if let Ok(tn) = ApName::from_str(target) {
                    safe_cname = Some(ApRecord::new(
                        qname.clone(),
                        self.local_ttl.load(Ordering::Acquire),
                        ApRData::Cname(tn.clone()),
                    ));
                    resolve_name = tn;
                }
            }
        }

        let resolve_req = if resolve_name == *qname && request.additionals.is_empty() {
            Cow::Borrowed(request)
        } else {
            let mut rewritten = request.clone();
            if let Some(question) = rewritten.questions.first_mut() {
                question.name = resolve_name.clone();
                question.qtype = qtype;
            }
            strip_client_hop_edns(&mut rewritten);
            Cow::Owned(rewritten)
        };

        onetdns_forward::clear_response_source();
        let response = match self.resolve_for(&resolve_req, &scope.client) {
            ResolveOutcome::Response(response) => response,
            ResolveOutcome::Failure(failure) => {
                let (reason, class, ede) = failure_diagnosis(&failure);
                let detail = format!(
                    "The DNS query was handled but no response was produced. backend={}, query class={class}",
                    self.resolver_mode(&scope.client)
                );
                self.rec_failure(
                    &scope.client,
                    Some(qname),
                    Some(qtype),
                    reason,
                    "resolver",
                    &detail,
                );
                return ControlFlow::Break(scope.reply(
                    error_resp(request, ResponseCode::ServFail),
                    ede.map(|code| (code, ede_text(code))),
                ));
            }
        };

        ControlFlow::Continue(Resolved {
            response,
            request: resolve_req,
            safe_cname,
        })
    }

    /**
     * @brief 해석 체인이 준 응답을 이 서버의 답으로 완성한다. 최소 ANY 와 DNS64 합성을 한다.
     * @details 상류가 SERVFAIL 이나 REFUSED 를 주면 필터를 거치지 않고 그대로 끝낸다.
     */
    fn complete_answer<'r>(
        &self,
        scope: &mut QueryScope<'r>,
        f: &NativeFeatures,
        mut resolved: Resolved<'r>,
    ) -> Stage<Resolved<'r>> {
        let request = scope.request;
        let qname = &scope.qname;
        let qtype = scope.qtype;
        let resp = &mut resolved.response;

        normalize_recursive_response(resp, request);

        /*
         * 표준 알고리즘이 낸 응답에서 답 구간만 합성 HINFO로 바꾼다. 없는 이름의 NXDOMAIN,
         * 자료가 없는 이름의 NODATA, 권한 표시는 그대로 둔다. RFC 8482는 QNAME에 CNAME이
         * 있으면 합성하지 말라고 하므로 그때도 그대로 둔다.
         */
        if scope.minimal_any(f)
            && resp.header.rcode == ResponseCode::NoError.0
            && !resp.answers.is_empty()
            && !resp
                .answers
                .iter()
                .any(|record| record.rtype == ApRt::CNAME && record.name.eq_ignore_case(qname))
        {
            resp.answers = vec![rfc8482_hinfo(qname)];
        }

        if let Some(prefix) = f.dns64_prefix {
            let has_aaaa = resp
                .answers
                .iter()
                .any(|record| matches!(&record.rdata, ApRData::Aaaa(_)));
            if qtype == ApRt::AAAA
                && resp.header.rcode != ResponseCode::NXDomain.0
                && (!has_aaaa || f.dns64_synthall)
            {
                let negative_ttl = dns64_negative_ttl(resp);
                let mut a_request = Message::clone(&resolved.request);
                if let Some(question) = a_request.questions.first_mut() {
                    question.qtype = ApRt::A;
                }
                if let Some(mut a_response) = self.resolve_message_for(&a_request, &scope.client) {
                    normalize_recursive_response(&mut a_response, &a_request);
                    if a_response.header.rcode == ResponseCode::NoError.0 {
                        let synthesized =
                            synthesize_dns64(&a_response.answers, &prefix, negative_ttl);
                        if !synthesized.is_empty() {
                            let mut merged = Vec::new();

                            for record in resp.answers.iter().chain(a_response.answers.iter()) {
                                if matches!(&record.rdata, ApRData::Cname(_) | ApRData::Dname(_))
                                    && !merged.iter().any(|existing: &ApRecord| {
                                        existing.name.eq_ignore_case(&record.name)
                                            && existing.rtype == record.rtype
                                            && existing.rdata == record.rdata
                                    })
                                {
                                    merged.push(record.clone());
                                }
                            }
                            if f.dns64_synthall {
                                for record in &resp.answers {
                                    if matches!(&record.rdata, ApRData::Aaaa(_)) {
                                        merged.push(record.clone());
                                    }
                                }
                            }
                            merged.extend(synthesized);
                            resp.answers = merged;

                            resp.authorities.clear();
                            resp.header.rcode = ResponseCode::NoError.0;
                            clear_dnssec_assertion(resp);
                        }
                    }
                }
            }
        }

        /*
         * 근거 없이 비어 온 NOERROR도 그대로 전달한다. RFC 2308이 모든 구간이 빈 것을
         * NODATA의 한 모양으로 열거해 두었고, SOA가 없을 때 규격이 정한 처분은 거절이 아니라
         * 캐시 금지다. 특히 RFC 4074는 IPv6 주소가 없는 이름의 AAAA에 SERVFAIL을 주면
         * 질의자가 A로 다시 묻지 못하고 되풀이한다고 고정한다. 담지 않는 것은 캐시 계층이 한다.
         */
        if resp.header.rcode == ResponseCode::NoError.0
            && !response_has_requested_answer(&resolved.request, resp)
            && !has_negative_soa(resp)
            && !is_delegation_referral(resp)
            && !has_alias_answer(resp)
        {
            onetdns_core::debug!(
                event = "dns.unproven_nodata",
                qname = %qname.to_ascii_lower(),
                qtype = qtype.0,
                "Passing through an empty NOERROR without a negative SOA; not caching it"
            );
        }

        if resp.header.rcode == ResponseCode::ServFail.0 {
            let detail = format!(
                "The DNS handling path returned a server error response. backend={}",
                self.resolver_mode(&scope.client)
            );
            self.rec_failure(
                &scope.client,
                Some(qname),
                Some(qtype),
                "UPSTREAM_SERVFAIL",
                "upstream",
                &detail,
            );
            return ControlFlow::Break(scope.reply(resolved.response, None));
        }
        if resp.header.rcode == ResponseCode::Refused.0 {
            self.rec(&scope.client, Action::Refused, Some(qname), Some(qtype));
            return ControlFlow::Break(scope.reply(resolved.response, None));
        }

        ControlFlow::Continue(resolved)
    }

    /**
     * @brief 응답 정책 단계. 완성된 답을 보고 걸러 낸다.
     * @details 리바인드 보호, 가짜 NXDOMAIN 주소, 답 주소 거부 목록, 별칭 뒤 차단, RPZ 주소
     *          규칙, 응답 정책 엔진 순서다. 답을 걷어내는 규칙은 각자 자기 응답을 만들어 끝낸다.
     */
    fn apply_response_policy(
        &self,
        scope: &mut QueryScope<'_>,
        f: &NativeFeatures,
        policy: &onetdns_policy::PolicyEngine,
        filter: &BlockEngine,
        resolved: Resolved<'_>,
    ) -> Stage<Message> {
        let request = scope.request;
        let qname = &scope.qname;
        let qtype = scope.qtype;
        let Resolved {
            response: mut resp,
            request: resolve_req,
            safe_cname,
        } = resolved;

        if f.rebind_protection {
            let exempt = f.rebind_allow.iter().any(|s| name_ends_with(qname, s));
            if !exempt {
                let before = resp.answers.len();
                let removed = strip_private_records(&mut resp);
                if removed {
                    clear_dnssec_assertion(&mut resp);
                }
                if resp.answers.len() != before
                    && !response_has_requested_answer(&resolve_req, &resp)
                {
                    self.rec(&scope.client, Action::Blocked, Some(qname), Some(qtype));
                    return ControlFlow::Break(scope.reply(
                        policy_negative_resp(
                            request,
                            qname,
                            ResponseCode::NXDomain,
                            scope.block_ttl,
                        ),
                        Some((
                            onetdns_proto::ede_code::FILTERED,
                            "private answer blocked by rebind protection",
                        )),
                    ));
                }
            }
        }

        if !f.bogus_nxdomain.is_empty()
            && resp
                .answers
                .iter()
                .any(|r| rdata_in_nets(&r.rdata, &f.bogus_nxdomain))
        {
            self.rec(&scope.client, Action::Blocked, Some(qname), Some(qtype));
            return ControlFlow::Break(scope.reply(
                policy_negative_resp(request, qname, ResponseCode::NXDomain, scope.block_ttl),
                None,
            ));
        }

        let denied_answer = resp.answers.iter().any(|record| {
            rdata_ip(&record.rdata).is_some_and(|ip| {
                f.recurse_deny_answers.iter().any(|net| net.contains(&ip))
                    && !f.recurse_allow_answers.iter().any(|net| net.contains(&ip))
            })
        });
        if denied_answer {
            self.rec(&scope.client, Action::Blocked, Some(qname), Some(qtype));
            return ControlFlow::Break(scope.reply(
                policy_negative_resp(request, qname, ResponseCode::NXDomain, scope.block_ttl),
                Some((onetdns_proto::ede_code::FILTERED, "answer address denied")),
            ));
        }

        if f.rrset_roundrobin && resp.answers.len() > 1 {
            let n = self.rotor.fetch_add(1, Ordering::Relaxed) % resp.answers.len();
            resp.answers.rotate_left(n);
        }

        if let Some(cname) = safe_cname {
            resp.answers.insert(0, cname);
            clear_dnssec_assertion(&mut resp);
        }

        if let Some(br) = Self::cname_uncloak(filter, &resp.answers, &scope.client) {
            self.rec_rc(
                &scope.client,
                Action::Blocked,
                Some(qname),
                Some(qtype),
                block_rcode(&br, qtype),
            );
            return ControlFlow::Break(
                scope.reply(block_resp(request, qname, qtype, br, scope.block_ttl), None),
            );
        }

        if let Some(v) = Self::rpz_ip_check(filter, &resp.answers) {
            match v {
                FilterVerdict::Allow => {}
                FilterVerdict::Block(br) => {
                    self.rec_rc(
                        &scope.client,
                        Action::Blocked,
                        Some(qname),
                        Some(qtype),
                        block_rcode(&br, qtype),
                    );
                    return ControlFlow::Break(scope.reply(
                        block_resp(request, qname, qtype, br, scope.block_ttl),
                        Some((onetdns_proto::ede_code::BLOCKED, "blocked by filter")),
                    ));
                }
                FilterVerdict::Rewrite(t) => {
                    let response = self.rewrite_resp(request, qname, qtype, t, &scope.client);
                    self.rec_rewrite_response(&scope.client, qname, qtype, &response, "rpz-ip");
                    return ControlFlow::Break(scope.reply(response, None));
                }
            }
        }

        if let Some((code, text)) = resp.opt().and_then(Edns::from_record).and_then(|e| e.ede()) {
            resp.additionals
                .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
            scope.resp_edns = with_ede(
                scope.resp_edns.take(),
                request,
                scope.edns_buffer,
                code,
                &text,
            );
        }

        /*
         * 후처리 뒤에도 같은 판단이다. 이 서버의 필터가 답을 걷어내 비게 된 경우는 걷어내는 곳에서
         * 각자 자기 응답을 만들어 돌려주므로 여기까지 오지 않는다.
         */
        if resp.header.rcode == ResponseCode::NoError.0
            && !response_has_requested_answer(request, &resp)
            && !has_negative_soa(&resp)
            && !is_delegation_referral(&resp)
            && !has_alias_answer(&resp)
        {
            onetdns_core::debug!(
                event = "dns.unproven_nodata_after_postprocess",
                qname = %qname.to_ascii_lower(),
                qtype = qtype.0,
                "Answer is still empty without proof after post-processing; passing it through"
            );
        }

        if policy.has_response_hook() {
            if let Some(qn) = normalized_text_name(qname) {
                let mut addrs: Vec<IpAddr> = Vec::new();
                for record in &resp.answers {
                    if let Some(ip) = rdata_ip(&record.rdata) {
                        addrs.push(ip);
                        if addrs.len() >= 16 {
                            break;
                        }
                    }
                }
                let rin = onetdns_policy::ResponseInput {
                    qname: &qn,
                    qtype: qtype.0,
                    rcode: resp.header.rcode,
                    addrs: &addrs,
                };
                match policy.evaluate_response(&rin) {
                    onetdns_policy::ResponseVerdict::Pass => {}
                    onetdns_policy::ResponseVerdict::Block => {
                        self.rec_rc(
                            &scope.client,
                            Action::Blocked,
                            Some(qname),
                            Some(qtype),
                            ResponseCode::NXDomain,
                        );
                        return ControlFlow::Break(scope.reply(
                            policy_negative_resp(
                                request,
                                qname,
                                ResponseCode::NXDomain,
                                scope.block_ttl,
                            ),
                            Some((
                                onetdns_proto::ede_code::FILTERED,
                                "blocked by response policy",
                            )),
                        ));
                    }
                    onetdns_policy::ResponseVerdict::Refuse => {
                        self.rec(&scope.client, Action::Refused, Some(qname), Some(qtype));
                        return ControlFlow::Break(scope.reply(
                            error_resp(request, ResponseCode::Refused),
                            Some((
                                onetdns_proto::ede_code::PROHIBITED,
                                "refused by response policy",
                            )),
                        ));
                    }
                }
            }
        }

        ControlFlow::Continue(resp)
    }
}

/**
 * @brief 단계가 응답을 확정했거나 질의를 버리기로 해 처리를 끝낸다는 표시.
 * @details Break 에 담긴 값이 handle_inner 의 반환값이 된다. None 은 응답하지 않는다는 뜻이다.
 */
type Stage<T> = ControlFlow<Option<Message>, T>;

/** @brief 입장을 통과한 질의 하나가 이후 단계를 지나는 동안 함께 쓰는 값. */
struct QueryScope<'r> {
    request: &'r Message,
    edns_buffer: u16,
    block_ttl: u32,
    client: ClientInfo,
    /** @brief 응답에 실을 OPT. 요청에 OPT가 없고 NSID 도 붙이지 않았으면 None 이다. */
    resp_edns: Option<Edns>,
    qname: ApName,
    qtype: ApRt,
}

impl QueryScope<'_> {
    /**
     * @brief 응답을 확정한다. ede 가 있으면 사유를 붙인다.
     * @note 응답 OPT를 가져가므로 한 질의에 한 번만 부른다.
     */
    fn reply(&mut self, message: Message, ede: Option<(u16, &str)>) -> Option<Message> {
        let edns = self.resp_edns.take();
        let edns = match ede {
            Some((code, text)) => with_ede(edns, self.request, self.edns_buffer, code, text),
            None => edns,
        };
        Some(finalize(message, edns))
    }

    /**
     * @brief ANY 를 RFC 8482의 합성 HINFO로 줄여 답할지.
     * @details RFC 8482는 ANY를 온전히 답하지 않는 방법을 셋만 열거하고, 그 밖에는 표준 알고리즘을
     *          따르라고 정한다. 거절은 그 셋에 없으므로 합성 HINFO로 답한다. DO를 설정한 질의자에게는
     *          관례대로 답한다. 서명된 영역이면 RRSIG를 함께 요구하는데 합성한 레코드에는 붙일 서명이
     *          없다. 관례적 응답은 그 자체로 표준 알고리즘이다.
     */
    fn minimal_any(&self, f: &NativeFeatures) -> bool {
        self.qtype == ApRt::ANY && !f.allow_any && !wants_dnssec(self.request)
    }
}

/** @brief 해석 단계가 넘기는 값. */
struct Resolved<'r> {
    response: Message,
    /** @brief 해석 체인에 보낸 요청. 이름을 바꿨거나 클라이언트 구간 EDNS를 걷어냈으면 사본이다. */
    request: Cow<'r, Message>,
    /** @brief 안전 검색이 원래 이름에서 바꾼 이름으로 잇는 CNAME. 답 맨 앞에 붙인다. */
    safe_cname: Option<ApRecord>,
}

/** @brief 질의 기록에 남길 걸린 규칙과 그 규칙이 들어 있던 목록. */
#[derive(Default, Clone, Copy)]
pub(crate) struct RuleMatch<'a> {
    /** @brief 걸린 규칙. */
    pub(crate) rule: &'a str,
    /** @brief 그 규칙이 들어 있던 목록. 목록에 속하지 않으면 비어 있다. */
    pub(crate) list: &'a str,
}

impl<'a> From<&'a str> for RuleMatch<'a> {
    /** @brief 목록 없이 규칙 이름만 남긴다. */
    fn from(rule: &'a str) -> Self {
        RuleMatch { rule, list: "" }
    }
}

/** @brief 출발지 주소를 한 형태로 맞춘다. IPv4를 담은 IPv6 표기를 펴지 않으면 같은 주소가 제한을 두 번 받는다. */
fn canonical_source_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/** @brief 전송 종류를 공통 표현으로. */
fn core_transport(t: RtTransport) -> Transport {
    match t {
        RtTransport::Do53Udp => Transport::Do53Udp,
        RtTransport::Do53Tcp => Transport::Do53Tcp,
        RtTransport::DoT => Transport::DoT,
        RtTransport::DoH => Transport::DoH,
        RtTransport::DoH3 => Transport::DoH3,
        RtTransport::DoQ => Transport::DoQ,
        RtTransport::DnsCrypt => Transport::DnsCrypt,
    }
}

/** @brief 전송 종류를 기록 형식의 표현으로. */
pub(crate) fn dnstap_proto(t: RtTransport) -> onetdns_control::DnstapProtocol {
    match t {
        RtTransport::Do53Udp => onetdns_control::DnstapProtocol::Udp,
        RtTransport::Do53Tcp => onetdns_control::DnstapProtocol::Tcp,
        RtTransport::DoT => onetdns_control::DnstapProtocol::Dot,
        RtTransport::DoH | RtTransport::DoH3 => onetdns_control::DnstapProtocol::Doh,
        RtTransport::DoQ => onetdns_control::DnstapProtocol::Doq,
        RtTransport::DnsCrypt => onetdns_control::DnstapProtocol::DnscryptUdp,
    }
}

/** @brief 요청에 담긴 쿠키. */
pub(crate) fn read_cookie(request: &Message) -> Option<Vec<u8>> {
    let opt = request.opt()?;
    let edns = Edns::from_record(opt)?;
    edns.options
        .iter()
        .find(|(c, _)| *c == OPT_COOKIE)
        .map(|(_, b)| b.clone())
}

/**
 * @brief 클라이언트와 이 서버의 사이에서만 뜻이 있는 옵션을 뗀다.
 * @warning 떼지 않고 업스트림으로 넘기면 그 옵션이 업스트림에 이 서버의 클라이언트 정보를 흘리거나,
 *          응답 캐시 키를 쓸데없이 구분한다.
 */
fn strip_client_hop_edns(request: &mut Message) {
    request
        .additionals
        .retain(|record| record.rtype != ApRt(250));
    for record in &mut request.additionals {
        if record.rtype != ApRt::OPT {
            continue;
        }
        let Some(mut edns) = Edns::from_record(record) else {
            continue;
        };
        edns.options.retain(|(code, _)| {
            !matches!(
                *code,
                OPT_COOKIE
                    | OPT_NSID
                    | onetdns_proto::EDNS_TCP_KEEPALIVE
                    | onetdns_proto::EDNS_PADDING
            )
        });
        *record = edns
            .try_to_record()
            .expect("A record with EDNS options removed cannot be larger than the original");
    }
}

/**
 * @brief 응답 OPT에 알릴 UDP 크기.
 * @details 설정이 512보다 작으면 기본값으로 올린다. 빠른 경로와 구조적 경로가 같은 값을
 *          알려야 한다. 어긋나면 같은 질의에 경로마다 다른 바이트가 나간다.
 */
pub(crate) fn advertised_udp_payload(configured: u16) -> u16 {
    if configured < 512 {
        DEFAULT_EDNS_PAYLOAD
    } else {
        configured
    }
}

/** @brief 응답에 담을 기본 옵션. */
pub(crate) fn base_edns(request: &Message, udp_payload: u16) -> Edns {
    let payload = advertised_udp_payload(udp_payload);
    let mut edns = request
        .opt()
        .and_then(Edns::from_record)
        .unwrap_or_default();
    edns.udp_payload = payload;
    edns.extended_rcode = 0;
    edns.version = 0;
    edns.options.clear();
    edns
}

/** @brief 쿠키를 담은 응답 옵션. */
fn cookie_edns(request: &Message, cookie: Vec<u8>, udp_payload: u16) -> Edns {
    let mut edns = base_edns(request, udp_payload);
    edns.options.push((OPT_COOKIE, cookie));
    edns
}

/** @brief 검증됐다는 표시를 지운다. 이 서버가 검증하지 않은 것을 검증됐다고 하면 안 된다. */
fn clear_dnssec_assertion(message: &mut Message) {
    message.header.authentic_data = false;
    let is_proof =
        |record: &ApRecord| matches!(record.rtype, ApRt::RRSIG | ApRt::NSEC | ApRt::NSEC3);
    message.answers.retain(|record| !is_proof(record));
    message.authorities.retain(|record| !is_proof(record));
    message.additionals.retain(|record| !is_proof(record));
}

#[cfg(test)]
/** @brief 일반 질의의 처리 순서와 판정. */
mod tests {
    use super::*;
    use crate::native::tests::{ctx, q, shaped_server, update_features};
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use onetdns_core::Transport;
    use onetdns_proto::{
        DnsClass, Edns, Message, Name as ApName, RData as ApRData, Record as ApRecord,
        RecordType as ApRt, ResponseCode,
    };
    use onetdns_runtime::{Handler, Transport as RtTransport};
    use onetdns_security::CookieKeeper;

    use crate::native::{CookiePolicy, OPT_COOKIE, OPT_NSID};

    #[test]
    /** @brief 표기가 다른 같은 주소를 하나로 보는지. 안 그러면 제한을 두 배로 받는다. */
    fn ipv4_mapped_v6_canonicalizes_to_v4() {
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(
            canonical_source_ip(mapped),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_source_ip(v6), v6);

        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(canonical_source_ip(v4), v4);
    }

    #[test]
    /** @brief 이 서버와 클라이언트 사이에서만 뜻이 있는 옵션만 떼는지. 더 떼면 응답이 달라진다. */
    fn client_hop_edns_is_stripped_before_resolver_and_semantic_options_remain() {
        /** @brief 쿠키를 담은 테스트용 질의. */
        fn request(cookie: u8) -> Message {
            let mut request = q("edns-hop.example");
            let mut edns = Edns {
                udp_payload: 1232,
                dnssec_ok: true,
                ..Default::default()
            };
            edns.options.push((OPT_COOKIE, vec![cookie; 8]));
            edns.options.push((OPT_NSID, Vec::new()));
            edns.options
                .push((onetdns_proto::EDNS_TCP_KEEPALIVE, vec![0, 10]));
            edns.options
                .push((onetdns_proto::EDNS_PADDING, vec![0; 32]));
            edns.options.push((8, vec![0, 1, 24, 0, 192, 0, 2]));
            request.additionals.push(edns.try_to_record().unwrap());
            request.additionals.push(ApRecord {
                name: ApName::from_str("client-key").unwrap(),
                rtype: ApRt(250),
                class: DnsClass(255),
                ttl: 0,
                rdata: ApRData::Unknown(250, vec![1, 2, 3]),
            });
            request
        }

        let mut first = request(1);
        let mut second = request(2);
        strip_client_hop_edns(&mut first);
        strip_client_hop_edns(&mut second);

        assert_eq!(
            first.try_encode().unwrap(),
            second.try_encode().unwrap(),
            "client cookie must not split cache keys"
        );
        let edns = first.opt().and_then(Edns::from_record).unwrap();
        assert!(edns.dnssec_ok, "DO is resolver-semantic");
        assert_eq!(edns.udp_payload, 1232);
        assert_eq!(edns.options, vec![(8, vec![0, 1, 24, 0, 192, 0, 2])]);
        assert!(first
            .additionals
            .iter()
            .all(|record| record.rtype != ApRt(250)));
    }

    #[test]
    /** @brief lenient 쿠키가 무쿠키 wire 질의는 늦추지 않고 쿠키 클라이언트에는 발급하는지. */
    fn lenient_cookie_keeps_plain_wire_and_handles_cookie_requests_structurally() {
        use onetdns_runtime::WireDisposition;

        let server = shaped_server(true);
        update_features(&server, |features| {
            features.cookies = CookiePolicy {
                keeper: Some(Arc::new(CookieKeeper::from_secret(&[2; 16]))),
                strict: false,
            };
        });

        let plain = q("cookie-wire.example");
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(
                &plain.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Respond,
            "쿠키를 보내지 않은 질의는 기존 wire 레인을 유지합니다"
        );

        let client_cookie = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut cookie_request = q("cookie-wire.example");
        let mut edns = Edns::default();
        edns.options.push((OPT_COOKIE, client_cookie.to_vec()));
        cookie_request
            .additionals
            .push(edns.try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &cookie_request.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Fallback,
            "COOKIE 옵션은 서버 쿠키를 만들 수 있는 구조적 경로가 맡습니다"
        );

        let response = server
            .handle(&cookie_request, &ctx())
            .expect("lenient 쿠키 응답");
        let returned = read_cookie(&response).expect("응답 COOKIE 옵션");
        assert_eq!(returned.len(), 24, "client 8 + RFC 9018 server 16");
        assert_eq!(&returned[..8], &client_cookie);

        update_features(&server, |features| features.cookies.strict = true);
        let strict = server
            .handle(&plain, &ctx())
            .expect("strict BADCOOKIE 응답");
        assert_eq!(strict.header.rcode, ResponseCode::BadCookie.0);
    }

    #[test]
    /**
     * @brief 형식이 틀린 COOKIE를 FORMERR로 거절하되 응답 OPT는 유지하는지.
     * @details RFC 7873이 길이 8도 16에서 40도 아닌 옵션을 FORMERR로 정하고,
     *          RFC 6891이 요청에 OPT가 있으면 응답에도 넣게 한다. OPT를 빼면 상대는
     *          이 서버가 EDNS를 모르는 것으로 보고 512바이트 평문으로 전환한다.
     */
    fn malformed_cookie_is_formerr_that_still_carries_opt() {
        let server = shaped_server(true);
        update_features(&server, |features| {
            features.cookies = CookiePolicy {
                keeper: Some(Arc::new(CookieKeeper::from_secret(&[3; 16]))),
                strict: false,
            };
        });

        for length in [1usize, 7, 9, 15, 41, 64] {
            let mut request = q("bad-cookie.example");
            let mut edns = Edns::default();
            edns.udp_payload = 1232;
            edns.options.push((OPT_COOKIE, vec![0x5a; length]));
            request.additionals.push(edns.try_to_record().unwrap());

            let response = server
                .handle(&request, &ctx())
                .expect("규격에 어긋난 COOKIE 응답");
            assert_eq!(
                response.header.rcode,
                ResponseCode::FormErr.0,
                "COOKIE 길이 {length}"
            );
            assert!(
                response.opt().is_some(),
                "COOKIE 길이 {length}: 요청 OPT를 그대로 돌려줘야 합니다"
            );
            assert!(
                read_cookie(&response).is_none(),
                "COOKIE 길이 {length}: 규격에 어긋난 요청에는 서버 쿠키를 주지 않습니다"
            );
        }

        let mut valid = q("bad-cookie.example");
        let mut edns = Edns::default();
        edns.udp_payload = 1232;
        edns.options.push((OPT_COOKIE, vec![0x5a; 8]));
        valid.additionals.push(edns.try_to_record().unwrap());
        let response = server.handle(&valid, &ctx()).expect("정상 COOKIE 응답");
        assert_ne!(
            response.header.rcode,
            ResponseCode::FormErr.0,
            "8바이트 클라이언트 쿠키는 규격에 맞습니다"
        );
    }

    #[test]
    /** @brief 암호화 전송으로 왔다는 사실이 정책까지 전해지는지. */
    fn encrypted_runtime_transport_is_preserved() {
        assert_eq!(core_transport(RtTransport::DoT), Transport::DoT);
        assert_eq!(core_transport(RtTransport::DoH), Transport::DoH);
        assert_eq!(core_transport(RtTransport::DoQ), Transport::DoQ);
        assert_eq!(core_transport(RtTransport::DnsCrypt), Transport::DnsCrypt);
        assert_eq!(
            dnstap_proto(RtTransport::DoT),
            onetdns_control::DnstapProtocol::Dot
        );
        assert_eq!(
            dnstap_proto(RtTransport::DoH),
            onetdns_control::DnstapProtocol::Doh
        );
        assert_eq!(
            dnstap_proto(RtTransport::DoQ),
            onetdns_control::DnstapProtocol::Doq
        );
        assert_eq!(
            dnstap_proto(RtTransport::DnsCrypt),
            onetdns_control::DnstapProtocol::DnscryptUdp
        );
    }
}
