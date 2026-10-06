/*!
 * @brief 전송 계층이 부르는 진입점과, 캐시가 맞은 UDP 질의를 파싱 없이 내보내는 wire 빠른 경로.
 */

use std::sync::atomic::Ordering;
#[cfg(unix)]
use std::sync::Arc;
use std::time::SystemTime;

use onetdns_control::Action;
use onetdns_core::{AclDecision, FilterEngine, FilterVerdict, RateDecision};
#[cfg(unix)]
use onetdns_proto::Edns;
use onetdns_proto::{DnsClass, Message, Name as ApName, RecordType as ApRt, ResponseCode};
use onetdns_runtime::{Handler, RequestCtx};

#[cfg(unix)]
use crate::native::ddr_owner;
#[cfg(unix)]
use crate::native::lane::{reactor_response_edns, LaneClient, LaneState, LANE};
use crate::native::query::dnstap_proto;
#[cfg(unix)]
use crate::native::query::read_cookie;
use crate::native::response::{
    answers_summary, edns_error_resp, error_resp, finalize, now_unix, postprocess, with_ede,
};
use crate::native::{NativeServer, MAX_LARGE_QUERY_BYTES};

impl Handler for NativeServer {
    /** @brief 질의 하나를 처리한다. */
    fn handle(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let timer = onetdns_control::RequestTimer::start();
        let ordinary_query = request.header.opcode == 0
            && request
                .questions
                .first()
                .is_none_or(|question| question.qtype != ApRt(251) && question.qtype != ApRt(252));
        let query_tsig = if ordinary_query && onetdns_dnssec::tsig::contains_tsig(request) {
            match self.check_tsig(request, ctx.raw, false, false) {
                Ok(context) => context,
                Err(response) => return Some(response),
            }
        } else {
            None
        };
        let mut resp = self.handle_inner(request, ctx)?;
        let features = self.features.load();
        if let Err(error) = postprocess(&features, &mut resp, request, ctx) {
            onetdns_core::error!(event = "dns.response_postprocess_failed", %error,
                "EDNS post-processing of the response failed; replacing it with SERVFAIL");
            resp = error_resp(request, ResponseCode::ServFail);
        }
        if let Some((key, request_tsig)) = query_tsig {
            resp.additionals.retain(|record| record.rtype != ApRt(250));
            if onetdns_dnssec::tsig::sign_response_message(
                &mut resp,
                &key,
                now_unix(),
                &request_tsig,
            )
            .is_err()
            {
                resp = error_resp(request, ResponseCode::ServFail);
                onetdns_dnssec::tsig::sign_response_message(
                    &mut resp,
                    &key,
                    now_unix(),
                    &request_tsig,
                )
                .expect("A minimal SERVFAIL can always be encoded before TSIG signing");
            }
        }
        if self.events().is_some() {
            let client = self.identify(ctx);
            self.rec_latency(
                &client,
                request.questions.first().map(|q| &q.name),
                timer.elapsed_us(),
            );
        }

        if let Some(dt) = &features.dnstap {
            let proto = dnstap_proto(ctx.transport);
            if let Ok(wire) = resp.try_encode() {
                dt.log_client_response(ctx.src, proto, SystemTime::now(), &wire);
            }
        }
        Some(resp)
    }

    /** @brief 파싱하기 전에 빠른 경로로 답할 수 있는지 본다. 못 하면 보통 경로로 보낸다. */
    fn handle_udp_wire(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        let authority = self.authority_wire_dispatch(packet, ctx, out);
        if authority != onetdns_runtime::WireDisposition::Fallback {
            return authority;
        }
        self.wire_dispatch(packet, ctx, out, now, false)
    }

    /** @brief 파싱하기 전에 권한 영역 빠른 경로로 답할 수 있는지 본다. */
    fn handle_tcp_wire(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        _now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        self.authority_wire_dispatch(packet, ctx, out)
    }

    /** @brief 이미 인코딩해 둔 응답을 그대로 내보낸다. */
    fn handle_preencoded_stream(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        emit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Option<bool> {
        self.handle_cached_axfr_wire(request, ctx, out, emit)
    }

    #[cfg(unix)]
    /** @brief 레인이 이미 캐시에 넣은 답을 빠른 경로로 내보낸다. */
    fn handle_udp_wire_hit(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::WireDisposition {
        self.wire_dispatch(packet, ctx, out, now, true)
    }
    #[cfg(unix)]
    /** @brief 레인이 붙어 있는지. */
    fn reactor_active(&self) -> bool {
        self.reactor_lane.is_some()
            && (self.features.load().lanes.reactor
                || LANE.with(|slot| {
                    slot.borrow()
                        .as_ref()
                        .is_some_and(|state| !state.clients.is_empty())
                }))
    }

    #[cfg(unix)]
    /** @brief 레인에 더 맡길 슬롯이 있는지. */
    fn reactor_has_capacity(&self) -> bool {
        let Some(lane) = &self.reactor_lane else {
            return false;
        };
        LANE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_none_or(|st| st.reactor.live() < lane.inflight)
        })
    }

    #[cfg(unix)]
    /** @brief 다음 데드라인까지 기다릴 밀리초. */
    fn reactor_deadline_ms(&self, now: std::time::Instant) -> i32 {
        LANE.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|st| st.reactor.next_deadline_in(now))
                .map(|d| (d.as_millis() as i32).clamp(1, 50))
                .unwrap_or(50)
        })
    }

    #[cfg(unix)]
    /** @brief 레인이 지켜보는 소켓들을 모은다. */
    fn reactor_collect(&self, fds: &mut Vec<libc::pollfd>, map: &mut Vec<usize>) {
        LANE.with(|slot| {
            if let Some(st) = slot.borrow().as_ref() {
                st.reactor.collect_pollfds(fds, map);
            }
        })
    }

    #[cfg(unix)]
    /**
     * @brief 이 질의를 레인에 맡긴다.
     * @warning 레인 조건이 닫혀 있으면 맡기지 않는다. 레인은 응답을 바꾸는 기능의 처리를
     *          하지 않으므로 맡기면 그 기능이 없는 것처럼 답이 나간다.
     */
    fn reactor_submit(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
    ) -> onetdns_runtime::ReactorDisposition {
        use onetdns_recurse::reactor::SubmitOutcome;
        use onetdns_runtime::ReactorDisposition as R;
        let Some(lane) = &self.reactor_lane else {
            return R::Fallback;
        };
        let f = self.features.load();
        if !f.lanes.reactor {
            return R::Fallback;
        }
        let Some(runtime) = f
            .lane_runtime
            .as_ref()
            .filter(|runtime| runtime.recursor.is_some())
            .cloned()
        else {
            return R::Fallback;
        };
        let epoch = runtime.cache.epoch();
        /*
         * 레인이 끝낸 답은 조건을 다시 보지 않고 이 캐시 세대로 담긴다. 세대를 잡기 전에 기능
         * 세트가 바뀌었다면 이전 조건으로 고른 답이 비운 뒤의 세대를 달게 되므로 맡기지 않는다.
         */
        if !Arc::ptr_eq(&f, &self.features.load()) {
            return R::Fallback;
        }
        if self.safe_search.load(Ordering::Relaxed) {
            return R::Fallback;
        }
        if f.harden_large_queries && packet.len() > MAX_LARGE_QUERY_BYTES {
            return R::Fallback;
        }
        let Ok(request) = Message::parse(packet) else {
            return R::Fallback;
        };
        if request.header.opcode != 0 || request.questions.len() != 1 {
            return R::Fallback;
        }
        // lenient는 쿠키 없는 질의만 이 레인에 맡긴다. COOKIE 질의는 정상 경로가 서버
        // 쿠키를 발급·검증해야 하므로, 여기서 답하면 보안 기능이 없는 것처럼 보인다.
        if f.cookies.keeper.is_some() && read_cookie(&request).is_some() {
            return R::Fallback;
        }
        // 이 레인은 handle_inner 를 거치지 않으므로 거기 있는 EDNS 버전 협상도 돌지 않는다.
        // 모르는 버전에는 RFC 6891이 BADVERS 를 요구하는데, 여기서 맡으면 답까지
        // 담아 보내 이 서버가 그 버전을 구현한다고 알리게 된다.
        if request
            .opt()
            .and_then(Edns::from_record)
            .is_some_and(|edns| edns.version != 0)
        {
            return R::Fallback;
        }
        if onetdns_dnssec::tsig::peek_key_name(&request).is_some() {
            return R::Fallback;
        }
        if f.ddr_enabled && ddr_owner(&request.questions[0].name) {
            return R::Fallback;
        }
        let qtype = request.questions[0].qtype;
        if qtype == ApRt(251) || qtype == ApRt(252) {
            return R::Fallback;
        }
        let client = self.identify(ctx);
        if self.acl.check(&client) == AclDecision::Deny {
            return R::Fallback;
        }
        let filter = self.filter.load();

        if filter.has_rpz_ns() || filter.has_rpz_ip() {
            return R::Fallback;
        }
        if !filter.is_trivially_allow() {
            if filter.client_safe_search(&client).unwrap_or(false) {
                return R::Fallback;
            }
            if !matches!(
                filter.verdict(&request.questions[0].name, qtype, &client),
                FilterVerdict::Allow
            ) {
                return R::Fallback;
            }
        }

        if let Some(mut resp) = runtime
            .cache
            .lane_response(&request)
            .or_else(|| runtime.cache.lane_failure(&request))
        {
            if !filter.is_trivially_allow()
                && Self::cname_uncloak(&filter, &resp.answers, &client).is_some()
            {
                return R::Fallback;
            }
            reactor_response_edns(&f, &mut resp, &request);
            if postprocess(&f, &mut resp, &request, ctx).is_err() {
                return R::Fallback;
            }
            onetdns_runtime::encode_limited(&request, &resp, out);
            if out.buf.is_empty() {
                return R::Fallback;
            }

            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    out.clear();
                    return R::Fallback;
                }
            }

            if let Some(recorder) = self.events() {
                recorder.record_cache(true);
                onetdns_forward::note_response_source("cache");
                let timer = onetdns_control::RequestTimer::start();
                let qname = &request.questions[0].name;
                self.rec_final_answer(&client, qname, qtype, &resp);
                self.rec_latency(&client, Some(qname), timer.elapsed_us());
            }
            return R::Respond;
        }

        for limiter in &self.rate_limiters {
            if limiter.check(&client) == RateDecision::Throttle {
                return R::Fallback;
            }
        }
        let qname = request.questions[0].name.clone();
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            if st.as_ref().is_some_and(|state| {
                !Arc::ptr_eq(&state.runtime, &runtime) && !state.clients.is_empty()
            }) {
                return R::Fallback;
            }
            if st
                .as_ref()
                .is_some_and(|state| !Arc::ptr_eq(&state.runtime, &runtime))
            {
                *st = None;
            }
            let st = st.get_or_insert_with(|| LaneState::new(lane.chain.clone(), runtime.clone()));
            let token = st.next;
            match st.reactor.submit(
                runtime
                    .recursor
                    .as_ref()
                    .expect("Only generations with a recursive resolver passed the check above"),
                qname,
                qtype,
                token,
                now,
                request.header.checking_disabled,
            ) {
                SubmitOutcome::Accepted | SubmitOutcome::Merged => {
                    st.next = st.next.wrapping_add(1);
                    if let Some(recorder) = self.events() {
                        recorder.record_cache(false);
                    }
                    st.clients.insert(
                        token,
                        LaneClient {
                            src: ctx.src,
                            raw: packet.to_vec(),
                            request,
                            client,
                            submitted: now,
                            epoch,
                            features: f,
                        },
                    );
                    R::Submitted
                }
                SubmitOutcome::Rejected | SubmitOutcome::Failed => R::Fallback,
            }
        })
    }

    #[cfg(unix)]
    /** @brief 준비된 소켓을 읽어 레인을 진행한다. */
    fn reactor_pump(
        &self,
        fds: &[libc::pollfd],
        base: usize,
        map: &[usize],
        now: std::time::Instant,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let Some(_lane) = &self.reactor_lane else {
            return;
        };
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            let Some(st) = st.as_mut() else { return };
            let mut comps = Vec::new();
            st.reactor.pump(
                st.runtime
                    .recursor
                    .as_ref()
                    .expect("The in-flight lane generation has a recursive resolver"),
                fds,
                base,
                map,
                now,
                &mut comps,
            );
            self.lane_drain_fallback(st, out);
            self.lane_finish(st, comps, out);
        })
    }

    #[cfg(unix)]
    /** @brief 데드라인이 지난 것을 처리한다. */
    fn reactor_tick(
        &self,
        now: std::time::Instant,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let Some(_lane) = &self.reactor_lane else {
            return;
        };
        LANE.with(|slot| {
            let mut st = slot.borrow_mut();
            let Some(st) = st.as_mut() else { return };
            let mut comps = Vec::new();
            st.reactor.on_tick(
                st.runtime
                    .recursor
                    .as_ref()
                    .expect("The in-flight lane generation has a recursive resolver"),
                now,
                &mut comps,
            );
            self.lane_drain_fallback(st, out);
            self.lane_finish(st, comps, out);
        })
    }

    /** @brief 응답이 여럿인 질의를 처리한다. */
    fn handle_multi(&self, request: &Message, ctx: &RequestCtx) -> Option<Vec<Message>> {
        let mut responses = Vec::new();
        self.emit_responses(request, ctx, &mut |message| {
            responses.push(message);
            true
        })?;
        Some(responses)
    }

    /**
     * @brief 파싱하지 못한 질의에 FORMERR로 답한다.
     *
     * @details 버리면 클라이언트는 데드라인을 다 기다린 뒤 재시도한다. 응답은 머리말뿐이라
     *          질의보다 크지 않으므로 증폭이 되지 않는다. 파싱 전이라 일반 경로를 지나오지
     *          못했으므로 접근 제어와 속도 제한을 여기서 본다.
     */
    fn handle_unparsable(&self, packet: &[u8], ctx: &RequestCtx) -> Option<Message> {
        if !self.client_allowed(ctx) {
            return None;
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let mut response = Message::default();
        response.header.id = u16::from_be_bytes([packet[0], packet[1]]);
        response.header.response = true;
        response.header.opcode = ((flags >> 11) & 0xF) as u8;
        response.header.recursion_desired = flags & 0x0100 != 0;
        response.header.recursion_available = true;
        response.header.rcode = ResponseCode::FormErr.0;
        onetdns_core::debug!(
            event = "dns.unparsable_query",
            client = %ctx.src.ip(),
            bytes = packet.len(),
            "Could not parse the query; answered FORMERR"
        );
        Some(response)
    }

    /** @brief 스트림 전송의 질의를 처리한다. */
    fn handle_stream(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        emit: &mut dyn FnMut(&Message) -> bool,
    ) -> bool {
        self.emit_responses(request, ctx, &mut |message| emit(&message))
            .is_some()
    }
}

impl NativeServer {
    /**
     * @brief 이 클라이언트에게 답해도 되는지.
     *
     * @details 질의를 해석하기 전에 답을 내보내는 경로들이 쓴다. 파이프라인을 타지 않는
     *          응답도 접근 제어와 속도 제한 뒤에 있어야 한다. 그렇지 않으면 그 경로만
     *          누구에게나 열린 증폭기가 된다.
     */
    pub fn client_allowed(&self, ctx: &RequestCtx) -> bool {
        let client = self.identify(ctx);
        if self.acl.check(&client) == AclDecision::Deny {
            return false;
        }
        !self
            .rate_limiters
            .iter()
            .any(|limiter| limiter.check(&client) == RateDecision::Throttle)
    }

    /**
     * @brief 캐시가 맞은 UDP 질의를 파싱 없이 내보낸다.
     * @warning 맞았더라도 접근 제어·속도 제한·차단은 지금 세대로 다시 본다. 통과하지 못하면
     *          보통 경로로 보낸다.
     */
    fn wire_dispatch(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        now: std::time::Instant,
        hit_only: bool,
    ) -> onetdns_runtime::WireDisposition {
        use onetdns_runtime::WireDisposition as Wire;
        let f = self.features.load();
        if !f.lanes.wire {
            return Wire::Fallback;
        }
        let Some(runtime) = f
            .lane_runtime
            .as_ref()
            .filter(|runtime| runtime.factory.is_some())
        else {
            return Wire::Fallback;
        };

        if self.safe_search.load(Ordering::Relaxed) {
            return Wire::Fallback;
        }
        if f.harden_large_queries && packet.len() > MAX_LARGE_QUERY_BYTES {
            return Wire::Fallback;
        }
        let Some(scanned) = crate::wirecache::scan_query(packet) else {
            return Wire::Fallback;
        };

        let filter = self.filter.load();
        let filter_tag = f.wire_tag(&filter);

        let trivial = filter.is_trivially_allow();

        if let Some((entry, elapsed_secs)) = runtime.cache.wire_get(scanned.key(), filter_tag, now)
        {
            let events = self.events();
            let timer = events.is_some().then(onetdns_control::RequestTimer::start);
            let client = self.identify(ctx);
            if self.acl.check(&client) == AclDecision::Deny {
                return Wire::Fallback;
            }

            let qname = if !trivial || events.is_some() {
                match ApName::from_uncompressed_wire(scanned.qname) {
                    Some(name) => Some(name),
                    None => return Wire::Fallback,
                }
            } else {
                None
            };
            if !trivial {
                if filter.client_safe_search(&client).unwrap_or(false) {
                    return Wire::Fallback;
                }

                if let Some(name) = &qname {
                    match filter.verdict(name, ApRt(scanned.qtype), &client) {
                        FilterVerdict::Allow => {}
                        _ => return Wire::Fallback,
                    }
                }
            }

            for limiter in &self.rate_limiters {
                if limiter.check(&client) == RateDecision::Throttle {
                    return Wire::Fallback;
                }
            }
            entry.emit_at_age(&scanned, elapsed_secs, out);
            if let Some(recorder) = events {
                let (log, stat) = filter.client_log_stat(&client);
                recorder.record_cache(true);
                self.rec_rc_diag_with(
                    recorder,
                    &client,
                    Action::Resolved,
                    qname.as_ref(),
                    Some(ApRt(scanned.qtype)),
                    ResponseCode::NoError,
                    entry.answers_summary(),
                    "cache",
                    "",
                    log,
                    stat,
                    None,
                );
                if let Some(timer) = timer {
                    recorder.record_latency_for(timer.elapsed_us(), stat, qname.as_ref());
                }
            }
            return Wire::Respond;
        }

        if hit_only {
            return Wire::Fallback;
        }

        let client = self.identify(ctx);

        let storable = trivial || {
            if filter.has_client_specific_rules() {
                return Wire::Fallback;
            }
            if filter.client_safe_search(&client).unwrap_or(false) {
                return Wire::Fallback;
            }
            let Some(qname) = ApName::from_uncompressed_wire(scanned.qname) else {
                return Wire::Fallback;
            };
            matches!(
                filter.verdict(&qname, ApRt(scanned.qtype), &client),
                FilterVerdict::Allow
            )
        };
        if !storable {
            return Wire::Fallback;
        }
        let Ok(request) = Message::parse(packet) else {
            return Wire::Fallback;
        };
        let epoch = runtime.cache.epoch();
        let Some(response) = self.handle(&request, ctx) else {
            return Wire::Drop;
        };
        onetdns_runtime::encode_limited(&request, &response, out);
        if out.buf.is_empty() {
            return Wire::Fallback;
        }

        let summary = if self.events().is_some() {
            answers_summary(&response.answers)
        } else {
            String::new()
        };
        runtime.store_wire_response(epoch, scanned.key(), &out.buf, filter_tag, summary, now);
        Wire::Respond
    }

    /** @brief 만든 응답들을 실제로 내보낸다. */
    fn emit_responses(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        emit: &mut dyn FnMut(Message) -> bool,
    ) -> Option<()> {
        let is_xfr = request.header.opcode == 0
            && request.questions.len() == 1
            && request
                .questions
                .first()
                .is_some_and(|q| q.qtype == ApRt(252) || q.qtype == ApRt(251));
        if !is_xfr {
            return emit(self.handle(request, ctx)?).then_some(());
        }
        if request.questions[0].qclass != DnsClass::IN {
            return emit(edns_error_resp(
                request,
                ResponseCode::FormErr,
                self.features.load().edns_buffer,
            ))
            .then_some(());
        }

        let _timer = onetdns_control::RequestTimer::start();
        let client = self.identify(ctx);
        let features = self.features.load();
        if self.acl.check(&client) == AclDecision::Deny {
            self.rec(&client, Action::Denied, None, None);
            let edns = with_ede(
                None,
                request,
                features.edns_buffer,
                onetdns_proto::ede_code::PROHIBITED,
                "access denied by ACL",
            );
            return emit(finalize(error_resp(request, ResponseCode::Refused), edns)).then_some(());
        }
        for rl in &self.rate_limiters {
            if rl.check(&client) == RateDecision::Throttle {
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
                    features.edns_buffer,
                    onetdns_proto::ede_code::PROHIBITED,
                    "query rate limit exceeded",
                );
                return emit(finalize(error_resp(request, ResponseCode::ServFail), edns))
                    .then_some(());
            }
        }
        let qname = request.questions.first()?.name.clone();
        let dnstap = features.dnstap.as_ref();
        let proto = dnstap_proto(ctx.transport);
        self.handle_axfr(request, ctx, &qname, &client, &mut |message| {
            if let Some(dt) = dnstap {
                if let Ok(wire) = message.try_encode() {
                    dt.log_client_response(ctx.src, proto, SystemTime::now(), &wire);
                }
            }
            emit(message)
        })
    }
}
