/*!
 * @brief 캐시에 없는 UDP 질의를 스레드별 reactor lane에서 비동기로 처리한다.
 */

use std::sync::atomic::Ordering;
use std::sync::Arc;

use onetdns_control::Action;
use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, MutexExt};
use onetdns_proto::{Edns, Message, ResponseCode};
use onetdns_runtime::RequestCtx;

use crate::native::query::base_edns;
use crate::native::response::{block_resp, ede_text, error_resp, finalize, postprocess, with_ede};
use crate::native::{
    failure_diagnosis, recurse_failure, strip_dnssec_unless_requested, LaneRuntime, NativeFeatures,
    NativeServer, ResolveFailure, ResolveOutcome, Resolver,
};

#[cfg(unix)]
/** @brief 이 스레드의 레인 상태. */
pub(crate) struct LaneState {
    /** @brief 이 상태 기계가 시작할 때 잡은 캐시·재귀 리졸버 세대. */
    pub(crate) runtime: Arc<LaneRuntime>,
    /** @brief 재귀를 돌리는 상태 기계. */
    pub(crate) reactor: onetdns_recurse::reactor::Reactor,
    /** @brief 답을 기다리는 클라이언트들. */
    pub(crate) clients: std::collections::HashMap<u64, LaneClient>,
    /** @brief 다음에 줄 질의 번호. */
    pub(crate) next: u64,

    /** @brief 레인이 끝내지 못한 것을 마저 푸는 곳. */
    fallback: LaneFallback,
}

#[cfg(unix)]
/** @brief 레인이 끝내지 못한 것을 보통 체인으로 마저 푸는 곳. 안 그러면 그 질의만 답을 못 받는다. */
struct LaneFallback {
    /** @brief 마저 풀 일을 맡기는 곳. */
    jobs: std::sync::mpsc::Sender<(u64, Message, ClientInfo)>,
    /**
     * @brief 마저 푼 결과들.
     * @details 실패도 종류를 담아 돌려준다. 없음으로 접으면 영구 실패까지 전송 실패로 보여
     *          클라이언트가 잘못된 사유를 받는다.
     */
    done: LaneFallbackResults,
}

#[cfg(unix)]
/** @brief 대체 처리가 끝낸 질의 번호와 그 결과. */
type LaneFallbackResults = Arc<std::sync::Mutex<Vec<(u64, Result<Message, ResolveFailure>)>>>;

#[cfg(unix)]
impl LaneFallback {
    /** @brief 체인을 잡고 워커를 시작한다. */
    fn new(chain: Arc<dyn Resolver>) -> Self {
        let (jobs, rx) = std::sync::mpsc::channel::<(u64, Message, ClientInfo)>();
        let done: LaneFallbackResults = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = done.clone();

        if let Err(error) = std::thread::Builder::new()
            .name("onetdns-lane-fallback".into())
            .spawn(move || {
                while let Ok((token, request, client)) = rx.recv() {
                    let answer = onetdns_core::isolation::catch_request(|| {
                        chain_resolve(&chain, &request, &client)
                    })
                    .unwrap_or(Err(ResolveFailure::Permanent(None)));
                    sink.lock_recover().push((token, answer));
                }
            })
        {
            onetdns_core::error!(event = "reactor.fallback_worker_start_failed", %error, "리액터의 대체 처리 스레드를 시작하지 못했습니다. 레인이 풀지 못한 질의는 수신 루프에서 바로 처리됩니다");
            return Self {
                jobs,
                done: Arc::new(std::sync::Mutex::new(Vec::new())),
            };
        }
        Self { jobs, done }
    }

    /** @brief 마저 푼 것들을 가져간다. */
    fn take_done(&self) -> Vec<(u64, Result<Message, ResolveFailure>)> {
        let mut slot = self.done.lock_recover();
        if slot.is_empty() {
            return Vec::new();
        }
        std::mem::take(&mut slot)
    }
}

#[cfg(unix)]
/** @brief 체인으로 해석한다. */
fn chain_resolve(
    chain: &Arc<dyn Resolver>,
    request: &Message,
    _client: &ClientInfo,
) -> Result<Message, ResolveFailure> {
    match chain.resolve_outcome(request) {
        ResolveOutcome::Response(response) => Ok(response),
        ResolveOutcome::Failure(failure) => Err(failure),
    }
}

#[cfg(unix)]
/** @brief 레인에 맡긴 질의 하나와 그것을 보낸 클라이언트. */
pub(crate) struct LaneClient {
    /** @brief 이 질의를 보낸 곳. */
    pub(crate) src: std::net::SocketAddr,

    /** @brief 받은 그대로의 바이트. */
    pub(crate) raw: Vec<u8>,
    /** @brief 읽어 낸 질의. */
    pub(crate) request: Message,
    /** @brief 알아본 클라이언트. */
    pub(crate) client: ClientInfo,

    /** @brief 레인에 맡긴 시각. */
    pub(crate) submitted: std::time::Instant,
}

#[cfg(unix)]
impl LaneState {
    /** @brief 이 스레드의 레인을 연다. 마저 풀 곳도 함께 만든다. */
    pub(crate) fn new(chain: Arc<dyn Resolver>, runtime: Arc<LaneRuntime>) -> Self {
        Self {
            runtime,
            reactor: onetdns_recurse::reactor::Reactor::new(
                onetdns_recurse::reactor::ReactorConfig::default(),
            ),
            clients: std::collections::HashMap::new(),
            next: 0,
            fallback: LaneFallback::new(chain),
        }
    }
}

#[cfg(unix)]
thread_local! {
    /** @brief 이 스레드의 레인. 스레드마다 따로 둔다. */
    pub(crate) static LANE: std::cell::RefCell<Option<LaneState>> = const { std::cell::RefCell::new(None) };
}

impl NativeServer {
    #[cfg(unix)]
    /** @brief 마저 푼 것들을 거둬 내보낸다. */
    pub(crate) fn lane_drain_fallback(
        &self,
        st: &mut LaneState,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        use onetdns_recurse::reactor::Completion;
        let finished = st.fallback.take_done();
        if finished.is_empty() {
            return;
        }
        let mut comps = Vec::with_capacity(finished.len());
        let mut failures = Vec::new();
        for (token, answer) in finished {
            match answer {
                Ok(response) => comps.push(Completion::Answer(token, response)),
                Err(failure) => failures.push((token, failure)),
            }
        }
        self.lane_finish(st, comps, out);
        for (token, failure) in failures {
            if let Some(cl) = st.clients.remove(&token) {
                self.lane_fail(cl, &failure, out);
            }
        }
    }

    #[cfg(unix)]
    /**
     * @brief 레인이나 대체 처리가 풀지 못한 질의에 실패 응답을 보낸다.
     * @param failure 실패 종류. 클라이언트에 붙일 확장 오류 코드가 여기서 정해진다.
     */
    fn lane_fail(
        &self,
        cl: LaneClient,
        failure: &ResolveFailure,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let f = self.features.load();
        let qname = cl.request.questions.first().map(|q| &q.name);
        let (reason, class, ede) = failure_diagnosis(failure);
        let detail = format!(
            "DNS 질의를 처리했지만 응답을 만들지 못했습니다. 처리 방식={}, 질의 클래스={class}",
            self.resolver_mode(&cl.client)
        );
        let timer = onetdns_control::RequestTimer::start_at(cl.submitted);
        self.rec_failure(
            &cl.client,
            qname,
            cl.request.questions.first().map(|q| q.qtype),
            reason,
            "resolver",
            &detail,
        );
        self.rec_latency(&f, &cl.client, qname, timer.elapsed_us());
        let mut resp = error_resp(&cl.request, ResponseCode::ServFail);
        if let Some(code) = ede {
            let edns = with_ede(None, &cl.request, f.edns_buffer, code, ede_text(code));
            resp = finalize(resp, edns);
        }
        let ctx = RequestCtx::new(cl.src, onetdns_runtime::Transport::Do53Udp);
        reactor_response_edns(&f, &mut resp, &cl.request);
        let _ = postprocess(&f, &mut resp, &cl.request, &ctx);
        let mut w = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&cl.request, &resp, &mut w);
        if !w.buf.is_empty() {
            out.push((cl.src, w.buf));
        }
    }

    #[cfg(unix)]
    /** @brief 레인이 끝낸 질의의 응답을 마무리한다. */
    pub(crate) fn lane_finish(
        &self,
        st: &mut LaneState,
        comps: Vec<onetdns_recurse::reactor::Completion>,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        use onetdns_recurse::reactor::Completion;
        if comps.is_empty() {
            return;
        }
        let f = self.features.load();
        let runtime = st.runtime.clone();
        let filter = self.filter.load();
        let filter_tag = (Arc::as_ptr(&filter) as usize).rotate_left(17)
            ^ self.wire_epoch.load(Ordering::Acquire);
        let mut w = onetdns_proto::Writer::with_limit(1232);
        for comp in comps {
            let (token, lane_answer) = match comp {
                Completion::Answer(token, resp) => (token, Some(resp)),
                Completion::Retry(token) => (token, None),
                Completion::Fail(token, error) => {
                    let Some(cl) = st.clients.remove(&token) else {
                        continue;
                    };
                    runtime.cache.lane_remember_failure(&cl.request);
                    let failure = match cl.request.questions.first() {
                        Some(question) => recurse_failure(error, &question.name),
                        None => ResolveFailure::Permanent(None),
                    };
                    self.lane_fail(cl, &failure, out);
                    continue;
                }
            };
            let Some(cl) = st.clients.remove(&token) else {
                continue;
            };
            let req = &cl.request;

            let timer = onetdns_control::RequestTimer::start_at(cl.submitted);
            let mut resp = match lane_answer {
                Some(mut resp) => {
                    onetdns_forward::clear_response_source();
                    // 레인은 체인을 거치지 않으므로 여기서 걷어낸다. 캐시
                    // 키에 DO가 들어 있어 두 모양이 섞이지는 않는다.
                    strip_dnssec_unless_requested(req, &mut resp);
                    resp
                }
                None => {
                    match st
                        .fallback
                        .jobs
                        .send((token, req.clone(), cl.client.clone()))
                    {
                        Ok(()) => {
                            st.clients.insert(token, cl);
                            continue;
                        }

                        Err(_) => {
                            reactor_fallback_unavailable();
                            onetdns_forward::clear_response_source();
                            match self.resolve_for(req, &cl.client) {
                                ResolveOutcome::Response(response) => response,
                                ResolveOutcome::Failure(failure) => {
                                    self.lane_fail(cl, &failure, out);
                                    continue;
                                }
                            }
                        }
                    }
                }
            };
            resp.header.id = req.header.id;
            resp.header.response = true;
            resp.header.opcode = req.header.opcode;
            resp.header.recursion_desired = req.header.recursion_desired;
            resp.header.recursion_available = true;
            resp.header.checking_disabled = req.header.checking_disabled;
            resp.questions = req.questions.clone();
            let ctx = RequestCtx::new(cl.src, onetdns_runtime::Transport::Do53Udp);
            reactor_response_edns(&f, &mut resp, req);
            if let Err(error) = postprocess(&f, &mut resp, req, &ctx) {
                onetdns_core::error!(event = "dns.response_postprocess_failed", %error,
                    "응답의 EDNS 후처리에 실패해 SERVFAIL로 교체합니다");
                resp = error_resp(req, ResponseCode::ServFail);
            }
            runtime.cache.store(req, &resp);

            let uncloaked = (!filter.is_trivially_allow())
                .then(|| Self::cname_uncloak(&filter, &resp.answers, &cl.client))
                .flatten();
            let blocked = uncloaked.is_some();
            if let Some(br) = uncloaked {
                let q = &req.questions[0];
                resp = block_resp(
                    req,
                    &q.name,
                    q.qtype,
                    br,
                    self.block_ttl.load(Ordering::Acquire),
                );
                self.rec_rc(
                    &cl.client,
                    Action::Blocked,
                    Some(&q.name),
                    Some(q.qtype),
                    ResponseCode(resp.header.rcode),
                );
            } else {
                self.rec_final_answer(
                    &f,
                    &cl.client,
                    &req.questions[0].name,
                    req.questions[0].qtype,
                    &resp,
                );
            }
            self.rec_latency(
                &f,
                &cl.client,
                Some(&req.questions[0].name),
                timer.elapsed_us(),
            );
            w.clear();
            onetdns_runtime::encode_limited(req, &resp, &mut w);
            if w.buf.is_empty() {
                continue;
            }

            if let (Some(fast_path), Some(scanned)) = (
                (!blocked && self.lane_switch.wire())
                    .then_some(runtime.as_ref())
                    .filter(|runtime| runtime.factory.is_some()),
                crate::wirecache::scan_query(&cl.raw),
            ) {
                let storable = filter.is_trivially_allow()
                    || (!filter.has_client_specific_rules()
                        && !filter.client_safe_search(&cl.client).unwrap_or(false)
                        && matches!(
                            filter.verdict(
                                &req.questions[0].name,
                                req.questions[0].qtype,
                                &cl.client
                            ),
                            FilterVerdict::Allow
                        ));
                if storable {
                    self.store_wire_response(
                        fast_path,
                        scanned.key(),
                        &w.buf,
                        filter_tag,
                        String::new(),
                        std::time::Instant::now(),
                    );
                }
            }
            out.push((cl.src, w.buf.clone()));
        }
    }
}

#[cfg(unix)]
/**
 * @brief 리액터의 대체 처리 경로가 막혔음을 알린다.
 * @details 이 경로가 막히면 리액터가 풀지 못한 질의를 그 자리에서 동기로 풀어, 수신
 *          루프가 그동안 멈춘다. 질의마다 호출되는 경로라 2의 거듭제곱 번째만 남긴다.
 */
fn reactor_fallback_unavailable() {
    /** @brief 누적 횟수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "reactor.fallback_unavailable", count = count, "리액터의 대체 처리 경로가 닫혀 질의를 수신 루프에서 바로 풀었습니다. 그동안 다른 질의가 밀립니다");
    }
}

/**
 * @brief 리액터 경로 응답의 OPT를 이 서버의 값으로 바꾼다.
 *
 * @details 동기 경로에서는 finalize가 하는 일이다. 이 경로는 그것을 거치지 않아, 두지 않으면
 *          재귀가 업스트림 권한 서버에서 담아 온 OPT가 그대로 나간다. 이 서버가 광고한 적 없는
 *          버퍼 크기와 남의 DO 비트다. RFC 6891은 요청에 OPT가 있을 때만 응답에 넣게
 *          하고, RFC 3225는 DO를 질의에서 복사하게 한다. base_edns가 그 둘을 지킨다.
 * @note 리액터 경로가 unix 에만 있으므로 이 함수도 그렇다. 붙이지 않으면 다른 platform 에서
 *       호출하는 곳이 없어 죽은 코드가 된다.
 */
#[cfg(unix)]
pub(crate) fn reactor_response_edns(f: &NativeFeatures, msg: &mut Message, request: &Message) {
    // 이 서버가 붙인 확장 오류는 살린다. 재귀는 bogus 판정의 사유를 이 옵션으로 담아 오고,
    // 동기 경로도 같은 사유를 담아 내보내므로 여기서 지우면 두 경로의 답이 갈린다.
    let carried: Vec<(u16, Vec<u8>)> = msg
        .opt()
        .and_then(Edns::from_record)
        .map(|edns| {
            edns.options
                .into_iter()
                .filter(|(code, _)| *code == onetdns_proto::EDE_OPTION)
                .collect()
        })
        .unwrap_or_default();
    msg.additionals
        .retain(|r| r.rtype != onetdns_proto::RecordType::OPT);
    if request.opt().is_none() {
        return;
    }
    let mut edns = base_edns(request, f.edns_buffer);
    edns.options = carried;
    if let Ok(record) = edns.try_to_record() {
        msg.additionals.push(record);
    }
}

#[cfg(test)]
/** @brief reactor lane의 실패 처리와 응답. */
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Message, Name as ApName, RecordType as ApRt};

    use crate::native::NativeFeatures;

    #[test]
    /**
     * @brief 리액터 경로가 업스트림의 OPT를 그대로 흘리지 않는지.
     * @details 재귀는 업스트림 권한 서버의 OPT를 응답에 담아 온다. 이 경로는 finalize를 거치지
     *          않으므로 여기서 걷지 않으면 이 서버가 광고한 적 없는 버퍼 크기와 남의 DO 비트가
     *          나간다. RFC 6891은 요청에 OPT가 있을 때만 응답에 넣게 하고, RFC 3225는
     *          DO를 질의에서 복사하게 한다.
     */
    #[cfg(unix)]
    fn the_reactor_path_never_forwards_an_upstream_opt() {
        let features = NativeFeatures {
            edns_buffer: 1232,
            ..NativeFeatures::default()
        };
        // 업스트림이 자기 값으로 광고한 OPT. 이 서버의 값(1232)과 다르고 DO도 서 있다.
        let upstream_opt = Edns {
            udp_payload: 4096,
            dnssec_ok: true,
            ..Edns::default()
        }
        .try_to_record()
        .expect("업스트림 OPT");

        let bare = Message::query(1, ApName::from_str("a.test").unwrap(), ApRt::A);
        let mut response = Message::default();
        response.additionals.push(upstream_opt.clone());
        reactor_response_edns(&features, &mut response, &bare);
        assert!(
            response.opt().is_none(),
            "OPT 없는 질의에 업스트림 OPT를 담아 보냈습니다"
        );

        for asked_do in [false, true] {
            let mut request = Message::query(2, ApName::from_str("b.test").unwrap(), ApRt::A);
            request.additionals.push(
                Edns {
                    udp_payload: 512,
                    dnssec_ok: asked_do,
                    ..Edns::default()
                }
                .try_to_record()
                .expect("질의 OPT"),
            );
            let mut response = Message::default();
            response.additionals.push(upstream_opt.clone());
            reactor_response_edns(&features, &mut response, &request);
            let answered = response
                .opt()
                .and_then(Edns::from_record)
                .expect("OPT 있는 질의에 OPT를 주지 않았습니다");
            assert_eq!(
                answered.udp_payload, 1232,
                "업스트림이 광고한 크기가 나갔습니다"
            );
            assert_eq!(
                answered.dnssec_ok, asked_do,
                "DO를 질의에서 복사하지 않았습니다"
            );
            assert_eq!(answered.version, 0);
        }
    }
}
