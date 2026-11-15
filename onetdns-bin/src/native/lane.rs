//! Resolves uncached UDP queries asynchronously on per-thread reactor lanes.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use onetdns_control::Action;
use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, MutexExt};
use onetdns_proto::{Edns, Message, ResponseCode};
use onetdns_runtime::RequestCtx;

use crate::native::query::base_edns;
use crate::native::response::{
    block_resp, ede_text, error_resp, finalize, postprocess, with_ede, CloakedBlock,
};
use crate::native::{
    failure_diagnosis, recurse_failure, strip_dnssec_unless_requested, LaneRuntime, NativeFeatures,
    NativeServer, ResolveFailure, ResolveOutcome, Resolver,
};

#[cfg(unix)]
/// Cap on waiting clients per lane. Each one holds the raw packet and the parsed query, so without
/// a cap, queries piling up on a slow name would grow memory without bound. Slot leaders,
/// followers, and fallback waits all live in this map, so this one number bounds all three. Past
/// it, queries take the synchronous path.
pub(crate) const MAX_LANE_PENDING: usize = 1024;

#[cfg(unix)]
/// Cap on queued fallback jobs. When full, the reactor thread resolves the query itself; an
/// unbounded channel would let jobs pile up while the fallback worker is slow.
pub(crate) const MAX_FALLBACK_QUEUE: usize = 256;

#[cfg(unix)]
pub(crate) struct LaneState {
    /// The cache and recursion generation taken when this lane started.
    pub(crate) runtime: Arc<LaneRuntime>,
    pub(crate) reactor: onetdns_recurse::reactor::Reactor,
    pub(crate) clients: std::collections::HashMap<u64, LaneClient>,
    pub(crate) next: u64,

    fallback: LaneFallback,
}

#[cfg(unix)]
/// Finishes on the normal chain what the lane could not; otherwise that query alone would get no
/// answer.
struct LaneFallback {
    /// Bounded; submission fails when full.
    jobs: std::sync::mpsc::SyncSender<(u64, Message, ClientInfo)>,
    /// Failures keep their kind. Collapsing them to None would report permanent failures as
    /// transport failures, and the client would get the wrong reason.
    done: LaneFallbackResults,
}

#[cfg(unix)]
type LaneFallbackResults = Arc<std::sync::Mutex<Vec<(u64, Result<Message, ResolveFailure>)>>>;

#[cfg(unix)]
impl LaneFallback {
    fn new(chain: Arc<dyn Resolver>) -> Self {
        let (jobs, rx) =
            std::sync::mpsc::sync_channel::<(u64, Message, ClientInfo)>(MAX_FALLBACK_QUEUE);
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
            onetdns_core::error!(event = "reactor.fallback_worker_start_failed", %error, "Could not start the reactor fallback thread; queries a lane cannot resolve are handled directly on the receive loop");
            return Self {
                jobs,
                done: Arc::new(std::sync::Mutex::new(Vec::new())),
            };
        }
        Self { jobs, done }
    }

    fn take_done(&self) -> Vec<(u64, Result<Message, ResolveFailure>)> {
        let mut slot = self.done.lock_recover();
        if slot.is_empty() {
            return Vec::new();
        }
        std::mem::take(&mut slot)
    }
}

#[cfg(unix)]
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
pub(crate) struct LaneClient {
    pub(crate) src: std::net::SocketAddr,

    pub(crate) raw: Vec<u8>,
    pub(crate) request: Message,
    pub(crate) client: ClientInfo,

    pub(crate) submitted: std::time::Instant,
    /// Taken before submission; this query's answer and failure are stored under this generation
    /// only.
    pub(crate) epoch: crate::cache::CacheEpoch,
    /// Read at submission, and used again to shape the finished answer and store it as a wire
    /// entry. A set swapped in meanwhile would tag an answer chosen under the old conditions with
    /// the new generation, and it would keep going out after those conditions changed.
    pub(crate) features: Arc<NativeFeatures>,
}

#[cfg(unix)]
impl LaneState {
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
    pub(crate) static LANE: std::cell::RefCell<Option<LaneState>> = const { std::cell::RefCell::new(None) };
}

impl NativeServer {
    #[cfg(unix)]
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
    /// `failure` decides the extended DNS error sent to the client.
    fn lane_fail(
        &self,
        cl: LaneClient,
        failure: &ResolveFailure,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        let f = &cl.features;
        let qname = cl.request.questions.first().map(|q| &q.name);
        let (reason, class, ede) = failure_diagnosis(failure);
        let detail = format!(
            "The DNS query was handled but no response was produced. backend={}, query class={class}",
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
        self.rec_latency(&cl.client, qname, timer.elapsed_us());
        let mut resp = error_resp(&cl.request, ResponseCode::ServFail);
        if let Some(code) = ede {
            let edns = with_ede(None, &cl.request, f.edns_buffer, code, ede_text(code));
            resp = finalize(resp, edns);
        }
        let ctx = RequestCtx::new(cl.src, onetdns_runtime::Transport::Do53Udp);
        reactor_response_edns(f, &mut resp, &cl.request);
        let _ = postprocess(f, &mut resp, &cl.request, &ctx);
        let mut w = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&cl.request, &resp, &mut w);
        if !w.buf.is_empty() {
            out.push((cl.src, w.buf));
        }
    }

    #[cfg(unix)]
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
        let runtime = st.runtime.clone();
        let filter = self.filter.load();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        for comp in comps {
            let (token, lane_answer) = match comp {
                Completion::Answer(token, resp) => (token, Some(resp)),
                Completion::Retry(token) => (token, None),
                Completion::Fail(token, error) => {
                    let Some(cl) = st.clients.remove(&token) else {
                        continue;
                    };
                    runtime.cache.lane_remember_failure(cl.epoch, &cl.request);
                    if let (onetdns_recurse::RecurseError::NoResponse, Some(recursor), Some(q)) = (
                        &error,
                        runtime.recursor.as_ref(),
                        cl.request.questions.first(),
                    ) {
                        // As on the synchronous path, a resolution that ran out of time keeps going
                        // in the background.
                        recursor.complete_in_background(
                            q.name.clone(),
                            q.qtype,
                            cl.request.header.checking_disabled,
                        );
                    }
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
            let f = &cl.features;

            let timer = onetdns_control::RequestTimer::start_at(cl.submitted);
            let mut resp = match lane_answer {
                Some(mut resp) => {
                    onetdns_forward::clear_response_source();
                    // The lane skips the chain, so DNSSEC records are stripped here. DO is part of
                    // the cache key, so the two shapes never mix.
                    strip_dnssec_unless_requested(req, &mut resp);
                    resp
                }
                None => {
                    match st
                        .fallback
                        .jobs
                        .try_send((token, req.clone(), cl.client.clone()))
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
            reactor_response_edns(f, &mut resp, req);
            if let Err(error) = postprocess(f, &mut resp, req, &ctx) {
                onetdns_core::error!(event = "dns.response_postprocess_failed", %error,
                    "EDNS post-processing of the response failed; replacing it with SERVFAIL");
                resp = error_resp(req, ResponseCode::ServFail);
            }
            runtime.cache.store(cl.epoch, req, &resp);

            let uncloaked = (!filter.is_trivially_allow())
                .then(|| Self::cname_uncloak(&filter, &resp.answers, &cl.client))
                .flatten();
            let blocked = uncloaked.is_some();
            let q = &req.questions[0];
            match uncloaked {
                Some(CloakedBlock::Respond(br)) => {
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
                }
                Some(CloakedBlock::Drop) => {
                    self.rec_dropped(&cl.client, &q.name, q.qtype, "");
                    continue;
                }
                None => self.rec_final_answer(&cl.client, &q.name, q.qtype, &resp),
            }
            self.rec_latency(&cl.client, Some(&q.name), timer.elapsed_us());
            w.clear();
            onetdns_runtime::encode_limited(req, &resp, &mut w);
            if w.buf.is_empty() {
                continue;
            }

            if let (Some(fast_path), Some(scanned)) = (
                (!blocked && f.lanes.wire)
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
                    fast_path.store_wire_response(
                        cl.epoch,
                        scanned.key(),
                        &w.buf,
                        f.wire_tag(&filter),
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
/// With the fallback path blocked, the reactor resolves queries itself and the receive loop stalls
/// meanwhile. Called per query, so only powers of two are logged.
fn reactor_fallback_unavailable() {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "reactor.fallback_unavailable", count = count, "Reactor fallback path is closed; resolved a query directly on the receive loop, delaying other queries meanwhile");
    }
}

/// Replaces the OPT in reactor-path responses with this server's. finalize does this on the
/// synchronous path; this path skips it, and recursion would otherwise pass on the upstream
/// authority's OPT, with a buffer size this server never advertised and someone else's DO bit. RFC
/// 6891 allows OPT in a response only when the request had one, and RFC 3225 copies DO from the
/// query; base_edns follows both.
#[cfg(unix)]
pub(crate) fn reactor_response_edns(f: &NativeFeatures, msg: &mut Message, request: &Message) {
    // Extended errors this server added stay. Recursion carries the reason for a bogus verdict in
    // this option, and the synchronous path sends the same reason; dropping it here would make the
    // two paths answer differently.
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
mod tests {
    use super::*;
    use onetdns_proto::{Edns, Message, Name as ApName, RecordType as ApRt};

    use crate::native::NativeFeatures;

    #[test]
    #[cfg(unix)]
    fn the_reactor_path_never_forwards_an_upstream_opt() {
        let features = NativeFeatures {
            edns_buffer: 1232,
            ..NativeFeatures::default()
        };
        // The upstream's own values: not this server's 1232, and DO set.
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
