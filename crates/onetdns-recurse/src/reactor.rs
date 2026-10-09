/*!
 * @brief 이벤트 구동 재귀 해석 레인.
 *
 * @details 동기 경로는 해석 하나가 스레드를 끝까지 붙잡는다. 이 레인은 여러 해석을 한
 *          스레드에서 겹쳐 돌린다. 판정 논리는 동기 경로의 것을 그대로 빌려 쓰므로,
 *          어느 경로로 가든 같은 답이 나온다.
 * @warning 결함은 판정이 아니라 수명에서 나온다. 슬롯, 데드라인, 예산이 부모와 자식 사이에서
 *          제대로 이어지지 않으면 해석이 새거나 서로를 굶긴다.
 */

use crate::{
    make_query, questions_case_exact, response_usable_for_iteration, IterationContext,
    IterationState, NextQuery, PendingReferral, Recursor, StepOutcome,
};
use onetdns_proto::{Message, Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/** @brief 제출한 해석을 식별하는 값. 호출자가 정하고 완료 통지에 그대로 실려 온다. */
pub type Token = u64;

/** @brief 해석 하나가 끝난 결과. */
pub enum Completion {
    /** @brief 응답을 얻었다. */
    Answer(Token, Message),

    /** @brief 해석이 실패했다. */
    Fail(Token, crate::RecurseError),

    /** @brief 이 레인으로는 처리할 수 없다. 동기 경로로 넘기라는 뜻이다. */
    Retry(Token),
}

/** @brief 제출 결과. */
pub enum SubmitOutcome {
    /** @brief 새 해석으로 받았다. */
    Accepted,

    /** @brief 같은 질의가 이미 진행 중이라 그쪽에 붙였다. */
    Merged,

    /** @brief 슬롯이 없어 받지 못했다. */
    Rejected,

    /** @brief 시작조차 하지 못했다. */
    Failed,
}

/** @brief 레인 설정. */
pub struct ReactorConfig {
    /** @brief 동시에 받을 해석 수. */
    pub inflight_max: usize,

    /** @brief 해석 하나의 전체 데드라인. 자식 해석도 이 데드라인을 나눠 쓴다. */
    pub session_budget: Duration,

    /** @brief 같은 질의를 하나로 합칠지. 같은 이름이 몰릴 때 업스트림 부하를 크게 줄인다. */
    pub singleflight: bool,
}

impl Default for ReactorConfig {
    /** @brief 기본 설정. */
    fn default() -> Self {
        Self {
            inflight_max: 32,
            session_budget: Duration::from_secs(5),
            singleflight: true,
        }
    }
}

/** @brief 지금 답을 기다리는 왕복 하나. */
struct Attempt {
    /** @brief 보낸 질의. 응답 대조에 쓰므로 그대로 가지고 있어야 한다. */
    sent: Message,
    /** @brief 물어본 서버. */
    target: SocketAddr,
    /** @brief 이 왕복의 데드라인. */
    deadline: Instant,
    /** @brief 보낸 시각. 왕복 시간 측정에 쓴다. */
    sent_at: Instant,
}

/** @brief 해석 하나의 진행 상태. 동기 경로의 지역 변수에 해당하는 것들이다. */
struct Session {
    /** @brief 해석 중인 이름. */
    qname: Name,
    /** @brief 해석 중인 타입. */
    qtype: RecordType,
    /** @brief 위임을 따라 내려가는 중의 위치. 동기 경로와 같은 타입이다. */
    state: IterationState,
    /** @brief 다음에 보낼 질의의 모양. */
    plan: NextQuery,
    /** @brief 이번 단계에서 순서대로 물을 서버들. */
    ladder: Vec<SocketAddr>,
    /** @brief 다음에 물을 서버의 순번. */
    next_idx: usize,
    /** @brief 서버 하나에 줄 시간. */
    per_server: Duration,
    /**
     * @brief 답을 기다리는 왕복들.
     * @details 앞 서버의 답을 기다리는 채로 다음 서버에도 물으므로 여럿일 수 있다. 먼저 온
     *          쓸 만한 답을 쓰고 나머지는 버린다. 동기 경로의 query_any_reserving과 같은 규칙이다.
     */
    attempts: Vec<Attempt>,
    /** @brief 이 시각까지 답이 없으면 다음 서버에도 묻는다. */
    ask_next_at: Instant,
    /** @brief 이 해석 전용 소켓. 포트 무작위화가 여기서 나온다. */
    sock: UdpSocket,

    /** @brief 지금 소켓이 IPv6인지. 계열이 바뀌면 소켓을 다시 연다. */
    sock_v6: bool,
    /** @brief 이 해석 전체의 데드라인. */
    session_deadline: Instant,
    /** @brief 지금까지 밟은 단계 수. */
    steps: usize,
    /** @brief 밟을 수 있는 단계 수 상한. 참조가 순환해도 멈춘다. */
    step_cap: usize,
    /**
     * @brief 위임마다 DS 증거를 모을지. 검증할 때만 참이다.
     * @note 네임서버 주소를 푸는 자식 해석은 결과를 검증하지 않으므로 끈다. 켜 두면 답변 절로
     *       드러난 경계에서 DS를 물으려고 부모까지 동기 경로로 넘어간다.
     */
    collect_ds: bool,
}

thread_local! {

    /** @brief 이 스레드가 재사용하는 수신 버퍼. */
    static RECV_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 65_535]);
}

/** @brief 발신용 비차단 소켓을 연다. 대상 계열에 맞춰 바인딩한다. */
fn bind_outgoing(target: SocketAddr) -> Option<UdpSocket> {
    let sock = match onetdns_core::udp::bind(onetdns_forward::outgoing_bind(target)) {
        Ok(sock) => sock,
        Err(error) => {
            record_bind_failure(&error);
            return None;
        }
    };
    if let Err(error) = sock.set_nonblocking(true) {
        record_bind_failure(&error);
        return None;
    }
    Some(sock)
}

/**
 * @brief 발신 소켓을 열지 못했음을 알린다.
 * @details 파일 디스크립터가 바닥나면 여기부터 막힌다. 질의마다 호출되는 경로라 2의 거듭제곱
 *          번째만 남긴다.
 */
fn record_bind_failure(error: &std::io::Error) {
    /** @brief 누적 실패 수. */
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "recurse.outgoing_bind_failed", count = count, %error, "Could not open a socket for recursive queries");
    }
}

/** @brief 해석 하나가 멈춘 이유. */
enum SessionEnd {
    /** @brief 최종 응답을 얻었다. */
    Done(Message),
    /** @brief 실패했다. */
    Failed(crate::RecurseError),

    /** @brief 이 레인으로는 못 한다. 동기 경로가 이어받아야 한다. */
    NeedsSync,
    /** @brief 네임서버 주소를 먼저 풀어야 한다. */
    NeedAddrs {
        /** @brief 주소를 알아내야 할 서버 이름들. */
        missing: Vec<Name>,
        /** @brief 그 주소를 기다리는 위임. */
        pending: Box<PendingReferral>,
    },
}

/** @brief 정리 단계에서 확정된 결과. */
enum Settled {
    /** @brief 답을 얻었다. */
    Answer(Message),
    /** @brief 실패했다. */
    Failed(crate::RecurseError),
    /** @brief 레인에서는 끝내지 못한다. 보통 체인이 마저 풀어야 한다. */
    NeedsSync,
}

/** @brief 해석 내내 바뀌지 않는 질의 정보를 만든다. */
fn make_ctx(qname: &Name, qtype: RecordType, collect_ds: bool) -> IterationContext<'_> {
    IterationContext {
        qname,
        qtype,
        total: qname.num_labels(),
        do_bit: true,
        collect_ds,
    }
}

impl Session {
    /** @brief 캐시된 위임에서, 없으면 루트에서 해석을 시작한다. */
    fn start(
        r: &Recursor,
        qname: Name,
        qtype: RecordType,
        budget: Duration,
        now: Instant,
    ) -> Option<Self> {
        let (zone, servers) = r
            .deepest_cached_delegation(&qname)
            .filter(|(zone, _)| r.validated_start_ok(zone))
            .unwrap_or_else(|| (Name::root(), r.roots.clone()));
        Self::start_at(r, qname, qtype, zone, servers, budget, now)
    }

    /** @brief 지정한 zone과 서버로 해석을 시작한다. */
    fn start_at(
        r: &Recursor,
        qname: Name,
        qtype: RecordType,
        zone: Name,
        servers: Vec<SocketAddr>,
        budget: Duration,
        now: Instant,
    ) -> Option<Self> {
        let state = IterationState::start(zone, servers);
        let step_cap = r.max_referrals + qname.num_labels() + 2;

        let sock = bind_outgoing((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
        let mut s = Self {
            qname,
            qtype,
            state,
            plan: NextQuery {
                target: 0,
                is_final: false,
                mname: Name::root(),
                mtype: qtype,
            },
            ladder: Vec::new(),
            next_idx: 0,
            per_server: Duration::ZERO,
            attempts: Vec::new(),
            ask_next_at: now,
            sock,
            sock_v6: false,
            session_deadline: now + budget,
            steps: 0,
            step_cap,
            collect_ds: r.is_validating(),
        };
        if s.send_next(r, now).is_err() {
            return None;
        }
        Some(s)
    }

    /** @brief 다음 질의를 만들어 보낸다. 보낼 서버가 없으면 실패다. */
    fn send_next(&mut self, r: &Recursor, now: Instant) -> Result<(), crate::RecurseError> {
        self.steps += 1;
        if self.steps > self.step_cap {
            return Err(crate::RecurseError::NoReachableNs);
        }
        let ctx = make_ctx(&self.qname, self.qtype, self.collect_ds);
        self.plan = self.state.next_query(&ctx);
        let ladder = r.ask_order(&self.state.servers, &self.state.zone)?;
        /*
         * 주소를 풀지 않은 이름 몫의 시간도 남긴다. 동기 경로의 query_any_reserving과 같은
         * 규칙이다.
         */
        let candidates = ladder.len() + self.state.unresolved_ns.len();
        self.per_server =
            (r.timeout / candidates.clamp(1, 4) as u32).max(Duration::from_millis(300));
        self.ladder = ladder;
        self.next_idx = 0;
        self.attempts.clear();
        self.fire_next(r, now)
            .map_err(|()| crate::RecurseError::NoReachableNs)
    }

    /**
     * @brief 사다리의 다음 서버에 실제로 보낸다.
     * @details 보내지 못한 서버는 실패로 기록하고 그다음 서버로 넘어간다. 기다리는 왕복이
     *          남아 있으면 보낼 서버가 더 없어도 실패가 아니다.
     * @note 0x20이 켜져 있으면 여기서 대소문자를 섞는다. 응답 대조에 쓰이므로 보낸 형태를
     *       그대로 기억해 둔다.
     */
    fn fire_next(&mut self, r: &Recursor, now: Instant) -> Result<(), ()> {
        while let Some(&target) = self.ladder.get(self.next_idx) {
            if !self.attempts.is_empty() && self.sock_v6 != target.is_ipv6() {
                /* 소켓을 바꾸면 기다리던 왕복의 답을 받을 수 없다. 그 왕복이 끝나면 보낸다. */
                self.ask_next_at = self
                    .attempts
                    .iter()
                    .map(|attempt| attempt.deadline)
                    .max()
                    .unwrap_or(now);
                return Ok(());
            }
            self.next_idx += 1;
            let ctx = make_ctx(&self.qname, self.qtype, self.collect_ds);
            let mut q = make_query(&self.plan.mname, self.plan.mtype, ctx.do_bit);
            q.header.id = u16::from_le_bytes(onetdns_core::rng::ephemeral_random_array::<2>());
            r.apply_outgoing_case(&mut q);
            let wire = q.try_encode().map_err(|_| ())?;
            if !self.use_socket_for(target) || self.sock.send_to(&wire, target).is_err() {
                r.infra_fail(target.ip(), &self.state.zone);
                continue;
            }
            self.attempts.push(Attempt {
                sent: q,
                target,
                deadline: (now + self.per_server).min(self.session_deadline),
                sent_at: now,
            });
            self.ask_next_at = now + r.server_patience(target.ip()).min(self.per_server);
            return Ok(());
        }
        if self.attempts.is_empty() {
            Err(())
        } else {
            Ok(())
        }
    }

    /** @brief 대상 계열에 맞는 소켓을 준비한다. 계열이 바뀌면 새로 연다. */
    fn use_socket_for(&mut self, target: SocketAddr) -> bool {
        if self.sock_v6 == target.is_ipv6() {
            return true;
        }
        match bind_outgoing(target) {
            Some(sock) => {
                self.sock = sock;
                self.sock_v6 = target.is_ipv6();
                true
            }
            None => false,
        }
    }

    /**
     * @brief 시간이 된 일을 처리한다.
     * @details 데드라인을 넘긴 왕복은 실패로 기록해 버린다. 기다리는 왕복이 없거나 다음 서버에
     *          물을 시각이 되었으면 다음 서버에 보낸다.
     * @return 더 물을 서버도 기다리는 왕복도 없으면 Err.
     */
    fn on_timers(&mut self, r: &Recursor, now: Instant) -> Result<(), ()> {
        let zone = &self.state.zone;
        self.attempts.retain(|attempt| {
            let live = now < attempt.deadline;
            if !live {
                r.infra_fail(attempt.target.ip(), zone);
            }
            live
        });
        if self.attempts.is_empty()
            || (now >= self.ask_next_at && self.attempts.len() < crate::MAX_EXCHANGES_PER_QUERY)
        {
            if self.next_idx >= self.ladder.len() && self.attempts.is_empty() {
                return Err(());
            }
            if self.next_idx < self.ladder.len() {
                return self.fire_next(r, now);
            }
        }
        Ok(())
    }

    /** @brief 다음에 깨어나야 할 시각. 기다리는 왕복의 데드라인과 다음 서버에 물을 시각이다. */
    fn next_wake(&self) -> Option<Instant> {
        let deadline = self.attempts.iter().map(|attempt| attempt.deadline).min();
        let ask_next = (self.next_idx < self.ladder.len()
            && self.attempts.len() < crate::MAX_EXCHANGES_PER_QUERY)
            .then_some(self.ask_next_at);
        deadline.into_iter().chain(ask_next).min()
    }

    /**
     * @brief 소켓에서 응답을 읽어 기다리는 왕복 가운데 하나에 대한 것인지 확인한다.
     * @return 받아들인 응답과, 그 응답이 답한 왕복.
     * @warning 트랜잭션 ID와 질문, 0x20 대소문자까지 맞아야 받아들인다. 이 검사가 위조
     *          응답을 막는 실체다.
     */
    fn try_recv(&mut self, r: &Recursor) -> Option<(Message, Attempt)> {
        if self.attempts.is_empty() {
            return None;
        }
        let matched = RECV_BUFFER.with(|slot| {
            let mut buf = slot.borrow_mut();
            loop {
                match self.sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let Some(resp) = Message::parse_udp_reply(&buf[..n]) else {
                            continue;
                        };
                        let Some(idx) = self.attempts.iter().position(|attempt| {
                            attempt.target == from && attempt.sent.header.id == resp.header.id
                        }) else {
                            continue;
                        };
                        let sent = &self.attempts[idx].sent;
                        if r.caps_for_id && !questions_case_exact(&resp.questions, &sent.questions)
                        {
                            continue;
                        }
                        /*
                         * 잘린 응답은 레코드가 비어 있어 아래 검사를 통과하지 못한다. 거기서
                         * 버리면 TCP 로 넘어가지 못하고 왕복 시간 초과까지 기다린다.
                         */
                        if resp.header.truncated {
                            return Some((resp, idx));
                        }
                        if !response_usable_for_iteration(&resp, sent, &self.state.zone) {
                            continue;
                        }
                        return Some((resp, idx));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => return None,
                    Err(_) => return None,
                }
            }
        });
        matched.map(|(resp, idx)| (resp, self.attempts.swap_remove(idx)))
    }

    /** @brief 받은 응답으로 한 단계 나아간다. 판정은 동기 경로의 advance를 그대로 쓴다. */
    fn on_response(
        &mut self,
        r: &Recursor,
        resp: Message,
        answered: Attempt,
        now: Instant,
    ) -> Option<SessionEnd> {
        r.infra_success(
            answered.target.ip(),
            &self.state.zone,
            answered.sent_at.elapsed(),
        );
        for attempt in self.attempts.drain(..) {
            r.record_rtt_at_least(attempt.target.ip(), attempt.sent_at.elapsed());
        }

        if resp.header.truncated {
            return Some(SessionEnd::NeedsSync);
        }
        let ctx = make_ctx(&self.qname, self.qtype, self.collect_ds);
        match r.advance(&mut self.state, resp, &self.plan, &ctx) {
            StepOutcome::Done(final_msg) => Some(SessionEnd::Done(final_msg)),
            StepOutcome::Continue => match self.send_next(r, now) {
                Ok(()) => None,
                Err(error) => Some(SessionEnd::Failed(error)),
            },
            StepOutcome::NeedNsAddrs { missing, pending } => {
                Some(SessionEnd::NeedAddrs { missing, pending })
            }
            /* DS를 따로 묻는 질의는 이 레인에 없다. 드문 경계라 동기 경로에 맡긴다. */
            StepOutcome::NeedDs { .. } => Some(SessionEnd::NeedsSync),
            StepOutcome::Failed(error) => Some(SessionEnd::Failed(error)),
        }
    }

    /** @brief 따로 풀어 온 네임서버 주소로 멈췄던 참조를 이어 간다. */
    fn resume_with_addrs(
        &mut self,
        r: &Recursor,
        mut pending: PendingReferral,
        addrs: Vec<SocketAddr>,
        addr_ttl: Option<u32>,
        now: Instant,
    ) -> Option<SessionEnd> {
        pending.addrs.extend(addrs);

        pending.address_ttl = crate::min_optional_ttl(pending.address_ttl, addr_ttl);
        let ctx = make_ctx(&self.qname, self.qtype, self.collect_ds);
        match r.finish_referral(&mut self.state, &ctx, pending) {
            StepOutcome::Done(final_msg) => Some(SessionEnd::Done(final_msg)),
            StepOutcome::Continue => match self.send_next(r, now) {
                Ok(()) => None,
                Err(error) => Some(SessionEnd::Failed(error)),
            },
            StepOutcome::NeedNsAddrs { .. } | StepOutcome::NeedDs { .. } => {
                Some(SessionEnd::Failed(crate::RecurseError::NoReachableNs))
            }
            StepOutcome::Failed(error) => Some(SessionEnd::Failed(error)),
        }
    }
}

/** @brief 최상위 해석 하나의 문맥. 합쳐진 요청과 별칭 진행 상황을 담는다. */
struct RootCtx {
    /** @brief 이 해석을 처음 요청한 쪽. */
    leader: Token,
    /** @brief 같은 질의라 여기 합쳐진 요청들. 끝나면 전부에게 같은 답을 준다. */
    followers: Vec<Token>,

    /** @brief 합치기 인덱스의 키. 끝날 때 반드시 지워야 다음 요청이 고아 항목에 붙지 않는다. */
    sf_key: (Vec<u8>, RecordType),

    /** @brief 별칭을 따라오며 모은 답변들. */
    acc_answers: Vec<Record>,
    /** @brief 따라온 CNAME 수. 체인 전체에 걸쳐 센다. */
    cname_hops: usize,
    /** @brief 따라온 DNAME 수. */
    dname_hops: usize,

    /** @brief 지금까지의 DNSSEC 상태. 체인 어느 한 곳만 깨져도 전체가 깨진다. */
    acc_status: crate::SecurityStatus,
}

/** @brief 이 슬롯이 무엇을 하고 있는지. */
enum SlotKind {
    /** @brief 클라이언트 요청 자체를 해석 중이다. */
    Root(RootCtx),

    /** @brief 부모를 위해 네임서버 주소를 푸는 중이다. */
    NsAddr { parent: usize },

    /** @brief 부모의 검증을 위해 DNSKEY를 받아 오는 중이다. */
    Dnskey { parent: usize, zone: Name },
}

/** @brief 검증에 필요한 키를 기다리며 멈춰 둔 응답. */
struct AwaitingKeys {
    /** @brief 검증을 기다리는 응답. */
    msg: Message,
    /** @brief 긍정 응답인지. 검증 방식이 갈린다. */
    positive: bool,

    /** @brief 지금까지 받아 온 DNSKEY 집합 수. 상한이 걸려 있다. */
    fetches: usize,

    /** @brief 이미 시도한 zone들. 같은 zone을 되풀이해 받지 않게 한다. */
    tried: Vec<Vec<u8>>,
}

/** @brief 네임서버 주소를 기다리며 멈춰 둔 참조. */
struct Parked {
    /** @brief 따라가던 위임. */
    pending: Box<PendingReferral>,
    /** @brief 주소를 아직 모르는 서버 이름들. */
    missing: Vec<Name>,
    /** @brief 다음에 풀 이름의 위치. 한 번에 하나씩 자식을 시작한다. */
    next_missing: usize,
    /** @brief 지금까지 알아낸 주소들. */
    addrs: Vec<SocketAddr>,

    /** @brief 그 주소들의 수명. */
    addr_ttl: Option<u32>,
    /** @brief 이 참조를 위해 시작한 자식 수. 예산에 잡힌다. */
    children_spawned: usize,
}

/** @brief 진행 중인 해석 하나가 차지하는 슬롯. */
struct Slot {
    /** @brief 그 해석의 진행 상태. */
    session: Session,
    /** @brief 이 슬롯의 역할. */
    kind: SlotKind,
    /** @brief 주소를 기다리며 멈춘 참조가 있으면. */
    parked: Option<Parked>,

    /** @brief 키를 기다리며 멈춘 응답이 있으면. */
    awaiting: Option<Box<AwaitingKeys>>,

    /** @brief 남은 부수 해석 예산. 부모에서 물려받아 자식과 나눈다. */
    ns_budget: usize,
}

/** @brief 검증 하나에 받아 올 수 있는 DNSKEY 집합 수 상한. 체인을 길게 만들어 이 서버를 붙잡는 것을 막는다. */
const MAX_KEY_FETCHES: usize = 20;

/**
 * @brief 이벤트 구동 레인 하나. 여러 해석을 겹쳐 돌린다.
 * @details 워커 스레드마다 하나씩 둔다. 안에서 잠그지 않으므로 여러 스레드가 공유하지 않는다.
 */
pub struct Reactor {
    /** @brief 이 레인의 설정. */
    cfg: ReactorConfig,
    /** @brief 슬롯 배열. 빈 슬롯은 None이다. */
    slots: Vec<Option<Slot>>,
    /** @brief 재사용할 수 있는 빈 슬롯들. */
    free: Vec<usize>,

    /** @brief 진행 중인 질의 인덱스. 같은 질의를 합치는 데 쓴다. */
    inflight: HashMap<(Vec<u8>, RecordType), usize>,

    /** @brief 합쳐진 요청 수. */
    pub merged: u64,
    /** @brief 끝낸 해석 수. */
    pub completed: u64,
    /** @brief 실패한 해석 수. */
    pub failed: u64,

    /** @brief 동기 경로로 넘긴 수. */
    pub retried: u64,
}

impl Reactor {
    /** @brief 설정으로 레인을 만든다. */
    pub fn new(cfg: ReactorConfig) -> Self {
        Self {
            cfg,
            slots: Vec::new(),
            free: Vec::new(),
            inflight: HashMap::new(),
            merged: 0,
            completed: 0,
            failed: 0,
            retried: 0,
        }
    }

    /**
     * @brief 지금 살아 있는 슬롯 수.
     * @details slots 는 줄지 않고 비워진 자리는 모두 free 에 들어오므로, 살아 있는 수는 전체
     *          길이에서 재사용 대기 수를 뺀 값이다. 매 패킷 입장마다 부르는 자리라 배열 전체를
     *          훑지 않는다.
     * @invariant free 에는 중복이 없고 그 인덱스의 슬롯은 항상 None 이다.
     */
    pub fn live(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    /** @brief 새 클라이언트 요청을 더 받을 수 있는지. */
    pub fn has_capacity(&self) -> bool {
        self.live() < self.cfg.inflight_max
    }

    /** @brief 자식까지 포함한 전체 슬롯 상한. 클라이언트 상한의 두 배다. */
    fn slot_max(&self) -> usize {
        self.cfg.inflight_max.saturating_mul(2)
    }

    /**
     * @brief 자식 해석을 더 시작할 위치가 있는지.
     * @note 클라이언트 상한과 따로 본다. 같은 상한을 쓰면 부모가 슬롯을 다 차지해 자식을
     *       시작하지 못하고, 부모는 자식을 기다리다 교착한다.
     */
    fn has_child_capacity(&self) -> bool {
        self.live() < self.slot_max()
    }

    /** @brief 자식에게 줄 남은 시간. 부모 데드라인을 넘기지 않는다. */
    fn child_budget(&self, parent: usize, now: Instant) -> Option<Duration> {
        let remaining = self.slots[parent]
            .as_ref()?
            .session
            .session_deadline
            .saturating_duration_since(now);
        (!remaining.is_zero()).then_some(remaining)
    }

    /** @brief 빈 위치에 슬롯을 넣고 그 인덱스를 준다. */
    fn insert(&mut self, slot: Slot) -> usize {
        match self.free.pop() {
            Some(i) => {
                self.slots[i] = Some(slot);
                i
            }
            None => {
                self.slots.push(Some(slot));
                self.slots.len() - 1
            }
        }
    }

    /**
     * @brief 새 해석을 제출한다.
     * @details 같은 질의가 이미 돌고 있으면 그쪽에 붙인다. 그러지 않으면 같은 이름이
     *          몰릴 때 업스트림에 같은 질의가 그만큼 나간다.
     */
    pub fn submit(
        &mut self,
        r: &Recursor,
        qname: Name,
        qtype: RecordType,
        token: Token,
        now: Instant,
        cd: bool,
    ) -> SubmitOutcome {
        if cd && !r.ignore_cd {
            return SubmitOutcome::Rejected;
        }
        /*
         * 이 레인은 UDP만 보내므로, TCP로만 물어야 하는 동안에는 동기 경로에 맡긴다.
         */
        if r.authority_over_tcp() {
            return SubmitOutcome::Rejected;
        }
        let key = (qname.canonical_key(), qtype);
        if self.cfg.singleflight {
            if let Some(&leader) = self.inflight.get(&key) {
                if let Some(slot) = self.slots[leader].as_mut() {
                    if let SlotKind::Root(root) = &mut slot.kind {
                        if root.sf_key == key {
                            root.followers.push(token);
                            self.merged += 1;
                            return SubmitOutcome::Merged;
                        }
                    }
                }
            }
        }
        if !self.has_capacity() {
            return SubmitOutcome::Rejected;
        }
        match Session::start(r, qname, qtype, self.cfg.session_budget, now) {
            Some(session) => {
                let idx = self.insert(Slot {
                    session,
                    kind: SlotKind::Root(RootCtx {
                        leader: token,
                        followers: vec![],
                        sf_key: key.clone(),
                        acc_answers: vec![],
                        cname_hops: 0,
                        dname_hops: 0,
                        acc_status: crate::SecurityStatus::Secure,
                    }),
                    parked: None,
                    awaiting: None,
                    ns_budget: r.max_ns_resolves,
                });
                if self.cfg.singleflight {
                    self.inflight.insert(key, idx);
                }
                SubmitOutcome::Accepted
            }
            None => SubmitOutcome::Failed,
        }
    }

    /**
     * @brief 합치기 인덱스에서 이 해석을 지운다.
     * @warning 인덱스의 값이 지금 이 슬롯일 때만 지운다. 확인하지 않고 지우면 이미 그 위치를
     *          물려받은 다른 해석의 항목을 없애 버린다.
     */
    fn forget_inflight(&mut self, key: &(Vec<u8>, RecordType), idx: usize) {
        if self.inflight.get(key) == Some(&idx) {
            self.inflight.remove(key);
        }
    }

    /** @brief 대기할 소켓들을 모은다. 호출자가 이것으로 한 번에 기다린다. */
    pub fn collect_pollfds(&self, fds: &mut Vec<libc::pollfd>, map: &mut Vec<usize>) {
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(slot) = s {
                if slot.parked.is_none() && slot.awaiting.is_none() {
                    fds.push(libc::pollfd {
                        fd: slot.session.sock.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    });
                    map.push(i);
                }
            }
        }
    }

    /** @brief 준비된 소켓에서 응답을 읽어 각 해석을 진행시킨다. */
    pub fn pump(
        &mut self,
        r: &Recursor,
        fds: &[libc::pollfd],
        base: usize,
        map: &[usize],
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        for (k, &slot_idx) in map.iter().enumerate() {
            if fds[base + k].revents & libc::POLLIN == 0 {
                continue;
            }
            let mut end: Option<SessionEnd> = None;
            if let Some(slot) = self.slots[slot_idx].as_mut() {
                while let Some((resp, answered)) = slot.session.try_recv(r) {
                    end = slot.session.on_response(r, resp, answered, now);
                    if end.is_some() {
                        break;
                    }
                }
            }
            if let Some(e) = end {
                self.settle(r, slot_idx, e, now, out);
            }
        }
    }

    /** @brief 시간이 지난 왕복과 데드라인을 넘긴 해석을 정리한다. */
    pub fn on_tick(&mut self, r: &Recursor, now: Instant, out: &mut Vec<Completion>) {
        for i in 0..self.slots.len() {
            let mut end: Option<SessionEnd> = None;
            if let Some(slot) = self.slots[i].as_mut() {
                if slot.parked.is_some() || slot.awaiting.is_some() {
                    continue;
                }
                if now >= slot.session.session_deadline {
                    end = Some(SessionEnd::Failed(crate::RecurseError::NoResponse));
                } else if slot.session.on_timers(r, now).is_err() {
                    end = Some(if slot.session.state.unresolved_ns.is_empty() {
                        SessionEnd::Failed(crate::RecurseError::NoResponse)
                    } else {
                        /*
                         * 이 영역의 서버가 모두 답하지 않았고 주소를 풀지 않은 이름이 남아 있다.
                         * 이 레인에는 그 이름을 이어서 푸는 경로가 없으므로 동기 경로에 맡긴다.
                         */
                        SessionEnd::NeedsSync
                    });
                }
            }
            if let Some(e) = end {
                self.settle(r, i, e, now, out);
            }
        }
    }

    /** @brief 가장 가까운 데드라인까지 남은 시간. 호출자의 대기 시간을 정한다. */
    pub fn next_deadline_in(&self, now: Instant) -> Option<Duration> {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.parked.is_none())
            .filter_map(|s| s.session.next_wake())
            .min()
            .map(|d| d.saturating_duration_since(now))
    }

    /** @brief 끝난 해석을 정리해 확정된 결과로 옮긴다. */
    fn settle(
        &mut self,
        r: &Recursor,
        idx: usize,
        end: SessionEnd,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        let Some(mut slot) = self.slots[idx].take() else {
            return;
        };
        match end {
            SessionEnd::NeedAddrs { missing, pending } => {
                if missing.is_empty() || slot.parked.is_some() {
                    self.finish(
                        r,
                        idx,
                        slot,
                        Settled::Failed(crate::RecurseError::NoReachableNs),
                        now,
                        out,
                    );
                    return;
                }
                let first = missing[0].clone();
                slot.parked = Some(Parked {
                    pending,
                    missing,
                    next_missing: 1,
                    addrs: vec![],
                    addr_ttl: None,
                    children_spawned: 1,
                });
                self.slots[idx] = Some(slot);
                self.spawn_child(r, idx, first, now, out);
            }
            SessionEnd::Done(final_msg) => {
                self.finish(r, idx, slot, Settled::Answer(final_msg), now, out)
            }
            SessionEnd::Failed(error) => {
                self.finish(r, idx, slot, Settled::Failed(error), now, out)
            }
            SessionEnd::NeedsSync => self.finish(r, idx, slot, Settled::NeedsSync, now, out),
        }
    }

    /** @brief 부수 해석을 자식 슬롯으로 시작한다. 예산과 데드라인을 부모에게서 물려받는다. */
    fn spawn_child(
        &mut self,
        r: &Recursor,
        parent: usize,
        qname: Name,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        let depth_left = self.slots[parent]
            .as_ref()
            .map(|slot| slot.ns_budget)
            .unwrap_or(0)
            .checked_sub(1)
            .filter(|_| self.has_child_capacity());
        let started = depth_left
            .zip(self.child_budget(parent, now))
            .and_then(|(_, budget)| Session::start(r, qname, RecordType::A, budget, now))
            .map(|mut session| {
                session.collect_ds = false;
                session
            });
        match started {
            Some(session) => {
                self.insert(Slot {
                    session,
                    kind: SlotKind::NsAddr { parent },
                    parked: None,
                    awaiting: None,
                    ns_budget: depth_left.unwrap_or(0),
                });
            }
            None => {
                if let Some(pslot) = self.slots[parent].take() {
                    self.finish(
                        r,
                        parent,
                        pslot,
                        Settled::Failed(crate::RecurseError::NoReachableNs),
                        now,
                        out,
                    );
                }
            }
        }
    }

    /**
     * @brief 해석 하나를 마무리한다. 역할에 따라 처리가 갈린다.
     * @details 최상위면 별칭을 더 따라갈지 보고, 자식이면 부모를 깨운다. 어느 쪽이든
     *          합치기 인덱스와 슬롯을 반드시 정리해야 슬롯이 새지 않는다.
     */
    fn finish(
        &mut self,
        r: &Recursor,
        idx: usize,
        slot: Slot,
        outcome: Settled,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        self.free.push(idx);
        match slot.kind {
            SlotKind::Root(mut root) => {
                self.forget_inflight(&root.sf_key, idx);
                match outcome {
                    Settled::Answer(final_msg) => {
                        let qname = &slot.session.qname;
                        let qtype = slot.session.qtype;
                        let chain = &slot.session.state.chain;
                        let validating = r.is_validating();
                        if let Some(mut hop) = crate::alias_hop(&final_msg, qname, qtype) {
                            let dname = hop.atype == RecordType::DNAME;
                            let (hops, limit, over) = if dname {
                                (
                                    root.dname_hops,
                                    r.max_dnames,
                                    crate::RecurseError::TooManyDnames,
                                )
                            } else {
                                (
                                    root.cname_hops,
                                    r.max_cnames,
                                    crate::RecurseError::TooManyCnames,
                                )
                            };
                            if hops < limit {
                                if validating {
                                    let Some((status, _)) = r.validate_terminal_without_fetch(
                                        &hop.owner, hop.atype, &final_msg, chain, true,
                                    ) else {
                                        self.retry_root(&root, out);
                                        return;
                                    };
                                    root.acc_status = root.acc_status.combine(status);
                                }

                                root.acc_answers.append(&mut hop.records);
                                if dname {
                                    root.dname_hops += 1;
                                } else {
                                    root.cname_hops += 1;
                                }

                                let remaining =
                                    slot.session.session_deadline.saturating_duration_since(now);
                                let ns_budget = slot.ns_budget;
                                self.restart_root(
                                    r, root, hop.target, remaining, ns_budget, now, out,
                                );
                                return;
                            }
                            self.fail_root(&root, &over, out);
                            return;
                        }
                        let positive = final_msg.header.rcode
                            == onetdns_proto::ResponseCode::NoError.0
                            && crate::has_direct_qtype_answer(&final_msg, qname, qtype);
                        let ns_budget = slot.ns_budget;
                        self.complete_terminal(
                            r,
                            slot.session,
                            root,
                            final_msg,
                            positive,
                            0,
                            Vec::new(),
                            ns_budget,
                            now,
                            out,
                        );
                    }
                    Settled::Failed(error) => self.fail_root(&root, &error, out),
                    Settled::NeedsSync => self.retry_root(&root, out),
                }
            }
            SlotKind::Dnskey { parent, zone } => {
                if let Settled::Answer(m) = outcome {
                    r.absorb_dnskey_response(&zone, &m);
                }
                self.resume_key_parent(r, parent, now, out);
            }
            SlotKind::NsAddr { parent } => {
                if matches!(outcome, Settled::NeedsSync) {
                    if let Some(pslot) = self.slots[parent].take() {
                        self.finish(r, parent, pslot, Settled::NeedsSync, now, out);
                    }
                    return;
                }
                let (addrs, addr_ttl) = match outcome {
                    Settled::Answer(m) => {
                        let mut ttl = None;
                        let addrs = m
                            .answers
                            .iter()
                            .filter_map(|rec| {
                                let ip = match &rec.rdata {
                                    RData::A(ip) => IpAddr::V4(*ip),
                                    RData::Aaaa(ip) => IpAddr::V6(*ip),
                                    _ => return None,
                                };

                                if !r.server_eligible(ip) {
                                    return None;
                                }
                                ttl = crate::min_optional_ttl(ttl, Some(rec.ttl));
                                Some(SocketAddr::new(ip, r.port))
                            })
                            .collect::<Vec<_>>();
                        (addrs, ttl)
                    }
                    _ => (vec![], None),
                };
                self.resume_parent(r, parent, addrs, addr_ttl, now, out);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /**
     * @brief 최종 응답을 다듬어 요청자들에게 돌려준다.
     * @details 검증이 필요한데 키가 없으면 여기서 멈추고 키를 받아 온다. 동기 경로처럼
     *          그 자리에서 질의할 수 없기 때문이다.
     */
    fn complete_terminal(
        &mut self,
        r: &Recursor,
        session: Session,
        mut root: RootCtx,
        mut msg: Message,
        positive: bool,
        fetches: usize,
        tried: Vec<Vec<u8>>,
        ns_budget: usize,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        msg.header.authentic_data = false;

        msg.header.authoritative = false;
        if r.is_validating() {
            let chain = &session.state.chain;
            if let Some((zone, servers)) = r.first_chain_zone_missing_dnskey(chain, &tried) {
                if fetches < MAX_KEY_FETCHES && self.has_child_capacity() {
                    let mut tried = tried;
                    tried.push(zone.canonical_key());
                    let sf_key = root.sf_key.clone();
                    let idx = self.insert(Slot {
                        session,
                        kind: SlotKind::Root(root),
                        parked: None,
                        awaiting: Some(Box::new(AwaitingKeys {
                            msg,
                            positive,
                            fetches: fetches + 1,
                            tried,
                        })),
                        ns_budget,
                    });
                    if self.cfg.singleflight {
                        self.inflight.insert(sf_key, idx);
                    }
                    self.spawn_key_child(r, idx, zone, servers, now, out);
                    return;
                }
                self.retry_root(&root, out);
                return;
            }
            let Some((status, proof)) = r.validate_terminal_without_fetch(
                &session.qname,
                session.qtype,
                &msg,
                chain,
                positive,
            ) else {
                self.retry_root(&root, out);
                return;
            };
            if !proof.is_empty() {
                msg.authorities = proof;
            }
            match root.acc_status.combine(status) {
                crate::SecurityStatus::Secure => msg.header.authentic_data = true,
                crate::SecurityStatus::Bogus(ede) if !r.permissive => {
                    msg = crate::bogus_servfail(&msg, ede)
                }
                _ => {}
            }
        }

        crate::sanitize_terminal_response(
            &mut msg,
            &session.qname,
            session.qtype,
            positive,
            session.state.chain.last().map(|step| &step.zone),
        );
        if r.is_validating() {
            r.apply_sentinel(&session.qname, session.qtype, &mut msg);
        }
        if !root.acc_answers.is_empty() {
            let mut all = std::mem::take(&mut root.acc_answers);
            all.extend(msg.answers);
            msg.answers = all;
        }
        for f in &root.followers {
            out.push(Completion::Answer(*f, msg.clone()));
            self.completed += 1;
        }
        out.push(Completion::Answer(root.leader, msg));
        self.completed += 1;
    }

    /** @brief 검증에 필요한 DNSKEY를 받아 올 자식을 시작한다. */
    fn spawn_key_child(
        &mut self,
        r: &Recursor,
        parent: usize,
        zone: Name,
        servers: Vec<SocketAddr>,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        let Some(budget) = self.child_budget(parent, now) else {
            self.resume_key_parent(r, parent, now, out);
            return;
        };
        match Session::start_at(
            r,
            zone.clone(),
            RecordType::DNSKEY,
            zone.clone(),
            servers,
            budget,
            now,
        ) {
            Some(session) => {
                let ns_budget = self.slots[parent]
                    .as_ref()
                    .map(|slot| slot.ns_budget)
                    .unwrap_or(0);
                self.insert(Slot {
                    session,
                    kind: SlotKind::Dnskey { parent, zone },
                    parked: None,
                    awaiting: None,
                    ns_budget,
                });
            }
            None => self.resume_key_parent(r, parent, now, out),
        }
    }

    /** @brief 키를 받아 온 뒤 멈춰 있던 부모의 검증을 이어 간다. */
    fn resume_key_parent(
        &mut self,
        r: &Recursor,
        parent: usize,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        let Some(mut pslot) = self.slots[parent].take() else {
            return;
        };

        let Some(awaiting) = pslot.awaiting.take() else {
            self.finish(
                r,
                parent,
                pslot,
                Settled::Failed(crate::RecurseError::NoReachableNs),
                now,
                out,
            );
            return;
        };
        let SlotKind::Root(root) = pslot.kind else {
            self.free.push(parent);
            return;
        };
        self.free.push(parent);
        self.forget_inflight(&root.sf_key, parent);
        let AwaitingKeys {
            msg,
            positive,
            fetches,
            tried,
        } = *awaiting;
        let ns_budget = pslot.ns_budget;
        self.complete_terminal(
            r,
            pslot.session,
            root,
            msg,
            positive,
            fetches,
            tried,
            ns_budget,
            now,
            out,
        );
    }

    /** @brief 이 해석을 동기 경로로 넘긴다. */
    fn retry_root(&mut self, root: &RootCtx, out: &mut Vec<Completion>) {
        for f in &root.followers {
            out.push(Completion::Retry(*f));
            self.retried += 1;
        }
        out.push(Completion::Retry(root.leader));
        self.retried += 1;
    }

    /** @brief 이 해석과 여기 합쳐진 요청 전부를 실패로 끝낸다. */
    fn fail_root(
        &mut self,
        root: &RootCtx,
        error: &crate::RecurseError,
        out: &mut Vec<Completion>,
    ) {
        for f in &root.followers {
            out.push(Completion::Fail(*f, error.clone()));
            self.failed += 1;
        }
        out.push(Completion::Fail(root.leader, error.clone()));
        self.failed += 1;
    }

    /** @brief 주소를 받아 온 뒤 멈춰 있던 부모의 참조를 이어 간다. */
    fn resume_parent(
        &mut self,
        r: &Recursor,
        parent: usize,
        addrs: Vec<SocketAddr>,
        addr_ttl: Option<u32>,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        let Some(mut pslot) = self.slots[parent].take() else {
            return;
        };
        let Some(mut parked) = pslot.parked.take() else {
            self.finish(
                r,
                parent,
                pslot,
                Settled::Failed(crate::RecurseError::NoReachableNs),
                now,
                out,
            );
            return;
        };
        parked.addrs.extend(addrs);
        parked.addr_ttl = crate::min_optional_ttl(parked.addr_ttl, addr_ttl);

        /*
         * 쓸 수 있는 주소가 생기면 남은 이름은 풀지 않고 내려간다. 그 주소들이 모두 답하지
         * 않으면 동기 경로가 남은 이름을 이어서 푼다.
         */
        let have_usable = parked.addrs.iter().any(|addr| r.usable_server(addr.ip()));
        if !have_usable && parked.next_missing < parked.missing.len() && parked.children_spawned < 8
        {
            let next = parked.missing[parked.next_missing].clone();
            parked.next_missing += 1;
            parked.children_spawned += 1;
            pslot.parked = Some(parked);
            self.slots[parent] = Some(pslot);
            self.spawn_child(r, parent, next, now, out);
            return;
        }
        let mut pending = *parked.pending;
        pending.unresolved = parked
            .missing
            .split_off(parked.next_missing.min(parked.missing.len()));
        match pslot
            .session
            .resume_with_addrs(r, pending, parked.addrs, parked.addr_ttl, now)
        {
            None => self.slots[parent] = Some(pslot),
            Some(e) => {
                self.slots[parent] = Some(pslot);
                self.settle(r, parent, e, now, out);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /** @brief 별칭을 따라 같은 슬롯에서 새 해석을 시작한다. 누적 상태는 그대로 이어 간다. */
    fn restart_root(
        &mut self,
        r: &Recursor,
        root: RootCtx,
        qname: Name,
        budget: Duration,
        ns_budget: usize,
        now: Instant,
        out: &mut Vec<Completion>,
    ) {
        if budget.is_zero() {
            self.fail_root(&root, &crate::RecurseError::NoResponse, out);
            return;
        }
        match Session::start(r, qname, root.sf_key.1, budget, now) {
            Some(session) => {
                let sf_key = root.sf_key.clone();
                let idx = self.insert(Slot {
                    session,
                    kind: SlotKind::Root(root),
                    parked: None,
                    awaiting: None,
                    ns_budget,
                });
                if self.cfg.singleflight {
                    self.inflight.insert(sf_key, idx);
                }
            }
            None => self.fail_root(&root, &crate::RecurseError::NoReachableNs, out),
        }
    }
}

#[cfg(test)]
/** @brief 레인이 동기 경로와 같은 판정을 내는지, 그리고 슬롯·데드라인·예산이 새지 않는지. */
mod tests {
    use super::*;
    use onetdns_proto::{DnsClass, Header, Question, ResponseCode};

    /** @brief 고정 응답을 내는 테스트용 권한 서버. */
    fn spawn_mock_authority() -> SocketAddr {
        spawn_mock_authority_forging_ad(false)
    }

    /** @brief AD 비트를 위조해 보내는 테스트용 서버. */
    fn spawn_mock_authority_forging_ad(forge_ad: bool) -> SocketAddr {
        spawn_mock_answering(
            forge_ad,
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            Duration::ZERO,
        )
    }

    /**
     * @brief 모든 질의에 주어진 주소로 권한 있게 답하는 테스트용 서버.
     * @param delay 답하기 전에 기다릴 시간.
     */
    fn spawn_mock_answering(
        forge_ad: bool,
        address: std::net::Ipv4Addr,
        delay: Duration,
    ) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                std::thread::sleep(delay);
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        authentic_data: forge_ad,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                resp.answers
                    .push(Record::new(q.name.clone(), 60, RData::A(address)));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[test]
    /** @brief 공개 API만으로 해석이 끝나고, 같은 질의가 하나로 합쳐지는지. */
    fn reactor_completes_and_merges_via_public_api() {
        let root = spawn_mock_authority();
        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut reactor = Reactor::new(ReactorConfig::default());
        let qname = Name::from_str("example.").unwrap();
        let now = Instant::now();

        assert!(matches!(
            reactor.submit(&recursor, qname.clone(), RecordType::A, 1, now, false),
            SubmitOutcome::Accepted
        ));
        assert!(matches!(
            reactor.submit(&recursor, qname.clone(), RecordType::A, 2, now, false),
            SubmitOutcome::Merged
        ));
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 3, now, false),
            SubmitOutcome::Merged
        ));
        assert_eq!(reactor.live(), 1, "단일비행이면 세션은 하나");

        let mut done: Vec<(Token, bool)> = vec![];
        let deadline = Instant::now() + Duration::from_secs(3);
        while done.len() < 3 && Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            if fds.is_empty() {
                break;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(&recursor, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(&recursor, now, &mut out);
            for c in out {
                match c {
                    Completion::Answer(t, m) => {
                        assert_eq!(m.answers.len(), 1);
                        assert!(matches!(m.answers[0].rdata, RData::A(_)));
                        done.push((t, true));
                    }
                    Completion::Fail(t, _) | Completion::Retry(t) => done.push((t, false)),
                }
            }
        }
        let mut tokens: Vec<Token> = done.iter().map(|(t, _)| *t).collect();
        tokens.sort_unstable();
        assert_eq!(tokens, vec![1, 2, 3], "리더+팔로워 전원 완료 통지");
        assert!(done.iter().all(|(_, ok)| *ok), "전원 Answer");
        assert_eq!(reactor.live(), 0);
        assert_eq!(reactor.merged, 2);
        assert_eq!(reactor.completed, 3);
    }

    #[test]
    /** @brief CD를 존중할 때만 검증을 건너뛰는지. */
    fn reactor_refuses_checking_disabled_only_when_cd_is_honored() {
        let root = spawn_mock_authority();
        let qname = Name::from_str("example.").unwrap();

        let ignoring = Recursor::new(vec![root], Duration::from_millis(200))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut lane = Reactor::new(ReactorConfig::default());
        assert!(
            matches!(
                lane.submit(
                    &ignoring,
                    qname.clone(),
                    RecordType::A,
                    1,
                    Instant::now(),
                    false
                ),
                SubmitOutcome::Accepted
            ),
            "CD=0은 그대로 받는다"
        );
        assert!(
            matches!(
                lane.submit(
                    &ignoring,
                    qname.clone(),
                    RecordType::A,
                    2,
                    Instant::now(),
                    true
                ),
                SubmitOutcome::Merged
            ),
            "ignore_cd=true면 CD=1도 동기 경로와 의미가 같아 레인이 받는다"
        );

        let honoring = Recursor::new(vec![root], Duration::from_millis(200))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()])
            .with_ignore_cd(false);
        let mut guarded = Reactor::new(ReactorConfig::default());
        assert!(
            matches!(
                guarded.submit(&honoring, qname, RecordType::A, 3, Instant::now(), true),
                SubmitOutcome::Rejected
            ),
            "CD를 존중하는 구성에서 CD=1은 거절한다"
        );
        assert_eq!(guarded.live(), 0, "거절된 제출은 세션을 만들지 않는다");
    }

    /** @brief 무관한 레코드를 끼워 넣는 테스트용 서버. */
    fn spawn_mock_authority_injecting_extras() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                resp.answers.push(Record::new(
                    q.name.clone(),
                    60,
                    RData::A(std::net::Ipv4Addr::new(192, 0, 2, 7)),
                ));

                resp.answers.push(Record::new(
                    Name::from_str("bank.test.").unwrap(),
                    60,
                    RData::A(std::net::Ipv4Addr::new(198, 51, 100, 66)),
                ));
                resp.authorities.push(Record::new(
                    Name::from_str("unrelated.test.").unwrap(),
                    60,
                    RData::Ns(Name::from_str("ns.evil.test.").unwrap()),
                ));
                resp.additionals.push(Record::new(
                    Name::from_str("ns.evil.test.").unwrap(),
                    60,
                    RData::A(std::net::Ipv4Addr::new(198, 51, 100, 67)),
                ));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[test]
    /** @brief 레인도 동기 경로처럼 무관한 레코드를 걷어내는지. */
    fn reactor_strips_unrelated_records_like_sync_path() {
        let root = spawn_mock_authority_injecting_extras();
        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let qname = Name::from_str("example.").unwrap();

        let sync = recursor
            .resolve(&qname, RecordType::A)
            .expect("동기 해석 성공");
        assert_eq!(sync.answers.len(), 1, "동기: 질의한 RRset만 남는다");
        assert!(sync.authorities.is_empty(), "동기: 권한 구획을 비운다");
        assert!(sync.additionals.is_empty(), "동기: OPT 외 부가를 버린다");

        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        let msg = drive_one(&mut reactor, &recursor).expect("리액터 응답");

        assert_eq!(
            msg.answers.len(),
            sync.answers.len(),
            "리액터가 무관한 답변 레코드를 흘렸다: {:?}",
            msg.answers
                .iter()
                .map(|r| r.name.to_ascii_lower())
                .collect::<Vec<_>>()
        );
        assert!(
            msg.authorities.is_empty(),
            "리액터가 권한 구획을 흘렸다: {:?}",
            msg.authorities
                .iter()
                .map(|r| r.name.to_ascii_lower())
                .collect::<Vec<_>>()
        );
        assert!(
            msg.additionals.is_empty(),
            "리액터가 부가 구획을 흘렸다: {:?}",
            msg.additionals
                .iter()
                .map(|r| r.name.to_ascii_lower())
                .collect::<Vec<_>>()
        );
    }

    /**
     * @brief 받은 질의에 A 레코드 하나를 담은 권한 응답을 만든다.
     * @param truncated 잘림 비트를 켤지.
     * @param with_answer 답 레코드를 담을지.
     */
    fn authority_reply(req: &Message, truncated: bool, with_answer: bool) -> Vec<u8> {
        let q = req.questions[0].clone();
        let mut resp = Message {
            header: Header {
                id: req.header.id,
                response: true,
                authoritative: true,
                truncated,
                ..Default::default()
            },
            questions: vec![Question {
                name: q.name.clone(),
                qtype: q.qtype,
                qclass: DnsClass::IN,
            }],
            ..Default::default()
        };
        resp.header.rcode = ResponseCode::NoError.0;
        if with_answer {
            resp.answers.push(Record::new(
                q.name.clone(),
                60,
                RData::A(std::net::Ipv4Addr::new(192, 0, 2, 7)),
            ));
        }
        resp.try_encode().unwrap()
    }

    /** @brief UDP 질의에 reply 가 만든 바이트로 답하는 테스트용 권한 서버. */
    fn spawn_mock_authority_replying(reply: fn(&Message) -> Vec<u8>) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                if req.questions.is_empty() {
                    continue;
                }
                let _ = sock.send_to(&reply(&req), from);
            }
        });
        addr
    }

    #[test]
    /** @brief 권한 서버에 TCP로만 물어야 하는 동안에는 UDP만 쓰는 레인이 제출을 거절하는지. */
    fn reactor_rejects_while_authority_tcp_switch_is_on() {
        let root: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let switch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let recursor = Recursor::new(vec![root], Duration::from_millis(200))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()])
            .with_authority_tcp(switch.clone());
        let qname = Name::from_str("example.").unwrap();
        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(
                &recursor,
                qname.clone(),
                RecordType::A,
                1,
                Instant::now(),
                false
            ),
            SubmitOutcome::Rejected
        ));
        switch.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 2, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
    }

    #[test]
    /** @brief 잘린 응답은 TCP가 필요하므로 동기 경로로 넘기는지. */
    fn reactor_hands_truncated_response_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            authority_reply(req, true, true)
        }));
    }

    #[test]
    /**
     * @brief 레코드 없이 잘림 비트만 켠 응답도 동기 경로로 넘기는지.
     * @details 이 응답은 반복 해석에 쓸 수 있는 응답인지 보는 검사를 통과하지 못한다. 그 검사보다
     *          잘림을 먼저 보지 않으면 왕복 시간 초과까지 기다렸다가 실패한다.
     */
    fn reactor_hands_empty_truncated_response_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            authority_reply(req, true, false)
        }));
    }

    #[test]
    /** @brief 잘림 비트 없이 레코드 중간에서 끊긴 응답도 동기 경로로 넘기는지. */
    fn reactor_hands_reply_cut_without_tc_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            let full = authority_reply(req, false, true);
            full[..full.len() - 3].to_vec()
        }));
    }

    /** @brief root 한 곳에 물은 해석이 재시도 통지로 끝나는지 확인한다. */
    fn assert_handed_to_sync_path(root: SocketAddr) {
        let recursor = Recursor::new(vec![root], Duration::from_millis(500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let qname = Name::from_str("example.").unwrap();

        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));

        let mut seen = None;
        let deadline = Instant::now() + Duration::from_secs(3);
        while seen.is_none() && Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            if fds.is_empty() {
                break;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(&recursor, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(&recursor, now, &mut out);
            seen = out.into_iter().next();
        }

        match seen {
            Some(Completion::Retry(token)) => assert_eq!(token, 1),
            Some(Completion::Answer(_, m)) => panic!(
                "절단된 응답을 최종 답으로 반환했다: truncated={}, answers={}",
                m.header.truncated,
                m.answers.len()
            ),
            Some(Completion::Fail(..)) => {
                panic!("동기 경로가 TCP로 성공할 응답을 SERVFAIL로 종결했다")
            }
            None => panic!("완료 통지가 없다"),
        }
    }

    #[test]
    /** @brief IPv6 권한 서버에도 닿는지. 계열이 바뀌면 소켓을 다시 열어야 한다. */
    fn reactor_reaches_ipv6_authority_like_sync_path() {
        let sock = UdpSocket::bind("[::1]:0").expect("v6 mock bind");
        let root = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                resp.answers.push(Record::new(
                    q.name.clone(),
                    60,
                    RData::A(std::net::Ipv4Addr::new(192, 0, 2, 7)),
                ));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_server_acl(vec![], vec!["::1/128".parse().unwrap()]);
        let qname = Name::from_str("example.").unwrap();
        assert!(
            recursor.resolve(&qname, RecordType::A).is_ok(),
            "동기 경로는 IPv6 권한 서버를 푼다"
        );

        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        let msg = drive_one(&mut reactor, &recursor).expect("리액터도 IPv6 서버를 풀어야 한다");
        assert_eq!(msg.answers.len(), 1);
    }

    #[test]
    /** @brief glue 없는 체인이 전체 데드라인을 넘기지 않는지. 자식이 데드라인을 새로 잡으면 무한정 늘어난다. */
    fn reactor_bounds_total_wall_time_of_a_glueless_chain() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let root = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let mut serial = 0u32;
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let lower = q.name.to_ascii_lower();

                if lower.ends_with("deep") {
                    continue;
                }
                let next = if lower.ends_with("chain") {
                    "deep"
                } else {
                    "chain"
                };
                serial += 1;
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                for index in 0..8u32 {
                    let child = Name::from_str(&format!("ns{index}.z{serial}.{next}.")).unwrap();
                    resp.authorities
                        .push(Record::new(q.name.clone(), 3600, RData::Ns(child)));
                }
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_millis(300))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let budget = Duration::from_millis(900);
        let mut reactor = Reactor::new(ReactorConfig {
            session_budget: budget,
            ..ReactorConfig::default()
        });
        let started = Instant::now();
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("victim.slow.").unwrap(),
                RecordType::A,
                1,
                started,
                false,
            ),
            SubmitOutcome::Accepted
        ));

        let hard_stop = started + budget * 4;
        let mut done = false;
        while Instant::now() < hard_stop {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            let now = Instant::now();
            let mut out = Vec::new();
            if !fds.is_empty() {
                let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
                if rc > 0 {
                    reactor.pump(&recursor, &fds, 0, &map, now, &mut out);
                }
            }
            reactor.on_tick(&recursor, Instant::now(), &mut out);
            if !out.is_empty() || reactor.live() == 0 {
                done = true;
                break;
            }
        }
        assert!(
            done,
            "글루 없는 연쇄가 예산 {budget:?}의 4배 안에 끝나지 않았다. 자식이 데드라인을 물려받지 않는다"
        );
    }

    #[test]
    /** @brief glue 없는 네임서버 체인의 깊이가 예산에 묶이는지. */
    fn reactor_bounds_glueless_ns_chain_depth() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let root = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let mut serial = 0u32;
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                serial += 1;
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;

                let child = Name::from_str(&format!("ns{serial}.chain.")).unwrap();
                resp.authorities.push(Record::new(
                    Name::from_str("chain.").unwrap(),
                    3600,
                    RData::Ns(child),
                ));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_millis(1500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("victim.chain.").unwrap(),
                RecordType::A,
                1,
                Instant::now(),
                false,
            ),
            SubmitOutcome::Accepted
        ));

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut peak = 0usize;
        while Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            peak = peak.max(reactor.live());
            if fds.is_empty() {
                break;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(&recursor, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(&recursor, now, &mut out);
            if !out.is_empty() {
                break;
            }
        }

        assert!(
            peak <= 65,
            "글루 없는 NS 연쇄에서 살아 있는 슬롯이 {peak}개까지 늘었다. 깊이 예산이 없다"
        );
        assert!(
            peak <= ReactorConfig::default().inflight_max * 2,
            "슬롯 총합이 자식 몫까지 합한 상한을 넘었다: {peak}"
        );
    }

    #[test]
    /** @brief 별칭을 따라가도 데드라인이 하나로 유지되는지. */
    fn reactor_shares_one_deadline_across_the_alias_chain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /** @brief 테스트에서 한 단계마다 늦출 시간. */
        const HOP_DELAY: Duration = Duration::from_millis(100);

        /** @brief 테스트에서 해석 하나에 줄 전체 예산. */
        const SESSION_BUDGET: Duration = Duration::from_millis(300);

        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let root = sock.local_addr().unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let mut serial = 0u32;
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                serial += 1;
                counter.fetch_add(1, Ordering::Relaxed);
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;

                let target = Name::from_str(&format!("hop{serial}.chain.")).unwrap();
                resp.answers
                    .push(Record::new(q.name.clone(), 60, RData::Cname(target)));
                std::thread::sleep(HOP_DELAY);
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_secs(2))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()])
            .with_cname_limit(40);
        let mut reactor = Reactor::new(ReactorConfig {
            session_budget: SESSION_BUDGET,
            ..ReactorConfig::default()
        });
        let started = Instant::now();
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("victim.chain.").unwrap(),
                RecordType::A,
                1,
                started,
                false,
            ),
            SubmitOutcome::Accepted
        ));

        let hard_stop = started + Duration::from_secs(8);
        let mut done = false;
        while !done && Instant::now() < hard_stop {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            let now = Instant::now();
            let mut out = Vec::new();
            if !fds.is_empty() {
                let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
                if rc > 0 {
                    reactor.pump(&recursor, &fds, 0, &map, now, &mut out);
                }
            }
            reactor.on_tick(&recursor, Instant::now(), &mut out);
            done = !out.is_empty();
        }
        let elapsed = started.elapsed();
        let hops = served.load(Ordering::Relaxed);
        assert!(done, "질의가 8초 안에 끝나지 않았다");

        assert!(
            elapsed < Duration::from_millis(1500),
            "별칭 연쇄가 세션 데드라인을 넘겨 {elapsed:?} 동안 슬롯을 쥐었다"
        );
        assert!(
            hops <= 8,
            "별칭 홉마다 예산이 되살아나 업스트림으로 {hops}번 나갔다"
        );
    }

    #[test]
    /** @brief DNAME 걸음이 예산에 제대로 잡히는지. */
    fn reactor_counts_dname_hops_against_the_dname_limit() {
        /** @brief 테스트에 쓸 단계 수. */
        const HOPS: usize = 3;

        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let root = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let mut given = 0usize;
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                let labels = q.name.num_labels();
                if q.qtype == RecordType::NS {
                    let ns = Name::from_str("ns.chain.").unwrap();
                    resp.authorities
                        .push(Record::new(q.name.clone(), 3600, RData::Ns(ns.clone())));
                    resp.additionals.push(Record::new(
                        ns,
                        3600,
                        RData::A(std::net::Ipv4Addr::LOCALHOST),
                    ));
                    resp.header.authoritative = false;
                } else if labels >= 3 && given < HOPS {
                    given += 1;
                    let owner = q.name.suffix(labels - 1);
                    let target = Name::from_str(&format!("d{given}.chain.")).unwrap();
                    resp.answers
                        .push(Record::new(owner, 60, RData::Dname(target)));
                } else {
                    resp.answers.push(Record::new(
                        q.name.clone(),
                        60,
                        RData::A(std::net::Ipv4Addr::new(192, 0, 2, 9)),
                    ));
                }
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_port(root.port())
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()])
            .with_cname_limit(1)
            .with_dname_limit(8);
        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("x.a.chain.").unwrap(),
                RecordType::A,
                1,
                Instant::now(),
                false,
            ),
            SubmitOutcome::Accepted
        ));

        let hard_stop = Instant::now() + Duration::from_secs(5);
        let mut result = None;
        while result.is_none() && Instant::now() < hard_stop {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            let mut out = Vec::new();
            if !fds.is_empty() {
                let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
                if rc > 0 {
                    reactor.pump(&recursor, &fds, 0, &map, Instant::now(), &mut out);
                }
            }
            reactor.on_tick(&recursor, Instant::now(), &mut out);
            result = out.into_iter().next();
        }
        match result {
            Some(Completion::Answer(_, msg)) => {
                assert!(
                    msg.answers.iter().any(|rec| rec.rtype == RecordType::DNAME),
                    "DNAME RRset이 답변에 누적돼야 한다"
                );
            }
            Some(Completion::Fail(_, e)) => {
                panic!("DNAME 홉 {HOPS}개는 DNAME 한도(8) 안인데 거절됐다: {e:?}")
            }
            Some(Completion::Retry(_)) => panic!("DNAME 연쇄가 동기 경로로 반송됐다"),
            None => panic!("5초 안에 끝나지 않았다"),
        }
    }

    #[test]
    /** @brief 레인도 내부망 위임을 거부하는지. 동기 경로와 방어가 같아야 한다. */
    fn reactor_refuses_internal_delegation_like_sync_path() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let root = sock.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((_, _from)) = sock.recv_from(&mut buf) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });

        let recursor = Recursor::new(vec![root], Duration::from_millis(400));
        let qname = Name::from_str("example.").unwrap();
        assert!(
            matches!(
                recursor.resolve(&qname, RecordType::A),
                Err(crate::RecurseError::NoReachableNs)
            ),
            "동기 경로는 내부 주소를 정책으로 거부한다(시간 초과가 아니라)"
        );

        let mut reactor = Reactor::new(ReactorConfig::default());
        let outcome = reactor.submit(&recursor, qname, RecordType::A, 1, Instant::now(), false);
        if matches!(outcome, SubmitOutcome::Accepted) {
            assert!(
                drive_one(&mut reactor, &recursor).is_none(),
                "레인도 내부 주소로는 답을 만들 수 없다"
            );
        }

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            seen.load(Ordering::Relaxed),
            0,
            "두 경로 어느 쪽도 내부 주소로 패킷을 보내면 안 된다"
        );
    }

    /** @brief 별칭을 돌려주는 테스트용 서버. */
    fn spawn_mock_authority_with_alias() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("mock bind");
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Ok(req) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(q) = req.questions.first().cloned() else {
                    continue;
                };
                let mut resp = Message {
                    header: Header {
                        id: req.header.id,
                        response: true,
                        authoritative: true,
                        ..Default::default()
                    },
                    questions: vec![Question {
                        name: q.name.clone(),
                        qtype: q.qtype,
                        qclass: DnsClass::IN,
                    }],
                    ..Default::default()
                };
                resp.header.rcode = ResponseCode::NoError.0;
                let rdata = match q.name.to_ascii_lower().as_str() {
                    "alias" => RData::Cname(Name::from_str("target.").unwrap()),
                    "other" => RData::A(std::net::Ipv4Addr::new(198, 51, 100, 9)),
                    _ => RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                };
                resp.answers.push(Record::new(q.name.clone(), 60, rdata));
                let _ = sock.send_to(&resp.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[test]
    /** @brief 별칭을 따라간 뒤 합치기 인덱스가 지워지는지. 남으면 다음 요청이 고아 항목에 붙는다. */
    fn reactor_clears_singleflight_index_after_cname_chase() {
        let root = spawn_mock_authority_with_alias();
        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut reactor = Reactor::new(ReactorConfig::default());
        let alias = Name::from_str("alias.").unwrap();

        assert!(matches!(
            reactor.submit(
                &recursor,
                alias.clone(),
                RecordType::A,
                1,
                Instant::now(),
                false
            ),
            SubmitOutcome::Accepted
        ));
        let chased = drive_one(&mut reactor, &recursor).expect("별칭 추적 응답");
        assert!(
            chased
                .answers
                .iter()
                .any(|rec| matches!(rec.rdata, RData::A(ip) if ip.octets() == [192, 0, 2, 1])),
            "추적이 목표의 A까지 도달해야 한다: {:?}",
            chased.answers
        );
        assert_eq!(reactor.live(), 0, "세션은 모두 끝났다");
        assert!(
            reactor.inflight.is_empty(),
            "추적 후 원 이름의 단일비행 항목이 남았다: {:?}",
            reactor
                .inflight
                .keys()
                .map(|(name, qtype)| (String::from_utf8_lossy(name).into_owned(), *qtype))
                .collect::<Vec<_>>()
        );

        let other = Name::from_str("other.").unwrap();
        assert!(matches!(
            reactor.submit(&recursor, other, RecordType::A, 2, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        assert!(
            matches!(
                reactor.submit(&recursor, alias, RecordType::A, 3, Instant::now(), false),
                SubmitOutcome::Accepted
            ),
            "다른 이름의 진행 중 해석에 병합되면 안 된다"
        );
    }

    /** @brief 레인을 한 해석이 끝날 때까지 돌린다. */
    fn drive_one(reactor: &mut Reactor, recursor: &Recursor) -> Option<Message> {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let mut fds = Vec::new();
            let mut map = Vec::new();
            reactor.collect_pollfds(&mut fds, &mut map);
            if fds.is_empty() {
                return None;
            }
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            let now = Instant::now();
            let mut out = Vec::new();
            if rc > 0 {
                reactor.pump(recursor, &fds, 0, &map, now, &mut out);
            }
            reactor.on_tick(recursor, now, &mut out);
            for c in out {
                if let Completion::Answer(_, m) = c {
                    return Some(m);
                }
            }
        }
        None
    }

    #[test]
    /** @brief 업스트림이 위조한 AD 비트를 그대로 흘리지 않는지. */
    fn reactor_never_relays_forged_authentic_data() {
        let root = spawn_mock_authority_forging_ad(true);
        let recursor = Recursor::new(vec![root], Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let qname = Name::from_str("example.").unwrap();

        let sync = recursor
            .resolve(&qname, RecordType::A)
            .expect("동기 해석 성공");
        assert!(!sync.header.authentic_data, "동기 경로: 미검증 AD는 0");

        let mut reactor = Reactor::new(ReactorConfig::default());
        assert!(matches!(
            reactor.submit(&recursor, qname, RecordType::A, 1, Instant::now(), false),
            SubmitOutcome::Accepted
        ));
        let msg = drive_one(&mut reactor, &recursor).expect("리액터 응답");
        assert!(!msg.header.authentic_data, "리액터: 미검증 AD는 0");
        assert_eq!(
            msg.header.authoritative, sync.header.authoritative,
            "리액터 AA는 동기 경로와 같아야 한다"
        );
        assert!(
            !sync.header.authoritative,
            "재귀 답은 이 서버의 권한이 아니므로 AA=0"
        );
    }

    #[test]
    /**
     * @brief 느린 서버의 답을 기다리는 동안 다음 서버에도 물어 먼저 온 답을 쓰는지.
     * @details 동기 경로의 a_slow_server_is_raced_by_the_next_one과 같은 규칙을 레인에서
     *          확인한다. 첫 서버를 끝까지 기다리면 그 서버의 지연만큼 늦는다.
     */
    fn reactor_races_a_slow_server_with_the_next_one() {
        /** @brief 느린 서버가 답을 미루는 시간. 서버당 제한 시간보다 짧아야 한다. */
        const SLOW_DELAY: Duration = Duration::from_millis(1500);
        let slow_ip = std::net::Ipv4Addr::new(192, 0, 2, 8);
        let fast_ip = std::net::Ipv4Addr::new(192, 0, 2, 9);
        let slow = spawn_mock_answering(false, slow_ip, SLOW_DELAY);
        let fast = spawn_mock_answering(false, fast_ip, Duration::ZERO);
        let recursor = Recursor::new(vec![slow, fast], Duration::from_secs(4))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut reactor = Reactor::new(ReactorConfig::default());
        let started = Instant::now();
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("example.").unwrap(),
                RecordType::A,
                1,
                started,
                false
            ),
            SubmitOutcome::Accepted
        ));

        let msg = drive_one(&mut reactor, &recursor).expect("리액터 응답");
        let elapsed = started.elapsed();
        assert!(
            matches!(msg.answers.first().map(|r| &r.rdata), Some(RData::A(ip)) if *ip == fast_ip),
            "{msg:?}"
        );
        assert!(
            elapsed >= crate::UNKNOWN_SERVER_PATIENCE && elapsed < SLOW_DELAY,
            "둘째 서버에 물은 시점이 기대와 다릅니다: {elapsed:?}"
        );
    }

    #[test]
    /**
     * @brief 세션 하나가 동시에 기다리는 왕복이 MAX_EXCHANGES_PER_QUERY를 넘지 않는지.
     * @details 동기 경로의 a_query_waits_on_at_most_two_exchanges_at_once와 같은 규칙을 레인에서
     *          확인한다. 앞의 두 서버는 답하지 않으므로, 셋째 서버에는 앞의 왕복 하나가 시간을
     *          넘긴 뒤에야 물어야 한다.
     */
    fn reactor_waits_on_at_most_two_exchanges_at_once() {
        let silent = || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = sock.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1500];
                while sock.recv_from(&mut buf).is_ok() {}
            });
            addr
        };
        let first = silent();
        let second = silent();
        let third_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let third = third_sock.local_addr().unwrap();
        let asked_third = std::sync::Arc::new(std::sync::Mutex::new(None::<Instant>));
        let record = asked_third.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while third_sock.recv_from(&mut buf).is_ok() {
                record.lock().unwrap().get_or_insert_with(Instant::now);
            }
        });

        let timeout = Duration::from_secs(4);
        let recursor = Recursor::new(vec![first, second, third], timeout)
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
        let mut reactor = Reactor::new(ReactorConfig::default());
        let started = Instant::now();
        assert!(matches!(
            reactor.submit(
                &recursor,
                Name::from_str("example.").unwrap(),
                RecordType::A,
                1,
                started,
                false
            ),
            SubmitOutcome::Accepted
        ));
        assert!(drive_one(&mut reactor, &recursor).is_none());

        let asked = asked_third
            .lock()
            .unwrap()
            .map(|at| at.duration_since(started))
            .expect("앞의 왕복이 끝나면 셋째 서버에도 물어야 합니다");
        assert!(
            asked >= timeout / 3,
            "앞의 두 왕복이 답을 기다리는 동안 셋째 서버에도 물었습니다: {asked:?}"
        );
    }
}
