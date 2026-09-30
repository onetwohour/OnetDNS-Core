/*!
 * @brief 레인의 처리 한계를 측정하는 테스트 전용 프로브.
 *
 * @details 실제 레인과 별개로 최소한의 세션 기계를 다시 만들어, 판정 논리를 걷어낸
 *          상태의 상한을 측정한다. 그래야 느린 이유가 판정 때문인지 구조 때문인지 갈린다.
 * @note 기본 실행에서 제외돼 있다. 환경 변수로 질의 목록과 업스트림을 지정해야 돌아간다.
 */

use super::*;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;

/** @brief 프로브의 왕복 하나. */
struct Exchange {
    /** @brief 보낸 질의. */
    sent: Message,
    /** @brief 지금 물어보는 서버. */
    target: SocketAddr,
    /** @brief 순서대로 시도할 서버들. */
    ladder: Vec<SocketAddr>,
    /** @brief 시도 중인 위치. */
    ladder_idx: usize,
    /** @brief 서버 하나에 줄 시간. */
    per_server: Duration,
    /** @brief 이 왕복의 데드라인. */
    deadline: Instant,
    /** @brief 보낸 시각. */
    sent_at: Instant,
}

/** @brief 프로브의 해석 하나. */
struct Session {
    /** @brief 해석 중인 이름. */
    qname: Name,
    /** @brief 해석 중인 타입. */
    qtype: RecordType,
    /** @brief 위임 진행 위치. */
    state: IterationState,
    /** @brief 다음 질의의 모양. */
    plan: NextQuery,
    /** @brief 답을 기다리는 왕복. */
    exchange: Option<Exchange>,
    /** @brief 이 해석 전용 소켓. */
    sock: std::net::UdpSocket,
    /** @brief 해석 전체의 데드라인. */
    session_deadline: Instant,
    /** @brief 밟은 단계 수. */
    steps: usize,
    /** @brief 단계 수 상한. */
    step_cap: usize,
}

/** @brief 프로브 해석이 멈춘 이유. */
enum SessionEnd {
    /** @brief 응답을 얻었다. */
    Done(Message),
    /** @brief 실패했다. */
    Failed,

    /** @brief 네임서버 주소가 필요하다. */
    NeedAddrs {
        /** @brief 주소를 알아내야 할 서버 이름들. */
        missing: Vec<Name>,
        /** @brief 그 주소를 기다리는 위임. */
        pending: Box<PendingReferral>,
    },
}

/**
 * @brief 질의 문맥을 만든다. 프로브는 검증하지 않는다.
 * @note 프로브가 얻은 답은 질의자에게 나가지 않고 경로를 측정하는 데만 쓰이므로, 서명을
 *       달라고 해서 응답만 키울 이유가 없다.
 */
fn make_ctx(qname: &Name, qtype: RecordType) -> IterationContext<'_> {
    IterationContext {
        qname,
        qtype,
        total: qname.num_labels(),
        do_bit: false,
        collect_ds: false,
    }
}

impl Session {
    /** @brief 캐시된 위임이나 루트에서 해석을 시작한다. */
    fn start(r: &Recursor, qname: Name, qtype: RecordType, now: Instant) -> Option<Self> {
        let (zone, servers) = r
            .deepest_cached_delegation(&qname)
            .unwrap_or_else(|| (Name::root(), r.roots.clone()));
        let state = IterationState::start(zone, servers);
        let step_cap = r.max_referrals + qname.num_labels() + 2;
        let sock = onetdns_core::udp::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        sock.set_nonblocking(true).ok()?;
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
            exchange: None,
            sock,
            session_deadline: now + Duration::from_secs(5),
            steps: 0,
            step_cap,
        };
        if s.send_next(r, now).is_err() {
            return None;
        }
        Some(s)
    }

    /** @brief 다음 질의를 보낸다. */
    fn send_next(&mut self, r: &Recursor, now: Instant) -> Result<(), ()> {
        self.steps += 1;
        if self.steps > self.step_cap {
            return Err(());
        }
        let ctx = make_ctx(&self.qname, self.qtype);
        self.plan = self.state.next_query(&ctx);
        let ladder: Vec<SocketAddr> = r
            .order_by_infra(&self.state.servers, &self.state.zone)
            .into_iter()
            .filter(|s| r.is_queryable(s.ip()))
            .collect();
        if ladder.is_empty() {
            return Err(());
        }
        let per_server =
            (r.timeout / ladder.len().clamp(1, 4) as u32).max(Duration::from_millis(300));
        self.exchange = None;
        self.fire_attempt(r, ladder, 0, per_server, now)
    }

    /** @brief 사다리의 현재 서버에 보낸다. */
    fn fire_attempt(
        &mut self,
        r: &Recursor,
        ladder: Vec<SocketAddr>,
        idx: usize,
        per_server: Duration,
        now: Instant,
    ) -> Result<(), ()> {
        let Some(&target) = ladder.get(idx) else {
            return Err(());
        };
        let ctx = make_ctx(&self.qname, self.qtype);
        let mut q = make_query(&self.plan.mname, self.plan.mtype, ctx.do_bit);
        q.header.id = u16::from_le_bytes(onetdns_core::rng::ephemeral_random_array::<2>());
        r.apply_outgoing_case(&mut q);
        let wire = q.try_encode().map_err(|_| ())?;
        self.sock.send_to(&wire, target).map_err(|_| ())?;
        let deadline = (now + per_server).min(self.session_deadline);
        self.exchange = Some(Exchange {
            sent: q,
            target,
            ladder,
            ladder_idx: idx,
            per_server,
            deadline,
            sent_at: now,
        });
        Ok(())
    }

    /** @brief 시간 초과 시 다음 서버로 넘어간다. */
    fn on_exchange_timeout(&mut self, r: &Recursor, now: Instant) -> Result<(), ()> {
        let Some(ex) = self.exchange.take() else {
            return Err(());
        };
        r.infra_fail(ex.target.ip(), &self.state.zone);
        self.fire_attempt(r, ex.ladder, ex.ladder_idx + 1, ex.per_server, now)
    }

    /** @brief 응답을 읽어 이 서버의 질의에 대한 것인지 확인한다. */
    fn try_recv(&mut self, r: &Recursor) -> Option<Message> {
        let ex = self.exchange.as_ref()?;
        let mut buf = [0u8; 4096];
        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if from != ex.target {
                        continue;
                    }
                    let Ok(resp) = Message::parse(&buf[..n]) else {
                        continue;
                    };
                    if resp.header.id != ex.sent.header.id {
                        continue;
                    }
                    if r.caps_for_id && !questions_case_exact(&resp.questions, &ex.sent.questions) {
                        continue;
                    }
                    if !response_usable_for_iteration(&resp, &ex.sent, &self.state.zone) {
                        continue;
                    }
                    return Some(resp);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return None,
                Err(_) => return None,
            }
        }
    }

    /** @brief 응답으로 한 단계 나아간다. */
    fn on_response(&mut self, r: &Recursor, resp: Message, now: Instant) -> Option<SessionEnd> {
        if let Some(ex) = self.exchange.take() {
            r.infra_success(ex.target.ip(), &self.state.zone, ex.sent_at.elapsed());
        }
        let ctx = make_ctx(&self.qname, self.qtype);
        match r.advance(&mut self.state, resp, &self.plan, &ctx) {
            StepOutcome::Done(final_msg) => Some(SessionEnd::Done(final_msg)),
            StepOutcome::Continue => match self.send_next(r, now) {
                Ok(()) => None,
                Err(()) => Some(SessionEnd::Failed),
            },
            StepOutcome::NeedNsAddrs { missing, pending } => {
                Some(SessionEnd::NeedAddrs { missing, pending })
            }
            StepOutcome::Failed(_) => Some(SessionEnd::Failed),
        }
    }

    /** @brief 받아 온 주소로 참조를 이어 간다. */
    fn resume_with_addrs(
        &mut self,
        r: &Recursor,
        mut pending: PendingReferral,
        addrs: Vec<SocketAddr>,
        now: Instant,
    ) -> Option<SessionEnd> {
        pending.addrs.extend(addrs);
        let ctx = make_ctx(&self.qname, self.qtype);
        match r.finish_referral(&mut self.state, &ctx, pending) {
            StepOutcome::Done(final_msg) => Some(SessionEnd::Done(final_msg)),
            StepOutcome::Continue => match self.send_next(r, now) {
                Ok(()) => None,
                Err(()) => Some(SessionEnd::Failed),
            },
            StepOutcome::NeedNsAddrs { .. } => Some(SessionEnd::Failed),
            StepOutcome::Failed(_) => Some(SessionEnd::Failed),
        }
    }
}

/** @brief 프로브용 리졸버. 업스트림은 환경 변수로 지정한다. */
fn build_recursor() -> (Recursor, SocketAddr) {
    let root: SocketAddr = std::env::var("RP_ROOT")
        .unwrap_or_else(|_| "127.0.1.1:53".into())
        .parse()
        .expect("RP_ROOT format");
    let r = Recursor::new(vec![root], Duration::from_millis(1500))
        .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]);
    (r, root)
}

/** @brief 질의 목록을 파일에서 읽는다. 지정하지 않으면 프로브를 건너뛴다. */
fn load_queries() -> Option<Vec<Name>> {
    let path = std::env::var("RP_QUERIES").ok()?;
    let text = std::fs::read_to_string(&path).expect("Query file");
    let mut names: Vec<Name> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|n| Name::from_str(n).ok())
        .collect();
    assert!(!names.is_empty(), "Query file is empty");
    names.reverse();
    Some(names)
}

/** @brief 환경 변수를 수로 읽는다. 없으면 기본값. */
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/** @brief 세션과 대기 목록에서 같은 위치를 함께 지운다. 둘이 어긋나면 엉뚱한 소켓을 기다린다. */
fn remove_at(sessions: &mut Vec<Session>, fds: &mut Vec<libc::pollfd>, i: usize) {
    sessions.swap_remove(i);
    if i < fds.len() {
        fds.swap_remove(i);
    }
}

#[test]
#[ignore]
/** @brief 판정 없이 세션만 돌렸을 때의 처리량 상한을 측정한다. */
fn reactor_ceiling_probe() {
    let Some(mut names) = load_queries() else {
        eprintln!("RP_QUERIES not set; skipping probe");
        return;
    };
    let inflight_max = env_usize("RP_INFLIGHT", 32);
    let (recursor, _) = build_recursor();

    let total = names.len();
    let (mut done, mut failed, mut bailed, mut timeouts) = (0usize, 0usize, 0usize, 0usize);
    let mut sessions: Vec<Session> = Vec::with_capacity(inflight_max);
    let started = Instant::now();

    loop {
        let now = Instant::now();
        while sessions.len() < inflight_max {
            let Some(qname) = names.pop() else { break };
            match Session::start(&recursor, qname, RecordType::A, now) {
                Some(s) => sessions.push(s),
                None => failed += 1,
            }
        }
        if sessions.is_empty() {
            break;
        }

        let mut fds: Vec<libc::pollfd> = sessions
            .iter()
            .map(|s| libc::pollfd {
                fd: s.sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
        let now = Instant::now();

        let mut i = 0;
        while i < sessions.len() {
            let mut end: Option<SessionEnd> = None;
            if rc > 0 && fds[i].revents & libc::POLLIN != 0 {
                while let Some(resp) = sessions[i].try_recv(&recursor) {
                    end = sessions[i].on_response(&recursor, resp, now);
                    if end.is_some() {
                        break;
                    }
                }
            }
            if end.is_none() {
                let past_exchange = sessions[i]
                    .exchange
                    .as_ref()
                    .is_some_and(|ex| now >= ex.deadline);
                if (past_exchange && sessions[i].on_exchange_timeout(&recursor, now).is_err())
                    || now >= sessions[i].session_deadline
                {
                    timeouts += 1;
                    end = Some(SessionEnd::Failed);
                }
            }
            match end {
                Some(SessionEnd::Done(_)) => {
                    done += 1;
                    remove_at(&mut sessions, &mut fds, i);
                }
                Some(SessionEnd::Failed) => {
                    failed += 1;
                    remove_at(&mut sessions, &mut fds, i);
                }
                Some(SessionEnd::NeedAddrs { .. }) => {
                    bailed += 1;
                    remove_at(&mut sessions, &mut fds, i);
                }
                None => i += 1,
            }
        }
    }

    let elapsed = started.elapsed();
    let qps = done as f64 / elapsed.as_secs_f64();
    println!(
        "reactor-ceiling: total={total} done={done} failed={failed} bailed={bailed} timeouts={timeouts} elapsed={:.2}s qps={qps:.0} inflight={inflight_max}",
        elapsed.as_secs_f64()
    );
    assert!(done > 0, "0 completed; is the authoritative tier running?");
}

/** @brief 프로브 서버가 받은 클라이언트 요청 하나. */
struct ClientReq {
    /** @brief 질의를 보낸 곳. */
    addr: SocketAddr,
    /** @brief 질의 번호. */
    id: u16,
    /** @brief 물어본 것들. */
    questions: Vec<Question>,
    /** @brief 재귀를 요구했는지. */
    rd: bool,

    /** @brief 별칭을 따라오며 모은 답들. */
    acc_answers: Vec<Record>,
    /** @brief 별칭을 몇 번 따라왔는지. 상한이 없으면 순환에서 못 빠져나온다. */
    cname_hops: usize,
}

/** @brief 프로브 슬롯의 역할. */
enum SlotKind {
    /** @brief 클라이언트가 직접 물은 것. */
    Root(ClientReq),

    /** @brief 서버 주소를 알아내려고 이 서버가 스스로 낸 질의. */
    NsAddr { parent: usize },
}

/** @brief 주소를 기다리며 멈춘 참조. */
struct Parked {
    /** @brief 따라가던 위임. */
    pending: Box<PendingReferral>,
    /** @brief 주소를 아직 모르는 서버 이름들. */
    missing: Vec<Name>,
    /** @brief 그중 다음에 물어볼 곳. */
    next_missing: usize,
    /** @brief 지금까지 알아낸 주소들. */
    addrs: Vec<SocketAddr>,
    /** @brief 이 슬롯이 낸 하위 질의 수. */
    children_spawned: usize,
}

/** @brief 프로브의 슬롯 하나. */
struct Slot {
    /** @brief 이 슬롯의 해석 상태. */
    session: Session,
    /** @brief 이 슬롯이 무엇을 위한 것인지. */
    kind: SlotKind,
    /** @brief 서버 주소를 기다리며 멈춰 있는 상태. */
    parked: Option<Parked>,

    /** @brief 같은 질의를 물어 이 슬롯의 답을 함께 받을 것들. */
    followers: Vec<ClientReq>,
}

#[derive(Default)]
/** @brief 프로브 서버가 세는 지표. */
struct SrvStats {
    /** @brief 끝낸 수. */
    done: usize,
    /** @brief 실패한 수. */
    failed: usize,
    /** @brief 같은 질의로 합쳐진 수. */
    merged: usize,
}

/** @brief 프로브용 최소 서버. 레인 구조만 흉내 낸다. */
struct Srv<'a> {
    /** @brief 돌고 있는 해석 슬롯들. */
    slots: Vec<Option<Slot>>,
    /** @brief 다시 쓸 수 있는 슬롯들. */
    free: Vec<usize>,
    /** @brief 쓰는 재귀 리졸버. */
    r: &'a Recursor,
    /** @brief 클라이언트 질의를 받는 소켓. */
    listener: &'a std::net::UdpSocket,
    /** @brief 지금까지의 셈. */
    stats: SrvStats,

    /** @brief 같은 질의를 이미 물어본 위치. */
    inflight: std::collections::HashMap<(Vec<u8>, RecordType), usize>,
    /** @brief 같은 질의를 하나로 합칠지. */
    singleflight: bool,
}

impl<'a> Srv<'a> {
    /** @brief 리졸버와 수신 소켓으로 서버를 만든다. */
    fn new(r: &'a Recursor, listener: &'a std::net::UdpSocket) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            r,
            listener,
            stats: SrvStats::default(),
            inflight: std::collections::HashMap::new(),
            singleflight: env_usize("RP_SINGLEFLIGHT", 1) != 0,
        }
    }

    /** @brief 살아 있는 슬롯 수. */
    fn live(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /** @brief 빈 위치에 슬롯을 넣는다. */
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

    /** @brief 끝난 해석을 정리한다. */
    fn settle(&mut self, idx: usize, end: SessionEnd, now: Instant) {
        let Some(mut slot) = self.slots[idx].take() else {
            return;
        };
        match end {
            SessionEnd::NeedAddrs { missing, pending } => {
                if missing.is_empty() || slot.parked.is_some() {
                    self.finish(idx, slot, None, now);
                    return;
                }
                let first = missing[0].clone();
                slot.parked = Some(Parked {
                    pending,
                    missing,
                    next_missing: 1,
                    addrs: vec![],
                    children_spawned: 1,
                });
                self.slots[idx] = Some(slot);
                self.spawn_child(idx, first, now);
            }
            SessionEnd::Done(final_msg) => self.finish(idx, slot, Some(final_msg), now),
            SessionEnd::Failed => self.finish(idx, slot, None, now),
        }
    }

    /** @brief 부수 해석을 자식으로 시작한다. */
    fn spawn_child(&mut self, parent: usize, qname: Name, now: Instant) {
        match Session::start(self.r, qname, RecordType::A, now) {
            Some(session) => {
                self.insert(Slot {
                    session,
                    kind: SlotKind::NsAddr { parent },
                    parked: None,
                    followers: vec![],
                });
            }
            None => {
                if let Some(pslot) = self.slots[parent].take() {
                    self.finish(parent, pslot, None, now);
                }
            }
        }
    }

    /** @brief 해석을 마무리하고 역할에 맞게 처리한다. */
    fn finish(&mut self, idx: usize, slot: Slot, outcome: Option<Message>, now: Instant) {
        self.free.push(idx);
        match slot.kind {
            SlotKind::Root(client) => {
                let sf_key = (slot.session.qname.canonical_key(), slot.session.qtype);
                if self.inflight.get(&sf_key) == Some(&idx) {
                    self.inflight.remove(&sf_key);
                }
                let followers = slot.followers;
                match outcome {
                    Some(final_msg) => {
                        if let Some(target) =
                            chase_target(&final_msg, &slot.session.qname, slot.session.qtype)
                        {
                            if client.cname_hops < self.r.max_cnames {
                                let mut acc = client.acc_answers;
                                acc.extend(final_msg.answers.iter().cloned());
                                let next = ClientReq {
                                    acc_answers: acc,
                                    cname_hops: client.cname_hops + 1,
                                    ..client
                                };
                                self.restart_root(next, followers, Some(sf_key), target, now);
                                return;
                            }
                            respond_servfail(self.listener, &client);
                            self.stats.failed += 1;
                            for f in &followers {
                                respond_servfail(self.listener, f);
                                self.stats.failed += 1;
                            }
                            return;
                        }
                        for f in &followers {
                            respond_final(self.listener, f, final_msg.clone());
                            self.stats.done += 1;
                        }
                        respond_final(self.listener, &client, final_msg);
                        self.stats.done += 1;
                    }
                    None => {
                        respond_servfail(self.listener, &client);
                        self.stats.failed += 1;
                        for f in &followers {
                            respond_servfail(self.listener, f);
                            self.stats.failed += 1;
                        }
                    }
                }
            }
            SlotKind::NsAddr { parent } => {
                let addrs = outcome
                    .map(|m| {
                        m.answers
                            .iter()
                            .filter_map(|rec| match &rec.rdata {
                                RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), self.r.port)),
                                RData::Aaaa(ip) => {
                                    Some(SocketAddr::new(IpAddr::V6(*ip), self.r.port))
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                self.resume_parent(parent, addrs, now);
            }
        }
    }

    /** @brief 주소를 받아 온 부모를 이어 간다. */
    fn resume_parent(&mut self, parent: usize, addrs: Vec<SocketAddr>, now: Instant) {
        let Some(mut pslot) = self.slots[parent].take() else {
            return;
        };
        let Some(mut parked) = pslot.parked.take() else {
            self.finish(parent, pslot, None, now);
            return;
        };
        parked.addrs.extend(addrs);

        if parked.next_missing < parked.missing.len() && parked.children_spawned < 8 {
            let next = parked.missing[parked.next_missing].clone();
            parked.next_missing += 1;
            parked.children_spawned += 1;
            pslot.parked = Some(parked);
            self.slots[parent] = Some(pslot);
            self.spawn_child(parent, next, now);
            return;
        }
        match pslot
            .session
            .resume_with_addrs(self.r, *parked.pending, parked.addrs, now)
        {
            None => self.slots[parent] = Some(pslot),
            Some(e) => {
                self.slots[parent] = Some(pslot);
                self.settle(parent, e, now);
            }
        }
    }

    /** @brief 별칭을 따라 같은 슬롯에서 다시 시작한다. */
    fn restart_root(
        &mut self,
        client: ClientReq,
        followers: Vec<ClientReq>,
        sf_key: Option<(Vec<u8>, RecordType)>,
        qname: Name,
        now: Instant,
    ) {
        match Session::start(self.r, qname, client.questions[0].qtype, now) {
            Some(session) => {
                let idx = self.insert(Slot {
                    session,
                    kind: SlotKind::Root(client),
                    parked: None,
                    followers,
                });

                if let Some(key) = sf_key {
                    self.inflight.insert(key, idx);
                }
            }
            None => {
                respond_servfail(self.listener, &client);
                self.stats.failed += 1;
                for f in &followers {
                    respond_servfail(self.listener, f);
                    self.stats.failed += 1;
                }
            }
        }
    }
}

/** @brief 응답에서 따라갈 별칭 대상을 찾는다. */
fn chase_target(m: &Message, qname: &Name, qtype: RecordType) -> Option<Name> {
    if qtype == RecordType::CNAME || m.header.rcode != ResponseCode::NoError.0 {
        return None;
    }
    let has_final = m
        .answers
        .iter()
        .any(|r| r.rtype == qtype && r.name.eq_ignore_case(qname));
    if has_final {
        return None;
    }
    m.answers
        .iter()
        .find(|r| r.rtype == RecordType::CNAME && r.name.eq_ignore_case(qname))
        .and_then(|r| match &r.rdata {
            RData::Cname(target) => Some(target.clone()),
            _ => None,
        })
}

/** @brief 클라이언트에게 최종 응답을 보낸다. */
fn respond_final(listener: &std::net::UdpSocket, client: &ClientReq, mut m: Message) {
    m.header.id = client.id;
    m.header.response = true;
    m.header.recursion_available = true;
    m.header.recursion_desired = client.rd;
    m.questions = client.questions.clone();
    if !client.acc_answers.is_empty() {
        let mut all = client.acc_answers.clone();
        all.extend(m.answers);
        m.answers = all;
    }
    if let Ok(wire) = m.try_encode() {
        let _ = listener.send_to(&wire, client.addr);
    }
}

/** @brief 클라이언트에게 SERVFAIL을 보낸다. */
fn respond_servfail(listener: &std::net::UdpSocket, client: &ClientReq) {
    let mut m = Message::default();
    m.header.id = client.id;
    m.header.response = true;
    m.header.recursion_available = true;
    m.header.recursion_desired = client.rd;
    m.header.rcode = ResponseCode::ServFail.0;
    m.questions = client.questions.clone();
    if let Ok(wire) = m.try_encode() {
        let _ = listener.send_to(&wire, client.addr);
    }
}

/** @brief 여러 워커가 같은 포트를 나눠 받도록 소켓을 연다. */
fn bind_reuseport(addr: SocketAddr) -> std::net::UdpSocket {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert!(fd >= 0, "socket");
        let one: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "SO_REUSEPORT");
        let SocketAddr::V4(v4) = addr else {
            panic!("IPv4 addresses only");
        };
        /* BSD 계열은 sin_len 필드가 더 있어 구조체 리터럴로는 그 플랫폼에서만 깨진다. */
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = v4.port().to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from(*v4.ip()).to_be(),
        };
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos"
        ))]
        {
            sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        let rc = libc::bind(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "bind");
        std::net::UdpSocket::from_raw_fd(fd)
    }
}

/** @brief 워커를 특정 코어에 묶는다. 측정에서 스케줄러 이동을 뺀다. */
#[cfg(target_os = "linux")]
fn pin_to_core(core: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/**
 * @brief 코어 고정을 지원하지 않는 플랫폼에서는 아무것도 하지 않는다.
 * @details sched_setaffinity 는 리눅스에만 있다. 고정은 측정 잡음을 줄이는 보조
 *          수단이라 리눅스 구현도 실패를 무시한다. 없어도 프로브는 그대로 돈다.
 */
#[cfg(not(target_os = "linux"))]
fn pin_to_core(_core: usize) {}

/** @brief 프로브 서버 워커 하나를 돌린다. */
fn run_reactor_worker(
    recursor: &Recursor,
    listener: std::net::UdpSocket,
    inflight_max: usize,
    duration: Duration,
) -> SrvStats {
    listener.set_nonblocking(true).expect("Nonblocking");
    let listener_fd = listener.as_raw_fd();
    let mut srv = Srv::new(recursor, &listener);
    let started = Instant::now();
    let mut buf = [0u8; 4096];

    loop {
        if started.elapsed() > duration {
            break;
        }

        let mut fds: Vec<libc::pollfd> = Vec::new();
        let mut map: Vec<usize> = Vec::new();
        for (i, s) in srv.slots.iter().enumerate() {
            if let Some(slot) = s {
                if slot.parked.is_none() {
                    fds.push(libc::pollfd {
                        fd: slot.session.sock.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    });
                    map.push(i);
                }
            }
        }

        let listener_pos = if srv.live() < inflight_max {
            fds.push(libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            });
            Some(fds.len() - 1)
        } else {
            None
        };
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
        let now = Instant::now();

        if rc > 0 {
            for (k, &slot_idx) in map.iter().enumerate() {
                if fds[k].revents & libc::POLLIN == 0 {
                    continue;
                }
                let mut pending_end: Option<SessionEnd> = None;
                if let Some(slot) = srv.slots[slot_idx].as_mut() {
                    while let Some(resp) = slot.session.try_recv(recursor) {
                        pending_end = slot.session.on_response(recursor, resp, now);
                        if pending_end.is_some() {
                            break;
                        }
                    }
                }
                if let Some(end) = pending_end {
                    srv.settle(slot_idx, end, now);
                }
            }
        }

        if let Some(pos) = listener_pos {
            if rc > 0 && fds[pos].revents & libc::POLLIN != 0 {
                while srv.live() < inflight_max {
                    match listener.recv_from(&mut buf) {
                        Ok((n, from)) => {
                            let Ok(req) = Message::parse(&buf[..n]) else {
                                continue;
                            };
                            if req.header.response || req.questions.len() != 1 {
                                continue;
                            }
                            let q = &req.questions[0];
                            let client = ClientReq {
                                addr: from,
                                id: req.header.id,
                                questions: req.questions.clone(),
                                rd: req.header.recursion_desired,
                                acc_answers: vec![],
                                cname_hops: 0,
                            };
                            let sf_key = (q.name.canonical_key(), q.qtype);
                            if srv.singleflight {
                                if let Some(&leader) = srv.inflight.get(&sf_key) {
                                    if let Some(slot) = srv.slots[leader].as_mut() {
                                        slot.followers.push(client);
                                        srv.stats.merged += 1;
                                        continue;
                                    }
                                }
                            }
                            match Session::start(recursor, q.name.clone(), q.qtype, now) {
                                Some(session) => {
                                    let idx = srv.insert(Slot {
                                        session,
                                        kind: SlotKind::Root(client),
                                        parked: None,
                                        followers: vec![],
                                    });
                                    if srv.singleflight {
                                        srv.inflight.insert(sf_key, idx);
                                    }
                                }
                                None => {
                                    respond_servfail(&listener, &client);
                                    srv.stats.failed += 1;
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }

        for i in 0..srv.slots.len() {
            let mut end: Option<SessionEnd> = None;
            if let Some(slot) = srv.slots[i].as_mut() {
                if slot.parked.is_some() {
                    continue;
                }
                let past = slot
                    .session
                    .exchange
                    .as_ref()
                    .is_some_and(|ex| now >= ex.deadline);
                if (past && slot.session.on_exchange_timeout(recursor, now).is_err())
                    || now >= slot.session.session_deadline
                {
                    end = Some(SessionEnd::Failed);
                }
            }
            if let Some(e) = end {
                srv.settle(i, e, now);
            }
        }
    }
    srv.stats
}

#[test]
#[ignore]
/** @brief 여러 워커로 실제 서버 모양을 흉내 내 처리량을 측정한다. */
fn reactor_server_probe() {
    let listen: SocketAddr = std::env::var("RP_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:5301".into())
        .parse()
        .expect("RP_LISTEN format");
    let inflight_max = env_usize("RP_INFLIGHT", 32);
    let duration = Duration::from_secs(env_usize("RP_DURATION_SECS", 30) as u64);
    let workers = env_usize("RP_WORKERS", 1).max(1);
    let cpu_base = env_usize("RP_CPU_BASE", 2);
    let shared = env_usize("RP_SHARED", 1) != 0;
    let (recursor, _) = build_recursor();

    let listeners: Vec<std::net::UdpSocket> =
        (0..workers).map(|_| bind_reuseport(listen)).collect();

    let started = Instant::now();
    let totals: Vec<SrvStats> = std::thread::scope(|scope| {
        let handles: Vec<_> = listeners
            .into_iter()
            .enumerate()
            .map(|(w, l)| {
                let r = &recursor;
                scope.spawn(move || {
                    pin_to_core(cpu_base + w);
                    if shared {
                        run_reactor_worker(r, l, inflight_max, duration)
                    } else {
                        let local = build_recursor().0;
                        run_reactor_worker(&local, l, inflight_max, duration)
                    }
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let done: usize = totals.iter().map(|s| s.done).sum();
    let failed: usize = totals.iter().map(|s| s.failed).sum();
    let merged: usize = totals.iter().map(|s| s.merged).sum();
    let per_worker: Vec<String> = totals.iter().map(|s| s.done.to_string()).collect();
    println!(
        "reactor-server: workers={workers} shared={shared} done={done} failed={failed} merged={merged} per_worker=[{}] elapsed={:.1}s inflight={inflight_max} listen={listen}",
        per_worker.join(","),
        started.elapsed().as_secs_f64()
    );
}
