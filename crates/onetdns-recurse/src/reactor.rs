//! Event-driven recursive resolution: one thread runs many resolutions at once, where the sync path
//! holds a thread per resolution. Decisions reuse the sync path's logic, so both paths give the
//! same answer.
//!
//! Bugs here come from lifetimes, not decisions: if slots, deadlines, or budgets are not handed
//! correctly between parent and child, resolutions leak or starve each other.

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

/// Identifies a submitted resolution. The caller picks it and gets it back in the completion.
pub type Token = u64;

pub enum Completion {
    Answer(Token, Message),

    Fail(Token, crate::RecurseError),

    /// The lane cannot handle this; hand it to the sync path.
    Retry(Token),
}

pub enum SubmitOutcome {
    Accepted,

    /// Joined an identical resolution already in flight.
    Merged,

    /// No free slot.
    Rejected,

    /// The resolution could not start.
    Failed,
}

pub struct ReactorConfig {
    pub inflight_max: usize,

    /// Total deadline of one resolution, shared with its children.
    pub session_budget: Duration,

    /// Merge identical in-flight queries, so a burst for one name sends one upstream query.
    pub singleflight: bool,
}

impl Default for ReactorConfig {
    fn default() -> Self {
        Self {
            inflight_max: 32,
            session_budget: Duration::from_secs(5),
            singleflight: true,
        }
    }
}

/// An outstanding query to one server.
struct Attempt {
    /// Kept as sent; replies are matched against it.
    sent: Message,
    target: SocketAddr,
    deadline: Instant,
    sent_at: Instant,
}

/// State of one resolution; the sync path keeps the same things in locals.
struct Session {
    qname: Name,
    qtype: RecordType,
    state: IterationState,
    plan: NextQuery,
    /// Servers to ask at this step, in order.
    ladder: Vec<SocketAddr>,
    /// Index of the next server in `ladder`.
    next_idx: usize,
    per_server: Duration,
    /// Outstanding exchanges. The next server is asked while earlier ones are still pending, so
    /// there can be several; the first usable reply wins. Same rule as the sync path's
    /// `query_any_reserving`.
    attempts: Vec<Attempt>,
    /// Ask the next server too if nothing usable has arrived by then.
    ask_next_at: Instant,
    /// Socket for this resolution alone, which randomizes the source port.
    sock: UdpSocket,

    /// Family of `sock`; a target in the other family needs a new socket.
    sock_v6: bool,
    session_deadline: Instant,
    steps: usize,
    /// Stops the walk even when referrals loop.
    step_cap: usize,
    /// Collect DS evidence at each delegation; set only when validating.
    ///
    /// Children resolving nameserver addresses turn it off: their results are not validated, and
    /// with it on, a zone cut seen in the answer section would push the parent to the sync path to
    /// fetch DS.
    collect_ds: bool,
}

thread_local! {

    static RECV_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 65_535]);
}

/// Non-blocking socket bound for the target's address family.
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

/// Running out of file descriptors fails here first. This runs per query, so only power-of-two
/// counts are logged.
fn record_bind_failure(error: &std::io::Error) {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "recurse.outgoing_bind_failed", count = count, %error, "Could not open a socket for recursive queries");
    }
}

enum SessionEnd {
    Done(Message),
    Failed(crate::RecurseError),

    NeedsSync,
    NeedAddrs {
        missing: Vec<Name>,
        pending: Box<PendingReferral>,
    },
}

/// Result of `settle`.
enum Settled {
    Answer(Message),
    Failed(crate::RecurseError),
    /// The lane cannot finish this; the resolver chain usually does.
    NeedsSync,
}

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
    /// Starts from the cached delegation, else from the root.
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

    /// Sends the next query; an error means no server is left.
    fn send_next(&mut self, r: &Recursor, now: Instant) -> Result<(), crate::RecurseError> {
        self.steps += 1;
        if self.steps > self.step_cap {
            return Err(crate::RecurseError::NoReachableNs);
        }
        let ctx = make_ctx(&self.qname, self.qtype, self.collect_ds);
        self.plan = self.state.next_query(&ctx);
        let ladder = r.ask_order(&self.state.servers, &self.state.zone)?;
        // Reserve time for names whose addresses are not resolved yet. Same rule as the sync path's
        // `query_any_reserving`.
        let candidates = ladder.len() + self.state.unresolved_ns.len();
        self.per_server =
            (r.timeout / candidates.clamp(1, 4) as u32).max(Duration::from_millis(300));
        self.ladder = ladder;
        self.next_idx = 0;
        self.attempts.clear();
        self.fire_next(r, now)
            .map_err(|()| crate::RecurseError::NoReachableNs)
    }

    /// Sends to the next server in `ladder`, recording a server that cannot be sent to as failed
    /// and moving on. Running out of servers is not an error while exchanges are pending. 0x20 case
    /// mixing happens here.
    fn fire_next(&mut self, r: &Recursor, now: Instant) -> Result<(), ()> {
        while let Some(&target) = self.ladder.get(self.next_idx) {
            if !self.attempts.is_empty() && self.sock_v6 != target.is_ipv6() {
                // A new socket cannot receive replies to pending exchanges, so wait for them to
                // finish.
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

    /// Reopens `sock` when the target's family differs; false if that fails.
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

    /// Drops timed-out exchanges as failures, then asks the next server when nothing is pending or
    /// `ask_next_at` has passed. Errors when no server is left and nothing is pending.
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

    /// Earliest exchange deadline or `ask_next_at`.
    fn next_wake(&self) -> Option<Instant> {
        let deadline = self.attempts.iter().map(|attempt| attempt.deadline).min();
        let ask_next = (self.next_idx < self.ladder.len()
            && self.attempts.len() < crate::MAX_EXCHANGES_PER_QUERY)
            .then_some(self.ask_next_at);
        deadline.into_iter().chain(ask_next).min()
    }

    /// Reads a reply and returns it with the exchange it answers.
    ///
    /// Transaction ID, question, and 0x20 case must all match; this is the check that stops forged
    /// replies.
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
                        // A truncated reply has empty sections and fails the checks below. Dropping
                        // it there skips the TCP fallback and waits out the exchange timeout.
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

    /// Advances one step; decisions come from the sync path's `advance`.
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
            // The lane has no separate DS query; this rare zone cut goes to the sync path.
            StepOutcome::NeedDs { .. } => Some(SessionEnd::NeedsSync),
            StepOutcome::Failed(error) => Some(SessionEnd::Failed(error)),
        }
    }

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

/// Context of one client resolution: merged requests and alias-chase progress.
struct RootCtx {
    leader: Token,
    followers: Vec<Token>,

    /// Singleflight index key. Remove it when the resolution ends, or later requests attach to an
    /// orphaned entry.
    sf_key: (Vec<u8>, RecordType),

    /// Answers gathered while following aliases.
    acc_answers: Vec<Record>,
    /// Counted across the whole chain.
    cname_hops: usize,
    dname_hops: usize,

    /// DNSSEC status so far; one broken link breaks the whole chain.
    acc_status: crate::SecurityStatus,
}

enum SlotKind {
    Root(RootCtx),

    /// Resolving a nameserver address for `parent`.
    NsAddr {
        parent: usize,
    },

    /// Fetching a DNSKEY for `parent`'s validation.
    Dnskey {
        parent: usize,
        zone: Name,
    },
}

/// A reply parked until the keys to validate it arrive.
struct AwaitingKeys {
    msg: Message,
    /// Positive and negative replies are validated differently.
    positive: bool,

    /// DNSKEY sets fetched so far; capped by `MAX_KEY_FETCHES`.
    fetches: usize,

    /// Zones already tried, so none is fetched twice.
    tried: Vec<Vec<u8>>,
}

/// A referral parked until its nameserver addresses arrive.
struct Parked {
    pending: Box<PendingReferral>,
    missing: Vec<Name>,
    /// Next name to resolve; children start one at a time.
    next_missing: usize,
    addrs: Vec<SocketAddr>,

    addr_ttl: Option<u32>,
    /// Children started for this referral; they count against the budget.
    children_spawned: usize,
}

struct Slot {
    session: Session,
    kind: SlotKind,
    parked: Option<Parked>,

    awaiting: Option<Box<AwaitingKeys>>,

    /// Side-resolution budget left, inherited from the parent and shared with children.
    ns_budget: usize,
}

/// DNSKEY sets one validation may fetch, so a long chain cannot pin this server.
const MAX_KEY_FETCHES: usize = 20;

/// One event-driven lane running many resolutions at once, one per worker thread. It takes no
/// locks, so it is never shared between threads.
pub struct Reactor {
    cfg: ReactorConfig,
    slots: Vec<Option<Slot>>,
    free: Vec<usize>,

    /// Singleflight index: query key to slot.
    inflight: HashMap<(Vec<u8>, RecordType), usize>,

    pub merged: u64,
    pub completed: u64,
    pub failed: u64,

    /// Resolutions handed to the sync path.
    pub retried: u64,
}

impl Reactor {
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

    /// `slots` never shrinks and every emptied index goes to `free`, so this subtracts instead of
    /// scanning; it runs for every admitted packet. `free` has no duplicates, and each slot it
    /// names is `None`.
    pub fn live(&self) -> usize {
        self.slots.len() - self.free.len()
    }

    pub fn has_capacity(&self) -> bool {
        self.live() < self.cfg.inflight_max
    }

    /// Slot limit including children: twice the client limit.
    fn slot_max(&self) -> usize {
        self.cfg.inflight_max.saturating_mul(2)
    }

    /// Checked against `slot_max`, not the client limit. With one shared limit, parents fill every
    /// slot, cannot start children, and deadlock waiting for them.
    fn has_child_capacity(&self) -> bool {
        self.live() < self.slot_max()
    }

    /// Time left for a child; never past the parent's deadline.
    fn child_budget(&self, parent: usize, now: Instant) -> Option<Duration> {
        let remaining = self.slots[parent]
            .as_ref()?
            .session
            .session_deadline
            .saturating_duration_since(now);
        (!remaining.is_zero()).then_some(remaining)
    }

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

    /// Submits a resolution, joining an identical query already in flight instead of sending it
    /// again.
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
        // The lane sends only UDP, so the sync path takes over while authorities must be asked over
        // TCP.
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

    /// Removes the singleflight entry only if it still points at `idx`; otherwise it would remove
    /// the entry of another resolution that reused the slot.
    fn forget_inflight(&mut self, key: &(Vec<u8>, RecordType), idx: usize) {
        if self.inflight.get(key) == Some(&idx) {
            self.inflight.remove(key);
        }
    }

    /// Collects the sockets of slots waiting on the network, for the caller to poll in one call;
    /// `map[i]` is the slot of `fds[i]`.
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

    /// Reads replies from ready sockets and advances their resolutions.
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

    /// Expires timed-out exchanges and resolutions past their deadline.
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
                        // Every server of this zone failed and some names still lack addresses. The
                        // lane cannot go back and resolve them, so the sync path takes over.
                        SessionEnd::NeedsSync
                    });
                }
            }
            if let Some(e) = end {
                self.settle(r, i, e, now, out);
            }
        }
    }

    /// Time until the nearest deadline; sets the caller's poll timeout.
    pub fn next_deadline_in(&self, now: Instant) -> Option<Duration> {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.parked.is_none())
            .filter_map(|s| s.session.next_wake())
            .min()
            .map(|d| d.saturating_duration_since(now))
    }

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

    /// Starts a side resolution in a child slot, with budget and deadline inherited from the
    /// parent.
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

    /// A root may chase an alias; a child wakes its parent. Either way the singleflight entry and
    /// the slot must be released, or the slot leaks.
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
    /// Finalizes the answer for its requesters. When validation needs keys that are missing, parks
    /// here and fetches them, since the lane cannot query inline like the sync path.
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

    /// Hands this resolution to the sync path.
    fn retry_root(&mut self, root: &RootCtx, out: &mut Vec<Completion>) {
        for f in &root.followers {
            out.push(Completion::Retry(*f));
            self.retried += 1;
        }
        out.push(Completion::Retry(root.leader));
        self.retried += 1;
    }

    /// Fails this resolution and every request merged into it.
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

        // Once a usable address exists, descend without resolving the remaining names. If those
        // addresses all fail, the sync path resolves the rest.
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
    /// Follows an alias with a new resolution in the same slot, keeping the accumulated state.
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
mod tests {
    use super::*;
    use onetdns_proto::{DnsClass, Header, Question, ResponseCode};

    fn spawn_mock_authority() -> SocketAddr {
        spawn_mock_authority_forging_ad(false)
    }

    fn spawn_mock_authority_forging_ad(forge_ad: bool) -> SocketAddr {
        spawn_mock_answering(
            forge_ad,
            std::net::Ipv4Addr::new(192, 0, 2, 7),
            Duration::ZERO,
        )
    }

    /// Answers every query authoritatively with `address`, after `delay`.
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
    fn reactor_hands_truncated_response_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            authority_reply(req, true, true)
        }));
    }

    #[test]
    /// This reply fails the usable-for-iteration check. Unless truncation is checked first, the
    /// exchange waits out its timeout and fails.
    fn reactor_hands_empty_truncated_response_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            authority_reply(req, true, false)
        }));
    }

    #[test]
    fn reactor_hands_reply_cut_without_tc_to_sync_path() {
        assert_handed_to_sync_path(spawn_mock_authority_replying(|req| {
            let full = authority_reply(req, false, true);
            full[..full.len() - 3].to_vec()
        }));
    }

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
    /// A target in another family must reopen the socket.
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
    /// A child that took a fresh deadline would stretch the chain without bound.
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
    fn reactor_shares_one_deadline_across_the_alias_chain() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        const HOP_DELAY: Duration = Duration::from_millis(100);

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
    fn reactor_counts_dname_hops_against_the_dname_limit() {
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
    /// A leftover entry would attach the next request to an orphan.
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
    /// Same rule as the sync path's `a_slow_server_is_raced_by_the_next_one`; waiting out the first
    /// server would add its whole delay.
    fn reactor_races_a_slow_server_with_the_next_one() {
        /// Must be shorter than the per-server timeout.
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
    /// Same rule as the sync path's `a_query_waits_on_at_most_two_exchanges_at_once`. The first two
    /// servers stay silent, so the third is asked only after one of them times out.
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
