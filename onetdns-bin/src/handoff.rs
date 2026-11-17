//! Handing a running generation over to its successor: the listening sockets, carried without
//! closing them so the queries queued on a socket are answered by whoever serves it next, the
//! channel between the two, and the order in which the successor takes over.

use std::net::{SocketAddr, TcpListener, UdpSocket};
#[cfg(not(any(target_os = "linux", windows)))]
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_config::Config;
use onetdns_control::{PersistOpts, Recorder, Stats};
use onetdns_core::MutexExt;
use zeroize::Zeroizing;

use crate::config_apply::{install_restart, SecondaryRestart};
use crate::listeners::{ListenerSet, TicketKeys, TlsSlots};
use crate::GenerationJobs;

#[cfg(any(target_os = "linux", windows))]
pub(crate) mod wire;

/// What a listening socket serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketRole {
    Do53,
    Dot,
    Doh,
    Doq,
    Doh3,
    Dnscrypt,
    /// The dashboard and management API.
    Control,
}

#[derive(Debug)]
pub(crate) enum ListeningSocket {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

/// Sockets that are open but not served, keyed by role and bound address, and the keys clients hold
/// on to. A listener opening an address takes its sockets and keys from here before it binds.
///
/// Port 0 never matches: the configured address then differs from the bound one, and the listener
/// binds a new socket.
#[derive(Default)]
pub(crate) struct SocketPool {
    entries: Vec<(SocketRole, SocketAddr, ListeningSocket)>,
    /// The resolver key each DNSCrypt address answered with.
    dnscrypt_keys: Vec<(SocketAddr, Zeroizing<[u8; 32]>)>,
    tickets: TicketKeys,
}

/// Leaves the keys out.
impl std::fmt::Debug for SocketPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketPool")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl SocketPool {
    pub(crate) fn put_dnscrypt_key(&mut self, addr: SocketAddr, secret: Zeroizing<[u8; 32]>) {
        self.dnscrypt_keys.push((addr, secret));
    }

    pub(crate) fn take_dnscrypt_key(&mut self, addr: SocketAddr) -> Option<Zeroizing<[u8; 32]>> {
        let at = self
            .dnscrypt_keys
            .iter()
            .position(|(bound, _)| *bound == addr)?;
        Some(self.dnscrypt_keys.swap_remove(at).1)
    }

    pub(crate) fn put_ticket_keys(&mut self, keys: TicketKeys) {
        self.tickets = keys;
    }

    pub(crate) fn take_ticket_keys(&mut self) -> TicketKeys {
        std::mem::take(&mut self.tickets)
    }

    pub(crate) fn put(&mut self, role: SocketRole, addr: SocketAddr, socket: ListeningSocket) {
        self.entries.push((role, addr, socket));
    }

    /// Every UDP socket for `role` at `addr`; several when they form a reuseport group.
    pub(crate) fn take_udp(&mut self, role: SocketRole, addr: SocketAddr) -> Vec<UdpSocket> {
        self.take(role, addr, |socket| match socket {
            ListeningSocket::Udp(socket) => Ok(socket),
            other => Err(other),
        })
    }

    /// Every TCP socket for `role` at `addr`; several when they form a reuseport group.
    pub(crate) fn take_tcp(&mut self, role: SocketRole, addr: SocketAddr) -> Vec<TcpListener> {
        self.take(role, addr, |socket| match socket {
            ListeningSocket::Tcp(socket) => Ok(socket),
            other => Err(other),
        })
    }

    fn take<T>(
        &mut self,
        role: SocketRole,
        addr: SocketAddr,
        mut kind: impl FnMut(ListeningSocket) -> Result<T, ListeningSocket>,
    ) -> Vec<T> {
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(self.entries.len());
        for (entry_role, entry_addr, socket) in self.entries.drain(..) {
            if entry_role != role || entry_addr != addr {
                kept.push((entry_role, entry_addr, socket));
                continue;
            }
            match kind(socket) {
                Ok(socket) => taken.push(socket),
                Err(socket) => kept.push((entry_role, entry_addr, socket)),
            }
        }
        self.entries = kept;
        taken
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Role and address of each socket, for logs.
    pub(crate) fn describe(&self) -> String {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|(role, addr, socket)| {
                let kind = match socket {
                    ListeningSocket::Udp(_) => "udp",
                    ListeningSocket::Tcp(_) => "tcp",
                };
                format!("{role:?}/{kind}/{addr}")
            })
            .collect();
        names.dedup();
        names.join(",")
    }
}

/// Sent by the running generation to its successor.
#[derive(Debug)]
pub(crate) enum FromPredecessor {
    /// Duplicates of the listening sockets, with the keys clients hold on to. The QUIC sockets are
    /// no longer read on this side.
    Sockets(SocketPool),
    /// Nothing that only one process may run is running on this side any more.
    Released(Carried),
}

/// What the predecessor counted, handed over once it has stopped serving.
#[derive(Debug, Default)]
pub(crate) struct Carried {
    /// `Recorder::export_state`; None when the predecessor could not export it.
    pub(crate) stats: Option<Vec<u8>>,
    /// The upstream statistics in their file format; None without a forwarding resolver.
    pub(crate) upstreams: Option<String>,
    /// `Auth::export_sessions`.
    pub(crate) sessions: Option<Vec<u8>>,
    /// `JobRegistry::export`.
    pub(crate) jobs: Option<String>,
}

/// Sent by the successor to the running generation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FromSuccessor {
    /// Everything is built; asks for the sockets.
    Request,
    /// Reads the sockets it was given.
    Reading,
    /// Runs everything; the predecessor may end.
    Ready,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkError {
    /// The other side dropped its end.
    Gone,
    TimedOut,
    /// The waiting side was told to stop.
    Aborted,
    /// The other side sent something this process cannot read.
    #[cfg(any(target_os = "linux", windows))]
    Unreadable,
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LinkError::Gone => "the other process ended",
            LinkError::TimedOut => "the other process did not answer in time",
            LinkError::Aborted => "stopped while waiting",
            #[cfg(any(target_os = "linux", windows))]
            LinkError::Unreadable => "the other process sent a message this one cannot read",
        })
    }
}

/// How often a wait checks whether to give up.
const LINK_POLL: Duration = Duration::from_millis(200);

/// One end of the channel between a running generation and its successor.
pub(crate) struct Link<Out, In> {
    #[cfg(any(target_os = "linux", windows))]
    stream: wire::Stream,
    #[cfg(any(target_os = "linux", windows))]
    messages: std::marker::PhantomData<fn(Out) -> In>,
    #[cfg(not(any(target_os = "linux", windows)))]
    tx: mpsc::Sender<Out>,
    #[cfg(not(any(target_os = "linux", windows)))]
    rx: mpsc::Receiver<In>,
}

/// Held by the running generation.
pub(crate) type SuccessorLink = Link<FromPredecessor, FromSuccessor>;
/// Held by the successor.
pub(crate) type PredecessorLink = Link<FromSuccessor, FromPredecessor>;

/// Both ends in one process.
#[cfg(all(test, any(target_os = "linux", windows)))]
pub(crate) fn link() -> (SuccessorLink, PredecessorLink) {
    let (predecessor, successor) = wire::stream_pair();
    (Link::over(predecessor), Link::over(successor))
}

/// Both ends in one process.
#[cfg(all(test, not(any(target_os = "linux", windows))))]
pub(crate) fn link() -> (SuccessorLink, PredecessorLink) {
    let (to_successor, from_predecessor) = mpsc::channel();
    let (to_predecessor, from_successor) = mpsc::channel();
    (
        Link {
            tx: to_successor,
            rx: from_successor,
        },
        Link {
            tx: to_predecessor,
            rx: from_predecessor,
        },
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
impl<Out, In> Link<Out, In> {
    pub(crate) fn send(&self, message: Out) -> Result<(), LinkError> {
        self.tx.send(message).map_err(|_| LinkError::Gone)
    }

    /// The next message, waiting until `deadline` or until `abort` returns true.
    pub(crate) fn recv(
        &self,
        deadline: Instant,
        abort: &dyn Fn() -> bool,
    ) -> Result<In, LinkError> {
        loop {
            if abort() {
                return Err(LinkError::Aborted);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(LinkError::TimedOut);
            }
            match self.rx.recv_timeout(left.min(LINK_POLL)) {
                Ok(message) => return Ok(message),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(LinkError::Gone),
            }
        }
    }
}

/// The handoff links of this process, kept across its generations.
#[derive(Default)]
pub(crate) struct Links {
    /// Set when this process starts as a successor; its first generation takes it.
    pub(crate) predecessor: Mutex<Option<PredecessorLink>>,
    /// Set when a successor asks to take over; the running generation takes it.
    pub(crate) successor: Mutex<Option<SuccessorLink>>,
}

type RestartSlot = Arc<Mutex<Option<SecondaryRestart>>>;

/// What only one process may run: edge services, DHCP lease sync, secondary zone refresh, ZSK
/// rollover, the singleton jobs, the management API and Raft. A generation that starts fresh runs
/// each part as it installs it; a successor installs them all first and runs them once its
/// predecessor has released its own.
pub(crate) struct Exclusive {
    slots: Vec<RestartSlot>,
    deferred: bool,
    jobs: GenerationJobs,
}

impl Exclusive {
    pub(crate) fn new(jobs: GenerationJobs, deferred: bool) -> Self {
        Self {
            slots: Vec::new(),
            deferred,
            jobs,
        }
    }

    pub(crate) fn deferred(&self) -> bool {
        self.deferred
    }

    /// `install_restart`, except that a successor only stores the hook.
    pub(crate) fn install(
        &mut self,
        slot: &RestartSlot,
        hook: SecondaryRestart,
        cfg: &Config,
    ) -> Result<(), String> {
        self.slots.push(slot.clone());
        if self.deferred {
            *slot.lock_recover() = Some(hook);
            return Ok(());
        }
        install_restart(slot, hook, cfg)
    }

    /// For a part whose first start differs from its restart: stores the restart, and returns
    /// whether the caller starts the part now.
    pub(crate) fn install_restart_only(
        &mut self,
        slot: &RestartSlot,
        hook: SecondaryRestart,
    ) -> bool {
        self.slots.push(slot.clone());
        *slot.lock_recover() = Some(hook);
        !self.deferred
    }

    /// Runs every hook in the order installed.
    fn start(&self, cfg: &Config) -> Result<(), String> {
        for slot in &self.slots {
            run_restart(slot, cfg)?;
        }
        Ok(())
    }

    /// Stops all of it and waits for its threads, so none still writes a file or holds a port when
    /// the successor starts its own.
    fn release(&self, cfg: &Config) {
        for group in [
            &self.jobs.edge,
            &self.jobs.lease_sync,
            &self.jobs.secondary,
            &self.jobs.zsk_rollover,
            &self.jobs.singletons,
            &self.jobs.control,
        ] {
            group.retire_all();
        }
        // Raft runs once per process, so only the generation that started it stops it.
        if cfg.cluster_raft {
            crate::cluster::stop_raft();
        }
    }
}

/// Saving statistics and the query log is exclusive too: two processes would overwrite each other's
/// files. A successor starts without it and turns it on once it has added its predecessor's counts.
pub(crate) fn persistence_restart(stats: Stats) -> SecondaryRestart {
    Arc::new(move |cfg: &Config| {
        stats
            .reconfigure_persist(crate::hot_apply::persist_opts(cfg))
            .map_err(|error| format!("Could not save the statistics or the query log: {error}"))
    })
}

/// Runs the hook with its slot locked, as `install_restart` does.
fn run_restart(slot: &RestartSlot, cfg: &Config) -> Result<(), String> {
    let hook = slot.lock_recover();
    hook.as_ref().map_or(Ok(()), |hook| hook(cfg))
}

/// What a generation hands to its successor, or takes from its predecessor.
pub(crate) struct Handoff {
    pub(crate) listeners: Arc<ListenerSet>,
    /// Matches the listeners to the config.
    pub(crate) listeners_slot: RestartSlot,
    /// The listeners the dashboard shows.
    pub(crate) registry: Arc<Mutex<Vec<(&'static str, String, String)>>>,
    pub(crate) control_listener: Arc<Mutex<Option<TcpListener>>>,
    pub(crate) exclusive: Exclusive,
    pub(crate) recorder: Recorder,
    pub(crate) stats: Stats,
    pub(crate) auth: Arc<onetdns_control::Auth>,
    pub(crate) jobs: Arc<crate::JobRegistry>,
    pub(crate) tls_slots: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    pub(crate) forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
    /// What the forwarding resolver was seeded with from the saved upstream statistics.
    pub(crate) upstream_seed: Vec<onetdns_forward::UpstreamStatReport>,
    pub(crate) upstream_stats_path: Option<std::path::PathBuf>,
}

impl Handoff {
    /// Serves the predecessor's sockets, then starts the exclusive part once the predecessor has
    /// released its own. If the predecessor ends first, opens the listening addresses itself.
    pub(crate) fn take_over(
        &self,
        link: &PredecessorLink,
        listeners_restart: SecondaryRestart,
        cfg: &Config,
        abort: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let handed = link
            .send(FromSuccessor::Request)
            .and_then(|()| link.recv(step_deadline(), abort));
        match handed {
            Ok(FromPredecessor::Sockets(mut pool)) => {
                if let Some(addr) = cfg.control_listen {
                    if let Some(socket) = pool.take_tcp(SocketRole::Control, addr).pop() {
                        *self.control_listener.lock_recover() = Some(socket);
                    }
                }
                self.listeners.adopt(pool);
            }
            Ok(FromPredecessor::Released(_)) => return Err(OUT_OF_ORDER.to_string()),
            Err(LinkError::Gone) => onetdns_core::info!(
                event = "handoff.predecessor_gone",
                "The previous process ended before handing over its sockets; opening the listening addresses"
            ),
            Err(error) => {
                return Err(format!(
                    "Could not take over from the previous process: {error}"
                ))
            }
        }
        install_restart(&self.listeners_slot, listeners_restart, cfg)?;
        self.listeners.drop_unclaimed();
        let released = link
            .send(FromSuccessor::Reading)
            .and_then(|()| link.recv(step_deadline(), abort));
        match released {
            Ok(FromPredecessor::Released(carried)) => self.carry_in(carried, cfg),
            Err(LinkError::Gone) => self.carry_in(Carried::default(), cfg),
            Ok(FromPredecessor::Sockets(_)) => return Err(OUT_OF_ORDER.to_string()),
            Err(error) => {
                return Err(format!(
                    "The previous process did not release its services: {error}"
                ))
            }
        }
        self.exclusive.start(cfg)
    }

    /// Hands the sockets and the exclusive part to the successor at the other end of `link`. True
    /// when this generation ends: the successor runs everything, or the supervisor says it does.
    /// Otherwise this generation takes back what it handed over and goes on.
    pub(crate) fn hand_over(
        &self,
        link: &SuccessorLink,
        cfg: &Config,
        abort: &dyn Fn() -> bool,
    ) -> bool {
        let Some(kept) = self.give_all(link, cfg, abort) else {
            let ends = crate::supervisor::settle(false, abort);
            if ends {
                onetdns_core::info!(
                    event = "handoff.superseded",
                    "The new process took over without this one; this process ends"
                );
            }
            return ends;
        };
        if crate::supervisor::settle(true, abort) {
            onetdns_core::info!(
                event = "handoff.completed",
                "Handed the DNS service over to the new process"
            );
            return true;
        }
        onetdns_core::warn!(
            event = "handoff.cancelled",
            "The new process stopped after taking over and the update was put back; this process serves again"
        );
        self.take_back(kept, true, cfg);
        false
    }

    /// The pool kept back, once the successor runs everything. Otherwise this generation has taken
    /// back what it handed over.
    fn give_all(
        &self,
        link: &SuccessorLink,
        cfg: &Config,
        abort: &dyn Fn() -> bool,
    ) -> Option<SocketPool> {
        if let Err(error) = expect(link, FromSuccessor::Request, abort) {
            onetdns_core::warn!(event = "handoff.not_requested", %error, "The new process did not ask for the listening sockets; this process keeps serving");
            return None;
        }
        let (kept, handed) = match self.export() {
            Ok(pools) => pools,
            Err(error) => {
                onetdns_core::warn!(event = "handoff.export_failed", %error, "Could not duplicate the listening sockets for the new process; this process keeps serving");
                return None;
            }
        };
        // On Windows a socket read on both sides cannot be stopped reliably, so every listener here
        // stops before the successor reads.
        if cfg!(windows) {
            self.listeners.stop_reading();
        } else {
            self.listeners.stop_reading_quic();
        }
        let mut released = false;
        match self.give(link, handed, cfg, abort, &mut released) {
            Ok(()) => Some(kept),
            Err(error) => {
                onetdns_core::warn!(event = "handoff.failed", %error, "Could not hand the DNS service over to the new process; this process serves again");
                self.take_back(kept, released, cfg);
                None
            }
        }
    }

    fn give(
        &self,
        link: &SuccessorLink,
        handed: SocketPool,
        cfg: &Config,
        abort: &dyn Fn() -> bool,
        released: &mut bool,
    ) -> Result<(), String> {
        link.send(FromPredecessor::Sockets(handed))
            .map_err(|error| error.to_string())?;
        expect(link, FromSuccessor::Reading, abort)?;
        self.listeners.stop_reading();
        self.exclusive.release(cfg);
        *released = true;
        link.send(FromPredecessor::Released(self.carry_out()))
            .map_err(|error| error.to_string())?;
        expect(link, FromSuccessor::Ready, abort)
    }

    /// Stops saving statistics, which writes the last state, and exports them. Saving resumes with
    /// the exclusive part if the handoff fails.
    fn carry_out(&self) -> Carried {
        if let Err(error) = self.stats.reconfigure_persist(PersistOpts::default()) {
            onetdns_core::warn!(event = "handoff.stats_not_saved", %error, "Could not save the last statistics and query log before handing them over");
        }
        let stats = self
            .recorder
            .export_state()
            .map_err(|error| {
                onetdns_core::warn!(event = "handoff.stats_not_exported", %error, "Could not hand over the statistics; the new process reads the saved ones");
            })
            .ok();
        let upstreams = self
            .forward_stats
            .lock_recover()
            .as_ref()
            .map(|forward| crate::upstream_stats::upstream_stats_json(&forward.snapshot()));
        Carried {
            stats,
            upstreams,
            sessions: Some(self.auth.export_sessions()),
            jobs: Some(self.jobs.export()),
        }
    }

    /// Adds the predecessor's statistics to what this process counted, or the saved ones when it
    /// handed over none this process can read.
    fn carry_in(&self, carried: Carried, cfg: &Config) {
        self.carry_stats_in(carried.stats, cfg);
        self.carry_upstreams_in(carried.upstreams);
        self.carry_sessions_in(carried.sessions);
        self.carry_jobs_in(carried.jobs);
    }

    fn carry_stats_in(&self, state: Option<Vec<u8>>, cfg: &Config) {
        let saved = || {
            self.recorder
                .merge_saved(&crate::hot_apply::persist_opts(cfg))
        };
        let merged = match state {
            Some(state) => self.recorder.merge_state(&state).or_else(|error| {
                onetdns_core::warn!(event = "handoff.stats_unreadable", %error, "Could not read the statistics the previous process handed over; adding the saved ones instead");
                saved()
            }),
            None => saved(),
        };
        if let Err(error) = merged {
            onetdns_core::warn!(event = "handoff.stats_not_merged", %error, "Could not add the previous process's statistics; they start over from zero");
        }
    }

    /// This process was seeded from the saved upstream statistics, so it adds only what the
    /// predecessor observed after they were saved. The predecessor saves once more as it releases,
    /// so the file stands in for statistics it could not hand over.
    fn carry_upstreams_in(&self, handed: Option<String>) {
        let Some(forward) = self.forward_stats.lock_recover().clone() else {
            return;
        };
        let saved = || {
            self.upstream_stats_path
                .as_deref()
                .map(crate::upstream_stats::load_upstream_stats)
                .unwrap_or_default()
        };
        let reports = match handed {
            Some(text) => crate::upstream_stats::parse_upstream_stats(&text).unwrap_or_else(|error| {
                onetdns_core::warn!(event = "handoff.upstream_stats_unreadable", %error, "Could not read the upstream DNS server statistics the previous process handed over; adding the saved ones instead");
                saved()
            }),
            None => saved(),
        };
        forward.add(&crate::upstream_stats::observed_since(
            reports,
            &self.upstream_seed,
        ));
    }

    /// Sign-ins live only in memory; without the predecessor's, users sign in again.
    fn carry_sessions_in(&self, handed: Option<Vec<u8>>) {
        let Some(state) = handed else {
            return;
        };
        if let Err(error) = self.auth.adopt_sessions(&state) {
            onetdns_core::warn!(event = "handoff.sessions_unreadable", %error, "Could not read the dashboard sign-ins the previous process handed over; users sign in again");
        }
    }

    /// The dashboard follows a job by its ID, also across the switch.
    fn carry_jobs_in(&self, handed: Option<String>) {
        let Some(state) = handed else {
            return;
        };
        if let Err(error) = self.jobs.adopt(&state) {
            onetdns_core::warn!(event = "handoff.jobs_unreadable", %error, "Could not read the job list the previous process handed over; jobs it started no longer show");
        }
    }

    /// One pool to hand over and one to keep, so this generation can serve again if the successor
    /// fails. Only the handed one carries the ticket keys: this generation's TLS slots outlive its
    /// listeners.
    fn export(&self) -> std::io::Result<(SocketPool, SocketPool)> {
        let kept = self.listeners.export()?;
        let mut handed = self.listeners.export()?;
        if let Some(control) = self.control_listener.lock_recover().as_ref() {
            handed.put(
                SocketRole::Control,
                control.local_addr()?,
                ListeningSocket::Tcp(control.try_clone()?),
            );
        }
        if let Some(slots) = self.tls_slots.lock_recover().as_ref() {
            handed.put_ticket_keys(slots.ticket_keys());
        }
        Ok((kept, handed))
    }

    /// Serves again from the sockets kept back, and restarts the exclusive part if it was released.
    fn take_back(&self, kept: SocketPool, released: bool, cfg: &Config) {
        self.listeners.close_all();
        self.registry.lock_recover().clear();
        self.listeners.adopt(kept);
        if let Err(error) = run_restart(&self.listeners_slot, cfg) {
            onetdns_core::error!(event = "handoff.listeners_not_restored", %error, "Could not reopen every listening address after the handoff failed");
        }
        self.listeners.drop_unclaimed();
        if released {
            if let Err(error) = self.exclusive.start(cfg) {
                onetdns_core::error!(event = "handoff.services_not_restored", %error, "Could not restart every service after the handoff failed");
            }
        }
    }
}

const OUT_OF_ORDER: &str = "The other process sent its handoff messages out of order";

/// Each step may wait as long as a trial may run.
fn step_deadline() -> Instant {
    Instant::now() + crate::update::trial::TRIAL_DEADLINE
}

fn expect(
    link: &SuccessorLink,
    wanted: FromSuccessor,
    abort: &dyn Fn() -> bool,
) -> Result<(), String> {
    match link.recv(step_deadline(), abort) {
        Ok(got) if got == wanted => Ok(()),
        Ok(_) => Err(OUT_OF_ORDER.to_string()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_only_the_matching_role_address_and_kind() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let mut pool = SocketPool::default();
        pool.put(SocketRole::Do53, udp_addr, ListeningSocket::Udp(udp));
        pool.put(SocketRole::Dot, tcp_addr, ListeningSocket::Tcp(tcp));

        assert!(pool.take_tcp(SocketRole::Do53, udp_addr).is_empty());
        assert!(pool.take_udp(SocketRole::Doq, udp_addr).is_empty());
        assert_eq!(pool.take_udp(SocketRole::Do53, udp_addr).len(), 1);
        assert!(pool.take_udp(SocketRole::Do53, udp_addr).is_empty());
        assert!(!pool.is_empty());
        assert_eq!(pool.take_tcp(SocketRole::Dot, tcp_addr).len(), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn a_wait_ends_with_the_message_the_deadline_the_abort_or_the_other_side_leaving() {
        let never = || false;
        let (successor, predecessor) = link();
        successor
            .send(FromPredecessor::Released(Carried::default()))
            .unwrap();
        assert!(matches!(
            predecessor.recv(Instant::now() + Duration::from_secs(5), &never),
            Ok(FromPredecessor::Released(_))
        ));

        let started = Instant::now();
        assert_eq!(
            successor
                .recv(Instant::now() + Duration::from_millis(50), &never)
                .unwrap_err(),
            LinkError::TimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            successor
                .recv(Instant::now() + Duration::from_secs(5), &|| true)
                .unwrap_err(),
            LinkError::Aborted
        );

        drop(predecessor);
        assert_eq!(
            successor
                .recv(Instant::now() + Duration::from_secs(5), &never)
                .unwrap_err(),
            LinkError::Gone
        );
        assert_eq!(
            successor
                .send(FromPredecessor::Released(Carried::default()))
                .unwrap_err(),
            LinkError::Gone
        );
    }

    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const OLD_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const NEW_ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    /// Answers names under handover.test with `answer` on `dns`.
    fn config(dns: SocketAddr, answer: Ipv4Addr, extra: &str) -> Config {
        Config::from_toml_str(&format!(
            "listen = [\"{dns}\"]\n\
             workers = 2\n\
             backend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\n\
             block_rules = [\"||handover.test^\"]\n\
             block_response = \"custom\"\n\
             block_ipv4 = \"{answer}\"\n{extra}"
        ))
        .unwrap()
    }

    struct Running {
        thread: std::thread::JoinHandle<crate::error::BoxResult<bool>>,
        ready: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    }

    fn start(cfg: Config, config_path: Option<PathBuf>, shared: crate::ServeShared) -> Running {
        let ready = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (ready, stop) = (ready.clone(), stop.clone());
            std::thread::spawn(move || {
                crate::serve(
                    cfg,
                    None,
                    config_path,
                    shared,
                    Some(stop),
                    Some(Box::new(move || ready.store(true, Ordering::SeqCst))),
                )
            })
        };
        Running {
            thread,
            ready,
            stop,
        }
    }

    /// Starts a successor of the generation that owns `links`.
    fn start_successor(
        cfg: Config,
        config_path: Option<PathBuf>,
        links: &Links,
        shared: crate::ServeShared,
    ) -> Running {
        let (successor, predecessor) = link();
        *shared.links.predecessor.lock_recover() = Some(predecessor);
        *links.successor.lock_recover() = Some(successor);
        start(cfg, config_path, shared)
    }

    fn wait_until(failure: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < deadline, "{failure}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Each TCP query leaves a client port in TIME_WAIT for a minute or two; without a pause, a few
    /// runs use up the machine's dynamic ports.
    const PACE: Duration = Duration::from_millis(10);

    /// The tests that put a generation under load run one at a time, so they neither pick the same
    /// port nor add up their client ports.
    fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        SERIAL.lock_recover()
    }

    /// Clients asking over UDP and TCP until stopped, counting who answered.
    struct Load {
        stop: Arc<AtomicBool>,
        clients: Vec<std::thread::JoinHandle<()>>,
        failed_udp: Arc<AtomicUsize>,
        failed_tcp: Arc<AtomicUsize>,
        by_old: Arc<AtomicUsize>,
        by_new: Arc<AtomicUsize>,
    }

    impl Load {
        fn start(dns: SocketAddr) -> Self {
            use crate::listeners::tests::{ask_tcp, ask_udp};
            let stop = Arc::new(AtomicBool::new(false));
            let [failed_udp, failed_tcp, by_old, by_new] =
                std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
            let clients = (0..4u16)
                .map(|client| {
                    let (stop, by_old, by_new) = (stop.clone(), by_old.clone(), by_new.clone());
                    let (failed_udp, failed_tcp) = (failed_udp.clone(), failed_tcp.clone());
                    std::thread::spawn(move || {
                        let mut sent = 0u16;
                        while !stop.load(Ordering::Acquire) {
                            sent = sent.wrapping_add(1);
                            let id = client * 10_000 + sent % 10_000;
                            let name = format!("q{id}.handover.test");
                            let over_udp = sent % 2 == 0;
                            let answer = if over_udp {
                                ask_udp(dns, id, &name)
                            } else {
                                ask_tcp(dns, id, &name)
                            };
                            let counter = match answer {
                                Some(OLD_ANSWER) => &by_old,
                                Some(NEW_ANSWER) => &by_new,
                                _ if over_udp => &failed_udp,
                                _ => &failed_tcp,
                            };
                            counter.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(PACE);
                        }
                    })
                })
                .collect();
            let load = Self {
                stop,
                clients,
                failed_udp,
                failed_tcp,
                by_old,
                by_new,
            };
            load.wait_for_more(&load.by_old, "the running generation did not answer");
            load
        }

        fn wait_for_more(&self, counter: &AtomicUsize, failure: &str) {
            let before = counter.load(Ordering::Relaxed);
            wait_until(failure, || counter.load(Ordering::Relaxed) > before);
        }

        /// Stops the clients; returns the failed UDP and TCP queries.
        fn finish(self) -> (usize, usize) {
            self.stop.store(true, Ordering::Release);
            for client in self.clients {
                client.join().unwrap();
            }
            (
                self.failed_udp.load(Ordering::Relaxed),
                self.failed_tcp.load(Ordering::Relaxed),
            )
        }
    }

    /// Free for both UDP and TCP, and released at once for the server to bind.
    fn dns_addr() -> SocketAddr {
        crate::tests::tcp_udp_test_listeners().2
    }

    /// Starts a generation and waits until it serves.
    fn start_serving(
        cfg: Config,
        config_path: Option<PathBuf>,
        shared: crate::ServeShared,
    ) -> Running {
        let running = start(cfg, config_path, shared);
        wait_until("the running generation did not start", || {
            running.ready.load(Ordering::SeqCst) || running.thread.is_finished()
        });
        if running.thread.is_finished() {
            let ended = running.thread.join().unwrap();
            panic!("the running generation ended: {:?}", ended.err());
        }
        running
    }

    #[test]
    /// A successor started in the same process takes over the running generation while clients keep
    /// asking over UDP and TCP. Every query is answered, the successor answers in the end, and the
    /// running generation returns once the successor is ready.
    fn a_successor_takes_over_a_running_generation_without_dropping_queries() {
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(dns, OLD_ANSWER, ""), None, old_shared);
        let load = Load::start(dns);

        let new = start_successor(
            config(dns, NEW_ANSWER, ""),
            None,
            &old_links,
            crate::ServeShared::default(),
        );
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        assert!(
            new.ready.load(Ordering::SeqCst),
            "the successor is not ready"
        );
        let reload = old
            .thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        assert!(
            !reload,
            "the running generation asked for a reload instead of ending"
        );
        load.wait_for_more(&load.by_new, "the successor did not answer");

        let failed = load.finish();
        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
        assert_eq!(failed, (0, 0), "queries went unanswered (UDP, TCP)");
    }

    #[test]
    /// The successor takes the sockets, then fails to start what only one process may run. The
    /// running generation serves again, and no query goes unanswered on the way there and back.
    fn a_failed_successor_hands_the_service_back() {
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let busy = TcpListener::bind("127.0.0.1:0").unwrap();
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(dns, OLD_ANSWER, ""), None, old_shared);
        let load = Load::start(dns);

        let failing = format!("control_listen = \"{}\"\n", busy.local_addr().unwrap());
        let new = start_successor(
            config(dns, NEW_ANSWER, &failing),
            None,
            &old_links,
            crate::ServeShared::default(),
        );
        wait_until("the successor did not end", || new.thread.is_finished());
        assert!(new.thread.join().unwrap().is_err(), "the successor started");
        assert!(!old.thread.is_finished(), "the running generation ended");
        load.wait_for_more(&load.by_old, "the running generation did not serve again");

        let failed = load.finish();
        old.stop.store(true, Ordering::SeqCst);
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        assert_eq!(failed, (0, 0), "queries went unanswered (UDP, TCP)");
    }

    #[test]
    /// The successor goes on from what the running generation counted: every answered query is
    /// counted once, the query log IDs run on in one ascending sequence, and the successor saves the
    /// merged totals.
    fn the_statistics_carry_over_to_the_successor() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-handoff-stats-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let stats_file = dir.join("stats.json");
        let path = |file: &std::path::Path| file.display().to_string().replace('\\', "/");
        let files = format!(
            "stats_file = \"{}\"\nquerylog_file = \"{}\"\nquerylog_size = 100000\npersist_flush_secs = 1\n",
            path(&stats_file),
            path(&dir.join("querylog.jsonl"))
        );
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(dns, OLD_ANSWER, &files), None, old_shared);
        let load = Load::start(dns);
        // A successor that also loaded the saved statistics would count them twice; make sure there
        // are some.
        wait_until("the running generation did not save its statistics", || {
            std::fs::read_to_string(&stats_file)
                .is_ok_and(|saved| !saved.contains("\"total\":\"0\""))
        });

        let new_shared = crate::ServeShared::default();
        let new = start_successor(
            config(dns, NEW_ANSWER, &files),
            None,
            &old_links,
            new_shared.clone(),
        );
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        load.wait_for_more(&load.by_new, "the successor did not answer");
        let (by_old, by_new) = (load.by_old.clone(), load.by_new.clone());
        assert_eq!(load.finish(), (0, 0), "queries went unanswered (UDP, TCP)");
        let answered = (by_old.load(Ordering::Relaxed) + by_new.load(Ordering::Relaxed)) as u64;

        let (_, stats) = new_shared.metrics.lock_recover().clone().unwrap();
        wait_until(
            "the successor did not count every answered query once",
            || stats.metrics.snapshot().total == answered,
        );
        let ids: Vec<u64> = stats
            .recent
            .lock_recover()
            .iter()
            .map(|event| event.id)
            .collect();
        assert!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "query log IDs do not ascend"
        );
        assert_eq!(ids.last(), Some(&answered), "query log IDs skip or repeat");
        stats.flush_persisted().unwrap();
        let saved = std::fs::read_to_string(&stats_file).unwrap();
        assert!(
            saved.contains(&format!("\"total\":\"{answered}\"")),
            "the successor did not save the merged totals"
        );

        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    /// The successor starts from the upstream statistics the running generation saved, then adds
    /// what it observed after saving them: every forwarded query is counted once.
    fn the_upstream_statistics_carry_over_to_the_successor() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-handoff-upstreams-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let upstream = crate::listeners::tests::upstream_answering(OLD_ANSWER);
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let text = format!(
            "listen = [\"{dns}\"]\nworkers = 2\nbackend = \"forward\"\n\
             upstream_urls = [\"udp://{upstream}\"]\npersist_flush_secs = 1\n"
        );
        let config_path = dir.join(crate::CONFIG_FILE_NAME);
        std::fs::write(&config_path, &text).unwrap();
        let config = || Config::from_toml_str(&text).unwrap();
        let saved = crate::upstream_stats::upstream_stats_path(Some(&config_path)).unwrap();

        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(), Some(config_path.clone()), old_shared);
        let load = Load::start(dns);
        // A successor that added the whole handed-over state on top of its seed would count the
        // saved queries twice; make sure there are some.
        wait_until(
            "the running generation did not save its upstream statistics",
            || {
                crate::upstream_stats::load_upstream_stats(&saved)
                    .iter()
                    .any(|report| report.queries > 0)
            },
        );

        let new_shared = crate::ServeShared::default();
        let new = start_successor(
            config(),
            Some(config_path.clone()),
            &old_links,
            new_shared.clone(),
        );
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        // Both forward to the same upstream; only the successor answers from here on.
        load.wait_for_more(&load.by_old, "the successor did not answer");
        let answered = load.by_old.clone();
        assert_eq!(load.finish(), (0, 0), "queries went unanswered (UDP, TCP)");
        let answered = answered.load(Ordering::Relaxed) as u64;

        let forward = new_shared
            .console
            .lock_recover()
            .as_ref()
            .unwrap()
            .upstreams
            .lock_recover()
            .clone()
            .unwrap();
        let reports = forward.snapshot();
        assert_eq!(reports.len(), 1);
        assert_eq!(
            (reports[0].queries, reports[0].ok, reports[0].fail),
            (answered, answered, 0),
            "forwarded queries counted (all, answered, failed)"
        );

        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Sends one request to the management API and returns the whole response.
    fn http(control: SocketAddr, request: &str) -> String {
        use std::io::{Read, Write};
        let mut stream =
            std::net::TcpStream::connect_timeout(&control, Duration::from_secs(5)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    fn stats_status(control: SocketAddr, cookie: &str) -> String {
        let response = http(
            control,
            &format!(
                "GET /v1/stats HTTP/1.1\r\nHost: {control}\r\nCookie: {cookie}\r\n\
                 Connection: close\r\n\r\n"
            ),
        );
        response.lines().next().unwrap_or_default().to_string()
    }

    #[test]
    /// A dashboard sign-in made on the running generation still works on the successor, through the
    /// management socket it took over.
    fn a_signed_in_session_carries_over_to_the_successor() {
        const PASSWORD: &str = "handover-passphrase";
        /// PBKDF2 at the lowest accepted cost, so signing in does not take seconds in a debug build.
        const PASSWORD_HASH: &str = "pbkdf2-sha256$100000$000102030405060708090a0b0c0d0e0f$\
            d342ca8060f543f59165684524a66a4a1db7b862b3661a9cb84632fa87479273";
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let account = format!(
            "control_listen = \"{control}\"\n[[users]]\nname = \"alice\"\n\
             password_hash = \"{PASSWORD_HASH}\"\nrole = \"admin\"\n"
        );
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(dns, OLD_ANSWER, &account), None, old_shared);

        let body = format!("{{\"user\":\"alice\",\"password\":\"{PASSWORD}\"}}");
        let login = format!(
            "POST /v1/login HTTP/1.1\r\nHost: {control}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response = http(control, &login);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let cookie = response
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .and_then(|cookie| cookie.split(';').next())
            .expect("no session cookie")
            .to_string();
        assert!(stats_status(control, &cookie).starts_with("HTTP/1.1 200"));

        let new = start_successor(
            config(dns, NEW_ANSWER, &account),
            None,
            &old_links,
            crate::ServeShared::default(),
        );
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        let status = stats_status(control, &cookie);
        assert!(
            status.starts_with("HTTP/1.1 200"),
            "the successor did not keep the sign-in: {status}"
        );
        let forged = format!("{cookie}x");
        assert!(stats_status(control, &forged).starts_with("HTTP/1.1 401"));

        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
    }

    #[test]
    /// The successor lists the running generation's jobs under the same IDs. The one still running
    /// stopped with the running generation and shows as failed.
    fn the_job_list_carries_over_to_the_successor() {
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let old_shared = crate::ServeShared::default();
        let (old_links, old_jobs) = (old_shared.links.clone(), old_shared.jobs.clone());
        let old = start_serving(config(dns, OLD_ANSWER, ""), None, old_shared);
        let done = old_jobs.create("refresh-lists").unwrap();
        old_jobs.finish(done, true, "block=10".to_string());
        let unfinished = old_jobs.create("update-check").unwrap();

        let new_shared = crate::ServeShared::default();
        let new_jobs = new_shared.jobs.clone();
        let new = start_successor(config(dns, NEW_ANSWER, ""), None, &old_links, new_shared);
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        assert!(new_jobs
            .get_json(done)
            .is_some_and(|job| job.contains("\"status\":\"done\"")));
        assert!(new_jobs
            .get_json(unfinished)
            .is_some_and(|job| job.contains("\"status\":\"failed\"")));

        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
    }

    /// One DoT query, resuming `session` when given. Returns whether it resumed and the tickets the
    /// server sent.
    fn ask_dot(
        dot: SocketAddr,
        session: Option<onetdns_tls::TlsSession>,
    ) -> (bool, Vec<onetdns_tls::TlsSession>) {
        let mut socket =
            std::net::TcpStream::connect_timeout(&dot, Duration::from_secs(5)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let client = onetdns_tls::ClientConfig {
            server_name: "localhost".to_string(),
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"dot".to_vec()],
            session,
            ..Default::default()
        };
        let mut conn = onetdns_tls::client_handshake(&mut socket, &client).unwrap();
        let wire = crate::listeners::tests::query(7, "dot.handover.test");
        let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&wire);
        conn.write_app(&mut socket, &framed).unwrap();
        assert!(!conn.read_app(&mut socket).unwrap().is_empty());
        (conn.is_resumed(), conn.take_sessions())
    }

    #[test]
    /// A DoT client resumes on the successor with a ticket the running generation issued, and the
    /// DNSCrypt certificate the successor serves names the same resolver key.
    fn the_keys_clients_hold_carry_over_to_the_successor() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-handoff-keys-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let _serial = one_at_a_time();
        let dns = dns_addr();
        let dnscrypt = dns_addr();
        let dot = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let text = format!(
            "listen = [\"{dns}\"]\nworkers = 2\nbackend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\nblock_rules = [\"||handover.test^\"]\n\
             listen_dot = [\"{dot}\"]\ntls_self_signed_host = \"localhost\"\n\
             listen_dnscrypt = [\"{dnscrypt}\"]\n"
        );
        let config_path = dir.join(crate::CONFIG_FILE_NAME);
        std::fs::write(&config_path, &text).unwrap();
        let config = || Config::from_toml_str(&text).unwrap();
        let provider_name = config().dnscrypt_provider_name;

        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start_serving(config(), Some(config_path.clone()), old_shared);
        let (resumed, mut tickets) = ask_dot(dot, None);
        assert!(!resumed);
        let ticket = tickets
            .pop()
            .expect("the running generation sent no ticket");
        let served = crate::listeners::tests::dnscrypt_resolver_key(dnscrypt, &provider_name);

        let new = start_successor(
            config(),
            Some(config_path.clone()),
            &old_links,
            crate::ServeShared::default(),
        );
        wait_until("the running generation did not hand over", || {
            old.thread.is_finished() || new.thread.is_finished()
        });
        assert!(!new.thread.is_finished(), "the successor ended");
        old.thread
            .join()
            .unwrap()
            .expect("the running generation failed");
        assert!(
            ask_dot(dot, Some(ticket)).0,
            "the successor did not resume the ticket"
        );
        assert_eq!(
            crate::listeners::tests::dnscrypt_resolver_key(dnscrypt, &provider_name),
            served,
            "the successor serves another resolver key"
        );

        new.stop.store(true, Ordering::SeqCst);
        new.thread.join().unwrap().expect("the successor failed");
        let _ = std::fs::remove_dir_all(dir);
    }
}
