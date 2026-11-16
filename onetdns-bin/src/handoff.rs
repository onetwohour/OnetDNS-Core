//! Handing a running generation over to its successor: the listening sockets, carried without
//! closing them so the queries queued on a socket are answered by whoever serves it next, the
//! channel between the two, and the order in which the successor takes over.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::config_apply::{install_restart, SecondaryRestart};
use crate::listeners::ListenerSet;
use crate::GenerationJobs;

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

/// Sockets that are open but not served, keyed by role and bound address. A listener opening an
/// address takes its sockets from here before it binds.
///
/// Port 0 never matches: the configured address then differs from the bound one, and the listener
/// binds a new socket.
#[derive(Debug, Default)]
pub(crate) struct SocketPool {
    entries: Vec<(SocketRole, SocketAddr, ListeningSocket)>,
}

impl SocketPool {
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
    /// Duplicates of the listening sockets. The QUIC ones are no longer read on this side.
    Sockets(SocketPool),
    /// Nothing that only one process may run is running on this side any more.
    Released,
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
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LinkError::Gone => "the other process ended",
            LinkError::TimedOut => "the other process did not answer in time",
            LinkError::Aborted => "stopped while waiting",
        })
    }
}

/// How often a wait checks whether to give up.
const LINK_POLL: Duration = Duration::from_millis(200);

/// One end of the channel between a running generation and its successor.
pub(crate) struct Link<Out, In> {
    tx: mpsc::Sender<Out>,
    rx: mpsc::Receiver<In>,
}

/// Held by the running generation.
pub(crate) type SuccessorLink = Link<FromPredecessor, FromSuccessor>;
/// Held by the successor.
pub(crate) type PredecessorLink = Link<FromSuccessor, FromPredecessor>;

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
            Ok(FromPredecessor::Released) => return Err(OUT_OF_ORDER.to_string()),
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
            Ok(FromPredecessor::Released) | Err(LinkError::Gone) => {}
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
    /// once the successor runs everything; otherwise this generation takes back what it handed over
    /// and goes on.
    pub(crate) fn hand_over(
        &self,
        link: &SuccessorLink,
        cfg: &Config,
        abort: &dyn Fn() -> bool,
    ) -> bool {
        if let Err(error) = expect(link, FromSuccessor::Request, abort) {
            onetdns_core::warn!(event = "handoff.not_requested", %error, "The new process did not ask for the listening sockets; this process keeps serving");
            return false;
        }
        let (kept, handed) = match self.export() {
            Ok(pools) => pools,
            Err(error) => {
                onetdns_core::warn!(event = "handoff.export_failed", %error, "Could not duplicate the listening sockets for the new process; this process keeps serving");
                return false;
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
            Ok(()) => {
                onetdns_core::info!(
                    event = "handoff.completed",
                    "Handed the DNS service over to the new process"
                );
                true
            }
            Err(error) => {
                onetdns_core::warn!(event = "handoff.failed", %error, "Could not hand the DNS service over to the new process; this process serves again");
                self.take_back(kept, released, cfg);
                false
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
        link.send(FromPredecessor::Released)
            .map_err(|error| error.to_string())?;
        expect(link, FromSuccessor::Ready, abort)
    }

    /// One pool to hand over and one to keep, so this generation can serve again if the successor
    /// fails.
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
        successor.send(FromPredecessor::Released).unwrap();
        assert!(matches!(
            predecessor.recv(Instant::now() + Duration::from_secs(5), &never),
            Ok(FromPredecessor::Released)
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
            successor.send(FromPredecessor::Released).unwrap_err(),
            LinkError::Gone
        );
    }

    use std::net::Ipv4Addr;
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

    fn start(cfg: Config, shared: crate::ServeShared) -> Running {
        let ready = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (ready, stop) = (ready.clone(), stop.clone());
            std::thread::spawn(move || {
                crate::serve(
                    cfg,
                    None,
                    None,
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
    fn start_successor(cfg: Config, links: &Links) -> Running {
        let (successor, predecessor) = link();
        let shared = crate::ServeShared::default();
        *shared.links.predecessor.lock_recover() = Some(predecessor);
        *links.successor.lock_recover() = Some(successor);
        start(cfg, shared)
    }

    fn wait_until(failure: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < deadline, "{failure}");
            std::thread::sleep(Duration::from_millis(20));
        }
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

    fn dns_addr() -> SocketAddr {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[test]
    /// A successor started in the same process takes over the running generation while clients keep
    /// asking over UDP and TCP. Every query is answered, the successor answers in the end, and the
    /// running generation returns once the successor is ready.
    fn a_successor_takes_over_a_running_generation_without_dropping_queries() {
        let dns = dns_addr();
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start(config(dns, OLD_ANSWER, ""), old_shared);
        wait_until("the running generation did not start", || {
            old.ready.load(Ordering::SeqCst) || old.thread.is_finished()
        });
        let load = Load::start(dns);

        let new = start_successor(config(dns, NEW_ANSWER, ""), &old_links);
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
        let dns = dns_addr();
        let busy = TcpListener::bind("127.0.0.1:0").unwrap();
        let old_shared = crate::ServeShared::default();
        let old_links = old_shared.links.clone();
        let old = start(config(dns, OLD_ANSWER, ""), old_shared);
        wait_until("the running generation did not start", || {
            old.ready.load(Ordering::SeqCst) || old.thread.is_finished()
        });
        let load = Load::start(dns);

        let failing = format!("control_listen = \"{}\"\n", busy.local_addr().unwrap());
        let new = start_successor(config(dns, NEW_ANSWER, &failing), &old_links);
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
}
