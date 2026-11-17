//! Full-screen console for `run` in an interactive terminal: status on top, the log below. Log
//! lines go to a ring in memory instead of stderr while it is up.

mod term;
mod view;

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use onetdns_config::{BackendKind, Config, Mode};
use onetdns_core::{ArcSwap, MutexExt};

const TICK: Duration = Duration::from_millis(200);

/// Saved terminal state while the console is up. Drawing happens under this lock, so `leave`
/// never restores the terminal in the middle of a frame.
static ACTIVE: Mutex<Option<term::Saved>> = Mutex::new(None);
/// Set while the log goes to the console instead of stderr, which starts before the console is
/// up when it waits for the terminal.
static CAPTURED: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<view::Log> = Mutex::new(view::Log::new());
/// Printed after the terminal is restored; on screen they would vanish with the console.
static PANICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// What one configuration generation serves. Each generation replaces it.
#[derive(Clone)]
pub(crate) struct Generation {
    pub(crate) cfg: Arc<ArcSwap<Config>>,
    pub(crate) listeners: Arc<Mutex<Vec<(&'static str, String, String)>>>,
    pub(crate) upstreams: Arc<Mutex<Option<onetdns_forward::ForwardStats>>>,
}

pub(crate) type GenerationSlot = Arc<Mutex<Option<Generation>>>;
pub(crate) type MetricsSlot =
    Arc<Mutex<Option<(onetdns_control::Recorder, onetdns_control::Stats)>>>;

/// Stdin, stdout and stderr are all a terminal and the log is not JSON.
pub(crate) fn wanted() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
        && !onetdns_core::log::json_format()
        && term::usable()
}

/// Leaves the console when dropped.
pub(crate) struct Session(());

impl Drop for Session {
    fn drop(&mut self) {
        DONE.store(true, Ordering::Release);
        let drawer = DRAWER.lock_recover().take();
        if let Some(Drawer::Running(thread)) = drawer {
            let _ = thread.join();
        }
        leave();
    }
}

/// The drawing thread, or what it needs until `start_drawing` starts it.
enum Drawer {
    Waiting(Feed, Arc<AtomicBool>, Option<Wait>),
    Running(JoinHandle<()>),
}

/// Blocks until another process lets go of the terminal and returns true, or returns false once
/// the flag is set.
pub(crate) type Wait = Box<dyn FnOnce(&AtomicBool) -> bool + Send>;

static DRAWER: Mutex<Option<Drawer>> = Mutex::new(None);
static DONE: AtomicBool = AtomicBool::new(false);

/// Switches the terminal and takes over the log. `None` when the terminal cannot host the
/// console; the log then stays on stderr. Nothing is drawn until `start_drawing`. With `wait`,
/// the terminal switches once it returns, and the log is kept for the console meanwhile.
pub(crate) fn start(
    metrics: MetricsSlot,
    generation: GenerationSlot,
    stop: Arc<AtomicBool>,
    wait: Option<Wait>,
) -> Option<Session> {
    if !wanted() {
        return None;
    }
    if wait.is_none() {
        let saved = term::enter()?;
        *ACTIVE.lock_recover() = Some(saved);
    }
    install_panic_hook();
    onetdns_core::log::set_sink(Some(Box::new(|record| {
        let mut text = record.event.to_string();
        for part in [record.message, record.fields] {
            if !part.is_empty() {
                text.push_str("  ");
                text.push_str(part);
            }
        }
        LOG.lock_recover().push(Some(record.level), clock(), text);
    })));
    CAPTURED.store(true, Ordering::Release);
    DONE.store(false, Ordering::Release);
    let feed = Feed {
        metrics,
        generation,
        started: Instant::now(),
        rate: Rate::default(),
    };
    *DRAWER.lock_recover() = Some(Drawer::Waiting(feed, stop, wait));
    Some(Session(()))
}

/// Starts the drawing thread once. Call it after privileges are dropped: Linux refuses to drop
/// them while another thread runs.
pub(crate) fn start_drawing() {
    let mut drawer = DRAWER.lock_recover();
    if !matches!(*drawer, Some(Drawer::Waiting(..))) {
        return;
    }
    let Some(Drawer::Waiting(feed, stop, wait)) = drawer.take() else {
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("console".to_string())
        .spawn(move || {
            if let Some(wait) = wait {
                if !wait(&DONE) || !enter_late() {
                    return;
                }
            }
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| draw_until(feed, &stop)))
                .is_err()
            {
                leave();
            }
        });
    match spawned {
        Ok(thread) => *drawer = Some(Drawer::Running(thread)),
        Err(error) => {
            drop(drawer);
            leave();
            onetdns_core::warn!(event = "console.start_failed", %error, "Could not start the console screen; printing the log instead");
        }
    }
}

/// Session::drop joins this thread before it leaves, so the terminal entered here is restored.
fn enter_late() -> bool {
    match term::enter() {
        Some(saved) => {
            *ACTIVE.lock_recover() = Some(saved);
            true
        }
        None => {
            leave();
            onetdns_core::warn!(
                event = "console.start_failed",
                "Could not switch the terminal to the console screen; printing the log instead"
            );
            false
        }
    }
}

/// Restores the terminal and sends the log back to stderr. Lines kept while the console waited
/// for the terminal are printed. Safe to call more than once and from any thread; call it before
/// exec or exit, which skip destructors.
pub(crate) fn leave() {
    let mut active = ACTIVE.lock_recover();
    let entered = match active.take() {
        Some(saved) => {
            saved.restore();
            true
        }
        None => false,
    };
    if CAPTURED.swap(false, Ordering::AcqRel) {
        onetdns_core::log::set_sink(None);
        if !entered {
            for line in LOG.lock_recover().lines() {
                eprintln!("{line}");
            }
        }
    }
    drop(active);
    for text in std::mem::take(&mut *PANICS.lock_recover()) {
        eprintln!("{text}");
    }
}

/// Lines the server prints for the operator, such as the dashboard address.
pub(crate) fn print_block(lines: &[String]) {
    if CAPTURED.load(Ordering::Acquire) {
        let mut log = LOG.lock_recover();
        for line in lines {
            log.push(None, clock(), line.clone());
        }
        return;
    }
    println!();
    for line in lines {
        println!("  {line}");
    }
    println!();
}

/// The supervisor parent's copy of the terminal settings. A child that is killed leaves the
/// terminal as its console set it, so the parent puts it back.
#[cfg(any(target_os = "linux", windows))]
pub(crate) struct ChildConsole(term::Saved);

#[cfg(any(target_os = "linux", windows))]
impl ChildConsole {
    pub(crate) fn capture() -> Option<Self> {
        wanted().then(term::Saved::capture).flatten().map(Self)
    }

    pub(crate) fn child_exited(&self, status: std::process::ExitStatus) {
        #[cfg(unix)]
        let killed = std::os::unix::process::ExitStatusExt::signal(&status).is_some();
        // A worker that ends on its own leaves the console first; one that is ended exits with
        // the code its killer chose.
        #[cfg(windows)]
        let killed = !matches!(
            status.code(),
            Some(0 | crate::update::launch::UPDATE_EXIT_CODE)
        );
        if killed {
            self.0.restore();
        }
    }

    /// Carries the settings across the supervisor's exec of a new version, when the terminal may
    /// already be in the console's state.
    #[cfg(target_os = "linux")]
    pub(crate) fn encode(&self) -> String {
        crate::update::hex(&self.0.to_bytes())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn decode(text: &str) -> Option<Self> {
        let digits = text.as_bytes();
        if digits.len() % 2 != 0 || !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let bytes = digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        term::Saved::from_bytes(&bytes).map(Self)
    }
}

fn clock() -> String {
    let (hour, minute, second) = crate::localtime::local_clock(SystemTime::now());
    format!("{hour:02}:{minute:02}:{second:02}")
}

fn install_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let active = match ACTIVE.try_lock() {
                Ok(saved) => saved.is_some(),
                Err(TryLockError::Poisoned(saved)) => saved.into_inner().is_some(),
                // Held while a frame is drawn, so the console is up.
                Err(TryLockError::WouldBlock) => true,
            };
            if !active {
                previous(info);
                return;
            }
            if onetdns_core::isolation::panic_is_contained() {
                return;
            }
            let thread = std::thread::current();
            let text = format!(
                "thread '{}' {}",
                thread.name().unwrap_or("unnamed"),
                info.to_string().replace('\n', " ")
            );
            // The panicking thread may hold the log lock.
            if let Ok(mut log) = LOG.try_lock() {
                log.push(Some(onetdns_core::log::Level::Error), clock(), text.clone());
            }
            PANICS.lock_recover().push(text);
        }));
    });
}

/// Ctrl+C reaches a supervisor parent too, which would otherwise start this process again, so
/// quitting sends it the same way.
fn quit(stop: &AtomicBool) {
    stop.store(true, Ordering::SeqCst);
    #[cfg(unix)]
    {
        // SAFETY: sends a signal; no memory is involved.
        unsafe {
            libc::kill(0, libc::SIGINT);
        }
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GenerateConsoleCtrlEvent(event: u32, process_group: u32) -> i32;
        }
        const CTRL_C_EVENT: u32 = 0;
        // SAFETY: takes no pointers; group 0 is every process on this console.
        unsafe {
            GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        }
    }
}

fn draw_until(mut feed: Feed, stop: &AtomicBool) {
    let mut view = view::View::default();
    let mut shown: Vec<String> = Vec::new();
    let mut shown_size = (0, 0);
    let mut keys = Vec::new();
    while !DONE.load(Ordering::Acquire) {
        term::read_keys(TICK, &mut keys);
        let now = Instant::now();
        for key in keys.drain(..) {
            let level = onetdns_core::log::level();
            let action = view.key(key, &LOG.lock_recover(), level, now);
            match action {
                view::Action::None => {}
                view::Action::Quit => quit(stop),
                view::Action::SetLevel(level) => onetdns_core::log::set_level(level),
            }
        }
        view.expire(now);

        let status = feed.status();
        let size = term::size();
        let frame = view::render(&status, &LOG.lock_recover(), &mut view, size.0, size.1);

        let active = ACTIVE.lock_recover();
        if active.is_none() {
            return;
        }
        let mut out = String::new();
        if size != shown_size {
            out.push_str("\x1b[2J");
            shown.clear();
            shown_size = size;
        }
        for (index, row) in frame.iter().enumerate() {
            if shown.get(index) != Some(row) {
                let _ = write!(out, "\x1b[{};1H{row}", index + 1);
            }
        }
        if !out.is_empty() {
            term::write(&out);
        }
        drop(active);
        shown = frame;
    }
}

struct Feed {
    metrics: MetricsSlot,
    generation: GenerationSlot,
    started: Instant,
    rate: Rate,
}

#[derive(Default)]
struct Rate {
    last: Option<(Instant, u64)>,
    per_second: Option<f64>,
}

impl Rate {
    fn sample(&mut self, total: u64) -> Option<f64> {
        let now = Instant::now();
        match self.last {
            Some((at, before)) => {
                let elapsed = now.duration_since(at).as_secs_f64();
                if elapsed >= 1.0 {
                    self.per_second = Some(total.saturating_sub(before) as f64 / elapsed);
                    self.last = Some((now, total));
                }
            }
            None => self.last = Some((now, total)),
        }
        self.per_second
    }
}

impl Feed {
    fn status(&mut self) -> view::Status {
        let metrics = self
            .metrics
            .lock_recover()
            .as_ref()
            .map(|(recorder, _)| recorder.metrics().clone());
        let traffic = metrics.map(|metrics| {
            let snapshot = metrics.snapshot();
            view::Traffic {
                per_second: self.rate.sample(snapshot.total),
                total: snapshot.total,
                blocked: snapshot.blocked,
                cache_hit_pct: snapshot.cache_hit_pct,
                latency_ms: snapshot.avg_latency_ms,
            }
        });
        let generation = self.generation.lock_recover().clone();
        let (serving, dashboard, listeners, upstreams) = match &generation {
            Some(generation) => {
                let cfg = generation.cfg.load();
                (
                    Some((
                        match cfg.mode {
                            Mode::Personal => "personal",
                            Mode::Public => "public",
                        },
                        match cfg.backend {
                            BackendKind::Forward => "forward",
                            BackendKind::Recurse => "recurse",
                            BackendKind::Split => "split",
                        },
                    )),
                    cfg.control_listen.map(|addr| format!("http://{addr}/")),
                    generation
                        .listeners
                        .lock_recover()
                        .iter()
                        .map(|(kind, _, bound)| (*kind, bound.clone()))
                        .collect(),
                    generation
                        .upstreams
                        .lock_recover()
                        .as_ref()
                        .map(|stats| stats.snapshot())
                        .unwrap_or_default(),
                )
            }
            None => (None, None, Vec::new(), Vec::new()),
        };
        view::Status {
            version: crate::update::VERSION,
            serving,
            uptime: self.started.elapsed(),
            traffic,
            dashboard,
            listeners,
            upstreams,
            level: onetdns_core::log::level(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn terminal_settings_survive_the_supervisor_exec() {
        let size = std::mem::size_of::<libc::termios>();
        let bytes: Vec<u8> = (0..size)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let console = ChildConsole(term::Saved::from_bytes(&bytes).unwrap());
        let text = console.encode();
        assert_eq!(ChildConsole::decode(&text).unwrap().0.to_bytes(), bytes);
        assert!(ChildConsole::decode(&text[1..]).is_none());
        assert!(ChildConsole::decode(&text[2..]).is_none());
        assert!(ChildConsole::decode(&"+1".repeat(size)).is_none());
    }
}
