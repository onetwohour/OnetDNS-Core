//! Which executable the server starts processes from while that executable changes. Package
//! managers and the self-update replace it by rename; a supervisor that restarted a dead child from
//! the install path would find another file there, and the restart would fail or start a different
//! build. A version swapped in by an update, in contrast, starts on trial: committed once ready,
//! and if it exits before that, the install path is restored to the previous executable and exec'd.
//!
//! An update applied while the server runs is handed over to a process started beside it, and no
//! query may fail meanwhile.
//!
//! The real binary is copied to a temporary directory and run both supervised and as a single
//! process. Only the handoff tests also run on Windows.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use onetdns_forward::{Forwarder, Message, TrustStore, Upstream};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Enough for a slow first start on CI.
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);
/// The install path's file name.
const PROGRAM: &str = if cfg!(windows) {
    "OnetDNS.exe"
} else {
    "OnetDNS"
};

/// Serializes writing executables and spawning processes. Tests run on threads of one process, and
/// a descriptor one thread opened for writing is copied into a child another thread spawns
/// meanwhile, where it stays until that child execs; running the file then fails with ETXTBSY.
/// spawn returns after the child execs, so writing and spawning under this lock leave no child
/// holding a write descriptor.
static EXEC_LOCK: Mutex<()> = Mutex::new(());

/// Keeps working after a test panicked while holding it.
fn exec_lock() -> std::sync::MutexGuard<'static, ()> {
    EXEC_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _exec = exec_lock();
    command.spawn()
}

/// Like Command::output, but spawns through spawn and does not hold the lock while waiting.
fn output_of(command: &mut Command) -> std::io::Result<std::process::Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn(command)?.wait_with_output()
}

struct Event {
    name: String,
    pid: i32,
}

/// Removed however the test ends.
struct ScratchDir(PathBuf);

impl ScratchDir {
    /// The path is canonical, with symlinks resolved.
    fn create() -> Self {
        // macOS clocks tick in microseconds, so tests starting together can read the same time.
        static CREATED: AtomicU32 = AtomicU32::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("시계")
            .as_nanos();
        let unique = format!("{unique}-{}", CREATED.fetch_add(1, Ordering::Relaxed));
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("임시 디렉터리의 실제 경로");
        // Windows canonical paths are verbatim (\\?\C:\...), which a running image does not report.
        #[cfg(windows)]
        let base = PathBuf::from(
            base.to_str()
                .and_then(|path| path.strip_prefix(r"\\?\"))
                .expect("드라이브 문자로 시작하는 임시 디렉터리"),
        );
        let dir = base.join(format!("onetdns-respawn-{}-{unique}", std::process::id()));
        std::fs::create_dir(&dir).expect("임시 디렉터리를 만들지 못했습니다");
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Cleaned up on drop, so a failed assertion leaves no process or port behind.
struct Server {
    /// Also the child's argv[0].
    program: PathBuf,
    /// exec keeps the PID.
    process: Child,
    /// None means stderr closed.
    events: Receiver<Option<Event>>,
    /// Shown on failure.
    log: Arc<Mutex<Vec<String>>>,
    /// Children that reported ready; ended here if the supervisor failed to.
    children: Vec<i32>,
}

impl Server {
    fn supervised(dir: &Path, program: PathBuf, config: &Path) -> Self {
        Self::start(dir, program, config, &[])
    }

    #[cfg(target_os = "linux")]
    fn single_process(dir: &Path, program: PathBuf, config: &Path) -> Self {
        Self::start(dir, program, config, &["--no-supervisor"])
    }

    fn start(dir: &Path, program: PathBuf, config: &Path, extra: &[&str]) -> Self {
        let mut process = spawn(
            Command::new(&program)
                .arg("run")
                .arg("--config")
                .arg(config)
                .arg("--no-web")
                .args(extra)
                .current_dir(dir)
                .env("ONETDNS_LOG_FORMAT", "json")
                .env_remove("ONETDNS_LOG")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        )
        .expect("서버를 띄우지 못했습니다");
        let stderr = process.stderr.take().expect("서버의 표준 오류가 없습니다");
        let (sender, events) = mpsc::channel();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else {
                    break;
                };
                let event = parse_event(&line);
                sink.lock().expect("기록 잠금").push(line);
                if let Some(event) = event {
                    if sender.send(Some(event)).is_err() {
                        return;
                    }
                }
            }
            let _ = sender.send(None);
        });
        Self {
            program,
            process,
            events,
            log,
            children: Vec::new(),
        }
    }

    fn pid(&self) -> i32 {
        self.process.id() as i32
    }

    /// Earlier events are dropped, and events from `exclude` are skipped. Returns the PID that
    /// logged it; fails if the server exits first or time runs out.
    fn wait_for(&self, name: &str, exclude: Option<i32>) -> i32 {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(Some(event)) if event.name == name && Some(event.pid) != exclude => {
                    return event.pid;
                }
                Ok(Some(_)) => continue,
                Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                    panic!("서버가 {name} 전에 끝났습니다.\n{}", self.log_text())
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("{name} 을 기다리다 시간이 지났습니다.\n{}", self.log_text())
                }
            }
        }
    }

    /// Records written after exec carry the same PID.
    fn wait_for_own(&self, name: &str) {
        let pid = self.wait_for(name, None);
        assert_eq!(
            pid,
            self.pid(),
            "{name} 을 남긴 프로세스\n{}",
            self.log_text()
        );
    }

    fn log_text(&self) -> String {
        self.log.lock().expect("기록 잠금").join("\n")
    }

    /// Signals `pid` only when it runs this test's binary.
    #[cfg(unix)]
    fn signal_if_ours(&self, pid: i32, signal: libc::c_int) {
        if self.runs_ours(pid) {
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn runs_ours(&self, pid: i32) -> bool {
        argv0(pid).as_deref() == Some(self.program.as_os_str().as_bytes())
    }

    /// An update renames the executable a process runs, so a process counts as ours while its
    /// executable is in this test's directory.
    #[cfg(target_os = "macos")]
    fn runs_ours(&self, pid: i32) -> bool {
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `path` is valid for the size passed.
        let len = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        let Ok(len) = usize::try_from(len) else {
            return false;
        };
        path.truncate(len);
        let running = Path::new(std::ffi::OsStr::from_bytes(&path));
        let ours = self
            .program
            .parent()
            .and_then(|dir| dir.canonicalize().ok());
        running
            .parent()
            .is_some_and(|dir| Some(dir) == ours.as_deref())
    }

    /// Stops `pid` where it is, when it runs this test's binary.
    fn freeze(&self, pid: i32) {
        #[cfg(unix)]
        self.signal_if_ours(pid, libc::SIGSTOP);
        #[cfg(windows)]
        if let Some(process) = self.open_if_ours(pid) {
            // SAFETY: the handle is open with PROCESS_SUSPEND_RESUME.
            unsafe { win32::NtSuspendProcess(process.as_raw_handle() as isize) };
        }
    }

    /// Ends `pid` at once, when it runs this test's binary.
    fn kill(&self, pid: i32) {
        #[cfg(unix)]
        self.signal_if_ours(pid, libc::SIGKILL);
        #[cfg(windows)]
        if let Some(process) = self.open_if_ours(pid) {
            win32::end(&process);
        }
    }

    /// A handle to `pid` while it runs an executable in this test's directory, so a reused PID is
    /// never touched.
    #[cfg(windows)]
    fn open_if_ours(&self, pid: i32) -> Option<std::os::windows::io::OwnedHandle> {
        win32::open_running_in(pid, self.program.parent()?)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(self.pid(), libc::SIGTERM);
            }
            let deadline = Instant::now() + EXIT_TIMEOUT;
            while Instant::now() < deadline {
                if matches!(self.process.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        // Windows cannot delete a running executable, so each child is opened while the
        // supervisor is still its parent and waited for once it is gone.
        #[cfg(windows)]
        let children: Vec<_> = children_of(self.pid())
            .into_iter()
            .filter_map(|pid| self.open_if_ours(pid))
            .collect();
        let _ = self.process.kill();
        let _ = self.process.wait();
        #[cfg(unix)]
        for pid in &self.children {
            self.kill(*pid);
        }
        #[cfg(windows)]
        for child in &children {
            win32::end(child);
        }
    }
}

fn parse_event(line: &str) -> Option<Event> {
    let json = onetdns_core::json::parse(line).ok()?;
    let name = json.get("event")?.as_str()?.to_string();
    let pid = i32::try_from(json.get("pid")?.as_u64()?).ok()?;
    Some(Event { name, pid })
}

/// None once it has exited.
#[cfg(target_os = "linux")]
fn argv0(pid: i32) -> Option<Vec<u8>> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    cmdline.split(|byte| *byte == 0).next().map(<[u8]>::to_vec)
}

/// Holds UDP and TCP on a free loopback port, so the server cannot bind it until they are dropped.
/// Returns the sockets it found with: releasing and rebinding would let another socket take the
/// port. Windows reserves port ranges per protocol, so a port one protocol picks can be closed to
/// the other; each round tries a port picked by each.
fn hold_free_port() -> (u16, (UdpSocket, TcpListener)) {
    let (mut udp_error, mut tcp_error) = (None, None);
    for _ in 0..32 {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("TCP 포트를 잡지 못했습니다");
        let port = tcp.local_addr().expect("TCP 주소").port();
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(udp) => return (port, (udp, tcp)),
            Err(error) => udp_error = Some(error),
        }
        let udp = UdpSocket::bind("127.0.0.1:0").expect("UDP 포트를 잡지 못했습니다");
        let port = udp.local_addr().expect("UDP 주소").port();
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(tcp) => return (port, (udp, tcp)),
            Err(error) => tcp_error = Some(error),
        }
    }
    panic!(
        "UDP 와 TCP 가 함께 비어 있는 포트를 찾지 못했습니다: UDP {udp_error:?}, TCP {tcp_error:?}"
    );
}

/// Released at once for the server to bind.
fn free_port() -> u16 {
    hold_free_port().0
}

#[cfg(target_os = "linux")]
fn write_config(dir: &Path, port: u16) -> PathBuf {
    let config = dir.join("onetdns.toml");
    std::fs::write(&config, format!("listen = [\"127.0.0.1:{port}\"]\n"))
        .expect("설정을 쓰지 못했습니다");
    config
}

fn install_copy(dir: &Path) -> PathBuf {
    let program = dir.join(PROGRAM);
    let _exec = exec_lock();
    std::fs::copy(env!("CARGO_BIN_EXE_OnetDNS"), &program).expect("바이너리를 복사하지 못했습니다");
    program
}

/// Lowercase hex, as update records use.
fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path).expect("해시할 파일을 읽지 못했습니다");
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn version_of(program: &Path) -> String {
    let output = output_of(Command::new(program).arg("--version"))
        .expect("--version 을 실행하지 못했습니다");
    assert!(output.status.success(), "--version 이 실패했습니다");
    String::from_utf8(output.stdout)
        .expect("버전 출력이 UTF-8 이 아닙니다")
        .trim_end()
        .strip_prefix("OnetDNS ")
        .expect("제품 이름 뒤에 버전이 와야 합니다")
        .to_string()
}

fn run_cli(program: &Path, dir: &Path, args: &[&str]) -> std::process::Output {
    output_of(
        Command::new(program)
            .arg("--cli")
            .args(args)
            .current_dir(dir)
            .env_remove("ONETDNS_LOG"),
    )
    .expect("관리 명령을 실행하지 못했습니다")
}

#[cfg(target_os = "linux")]
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("디렉터리를 읽지 못했습니다")
        .map(|entry| {
            entry
                .expect("디렉터리 항목")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// A directory as an update leaves it right after swapping the install path.
struct Swapped {
    /// The install path, holding the new version.
    program: PathBuf,
    /// The executable from before the swap.
    previous: PathBuf,
    record: PathBuf,
    new_sha256: String,
    previous_sha256: String,
}

impl Swapped {
    /// Puts this binary at the install path and the same binary with bytes appended at .previous,
    /// so only the hash differs, and writes a pending record. Both have the same version, so the
    /// record's from and to match.
    fn prepare(dir: &Path) -> Self {
        let program = install_copy(dir);
        let previous = dir.join(format!("OnetDNS.previous{}", std::env::consts::EXE_SUFFIX));
        let mut image = std::fs::read(&program).expect("바이너리를 읽지 못했습니다");
        image.extend_from_slice(b"\0previous\0");
        let exec = exec_lock();
        std::fs::write(&previous, &image).expect("이전 실행 파일을 쓰지 못했습니다");
        #[cfg(unix)]
        std::fs::set_permissions(&previous, std::fs::Permissions::from_mode(0o755))
            .expect("이전 실행 파일 권한");
        drop(exec);
        let version = version_of(&program);
        let new_sha256 = sha256_hex(&program);
        let previous_sha256 = sha256_hex(&previous);
        let record = dir.join("OnetDNS.update");
        std::fs::write(
            &record,
            format!(
                "format=1\nstate=pending\nfrom={version}\nto={version}\nfrom_sha256={previous_sha256}\nto_sha256={new_sha256}\n"
            ),
        )
        .expect("업데이트 기록을 쓰지 못했습니다");
        Self {
            program,
            previous,
            record,
            new_sha256,
            previous_sha256,
        }
    }

    fn record_text(&self) -> String {
        std::fs::read_to_string(&self.record).expect("업데이트 기록을 읽지 못했습니다")
    }

    /// The same record a finished trial leaves.
    fn commit(&self) {
        let record = self
            .record_text()
            .replace("state=pending\n", "state=committed\n");
        std::fs::write(&self.record, record).expect("업데이트 기록을 쓰지 못했습니다");
    }

    /// The install path and .previous must be unchanged, so they remain usable for rollback.
    #[cfg(target_os = "linux")]
    fn assert_committed(&self) {
        let record = self.record_text();
        assert!(record.contains("state=committed\n"), "{record}");
        assert_eq!(sha256_hex(&self.program), self.new_sha256, "설치 경로");
        assert_eq!(
            sha256_hex(&self.previous),
            self.previous_sha256,
            ".previous"
        );
    }

    /// The record must hold `reason`.
    #[cfg(target_os = "linux")]
    fn assert_reverted(&self, reason: &str) {
        assert_eq!(
            sha256_hex(&self.program),
            self.previous_sha256,
            "설치 경로에 돌아온 실행 파일"
        );
        assert!(
            !self.previous.exists(),
            ".previous 가 설치 경로로 옮겨지지 않았습니다"
        );
        let record = self.record_text();
        assert!(record.contains("state=reverted\n"), "{record}");
        assert!(record.contains(&format!("reason={reason}")), "{record}");
    }
}

#[cfg(target_os = "linux")]
#[test]
/// The install path holds a file that cannot run. A supervisor restarting from that path would fail
/// and exit, and the next ready notice would never come. The restarted child must also keep its
/// process name and argv[0], so pgrep and service managers still find it.
fn child_restarts_from_the_running_image_after_the_binary_is_replaced() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let program = install_copy(dir);
    let config = write_config(dir, free_port());

    let mut server = Server::supervised(dir, program.clone(), &config);
    let first = server.wait_for("server.ready", None);
    server.children.push(first);

    let replacement = dir.join("OnetDNS.replacement");
    std::fs::write(&replacement, b"not an executable\n").expect("대체 파일을 쓰지 못했습니다");
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755))
        .expect("대체 파일 권한");
    std::fs::rename(&replacement, &program).expect("설치 경로를 갈아 끼우지 못했습니다");

    unsafe {
        libc::kill(first, libc::SIGKILL);
    }
    let second = server.wait_for("server.ready", Some(first));
    server.children.push(second);

    let comm = std::fs::read_to_string(format!("/proc/{second}/comm")).expect("프로세스 이름");
    assert_eq!(comm.trim_end(), "OnetDNS", "다시 뜬 자식의 프로세스 이름");
    assert_eq!(
        argv0(second).as_deref(),
        Some(program.as_os_str().as_bytes()),
        "다시 뜬 자식의 argv[0]"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn supervised_trial_that_becomes_ready_is_committed() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let swapped = Swapped::prepare(dir);
    let config = write_config(dir, free_port());

    let mut server = Server::supervised(dir, swapped.program.clone(), &config);
    server.wait_for_own("update.trial_started");
    let child = server.wait_for("server.ready", None);
    server.children.push(child);
    server.wait_for_own("update.committed");

    swapped.assert_committed();
}

#[cfg(target_os = "linux")]
#[test]
/// Holding the listen port makes the new version's child exit before it gets ready. The supervisor
/// reverts, execs, and reports the reverted update under the same PID. Once the port is released,
/// the restored executable's child gets ready; if it tries to bind before the release and fails,
/// the supervisor starts it again.
fn supervised_trial_that_fails_before_ready_starts_the_previous_executable() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let swapped = Swapped::prepare(dir);
    let (port, held) = hold_free_port();
    let config = write_config(dir, port);

    let mut server = Server::supervised(dir, swapped.program.clone(), &config);
    server.wait_for_own("update.trial_started");
    server.wait_for_own("update.reverted");
    server.wait_for_own("update.reverted_earlier");
    drop(held);
    let child = server.wait_for("server.ready", None);
    server.children.push(child);

    swapped.assert_reverted("The new version exited before it became ready");
}

#[cfg(target_os = "linux")]
#[test]
fn single_process_trial_that_becomes_ready_is_committed() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let swapped = Swapped::prepare(dir);
    let config = write_config(dir, free_port());

    let server = Server::single_process(dir, swapped.program.clone(), &config);
    server.wait_for_own("update.trial_started");
    server.wait_for_own("server.ready");
    server.wait_for_own("update.committed");

    swapped.assert_committed();
}

#[cfg(target_os = "linux")]
#[test]
/// A single process has no supervisor to start it again, so the exec'd previous executable also
/// fails while the port is held; this test only checks that the exec'd process reports the reverted
/// update.
fn single_process_trial_that_fails_before_ready_execs_the_previous_executable() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let swapped = Swapped::prepare(dir);
    let (port, _held) = hold_free_port();
    let config = write_config(dir, port);

    let server = Server::single_process(dir, swapped.program.clone(), &config);
    server.wait_for_own("update.trial_started");
    server.wait_for_own("update.reverted");
    server.wait_for_own("update.reverted_earlier");

    swapped.assert_reverted("The new version stopped with an error before it became ready");
}

#[cfg(target_os = "linux")]
#[test]
/// Rolling back goes through the same preflight and swap as installing a new version: the real
/// binary checks its own copy with --version and --cli check. The next start trial-runs the
/// restored executable and commits it.
fn cli_rollback_installs_the_previous_executable_for_a_trial() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let swapped = Swapped::prepare(dir);
    swapped.commit();
    let config = write_config(dir, free_port());
    let config_arg = config.to_str().expect("설정 경로가 UTF-8 이 아닙니다");

    let output = run_cli(
        &swapped.program,
        dir,
        &["update", "rollback", "--config", config_arg],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        sha256_hex(&swapped.program),
        swapped.previous_sha256,
        "설치 경로"
    );
    assert_eq!(
        sha256_hex(&swapped.previous),
        swapped.new_sha256,
        ".previous"
    );
    let record = swapped.record_text();
    assert!(record.contains("state=pending\n"), "{record}");
    assert!(
        record.contains(&format!("from_sha256={}\n", swapped.new_sha256)),
        "{record}"
    );
    assert!(
        record.contains(&format!("to_sha256={}\n", swapped.previous_sha256)),
        "{record}"
    );

    let server = Server::single_process(dir, swapped.program.clone(), &config);
    server.wait_for_own("update.trial_started");
    server.wait_for_own("update.committed");
    let record = swapped.record_text();
    assert!(record.contains("state=committed\n"), "{record}");
}

#[cfg(target_os = "linux")]
#[test]
/// Not even a lock file may appear in the install directory when there is nothing to roll back.
fn cli_rollback_without_an_update_leaves_the_directory_alone() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let program = install_copy(dir);
    let config = write_config(dir, free_port());
    let config_arg = config.to_str().expect("설정 경로가 UTF-8 이 아닙니다");
    let before = listing(dir);

    let output = run_cli(
        &program,
        dir,
        &["update", "rollback", "--config", config_arg],
    );
    assert!(
        !output.status.success(),
        "되돌릴 것이 없으면 실패해야 합니다"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("There is no confirmed update to go back from"),
        "{stderr}"
    );
    assert_eq!(listing(dir), before);
}

/// Answered from `rewrites`, so no query leaves the machine. Also the name on the TLS certificate.
const LOCAL_NAME: &str = "handoff.test";
/// The default `dnscrypt_provider_name`.
const DNSCRYPT_PROVIDER: &str = "2.dnscrypt-cert.onetdns";
const CONTROL_TOKEN: &str = "handoff-test-control-token-0123456789";
const ADMIN_PASSWORD: &str = "handoff-test-password";
/// A query unanswered this long counts as lost.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(3);
/// Keeps the TCP lanes from piling up TIME_WAIT sockets.
const QUERY_PACE: Duration = Duration::from_millis(20);
/// Longer than the successor takes to start answering, so the predecessor has counted more
/// queries by then than the successor counts by itself.
const LOAD_BEFORE_UPDATE: Duration = Duration::from_secs(4);
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;

struct Ports {
    dns: u16,
    dot: u16,
    doh: u16,
    doq: u16,
    doh3: u16,
    dnscrypt: u16,
    control: u16,
}

/// What a lane may see while the processes trade sockets.
#[derive(Clone, Copy, PartialEq)]
enum Promise {
    Answered,
    /// QUIC connection state stays with the old process, so a query on a connection it closes can
    /// fail; the client connects again.
    Reconnects,
}

/// An install directory right after an update, serving every DNS transport and the management
/// API, each on its own free port.
struct Handoff {
    swapped: Swapped,
    config: PathBuf,
    ports: Ports,
    /// Trusts the server's self-signed certificate.
    trust: Arc<TrustStore>,
    /// Kept to ask again once the load stops.
    quic: Vec<(&'static str, Arc<Forwarder>)>,
}

impl Handoff {
    /// The update is committed, so the management API can roll it back.
    fn prepare(dir: &Path) -> Self {
        let swapped = Swapped::prepare(dir);
        swapped.commit();
        let cert = dir.join("tls.crt");
        let key = dir.join("tls.key");
        let output = run_cli(
            &swapped.program,
            dir,
            &[
                "cert",
                "--host",
                LOCAL_NAME,
                "--cert-out",
                cert.to_str().expect("인증서 경로가 UTF-8 이 아닙니다"),
                "--key-out",
                key.to_str().expect("키 경로가 UTF-8 이 아닙니다"),
            ],
        );
        assert!(
            output.status.success(),
            "인증서를 만들지 못했습니다: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let pem = std::fs::read(&cert).expect("인증서를 읽지 못했습니다");
        let ports = Ports {
            dns: free_port(),
            dot: free_port(),
            doh: free_port(),
            doq: free_port(),
            doh3: free_port(),
            dnscrypt: free_port(),
            control: free_port(),
        };
        let config = dir.join("onetdns.toml");
        std::fs::write(
            &config,
            format!(
                "listen = [\"127.0.0.1:{}\"]\nlisten_dot = [\"127.0.0.1:{}\"]\nlisten_doh = [\"127.0.0.1:{}\"]\nlisten_doq = [\"127.0.0.1:{}\"]\nlisten_doh3 = [\"127.0.0.1:{}\"]\nlisten_dnscrypt = [\"127.0.0.1:{}\"]\ntls_cert = \"{}\"\ntls_key = \"{}\"\ncontrol_listen = \"127.0.0.1:{}\"\ncontrol_token = \"{CONTROL_TOKEN}\"\nrewrites = [{{ domain = \"{LOCAL_NAME}\", answer = \"192.0.2.1\" }}]\n",
                ports.dns,
                ports.dot,
                ports.doh,
                ports.doq,
                ports.doh3,
                ports.dnscrypt,
                toml_path(&cert),
                toml_path(&key),
                ports.control
            ),
        )
        .expect("설정을 쓰지 못했습니다");
        let trust = Arc::new(TrustStore::from_pem(&pem));
        let quic = vec![
            ("DoQ", Upstream::doq(loopback(ports.doq), LOCAL_NAME)),
            (
                "DoH3",
                Upstream::doh3(loopback(ports.doh3), LOCAL_NAME, "/dns-query"),
            ),
        ]
        .into_iter()
        .map(|(name, upstream)| {
            let forwarder =
                Forwarder::with_upstreams(vec![upstream], ANSWER_TIMEOUT).with_trust(trust.clone());
            (name, Arc::new(forwarder))
        })
        .collect();
        Self {
            swapped,
            config,
            ports,
            trust,
            quic,
        }
    }

    /// One lane per transport. Do53 TCP opens a new connection per query; the others keep theirs
    /// as clients do, and connect again once the process that served it closes it.
    fn lanes(&self) -> Vec<(&'static str, Promise, Ask)> {
        let ports = &self.ports;
        let udp = connected_udp(ports.dns);
        let dnscrypt = connected_udp(ports.dnscrypt);
        let dns = ports.dns;
        let dot = Forwarder::with_upstreams(
            vec![Upstream::dot(loopback(ports.dot), LOCAL_NAME)],
            ANSWER_TIMEOUT,
        )
        .with_trust(self.trust.clone());
        let doh = Forwarder::with_upstreams(
            vec![Upstream::doh(loopback(ports.doh), LOCAL_NAME, "/dns-query")],
            ANSWER_TIMEOUT,
        )
        .with_trust(self.trust.clone());
        let mut lanes = vec![
            (
                "UDP",
                Promise::Answered,
                Box::new(move |id| ask_udp(&udp, id, LOCAL_NAME, TYPE_A)) as Ask,
            ),
            (
                "TCP",
                Promise::Answered,
                Box::new(move |id| ask_tcp(dns, id)),
            ),
            (
                "DoT",
                Promise::Answered,
                Box::new(move |id| ask_forwarder(&dot, id)),
            ),
            (
                "DoH",
                Promise::Answered,
                Box::new(move |id| ask_forwarder(&doh, id)),
            ),
            // The DNSCrypt listener answers its certificate query without encryption.
            (
                "DNSCrypt",
                Promise::Answered,
                Box::new(move |id| ask_udp(&dnscrypt, id, DNSCRYPT_PROVIDER, TYPE_TXT)),
            ),
        ];
        for (name, forwarder) in &self.quic {
            let forwarder = forwarder.clone();
            lanes.push((
                *name,
                Promise::Reconnects,
                Box::new(move |id| ask_forwarder(&forwarder, id)),
            ));
        }
        lanes
    }

    /// The QUIC clients from the lanes get answers again.
    fn assert_quic_reconnected(&self) {
        for (name, forwarder) in &self.quic {
            if let Err(error) = ask_forwarder(forwarder, 1) {
                panic!("{name} 클라이언트가 다시 연결하지 못했습니다: {error}");
            }
        }
    }

    /// Creates the first account with the setup code, as the dashboard does, and returns its
    /// session cookie.
    fn sign_in(&self, dir: &Path) -> String {
        let code = std::fs::read_to_string(dir.join("setup-code.txt"))
            .expect("설정 코드를 읽지 못했습니다");
        let body = format!(
            "{{\"code\":\"{}\",\"user\":\"admin\",\"password\":\"{ADMIN_PASSWORD}\"}}",
            code.trim()
        );
        let response = http(
            self.ports.control,
            "POST",
            "/v1/setup",
            "Content-Type: application/json\r\n",
            &body,
        )
        .expect("계정을 만들지 못했습니다");
        response
            .lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .and_then(|cookie| cookie.split(';').next())
            .unwrap_or_else(|| panic!("세션 쿠키가 없습니다:\n{response}"))
            .to_string()
    }

    fn signed_in(&self, cookie: &str) -> bool {
        http(
            self.ports.control,
            "GET",
            "/v1/stats",
            &format!("Cookie: {cookie}\r\n"),
            "",
        )
        .is_ok_and(|response| response.starts_with("HTTP/1.1 200"))
    }

    fn total_queries(&self) -> u64 {
        let response = http(self.ports.control, "GET", "/v1/stats", &bearer(), "")
            .expect("통계를 읽지 못했습니다");
        response
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| onetdns_core::json::parse(body).ok())
            .and_then(|json| json.get("metrics")?.get("total")?.as_u64())
            .unwrap_or_else(|| panic!("통계 응답에 total 이 없습니다:\n{response}"))
    }

    /// The resolver public key and client magic in the DNSCrypt certificate, which clients
    /// encrypt their queries with.
    fn dnscrypt_resolver_key(&self) -> Vec<u8> {
        let socket = connected_udp(self.ports.dnscrypt);
        let request = query(1, DNSCRYPT_PROVIDER, TYPE_TXT);
        socket
            .send(&request)
            .expect("인증서 질의를 보내지 못했습니다");
        let mut answer = [0u8; 1232];
        let length = socket
            .recv(&mut answer)
            .expect("인증서 질의의 응답이 없습니다");
        // After the question: name pointer, type, class, TTL, RDATA length, TXT length.
        let cert = &answer[request.len() + 13..length];
        cert[72..112].to_vec()
    }

    /// Starts a rollback, as the dashboard does, once the management API takes it.
    fn request_rollback(&self) {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            match http(
                self.ports.control,
                "POST",
                "/v1/system/update/rollback",
                &bearer(),
                "",
            ) {
                Ok(response) if response.starts_with("HTTP/1.1 200") => return,
                Ok(response) if !response.starts_with("HTTP/1.1 503") => {
                    panic!("되돌리기 요청이 거절됐습니다:\n{response}")
                }
                _ if Instant::now() >= deadline => {
                    panic!("관리 API 가 되돌리기 요청을 받지 않습니다")
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

/// Backslashes in a TOML string are escapes, and Windows accepts forward slashes.
fn toml_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn bearer() -> String {
    format!("Authorization: Bearer {CONTROL_TOKEN}\r\n")
}

/// The whole response, status line first.
fn http(port: u16, method: &str, path: &str, headers: &str, body: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(loopback(port))?;
    stream.set_read_timeout(Some(EVENT_TIMEOUT))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    message
}

fn check_answer(id: u16, answer: &[u8]) -> Result<(), String> {
    if answer.len() < 12 || answer[..2] != id.to_be_bytes() || answer[2] & 0x80 == 0 {
        return Err(format!("질의 {id} 의 응답이 아닙니다: {answer:?}"));
    }
    let rcode = answer[3] & 0x0f;
    let answers = u16::from_be_bytes([answer[6], answer[7]]);
    if rcode != 0 || answers == 0 {
        return Err(format!(
            "질의 {id} 의 응답 코드 {rcode}, 응답 레코드 {answers}개"
        ));
    }
    Ok(())
}

fn connected_udp(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("UDP 소켓을 열지 못했습니다");
    socket
        .connect(loopback(port))
        .expect("UDP 소켓을 연결하지 못했습니다");
    socket
        .set_read_timeout(Some(ANSWER_TIMEOUT))
        .expect("UDP 대기 시간");
    socket
}

fn ask_udp(socket: &UdpSocket, id: u16, name: &str, qtype: u16) -> Result<(), String> {
    socket
        .send(&query(id, name, qtype))
        .map_err(|error| format!("질의 {id} 를 보내지 못했습니다: {error}"))?;
    let mut answer = [0u8; 1232];
    let length = socket
        .recv(&mut answer)
        .map_err(|error| format!("질의 {id} 의 응답이 없습니다: {error}"))?;
    check_answer(id, &answer[..length])
}

fn ask_tcp(port: u16, id: u16) -> Result<(), String> {
    let exchange = || -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&loopback(port), ANSWER_TIMEOUT)?;
        stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
        let message = query(id, LOCAL_NAME, TYPE_A);
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&message);
        stream.write_all(&framed)?;
        let mut length = [0u8; 2];
        stream.read_exact(&mut length)?;
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut answer)?;
        Ok(answer)
    };
    let answer = exchange().map_err(|error| format!("질의 {id} 가 실패했습니다: {error}"))?;
    check_answer(id, &answer)
}

fn ask_forwarder(forwarder: &Forwarder, id: u16) -> Result<(), String> {
    let request = Message::parse(&query(id, LOCAL_NAME, TYPE_A))
        .map_err(|error| format!("질의 {id} 를 만들지 못했습니다: {error:?}"))?;
    let answer = forwarder
        .resolve(&request)
        .map_err(|error| format!("질의 {id} 가 실패했습니다: {error}"))?;
    if answer.header.rcode != 0 || answer.answers.is_empty() {
        return Err(format!(
            "질의 {id} 의 응답 코드 {}, 응답 레코드 {}개",
            answer.header.rcode,
            answer.answers.len()
        ));
    }
    Ok(())
}

type Ask = Box<dyn FnMut(u16) -> Result<(), String> + Send>;

#[derive(Default)]
struct Tally {
    answered: u64,
    /// Failures a lane's promise does not allow.
    failures: Vec<String>,
    /// Failures a lane's promise allows.
    allowed: u64,
}

/// Each lane asks in turn on its own thread until finished.
struct Load {
    stop: Arc<AtomicBool>,
    lanes: Vec<std::thread::JoinHandle<Tally>>,
}

impl Load {
    fn start(lanes: Vec<(&'static str, Promise, Ask)>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let lanes = lanes
            .into_iter()
            .map(|(name, promise, mut ask)| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut tally = Tally::default();
                    let mut id: u16 = 0;
                    while !stop.load(Ordering::Relaxed) {
                        id = id.wrapping_add(1);
                        match ask(id) {
                            Ok(()) => tally.answered += 1,
                            Err(_) if promise == Promise::Reconnects => tally.allowed += 1,
                            Err(error) => tally.failures.push(format!("{name}: {error}")),
                        }
                        std::thread::sleep(QUERY_PACE);
                    }
                    if tally.answered == 0 {
                        tally
                            .failures
                            .push(format!("{name}: 답을 받은 질의가 없습니다"));
                    }
                    tally
                })
            })
            .collect();
        Self { stop, lanes }
    }

    fn finish(mut self) -> Tally {
        self.stop.store(true, Ordering::Relaxed);
        let mut total = Tally::default();
        for lane in std::mem::take(&mut self.lanes) {
            let tally = lane.join().expect("질의 스레드가 패닉했습니다");
            total.answered += tally.answered;
            total.failures.extend(tally.failures);
            total.allowed += tally.allowed;
        }
        total
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn children_of(parent: i32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let ppid: i32 = stat
                .rsplit_once(')')?
                .1
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()?;
            (ppid == parent).then_some(pid)
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn children_of(parent: i32) -> Vec<i32> {
    let mut pids = vec![0 as libc::pid_t; 256];
    let size = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
    // SAFETY: `pids` is valid for `size` bytes.
    let found = unsafe { libc::proc_listchildpids(parent, pids.as_mut_ptr().cast(), size) };
    // The count is in PIDs on current systems; unfilled entries stay zero either way.
    let found = usize::try_from(found).unwrap_or(0).min(pids.len());
    pids.into_iter()
        .take(found)
        .filter(|pid| *pid > 0)
        .collect()
}

/// Only the server's own children: a console the supervisor gets also shows up as its child.
#[cfg(windows)]
fn children_of(parent: i32) -> Vec<i32> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    // SAFETY: takes no pointers; the result is checked before use.
    let snapshot = unsafe { win32::CreateToolhelp32Snapshot(win32::TH32CS_SNAPPROCESS, 0) };
    if snapshot == -1 {
        return Vec::new();
    }
    // SAFETY: a new handle that nothing else owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as _) };
    // SAFETY: all-zero bits are a valid PROCESSENTRY32W for the calls to fill.
    let mut entry: win32::PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<win32::PROCESSENTRY32W>() as u32;
    let mut children = Vec::new();
    // SAFETY: `entry` is sized as dwSize says.
    let mut more =
        unsafe { win32::Process32FirstW(snapshot.as_raw_handle() as isize, &mut entry) } != 0;
    while more {
        let length = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(0);
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ParentProcessID == parent as u32 && name.eq_ignore_ascii_case(PROGRAM) {
            children.push(entry.th32ProcessID as i32);
        }
        // SAFETY: as above.
        more = unsafe { win32::Process32NextW(snapshot.as_raw_handle() as isize, &mut entry) } != 0;
    }
    children
}

#[cfg(windows)]
#[allow(non_snake_case, clippy::upper_case_acronyms)]
mod win32 {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;

    pub const TH32CS_SNAPPROCESS: u32 = 0x2;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    #[repr(C)]
    pub struct PROCESSENTRY32W {
        pub dwSize: u32,
        pub cntUsage: u32,
        pub th32ProcessID: u32,
        pub th32DefaultHeapID: usize,
        pub th32ModuleID: u32,
        pub cntThreads: u32,
        pub th32ParentProcessID: u32,
        pub pcPriClassBase: i32,
        pub dwFlags: u32,
        pub szExeFile: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateToolhelp32Snapshot(flags: u32, process: u32) -> isize;
        pub fn Process32FirstW(snapshot: isize, entry: *mut PROCESSENTRY32W) -> i32;
        pub fn Process32NextW(snapshot: isize, entry: *mut PROCESSENTRY32W) -> i32;
        fn OpenProcess(access: u32, inherit: i32, process: u32) -> isize;
        fn QueryFullProcessImageNameW(
            process: isize,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn TerminateProcess(process: isize, code: u32) -> i32;
        fn WaitForSingleObject(handle: isize, milliseconds: u32) -> u32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        /// Undocumented, and what debuggers use to stop a process where it is.
        pub fn NtSuspendProcess(process: isize) -> i32;
    }

    /// A handle to `pid` while it runs an executable in `dir`.
    pub fn open_running_in(pid: i32, dir: &Path) -> Option<OwnedHandle> {
        // SAFETY: takes no pointers; the result is checked before use.
        let handle = unsafe {
            OpenProcess(
                PROCESS_TERMINATE
                    | PROCESS_SUSPEND_RESUME
                    | PROCESS_QUERY_LIMITED_INFORMATION
                    | SYNCHRONIZE,
                0,
                pid as u32,
            )
        };
        if handle == 0 {
            return None;
        }
        // SAFETY: a new handle that nothing else owns.
        let process = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        let mut name = [0u16; 1024];
        let mut size = name.len() as u32;
        // SAFETY: `name` holds `size` units.
        let named = unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle() as isize,
                0,
                name.as_mut_ptr(),
                &mut size,
            )
        } != 0;
        let image = String::from_utf16_lossy(&name[..size as usize]);
        let image_dir = Path::new(&image).parent()?.display().to_string();
        (named && image_dir.eq_ignore_ascii_case(&dir.display().to_string())).then_some(process)
    }

    /// Terminates the process and waits until it has exited.
    pub fn end(process: &OwnedHandle) {
        // SAFETY: the handle is open with PROCESS_TERMINATE and SYNCHRONIZE.
        unsafe {
            TerminateProcess(process.as_raw_handle() as isize, 1);
            WaitForSingleObject(
                process.as_raw_handle() as isize,
                super::EXIT_TIMEOUT.as_millis() as u32,
            );
        }
    }
}

fn assert_no_query_failed(load: Load, server: &Server) {
    let tally = load.finish();
    assert!(
        tally.failures.is_empty(),
        "질의 {}개가 답을 받았고 {}개가 실패했습니다(QUIC 에서 허용한 실패 {}개 제외): {:?}\n{}",
        tally.answered,
        tally.failures.len(),
        tally.allowed,
        tally.failures,
        server.log_text()
    );
}

/// Logged once the successor is the supervisor's only child. A Linux or macOS supervisor then runs
/// from the install path; a Windows supervisor stays the version it started as.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SUPERVISING_THE_SUCCESSOR: &str = "supervisor.update_exec";
#[cfg(windows)]
const SUPERVISING_THE_SUCCESSOR: &str = "supervisor.predecessor_ended";

#[test]
/// A rollback through the management API starts the previous executable beside the running worker,
/// which hands its sockets and state over. Queries keep being answered on every transport but
/// QUIC, whose clients connect again; the counts, the dashboard session, and the DNSCrypt key
/// carry over; and the successor is then the supervisor's only child.
fn an_update_hands_over_without_failing_a_query() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let handoff = Handoff::prepare(dir);

    let mut server = Server::supervised(dir, handoff.swapped.program.clone(), &handoff.config);
    let first = server.wait_for("server.ready", None);
    server.children.push(first);
    let cookie = handoff.sign_in(dir);
    let dnscrypt_key = handoff.dnscrypt_resolver_key();
    let load = Load::start(handoff.lanes());
    std::thread::sleep(LOAD_BEFORE_UPDATE);
    handoff.request_rollback();
    server.wait_for_own("update.trial_started");
    let counted_before = handoff.total_queries();
    server.wait_for_own(SUPERVISING_THE_SUCCESSOR);
    let children = children_of(server.pid());
    server.children.extend(&children);
    let counted_after = handoff.total_queries();
    // Lets the successor answer under the supervisor's new image for a while.
    std::thread::sleep(Duration::from_secs(1));
    assert_no_query_failed(load, &server);
    handoff.assert_quic_reconnected();

    assert!(
        children.len() == 1 && children[0] != first,
        "감독자의 자식 {children:?}, 이전 작업 프로세스 {first}"
    );
    assert!(
        counted_after >= counted_before,
        "인계 전 질의 수 {counted_before}, 인계 뒤 {counted_after}"
    );
    assert!(
        handoff.signed_in(&cookie),
        "인계 뒤 대시보드 세션이 풀렸습니다"
    );
    assert_eq!(
        handoff.dnscrypt_resolver_key(),
        dnscrypt_key,
        "DNSCrypt 리졸버 키"
    );
    let record = handoff.swapped.record_text();
    assert!(record.contains("state=committed\n"), "{record}");
    assert_eq!(
        sha256_hex(&handoff.swapped.program),
        handoff.swapped.previous_sha256,
        "설치 경로"
    );
    assert_eq!(
        sha256_hex(&handoff.swapped.previous),
        handoff.swapped.new_sha256,
        ".previous"
    );
}

#[test]
/// The successor is stopped as soon as its trial begins, before the running worker notices the
/// link on its next wake and gives it sockets, and killed once the handoff starts. The running
/// worker takes its sockets back and serves on, and the rollback is put back.
fn a_successor_that_dies_during_the_handoff_fails_no_query() {
    let scratch = ScratchDir::create();
    let dir = &scratch.0;
    let handoff = Handoff::prepare(dir);

    let mut server = Server::supervised(dir, handoff.swapped.program.clone(), &handoff.config);
    let first = server.wait_for("server.ready", None);
    server.children.push(first);
    let load = Load::start(handoff.lanes());
    handoff.request_rollback();
    server.wait_for_own("update.trial_started");
    let successor = children_of(server.pid())
        .into_iter()
        .find(|pid| *pid != first)
        .expect("후속 프로세스가 없습니다");
    server.freeze(successor);
    assert_eq!(server.wait_for("handoff.started", None), first);
    server.kill(successor);
    server.wait_for_own("update.reverted");
    std::thread::sleep(Duration::from_secs(1));
    assert_no_query_failed(load, &server);
    handoff.assert_quic_reconnected();

    assert_eq!(children_of(server.pid()), vec![first]);
    let record = handoff.swapped.record_text();
    assert!(record.contains("state=reverted\n"), "{record}");
    assert!(
        record.contains("reason=The new version exited before it became ready"),
        "{record}"
    );
    assert_eq!(
        sha256_hex(&handoff.swapped.program),
        handoff.swapped.new_sha256,
        "설치 경로"
    );
}
