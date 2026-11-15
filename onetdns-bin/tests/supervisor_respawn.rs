//! Which executable the server starts processes from while that executable changes. Package
//! managers and the self-update replace it by rename; a supervisor that restarted a dead child from
//! the install path would find another file there, and the restart would fail or start a different
//! build. A version swapped in by an update, in contrast, starts on trial: committed once ready,
//! and if it exits before that, the install path is restored to the previous executable and exec'd.
//!
//! The real binary is copied to a temporary directory and run both supervised and as a single
//! process.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Enough for a slow first start on CI.
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

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
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("시계")
            .as_nanos();
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("임시 디렉터리의 실제 경로");
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

    /// Kills `pid` only when it runs this test's binary.
    fn kill_if_ours(&self, pid: i32) {
        if argv0(pid).as_deref() == Some(self.program.as_os_str().as_bytes()) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
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
        let _ = self.process.kill();
        let _ = self.process.wait();
        for pid in &self.children {
            self.kill_if_ours(*pid);
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
fn argv0(pid: i32) -> Option<Vec<u8>> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    cmdline.split(|byte| *byte == 0).next().map(<[u8]>::to_vec)
}

/// Holds UDP and TCP on a free loopback port, so the server cannot bind it until they are dropped.
/// Returns the sockets it found with: releasing and rebinding would let another socket take the
/// port.
fn hold_free_port() -> (u16, (UdpSocket, TcpListener)) {
    for _ in 0..32 {
        let tcp = TcpListener::bind("127.0.0.1:0").expect("TCP 포트를 잡지 못했습니다");
        let port = tcp.local_addr().expect("TCP 주소").port();
        if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) {
            return (port, (udp, tcp));
        }
    }
    panic!("UDP 와 TCP 가 함께 비어 있는 포트를 찾지 못했습니다");
}

/// Released at once for the server to bind.
fn free_port() -> u16 {
    hold_free_port().0
}

fn write_config(dir: &Path, port: u16) -> PathBuf {
    let config = dir.join("onetdns.toml");
    std::fs::write(&config, format!("listen = [\"127.0.0.1:{port}\"]\n"))
        .expect("설정을 쓰지 못했습니다");
    config
}

fn install_copy(dir: &Path) -> PathBuf {
    let program = dir.join("OnetDNS");
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
        let previous = dir.join("OnetDNS.previous");
        let mut image = std::fs::read(&program).expect("바이너리를 읽지 못했습니다");
        image.extend_from_slice(b"\0previous\0");
        let exec = exec_lock();
        std::fs::write(&previous, &image).expect("이전 실행 파일을 쓰지 못했습니다");
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
