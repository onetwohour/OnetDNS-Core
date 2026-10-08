/*!
 * @brief 실행 파일이 바뀌는 상황에서 서버가 어느 실행 파일로 프로세스를 띄우는지 확인한다.
 *
 * @details 패키지 관리자와 자체 업데이트는 실행 파일을 rename 으로 바꾼다. 그 뒤 자식이
 *          죽었을 때 감독자가 설치 경로로 다시 띄우면, 그 경로에는 다른 파일이 있으므로
 *          재시작이 실패하거나 다른 판이 뜬다. 반대로 업데이트가 맞바꾼 새 버전은 시험 실행으로
 *          시작해서, 준비 상태에 이르면 확정하고 준비 전에 끝나면 설치 경로를 이전 실행 파일로
 *          되돌린 뒤 그 경로를 exec 해야 한다. 실제 바이너리를 임시 디렉터리에 복사해 감독 모드와
 *          단독 프로세스로 띄워 확인한다.
 */
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

/** @brief 사건 하나를 기다리는 상한. 느린 CI 에서 첫 기동이 늦어도 넘지 않을 만큼 둔다. */
const EVENT_TIMEOUT: Duration = Duration::from_secs(60);
/** @brief 서버가 종료 신호를 받고 끝나기를 기다리는 상한. */
const EXIT_TIMEOUT: Duration = Duration::from_secs(15);

/**
 * @brief 실행할 파일을 쓰는 일과 프로세스를 띄우는 일을 한 번에 하나만 하게 하는 잠금.
 * @details 테스트는 한 프로세스의 여러 스레드에서 돈다. 한 스레드가 파일을 쓰려고 연 기술자는
 *          그동안 다른 스레드가 띄운 자식에게 복제되어 그 자식이 exec 할 때까지 남는다. 그사이에
 *          그 파일을 실행하면 리눅스는 ETXTBSY 로 거부한다. spawn 은 자식이 exec 한 뒤에
 *          돌아오므로, 쓰기와 띄우기를 이 잠금 안에서 하면 쓰기용 기술자를 쥔 자식이 남지 않는다.
 */
static EXEC_LOCK: Mutex<()> = Mutex::new(());

/** @brief EXEC_LOCK 을 잡는다. 잡은 채 실패한 테스트가 있어도 다른 테스트는 계속 잡는다. */
fn exec_lock() -> std::sync::MutexGuard<'static, ()> {
    EXEC_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/** @brief 실행할 파일을 쓰는 스레드가 없을 때 띄운다. */
fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _exec = exec_lock();
    command.spawn()
}

/**
 * @brief Command::output 처럼 표준 출력과 오류를 모으며 끝날 때까지 기다린다.
 * @details 띄우는 일은 spawn 이 맡는다. 기다리는 동안에는 잠금을 잡지 않는다.
 */
fn output_of(command: &mut Command) -> std::io::Result<std::process::Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn(command)?.wait_with_output()
}

/** @brief 기록 한 줄에서 꺼낸 사건 이름과 그 기록을 남긴 프로세스. */
struct Event {
    /** @brief event 필드. */
    name: String,
    /** @brief 기록을 남긴 프로세스 번호. */
    pid: i32,
}

/** @brief 바이너리와 설정을 둘 임시 디렉터리. 테스트가 어디서 실패해도 지운다. */
struct ScratchDir(PathBuf);

impl ScratchDir {
    /** @brief 이 테스트만 쓰는 디렉터리를 만든다. 경로는 심볼릭 링크를 푼 실제 경로다. */
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

/**
 * @brief 띄운 서버.
 * @details 단언이 실패해도 프로세스와 포트가 남지 않도록 drop 에서 정리한다.
 */
struct Server {
    /** @brief 띄운 바이너리의 경로. 자식의 argv[0] 도 이것이다. */
    program: PathBuf,
    /** @brief 띄운 프로세스. exec 해도 번호는 그대로다. */
    process: Child,
    /** @brief 표준 오류에서 읽은 사건. None 은 표준 오류가 닫혔다는 뜻이다. */
    events: Receiver<Option<Event>>,
    /** @brief 실패했을 때 보여 줄 전체 기록. */
    log: Arc<Mutex<Vec<String>>>,
    /** @brief 준비를 알린 자식들. 감독자가 정리하지 못했을 때 대신 끝낸다. */
    children: Vec<i32>,
}

impl Server {
    /** @brief 감독 모드로 띄운다. */
    fn supervised(dir: &Path, program: PathBuf, config: &Path) -> Self {
        Self::start(dir, program, config, &[])
    }

    /** @brief 감독자 없이 단독 프로세스로 띄운다. */
    fn single_process(dir: &Path, program: PathBuf, config: &Path) -> Self {
        Self::start(dir, program, config, &["--no-supervisor"])
    }

    /** @brief 띄우고 표준 오류를 읽기 시작한다. */
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

    /** @brief 띄운 프로세스의 번호. */
    fn pid(&self) -> i32 {
        self.process.id() as i32
    }

    /**
     * @brief 이 이름의 사건을 남긴 프로세스를 기다린다. 그 앞의 사건은 버린다.
     * @param exclude 이 프로세스가 남긴 것은 건너뛴다.
     * @return 사건을 남긴 프로세스 번호. 서버가 먼저 끝나거나 시간이 지나면 실패한다.
     */
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

    /** @brief 띄운 프로세스가 이 사건을 남기기를 기다린다. exec 한 뒤의 기록도 같은 번호다. */
    fn wait_for_own(&self, name: &str) {
        let pid = self.wait_for(name, None);
        assert_eq!(
            pid,
            self.pid(),
            "{name} 을 남긴 프로세스\n{}",
            self.log_text()
        );
    }

    /** @brief 지금까지 읽은 기록 전체. */
    fn log_text(&self) -> String {
        self.log.lock().expect("기록 잠금").join("\n")
    }

    /** @brief 이 프로세스가 이 테스트가 띄운 바이너리로 돌고 있으면 끝낸다. */
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

/** @brief JSON 기록 한 줄에서 사건 이름과 프로세스 번호를 꺼낸다. */
fn parse_event(line: &str) -> Option<Event> {
    let json = onetdns_core::json::parse(line).ok()?;
    let name = json.get("event")?.as_str()?.to_string();
    let pid = i32::try_from(json.get("pid")?.as_u64()?).ok()?;
    Some(Event { name, pid })
}

/** @brief 프로세스의 argv[0]. 이미 끝났으면 없다. */
fn argv0(pid: i32) -> Option<Vec<u8>> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    cmdline.split(|byte| *byte == 0).next().map(<[u8]>::to_vec)
}

/**
 * @brief 비어 있는 루프백 포트의 UDP 와 TCP 를 함께 잡아 둔다. 놓을 때까지 서버는 이 포트에
 *        묶지 못한다.
 * @details 찾을 때 잡은 소켓을 그대로 돌려준다. 빈 포트를 찾고 놓았다가 다시 잡으면 그사이에
 *          다른 소켓이 그 포트를 가져갈 수 있다.
 */
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

/** @brief UDP 와 TCP 모두 비어 있는 루프백 포트. 서버가 묶도록 바로 놓는다. */
fn free_port() -> u16 {
    hold_free_port().0
}

/** @brief 이 포트에서 듣는 설정 파일을 쓴다. */
fn write_config(dir: &Path, port: u16) -> PathBuf {
    let config = dir.join("onetdns.toml");
    std::fs::write(&config, format!("listen = [\"127.0.0.1:{port}\"]\n"))
        .expect("설정을 쓰지 못했습니다");
    config
}

/** @brief 이 바이너리를 임시 디렉터리의 설치 경로에 복사한다. */
fn install_copy(dir: &Path) -> PathBuf {
    let program = dir.join("OnetDNS");
    let _exec = exec_lock();
    std::fs::copy(env!("CARGO_BIN_EXE_OnetDNS"), &program).expect("바이너리를 복사하지 못했습니다");
    program
}

/** @brief 파일의 SHA-256 을 업데이트 기록에 쓰는 소문자 16진 표기로. */
fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let bytes = std::fs::read(path).expect("해시할 파일을 읽지 못했습니다");
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/** @brief 실행 파일이 --version 으로 알리는 버전. */
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

/** @brief 관리 명령을 실행하고 끝날 때까지 기다린다. */
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

/** @brief 디렉터리에 있는 파일 이름들. */
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

/** @brief 업데이트가 설치 경로를 맞바꾼 직후의 디렉터리. */
struct Swapped {
    /** @brief 설치 경로. 새 버전이 들어 있다. */
    program: PathBuf,
    /** @brief 맞바꾸기 전 실행 파일. */
    previous: PathBuf,
    /** @brief 업데이트 기록. */
    record: PathBuf,
    /** @brief 새 버전의 해시. */
    new_sha256: String,
    /** @brief 맞바꾸기 전 실행 파일의 해시. */
    previous_sha256: String,
}

impl Swapped {
    /**
     * @brief 업데이트가 설치 경로를 맞바꾼 직후의 디렉터리를 꾸민다.
     * @details 설치 경로에는 이 바이너리를, .previous 에는 끝에 바이트를 덧붙여 해시만 다른 같은
     *          바이너리를 두고 pending 기록을 쓴다. 두 실행 파일의 버전이 같으므로 기록의 from 과
     *          to 도 같다.
     */
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

    /** @brief 기록 파일의 글. */
    fn record_text(&self) -> String {
        std::fs::read_to_string(&self.record).expect("업데이트 기록을 읽지 못했습니다")
    }

    /** @brief 기록을 확정 상태로 바꾼다. 시험을 마친 업데이트가 남기는 기록과 같다. */
    fn commit(&self) {
        let record = self
            .record_text()
            .replace("state=pending\n", "state=committed\n");
        std::fs::write(&self.record, record).expect("업데이트 기록을 쓰지 못했습니다");
    }

    /** @brief 새 버전이 확정됐는지. 설치 경로와 .previous 는 그대로여야 되돌리기에 쓸 수 있다. */
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

    /** @brief 이전 실행 파일로 되돌렸는지. 기록에는 이 이유가 남아야 한다. */
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
/**
 * @brief 설치 경로가 다른 파일로 바뀐 뒤 자식이 죽어도 같은 이미지로 다시 뜨는지.
 * @details 설치 경로에는 실행할 수 없는 파일을 둔다. 감독자가 그 경로로 띄우면 재시작이
 *          실패하고 감독자도 끝나므로 다음 준비 통지가 오지 않는다. 다시 뜬 자식은 프로세스
 *          이름과 argv[0] 도 원래 것이어야 pgrep 과 서비스 관리자가 찾는다.
 */
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
/** @brief 감독자가 시험 중인 새 버전의 자식이 준비되면 업데이트를 확정하는지. */
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
/**
 * @brief 시험 중인 새 버전의 자식이 준비 전에 끝나면 감독자가 이전 실행 파일로 되돌려 띄우는지.
 * @details 수신 포트를 미리 잡아 두면 새 버전의 자식은 준비 전에 끝난다. 감독자가 되돌린 뒤
 *          exec 하면 프로세스 번호가 그대로인 채 되돌린 업데이트를 알린다. 포트를 놓으면 되돌린
 *          실행 파일의 자식이 준비된다. 그 자식이 포트를 놓기 전에 묶으려다 실패해도 감독자가
 *          다시 띄운다.
 */
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
/** @brief 감독자 없이 도는 새 버전이 준비되면 업데이트를 확정하는지. */
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
/**
 * @brief 감독자 없이 도는 새 버전이 준비 전에 오류로 끝나면 되돌린 실행 파일을 exec 하는지.
 * @details 단독 프로세스는 다시 띄워 줄 감독자가 없다. 그래서 exec 한 이전 실행 파일도 포트가
 *          잡혀 있으면 오류로 끝나고, 이 테스트는 exec 한 프로세스가 되돌린 업데이트를 알리는
 *          데까지만 본다.
 */
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
/**
 * @brief 확정된 업데이트를 관리 명령으로 되돌리면 이전 실행 파일이 설치 경로에 들어가고, 다음
 *        시작이 그것을 시험해 확정하는지.
 * @details 되돌리기는 새 버전을 설치할 때와 같은 사전 점검과 맞바꾸기를 거친다. 실제 바이너리가
 *          자기 사본을 --version 과 --cli check 로 점검한다.
 */
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
/**
 * @brief 되돌릴 업데이트가 없으면 관리 명령이 실패하고 설치 디렉터리에 아무것도 만들지 않는지.
 * @details 잠금 파일도 만들지 않아야 한다. 되돌릴 것이 없는데 설치 디렉터리에 파일을 남기면 안 된다.
 */
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
