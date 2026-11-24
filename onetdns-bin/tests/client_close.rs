//! A client that closes its TCP connection before reading the answers must not end the server.
//! On Unix a write to such a connection raises SIGPIPE, which ends a process that does not ignore
//! it.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(60);

/// Killed on drop, so a failed assertion leaves no process behind.
struct Server {
    process: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Free for both TCP and UDP when this returns.
fn free_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A length-prefixed A query for a blocked name, so the server answers without an upstream.
fn framed_query(id: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in [format!("q{id}").as_str(), "blocked", "test"] {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&wire);
    framed
}

fn answers(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut len = [0u8; 2];
    stream.write_all(&framed_query(1)).is_ok() && stream.read_exact(&mut len).is_ok()
}

#[test]
fn a_client_that_closes_before_reading_does_not_end_the_server() {
    let dir = std::env::temp_dir().join(format!("onetdns-client-close-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    let config = dir.join("OnetDNS.toml");
    std::fs::write(
        &config,
        format!(
            "listen = [\"{addr}\"]\nbackend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\nblock_rules = [\"||blocked.test^\"]\n"
        ),
    )
    .unwrap();
    let process = Command::new(env!("CARGO_BIN_EXE_OnetDNS"))
        .args(["run", "--no-web", "--no-supervisor", "--config"])
        .arg(&config)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("서버를 띄우지 못했습니다");
    let mut server = Server { process, dir };

    let deadline = Instant::now() + START_TIMEOUT;
    while !answers(addr) {
        assert!(
            server.process.try_wait().unwrap().is_none(),
            "서버가 답하기 전에 끝났습니다"
        );
        assert!(Instant::now() < deadline, "서버가 답하지 않습니다");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Several queries in one write, then a close: the answers after the first meet a reset
    // connection.
    for round in 0..20u16 {
        let Ok(mut stream) = TcpStream::connect(addr) else {
            break;
        };
        let batch: Vec<u8> = (0..8).flat_map(|k| framed_query(round * 8 + k)).collect();
        let _ = stream.write_all(&batch);
    }
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        server.process.try_wait().unwrap(),
        None,
        "먼저 연결을 닫은 클라이언트 때문에 서버가 끝났습니다"
    );
    assert!(answers(addr), "서버가 더 이상 답하지 않습니다");
}
