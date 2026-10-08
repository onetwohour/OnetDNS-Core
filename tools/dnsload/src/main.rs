/*!
 * @brief 어느 플랫폼에서나 실행되는 DNS 부하 발생기.
 *
 * @details dnsperf는 윈도우에 없다. WSL에서 가상 스위치를 건너 때리면 경로가 초당
 *          1만 질의에서 막혀 서버를 채우지 못하고, 그러면 측정하는 값이 서버가 아니라
 *          가상 스위치의 성질이 된다. 루프백으로 부하를 넣을 수 있는 도구가 있어야
 *          윈도우에서 서버를 판정할 수 있다.
 * @details 질의 목록과 요약 출력은 dnsperf와 같은 모양이라 기존 하네스가 그대로 읽는다.
 * @note 루트 워크스페이스에 넣지 않는다. tls-diff와 같은 방식으로 따로 빌드한다.
 */

use std::net::UdpSocket;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use onetdns_proto::{Message, Name, RecordType};

/** @brief 응답을 받을 버퍼 크기. 잘린 응답도 세어야 하므로 넉넉히 잡는다. */
const RECV_BUF: usize = 4096;

/** @brief 응답을 기다리다 포기하는 시간. 이보다 길면 종료가 굼떠진다. */
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

/** @brief 데드라인을 확인하기 전에 보낼 질의 수. 매번 시계를 보면 그 비용이 측정을 흔든다. */
const DEADLINE_CHECK_EVERY: u64 = 256;

/**
 * @brief 이 호스트의 UDP 왕복 바닥값을 재기 위한 최소 에코 서버.
 *
 * @details 측정한 지연이 서버 탓인지 이 플랫폼의 UDP 경로 탓인지 가르려면 비교 대상이
 *          있어야 한다. 받은 바이트를 그대로 돌려주므로 DNS 처리 비용이 0인 서버다.
 *          여기서 나온 값이 어떤 DNS 서버도 넘을 수 없는 바닥이다.
 * @param port 받을 포트.
 * @param workers 수신 스레드 수.
 */
fn serve_echo(port: u16, workers: usize) -> Result<(), String> {
    let sock = UdpSocket::bind(("127.0.0.1", port))
        .map_err(|e| format!("{port} 포트를 열지 못했습니다: {e}"))?;
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let sock = sock
            .try_clone()
            .map_err(|e| format!("소켓을 복제하지 못했습니다: {e}"))?;
        handles.push(std::thread::spawn(move || {
            let mut buf = [0u8; RECV_BUF];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        let _ = sock.send_to(&buf[..len], from);
                    }
                    Err(_) => break,
                }
            }
        }));
    }
    println!("에코 서버가 127.0.0.1:{port}에서 {workers}개 스레드로 돕니다. Ctrl+C로 끝냅니다.");
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

/** @brief 명령줄 설정. */
struct Args {
    /** @brief 때릴 서버 주소. */
    server: String,
    /** @brief 질의 목록 파일. 한 줄에 "이름 타입". */
    queries: String,
    /** @brief 부하를 넣을 시간. */
    seconds: u64,
    /** @brief 스레드 수. 스레드마다 소켓 하나를 쓴다. */
    threads: usize,
    /** @brief 스레드당 미회수 질의 상한. */
    outstanding: usize,
}

/** @brief 인자를 읽는다. 없으면 기본값을 쓴다. */
fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        server: "127.0.0.1:15353".to_string(),
        queries: String::new(),
        seconds: 10,
        threads: 4,
        outstanding: 64,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} 뒤에 값이 없습니다"));
        match flag.as_str() {
            "-s" | "--server" => args.server = value()?,
            "-d" | "--queries" => args.queries = value()?,
            "-l" | "--seconds" => {
                args.seconds = value()?.parse().map_err(|_| "초는 숫자여야 합니다".to_string())?
            }
            "-T" | "--threads" => {
                args.threads = value()?
                    .parse()
                    .map_err(|_| "스레드 수는 숫자여야 합니다".to_string())?
            }
            "-c" | "--outstanding" => {
                args.outstanding = value()?
                    .parse()
                    .map_err(|_| "미회수 상한은 숫자여야 합니다".to_string())?
            }
            other => return Err(format!("모르는 인자입니다: {other}")),
        }
    }
    if args.queries.is_empty() {
        return Err("-d 로 질의 목록 파일을 주어야 합니다".to_string());
    }
    if args.threads == 0 || args.outstanding == 0 {
        return Err("스레드 수와 미회수 상한은 1 이상이어야 합니다".to_string());
    }
    Ok(args)
}

/** @brief 이름 문자열을 레코드 타입으로. 목록에 없는 타입은 A로 본다. */
fn record_type(text: &str) -> RecordType {
    match text.to_ascii_uppercase().as_str() {
        "AAAA" => RecordType::AAAA,
        "NS" => RecordType::NS,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "SOA" => RecordType::SOA,
        "PTR" => RecordType::PTR,
        _ => RecordType::A,
    }
}

/**
 * @brief 질의 목록을 미리 와이어 바이트로 굽는다.
 *
 * @details 보낼 때마다 인코딩하면 그 비용이 발생기 쪽 병목이 된다. 응답은 개수만 세므로
 *          거래 번호를 위치마다 고정해도 된다.
 * @return 질의 하나당 바이트열. 목록이 비었으면 오류.
 */
fn bake_queries(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}를 읽지 못했습니다: {e}"))?;
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name_text) = parts.next() else {
            continue;
        };
        let qtype = record_type(parts.next().unwrap_or("A"));
        let name = Name::from_str(name_text).map_err(|e| format!("{name_text}: {e:?}"))?;
        let message = Message::query((index & 0xffff) as u16, name, qtype);
        out.push(
            message
                .try_encode()
                .map_err(|e| format!("{name_text} 인코딩 실패: {e:?}"))?,
        );
    }
    if out.is_empty() {
        return Err(format!("{path}에 질의가 없습니다"));
    }
    Ok(out)
}

/**
 * @brief 스레드 하나가 데드라인까지 질의를 넣고 응답을 센다.
 *
 * @details 미회수 상한까지 보내고 하나 받으면 하나 더 보낸다. 상한이 곧 이 스레드가
 *          서버에 거는 압력이다. 수신이 시간을 넘기면 그 시점의 미회수는 잃은 것으로
 *          보고 다시 채운다 — 그러지 않으면 상한이 영구히 잠긴다.
 * @return (보낸 수, 받은 수).
 */
fn run_thread(
    server: &str,
    queries: &[Vec<u8>],
    start_index: usize,
    outstanding: usize,
    deadline: Instant,
) -> Result<(u64, u64), String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("소켓을 열지 못했습니다: {e}"))?;
    sock.connect(server)
        .map_err(|e| format!("{server}에 연결하지 못했습니다: {e}"))?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))
        .map_err(|e| format!("수신 데드라인을 걸지 못했습니다: {e}"))?;

    let mut buf = [0u8; RECV_BUF];
    let mut sent = 0u64;
    let mut completed = 0u64;
    let mut in_flight = 0usize;
    let mut index = start_index;
    let mut since_check = 0u64;

    loop {
        while in_flight < outstanding {
            if sock.send(&queries[index % queries.len()]).is_err() {
                break;
            }
            index += 1;
            sent += 1;
            in_flight += 1;
            since_check += 1;
        }
        match sock.recv(&mut buf) {
            Ok(_) => {
                completed += 1;
                in_flight -= 1;
            }
            Err(_) => {
                /* 데드라인을 넘긴 미회수는 다시 오지 않는다. 잠긴 곳을 풀어 준다. */
                in_flight = 0;
            }
        }
        since_check += 1;
        if since_check >= DEADLINE_CHECK_EVERY {
            since_check = 0;
            if Instant::now() >= deadline {
                break;
            }
        }
    }
    Ok((sent, completed))
}

/** @brief 두 수의 비율을 백분율로. 분모가 0이면 0. */
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

fn main() {
    /* 바닥값 측정 모드. 질의 목록도 데드라인도 필요 없으므로 인자 검사 앞에서 갈라진다. */
    let raw: Vec<String> = std::env::args().collect();
    if let Some(at) = raw.iter().position(|a| a == "--serve-echo") {
        let port: u16 = raw
            .get(at + 1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(15354);
        let workers: usize = raw.get(at + 2).and_then(|v| v.parse().ok()).unwrap_or(4);
        if let Err(message) = serve_echo(port, workers) {
            eprintln!("{message}");
            std::process::exit(1);
        }
        return;
    }

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("사용법: dnsload -s IP:PORT -d 질의목록 [-l 초] [-T 스레드] [-c 미회수]");
            std::process::exit(2);
        }
    };
    let queries = match bake_queries(&args.queries) {
        Ok(queries) => Arc::new(queries),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let sent = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    let started = Instant::now();

    let mut handles = Vec::with_capacity(args.threads);
    for worker in 0..args.threads {
        let queries = Arc::clone(&queries);
        let sent = Arc::clone(&sent);
        let completed = Arc::clone(&completed);
        let server = args.server.clone();
        let outstanding = args.outstanding;
        /* 스레드마다 목록의 다른 지점에서 시작해 같은 이름에 몰리지 않게 한다. */
        let start = worker.wrapping_mul(queries.len() / args.threads.max(1));
        handles.push(std::thread::spawn(move || {
            match run_thread(&server, &queries, start, outstanding, deadline) {
                Ok((s, c)) => {
                    sent.fetch_add(s, Ordering::Relaxed);
                    completed.fetch_add(c, Ordering::Relaxed);
                }
                Err(message) => eprintln!("{message}"),
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }

    let elapsed = started.elapsed().as_secs_f64();
    let sent = sent.load(Ordering::Relaxed);
    let completed = completed.load(Ordering::Relaxed);
    let lost = sent.saturating_sub(completed);
    let rate = if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    };

    println!("Statistics:");
    println!();
    println!("  Queries sent:         {sent}");
    println!(
        "  Queries completed:    {completed} ({:.2}%)",
        percent(completed, sent)
    );
    println!("  Queries lost:         {lost} ({:.2}%)", percent(lost, sent));
    println!();
    println!("  Run time (s):         {elapsed:.6}");
    println!("  Queries per second:   {rate:.6}");
}
