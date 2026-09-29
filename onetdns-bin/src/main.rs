#[macro_use]
/** @brief 오류에 맥락을 붙이는 것. */
mod error;
/** @brief 인증서 자동 발급. */
mod acme;
/** @brief 응답 캐시와 같은 질의 합치기. */
mod cache;
/** @brief 설정 키마다 교체 방법, 클러스터 공유 여부, 빠른 경로 영향을 정한 표. */
mod config_keys;
/** @brief 주소별 연결 수 제한. */
mod connection_limit;
/** @brief 관리 API 콜백을 실행 중 서버 상태에 연결한다. */
mod control_api;
/** @brief DHCPv4 서버. */
mod dhcp;
/** @brief DHCPv6 서버. */
mod dhcp6;
/** @brief 주소가 없는 DHCPv4 클라이언트의 L2 직접 전달. */
mod dhcp_l2;
/** @brief DNSCrypt 리스너. */
mod dnscrypt;
/** @brief 전달 방식에서 받은 응답의 DNSSEC 검증. */
mod dnssecfwd;
/** @brief DoH 리스너. */
mod doh;
/** @brief DoH3 리스너. */
mod doh3;
/** @brief DoQ 리스너. */
mod doq;
/** @brief DoT 리스너. */
mod dot;
#[cfg(test)]
/** @brief 파서 훑기 테스트 도구. */
mod fuzzutil;
/** @brief HTTP 클라이언트. */
/** @brief 재시작 없는 설정 교체. */
mod hot_apply;
mod http;
/** @brief 해석 체인을 이루는 계층들. */
mod layers;
/** @brief 지역 시각 계산. */
mod localtime;
/** @brief 하드웨어 주소와 제조사 조회. */
mod mac;
/** @brief 모든 전송이 모이는 질의 핸들러. */
mod native;
/** @brief 비차단 TCP 접속. */
mod nonblocking_tcp;
/** @brief 운영체제 DNS 설정과 방화벽 조작. */
mod osnet;
#[cfg(target_os = "linux")]
/** @brief 권한 내려놓기. */
mod privdrop;
/** @brief DoQ·DoH3 전역 연결 메모리 예산. */
mod quic_memory;
/** @brief 질의 처리 워커 풀. */
mod qworker;
/** @brief IPv6 라우터 광고. */
mod ra;
mod redis;
/** @brief 외부 공유 캐시 클라이언트. */
/** @brief 설정에서 해석 체인을 조립한다. */
mod resolver_chain;
/** @brief 업스트림 인증서 폐기 확인. */
mod revoke;
/** @brief 서명 키 교체. */
mod rollover;
#[cfg(windows)]
/** @brief Windows 서비스 등록과 실행. */
mod service;
/** @brief 프로세스 감독자. */
mod supervisor;
/** @brief PXE 부팅용 TFTP 서버. */
mod tftp;
/** @brief 전송별 지표 관측. */
mod transport_observe;
/** @brief 업스트림 주소 해석. */
mod upstream;
/** @brief UDP 고속 경로가 쓰는 저장 형태. */
mod wirecache;

#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
/**
 * @brief 스레드마다 작은 캐시를 두는 할당기.
 * @details 정적 링크 빌드의 기본 할당기는 스레드가 늘수록 경합한다. 질의 처리는 스레드
 *          하나가 짧은 할당을 많이 하므로 그 경합이 그대로 지연이 된다.
 */
static GLOBAL_ALLOC: onetdns_core::talloc::ThreadCachedSystem =
    onetdns_core::talloc::ThreadCachedSystem;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Mutex;

use crate::error::{BoxResult, Context};
use config_keys::ApplyGroup;
use onetdns_core::ArcSwap;
use onetdns_core::MutexExt;
use std::net::UdpSocket;

use onetdns_config::SplitTarget;
use onetdns_config::{
    BackendKind, BlockResponseKind, Config, CookieMode, EcsMode, LocalZone, LocalZoneKind, Mode,
    Rewrite, UpstreamStrategy,
};
use onetdns_core::{AccessControl, BlockResponse, RateLimiter, RewriteTarget};
use onetdns_filter::{BlockEngine, EngineParts, LocalZoneAction, SharedFilter, StaticZone};
use onetdns_security::{CookieKeeper, IpAcl, KeyedRateLimiter, SubnetRateLimiter};
use zeroize::Zeroizing;

/** @brief 실행할 명령. */
enum Command {
    /** @brief 서버로 시작한다. */
    Run {
        /** @brief 쓸 설정 파일. */
        config: Option<PathBuf>,
        /** @brief 대시보드를 시작하지 않는다. */
        no_web: bool,
        /** @brief 프로세스 감독 없이 곧장 돈다. */
        no_supervisor: bool,
    },
    /** @brief 이름 하나를 물어본다. */
    Query { name: String, qtype: Option<String> },
    /** @brief 자체 서명 인증서를 만든다. */
    Cert {
        /** @brief 인증서에 적을 이름. */
        host: String,
        /** @brief 인증서를 쓸 곳. */
        cert_out: PathBuf,
        /** @brief 키를 쓸 곳. */
        key_out: PathBuf,
    },
    /** @brief 지표를 본다. */
    Stats { ctl: CtlArgs },
    /** @brief 설정을 다시 읽게 한다. */
    Reload { ctl: CtlArgs },
    /** @brief 차단 목록에 넣는다. */
    Block { domain: String, ctl: CtlArgs },
    /** @brief 허용 목록에 넣는다. */
    Allow { domain: String, ctl: CtlArgs },
    /** @brief 서비스로 등록하거나 제거한다. */
    Service { action: ServiceAction },
    /** @brief 설정만 검사한다. */
    Check { config: Option<PathBuf> },
    /** @brief 많이 물은 이름을 본다. */
    Top { ctl: CtlArgs },
    /** @brief 차단할 수 있는 서비스 목록을 본다. */
    Services,
    /** @brief 대시보드 로그인에 쓸 암호 해시를 만든다. */
    Passwd { name: Option<String> },
}

/** @brief 서비스 관련 동작. */
enum ServiceAction {
    /** @brief 서비스로 등록한다. */
    Install {
        #[cfg(windows)]
        /** @brief 서비스로 등록할 때 고정해 둘 설정 파일. */
        config: Option<PathBuf>,
    },
    /** @brief 등록한 서비스를 지운다. */
    Uninstall,
    /** @brief 서비스로 돈다. */
    Run {
        #[cfg(windows)]
        /** @brief 서비스로 돌 때 쓸 설정 파일. */
        config: Option<PathBuf>,
    },
}

#[derive(Default)]
/** @brief 컨트롤 플레인에 붙을 때 쓰는 인수. */
struct CtlArgs {
    /** @brief 설정 파일 경로. */
    config: Option<PathBuf>,
    /** @brief 컨트롤 플레인 주소. */
    url: Option<String>,
    /** @brief 컨트롤 플레인 토큰. */
    token: Option<String>,
}

/**
 * @brief 사람과 상대 서버에게 내보이는 프로그램 이름. 실행 파일 이름도 이것이다.
 *
 * @details 크레이트 이름은 이 이름을 못 쓴다. 대문자가 섞이면 rustc가
 *          non_snake_case로 막아 -D warnings 게이트가 깨진다. 지표 이름은
 *          Prometheus 규약을, 환경 변수와 자료 파일 헤더는 한 토큰을 전부
 *          대문자로 쓰는 규약을 각각 따른다.
 */
pub(crate) const PRODUCT_NAME: &str = "OnetDNS";

/** @brief 인수 없이 띄웠을 때 찾아 쓰는 설정 파일 이름. */
pub(crate) const CONFIG_FILE_NAME: &str = "OnetDNS.toml";

/** @brief 사용법 안내. */
const HELP: &str = "\
OnetDNS: 광고 차단 DNS 리졸버

사용법:
  OnetDNS [--config PATH] [--no-web] [--no-supervisor]
                                      # 기본: DNS 서버 + 웹 대시보드(127.0.0.1:8553) 자동 시작
  OnetDNS --cli <명령> [...]           # 관리 명령(아래)을 CLI로 실행
  OnetDNS run [--config PATH] [--no-web]   # 위 기본 동작과 동일(명시적)

관리 명령(--cli 필수):
  OnetDNS --cli query NAME [--type TYPE]
  OnetDNS --cli cert --host HOST [--cert-out PATH] [--key-out PATH]
  OnetDNS --cli stats|reload|top [--config PATH] [--url URL] [--token TOKEN]
  OnetDNS --cli block DOMAIN [ctl옵션]
  OnetDNS --cli allow DOMAIN [ctl옵션]
  OnetDNS --cli check [--config PATH]
  OnetDNS --cli services
  OnetDNS --cli passwd [--name 이름]  # 웹 콘솔 [[users]] 항목 생성(비밀번호는 물어봄)
  OnetDNS service install|uninstall|run [--config PATH]

비고:
  query      돌고 있는 서버가 아니라 기본 설정의 업스트림에 직접 묻는다.
             접근 제한, 필터, 캐시를 거치지 않으므로 서버의 판정과 다를 수 있다.
  --no-web   기본 웹 대시보드 자동 활성화를 끄고 DNS 서버만 시작(헤드리스).
             config에 control_listen이 있으면 그 설정이 항상 우선한다.
  --no-supervisor  Linux 프로세스 자가 복구를 끄고 서버를 직접 실행(외부 supervisor용).
";

/** @brief 뒤에 값을 하나 받는 플래그들. */
const VALUE_FLAGS: &[&str] = &[
    "--config",
    "--url",
    "--token",
    "--type",
    "--host",
    "--cert-out",
    "--key-out",
    "--name",
];

/** @brief 관리 명령이 쓰는 접속 플래그. */
const CTL_FLAGS: &[&str] = &["--config", "--url", "--token"];

/**
 * @brief 명령마다 받는 긴 플래그의 전부.
 *
 * @details 목록에 없는 플래그를 조용히 흘리면 진단이 거짓이 된다. query 에 서버를
 *          지정했다고 믿는 운영자는 사실 기본 업스트림이 돌려준 답을 자기 서버의
 *          답으로 읽게 된다. 오타 하나가 자신 있게 틀린 답으로 바뀌므로, 모르는
 *          플래그는 무시하지 않고 거부한다.
 * @invariant 새 플래그를 붙이는 사람은 여기에도 적어야 한다. 빠뜨리면 그 플래그가
 *            거부되므로 빠뜨린 사실이 첫 실행에서 드러난다.
 */
const COMMAND_FLAGS: &[(&str, &[&str])] = &[
    ("run", &["--config", "--no-web", "--no-supervisor"]),
    ("query", &["--type"]),
    ("cert", &["--host", "--cert-out", "--key-out"]),
    ("stats", CTL_FLAGS),
    ("reload", CTL_FLAGS),
    ("top", CTL_FLAGS),
    ("block", CTL_FLAGS),
    ("allow", CTL_FLAGS),
    ("check", &["--config"]),
    ("services", &[]),
    ("passwd", &["--name"]),
    ("service", &["--config"]),
];

/**
 * @brief 이 명령이 모르는 긴 플래그가 있으면 거부한다.
 * @note 목록에 없는 명령은 검사하지 않는다. 도움말과 판본 표시가 그렇다.
 * @param sub 하위 명령 이름.
 * @param rest 하위 명령 뒤에 남은 인수 전부.
 * @return 모르는 플래그를 만나면 그 이름을 담은 오류.
 */
fn reject_unknown_flags(sub: &str, rest: &[String]) -> Result<(), String> {
    let Some((_, allowed)) = COMMAND_FLAGS.iter().find(|(name, _)| *name == sub) else {
        return Ok(());
    };
    for arg in rest {
        let Some(body) = arg.strip_prefix("--") else {
            continue;
        };
        let name = body.split('=').next().unwrap_or(body);
        if name.is_empty() {
            continue;
        }
        let flag = format!("--{name}");
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("{sub}: 알 수 없는 옵션 {flag} (OnetDNS help 참고)"));
        }
    }
    Ok(())
}

/** @brief 이 플래그의 값. 붙여 쓴 형태와 띄어 쓴 형태를 모두 받는다. */
fn opt_val(args: &[String], flag: &str) -> Option<String> {
    let pref = format!("{flag}=");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&pref) {
            return Some(v.to_string());
        }
    }
    None
}

/** @brief 이 플래그의 값을 경로로. */
fn opt_path(args: &[String], flag: &str) -> Option<PathBuf> {
    opt_val(args, flag).map(PathBuf::from)
}

/** @brief 플래그가 아닌 첫 인수. */
fn positional(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") && a.contains('=') {
            i += 1;
        } else if VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return Some(a.clone());
        }
    }
    None
}

/** @brief 컨트롤 플레인 인수를 모은다. */
fn ctl_args(args: &[String]) -> CtlArgs {
    CtlArgs {
        config: opt_path(args, "--config"),
        url: opt_val(args, "--url"),
        token: opt_val(args, "--token"),
    }
}

/** @brief 실행 인수를 읽는다. */
fn parse_args() -> Result<Command, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_argv(&argv)
}

/** @brief 인수 목록을 명령으로. */
fn parse_argv(argv: &[String]) -> Result<Command, String> {
    if argv.first().map(String::as_str) == Some("--cli") {
        let sub = argv
            .get(1)
            .cloned()
            .ok_or("--cli: 서브커맨드가 필요합니다 (OnetDNS --cli help)")?;
        return parse_subcommand(&sub, &argv[2..]);
    }

    let Some(first) = argv.first().map(String::as_str) else {
        return Ok(Command::Run {
            config: None,
            no_web: false,
            no_supervisor: false,
        });
    };

    if matches!(
        first,
        "-h" | "--help" | "help" | "-V" | "--version" | "version" | "run" | "service"
    ) {
        return parse_subcommand(first, &argv[1..]);
    }

    if first.starts_with('-') {
        reject_unknown_flags("run", argv)?;
        return Ok(Command::Run {
            config: opt_path(argv, "--config"),
            no_web: argv.iter().any(|a| a == "--no-web"),
            no_supervisor: argv.iter().any(|a| a == "--no-supervisor"),
        });
    }

    Err(format!("알 수 없는 명령: {first} (OnetDNS help 참고)"))
}

/**
 * @brief 하위 명령을 읽는다.
 * @warning 관리 명령은 앞에 표시가 있어야 받는다. 없이 받으면 서버로 시작하려던 것이
 *          엉뚱한 관리 명령으로 실행된다.
 */
fn parse_subcommand(sub: &str, rest: &[String]) -> Result<Command, String> {
    reject_unknown_flags(sub, rest)?;
    match sub {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            std::process::exit(0);
        }
        "-V" | "--version" | "version" => {
            println!("{PRODUCT_NAME} {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        "run" => Ok(Command::Run {
            config: opt_path(rest, "--config"),
            no_web: rest.iter().any(|a| a == "--no-web"),
            no_supervisor: rest.iter().any(|a| a == "--no-supervisor"),
        }),
        "query" => Ok(Command::Query {
            name: positional(rest).ok_or("query 명령에는 조회할 도메인이 필요합니다")?,
            qtype: opt_val(rest, "--type"),
        }),
        "cert" => Ok(Command::Cert {
            host: opt_val(rest, "--host").ok_or("cert 명령에는 --host 옵션이 필요합니다")?,
            cert_out: opt_path(rest, "--cert-out").unwrap_or_else(|| "cert.pem".into()),
            key_out: opt_path(rest, "--key-out").unwrap_or_else(|| "key.pem".into()),
        }),
        "stats" => Ok(Command::Stats {
            ctl: ctl_args(rest),
        }),
        "reload" => Ok(Command::Reload {
            ctl: ctl_args(rest),
        }),
        "top" => Ok(Command::Top {
            ctl: ctl_args(rest),
        }),
        "block" => Ok(Command::Block {
            domain: positional(rest).ok_or("block 명령에는 차단할 도메인이 필요합니다")?,
            ctl: ctl_args(rest),
        }),
        "allow" => Ok(Command::Allow {
            domain: positional(rest).ok_or("allow 명령에는 허용할 도메인이 필요합니다")?,
            ctl: ctl_args(rest),
        }),
        "check" => Ok(Command::Check {
            config: opt_path(rest, "--config"),
        }),
        "services" => Ok(Command::Services),
        "passwd" => {
            if positional(rest).is_some() {
                return Err(
                    "passwd: 평문 비밀번호 인수는 허용되지 않습니다; 물어볼 때 입력하거나 표준 입력으로 넣으십시오"
                        .into(),
                );
            }
            Ok(Command::Passwd {
                name: opt_val(rest, "--name"),
            })
        }
        "service" => {
            let action = match rest.first().map(|s| s.as_str()) {
                Some("install") => ServiceAction::Install {
                    #[cfg(windows)]
                    config: opt_path(rest, "--config"),
                },
                Some("uninstall") => ServiceAction::Uninstall,
                Some("run") => ServiceAction::Run {
                    #[cfg(windows)]
                    config: opt_path(rest, "--config"),
                },
                _ => {
                    return Err(
                        "service 명령에는 install, uninstall, run 중 하나를 지정해야 합니다".into(),
                    )
                }
            };
            Ok(Command::Service { action })
        }
        other => Err(format!("알 수 없는 명령: {other} (OnetDNS help 참고)")),
    }
}

/** @brief 진입점. 인수를 읽어 해당 동작으로 간다. */
fn main() -> BoxResult<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    init_tracing();
    let cmd = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let mut rng_probe = [0u8; 32];
    onetdns_core::try_fill_random(&mut rng_probe)
        .map_err(|error| crate::anyhow!("운영체제 보안 난수원을 사용할 수 없습니다: {error}"))?;

    #[cfg(windows)]
    if let Command::Service {
        action: ServiceAction::Run { config },
    } = &cmd
    {
        return service::run_dispatcher(config.clone());
    }

    match cmd {
        Command::Run {
            config,
            no_web,
            no_supervisor,
        } => {
            #[cfg(target_os = "linux")]
            if !no_supervisor {
                return supervisor::run(config, no_web);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = no_supervisor;
            run(config, no_web)
        }
        Command::Query { name, qtype } => query(name, qtype),
        Command::Cert {
            host,
            cert_out,
            key_out,
        } => gen_cert(host, cert_out, key_out),
        Command::Stats { ctl } => ctl_stats(&ctl),
        Command::Reload { ctl } => ctl_reload(&ctl),
        Command::Block { domain, ctl } => ctl_add("block", &domain, &ctl),
        Command::Allow { domain, ctl } => ctl_add("allow", &domain, &ctl),
        Command::Service { action } => run_service(action),
        Command::Check { config } => check_config(config),
        Command::Top { ctl } => ctl_top(&ctl),
        Command::Services => {
            println!("차단 가능한 서비스:");
            for (id, name) in onetdns_filter::services::list() {
                println!("  {id:12} {name}");
            }
            Ok(())
        }
        Command::Passwd { name } => gen_passwd(name),
    }
}

/**
 * @brief 대시보드 로그인에 쓸 계정 항목을 만든다.
 *
 * @details 한 줄만 읽는다. 표준 입력 전체를 EOF까지 읽으면 사람이 직접 칠 때 Enter로
 *          끝나지 않아 멈춘 것처럼 보인다. 무엇을 입력해야 하는지도 먼저 알린다.
 * @param name  설정에 적을 로그인 이름. 없으면 admin.
 * @return 붙여 넣을 수 있는 설정 조각을 표준 출력으로 낸다.
 */
fn gen_passwd(name: Option<String>) -> BoxResult<()> {
    use std::io::{BufRead, Read};

    let login = name.unwrap_or_else(|| "admin".to_string());
    if login.trim().is_empty() || login.len() > 64 {
        return Err(crate::anyhow!("로그인 이름은 1~64자여야 합니다"));
    }

    eprintln!("웹 콘솔 계정 '{login}'의 비밀번호를 입력하고 Enter를 누르십시오.");
    eprintln!("(입력한 글자가 화면에 그대로 보입니다. 12자 이상을 권합니다.)");

    /** @brief 읽어들일 암호 길이 상한. */
    const MAX_PASSWORD_INPUT: u64 = 4097;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD_INPUT)
        .read_line(&mut line)
        .with_context(|| "비밀번호를 읽지 못했습니다")?;
    if line.len() as u64 >= MAX_PASSWORD_INPUT {
        return Err(crate::anyhow!("비밀번호가 너무 깁니다"));
    }
    let pw = line.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        return Err(crate::anyhow!("빈 비밀번호는 허용되지 않습니다"));
    }

    eprintln!();
    eprintln!(
        "아래 세 줄을 설정 파일({CONFIG_FILE_NAME}) 맨 끝에 붙여 넣고 서버를 다시 시작하십시오."
    );
    eprintln!("웹 콘솔을 열 수 있으면 이 명령 없이 첫 화면에서 바로 계정을 만들 수 있습니다.");
    eprintln!();
    println!("[[users]]");
    println!("name = \"{login}\"");
    println!("password_hash = \"{}\"", onetdns_control::hash_password(pw));
    println!("role = \"admin\"");
    Ok(())
}

/**
 * @brief 설정을 검사만 하고 결과를 알린다.
 * @details 저장은 되지만 지금 조건에서 동작하지 않을 항목도 함께 보여 준다. 그렇지 않으면
 *          검사를 통과한 설정이 시작한 뒤에야 로그로 드러난다.
 */
fn check_config(config: Option<PathBuf>) -> BoxResult<()> {
    let cfg = Config::load_or_default(config.as_deref())?;
    runtime_preflight(&cfg).map_err(|error| crate::anyhow!(error))?;

    let mode_label = match cfg.mode {
        Mode::Personal => "개인·내부망용",
        Mode::Public => "공개 서비스용",
    };
    let backend_label = match cfg.backend {
        BackendKind::Forward => "업스트림 DNS 서버에 전달",
        BackendKind::Recurse => "직접 재귀 조회",
        BackendKind::Split => "도메인별 분리 처리",
    };
    let cookie_label = match cfg.cookies {
        CookieMode::Off => "사용 안 함",
        CookieMode::Lenient => "지원하는 클라이언트에만 적용",
        CookieMode::Strict => "모든 클라이언트에 요구",
    };

    println!("설정 파일을 확인했습니다.");
    println!("  운영 대상: {mode_label}");
    println!("  질의 처리 방식: {backend_label}");
    println!("  일반 DNS 수신 주소: {:?}", cfg.listen);
    if cfg.tls_enabled() {
        println!(
            "  암호화 DNS 수신 주소: DoT {}개, DoH {}개, DoQ {}개, DoH3 {}개",
            cfg.listen_dot.len(),
            cfg.listen_doh.len(),
            cfg.listen_doq.len(),
            cfg.listen_doh3.len()
        );
        println!(
            "  클라이언트 인증서 확인: {}",
            if cfg.tls_authenticated() {
                "사용"
            } else {
                "사용 안 함"
            }
        );
    }
    if !cfg.listen_dnscrypt.is_empty() {
        println!("  DNSCrypt 수신 주소: {:?}", cfg.listen_dnscrypt);
    }
    println!(
        "  접근 제어: 허용 대역 {}개, 차단 대역 {}개",
        cfg.acl_allow.len(),
        cfg.acl_deny.len()
    );
    /* 한도 설정의 0은 끔을 뜻한다. 0건으로 적으면 모든 요청을 막는 것처럼 읽힌다. */
    if cfg.rate_limit_per_sec == 0 {
        println!("  클라이언트별 속도 제한: 사용 안 함");
    } else {
        println!(
            "  클라이언트별 속도 제한: 초당 {}건, 순간 허용 {}건",
            cfg.rate_limit_per_sec, cfg.rate_limit_burst
        );
    }
    if cfg.subnet_rrl_per_sec == 0 {
        println!("  대역별 응답 제한: 사용 안 함");
    } else {
        println!("  대역별 응답 제한: 초당 {}건", cfg.subnet_rrl_per_sec);
    }
    println!("  DNS 쿠키: {cookie_label}");
    let inflight = if cfg.max_inflight == 0 {
        "제한 없음".to_string()
    } else {
        format!("{}건", cfg.max_inflight)
    };
    println!(
        "  처리 자원: 캐시 {}건, 동시 질의 {inflight}, 질의 제한 시간 {}초",
        cfg.cache_size, cfg.query_timeout_secs
    );
    if let Some(c) = cfg.control_listen {
        println!("  관리 화면 수신 주소: {c}");
    }

    let mut ext: Vec<String> = Vec::new();
    if cfg.block_response == BlockResponseKind::Custom {
        ext.push("사용자 지정 주소로 차단 응답".into());
    }
    if cfg.block_aaaa {
        ext.push("AAAA 응답이 비활성화되어 있습니다".into());
    }
    if !cfg.upstream_urls.is_empty() {
        // 섞여 있으면 "암호화 N개"만 보여 주는 것이 사실을 가린다. 실제로 나가는 질의는
        // 대부분 평문 쪽이다.
        if cfg.mixes_plain_and_encrypted_upstreams() {
            ext.push(format!(
                "업스트림 DNS 서버 {}개(암호화) + {}개(평문)",
                cfg.upstream_urls.len(),
                cfg.upstreams.len()
            ));
        } else {
            ext.push(format!(
                "암호화 업스트림 DNS 서버 {}개",
                cfg.upstream_urls.len()
            ));
        }
    }
    if !cfg.fallback_upstreams.is_empty() {
        ext.push("예비 업스트림 DNS 서버".into());
    }
    if cfg.ecs_mode != EcsMode::Off {
        ext.push(match cfg.ecs_mode {
            EcsMode::Off => unreachable!(),
            EcsMode::Strip => "클라이언트 서브넷 정보 제거".into(),
            EcsMode::Send => "클라이언트 서브넷 정보 전달".into(),
        });
    }
    if !cfg.stub_zones.is_empty() {
        ext.push(format!(
            "별도 DNS 서버로 보낼 영역 {}개",
            cfg.stub_zones.len()
        ));
    }
    if !cfg.local_zones.is_empty() {
        ext.push(format!("로컬 영역 {}개", cfg.local_zones.len()));
    }
    if !cfg.rewrites.is_empty() {
        ext.push(format!("질의 재작성 규칙 {}개", cfg.rewrites.len()));
    }
    if !cfg.rpz_files.is_empty() || !cfg.rpz_urls.is_empty() {
        ext.push(format!(
            "응답 정책 영역: 파일 {}개, 원격 목록 {}개",
            cfg.rpz_files.len(),
            cfg.rpz_urls.len()
        ));
    }
    if cfg.dnssec_validation_active() {
        ext.push("DNSSEC 검증".into());
    }
    if cfg.safe_browsing {
        ext.push("위험 사이트 차단".into());
    }
    if cfg.parental_control {
        ext.push("보호자 통제".into());
    }
    if !cfg.service_schedule.is_empty() {
        ext.push("시간대별 서비스 차단 멈춤".into());
    }
    if cfg.anonymize_client_ip {
        ext.push("로그 익명화".into());
    }
    if cfg.clients.iter().any(|c| !c.mac.is_empty()) {
        ext.push("MAC 식별".into());
    }
    if !ext.is_empty() {
        println!("  추가 기능: {}", ext.join(", "));
    }
    for warning in cfg.open_resolver_warnings().iter().chain(&cfg.advisories()) {
        println!("  주의: {warning}");
    }
    Ok(())
}

/** @brief 서비스 등록·제거·실행. */
fn run_service(action: ServiceAction) -> BoxResult<()> {
    #[cfg(windows)]
    {
        match action {
            ServiceAction::Install { config } => {
                println!("{}", service::install(config)?);
                Ok(())
            }
            ServiceAction::Uninstall => {
                println!("{}", service::uninstall()?);
                Ok(())
            }
            ServiceAction::Run { config } => service::run_dispatcher(config),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        crate::bail!("service 명령은 Windows 전용입니다")
    }
}

/**
 * @brief 설정된 암호화 수신 주소로 DDR이 알릴 전송 목록을 만든다.
 *
 * @details 우선순위는 클라이언트 지원 폭이 넓은 것부터다. 승격이 실제로 성사되는 확률을
 *          높이려는 것이다. 같은 전송이 포트를 여러 개 열고 있으면 포트마다 하나씩 알린다.
 * @return 암호화 수신 주소가 하나도 없으면 빈 목록.
 */
fn ddr_endpoints_from(cfg: &Config) -> Vec<layers::DdrEndpoint> {
    /** @brief 주소 목록에서 중복 없는 포트만 등장 순서대로. */
    fn ports(addrs: &[SocketAddr]) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        for addr in addrs {
            if !out.contains(&addr.port()) {
                out.push(addr.port());
            }
        }
        out
    }

    // RFC 9461의 dohpath는 dns 변수를 담은 URI template이어야 한다.
    let dohpath = format!("{}{{?dns}}", cfg.doh_path);
    let mut out = Vec::new();
    for (priority, alpn, addrs, path) in [
        (1u16, &["h2"][..], &cfg.listen_doh, Some(dohpath.clone())),
        (2, &["h3"][..], &cfg.listen_doh3, Some(dohpath)),
        (3, &["dot"][..], &cfg.listen_dot, None),
        (4, &["doq"][..], &cfg.listen_doq, None),
    ] {
        for port in ports(addrs) {
            out.push(layers::DdrEndpoint {
                priority,
                alpn,
                port,
                dohpath: path.clone(),
            });
        }
    }
    out
}

/** @brief 외부 응답 캐시에서 서로 섞이면 안 되는 기본 해석·TTL 정책 이름. */
fn cache_namespace_base(cfg: &Config) -> String {
    format!(
        "{:?}/dnssec={}/strict={}/min_ttl={}/max_ttl={}",
        cfg.backend, cfg.dnssec, cfg.dnssec_strict, cfg.min_ttl, cfg.max_ttl
    )
}

/** @brief 신호 핸들러가 보내는 종료 플래그. */
static SHUTDOWN_FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
    std::sync::OnceLock::new();

#[cfg(unix)]
/**
 * @brief 종료 신호를 받는다.
 * @warning 신호 핸들러 안에서는 할 수 있는 일이 거의 없다. 플래그만 설정하고 나머지는
 *          본 흐름이 한다.
 */
extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/** @brief 종료 신호 핸들러를 건다. */
fn install_shutdown_handler() -> Arc<std::sync::atomic::AtomicBool> {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _ = SHUTDOWN_FLAG.set(flag.clone());
    #[cfg(unix)]
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
    flag
}

/**
 * @brief 서버를 시작하고 설정을 다시 읽을 때마다 새 세대로 교체한다.
 * @details 한 세대가 끝나면 그 세대가 잡은 스레드와 리스너를 모두 정리한 뒤 다음 세대를
 *          시작한다. 그래야 포트가 확실히 풀린다.
 */
fn run(config_path: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
    let _raft_process_cleanup = RaftProcessCleanup;
    let mut config_path = config_path;
    if config_path.is_none() && !no_web {
        config_path = ensure_auto_config();
    }
    let stop = install_shutdown_handler();

    let shared = ServeShared::default();
    let ready_callback = Arc::new(Mutex::new(supervisor::take_ready_callback()?));
    let mut recovery_error: Option<String> = None;
    loop {
        let loaded = Config::load_or_default(config_path.as_deref());
        let mut cfg = match loaded {
            Ok(cfg) => cfg,
            Err(error) => {
                if recovery_error.is_none()
                    && restore_last_applied_config(config_path.as_deref(), &shared)?
                {
                    recovery_error = Some(error.to_string());
                    continue;
                }
                if let Some(first_error) = recovery_error.take() {
                    return Err(crate::anyhow!(format!(
                        "새 설정을 적용하지 못했고 마지막 정상 설정으로도 서비스를 복구하지 못했습니다: 새 설정 오류={first_error}; 복구 설정 오류={error}"
                    )));
                }
                return Err(error.into());
            }
        };
        apply_web_defaults(&mut cfg, no_web, config_path.as_deref());
        let cfg_text = config_path
            .as_deref()
            .and_then(|p| Config::read_text(p).ok())
            .map(onetdns_core::SecretString::from);
        let session_checkpoint = shared.sessions.checkpoint();
        let ready_slot = ready_callback.clone();
        let attempt_ready: Box<dyn FnOnce() + Send> = Box::new(move || {
            if let Some(callback) = ready_slot.lock_recover().take() {
                callback();
            }
        });
        match serve(
            cfg,
            cfg_text,
            config_path.clone(),
            shared.clone(),
            Some(stop.clone()),
            Some(attempt_ready),
        ) {
            Ok(false) => return Ok(()),
            Ok(true) => {
                recovery_error = None;
                onetdns_core::info!(
                    event = "config.reload_restarted",
                    "설정을 다시 불러온 뒤 DNS 서비스를 재시작했습니다"
                );
            }
            Err(error) => {
                shared.sessions.restore(session_checkpoint);
                if recovery_error.is_none()
                    && restore_last_applied_config(config_path.as_deref(), &shared)?
                {
                    recovery_error = Some(error.to_string());
                    continue;
                }
                if let Some(first_error) = recovery_error.take() {
                    return Err(crate::anyhow!(format!(
                        "새 설정을 적용하지 못했고 마지막 정상 설정으로도 서비스를 복구하지 못했습니다: 새 설정 오류={first_error}; 복구 설정 오류={error}"
                    )));
                }
                return Err(error);
            }
        }
    }
}

/** @brief 새 설정으로 뜨지 못했으면 마지막으로 성공한 설정으로 되돌린다. */
fn restore_last_applied_config(
    path: Option<&std::path::Path>,
    shared: &ServeShared,
) -> BoxResult<bool> {
    let (Some(path), Some(text)) = (path, shared.applied_config_text.lock_recover().clone()) else {
        return Ok(false);
    };
    let current = Config::read_text(path)
        .ok()
        .map(onetdns_core::SecretString::from);
    if current.as_deref() == Some(text.as_str()) {
        return Ok(false);
    }
    atomic_write(path, text.as_bytes()).with_context(|| {
        format!(
            "새 설정으로 서비스를 시작하지 못한 뒤 마지막 정상 설정을 복구하지 못했습니다: {}",
            path.display()
        )
    })?;
    onetdns_core::warn!(
        event = "config.start_failed_rollback",
        path = %path.display(),
        "새 설정으로 서비스를 시작하지 못해 마지막 정상 설정을 복구합니다"
    );
    Ok(true)
}

/** @brief 대시보드 기본값을 채운다. 설정에 적힌 것이 있으면 그것이 이긴다. */
fn apply_web_defaults(cfg: &mut Config, no_web: bool, config_path: Option<&std::path::Path>) {
    if cfg.control_listen.is_some() {
        return;
    }
    if no_web {
        onetdns_core::info!(
            event = "serve.dashboard_disabled",
            "대시보드 없이 DNS만 켭니다"
        );
        return;
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], 8553));
    cfg.control_listen = Some(addr);
    let auto_token = cfg.control_token.is_empty();
    let mut persisted = false;
    if auto_token {
        cfg.control_token = gen_token().into();
        if let Some(path) = config_path {
            match persist_control_token(path, &cfg.control_token) {
                Ok(()) => persisted = true,
                Err(error) => onetdns_core::error!(event = "control.token_save_failed",
                    path = %path.display(), %error,
                    "관리 토큰을 설정 파일에 저장하지 못했습니다. 이번 실행에만 유효한 임시 토큰을 사용합니다"
                ),
            }
        }
    }
    // 토큰을 설정에 적어 둔 사람은 그 값을 이미 안다. 그때는 주소만 알려 준다.
    println!();
    println!("  대시보드: http://{addr}/");
    if auto_token {
        println!("  토큰: {}", cfg.control_token.as_str());
        if persisted {
            println!("  토큰은 설정 파일에 적어 뒀습니다. 다음에도 이 값으로 들어가면 됩니다.");
        } else {
            println!("  이 토큰은 이번에만 씁니다. 고정하려면 설정 파일에 control_token 을 적으면 됩니다.");
        }
        println!("  --no-web 을 주면 대시보드 없이 DNS만 돕니다.");
    }
    println!();
}

/** @brief 만든 제어 토큰을 설정 파일에 적는다. */
fn persist_control_token(path: &std::path::Path, token: &str) -> Result<(), String> {
    let text =
        onetdns_core::SecretString::from(Config::read_text(path).map_err(|e| e.to_string())?);
    let new_text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "control_token",
        &toml_quote(token),
    )?);
    atomic_write_secret(path, new_text.as_bytes()).map_err(|e| e.to_string())
}

/** @brief 설정 파일을 둘 기본 경로. */
fn auto_config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join(PRODUCT_NAME).join(CONFIG_FILE_NAME))
}

/** @brief 설정 파일이 없으면 만든다. */
fn ensure_auto_config() -> Option<PathBuf> {
    let path = auto_config_path()?;
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            onetdns_core::error!(event = "config.autocreate_dir_failed", path = %parent.display(), %error, "자동 설정 디렉터리를 만들지 못했습니다");
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                onetdns_core::error!(event = "config.autocreate_dir_acl_failed", path = %parent.display(), %error, "자동 설정 디렉터리의 접근 권한을 설정하지 못했습니다");
                return None;
            }
        }
    }
    if !path.exists() {
        let body = format!(
            "# OnetDNS가 자동으로 만든 설정 파일입니다. 웹 관리 화면이나 텍스트 편집기로 변경할 수 있습니다.\n# 각 항목의 설명은 문서와 웹 관리 화면의 전체 설정에서 확인할 수 있습니다.\ncontrol_token = \"{}\"\n",
            gen_token()
        );

        if let Err(error) = atomic_write_secret(&path, body.as_bytes()) {
            onetdns_core::error!(event = "config.autocreate_file_failed", path = %path.display(), %error, "자동 설정 파일을 만들지 못했습니다");
            return None;
        }
        onetdns_core::info!(event = "config.autocreated", path = %path.display(), "기본 설정 파일을 만들었습니다");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            {
                onetdns_core::error!(event = "config.autocreate_chmod_failed", path = %path.display(), %error, "자동 설정 파일의 접근 권한을 바로잡지 못했습니다");
                return None;
            }
        }
    }
    #[cfg(windows)]
    if let Err(error) = harden_windows_secret_acl(&path) {
        onetdns_core::error!(event = "config.autocreate_acl_failed", path = %path.display(), %error, "자동 설정 파일의 Windows 접근 제어 목록을 바로잡지 못했습니다");
        return None;
    }
    Some(path)
}

/** @brief 제어 토큰 하나를 만든다. */
fn gen_token() -> String {
    use std::fmt::Write;
    let bytes: [u8; 32] = onetdns_core::random_array();
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/** @brief 이 세대가 시작한 스레드를 모두 붙잡아 두었다가 함께 끝내는 것. */
struct ServiceCleanup {
    /** @brief 이 세대의 종료 플래그. */
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 정리해야 할 스레드들. */
    threads: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl ServiceCleanup {
    /** @brief 종료 플래그를 잡고 만든다. */
    fn new(shutdown: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self {
            shutdown,
            threads: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /** @brief 이 스레드를 정리 대상에 넣는다. */
    fn track(&self, thread: std::thread::JoinHandle<()>) {
        track_service_thread(&self.threads, thread);
    }

    /** @brief 정리 대상 목록. */
    fn tracker(&self) -> Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>> {
        self.threads.clone()
    }

    /**
     * @brief 종료를 알리고 스레드가 모두 끝나기를 기다린다.
     * @warning 기다리지 않으면 포트를 잡은 리스너가 살아 있는 채로 다음 세대가 같은 포트에
     *          묶으려 한다.
     */
    fn shutdown_and_join(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::SeqCst);
        loop {
            let threads = {
                let mut threads = self
                    .threads
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                std::mem::take(&mut *threads)
            };
            if threads.is_empty() {
                break;
            }
            for thread in threads {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for ServiceCleanup {
    /** @brief 스레드를 모두 정리한다. */
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

/** @brief 스레드를 정리 대상에 넣는다. */
fn track_service_thread(
    threads: &Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    thread: std::thread::JoinHandle<()>,
) {
    threads
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(thread);
}

#[derive(Clone, Default)]
/** @brief 세대가 바뀌어도 살아남는 것들. 제어 리스너와 로그인 상태가 그렇다. */
pub struct ServeShared {
    /** @brief 로그인 상태. 세대가 바뀌어도 이어진다. */
    sessions: onetdns_control::SessionStore,
    /** @brief 제어 리스너. 묶는 주소가 같으면 다음 세대가 이어받는다. */
    control_listener: Arc<Mutex<Option<TcpListener>>>,
    /**
     * @brief 관리 화면을 받는 스레드들. 세대가 바뀌어도 이어진다.
     *
     * @details 세대마다 새로 만들면 재시작하는 동안 아무도 연결을 받지 않아, 차단 목록을
     *          올리는 몇 초 동안 웹 화면이 멈춘다. 이전 스레드는 다음 세대가 자기 것을 시작한
     *          뒤에 멈춘다.
     */
    control_jobs: Arc<EdgeServices>,

    /** @brief 지표 기록기와 저장소. */
    metrics: Arc<Mutex<Option<(onetdns_control::Recorder, onetdns_control::Stats)>>>,
    /** @brief 감사 로그. */
    audit: Arc<Mutex<Option<onetdns_control::AuditLog>>>,

    /** @brief 마지막으로 성공한 설정 텍스트. */
    applied_config_text: ConfigTextSlot,
    /** @brief 그 앞의 설정 텍스트. 되돌릴 때 쓴다. */
    previous_config_text: ConfigTextSlot,
}

/** @brief 자격증명이 든 설정 원문을 공유·zeroize 소유권으로 보관하는 슬롯. */
type ConfigTextSlot = Arc<Mutex<Option<onetdns_core::SecretString>>>;

/**
 * @brief 앞 세대의 제어 리스너를 이어받는다. 묶는 주소가 같을 때만 이어받는다.
 * @details 주소가 다르면 꺼내지 않고 그대로 둔다. 꺼낸 뒤에 버리면 이어서 하는 bind가
 *          실패했을 때 관리 리스너가 아무것도 남지 않아 웹 화면에 닿을 길이 사라진다.
 *          SO_REUSEPORT가 없는 플랫폼에서는 그 bind가 실제로 실패할 수 있다.
 */
fn reuse_control_listener(
    slot: &Arc<Mutex<Option<TcpListener>>>,
    caddr: SocketAddr,
) -> Option<TcpListener> {
    let mut slot = slot.lock_recover();
    let same = slot
        .as_ref()
        .and_then(|listener| listener.local_addr().ok())
        .is_some_and(|bound| bound == caddr);
    same.then(|| slot.take()).flatten()
}

/** @brief 세대마다 하나씩 늘어나는 관리 리스너 이름표. 세대가 다르면 새로 시작한다. */
static CONTROL_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/** @brief 재귀일 때 코어당 UDP 워커 수. */
const RECURSIVE_UDP_WORKERS_PER_CPU: usize = 5;

/** @brief 전달일 때 코어당 UDP 워커 수. */
const FORWARD_UDP_WORKERS_PER_CPU: usize = 4;
/** @brief 일반 DNS 워커 수 상한. */
const MAX_PLAIN_DNS_WORKERS: usize = 256;

/** @brief 한 번에 받아들일 임대 수 상한. */
const MAX_SYNCED_LEASES: usize = 16_384;

/** @brief UDP와 TCP 워커 수를 정한다. 재귀는 응답을 기다리는 시간이 길어 더 많이 둔다. */
fn plain_dns_worker_counts(
    configured: usize,
    backend: BackendKind,
    available_cpus: usize,
) -> (usize, usize) {
    if configured != 0 {
        let workers = configured.min(MAX_PLAIN_DNS_WORKERS);
        return (workers, workers);
    }
    let cpus = available_cpus.clamp(1, MAX_PLAIN_DNS_WORKERS);
    let per_cpu = if matches!(backend, BackendKind::Recurse | BackendKind::Split) {
        RECURSIVE_UDP_WORKERS_PER_CPU
    } else {
        FORWARD_UDP_WORKERS_PER_CPU
    };
    let udp_workers = cpus.saturating_mul(per_cpu).min(MAX_PLAIN_DNS_WORKERS);
    (udp_workers, cpus)
}

/**
 * @brief 한 세대를 시작하고 종료나 다시 읽기를 기다린다.
 * @details 리스너를 모두 묶고, 필터·영역·정책을 올리고, 컨트롤 플레인을 시작한 뒤 대기한다.
 * @return 다시 읽어야 하면 참, 끝내야 하면 거짓.
 */
pub fn serve(
    cfg: Config,
    cfg_text: Option<onetdns_core::SecretString>,
    config_path: Option<PathBuf>,
    shared: ServeShared,
    external_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    on_ready: Option<Box<dyn FnOnce() + Send>>,
) -> BoxResult<bool> {
    use std::sync::atomic::{AtomicBool, Ordering};
    cfg.validate()?;
    ensure_resolution_sources_not_self(&cfg).map_err(|error| crate::anyhow!(error))?;
    if let Some(lvl) = &cfg.log_level {
        onetdns_core::log::set_level_str(lvl);
    }
    onetdns_dnssec::set_accept_expired(cfg.dnssec_accept_expired);
    onetdns_forward::set_query_source(cfg.query_source, cfg.query_source_v6);

    // 해석 체인을 다시 만들어 교체하는 핸들. 체인을 만드는 코드와 넣을 슬롯은 한참
    // 뒤에서 준비되므로 슬롯을 먼저 잡아 둔다.
    let chain_rebuild: Arc<Mutex<Option<ChainRebuild>>> = Arc::new(Mutex::new(None));
    let tls_slot_handle: Arc<Mutex<Option<Arc<TlsSlots>>>> = Arc::new(Mutex::new(None));
    // 재귀 리졸버에 딸린 보조 작업들. 재귀 리졸버를 다시 만들 때 이전 것을 멈춘다.
    let recursor_jobs = Arc::new(EdgeServices::default());
    // 웹 관리 리스너. 주소가 바뀌면 새로 시작하고 이전 것을 멈춘다. 세대를 넘어 이어지므로
    // 재시작하는 동안에도 이전 스레드가 계속 연결을 받는다.
    let control_jobs = shared.control_jobs.clone();
    let control_rebind: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    // 보조 영역 갱신 작업. 설정이 바뀌면 이전 것을 멈추고 새 설정으로 재시작한다.
    let secondary_jobs = Arc::new(EdgeServices::default());
    let secondary_restart: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    // 임대 정보 동기화와 Raft. 설정이 바뀌면 멈추고 새 설정으로 재시작한다.
    let lease_sync_jobs = Arc::new(EdgeServices::default());
    let lease_sync_restart: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    let raft_restart: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    // ZSK 교체 작업. 영역 목록이나 주기가 바뀌면 멈추고 재시작한다.
    let zsk_rollover_jobs = Arc::new(EdgeServices::default());
    let zsk_rollover_restart: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    // 수신 주소 맞추기. 설정이 그대로인 주소는 건드리지 않는다.
    let listener_sync: Arc<Mutex<Option<SecondaryRestart>>> = Arc::new(Mutex::new(None));
    onetdns_core::info!(event = "serve.starting", mode = ?cfg.mode, backend = ?cfg.backend, "DNS 서버를 켭니다");

    let reload = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(AtomicBool::new(false));
    let service_cleanup = ServiceCleanup::new(shutdown.clone());
    let readiness = Arc::new(AtomicBool::new(false));

    let listener_reg: Arc<Mutex<Vec<(&'static str, String, String)>>> =
        Arc::new(Mutex::new(Vec::new()));

    let runtime_cfg = Arc::new(ArcSwap::from_pointee(cfg.clone()));

    let forward_stats: Arc<Mutex<Option<onetdns_forward::ForwardStats>>> =
        Arc::new(Mutex::new(None));
    let forward_slot = if backend_uses_forward(cfg.backend) {
        let (resolver, stats) =
            build_forward_backend(&cfg).map_err(|error| crate::anyhow!(error))?;

        if let Some(path) = upstream_stats_path(config_path.as_deref()) {
            stats.seed(&load_upstream_stats(&path));
        }
        *forward_stats.lock_recover() = Some(stats);
        native::ResolverSlot::new(resolver)
    } else {
        native::ResolverSlot::new(Arc::new(native::UnbuiltForward))
    };

    if let Some(stats_path) = upstream_stats_path(config_path.as_deref()) {
        let handle = forward_stats.clone();
        let sd = shutdown.clone();
        let flush = cfg.persist_flush_secs.max(1);
        let thread = std::thread::Builder::new()
            .name("upstream-stats-flush".into())
            .spawn(move || loop {
                let stop = sleep_or_shutdown(flush, &sd);
                let snapshot = handle.lock_recover().as_ref().map(|h| h.snapshot());
                if let Some(reports) = snapshot {
                    save_upstream_stats(&stats_path, &reports);
                }
                if stop {
                    break;
                }
            })
            .with_context(|| "업스트림 DNS 서버 통계 저장 스레드를 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    let block_response = map_block(&cfg);
    // 이름을 푸는 데 쓰는 업스트림 서버와 루트 힌트는 무중단으로 바뀐다. 시작할 때 만든 것을
    // 그대로 계속 가지고 있으면 주소를 바꿔도 목록은 계속 이전 서버에서 받아 온다. 겉은 그대로 두고
    // 속만 교체한다.
    let blocklist_resolver_slot: Arc<Mutex<http::HostResolver>> =
        Arc::new(Mutex::new(blocklist_host_resolver(&cfg)));
    let blocklist_resolver: http::HostResolver = {
        let slot = blocklist_resolver_slot.clone();
        Arc::new(move |host: &str, timeout: Duration| {
            let inner = slot.lock_recover().clone();
            inner(host, timeout)
        })
    };
    let blocklist_cache_dir = config_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.join("blocklist-cache"));
    let compiled_filter_cache = blocklist_cache_dir
        .as_ref()
        .map(|dir| dir.join("compiled-filter.bin"));

    let cached_rpz_texts = load_rpz_cache(&cfg.rpz_urls, blocklist_cache_dir.as_deref());
    let all_rpz_cached = !cfg.rpz_urls.is_empty()
        && cached_rpz_texts.len() == cfg.rpz_urls.len()
        && cached_rpz_texts.iter().all(|text| !text.is_empty());
    let rpz_texts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cached_rpz_texts));
    let overlay: Arc<Mutex<(Vec<String>, Vec<String>)>> = Arc::new(Mutex::new((
        cfg.block_rules.clone(),
        cfg.allow_rules.clone(),
    )));
    let refused_domains_state: Arc<Mutex<Vec<String>>> =
        Arc::new(Mutex::new(cfg.refused_domains.clone()));
    let filter = Arc::new(SharedFilter::from_pointee(BlockEngine::empty(
        block_response,
    )));

    let service_set: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cfg.blocked_services.clone()));

    let sub_meta: Arc<Mutex<Vec<SubMeta>>> = Arc::new(Mutex::new(vec![]));
    let rebuild: FilterRebuild = {
        let filter = filter.clone();
        let runtime_cfg = runtime_cfg.clone();
        let service_set = service_set.clone();
        let sub_meta = sub_meta.clone();
        let rpz_texts = rpz_texts.clone();
        let overlay = overlay.clone();
        let refused_domains = refused_domains_state.clone();
        let compiled_filter_cache = compiled_filter_cache.clone();
        let subscription_cache_dir = blocklist_cache_dir.clone();
        Arc::new(move || -> Result<(usize, usize), String> {
            let current = runtime_cfg.load();
            let subscriptions = sub_meta.lock_recover().clone();
            let (overlay_block, overlay_allow) = {
                let overlay = overlay.lock_recover();
                (overlay.0.clone(), overlay.1.clone())
            };
            let blocked_services = service_set.lock_recover().clone();
            let refused_domains = refused_domains.lock_recover().clone();
            let rpz_texts_snapshot = rpz_texts.lock_recover().clone();
            let engine = build_filter_engine_for_config(
                &current,
                &FilterBuildInputs {
                    blocked_services: &blocked_services,
                    subscriptions: &subscriptions,
                    overlay_block: &overlay_block,
                    overlay_allow: &overlay_allow,
                    refused_domains: &refused_domains,
                    rpz_texts: &rpz_texts_snapshot,
                    compiled_filter_cache: compiled_filter_cache.as_deref(),
                    subscription_cache_dir: subscription_cache_dir.as_deref(),
                },
            )?;
            if let Some(dir) = subscription_cache_dir.as_deref() {
                release_subscription_lines(&sub_meta, dir);
            }
            let counts = (engine.block_count(), engine.allow_count());
            filter.store(Arc::new(engine));
            Ok(counts)
        })
    };

    let sub_urls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cfg.blocklist_urls.clone()));
    let mut configured_titles = cfg.blocklist_titles.clone();
    configured_titles.resize(cfg.blocklist_urls.len(), String::new());
    configured_titles.truncate(cfg.blocklist_urls.len());
    let sub_titles: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(configured_titles));
    let sub_disabled: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(
        cfg.disabled_blocklist_urls
            .iter()
            .filter(|url| {
                cfg.blocklist_urls
                    .iter()
                    .any(|configured| configured == *url)
            })
            .cloned()
            .collect(),
    ));
    let preset_urls = Arc::new(Mutex::new(preset_list_urls(&cfg)));
    let (subscriptions_settled, had_cached_blocklists) = {
        let active = active_subscription_urls(
            &sub_urls.lock_recover(),
            &sub_disabled.lock_recover(),
            &preset_urls.lock_recover(),
        );
        let cached = load_blocklist_cache(&active, blocklist_cache_dir.as_deref());
        // 받아 둔 사본이 활성 목록을 모두 덮으면, 그리고 원격 목록이 하나도 없으면
        // 시작 직후에 다시 받을 것이 없다.
        let all_loaded = cached.len() == active.len();
        let had_cached = !cached.is_empty();
        if had_cached {
            *sub_meta.lock_recover() = cached;
        }
        (all_loaded, had_cached)
    };
    let (block, allow) = rebuild()
        .map_err(|error| crate::anyhow!(format!("필터 정책을 적용하지 못했습니다: {error}")))?;
    if had_cached_blocklists {
        onetdns_core::info!(
            event = "filter.cache_applied",
            block,
            allow,
            complete = subscriptions_settled,
            "차단 목록을 걸었습니다"
        );
    } else {
        onetdns_core::info!(
            event = "filter.lists_loaded",
            block,
            allow,
            services = cfg.blocked_services.len(),
            "차단 목록을 불러왔습니다"
        );
    }
    {
        let runtime = runtime_cfg.clone();
        let rebuild = rebuild.clone();
        let sd = shutdown.clone();
        let mut applied = service_blocking_paused(&cfg, std::time::SystemTime::now());
        let thread = std::thread::Builder::new()
            .name("service-schedule".into())
            .spawn(move || loop {
                if sleep_or_shutdown(SERVICE_SCHEDULE_TICK_SECS, &sd) {
                    break;
                }
                let paused = service_blocking_paused(&runtime.load(), std::time::SystemTime::now());
                if paused == applied {
                    continue;
                }
                match rebuild() {
                    Ok(_) => {
                        applied = paused;
                        onetdns_core::info!(
                            event = "filter.service_schedule_applied",
                            paused,
                            "서비스 차단 일정에 따라 서비스 차단 규칙을 다시 걸었습니다"
                        );
                    }
                    Err(error) => onetdns_core::warn!(
                        event = "filter.service_schedule_failed",
                        %error,
                        "서비스 차단 일정을 적용하지 못했습니다. 다음 확인 주기에 다시 시도합니다"
                    ),
                }
            })
            .with_context(|| "서비스 차단 일정 스레드를 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }
    let list_refresh_lock = Arc::new(Mutex::new(()));
    let refresh_url_lists: Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static> = {
        let urls = sub_urls.clone();
        let disabled_urls = sub_disabled.clone();
        let presets = preset_urls.clone();
        let sm = sub_meta.clone();
        let rebuild = rebuild.clone();
        let resolver = blocklist_resolver.clone();
        let cache_dir = blocklist_cache_dir.clone();
        let operation_lock = list_refresh_lock.clone();
        Arc::new(move || {
            let _guard = try_list_refresh_lock(&operation_lock)?;
            let snapshot = urls.lock_recover().clone();
            let disabled = disabled_urls.lock_recover().clone();
            let presets_now = presets.lock_recover().clone();
            let active = active_subscription_urls(&snapshot, &disabled, &presets_now);
            let previous_meta = sm.lock_recover().clone();
            let meta =
                fetch_blocklists_meta(&active, &resolver, &previous_meta, cache_dir.as_deref());
            *sm.lock_recover() = meta;
            match rebuild() {
                Ok(counts) => Ok(counts),
                Err(error) => {
                    *sm.lock_recover() = previous_meta;
                    let error = with_rollback_result(
                        error,
                        "URL 차단 목록의 실행 상태를 이전 값으로 되돌리지 못했습니다",
                        rebuild().map(|_| ()),
                    );
                    Err(error)
                }
            }
        })
    };
    let list_refresh_secs = Arc::new(std::sync::atomic::AtomicU64::new(cfg.list_refresh_secs));
    let list_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let refresh_lists = refresh_url_lists.clone();
        let interval = list_refresh_secs.clone();
        let generation = list_generation.clone();
        let sd = shutdown.clone();
        let mut done_first = subscriptions_settled;
        let thread = std::thread::Builder::new()
            .name("blocklist-refresh".into())
            .spawn(move || {
                let mut seen_generation = 0u64;
                let mut waited = 0u64;
                loop {
                    if sd.load(Ordering::Relaxed) {
                        break;
                    }
                    let period = interval.load(Ordering::Acquire);
                    let now_generation = generation.load(Ordering::Acquire);
                    // 목록이 바뀌면 주기를 기다리지 않고 바로 받아 온다.
                    let due = now_generation != seen_generation
                        || !done_first
                        || (period > 0 && waited >= period);
                    if due {
                        seen_generation = now_generation;
                        done_first = true;
                        waited = 0;
                        match refresh_lists() {
                            Ok((block, _)) => {
                                onetdns_core::info!(event = "filter.subscription_applied", block, "다운로드한 차단 목록을 적용했습니다")
                            }
                            Err(error) if error == LIST_REFRESH_BUSY => {
                                onetdns_core::info!(event = "filter.subscription_refresh_inflight", "차단 목록 갱신이 이미 진행 중입니다")
                            }
                            Err(error) => {
                                onetdns_core::warn!(event = "filter.subscription_refresh_failed", %error, "원격 차단 목록을 갱신하지 못했습니다")
                            }
                        }
                    }
                    if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                        break;
                    }
                    waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                }
            })
            .with_context(|| "URL 차단 목록 갱신 스레드를 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    let rpz_url_state: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(cfg.rpz_urls.clone()));
    {
        let urls = rpz_url_state.clone();
        let rpz_texts = rpz_texts.clone();
        let rebuild3 = rebuild.clone();
        let interval = list_refresh_secs.clone();
        let generation = list_generation.clone();
        let sd = shutdown.clone();
        let resolver = blocklist_resolver.clone();
        let cache_dir = blocklist_cache_dir.clone();
        let mut done_first = all_rpz_cached;
        let mut fetched_urls = cfg.rpz_urls.clone();
        let thread = std::thread::Builder::new()
            .name("rpz-refresh".into())
            .spawn(move || {
                let mut seen_generation = 0u64;
                let mut waited = 0u64;
                loop {
                    if sd.load(Ordering::Relaxed) {
                        break;
                    }
                    let period = interval.load(Ordering::Acquire);
                    let now_generation = generation.load(Ordering::Acquire);
                    let due = now_generation != seen_generation
                        || !done_first
                        || (period > 0 && waited >= period);
                    let urls_now = urls.lock_recover().clone();
                    if !due || (urls_now.is_empty() && fetched_urls.is_empty()) {
                        seen_generation = now_generation;
                        if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                            break;
                        }
                        waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                        continue;
                    }
                    seen_generation = now_generation;
                    done_first = true;
                    waited = 0;
                    let previous = rpz_texts.lock_recover().clone();
                    let kept = rpz_texts_by_url(&fetched_urls, &previous, &urls_now);
                    let fetched =
                        fetch_rpz_texts(&urls_now, &resolver, &kept, cache_dir.as_deref());
                    *rpz_texts.lock_recover() = fetched;
                    let previous_urls = std::mem::replace(&mut fetched_urls, urls_now);
                    match rebuild3() {
                        Ok((b, _)) => onetdns_core::info!(event = "filter.rpz_applied", block = b, "다운로드한 RPZ 규칙을 적용했습니다"),
                        Err(e) => {
                            *rpz_texts.lock_recover() = previous;
                            fetched_urls = previous_urls;
                            let error = with_rollback_result(
                                e,
                                "RPZ 실행 상태를 이전 값으로 되돌리지 못했습니다",
                                rebuild3().map(|_| ()),
                            );
                            onetdns_core::warn!(event = "filter.rpz_rebuild_failed", error = %error, "RPZ 규칙을 다시 구성하지 못해 이전 규칙을 유지합니다");
                        }
                    }
                    if sleep_or_shutdown(LIST_REFRESH_TICK_SECS, &sd) {
                        break;
                    }
                    waited = waited.saturating_add(LIST_REFRESH_TICK_SECS);
                }
            })
            .with_context(|| "RPZ 갱신 스레드를 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    let vendor_db = Arc::new(onetdns_core::ArcSwap::new(Arc::new(mac::VendorDb::load(
        cfg.mac_vendor_db.as_deref(),
    ))));
    if cfg.dhcp_enable || cfg.dhcp6_enable {
        onetdns_core::info!(
            event = "dhcp.vendor_db_ready",
            oui_entries = vendor_db.load().len(),
            "DHCP 임대 정보에 사용할 MAC 주소 제조사 데이터베이스를 준비했습니다"
        );
    }

    let edge_services = Arc::new(EdgeServices::default());
    let dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>> = Arc::new(Mutex::new(None));
    let dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>> = Arc::new(Mutex::new(None));
    reconcile_edge_services(&cfg, &edge_services, &dhcp_slot, &dhcp6_slot)
        .map_err(std::io::Error::other)?;
    {
        // 세대가 끝나면 등록된 서비스 신호를 모두 보낸다. 이것이 없으면 그 스레드들이 남아
        // 포트를 잡은 채로 다음 세대가 뜬다.
        let services = edge_services.clone();
        let recursor_jobs_for_retire = recursor_jobs.clone();
        let control_jobs_for_retire = control_jobs.clone();
        let secondary_jobs_for_retire = secondary_jobs.clone();
        let lease_sync_jobs_for_retire = lease_sync_jobs.clone();
        let zsk_rollover_jobs_for_retire = zsk_rollover_jobs.clone();
        let sd = shutdown.clone();
        let rl = reload.clone();
        let thread = std::thread::Builder::new()
            .name("edge-retire".into())
            .spawn(move || {
                while !sd.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                services.retire_all();
                recursor_jobs_for_retire.retire_all();
                // 재시작하는 중이면 관리 수신 스레드는 그대로 둔다. 여기서 멈추면 새
                // 세대가 자기 것을 시작할 때까지 웹 화면에 닿을 길이 없다. 이전 스레드는
                // 새 세대의 control_rebind가 자기 것을 시작한 뒤에 멈춘다.
                if !rl.load(Ordering::Relaxed) {
                    control_jobs_for_retire.retire_all();
                }
                secondary_jobs_for_retire.retire_all();
                lease_sync_jobs_for_retire.retire_all();
                zsk_rollover_jobs_for_retire.retire_all();
            })
            .with_context(|| "가장자리 서비스 종료 전파 작업을 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    *lease_sync_restart.lock_recover() = Some({
        let jobs = lease_sync_jobs.clone();
        let slot = dhcp_slot.clone();
        let resolver = blocklist_resolver.clone();
        let tracker = service_cleanup.tracker();
        Arc::new(move |next: &Config| -> Result<(), String> {
            let stop = jobs.restart_all();
            let Some(pool) = slot.lock_recover().clone() else {
                return Ok(());
            };
            if next.cluster_peers.is_empty() || next.control_token.is_empty() {
                return Ok(());
            }
            let thread = spawn_lease_sync(
                pool,
                next.cluster_peers.clone(),
                next.control_token.clone(),
                resolver.clone(),
                stop,
            )
            .map_err(|error| {
                format!("DHCP 임대 정보 동기화 스레드를 시작하지 못했습니다: {error}")
            })?;
            if let Some(thread) = thread {
                track_service_thread(&tracker, thread);
            }
            onetdns_core::info!(
                event = "dhcp.lease_sync_started",
                peers = next.cluster_peers.len(),
                "DHCP 임대 정보 동기화를 시작합니다(30초 주기)"
            );
            Ok(())
        }) as SecondaryRestart
    });
    (lease_sync_restart
        .lock_recover()
        .as_ref()
        .expect("방금 넣었습니다"))(&cfg)
    .map_err(std::io::Error::other)?;

    install_revocation_policy(&cfg, &blocklist_resolver);

    let dns64_prefix_bytes: Option<[u8; 16]> = cfg.dns64_prefix.as_ref().and_then(|s| {
        let ip_part = s.split('/').next()?;
        let v6: std::net::Ipv6Addr = ip_part.parse().ok()?;
        let mut o = v6.octets();
        o[12..16].fill(0);
        Some(o)
    });
    if dns64_prefix_bytes.is_some() {
        onetdns_core::info!(event = "dns64.enabled", prefix = ?cfg.dns64_prefix, "IPv6만 있는 망을 위해 A를 AAAA로 합성합니다");
    }
    if cfg.rebind_protection {
        onetdns_core::info!(
            event = "rebind.protection_enabled",
            "리바인딩 공격을 막습니다. 바깥에서 온 답에 사설 주소가 있으면 걸러냅니다"
        );
    }
    if cfg.safe_search {
        onetdns_core::info!(
            event = "safesearch.forced",
            "검색 서비스의 안전 검색을 강제로 적용합니다"
        );
    }
    let safe_search_flag = Arc::new(std::sync::atomic::AtomicBool::new(cfg.safe_search));

    let acl_state = Arc::new(DynamicAccessControl::new(runtime_access_control(&cfg)));
    let acl: Arc<dyn AccessControl> = acl_state.clone();
    let rate_state = Arc::new(DynamicRateLimiter::new(runtime_rate_limiters(&cfg)));
    let rate_limiters: Vec<Arc<dyn RateLimiter>> = vec![rate_state.clone()];
    onetdns_core::info!(event = "serve.protections_summary",
        acl_allow = cfg.acl_allow.len(),
        acl_deny = cfg.acl_deny.len(),
        rate_layers = rate_state.layer_count(),
        cookies = ?cfg.cookies,
        mtls = cfg.tls_authenticated(),
        "접근 제한과 속도 제한을 걸었습니다"
    );

    for warning in cfg.open_resolver_warnings() {
        onetdns_core::warn!(
            event = "security.open_resolver_warning",
            security = "open-resolver",
            detail = %warning,
            "외부에 공개된 재귀 DNS 서버 설정을 확인하십시오"
        );
    }
    // 조건이 맞지 않아 동작하지 않을 항목들. 설정을 막지 않고 알리기만 한다.
    for advisory in cfg.advisories() {
        onetdns_core::warn!(
            event = "config.advisory",
            detail = %advisory,
            "설정은 저장했지만 이 항목은 지금 조건에서 동작하지 않습니다"
        );
    }

    let tsig_keys = build_tsig_keys(&cfg).map_err(|error| crate::anyhow!(error))?;

    let native_hot_state: Arc<Mutex<Option<NativeHotState>>> = Arc::new(Mutex::new(None));
    let zone_signers: SharedZoneSigners = Arc::new(onetdns_core::ArcSwap::new(Arc::new(
        cfg.zones
            .iter()
            .filter(|z| z.dnssec_sign)
            .map(|zone| {
                let origin = onetdns_proto::Name::from_str(&zone.origin)
                    .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zone.origin))?;
                Ok((origin, load_zone_signer(zone)?))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|error| crate::anyhow!(error))?,
    )));
    let zone_store = Arc::new(onetdns_core::ArcSwap::new(Arc::new(
        build_zone_store(&cfg, &tsig_keys, &zone_signers.load())
            .map_err(|error| crate::anyhow!(error))?,
    )));

    let ixfr_journal = Arc::new(Mutex::new(std::collections::HashMap::<
        Vec<u8>,
        native::ZoneJournal,
    >::new()));
    let (notify_sender, notify_thread) =
        start_notify_dispatcher(&cfg.notify, &tsig_keys, shutdown.clone())
            .with_context(|| "DNS NOTIFY 발신 작업을 시작하지 못했습니다")?;
    if let Some(thread) = notify_thread {
        service_cleanup.track(thread);
    }
    {
        let store = zone_store.load();
        for zone in store.zones() {
            notify_sender.enqueue_zone(zone);
        }
    }

    // 인증서 갱신은 설정을 건드리지 않고 같은 경로의 내용만 바꾼다. 영역 파일과 같은
    // 이유로 파일 쪽을 주기적으로 본다. 갱신 도구가 이 서버에 아무것도 알리지 않아도
    // 다음 연결부터 새 인증서를 쓴다.
    {
        let watch_cfg = runtime_cfg.clone();
        let watch_slots = tls_slot_handle.clone();
        let watch_stop = shutdown.clone();
        let thread = std::thread::Builder::new()
            .name("tls-cert-watch".into())
            .spawn(move || {
                let mut last_error: Option<String> = None;
                loop {
                    if sleep_or_shutdown(TLS_CERT_WATCH_SECS, &watch_stop) {
                        break;
                    }
                    let Some(slots) = watch_slots.lock_recover().clone() else {
                        continue;
                    };
                    match slots.refresh_certificate_files(&watch_cfg.load()) {
                        Ok(swapped) => {
                            last_error = None;
                            if !swapped.is_empty() {
                                onetdns_core::info!(
                                    event = "tls.certificate_reloaded",
                                    changed = %swapped.join(","),
                                    "수신 주소를 닫지 않고 TLS 인증서를 교체했습니다"
                                );
                            }
                        }
                        // 갱신 도구가 파일을 쓰는 중이면 한두 번은 읽기에 실패한다. 같은
                        // 실패를 반복해 적으면 기록이 그것으로 덮인다.
                        Err(error) => {
                            if last_error.as_deref() != Some(error.as_str()) {
                                onetdns_core::warn!(
                                    event = "tls.certificate_reload_failed",
                                    %error,
                                    "갱신된 TLS 인증서를 읽지 못했습니다. 이전 인증서를 그대로 씁니다"
                                );
                                last_error = Some(error);
                            }
                        }
                    }
                }
            })
            .with_context(|| "TLS 인증서 감시 작업을 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    let zone_watchers = Arc::new(ZoneWatchers::default());
    reconcile_zone_watchers(
        &cfg,
        &zone_watchers,
        &zone_store,
        &notify_sender,
        &shutdown,
        &service_cleanup.tracker(),
    )
    .map_err(std::io::Error::other)?;

    let resign_zone_files = cfg
        .zones
        .iter()
        .map(|zone| {
            let origin = onetdns_proto::Name::from_str(&zone.origin)
                .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zone.origin))?;
            let file = zone
                .file
                .clone()
                .ok_or_else(|| format!("DNS 영역 '{}'에 file 설정이 없습니다", zone.origin))?;
            Ok((origin, file))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|error| crate::anyhow!(error))?;
    if let Some(thread) = spawn_resign_timer(
        zone_signers.clone(),
        zone_store.clone(),
        ixfr_journal.clone(),
        resign_zone_files,
        notify_sender.clone(),
        shutdown.clone(),
    )
    .with_context(|| "DNSSEC 재서명 스레드를 시작하지 못했습니다")?
    {
        service_cleanup.track(thread);
    }
    let reload_zone_keys: ZoneKeyReload = {
        let runtime = runtime_cfg.clone();
        let signers = zone_signers.clone();
        let zones = zone_store.clone();
        let hot_state = native_hot_state.clone();
        let notify = notify_sender.clone();
        Arc::new(
            move |rolled: &[onetdns_proto::Name]| -> Result<(), String> {
                let _write_guard = config_write_lock().lock_recover();
                let cfg = runtime.load();
                let settings = build_authority_settings(&cfg)?;
                let store = build_zone_store(&cfg, &settings.tsig_keys, &settings.zone_signers)?;
                signers.store(Arc::new(settings.zone_signers.clone()));
                if let Some(state) = hot_state.lock_recover().as_ref() {
                    state.authority.store(Arc::new(settings));
                }
                for origin in rolled {
                    if let Some(zone) = store.zone_exact(origin) {
                        notify.enqueue(origin, zone.soa().serial);
                    }
                }
                zones.store(Arc::new(store));
                Ok(())
            },
        )
    };
    // 설정에 직접 적은 영역 파일도 zones_dir 의 파일과 똑같이 편집된다. 여기서 보지 않으면
    // 직렬 번호를 올려도 이 서버가 옛 영역을 계속 답하고, 세컨더리는 변경을 영영 못 받는다.
    // 원본 하나만 바꿔 끼우지 않고 설정 전체로 다시 만드는 이유는, 서명과 TSIG, ZONEMD
    // 정책이 그 경로에만 있기 때문이다.
    {
        let watch_cfg = runtime_cfg.clone();
        let watch_reload = reload_zone_keys.clone();
        let watch_stop = shutdown.clone();
        let thread = std::thread::Builder::new()
            .name("zones-file-watch".into())
            .spawn(move || {
                let mut seen: std::collections::HashMap<PathBuf, std::time::SystemTime> =
                    zone_file_mtimes(&watch_cfg.load());
                loop {
                    if sleep_or_shutdown(ZONE_FILE_WATCH_SECS, &watch_stop) {
                        break;
                    }
                    let cfg = watch_cfg.load();
                    let now = zone_file_mtimes(&cfg);
                    let origins = zones_with_edited_files(&cfg, &seen, &now);
                    if origins.is_empty() {
                        seen = now;
                        continue;
                    }
                    match watch_reload(&origins) {
                        Ok(()) => {
                            seen = now;
                            onetdns_core::info!(
                                event = "authority.zones_reloaded_file",
                                zones = origins.len(),
                                "바뀐 영역 파일을 다시 읽어 실행 중인 영역을 교체했습니다"
                            );
                        }
                        // mtime 을 남겨 두면 다음 주기에 다시 시도한다. 편집 도중의 반쪽 파일은
                        // 그렇게 저절로 회복된다.
                        Err(error) => onetdns_core::warn!(
                            event = "authority.zone_file_reload_failed",
                            %error,
                            "바뀐 영역 파일을 읽지 못해 이전 영역을 그대로 답합니다"
                        ),
                    }
                }
            })
            .with_context(|| "DNS 영역 파일 감시 작업을 시작하지 못했습니다")?;
        service_cleanup.track(thread);
    }

    *zsk_rollover_restart.lock_recover() = Some({
        let jobs = zsk_rollover_jobs.clone();
        let reload_zone_keys = reload_zone_keys.clone();
        let tracker = service_cleanup.tracker();
        Arc::new(move |next: &Config| -> Result<(), String> {
            let stop = jobs.restart_all();
            let zones = next
                .zones
                .iter()
                .filter(|zone| zone.dnssec_sign && zone_is_split_key(zone))
                .map(|zone| {
                    onetdns_proto::Name::from_str(&zone.origin)
                        .map(|origin| (origin, zsk_path_for(zone)))
                        .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zone.origin))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let thread = spawn_zsk_rollover(
                zones,
                next.dnssec_roll_interval_secs,
                reload_zone_keys.clone(),
                stop,
            )
            .map_err(|error| format!("DNSSEC ZSK 교체 스레드를 시작하지 못했습니다: {error}"))?;
            if let Some(thread) = thread {
                track_service_thread(&tracker, thread);
            }
            Ok(())
        }) as SecondaryRestart
    });
    (zsk_rollover_restart
        .lock_recover()
        .as_ref()
        .expect("방금 넣었습니다"))(&cfg)
    .map_err(std::io::Error::other)?;
    let policy_engine = Arc::new(native::GatedSwap::new(Arc::new(
        build_policy_engine(&cfg).map_err(std::io::Error::other)?,
    )));

    let cache_slot: Arc<Mutex<Option<cache::CacheHandle>>> = Arc::new(Mutex::new(None));

    // 재귀 리졸버는 기반을 만들 때 정해지고 리액터 레인이 나중에 읽는다. 기반 만들기가
    // 다시 불릴 수 있으므로 공유 슬롯에 담는다.
    let lane_recursor: Arc<Mutex<Option<Arc<onetdns_recurse::Recursor>>>> =
        Arc::new(Mutex::new(None));

    let config_prev = shared.previous_config_text.clone();
    let applied_config_text = shared.applied_config_text.clone();
    let raft_hot_apply: Option<HotConfigApply>;

    // 컨트롤 플레인은 수신 주소가 없어도 만들어 둔다. 주소를 나중에 넣어도 그때 리스너만 열면
    // 되도록 하기 위해서다. 주소가 없으면 리스너를 시작하지 않을 뿐이다.
    let recorder = {
        let persist_opts = onetdns_control::PersistOpts {
            querylog_file: cfg
                .querylog_file
                .clone()
                .filter(|p| !p.as_os_str().is_empty()),
            stats_file: cfg.stats_file.clone().filter(|p| !p.as_os_str().is_empty()),
            flush_secs: cfg.persist_flush_secs,
        };
        let (recorder, stats) = {
            let mut slot = shared.metrics.lock_recover();
            if let Some((recorder, stats)) = slot.as_ref() {
                onetdns_core::info!(
                    event = "stats.channel_reused",
                    "기존 통계와 질의 기록을 유지한 채 새 설정을 적용합니다"
                );
                recorder.reconfigure(
                    cfg.querylog,
                    cfg.anonymize_client_ip,
                    cfg.querylog_ignored.clone(),
                    cfg.querylog_size.max(1),
                    cfg.querylog_retention_secs,
                    cfg.stats_retention_secs,
                );
                stats.reconfigure_persist(persist_opts.clone()).with_context(|| {
                    "새 통계 또는 질의 기록 저장 설정을 사용할 수 없어 DNS 서비스를 시작하지 못했습니다"
                })?;
                onetdns_core::info!(
                    event = "stats.persistence_reconfigured",
                    querylog_file = ?persist_opts.querylog_file,
                    stats_file = ?persist_opts.stats_file,
                    flush_secs = persist_opts.flush_secs,
                    "통계와 질의 로그의 저장 설정을 갱신했습니다"
                );
                (recorder.clone(), stats.clone())
            } else {
                let pair = onetdns_control::channel(
                    1024,
                    cfg.querylog_size.max(1),
                    cfg.querylog_retention_secs,
                    onetdns_control::RecorderOpts {
                        querylog: cfg.querylog,
                        anonymize: cfg.anonymize_client_ip,
                        ignored: cfg.querylog_ignored.clone(),
                        stats_retention_secs: cfg.stats_retention_secs,
                    },
                    persist_opts.clone(),
                );
                pair.1.flush_persisted().with_context(|| {
                    "통계 또는 질의 기록 파일을 사용할 수 없어 관리 기능을 시작하지 못했습니다"
                })?;
                onetdns_core::debug!(
                    event = "stats.channel_created",
                    querylog_capacity = cfg.querylog_size.max(1),
                    history_retention_secs = cfg.stats_retention_secs,
                    "통계를 모으기 시작했습니다"
                );
                *slot = Some((pair.0.clone(), pair.1.clone()));
                pair
            }
        };
        recorder.set_collecting(telemetry_consumed(&cfg));

        let jobs = Arc::new(JobRegistry::new(64));

        // 컨트롤 플레인 인증은 이 뒤에서 만들어진다. 계정만 바뀌었을 때 DNS를 건드리지 않고
        // 목록만 교체하려면 그 핸들이 필요하므로 슬롯을 먼저 잡아 둔다.
        let console_auth: Arc<Mutex<Option<Arc<onetdns_control::Auth>>>> =
            Arc::new(Mutex::new(None));

        let hot_config_apply = hot_apply::build(hot_apply::HotApplyDeps {
            chain_rebuild: chain_rebuild.clone(),
            console_auth: console_auth.clone(),
            runtime_cfg: runtime_cfg.clone(),
            filter: filter.clone(),
            overlay: overlay.clone(),
            service_set: service_set.clone(),
            refused_domains: refused_domains_state.clone(),
            safe_search: safe_search_flag.clone(),
            sub_meta: sub_meta.clone(),
            rpz_texts: rpz_texts.clone(),
            compiled_filter_cache: compiled_filter_cache.clone(),
            subscription_cache_dir: blocklist_cache_dir.clone(),
            acl_state: acl_state.clone(),
            rate_state: rate_state.clone(),
            recorder: recorder.clone(),
            forward_slot: forward_slot.clone(),
            forward_stats: forward_stats.clone(),
            native_hot_state: native_hot_state.clone(),
            stats: stats.clone(),
            zone_store: zone_store.clone(),
            zone_watchers: zone_watchers.clone(),
            zone_notify: notify_sender.clone(),
            zone_shutdown: shutdown.clone(),
            zone_threads: service_cleanup.tracker(),
            sub_urls: sub_urls.clone(),
            sub_titles: sub_titles.clone(),
            sub_disabled: sub_disabled.clone(),
            preset_urls: preset_urls.clone(),
            rpz_url_state: rpz_url_state.clone(),
            list_refresh_secs: list_refresh_secs.clone(),
            list_generation: list_generation.clone(),
            edge_services: edge_services.clone(),
            dhcp_slot: dhcp_slot.clone(),
            dhcp6_slot: dhcp6_slot.clone(),
            tls_slots: tls_slot_handle.clone(),
            secondary_restart: secondary_restart.clone(),
            zsk_rollover_restart: zsk_rollover_restart.clone(),
            zone_signers: zone_signers.clone(),
            vendor_db: vendor_db.clone(),
            lease_sync_restart: lease_sync_restart.clone(),
            raft_restart: raft_restart.clone(),
            listener_sync: listener_sync.clone(),
            control_rebind: control_rebind.clone(),
            blocklist_resolver_slot: blocklist_resolver_slot.clone(),
            blocklist_resolver: blocklist_resolver.clone(),
            cache_slot: cache_slot.clone(),
            lane_recursor: lane_recursor.clone(),
        });
        raft_hot_apply = Some(hot_config_apply.clone());

        let controls = control_api::build(control_api::ControlDeps {
            runtime_cfg: runtime_cfg.clone(),
            config_path: config_path.clone(),
            cfg_text: cfg_text.clone(),
            reload: reload.clone(),
            config_prev: config_prev.clone(),
            applied_config_text: applied_config_text.clone(),
            hot_config_apply: hot_config_apply.clone(),
            rebuild: rebuild.clone(),
            refresh_url_lists: refresh_url_lists.clone(),
            filter: filter.clone(),
            overlay: overlay.clone(),
            service_set: service_set.clone(),
            refused_domains_state: refused_domains_state.clone(),
            safe_search_flag: safe_search_flag.clone(),
            policy_engine: policy_engine.clone(),
            blocklist_resolver: blocklist_resolver.clone(),
            sub_urls: sub_urls.clone(),
            sub_meta: sub_meta.clone(),
            sub_disabled: sub_disabled.clone(),
            sub_titles: sub_titles.clone(),
            preset_urls: preset_urls.clone(),
            list_refresh_lock: list_refresh_lock.clone(),
            zone_store: zone_store.clone(),
            zone_signers: zone_signers.clone(),
            ixfr_journal: ixfr_journal.clone(),
            notify_sender: notify_sender.clone(),
            dhcp_slot: dhcp_slot.clone(),
            dhcp6_slot: dhcp6_slot.clone(),
            vendor_db: vendor_db.clone(),
            cache_slot: cache_slot.clone(),
            forward_stats: forward_stats.clone(),
            listener_reg: listener_reg.clone(),
            tls_slot_handle: tls_slot_handle.clone(),
            jobs: jobs.clone(),
            service_threads: service_cleanup.tracker(),
        });
        let state = onetdns_control::AppState {
            stats,
            auth: Arc::new(
                onetdns_control::Auth::new(
                    {
                        let mut admin = cfg.control_admin_tokens.clone();
                        if !cfg.control_token.is_empty() {
                            admin.push(cfg.control_token.clone());
                        }
                        admin
                    },
                    cfg.control_readonly_tokens.clone(),
                )
                .with_users(build_user_creds(&cfg).map_err(|error| crate::anyhow!(error))?)
                .with_sessions(shared.sessions.clone()),
            ),
            audit: {
                let mut slot = shared.audit.lock_recover();
                slot.get_or_insert_with(|| onetdns_control::AuditLog::new(1000))
                    .clone()
            },
            controls: Arc::new(controls),
            readiness: readiness.clone(),

            secure_cookies: false,
        };
        *console_auth.lock_recover() = Some(state.auth.clone());
        let state_for_control = state;

        *control_rebind.lock_recover() = Some({
            let jobs = control_jobs.clone();
            let shared_slot = shared.control_listener.clone();
            // 이 세대를 나타내는 이름. 주소가 같아도 세대가 다르면 새로 시작해야 한다 --
            // 이전 스레드는 앞 세대의 데이터 플레인을 가지고 있기 때문이다.
            let generation = CONTROL_GENERATION.fetch_add(1, Ordering::Relaxed);
            Arc::new(move |next: &Config| -> Result<(), String> {
                let Some(addr) = next.control_listen else {
                    // 주소를 지웠으면 리스너를 세우기만 한다. 재시작할 이유가 없다.
                    let mut running = jobs.running.lock_recover();
                    let had = !running.is_empty();
                    for (_, old) in running.iter() {
                        old.store(true, std::sync::atomic::Ordering::Release);
                    }
                    running.clear();
                    *shared_slot.lock_recover() = None;
                    if had {
                        onetdns_core::info!(
                            event = "control.stopped",
                            "control_listen을 지워 관리 화면과 API를 닫았습니다"
                        );
                    }
                    return Ok(());
                };
                let key = format!("{addr}#{generation}");
                if jobs
                    .running
                    .lock_recover()
                    .iter()
                    .any(|(have, _)| have == &key)
                {
                    return Ok(());
                }
                if !addr.ip().is_loopback() {
                    onetdns_core::warn!(event = "control.non_loopback_bind", %addr, "관리 API가 루프백이 아닌 주소에서 수신합니다. 방화벽과 접근 제어를 확인하세요");
                }
                let listener = match reuse_control_listener(&shared_slot, addr) {
                    Some(listener) => listener,
                    None => TcpListener::bind(addr).map_err(|error| {
                        format!("웹 관리 수신 주소를 열지 못했습니다: {addr}: {error}")
                    })?,
                };
                *shared_slot.lock_recover() = match listener.try_clone() {
                    Ok(clone) => Some(clone),
                    Err(error) => {
                        onetdns_core::warn!(event = "control.listener_share_failed", %addr, %error, "관리 수신 소켓을 세대 간에 물려주지 못했습니다. 설정을 다시 읽을 때 이 포트를 다시 열어야 합니다");
                        None
                    }
                };
                let bound = listener.local_addr().map_err(|error| {
                    format!("웹 관리 수신 주소를 확인하지 못했습니다: {addr}: {error}")
                })?;
                // 새 리스너를 시작한 뒤에 이전 것을 멈춘다. 지금 처리 중인 응답은 이전 리스너가
                // 끝까지 보낸다.
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let state = state_for_control.clone();
                let listener_stop = stop.clone();
                let thread = std::thread::Builder::new()
                    .name("onetdns-control".into())
                    .spawn(move || {
                        if let Err(error) =
                            onetdns_control::serve_listener(listener, state, listener_stop)
                        {
                            onetdns_core::error!(event = "control.stopped", %error, "웹 관리 서비스를 중지했습니다");
                        }
                    })
                    .map_err(|error| format!("웹 관리 스레드를 시작하지 못했습니다: {error}"))?;
                // 이 세대의 정리 목록에 넣지 않는다. 재시작하는 동안 살아 있어야 하므로
                // 여기서 기다리면 세대 정리가 끝나지 않는다. 멈추는 일은 다음 세대나
                // 종료 전파가 맡는다.
                drop(thread);
                let mut running = jobs.running.lock_recover();
                for (_, old) in running.iter() {
                    old.store(true, std::sync::atomic::Ordering::Release);
                }
                running.clear();
                running.push((key, stop));
                onetdns_core::info!(event = "control.started", addr = %bound, "관리 화면과 API를 열었습니다");
                Ok(())
            }) as SecondaryRestart
        });
        (control_rebind
            .lock_recover()
            .as_ref()
            .expect("방금 넣었습니다"))(&cfg)
        .map_err(std::io::Error::other)?;
        Some(recorder)
    };

    let start_raft = {
        let path = config_path.clone();
        let prev = config_prev.clone();
        let applied = applied_config_text.clone();
        let reload = reload.clone();
        let hot = raft_hot_apply.clone();
        Arc::new(
            move |next: &Config, expected_text: Option<&str>| -> Result<(), String> {
                // 언제나 먼저 멈춘다. 켜져 있는 채로 재시작하면 수신 주소가 겹친다.
                stop_raft();
                if !next.cluster_raft || next.cluster_node_id == 0 {
                    return Ok(());
                }
                ensure_raft_runtime(
                    next,
                    expected_text,
                    path.clone(),
                    prev.clone(),
                    applied.clone(),
                    reload.clone(),
                    hot.clone(),
                )
            },
        )
    };
    *raft_restart.lock_recover() = Some({
        let start_raft = start_raft.clone();
        Arc::new(move |next: &Config| start_raft(next, None)) as SecondaryRestart
    });
    start_raft(&cfg, cfg_text.as_deref()).map_err(std::io::Error::other)?;

    let mac_cache = if cfg.clients.iter().any(|c| !c.mac.is_empty()) {
        let cache = mac::NeighborCache::new();
        let thread = cache
            .clone()
            .spawn_refresh(Duration::from_secs(30), shutdown.clone())
            .with_context(|| "MAC 이웃 정보 갱신 스레드를 시작하지 못했습니다")?;
        service_cleanup.track(thread);
        onetdns_core::info!(
            event = "mac.neighbor_scan_started",
            "이웃 테이블을 사용한 MAC 주소 식별을 시작합니다(30초 주기)"
        );
        Some(cache)
    } else {
        None
    };

    let local_only_names = Arc::new(layers::LocalOnlyNames::new(
        cfg.domain_needed,
        cfg.bogus_priv,
        cfg.empty_zones,
    ));

    let native_handler: Arc<native::NativeServer> = {
        let timeout = Duration::from_secs(cfg.query_timeout_secs);
        let block_ttl = Arc::new(std::sync::atomic::AtomicU32::new(cfg.blocked_response_ttl));
        let local_ttl = Arc::new(std::sync::atomic::AtomicU32::new(cfg.local_ttl));
        let local_only_names = local_only_names.clone();
        let split_local_wire_cache = Arc::new(std::sync::OnceLock::new());

        let plan = resolver_chain::ChainPlan::new(&cfg);

        let base = resolver_chain::ResolverBase {
            forward_slot: forward_slot.clone(),
            recurse: resolver_chain::RecursiveBase {
                recursor_jobs: recursor_jobs.clone(),
                block_ttl: block_ttl.clone(),
                filter: filter.clone(),
                lane_recursor: lane_recursor.clone(),
                local_ttl: local_ttl.clone(),
                thread_tracker: service_cleanup.tracker(),
                shutdown: shutdown.clone(),
            },
        };
        let chain_layers = resolver_chain::ChainLayers {
            block_ttl: block_ttl.clone(),
            cache_slot: cache_slot.clone(),
            dhcp_slot: dhcp_slot.clone(),
            local_ttl: local_ttl.clone(),
            local_only_names: local_only_names.clone(),
            recorder: recorder.clone(),
            shutdown: shutdown.clone(),
            split_local_wire_cache: split_local_wire_cache.clone(),
            zone_store: zone_store.clone(),
        };

        let default_base: Arc<dyn native::Resolver> = base.build(&plan)?;
        let chain = chain_layers
            .wrap_common_layers(
                &plan,
                default_base,
                true,
                true,
                plan.is_split(),
                plan.cache_namespace(),
            )
            .map_err(|e| crate::anyhow!(e))?;

        let client_upstreams: Vec<native::ClientUpstream> =
            build_client_upstream_routes(&cfg, timeout)
                .map_err(|e| crate::anyhow!(e))?
                .into_iter()
                .map(|mut route| {
                    let ns = format!("{}/route={}", plan.cache_namespace(), route.namespace_key());
                    route.resolver = chain_layers.wrap_common_layers(
                        &plan,
                        route.resolver,
                        false,
                        false,
                        false,
                        &ns,
                    )?;
                    Ok(route)
                })
                .collect::<Result<_, String>>()
                .map_err(|e| crate::anyhow!(e))?;

        let notify_kick = Arc::new(native::NotifyKick::default());
        *secondary_restart.lock_recover() = Some({
            let jobs = secondary_jobs.clone();
            let store = zone_store.clone();
            let kick = notify_kick.clone();
            let sender = notify_sender.clone();
            let tracker = service_cleanup.tracker();
            Arc::new(move |next: &Config| -> Result<(), String> {
                let stop = jobs.restart_all();
                if next.secondary.is_empty() && next.catalog.is_empty() {
                    return Ok(());
                }
                let keys = build_tsig_keys(next)?;
                let thread = spawn_secondary_refresh(
                    next.clone(),
                    keys,
                    store.clone(),
                    kick.clone(),
                    sender.clone(),
                    stop,
                )
                .map_err(|error| format!("보조 영역 갱신 작업을 시작하지 못했습니다: {error}"))?;
                track_service_thread(&tracker, thread);
                Ok(())
            }) as SecondaryRestart
        });
        (secondary_restart
            .lock_recover()
            .as_ref()
            .expect("방금 넣었습니다"))(&cfg)
        .map_err(|error| crate::anyhow!(error))?;
        let views = build_views(&cfg).map_err(|error| crate::anyhow!(error))?;

        // 빠른 경로 구조는 조건과 무관하게 만들어 둔다. 조건 판정은 스위치가 맡으므로
        // 설정이 바뀌면 스위치만 올리고 내리면 되고, 소켓과 스레드는 그대로 둔다.
        let authority_wire_path = Some(zone_store.clone());

        let wire_fast_path = cache_slot.lock_recover().clone().map(|response_cache| {
            let _ = split_local_wire_cache.set(response_cache.clone());
            (
                wirecache::WireEntryFactory::new(cfg.min_ttl as u32, cfg.max_ttl as u32),
                response_cache,
            )
        });

        let lane_facts = LaneFacts {
            dhcp_pool: dhcp_slot.lock_recover().is_some(),
            views_present: !views.is_empty(),
            policy_present: policy_engine.present(),
        };
        let lane_gates = evaluate_lane_gates(&cfg, &lane_facts);

        // 해석 체인을 교체 가능한 슬롯에 넣어 넘긴다. 설정이 바뀌면 체인만 새로 만들어
        // 교체하면 되므로 스레드와 소켓을 내렸다 올릴 이유가 없어진다.
        let chain_slot = Arc::new(native::ResolverSlot::new(chain));
        // 설정이 바뀌면 같은 위치에서 기반과 체인을 새로 만들어 슬롯에 넣는다.
        *chain_rebuild.lock_recover() = Some({
            let layers = chain_layers.clone();
            let slot = chain_slot.clone();
            let make_base = Mutex::new(base);
            Arc::new(
                move |next: &resolver_chain::ChainPlan| -> Result<(), String> {
                    let base = make_base
                        .lock_recover()
                        .build(next)
                        .map_err(|error| error.to_string())?;
                    /*
                     * 공유 캐시 이름 공간도 새 계획에서 낸다. 시작할 때 낸 것을 쓰면 처리 방식이나
                     * DNSSEC 을 바꿔도 같은 슬롯을 가리켜, 이전 의미로 담긴 답이 새 설정의 답인
                     * 것처럼 나온다.
                     */
                    let chain = layers.wrap_common_layers(
                        next,
                        base,
                        true,
                        true,
                        next.is_split(),
                        next.cache_namespace(),
                    )?;
                    slot.replace(chain);
                    Ok(())
                },
            ) as ChainRebuild
        });

        let mut native_server = native::NativeServer::new(
            filter.clone(),
            acl.clone(),
            rate_limiters.clone(),
            chain_slot.clone(),
            cfg.blocked_response_ttl,
        )
        .with_ttl_sources(block_ttl, local_ttl)
        .with_client_upstreams(client_upstreams)
        .with_features(build_native_features(
            &cfg,
            dns64_prefix_bytes,
            safe_search_flag.clone(),
            recorder.clone(),
            mac_cache.clone(),
        )?)
        .with_policy(policy_engine.clone())
        .with_xfr(zone_store.clone(), Vec::new())
        .with_notify_kick(notify_kick)
        .with_journal(ixfr_journal.clone())
        .with_views(views)
        .with_authority_wire_path(authority_wire_path, recursion_offered_by(&cfg))
        .with_wire_fast_path(wire_fast_path);
        native_server.replace_authority(
            build_authority_settings(&cfg).map_err(|error| crate::anyhow!(error))?,
        );
        {
            let notify = notify_sender.clone();
            native_server = native_server.with_update_notify(Arc::new(move |origin, serial| {
                notify.enqueue(origin, serial)
            }));
        }
        if let Some(ch) = cache_slot.lock_recover().clone() {
            let recursor = lane_recursor.lock_recover().clone();
            native_server = native_server.with_reactor_lane_runtime(recursor, ch, 32);
        }
        let _ = native_server.lane_switch.set(
            lane_gates.wire,
            lane_gates.authority,
            lane_gates.reactor,
        );
        onetdns_core::debug!(
            event = "do53.lane_switch",
            wire = lane_gates.wire,
            authority = lane_gates.authority,
            reactor = lane_gates.reactor,
            "빠른 경로 적격 여부를 정했습니다"
        );
        Arc::new(native_server)
    };
    *native_hot_state.lock_recover() = Some(NativeHotState {
        handler: native_handler.clone(),
        features: native_handler.features.clone(),
        policy: native_handler.policy.clone(),
        views: native_handler.views.clone(),
        block_ttl: native_handler.block_ttl.clone(),
        local_ttl: native_handler.local_ttl.clone(),
        local_only_names: local_only_names.clone(),
        wire_epoch: native_handler.wire_epoch.clone(),
        lane_switch: native_handler.lane_switch.clone(),
        authority: native_handler.authority.clone(),
    });

    // 인증서는 교체 가능한 슬롯에 넣는다. 인증서를 갈아도 수신 소켓은 그대로 두고 다음
    // 연결부터 새 인증서를 쓴다.

    let listeners = Arc::new(ListenerSet::default());
    *listener_sync.lock_recover() = Some({
        let set = listeners.clone();
        let handler = native_handler.clone();
        let slots = tls_slot_handle.clone();
        let sd = shutdown.clone();
        let registry = listener_reg.clone();
        let path = config_path.clone();
        let tracker = service_cleanup.tracker();
        Arc::new(move |next: &Config| -> Result<(), String> {
            reconcile_listeners(next, &set, &handler, &slots, &sd, &registry)?;
            reconcile_dnscrypt(next, &set, &handler, &path, &tracker, &registry)
        }) as SecondaryRestart
    });
    (listener_sync
        .lock_recover()
        .as_ref()
        .expect("방금 넣었습니다"))(&cfg)
    .map_err(std::io::Error::other)?;

    onetdns_core::info!(event = "server.ready", "이제 질의를 받습니다");

    #[cfg(target_os = "linux")]
    if let Some(user) = cfg.run_as_user.as_deref() {
        /** @brief 권한 내려놓기를 한 번만 하게 한다. */
        static DROP_ONCE: std::sync::Once = std::sync::Once::new();
        let mut drop_result: Option<Result<(), String>> = None;
        DROP_ONCE.call_once(|| {
            let r = privdrop::drop_privileges(user, cfg.run_as_group.as_deref());
            if r.is_ok() {
                onetdns_core::info!(
                    event = "privdrop.applied",
                    user,
                    "프로세스의 사용자·그룹 권한을 낮추고 추가 권한 획득을 차단했습니다"
                );
            }
            drop_result = Some(r);
        });
        if let Some(Err(e)) = drop_result {
            return Err(crate::anyhow!(format!(
                "프로세스 권한을 낮추지 못해 서비스를 중지합니다: {e}"
            )));
        }
    }

    if !reload.load(Ordering::Acquire) {
        if let Some(text) = cfg_text.as_ref() {
            *shared.applied_config_text.lock_recover() = Some(text.clone());
        }
    } else {
        onetdns_core::info!(
            event = "config.changed_during_start",
            "서비스 준비 중 설정이 다시 바뀌어 현재 구성을 복구 기준으로 채택하지 않습니다"
        );
    }
    readiness.store(true, Ordering::Release);
    if let Some(cb) = on_ready {
        cb();
    }

    let reloaded = loop {
        if external_stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
        {
            onetdns_core::info!(
                event = "server.shutdown_requested",
                reason = "external_signal",
                "외부 종료 신호를 받았습니다"
            );
            break false;
        }
        if reload.load(Ordering::Relaxed) {
            onetdns_core::info!(
                event = "server.restart_requested",
                reason = "config_change",
                "설정 변경을 적용하기 위해 DNS 서비스를 다시 시작합니다"
            );
            break true;
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    readiness.store(false, Ordering::Release);
    shutdown.store(true, Ordering::Relaxed);
    for (_, server) in listeners.plain.lock_recover().drain(..) {
        server.shutdown();
    }
    listeners.dot.lock_recover().clear();
    listeners.doh.lock_recover().clear();
    listeners.doq.lock_recover().clear();
    listeners.doh3.lock_recover().clear();
    for (_, stop, tcp) in listeners.dnscrypt.lock_recover().drain(..) {
        stop.store(true, Ordering::Release);
        drop(tcp);
    }

    service_cleanup.shutdown_and_join();
    std::thread::sleep(Duration::from_millis(500));
    onetdns_core::info!(
        event = "server.configuration_stopped",
        reload = reloaded,
        "지금 구성을 내립니다"
    );
    Ok(reloaded)
}

/**
 * @brief 이름 하나를 물어 결과를 보여 준다.
 *
 * @details 돌고 있는 서버에 묻지 않고 기본 설정의 업스트림에 직접 묻는다. 따라서
 *          접근 제한, 필터, 캐시, 백엔드를 하나도 거치지 않는다. 서버가 실제로
 *          무엇을 돌려주는지 보려면 수신 주소로 진짜 질의를 보내야 한다.
 * @param name 조회할 도메인 이름.
 * @param qtype 조회할 레코드 유형. 없으면 A 로 본다.
 */
fn query(name: String, qtype: Option<String>) -> BoxResult<()> {
    let cfg = Config::default();
    let ups = upstream::native_upstreams(&cfg.upstreams, &cfg.upstream_urls, &cfg.bootstrap);
    if ups.is_empty() {
        crate::bail!("`upstreams`에 사용할 업스트림 DNS 서버가 지정되지 않았습니다");
    }
    let fwd = onetdns_forward::Forwarder::with_upstreams(
        ups,
        Duration::from_secs(cfg.query_timeout_secs),
    )
    .with_strategy(forward_strategy(cfg.upstream_strategy))
    .with_parallel_limit(cfg.upstream_concurrency);
    let qtype = parse_qtype(qtype.as_deref())?;
    let qname = onetdns_proto::Name::from_str(&name)
        .map_err(|_| crate::anyhow!("도메인 이름의 형식이 올바르지 않습니다: {name}"))?;
    let req = onetdns_proto::Message::query(0x4242, qname, qtype);
    let resp = fwd
        .resolve(&req)
        .map_err(|e| crate::anyhow!("DNS 질의를 처리하지 못했습니다: {e}"))?;

    println!(
        "응답 코드: {} ({})",
        native::rcode_str(onetdns_proto::ResponseCode(resp.header.rcode)),
        resp.header.rcode
    );
    if resp.answers.is_empty() {
        println!("응답 레코드가 없습니다");
    }
    for r in &resp.answers {
        println!("{}\t{}\t{:?}\t{:?}", r.name, r.ttl, r.rtype, r.rdata);
    }
    Ok(())
}

/**
 * @brief 이 서버의 수신 주소로 이름 하나를 실제로 물어 답을 돌려준다.
 *
 * @details 진단(explain)은 처분을 설명할 뿐이라 「그래서 무엇으로 풀리는지」를 알 수 없다.
 *          체인을 안에서 직접 부르지 않고 이 서버의 수신 주소에 진짜 질의를 보낸다. 그래야
 *          접근 제한·필터·캐시·백엔드를 전부 거친, 클라이언트가 실제로 받을 답이 나온다.
 * @param listeners 설정된 평문 수신 주소들. 첫 번째를 쓴다.
 * @param timeout 한 번의 왕복에 줄 상한.
 * @return 응답 코드와 답 레코드를 담은 JSON. 물어보지 못하면 오류 문구.
 */
fn resolve_probe(
    listeners: &[SocketAddr],
    timeout: Duration,
    body: &str,
) -> Result<String, String> {
    let esc = onetdns_core::json::escape;
    let j = onetdns_core::json::parse(body)
        .map_err(|error| format!("JSON 요청 본문이 올바르지 않습니다: {error}"))?;
    let qname = j
        .get("qname")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or("`qname` 항목에 물어볼 도메인을 입력해야 합니다")?;
    let name = onetdns_proto::Name::from_str(qname)
        .map_err(|_| format!("도메인 이름의 형식이 올바르지 않습니다: {qname}"))?;
    let qtype_text = j
        .get("qtype")
        .and_then(|v| v.as_str())
        .unwrap_or("A")
        .to_string();
    let qtype = onetdns_proto::RecordType(
        *qtype_numbers(&[qtype_text.clone()])
            .first()
            .ok_or("질의 종류를 알아보지 못했습니다")?,
    );

    // 0.0.0.0이나 ::는 "모든 주소"라 목적지가 될 수 없다. 같은 포트의 루프백으로 바꾼다.
    let target = listeners
        .first()
        .map(|addr| match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
            }
            IpAddr::V6(ip) if ip.is_unspecified() => {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), addr.port())
            }
            _ => *addr,
        })
        .ok_or("일반 DNS 수신 주소가 없어 물어볼 곳이 없습니다")?;

    let request = onetdns_proto::Message::query(
        u16::from_be_bytes(onetdns_core::ephemeral_random_array::<2>()),
        name,
        qtype,
    );
    let started = std::time::Instant::now();
    let response = onetdns_forward::query_server(target, &request, timeout)
        .map_err(|error| format!("이 서버에 물어보지 못했습니다: {error}"))?;
    let elapsed_ms = started.elapsed().as_millis();

    let record_json = |record: &onetdns_proto::Record| {
        // 루트 이름은 소문자로 바꾸면 빈 문자열이 된다. 화면에 빈칸이 뜨지 않게 점으로 적는다.
        let owner = record.name.to_ascii_lower();
        let owner = if owner.is_empty() {
            ".".to_string()
        } else {
            owner
        };
        format!(
            "{{\"name\":{},\"type\":{},\"ttl\":{},\"data\":{}}}",
            esc(&owner),
            esc(record.rtype.name()),
            record.ttl,
            esc(&native::rdata_brief(&record.rdata))
        )
    };
    let answers: Vec<String> = response.answers.iter().map(record_json).collect();
    let authorities: Vec<String> = response.authorities.iter().map(record_json).collect();
    Ok(format!(
        "{{\"qname\":{},\"qtype\":{},\"rcode\":{},\"authentic_data\":{},\"truncated\":{},\"elapsed_ms\":{},\"server\":{},\"answers\":[{}],\"authorities\":[{}]}}",
        esc(qname),
        esc(&qtype_text),
        esc(&native::rcode_str(onetdns_proto::ResponseCode(
            response.header.rcode
        ))),
        response.header.authentic_data,
        response.header.truncated,
        elapsed_ms,
        esc(&target.to_string()),
        answers.join(","),
        authorities.join(",")
    ))
}

/** @brief 이 서버가 DNS 질의를 받는 모든 수신 주소. */
fn dns_listeners(cfg: &Config) -> Vec<SocketAddr> {
    cfg.listen
        .iter()
        .chain(cfg.listen_dot.iter())
        .chain(cfg.listen_doh.iter())
        .chain(cfg.listen_doq.iter())
        .chain(cfg.listen_doh3.iter())
        .chain(cfg.listen_dnscrypt.iter())
        .copied()
        .collect()
}

/** @brief 업스트림이 이 서버의 리스너를 가리키지 않는지 확인한다. 가리키면 질의가 무한히 돌아온다. */
fn ensure_upstreams_not_self(
    cfg: &Config,
    upstreams: &[onetdns_forward::Upstream],
    label: &str,
) -> Result<(), String> {
    upstream::ensure_not_listener(upstreams, &dns_listeners(cfg), label)
}

/**
 * @brief 서버가 뜰 때 거절할 설정을 미리 가린다.
 * @details 설정 파일 형식만 보면 통과하는데 서버는 뜨지 않는 설정이 있다. 앵커 파일,
 *          정책 모듈, 영역 원본 주소, 공유 캐시 주소, 차단 서비스 이름은 읽거나 풀어 봐야
 *          알 수 있다. 설정 확인 명령과 관리 API의 설정 검증이 이 함수를 같이 쓴다.
 * @return 서버가 거절할 첫 이유.
 */
fn runtime_preflight(cfg: &Config) -> Result<(), String> {
    ensure_resolution_sources_not_self(cfg)?;
    if let Some(path) = cfg.dnssec_anchor_file.as_deref() {
        load_configured_trust_anchors(path).map_err(|error| error.to_string())?;
    }
    build_policy_engine(cfg)?;
    for (key, source) in zone_source_specs(cfg) {
        if source.is_none() {
            return Err(format!("DNS 영역 원본 '{key}'의 주소가 올바르지 않습니다"));
        }
    }
    if let Some(host) = &cfg.cachedb_redis_host {
        cachedb_redis_addr(host, cfg.cachedb_redis_port, &cfg.bootstrap)?;
    }
    edge_service_preflight(cfg)?;
    if let Some(url) = &cfg.zones_postgres {
        onetdns_authority::PostgresZoneSource::from_url(url, &cfg.zones_sql_table)
            .ok_or("zones_postgres 주소를 해석하지 못했습니다")?
            .check()
            .map_err(|error| format!("zones_postgres: {error}"))?;
    }
    if let Some(url) = &cfg.zones_mysql {
        onetdns_authority::MysqlZoneSource::from_url(url, &cfg.zones_sql_table)
            .ok_or("zones_mysql 주소를 해석하지 못했습니다")?
            .check()
            .map_err(|error| format!("zones_mysql: {error}"))?;
    }
    if let Some(path) = &cfg.tls_client_ca {
        load_client_ca(path)?;
    }
    let services = cfg.blocked_services.iter().chain(
        cfg.clients
            .iter()
            .flat_map(|client| client.blocked_services.iter()),
    );
    for service in services {
        if onetdns_filter::services::service_rules(service).is_none() {
            return Err(format!("알 수 없는 차단 서비스: {service}"));
        }
    }
    Ok(())
}

/** @brief 이름을 풀 곳들이 자기 자신을 가리키지 않는지 확인한다. */
fn ensure_resolution_sources_not_self(cfg: &Config) -> Result<(), String> {
    for (label, addresses) in [
        ("bootstrap", cfg.bootstrap.as_slice()),
        ("root_hints", cfg.root_hints.as_slice()),
        ("upstreams", cfg.upstreams.as_slice()),
    ] {
        let upstreams: Vec<_> = addresses
            .iter()
            .map(|ip| onetdns_forward::Upstream::udp(SocketAddr::new(*ip, 53)))
            .collect();
        ensure_upstreams_not_self(cfg, &upstreams, label)?;
    }
    Ok(())
}

/** @brief 클라이언트별 업스트림 경로를 만든다. */
fn build_client_upstream_routes(
    cfg: &Config,
    timeout: Duration,
) -> Result<Vec<native::ClientUpstream>, String> {
    let mut routes = Vec::new();
    for c in &cfg.clients {
        if c.upstreams.is_empty() {
            continue;
        }
        let ups = upstream::servers_to_upstreams(&c.upstreams, &cfg.bootstrap);
        if ups.is_empty() {
            return Err(format!(
                "클라이언트 '{}'에 사용할 수 있는 전용 업스트림 DNS 서버가 없습니다",
                c.name
            ));
        }
        ensure_upstreams_not_self(
            cfg,
            &ups,
            &format!("클라이언트 '{}' 전용 업스트림 DNS 서버", c.name),
        )?;
        let mut ids = c.client_ids.clone();
        ids.extend(c.mac.iter().map(|m| mac::normalize_mac(m)));
        let fwd = onetdns_forward::Forwarder::with_upstreams(ups, timeout)
            .with_strategy(forward_strategy(cfg.upstream_strategy))
            .with_parallel_limit(cfg.upstream_concurrency);
        let backend: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Forward(fwd));
        routes.push(native::ClientUpstream::new(c.ids.clone(), ids, backend));
    }
    Ok(routes)
}

/** @brief 전달 체인을 만든다. */
fn build_forward_backend(
    cfg: &Config,
) -> Result<(Arc<dyn native::Resolver>, onetdns_forward::ForwardStats), String> {
    ensure_resolution_sources_not_self(cfg)?;
    let upstreams = upstream::native_upstreams(&cfg.upstreams, &cfg.upstream_urls, &cfg.bootstrap);
    if upstreams.is_empty() {
        let configured = cfg.upstreams.len() + cfg.upstream_urls.len();
        if configured > 0 {
            let has_hostname = cfg
                .upstream_urls
                .iter()
                .any(|u| upstream::url_uses_hostname(u));
            let hint = if has_hostname && cfg.bootstrap.is_empty() {
                " (호스트 이름으로 업스트림 DNS 서버를 지정하려면 bootstrap가 필요합니다. 또는 IP 주소와 TLS 서버 이름을 함께 지정하십시오. 예: h3://1.1.1.1/dns-query#cloudflare-dns.com)"
            } else if has_hostname {
                " (업스트림 DNS 서버의 호스트 이름을 찾지 못했습니다. `bootstrap`가 연결 가능한지 확인하거나 IP 주소와 TLS 서버 이름을 함께 지정하십시오. 예: h3://1.1.1.1/dns-query#cloudflare-dns.com)"
            } else {
                " (업스트림 DNS 서버 주소 형식을 확인하십시오)"
            };
            return Err(format!(
                "설정한 업스트림 DNS 서버 {configured}개를 모두 해석하지 못했습니다{hint}"
            ));
        }
        return Err("업스트림 DNS 서버 전달 또는 도메인별 처리 방식을 사용하려면 업스트림 DNS 서버를 하나 이상 지정해야 합니다".to_string());
    }
    ensure_upstreams_not_self(cfg, &upstreams, "upstreams")?;
    let forwarder = onetdns_forward::Forwarder::with_upstreams(
        upstreams,
        Duration::from_secs(cfg.query_timeout_secs),
    )
    .with_strategy(forward_strategy(cfg.upstream_strategy))
    .with_parallel_limit(cfg.upstream_concurrency);
    let stats = forwarder.stats_handle();
    Ok((Arc::new(native::NativeBackend::Forward(forwarder)), stats))
}

/** @brief 설정한 업스트림 고르기 방식. */
fn forward_strategy(s: UpstreamStrategy) -> onetdns_forward::Strategy {
    match s {
        UpstreamStrategy::RoundRobin => onetdns_forward::Strategy::RoundRobin,
        UpstreamStrategy::Parallel => onetdns_forward::Strategy::Parallel,

        UpstreamStrategy::QueryStatistics => onetdns_forward::Strategy::QueryStatistics,
        UpstreamStrategy::UserOrder => onetdns_forward::Strategy::Sequential,
    }
}

/**
 * @brief 암호화 전송이 함께 쓸 인증서와 개인키를 한 번만 마련한다.
 *
 * @details 전송마다 따로 만들면 자체 서명일 때 DoT·DoH·DoQ·DoH3 이 서로 다른 인증서를
 *          내놓는다. 자체 서명은 고정해 쓰는 것이므로, 한 곳에서 받은 인증서로 다른
 *          전송에 붙지 못한다. DDR 로 여러 암호화 주소를 알리는 배포에서 특히 드러난다.
 */
fn native_tls_material(cfg: &Config) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    if let Some(host) = &cfg.tls_self_signed_host {
        onetdns_core::warn!(event = "tls.self_signed_in_use", host = %host, "자체 서명 인증서로 암호화 DNS를 제공합니다. 클라이언트는 이 인증서를 신뢰하지 않으므로 검증을 끄지 않으면 연결하지 못합니다");
        return onetdns_transport::self_signed_material(host)
            .map_err(|error| format!("자체 서명 TLS 인증서를 만들지 못했습니다: {error}"));
    }
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        return onetdns_transport::load_pem(c, k)
            .map_err(|error| format!("TLS 인증서 또는 개인키를 읽지 못했습니다: {error}"));
    }
    Err("암호화 DNS 수신 주소에 사용할 TLS 인증서가 없습니다".to_string())
}

/** @brief 암호화 전송에 쓸 TLS 설정을 만든다. */
fn native_tls_config(
    cfg: &Config,
    alpn: Vec<Vec<u8>>,
    material: &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<Arc<onetdns_tls::ServerConfig>, String> {
    let (certs, key) = (material.0.clone(), material.1.clone());
    if certs.is_empty() {
        return Err("TLS 인증서 체인이 비어 있습니다".to_string());
    }
    let mut sc = onetdns_tls::ServerConfig::from_chain_pkcs8(certs, &key)
        .ok_or_else(|| {
            "TLS 인증서와 개인키가 일치하지 않거나 지원하지 않는 형식입니다".to_string()
        })?
        .with_alpn(alpn);
    if let Some(ca_path) = &cfg.tls_client_ca {
        sc = sc.with_client_ca(load_client_ca(ca_path)?);
    }

    if cfg.tls_client_ca.is_none() {
        sc = sc.with_resumption(onetdns_tls::conn::ServerResumption::secure_default());
    }
    Ok(Arc::new(sc))
}

/** @brief 클라이언트 인증서를 확인할 CA 번들을 읽는다. */
fn load_client_ca(path: &std::path::Path) -> Result<onetdns_tls::TrustStore, String> {
    let pem = read_bytes_limited(path, LOCAL_CA_MAX_BYTES).map_err(|error| {
        format!(
            "mTLS CA 파일을 읽지 못했습니다({}): {error}",
            path.display()
        )
    })?;
    onetdns_tls::TrustStore::try_from_pem(&pem).map_err(|error| {
        format!("mTLS CA 파일에 손상됐거나 지원하지 않는 형식의 인증서가 있습니다: {error}")
    })
}

/** @brief 자체 서명 인증서를 만든다. */
fn gen_cert(host: String, cert_out: PathBuf, key_out: PathBuf) -> BoxResult<()> {
    let (cert_pem, key_pem) = onetdns_transport::generate_self_signed_pem(&host)?;
    commit_cert_key(&cert_out, cert_pem.as_bytes(), &key_out, key_pem.as_bytes()).with_context(
        || {
            format!(
                "인증서 또는 개인키 파일을 저장하지 못했습니다: {} / {}",
                cert_out.display(),
                key_out.display()
            )
        },
    )?;
    println!(
        "자체 서명 인증서 생성: {} / {} (host={host})",
        cert_out.display(),
        key_out.display()
    );
    Ok(())
}

/** @brief 컨트롤 플레인 주소와 토큰을 정한다. */
fn resolve_ctl(ctl: &CtlArgs) -> BoxResult<(String, String)> {
    if let Some(p) = &ctl.config {
        let cfg = Config::load_or_default(Some(p))?;
        let addr = cfg
            .control_listen
            .ok_or_else(|| crate::anyhow!("설정 파일에 control_listen 항목이 없습니다"))?;
        Ok((base_url(addr), cfg.control_token.as_str().to_owned()))
    } else {
        let url = ctl
            .url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8553".to_string());
        Ok((url, ctl.token.clone().unwrap_or_default()))
    }
}

/** @brief 컨트롤 플레인 기본 주소. */
fn base_url(addr: SocketAddr) -> String {
    let ip = addr.ip();
    if ip.is_unspecified() {
        match ip {
            IpAddr::V4(_) => format!("http://127.0.0.1:{}", addr.port()),
            IpAddr::V6(_) => format!("http://[::1]:{}", addr.port()),
        }
    } else if addr.is_ipv6() {
        format!("http://[{}]:{}", ip, addr.port())
    } else {
        format!("http://{addr}")
    }
}

/**
 * @brief 관리 API 응답이 성공일 때만 본문을 돌려준다.
 *
 * @details 요청이 거절되어도 HTTP 응답 자체는 도착하므로, 상태 코드를 보지 않으면 인증
 *          실패나 리더가 아닌 노드의 거절을 성공으로 출력하게 된다. 서버가 보낸 error
 *          문구가 있으면 그 문구를 오류로 쓴다.
 */
fn ctl_body(resp: http::Resp) -> BoxResult<String> {
    let status = resp.status;
    let body = resp.into_string()?;
    if (200..300).contains(&status) {
        return Ok(body);
    }
    let message = onetdns_core::json::parse(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_else(|| body.trim().to_owned());
    if message.is_empty() {
        crate::bail!("관리 API가 요청을 거절했습니다(HTTP {status})");
    }
    crate::bail!("관리 API가 요청을 거절했습니다(HTTP {status}): {message}")
}

/** @brief 토큰을 인증 헤더 값으로. */
fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/** @brief 지표를 보여 준다. */
fn ctl_stats(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::get(&format!("{base}/v1/stats"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("관리 API 요청을 처리하지 못했습니다: {e}"))?;
    let body = ctl_body(resp)?;

    println!("{body}");
    Ok(())
}

/** @brief 많이 물은 이름들을 보여 준다. */
fn ctl_top(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::get(&format!("{base}/v1/top"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("관리 API 요청을 처리하지 못했습니다: {e}"))?;
    let body = ctl_body(resp)?;
    let v = onetdns_core::json::parse(&body)
        .map_err(|e| crate::anyhow!("관리 API 응답을 해석하지 못했습니다: {e}"))?;
    let show = |label: &str, key: &str| {
        println!("[{label}]");
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            for item in arr.iter().take(10) {
                if let Some(pair) = item.as_array() {
                    let count = pair.get(1).and_then(|c| c.as_u64()).unwrap_or(0);
                    let name = pair.first().and_then(|n| n.as_str()).unwrap_or("");
                    println!("  {count:>6}  {name}");
                }
            }
        }
    };
    show("업스트림 도메인", "domains");
    show("업스트림 차단", "blocked");
    show("업스트림 클라이언트", "clients");
    Ok(())
}

/** @brief 설정을 다시 읽게 한다. */
fn ctl_reload(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::post(&format!("{base}/v1/reload"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("관리 API 요청을 처리하지 못했습니다: {e}"))?;
    let body = ctl_body(resp)?;
    println!("설정을 다시 불러왔습니다: {body}");
    Ok(())
}

/** @brief 차단 또는 허용 목록에 이름을 넣는다. */
fn ctl_add(kind: &str, domain: &str, ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let json = format!("{{\"domain\":{}}}", onetdns_core::json::escape(domain));
    let resp = http::post(&format!("{base}/v1/{kind}"))
        .header("Authorization", &bearer(&token))
        .header("Content-Type", "application/json")
        .resolver(resolver)
        .body_string(&json)
        .call()
        .map_err(|e| crate::anyhow!("관리 API 요청을 처리하지 못했습니다: {e}"))?;
    let body = ctl_body(resp)?;
    println!("{kind} 규칙에 {domain}을 추가했습니다: {body}");
    Ok(())
}

/** @brief 목록 개수. */
fn counts((block, allow): (usize, usize)) -> onetdns_control::ListCounts {
    onetdns_control::ListCounts { block, allow }
}

/** @brief 컨트롤 플레인이 만든 백업을 읽는다. 형식이 다르면 거부한다. */
fn parse_control_backup(
    body: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>, bool), String> {
    use onetdns_core::json::Json;

    let root = onetdns_core::json::parse(body)
        .map_err(|error| format!("백업 JSON을 해석하지 못했습니다: {error}"))?;
    let Json::Obj(fields) = &root else {
        return Err("백업 JSON의 최상위 값은 객체여야 합니다".to_string());
    };
    if fields.len() != 6
        || fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "version" | "block" | "allow" | "services" | "refused_domains" | "safe_search"
            )
        })
    {
        return Err("백업 JSON의 항목 구성이 현재 형식과 일치하지 않습니다".to_string());
    }
    if root.get("version").and_then(Json::as_u64) != Some(1) {
        return Err("백업 JSON의 version은 현재 형식 1이어야 합니다".to_string());
    }
    let strings = |key: &str| -> Result<Vec<String>, String> {
        root.get(key)
            .and_then(Json::as_array)
            .ok_or_else(|| format!("백업 JSON의 {key} 항목은 문자열 배열이어야 합니다"))?
            .iter()
            .map(|item| {
                item.as_str()
                    .map(String::from)
                    .ok_or_else(|| format!("백업 JSON의 {key} 항목은 문자열 배열이어야 합니다"))
            })
            .collect()
    };
    let block = strings("block")?;
    let allow = strings("allow")?;
    let services = strings("services")?;
    let refused_domains = strings("refused_domains")?;
    let safe_search = root
        .get("safe_search")
        .and_then(Json::as_bool)
        .ok_or_else(|| "백업 JSON의 safe_search 항목은 불리언이어야 합니다".to_string())?;
    Ok((block, allow, services, refused_domains, safe_search))
}

/** @brief 업스트림 성적을 담아 둘 파일 이름. */
const UPSTREAM_STATS_FILE: &str = "upstream-stats.json";
/** @brief 읽어들일 업스트림 성적 파일 크기 상한. */
const MAX_UPSTREAM_STATS_BYTES: u64 = 16 * 1024 * 1024;

/** @brief 업스트림 성적 파일 경로. */
fn upstream_stats_path(config_path: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    Some(config_path?.parent()?.join(UPSTREAM_STATS_FILE))
}

/** @brief 업스트림 성적을 저장한다. 재시작해도 어느 업스트림이 좋았는지 잊지 않으려는 것이다. */
fn save_upstream_stats(path: &std::path::Path, reports: &[onetdns_forward::UpstreamStatReport]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /** @brief 연달아 실패한 횟수. 계속 실패하면 경고 소리를 줄인다. */
    static CONSECUTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);

    let items: Vec<String> = reports
        .iter()
        .map(|r| {
            format!(
                "{{\"label\":{},\"queries\":{},\"ok\":{},\"fail\":{},\"ewma_ms\":{:.1}}}",
                onetdns_core::json::escape(&r.label),
                r.queries,
                r.ok,
                r.fail,
                r.ewma_ms
            )
        })
        .collect();
    match atomic_write(
        path,
        format!("{{\"version\":1,\"reports\":[{}]}}", items.join(",")).as_bytes(),
    ) {
        Ok(()) => {
            let failures = CONSECUTIVE_FAILURES.swap(0, Ordering::Relaxed);
            if failures > 0 {
                onetdns_core::info!(
                    event = "upstream.stats_save_recovered",
                    path = %path.display(),
                    failed_attempts = failures,
                    "업스트림 DNS 서버 통계 파일 저장이 정상으로 돌아왔습니다"
                );
            }
        }
        Err(error) => {
            let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;

            if failures.is_power_of_two() {
                onetdns_core::warn!(
                    event = "upstream.stats_save_failed",
                    path = %path.display(),
                    consecutive_failures = failures,
                    %error,
                    "업스트림 DNS 서버 통계를 파일에 저장하지 못했습니다"
                );
            }
        }
    }
}

/** @brief 저장된 업스트림 성적을 읽는다. */
fn load_upstream_stats(path: &std::path::Path) -> Vec<onetdns_forward::UpstreamStatReport> {
    let text = match read_text_limited(path, MAX_UPSTREAM_STATS_BYTES) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return vec![],
        Err(error) => {
            onetdns_core::warn!(
                event = "upstream.stats_load_failed",
                path = %path.display(),
                %error,
                "업스트림 DNS 서버 통계 파일을 읽지 못해 이번 실행에서는 새로 집계합니다"
            );
            return vec![];
        }
    };
    let json = match onetdns_core::json::parse(&text) {
        Ok(json) => json,
        Err(error) => {
            onetdns_core::warn!(
                event = "upstream.stats_parse_failed",
                path = %path.display(),
                %error,
                "업스트림 DNS 서버 통계 파일이 손상되어 이번 실행에서는 새로 집계합니다"
            );
            return vec![];
        }
    };
    let onetdns_core::json::Json::Obj(fields) = &json else {
        onetdns_core::warn!(
            event = "upstream.stats_format_invalid",
            path = %path.display(),
            "업스트림 DNS 서버 통계 파일의 최상위 값이 객체가 아니어서 새로 집계합니다"
        );
        return vec![];
    };
    let reports = (|| {
        if fields.len() != 2
            || fields
                .iter()
                .any(|(key, _)| !matches!(key.as_str(), "version" | "reports"))
            || json
                .get("version")
                .and_then(onetdns_core::json::Json::as_u64)
                != Some(1)
        {
            return None;
        }
        let items = json.get("reports")?.as_array()?;
        items
            .iter()
            .map(|item| {
                let onetdns_core::json::Json::Obj(fields) = item else {
                    return None;
                };
                if fields.len() != 5
                    || fields.iter().any(|(key, _)| {
                        !matches!(
                            key.as_str(),
                            "label" | "queries" | "ok" | "fail" | "ewma_ms"
                        )
                    })
                {
                    return None;
                }
                let ewma_ms = item.get("ewma_ms")?.as_num()?;
                if !ewma_ms.is_finite() || ewma_ms < 0.0 {
                    return None;
                }
                Some(onetdns_forward::UpstreamStatReport {
                    label: item.get("label")?.as_str()?.to_string(),
                    queries: item.get("queries")?.as_u64()?,
                    ok: item.get("ok")?.as_u64()?,
                    fail: item.get("fail")?.as_u64()?,
                    ewma_ms,
                })
            })
            .collect::<Option<Vec<_>>>()
    })();
    let Some(reports) = reports else {
        onetdns_core::warn!(
            event = "upstream.stats_format_invalid",
            path = %path.display(),
            "업스트림 DNS 서버 통계 파일이 현재 형식과 일치하지 않아 새로 집계합니다"
        );
        return vec![];
    };
    reports
}

/** @brief 사용자가 넣은 규칙을 고친다. 형식을 확인하고 종류를 구분한다. */
fn mutate_user_rule(
    overlay: &Mutex<(Vec<String>, Vec<String>)>,
    config_path: Option<&std::path::Path>,
    rebuild: &dyn Fn() -> Result<(usize, usize), String>,
    rule: &str,
    tab_allow: bool,
    add: bool,
) -> Result<(usize, usize), String> {
    use onetdns_core::MutexExt;

    let rule = rule.trim();
    if rule.is_empty() {
        return Err("`rule` 항목을 입력해야 합니다".to_string());
    }
    if add {
        onetdns_filter::validate_rule(rule)
            .map_err(|reason| format!("유효하지 않은 규칙: {reason}"))?;
    }
    let into_allow = tab_allow || rule.starts_with("@@");

    let previous = overlay.lock_recover().clone();
    let mut next = previous.clone();
    if add {
        let list = if into_allow { &mut next.1 } else { &mut next.0 };
        if !list.iter().any(|item| item == rule) {
            list.push(rule.to_string());
        }
    } else {
        next.0.retain(|item| item != rule);
        next.1.retain(|item| item != rule);
    }

    let block_changed = previous.0 != next.0;
    let allow_changed = previous.1 != next.1;

    let persisted_change =
        if let Some(path) = config_path.filter(|_| block_changed || allow_changed) {
            let _write_guard = config_write_lock().lock_recover();
            let previous_text = onetdns_core::SecretString::from(
                Config::read_text(path).map_err(|error| error.to_string())?,
            );
            let mut updated_text = previous_text.clone();
            if block_changed {
                updated_text = onetdns_core::SecretString::from(rewrite_config_string_array(
                    &updated_text,
                    "block_rules",
                    &next.0,
                )?);
            }
            if allow_changed {
                updated_text = onetdns_core::SecretString::from(rewrite_config_string_array(
                    &updated_text,
                    "allow_rules",
                    &next.1,
                )?);
            }
            atomic_write(path, updated_text.as_bytes()).map_err(|error| error.to_string())?;
            Some((path.to_path_buf(), previous_text, updated_text))
        } else {
            None
        };
    *overlay.lock_recover() = next;
    match rebuild() {
        Ok(value) => Ok(value),
        Err(error) => {
            *overlay.lock_recover() = previous;
            let error = if let Some((path, previous_text, updated_text)) = persisted_change {
                let rollback = (|| -> Result<(), String> {
                    let _write_guard = config_write_lock().lock_recover();
                    let current = onetdns_core::SecretString::from(
                        Config::read_text(&path)
                            .map_err(|rollback_error| rollback_error.to_string())?,
                    );
                    if current != updated_text {
                        return Err("실행 상태를 갱신하는 동안 설정 파일이 다시 변경되어 자동으로 되돌리지 않았습니다".to_string());
                    }
                    atomic_write(&path, previous_text.as_bytes())
                        .map_err(|rollback_error| rollback_error.to_string())
                })();
                with_rollback_result(
                    error,
                    "규칙 설정을 이전 값으로 되돌리지 못했습니다",
                    rollback,
                )
            } else {
                error
            };
            Err(error)
        }
    }
}

/** @brief 서비스 이름을 그것이 쓰는 도메인 목록으로 편다. */
fn expand_services(services: &[String]) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for svc in services {
        let rules = onetdns_filter::services::service_rules(svc)
            .ok_or_else(|| format!("지원하지 않는 서비스 차단 항목입니다: {svc}"))?;
        out.extend(rules.iter().map(|rule| (*rule).to_string()));
    }
    Ok(out)
}

#[derive(Clone)]
/** @brief 내려받은 목록 하나의 정보. */
struct SubMeta {
    /** @brief 내려받은 곳. */
    url: String,
    /** @brief 목록에 적힌 제목. */
    title: String,
    /** @brief 이 목록에 든 규칙 수. */
    rules: usize,
    /** @brief 마지막으로 내려받은 시각. */
    updated_unix: u64,

    /** @brief 규칙 원문 줄들. 고정한 뒤에는 놓아준다. */
    lines: Arc<[String]>,
}

/** @brief 차단 엔진을 만드는 데 드는 것들. */
struct FilterBuildInputs<'a> {
    /** @brief 차단할 서비스 이름들. */
    blocked_services: &'a [String],
    /** @brief 내려받은 목록들. */
    subscriptions: &'a [SubMeta],
    /** @brief 설정에 적은 차단 규칙. */
    overlay_block: &'a [String],
    /** @brief 설정에 적은 허용 규칙. */
    overlay_allow: &'a [String],
    /** @brief REFUSED로 답할 도메인 접미사. */
    refused_domains: &'a [String],
    /** @brief 영역 형식 목록 글. */
    rpz_texts: &'a [String],
    /** @brief 고정한 결과를 담아 둘 곳. */
    compiled_filter_cache: Option<&'a std::path::Path>,
    /** @brief 내려받은 목록을 담아 둘 곳. */
    subscription_cache_dir: Option<&'a std::path::Path>,
}

/**
 * @brief 지금이 서비스 차단을 멈추는 시간대인지.
 * @details service_schedule의 구간 안에서는 서비스 차단 규칙만 빠진다. 차단 목록과 사용자
 *          규칙은 그대로 건다. 설정 검증을 통과한 구간만 들어오므로 읽지 못하는 구간은 없다.
 */
fn service_blocking_paused(cfg: &Config, now: std::time::SystemTime) -> bool {
    let windows = cfg
        .service_schedule
        .iter()
        .filter_map(|window| {
            let days = days_mask(&window.days);
            let start_min = parse_hhmm(&window.start)?;
            let end_min = parse_hhmm(&window.end)?;
            (days != 0).then_some(native::SchedWindow {
                days,
                start_min,
                end_min,
            })
        })
        .collect();
    native::Schedule { windows }.is_active(now)
}

/**
 * @brief 설정대로 차단 엔진을 만든다.
 * @details 내려받은 목록, 파일, 설정에 적은 규칙을 모두 모아 하나로 고정한다. 고정하면
 *          질의 경로에서 잠금도 할당도 없다.
 */
fn build_filter_engine_for_config(
    config: &Config,
    input: &FilterBuildInputs<'_>,
) -> Result<BlockEngine, String> {
    let blocked_services = input.blocked_services;
    let subscriptions = input.subscriptions;
    let overlay_block = input.overlay_block;
    let overlay_allow = input.overlay_allow;
    let refused_domains = input.refused_domains;
    let rpz_texts = input.rpz_texts;
    let compiled_filter_cache = input.compiled_filter_cache;
    let subscription_cache_dir = input.subscription_cache_dir;
    let services_paused = service_blocking_paused(config, std::time::SystemTime::now());
    let service_rules = if services_paused {
        Vec::new()
    } else {
        expand_services(blocked_services)?
    };
    let fingerprint = compiled_filter_fingerprint(&CompiledFilterInputs {
        blocklists: &config.blocklists,
        allowlists: &config.allowlists,
        service_rules: &service_rules,
        subscriptions,
        subscription_cache_dir,
        overlay_block,
        overlay_allow,
        rewrites: &config.rewrites,
        local_zones: &config.local_zones,
        refused_domains,
        rpz_files: &config.rpz_files,
        rpz_texts,
    });
    let cached =
        compiled_filter_cache.and_then(|path| load_compiled_filter_cache(path, fingerprint));
    let parts = if let Some(parts) = cached {
        onetdns_core::debug!(
            event = "filter.cache_loaded",
            "미리 만들어 둔 차단 목록을 읽었습니다"
        );
        parts
    } else {
        let disk_subscription_files: Vec<Option<PathBuf>> = subscriptions
            .iter()
            .map(|meta| {
                subscription_cache_dir
                    .map(|dir| dir.join(blocklist_cache_key(&meta.url)))
                    .filter(|path| path.is_file())
            })
            .collect();
        let subscription_sources: Vec<onetdns_filter::SubscriptionSource<'_>> = subscriptions
            .iter()
            .zip(&disk_subscription_files)
            .map(|(meta, file)| onetdns_filter::SubscriptionSource {
                name: &meta.url,
                rules: match file {
                    Some(path) => onetdns_filter::SubscriptionRules::File(path),
                    None => onetdns_filter::SubscriptionRules::Lines(&meta.lines),
                },
            })
            .collect();

        for meta in subscriptions {
            let cached = subscription_cache_dir
                .is_some_and(|dir| dir.join(blocklist_cache_key(&meta.url)).is_file());
            if !cached && meta.lines.is_empty() {
                onetdns_core::warn!(
                    event = "filter.subscription_unavailable",
                    url = %meta.url,
                    "구독 캐시 파일이 없어 이 차단 목록의 규칙을 적용하지 못합니다"
                );
            }
        }
        let mut extra_block: Vec<&str> = service_rules.iter().map(String::as_str).collect();
        extra_block.extend(overlay_block.iter().map(String::as_str));
        let overlay_allow_refs: Vec<&str> = overlay_allow.iter().map(String::as_str).collect();
        let mut parts = onetdns_filter::load_parts_with_subscriptions(
            &config.blocklists,
            &config.allowlists,
            &subscription_sources,
            &extra_block,
            &overlay_allow_refs,
        )
        .map_err(|error| error.to_string())?;
        merge_config_filters(
            &mut parts,
            &config.rewrites,
            &config.local_zones,
            refused_domains,
            &config.rpz_files,
        )?;
        for text in rpz_texts {
            onetdns_filter::parse_rpz_text(text, &mut parts);
        }
        if let Some(path) = compiled_filter_cache {
            save_compiled_filter_cache(path, &mut parts, fingerprint);
        }
        parts
    };

    let policies = config
        .clients
        .iter()
        .map(|client| -> Result<_, String> {
            let mut ids = client.client_ids.clone();
            ids.extend(client.mac.iter().map(|mac| mac::normalize_mac(mac)));
            let mut block = client.block.clone();
            if !services_paused {
                block.extend(expand_services(&client.blocked_services)?);
            }
            Ok(onetdns_filter::ClientPolicy::with_options(
                client.ids.clone(),
                ids,
                client.tags.clone(),
                &block,
                &client.allow,
                client.disable_filtering,
                client.safe_search,
            )
            .with_log_flags(client.ignore_querylog, client.ignore_stats))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(BlockEngine::new(parts, map_block(config))
        .with_clients(policies)
        .with_hit_tracking(config.track_rule_hits))
}

/** @brief 고정한 결과가 어떤 입력에서 나왔는지. */
struct CompiledFilterInputs<'a> {
    /** @brief 차단 목록 파일들. */
    blocklists: &'a [PathBuf],
    /** @brief 허용 목록 파일들. */
    allowlists: &'a [PathBuf],
    /** @brief 서비스에서 편 규칙들. */
    service_rules: &'a [String],
    /** @brief 내려받은 목록들. */
    subscriptions: &'a [SubMeta],
    /** @brief 내려받은 목록을 담아 둔 곳. */
    subscription_cache_dir: Option<&'a std::path::Path>,
    /** @brief 설정에 적은 차단 규칙. */
    overlay_block: &'a [String],
    /** @brief 설정에 적은 허용 규칙. */
    overlay_allow: &'a [String],
    /** @brief 재작성 규칙. */
    rewrites: &'a [Rewrite],
    /** @brief 영역 규칙. */
    local_zones: &'a [LocalZone],
    /** @brief REFUSED로 답할 도메인 접미사. */
    refused_domains: &'a [String],
    /** @brief 영역 형식 목록 파일들. */
    rpz_files: &'a [PathBuf],
    /** @brief 영역 형식 목록 글. */
    rpz_texts: &'a [String],
}

/** @brief 입력의 지문. 지문이 같아야 고정해 둔 것을 다시 쓸 수 있다. */
fn compiled_filter_fingerprint(input: &CompiledFilterInputs<'_>) -> [u8; 32] {
    let mut digest = Sha256::new();
    fingerprint_bytes(&mut digest, b"format", b"onetdns-compiled-filter-input-v1");
    fingerprint_files(&mut digest, b"blocklists", input.blocklists);
    fingerprint_files(&mut digest, b"allowlists", input.allowlists);
    fingerprint_strings(&mut digest, b"service-rules", input.service_rules.iter());
    fingerprint_header(
        &mut digest,
        b"subscriptions",
        input.subscriptions.len() as u64,
    );
    for meta in input.subscriptions {
        let cache_path = input
            .subscription_cache_dir
            .map(|dir| dir.join(blocklist_cache_key(&meta.url)))
            .filter(|path| path.is_file());
        if let Some(path) = cache_path {
            fingerprint_files(&mut digest, b"subscription-file", &[path]);
        } else {
            fingerprint_strings(&mut digest, b"subscription-lines", meta.lines.iter());
        }
    }
    fingerprint_strings(&mut digest, b"overlay-block", input.overlay_block.iter());
    fingerprint_strings(&mut digest, b"overlay-allow", input.overlay_allow.iter());

    fingerprint_header(&mut digest, b"rewrites", input.rewrites.len() as u64);
    for rewrite in input.rewrites {
        fingerprint_bytes(&mut digest, b"domain", rewrite.domain.as_bytes());
        fingerprint_bytes(&mut digest, b"answer", rewrite.answer.as_bytes());
    }
    fingerprint_header(&mut digest, b"local-zones", input.local_zones.len() as u64);
    for zone in input.local_zones {
        fingerprint_bytes(&mut digest, b"name", zone.name.as_bytes());
        let kind = match zone.kind {
            LocalZoneKind::Deny => 0,
            LocalZoneKind::Refuse => 1,
            LocalZoneKind::Static => 2,
            LocalZoneKind::Redirect => 3,
            LocalZoneKind::AlwaysNull => 4,
            LocalZoneKind::Transparent => 5,
        };
        fingerprint_bytes(&mut digest, b"kind", &[kind]);
        fingerprint_strings(&mut digest, b"records", zone.records.iter());
    }
    fingerprint_strings(
        &mut digest,
        b"refused-domains",
        input.refused_domains.iter(),
    );
    fingerprint_files(&mut digest, b"rpz-files", input.rpz_files);
    fingerprint_strings(&mut digest, b"rpz-texts", input.rpz_texts.iter());
    digest.finalize().into()
}

/** @brief 고정한 뒤 원본 줄들을 놓아준다. 고정한 것만 있으면 되므로 그만큼 메모리가 준다. */
fn release_subscription_lines(meta: &Mutex<Vec<SubMeta>>, cache_dir: &std::path::Path) {
    for item in meta.lock_recover().iter_mut() {
        if cache_dir.join(blocklist_cache_key(&item.url)).is_file() {
            item.lines = Vec::new().into();
        }
    }
}

/** @brief 지문에 항목 헤더를 넣는다. */
fn fingerprint_header(digest: &mut Sha256, label: &[u8], count: u64) {
    digest.update((label.len() as u64).to_le_bytes());
    digest.update(label);
    digest.update(count.to_le_bytes());
}

/** @brief 지문에 바이트를 넣는다. */
fn fingerprint_bytes(digest: &mut Sha256, label: &[u8], bytes: &[u8]) {
    fingerprint_header(digest, label, bytes.len() as u64);
    digest.update(bytes);
}

/** @brief 지문에 문자열들을 넣는다. */
fn fingerprint_strings<'a>(
    digest: &mut Sha256,
    label: &[u8],
    values: impl ExactSizeIterator<Item = &'a String>,
) {
    fingerprint_header(digest, label, values.len() as u64);
    for value in values {
        fingerprint_bytes(digest, b"value", value.as_bytes());
    }
}

/** @brief 지문에 파일 내용을 넣는다. */
fn fingerprint_files(digest: &mut Sha256, label: &[u8], paths: &[PathBuf]) {
    use std::io::Read;

    /** @brief 읽어들일 목록 파일 크기 상한. */
    const MAX_FILTER_FILE: u64 = 128 * 1024 * 1024;
    fingerprint_header(digest, label, paths.len() as u64);
    for path in paths {
        fingerprint_bytes(digest, b"path", path.to_string_lossy().as_bytes());
        let Ok(file) = std::fs::File::open(path) else {
            fingerprint_bytes(digest, b"file-status", b"unreadable");
            continue;
        };
        let mut reader = file.take(MAX_FILTER_FILE + 1);
        let mut content = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        let status = loop {
            match reader.read(&mut buffer) {
                Ok(0) => break b"ok".as_slice(),
                Ok(read) => {
                    total += read as u64;
                    if total > MAX_FILTER_FILE {
                        break b"oversize".as_slice();
                    }
                    content.update(&buffer[..read]);
                }
                Err(_) => break b"unreadable".as_slice(),
            }
        };
        fingerprint_bytes(digest, b"file-status", status);
        if status == b"ok" {
            digest.update(total.to_le_bytes());
            digest.update(content.finalize());
        }
    }
}

/** @brief 고정해 둔 것을 읽는다. 지문이 다르면 쓰지 않는다. */
fn load_compiled_filter_cache(
    path: &std::path::Path,
    fingerprint: [u8; 32],
) -> Option<EngineParts> {
    use std::io::Read;

    let metadata = std::fs::metadata(path).ok()?;
    if metadata.len() > onetdns_filter::MAX_CACHE_BYTES as u64 {
        onetdns_core::warn!(event = "filter.cache_evicted_oversize", path = %path.display(), "크기 제한을 넘은 컴파일된 필터 캐시를 삭제했습니다");
        return None;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(metadata.len() as usize).ok()?;
    let mut file = std::fs::File::open(path)
        .ok()?
        .take(onetdns_filter::MAX_CACHE_BYTES as u64 + 1);
    file.read_to_end(&mut bytes).ok()?;
    if bytes.len() > onetdns_filter::MAX_CACHE_BYTES {
        return None;
    }
    match onetdns_filter::decode_engine_cache(&bytes, fingerprint) {
        Ok(parts) => Some(parts),
        Err(error) => {
            onetdns_core::debug!(event = "filter.cache_unusable", path = %path.display(), %error, "컴파일된 필터 캐시를 사용할 수 없어 원본 규칙을 다시 처리합니다");
            None
        }
    }
}

/** @brief 고정한 것을 저장한다. 전체를 메모리에 담지 않고 흘려 쓴 뒤 교체한다. 다음 시작이 훨씬 빠르다. */
fn save_compiled_filter_cache(
    path: &std::path::Path,
    parts: &mut EngineParts,
    fingerprint: [u8; 32],
) {
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            onetdns_core::warn!(event = "filter.cache_dir_failed", path = %path.display(), %error, "컴파일된 필터 캐시 디렉터리를 만들지 못했습니다");
            return;
        }
    }
    if let Err(error) = atomic_write_with(path, false, |file| {
        onetdns_filter::write_engine_cache(parts, fingerprint, file).map_err(std::io::Error::other)
    }) {
        onetdns_core::warn!(event = "filter.cache_save_failed", path = %path.display(), %error, "컴파일된 필터 캐시를 저장하지 못했습니다");
    }
}

/** @brief 목록 본문에서 제목을 찾는다. */
fn parse_list_title(body: &str) -> String {
    for raw in body.lines().take(64) {
        let t = raw.trim();
        let stripped = t
            .strip_prefix('!')
            .or_else(|| t.strip_prefix('#'))
            .map(str::trim);
        if let Some(rest) = stripped {
            if let Some(v) = rest
                .strip_prefix("Title:")
                .or_else(|| rest.strip_prefix("title:"))
            {
                let v = v.trim();
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

/** @brief 목록에 든 규칙 수. */
fn count_list_rules(body: &str) -> usize {
    body.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('#')
        })
        .count()
}

/** @brief 목록 대신 오류 문서를 받은 것 같은지. 그대로 규칙으로 읽으면 엉뚱한 것이 차단된다. */
fn looks_like_error_document(body: &str) -> bool {
    let prefix = body
        .trim_start()
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.contains("<head>")
        || prefix.contains("<body>")
        || body.as_bytes().contains(&0)
}

/** @brief 영역 형식 목록에 든 규칙 수. */
fn likely_rpz_rule_count(body: &str) -> usize {
    body.lines()
        .filter(|raw| {
            let line = raw.trim();
            if line.is_empty()
                || line.starts_with(';')
                || line.starts_with('$')
                || line.starts_with('@')
            {
                return false;
            }
            line.split_whitespace().any(|token| {
                matches!(
                    token.to_ascii_uppercase().as_str(),
                    "CNAME" | "A" | "AAAA" | "PTR" | "TXT"
                )
            })
        })
        .count()
}

/** @brief 내려받을 목록 크기 상한. */
const BLOCKLIST_MAX_RESPONSE: u64 = 128 * 1024 * 1024;
/** @brief 읽어들일 인증 기관 파일 크기 상한. */
const LOCAL_CA_MAX_BYTES: u64 = 4 * 1024 * 1024;
/** @brief 읽어들일 키 파일 크기 상한. */
const LOCAL_KEY_MAX_BYTES: u64 = 1024 * 1024;
/** @brief 읽어들일 상태 파일 크기 상한. */
const LOCAL_STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/** @brief 읽어들일 정책 플러그인 크기 상한. */
const WASM_MODULE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/** @brief 이름 해석 결과를 담아 둘 개수. */
const HOST_RESOLVER_CACHE_CAPACITY: usize = 512;
/** @brief 이름 해석 결과를 담아 둘 최대 기간. */
const HOST_RESOLVER_CACHE_TTL_MAX_SECS: u64 = 300;
/** @brief 이름 해석 실패를 기억할 기간. */
const HOST_RESOLVER_FAILURE_CACHE_TTL: Duration = Duration::from_secs(10);

/** @brief 크기 상한을 걸어 파일을 읽는다. */
fn read_bytes_limited(path: &std::path::Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "파일 크기가 허용 한도를 넘었습니다",
        ));
    }
    Ok(bytes)
}

/** @brief 크기 상한을 걸어 파일을 글자로 읽는다. */
fn read_text_limited(path: &std::path::Path, max_bytes: u64) -> std::io::Result<String> {
    let bytes = read_bytes_limited(path, max_bytes)?;
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/** @brief 목록을 내려받을 때 이름을 풀 서버들. 자기 자신은 쓰지 않는다. 아직 서빙 전일 수 있다. */
fn blocklist_bootstrap(cfg: &Config) -> Vec<IpAddr> {
    let mut addresses = if cfg.bootstrap.is_empty() {
        cfg.upstreams.clone()
    } else {
        cfg.bootstrap.clone()
    };
    addresses.retain(|address| {
        !upstream::is_local_ip(*address) && !address.is_unspecified() && !address.is_multicast()
    });
    addresses.sort();
    addresses.dedup();
    addresses
}

/** @brief 목록을 내려받을 때 쓸 이름 해석 방법. */
fn blocklist_host_resolver(cfg: &Config) -> http::HostResolver {
    let bootstrap = blocklist_bootstrap(cfg);
    let recursor = Arc::new(
        new_recursor(recursor_roots(cfg), Duration::from_secs(8))
            .with_recursive_cache_ttl_max(cfg.max_ttl as u32),
    );
    let success_ttl_cap_secs = cfg.max_ttl.min(HOST_RESOLVER_CACHE_TTL_MAX_SECS);
    let cache = Arc::new(Mutex::new(onetdns_core::LruMap::<
        String,
        (std::time::Instant, Duration, Result<Vec<IpAddr>, String>),
    >::new(HOST_RESOLVER_CACHE_CAPACITY)));

    Arc::new(move |host: &str, timeout: Duration| {
        let cache_key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some((stored_at, ttl, result)) = cache.lock_recover().get(&cache_key).cloned() {
            if stored_at.elapsed() < ttl {
                return result;
            }
        }

        let resolved = if !bootstrap.is_empty() {
            onetdns_forward::resolve_via_bootstrap(host, &bootstrap, timeout)
                .map(|(ip, ttl)| (vec![ip], ttl))
                .ok_or_else(|| format!("호스트명 확인용 DNS 서버로 주소를 찾지 못했습니다: {host}"))
        } else {
            let name = onetdns_proto::Name::from_str(host)
                .map_err(|_| format!("다운로드 주소의 호스트 이름이 올바르지 않습니다: {host}"));
            name.and_then(|name| {
                let mut addresses = Vec::new();
                let mut ttl: Option<u32> = None;
                for qtype in [
                    onetdns_proto::RecordType::A,
                    onetdns_proto::RecordType::AAAA,
                ] {
                    let Ok(response) = recursor.resolve(&name, qtype) else {
                        continue;
                    };
                    for answer in response.answers {
                        ttl = Some(ttl.map_or(answer.ttl, |current| current.min(answer.ttl)));
                        match answer.rdata {
                            onetdns_proto::RData::A(ip) => addresses.push(IpAddr::V4(ip)),
                            onetdns_proto::RData::Aaaa(ip) => addresses.push(IpAddr::V6(ip)),
                            _ => {}
                        }
                    }
                }
                addresses.sort();
                addresses.dedup();
                if addresses.is_empty() {
                    Err(format!(
                        "내장 재귀 리졸버로 호스트 이름을 찾지 못했습니다: {host}"
                    ))
                } else {
                    Ok((addresses, ttl.unwrap_or(0)))
                }
            })
        };

        let (ttl, result) = match resolved {
            Ok((addresses, authoritative_ttl)) => (
                Duration::from_secs(u64::from(authoritative_ttl).min(success_ttl_cap_secs)),
                Ok(addresses),
            ),
            Err(error) => (HOST_RESOLVER_FAILURE_CACHE_TTL, Err(error)),
        };

        if !ttl.is_zero() {
            cache
                .lock_recover()
                .put(cache_key, (std::time::Instant::now(), ttl, result.clone()));
        }
        result
    })
}

/** @brief 목록 하나를 내려받는다. */
fn fetch_blocklist(
    url: &str,
    resolver: &http::HostResolver,
    cache_dir: Option<&std::path::Path>,
) -> Result<SubMeta, String> {
    let resp = http::get(url)
        .timeout(Duration::from_secs(120))
        .max_response(BLOCKLIST_MAX_RESPONSE)
        .resolver(resolver.clone())
        .deny_private_targets()
        .call()
        .map_err(|error| format!("차단 목록을 내려받지 못했습니다: {error}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!(
            "차단 목록 서버가 오류 상태를 반환했습니다: {}",
            resp.status
        ));
    }
    let body = resp
        .into_string()
        .map_err(|error| format!("차단 목록 응답을 읽지 못했습니다: {error}"))?;
    if body.trim().is_empty() || looks_like_error_document(&body) {
        return Err("블록리스트 본문이 비어 있거나 HTML 오류 문서입니다".to_string());
    }
    let rules = count_list_rules(&body);
    if rules == 0 {
        return Err("블록리스트에서 유효 규칙을 찾지 못했습니다".to_string());
    }
    onetdns_core::debug!(event = "filter.subscription_downloaded", %url, lines = rules, "차단 목록을 내려받았습니다");
    let updated_unix = unix_now();
    save_blocklist_cache_text(url, updated_unix, &body, cache_dir)?;

    let lines: Vec<String> = if cache_dir.is_some() {
        Vec::new()
    } else {
        body.lines().map(str::to_string).collect()
    };
    Ok(SubMeta {
        url: url.to_string(),
        title: parse_list_title(&body),
        rules,
        updated_unix,
        lines: lines.into(),
    })
}

/** @brief 이 주소의 목록을 담아 둘 파일 이름. */
fn blocklist_cache_key(url: &str) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in url.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}.list")
}

/** @brief 내려받은 목록을 담아 둔다. */
fn save_blocklist_cache_text(
    url: &str,
    updated_unix: u64,
    text: &str,
    dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("차단 목록 캐시 디렉터리를 만들지 못했습니다: {e}"))?;
    let path = dir.join(blocklist_cache_key(url));
    let mut body = format!("# onetdns-url:{url}\n# onetdns-updated:{updated_unix}\n");
    body.reserve(text.len() + 1);
    for line in text.lines() {
        body.push_str(line);
        body.push('\n');
    }

    atomic_write(&path, body.as_bytes())
        .map_err(|e| format!("차단 목록 캐시를 저장하지 못했습니다({url}): {e}"))
}

/** @brief 담아 둔 목록을 읽는다. 못 받아도 시작할 수 있게 하려는 것이다. */
fn load_blocklist_cache(urls: &[String], dir: Option<&std::path::Path>) -> Vec<SubMeta> {
    let Some(dir) = dir else {
        return Vec::new();
    };
    urls.iter()
        .filter_map(|url| {
            let text =
                read_text_limited(&dir.join(blocklist_cache_key(url)), BLOCKLIST_MAX_RESPONSE)
                    .ok()?;
            let mut parts = text.splitn(3, '\n');
            let stored_url = parts
                .next()?
                .trim_end_matches('\r')
                .strip_prefix("# onetdns-url:")?;
            if stored_url != url {
                return None;
            }
            let updated_unix = parts
                .next()
                .map(|line| line.trim_end_matches('\r'))
                .and_then(|v| v.strip_prefix("# onetdns-updated:"))
                .and_then(|v| v.parse().ok())?;
            let body = parts.next()?;
            let rules = count_list_rules(body);
            let title = parse_list_title(body);

            (rules > 0).then(|| SubMeta {
                url: url.clone(),
                title,
                rules,
                updated_unix,
                lines: Vec::new().into(),
            })
        })
        .collect()
}

/** @brief 목록들을 내려받고 그 정보를 모은다. */
fn fetch_blocklists_meta(
    urls: &[String],
    resolver: &http::HostResolver,
    previous: &[SubMeta],
    cache_dir: Option<&std::path::Path>,
) -> Vec<SubMeta> {
    let previous_by_url: std::collections::HashMap<&str, &SubMeta> = previous
        .iter()
        .map(|item| (item.url.as_str(), item))
        .collect();
    let mut meta = Vec::new();
    for url in urls {
        match fetch_blocklist(url, resolver, cache_dir) {
            Ok(item) => meta.push(item),
            Err(error) => {
                if let Some(old) = previous_by_url.get(url.as_str()) {
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed_kept", %url, %error, retained_rules = old.rules, "차단 목록을 갱신하지 못해 이전 목록을 유지합니다");
                    meta.push((*old).clone());
                } else {
                    onetdns_core::warn!(event = "filter.subscription_refresh_failed", %url, %error, "차단 목록을 갱신하지 못했습니다");
                    meta.push(SubMeta {
                        url: url.clone(),
                        title: String::new(),
                        rules: 0,
                        updated_unix: 0,
                        lines: Vec::new().into(),
                    });
                }
            }
        }
    }
    meta
}

/** @brief 이 주소의 영역 형식 목록을 담아 둘 파일 이름. */
fn rpz_cache_key(url: &str) -> String {
    format!("{}.rpz", blocklist_cache_key(url).trim_end_matches(".list"))
}

/** @brief 내려받은 영역 형식 목록을 담아 둔다. */
fn save_rpz_cache(url: &str, body: &str, dir: Option<&std::path::Path>) -> Result<(), String> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("RPZ 캐시 디렉터리를 만들지 못했습니다: {error}"))?;
    let mut cached = format!(
        "# onetdns-rpz-url:{url}\n# onetdns-updated:{}\n",
        unix_now()
    );
    cached.push_str(body);
    if !cached.ends_with('\n') {
        cached.push('\n');
    }
    atomic_write(&dir.join(rpz_cache_key(url)), cached.as_bytes())
        .map_err(|error| format!("RPZ 캐시를 저장하지 못했습니다({url}): {error}"))
}

/** @brief 담아 둔 영역 형식 목록을 읽는다. */
fn load_rpz_cache(urls: &[String], dir: Option<&std::path::Path>) -> Vec<String> {
    let Some(dir) = dir else {
        return vec![String::new(); urls.len()];
    };
    urls.iter()
        .map(|url| {
            let Ok(text) = read_text_limited(&dir.join(rpz_cache_key(url)), BLOCKLIST_MAX_RESPONSE)
            else {
                return String::new();
            };
            let mut lines = text.lines();
            let Some(stored_url) = lines
                .next()
                .and_then(|line| line.strip_prefix("# onetdns-rpz-url:"))
            else {
                return String::new();
            };
            if stored_url != url {
                return String::new();
            }
            let updated = lines
                .next()
                .and_then(|line| line.strip_prefix("# onetdns-updated:"))
                .and_then(|value| value.parse::<u64>().ok());
            if updated.is_none() {
                return String::new();
            }
            let body = lines.collect::<Vec<_>>().join("\n");
            if body.trim().is_empty()
                || looks_like_error_document(&body)
                || likely_rpz_rule_count(&body) == 0
            {
                String::new()
            } else {
                body
            }
        })
        .collect()
}

/** @brief 영역 형식 목록들을 내려받는다. */
/**
 * @brief 이전에 받아 둔 RPZ 본문을 새 URL 목록 순서로 다시 정렬한다.
 * @details 받아 둔 본문은 URL 목록과 같은 순서로 놓인다. 목록 가운데 하나를 빼면 뒤쪽이
 *          당겨지므로, 위치로 짝지으면 다운로드에 실패한 URL 위치에 다른 목록의 규칙이 들어간다.
 * @param old_urls 받아 둔 본문이 따르는 URL 목록.
 * @param old_texts 받아 둔 본문.
 * @param urls 새 URL 목록.
 * @return urls와 같은 길이. 받아 둔 적 없는 URL 슬롯은 빈 문자열이다.
 */
fn rpz_texts_by_url(old_urls: &[String], old_texts: &[String], urls: &[String]) -> Vec<String> {
    urls.iter()
        .map(|url| {
            old_urls
                .iter()
                .position(|old| old == url)
                .and_then(|index| old_texts.get(index))
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

fn fetch_rpz_texts(
    urls: &[String],
    resolver: &http::HostResolver,
    previous: &[String],
    cache_dir: Option<&std::path::Path>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(urls.len());
    for (index, url) in urls.iter().enumerate() {
        let fetched = http::get(url)
            .timeout(Duration::from_secs(120))
            .max_response(BLOCKLIST_MAX_RESPONSE)
            .resolver(resolver.clone())
            .deny_private_targets()
            .call()
            .and_then(|resp| {
                if !(200..300).contains(&resp.status) {
                    return Err(http::HttpError::Protocol(format!(
                        "HTTP 상태 {}",
                        resp.status
                    )));
                }
                resp.into_string()
            });
        match fetched {
            Ok(body)
                if !body.trim().is_empty()
                    && !looks_like_error_document(&body)
                    && likely_rpz_rule_count(&body) > 0 =>
            {
                onetdns_core::debug!(event = "filter.rpz_downloaded", %url, bytes = body.len(), "RPZ 규칙을 내려받았습니다");
                if let Err(error) = save_rpz_cache(url, &body, cache_dir) {
                    onetdns_core::warn!(event = "filter.rpz_cache_save_failed", %url, %error, "RPZ 캐시 파일을 저장하지 못했습니다");
                }
                out.push(body);
            }
            Ok(_) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_empty_kept", %url, "내려받은 RPZ 데이터에 사용할 수 있는 규칙이 없어 이전 규칙을 유지합니다");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_empty", %url, "내려받은 RPZ 데이터에 사용할 수 있는 규칙이 없습니다");
                    out.push(String::new());
                }
            }
            Err(error) => {
                if let Some(old) = previous.get(index) {
                    onetdns_core::warn!(event = "filter.rpz_refresh_failed_kept", %url, %error, "RPZ 규칙을 갱신하지 못해 이전 규칙을 유지합니다");
                    out.push(old.clone());
                } else {
                    onetdns_core::warn!(event = "filter.rpz_download_failed", %url, %error, "RPZ 규칙을 내려받지 못했습니다");
                    out.push(String::new());
                }
            }
        }
    }
    out
}

/** @brief 설정에 적은 규칙을 엔진에 넣는다. */
fn merge_config_filters(
    parts: &mut EngineParts,
    rewrites: &[Rewrite],
    local_zones: &[LocalZone],
    refused_domains: &[String],
    rpz_files: &[PathBuf],
) -> Result<(), String> {
    for h in refused_domains {
        parts.refuse.add_suffix(h);
    }
    for (index, rw) in rewrites.iter().enumerate() {
        let target = parse_rewrite_answer(&rw.answer).ok_or_else(|| {
            format!("rewrites[{index}].answer에 올바른 IP 주소 또는 DNS 이름이 필요합니다")
        })?;
        add_rewrite(parts, &rw.domain, target)
            .map_err(|error| format!("rewrites[{index}].domain: {error}"))?;
    }
    for (index, lz) in local_zones.iter().enumerate() {
        apply_local_zone(parts, lz).map_err(|error| format!("local_zones[{index}]: {error}"))?;
    }
    for f in rpz_files {
        let text = read_text_limited(f, BLOCKLIST_MAX_RESPONSE)
            .map_err(|error| format!("RPZ 파일을 읽지 못했습니다({}): {error}", f.display()))?;
        onetdns_filter::parse_rpz_text(&text, parts);
    }
    Ok(())
}

/** @brief 재작성이 답할 값을 읽는다. */
fn parse_rewrite_answer(answer: &str) -> Option<RewriteTarget> {
    let a = answer.trim();
    if let Ok(ip) = a.parse::<IpAddr>() {
        Some(RewriteTarget::ip(ip))
    } else {
        onetdns_proto::Name::from_str(a)
            .ok()
            .map(RewriteTarget::Cname)
    }
}

/** @brief 재작성 규칙 하나를 넣는다. */
fn add_rewrite(parts: &mut EngineParts, domain: &str, target: RewriteTarget) -> Result<(), String> {
    let domain = domain.trim();
    let parsed = domain.strip_prefix("*.").unwrap_or(domain);
    if parsed.is_empty() || parsed.contains('*') || onetdns_proto::Name::from_str(parsed).is_err() {
        return Err("올바른 정확 일치 이름 또는 `*.하위영역`이 아닙니다".to_string());
    }
    if domain.starts_with("*.") {
        parts.rewrites.add_suffix(domain, target);
    } else {
        parts.rewrites.add_exact(domain, target);
    }
    Ok(())
}

/** @brief 설정에서 읽은 로컬 영역 답을 필터가 쓰는 형태로 바꾼다. */
fn local_answer_target(answer: &onetdns_config::LocalAnswer) -> Result<RewriteTarget, String> {
    Ok(match answer {
        onetdns_config::LocalAnswer::Addresses(ips) => RewriteTarget::Records(
            ips.iter()
                .map(|ip| match ip {
                    IpAddr::V4(v4) => onetdns_proto::RData::A(*v4),
                    IpAddr::V6(v6) => onetdns_proto::RData::Aaaa(*v6),
                })
                .collect(),
        ),
        onetdns_config::LocalAnswer::Alias(name) => RewriteTarget::Cname(
            onetdns_proto::Name::from_str(name)
                .map_err(|_| format!("CNAME 대상 '{name}'이 올바른 DNS 이름이 아닙니다"))?,
        ),
    })
}

/**
 * @brief 설정에 적은 영역 규칙을 엔진에 넣는다.
 * @details 영역은 엔진의 로컬 영역 집합에 따로 들어간다. 한 이름에는 가장 구체적인 영역만
 *          걸리므로 transparent 영역은 둘러싼 로컬 영역의 처분만 거두고, 차단 목록과 사용자
 *          규칙에는 손대지 않는다.
 */
fn apply_local_zone(parts: &mut EngineParts, lz: &LocalZone) -> Result<(), String> {
    if onetdns_proto::Name::from_str(lz.name.trim()).is_err() {
        return Err("name에 올바른 DNS 영역 이름이 필요합니다".to_string());
    }
    let action = match lz.kind {
        LocalZoneKind::Deny => LocalZoneAction::Deny,
        LocalZoneKind::Refuse => LocalZoneAction::Refuse,
        LocalZoneKind::Transparent => LocalZoneAction::Transparent,
        LocalZoneKind::AlwaysNull => LocalZoneAction::Rewrite(RewriteTarget::Records(vec![
            onetdns_proto::RData::A(Ipv4Addr::UNSPECIFIED),
            onetdns_proto::RData::Aaaa(Ipv6Addr::UNSPECIFIED),
        ])),
        LocalZoneKind::Redirect => {
            let answers = lz.answers()?;
            let [(_, answer)] = answers.as_slice() else {
                return Err("redirect 영역에는 영역 이름 하나의 답만 있어야 합니다".to_string());
            };
            LocalZoneAction::Rewrite(local_answer_target(answer)?)
        }
        LocalZoneKind::Static => {
            let mut data = StaticZone::new(&lz.name);
            for (name, answer) in lz.answers()? {
                data.insert(&name, local_answer_target(&answer)?)?;
            }
            LocalZoneAction::Static(data)
        }
    };
    parts.local_zones.insert(&lz.name, action)
}

#[derive(Clone, Copy, PartialEq, Eq)]
/**
 * @brief 영역을 올리기 전에 ZONEMD를 어떻게 볼지.
 * @details 파일, 디렉터리, 외부 저장소, 영역 전송 어느 길로 들어온 영역이든 같은 방침을 쓴다.
 */
struct ZonemdPolicy {
    /** @brief ZONEMD를 검증할지. */
    check: bool,
    /** @brief ZONEMD가 없는 영역을 거부할지. */
    reject_absence: bool,
}

impl ZonemdPolicy {
    /** @brief 설정에서 방침을 읽는다. */
    fn of(cfg: &Config) -> Self {
        ZonemdPolicy {
            check: cfg.zonemd_check,
            reject_absence: cfg.zonemd_reject_absence,
        }
    }
}

/** @brief 영역이 제 안에 적어 둔 요약값과 맞는지. 맞지 않으면 오는 길에 바뀐 것이다. */
fn zonemd_ok(zone: &onetdns_authority::Zone, policy: ZonemdPolicy) -> bool {
    if !policy.check {
        return true;
    }
    let records = zone.axfr_records();
    let serial = records
        .iter()
        .find_map(|r| match &r.rdata {
            onetdns_proto::RData::Soa(s) => Some(s.serial),
            _ => None,
        })
        .unwrap_or(0);
    let origin = zone.origin().to_ascii_lower();
    match onetdns_dnssec::verify_zonemd(&records, zone.origin(), serial) {
        onetdns_dnssec::ZonemdResult::Verified => {
            onetdns_core::info!(event = "authority.zonemd_verified", origin = %origin, "ZONEMD 검증을 통과했습니다");
            true
        }
        onetdns_dnssec::ZonemdResult::Absent => {
            if policy.reject_absence {
                onetdns_core::error!(event = "authority.zonemd_missing_rejected", origin = %origin, "ZONEMD 레코드가 없어 설정에 따라 DNS 영역을 거부했습니다");
                false
            } else {
                onetdns_core::warn!(event = "authority.zonemd_missing_allowed", origin = %origin, "ZONEMD 레코드가 없지만 설정에 따라 DNS 영역을 허용했습니다");
                true
            }
        }
        other => {
            onetdns_core::error!(event = "authority.zonemd_failed", origin = %origin, result = ?other, "ZONEMD 검증에 실패해 DNS 영역을 제공하지 않습니다");
            false
        }
    }
}

/** @brief 설정대로 권한 영역들을 올린다. */
fn build_zone_store(
    cfg: &Config,
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    zone_signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
) -> Result<onetdns_authority::ZoneStore, String> {
    let mut store = onetdns_authority::ZoneStore::new();
    for z in &cfg.zones {
        let path = z
            .file
            .as_ref()
            .ok_or_else(|| format!("DNS 영역 '{}'에 file 설정이 없습니다", z.origin))?;
        let text = onetdns_authority::source::read_zone_text(path).map_err(|error| {
            format!(
                "DNS 영역 파일 '{}'을 읽지 못했습니다: {error}",
                path.display()
            )
        })?;
        let origin = if z.origin.is_empty() { "." } else { &z.origin };
        let zone = onetdns_authority::parse_zone(&text, origin).map_err(|error| {
            format!(
                "DNS 영역 파일 '{}'을 해석하지 못했습니다: {error}",
                path.display()
            )
        })?;
        let zone = if z.dnssec_sign {
            let signer = zone_signers
                .iter()
                .find(|(signer_origin, _)| signer_origin.eq_ignore_case(zone.origin()))
                .map(|(_, signer)| signer)
                .ok_or_else(|| {
                    format!("DNS 영역 '{}'의 서명 키를 준비하지 못했습니다", z.origin)
                })?;
            sign_authority_zone(zone, signer)
                .ok_or_else(|| format!("DNS 영역 '{}'을 서명하지 못했습니다", z.origin))?
        } else {
            zone
        };
        if !zonemd_ok(&zone, ZonemdPolicy::of(cfg)) {
            return Err(format!(
                "DNS 영역 '{}'의 ZONEMD 검증에 실패했습니다",
                z.origin
            ));
        }
        onetdns_core::info!(event = "authority.zones_loaded_config", origin = %zone.origin().to_ascii_lower(), "설정 파일에서 권한 DNS 영역을 불러왔습니다");
        store.add(zone);
    }

    if let Some(dir) = &cfg.zones_dir {
        let src = onetdns_authority::DirZoneSource::new(dir.clone());
        match onetdns_authority::ZoneSource::load(&src) {
            Ok(dir_store) => {
                for z in dir_store.zones() {
                    if zonemd_ok(z, ZonemdPolicy::of(cfg)) {
                        onetdns_core::info!(event = "authority.zones_loaded_dir", origin = %z.origin().to_ascii_lower(), dir = %dir.display(), "디렉터리에서 권한 DNS 영역을 불러왔습니다");
                        store.add(z.clone());
                    }
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.zone_dir_read_failed", dir = %dir.display(), error = %e, "DNS 영역 디렉터리를 읽지 못했습니다")
            }
        }
    }

    if let Some(db) = &cfg.zones_db {
        let src =
            onetdns_authority::SqliteZoneSource::with_table(db.clone(), cfg.zones_db_table.clone());
        match onetdns_authority::ZoneSource::load(&src) {
            Ok(db_store) => {
                for z in db_store.zones() {
                    if zonemd_ok(z, ZonemdPolicy::of(cfg)) {
                        onetdns_core::info!(event = "authority.zones_loaded_sqlite", origin = %z.origin().to_ascii_lower(), db = %db.display(), "SQLite에서 권한 DNS 영역을 불러왔습니다");
                        store.add(z.clone());
                    }
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.sqlite_read_failed", db = %db.display(), error = %e, "SQLite에서 DNS 영역을 읽지 못했습니다")
            }
        }
    }

    if let Some(ep) = &cfg.zones_etcd {
        if let Some(src) = build_etcd_source(cfg) {
            match onetdns_authority::ZoneSource::load(&src) {
                Ok(etcd_store) => {
                    for z in etcd_store
                        .zones()
                        .iter()
                        .filter(|z| zonemd_ok(z, ZonemdPolicy::of(cfg)))
                    {
                        onetdns_core::info!(event = "authority.zones_loaded_etcd", origin = %z.origin().to_ascii_lower(), endpoint = %ep, "etcd에서 권한 DNS 영역을 불러왔습니다");
                        store.add(z.clone());
                    }
                }
                Err(e) => {
                    onetdns_core::error!(event = "authority.etcd_read_failed", endpoint = %ep, error = %e, "etcd에서 DNS 영역을 읽지 못했습니다. 다음 확인 주기에 다시 시도합니다")
                }
            }
        }
    }

    let sql_table = cfg.zones_sql_table.clone();
    let mut sql_sources: Vec<(String, Box<dyn onetdns_authority::ZoneSource>)> = Vec::new();
    if let Some(url) = &cfg.zones_postgres {
        if let Some(s) = onetdns_authority::PostgresZoneSource::from_url(url, &sql_table) {
            sql_sources.push((
                format!("postgres({})", onetdns_config::redact_url_credentials(url)),
                Box::new(s),
            ));
        }
    }
    if let Some(url) = &cfg.zones_mysql {
        if let Some(s) = onetdns_authority::MysqlZoneSource::from_url(url, &sql_table) {
            sql_sources.push((
                format!("mysql({})", onetdns_config::redact_url_credentials(url)),
                Box::new(s),
            ));
        }
    }
    if let Some(path) = &cfg.zones_lmdb {
        sql_sources.push((
            format!("lmdb({})", path.display()),
            Box::new(onetdns_authority::LmdbZoneSource::new(path.clone())),
        ));
    }
    for (label, src) in &sql_sources {
        match onetdns_authority::ZoneSource::load(src.as_ref()) {
            Ok(db_store) => {
                for z in db_store
                    .zones()
                    .iter()
                    .filter(|z| zonemd_ok(z, ZonemdPolicy::of(cfg)))
                {
                    onetdns_core::info!(event = "authority.zones_loaded_db", origin = %z.origin().to_ascii_lower(), backend = %label, "데이터베이스에서 권한 DNS 영역을 불러왔습니다");
                    store.add(z.clone());
                }
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.db_read_failed", backend = %label, error = %e, "데이터베이스의 DNS 영역을 읽지 못했습니다. 다음 확인 주기에 다시 시도합니다")
            }
        }
    }

    for s in &cfg.secondary {
        let Some(primary) = s.primary else {
            onetdns_core::warn!(event = "authority.secondary_no_primary", origin = %s.origin, "보조 영역에 주 서버가 없어 해당 영역을 제외했습니다");
            continue;
        };
        let origin = match onetdns_proto::Name::from_str(&s.origin) {
            Ok(n) => n,
            Err(_) => {
                onetdns_core::error!(event = "authority.secondary_name_invalid", origin = %s.origin, "보조 DNS 영역 이름의 형식이 잘못되었습니다");
                continue;
            }
        };
        let key = tsig_for_secondary(tsig_keys, &s.tsig_key);
        if s.tsig_key.is_some() && key.is_none() {
            onetdns_core::error!(event = "authority.secondary_tsig_missing", origin = %s.origin, "보조 영역에서 지정한 TSIG 키를 찾지 못해 해당 영역을 제외했습니다");
            continue;
        }
        if let Some(zone) = load_secondary_cache(s, cfg, &origin) {
            onetdns_core::info!(event = "authority.secondary_cache_path_missing", origin = %s.origin, file = %s.file.as_ref().expect("보조 DNS 영역 캐시 경로가 설정되어 있어야 합니다").display(), "저장된 보조 DNS 영역을 복구하고 별도 갱신 작업을 예약했습니다");
            store.add(zone);
            continue;
        }
        onetdns_core::info!(event = "authority.secondary_initial_transfer_scheduled", origin = %s.origin, %primary, "보조 DNS 영역의 최초 전송을 비차단 갱신 작업에 예약했습니다");
    }

    if let Some(cat) = &cfg.catalog_serve {
        match onetdns_proto::Name::from_str(cat) {
            Ok(cat_origin) => {
                let cat_lc = cat_origin.to_ascii_lower();
                let members: Vec<String> = store
                    .zones()
                    .iter()
                    .map(|z| z.origin().to_ascii_lower())
                    .filter(|o| o != &cat_lc)
                    .collect();
                match build_catalog_zone(&cat_origin, &members, catalog_serial(unix_now())) {
                    Ok(z) => {
                        onetdns_core::info!(event = "authority.catalog_published", catalog = %cat, members = members.len(), "카탈로그 DNS 영역을 게시했습니다");
                        store.add(z);
                    }
                    Err(e) => {
                        onetdns_core::error!(event = "authority.catalog_build_failed", catalog = %cat, error = %e, "카탈로그 DNS 영역을 만들지 못했습니다")
                    }
                }
            }
            Err(_) => {
                onetdns_core::error!(event = "authority.catalog_name_invalid", catalog = %cat, "제공할 카탈로그 영역 이름의 형식이 잘못되었습니다")
            }
        }
    }
    Ok(store)
}

/** @brief 받아 둔 하위 영역을 읽는다. 못 받아도 시작할 수 있게 하려는 것이다. */
fn load_secondary_cache(
    config: &onetdns_config::SecondaryZone,
    global: &Config,
    origin: &onetdns_proto::Name,
) -> Option<onetdns_authority::Zone> {
    let path = config.file.as_ref()?;
    let last_ok = secondary_last_refresh(path)?;
    let age = unix_now().checked_sub(last_ok)?;
    let text = read_text_limited(path, MAX_AXFR_WIRE_BYTES as u64).ok()?;
    let zone = onetdns_authority::parse_zone(&text, &config.origin).ok()?;
    if !zone.origin().eq_ignore_case(origin)
        || age > zone.soa().expire as u64
        || !zonemd_ok(&zone, ZonemdPolicy::of(global))
    {
        return None;
    }
    Some(zone)
}

/** @brief 마지막으로 받아 온 시각을 적어 둘 경로. */
fn secondary_refresh_state_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".state");
    std::path::PathBuf::from(value)
}

/** @brief 마지막으로 받아 온 시각. */
fn secondary_last_refresh(path: &std::path::Path) -> Option<u64> {
    let now = unix_now();
    let text = read_text_limited(&secondary_refresh_state_path(path), 64).ok()?;
    let timestamp = text.trim().parse::<u64>().ok()?;
    (timestamp <= now).then_some(timestamp)
}

/** @brief 지금 받아 왔다고 적는다. */
fn mark_secondary_refresh(path: &std::path::Path, timestamp: u64) -> std::io::Result<()> {
    atomic_write(
        &secondary_refresh_state_path(path),
        timestamp.to_string().as_bytes(),
    )
}

/** @brief 받아들일 영역 전송 크기 상한. */
const MAX_AXFR_WIRE_BYTES: usize = 64 * 1024 * 1024;
/** @brief 받아들일 기록 수 상한. */
const MAX_AXFR_RECORDS: usize = 1_000_000;
/** @brief 받아들일 청크 수 상한. */
const MAX_AXFR_MESSAGES: usize = 10_000;

/** @brief 상대가 조용할 때 끊기까지 기다릴 시간. */
const SECONDARY_XFR_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
/** @brief 전체 데드라인을 늘리려면 실제 응답이 유지해야 하는 최소 처리율. */
const SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC: u64 = 16 * 1024;

/** @brief 실제로 받은 응답 바이트만큼만 늘어나는 XFR 전체 시간 예산. */
struct XfrProgressDeadline {
    /** @brief 접속을 시작한 시각. */
    started: std::time::Instant,
    /** @brief 진전이 없어도 허용하는 접속·요청 기본 시간. */
    base_timeout: Duration,
    /** @brief 소켓에서 실제로 읽은 응답 바이트. */
    response_bytes: u64,
}

impl XfrProgressDeadline {
    /** @brief 빈 시간 예산을 만든다. */
    fn new(started: std::time::Instant, base_timeout: Duration) -> Self {
        Self {
            started,
            base_timeout,
            response_bytes: 0,
        }
    }

    /** @brief 소켓에서 실제로 읽은 응답 바이트만 시간으로 바꾼다. */
    fn record_response_bytes(&mut self, bytes: usize) {
        self.response_bytes = self
            .response_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    /** @brief 지금까지의 실제 진전으로 허용할 전체 시간. */
    fn allowed(&self) -> Duration {
        let seconds = self.response_bytes / SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        let remainder = self.response_bytes % SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        let nanos =
            remainder.saturating_mul(1_000_000_000) / SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        self.base_timeout
            .saturating_add(Duration::from_secs(seconds))
            .saturating_add(Duration::from_nanos(nanos))
    }

    /** @brief 주어진 시각에 전체 시간 예산이 끝났는지. */
    fn expired(&self, now: std::time::Instant) -> bool {
        now.saturating_duration_since(self.started) >= self.allowed()
    }
}

/** @brief 보낼 전송 요청과 그 서명. */
struct EncodedXfrRequest {
    /** @brief 보낼 요청. */
    query: onetdns_proto::Message,
    /** @brief 길이 접두사를 붙인 바이트. */
    framed_wire: Box<[u8]>,
    /** @brief 요청에 붙인 서명. 응답 검증에 쓴다. */
    request_mac: Option<Vec<u8>>,
}

/** @brief 이미 요청을 보내고 종료 SOA까지 받아 둔 전송. */
struct PreparedXfrIo {
    /** @brief 이 서버가 보낸 요청. */
    query: onetdns_proto::Message,
    /** @brief 요청에 붙인 서명. */
    request_mac: Option<Vec<u8>>,
    /** @brief 종료 SOA까지 받아 둔 응답 frame들. */
    messages: Vec<Box<[u8]>>,
}

/** @brief AXFR 레코드 열의 시작·끝과 개수만 추적한다. */
struct AxfrSequence {
    /** @brief 받아야 하는 영역 이름. */
    origin: onetdns_proto::Name,
    /** @brief 마지막 SOA와 비교할 첫 SOA. */
    opening_soa: Option<onetdns_proto::Record>,
    /** @brief 지금까지 받은 레코드 수. */
    record_count: usize,
}

impl AxfrSequence {
    /** @brief 빈 AXFR 열 추적기를 만든다. */
    fn new(origin: &onetdns_proto::Name) -> Self {
        Self {
            origin: origin.clone(),
            opening_soa: None,
            record_count: 0,
        }
    }

    /** @brief 응답 하나를 검사하고 종료 SOA까지 왔는지 돌려준다. */
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        use onetdns_proto::RecordType;

        let answer_count = message.answers.len();
        for (index, record) in message.answers.iter().enumerate() {
            if self.record_count >= MAX_AXFR_RECORDS {
                return Err("AXFR 응답의 레코드 수가 허용 범위를 넘었습니다".to_string());
            }
            if self.record_count == 0
                && (record.rtype != RecordType::SOA || !record.name.eq_ignore_case(&self.origin))
            {
                return Err("AXFR 응답의 첫 레코드는 영역 최상위 SOA여야 합니다".to_string());
            }
            if record.rtype == RecordType::SOA && record.name.eq_ignore_case(&self.origin) {
                if let Some(opening) = &self.opening_soa {
                    if !xfr_rr_equal(record, opening) {
                        return Err("AXFR 종료 SOA가 시작 SOA와 일치하지 않습니다".to_string());
                    }
                    if index + 1 != answer_count {
                        return Err("AXFR 종료 SOA 뒤에 추가 레코드 존재".to_string());
                    }
                    self.record_count += 1;
                    return Ok(true);
                }
                self.opening_soa = Some(record.clone());
            }
            self.record_count += 1;
        }
        Ok(false)
    }
}

/** @brief 전송 요청을 만든다. 키가 있으면 서명한다. */
fn encode_xfr_request(
    mut query: onetdns_proto::Message,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
) -> Result<EncodedXfrRequest, String> {
    let request_mac = tsig
        .map(|key| onetdns_dnssec::tsig::sign_message(&mut query, key, unix_now(), None))
        .transpose()
        .map_err(|error| format!("XFR 질의를 서명하지 못했습니다: {error}"))?;
    let wire = query
        .try_encode()
        .map_err(|error| format!("XFR 질의를 인코딩하지 못했습니다: {error}"))?;
    let length = u16::try_from(wire.len())
        .map_err(|_| "XFR 질의가 DNS/TCP frame 크기를 넘었습니다".to_string())?;
    let mut framed_wire = Vec::with_capacity(wire.len() + 2);
    framed_wire.extend_from_slice(&length.to_be_bytes());
    framed_wire.extend_from_slice(&wire);
    Ok(EncodedXfrRequest {
        query,
        framed_wire: framed_wire.into_boxed_slice(),
        request_mac,
    })
}

/** @brief 영역 전체를 달라는 요청. */
fn build_axfr_query(origin: &onetdns_proto::Name) -> onetdns_proto::Message {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};

    let mut query = Message::default();
    query.header.id = 0x4242;
    query.questions = vec![Question {
        name: origin.clone(),
        qtype: RecordType(252),
        qclass: DnsClass::IN,
    }];
    query
}

/** @brief 이미 열린 연결로 영역 전체를 받아 온다. */
fn axfr_fetch_prepared(
    origin: &onetdns_proto::Name,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    prepared: PreparedXfrIo,
) -> Result<Vec<onetdns_proto::Record>, String> {
    collect_axfr(origin, |accept| {
        xfr_exchange_prepared(prepared, tsig, accept)
    })
}

/**
 * @brief 받은 청크들을 영역 하나로 모은다.
 * @warning 처음과 끝의 권한 기록이 짝을 이뤄야 끝난 것이다. 확인하지 않으면 중간에
 *          끊긴 영역을 온전한 것으로 받아들인다.
 */
fn collect_axfr(
    origin: &onetdns_proto::Name,
    exchange: impl FnOnce(
        &mut dyn FnMut(&onetdns_proto::Message) -> Result<bool, String>,
    ) -> Result<(), String>,
) -> Result<Vec<onetdns_proto::Record>, String> {
    let mut records = Vec::new();
    let mut sequence = AxfrSequence::new(origin);
    exchange(&mut |msg| {
        let complete = sequence.accept(msg)?;
        records.extend(msg.answers.iter().cloned());
        Ok(complete)
    })?;
    Ok(records)
}

/** @brief nonblocking 리스너가 끝까지 모은 응답 청크들을 검증한다. */
fn xfr_exchange_prepared(
    prepared: PreparedXfrIo,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    mut accept: impl FnMut(&onetdns_proto::Message) -> Result<bool, String>,
) -> Result<(), String> {
    let mut transferred_bytes = 0usize;
    let mut previous_mac = prepared.request_mac;
    for (message_index, message) in prepared.messages.into_iter().enumerate() {
        if accept_xfr_message(
            &prepared.query,
            &mut previous_mac,
            &mut transferred_bytes,
            message_index,
            &message,
            tsig,
            &mut accept,
        )? {
            return Ok(());
        }
    }
    Err("영역 전송 응답에 종료 SOA가 없습니다".to_string())
}

/** @brief XFR frame 하나의 크기·TSIG·엔벨로프를 검증하고 내용 소비자에게 넘긴다. */
#[allow(clippy::too_many_arguments)]
fn accept_xfr_message(
    query: &onetdns_proto::Message,
    previous_mac: &mut Option<Vec<u8>>,
    transferred_bytes: &mut usize,
    message_index: usize,
    buffer: &[u8],
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    accept: &mut impl FnMut(&onetdns_proto::Message) -> Result<bool, String>,
) -> Result<bool, String> {
    if message_index >= MAX_AXFR_MESSAGES {
        return Err("영역 전송 응답에 종료 SOA가 없습니다".to_string());
    }
    *transferred_bytes = transferred_bytes
        .checked_add(2 + buffer.len())
        .ok_or_else(|| "AXFR 전송 크기 계산 범위를 넘었습니다".to_string())?;
    if *transferred_bytes > MAX_AXFR_WIRE_BYTES {
        return Err("AXFR 응답의 전체 크기가 허용 범위를 넘었습니다".to_string());
    }

    let stripped_wire;
    let effective = if let Some(key) = tsig {
        let verified = if message_index == 0 {
            onetdns_dnssec::tsig::verify_wire(buffer, key, unix_now(), previous_mac.as_deref())
        } else {
            onetdns_dnssec::tsig::verify_wire_subsequent(
                buffer,
                key,
                unix_now(),
                previous_mac.as_deref().unwrap_or(&[]),
            )
        };
        match verified {
            Ok((wire, mac)) => {
                *previous_mac = Some(mac);
                stripped_wire = wire;
                stripped_wire.as_slice()
            }
            Err(error) => {
                return Err(format!(
                    "영역 전송 응답의 TSIG 검증에 실패했습니다: {error:?}"
                ));
            }
        }
    } else {
        buffer
    };
    let message = onetdns_proto::Message::parse(effective)
        .map_err(|_| "영역 전송 응답을 해석하지 못했습니다".to_string())?;
    let question_ok = if message_index == 0 {
        message.questions.len() == 1
            && message.questions[0]
                .name
                .eq_ignore_case(&query.questions[0].name)
            && message.questions[0].qtype == query.questions[0].qtype
            && message.questions[0].qclass == query.questions[0].qclass
    } else {
        message.questions.is_empty()
    };
    if message.header.rcode != 0 {
        return Err(xfr_rcode_error(message.header.rcode));
    }
    if !message.header.response
        || message.header.id != query.header.id
        || message.header.opcode != 0
        || !message.header.authoritative
        || message.header.truncated
        || !question_ok
        || !message.authorities.is_empty()
    {
        return Err("영역 전송 응답의 헤더와 질의 정보가 요청과 일치하지 않습니다".to_string());
    }
    accept(&message)
}

/** @brief 이 응답 코드의 실패 사유. */
fn xfr_rcode_error(rcode: u16) -> String {
    format!("영역 전송 응답 코드: {rcode}")
}

/**
 * @brief 상대가 바뀐 부분만 보내기를 지원하지 않는다는 사유인지.
 * @warning 사유를 만드는 쪽과 판별하는 쪽이 같은 곳을 봐야 한다. 문구가 어긋나면 전부
 *          받아 오는 길이 조용히 막힌다.
 */
fn xfr_error_is_notimp(error: &str) -> bool {
    error == xfr_rcode_error(onetdns_proto::ResponseCode::NotImp.0)
}

/** @brief 두 기록이 같은지. */
fn xfr_rr_equal(left: &onetdns_proto::Record, right: &onetdns_proto::Record) -> bool {
    left.name.eq_ignore_case(&right.name)
        && left.rtype == right.rtype
        && left.class == right.class
        && onetdns_dnssec::canonical_rdata(&left.rdata)
            == onetdns_dnssec::canonical_rdata(&right.rdata)
}

/** @brief 바뀐 부분만 받아 온 결과. */
enum IxfrFetchResult {
    /** @brief 상대의 시리얼이 이 서버와 같다. */
    Unchanged,
    /** @brief 바뀐 부분만 받아 적용했다. */
    Incremental(onetdns_authority::Zone),
    /** @brief 상대가 전체를 보내 왔다. */
    Full(onetdns_authority::Zone),
}

#[derive(Clone, Copy)]
/** @brief 상대가 어떤 형태로 답했는지. */
enum IxfrWireMode {
    /** @brief 아직 어느 형태인지 모른다. */
    Undecided,
    /** @brief 전체를 보내고 있다. */
    Full,
    /** @brief 지울 기록을 세는 중이다. */
    Delete,
    /** @brief 더할 기록을 세는 중이다. 값은 그 변경분의 일련번호. */
    Add(u32),
}

/** @brief IXFR 변경 열의 형태·연속성·종료만 추적한다. */
struct IxfrSequence {
    /** @brief 받아야 하는 영역 이름. */
    origin: onetdns_proto::Name,
    /** @brief 이 서버가 가진 시리얼. */
    client_serial: u32,
    /** @brief 지금까지 받은 레코드 수. */
    record_count: usize,
    /** @brief 상대가 보내는 열의 현재 형태. */
    mode: IxfrWireMode,
    /** @brief 상대가 처음 알린 최신 시리얼. */
    server_serial: Option<u32>,
    /** @brief 변경할 것이 없다는 단일 SOA 응답인지. */
    unchanged: bool,
    /** @brief 전체 전송 종료와 비교할 첫 SOA. */
    opening_soa: Option<onetdns_proto::Record>,
}

impl IxfrSequence {
    /** @brief 현재 영역을 기준으로 빈 IXFR 열 추적기를 만든다. */
    fn new(current: &onetdns_authority::Zone) -> Self {
        Self {
            origin: current.origin().clone(),
            client_serial: current.soa().serial,
            record_count: 0,
            mode: IxfrWireMode::Undecided,
            server_serial: None,
            unchanged: false,
            opening_soa: None,
        }
    }

    /** @brief 응답 하나를 검사하고 IXFR 열이 끝났는지 돌려준다. */
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        use onetdns_proto::{DnsClass, RecordType};

        let answer_count = message.answers.len();
        for (index, record) in message.answers.iter().enumerate() {
            if self.record_count >= MAX_AXFR_RECORDS {
                return Err("IXFR 응답의 레코드 수가 허용 범위를 넘었습니다".to_string());
            }
            let last_in_message = index + 1 == answer_count;
            let is_apex_soa = record.rtype == RecordType::SOA
                && record.class == DnsClass::IN
                && record.name.eq_ignore_case(&self.origin);
            if record.rtype == RecordType::SOA && !is_apex_soa {
                return Err("IXFR에 apex 밖 SOA가 포함됨".to_string());
            }
            if self.record_count == 0 {
                if !is_apex_soa {
                    return Err("IXFR 응답의 첫 레코드는 영역 최상위 SOA여야 합니다".to_string());
                }
                let serial = record_soa_serial(record)
                    .ok_or_else(|| "IXFR 응답의 첫 SOA 데이터를 해석하지 못했습니다".to_string())?;
                if serial != self.client_serial && !serial_gt(serial, self.client_serial) {
                    return Err("IXFR 응답의 영역 일련번호가 요청한 클라이언트의 일련번호보다 오래되었습니다".to_string());
                }
                self.server_serial = Some(serial);
                self.opening_soa = Some(record.clone());
                self.record_count += 1;
                continue;
            }

            match self.mode {
                IxfrWireMode::Undecided => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "IXFR 응답의 SOA 데이터를 해석하지 못했습니다".to_string()
                        })?;
                        if serial == self.client_serial
                            && self
                                .server_serial
                                .is_some_and(|current| current != self.client_serial)
                        {
                            self.mode = IxfrWireMode::Delete;
                        } else {
                            self.mode = IxfrWireMode::Full;
                        }
                    } else {
                        self.mode = IxfrWireMode::Full;
                    }
                }
                IxfrWireMode::Full => {}
                IxfrWireMode::Delete => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "IXFR 응답의 새 SOA 데이터를 해석하지 못했습니다".to_string()
                        })?;
                        self.mode = IxfrWireMode::Add(serial);
                    }
                }
                IxfrWireMode::Add(latest) => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "IXFR 변경 구간의 SOA 데이터를 해석하지 못했습니다".to_string()
                        })?;
                        if Some(latest) == self.server_serial {
                            let opening = self
                                .opening_soa
                                .as_ref()
                                .expect("첫 IXFR 레코드를 앞에서 저장했습니다");
                            if Some(serial) != self.server_serial
                                || !xfr_rr_equal(record, opening)
                                || !last_in_message
                            {
                                return Err(
                                    "IXFR 응답의 마지막 SOA가 시작 SOA와 일치하지 않습니다"
                                        .to_string(),
                                );
                            }
                            self.record_count += 1;
                            return Ok(true);
                        }
                        if serial != latest {
                            return Err("IXFR 변경분의 일련번호가 앞선 변경분과 이어지지 않습니다"
                                .to_string());
                        }
                        self.mode = IxfrWireMode::Delete;
                    }
                }
            }

            if matches!(self.mode, IxfrWireMode::Full) && is_apex_soa {
                let opening = self
                    .opening_soa
                    .as_ref()
                    .expect("첫 IXFR 레코드를 앞에서 저장했습니다");
                if xfr_rr_equal(record, opening) {
                    if !last_in_message {
                        return Err("IXFR에서 전체 영역 전송으로 전환한 응답의 마지막 SOA 뒤에 레코드가 남아 있습니다".to_string());
                    }
                    self.record_count += 1;
                    return Ok(true);
                }
            }
            self.record_count += 1;
        }

        if self.record_count == 1 && self.server_serial == Some(self.client_serial) {
            self.unchanged = true;
            return Ok(true);
        }
        Ok(false)
    }
}

/** @brief 권한 기록의 시리얼. */
fn record_soa_serial(record: &onetdns_proto::Record) -> Option<u32> {
    match &record.rdata {
        onetdns_proto::RData::Soa(soa) => Some(soa.serial),
        _ => None,
    }
}

/** @brief 이미 열린 연결로 바뀐 부분만 받아 온다. */
fn ixfr_fetch_prepared(
    current: &onetdns_authority::Zone,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    prepared: PreparedXfrIo,
) -> Result<IxfrFetchResult, String> {
    collect_ixfr(current, |accept| {
        xfr_exchange_prepared(prepared, tsig, accept)
    })
}

/** @brief 이 시리얼 이후로 바뀐 것을 달라는 요청. */
fn build_ixfr_query(current: &onetdns_authority::Zone) -> Result<onetdns_proto::Message, String> {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};

    let origin = current.origin();
    let mut query = Message::default();
    query.header.id = 0x4946;
    query.questions.push(Question {
        name: origin.clone(),
        qtype: RecordType(251),
        qclass: DnsClass::IN,
    });
    let client_soa = current
        .axfr_records_iter()
        .next()
        .ok_or_else(|| "IXFR 요청에 클라이언트 SOA 레코드가 없습니다".to_string())?;
    query.authorities.push(client_soa);
    Ok(query)
}

/**
 * @brief 받은 변경 청크들을 읽는다.
 * @details 상대가 바뀐 부분 대신 전부 보낼 수도 있다. 형태를 보고 어느 쪽인지 구분한다.
 */
fn collect_ixfr(
    current: &onetdns_authority::Zone,
    exchange: impl FnOnce(
        &mut dyn FnMut(&onetdns_proto::Message) -> Result<bool, String>,
    ) -> Result<(), String>,
) -> Result<IxfrFetchResult, String> {
    let origin = current.origin();
    let mut records = Vec::new();
    let mut sequence = IxfrSequence::new(current);
    exchange(&mut |message| {
        let complete = sequence.accept(message)?;
        records.extend(message.answers.iter().cloned());
        Ok(complete)
    })?;

    if sequence.unchanged {
        return Ok(IxfrFetchResult::Unchanged);
    }
    if matches!(sequence.mode, IxfrWireMode::Full) {
        let zone = onetdns_authority::Zone::from_records(records)
            .map_err(|error| format!("IXFR 응답을 전체 영역 전송으로 처리하는 과정에서 영역 데이터가 올바르지 않았습니다: {error}"))?;
        if !zone.origin().eq_ignore_case(origin)
            || zone.soa().serial != sequence.server_serial.unwrap_or(0)
        {
            return Err("IXFR에서 전체 영역 전송으로 전환한 응답의 영역 이름 또는 일련번호가 요청과 일치하지 않습니다".to_string());
        }
        return Ok(IxfrFetchResult::Full(zone));
    }
    apply_ixfr_records(current, &records).map(IxfrFetchResult::Incremental)
}

/**
 * @brief 변경을 순서대로 적용한다.
 * @warning 지우라는 기록이 실제로 없으면 거부한다. 이 서버의 영역이 상대와 어긋나 있다는 뜻이고,
 *          그대로 적용하면 어긋남이 더 벌어진다.
 */
fn apply_ixfr_records(
    current: &onetdns_authority::Zone,
    transfer: &[onetdns_proto::Record],
) -> Result<onetdns_authority::Zone, String> {
    use onetdns_proto::{RData, RecordType};

    let current_soa = transfer
        .first()
        .and_then(record_soa_serial)
        .ok_or_else(|| "IXFR 응답에 현재 SOA가 없습니다".to_string())?;
    if transfer.len() < 4
        || !xfr_rr_equal(
            &transfer[0],
            transfer.last().expect("앞에서 응답 길이를 확인했습니다"),
        )
    {
        return Err("IXFR 응답의 시작 SOA와 마지막 SOA가 일치하지 않습니다".to_string());
    }
    let mut records = current.axfr_records();
    records.pop();
    let mut working_serial = current.soa().serial;
    let mut index = 1usize;
    while index + 1 < transfer.len() {
        let old_serial = record_soa_serial(&transfer[index])
            .ok_or_else(|| "IXFR 변경 구간에 이전 SOA가 없습니다".to_string())?;
        if old_serial != working_serial {
            return Err(
                "IXFR 변경 내역이 클라이언트의 현재 일련번호에서 이어지지 않습니다".to_string(),
            );
        }
        index += 1;
        while index + 1 < transfer.len() && transfer[index].rtype != RecordType::SOA {
            let deleted = &transfer[index];
            let Some(position) = records
                .iter()
                .position(|record| xfr_rr_equal(record, deleted))
            else {
                return Err("IXFR가 존재하지 않는 RR 삭제를 요구함".to_string());
            };
            records.remove(position);
            index += 1;
        }
        if index + 1 >= transfer.len() {
            return Err("IXFR 변경 구간에 새 SOA가 없습니다".to_string());
        }
        let new_soa = transfer[index].clone();
        let new_serial = record_soa_serial(&new_soa)
            .ok_or_else(|| "IXFR 변경 구간의 새 SOA가 올바르지 않습니다".to_string())?;
        if !serial_gt(new_serial, working_serial) {
            return Err("IXFR 변경 구간의 일련번호가 증가하지 않았습니다".to_string());
        }
        let soa_position = records
            .iter()
            .position(|record| record.rtype == RecordType::SOA)
            .ok_or_else(|| "클라이언트 DNS 영역에 SOA 레코드가 없습니다".to_string())?;
        records[soa_position] = new_soa;
        working_serial = new_serial;
        index += 1;
        while index + 1 < transfer.len() && transfer[index].rtype != RecordType::SOA {
            let added = transfer[index].clone();
            if matches!(added.rdata, RData::Soa(_)) {
                return Err("IXFR 추가 구간의 SOA 위치가 올바르지 않습니다".to_string());
            }
            if let Some(existing) = records
                .iter_mut()
                .find(|record| xfr_rr_equal(record, &added))
            {
                existing.ttl = added.ttl;
            } else {
                records.push(added);
            }
            index += 1;
        }
        if working_serial == current_soa {
            if index + 1 != transfer.len() {
                return Err(
                    "IXFR 응답에서 현재 일련번호 뒤에 불필요한 변경 내역이 이어집니다".to_string(),
                );
            }
            break;
        }
    }
    if working_serial != current_soa {
        return Err(
            "IXFR 적용을 마친 뒤 영역 일련번호가 응답의 최종 일련번호와 일치하지 않습니다"
                .to_string(),
        );
    }
    let zone = onetdns_authority::Zone::from_records(records).map_err(|error| {
        format!("IXFR 변경을 적용한 뒤 영역 데이터 검증에 실패했습니다: {error}")
    })?;
    if !zone.origin().eq_ignore_case(current.origin()) || zone.soa().serial != current_soa {
        return Err(
            "IXFR 적용을 마친 뒤 영역 이름 또는 일련번호가 예상값과 일치하지 않습니다".to_string(),
        );
    }
    Ok(zone)
}

#[derive(Clone, PartialEq, Eq)]
/** @brief 받아 올 영역 하나의 설정. */
struct XferEntry {
    /** @brief 이 영역의 꼭대기 이름. */
    origin: String,
    /** @brief 받아 온 영역을 담아 둘 파일. */
    file: Option<std::path::PathBuf>,
    /** @brief 받아 올 업스트림 서버. */
    primary: std::net::IpAddr,
    /** @brief 업스트림 서버 포트. */
    port: u16,
    /** @brief 전송에 쓸 공유 키 이름. */
    tsig_key: Option<String>,

    /** @brief 회원 영역을 담은 목록 영역인지. */
    is_catalog: bool,
}

impl XferEntry {
    /** @brief 설정 한 줄을 항목으로. */
    fn from_cfg(s: &onetdns_config::SecondaryZone, is_catalog: bool) -> Option<XferEntry> {
        Some(XferEntry {
            origin: onetdns_proto::Name::from_str(&s.origin)
                .ok()?
                .to_ascii_lower(),
            file: s.file.clone(),
            primary: s.primary?,
            port: s.primary_port.unwrap_or(53),
            tsig_key: s.tsig_key.clone(),
            is_catalog,
        })
    }
}

/** @brief 동시에 받아 올 영역 수. */
const SECONDARY_REFRESH_MAX_IN_FLIGHT: usize = 4;
/** @brief 동시에 접속을 진행할 영역 수. 여기서는 스레드를 쓰지 않아 더 많이 열 수 있다. */
const SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT: usize = 64;
/** @brief frame 하나마다 실제 payload 밖에 보수적으로 잡아 둘 관리 메모리. */
const SECONDARY_XFR_FRAME_OVERHEAD_BYTES: usize = 2 + 2 * std::mem::size_of::<Box<[u8]>>();
/** @brief 모든 진행 중 XFR의 응답 버퍼가 함께 쓸 수 있는 메모리. */
const SECONDARY_XFR_BUFFER_BUDGET_BYTES: usize =
    MAX_AXFR_WIRE_BYTES + MAX_AXFR_MESSAGES * (SECONDARY_XFR_FRAME_OVERHEAD_BYTES - 2);
const _: () = assert!(SECONDARY_XFR_BUFFER_BUDGET_BYTES < 65 * 1024 * 1024);
/** @brief 한 coordinator 순회에서 연결 하나가 처리할 최대 frame 수. */
const SECONDARY_XFR_FRAMES_PER_POLL: usize = 4;
/** @brief 한 coordinator 순회에서 연결 하나가 처리할 최대 응답 바이트. */
const SECONDARY_XFR_BYTES_PER_POLL: usize = 256 * 1024;
/** @brief 전송 스레드의 스택 크기. */
const SECONDARY_XFER_STACK_BYTES: usize = 1024 * 1024;

/** @brief 모든 XFR 리스너가 나눠 쓰는 정확한 응답 버퍼 카운터. */
struct XfrBufferBudget {
    /** @brief 허용한 전체 바이트. */
    limit: usize,
    /** @brief 지금 빌려 준 전체 바이트. */
    used: std::sync::atomic::AtomicUsize,
}

impl XfrBufferBudget {
    /** @brief 주어진 상한의 빈 카운터를 만든다. */
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /** @brief 이 카운터에서 아무것도 빌리지 않은 몫을 만든다. */
    fn reservation(self: &Arc<Self>) -> XfrBufferReservation {
        XfrBufferReservation {
            budget: self.clone(),
            bytes: 0,
        }
    }

    #[cfg(test)]
    /** @brief 테스트에서 현재 대여량을 확인한다. */
    fn used(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::Acquire)
    }
}

/** @brief XFR 하나가 전역 응답 버퍼에서 빌린 몫. 버리면 자동 반환한다. */
struct XfrBufferReservation {
    /** @brief 함께 쓰는 카운터. */
    budget: Arc<XfrBufferBudget>,
    /** @brief 이 전송이 빌린 바이트. */
    bytes: usize,
}

impl XfrBufferReservation {
    /** @brief 전역 상한을 넘지 않을 때만 이 몫을 늘린다. */
    fn try_grow(&mut self, additional: usize) -> bool {
        let mut used = self.budget.used.load(std::sync::atomic::Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(additional) else {
                return false;
            };
            if next > self.budget.limit {
                return false;
            }
            match self.budget.used.compare_exchange_weak(
                used,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bytes += additional;
                    return true;
                }
                Err(actual) => used = actual,
            }
        }
    }
}

impl Drop for XfrBufferReservation {
    /** @brief 빌린 응답 버퍼 몫을 정확히 돌려준다. */
    fn drop(&mut self) {
        self.budget
            .used
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

/** @brief 받아 올 영역 하나와 그 시각들. */
struct SecondaryRefreshJob {
    /** @brief 받아 올 영역 설정. */
    entry: XferEntry,
    /** @brief 이 서버가 잡은 시리얼. */
    current_serial: Option<u32>,
    /** @brief 이미 영역을 잡고 있었는지. */
    had_zone: bool,
    /** @brief 마지막으로 받아 온 시각. */
    last_ok: u64,
    /** @brief 다음에 물어볼 간격. */
    refresh: u64,
    /** @brief 실패했을 때 다시 물어볼 간격. */
    retry: u64,
    /** @brief 이 시간이 지나면 잡은 영역을 버린다. */
    expire: u64,
    /** @brief 알림을 받아 먼저 처리할 것인지. */
    priority: bool,

    /** @brief 바뀐 부분만 받기를 건너뛰고 전체를 받는다. */
    force_axfr: bool,
}

#[derive(Clone, Copy)]
/** @brief 어떤 방식으로 받아 왔는지. */
enum SecondaryXferKind {
    /** @brief 전체를 받았다. */
    Axfr,
    /** @brief 바뀐 부분만 받았다. */
    Ixfr,
    /** @brief 바뀐 부분을 물었는데 전체가 왔다. */
    IxfrFull,
}

/** @brief 받아 온 결과. */
enum SecondaryXferOutcome {
    /** @brief 이 서버의 시리얼이 최신이라 받을 것이 없다. */
    UpToDate,
    /** @brief 영역을 받아 왔다. */
    Zone(Box<onetdns_authority::Zone>, SecondaryXferKind),
    /** @brief 목록 영역을 받아 왔다. */
    Catalog { serial: u32, members: Vec<String> },

    /** @brief 바뀐 부분만으로는 안 되니 전체를 받아야 한다. */
    NeedsFullTransfer { remote_serial: u32 },
}

/** @brief 지금 받아 오고 있는 영역 하나. */
struct ActiveSecondaryXfer {
    /** @brief 받아 오는 중인 영역. */
    job: SecondaryRefreshJob,
    /** @brief 그 전송을 실행하는 스레드. */
    handle: std::thread::JoinHandle<Result<SecondaryXferOutcome, String>>,
}

/** @brief 응답 레코드 열이 끝났는지 판별하는 방식. */
enum SecondaryXfrBoundary {
    /** @brief 전체 영역 전송. */
    Axfr(AxfrSequence),
    /** @brief 증분 또는 전체 fallback 전송. */
    Ixfr(IxfrSequence),
}

impl SecondaryXfrBoundary {
    /** @brief 응답 하나를 반영하고 영역 전송이 끝났는지 돌려준다. */
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        match self {
            Self::Axfr(sequence) => sequence.accept(message),
            Self::Ixfr(sequence) => sequence.accept(message),
        }
    }
}

/** @brief XFR 연결·송신·응답 수신 단계. */
enum SecondaryXfrAdmissionState {
    /** @brief 접속을 거는 중. */
    Connecting,
    /** @brief 요청을 보내는 중. */
    Writing { offset: usize },
    /** @brief 다음 응답 길이를 읽는 중. */
    ReadingLength { bytes: [u8; 2], offset: usize },
    /** @brief 다음 응답 본문을 읽는 중. */
    ReadingMessage { bytes: Vec<u8>, offset: usize },
}

/**
 * @brief 접속부터 종료 SOA까지 nonblocking으로 받는 중인 전송.
 * @details 네트워크를 기다리는 동안은 스레드를 쓰지 않는다. 느린 상대 여럿이 전송 워커를
 *          붙잡으면 멀쩡한 영역까지 못 받아 오므로 완결된 전송만 파서로 넘긴다.
 */
struct PendingSecondaryXfrAdmission {
    /** @brief 받아 올 영역 설정. */
    job: SecondaryRefreshJob,
    /** @brief 상대가 알린 시리얼. */
    remote_serial: u32,
    /** @brief 이 서버가 잡은 영역. */
    current: Option<onetdns_authority::Zone>,
    /** @brief 이어진 연결. */
    stream: std::net::TcpStream,
    /** @brief 보낸 요청. */
    query: onetdns_proto::Message,
    /** @brief 길이 접두사를 붙인 바이트. */
    framed_wire: Box<[u8]>,
    /** @brief 요청에 붙인 서명. */
    request_mac: Option<Vec<u8>>,
    /** @brief 종료 SOA까지 받은 원본 응답들. */
    messages: Vec<Box<[u8]>>,
    /** @brief 종료 SOA 판별 상태. */
    boundary: SecondaryXfrBoundary,
    /** @brief 이 전송이 빌린 응답 버퍼 몫. */
    reservation: XfrBufferReservation,
    /** @brief 길이 접두사를 포함해 지금까지 받은 응답 바이트. */
    wire_bytes: usize,
    /** @brief 실제 응답 진전에 비례하는 전체 시간 예산. */
    progress_deadline: XfrProgressDeadline,
    /** @brief 마지막 진행 뒤 아무 바이트도 오지 않을 때의 데드라인. */
    idle_deadline: std::time::Instant,
    /** @brief 지금 어느 단계인지. */
    state: SecondaryXfrAdmissionState,
}

/** @brief 종료 SOA까지 받아 이제 검증·영역 구축할 수 있는 전송. */
struct PreparedSecondaryXfr {
    /** @brief 받아 올 영역 설정. */
    job: SecondaryRefreshJob,
    /** @brief 상대가 알린 시리얼. */
    remote_serial: u32,
    /** @brief 이 서버가 잡은 영역. */
    current: Option<onetdns_authority::Zone>,
    /** @brief 종료 SOA까지 받아 둔 응답. */
    io: PreparedXfrIo,
    /** @brief 영역 구축이 끝날 때까지 유지할 전역 수신 버퍼 몫. */
    reservation: XfrBufferReservation,
}

/** @brief 네트워크 수신을 nonblocking으로 진행하는 전송들. */
struct SecondaryXfrAdmission {
    /** @brief 아직 종료 SOA까지 받지 못한 전송들. */
    pending: Vec<PendingSecondaryXfrAdmission>,
    /** @brief pending·prepared·parser가 함께 쓰는 응답 버퍼 상한. */
    budget: Arc<XfrBufferBudget>,
}

impl PendingSecondaryXfrAdmission {
    /** @brief 접속부터 종료 SOA까지 제한된 양만 진행한다. 끝났으면 참. */
    fn advance(&mut self) -> Result<bool, String> {
        use std::io::{Read, Write};

        let mut frames = 0usize;
        let mut bytes_this_poll = 0usize;
        loop {
            match &mut self.state {
                SecondaryXfrAdmissionState::Connecting => {
                    if let Some(error) = self.stream.take_error().map_err(|e| e.to_string())? {
                        return Err(format!("XFR TCP 연결에 실패했습니다: {error}"));
                    }
                    match self.stream.peer_addr() {
                        Ok(_) => {
                            self.state = SecondaryXfrAdmissionState::Writing { offset: 0 };
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::NotConnected
                                    | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!(
                                "XFR TCP 연결 상태를 확인하지 못했습니다: {error}"
                            ));
                        }
                    }
                }
                SecondaryXfrAdmissionState::Writing { offset } => {
                    match self.stream.write(&self.framed_wire[*offset..]) {
                        Ok(0) => return Err("XFR 질의를 보내는 중 연결이 닫혔습니다".to_string()),
                        Ok(written) => {
                            *offset += written;
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if *offset == self.framed_wire.len() {
                                self.state = SecondaryXfrAdmissionState::ReadingLength {
                                    bytes: [0; 2],
                                    offset: 0,
                                };
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => return Err(format!("XFR 질의를 보내지 못했습니다: {error}")),
                    }
                }
                SecondaryXfrAdmissionState::ReadingLength { bytes, offset } => {
                    if *offset == bytes.len() {
                        let length = u16::from_be_bytes(*bytes) as usize;
                        if length == 0 {
                            return Err("XFR 응답 frame 길이가 0입니다".to_string());
                        }
                        if self.messages.len() >= MAX_AXFR_MESSAGES {
                            return Err("영역 전송 응답에 종료 SOA가 없습니다".to_string());
                        }
                        let wire_bytes = self
                            .wire_bytes
                            .checked_add(2 + length)
                            .ok_or_else(|| "AXFR 전송 크기 계산 범위를 넘었습니다".to_string())?;
                        if wire_bytes > MAX_AXFR_WIRE_BYTES {
                            return Err(
                                "AXFR 응답의 전체 크기가 허용 범위를 넘었습니다".to_string()
                            );
                        }
                        let charge = length
                            .checked_add(SECONDARY_XFR_FRAME_OVERHEAD_BYTES)
                            .ok_or_else(|| {
                                "XFR 응답 버퍼 크기 계산 범위를 넘었습니다".to_string()
                            })?;
                        if !self.reservation.try_grow(charge) {
                            return Err(
                                "동시 XFR 응답 버퍼가 전체 메모리 상한에 도달했습니다".to_string()
                            );
                        }
                        self.wire_bytes = wire_bytes;
                        self.state = SecondaryXfrAdmissionState::ReadingMessage {
                            bytes: vec![0; length],
                            offset: 0,
                        };
                        continue;
                    }
                    match self.stream.read(&mut bytes[*offset..]) {
                        Ok(0) => {
                            return Err("XFR 종료 SOA 없이 연결이 닫혔습니다".to_string());
                        }
                        Ok(read) => {
                            *offset += read;
                            bytes_this_poll += read;
                            self.progress_deadline.record_response_bytes(read);
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL {
                                return Ok(false);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!("XFR 응답 길이를 읽지 못했습니다: {error}"));
                        }
                    }
                }
                SecondaryXfrAdmissionState::ReadingMessage { bytes, offset } => {
                    if *offset == bytes.len() {
                        let wire = std::mem::take(bytes);
                        let message = onetdns_proto::Message::parse(&wire)
                            .map_err(|_| "영역 전송 응답을 해석하지 못했습니다".to_string())?;
                        let complete = if message.header.rcode != 0 {
                            true
                        } else {
                            self.boundary.accept(&message)?
                        };
                        self.messages.push(wire.into_boxed_slice());
                        frames += 1;
                        self.state = SecondaryXfrAdmissionState::ReadingLength {
                            bytes: [0; 2],
                            offset: 0,
                        };
                        if complete {
                            return Ok(true);
                        }
                        if frames >= SECONDARY_XFR_FRAMES_PER_POLL
                            || bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL
                        {
                            return Ok(false);
                        }
                        continue;
                    }
                    match self.stream.read(&mut bytes[*offset..]) {
                        Ok(0) => {
                            return Err("XFR 종료 SOA 없이 연결이 닫혔습니다".to_string());
                        }
                        Ok(read) => {
                            *offset += read;
                            bytes_this_poll += read;
                            self.progress_deadline.record_response_bytes(read);
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL {
                                return Ok(false);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!("XFR 응답 본문을 읽지 못했습니다: {error}"));
                        }
                    }
                }
            }
        }
    }

    /** @brief 완결된 응답을 검증·영역 구축 단계로 넘긴다. */
    fn into_prepared(self) -> PreparedSecondaryXfr {
        let Self {
            job,
            remote_serial,
            current,
            query,
            request_mac,
            messages,
            reservation,
            ..
        } = self;
        PreparedSecondaryXfr {
            job,
            remote_serial,
            current,
            io: PreparedXfrIo {
                query,
                request_mac,
                messages,
            },
            reservation,
        }
    }
}

impl Default for SecondaryXfrAdmission {
    /** @brief 프로세스 전체 수신 버퍼 상한을 공유하는 빈 admission을 만든다. */
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            budget: Arc::new(XfrBufferBudget::new(SECONDARY_XFR_BUFFER_BUDGET_BYTES)),
        }
    }
}

impl SecondaryXfrAdmission {
    /** @brief 기다리는 전송 수. */
    fn len(&self) -> usize {
        self.pending.len()
    }

    /** @brief 설정에서 사라진 영역의 전송을 버린다. */
    fn retain_current(&mut self, entries: &[XferEntry]) {
        self.pending
            .retain(|pending| secondary_entry_is_current(entries, &pending.job));
    }

    /** @brief 접속을 걸고 요청을 보낸다. */
    fn start(
        &mut self,
        job: SecondaryRefreshJob,
        remote_serial: u32,
        current: Option<onetdns_authority::Zone>,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        timeout: Duration,
    ) -> Result<(), Box<(SecondaryRefreshJob, String)>> {
        if self.pending.len() >= SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT {
            return Err(Box::new((
                job,
                "XFR admission 연결 상한에 도달했습니다".to_string(),
            )));
        }
        let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
            Ok(origin) => origin,
            Err(_) => {
                return Err(Box::new((
                    job,
                    "보조 DNS 영역 이름의 형식이 잘못되었습니다".to_string(),
                )));
            }
        };
        let key = tsig_for_secondary(tsig_keys, &job.entry.tsig_key);
        if job.entry.tsig_key.is_some() && key.is_none() {
            return Err(Box::new((
                job,
                "보조 영역에 사용할 TSIG 키를 찾지 못했습니다".to_string(),
            )));
        }

        let current = if job.force_axfr { None } else { current };
        let boundary = match current.as_ref() {
            Some(current) if !job.entry.is_catalog => {
                SecondaryXfrBoundary::Ixfr(IxfrSequence::new(current))
            }
            _ => SecondaryXfrBoundary::Axfr(AxfrSequence::new(&origin)),
        };
        let mut query = match current.as_ref() {
            Some(current) if !job.entry.is_catalog => match build_ixfr_query(current) {
                Ok(query) => query,
                Err(error) => return Err(Box::new((job, error))),
            },
            _ => build_axfr_query(&origin),
        };
        query.header.id = u16::from_ne_bytes(onetdns_core::random_array());
        let encoded = match encode_xfr_request(query, key) {
            Ok(encoded) => encoded,
            Err(error) => return Err(Box::new((job, error))),
        };
        let address = std::net::SocketAddr::new(job.entry.primary, job.entry.port);
        let stream = match nonblocking_tcp::connect(address) {
            Ok(stream) => stream,
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("XFR TCP 연결을 시작하지 못했습니다: {error}"),
                )));
            }
        };
        let _ = stream.set_nodelay(true);
        let now = std::time::Instant::now();
        self.pending.push(PendingSecondaryXfrAdmission {
            job,
            remote_serial,
            current,
            stream,
            query: encoded.query,
            framed_wire: encoded.framed_wire,
            request_mac: encoded.request_mac,
            messages: Vec::new(),
            boundary,
            reservation: self.budget.reservation(),
            wire_bytes: 0,
            progress_deadline: XfrProgressDeadline::new(now, timeout),
            // 접속은 아직 읽을 바이트가 없으므로 기본 전체 시간까지 허용한다. 연결된 뒤부터
            // write/read 진전마다 짧은 무진전 데드라인으로 바뀐다.
            idle_deadline: now + timeout,
            state: SecondaryXfrAdmissionState::Connecting,
        });
        Ok(())
    }

    /** @brief 진행 중 연결들을 공평한 작업량만큼 진행시킨다. */
    fn poll(
        &mut self,
    ) -> (
        Vec<PreparedSecondaryXfr>,
        Vec<(SecondaryRefreshJob, String)>,
    ) {
        let now = std::time::Instant::now();
        let mut ready = Vec::new();
        let mut failed = Vec::new();
        let mut index = self.pending.len();
        while index > 0 {
            index -= 1;
            let result = if self.pending[index].progress_deadline.expired(now) {
                Err("XFR 전송 전체 시간이 초과됐습니다".to_string())
            } else if now >= self.pending[index].idle_deadline {
                Err("XFR 응답 대기 시간이 초과됐습니다".to_string())
            } else {
                self.pending[index].advance()
            };
            match result {
                Ok(false) => {}
                Ok(true) => {
                    let pending = self.pending.swap_remove(index);
                    ready.push(pending.into_prepared());
                }
                Err(error) => {
                    let pending = self.pending.swap_remove(index);
                    failed.push((pending.job, error));
                }
            }
        }
        (ready, failed)
    }
}

/** @brief 영역 수에 맞춘 동시 전송 수. */
fn secondary_refresh_parallelism(entries: usize) -> usize {
    entries.clamp(1, SECONDARY_REFRESH_MAX_IN_FLIGHT)
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
/** @brief 시리얼을 물은 질의 하나를 가리키는 키. */
struct SecondarySoaProbeKey {
    /** @brief 이 소켓과 질의 번호로 응답을 짝짓는다. */
    source: std::net::SocketAddr,
    /** @brief 이 서버가 보낸 질의 번호. */
    id: u16,
}

/** @brief 시리얼 응답을 기다리는 중인 질의. */
struct PendingSecondarySoa {
    /** @brief 이 시리얼을 물어본 영역. */
    job: SecondaryRefreshJob,
    /** @brief 물어본 이름. */
    origin: onetdns_proto::Name,
    /** @brief 서명에 쓴 키. */
    tsig_key: Option<usize>,
    /** @brief 요청에 붙인 서명. */
    request_mac: Option<Vec<u8>>,
    /** @brief 답을 기다릴 데드라인. */
    deadline: std::time::Instant,
}

/** @brief 물어본 시리얼 결과. */
struct SecondarySoaProbeResult {
    /** @brief 물어본 영역. */
    job: SecondaryRefreshJob,
    /** @brief 받은 시리얼. 실패하면 사유. */
    result: Result<u32, String>,
}

/**
 * @brief 여러 영역의 시리얼을 소켓 몇 개로 한꺼번에 묻는 것.
 * @details 영역마다 소켓을 열면 영역이 많을 때 그것만으로 핸들이 동난다.
 */
struct SecondarySoaProber {
    /** @brief IPv4 업스트림 서버에 쓸 소켓. */
    ipv4: Option<std::net::UdpSocket>,
    /** @brief IPv6 업스트림 서버에 쓸 소켓. */
    ipv6: Option<std::net::UdpSocket>,
    /** @brief 답을 기다리는 질의들. */
    pending: std::collections::HashMap<SecondarySoaProbeKey, PendingSecondarySoa>,
    /** @brief 지금 묻고 있는 영역들. 같은 영역을 두 번 묻지 않으려는 것이다. */
    pending_origins: std::collections::HashSet<String>,
}

impl SecondarySoaProber {
    /** @brief 물어볼 영역들로 만든다. */
    fn new(entries: &[XferEntry]) -> std::io::Result<Self> {
        let ipv4 = if entries.iter().any(|entry| entry.primary.is_ipv4()) {
            let socket = onetdns_core::udp::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
            socket.set_nonblocking(true)?;
            Some(socket)
        } else {
            None
        };
        let ipv6 = if entries.iter().any(|entry| entry.primary.is_ipv6()) {
            let socket = onetdns_core::udp::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))?;
            socket.set_nonblocking(true)?;
            Some(socket)
        } else {
            None
        };
        Ok(Self {
            ipv4,
            ipv6,
            pending: std::collections::HashMap::new(),
            pending_origins: std::collections::HashSet::new(),
        })
    }

    /** @brief 이 영역을 지금 묻고 있는지. */
    fn contains(&self, origin: &str) -> bool {
        self.pending_origins.contains(origin)
    }

    /** @brief 답을 기다리는 질의 수. */
    fn len(&self) -> usize {
        self.pending.len()
    }

    /** @brief 설정에서 사라진 영역의 질의를 버린다. */
    fn retain_current(&mut self, entries: &[XferEntry]) {
        self.pending
            .retain(|_, probe| secondary_entry_is_current(entries, &probe.job));
        self.pending_origins.clear();
        self.pending_origins.extend(
            self.pending
                .values()
                .map(|probe| probe.job.entry.origin.clone()),
        );
    }

    /** @brief 시리얼을 묻는다. */
    fn start(
        &mut self,
        job: SecondaryRefreshJob,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        timeout: Duration,
    ) -> Result<(), Box<(SecondaryRefreshJob, String)>> {
        use onetdns_proto::RecordType;

        if self.contains(&job.entry.origin) {
            return Err(Box::new((
                job,
                "같은 영역의 SOA 질의가 이미 진행 중입니다".to_string(),
            )));
        }
        let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
            Ok(origin) => origin,
            Err(_) => {
                return Err(Box::new((
                    job,
                    "보조 DNS 영역 이름의 형식이 잘못되었습니다".to_string(),
                )));
            }
        };
        let tsig_key = tsig_for_secondary(tsig_keys, &job.entry.tsig_key)
            .and_then(|wanted| tsig_keys.iter().position(|key| std::ptr::eq(key, wanted)));
        if job.entry.tsig_key.is_some() && tsig_key.is_none() {
            return Err(Box::new((
                job,
                "보조 영역에 사용할 TSIG 키를 찾지 못했습니다".to_string(),
            )));
        }
        let source = std::net::SocketAddr::new(job.entry.primary, job.entry.port);
        let start_id = u16::from_ne_bytes(onetdns_core::random_array());
        let Some(key) = (0..=u16::MAX).find_map(|offset| {
            let key = SecondarySoaProbeKey {
                source,
                id: start_id.wrapping_add(offset),
            };
            (!self.pending.contains_key(&key)).then_some(key)
        }) else {
            return Err(Box::new((
                job,
                "같은 primary에 보낼 SOA 질의 ID 공간이 가득 찼습니다".to_string(),
            )));
        };

        let mut query = onetdns_proto::Message::query(key.id, origin.clone(), RecordType::SOA);
        query.header.recursion_desired = false;
        let request_mac = match tsig_key.and_then(|index| tsig_keys.get(index)) {
            Some(tsig_key) => {
                match onetdns_dnssec::tsig::sign_message(&mut query, tsig_key, unix_now(), None) {
                    Ok(mac) => Some(mac),
                    Err(error) => {
                        return Err(Box::new((
                            job,
                            format!("SOA 질의를 서명하지 못했습니다: {error}"),
                        )));
                    }
                }
            }
            None => None,
        };
        let wire = match query.try_encode() {
            Ok(wire) => wire,
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("SOA 질의를 인코딩하지 못했습니다: {error}"),
                )));
            }
        };
        let socket = if source.is_ipv4() {
            self.ipv4.as_ref()
        } else {
            self.ipv6.as_ref()
        };
        let Some(socket) = socket else {
            return Err(Box::new((
                job,
                "SOA 질의용 UDP 소켓이 없습니다".to_string(),
            )));
        };
        match socket.send_to(&wire, source) {
            Ok(written) if written == wire.len() => {}
            Ok(_) => {
                return Err(Box::new((
                    job,
                    "SOA UDP 질의가 일부만 전송됐습니다".to_string(),
                )));
            }
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("SOA 질의를 전송하지 못했습니다: {error}"),
                )));
            }
        }
        self.pending_origins.insert(job.entry.origin.clone());
        self.pending.insert(
            key,
            PendingSecondarySoa {
                job,
                origin,
                tsig_key,
                request_mac,
                deadline: std::time::Instant::now() + timeout,
            },
        );
        Ok(())
    }

    /** @brief 이 소켓에 온 응답들을 읽는다. */
    fn receive_socket(
        socket: &std::net::UdpSocket,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        pending: &mut std::collections::HashMap<SecondarySoaProbeKey, PendingSecondarySoa>,
        pending_origins: &mut std::collections::HashSet<String>,
        completed: &mut Vec<SecondarySoaProbeResult>,
    ) {
        let mut wire = [0u8; 65_535];
        loop {
            let (length, source) = match socket.recv_from(&mut wire) {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    onetdns_core::warn!(event = "authority.secondary_soa_receive_failed", %error, "보조 DNS SOA 응답 소켓에서 읽지 못했습니다");
                    break;
                }
            };
            if length < 2 {
                continue;
            }
            let id = u16::from_be_bytes([wire[0], wire[1]]);
            let key = SecondarySoaProbeKey { source, id };
            let Some(probe) = pending.get(&key) else {
                continue;
            };
            let message =
                if let Some(tsig_key) = probe.tsig_key.and_then(|index| tsig_keys.get(index)) {
                    onetdns_dnssec::tsig::verify_wire(
                        &wire[..length],
                        tsig_key,
                        unix_now(),
                        probe.request_mac.as_deref(),
                    )
                    .ok()
                    .and_then(|(stripped, _)| onetdns_proto::Message::parse(&stripped).ok())
                } else {
                    onetdns_proto::Message::parse(&wire[..length]).ok()
                };
            let Some(message) = message else { continue };
            if !soa_response_matches_question(&message, key.id, &probe.origin) {
                continue;
            }
            let result = soa_serial_from_response(&message, key.id, &probe.origin);
            let Some(probe) = pending.remove(&key) else {
                continue;
            };
            pending_origins.remove(&probe.job.entry.origin);
            completed.push(SecondarySoaProbeResult {
                job: probe.job,
                result,
            });
        }
    }

    /** @brief 온 응답을 거두고 데드라인이 지난 것을 버린다. */
    fn poll(
        &mut self,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    ) -> Vec<SecondarySoaProbeResult> {
        let mut completed = Vec::new();
        if let Some(socket) = &self.ipv4 {
            Self::receive_socket(
                socket,
                tsig_keys,
                &mut self.pending,
                &mut self.pending_origins,
                &mut completed,
            );
        }
        if let Some(socket) = &self.ipv6 {
            Self::receive_socket(
                socket,
                tsig_keys,
                &mut self.pending,
                &mut self.pending_origins,
                &mut completed,
            );
        }
        let now = std::time::Instant::now();
        let expired: Vec<SecondarySoaProbeKey> = self
            .pending
            .iter()
            .filter_map(|(key, probe)| (probe.deadline <= now).then_some(*key))
            .collect();
        for key in expired {
            if let Some(probe) = self.pending.remove(&key) {
                self.pending_origins.remove(&probe.job.entry.origin);
                completed.push(SecondarySoaProbeResult {
                    job: probe.job,
                    result: Err("SOA 질의 시간이 초과됐습니다".to_string()),
                });
            }
        }
        completed
    }
}

/** @brief 준비된 전송을 실제로 끝까지 받아 온다. */
fn run_prepared_secondary_transfer(
    entry: &XferEntry,
    current: Option<&onetdns_authority::Zone>,
    remote_serial: u32,
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    prepared: PreparedXfrIo,
    _reservation: XfrBufferReservation,
) -> Result<SecondaryXferOutcome, String> {
    let origin = onetdns_proto::Name::from_str(&entry.origin)
        .map_err(|_| "보조 DNS 영역 이름의 형식이 잘못되었습니다".to_string())?;
    let key = tsig_for_secondary(tsig_keys, &entry.tsig_key);
    if entry.tsig_key.is_some() && key.is_none() {
        return Err("보조 영역에 사용할 TSIG 키를 찾지 못했습니다".to_string());
    }
    if entry.is_catalog {
        let records = axfr_fetch_prepared(&origin, key, prepared)?;
        return Ok(SecondaryXferOutcome::Catalog {
            serial: remote_serial,
            members: catalog_members(&records, &entry.origin),
        });
    }

    if let Some(current) = current {
        return match ixfr_fetch_prepared(current, key, prepared) {
            Ok(IxfrFetchResult::Unchanged) => Ok(SecondaryXferOutcome::UpToDate),
            Ok(IxfrFetchResult::Incremental(zone)) => Ok(SecondaryXferOutcome::Zone(
                Box::new(zone),
                SecondaryXferKind::Ixfr,
            )),
            Ok(IxfrFetchResult::Full(zone)) => Ok(SecondaryXferOutcome::Zone(
                Box::new(zone),
                SecondaryXferKind::IxfrFull,
            )),
            Err(error) if xfr_error_is_notimp(&error) => {
                Ok(SecondaryXferOutcome::NeedsFullTransfer { remote_serial })
            }
            Err(error) => Err(error),
        };
    }

    let records = axfr_fetch_prepared(&origin, key, prepared)?;
    let zone = onetdns_authority::Zone::from_records(records)
        .map_err(|error| format!("AXFR 영역 데이터가 올바르지 않습니다: {error}"))?;
    Ok(SecondaryXferOutcome::Zone(
        Box::new(zone),
        SecondaryXferKind::Axfr,
    ))
}

/** @brief 상대의 시리얼이 더 새것이라 받아 와야 하는지. */
fn secondary_needs_transfer(job: &SecondaryRefreshJob, remote_serial: u32) -> bool {
    job.current_serial
        .is_none_or(|serial| serial_gt(remote_serial, serial))
}

/** @brief 이 전송이 지금 설정에도 남아 있는지. */
fn secondary_entry_is_current(entries: &[XferEntry], job: &SecondaryRefreshJob) -> bool {
    entries.iter().any(|entry| entry == &job.entry)
}

#[allow(clippy::too_many_arguments)]
/**
 * @brief 받아 온 것을 영역 저장소에 올리고 다음 시각을 잡는다.
 * @details 파일에서 읽은 영역과 똑같이 ZONEMD를 검사한다. 전송으로 받은 영역을 검사하지 않으면
 *          zonemd_check를 켜도 보조 영역은 변조된 채로 나간다.
 */
fn complete_secondary_refresh(
    job: SecondaryRefreshJob,
    result: Result<SecondaryXferOutcome, String>,
    entries: &mut Vec<XferEntry>,
    sched: &mut std::collections::HashMap<String, (u64, u64)>,
    cat_state: &mut std::collections::HashMap<String, (u32, Vec<String>)>,
    ready: &mut std::collections::VecDeque<(SecondaryRefreshJob, u32)>,
    xfr_origins: &mut std::collections::HashSet<String>,
    urgent: &mut std::collections::HashSet<String>,
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    notify: &NotifySender,
    cfg: &Config,
) {
    xfr_origins.remove(&job.entry.origin);
    if !secondary_entry_is_current(entries, &job) {
        return;
    }

    if let Ok(SecondaryXferOutcome::NeedsFullTransfer { remote_serial }) = &result {
        let remote_serial = *remote_serial;
        if !job.force_axfr {
            onetdns_core::info!(event = "authority.secondary_ixfr_notimp", origin = %job.entry.origin, primary = %job.entry.primary, "primary가 IXFR를 지원하지 않아 AXFR로 다시 받습니다");
            let mut job = job;
            job.force_axfr = true;
            xfr_origins.insert(job.entry.origin.clone());
            if job.priority {
                ready.push_front((job, remote_serial));
            } else {
                ready.push_back((job, remote_serial));
            }
            return;
        }
    }
    let completed = unix_now();
    let mut ok = false;
    let mut refresh = job.refresh;
    match result {
        Ok(SecondaryXferOutcome::UpToDate) => ok = true,
        Ok(SecondaryXferOutcome::Zone(zone, _)) if !zonemd_ok(&zone, ZonemdPolicy::of(cfg)) => {
            onetdns_core::warn!(event = "authority.secondary_zonemd_rejected", origin = %job.entry.origin, serial = zone.soa().serial, "받아 온 보조 DNS 영역이 ZONEMD 검증을 통과하지 못해 적용하지 않습니다. 다음 갱신 주기에 다시 받습니다");
        }
        Ok(SecondaryXferOutcome::Zone(zone, kind)) => {
            refresh = zone.soa().refresh as u64;
            let serial = zone.soa().serial;
            let zone_origin = zone.origin().clone();
            let persisted = job.entry.file.as_ref().is_none_or(|path| {
                match atomic_write(path, zone.to_master_file().as_bytes()) {
                    Ok(()) => true,
                    Err(error) => {
                        onetdns_core::warn!(event = "authority.secondary_cache_save_failed", origin = %job.entry.origin, path = %path.display(), %error, "보조 DNS 영역 캐시를 저장하지 못해 새 구성을 적용하지 않습니다");
                        false
                    }
                }
            });
            if persisted {
                match kind {
                    SecondaryXferKind::Axfr => {
                        onetdns_core::info!(event = "authority.secondary_axfr_done", origin = %job.entry.origin, serial, primary = %job.entry.primary, "보조 DNS 영역의 전체 전송을 적용했습니다")
                    }
                    SecondaryXferKind::Ixfr => {
                        onetdns_core::info!(event = "authority.secondary_ixfr_applied", origin = %job.entry.origin, serial, "보조 DNS 영역의 증분 갱신을 적용했습니다")
                    }
                    SecondaryXferKind::IxfrFull => {
                        onetdns_core::info!(event = "authority.secondary_ixfr_fallback_axfr", origin = %job.entry.origin, serial, "IXFR 응답이 완전 전송 형식이어서 AXFR로 처리했습니다")
                    }
                }
                swap_zone(store, *zone);
                notify.enqueue(&zone_origin, serial);
                ok = true;
            }
        }
        Ok(SecondaryXferOutcome::Catalog { serial, members }) => {
            let old = cat_state
                .get(&job.entry.origin)
                .map(|(_, members)| members.clone())
                .unwrap_or_default();
            for gone in old.iter().filter(|member| !members.contains(member)) {
                entries.retain(|entry| entry.origin != *gone);
                sched.remove(gone);
                urgent.remove(gone);
                xfr_origins.remove(gone);
                ready.retain(|(ready_job, _)| ready_job.entry.origin != *gone);
                if let Ok(origin) = onetdns_proto::Name::from_str(gone) {
                    remove_zone(store, &origin);
                }
                onetdns_core::info!(event = "authority.catalog_zone_removed", catalog = %job.entry.origin, member = %gone, "카탈로그에서 빠진 DNS 영역을 제거했습니다");
            }
            for added in members.iter().filter(|member| !old.contains(member)) {
                if entries.iter().any(|entry| entry.origin == *added) {
                    continue;
                }
                entries.push(XferEntry {
                    origin: added.clone(),
                    file: None,
                    primary: job.entry.primary,
                    port: job.entry.port,
                    tsig_key: job.entry.tsig_key.clone(),
                    is_catalog: false,
                });
                sched.insert(added.clone(), (completed, completed));
                onetdns_core::info!(event = "authority.catalog_zone_added", catalog = %job.entry.origin, member = %added, "카탈로그에서 새 DNS 영역을 찾았습니다");
            }
            cat_state.insert(job.entry.origin.clone(), (serial, members));
            ok = true;
        }
        Ok(SecondaryXferOutcome::NeedsFullTransfer { .. }) => {
            onetdns_core::warn!(event = "authority.secondary_axfr_refused", origin = %job.entry.origin, primary = %job.entry.primary, "AXFR 재시도까지 NOTIMP로 거절되어 다음 갱신 주기에 다시 시도합니다");
        }
        Err(error) => {
            let event = if job.entry.is_catalog {
                "authority.catalog_axfr_failed"
            } else {
                "authority.secondary_transfer_failed"
            };
            onetdns_core::warn!(event = event, origin = %job.entry.origin, %error, "보조 DNS 영역 전송에 실패했습니다. 다음 갱신 주기에 다시 시도합니다");
        }
    }

    if ok {
        if let Some(path) = &job.entry.file {
            if let Err(error) = mark_secondary_refresh(path, completed) {
                onetdns_core::warn!(event = "authority.secondary_state_save_failed", origin = %job.entry.origin, path = %path.display(), %error, "보조 DNS 영역의 갱신 상태를 저장하지 못했습니다");
            }
        }
    } else if job.had_zone && completed.saturating_sub(job.last_ok) > job.expire {
        if let Ok(origin) = onetdns_proto::Name::from_str(&job.entry.origin) {
            remove_zone(store, &origin);
        }
        onetdns_core::warn!(event = "authority.secondary_expired", origin = %job.entry.origin, "보조 DNS 영역이 만료되어 응답 제공을 중지합니다");
    }
    let next_check = if urgent.contains(&job.entry.origin) {
        completed
    } else {
        let delay = if ok {
            refresh.clamp(15, 86_400)
        } else {
            job.retry.clamp(15, 3_600)
        };
        completed.saturating_add(delay)
    };
    let last_ok = if ok { completed } else { job.last_ok };
    sched.insert(job.entry.origin, (next_check, last_ok));
}

/** @brief 목록 영역에 적힌 회원 영역들. */
fn catalog_members(records: &[onetdns_proto::Record], catalog: &str) -> Vec<String> {
    let catalog = catalog.trim_end_matches('.').to_ascii_lowercase();
    let zones_suffix = format!(".zones.{catalog}");
    let mut out = Vec::new();
    for r in records {
        if let onetdns_proto::RData::Ptr(member) = &r.rdata {
            let owner = r.name.to_ascii_lower();
            if owner.ends_with(&zones_suffix) {
                out.push(member.to_ascii_lower());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/** @brief 회원 영역 하나를 가리키는 이름. */
fn catalog_member_id(member: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    member
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .hash(&mut h);
    format!("m{:016x}", h.finish())
}

/**
 * @brief 카탈로그 영역의 SOA serial.
 * @details 영역 저장소를 다시 만들 때마다 카탈로그도 다시 만든다. 구성원이 바뀌어도 serial이
 *          그대로면 소비자는 SOA만 보고 받아 가지 않으므로, 시각에서 계산해 늘 커지게 한다.
 */
fn catalog_serial(now: u64) -> u32 {
    (now & u64::from(u32::MAX)) as u32
}

/** @brief 이 서버가 내보낼 목록 영역을 만든다. */
fn build_catalog_zone(
    origin: &onetdns_proto::Name,
    members: &[String],
    serial: u32,
) -> Result<onetdns_authority::Zone, String> {
    use onetdns_proto::{Name, RData, Record, Soa};
    let apex = origin.to_ascii_lower();
    let mut recs = vec![
        Record::new(
            origin.clone(),
            3600,
            RData::soa(Soa {
                mname: origin.clone(),
                rname: origin.clone(),
                serial,
                refresh: 3600,
                retry: 600,
                expire: 604_800,
                minimum: 0,
            }),
        ),
        Record::new(
            origin.clone(),
            3600,
            RData::Ns(Name::from_str("invalid.").map_err(|_| "NS")?),
        ),
        Record::new(
            Name::from_str(&format!("version.{apex}")).map_err(|_| "version 이름")?,
            0,
            RData::Txt(vec![b"2".to_vec()]),
        ),
    ];
    for m in members {
        let id = catalog_member_id(m);
        let owner = Name::from_str(&format!("{id}.zones.{apex}")).map_err(|_| "멤버 이름")?;
        let member = Name::from_str(m).map_err(|_| "멤버 origin")?;
        recs.push(Record::new(owner, 0, RData::Ptr(member)));
    }
    onetdns_authority::Zone::from_records(recs)
}

/** @brief 하위 영역을 주기적으로 받아 오는 스레드를 시작한다. */
fn spawn_secondary_refresh(
    cfg: Config,
    tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    kick: Arc<native::NotifyKick>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn_secondary_refresh_with_timeout(
        cfg,
        tsig_keys,
        store,
        kick,
        notify,
        shutdown,
        Duration::from_secs(10),
    )
}

/**
 * @brief 하위 영역 받아 오기를 돌린다.
 * @details 시리얼을 먼저 묻고, 더 새것일 때만 받아 온다. 접속부터 종료 SOA까지 스레드 없이
 *          처리해 응답이 느리거나 중간에 멈춘 상대가 워커를 붙잡지 못하게 한다.
 */
fn spawn_secondary_refresh_with_timeout(
    cfg: Config,
    tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    kick: Arc<native::NotifyKick>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    timeout: Duration,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let entries: Vec<XferEntry> = cfg
        .secondary
        .iter()
        .filter_map(|secondary| XferEntry::from_cfg(secondary, false))
        .chain(
            cfg.catalog
                .iter()
                .filter_map(|catalog| XferEntry::from_cfg(catalog, true)),
        )
        .collect();
    let prober = SecondarySoaProber::new(&entries)?;
    std::thread::Builder::new()
        .name("secondary-refresh".into())
        .spawn(move || {
        use std::collections::{HashMap, HashSet};
        let mut entries = entries;
        let mut prober = prober;
        let mut sched: HashMap<String, (u64, u64)> = HashMap::new();
        let mut cat_state: HashMap<String, (u32, Vec<String>)> = HashMap::new();
        let mut active: Vec<ActiveSecondaryXfer> = Vec::new();
        let mut admission = SecondaryXfrAdmission::default();
        let mut prepared = std::collections::VecDeque::<PreparedSecondaryXfr>::new();
        let mut ready: std::collections::VecDeque<(SecondaryRefreshJob, u32)> =
            std::collections::VecDeque::new();
        let mut xfr_origins: HashSet<String> = HashSet::new();
        let mut urgent: HashSet<String> = HashSet::new();
        let tsig_keys = Arc::new(tsig_keys);
        let now0 = unix_now();
        for e in &entries {
            let last_ok = e
                .file
                .as_ref()
                .and_then(|path| secondary_last_refresh(path))
                .unwrap_or(now0);
            sched.insert(e.origin.clone(), (now0, last_ok));
        }
        let max_in_flight = secondary_refresh_parallelism(entries.len());
        onetdns_core::info!(event = "authority.secondary_refresh_started", zones = entries.len(), parser_max_in_flight = max_in_flight, admission_max_in_flight = SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT, "보조 DNS 영역 갱신 작업을 bounded 병렬 모드로 시작했습니다");

        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let mut completed = Vec::<(
                SecondaryRefreshJob,
                Result<SecondaryXferOutcome, String>,
            )>::new();
            for probe in prober.poll(&tsig_keys) {
                let mut job = probe.job;
                job.priority |= urgent.contains(&job.entry.origin);
                match probe.result {
                    Ok(remote_serial)
                        if secondary_entry_is_current(&entries, &job)
                            && secondary_needs_transfer(&job, remote_serial) =>
                    {
                        xfr_origins.insert(job.entry.origin.clone());
                        if job.priority {
                            ready.push_front((job, remote_serial));
                        } else {
                            ready.push_back((job, remote_serial));
                        }
                    }
                    Ok(_) => completed.push((job, Ok(SecondaryXferOutcome::UpToDate))),
                    Err(error) => completed.push((job, Err(error))),
                }
            }

            let (admitted, failed) = admission.poll();
            for transfer in admitted {
                if transfer.job.priority || urgent.contains(&transfer.job.entry.origin) {
                    prepared.push_front(transfer);
                } else {
                    prepared.push_back(transfer);
                }
            }
            completed.extend(
                failed
                    .into_iter()
                    .map(|(job, error)| (job, Err(error))),
            );

            let mut index = active.len();
            while index > 0 {
                index -= 1;
                if !active[index].handle.is_finished() {
                    continue;
                }
                let finished = active.swap_remove(index);
                let result = finished
                    .handle
                    .join()
                    .map_err(|_| "보조 영역 전송 작업이 패닉으로 중단됐습니다".to_string())
                    .and_then(|result| result);
                completed.push((finished.job, result));
            }

            let now = unix_now();
            let current_store = store.load();
            for entry in entries.clone() {
                let due = sched
                    .get(&entry.origin)
                    .is_some_and(|(next_check, _)| *next_check <= now);
                let busy = prober.contains(&entry.origin)
                    || xfr_origins.contains(&entry.origin)
                    || active
                        .iter()
                        .any(|active| active.job.entry.origin == entry.origin);
                if !due || busy {
                    continue;
                }
                let Some((_, last_ok)) = sched.get(&entry.origin).copied() else {
                    continue;
                };
                let origin = match onetdns_proto::Name::from_str(&entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        sched.insert(entry.origin.clone(), (now.saturating_add(3_600), last_ok));
                        continue;
                    }
                };
                let current = current_store.zone_exact(&origin);
                let (refresh, retry, expire) = current
                    .as_ref()
                    .map(|zone| {
                        (
                            zone.soa().refresh as u64,
                            zone.soa().retry as u64,
                            zone.soa().expire as u64,
                        )
                    })
                    .unwrap_or((300, 60, 86_400));
                let catalog_serial = cat_state.get(&entry.origin).map(|(serial, _)| *serial);
                let current_serial = if entry.is_catalog {
                    catalog_serial
                } else {
                    current.map(|zone| zone.soa().serial)
                };
                let initial = current_serial.is_none();
                let priority = urgent.remove(&entry.origin) || initial;
                let job = SecondaryRefreshJob {
                    entry,
                    current_serial,
                    had_zone: current.is_some(),
                    last_ok,
                    refresh,
                    retry,
                    expire,
                    priority,
                    force_axfr: false,
                };
                if let Err(error) = prober.start(job, &tsig_keys, timeout) {
                    let (job, error) = *error;
                    completed.push((job, Err(error)));
                }
            }
            drop(current_store);

            for (job, result) in completed {
                complete_secondary_refresh(
                    job,
                    result,
                    &mut entries,
                    &mut sched,
                    &mut cat_state,
                    &mut ready,
                    &mut xfr_origins,
                    &mut urgent,
                    &store,
                    &notify,
                    &cfg,
                );
            }
            prober.retain_current(&entries);
            admission.retain_current(&entries);
            prepared.retain(|transfer| secondary_entry_is_current(&entries, &transfer.job));

            loop {
                let admission_load = admission.len().saturating_add(prepared.len());
                if admission_load >= SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT || ready.is_empty() {
                    break;
                }
                let background_limit = SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT - 1;
                let candidate = ready
                    .iter()
                    .position(|(job, _)| job.priority || urgent.contains(&job.entry.origin))
                    .or_else(|| (admission_load < background_limit).then_some(0));
                let Some(candidate) = candidate else { break };
                let Some((mut job, remote_serial)) = ready.remove(candidate) else {
                    continue;
                };
                if !secondary_entry_is_current(&entries, &job) {
                    xfr_origins.remove(&job.entry.origin);
                    continue;
                }
                job.priority |= urgent.contains(&job.entry.origin);
                let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        complete_secondary_refresh(
                            job,
                            Err("보조 DNS 영역 이름의 형식이 잘못되었습니다".to_string()),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &notify,
                            &cfg,
                        );
                        continue;
                    }
                };
                let current = if job.entry.is_catalog {
                    None
                } else {
                    store.load().zone_exact(&origin).cloned()
                };
                job.current_serial = if job.entry.is_catalog {
                    cat_state
                        .get(&job.entry.origin)
                        .map(|(serial, _)| *serial)
                } else {
                    current.as_ref().map(|zone| zone.soa().serial)
                };
                job.had_zone = current.is_some();
                if let Some(zone) = &current {
                    job.refresh = zone.soa().refresh as u64;
                    job.retry = zone.soa().retry as u64;
                    job.expire = zone.soa().expire as u64;
                }
                if !secondary_needs_transfer(&job, remote_serial) {
                    complete_secondary_refresh(
                        job,
                        Ok(SecondaryXferOutcome::UpToDate),
                        &mut entries,
                        &mut sched,
                        &mut cat_state,
                        &mut ready,
                        &mut xfr_origins,
                        &mut urgent,
                        &store,
                        &notify,
                        &cfg,
                    );
                    continue;
                }
                if let Err(error) =
                    admission.start(job, remote_serial, current, &tsig_keys, timeout)
                {
                    let (job, error) = *error;
                    complete_secondary_refresh(
                        job,
                        Err(error),
                        &mut entries,
                        &mut sched,
                        &mut cat_state,
                        &mut ready,
                        &mut xfr_origins,
                        &mut urgent,
                        &store,
                        &notify,
                        &cfg,
                    );
                }
            }

            let max_active = secondary_refresh_parallelism(entries.len());
            loop {
                if active.len() >= max_active || prepared.is_empty() {
                    break;
                }
                let background_limit = if max_active > 1 { max_active - 1 } else { 1 };
                let candidate = prepared
                    .iter()
                    .position(|transfer| {
                        transfer.job.priority || urgent.contains(&transfer.job.entry.origin)
                    })
                    .or_else(|| (active.len() < background_limit).then_some(0));
                let Some(candidate) = candidate else { break };
                let Some(transfer) = prepared.remove(candidate) else {
                    continue;
                };
                let mut job = transfer.job;
                if !secondary_entry_is_current(&entries, &job) {
                    xfr_origins.remove(&job.entry.origin);
                    continue;
                }
                job.priority |= urgent.contains(&job.entry.origin);
                let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        complete_secondary_refresh(
                            job,
                            Err("보조 DNS 영역 이름의 형식이 잘못되었습니다".to_string()),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &notify,
                            &cfg,
                        );
                        continue;
                    }
                };
                let latest_current = if job.entry.is_catalog {
                    None
                } else {
                    store.load().zone_exact(&origin).cloned()
                };
                let latest_serial = if job.entry.is_catalog {
                    cat_state
                        .get(&job.entry.origin)
                        .map(|(serial, _)| *serial)
                } else {
                    latest_current.as_ref().map(|zone| zone.soa().serial)
                };
                if latest_serial != job.current_serial {
                    job.current_serial = latest_serial;
                    job.had_zone = latest_current.is_some();
                    if let Some(zone) = &latest_current {
                        job.refresh = zone.soa().refresh as u64;
                        job.retry = zone.soa().retry as u64;
                        job.expire = zone.soa().expire as u64;
                    }
                    if secondary_needs_transfer(&job, transfer.remote_serial) {
                        if job.priority {
                            ready.push_front((job, transfer.remote_serial));
                        } else {
                            ready.push_back((job, transfer.remote_serial));
                        }
                    } else {
                        complete_secondary_refresh(
                            job,
                            Ok(SecondaryXferOutcome::UpToDate),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &notify,
                            &cfg,
                        );
                    }
                    continue;
                }
                let task_entry = job.entry.clone();
                let task_keys = tsig_keys.clone();
                let handle = std::thread::Builder::new()
                    .name("secondary-xfer".into())
                    .stack_size(SECONDARY_XFER_STACK_BYTES)
                    .spawn(move || {
                        run_prepared_secondary_transfer(
                            &task_entry,
                            transfer.current.as_ref(),
                            transfer.remote_serial,
                            &task_keys,
                            transfer.io,
                            transfer.reservation,
                        )
                    });
                match handle {
                    Ok(handle) => {
                        active.push(ActiveSecondaryXfer { job, handle });
                    }
                    Err(error) => {
                        let origin = job.entry.origin.clone();
                        complete_secondary_refresh(
                            job,
                            Err(format!("보조 DNS 영역 전송 작업을 시작하지 못했습니다: {error}")),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &notify,
                            &cfg,
                        );
                        onetdns_core::warn!(event = "authority.secondary_worker_spawn_failed", origin = %origin, %error, "보조 DNS 영역 전송 작업을 시작하지 못했습니다");
                        break;
                    }
                }
            }

            let wait = if active.is_empty()
                && admission.len() == 0
                && prepared.is_empty()
                && ready.is_empty()
                && prober.len() == 0
            {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(20)
            };
            let now = unix_now();
            for origin in kick.wait_take(wait) {
                if let Some(schedule) = sched.get_mut(&origin) {
                    schedule.0 = now;
                    urgent.insert(origin);
                }
            }
        }

        for transfer in active {
            let _ = transfer.handle.join();
        }
        })
}

/** @brief 영역 파일 디렉터리를 지켜보고 바뀌면 다시 올린다. */
fn spawn_zones_dir_watcher(
    dir: std::path::PathBuf,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    notify: NotifySender,
    zonemd: ZonemdPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    retire: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zones-dir-watch".into())
        .spawn(move || {
        use onetdns_authority::{DirZoneSource, ZoneSource};
        let src = DirZoneSource::new(dir.clone());
        let mut last = std::time::SystemTime::now();
        let mut prev_origins: Vec<String> = Vec::new();
        loop {
            if sleep_or_retire(10, &shutdown, &retire) {
                break;
            }
            if !src.changed_since(last) {
                continue;
            }
            last = std::time::SystemTime::now();
            match src.load() {
                Ok(new_store) => {
                    let new_origins: Vec<String> =
                        new_store.zones().iter().map(|z| z.origin().to_ascii_lower()).collect();

                    for gone in prev_origins.iter().filter(|o| !new_origins.contains(o)) {
                        if let Ok(n) = onetdns_proto::Name::from_str(gone) {
                            remove_zone(&store, &n);
                            onetdns_core::info!(event = "authority.zone_file_removed", origin = %gone, "영역 파일이 삭제되어 DNS 영역을 제거했습니다");
                        }
                    }

                    let current = store.load();
                    for z in new_store.zones().iter().filter(|z| zonemd_ok(z, zonemd)) {
                        let changed = current
                            .zones()
                            .iter()
                            .find(|old| old.origin().eq_ignore_case(z.origin()))
                            .is_none_or(|old| old.soa().serial != z.soa().serial);
                        swap_zone(&store, z.clone());
                        if changed {
                            notify.enqueue_zone(z);
                        }
                    }
                    onetdns_core::info!(event = "authority.zones_reloaded_dir", dir = %dir.display(), zones = new_origins.len(), "실행 중인 DNS 영역 구성을 디렉터리의 최신 내용으로 교체했습니다");
                    prev_origins = new_origins;
                }
                Err(e) => {
                    onetdns_core::warn!(event = "authority.zone_dir_reload_failed", dir = %dir.display(), error = %e, "DNS 영역 디렉터리를 다시 읽지 못해 기존 영역을 유지합니다")
                }
            }
        }
        })
}

/**
 * @brief 지금 실행 중인 영역 원본 감시 작업들.
 *
 * @details 원본마다 종료 신호를 하나씩 가지고 있어서, 설정에서 빠진 원본의 감시만 멈추고
 *          새로 생긴 원본의 감시를 시작할 수 있다. 서버를 내렸다 올리지 않는다.
 */
#[derive(Default)]
struct ZoneWatchers {
    /** @brief 원본 이름과 그 감시를 멈출 신호. */
    running: Mutex<Vec<(String, Arc<std::sync::atomic::AtomicBool>)>>,
}

/**
 * @brief 설정에 적힌 영역 원본들을 이름으로 늘어놓는다.
 *
 * @details 이름이 같으면 같은 원본이다. 이름이 달라지면 이전 감시를 멈추고 새로 시작한다.
 * @return (이름, 그 원본을 만드는 함수) 목록. 만들지 못하는 원본은 이름만 남고 함수가 없다.
 */
fn zone_source_specs(
    cfg: &Config,
) -> Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> {
    let mut specs: Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> = Vec::new();
    if let Some(db) = &cfg.zones_db {
        specs.push((
            format!("sqlite:{}:{}", db.display(), cfg.zones_db_table),
            Some(Arc::new(onetdns_authority::SqliteZoneSource::with_table(
                db.clone(),
                cfg.zones_db_table.clone(),
            ))),
        ));
    }
    if let Some(endpoint) = &cfg.zones_etcd {
        let credentials = format!(
            "{}\n{}",
            cfg.zones_etcd_password
                .as_ref()
                .map(|password| password.as_str())
                .unwrap_or(""),
            cfg.zones_etcd_ca
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        );
        let key = format!(
            "etcd:{endpoint}:{}:{}:{}",
            cfg.zones_etcd_prefix,
            cfg.zones_etcd_user.as_deref().unwrap_or(""),
            private_resource_id("etcd-source", &credentials)
        );
        specs.push((
            key,
            build_etcd_source(cfg)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(url) = &cfg.zones_postgres {
        let redacted = onetdns_config::redact_url_credentials(url.as_str());
        let identity = private_resource_id("postgres-source", url.as_str());
        specs.push((
            format!("postgres:{redacted}:{identity}:{}", cfg.zones_sql_table),
            onetdns_authority::PostgresZoneSource::from_url(url, &cfg.zones_sql_table)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(url) = &cfg.zones_mysql {
        let redacted = onetdns_config::redact_url_credentials(url.as_str());
        let identity = private_resource_id("mysql-source", url.as_str());
        specs.push((
            format!("mysql:{redacted}:{identity}:{}", cfg.zones_sql_table),
            onetdns_authority::MysqlZoneSource::from_url(url, &cfg.zones_sql_table)
                .map(|src| Arc::new(src) as Arc<dyn onetdns_authority::ZoneSource>),
        ));
    }
    if let Some(path) = &cfg.zones_lmdb {
        specs.push((
            format!("lmdb:{}", path.display()),
            Some(Arc::new(onetdns_authority::LmdbZoneSource::new(
                path.clone(),
            ))),
        ));
    }
    specs
}

/**
 * @brief 설정에 맞춰 영역 원본 감시를 시작하고 멈춘다.
 *
 * @details 시작할 때와 설정을 교체할 때 모두 이 함수만 부른다. 두 곳에서 따로 시작하면
 *          교체한 뒤 이전 원본을 보는 감시가 남아 지운 영역이 되살아난다.
 * @param cfg      맞출 설정.
 * @param watchers 지금 실행 중인 감시들.
 * @return 원본 주소가 틀려 시작하지 못한 것이 있으면 실패. 이미 뜬 것은 그대로 둔다.
 */
fn reconcile_zone_watchers(
    cfg: &Config,
    watchers: &ZoneWatchers,
    store: &Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    notify: &NotifySender,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    tracker: &Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let mut wanted: Vec<(String, Option<Arc<dyn onetdns_authority::ZoneSource>>)> =
        zone_source_specs(cfg);
    if let Some(dir) = &cfg.zones_dir {
        wanted.push((format!("dir:{}", dir.display()), None));
    }
    let zonemd = ZonemdPolicy::of(cfg);
    let zonemd_tag = format!("#zonemd={}{}", zonemd.check, zonemd.reject_absence);

    let mut running = watchers.running.lock_recover();
    running.retain(|(key, retire)| {
        let keep = wanted
            .iter()
            .any(|(want, _)| format!("{want}{zonemd_tag}") == *key);
        if !keep {
            retire.store(true, Ordering::Release);
            onetdns_core::info!(
                event = "authority.source_watch_retired",
                source = %key,
                "설정에서 빠진 DNS 영역 원본의 감시를 멈췄습니다"
            );
        }
        keep
    });

    for (key, source) in wanted {
        let tagged = format!("{key}{zonemd_tag}");
        if running.iter().any(|(have, _)| have == &tagged) {
            continue;
        }
        let retire = Arc::new(AtomicBool::new(false));
        let thread = if let Some(dir) = key.strip_prefix("dir:") {
            spawn_zones_dir_watcher(
                std::path::PathBuf::from(dir),
                store.clone(),
                notify.clone(),
                ZonemdPolicy::of(cfg),
                shutdown.clone(),
                retire.clone(),
            )
        } else {
            let Some(source) = source else {
                return Err(format!("DNS 영역 원본 '{key}'의 주소가 올바르지 않습니다"));
            };
            spawn_zone_source_watcher(
                source,
                store.clone(),
                notify.clone(),
                ZonemdPolicy::of(cfg),
                shutdown.clone(),
                retire.clone(),
            )
        }
        .map_err(|error| format!("DNS 영역 감시 작업을 시작하지 못했습니다: {error}"))?;
        track_service_thread(tracker, thread);
        onetdns_core::info!(
            event = "authority.source_watch_started",
            source = %key,
            "DNS 영역 원본 감시를 시작했습니다"
        );
        running.push((tagged, retire));
    }
    Ok(())
}

/** @brief 외부 저장소에서 영역을 읽는 곳을 만든다. */
fn build_etcd_source(cfg: &Config) -> Option<onetdns_authority::EtcdZoneSource> {
    let ep = cfg.zones_etcd.as_ref()?;
    let mut src = onetdns_authority::EtcdZoneSource::new(ep.clone(), cfg.zones_etcd_prefix.clone());
    let (host, port) = match src.endpoint_host_port() {
        Ok(parts) => parts,
        Err(error) => {
            onetdns_core::error!(event = "authority.etcd_addr_invalid", endpoint = %ep, %error, "etcd 서버 주소의 형식이 잘못되었습니다");
            return None;
        }
    };
    let ip = if host.eq_ignore_ascii_case("localhost") {
        std::net::Ipv4Addr::LOCALHOST.into()
    } else {
        match upstream::resolve_host_via_bootstrap(&host, &cfg.bootstrap) {
            Some(ip) => ip,
            None => {
                onetdns_core::error!(event = "authority.etcd_bootstrap_missing", endpoint = %ep, %host, "etcd 서버 이름을 찾지 못했습니다. bootstrap 설정이 필요합니다");
                return None;
            }
        }
    };
    src = src.with_connect_addr(SocketAddr::new(ip, port));
    if let Some(ca) = &cfg.zones_etcd_ca {
        match read_bytes_limited(ca, LOCAL_CA_MAX_BYTES) {
            Ok(pem) => {
                let store = match onetdns_tls::TrustStore::try_from_pem(&pem) {
                    Ok(store) => store,
                    Err(error) => {
                        onetdns_core::error!(event = "authority.etcd_ca_invalid", ca = %ca.display(), %error, "etcd TLS CA 파일에 손상됐거나 지원하지 않는 형식의 인증서가 있습니다");
                        return None;
                    }
                };
                src = src.with_tls(store);
            }
            Err(e) => {
                onetdns_core::error!(event = "authority.etcd_ca_read_failed", ca = %ca.display(), error = %e, "etcd TLS CA 파일을 읽지 못했습니다");
                return None;
            }
        }
    }
    if let (Some(user), Some(pass)) = (&cfg.zones_etcd_user, &cfg.zones_etcd_password) {
        src = src.with_auth(user.clone(), pass.clone());
    }
    Some(src)
}

/** @brief 외부 저장소를 지켜보고 바뀌면 다시 올린다. */
fn spawn_zone_source_watcher(
    src: std::sync::Arc<dyn onetdns_authority::ZoneSource>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    notify: NotifySender,
    zonemd: ZonemdPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    retire: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zone-source-watch".into())
        .spawn(move || {
        let mut last = std::time::SystemTime::now();

        let mut prev_origins: Vec<String> = match src.load() {
            Ok(s) => s.zones().iter().map(|z| z.origin().to_ascii_lower()).collect(),
            Err(error) => {
                onetdns_core::error!(event = "authority.source_initial_load_failed", source = %src.describe(), %error, "저장소에서 DNS 영역을 처음 읽지 못했습니다. 이 저장소의 영역은 아직 응답하지 않습니다");
                Vec::new()
            }
        };
        let mut consecutive_failures = 0u64;
        loop {
            if sleep_or_retire(10, &shutdown, &retire) {
                break;
            }
            if !src.changed_since(last) {
                continue;
            }
            last = std::time::SystemTime::now();
            match src.load() {
                Ok(new_store) => {
                    if consecutive_failures > 0 {
                        onetdns_core::info!(event = "authority.source_recovered", source = %src.describe(), failures = consecutive_failures, "저장소를 다시 읽을 수 있게 되었습니다");
                        consecutive_failures = 0;
                    }
                    let new_origins: Vec<String> =
                        new_store.zones().iter().map(|z| z.origin().to_ascii_lower()).collect();
                    for gone in prev_origins.iter().filter(|o| !new_origins.contains(o)) {
                        if let Ok(n) = onetdns_proto::Name::from_str(gone) {
                            remove_zone(&store, &n);
                            onetdns_core::info!(event = "authority.zone_removed_source", origin = %gone, source = %src.describe(), "원본에서 삭제된 DNS 영역을 제거했습니다");
                        }
                    }
                    let current = store.load();
                    for z in new_store.zones().iter().filter(|z| zonemd_ok(z, zonemd)) {
                        let changed = current
                            .zones()
                            .iter()
                            .find(|old| old.origin().eq_ignore_case(z.origin()))
                            .is_none_or(|old| old.soa().serial != z.soa().serial);
                        swap_zone(&store, z.clone());
                        if changed {
                            notify.enqueue_zone(z);
                        }
                    }
                    onetdns_core::info!(event = "authority.zones_reloaded_source", source = %src.describe(), zones = new_origins.len(), "실행 중인 DNS 영역 구성을 저장소의 최신 내용으로 교체했습니다");
                    prev_origins = new_origins;
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures == 1 || consecutive_failures % 60 == 0 {
                        onetdns_core::warn!(event = "authority.source_reload_failed", source = %src.describe(), error = %e, failures = consecutive_failures, "DNS 영역 저장소를 다시 읽지 못해 기존 영역을 유지합니다");
                    }
                }
            }
        }
        })
}

/** @brief 응답에서 시리얼을 읽는다. */
fn soa_serial_from_response(
    response: &onetdns_proto::Message,
    request_id: u16,
    origin: &onetdns_proto::Name,
) -> Result<u32, String> {
    use onetdns_proto::{DnsClass, RData, RecordType, ResponseCode};

    if !soa_response_matches_question(response, request_id, origin)
        || !response.header.response
        || response.header.opcode != 0
        || response.header.rcode != ResponseCode::NoError.0
        || !response.header.authoritative
        || response.header.truncated
    {
        return Err("SOA 응답의 헤더와 질의 정보가 요청과 일치하지 않습니다".to_string());
    }
    let mut serials = response.answers.iter().filter_map(|record| {
        if record.name.eq_ignore_case(origin)
            && record.rtype == RecordType::SOA
            && record.class == DnsClass::IN
        {
            match &record.rdata {
                RData::Soa(soa) => Some(soa.serial),
                _ => None,
            }
        } else {
            None
        }
    });
    let serial = serials
        .next()
        .ok_or_else(|| "SOA 응답에 영역 최상위 SOA가 없습니다".to_string())?;
    if serials.next().is_some() {
        return Err("SOA 응답에 apex SOA가 중복됨".to_string());
    }
    Ok(serial)
}

/** @brief 이 응답이 이 서버가 물은 것에 대한 답인지. 확인하지 않으면 남이 끼워 넣은 시리얼을 믿는다. */
fn soa_response_matches_question(
    response: &onetdns_proto::Message,
    request_id: u16,
    origin: &onetdns_proto::Name,
) -> bool {
    use onetdns_proto::{DnsClass, RecordType};

    response.header.id == request_id
        && response.questions.len() == 1
        && response.questions[0].name.eq_ignore_case(origin)
        && response.questions[0].qtype == RecordType::SOA
        && response.questions[0].qclass == DnsClass::IN
}

/** @brief 시리얼이 더 새것인지. 한 바퀴 도는 값이라 크기만 비교하면 안 된다. */
fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

/** @brief 영역 하나를 교체한다. */
fn swap_zone(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    zone: onetdns_authority::Zone,
) {
    store.update(|current| {
        let mut next = onetdns_authority::ZoneStore::new();
        for current_zone in current.zones() {
            if !current_zone.origin().eq_ignore_case(zone.origin()) {
                next.add(current_zone.clone());
            }
        }
        next.add(zone);
        next
    });
}

/** @brief 영역 하나를 뺀다. */
fn remove_zone(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    origin: &onetdns_proto::Name,
) {
    store.update(|current| {
        let mut next = onetdns_authority::ZoneStore::new();
        for zone in current.zones() {
            if !zone.origin().eq_ignore_case(origin) {
                next.add(zone.clone());
            }
        }
        next
    });
}

/** @brief 영역을 고친 결과. */
struct ZoneApplyResult {
    /** @brief 고친 영역의 이름. */
    origin: String,
    /** @brief 고친 뒤의 시리얼. */
    serial: u32,
    /** @brief 고친 뒤의 기록 수. */
    records: usize,
    /** @brief 파일에 저장했는지. */
    persisted: bool,
    /** @brief 다시 서명했는지. */
    signed: bool,
}

/** @brief 기록 하나를 사람이 읽을 문자열로. */
fn zone_record_value(record: &onetdns_proto::Record) -> String {
    let line = onetdns_authority::record_to_master_line(record);
    line.trim_end()
        .splitn(5, ' ')
        .nth(4)
        .unwrap_or("")
        .to_string()
}

/**
 * @brief 기록 하나를 JSON으로.
 * @invariant 이름은 끝에 점을 붙인 절대 이름으로 낸다. 레코드 삭제 API는 점 없는 이름을
 *            영역 기준 상대 이름으로 읽는다. 목록이 점 없이 내보내면 목록에서 받은 이름을
 *            그대로 돌려준 삭제가 영역 이름이 두 번 붙은 이름을 찾아 늘 실패한다.
 */
fn zone_record_json(record: &onetdns_proto::Record) -> String {
    format!(
        "{{\"name\":{},\"type\":{},\"ttl\":{},\"value\":{}}}",
        onetdns_core::json::escape(&format!("{}.", record.name.to_ascii_lower())),
        onetdns_core::json::escape(record.rtype.name()),
        record.ttl,
        onetdns_core::json::escape(&zone_record_value(record))
    )
}

/** @brief 끝맺음 권한 기록을 뺀 기록들. */
fn zone_records_without_closing_soa(zone: &onetdns_authority::Zone) -> Vec<onetdns_proto::Record> {
    let mut recs = zone.axfr_records();
    recs.pop();
    recs
}

/** @brief 내용이 바뀌었으면 시리얼을 올린다. 올리지 않으면 하위 서버가 바뀐 줄 모른다. */
fn bump_soa_serial_if_needed(recs: &mut [onetdns_proto::Record], old_serial: Option<u32>) {
    let Some(old) = old_serial else { return };
    for r in recs.iter_mut() {
        if r.rtype == onetdns_proto::RecordType::SOA {
            if let onetdns_proto::RData::Soa(soa) = &mut r.rdata {
                if !serial_gt(soa.serial, old) {
                    soa.serial = old.wrapping_add(1);
                }
            }
            break;
        }
    }
}

/** @brief 오래 걸리는 작업들의 진행 상황. */
struct JobRegistry {
    /** @brief 지금 아는 작업들. */
    jobs: std::sync::Mutex<std::collections::HashMap<u64, Job>>,
    /** @brief 다음 작업 번호. */
    next: std::sync::atomic::AtomicU64,
    /** @brief 담아 둘 작업 수. */
    cap: usize,
}

#[derive(Clone)]
/** @brief 작업 하나. */
struct Job {
    /** @brief 작업 번호. */
    id: u64,
    /** @brief 무슨 작업인지. */
    kind: String,
    /** @brief 실행 중인지 끝났는지. */
    status: &'static str,
    /** @brief 시작한 시각. */
    created: u64,
    /** @brief 끝난 시각. 아직이면 없다. */
    finished: Option<u64>,
    /** @brief 끝난 뒤의 결과 문구. */
    result: String,
}

impl JobRegistry {
    /** @brief 담아 둘 개수를 정해 만든다. */
    fn new(cap: usize) -> Self {
        JobRegistry {
            jobs: std::sync::Mutex::new(std::collections::HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
            cap: cap.max(1),
        }
    }

    /** @brief 작업을 시작한다. 이미 실행 중인 것이 있으면 시작하지 않는다. */
    fn create(&self, kind: &str) -> Option<u64> {
        use std::sync::atomic::Ordering;
        let mut g = self.jobs.lock_recover();
        if g.len() >= self.cap {
            if let Some(&oldest) = g
                .iter()
                .filter(|(_, j)| j.status != "running")
                .map(|(k, _)| k)
                .min()
            {
                g.remove(&oldest);
            } else {
                return None;
            }
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        g.insert(
            id,
            Job {
                id,
                kind: kind.to_string(),
                status: "running",
                created: unix_now(),
                finished: None,
                result: String::new(),
            },
        );
        Some(id)
    }

    /** @brief 작업이 끝났다고 적는다. */
    fn finish(&self, id: u64, ok: bool, result: String) {
        if let Some(j) = self.jobs.lock_recover().get_mut(&id) {
            j.status = if ok { "done" } else { "failed" };
            j.finished = Some(unix_now());
            j.result = result;
        }
    }

    /** @brief 작업 하나를 JSON으로. */
    fn job_json(j: &Job) -> String {
        format!(
            "{{\"id\":{},\"kind\":{},\"status\":\"{}\",\"created\":{},\"finished\":{},\"result\":{}}}",
            j.id,
            onetdns_core::json::escape(&j.kind),
            j.status,
            j.created,
            j.finished.map(|f| f.to_string()).unwrap_or_else(|| "null".to_string()),
            onetdns_core::json::escape(&j.result)
        )
    }

    /** @brief 작업 목록을 JSON으로. */
    fn list_json(&self) -> String {
        let g = self.jobs.lock_recover();
        let mut items: Vec<&Job> = g.values().collect();
        items.sort_by_key(|j| std::cmp::Reverse(j.id));
        format!(
            "[{}]",
            items
                .iter()
                .map(|j| Self::job_json(j))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /** @brief 이 작업을 JSON으로. */
    fn get_json(&self, id: u64) -> Option<String> {
        self.jobs.lock_recover().get(&id).map(Self::job_json)
    }
}

/** @brief 기다리되 종료 신호가 오면 곧장 돌아온다. */
fn sleep_or_shutdown(secs: u64, shutdown: &std::sync::atomic::AtomicBool) -> bool {
    use std::sync::atomic::Ordering;
    for _ in 0..(secs.saturating_mul(2)) {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    shutdown.load(Ordering::Relaxed)
}

/**
 * @brief 서버가 내려가거나 이 작업 하나만 물러날 때까지 쉰다.
 *
 * @details 설정에서 원본이 빠지면 그 감시 작업만 종료해야 한다. 서버 전체 종료 신호와
 *          작업별 종료 신호를 함께 본다.
 * @return 둘 중 하나라도 서면 참. 그때는 반복을 끝내야 한다.
 */
fn sleep_or_retire(
    secs: u64,
    shutdown: &std::sync::atomic::AtomicBool,
    retire: &std::sync::atomic::AtomicBool,
) -> bool {
    use std::sync::atomic::Ordering;
    for _ in 0..(secs.saturating_mul(2)) {
        if shutdown.load(Ordering::Relaxed) || retire.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    shutdown.load(Ordering::Relaxed) || retire.load(Ordering::Relaxed)
}

/** @brief 공유 DHCP 임대 수명을 두 wire 형식의 32비트 값으로 손실 없이 바꾼다. */
fn wire_dhcp_lease_secs(value: u64) -> Result<u32, String> {
    let value = u32::try_from(value).map_err(|_| {
        "dhcp_lease_secs는 DHCP wire 범위인 4294967295초 이하여야 합니다".to_string()
    })?;
    if value == 0 {
        return Err("dhcp_lease_secs는 1초 이상이어야 합니다".to_string());
    }
    Ok(value)
}

/** @brief 설정에서 DHCPv4 설정을 만든다. */
fn build_dhcp_config(cfg: &Config) -> Result<dhcp::DhcpConfig, String> {
    use std::net::Ipv4Addr;
    let p = |o: &Option<String>, name: &str| -> Result<Ipv4Addr, String> {
        o.as_deref()
            .ok_or_else(|| format!("{name} 값을 입력해야 합니다"))?
            .parse()
            .map_err(|_| format!("{name} 값의 형식이 올바르지 않습니다"))
    };
    let opt = |o: &Option<String>, name: &str, default: Ipv4Addr| -> Result<Ipv4Addr, String> {
        match o.as_deref() {
            None => Ok(default),
            Some(s) => s
                .parse()
                .map_err(|_| format!("{name} 값의 형식이 올바르지 않습니다")),
        }
    };
    let server_ip = p(&cfg.dhcp_server_ip, "dhcp_server_ip")?;
    let range_start = p(&cfg.dhcp_range_start, "dhcp_range_start")?;
    let range_end = p(&cfg.dhcp_range_end, "dhcp_range_end")?;
    let subnet_mask = opt(
        &cfg.dhcp_subnet_mask,
        "dhcp_subnet_mask",
        Ipv4Addr::new(255, 255, 255, 0),
    )?;
    let router = opt(&cfg.dhcp_router, "dhcp_router", server_ip)?;

    if u32::from(range_start) > u32::from(range_end) {
        return Err("dhcp_range_start는 dhcp_range_end보다 작거나 같아야 합니다".to_string());
    }
    let mask = u32::from(subnet_mask);

    let inv = !mask;
    if mask == 0 || (inv & inv.wrapping_add(1)) != 0 {
        return Err(
            "dhcp_subnet_mask에는 연속된 비트로 이루어진 올바른 넷마스크를 입력해야 합니다"
                .to_string(),
        );
    }
    let net = u32::from(server_ip) & mask;
    let bcast = net | inv;
    let in_subnet = |ip: Ipv4Addr| (u32::from(ip) & mask) == net;
    for (ip, name) in [
        (range_start, "dhcp_range_start"),
        (range_end, "dhcp_range_end"),
    ] {
        if !in_subnet(ip) {
            return Err(format!(
                "{name} 주소가 DHCP 서버 서브넷({})에 속하지 않습니다",
                Ipv4Addr::from(net)
            ));
        }
        let v = u32::from(ip);
        if v == net || v == bcast {
            return Err(format!("{name}가 네트워크/브로드캐스트 주소"));
        }
    }
    if !in_subnet(router) {
        return Err("dhcp_router 주소가 DHCP 서버 서브넷에 속하지 않습니다".to_string());
    }
    let in_range = |ip: Ipv4Addr| {
        let value = u32::from(ip);
        value >= u32::from(range_start) && value <= u32::from(range_end)
    };
    for (ip, name) in [(server_ip, "dhcp_server_ip"), (router, "dhcp_router")] {
        if in_range(ip) {
            return Err(format!(
                "{name} 주소는 DHCP 동적 할당 범위에 포함될 수 없습니다"
            ));
        }
    }
    let static_file = cfg.dhcp_static_file.as_ref().map(std::path::PathBuf::from);
    if let Some(path) = &static_file {
        dhcp::read_reservations(path)?;
    }
    let dns: Vec<Ipv4Addr> =
        if cfg.dhcp_dns.is_empty() {
            vec![server_ip]
        } else {
            let mut out = Vec::with_capacity(cfg.dhcp_dns.len());
            for s in &cfg.dhcp_dns {
                out.push(s.parse().map_err(|_| {
                    format!("dhcp_dns 항목에 올바른 IPv4 주소를 입력해야 합니다: {s}")
                })?);
            }
            out
        };
    Ok(dhcp::DhcpConfig {
        server_ip,
        range_start,
        range_end,
        subnet_mask,
        router,
        dns,
        lease_secs: wire_dhcp_lease_secs(cfg.dhcp_lease_secs)?,
        tftp_server: cfg.dhcp_tftp_server.as_deref().and_then(|s| s.parse().ok()),
        boot_file: cfg.dhcp_boot_file.clone(),
        domain_name: (!cfg.dhcp_local_domain.is_empty())
            .then(|| cfg.dhcp_local_domain.trim_end_matches('.').to_string()),
        lease_file: cfg.dhcp_lease_file.as_ref().map(std::path::PathBuf::from),
        static_file,
    })
}

/**
 * @brief 설정에서 라우터 광고 설정을 만든다.
 * @return ra_prefix가 없거나 읽을 수 없으면 실패. 값의 범위는 설정 검사가 이미 거른다.
 */
fn build_ra_config(cfg: &Config) -> Result<ra::RaConfig, String> {
    let missing = || "ra_enable에는 fd00:1::/64 처럼 적은 ra_prefix가 필요합니다".to_string();
    let spec = cfg.ra_prefix.as_deref().ok_or_else(missing)?;
    let (addr_s, len_s) = spec.split_once('/').ok_or_else(missing)?;
    let prefix: std::net::Ipv6Addr = addr_s.trim().parse().map_err(|_| missing())?;
    let prefix_len: u8 = len_s
        .trim()
        .parse()
        .ok()
        .filter(|l| *l <= 128)
        .ok_or_else(missing)?;
    Ok(ra::RaConfig {
        prefix,
        prefix_len,
        managed: cfg.ra_managed,
        other: cfg.ra_other,
        router_lifetime: cfg.ra_router_lifetime,
        valid_lifetime: 86_400,
        preferred_lifetime: 14_400,
        mtu: (cfg.ra_mtu != 0).then_some(cfg.ra_mtu),
        source_mac: None,
        interval: cfg.ra_interval,
        interface_index: cfg.ra_interface_index,
    })
}

/**
 * @brief 설정에서 DHCPv6 설정을 만든다.
 * @note 서버 식별자 파일을 만들 수 있다. 검사만 할 때는 dhcp6_addresses를 쓴다.
 */
fn build_dhcp6_config(cfg: &Config) -> Result<dhcp6::Dhcp6Config, String> {
    let (range_start, range_end, dns) = dhcp6_addresses(cfg)?;
    Ok(dhcp6::Dhcp6Config {
        server_duid: load_or_create_server_duid6(cfg.dhcp6_lease_file.as_deref())?,
        range_start,
        range_end,
        dns,
        interface_index: cfg.dhcp6_interface_index,
        lease_secs: wire_dhcp_lease_secs(cfg.dhcp_lease_secs)?,
        lease_file: cfg.dhcp6_lease_file.as_ref().map(std::path::PathBuf::from),
    })
}

/**
 * @brief DHCPv6 범위와 알릴 DNS 서버를 읽는다. 파일은 건드리지 않는다.
 * @return (범위 시작, 범위 끝, DNS 서버). 주소를 읽을 수 없거나 범위가 뒤집혔으면 실패.
 */
#[allow(clippy::type_complexity)]
fn dhcp6_addresses(
    cfg: &Config,
) -> Result<
    (
        std::net::Ipv6Addr,
        std::net::Ipv6Addr,
        Vec<std::net::Ipv6Addr>,
    ),
    String,
> {
    use std::net::Ipv6Addr;
    let p = |o: &Option<String>, name: &str| -> Result<Ipv6Addr, String> {
        o.as_deref()
            .ok_or_else(|| format!("{name} 값을 입력해야 합니다"))?
            .parse()
            .map_err(|_| format!("{name} 값의 형식이 올바르지 않습니다"))
    };
    let range_start = p(&cfg.dhcp6_range_start, "dhcp6_range_start")?;
    let range_end = p(&cfg.dhcp6_range_end, "dhcp6_range_end")?;
    if u128::from(range_start) > u128::from(range_end) {
        return Err(
            "`dhcp6_range_start`는 `dhcp6_range_end`보다 작거나 같은 주소여야 합니다".to_string(),
        );
    }
    let dns = cfg
        .dhcp6_dns
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|_| format!("dhcp6_dns 항목에는 IPv6 주소를 입력해야 합니다: {s}"))
        })
        .collect::<Result<Vec<Ipv6Addr>, String>>()?;
    Ok((range_start, range_end, dns))
}

/**
 * @brief 켜 둔 가장자리 서비스가 뜰 수 있는 설정인지 파일을 만들지 않고 가린다.
 * @note 저장 파일은 디렉터리만 본다. 없으면 DHCPv4는 임대를 잃고 DHCPv6는 뜨지 않는다.
 */
fn edge_service_preflight(cfg: &Config) -> Result<(), String> {
    let parent_exists = |path: &Option<String>, key: &str| -> Result<(), String> {
        let Some(path) = path else { return Ok(()) };
        let parent = std::path::Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        if parent.is_dir() {
            Ok(())
        } else {
            Err(format!(
                "{key}를 둘 디렉터리가 없습니다: {}",
                parent.display()
            ))
        }
    };
    if cfg.dhcp_enable {
        build_dhcp_config(cfg)?;
        parent_exists(&cfg.dhcp_lease_file, "dhcp_lease_file")?;
        parent_exists(&cfg.dhcp_static_file, "dhcp_static_file")?;
    }
    if cfg.dhcp6_enable {
        dhcp6_addresses(cfg)?;
        parent_exists(&cfg.dhcp6_lease_file, "dhcp6_lease_file")?;
    }
    if cfg.ra_enable {
        build_ra_config(cfg)?;
    }
    if cfg.tftp_enable {
        let root = cfg
            .tftp_root
            .as_deref()
            .ok_or("tftp_enable에는 tftp_root가 필요합니다")?;
        if !std::path::Path::new(root).is_dir() {
            return Err(format!("tftp_root 디렉터리가 없습니다: {root}"));
        }
        if std::net::UdpSocket::bind((cfg.tftp_listen.ip(), 0)).is_err() {
            return Err(format!(
                "tftp_listen 주소 {}는 이 기기에 없는 주소입니다",
                cfg.tftp_listen.ip()
            ));
        }
    }
    #[cfg(unix)]
    for (enabled, index, key) in [
        (cfg.ra_enable, cfg.ra_interface_index, "ra_interface_index"),
        (
            cfg.dhcp6_enable,
            cfg.dhcp6_interface_index,
            "dhcp6_interface_index",
        ),
    ] {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        /* @safety 버퍼는 IF_NAMESIZE 바이트이고 함수는 그 안에만 쓴다. */
        if enabled
            && index != 0
            && unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null()
        {
            return Err(format!("{key} {index}번 네트워크 인터페이스가 없습니다"));
        }
    }
    if cfg.dhcp_enable || cfg.dhcp6_enable {
        if let Some(path) = cfg.mac_vendor_db.as_deref() {
            if !std::path::Path::new(path).is_file() {
                return Err(format!("mac_vendor_db 파일이 없습니다: {path}"));
            }
        }
    }
    Ok(())
}

/** @brief 서버 식별자를 읽거나 만든다. 재시작해도 같은 것을 써야 클라이언트가 이 서버를 알아본다. */
fn load_or_create_server_duid6(lease_file: Option<&str>) -> Result<Vec<u8>, String> {
    let generate = || {
        let mut seed = [0u8; 6];
        onetdns_tls::sys::fill_random(&mut seed);
        dhcp6::make_server_duid(&seed)
    };
    let Some(lease_file) = lease_file else {
        return Ok(generate());
    };
    let path = std::path::PathBuf::from(format!("{lease_file}.duid"));
    match read_text_limited(&path, 4096) {
        Ok(text) => {
            if let Some(duid) = parse_hex_bytes(text.trim()).filter(|duid| dhcp6::valid_duid(duid))
            {
                return Ok(duid);
            }
            onetdns_core::warn!(event = "dhcp6.duid_regenerated", path = %path.display(), "DHCPv6 DUID 파일이 손상되어 새 식별자를 만들었습니다");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "DHCPv6 DUID 파일을 읽지 못했습니다({}): {error}",
                path.display()
            ));
        }
    }
    let duid = generate();
    let hex: String = duid.iter().map(|byte| format!("{byte:02x}")).collect();
    atomic_write(&path, hex.as_bytes()).map_err(|error| {
        format!(
            "DHCPv6 DUID를 파일에 저장하지 못했습니다({}): {error}. 재시작 후 같은 서버 식별자를 유지할 수 없어 DHCPv6를 시작하지 않습니다",
            path.display()
        )
    })?;
    Ok(duid)
}

/** @brief 16진 문자열을 바이트열로. */
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/** @brief DNSCrypt 제공자 키를 둘 경로. */
fn dnscrypt_provider_key_path(
    config_path: &Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    let p = config_path.as_ref()?;
    let dir = p.parent()?;
    Some(dir.join("dnscrypt-provider.key"))
}

/** @brief DNSCrypt 제공자 키를 읽거나 만든다. */
fn load_or_create_dnscrypt_provider(
    cfg: &Config,
    config_path: &Option<std::path::PathBuf>,
    valid_secs: u32,
) -> Result<onetdns_dnscrypt::Provider, String> {
    let path = dnscrypt_provider_key_path(config_path).ok_or_else(|| {
        "DNSCrypt 제공자 키를 저장할 설정 파일 경로가 없습니다. 다시 시작할 때 공개 키가 바뀌는 것을 막기 위해 DNSCrypt를 시작하지 않습니다".to_string()
    })?;
    match read_text_limited(&path, 4096) {
        Ok(text) => {
            let text = zeroize::Zeroizing::new(text);
            if let Some(bytes) = parse_hex_bytes(text.trim()).filter(|bytes| bytes.len() == 32) {
                let bytes = zeroize::Zeroizing::new(bytes);
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                seed.copy_from_slice(&bytes);
                return Ok(onetdns_dnscrypt::Provider::with_signing_seed(
                    &seed,
                    &cfg.dnscrypt_provider_name,
                    valid_secs,
                ));
            }
            return Err(format!(
                "DNSCrypt provider 키 파일이 손상되었습니다({}); 기존 공개키 신뢰를 보존하기 위해 자동 교체하지 않습니다",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "DNSCrypt 공급자 키 파일을 읽지 못했습니다({}): {error}",
                path.display()
            ));
        }
    }

    let provider = onetdns_dnscrypt::Provider::generate(&cfg.dnscrypt_provider_name, valid_secs);
    let seed = provider.signing_seed();
    let mut hex = zeroize::Zeroizing::new(String::with_capacity(64));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in seed.iter() {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    atomic_write_secret(&path, hex.as_bytes()).map_err(|error| {
        format!(
            "DNSCrypt 공급자 키를 파일에 저장하지 못했습니다({}): {error}. 재시작 후 같은 공개 키를 유지할 수 없어 DNSCrypt를 시작하지 않습니다",
            path.display()
        )
    })?;
    Ok(provider)
}

/** @brief 유한 임대와 wire infinity를 JSON에서 모호하지 않게 구별한다. */
fn lease_time_json(expiry: u64, now: u64) -> String {
    if expiry == u64::MAX {
        "\"expires\":null,\"remaining\":null,\"infinite\":true".to_string()
    } else {
        let remaining = expiry.saturating_sub(now);
        format!("\"expires\":{expiry},\"remaining\":{remaining},\"infinite\":false")
    }
}

/** @brief 임대 목록을 JSON으로. */
fn leases_json(
    v4: Option<&Arc<Mutex<dhcp::LeasePool>>>,
    v6: Option<&Arc<Mutex<dhcp6::Lease6Pool>>>,
    vendor: &mac::VendorDb,
) -> String {
    use onetdns_core::MutexExt;
    let now = unix_now();
    let esc = onetdns_core::json::escape;
    let v4_items: Vec<String> = match v4 {
        Some(p) => p
            .lock_recover()
            .snapshot()
            .iter()
            .map(|l| {
                let identity = onetdns_core::json::escape(&l.identity.to_text());
                let mac =
                    l.mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                let vn =
                    vendor.lookup(l.mac).map(esc).unwrap_or_else(|| "null".to_string());
                let host =
                    l.hostname.as_deref().map(esc).unwrap_or_else(|| "null".to_string());
                let time = lease_time_json(l.expiry_unix, now);
                format!(
                    "{{\"ip\":\"{}\",\"identity\":{identity},\"mac\":\"{mac}\",\"vendor\":{vn},\"hostname\":{host},{time}}}",
                    l.ip
                )
            })
            .collect(),
        None => Vec::new(),
    };
    let v6_items: Vec<String> = match v6 {
        Some(p) => p
            .lock_recover()
            .snapshot()
            .iter()
            .map(|l| {
                let duid = l
                    .duid
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let iaid = l
                    .iaid
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let time = lease_time_json(l.expiry_unix, now);
                format!(
                    "{{\"ip\":\"{}\",\"duid\":\"{duid}\",\"iaid\":\"{iaid}\",{time}}}",
                    l.ip
                )
            })
            .collect(),
        None => Vec::new(),
    };
    format!(
        "{{\"v4\":[{}],\"v6\":[{}]}}",
        v4_items.join(","),
        v6_items.join(",")
    )
}

/** @brief 콜론으로 나뉜 하드웨어 주소를 읽는다. */
fn parse_mac_colon(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/**
 * @brief 고정 할당 목록과, 지금 고정 할당을 받을 수 있는지를 함께 돌려준다.
 * @details 고정 할당은 실행 중인 DHCPv4 주소 풀에만 있다. 풀이 없을 때 빈 목록만 돌려주면
 *          할당이 없는 것과 넣을 곳이 없는 것을 구분할 수 없어, 화면이 받지 못할 입력을
 *          받아 놓고 제출한 뒤에야 실패한다.
 */
fn static_reservations_json(pool: Option<&Arc<Mutex<dhcp::LeasePool>>>) -> String {
    use onetdns_core::MutexExt;
    let Some(pool) = pool else {
        return "{\"available\":false,\"reservations\":[]}".to_string();
    };
    let esc = onetdns_core::json::escape;
    let items: Vec<String> = pool
        .lock_recover()
        .reservations()
        .iter()
        .map(|r| {
            let identity = esc(&r.identity.to_text());
            let host = r
                .hostname
                .as_deref()
                .map(esc)
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"ip\":\"{}\",\"identity\":{identity},\"hostname\":{host}}}",
                r.ip
            )
        })
        .collect();
    format!(
        "{{\"available\":true,\"reservations\":[{}]}}",
        items.join(",")
    )
}

/** @brief 고정 할당을 넣는다. */
fn apply_static_add(pool: &Arc<Mutex<dhcp::LeasePool>>, body: &str) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let j = onetdns_core::json::parse(body)
        .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
    let identity_s = j
        .get("identity")
        .and_then(|v| v.as_str())
        .ok_or("identity 값을 입력해야 합니다")?;
    let ip_s = j
        .get("ip")
        .and_then(|v| v.as_str())
        .ok_or("ip 값을 입력해야 합니다")?;
    let hostname = j.get("hostname").and_then(|v| v.as_str()).map(String::from);
    if hostname
        .as_deref()
        .is_some_and(|value| !dhcp::valid_hostname(value))
    {
        return Err(
            "hostname 값은 1~255바이트이며 공백이나 제어문자를 포함할 수 없습니다".to_string(),
        );
    }
    let identity = dhcp::ClientIdentity::from_text(identity_s)
        .ok_or("identity 값은 mac:<12자리 16진수> 또는 id:<4~510자리 16진수>여야 합니다")?;
    let ip: std::net::Ipv4Addr = ip_s
        .parse()
        .map_err(|_| "ip 값의 형식이 올바르지 않습니다")?;
    pool.lock_recover()
        .add_reservation(identity, u32::from(ip), hostname)?;
    Ok(format!(
        "{{\"added\":true,\"identity\":{},\"ip\":\"{ip}\"}}",
        onetdns_core::json::escape(identity_s)
    ))
}

/** @brief 고정 할당을 뺀다. */
fn apply_static_remove(
    pool: &Arc<Mutex<dhcp::LeasePool>>,
    identity_s: &str,
) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let identity = dhcp::ClientIdentity::from_text(identity_s)
        .ok_or("identity 값은 mac:<12자리 16진수> 또는 id:<4~510자리 16진수>여야 합니다")?;
    if pool.lock_recover().remove_reservation(&identity) {
        Ok(format!(
            "{{\"removed\":true,\"identity\":{}}}",
            onetdns_core::json::escape(identity_s)
        ))
    } else {
        Err(format!(
            "해당 클라이언트 식별자의 고정 할당을 찾을 수 없습니다: {identity_s}"
        ))
    }
}

/** @brief 다른 서버와 임대를 주고받는 스레드를 시작한다. */
fn spawn_lease_sync(
    pool: Arc<Mutex<dhcp::LeasePool>>,
    peers: Vec<String>,
    token: onetdns_core::SecretString,
    resolver: http::HostResolver,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if peers.is_empty() || token.is_empty() {
        return Ok(None);
    }
    use onetdns_core::MutexExt;
    std::thread::Builder::new()
        .name("dhcp-sync".into())
        .spawn(move || loop {
            if sleep_or_shutdown(30, &shutdown) {
                break;
            }
            let snapshot = pool.lock_recover().snapshot();
            if snapshot.is_empty() {
                continue;
            }
            let leases: Vec<String> = snapshot
                .iter()
                .map(|l| {
                    let identity = onetdns_core::json::escape(&l.identity.to_text());
                    let mac = l
                        .mac
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":");
                    let host = l
                        .hostname
                        .as_deref()
                        .map(|h| format!(",\"hostname\":{}", onetdns_core::json::escape(h)))
                        .unwrap_or_default();
                    format!(
                        "{{\"identity\":{identity},\"mac\":\"{mac}\",\"ip\":\"{}\",\"expiry\":\"{}\"{host}}}",
                        l.ip, l.expiry_unix
                    )
                })
                .collect();
            let body = format!("[{}]", leases.join(","));
            for peer in &peers {
                let base = peer.trim_end_matches('/');
                match http::post(&format!("{base}/v1/dhcp/leases"))
                    .header("Authorization", &format!("Bearer {}", token.as_str()))
                    .header("Content-Type", "application/json")
                    .timeout(Duration::from_secs(3))
                    .resolver(resolver.clone())
                    .body_string(&body)
                    .call()
                {
                    Ok(_) => onetdns_core::debug!(
                        event = "dhcp.lease_sync_sent",
                        peer = %peer,
                        leases = snapshot.len(),
                        "DHCP 임대 스냅샷을 상대 노드에 보냈습니다"
                    ),
                    Err(error) => onetdns_core::warn!(
                        event = "dhcp.lease_sync_failed",
                        peer = %peer,
                        leases = snapshot.len(),
                        error = %error,
                        "DHCP 임대를 상대 노드에 복제하지 못했습니다"
                    ),
                }
            }
        })
        .map(Some)
}

/** @brief 받은 임대를 기록에 넣는다. 하나라도 형식이 어긋나면 전체를 거부한다. */
fn apply_lease_sync(pool: &Arc<Mutex<dhcp::LeasePool>>, body: &str) -> Result<String, String> {
    use onetdns_core::MutexExt;
    let parsed = onetdns_core::json::parse(body)
        .map_err(|e| format!("JSON 요청 본문이 올바르지 않습니다: {e}"))?;
    let items: Vec<&onetdns_core::json::Json> = match &parsed {
        onetdns_core::json::Json::Arr(items) => items.iter().collect(),
        single => vec![single],
    };
    if items.is_empty() {
        return Ok("{\"synced\":0}".to_string());
    }
    if items.len() > MAX_SYNCED_LEASES {
        return Err(format!(
            "한 번에 반영할 수 있는 임대는 최대 {MAX_SYNCED_LEASES}개입니다"
        ));
    }

    let mut pending = Vec::with_capacity(items.len());
    let mut seen_identities = std::collections::HashSet::with_capacity(items.len());
    let mut seen_ips = std::collections::HashSet::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = |what: &str| format!("임대 {}번 항목의 {what}", index + 1);
        let identity_s = item
            .get("identity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("identity 값을 입력해야 합니다"))?;
        let mac_s = item
            .get("mac")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("mac 값을 입력해야 합니다"))?;
        let ip_s = item
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or_else(|| at("ip 값을 입력해야 합니다"))?;
        let expiry = item
            .get("expiry")
            .and_then(|v| v.as_str())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| at("expiry 값에는 u64 범위의 10진 문자열을 입력해야 합니다"))?;
        let hostname = item
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from);
        if hostname
            .as_deref()
            .is_some_and(|value| !dhcp::valid_hostname(value))
        {
            return Err(at(
                "hostname 값은 1~255바이트이며 공백이나 제어문자를 포함할 수 없습니다",
            ));
        }
        let mac = parse_mac_colon(mac_s).ok_or_else(|| at("mac 값의 형식이 올바르지 않습니다"))?;
        let identity = dhcp::ClientIdentity::from_text(identity_s).ok_or_else(|| {
            at("identity 값은 mac:<12자리 16진수> 또는 id:<4~510자리 16진수>여야 합니다")
        })?;
        if identity
            .hardware()
            .is_some_and(|identity_mac| identity_mac != mac)
        {
            return Err(at("MAC fallback identity와 mac 값이 일치하지 않습니다"));
        }
        let ip: std::net::Ipv4Addr = ip_s
            .parse()
            .map_err(|_| at("ip 값의 형식이 올바르지 않습니다"))?;
        let ip = u32::from(ip);
        if !seen_identities.insert(identity.clone()) {
            return Err(at("identity 값이 같은 배치에서 중복되었습니다"));
        }
        if !seen_ips.insert(ip) {
            return Err(at("ip 값이 같은 배치에서 중복되었습니다"));
        }
        pending.push((identity, mac, ip, expiry, hostname));
    }

    let mut pool = pool.lock_recover();
    pool.validate_synced_batch(
        pending
            .iter()
            .map(|(identity, _, ip, expiry, _)| (identity.clone(), *ip, *expiry)),
    )?;
    let mut changed = 0usize;
    for (identity, mac, ip, expiry, hostname) in pending {
        if pool.insert(&identity, mac, ip, expiry, hostname) {
            changed += 1;
        }
    }

    if changed > 0 {
        pool.save();
    }
    Ok(format!("{{\"synced\":{changed}}}"))
}

/** @brief 문자열 목록을 JSON 배열로. */
fn json_str_array(items: &[String]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|s| onetdns_core::json::escape(s))
        .collect();
    format!("[{}]", parts.join(","))
}

/** @brief 영역 이름을 파일 이름으로 쓸 수 있는 형태로. 경로를 벗어나는 표기는 거부한다. */
fn safe_zone_key(origin: &str) -> Result<String, String> {
    let key = origin.trim_end_matches('.').to_ascii_lowercase();
    if key.is_empty() {
        return Err("영역의 origin 값이 비어 있습니다".to_string());
    }
    let valid = key.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if !valid {
        return Err(format!(
            "DNS 영역 이름 형식이 올바르지 않습니다(경로/허용되지 않는 문자): {origin}"
        ));
    }
    Ok(key)
}

/** @brief 관리 API가 고칠 영역과 고친 내용을 쓸 파일. */
struct ZoneApiTarget {
    /** @brief 소문자로 맞춘 영역 이름. */
    key: String,
    /** @brief 고친 영역을 쓸 파일. 없으면 메모리에만 남는다. */
    path: Option<std::path::PathBuf>,
}

/**
 * @brief 이 영역을 관리 API로 고칠 수 있는지 지금 설정으로 가린다.
 * @details 보조 영역은 주 서버가 내용을 정한다. 외부 저장소(DB, etcd, LMDB, 카탈로그)에서
 *          온 영역은 다음 읽기에서 저장소 내용으로 되돌아가므로, 파일로 관리되는 영역이
 *          아니면 고치지 않는다. 설정은 부를 때마다 읽는다. 부팅 때 값을 붙잡으면 나중에
 *          더한 보조 영역을 고칠 수 있게 되고, 바꾼 영역 디렉터리 대신 이전 디렉터리에 쓴다.
 * @param verb 오류 문구에 넣을 동작 이름.
 */
fn zone_api_target(
    cfg: &Config,
    store: &onetdns_authority::ZoneStore,
    origin: &str,
    verb: &str,
) -> Result<ZoneApiTarget, String> {
    let key = safe_zone_key(origin)?;
    let same = |configured: &str| {
        configured
            .trim()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&key)
    };
    if cfg.secondary.iter().any(|zone| same(&zone.origin)) {
        return Err(format!(
            "보조 DNS 영역은 이 API에서 {verb}할 수 없습니다: {key}"
        ));
    }
    let file = cfg
        .zones
        .iter()
        .find(|zone| same(&zone.origin))
        .and_then(|zone| zone.file.clone());
    let dir_file = cfg
        .zones_dir
        .as_ref()
        .map(|dir| dir.join(format!("{key}.zone")));
    let file_backed = file.is_some() || dir_file.as_ref().is_some_and(|path| path.exists());
    let external = cfg.zones_db.is_some()
        || cfg.zones_etcd.is_some()
        || cfg.zones_postgres.is_some()
        || cfg.zones_mysql.is_some()
        || cfg.zones_lmdb.is_some()
        || !cfg.catalog.is_empty();
    let exists = onetdns_proto::Name::from_str(origin)
        .ok()
        .is_some_and(|name| store.zone_exact(&name).is_some());
    if exists && external && !file_backed {
        return Err(format!(
            "{key} 영역은 외부 저장소(DB, etcd, LMDB, 카탈로그)에서 옵니다. 이 API에서 {verb}하면 다음 읽기에서 되돌아가므로 그 저장소에서 바꾸십시오"
        ));
    }
    Ok(ZoneApiTarget {
        key,
        path: file.or(dir_file),
    })
}

/** @brief 영역 기준으로 이름을 푼다. */
fn resolve_zone_name(s: &str, origin: &str) -> Option<onetdns_proto::Name> {
    let o = origin.trim_end_matches('.');
    if s == "@" {
        return onetdns_proto::Name::from_str(o).ok();
    }
    if s.ends_with('.') {
        onetdns_proto::Name::from_str(s).ok()
    } else {
        onetdns_proto::Name::from_str(&format!("{s}.{o}")).ok()
    }
}

/** @brief 영역을 고친다. */
fn apply_zone_mutation(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    zone: onetdns_authority::Zone,
    signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
    journal: &Arc<Mutex<std::collections::HashMap<Vec<u8>, native::ZoneJournal>>>,
    persist_path: Option<&std::path::Path>,
    notify: &NotifySender,
    source: &str,
) -> Result<ZoneApplyResult, String> {
    let mut journals = journal.lock().unwrap_or_else(|e| e.into_inner());
    apply_zone_mutation_locked(
        store,
        zone,
        signers,
        &mut journals,
        persist_path,
        notify,
        source,
    )
}

/** @brief 영역을 고친다. 저장에 실패하면 저장소와 변경 기록을 되돌린다. 안 되돌리면 파일과 메모리가 어긋난다. */
fn apply_zone_mutation_locked(
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    zone: onetdns_authority::Zone,
    signers: &[(onetdns_proto::Name, ZoneSigningCtx)],
    journals: &mut std::collections::HashMap<Vec<u8>, native::ZoneJournal>,
    persist_path: Option<&std::path::Path>,
    notify: &NotifySender,
    source: &str,
) -> Result<ZoneApplyResult, String> {
    let origin_name = zone.origin().clone();
    let origin = origin_name.to_ascii_lower();
    let origin_key = origin_name.canonical_key();
    let cur = store.load();
    let old_zone = cur
        .zones()
        .iter()
        .find(|z| z.origin().eq_ignore_case(&origin_name))
        .cloned();
    let old_serial = old_zone.as_ref().map(|z| z.soa().serial);
    let old_recs = old_zone
        .as_ref()
        .map(zone_records_without_closing_soa)
        .unwrap_or_default();

    let mut recs = zone_records_without_closing_soa(&zone);
    bump_soa_serial_if_needed(&mut recs, old_serial);
    let mut signed = false;
    if let Some((_, ctx)) = signers.iter().find(|(o, _)| o.eq_ignore_case(&origin_name)) {
        // 지난 서명은 이 서버가 만들어 저장소에 가지고 있던 것이다. 바뀐 RRset과 새 부재 증명만
        // 새로 서명하면 레코드 하나를 고치는 값이 영역 크기에 비례하지 않는다.
        recs = ctx.sign_reusing(&recs, &old_recs);
        signed = true;
    }
    let new_zone = onetdns_authority::Zone::from_records(recs)
        .map_err(|e| format!("영역 DNS 영역을 다시 구성하지 못했습니다: {e}"))?;
    let new_recs = zone_records_without_closing_soa(&new_zone);
    let serial = new_zone.soa().serial;
    let records = new_zone.axfr_records().len().saturating_sub(2);

    let persisted = if let Some(path) = persist_path {
        crate::atomic_write(path, new_zone.to_master_file().as_bytes())
            .map_err(|e| format!("파일에 저장하지 못했습니다({}): {e}", path.display()))?;
        true
    } else {
        false
    };

    swap_zone(store, new_zone.clone());
    if let Some(old) = old_serial {
        journals
            .entry(origin_key)
            .or_default()
            .record(old, serial, &old_recs, &new_recs);
    }
    notify.enqueue_zone(&new_zone);
    onetdns_core::info!(event = "authority.zone_hooks_applied", origin = %origin, serial, source = %source, signed, persisted, "DNS 영역 변경 처리 절차를 적용했습니다");
    Ok(ZoneApplyResult {
        origin,
        serial,
        records,
        persisted,
        signed,
    })
}

/** @brief 이 질의가 어떻게 판정될지 실제로 묻지 않고 보여 준다. */
fn simulate_policy(
    policy: &onetdns_policy::PolicyEngine,
    filter: &onetdns_filter::SharedFilter,
    body: &str,
) -> String {
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};
    let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
    let gets = |k: &str, d: &str| -> String {
        j.get(k)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| d.to_string())
    };
    let client: std::net::IpAddr = gets("client", "127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

    let client_id = j
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let qname = gets("qname", "");
    if qname.is_empty() {
        return "{\"error\":\"qname 항목을 입력해야 합니다\"}".to_string();
    }
    let Some(qtype) = requested_qtype(&gets("qtype", "A")) else {
        return "{\"error\":\"qtype 값의 형식이 올바르지 않습니다\"}".to_string();
    };

    let name = match onetdns_proto::Name::from_str(&qname) {
        Ok(n) => n,
        Err(_) => return "{\"error\":\"qname 값의 형식이 올바르지 않습니다\"}".to_string(),
    };

    let Some(policy_qname) = native::normalized_text_name(&name) else {
        return "{\"error\":\"UTF-8로 표현할 수 없는 이름은 정책 평가에서 제외됩니다\"}"
            .to_string();
    };

    let now = std::time::SystemTime::now();
    let pin = onetdns_policy::PolicyInput {
        client,
        qname: &policy_qname,
        qtype,
        unix_time: localtime::unix_seconds(now),
        local_minute_of_week: localtime::local_minute_of_week(now),
        transport: onetdns_policy::QueryTransport::Do53Udp,
        client_id: None,
        authenticated: false,
    };
    let pol = match policy.evaluate(&pin) {
        onetdns_policy::Action::Continue => "continue".to_string(),
        onetdns_policy::Action::Allow => "allow".to_string(),
        onetdns_policy::Action::Block => "block".to_string(),
        onetdns_policy::Action::Refuse => "refuse".to_string(),
        onetdns_policy::Action::Rewrite(ip) => format!("rewrite:{ip}"),
    };
    let ci = ClientInfo {
        source_ip: client,
        client_id,
        transport: Transport::Do53Udp,
        authenticated: false,
    };

    let exp = filter
        .load()
        .explain(&name, onetdns_proto::RecordType(qtype), &ci);
    let flt = match &exp.verdict {
        FilterVerdict::Allow => "allow",
        FilterVerdict::Block(_) => "block",
        FilterVerdict::Rewrite(_) => "rewrite",
    };
    let stage = exp.stage.as_str();
    let matched_json = match &exp.matched {
        Some(m) => onetdns_core::json::escape(m),
        None => "null".to_string(),
    };
    let list_json = match &exp.source {
        Some(list) => onetdns_core::json::escape(list),
        None => "null".to_string(),
    };

    let decision = if pol != "continue" {
        pol.clone()
    } else {
        flt.to_string()
    };
    format!(
        "{{\"policy\":{},\"filter\":{},\"filter_stage\":{},\"filter_matched\":{matched_json},\"filter_list\":{list_json},\"decision\":{}}}",
        onetdns_core::json::escape(&pol),
        onetdns_core::json::escape(flt),
        onetdns_core::json::escape(stage),
        onetdns_core::json::escape(&decision),
    )
}

/** @brief 해석 방식의 API 표기. */
fn backend_label(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Recurse => "recurse",
        BackendKind::Forward => "forward",
        BackendKind::Split => "split",
    }
}

/**
 * @brief 이 질의가 왜 그렇게 판정됐는지 설명한다.
 * @details 해석 방식과 업스트림은 호출할 때의 설정에서 읽는다. 부팅 때 값을 붙잡아 두면
 *          설정을 바꾼 뒤에도 이전 경로를 설명한다.
 * @param cfg 지금 적용된 설정.
 * @param zones 지금 적용된 권한 영역.
 */
fn explain_query(
    policy: &onetdns_policy::PolicyEngine,
    filter: &onetdns_filter::SharedFilter,
    cfg: &Config,
    zones: &onetdns_authority::ZoneStore,
    body: &str,
) -> String {
    use onetdns_core::{ClientInfo, FilterEngine, FilterVerdict, Transport};
    let esc = onetdns_core::json::escape;
    let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
    let gets = |k: &str, d: &str| -> String {
        j.get(k)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| d.to_string())
    };
    let client: std::net::IpAddr = gets("client", "127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client_id = j
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let qname = gets("qname", "");
    if qname.is_empty() {
        return "{\"error\":\"qname 항목을 입력해야 합니다\"}".to_string();
    }
    let Some(qtype) = requested_qtype(&gets("qtype", "A")) else {
        return "{\"error\":\"qtype 값의 형식이 올바르지 않습니다\"}".to_string();
    };
    let name = match onetdns_proto::Name::from_str(&qname) {
        Ok(n) => n,
        Err(_) => return "{\"error\":\"qname 값의 형식이 올바르지 않습니다\"}".to_string(),
    };
    let ci = ClientInfo {
        source_ip: client,
        client_id: client_id.clone(),
        transport: Transport::Do53Udp,
        authenticated: false,
    };

    let Some(policy_qname) = native::normalized_text_name(&name) else {
        return "{\"error\":\"UTF-8로 표현할 수 없는 이름은 정책 평가에서 제외됩니다\"}"
            .to_string();
    };
    let now = std::time::SystemTime::now();
    let pin = onetdns_policy::PolicyInput {
        client,
        qname: &policy_qname,
        qtype,
        unix_time: localtime::unix_seconds(now),
        local_minute_of_week: localtime::local_minute_of_week(now),
        transport: onetdns_policy::QueryTransport::Do53Udp,
        client_id: client_id.as_deref(),
        authenticated: false,
    };
    let pol = match policy.evaluate(&pin) {
        onetdns_policy::Action::Continue => "continue".to_string(),
        onetdns_policy::Action::Allow => "allow".to_string(),
        onetdns_policy::Action::Block => "block".to_string(),
        onetdns_policy::Action::Refuse => "refuse".to_string(),
        onetdns_policy::Action::Rewrite(ip) => format!("rewrite:{ip}"),
    };

    let eng = filter.load();
    let exp = eng.explain(&name, onetdns_proto::RecordType(qtype), &ci);
    let flt = match &exp.verdict {
        FilterVerdict::Allow => "allow",
        FilterVerdict::Block(_) => "block",
        FilterVerdict::Rewrite(_) => "rewrite",
    };
    let stage = exp.stage.as_str();
    let matched_json = exp
        .matched
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());
    let list_json = exp
        .source
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());
    let safe_search = eng.client_safe_search(&ci);

    let decision = if pol != "continue" {
        pol.clone()
    } else {
        flt.to_string()
    };
    let rcode = match (&exp.verdict, decision.as_str()) {
        (_, "refuse") => "REFUSED".to_string(),
        (FilterVerdict::Block(response), "block") if pol == "continue" => native::rcode_str(
            native::block_rcode(response, onetdns_proto::RecordType(qtype)),
        )
        .into_owned(),
        (_, "block") => "NXDOMAIN".to_string(),
        _ => "NOERROR".to_string(),
    };

    let mut stages: Vec<String> = Vec::new();
    if pol != "continue" {
        stages.push(format!("{{\"stage\":\"policy\",\"action\":{}}}", esc(&pol)));
    }
    stages.push(format!(
        "{{\"stage\":{},\"rule\":{matched_json}}}",
        esc(&format!("filter:{stage}"))
    ));

    let backend = backend_label(cfg.backend);
    let authority = authority_sources_configured(cfg)
        .then(|| zones.zone_for(&name))
        .flatten()
        .map(|zone| zone.origin().to_ascii_lower());
    let (route, resolution) = match decision.as_str() {
        "allow" | "continue" => match &authority {
            Some(origin) => ("authority", format!("local authoritative zone {origin}")),
            None => (
                backend,
                match cfg.backend {
                    BackendKind::Recurse => "recursive root resolution".to_string(),
                    BackendKind::Split => "split (forward/recurse by zone)".to_string(),
                    BackendKind::Forward => {
                        let upstreams: Vec<String> = cfg
                            .upstreams
                            .iter()
                            .map(|ip| ip.to_string())
                            .chain(cfg.upstream_urls.iter().cloned())
                            .collect();
                        format!("forward to [{}]", upstreams.join(", "))
                    }
                },
            ),
        },
        "rewrite" => ("rewrite", "answered by rewrite rule".to_string()),
        d if d.starts_with("rewrite:") => ("rewrite", "answered by policy rewrite".to_string()),
        "refuse" => ("refused", "refused before resolution".to_string()),
        _ => ("blocked", "blocked before resolution".to_string()),
    };
    let ss = safe_search
        .map(|b| b.to_string())
        .unwrap_or_else(|| "null".to_string());
    let cid = client_id
        .as_deref()
        .map(esc)
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"client\":{},\"client_id\":{cid},\"qname\":{qn},\"qtype\":{qt},\
\"decision\":{},\"rcode\":{},\
\"policy\":{},\"filter\":{},\"filter_stage\":{},\"filter_matched\":{matched_json},\
\"filter_list\":{list_json},\"client_safe_search\":{ss},\"matched\":[{matched_arr}],\
\"backend\":{},\"route\":{},\"dnssec\":{dnssec},\"resolution\":{},\
\"note\":{}}}",
        esc(&client.to_string()),
        esc(&decision),
        esc(&rcode),
        esc(&pol),
        esc(flt),
        esc(stage),
        esc(backend),
        esc(route),
        esc(&resolution),
        esc("미리 보기 결과이며 캐시 조회, 업스트림 DNS 서버 질의, DNSSEC 검증은 수행하지 않았습니다"),
        qn = esc(&qname),
        qt = esc(&qtype_text(qtype)),
        matched_arr = stages.join(","),
        dnssec = cfg.dnssec_validation_active(),
    )
}

/**
 * @brief 요청이 적은 질의 종류를 번호로 읽는다.
 *
 * @details 읽지 못한 이름을 A 로 되돌리면 물어본 것과 다른 종류를 설명한 응답이
 *          오류 없이 나간다. qname 과 마찬가지로 형식 오류로 알린다.
 * @param text 요청이 적은 종류 이름.
 * @return 번호. 읽지 못하면 없다.
 */
fn requested_qtype(text: &str) -> Option<u16> {
    qtype_numbers(&[text.to_string()]).first().copied()
}

/**
 * @brief 질의 타입을 요청과 같은 문자열 모양으로 되돌린다.
 *
 * @details 요청은 "A" 같은 약칭을 받으므로 응답도 같은 모양이어야 화면에 그대로 쓸 수 있다.
 *          약칭을 모르는 타입은 RFC 3597 표기를 쓴다. "UNKNOWN"은 번호를 잃어버린다.
 * @param qtype 타입 번호.
 * @return 약칭 또는 TYPE 뒤에 번호를 붙인 표기.
 */
fn qtype_text(qtype: u16) -> String {
    let name = onetdns_proto::RecordType(qtype).name();
    if name == "UNKNOWN" {
        format!("TYPE{qtype}")
    } else {
        name.to_string()
    }
}

#[derive(Clone, PartialEq, Eq)]
/** @brief 이 노드의 클러스터 신원. */
struct RaftRuntimeIdentity {
    /** @brief 이 노드 번호. */
    node_id: u64,
    /** @brief 이 노드가 묶을 주소. */
    listen: String,
    /** @brief 다른 노드들의 번호·주소·키. */
    peers: Vec<(u64, String, [u8; 32])>,
    /** @brief 이 노드만의 시드. 노드마다 달라야 한다. */
    node_seed: [u8; 32],
    /** @brief 클러스터 공유 비밀의 지문. 설정이 바뀌었는지 본다. */
    secret_digest: [u8; 32],
    /** @brief 합의 상태를 담아 둘 파일. */
    state_path: PathBuf,
}

#[derive(Clone)]
/** @brief 이 세대에서 Raft 로그 항목을 적용할 방법. */
struct RaftGenerationApply {
    /** @brief 설정을 다시 읽게 하는 플래그. */
    reload: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 재시작하지 않고 교체하는 방법. 없으면 재시작한다. */
    hot_apply: Option<HotConfigApply>,
}

/** @brief Raft 로그 항목을 적용하는 곳. 세대가 바뀌면 교체한다. */
struct RaftApplyContext {
    /** @brief 설정 파일 경로. */
    path: Option<PathBuf>,
    /** @brief 앞선 설정 텍스트. */
    prev: ConfigTextSlot,
    /** @brief 마지막으로 성공한 설정 텍스트. */
    applied: ConfigTextSlot,
    /** @brief 이 세대의 적용 방법. 세대가 바뀌면 교체한다. */
    generation: Mutex<RaftGenerationApply>,
}

impl RaftApplyContext {
    /** @brief 만든다. */
    fn new(
        path: Option<PathBuf>,
        prev: ConfigTextSlot,
        applied: ConfigTextSlot,
        generation: RaftGenerationApply,
    ) -> Self {
        Self {
            path,
            prev,
            applied,
            generation: Mutex::new(generation),
        }
    }

    /**
     * @brief 이 세대의 적용 방법을 끼운다.
     * @details 세대를 새로 시작할 때는 시작하는 동안 설정 파일이 바뀌었는지 보고, 바뀌었으면
     *          다시 읽도록 표시한다. 비교와 교체는 설정 쓰기 잠금 하나 안에서 한다. 적용은
     *          같은 잠금을 잡고 세대를 읽으므로, 비교한 뒤 잠금을 풀고 교체하면 그 사이에 온
     *          변경은 옛 세대에만 알려지고 파일 비교에도 잡히지 않아 사라진다.
     * @param expected_text 이 세대가 읽은 설정 텍스트. 없음은 호출자가 이미 설정 쓰기 잠금을
     *        잡고 있다는 뜻이며, 핫 적용이 그렇게 부른다.
     * @warning 핫 적용은 설정 쓰기 잠금을 잡은 채 지금 파일 내용으로 부른다. 여기서 잠금을
     *          다시 잡으면 멈추고, 부팅 때 텍스트와 비교하면 부팅 뒤 바뀐 파일을 보고 서비스
     *          전체를 재시작한다.
     */
    fn install_generation(
        &self,
        expected_text: Option<&str>,
        generation: RaftGenerationApply,
    ) -> Result<bool, String> {
        let _write_guard = expected_text.map(|_| config_write_lock().lock_recover());
        let changed_during_start = match (self.path.as_deref(), expected_text) {
            (Some(path), Some(expected)) => {
                let current = onetdns_core::SecretString::from(
                    Config::read_text(path).map_err(|error| error.to_string())?,
                );
                current.as_str() != expected
            }
            _ => false,
        };
        *self.generation.lock_recover() = generation.clone();
        if changed_during_start {
            generation
                .reload
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(changed_during_start)
    }

    /**
     * @brief 설정 파일을 요청 전 내용으로 되돌린다. 커밋되지 않은 변경을 이 노드에서 취소한다.
     * @param previous_slot 요청 전의 롤백용 이전 설정. 되돌린 뒤 이 값도 복원해야 설정
     *        롤백 API가 커밋되지 않은 변경을 다시 적용하지 않는다.
     */
    fn restore_text(
        &self,
        text: &str,
        previous_slot: Option<onetdns_core::SecretString>,
    ) -> Result<(), String> {
        let _write_guard = config_write_lock().lock_recover();
        let generation = self.generation.lock_recover().clone();
        let edit = |_: &str| Ok(text.to_string());
        let result = if let Some(hot_apply) = generation.hot_apply.as_ref() {
            apply_config_edit_smart_locked(
                &self.path,
                &self.prev,
                &self.applied,
                &generation.reload,
                hot_apply,
                edit,
            )
            .map(|_| ())
        } else {
            apply_config_edit_locked(&self.path, &self.prev, &generation.reload, edit)
        };
        *self.prev.lock_recover() = previous_slot;
        result
    }

    /** @brief 클러스터가 정한 명령을 적용한다. */
    fn apply_command(&self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        self.apply_patch(&patch)
    }

    /** @brief 클러스터가 정한 설정 변경을 적용한다. */
    fn apply_patch(&self, patch: &[(String, onetdns_core::json::Json)]) -> Result<(), String> {
        apply_raft_patch(self, patch)
    }
}

/** @brief 실행 중인 클러스터 노드 하나. */
struct RaftRuntime {
    /** @brief 이 노드의 신원. */
    identity: RaftRuntimeIdentity,
    /** @brief Raft 로그 항목을 적용하는 곳. */
    apply: Arc<RaftApplyContext>,
    /** @brief 노드를 조종할 핸들. */
    handle: onetdns_cluster::transport::RaftHandle,
}

/** @brief 이 프로세스의 클러스터 노드. */
static RAFT: std::sync::OnceLock<Mutex<Option<RaftRuntime>>> = std::sync::OnceLock::new();

/** @brief 클러스터 노드가 들어가는 곳. */
fn raft_slot() -> &'static Mutex<Option<RaftRuntime>> {
    RAFT.get_or_init(|| Mutex::new(None))
}

/** @brief 클러스터 노드 핸들. 돌고 있지 않으면 없다. */
pub fn raft_handle() -> Option<onetdns_cluster::transport::RaftHandle> {
    raft_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|runtime| runtime.handle.clone())
}

/** @brief 클러스터 노드를 멈춘다. */
fn stop_raft() {
    let runtime = {
        raft_slot()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    };
    if let Some(runtime) = runtime {
        runtime.handle.shutdown();
    }
}

/** @brief 프로세스가 끝날 때 클러스터 노드를 멈추는 것. */
struct RaftProcessCleanup;

impl Drop for RaftProcessCleanup {
    /** @brief 클러스터 노드를 멈춘다. */
    fn drop(&mut self) {
        stop_raft();
    }
}

/** @brief 16진 문자열을 32바이트로. */
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/** @brief 클러스터 노드를 시작하거나 이미 있으면 그대로 쓴다. */
fn ensure_raft_runtime(
    cfg: &Config,
    expected_text: Option<&str>,
    path: Option<PathBuf>,
    prev: ConfigTextSlot,
    applied: ConfigTextSlot,
    reload: Arc<std::sync::atomic::AtomicBool>,
    hot_apply: Option<HotConfigApply>,
) -> Result<(), String> {
    let listen = cfg.cluster_raft_listen.clone().ok_or(
        "Raft 고가용성이 켜져 있지만 수신 주소(`cluster_raft_listen`)가 설정되어 있지 않습니다",
    )?;
    let mut peers: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    let mut peer_keys: std::collections::HashMap<u64, [u8; 32]> = std::collections::HashMap::new();
    let mut ids = vec![cfg.cluster_node_id];
    for p in &cfg.cluster_raft_peers {
        if let Some((id_s, rest)) = p.split_once('@') {
            if let Some((addr, pubkey)) = rest.split_once('#') {
                if let (Ok(id), Some(pk)) = (id_s.trim().parse::<u64>(), hex32(pubkey.trim())) {
                    peers.insert(id, addr.trim().to_string());
                    peer_keys.insert(id, pk);
                    ids.push(id);
                }
            }
        }
    }
    let node_seed = hex32(cfg.cluster_raft_node_key.trim()).ok_or(
        "cluster_raft_node_key에는 32바이트 Ed25519 시드를 64자리 16진수로 입력해야 합니다",
    )?;
    let state_path = path
        .as_ref()
        .map(|config_path| {
            std::path::PathBuf::from(format!(
                "{}.raft-{}.state",
                config_path.display(),
                cfg.cluster_node_id
            ))
        })
        .unwrap_or_else(|| {
            std::path::PathBuf::from(format!("onetdns.raft-{}.state", cfg.cluster_node_id))
        });
    let mut identity_peers = peers
        .iter()
        .filter_map(|(id, address)| peer_keys.get(id).map(|key| (*id, address.clone(), *key)))
        .collect::<Vec<_>>();
    identity_peers.sort_unstable_by_key(|(id, _, _)| *id);
    let identity = RaftRuntimeIdentity {
        node_id: cfg.cluster_node_id,
        listen: listen.clone(),
        peers: identity_peers,
        node_seed,
        secret_digest: Sha256::digest(cfg.cluster_raft_secret.as_bytes()).into(),
        state_path: state_path.clone(),
    };
    let generation = RaftGenerationApply { reload, hot_apply };

    {
        let slot = raft_slot().lock_recover();
        if let Some(runtime) = slot.as_ref().filter(|runtime| runtime.identity == identity) {
            let apply = runtime.apply.clone();
            drop(slot);
            let changed_during_start =
                apply.install_generation(expected_text, generation.clone())?;
            onetdns_core::info!(
                event = "raft.consensus_reused",
                node = cfg.cluster_node_id,
                changed_during_start,
                "DNS 서비스 구성을 교체하면서 기존 Raft 합의 런타임을 유지합니다"
            );
            return Ok(());
        }
    }

    let previous = { raft_slot().lock_recover().take() };
    if let Some(previous) = previous {
        previous.handle.shutdown();
    }

    let apply_context = Arc::new(RaftApplyContext::new(
        path.clone(),
        prev,
        applied,
        generation.clone(),
    ));
    let changed_during_start =
        apply_context.install_generation(expected_text, generation.clone())?;
    let node = onetdns_cluster::RaftNode::new_persistent(
        cfg.cluster_node_id,
        ids,
        onetdns_cluster::Config {
            election_base: 10,
            heartbeat: 3,
        },
        state_path.clone(),
    )
    .map_err(|error| {
        format!(
            "디스크에서 Raft 상태를 복구하지 못했습니다({}): {error}",
            state_path.display()
        )
    })?;
    let mut initial_snapshot = if let Some(snapshot) = node.snapshot() {
        RaftConfigSnapshot::decode(&snapshot.data)?
    } else {
        RaftConfigSnapshot::default()
    };
    for entry in node.applied_entries_after_snapshot() {
        if !entry.data.is_empty() {
            initial_snapshot.merge_command(&entry.data)?;
        }
    }
    let snapshot_state = Arc::new(Mutex::new(initial_snapshot));

    let apply_state = snapshot_state.clone();
    let apply_context_for_entry = apply_context.clone();
    let apply: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync> = Box::new(move |data| {
        apply_context_for_entry.apply_command(data)?;
        apply_state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .merge_command(data)
    });
    let snapshot_for_create = snapshot_state.clone();
    let create_snapshot: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync> =
        Box::new(move || {
            snapshot_for_create
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .encode()
        });
    let install_state = snapshot_state.clone();
    let apply_context_for_snapshot = apply_context.clone();
    let install_snapshot: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync> =
        Box::new(move |data| {
            let next = RaftConfigSnapshot::decode(data)?;
            apply_context_for_snapshot.apply_patch(&next.patch())?;
            *install_state
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = next;
            Ok(())
        });
    let handle = onetdns_cluster::transport::RaftServer::spawn(
        cfg.cluster_node_id,
        listen.clone(),
        peers,
        node,
        50,
        cfg.cluster_raft_secret.as_bytes().to_vec(),
        node_seed,
        peer_keys,
        apply,
        create_snapshot,
        install_snapshot,
    )
    .map_err(|error| format!("Raft 고가용성 기능을 시작하지 못했습니다: {error}"))?;
    *raft_slot().lock_recover() = Some(RaftRuntime {
        identity,
        apply: apply_context,
        handle,
    });
    onetdns_core::info!(event = "raft.consensus_started",
        node = cfg.cluster_node_id,
        listen = %listen,
        peers = cfg.cluster_raft_peers.len(),
        changed_during_start,
        "Raft 클러스터 합의를 시작합니다(리더 선출 및 로그 복제)"
    );
    Ok(())
}

/**
 * @brief 클러스터가 정할 수 있는 설정인지 확인한다.
 * @warning 노드별 설정은 거부한다. 퍼뜨리면 모든 노드가 같은 비밀을 쓰거나 서로 신원이
 *          겹친다.
 */
fn validate_raft_patch_scope(value: &onetdns_core::json::Json) -> Result<(), String> {
    let onetdns_core::json::Json::Obj(pairs) = value else {
        return Err("Raft로 전달하는 설정 변경 내용은 JSON 객체여야 합니다".to_string());
    };
    if let Some((key, _)) = pairs.iter().find(|(key, _)| config_keys::node_local(key)) {
        return Err(format!(
            "{key}는 노드마다 따로 두는 설정이라 Raft로 복제할 수 없습니다. 각 노드에서 별도로 설정하십시오"
        ));
    }
    Ok(())
}

/**
 * @brief 팔로워가 처리 전에 거절할 요청인지. 클러스터 공유 설정을 바꾸는 요청이 대상이다.
 * @details 설정 편집 요청은 본문의 키를 보고 판단한다. 노드별 설정만 바꾸는 편집은 팔로워도
 *          받는다. 본문을 파싱하지 못하면 여기서 거절하지 않고, 요청 처리 단계에서 본문 오류로
 *          응답하게 둔다.
 */
fn cluster_follower_must_reject(path: &str, body: &str) -> bool {
    match path {
        "/v1/block"
        | "/v1/allow"
        | "/v1/restore"
        | "/v1/services"
        | "/v1/safesearch"
        | "/v1/rewrites"
        | "/v1/filter/rules"
        | "/v1/filter/subscriptions"
        | "/v1/clients"
        | "/v1/upstreams"
        | "/v1/config/rollback" => true,
        "/v1/config/set" => match onetdns_core::json::parse(body) {
            Ok(onetdns_core::json::Json::Obj(fields)) => {
                fields.iter().any(|(key, _)| !config_keys::node_local(key))
            }
            _ => false,
        },
        "/v1/config/apply" => match onetdns_config::toml::parse(body) {
            Ok(onetdns_config::toml::Value::Table(fields)) => {
                fields.keys().any(|key| !config_keys::node_local(key))
            }
            _ => false,
        },
        _ => false,
    }
}

/** @brief 클러스터 제안을 하나씩 올리게 하는 잠금. 설정 쓰기 잠금과는 따로 둔다. */
fn cluster_proposal_lock() -> &'static Mutex<()> {
    /** @brief 제안 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 클러스터 요청 처리가 실패로 끝났을 때의 응답. */
fn cluster_write_error(status: &'static str, message: String) -> onetdns_control::ApiResponse {
    (
        status,
        "application/json",
        format!("{{\"error\":{}}}", onetdns_core::json::escape(&message)),
    )
}

/** @brief 팔로워가 거절할 때 쓰는 문구. 알면 리더 번호를 알려 준다. */
fn cluster_not_leader_message(leader: Option<u64>) -> String {
    match leader {
        Some(id) => format!(
            "이 노드는 Raft 리더가 아니므로 클러스터 전체에 적용되는 설정을 바꿀 수 없습니다. 리더인 {id}번 노드의 관리 화면에서 변경하십시오"
        ),
        None => "Raft 리더를 선출하는 중이라 클러스터 전체에 적용되는 설정을 바꿀 수 없습니다. 잠시 후 다시 시도하십시오".to_string(),
    }
}

/**
 * @brief 두 설정 파일 내용을 비교해 바뀐 클러스터 공유 설정을 구한다.
 * @return 바뀐 키와 새 값. 삭제된 키의 값은 null 이다. 바뀐 것이 없으면 빈 목록이다.
 */
fn cluster_config_changes(
    before: &str,
    after: &str,
) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let keys: Vec<String> = changed_config_keys(before, after)?
        .into_iter()
        .filter(|key| !config_keys::node_local(key))
        .collect();
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = onetdns_config::toml::parse(after)?;
    keys.into_iter()
        .map(|key| {
            let value = match parsed.get(&key) {
                Some(value) => toml_value_to_json(value)?,
                None => onetdns_core::json::Json::Null,
            };
            Ok((key, value))
        })
        .collect()
}

/**
 * @brief 상태를 바꾸는 관리 요청을 Raft 합의를 거쳐 처리한다.
 * @details 리더는 요청을 먼저 처리하고, 클러스터 공유 설정이 바뀌었으면 바뀐 값을 제안한다.
 *          제안이 실패하면 설정 파일을 요청 전 상태로 되돌리고 실패로 응답한다. 먼저 처리하는
 *          이유는 요청마다 설정 파일을 고치는 방식이 달라서, 처리 전후 파일 내용을 비교해야
 *          모든 요청을 한 경로로 다룰 수 있기 때문이다.
 *          팔로워는 공유 설정을 바꾸는 요청을 처리 전에 거절한다. 사전에 걸러지지 않은 요청이
 *          공유 설정을 바꿨다면 되돌리고 거절한다. 팔로워에서 바꾼 값은 다음 커밋에 덮어써져
 *          노드 간 설정이 어긋나기 때문이다.
 * @warning 제안은 설정 쓰기 잠금을 잡지 않은 채 커밋을 기다린다. 커밋된 항목을 적용하는 쪽이
 *          그 잠금을 잡기 때문이다. 제안 간 순서는 별도의 제안 잠금으로 보장한다.
 */
fn cluster_routed_write(
    method: &str,
    path: &str,
    body: &str,
    dispatch: &mut dyn FnMut() -> onetdns_control::ApiResponse,
) -> onetdns_control::ApiResponse {
    let runtime = raft_slot()
        .lock_recover()
        .as_ref()
        .map(|runtime| (runtime.handle.clone(), runtime.apply.clone()));
    let Some((handle, context)) = runtime else {
        return dispatch();
    };
    let Some(config_path) = context.path.clone() else {
        return dispatch();
    };
    let leader = handle.is_leader();
    if !leader && cluster_follower_must_reject(path, body) {
        return cluster_write_error("409 Conflict", cluster_not_leader_message(handle.leader()));
    }

    let _proposal = cluster_proposal_lock().lock_recover();
    let read = |when: &str| {
        Config::read_text(&config_path)
            .map(onetdns_core::SecretString::from)
            .map_err(|error| format!("{when} 설정 파일을 읽지 못했습니다: {error}"))
    };
    let before = match read("요청을 처리하기 전에") {
        Ok(text) => text,
        Err(error) => return cluster_write_error("503 Service Unavailable", error),
    };
    let previous_slot = context.prev.lock_recover().clone();
    let response = dispatch();
    if !response.0.starts_with('2') {
        return response;
    }
    let changes =
        read("요청을 처리한 뒤").and_then(|after| cluster_config_changes(&before, &after));
    let (status, message) = match changes {
        Ok(changes) if changes.is_empty() => return response,
        Ok(_) if !leader => ("409 Conflict", cluster_not_leader_message(handle.leader())),
        Ok(changes) => {
            let command = onetdns_core::json::Json::Obj(vec![(
                "patch".to_string(),
                onetdns_core::json::Json::Obj(changes),
            )])
            .to_text();
            /*
             * 확인하지 못한 경우에도 이 노드의 변경은 되돌린다. 나중에 커밋되면 적용 쪽이 이
             * 노드에도 다시 적어 모든 노드가 같아지고, 폐기되면 되돌린 상태가 맞다.
             */
            match handle.propose(command.into_bytes()) {
                Ok(_) => return response,
                Err(onetdns_cluster::transport::ProposalError::Undetermined(error)) => (
                    "503 Service Unavailable",
                    format!("Raft 클러스터가 이 변경을 합의했는지 아직 확인하지 못해 이 노드에서는 되돌렸습니다({error}). 과반의 노드가 연결되어 합의되면 그때 모든 노드에 적용되고, 합의되지 않으면 적용되지 않습니다. 잠시 뒤 설정을 다시 확인하십시오"),
                ),
                Err(error) => (
                    "503 Service Unavailable",
                    format!("변경 내용이 Raft 클러스터에 합의되지 않아 이 노드의 변경도 되돌렸습니다: {error}"),
                ),
            }
        }
        Err(error) => (
            "503 Service Unavailable",
            format!("변경 내용을 Raft 클러스터에 올릴 수 없어 되돌렸습니다: {error}"),
        ),
    };
    let message = match context.restore_text(&before, previous_slot) {
        Ok(()) => message,
        Err(error) => format!("{message}. 이 노드의 설정 파일을 되돌리지도 못했습니다: {error}"),
    };
    onetdns_core::warn!(
        event = "raft.write_rejected",
        method = %method,
        path = %path,
        reason = %message,
        "Raft 에 커밋되지 않은 관리 요청을 되돌렸습니다"
    );
    cluster_write_error(status, message)
}

/** @brief 클러스터 설정 스냅숏의 매직 바이트. */
const RAFT_CONFIG_SNAPSHOT_MAGIC: &[u8; 12] = b"ONETCFGSNAP1";
/** @brief 스냅숏에 담을 설정 항목 수 상한. */
const MAX_RAFT_SNAPSHOT_KEYS: usize = 1_024;

#[derive(Default)]
/** @brief 클러스터가 합의한 설정 스냅숏. */
struct RaftConfigSnapshot {
    /** @brief 클러스터가 합의한 설정 항목들. */
    values: std::collections::BTreeMap<String, onetdns_core::json::Json>,
}

impl RaftConfigSnapshot {
    /** @brief 로그 항목 하나를 스냅숏에 반영한다. 나중 것이 이긴다. */
    fn merge_command(&mut self, data: &[u8]) -> Result<(), String> {
        let patch = decode_raft_command_patch(data)?;
        for (key, value) in patch {
            self.values.insert(key, value);
        }
        Ok(())
    }

    /** @brief 스냅숏을 바이트로 인코딩한다. */
    fn encode(&self) -> Result<Vec<u8>, String> {
        if self.values.is_empty() || self.values.len() > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft 설정 스냅샷 항목 수가 허용 범위를 벗어났습니다".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(RAFT_CONFIG_SNAPSHOT_MAGIC);
        out.extend_from_slice(&(self.values.len() as u32).to_be_bytes());
        for (key, value) in &self.values {
            if key.is_empty() || key.len() > 128 || key.len() > u16::MAX as usize {
                return Err("Raft 설정 스냅샷 키가 올바르지 않습니다".into());
            }
            out.extend_from_slice(&(key.len() as u16).to_be_bytes());
            out.extend_from_slice(key.as_bytes());
            encode_raft_snapshot_value(value, &mut out, 0)?;
            if out.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES {
                return Err("Raft 설정 스냅샷이 허용 크기를 넘었습니다".into());
            }
        }
        Ok(out)
    }

    /** @brief 바이트를 스냅숏으로 디코딩한다. */
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > onetdns_cluster::raft::MAX_SNAPSHOT_BYTES
            || bytes.get(..RAFT_CONFIG_SNAPSHOT_MAGIC.len())
                != Some(RAFT_CONFIG_SNAPSHOT_MAGIC.as_slice())
        {
            return Err("Raft 설정 스냅샷 헤더가 올바르지 않습니다".into());
        }
        let mut pos = RAFT_CONFIG_SNAPSHOT_MAGIC.len();
        let count = raft_snapshot_take_u32(bytes, &mut pos)? as usize;
        if count == 0 || count > MAX_RAFT_SNAPSHOT_KEYS {
            return Err("Raft 설정 스냅샷 항목 수가 허용 범위를 벗어났습니다".into());
        }
        let mut values = std::collections::BTreeMap::new();
        for _ in 0..count {
            let key_len = raft_snapshot_take_u16(bytes, &mut pos)? as usize;
            if key_len == 0 || key_len > 128 {
                return Err("Raft 설정 스냅샷 키 길이가 올바르지 않습니다".into());
            }
            let key = std::str::from_utf8(raft_snapshot_take(bytes, &mut pos, key_len)?)
                .map_err(|_| "Raft 설정 스냅샷 키가 UTF-8이 아닙니다")?
                .to_string();
            let value = decode_raft_snapshot_value(bytes, &mut pos, 0)?;
            if values.insert(key, value).is_some() {
                return Err("Raft 설정 스냅샷에 중복 키가 있습니다".into());
            }
        }
        if pos != bytes.len() {
            return Err("Raft 설정 스냅샷 끝에 불필요한 데이터가 있습니다".into());
        }
        let patch = onetdns_core::json::Json::Obj(
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        validate_raft_patch_scope(&patch)?;
        for value in values.values() {
            if !matches!(value, onetdns_core::json::Json::Null) {
                json_to_raft_toml_literal(value, 0)?;
            }
        }
        Ok(Self { values })
    }

    /** @brief 스냅숏을 설정 변경 목록으로 바꾼다. */
    fn patch(&self) -> Vec<(String, onetdns_core::json::Json)> {
        self.values
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

/**
 * @brief 값 하나를 스냅숏에 담을 바이트로 인코딩한다.
 * @details 맨 위의 null 은 그 항목을 지웠다는 합의라서 담는다. 배열과 테이블은 설정 파일에
 *          있는 모양 그대로 중첩을 허용하되 깊이를 제한한다.
 */
fn encode_raft_snapshot_value(
    value: &onetdns_core::json::Json,
    out: &mut Vec<u8>,
    depth: usize,
) -> Result<(), String> {
    use onetdns_core::json::Json;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft 설정 스냅샷 값의 중첩이 너무 깊습니다".into());
    }
    match value {
        Json::Null if depth == 0 => out.push(0),
        Json::Bool(false) => out.push(1),
        Json::Bool(true) => out.push(2),
        Json::Num(number) if number.is_finite() => {
            out.push(3);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
        }
        Json::Str(text) => {
            out.push(4);
            let len =
                u32::try_from(text.len()).map_err(|_| "Raft 설정 스냅샷 문자열이 너무 큽니다")?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        Json::Arr(items) => {
            out.push(5);
            let count =
                u32::try_from(items.len()).map_err(|_| "Raft 설정 스냅샷 배열이 너무 큽니다")?;
            out.extend_from_slice(&count.to_be_bytes());
            for item in items {
                encode_raft_snapshot_value(item, out, depth + 1)?;
            }
        }
        Json::Obj(fields) => {
            out.push(6);
            let count =
                u32::try_from(fields.len()).map_err(|_| "Raft 설정 스냅샷 테이블이 너무 큽니다")?;
            out.extend_from_slice(&count.to_be_bytes());
            for (key, value) in fields {
                let len = u16::try_from(key.len())
                    .map_err(|_| "Raft 설정 스냅샷 테이블의 키가 너무 깁니다")?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(key.as_bytes());
                encode_raft_snapshot_value(value, out, depth + 1)?;
            }
        }
        _ => return Err("Raft 설정 스냅샷 값 형식이 지원되지 않습니다".into()),
    }
    Ok(())
}

/** @brief 스냅숏의 바이트를 값으로 디코딩한다. */
fn decode_raft_snapshot_value(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<onetdns_core::json::Json, String> {
    use onetdns_core::json::Json;
    /** @brief 배열이나 테이블 하나가 가질 수 있는 항목 수 상한. */
    const MAX_ITEMS: usize = 100_000;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft 설정 스냅샷 값의 중첩이 너무 깊습니다".into());
    }
    let tag = *raft_snapshot_take(bytes, pos, 1)?
        .first()
        .ok_or("Raft 설정 스냅샷 값 태그가 없습니다")?;
    match tag {
        0 if depth == 0 => Ok(Json::Null),
        1 => Ok(Json::Bool(false)),
        2 => Ok(Json::Bool(true)),
        3 => {
            let bits = u64::from_be_bytes(
                raft_snapshot_take(bytes, pos, 8)?
                    .try_into()
                    .map_err(|_| "Raft 설정 스냅샷의 숫자 데이터를 8바이트로 읽을 수 없습니다")?,
            );
            let number = f64::from_bits(bits);
            number
                .is_finite()
                .then_some(Json::Num(number))
                .ok_or_else(|| "Raft 설정 스냅샷 숫자가 유한하지 않습니다".into())
        }
        4 => {
            let len = raft_snapshot_take_u32(bytes, pos)? as usize;
            let text = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                .map_err(|_| "Raft 설정 스냅샷 문자열이 UTF-8이 아닙니다")?;
            Ok(Json::Str(text.to_string()))
        }
        5 => {
            let count = raft_snapshot_take_u32(bytes, pos)? as usize;
            if count > MAX_ITEMS {
                return Err("Raft 설정 스냅샷 배열 항목이 너무 많습니다".into());
            }
            let mut items = Vec::with_capacity(count.min(1_024));
            for _ in 0..count {
                items.push(decode_raft_snapshot_value(bytes, pos, depth + 1)?);
            }
            Ok(Json::Arr(items))
        }
        6 => {
            let count = raft_snapshot_take_u32(bytes, pos)? as usize;
            if count > MAX_ITEMS {
                return Err("Raft 설정 스냅샷 테이블 항목이 너무 많습니다".into());
            }
            let mut fields: Vec<(String, Json)> = Vec::with_capacity(count.min(1_024));
            for _ in 0..count {
                let len = raft_snapshot_take_u16(bytes, pos)? as usize;
                let key = std::str::from_utf8(raft_snapshot_take(bytes, pos, len)?)
                    .map_err(|_| "Raft 설정 스냅샷 테이블의 키가 UTF-8이 아닙니다")?
                    .to_string();
                if fields.iter().any(|(existing, _)| *existing == key) {
                    return Err("Raft 설정 스냅샷 테이블에 중복 키가 있습니다".into());
                }
                let value = decode_raft_snapshot_value(bytes, pos, depth + 1)?;
                fields.push((key, value));
            }
            Ok(Json::Obj(fields))
        }
        _ => Err("Raft 설정 스냅샷 값 태그가 올바르지 않습니다".into()),
    }
}

/** @brief 바이트를 이만큼 잘라 낸다. */
fn raft_snapshot_take<'a>(
    bytes: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], String> {
    let end = pos
        .checked_add(len)
        .ok_or("Raft 설정 스냅샷 위치가 범위를 넘었습니다")?;
    let value = bytes
        .get(*pos..end)
        .ok_or("Raft 설정 스냅샷 데이터가 중간에서 잘렸습니다")?;
    *pos = end;
    Ok(value)
}

/** @brief 16비트 수를 잘라 낸다. */
fn raft_snapshot_take_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        raft_snapshot_take(bytes, pos, 2)?
            .try_into()
            .map_err(|_| "Raft 설정 스냅샷의 16비트 정수 데이터를 읽을 수 없습니다")?,
    ))
}

/** @brief 32비트 수를 잘라 낸다. */
fn raft_snapshot_take_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    Ok(u32::from_be_bytes(
        raft_snapshot_take(bytes, pos, 4)?
            .try_into()
            .map_err(|_| "Raft 설정 스냅샷의 32비트 정수 데이터를 읽을 수 없습니다")?,
    ))
}

/** @brief 클러스터에 올릴 제안을 읽는다. 형식이 다르면 거부한다. */
fn parse_cluster_proposal(body: &str) -> Result<onetdns_core::json::Json, String> {
    let json = onetdns_core::json::parse(body)
        .map_err(|error| format!("JSON 요청 본문을 해석할 수 없습니다: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = json else {
        return Err("Raft 설정 변경 요청은 patch 객체 하나만 포함해야 합니다".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("Raft 설정 변경 요청은 patch 객체 하나만 포함해야 합니다".into());
    }
    let patch = fields[0].1.clone();
    let onetdns_core::json::Json::Obj(entries) = &patch else {
        return Err("Raft 설정 변경 요청의 patch는 객체여야 합니다".into());
    };
    if entries.is_empty() || entries.len() > 128 {
        return Err("Raft 설정 변경 항목 수가 허용 범위를 벗어났습니다".into());
    }
    Ok(patch)
}

/** @brief Raft 로그 항목을 설정 변경 목록으로 바꾼다. */
fn decode_raft_command_patch(
    data: &[u8],
) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let text = std::str::from_utf8(data)
        .map_err(|error| format!("Raft 명령이 올바른 UTF-8 문자열이 아닙니다: {error}"))?;
    let json = onetdns_core::json::parse(text)
        .map_err(|error| format!("Raft 명령 JSON 요청 본문이 올바르지 않습니다: {error}"))?;
    let onetdns_core::json::Json::Obj(fields) = &json else {
        return Err("Raft 명령은 patch 객체 하나만 포함해야 합니다".into());
    };
    if fields.len() != 1 || fields[0].0 != "patch" {
        return Err("Raft 명령은 patch 객체 하나만 포함해야 합니다".into());
    }
    let patch_value = json
        .get("patch")
        .ok_or_else(|| "Raft 설정 변경 요청에 patch 객체가 없습니다".to_string())?;
    validate_raft_patch_scope(patch_value)?;
    let onetdns_core::json::Json::Obj(patch) = patch_value else {
        return Err("Raft 설정 변경 요청에 patch 객체가 없습니다".into());
    };
    if patch.is_empty() || patch.len() > 128 {
        return Err("Raft 설정 변경 항목 수가 허용 범위를 벗어났습니다".into());
    }
    let mut patch = patch.clone();
    materialize_mode_acl_patch(&mut patch)?;
    Ok(patch)
}

/** @brief 클러스터가 정한 설정 변경을 실제로 적용한다. */
fn apply_raft_patch(
    context: &RaftApplyContext,
    patch: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    if patch.is_empty() || patch.len() > MAX_RAFT_SNAPSHOT_KEYS {
        return Err("Raft 설정 상태 항목 수가 허용 범위를 벗어났습니다".into());
    }
    validate_raft_patch_scope(&onetdns_core::json::Json::Obj(patch.to_vec()))?;
    let edit = |text: &str| {
        let mut output = text.to_string();
        for (key, value) in patch {
            if key.is_empty() || key.len() > 128 {
                return Err("Raft 설정 항목 이름의 길이가 허용 범위를 벗어났습니다".into());
            }
            output = match value {
                /* null 은 항목을 지우라는 합의다. 빈 값으로 적으면 기본값으로 돌아가지 않는다. */
                onetdns_core::json::Json::Null => remove_config_key(&output, key)?,
                value => rewrite_config_kv(&output, key, &json_to_raft_toml_literal(value, 0)?)?,
            };
        }
        Ok(output)
    };

    let _write_guard = config_write_lock().lock_recover();
    let generation = context.generation.lock_recover().clone();
    let mode = if let Some(hot_apply) = generation.hot_apply.as_ref() {
        apply_config_edit_smart_locked(
            &context.path,
            &context.prev,
            &context.applied,
            &generation.reload,
            hot_apply,
            edit,
        )?
        .mode
    } else {
        apply_config_edit_locked(&context.path, &context.prev, &generation.reload, edit)?;
        ConfigApplyMode::ServiceRestart
    };
    onetdns_core::info!(
        event = "raft.config_applied",
        keys = patch.len(),
        mode = mode.as_str(),
        "Raft로 복제된 설정을 적용했습니다"
    );
    Ok(())
}

/**
 * @brief 클러스터 상태 JSON에 이 노드의 Raft 신원을 붙인다.
 * @details 다른 노드의 cluster_raft_peers 에 적을 공개 키와 그대로 붙여 넣을 항목을 알려
 *          준다. 서명 키만 있으면 Raft를 켜기 전에도 보여 준다. 노드를 연결하려면 켜기 전에
 *          서로의 공개 키를 알아야 하기 때문이다. 서명 키가 없거나 형식이 틀리면 null 이다.
 */
fn with_raft_identity(status: &str, config: &Config) -> String {
    use onetdns_core::json::Json;
    let public_key = hex32(config.cluster_raft_node_key.trim())
        .map(|seed| hex_lower(&onetdns_cluster::transport::node_public_key(&seed)));
    let peer_entry = match (&public_key, &config.cluster_raft_listen) {
        (Some(key), Some(listen)) => {
            Json::Str(format!("{}@{listen}#{key}", config.cluster_node_id))
        }
        _ => Json::Null,
    };
    let identity = Json::Obj(vec![
        ("node_id".into(), Json::Num(config.cluster_node_id as f64)),
        (
            "public_key".into(),
            public_key.map_or(Json::Null, Json::Str),
        ),
        ("peer_entry".into(), peer_entry),
    ]);
    match onetdns_core::json::parse(status) {
        Ok(Json::Obj(mut fields)) => {
            fields.push(("identity".into(), identity));
            Json::Obj(fields).to_text()
        }
        _ => status.to_string(),
    }
}

/** @brief 바이트를 소문자 16진 문자열로. */
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/** @brief 클러스터 없이 실행 중인 상태를 JSON으로. */
fn standalone_cluster_status_json(backend: &str, listeners: usize) -> String {
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"standalone\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true}},\"peers\":[]}}",
        onetdns_core::json::escape(backend)
    )
}

/** @brief 클러스터 상태를 JSON으로. */
fn peer_cluster_status_json(
    peers: &[String],
    backend: &str,
    listeners: usize,
    resolver: &http::HostResolver,
) -> String {
    let probes: Vec<_> = peers
        .iter()
        .map(|url| {
            let probe_url = url.clone();
            let resolver = resolver.clone();
            let spawned = std::thread::Builder::new()
                .name("cluster-probe".into())
                .spawn(move || {
                    let base = probe_url.trim_end_matches('/');
                    let started = std::time::Instant::now();
                    let healthy = http::get(&format!("{base}/healthz"))
                        .timeout(Duration::from_secs(2))
                        .resolver(resolver)
                        .call()
                        .ok()
                        .and_then(|r| r.into_string().ok())
                        .map(|b| b.trim() == "ok")
                        .unwrap_or(false);
                    (healthy, started.elapsed())
                });
            if let Err(error) = &spawned {
                onetdns_core::warn!(
                    event = "cluster.peer_probe_spawn_failed",
                    peer = %url,
                    error = %error,
                    "상대 노드 상태 조사 스레드를 만들지 못했습니다"
                );
            }
            (url, spawned.ok())
        })
        .collect();

    let items: Vec<String> = probes
        .into_iter()
        .map(|(url, handle)| {

            let outcome = handle.and_then(|handle| handle.join().ok());
            let healthy = outcome.map(|(healthy, _)| healthy).unwrap_or(false);
            let rtt = match outcome {
                Some((true, elapsed)) => elapsed.as_millis().to_string(),
                _ => "null".to_string(),
            };
            format!(
                "{{\"id\":null,\"url\":{},\"healthy\":{healthy},\"role\":\"member\",\"rtt_ms\":{rtt}}}",
                onetdns_core::json::escape(url)
            )
        })
        .collect();
    format!(
        "{{\"self\":{{\"id\":null,\"role\":\"member\",\"backend\":{},\"listeners\":{listeners},\"leader\":null,\"term\":null,\"commit_index\":null,\"last_applied\":null,\"last_index\":null,\"snapshot_index\":null,\"retained_log_entries\":null,\"fatal\":null,\"healthy\":true}},\"peers\":[{}]}}",
        onetdns_core::json::escape(backend),
        items.join(",")
    )
}

/**
 * @brief 하루마다 서명 영역의 RRSIG를 다시 서명하는 스레드를 시작한다.
 * @details 서명 키는 돌 때마다 공유 핸들에서 읽는다. 키 교체나 설정 변경 뒤에도 이전 키로
 *          서명하지 않는다.
 */
fn spawn_resign_timer(
    zone_signers: SharedZoneSigners,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: Arc<Mutex<std::collections::HashMap<Vec<u8>, native::ZoneJournal>>>,
    zone_files: Vec<(onetdns_proto::Name, std::path::PathBuf)>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    std::thread::Builder::new()
        .name("dnssec-resign".into())
        .spawn(move || loop {
            if sleep_or_shutdown(86_400, &shutdown) {
                break;
            }
            let signers = zone_signers.load();
            for (origin, ctx) in signers.iter() {
                let zone = {
                    let cur = store.load();
                    cur.zones()
                        .iter()
                        .find(|z| z.origin().eq_ignore_case(origin))
                        .cloned()
                };
                let Some(zone) = zone else {
                    continue;
                };
                let path = zone_files
                    .iter()
                    .find(|(candidate, _)| candidate.eq_ignore_case(origin))
                    .map(|(_, path)| path.as_path());
                if let Err(error) = apply_zone_mutation(
                    &store,
                    zone,
                    std::slice::from_ref(&(origin.clone(), ctx.clone())),
                    &journal,
                    path,
                    &notify,
                    "dnssec resign",
                ) {
                    onetdns_core::error!(event = "dnssec.resign_failed", zone = %origin.to_ascii_lower(), %error, "DNSSEC 재서명에 실패해 기존 서명을 유지합니다");
                } else {
                    onetdns_core::info!(event = "dnssec.resigned", zone = %origin.to_ascii_lower(), "RRSIG를 다시 서명하고 영역 일련번호를 갱신했습니다");
                }
            }
        })
        .map(Some)
}

/** @brief 이 영역의 서명 키 경로. */
fn zsk_path_for(zc: &onetdns_config::ZoneConfig) -> std::path::PathBuf {
    zc.dnssec_key.clone().unwrap_or_else(|| {
        let base = zc.file.clone().unwrap_or_default();
        std::path::PathBuf::from(format!("{}.key", base.display()))
    })
}

/** @brief 이 영역이 키를 둘로 나눠 쓰는지. */
fn zone_is_split_key(zc: &onetdns_config::ZoneConfig) -> bool {
    if zc.dnssec_ksk.is_some() {
        return true;
    }
    let base = zc.file.clone().unwrap_or_default();
    std::path::PathBuf::from(format!("{}.ksk", base.display())).exists()
}

/** @brief 서명 키를 주기적으로 교체하는 스레드를 시작한다. */
fn spawn_zsk_rollover(
    zones: Vec<(onetdns_proto::Name, std::path::PathBuf)>,
    interval: u64,
    reload_keys: ZoneKeyReload,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if interval == 0 || zones.is_empty() {
        return Ok(None);
    }
    let timing = rollover::RollTiming::from_interval(interval);
    let check = (interval / 100).clamp(1, 3600);
    std::thread::Builder::new()
        .name("zsk-rollover".into())
        .spawn(move || loop {
            if sleep_or_shutdown(check, &shutdown) {
                break;
            }
            let now = unix_now();
            let mut rolled = Vec::new();
            for (origin, zsk) in &zones {
                let sp = rollover::state_path(zsk);
                let stored = match read_text_limited(&sp, LOCAL_STATE_MAX_BYTES) {
                    Ok(text) => match rollover::RollState::parse(&text) {
                        Some(state) => Some(state),
                        None => {
                            onetdns_core::warn!(event = "dnssec.zsk_state_corrupt", zone = %origin.to_ascii_lower(), path = %sp.display(), "ZSK 교체 상태 파일의 형식이 깨져 있어 첫 단계부터 다시 시작합니다");
                            None
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => {
                        onetdns_core::warn!(event = "dnssec.zsk_state_read_failed", zone = %origin.to_ascii_lower(), path = %sp.display(), error = %e, "ZSK 교체 상태 파일을 읽지 못해 첫 단계부터 다시 시작합니다");
                        None
                    }
                };
                let state = match stored {
                    Some(state) => state,
                    None => {
                        let state = rollover::RollState::stable(now);
                        if let Err(e) = atomic_write_secret(&sp, state.serialize().as_bytes()) {
                            onetdns_core::error!(event = "dnssec.zsk_init_save_failed", zone = %origin.to_ascii_lower(), error = %e, "ZSK 교체 초기 상태를 저장하지 못해 키 교체를 시작하지 않습니다");
                            continue;
                        }
                        state
                    }
                };
                let Some(next_state) = rollover::advance(state, now, timing) else {
                    continue;
                };
                let key_backup = match RollKeyBackup::capture(zsk) {
                    Ok(backup) => backup,
                    Err(e) => {
                        onetdns_core::error!(event = "dnssec.zsk_backup_failed", zone = %origin.to_ascii_lower(), error = %e, "ZSK 파일을 백업하지 못해 키 교체를 보류합니다");
                        continue;
                    }
                };
                if !apply_roll_transition(origin, zsk, state.phase, next_state.phase) {

                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_restore_failed", zone = %origin.to_ascii_lower(), error = %rollback_err, "ZSK 교체 실패 후 키 파일을 이전 상태로 되돌리지 못했습니다");
                    }
                    continue;
                }

                if let Err(e) = atomic_write_secret(&sp, next_state.serialize().as_bytes()) {
                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_save_and_restore_failed", zone = %origin.to_ascii_lower(), error = %e, rollback_error = %rollback_err, "ZSK 상태 저장과 키 복구가 모두 실패했습니다");
                    } else {
                        onetdns_core::error!(event = "dnssec.zsk_rolled_back", zone = %origin.to_ascii_lower(), error = %e, "ZSK 교체 상태를 저장하지 못해 키 변경을 되돌렸습니다");
                    }
                    continue;
                }
                rolled.push(origin.clone());
            }
            if !rolled.is_empty() {
                match reload_keys(&rolled) {
                    Ok(()) => onetdns_core::info!(event = "dnssec.zsk_step_applied", zones = rolled.len(), "ZSK 교체 단계를 갱신하고 서명 키와 DNS 영역만 다시 불러왔습니다"),
                    Err(error) => onetdns_core::error!(event = "dnssec.zsk_reload_failed", %error, "ZSK 교체 단계는 저장했지만 새 키로 DNS 영역을 다시 만들지 못했습니다. 다음 확인 주기에 다시 시도합니다"),
                }
            }
        })
        .map(Some)
}

/** @brief 서명 영역과 그 키. 키 교체와 설정 변경이 이 핸들 하나를 교체한다. */
type SharedZoneSigners = Arc<onetdns_core::ArcSwap<Vec<(onetdns_proto::Name, ZoneSigningCtx)>>>;

/** @brief 키를 교체한 영역들을 새 키로 다시 만든다. */
type ZoneKeyReload = Arc<dyn Fn(&[onetdns_proto::Name]) -> Result<(), String> + Send + Sync>;

/** @brief 교체 전 키. 실패하면 되돌린다. */
struct RollKeyBackup {
    /** @brief 지금 쓰는 키. */
    active: FileBackup,
    /** @brief 다음에 쓸 키. */
    next: FileBackup,
    /** @brief 직전에 쓰던 키. */
    prev: FileBackup,
}

impl RollKeyBackup {
    /** @brief 지금 키를 담아 둔다. */
    fn capture(zsk: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            active: FileBackup::capture(zsk, true)?,
            next: FileBackup::capture(&rollover::next_path(zsk), true)?,
            prev: FileBackup::capture(&rollover::prev_path(zsk), true)?,
        })
    }

    /** @brief 담아 둔 키로 되돌린다. */
    fn restore(&self, zsk: &std::path::Path) -> std::io::Result<()> {
        let next_path = rollover::next_path(zsk);
        let prev_path = rollover::prev_path(zsk);
        let paths = [
            (zsk, &self.active),
            (next_path.as_path(), &self.next),
            (prev_path.as_path(), &self.prev),
        ];
        let mut errors = Vec::new();
        for (path, backup) in paths {
            if let Err(e) = backup.restore(path) {
                errors.push(format!("{}: {e}", path.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }
}

/** @brief 키 교체를 한 단계 진행한다. 새 키를 미리 알리고 충분히 기다린 뒤에 바꿔야 검증이 끊기지 않는다. */
fn apply_roll_transition(
    origin: &onetdns_proto::Name,
    zsk: &std::path::Path,
    from: rollover::Phase,
    to: rollover::Phase,
) -> bool {
    use rollover::Phase;
    let next = rollover::next_path(zsk);
    let prev = rollover::prev_path(zsk);
    match (from, to) {
        (Phase::Stable, Phase::Publish) => {
            match onetdns_dnssec::sign::ZoneSigner::generate(origin.clone(), random_seed())
                .to_pkcs8_pem()
            {
                Some(pem) => match atomic_write_secret(&next, pem.as_bytes()) {
                    Ok(()) => {
                        onetdns_core::info!(event = "dnssec.zsk_next_published", zone = %origin.to_ascii_lower(), "다음 ZSK를 미리 게시했습니다");
                        true
                    }
                    Err(e) => {
                        onetdns_core::error!(event = "dnssec.zsk_next_save_failed", zone = %origin.to_ascii_lower(), error = %e, "다음 ZSK를 저장하지 못해 키 교체를 보류합니다");
                        false
                    }
                },
                None => {
                    onetdns_core::error!(event = "dnssec.zsk_next_encode_failed", zone = %origin.to_ascii_lower(), "새로 만든 ZSK를 PKCS#8로 옮기지 못해 키 교체를 보류합니다");
                    false
                }
            }
        }
        (Phase::Publish, Phase::Activate) => {
            if !next.exists() {
                onetdns_core::warn!(event = "dnssec.zsk_promote_no_next", zone = %origin.to_ascii_lower(), ".next 키가 없어 ZSK 승격을 보류합니다");
                return false;
            }
            if let Err(e) = replace_file(zsk, &prev) {
                onetdns_core::error!(event = "dnssec.zsk_prev_move_failed", error = %e, "현재 ZSK를 .prev 파일로 옮기지 못했습니다");
                return false;
            }
            if let Err(e) = replace_file(&next, zsk) {
                onetdns_core::error!(event = "dnssec.zsk_promote_failed", error = %e, ".next 키를 활성 ZSK로 바꾸지 못해 이전 키를 유지합니다");
                if let Err(rollback_err) = replace_file(&prev, zsk) {
                    onetdns_core::error!(event = "dnssec.zsk_revert_failed", error = %rollback_err, "현재 ZSK를 즉시 이전 상태로 되돌리지 못했습니다");
                }
                return false;
            }
            onetdns_core::info!(event = "dnssec.zsk_activated", zone = %origin.to_ascii_lower(), "새 ZSK를 활성화했습니다");
            true
        }
        (Phase::Activate, Phase::Stable) => {
            if let Err(e) = std::fs::remove_file(&prev) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    onetdns_core::error!(event = "dnssec.zsk_retire_failed", error = %e, "이전 ZSK를 폐기하지 못해 안정 상태 전환을 보류합니다");
                    return false;
                }
            }
            onetdns_core::info!(event = "dnssec.zsk_retired", zone = %origin.to_ascii_lower(), "이전 ZSK를 폐기해 안정 상태로 전환했습니다");
            true
        }
        _ => {
            onetdns_core::error!(event = "dnssec.zsk_phase_unexpected", zone = %origin.to_ascii_lower(), from = ?from, to = ?to, "ZSK 교체 단계가 순서를 벗어나 이번 전환을 건너뜁니다");
            false
        }
    }
}

/** @brief 재귀를 시작할 루트 서버들. */
fn recursor_roots(cfg: &Config) -> Vec<SocketAddr> {
    if cfg.root_hints.is_empty() {
        onetdns_recurse::default_roots()
    } else {
        cfg.root_hints
            .iter()
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect()
    }
}

/**
 * @brief 권한 서버에 TCP로만 물을지의 판정. 프로세스에 하나만 둔다.
 *
 * @details UDP 53번 가로채기는 호스트 망의 성질이라 설정을 다시 읽어도 바뀌지 않는다.
 *          재귀기마다 따로 두면 다시 읽을 때 새로 만든 재귀기가 판정을 잃는다.
 */
fn authority_tcp_switch() -> Arc<std::sync::atomic::AtomicBool> {
    /** @brief 판정 값. */
    static SWITCH: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    SWITCH
        .get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .clone()
}

/** @brief 가로채기 판정을 공유하는 재귀기를 만든다. */
fn new_recursor(roots: Vec<SocketAddr>, timeout: Duration) -> onetdns_recurse::Recursor {
    onetdns_recurse::Recursor::new(roots, timeout).with_authority_tcp(authority_tcp_switch())
}

/**
 * @brief 일반 DNS가 중간에서 가로채이는지 확인한다.
 *
 * @details 루트 서버는 비재귀 질의에 위임만 돌려주므로, 주소 답이 오면 중간에서 다른 것이
 *          대신 답한 것이다. UDP로 물은 루트가 하나도 답하지 않는 망도 있다. 두 경우 모두
 *          같은 루트에 TCP로 다시 물어 위임이 오면 권한 서버 질의를 TCP로 돌린다. TCP까지
 *          가로채이면 재귀를 쓸 수 없으므로 경고만 남긴다.
 */
fn detect_dns53_interception(
    roots: Vec<SocketAddr>,
    timeout: Duration,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    /** @brief 한 번만 확인한다. */
    static PROBED: AtomicBool = AtomicBool::new(false);
    if roots.is_empty() || PROBED.swap(true, Ordering::Relaxed) {
        return None;
    }
    let probe_timeout = timeout.min(Duration::from_secs(2));
    match std::thread::Builder::new()
        .name("dns53-hijack-probe".into())
        .spawn(move || {
            use onetdns_proto::{DnsClass, Header, Message, Question, RecordType};
            let Ok(name) = onetdns_proto::Name::from_str("example.com") else {
                return;
            };
            let probe = Message {
                header: Header {
                    id: 0x5454,
                    recursion_desired: false,
                    ..Default::default()
                },
                questions: vec![Question {
                    name,
                    qtype: RecordType::A,
                    qclass: DnsClass::IN,
                }],
                ..Default::default()
            };
            let Ok(wire) = probe.try_encode() else {
                return;
            };
            let tcp_gives_referral = |root: SocketAddr| {
                onetdns_forward::query_server_over(
                    root,
                    &probe,
                    probe_timeout,
                    onetdns_forward::AuthorityTransport::Tcp,
                    false,
                )
                .is_ok_and(|tcp| !is_forged_root_answer(&tcp))
            };
            let mut silent_root = None;
            'roots: for root in roots.iter().take(3) {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let bind = if root.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let Ok(sock) = std::net::UdpSocket::bind(bind) else {
                    continue;
                };
                let wait = onetdns_core::udp::RecvWait::new(
                    probe_timeout.min(Duration::from_millis(250)),
                );
                if wait.install(&sock).is_err() || sock.send_to(&wire, root).is_err() {
                    continue;
                }
                let mut buf = [0u8; 1500];
                let deadline = std::time::Instant::now() + probe_timeout;
                let (n, from) = loop {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    match wait.recv_from(&sock, &mut buf) {
                        Ok(received) => break received,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) && std::time::Instant::now() < deadline => {}
                        Err(_) => {
                            silent_root.get_or_insert(*root);
                            continue 'roots;
                        }
                    }
                };
                if from != *root {
                    continue;
                }
                let Ok(resp) = Message::parse(&buf[..n]) else {
                    continue;
                };

                if !is_forged_root_answer(&resp) {
                    return;
                }
                if tcp_gives_referral(*root) {
                    authority_tcp_switch().store(true, Ordering::Relaxed);
                    onetdns_core::warn!(event = "net.port53_udp_intercepted",
                        root = %root,
                        "외부 UDP 53번이 가로채져 있어 재귀 해석의 권한 서버 질의를 TCP로 보냅니다"
                    );
                } else {
                    onetdns_core::warn!(event = "net.port53_intercepted",
                        root = %root,
                        "외부 53번 포트가 가로채져 직접 재귀 해석을 사용할 수 없습니다. 암호화 업스트림 DNS 서버 사용을 권장합니다"
                    );
                }
                return;
            }
            if let Some(root) = silent_root {
                if !shutdown.load(Ordering::Relaxed) && tcp_gives_referral(root) {
                    authority_tcp_switch().store(true, Ordering::Relaxed);
                    onetdns_core::warn!(event = "net.port53_udp_blocked",
                        root = %root,
                        "루트 서버가 UDP 53번으로 답하지 않아 재귀 해석의 권한 서버 질의를 TCP로 보냅니다"
                    );
                }
            }
        })
    {
        Ok(thread) => Some(thread),
        Err(error) => {
            PROBED.store(false, Ordering::Relaxed);
            onetdns_core::warn!(event = "net.intercept_probe_thread_failed", %error, "53번 포트 가로채기 진단 스레드를 시작하지 못했습니다");
            None
        }
    }
}

/** @brief 루트 서버가 비재귀 질의에 줄 수 없는 주소 답이 들어 있는지. */
fn is_forged_root_answer(resp: &onetdns_proto::Message) -> bool {
    resp.answers
        .iter()
        .any(|r| matches!(r.rdata, onetdns_proto::RData::A(_)))
}

/**
 * @brief RFC 8145 신호 질의에 쓸 이름의 첫 레이블.
 * @param anchors 검증에 실제로 쓰는 루트 신뢰 앵커.
 * @return 앵커가 없으면 알릴 것이 없으므로 없다.
 */
fn ta_signal_label(anchors: &[onetdns_dnssec::Ds]) -> Option<String> {
    let mut tags: Vec<u16> = anchors.iter().map(|anchor| anchor.key_tag).collect();
    tags.sort_unstable();
    tags.dedup();
    if tags.is_empty() {
        return None;
    }
    Some(format!(
        "_ta-{}",
        tags.iter()
            .map(|tag| format!("{tag:04x}"))
            .collect::<Vec<_>>()
            .join("-")
    ))
}

/**
 * @brief 이 서버가 쓰는 신뢰 루트를 주기적으로 알린다.
 * @param anchors 리졸버가 검증에 쓰는 앵커 저장소. 설정 파일의 앵커나 RFC 5011로 바뀐
 *                앵커가 여기 담기므로, 내장 앵커 대신 이것을 알려야 실제 상태가 나간다.
 */
fn spawn_ta_signaling(
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    timeout: Duration,
    roots: Vec<SocketAddr>,
    deny: Vec<onetdns_core::IpNet>,
    allow: Vec<onetdns_core::IpNet>,
    max_ttl: u32,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("ta-signaling".into())
        .spawn(move || loop {
            let current = anchors.load();
            if let Some(label) = ta_signal_label(&current) {
                let r = new_recursor(roots.clone(), timeout)
                    .with_server_acl(deny.clone(), allow.clone())
                    .with_recursive_cache_ttl_max(max_ttl)
                    .with_trust_anchors(current.to_vec());
                match onetdns_proto::Name::from_str(&label) {
                    Ok(name) => match r.resolve(&name, onetdns_proto::RecordType(10)) {
                        Ok(_) => {
                            onetdns_core::info!(event = "dnssec.ta_signal_sent", signal = %label, "RFC 8145 신뢰 앵커 신호를 전송했습니다");
                        }
                        Err(error) => {
                            onetdns_core::warn!(event = "dnssec.ta_signal_failed", signal = %label, error = ?error, "RFC 8145 신뢰 앵커 신호를 보내지 못했습니다");
                        }
                    },
                    Err(error) => {
                        onetdns_core::warn!(event = "dnssec.ta_signal_name_invalid", signal = %label, error = ?error, "신뢰 앵커 신호 이름을 만들지 못했습니다");
                    }
                }
            }
            if sleep_or_shutdown(24 * 3600, &shutdown) {
                break;
            }
        })
}

/**
 * @brief 전달 검증기가 쓸 루트 신뢰 기준.
 * @details 설정 파일로 앵커를 준 사람은 그것을, 아니면 내장 앵커를 쓴다. 체인을 새로 구성할
 *          때마다 이 설정에서 다시 읽는다. 처음 구성할 때 읽은 값을 계속 가지고 있으면 앵커 파일을
 *          바꿔도 이전 키로 검증한다.
 */
fn forward_trust_anchors(
    anchor_file: Option<&std::path::Path>,
) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    match anchor_file {
        Some(path) => load_configured_trust_anchors(path),
        None => Ok(onetdns_dnssec::root_trust_anchors()),
    }
}

/** @brief 설정한 신뢰 루트를 읽는다. 못 읽으면 시작하지 않는다. */
fn load_configured_trust_anchors(path: &std::path::Path) -> BoxResult<Vec<onetdns_dnssec::Ds>> {
    let text = read_text_limited(path, LOCAL_STATE_MAX_BYTES).with_context(|| {
        format!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'을 읽지 못했습니다",
            path.display()
        )
    })?;
    let manager = onetdns_dnssec::anchor::AnchorManager::deserialize(&text).ok_or_else(|| {
        crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'의 형식이 올바르지 않습니다",
            path.display()
        )
    })?;
    if !manager.zone.is_root() {
        return Err(crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'은 현재 루트 영역 앵커만 지원합니다",
            path.display()
        ));
    }
    let anchors = manager.active_ds();
    if anchors.is_empty() {
        return Err(crate::anyhow!(
            "DNSSEC 신뢰 앵커 상태 파일 '{}'에 활성 키가 없습니다",
            path.display()
        ));
    }
    Ok(anchors)
}

/** @brief 신뢰 루트가 바뀌는 것을 따라가는 스레드를 시작한다. */
fn spawn_rfc5011(
    plan: &resolver_chain::RecursivePlan,
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use onetdns_dnssec::anchor::{extract_dnskey_rrset, AnchorManager};
    let anchor_file = plan.anchor_state_file();
    let (deny, allow) = plan.server_acl();
    let roots = plan.roots();
    let max_ttl = plan.max_ttl();
    let timeout = plan.timeout();
    std::thread::Builder::new()
        .name("rfc5011".into())
        .spawn(move || {
        let root = onetdns_proto::Name::root();

        let mut mgr = read_text_limited(&anchor_file, LOCAL_STATE_MAX_BYTES)
            .ok()
            .and_then(|t| AnchorManager::deserialize(&t))
            .unwrap_or_else(|| AnchorManager {
                zone: root.clone(),
                keys: Vec::new(),
                hold_down_secs: onetdns_dnssec::anchor::DEFAULT_HOLD_DOWN_SECS,
            });

        let fetcher = new_recursor(roots, timeout)
            .with_server_acl(deny, allow)
            .with_recursive_cache_ttl_max(max_ttl)
            .with_dnssec();
        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            match fetcher.fetch_zone_dnskey(&root) {
                Ok(records) => {
                    let previous_mgr = mgr.clone();
                    let (keys, sigs) = extract_dnskey_rrset(&records, &root);
                    if mgr.keys.is_empty() {

                        let anchors_ds = onetdns_dnssec::root_trust_anchors();
                        let bootstrap: Vec<onetdns_dnssec::Dnskey> = keys
                            .iter()
                            .filter_map(onetdns_dnssec::Dnskey::from_record)
                            .filter(|k| {
                                anchors_ds.iter().any(|ds| {
                                    onetdns_dnssec::verify_ds(ds, k, &root).is_ok()
                                })
                            })
                            .collect();
                        if !bootstrap.is_empty() {
                            mgr = AnchorManager::bootstrap(root.clone(), bootstrap, unix_now());
                            onetdns_core::info!(event = "dnssec.rfc5011_initialized", keys = mgr.active_ds().len(), "RFC 5011 루트 KSK 초기화를 마쳤습니다");
                        }
                    } else {
                        let changed = mgr.update(&keys, &sigs, unix_now());
                        if changed {
                            onetdns_core::info!(event = "dnssec.rfc5011_state_changed", active = mgr.active_ds().len(), "RFC 5011 신뢰 앵커 상태가 바뀌었습니다");
                        }
                    }

                    if let Err(e) = crate::atomic_write(&anchor_file, mgr.serialize().as_bytes()) {

                        mgr = previous_mgr;
                        onetdns_core::warn!(event = "dnssec.rfc5011_save_failed", error = %e, "RFC 5011 신뢰 앵커 상태를 저장하지 못해 메모리의 변경도 되돌렸습니다");
                    } else {
                        let active = mgr.active_ds();
                        if !active.is_empty() {
                            anchors.store(Arc::new(active));
                        }
                    }
                }
                Err(e) => onetdns_core::warn!(event = "dnssec.rfc5011_query_failed", error = %e, "RFC 5011 루트 DNSKEY를 조회하지 못했습니다. 다음 주기에 다시 시도합니다"),
            }

            if sleep_or_shutdown(12 * 3600, &shutdown) {
                break;
            }
        }
        })
}

#[derive(Clone)]
/** @brief 영역 하나를 서명할 키들. */
struct ZoneSigningCtx {
    /** @brief 실제로 서명하는 것. */
    signer: Arc<onetdns_dnssec::sign::ZoneSigner>,
    /** @brief 부재 증명 방식. */
    mode: onetdns_dnssec::sign::DenialMode,
}

impl ZoneSigningCtx {
    /** @brief 이 기록들에 서명한다. */
    fn sign(&self, records: &[onetdns_proto::Record]) -> Vec<onetdns_proto::Record> {
        self.sign_reusing(records, &[])
    }

    /**
     * @brief 지난 서명을 물려받아 서명한다.
     * @param previous 이 서버가 직접 서명해 저장소에 가지고 있던 레코드들. 바깥에서 받은 것을
     *                 넘기면 검증하지 않은 서명을 내보내게 된다.
     */
    fn sign_reusing(
        &self,
        records: &[onetdns_proto::Record],
        previous: &[onetdns_proto::Record],
    ) -> Vec<onetdns_proto::Record> {
        onetdns_dnssec::sign::sign_zone_reusing(
            records,
            &self.signer,
            unix_now(),
            &self.mode,
            previous,
        )
    }
}

/** @brief 무작위 시드. */
fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    onetdns_tls::sys::fill_random(&mut s);
    s
}

/**
 * @brief 키를 읽거나 만든다.
 * @param algorithm 새로 만들 때 쓸 알고리즘. 이미 있는 키는 파일이 스스로 무엇인지 말한다.
 */
fn load_or_create_key_pem(
    path: &std::path::Path,
    label: &str,
    algorithm: onetdns_dnssec::sign::SignAlgorithm,
) -> Result<Zeroizing<String>, String> {
    match read_text_limited(path, LOCAL_KEY_MAX_BYTES) {
        Ok(pem) => return Ok(Zeroizing::new(pem)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "{label} DNSSEC 키 '{}'를 읽지 못했습니다: {error}",
                path.display()
            ));
        }
    }
    let s = onetdns_dnssec::sign::ZoneSigner::generate_with(
        onetdns_proto::Name::root(),
        random_seed(),
        algorithm,
    );
    let pem = s
        .to_pkcs8_pem()
        .ok_or_else(|| format!("{label} DNSSEC 키를 PKCS#8 형식으로 만들지 못했습니다"))?;
    if let Err(e) = atomic_write_secret(path, pem.as_bytes()) {
        return Err(format!(
            "{label} DNSSEC 키 '{}'를 저장하지 못했습니다: {e}",
            path.display()
        ));
    }
    onetdns_core::info!(event = "dnssec.key_created", key_role = label, path = %path.display(), key_algorithm = algorithm.number(), "DNSSEC 서명 키를 생성해 저장했습니다");
    Ok(pem)
}

/** @brief 이 영역의 서명기를 올린다. */
fn load_zone_signer(zc: &onetdns_config::ZoneConfig) -> Result<ZoneSigningCtx, String> {
    use onetdns_dnssec::sign::{DenialMode, Nsec3Params, ZoneSigner};
    let origin = onetdns_proto::Name::from_str(&zc.origin)
        .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zc.origin))?;
    let base = zc.file.clone().unwrap_or_default();
    let zsk_path = zc
        .dnssec_key
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.key", base.display())));
    let algorithm = if zc.dnssec_algorithm.is_empty() {
        onetdns_dnssec::sign::SignAlgorithm::default()
    } else {
        onetdns_dnssec::sign::SignAlgorithm::from_str(&zc.dnssec_algorithm).ok_or_else(|| {
            format!(
                "DNS 영역 '{}'의 `dnssec_algorithm` 값을 알 수 없습니다: {}",
                zc.origin, zc.dnssec_algorithm
            )
        })?
    };
    let zsk_pem = load_or_create_key_pem(&zsk_path, "ZSK", algorithm)?;

    let ksk_path = zc
        .dnssec_ksk
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.ksk", base.display())));
    let split = zc.dnssec_ksk.is_some() || ksk_path.exists();
    let signer = if split {
        let ksk_pem = load_or_create_key_pem(&ksk_path, "KSK", algorithm)?;
        ZoneSigner::from_pkcs8_pems(zsk_pem.as_str(), Some(ksk_pem.as_str()), origin.clone())
            .ok_or_else(|| {
                format!(
                    "DNS 영역 '{}'의 ZSK 또는 KSK 형식이 잘못되었습니다",
                    zc.origin
                )
            })?
    } else {
        ZoneSigner::from_pkcs8_pem(zsk_pem.as_str(), origin.clone())
            .ok_or_else(|| format!("DNS 영역 '{}'의 ZSK 형식이 잘못되었습니다", zc.origin))?
    };

    if signer.algorithm() != algorithm {
        return Err(format!(
            "DNS 영역 '{}'의 저장된 키는 알고리즘 {}인데 `dnssec_algorithm`은 {}입니다. 키 파일을 옮기거나 설정을 맞추십시오",
            zc.origin,
            signer.algorithm().number(),
            algorithm.number()
        ));
    }

    let mut published: Vec<onetdns_dnssec::Dnskey> = Vec::new();
    let mut seen_tags: Vec<u16> = vec![signer.dnskey().key_tag()];
    let mut add = |pem: &str, label: &str| -> Result<(), String> {
        if let Some(dk) = onetdns_dnssec::sign::zsk_dnskey_from_pkcs8_pem(pem) {
            let tag = dk.key_tag();
            if !seen_tags.contains(&tag) {
                seen_tags.push(tag);
                published.push(dk);
                onetdns_core::info!(event = "dnssec.additional_zsk_published", zone = %zc.origin, key_tag = tag, key_source = label, "추가 ZSK를 DNSKEY 응답에 게시했습니다");
            }
            Ok(())
        } else {
            Err(format!(
                "DNS 영역 '{}'의 추가 ZSK 형식이 잘못되었습니다: {label}",
                zc.origin
            ))
        }
    };
    if let Some(next_path) = &zc.dnssec_key_next {
        let pem = Zeroizing::new(read_text_limited(next_path, LOCAL_KEY_MAX_BYTES).map_err(
            |error| {
                format!(
                    "차기 ZSK '{}'를 읽지 못했습니다: {error}",
                    next_path.display()
                )
            },
        )?);
        add(pem.as_str(), "차기 ZSK 사전발행(dnssec_key_next)")?;
    }
    for slot in [
        rollover::next_path(&zsk_path),
        rollover::prev_path(&zsk_path),
    ] {
        match read_text_limited(&slot, LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => {
                let pem = Zeroizing::new(pem);
                add(pem.as_str(), "롤오버 슬롯 키 게시(DNSKEY)")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "롤오버 ZSK '{}'를 읽지 못했습니다: {error}",
                    slot.display()
                ));
            }
        }
    }
    let signer = if published.is_empty() {
        signer
    } else {
        signer.with_published_keys(published)
    };
    let mode = if zc.dnssec_nsec3 {
        DenialMode::Nsec3(Nsec3Params {
            iterations: zc.dnssec_nsec3_iterations,
            salt: Vec::new(),
        })
    } else {
        DenialMode::Nsec
    };
    Ok(ZoneSigningCtx {
        signer: Arc::new(signer),
        mode,
    })
}

/** @brief 영역에 서명을 붙인다. */
fn sign_authority_zone(
    zone: onetdns_authority::Zone,
    ctx: &ZoneSigningCtx,
) -> Option<onetdns_authority::Zone> {
    let origin = zone.origin().clone();
    let mut records = zone.axfr_records();
    records.pop();
    let signed = ctx.sign(&records);
    let out = onetdns_authority::Zone::from_records(signed).ok()?;
    if let Some(ds) = ctx.signer.ds() {
        let digest: String = ds.digest.iter().map(|b| format!("{b:02X}")).collect();
        let kind = if ctx.signer.is_split() {
            "KSK/ZSK 분리"
        } else {
            "CSK"
        };
        onetdns_core::info!(
            event = "dnssec.zone_signed",
            zone = %origin.to_ascii_lower(),
            ds = %format!("{} IN DS {} 13 2 {}", origin.to_ascii_lower(), ds.key_tag, digest),
            mode = kind,
            "DNSSEC 서명을 마쳤습니다. 표시된 DS 레코드를 부모 영역에 등록해야 합니다"
        );
    }
    Some(out)
}

/** @brief 클라이언트별로 다르게 답할 뷰들을 만든다. */
fn build_views(cfg: &Config) -> Result<Vec<native::NativeView>, String> {
    cfg.views
        .iter()
        .enumerate()
        .map(|(index, v)| {
            let mut nets = Vec::new();
            let mut ids = Vec::new();
            for c in &v.clients {
                match c.parse::<onetdns_core::IpNet>() {
                    Ok(n) => nets.push(n),
                    Err(_) => ids.push(c.clone()),
                }
            }
            let local_a = v
                .local_a
                .iter()
                .enumerate()
                .map(|(item, (name, ip))| {
                    let name = onetdns_proto::Name::from_str(name.trim()).map_err(|_| {
                        format!("views[{index}].local_a[{item}]의 DNS 이름이 올바르지 않습니다")
                    })?;
                    Ok((name.canonical_key(), *ip))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let local_aaaa = v
                .local_aaaa
                .iter()
                .enumerate()
                .map(|(item, (name, ip))| {
                    let name = onetdns_proto::Name::from_str(name.trim()).map_err(|_| {
                        format!("views[{index}].local_aaaa[{item}]의 DNS 이름이 올바르지 않습니다")
                    })?;
                    Ok((name.canonical_key(), *ip))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(native::NativeView {
                nets,
                ids,
                local_a,
                local_aaaa,
            })
        })
        .collect()
}

/** @brief 누가 무엇을 고칠 수 있는지 정한 규칙들을 만든다. */
fn build_update_policy(cfg: &Config) -> Result<Vec<native::UpdateRule>, String> {
    cfg.update_policy
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let grant = match r.action.as_str() {
                "grant" => true,
                "deny" => false,
                other => {
                    return Err(format!(
                        "update_policy[{index}].action에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            let types = r
                .types
                .iter()
                .enumerate()
                .map(|(item, rtype)| {
                    onetdns_config::parse_update_rtype(rtype).ok_or_else(|| {
                        format!(
                            "update_policy[{index}].types[{item}]에 허용되지 않은 DNS 레코드 형식이 있습니다: '{rtype}'"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            native::UpdateRule::new(
                grant,
                &r.identity,
                &r.name,
                types,
            )
            .ok_or_else(|| format!("update_policy[{index}]의 identity 또는 name이 올바르지 않습니다"))
        })
        .collect()
}

/** @brief 대시보드 로그인 정보를 만든다. */
fn build_user_creds(cfg: &Config) -> Result<Vec<onetdns_control::UserCred>, String> {
    let mut names = std::collections::HashSet::new();
    cfg.users
        .iter()
        .enumerate()
        .map(|(index, user)| {
            if user.name.is_empty() || user.password_hash.is_empty() {
                return Err(format!(
                    "users[{index}]에 비어 있지 않은 name과 password_hash가 필요합니다"
                ));
            }
            if !names.insert(user.name.clone()) {
                return Err(format!("users[{index}]의 name이 중복되었습니다"));
            }
            let role = match user.role.as_str() {
                "admin" => onetdns_control::Role::Admin,
                "readonly" => onetdns_control::Role::ReadOnly,
                other => {
                    return Err(format!(
                        "users[{index}].role에 허용되지 않은 값이 있습니다: '{other}'"
                    ));
                }
            };
            Ok(onetdns_control::UserCred {
                name: user.name.clone(),
                hash: user.password_hash.clone(),
                role,
            })
        })
        .collect()
}

/** @brief 파일을 원자적으로 교체해 쓴다. 중간에 끊겨도 반쪽 파일이 남지 않는다. */
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, false)
}

/** @brief 비밀 파일을 교체해 쓴다. 남이 읽지 못하게 권한을 좁힌다. */
pub fn atomic_write_secret(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, true)
}

/** @brief 교체 쓰기의 실제 구현. */
fn atomic_write_inner(path: &std::path::Path, data: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    atomic_write_with(path, secret, |file| file.write_all(data))
}

/** @brief 임시 파일에 쓰고 제 이름으로 옮긴다. */
fn atomic_write_with(
    path: &std::path::Path,
    secret: bool,
    write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    /** @brief 임시 파일 이름이 겹치지 않게 하는 일련번호. */
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("onetdns");
    let nonce = u64::from_le_bytes(onetdns_core::rng::try_random_array::<8>()?);
    let tmp_name = format!(
        ".{fname}.tmp.{}.{}.{nonce:016x}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let tmp = match dir {
        Some(d) => d.join(&tmp_name),
        None => std::path::PathBuf::from(&tmp_name),
    };

    let write_result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        #[cfg(windows)]
        if secret {
            harden_windows_secret_acl(&tmp)?;
        }
        write(&mut f)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let target_mode = std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777);
        let mode = if secret { Some(0o600) } else { target_mode };
        if let Some(mode) = mode {
            if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
    }
    let _ = secret;
    if let Err(e) = replace_file(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    #[cfg(unix)]
    if let Some(directory) = dir {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
/** @brief 비밀 파일의 권한을 좁힌다. 좁히지 않으면 같은 기계의 다른 사용자가 키를 읽는다. */
fn harden_windows_secret_acl(path: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null_mut, NonNull};

    /** @brief 권한 문자열 버전. */
    const SDDL_REVISION_1: u32 = 1;
    /** @brief 접근 목록만 바꾼다는 표시. */
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

    #[link(name = "Advapi32")]
    extern "system" {
        /** @brief 권한 문자열을 구조체로. */
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        /** @brief 파일 권한을 건다. */
        fn SetFileSecurityW(
            file_name: *const u16,
            security_information: u32,
            security_descriptor: *mut c_void,
        ) -> i32;
    }
    #[link(name = "Kernel32")]
    extern "system" {
        /** @brief 받은 메모리를 돌려준다. */
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    let sddl: Vec<u16> = std::ffi::OsStr::new("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
        .encode_wide()
        .chain(once(0))
        .collect();
    let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    let mut descriptor: *mut c_void = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let descriptor = NonNull::new(descriptor)
        .ok_or_else(|| std::io::Error::other("Windows 보안 설명자를 변환하지 못했습니다"))?;
    let applied = unsafe {
        SetFileSecurityW(
            path_w.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    };
    unsafe {
        LocalFree(descriptor.as_ptr());
    }
    if applied == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
/** @brief 파일을 전부 교체한다. */
fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(src, dst)
}

#[cfg(windows)]
/** @brief 파일을 전부 교체한다. 디스크에 닿은 뒤에 돌아온다. */
fn replace_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    /** @brief 이미 있어도 덮는다. */
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    /** @brief 디스크에 닿은 뒤에 돌아온다. */
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    extern "system" {
        /** @brief 파일을 옮긴다. */
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(once(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(once(0)).collect();
    retry_windows_replace(|| {
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

#[cfg(windows)]
/** @brief 백신·짧은 독점 열기와 겹친 파일 교체만 제한적으로 다시 시도한다. */
fn retry_windows_replace(mut replace: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    /** @brief 첫 시도 뒤 허용할 재시도 수. 전체 대기는 최대 191 ms다. */
    const RETRIES: u32 = 8;
    for attempt in 0..=RETRIES {
        match replace() {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt < RETRIES && matches!(error.raw_os_error(), Some(5 | 32 | 33)) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1u64 << attempt.min(6)));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("Windows 파일 교체 재시도 반복은 반드시 반환합니다")
}

#[derive(Clone)]
/** @brief 고치기 전 파일. 실패하면 되돌린다. */
struct FileBackup {
    /** @brief 고치기 전 내용. 없으면 파일이 없었다는 뜻이다. */
    data: Option<Vec<u8>>,
    /** @brief 비밀 파일이라 권한을 좁혀 되돌려야 하는지. */
    secret: bool,
}

impl FileBackup {
    /** @brief 지금 내용을 담아 둔다. */
    fn capture(path: &std::path::Path, secret: bool) -> std::io::Result<Self> {
        match read_bytes_limited(path, LOCAL_CA_MAX_BYTES) {
            Ok(data) => Ok(Self {
                data: Some(data),
                secret,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self { data: None, secret }),
            Err(e) => Err(e),
        }
    }

    /** @brief 담아 둔 내용으로 되돌린다. */
    fn restore(&self, path: &std::path::Path) -> std::io::Result<()> {
        match &self.data {
            Some(data) if self.secret => atomic_write_secret(path, data),
            Some(data) => atomic_write(path, data),
            None => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
        }
    }
}

#[derive(Clone)]
/** @brief 바꾸기 전 인증서와 키. */
struct CertKeyBackup {
    /** @brief 바꾸기 전 인증서. */
    cert: FileBackup,
    /** @brief 바꾸기 전 키. */
    key: FileBackup,
}

/** @brief 인증서와 키를 되돌린다. 둘 중 하나만 바뀐 채로 두면 서빙이 전부 멈춘다. */
fn rollback_cert_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    backup: &CertKeyBackup,
) -> std::io::Result<()> {
    let key_result = backup.key.restore(key_path);
    let cert_result = backup.cert.restore(cert_path);
    match (key_result, cert_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(key_err), Ok(())) => Err(key_err),
        (Ok(()), Err(cert_err)) => Err(cert_err),
        (Err(key_err), Err(cert_err)) => Err(std::io::Error::new(
            key_err.kind(),
            format!("개인키와 인증서 파일을 모두 이전 상태로 되돌리지 못했습니다: 개인키={key_err}; 인증서={cert_err}"),
        )),
    }
}

/** @brief 인증서와 키를 함께 바꾼다. */
fn commit_cert_key(
    cert_path: &std::path::Path,
    cert_data: &[u8],
    key_path: &std::path::Path,
    key_data: &[u8],
) -> std::io::Result<CertKeyBackup> {
    if cert_path == key_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "인증서와 개인키는 서로 다른 파일 경로에 저장해야 합니다",
        ));
    }
    let backup = CertKeyBackup {
        cert: FileBackup::capture(cert_path, false)?,
        key: FileBackup::capture(key_path, true)?,
    };
    if let Err(e) = atomic_write(cert_path, cert_data) {
        if let Err(rollback_err) = rollback_cert_key(cert_path, key_path, &backup) {
            return Err(std::io::Error::new(
                e.kind(),
                format!("인증서 파일을 저장하지 못했고 이전 파일 복구에도 실패했습니다: 저장 오류={e}; 복구 오류={rollback_err}"),
            ));
        }
        return Err(e);
    }
    if let Err(e) = atomic_write_secret(key_path, key_data) {
        if let Err(rollback_err) = rollback_cert_key(cert_path, key_path, &backup) {
            return Err(std::io::Error::new(
                e.kind(),
                format!("개인키 파일을 저장하지 못했고 이전 파일 복구에도 실패했습니다: 저장 오류={e}; 복구 오류={rollback_err}"),
            ));
        }
        return Err(e);
    }
    Ok(backup)
}

/** @brief 되돌리기 결과까지 붙인 응답 문구. */
fn with_rollback_result(primary: String, operation: &str, result: Result<(), String>) -> String {
    match result {
        Ok(()) => primary,
        Err(rollback_error) => format!("{primary}; 이전 설정으로 되돌리는 과정에서도 오류가 발생했습니다: {operation}: {rollback_error}"),
    }
}

/** @brief 설정 파일의 이 배열을 다시 쓴다. */
fn persist_config_string_array(
    path: &std::path::Path,
    key: &str,
    values: &[String],
) -> std::io::Result<()> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    let text =
        onetdns_core::SecretString::from(Config::read_text(path).map_err(std::io::Error::other)?);
    let updated = onetdns_core::SecretString::from(
        rewrite_config_string_array(&text, key, values).map_err(std::io::Error::other)?,
    );
    atomic_write(path, updated.as_bytes())
}

/** @brief 설정 텍스트에서 이 배열만 바꿔 넣는다. */
fn rewrite_config_string_array<T: AsRef<str>>(
    text: &str,
    key: &str,
    values: &[T],
) -> Result<String, String> {
    rewrite_config_kv(text, key, &toml_string_array(values))
}

/** @brief 설정 텍스트의 항목 하나. */
type TomlEntry = onetdns_config::toml::TopEntry;

/** @brief 설정 텍스트에서 이 항목이 차지하는 구간. */
struct TomlBlock {
    /** @brief 이 구간의 맨 위 항목 이름. */
    root: String,
    /** @brief 테이블 배열 구간인지. */
    is_array: bool,
    /** @brief 테이블 헤더 줄 번호. */
    header_idx: usize,
    /** @brief 구간이 시작하는 위치. */
    start: usize,
    /** @brief 구간이 끝나는 위치. */
    end: usize,
}

/** @brief 항목마다 텍스트에서 차지하는 구간을 찾는다. */
fn toml_blocks(entries: &[TomlEntry]) -> Vec<TomlBlock> {
    let mut blocks: Vec<TomlBlock> = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        match entry {
            TomlEntry::Header {
                name,
                is_array,
                start,
                end,
            } => blocks.push(TomlBlock {
                root: name.split('.').next().unwrap_or(name).to_string(),
                is_array: *is_array,
                header_idx: idx,
                start: *start,
                end: *end,
            }),
            TomlEntry::Assign {
                table: Some(header),
                end,
                ..
            } => {
                if let Some(block) = blocks.last_mut() {
                    if block.header_idx == *header {
                        block.end = block.end.max(*end);
                    }
                }
            }
            TomlEntry::Assign { .. } => {}
        }
    }
    blocks
}

/** @brief 설정 텍스트의 여러 구간을 한꺼번에 바꾼다. 뒤에서부터 바꿔야 앞 구간의 위치가 틀어지지 않는다. */
fn splice_config_edits(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|(start, end, _)| (*start, *end));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, replacement) in edits {
        if start > cursor {
            out.push_str(&text[cursor..start]);
        }
        out.push_str(&replacement);
        cursor = cursor.max(end);
    }
    out.push_str(&text[cursor..]);
    out
}

/** @brief 설정 텍스트에서 이 항목의 값만 바꾼다. */
/**
 * @brief 설정 파일에서 항목 하나를 지운다.
 *
 * @details 값을 비우는 것과 항목을 지우는 것은 다르다. 지워야 기본값으로 돌아가고, 선택
 *          항목은 꺼진다. 이것이 없으면 한 번 넣은 선택 항목을 되돌릴 방법이 없다.
 * @param key 지울 최상위 항목 이름. 테이블 안의 항목은 건드리지 않는다.
 * @return 원래 없었으면 그대로 돌려준다. 지우는 것은 실패로 보지 않는다.
 */
fn remove_config_key(text: &str, key: &str) -> Result<String, String> {
    let text = &drop_config_tables(text, key)?;
    let entries = onetdns_config::toml::top_entries(text)?;
    let mut cuts = Vec::new();
    for entry in &entries {
        if let TomlEntry::Assign {
            key: existing,
            table: None,
            start,
            end,
            ..
        } = entry
        {
            if existing == key {
                cuts.push((*start, *end, String::new()));
            }
        }
    }
    if cuts.is_empty() {
        return Ok(text.to_string());
    }
    Ok(splice_config_edits(text, cuts))
}

/**
 * @brief 이 이름의 테이블과 테이블 배열 블록을 설정 텍스트에서 걷어 낸다.
 * @details 최상위 항목으로 값을 주면 같은 이름의 테이블 블록은 그 값으로 대체돼야 한다. 남겨 두면
 *          같은 키가 두 번 적혀 테이블 쪽이 이기므로, 마지막 항목을 지우려고 빈 배열을 줘도 아무
 *          것도 지워지지 않는다.
 */
fn drop_config_tables(text: &str, key: &str) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    let cuts: Vec<(usize, usize, String)> = toml_blocks(&entries)
        .into_iter()
        .filter(|block| block.root == key)
        .map(|block| (block.start, block.end, String::new()))
        .collect();
    if cuts.is_empty() {
        return Ok(text.to_string());
    }
    Ok(splice_config_edits(text, cuts))
}

fn rewrite_config_kv(text: &str, key: &str, rhs: &str) -> Result<String, String> {
    let text = &drop_config_tables(text, key)?;
    let entries = onetdns_config::toml::top_entries(text)?;
    let line = format!("{key} = {rhs}\n");
    for entry in &entries {
        if let TomlEntry::Assign {
            key: existing,
            table: None,
            start,
            end,
            ..
        } = entry
        {
            if existing == key {
                return Ok(splice_config_edits(text, vec![(*start, *end, line)]));
            }
        }
    }
    let first_header = entries.iter().find_map(|entry| match entry {
        TomlEntry::Header { start, .. } => Some(*start),
        _ => None,
    });
    Ok(match first_header {
        Some(pos) => splice_config_edits(text, vec![(pos, pos, line)]),
        None => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&line);
            out
        }
    })
}

/** @brief 설정 조각을 지금 텍스트에 합친다. 건드리지 않은 항목과 주석은 그대로 둔다. */
fn merge_config_snippet(current: &str, snippet: &str) -> Result<String, String> {
    let snip_entries = onetdns_config::toml::top_entries(snippet)?;
    if snip_entries.is_empty() {
        return Ok(current.to_string());
    }
    let mut base = current.to_string();
    for entry in &snip_entries {
        if let TomlEntry::Assign {
            key, table: None, ..
        } = entry
        {
            base = drop_config_tables(&base, key)
                .map_err(|error| format!("현재 설정을 해석하지 못했습니다: {error}"))?;
        }
    }
    let current = base.as_str();
    let cur_entries = onetdns_config::toml::top_entries(current)
        .map_err(|error| format!("현재 설정을 해석하지 못했습니다: {error}"))?;
    let fragment = |source: &str, start: usize, end: usize| {
        let mut piece = source[start..end].to_string();
        if !piece.ends_with('\n') {
            piece.push('\n');
        }
        piece
    };

    let snip_blocks = toml_blocks(&snip_entries);
    let replaced_tables: std::collections::HashSet<&str> = snip_blocks
        .iter()
        .map(|block| block.root.as_str())
        .collect();
    let first_header = cur_entries.iter().find_map(|entry| match entry {
        TomlEntry::Header { start, .. } => Some(*start),
        _ => None,
    });

    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut tail = String::new();
    'assign: for entry in &snip_entries {
        let TomlEntry::Assign {
            key,
            table: None,
            start,
            end,
            ..
        } = entry
        else {
            continue;
        };
        let piece = fragment(snippet, *start, *end);
        for cur in &cur_entries {
            if let TomlEntry::Assign {
                key: existing,
                table: None,
                start,
                end,
                ..
            } = cur
            {
                if existing == key {
                    edits.push((*start, *end, piece));
                    continue 'assign;
                }
            }
        }
        match first_header {
            Some(pos) => edits.push((pos, pos, piece)),
            None => tail.push_str(&piece),
        }
    }
    for block in toml_blocks(&cur_entries) {
        if replaced_tables.contains(block.root.as_str()) {
            edits.push((block.start, block.end, String::new()));
        }
    }
    let mut out = splice_config_edits(current, edits);
    for block in &snip_blocks {
        tail.push_str(&fragment(snippet, block.start, block.end));
    }
    if !tail.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&tail);
    }
    Ok(out)
}

/** @brief 문자열을 설정 텍스트에 적을 형태로 감싼다. */
fn toml_quote(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for character in s.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control.is_control() => {
                let code = control as u32;
                if code <= 0xffff {
                    let _ = write!(out, "\\u{code:04X}");
                } else {
                    let _ = write!(out, "\\U{code:08X}");
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/** @brief 토큰을 가리키는 이름. 토큰 자체는 드러내지 않는다. */
fn token_id(tok: &str) -> String {
    stable_resource_id("token", tok)
}

/**
 * @brief 지문이 일치하는 제어 토큰을 설정 본문에서 지운다.
 * @return 고친 본문과 지운 개수.
 * @details 일치하는 토큰이 없으면 반드시 오류를 낸다. 바뀐 것 없는 본문을 그대로
 *          돌려주면 호출자가 파일을 다시 쓰고 서비스 재시작까지 걸게 된다.
 */
fn remove_token_by_id(text: &str, id: &str) -> Result<(String, usize), String> {
    let cur = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
    let before = cur.control_admin_tokens.len() + cur.control_readonly_tokens.len();
    let admin: Vec<_> = cur
        .control_admin_tokens
        .into_iter()
        .filter(|t| token_id(t) != id)
        .collect();
    let ro: Vec<_> = cur
        .control_readonly_tokens
        .into_iter()
        .filter(|t| token_id(t) != id)
        .collect();
    let removed = before - (admin.len() + ro.len());
    if removed == 0 {
        return Err("일치하는 토큰이 없거나 기본 관리 토큰은 삭제할 수 없습니다".to_string());
    }
    let out = rewrite_config_string_array(text, "control_admin_tokens", &admin)?;
    let out = rewrite_config_string_array(&out, "control_readonly_tokens", &ro)?;
    Ok((out, removed))
}

/** @brief 토큰을 가린 표기. */
fn token_mask(tok: &str) -> String {
    let count = tok.chars().count();
    if count > 10 {
        let head: String = tok.chars().take(6).collect();
        let tail: String = tok.chars().skip(count - 2).collect();
        format!("{head}…{tail}")
    } else {
        "••••••".to_string()
    }
}

/** @brief 재작성 규칙들을 설정 텍스트로. */
fn rewrites_to_toml(rw: &[onetdns_config::Rewrite]) -> String {
    let items: Vec<String> = rw
        .iter()
        .map(|r| {
            format!(
                "{{ domain = {}, answer = {} }}",
                toml_quote(&r.domain),
                toml_quote(&r.answer)
            )
        })
        .collect();
    format!("[{}]", items.join(", "))
}

/** @brief 수를 설정 텍스트에 적을 형태로. */
fn toml_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/** @brief 모드를 바꿀 때 접근 제어도 함께 적어 준다. */
fn materialize_mode_acl_patch(
    pairs: &mut Vec<(String, onetdns_core::json::Json)>,
) -> Result<(), String> {
    if pairs.iter().any(|(key, _)| key == "acl_allow") {
        return Ok(());
    }
    let Some((_, value)) = pairs.iter().find(|(key, _)| key == "mode") else {
        return Ok(());
    };
    let mode = value
        .as_str()
        .ok_or_else(|| "mode는 문자열 personal 또는 public이어야 합니다".to_string())?;
    let mode = match mode.to_ascii_lowercase().as_str() {
        "personal" => onetdns_config::Mode::Personal,
        "public" => onetdns_config::Mode::Public,
        _ => return Err("mode는 personal 또는 public이어야 합니다".into()),
    };
    pairs.push((
        "acl_allow".into(),
        onetdns_core::json::Json::Arr(
            mode.preset_acl_allow()
                .into_iter()
                .map(|cidr| onetdns_core::json::Json::Str(cidr.to_string()))
                .collect(),
        ),
    ));
    Ok(())
}

/**
 * @brief 대시보드가 보낸 설정 변경을 받아들여도 되는지 본다.
 * @warning 가려서 보여 준 값을 그대로 되돌려받으면 거부한다. 그대로 저장하면 진짜 비밀이
 *          가림 문자열로 덮인다.
 */
fn validate_config_patch_values(
    pairs: &[(String, onetdns_core::json::Json)],
) -> Result<(), String> {
    use onetdns_core::json::Json;
    /** @brief 토큰이 든 배열들. */
    const TOKEN_ARRAYS: &[&str] = &["control_admin_tokens", "control_readonly_tokens"];
    /** @brief 넣을 수만 있고 되읽어 주지 않는 항목들. */
    const WRITE_ONLY_STRINGS: &[&str] = &[
        "control_token",
        "cluster_raft_secret",
        "cluster_raft_node_key",
        "zones_etcd_password",
    ];
    /** @brief 암호가 섞여 있어 가려서 보여 주는 주소들. */
    const REDACTED_URLS: &[&str] = &["zones_postgres", "zones_mysql"];

    for (key, value) in pairs {
        // null은 항목을 지우라는 뜻이다. 값 검사는 넣을 때만 한다.
        if matches!(value, Json::Null) {
            continue;
        }
        if TOKEN_ARRAYS.contains(&key.as_str()) {
            return Err(format!(
                "{key}는 일반 설정 편집기로 변경할 수 없습니다. 접근 토큰 전용 화면을 사용하십시오"
            ));
        }
        if REDACTED_URLS.contains(&key.as_str()) {
            let Some(text) = value.as_str() else {
                return Err(format!("{key}에는 접속 문자열을 입력해야 합니다"));
            };
            let lowered = text.to_ascii_lowercase();
            if text.contains("***") || lowered.contains("redacted") || lowered.contains("masked") {
                return Err(format!(
                    "{key}에 마스킹된 표시값을 저장할 수 없습니다. 새 접속 문자열을 직접 입력하십시오"
                ));
            }
        }
        if WRITE_ONLY_STRINGS.contains(&key.as_str()) {
            match value {
                Json::Str(text)
                    if !text.trim().is_empty()
                        && !text.contains("***")
                        && !text.to_ascii_lowercase().contains("redacted") => {}
                _ => {
                    return Err(format!(
                        "{key}는 기존 값을 표시하지 않는 비밀 설정입니다. 변경할 새 값을 직접 입력하십시오"
                    ))
                }
            }
        }
    }
    Ok(())
}

/** @brief JSON 값을 설정 텍스트의 값으로. */
fn json_to_toml_literal(v: &onetdns_core::json::Json) -> Result<String, String> {
    use onetdns_core::json::Json;
    Ok(match v {
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => toml_num(*n),
        Json::Str(s) => toml_quote(s),
        Json::Arr(a) => {
            let mut parts = Vec::with_capacity(a.len());
            for it in a {
                parts.push(match it {
                    Json::Str(s) => toml_quote(s),
                    Json::Num(n) => toml_num(*n),
                    Json::Bool(b) => b.to_string(),
                    _ => {
                        return Err("배열에는 문자열, 숫자 또는 논리값만 사용할 수 있습니다".into())
                    }
                });
            }
            format!("[{}]", parts.join(", "))
        }
        Json::Null => return Err("null 값은 사용할 수 없습니다".into()),
        Json::Obj(_) => {
            return Err("중첩 설정은 DNS 영역이나 클라이언트 전용 API를 사용해야 합니다".into())
        }
    })
}

/** @brief 클러스터 설정 값의 중첩 깊이 상한. 설정 파일에 이보다 깊은 값은 없다. */
const MAX_RAFT_VALUE_DEPTH: usize = 8;

/**
 * @brief 설정 파일의 TOML 값을 Raft 로그 항목에 담을 JSON 값으로 바꾼다.
 * @warning 2의 53제곱을 넘는 정수는 거부한다. JSON 수는 실수라 그 위에서는 다른 수로 바뀐
 *          채 모든 노드에 퍼진다.
 */
fn toml_value_to_json(
    value: &onetdns_config::toml::Value,
) -> Result<onetdns_core::json::Json, String> {
    use onetdns_config::toml::Value;
    use onetdns_core::json::Json;
    /** @brief 실수로 정확히 담을 수 있는 정수 상한. */
    const MAX_EXACT: i64 = 9_007_199_254_740_991;
    Ok(match value {
        Value::String(text) => Json::Str(text.to_string()),
        Value::Int(number) if number.unsigned_abs() <= MAX_EXACT as u64 => {
            Json::Num(*number as f64)
        }
        Value::Int(_) => return Err("Raft로 복제할 수 없을 만큼 큰 정수가 설정에 있습니다".into()),
        Value::Float(number) => Json::Num(*number),
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Array(items) => Json::Arr(
            items
                .iter()
                .map(toml_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        Value::Table(fields) => Json::Obj(
            fields
                .iter()
                .map(|(key, value)| Ok((key.clone(), toml_value_to_json(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

/**
 * @brief Raft 로그 항목의 값을 TOML 값 표기로 바꾼다.
 * @details 설정 편집 API가 쓰는 json_to_toml_literal 과 달리 테이블과 중첩 배열도 받는다.
 *          clients, local_zones 같은 테이블 배열도 클러스터가 공유해야 하기 때문이다. 테이블은
 *          인라인 테이블로 쓴다. 파일 모양은 원래와 달라지지만 파싱한 값은 같다.
 * @retval Err 값 안에 null 이 있거나 중첩이 너무 깊을 때. 최상위 null 은 키 삭제를 뜻하므로
 *             호출하는 쪽이 따로 처리한다.
 */
fn json_to_raft_toml_literal(
    value: &onetdns_core::json::Json,
    depth: usize,
) -> Result<String, String> {
    use onetdns_core::json::Json;
    if depth > MAX_RAFT_VALUE_DEPTH {
        return Err("Raft 설정 값의 중첩이 너무 깊습니다".into());
    }
    Ok(match value {
        Json::Null => return Err("Raft 설정 값 안에는 null을 둘 수 없습니다".into()),
        Json::Bool(flag) => flag.to_string(),
        Json::Num(number) if number.is_finite() => toml_num(*number),
        Json::Num(_) => return Err("Raft 설정 값의 수가 유한하지 않습니다".into()),
        Json::Str(text) => toml_quote(text),
        Json::Arr(items) => {
            let parts = items
                .iter()
                .map(|item| json_to_raft_toml_literal(item, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            format!("[{}]", parts.join(", "))
        }
        Json::Obj(fields) => {
            let mut parts = Vec::with_capacity(fields.len());
            for (key, value) in fields {
                let bare = !key.is_empty()
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
                let key = if bare { key.clone() } else { toml_quote(key) };
                parts.push(format!(
                    "{key} = {}",
                    json_to_raft_toml_literal(value, depth + 1)?
                ));
            }
            format!("{{ {} }}", parts.join(", "))
        }
    })
}

/** @brief 교체할 수 있는 접근 제어. 아무것도 막지 않는지를 값싸게 답한다. */
struct DynamicAccessControl {
    /** @brief 지금 걸린 규칙. */
    inner: std::sync::RwLock<Arc<dyn AccessControl>>,
    /** @brief 아무것도 막지 않는지. 복제 없이 답하려고 따로 둔다. */
    trivially_allow: std::sync::atomic::AtomicBool,
}

impl DynamicAccessControl {
    /** @brief 지금 규칙으로 만든다. */
    fn new(inner: Arc<dyn AccessControl>) -> Self {
        let trivially_allow = inner.is_trivially_allow();
        Self {
            inner: std::sync::RwLock::new(inner),
            trivially_allow: std::sync::atomic::AtomicBool::new(trivially_allow),
        }
    }

    /** @brief 규칙을 교체하고 요약 판정도 함께 맞춘다. */
    fn replace(&self, next: Arc<dyn AccessControl>) {
        let trivially_allow = next.is_trivially_allow();
        if !trivially_allow {
            self.trivially_allow
                .store(false, std::sync::atomic::Ordering::Release);
        }
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        if trivially_allow {
            self.trivially_allow
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

impl AccessControl for DynamicAccessControl {
    /** @brief 이 클라이언트를 받아 줄지. */
    fn check(&self, client: &onetdns_core::ClientInfo) -> onetdns_core::AclDecision {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(client)
    }

    /** @brief 아무것도 막지 않는지. 빠른 경로가 이 판정을 믿고 검사를 건너뛴다. */
    fn is_trivially_allow(&self) -> bool {
        self.trivially_allow
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

/** @brief 교체할 수 있는 속도 제한. */
struct DynamicRateLimiter {
    /** @brief 지금 걸린 제한기들. */
    inner: std::sync::RwLock<Vec<Arc<dyn RateLimiter>>>,
    /** @brief 걸린 제한기 수. 복제 없이 답하려고 따로 둔다. */
    active: std::sync::atomic::AtomicUsize,
}

/**
 * @brief 빠른 경로 조건을 볼 때 설정만으로는 알 수 없는 사실들.
 *
 * @details 셋 다 이번 세대 안에서 바뀔 수 있어서 설정에서 다시 계산할 수 없다. DHCP 임대
 *          풀은 세대가 바뀔 때만 서고, 뷰와 정책은 살아 있는 값을 봐야 한다.
 */
struct LaneFacts {
    /** @brief DHCP 임대 풀이 서 있는지. */
    dhcp_pool: bool,
    /** @brief 클라이언트별로 다르게 답할 뷰가 있는지. */
    views_present: bool,
    /** @brief 정책 규칙이 하나라도 있는지. */
    policy_present: bool,
}

/** @brief 세 빠른 경로 각각을 지금 써도 되는지. */
struct LaneGates {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    wire: bool,
    /** @brief 권한 영역 단순 질의 빠른 경로. */
    authority: bool,
    /** @brief 재귀 콜드미스 리액터 레인. */
    reactor: bool,
}

/**
 * @brief 답한 주소를 커널 주소 집합에 넣는 계층이 이 설정에서 붙는지.
 * @details 집합 이름과 대상 도메인이 함께 있어야 하고, 커널 집합은 Linux에만 있다. 붙지 않는
 *          설정으로 빠른 경로를 끄면 하는 일 없이 느려지기만 한다.
 */
fn ipset_layer_active(cfg: &Config) -> bool {
    cfg!(target_os = "linux")
        && (cfg.ipset_name_v4.is_some() || cfg.ipset_name_v6.is_some())
        && !cfg.ipset_domains.is_empty()
}

/**
 * @brief 지금 설정으로 세 빠른 경로가 적격인지 판정한다.
 *
 * @details 시작할 때와 설정을 교체할 때 모두 이 함수 하나만 부른다. 두 곳에서 따로
 *          판정하면 교체한 뒤 레인이 이전 조건으로 남아 없는 기능처럼 답한다. 어느 키가
 *          경로를 닫는지는 config_keys 의 표가 정하고, 여기서는 경로마다의 전제만 본다.
 * @param cfg    판정할 설정.
 * @param facts  설정만으로 알 수 없는 사실들.
 * @return 세 경로 각각의 적격 여부.
 */
fn evaluate_lane_gates(cfg: &Config, facts: &LaneFacts) -> LaneGates {
    use config_keys::{lane_unblocked, Lane};
    let wire = lane_unblocked(Lane::Wire, cfg, facts);
    let authority =
        authority_sources_configured(cfg) && lane_unblocked(Lane::Authority, cfg, facts);
    let reactor = cfg!(unix) && wire && lane_unblocked(Lane::Reactor, cfg, facts);
    LaneGates {
        wire,
        authority,
        reactor,
    }
}

#[derive(Clone)]
/** @brief 설정을 다시 읽을 때 교체할 것들. */
struct NativeHotState {
    /** @brief 빠른 경로의 체인 세대까지 함께 교체할 핸들러. */
    handler: Arc<native::NativeServer>,
    /** @brief 기능 세트. */
    features: Arc<native::NativeFeatureSwap>,
    /** @brief 정책 엔진. */
    policy: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    /** @brief 클라이언트별 뷰. */
    views: Arc<native::GatedSwap<Vec<native::NativeView>>>,
    /** @brief 차단 답의 수명. */
    block_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 고정해 둔 주소의 수명. */
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
    /** @brief 밖에 물어보면 안 되는 이름의 범주. */
    local_only_names: Arc<layers::LocalOnlyNames>,
    /** @brief 설정 세대. 이전 세대가 만든 항목이 들어오지 못하게 한다. */
    wire_epoch: Arc<std::sync::atomic::AtomicUsize>,
    /** @brief 빠른 경로 켜짐 여부. */
    lane_switch: Arc<native::LaneSwitch>,
    /** @brief 권한 영역 설정 세트. */
    authority: Arc<onetdns_core::ArcSwap<native::AuthoritySettings>>,
}

impl DynamicRateLimiter {
    /** @brief 지금 제한기들로 만든다. */
    fn new(inner: Vec<Arc<dyn RateLimiter>>) -> Self {
        let active = inner.len();
        Self {
            inner: std::sync::RwLock::new(inner),
            active: std::sync::atomic::AtomicUsize::new(active),
        }
    }

    /** @brief 제한기들을 교체한다. */
    fn replace(&self, next: Vec<Arc<dyn RateLimiter>>) {
        let active = next.len();
        if active != 0 {
            self.active
                .store(active, std::sync::atomic::Ordering::Release);
        }
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = next;
        if active == 0 {
            self.active.store(0, std::sync::atomic::Ordering::Release);
        }
    }

    /** @brief 걸린 제한기 수. */
    fn layer_count(&self) -> usize {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl RateLimiter for DynamicRateLimiter {
    /** @brief 이번 질의를 받아 줄지. */
    fn check(&self, client: &onetdns_core::ClientInfo) -> onetdns_core::RateDecision {
        if self.active.load(std::sync::atomic::Ordering::Acquire) == 0 {
            return onetdns_core::RateDecision::Permit;
        }
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .iter()
            .any(|limiter| limiter.check(client) == onetdns_core::RateDecision::Throttle)
        {
            onetdns_core::RateDecision::Throttle
        } else {
            onetdns_core::RateDecision::Permit
        }
    }

    /** @brief 제한이 걸려 있는지. */
    fn is_active(&self) -> bool {
        self.layer_count() != 0
    }
}

/** @brief 설정대로 접근 제어를 만든다. */
fn runtime_access_control(cfg: &Config) -> Arc<dyn AccessControl> {
    Arc::new(
        IpAcl::new(
            cfg.acl_allow.clone(),
            cfg.acl_deny.clone(),
            cfg.acl_default_allow(),
        )
        .with_ids(cfg.acl_allow_ids.clone(), cfg.acl_deny_ids.clone()),
    )
}

/**
 * @brief 공유 캐시로 쓸 Redis 주소를 찾는다.
 *
 * @details 체인을 만들 때마다 다시 찾는다. 한 번 찾아 두면 주소를 바꿔도 이전 서버를 계속
 *          바라본다.
 * @return 이름을 주소로 바꾸지 못하면 실패.
 */
fn cachedb_redis_addr(host: &str, port: u16, bootstrap: &[IpAddr]) -> Result<SocketAddr, String> {
    let ip = upstream::resolve_host_via_bootstrap(host, bootstrap).ok_or_else(|| {
        format!(
            "cachedb_redis_host={host}의 주소를 찾지 못했습니다. 호스트 이름을 사용하려면 bootstrap를 지정해야 합니다"
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

/**
 * @brief 설정대로 권한 영역 설정 세트를 만든다.
 *
 * @details 시작할 때와 교체할 때 모두 이 함수만 부른다. 영역 목록에서 저장 경로와
 *          고칠 수 있는 영역이 함께 나오므로 따로 만들면 서로 어긋난다.
 * @return 키나 규칙이 올바르지 않으면 실패. 그때는 이전 설정을 그대로 둔다.
 */
fn build_authority_settings(cfg: &Config) -> Result<native::AuthoritySettings, String> {
    let tsig_keys = build_tsig_keys(cfg)?;
    let zone_signers = cfg
        .zones
        .iter()
        .filter(|zone| zone.dnssec_sign)
        .map(|zone| {
            let origin = onetdns_proto::Name::from_str(&zone.origin)
                .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zone.origin))?;
            Ok((origin, load_zone_signer(zone)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let notify_secondaries = cfg
        .secondary
        .iter()
        .chain(&cfg.catalog)
        .filter_map(|s| {
            Some((
                onetdns_proto::Name::from_str(&s.origin).ok()?,
                s.primary?,
                tsig_for_secondary(&tsig_keys, &s.tsig_key).map(|key| key.name.clone()),
            ))
        })
        .collect();
    let notify_catalog_primaries = cfg
        .catalog
        .iter()
        .filter_map(|catalog| {
            Some((
                catalog.primary?,
                tsig_for_secondary(&tsig_keys, &catalog.tsig_key).map(|key| key.name.clone()),
            ))
        })
        .collect();
    Ok(native::AuthoritySettings {
        xfr_allow: cfg.xfr_allow.clone(),
        tsig_keys,
        xfr_tsig_required: cfg.xfr_tsig_required,
        update_allow: cfg.update_allow.clone(),
        update_policy: build_update_policy(cfg)?,
        update_tsig_required: cfg.update_tsig_required,
        zone_files: cfg
            .zones
            .iter()
            .filter_map(|zone| {
                let file = zone.file.clone()?;
                let origin = onetdns_proto::Name::from_str(&zone.origin).ok()?;
                Some((origin, file))
            })
            .collect(),
        update_zones: cfg
            .zones
            .iter()
            .filter_map(|zone| onetdns_proto::Name::from_str(&zone.origin).ok())
            .collect(),
        notify_secondaries,
        notify_catalog_primaries,
        zone_signers,
    })
}

/**
 * @brief 이 설정이 재귀를 제공한다고 알릴지.
 *
 * @details 체인을 다시 만들 때마다 그때 설정으로 다시 본다. 처리 방식이나 업스트림 서버가
 *          바뀌면 답의 RA 비트도 함께 바뀌어야 한다.
 */
fn recursion_offered_by(cfg: &Config) -> bool {
    cfg.backend != BackendKind::Forward
        || !cfg.upstreams.is_empty()
        || !cfg.upstream_urls.is_empty()
}

/**
 * @brief 목록 갱신 스레드가 한 번 실행되는 간격(초).
 *
 * @details 주기를 기다리는 동안에도 설정이 바뀌었는지 이 간격마다 본다. 짧게 두면 주소를
 *          더한 직후 바로 받아 오지만 그만큼 자주 깬다.
 */
const LIST_REFRESH_TICK_SECS: u64 = 5;

/**
 * @brief 서비스 차단 일정의 경계를 확인하는 간격.
 * @details 일정은 분 단위로 적으므로 경계를 이만큼 늦게 알아챌 수 있다.
 */
const SERVICE_SCHEDULE_TICK_SECS: u64 = 20;

/**
 * @brief 켜 둔 미리 담긴 차단 목록의 주소들.
 *
 * @details 시작할 때와 교체할 때 모두 이 함수만 부른다. 두 곳에서 따로 만들면 켠 뒤
 *          다시 읽었을 때 목록이 서로 달라진다.
 */
fn preset_list_urls(cfg: &Config) -> Vec<String> {
    let mut urls = Vec::new();
    if cfg.safe_browsing {
        urls.extend(
            onetdns_filter::presets::SAFE_BROWSING_LISTS
                .iter()
                .map(|value| value.to_string()),
        );
    }
    if cfg.parental_control {
        urls.extend(
            onetdns_filter::presets::PARENTAL_LISTS
                .iter()
                .map(|value| value.to_string()),
        );
    }
    urls.sort();
    urls.dedup();
    urls
}

/**
 * @brief 지금 실행 중인 가장자리 서비스들. DHCP·DHCPv6·라우터 광고·TFTP.
 *
 * @details 서비스마다 자기 종료 신호를 하나씩 가지고 있다. 설정이 바뀐 서비스만 멈추고 새
 *          설정으로 재시작한다. DNS 소켓과 워커는 건드리지 않으므로 이름 해석은 이어진다.
 * @invariant 등록한 신호는 세대가 끝날 때 전파 작업이 모두 보낸다. 등록을 빠뜨리면 그
 *            스레드가 남아 포트를 잡는다.
 */
#[derive(Default)]
struct EdgeServices {
    /** @brief 서비스 이름과 그것을 멈출 신호. */
    running: Mutex<Vec<(String, Arc<std::sync::atomic::AtomicBool>)>>,
    /** @brief 가장자리 서비스 이름별 스레드. 같은 포트를 다시 열기 전에 합류하려고 잡는다. */
    threads: Mutex<std::collections::HashMap<String, std::thread::JoinHandle<()>>>,
}

impl EdgeServices {
    /** @brief 등록된 서비스를 모두 멈추고, 이름으로 맡긴 스레드는 끝날 때까지 기다린다. */
    fn retire_all(&self) {
        for (_, stop) in self.running.lock_recover().iter() {
            stop.store(true, std::sync::atomic::Ordering::Release);
        }
        let threads: Vec<_> = self.threads.lock_recover().drain().collect();
        for (_, thread) in threads {
            let _ = thread.join();
        }
    }

    /** @brief 이름으로 맡긴 스레드 하나가 끝날 때까지 기다린다. 신호는 호출한 쪽이 보낸다. */
    fn join_service(&self, key: &str) {
        let thread = self.threads.lock_recover().remove(key);
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }

    /**
     * @brief 등록된 것을 모두 멈추고 목록을 비운 뒤 새 신호를 하나 낸다.
     *
     * @details 재귀 리졸버에 딸린 보조 작업은 그 재귀 리졸버의 앵커 핸들을 가지고 있다. 재귀 리졸버를 새로
     *          만들면 이전 작업은 이전 핸들을 갱신하므로 반드시 멈추고 새로 시작해야 한다.
     * @return 새로 시작할 작업들이 함께 볼 종료 신호.
     */
    fn restart_all(&self) -> Arc<std::sync::atomic::AtomicBool> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut running = self.running.lock_recover();
        for (_, old) in running.iter() {
            old.store(true, std::sync::atomic::Ordering::Release);
        }
        running.clear();
        running.push(("recursor-jobs".to_string(), stop.clone()));
        stop
    }
}

/**
 * @brief 가장자리 서비스가 지금 설정에서 어떤 모습이어야 하는지.
 *
 * @details 이름이 같으면 재시작하지 않는다. 설정값 하나라도 다르면 이름이 달라져 이전 것을
 *          멈추고 새로 시작한다.
 * @return (이름, 시작하는 함수) 목록. 꺼져 있는 서비스는 목록에 없다.
 */
fn edge_service_keys(cfg: &Config) -> Vec<String> {
    let mut keys = Vec::new();
    if cfg.dhcp_enable {
        keys.push(format!(
            "dhcp4:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{}:{:?}:{:?}:{:?}:{:?}:{:?}",
            cfg.dhcp_server_ip,
            cfg.dhcp_range_start,
            cfg.dhcp_range_end,
            cfg.dhcp_subnet_mask,
            cfg.dhcp_router,
            cfg.dhcp_dns,
            cfg.dhcp_lease_secs,
            cfg.dhcp_tftp_server,
            cfg.dhcp_boot_file,
            cfg.dhcp_lease_file,
            cfg.dhcp_static_file,
            cfg.dhcp_local_domain,
        ));
    }
    if cfg.tftp_enable {
        keys.push(format!(
            "tftp:{:?}:{}:{}:{:?}:{}",
            cfg.tftp_root,
            cfg.tftp_listen,
            cfg.tftp_writable,
            cfg.tftp_write_allow,
            cfg.tftp_allow_overwrite,
        ));
    }
    if cfg.ra_enable {
        keys.push(format!(
            "ra:{:?}:{}:{}:{}:{}:{}:{:?}",
            cfg.ra_prefix,
            cfg.ra_managed,
            cfg.ra_other,
            cfg.ra_router_lifetime,
            cfg.ra_interval,
            cfg.ra_mtu,
            cfg.ra_interface_index,
        ));
    }
    if cfg.dhcp6_enable {
        keys.push(format!(
            "dhcp6:{:?}:{:?}:{:?}:{}:{}:{:?}",
            cfg.dhcp6_range_start,
            cfg.dhcp6_range_end,
            cfg.dhcp6_dns,
            cfg.dhcp6_interface_index,
            cfg.dhcp_lease_secs,
            cfg.dhcp6_lease_file,
        ));
    }
    keys
}

/**
 * @brief 설정에 맞춰 가장자리 서비스를 시작하고 멈춘다.
 * @invariant 이전 스레드가 끝나기 전에 같은 포트를 열지 않는다. 임대 풀은 바꿔 끼우지 않고
 *            이어 쓴다. 관리 API와 DNS 계층이 같은 풀을 본다.
 * @return 설정이 틀리면 아무것도 멈추지 않고 실패. 포트를 열지 못하면 실패하며, 그때는
 *         호출한 쪽이 이전 설정으로 다시 불러야 한다.
 */
fn reconcile_edge_services(
    cfg: &Config,
    services: &EdgeServices,
    dhcp_slot: &Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    dhcp6_slot: &Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let wanted = edge_service_keys(cfg);
    let mut running = services.running.lock_recover();
    let starting: Vec<&String> = wanted
        .iter()
        .filter(|key| !running.iter().any(|(have, _)| have == *key))
        .collect();
    for key in &starting {
        match key.split(':').next().unwrap_or("") {
            "dhcp4" => {
                build_dhcp_config(cfg)?;
            }
            "tftp" => {
                cfg.tftp_root
                    .as_deref()
                    .ok_or("tftp_enable에는 tftp_root가 필요합니다")?;
            }
            "ra" => {
                build_ra_config(cfg)?;
            }
            "dhcp6" => {
                dhcp6_addresses(cfg)?;
            }
            _ => {}
        }
    }

    let mut retired = Vec::new();
    running.retain(|(key, stop)| {
        let keep = wanted.contains(key);
        if !keep {
            stop.store(true, Ordering::Release);
            retired.push(key.clone());
        }
        keep
    });
    for key in retired {
        services.join_service(&key);
        onetdns_core::info!(
            event = "edge.service_retired",
            service = %key.split(':').next().unwrap_or(&key),
            "설정에서 빠졌거나 바뀐 가장자리 서비스를 멈췄습니다"
        );
    }
    if !wanted.iter().any(|key| key.starts_with("dhcp4:")) {
        *dhcp_slot.lock_recover() = None;
    }
    if !wanted.iter().any(|key| key.starts_with("dhcp6:")) {
        *dhcp6_slot.lock_recover() = None;
    }

    for key in wanted {
        if running.iter().any(|(have, _)| have == &key) {
            continue;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let kind = key.split(':').next().unwrap_or("").to_string();
        let thread = match kind.as_str() {
            "dhcp4" => {
                let dc = build_dhcp_config(cfg)?;
                let existing = dhcp_slot.lock_recover().clone();
                let pool = match existing {
                    Some(pool) => {
                        pool.lock_recover().reconfigure(&dc)?;
                        pool
                    }
                    None => {
                        let pool = Arc::new(Mutex::new(dhcp::LeasePool::new(&dc)));
                        *dhcp_slot.lock_recover() = Some(pool.clone());
                        pool
                    }
                };
                dhcp::spawn_dhcp(dc, 67, pool, stop.clone()).map_err(|error| {
                    format!("DHCP 수신 주소를 열지 못했습니다. UDP 67번 포트 권한을 확인하십시오: {error}")
                })?
            }
            "tftp" => {
                let root = cfg
                    .tftp_root
                    .as_deref()
                    .ok_or("tftp_enable에는 tftp_root가 필요합니다")?;
                tftp::spawn_tftp(
                    root.into(),
                    cfg.tftp_listen,
                    cfg.tftp_writable,
                    cfg.tftp_write_allow.clone(),
                    cfg.tftp_allow_overwrite,
                    stop.clone(),
                )
                .map_err(|error| format!("TFTP 수신 주소를 열지 못했습니다: {error}"))?
            }
            "ra" => {
                let ra_cfg = build_ra_config(cfg)?;
                match ra::spawn_ra(ra_cfg, stop.clone())
                    .map_err(|error| format!("IPv6 라우터 광고를 시작하지 못했습니다: {error}"))?
                {
                    Some(thread) => thread,
                    None => continue,
                }
            }
            "dhcp6" => {
                let dc = build_dhcp6_config(cfg)?;
                let existing = dhcp6_slot.lock_recover().clone();
                let pool = match existing {
                    Some(pool) => {
                        pool.lock_recover().reconfigure(&dc);
                        pool
                    }
                    None => Arc::new(Mutex::new(dhcp6::Lease6Pool::new(&dc))),
                };
                let thread = dhcp6::spawn_dhcp6(dc, 547, pool.clone(), stop.clone()).map_err(|error| {
                    format!("DHCPv6 UDP 547 수신 주소를 열거나 ff02::1:2 multicast에 가입하지 못했습니다. dhcp6_interface_index와 포트 권한을 확인하십시오: {error}")
                })?;
                *dhcp6_slot.lock_recover() = Some(pool);
                thread
            }
            _ => continue,
        };
        services.threads.lock_recover().insert(key.clone(), thread);
        onetdns_core::info!(
            event = "edge.service_started",
            service = %kind,
            "가장자리 서비스를 시작했습니다"
        );
        running.push((key, stop));
    }
    Ok(())
}

/**
 * @brief 전송별 TLS 설정을 담는 교체 가능한 슬롯들.
 *
 * @details 인증서를 갈 때 수신 소켓을 다시 열지 않기 위해 있다. 이미 맺힌 연결은 이전
 *          인증서로 이어지고, 다음 연결부터 새 인증서를 쓴다.
 * @invariant 네 슬롯은 항상 같은 인증서에서 나온다. ALPN만 다르다.
 */
struct TlsSlots {
    /** @brief DoT용. */
    dot: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    /** @brief DoH용. */
    doh: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    /** @brief DoQ용. */
    doq: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    /** @brief DoH3용. */
    doh3: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    /**
     * @brief 지금 네 슬롯이 쓰고 있는 파일 기반 재료.
     * @details 파일 경로가 그대로여도 내용이 갱신되었는지 가리는 근거다. 공개 값만 담는다.
     *          개인키는 슬롯 안에만 두고 여기에 사본을 남기지 않는다.
     */
    live_files: Mutex<LiveTlsFiles>,
}

/** @brief 슬롯이 파일에서 읽어 쓰고 있는 값들. 갱신 여부를 가리는 데만 쓴다. */
#[derive(PartialEq, Eq)]
struct LiveTlsFiles {
    /** @brief 내밀고 있는 인증서 체인. */
    certs: Vec<Vec<u8>>,
    /** @brief 클라이언트 인증서를 확인하는 CA 번들 원문. mTLS 를 쓰지 않으면 없다. */
    client_ca: Option<Vec<u8>>,
}

/** @brief 설정이 가리키는 파일들을 지금 내용대로 읽는다. */
fn live_tls_files(cfg: &Config, certs: Vec<Vec<u8>>) -> Result<LiveTlsFiles, String> {
    let client_ca = match &cfg.tls_client_ca {
        Some(path) => Some(
            read_bytes_limited(path, LOCAL_CA_MAX_BYTES).map_err(|error| {
                format!(
                    "mTLS CA 파일을 읽지 못했습니다({}): {error}",
                    path.display()
                )
            })?,
        ),
        None => None,
    };
    Ok(LiveTlsFiles { certs, client_ca })
}

impl TlsSlots {
    /**
     * @brief 인증서 슬롯을 얻는다. 아직 없으면 지금 설정으로 만든다.
     *
     * @details 시작할 때 암호화 수신 주소가 없었어도, 나중에 인증서와 주소를 넣으면 그때
     *          만들어서 쓴다. 미리 만들어 두려 하면 인증서가 없을 때 시작이 실패한다.
     * @return 인증서를 읽지 못하면 실패.
     */
    fn get_or_build(
        handle: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
        cfg: &Config,
    ) -> Result<Arc<TlsSlots>, String> {
        if let Some(slots) = handle.lock_recover().clone() {
            return Ok(slots);
        }
        let slots = Arc::new(TlsSlots::from_config(cfg)?);
        *handle.lock_recover() = Some(slots.clone());
        Ok(slots)
    }

    /** @brief 설정에 적힌 인증서로 네 슬롯을 만든다. */
    fn from_config(cfg: &Config) -> Result<Self, String> {
        let material = native_tls_material(cfg)?;
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material)?;
        Ok(TlsSlots {
            dot: Arc::new(onetdns_core::ArcSwap::new(dot)),
            doh: Arc::new(onetdns_core::ArcSwap::new(doh)),
            doq: Arc::new(onetdns_core::ArcSwap::new(doq)),
            doh3: Arc::new(onetdns_core::ArcSwap::new(doh3)),
            live_files: Mutex::new(live_tls_files(cfg, material.0)?),
        })
    }

    /**
     * @brief 경로는 그대로인 채 내용만 갱신된 인증서를 다시 읽어 슬롯에 올린다.
     *
     * @details 갱신 도구는 같은 경로에 새 인증서를 덮어쓴다. 설정 항목은 그대로이므로
     *          항목 비교만으로는 아무것도 바뀌지 않은 것으로 보이고, 그대로 두면 다시
     *          시작할 때까지 만료된 인증서를 계속 내민다.
     * @return 내용이 달라져 교체한 설정 항목들. 바뀐 것이 없거나 자체 서명으로 돌고
     *         있으면 빈 목록이다. 자체 서명은 파일이 근거가 아니므로 읽지 않는다.
     */
    fn refresh_certificate_files(&self, cfg: &Config) -> Result<Vec<&'static str>, String> {
        if cfg.tls_self_signed_host.is_some() || cfg.tls_cert.is_none() || cfg.tls_key.is_none() {
            return Ok(Vec::new());
        }
        // 교체 전체를 이 잠금 아래에서 한다. 다시 적용 요청과 감시 작업이 겹칠 때 서로 다른
        // 인증서를 슬롯마다 나눠 넣으면 전송마다 다른 인증서를 내밀게 된다.
        let mut live = self.live_files.lock_recover();
        let material = native_tls_material(cfg)?;
        let fresh = live_tls_files(cfg, material.0.clone())?;
        let mut changed = Vec::new();
        if live.certs != fresh.certs {
            changed.push("tls_cert");
        }
        if live.client_ca != fresh.client_ca {
            changed.push("tls_client_ca");
        }
        if changed.is_empty() {
            return Ok(changed);
        }
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material)?;
        self.dot.store(dot);
        self.doh.store(doh);
        self.doq.store(doq);
        self.doh3.store(doh3);
        *live = fresh;
        Ok(changed)
    }

    /**
     * @brief 설정에 적힌 인증서를 읽어 네 슬롯을 한꺼번에 교체한다.
     *
     * @details 하나라도 읽지 못하면 아무 슬롯도 건드리지 않고 실패한다. 절반만 교체하면 전송마다
     *          다른 인증서를 내밀게 된다.
     * @return 인증서나 개인키가 올바르지 않으면 실패. 그때 이전 인증서가 그대로 쓰인다.
     */
    fn reload(&self, cfg: &Config) -> Result<(), String> {
        let mut live = self.live_files.lock_recover();
        let material = native_tls_material(cfg)?;
        let fresh = live_tls_files(cfg, material.0.clone())?;
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material)?;
        self.dot.store(dot);
        self.doh.store(doh);
        self.doq.store(doq);
        self.doh3.store(doh3);
        *live = fresh;
        Ok(())
    }
}

/** @brief 이미 읽어 둔 인증서로 전송 넷에 쓸 TLS 설정을 만든다. ALPN만 다르다. */
#[allow(clippy::type_complexity)]
fn tls_configs_from(
    cfg: &Config,
    material: &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<
    (
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
    ),
    String,
> {
    // 네 전송이 같은 인증서를 내놓아야 한다. 하나를 넷이 나눠 쓴다.
    Ok((
        native_tls_config(cfg, vec![b"dot".to_vec()], material)?,
        native_tls_config(cfg, vec![b"h2".to_vec(), b"http/1.1".to_vec()], material)?,
        native_tls_config(cfg, vec![b"doq".to_vec()], material)?,
        native_tls_config(cfg, vec![b"h3".to_vec()], material)?,
    ))
}

/**
 * @brief 지금 열려 있는 수신 주소들.
 *
 * @details 주소마다 그 주소를 연 설정을 이름으로 함께 가지고 있다. 이름이 그대로면 그 리스너는
 *          손대지 않는다. 그 주소로 오던 질의는 한 건도 끊기지 않는다.
 * @invariant 새 리스너를 모두 연 뒤에 이전 것을 닫는다. 반대로 하면 그 사이에 아무도 받지
 *            않는 구간이 생긴다. 리눅스는 SO_REUSEPORT라 같은 주소를 겹쳐 열 수 있다.
 */
#[derive(Default)]
struct ListenerSet {
    /** @brief 일반 DNS. */
    plain: Mutex<Vec<(String, onetdns_runtime::Server)>>,
    /** @brief DoT. */
    dot: Mutex<Vec<(String, dot::DotListener)>>,
    /** @brief DoH. */
    doh: Mutex<Vec<(String, doh::DohListener)>>,
    /** @brief DoQ. */
    doq: Mutex<Vec<(String, doq::DoqListener)>>,
    /** @brief DoH3. */
    doh3: Mutex<Vec<(String, doh3::Doh3Listener)>>,
    /** @brief 모든 주소의 DoQ·DoH3 연결이 함께 쓰는 전역 메모리 예산. */
    quic_memory: Arc<quic_memory::QuicMemoryBudget>,
    /** @brief 모든 주소의 DoH·DoT·DNSCrypt TCP 연결이 함께 쓰는 admission. */
    encrypted_tcp_admission: Arc<connection_limit::ConnectionLimiter>,
    /**
     * @brief DNSCrypt. UDP 리스너가 스레드라 종료 신호를 가지고 있고, 같은 주소의 TCP
     *        리스너는 사라질 때 스스로 합류하므로 함께 가지고 있는다.
     */
    dnscrypt: Mutex<
        Vec<(
            String,
            Arc<std::sync::atomic::AtomicBool>,
            dnscrypt::DnscryptTcpListener,
        )>,
    >,
}

/** @brief 일반 DNS 리스너 하나를 여는 설정을 이름으로 만든다. */
fn plain_listener_key(cfg: &Config, addr: &SocketAddr, workers: usize, acceptors: usize) -> String {
    format!(
        "{addr}|{}|{}|{}|{}|{:?}",
        cfg.do_udp,
        cfg.do_tcp,
        workers,
        acceptors,
        (
            cfg.proxy_protocol_ports.contains(&addr.port()),
            &cfg.proxy_protocol_trusted
        ),
    )
}

/**
 * @brief 수신 주소를 열지 못한 이유를 운영자가 고칠 수 있게 적는다.
 *
 * @details 주소가 이미 쓰이고 있다는 사실만으로는 누가 잡고 있는지 알 수 없어 고칠 방법이
 *          없다. 특히 와일드카드 주소는 구체 주소가 모두 비어 있어도 막히므로, 포트가 비어
 *          보인다는 이유로 설정을 의심하게 된다. 점유자를 찾는 명령을 함께 알려 준다.
 * @param role  어떤 수신 주소인지.
 * @param addr  열려던 주소.
 * @param error 바인딩이 낸 오류.
 * @return 운영자에게 보일 문장.
 */
fn listener_open_error(role: &str, addr: SocketAddr, error: &std::io::Error) -> String {
    let mut text = format!("{role} 수신 주소를 열지 못했습니다: {addr}: {error}");
    if error.kind() != std::io::ErrorKind::AddrInUse {
        return text;
    }
    let port = addr.port();
    text.push_str(&format!(". {port}번을 다른 프로세스가 잡고 있습니다."));
    if cfg!(windows) {
        text.push_str(&format!(
            " 확인: netstat -ano | findstr :{port}, tasklist /svc /FI \"PID eq <번호>\"."
        ));
    } else {
        text.push_str(&format!(" 확인: ss -lnup sport = :{port}."));
    }
    if addr.ip().is_unspecified() {
        text.push_str(" 와일드카드는 구체 주소가 모두 비어 있어도 막힙니다.");
    }
    text
}

/**
 * @brief 닫은 리스너 하나를 수신 상태 목록에서 뺀다.
 *
 * @details 설정 주소나 실제 주소가 같은 항목 가운데 먼저 들어간 것 하나만 뺀다. 같은
 *          주소로 새 리스너를 먼저 연 뒤 이전 것을 닫으므로, 같은 주소의 항목을 모두 지우면
 *          방금 연 리스너까지 목록에서 사라진다.
 * @warning 빼지 않으면 설정에서 지운 주소가 관리 화면에 계속 수신 중으로 남는다.
 */
fn forget_listener(
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
    kind: &str,
    addr: &str,
) {
    let mut entries = registry.lock_recover();
    if let Some(index) = entries.iter().position(|(entry_kind, configured, bound)| {
        *entry_kind == kind && (configured == addr || bound == addr)
    }) {
        entries.remove(index);
    }
}

/**
 * @brief 설정에 맞춰 수신 주소를 열고 닫는다.
 *
 * @details 시작할 때와 교체할 때 모두 이 함수만 부른다. 설정이 그대로인 주소는 건드리지
 *          않으므로 그 주소의 질의는 끊기지 않는다. 새 것을 다 연 뒤에 이전 것을 닫는다.
 * @return 주소를 열지 못하면 실패. 그때 이전 리스너는 그대로 살아 있어 계속 답한다.
 */
fn reconcile_listeners(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    tls: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
) -> Result<(), String> {
    let available_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let (udp_workers, tcp_acceptors) =
        plain_dns_worker_counts(cfg.workers, cfg.backend, available_cpus);

    let mut plain = set.plain.lock_recover();
    let wanted_plain: Vec<(String, SocketAddr)> = cfg
        .listen
        .iter()
        .map(|addr| {
            (
                plain_listener_key(cfg, addr, udp_workers, tcp_acceptors),
                *addr,
            )
        })
        .collect();
    let mut fresh_plain = Vec::new();
    for (key, addr) in &wanted_plain {
        if plain.iter().any(|(have, _)| have == key) {
            continue;
        }
        /* 같은 주소는 이전 리스너가 포트를 놓아야 열 수 있다. 드롭이 워커 합류까지 기다린다. */
        let same_addr = format!("{addr}|");
        plain.retain(|(have, server)| {
            let replaced = have.starts_with(&same_addr);
            if replaced {
                if let Some(bound) = server.udp_addr() {
                    forget_listener(registry, "do53-udp", &bound.to_string());
                }
                if let Some(bound) = server.tcp_addr() {
                    forget_listener(registry, "do53-tcp", &bound.to_string());
                }
            }
            !replaced
        });
        let server = onetdns_runtime::Server::bind(
            *addr,
            handler.clone(),
            onetdns_runtime::ServerConfig {
                proxy_protocol: cfg.proxy_protocol_ports.contains(&addr.port()),
                trusted_proxies: cfg.proxy_protocol_trusted.clone(),
                udp: cfg.do_udp,
                tcp: cfg.do_tcp,
                udp_workers,
                tcp_acceptors,
                udp_reactor: true,
                ..Default::default()
            },
        )
        .map_err(|error| listener_open_error("일반 DNS", *addr, &error))?;
        onetdns_core::info!(event = "do53.started", %addr, udp_workers, tcp_acceptors, udp = cfg.do_udp, tcp = cfg.do_tcp, backend = ?cfg.backend, "일반 DNS를 받습니다");
        if let Some(bound) = server.udp_addr() {
            registry
                .lock_recover()
                .push(("do53-udp", addr.to_string(), bound.to_string()));
        }
        if let Some(bound) = server.tcp_addr() {
            registry
                .lock_recover()
                .push(("do53-tcp", addr.to_string(), bound.to_string()));
        }
        fresh_plain.push((key.clone(), server));
    }
    // 새 리스너를 다 연 뒤에 이전 것을 닫는다. 닫기는 Drop이 한다.
    plain.retain(|(key, server)| {
        let keep = wanted_plain.iter().any(|(want, _)| want == key);
        if !keep {
            if let Some(bound) = server.udp_addr() {
                forget_listener(registry, "do53-udp", &bound.to_string());
            }
            if let Some(bound) = server.tcp_addr() {
                forget_listener(registry, "do53-tcp", &bound.to_string());
            }
        }
        keep
    });
    plain.extend(fresh_plain);
    drop(plain);

    reconcile_encrypted(cfg, set, handler, tls, shutdown, registry)
}

/** @brief 암호화 수신 주소들만 설정에 맞춘다. 일반 DNS는 건드리지 않는다. */
fn reconcile_encrypted(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    tls: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
) -> Result<(), String> {
    /** @brief 인증서 슬롯이 없으면 암호화 수신 주소를 열 수 없다. */
    const NEED_TLS: &str = "암호화 DNS를 사용하려면 질의를 업스트림 서버로 전달하거나 직접 재귀 조회하도록 설정하고, ECDSA P-256 인증서와 개인 키를 지정해야 합니다";

    /* DoH 경로는 리스너가 열 때 고정한다. 같은 주소는 이전 리스너를 먼저 내려야 다시 열 수 있다. */
    macro_rules! sync_one {
        ($field:ident, $addrs:expr, $kind:literal, $open:expr) => {{
            let mut live = set.$field.lock_recover();
            let path_part = if matches!($kind, "doh" | "doh3") {
                cfg.doh_path.as_str()
            } else {
                ""
            };
            let wanted: Vec<(String, SocketAddr)> = $addrs
                .iter()
                .map(|addr: &SocketAddr| (format!("{}|{}|{}", $kind, addr, path_part), *addr))
                .collect();
            let mut fresh = Vec::new();
            for (key, addr) in &wanted {
                if live.iter().any(|(have, _)| have == key) {
                    continue;
                }
                let same_addr = format!("{}|{}|", $kind, addr);
                live.retain(|(have, listener)| {
                    let replaced = have.starts_with(&same_addr);
                    if replaced {
                        forget_listener(registry, $kind, &listener.addr().to_string());
                    }
                    !replaced
                });
                let listener = $open(*addr)?;
                onetdns_core::info!(
                    event = "listener.started",
                    transport = $kind,
                    bound = %listener.addr(),
                    "암호화 DNS 수신 주소를 열었습니다"
                );
                registry
                    .lock_recover()
                    .push(($kind, addr.to_string(), listener.addr().to_string()));
                fresh.push((key.clone(), listener));
            }
            live.retain(|(key, listener)| {
                let keep = wanted.iter().any(|(want, _)| want == key);
                if !keep {
                    forget_listener(registry, $kind, &listener.addr().to_string());
                }
                keep
            });
            live.extend(fresh);
        }};
    }

    let need = |pick: fn(&TlsSlots) -> Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>| {
        TlsSlots::get_or_build(tls, cfg)
            .map(|slots| pick(&slots))
            .map_err(|error| format!("{NEED_TLS}: {error}"))
    };

    if !cfg.listen_dot.is_empty() || !set.dot.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.dot.clone())?;
        sync_one!(dot, cfg.listen_dot, "dot", |addr| dot::serve_dot(
            addr,
            tls_cfg.clone(),
            handler.clone(),
            set.encrypted_tcp_admission.clone(),
            shutdown.clone()
        )
        .map_err(|error| listener_open_error("DoT", addr, &error)));
    }
    if !cfg.listen_doh.is_empty() || !set.doh.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doh.clone())?;
        sync_one!(doh, cfg.listen_doh, "doh", |addr| doh::serve_doh(
            addr,
            tls_cfg.clone(),
            handler.clone(),
            cfg.doh_path.clone(),
            set.encrypted_tcp_admission.clone(),
            shutdown.clone()
        )
        .map_err(|error| listener_open_error("DoH", addr, &error)));
    }
    if !cfg.listen_doq.is_empty() || !set.doq.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doq.clone())?;
        sync_one!(doq, cfg.listen_doq, "doq", |addr| doq::serve_doq(
            addr,
            tls_cfg.clone(),
            handler.clone(),
            shutdown.clone(),
            set.quic_memory.clone()
        )
        .map_err(|error| listener_open_error("DoQ", addr, &error)));
    }
    if !cfg.listen_doh3.is_empty() || !set.doh3.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doh3.clone())?;
        sync_one!(doh3, cfg.listen_doh3, "doh3", |addr| doh3::serve_doh3(
            addr,
            tls_cfg.clone(),
            handler.clone(),
            cfg.doh_path.clone(),
            shutdown.clone(),
            set.quic_memory.clone()
        )
        .map_err(|error| listener_open_error("DoH3", addr, &error)));
    }
    Ok(())
}

/** @brief DNSCrypt 인증서의 유효 기간. */
const DNSCRYPT_CERT_VALID_SECS: u32 = 24 * 60 * 60;

/**
 * @brief TLS 인증서 파일을 다시 확인하는 주기(초).
 * @details 갱신은 드물고 몇 분 늦게 반영되어도 무방하다. 짧게 잡을수록 아무 일도 없는
 *          동안 파일을 읽는 횟수만 늘어난다.
 */
const TLS_CERT_WATCH_SECS: u64 = 300;

/** @brief 설정에 직접 적은 영역 파일을 다시 확인하는 주기(초). 디렉터리 감시와 같다. */
const ZONE_FILE_WATCH_SECS: u64 = 10;

/**
 * @brief 파일이 편집된 영역들의 이름.
 *
 * @details 설정에 적힌 파일만 본다. 수정 시각이 달라진 파일과 이번에 처음 보이는 파일이
 *          대상이다. 처음 보이는 파일은 설정이 방금 그 영역을 더했다는 뜻이라 한 번 읽는다.
 * @param previous 지난 주기에 본 수정 시각.
 * @param current 이번 주기에 본 수정 시각.
 */
fn zones_with_edited_files(
    cfg: &Config,
    previous: &std::collections::HashMap<PathBuf, std::time::SystemTime>,
    current: &std::collections::HashMap<PathBuf, std::time::SystemTime>,
) -> Vec<onetdns_proto::Name> {
    cfg.zones
        .iter()
        .filter(|zone| {
            zone.file.as_ref().is_some_and(|file| {
                current
                    .get(file)
                    .is_some_and(|stamp| previous.get(file) != Some(stamp))
            })
        })
        .filter_map(|zone| onetdns_proto::Name::from_str(&zone.origin).ok())
        .collect()
}

/** @brief 설정에 직접 적은 영역 파일들의 지금 수정 시각. 읽지 못하는 파일은 빠진다. */
fn zone_file_mtimes(cfg: &Config) -> std::collections::HashMap<PathBuf, std::time::SystemTime> {
    cfg.zones
        .iter()
        .filter_map(|zone| zone.file.clone())
        .filter_map(|path| {
            let stamp = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()?;
            Some((path, stamp))
        })
        .collect()
}

/**
 * @brief DNSCrypt 수신 주소를 설정에 맞춘다.
 *
 * @details 주소와 공급자 이름을 이름으로 삼는다. 이름이 그대로면 그 리스너는 손대지 않는다.
 *          수신 반복은 500밀리초마다 종료 신호를 보므로 보내면 곧 포트를 놓는다.
 * @return 주소를 열지 못하거나 공급자 키를 읽지 못하면 실패. 이전 리스너는 그대로 둔다.
 */
/**
 * @brief 주소가 풀릴 때까지 잠깐 기다리며 리스너를 연다.
 *
 * @details 앞서 닫은 리스너의 반복은 종료 신호를 확인하고 나가야 소켓을 놓는다. 그
 *          사이를 기다리지 않으면 같은 주소를 다시 열 때 이미 쓰이고 있다며 실패한다.
 * @return 열린 리스너, 또는 기다려도 풀리지 않았을 때의 오류.
 */
fn open_when_free<T>(mut open: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match open() {
            Ok(value) => return Ok(value),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error),
        }
    }
}

fn reconcile_dnscrypt(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    config_path: &Option<PathBuf>,
    tracker: &Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let wanted: Vec<(String, SocketAddr)> = cfg
        .listen_dnscrypt
        .iter()
        .map(|addr| {
            (
                format!("dnscrypt|{addr}|{}", cfg.dnscrypt_provider_name),
                *addr,
            )
        })
        .collect();
    let mut live = set.dnscrypt.lock_recover();
    let need_new = wanted
        .iter()
        .any(|(key, _)| !live.iter().any(|(have, _, _)| have == key));
    if !need_new {
        live.retain(|(key, stop, _)| {
            let keep = wanted.iter().any(|(want, _)| want == key);
            if !keep {
                stop.store(true, Ordering::Release);
                if let Some(addr) = key.split('|').nth(1) {
                    forget_listener(registry, "dnscrypt", addr);
                }
            }
            keep
        });
        return Ok(());
    }

    let provider = load_or_create_dnscrypt_provider(cfg, config_path, DNSCRYPT_CERT_VALID_SECS)?;
    let pubkey: String = provider
        .provider_public_key()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    onetdns_core::info!(event = "dnscrypt.provider_key_loaded",
        provider = %cfg.dnscrypt_provider_name,
        provider_pubkey = %pubkey,
        "DNSCrypt 공급자 키를 불러왔습니다. 클라이언트는 이 공개 키를 신뢰해야 합니다"
    );

    let mut fresh = Vec::new();
    for (key, addr) in &wanted {
        if live.iter().any(|(have, _, _)| have == key) {
            continue;
        }
        // 주소는 그대로인데 설정만 바뀌었으면 이전 리스너를 먼저 닫는다. 잡고 있는 채로
        // 다시 열면 주소가 이미 쓰이고 있다며 실패한다.
        let prefix = format!("dnscrypt|{addr}|");
        let mut index = 0;
        while index < live.len() {
            if live[index].0 != *key && live[index].0.starts_with(&prefix) {
                let (_, old_stop, old_tcp) = live.swap_remove(index);
                old_stop.store(true, Ordering::Release);
                drop(old_tcp);
                forget_listener(registry, "dnscrypt", &addr.to_string());
            } else {
                index += 1;
            }
        }
        let socket = open_when_free(|| UdpSocket::bind(addr))
            .map_err(|error| listener_open_error("DNSCrypt", *addr, &error))?;
        let bound = socket
            .local_addr()
            .map(|value| value.to_string())
            .unwrap_or_else(|_| addr.to_string());
        registry
            .lock_recover()
            .push(("dnscrypt", addr.to_string(), bound.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let provider = provider.clone();
            let stop = stop.clone();
            let thread = std::thread::Builder::new()
                .name("dnscrypt-cert-refresh".into())
                .spawn(move || loop {
                    if sleep_or_shutdown((DNSCRYPT_CERT_VALID_SECS / 2) as u64, &stop) {
                        break;
                    }
                    provider.reissue_cert(DNSCRYPT_CERT_VALID_SECS);
                    onetdns_core::info!(
                        event = "dnscrypt.cert_rotated",
                        "DNSCrypt 리졸버 인증서를 만료 전에 갱신했습니다"
                    );
                })
                .map_err(|error| {
                    format!("DNSCrypt 인증서 갱신 작업을 시작하지 못했습니다: {error}")
                })?;
            track_service_thread(tracker, thread);
        }
        // 규격은 인증서 조회와 잘린 응답의 재시도를 TCP 로 시킨다. UDP 만 열면 그 경로가
        // 전부 막히므로 같은 주소를 둘 다로 받는다.
        let tcp = open_when_free(|| {
            dnscrypt::serve_tcp(
                *addr,
                handler.clone(),
                provider.clone(),
                set.encrypted_tcp_admission.clone(),
                stop.clone(),
            )
        })
        .map_err(|error| listener_open_error("DNSCrypt TCP", *addr, &error))?;
        let handler = handler.clone();
        let provider = provider.clone();
        let listener_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name(format!("dnscrypt-{bound}"))
            .spawn(move || {
                if let Err(error) = dnscrypt::serve(handler, socket, provider, listener_stop) {
                    onetdns_core::error!(event = "dnscrypt.stopped", %error, "DNSCrypt 수신을 중지했습니다");
                }
            })
            .map_err(|error| format!("DNSCrypt 수신 스레드를 시작하지 못했습니다: {bound}: {error}"))?;
        track_service_thread(tracker, thread);
        onetdns_core::info!(event = "dnscrypt.started", %addr, "DNSCrypt로 질의를 받습니다 (UDP·TCP)");
        fresh.push((key.clone(), stop, tcp));
    }
    live.retain(|(key, stop, _)| {
        let keep = wanted.iter().any(|(want, _)| want == key);
        if !keep {
            stop.store(true, Ordering::Release);
        }
        keep
    });
    live.extend(fresh);
    Ok(())
}

/** @brief 설정대로 속도 제한을 만든다. */
fn runtime_rate_limiters(cfg: &Config) -> Vec<Arc<dyn RateLimiter>> {
    let mut rate_limiters: Vec<Arc<dyn RateLimiter>> = Vec::new();
    if let Some(srl) = SubnetRateLimiter::new(cfg.subnet_rrl_per_sec, cfg.subnet_rrl_burst, 24, 56)
        .map(|r| r.with_allow(cfg.rate_limit_allow.clone()))
    {
        rate_limiters.push(Arc::new(srl));
    }
    if let Some(rl) = KeyedRateLimiter::new(cfg.rate_limit_per_sec, cfg.rate_limit_burst)
        .map(|r| r.with_allow(cfg.rate_limit_allow.clone()))
    {
        rate_limiters.push(Arc::new(rl));
    }
    rate_limiters
}

/**
 * @brief 응답 캐시 아래에서 판정하는 로컬 전용 이름 설정들.
 * @details 판정 결과가 캐시에 담기므로, 이 값을 바꾸면 캐시를 비워야 바뀐 판정이 바로 나간다.
 */
const LOCAL_ONLY_CONFIG_KEYS: &[&str] = &["domain_needed", "bogus_priv", "empty_zones"];

/** @brief 무엇이 바뀌었느냐에 따라 재시작 여부가 갈리는 설정들. */
const CONDITIONAL_HOT_RELOAD_CONFIG_KEYS: &[&str] = &["clients"];

/** @brief 직접 바뀐 설정과 그 설정이 다시 만들어야 하는 파생 그룹을 모은다. */
fn hot_reload_groups(previous: &Config, next: &Config, changed: &[String]) -> Vec<ApplyGroup> {
    let mut groups = changed
        .iter()
        .filter_map(|key| config_keys::hot_group(key))
        .collect::<Vec<_>>();
    /*
     * 체인은 계획만 읽으므로, 어느 키가 바뀌었든 계획이 달라지면 체인을 다시 만든다.
     * 질의 제한 시간처럼 전달 그룹에 속한 키도 스텁 영역과 예비 업스트림의 전달기에 쓰인다.
     */
    if resolver_chain::ChainPlan::new(previous) != resolver_chain::ChainPlan::new(next) {
        groups.push(ApplyGroup::Chain);
    }
    /* DHCP 임대 풀은 서비스를 다시 띄우면 새로 만들어지므로, DHCP DNS 계층도 새 풀을 봐야 한다. */
    if groups.contains(&ApplyGroup::EdgeServices) {
        groups.push(ApplyGroup::Chain);
    }
    /* 로컬 도메인은 DHCP 옵션 15로도 나간다. */
    if changed.iter().any(|key| key == "dhcp_local_domain") {
        groups.push(ApplyGroup::EdgeServices);
    }
    // 클러스터 활성 상태나 공용 비밀이 바뀌면 DNS Cookie의 공유 루트도 같은 설정 세대에서
    // 다시 만들어야 한다. native 그룹은 ArcSwap 한 번으로 기존/새 정책 중 하나만 보인다.
    if changed.iter().any(|key| key == "cluster_raft")
        || ((previous.cluster_raft || next.cluster_raft)
            && changed.iter().any(|key| key == "cluster_raft_secret"))
    {
        groups.push(ApplyGroup::Native);
    }
    groups.sort_unstable();
    groups.dedup();
    groups
}

/**
 * @brief 업스트림 TLS 인증서 폐기 확인 정책을 설정대로 설치한다.
 *
 * @details 정책을 바꾸면 전달 계층의 세대가 올라가므로, 이전 정책으로 검증된 풀 연결과
 *          세션 재개 정보는 다음 질의부터 쓰이지 않는다.
 */
fn install_revocation_policy(cfg: &Config, resolver: &http::HostResolver) {
    let mode = revoke::RevocationMode::parse(&cfg.tls_revocation);
    if mode == revoke::RevocationMode::Off {
        onetdns_forward::clear_revocation_hook();
        return;
    }
    let checker =
        revoke::RevocationChecker::new(mode, cfg.tls_revocation_softfail, Duration::from_secs(10))
            .with_resolver(resolver.clone());
    onetdns_forward::set_revocation_hook(Box::new(move |chain, _host| {
        checker.check_chain(chain, unix_now() as i64).map(|_| ())
    }));
    onetdns_core::info!(event = "tls.revocation_check_enabled",
        mode = ?mode,
        softfail = cfg.tls_revocation_softfail,
        "업스트림 TLS 서버 인증서의 폐기 상태를 확인합니다(OCSP/CRL)"
    );
}

/** @brief 이 backend가 전달 리졸버를 쓰는지. */
fn backend_uses_forward(backend: BackendKind) -> bool {
    matches!(backend, BackendKind::Forward | BackendKind::Split)
}

/** @brief 클라이언트 설정 변화가 재시작를 요구하는지. 경로가 바뀌면 체인을 다시 지어야 한다. */
fn clients_require_service_restart(current: &Config, proposed: &Config) -> bool {
    let current_routes: Vec<_> = current
        .clients
        .iter()
        .filter(|client| !client.upstreams.is_empty())
        .collect();
    let proposed_routes: Vec<_> = proposed
        .clients
        .iter()
        .filter(|client| !client.upstreams.is_empty())
        .collect();

    let routes_changed = current_routes.len() != proposed_routes.len()
        || current_routes
            .iter()
            .zip(proposed_routes.iter())
            .any(|(old, new)| {
                old.ids != new.ids
                    || old.client_ids != new.client_ids
                    || old.mac != new.mac
                    || old.upstreams != new.upstreams
            });
    if routes_changed {
        return true;
    }

    let had_mac = current.clients.iter().any(|client| !client.mac.is_empty());
    let needs_mac = proposed.clients.iter().any(|client| !client.mac.is_empty());
    !had_mac && needs_mac
}

/** @brief 클라이언트별 업스트림 경로가 있는지. */
fn has_client_upstream_routes(config: &Config) -> bool {
    config
        .clients
        .iter()
        .any(|client| !client.upstreams.is_empty())
}

/** @brief 이 변화를 재시작하지 않고 반영할 수 있는지. */
fn is_hot_reload_config_change(current: &Config, proposed: &Config, key: &str) -> bool {
    if !config_keys::is_hot(key) {
        return false;
    }
    let client_routes_active =
        has_client_upstream_routes(current) || has_client_upstream_routes(proposed);
    match key {
        "clients" => !clients_require_service_restart(current, proposed),

        "query_timeout_secs" => {
            current.backend == proposed.backend
                && current.backend == BackendKind::Forward
                && !client_routes_active
        }

        "upstream_strategy" | "upstream_concurrency" => {
            current.backend == proposed.backend && !client_routes_active
        }
        _ => true,
    }
}

/** @brief 새 계획으로 해석 체인을 다시 만들어 교체하는 함수. */
type ChainRebuild = Arc<dyn Fn(&resolver_chain::ChainPlan) -> Result<(), String> + Send + Sync>;

/** @brief 세대가 소유한 보조 작업을 새 설정으로 다시 시작하는 함수. */
type SecondaryRestart = Arc<dyn Fn(&Config) -> Result<(), String> + Send + Sync>;

/**
 * @brief 차단 엔진을 지금 설정과 목록으로 다시 만들어 교체하는 함수.
 * @return 차단 규칙 수와 허용 규칙 수.
 */
type FilterRebuild = Arc<dyn Fn() -> Result<(usize, usize), String> + Send + Sync + 'static>;

/** @brief 교체를 실제로 하는 함수. */
type HotConfigApply =
    Arc<dyn Fn(&Config, &[String]) -> Result<(bool, Vec<String>), String> + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 설정을 어떻게 반영했는지. */
enum ConfigApplyMode {
    /** @brief 바뀐 것이 없다. */
    NoChange,
    /** @brief 재시작하지 않고 교체했다. */
    HotReload,
    /** @brief 재시작해야 한다. */
    ServiceRestart,
}

impl ConfigApplyMode {
    /** @brief 이름. */
    fn as_str(self) -> &'static str {
        match self {
            Self::NoChange => "no_change",
            Self::HotReload => "hot_reload",
            Self::ServiceRestart => "service_restart",
        }
    }

    /** @brief 재시작해야 하는지. */
    fn restart_required(self) -> bool {
        matches!(self, Self::ServiceRestart)
    }
}

#[derive(Debug, Clone)]
/** @brief 설정 반영 결과. */
struct ConfigApplyResult {
    /** @brief 어떻게 반영했는지. */
    mode: ConfigApplyMode,
    /** @brief 달라진 설정 항목들. */
    changed: Vec<String>,
}

impl ConfigApplyResult {
    /** @brief 결과를 JSON 항목들로. */
    fn json_fields(&self) -> String {
        let changed = self
            .changed
            .iter()
            .map(|key| onetdns_core::json::escape(key))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "\"mode\":\"{}\",\"restart_required\":{},\"reloading\":{},\"changed\":[{}]",
            self.mode.as_str(),
            self.mode.restart_required(),
            self.mode.restart_required(),
            changed
        )
    }
}

/** @brief 두 설정 텍스트에서 달라진 항목들. */
fn changed_config_keys(current: &str, proposed: &str) -> Result<Vec<String>, String> {
    let (added, removed, changed) =
        onetdns_config::Config::diff_toml(current, proposed).map_err(|e| e.to_string())?;
    let mut keys = Vec::with_capacity(added.len() + removed.len() + changed.len());
    keys.extend(added);
    keys.extend(removed);
    keys.extend(changed);
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/** @brief 설정 파일을 한 번에 하나씩만 고치게 한다. */
fn config_write_lock() -> &'static Mutex<()> {
    /** @brief 설정 파일 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 바뀐 것만 보고 교체하거나 재시작한다. */
fn apply_config_edit_smart(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    applied: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    hot_apply: &HotConfigApply,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<ConfigApplyResult, String> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    apply_config_edit_smart_locked(path, prev, applied, reload, hot_apply, edit)
}

/** @brief 잠금을 잡은 채로 반영한다. */
fn apply_config_edit_smart_locked(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    applied: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    hot_apply: &HotConfigApply,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<ConfigApplyResult, String> {
    use onetdns_core::MutexExt;
    use std::sync::atomic::Ordering;
    let Some(p) = path else {
        return Err("설정 파일 경로가 없습니다. 현재 설정은 메모리에만 있습니다".to_string());
    };
    let current =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| e.to_string())?);
    let new_text = onetdns_core::SecretString::from(edit(&current)?);
    let new_cfg = onetdns_config::Config::from_toml_str(&new_text)
        .map_err(|e| format!("변경한 설정이 유효하지 않습니다: {e}"))?;
    let changed = changed_config_keys(&current, &new_text)?;
    if changed.is_empty() {
        return Ok(ConfigApplyResult {
            mode: ConfigApplyMode::NoChange,
            changed,
        });
    }
    /* 검증 API와 같은 기준으로 거른다. 통과시키면 저장한 뒤 재시작할 때 서버가 뜨지 않는다. */
    runtime_preflight(&new_cfg).map_err(|e| format!("변경한 설정이 유효하지 않습니다: {e}"))?;

    atomic_write(p, new_text.as_bytes()).map_err(|e| e.to_string())?;
    let (mode, effective_changed) = match hot_apply(&new_cfg, &changed) {
        Ok((true, effective_changed)) => (ConfigApplyMode::HotReload, effective_changed),
        Ok((false, effective_changed)) => {
            reload.store(true, Ordering::Release);
            (ConfigApplyMode::ServiceRestart, effective_changed)
        }
        Err(error) => {
            let restore = atomic_write(p, current.as_bytes())
                .map_err(|e| format!("{error}; 설정 파일도 이전 상태로 복구하지 못했습니다: {e}"));
            return match restore {
                Ok(()) => Err(error),
                Err(combined) => Err(combined),
            };
        }
    };
    *prev.lock_recover() = Some(current);
    if mode == ConfigApplyMode::HotReload {
        *applied.lock_recover() = Some(new_text);
    }
    Ok(ConfigApplyResult {
        mode,
        changed: effective_changed,
    })
}

/** @brief 설정을 고쳐 저장한다. 건드리지 않은 항목은 그대로 둔다. 전체를 덮어쓰면 다른 설정이 사라진다. */
fn apply_config_edit(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    let _write_guard = config_write_lock().lock_recover();
    apply_config_edit_locked(path, prev, reload, edit)
}

/** @brief 잠금을 잡은 채로 고쳐 저장한다. */
fn apply_config_edit_locked(
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
    edit: impl FnOnce(&str) -> Result<String, String>,
) -> Result<(), String> {
    use onetdns_core::MutexExt;
    use std::sync::atomic::Ordering;
    let Some(p) = path else {
        return Err("설정 파일 경로가 없습니다. 현재 설정은 메모리에만 있습니다".to_string());
    };
    let current =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|e| e.to_string())?);
    let new_text = onetdns_core::SecretString::from(edit(&current)?);
    onetdns_config::Config::from_toml_str(&new_text)
        .map_err(|e| format!("변경한 설정이 유효하지 않습니다: {e}"))?;
    atomic_write(p, new_text.as_bytes()).map_err(|e| e.to_string())?;
    *prev.lock_recover() = Some(current);
    reload.store(true, Ordering::Relaxed);
    Ok(())
}

/** @brief 인증서와 키에서 읽어 낸 정보. */
struct TlsMaterialInfo {
    /** @brief 읽어 낸 인증서들. */
    parsed: Vec<onetdns_tls::X509>,
    /** @brief 모든 인증서가 유효 기간 안인지. */
    all_times_valid: bool,
    /** @brief 체인의 연결이 맞는지. */
    chain_links_valid: bool,
    /** @brief 체인의 제약이 지켜지는지. */
    chain_constraints_valid: bool,
    /** @brief 스스로 서명한 인증서인지. */
    self_signed: bool,
}

/** @brief 인증서와 키를 살펴본다. */
fn inspect_tls_material(certs: &[Vec<u8>], key: &[u8]) -> Result<TlsMaterialInfo, String> {
    let cert0 = certs.first().ok_or("빈 인증서 체인".to_string())?;
    if onetdns_tls::ServerConfig::from_chain_pkcs8(certs.to_vec(), key).is_none() {
        return Err(
            "인증서와 개인 키를 해석하지 못했습니다. ECDSA P-256 PKCS#8 형식이 필요합니다"
                .to_string(),
        );
    }
    onetdns_transport::verify_key_matches_cert(cert0, key).map_err(|e| e.to_string())?;
    let parsed: Vec<onetdns_tls::X509> = certs
        .iter()
        .map(|der| onetdns_tls::X509::parse(der).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let leaf = parsed.first().ok_or("빈 인증서 체인".to_string())?;
    let self_signed = leaf.issuer_raw == leaf.subject_raw;
    let now = unix_now() as i64;
    let all_times_valid = parsed.iter().all(|cert| cert.valid_at(now));

    let chain_links_valid = if parsed.len() == 1 {
        self_signed && leaf.verify_signed_by(leaf).is_ok()
    } else {
        parsed.windows(2).all(|pair| {
            pair[0].issuer_raw == pair[1].subject_raw && pair[0].verify_signed_by(&pair[1]).is_ok()
        })
    };
    let leaf_usage_valid = leaf.allows_tls_leaf_usage() && leaf.allows_server_auth();
    let issuer_constraints_valid = parsed.iter().enumerate().skip(1).all(|(index, cert)| {
        let below_ca_count = index.saturating_sub(1) as u32;
        cert.is_ca
            && cert.allows_cert_sign()
            && cert.path_len.is_none_or(|limit| below_ca_count <= limit)
    });
    let chain_constraints_valid = leaf_usage_valid && issuer_constraints_valid;
    Ok(TlsMaterialInfo {
        parsed,
        all_times_valid,
        chain_links_valid,
        chain_constraints_valid,
        self_signed,
    })
}

/** @brief 이 인증서와 키로 실제로 서빙할 수 있는지 확인한다. 확인 없이 바꾸면 다음 연결부터 전부 실패한다. */
fn require_servable_tls_material(certs: &[Vec<u8>], key: &[u8]) -> Result<(), String> {
    let info = inspect_tls_material(certs, key)?;
    if !info.all_times_valid {
        return Err("인증서 체인에 아직 유효하지 않거나 만료된 인증서가 있습니다".to_string());
    }
    if !info.chain_links_valid {
        return Err("인증서 체인이 불완전하거나 서명/issuer 연결이 올바르지 않습니다".to_string());
    }
    if !info.chain_constraints_valid {
        return Err(
            "인증서의 basicConstraints/keyUsage/EKU/pathLen 제약이 서버 체인에 맞지 않습니다"
                .to_string(),
        );
    }
    Ok(())
}

/** @brief 인증서와 키를 바꾼다. */
fn tls_configure(
    body: &str,
    cfg_cert: &Option<std::path::PathBuf>,
    cfg_key: &Option<std::path::PathBuf>,
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
) -> Result<String, String> {
    use std::path::PathBuf;
    let j = onetdns_core::json::parse(body)
        .map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
    let onetdns_core::json::Json::Obj(fields) = &j else {
        return Err("TLS 설정 요청은 JSON 객체여야 합니다".into());
    };
    /** @brief 인증서 설정 항목들. */
    const TLS_FIELDS: [&str; 4] = ["certificate_chain", "private_key", "cert_path", "key_path"];
    if fields
        .iter()
        .any(|(key, _)| !TLS_FIELDS.contains(&key.as_str()))
        || TLS_FIELDS.iter().any(|key| {
            fields
                .iter()
                .filter(|(candidate, _)| candidate == key)
                .count()
                > 1
        })
    {
        return Err("TLS 설정 요청에 지원하지 않는 항목이나 중복 항목이 있습니다".into());
    }
    let getstr = |k: &str| {
        j.get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let inline_cert = getstr("certificate_chain");
    let inline_key = getstr("private_key");
    let requested_cert_path = getstr("cert_path");
    let requested_key_path = getstr("key_path");
    if inline_cert.is_some() != inline_key.is_some()
        || requested_cert_path.is_some() != requested_key_path.is_some()
    {
        return Err(
            "인증서와 개인 키, 인증서 경로와 개인 키 경로는 각각 함께 입력해야 합니다".into(),
        );
    }

    let (cert_path, key_path, chain_len, material_backup) =
        if let (Some(cpem), Some(kpem)) = (inline_cert, inline_key) {
            let (certs, key) = onetdns_transport::parse_pem(cpem, kpem)
                .map_err(|e| format!("PEM 인증서와 개인 키 검증에 실패했습니다: {e}"))?;
            let chain_len = certs.len();
            require_servable_tls_material(&certs, &key)?;
            let cert_p = requested_cert_path
                .map(PathBuf::from)
                .or_else(|| cfg_cert.clone())
                .ok_or("인증서를 저장할 cert_path 또는 기존 tls_cert 경로가 필요합니다")?;
            let key_p = requested_key_path
                .map(PathBuf::from)
                .or_else(|| cfg_key.clone())
                .ok_or("개인키를 저장할 key_path 또는 기존 tls_key 경로가 필요합니다")?;
            let backup = commit_cert_key(&cert_p, cpem.as_bytes(), &key_p, kpem.as_bytes())
                .map_err(|e| format!("인증서와 개인 키를 저장하지 못했습니다: {e}"))?;
            (cert_p, key_p, chain_len, Some(backup))
        } else {
            let cert_p = requested_cert_path
                .map(PathBuf::from)
                .ok_or("cert_path 파일 경로나 certificate_chain 값을 입력해야 합니다")?;
            let key_p = requested_key_path
                .map(PathBuf::from)
                .ok_or("key_path 파일 경로나 private_key 값을 입력해야 합니다")?;
            let (certs, key) = onetdns_transport::load_pem(&cert_p, &key_p)
                .map_err(|e| format!("PEM 데이터를 불러오지 못했습니다: {e}"))?;
            let chain_len = certs.len();
            require_servable_tls_material(&certs, &key)?;
            (cert_p, key_p, chain_len, None)
        };

    let cert_s = cert_path.display().to_string();
    let key_s = key_path.display().to_string();
    let config_result = apply_config_edit(path, prev, reload, |text| {
        let out = rewrite_config_kv(text, "tls_cert", &toml_quote(&cert_s))?;
        rewrite_config_kv(&out, "tls_key", &toml_quote(&key_s))
    });
    if let Err(config_err) = config_result {
        if let Some(backup) = &material_backup {
            if let Err(rollback_err) = rollback_cert_key(&cert_path, &key_path, backup) {
                return Err(format!(
                    "설정 저장에 실패했고 인증서와 개인 키도 이전 상태로 되돌리지 못했습니다: 설정 오류={config_err}; 복구 오류={rollback_err}"
                ));
            }
        }
        return Err(config_err);
    }
    onetdns_core::info!(event = "tls.cert_installed", cert = %cert_s, key = %key_s, "TLS 인증서를 검증하고 저장한 뒤 수신 서비스를 다시 시작했습니다");
    Ok(format!(
        "{{\"configured\":true,\"chain_len\":{chain_len},\"reloading\":true,\"cert\":{},\"key\":{}}}",
        onetdns_core::json::escape(&cert_s),
        onetdns_core::json::escape(&key_s)
    ))
}

/** @brief 인증서 발급을 돌린다. */
fn acme_issue_run(
    cfg: &Config,
    body: &str,
    resolver: http::HostResolver,
    tls_slots: Option<Arc<TlsSlots>>,
) -> Result<String, String> {
    let j = onetdns_core::json::parse(body)
        .map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
    let bstr = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
    let directory_url = bstr("directory")
        .or_else(|| cfg.acme_directory_url.clone())
        .ok_or("ACME 디렉터리 주소를 directory 또는 acme_directory_url에 입력해야 합니다")?;
    let domains: Vec<String> = j
        .get("domains")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| cfg.acme_domains.clone());
    let contact = bstr("contact").or_else(|| cfg.acme_contact_email.clone());
    let challenge = bstr("challenge").unwrap_or_else(|| cfg.acme_challenge.clone());
    let account_only = j
        .get("account_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    onetdns_config::validate_acme_request(
        Some(&directory_url),
        &domains,
        contact.as_deref(),
        &challenge,
    )?;

    let account_key_pem = match cfg.acme_account_key_file.as_ref() {
        Some(path) => match read_text_limited(std::path::Path::new(path), LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => Some(Zeroizing::new(pem)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!("ACME 계정 키를 읽지 못했습니다({path}): {error}"));
            }
        },
        None => None,
    };

    let params_domains = domains.clone();
    let params = acme::IssueParams {
        directory_url,
        domains,
        contact,
        challenge,
        account_key_pem,
        account_only,
    };
    let res = acme::run_issue(params, Duration::from_secs(20), resolver)?;

    if let Some(p) = &cfg.acme_account_key_file {
        if !std::path::Path::new(p).exists() {
            atomic_write_secret(std::path::Path::new(p), res.account_key_pem.as_bytes())
                .map_err(|e| format!("ACME 계정 키를 저장하지 못했습니다: {e}"))?;
        }
    }

    let mut issued = false;
    if let (Some(cert), Some(key)) = (&res.cert_pem, &res.cert_key_pem) {
        match (&cfg.acme_cert_file, &cfg.acme_key_file) {
            (Some(cf), Some(kf)) => {
                commit_cert_key(
                    std::path::Path::new(cf),
                    cert.as_bytes(),
                    std::path::Path::new(kf),
                    key.as_bytes(),
                )
                .map_err(|e| format!("인증서와 개인 키를 저장하지 못했습니다: {e}"))?;
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "acme_cert_file과 acme_key_file은 둘 다 설정하거나 둘 다 생략해야 합니다"
                        .to_string(),
                );
            }
            (None, None) => {}
        }
        // 발급은 인증서 파일만 바꾼다. 실행 중인 수신 주소가 쥐고 있는 인증서까지 여기서
        // 갈지 않으면, 발급에 성공하고도 다시 시작할 때까지 이전 인증서를 계속 내민다.
        if let Some(slots) = &tls_slots {
            match slots.refresh_certificate_files(cfg) {
                Ok(swapped) if !swapped.is_empty() => onetdns_core::info!(
                    event = "tls.certificate_reloaded",
                    changed = %swapped.join(","),
                    "수신 주소를 닫지 않고 TLS 인증서를 교체했습니다"
                ),
                Ok(_) => {}
                Err(error) => onetdns_core::warn!(
                    event = "tls.certificate_reload_failed",
                    %error,
                    "발급받은 인증서를 실행 중인 수신 주소에 올리지 못했습니다. 이전 인증서를 그대로 씁니다"
                ),
            }
        }
        issued = true;
        onetdns_core::info!(event = "acme.certificate_issued", account = %res.account_url, domains = %params_domains.join(","), stored = cfg.acme_cert_file.is_some(), "ACME로 인증서를 새로 발급받았습니다");
    }

    Ok(format!(
        "{{\"account\":{},\"issued\":{issued},\"cert_file\":{},\"key_file\":{}}}",
        onetdns_core::json::escape(&res.account_url),
        cfg.acme_cert_file
            .as_deref()
            .map(onetdns_core::json::escape)
            .unwrap_or_else(|| "null".to_string()),
        cfg.acme_key_file
            .as_deref()
            .map(onetdns_core::json::escape)
            .unwrap_or_else(|| "null".to_string()),
    ))
}

/** @brief 이 업스트림 표기가 어느 설정 항목에 속하는지. */
fn upstream_key(entry: &str) -> &'static str {
    if entry.contains("://") {
        "upstream_urls"
    } else {
        "upstreams"
    }
}

/** @brief 이 설정 항목에 적힌 업스트림들. */
fn upstream_values(cfg: &onetdns_config::Config, key: &str) -> Vec<String> {
    if key == "upstream_urls" {
        cfg.upstream_urls.clone()
    } else {
        cfg.upstreams.iter().map(|ip| ip.to_string()).collect()
    }
}

/** @brief 대시보드가 보낸 클라이언트 설정을 설정 텍스트로. */
fn client_block_from_json(body: &str) -> Result<(String, String), String> {
    use onetdns_core::json;
    let j = json::parse(body).map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
    let name = j
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(name) = name else {
        return Err("`name` 항목을 입력해야 합니다".to_string());
    };
    let arr = |k: &str| -> Vec<String> {
        j.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let boolean = |k: &str| j.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let mut b = String::from("\n[[clients]]\n");
    b.push_str(&format!("name = {}\n", toml_quote(name)));
    for (k, json_k) in [
        ("ids", "ids"),
        ("client_ids", "client_ids"),
        ("mac", "mac"),
        ("tags", "tags"),
        ("block", "block"),
        ("allow", "allow"),
        ("blocked_services", "blocked_services"),
    ] {
        let v = arr(json_k);
        if !v.is_empty() {
            b.push_str(&format!("{k} = {}\n", toml_string_array(&v)));
        }
    }
    if boolean("disable_filtering") {
        b.push_str("disable_filtering = true\n");
    }
    if boolean("safe_search") {
        b.push_str("safe_search = true\n");
    }
    Ok((b, name.to_string()))
}

/** @brief 설정 텍스트에서 이 클라이언트 구간을 뺀다. */
fn remove_client_block(text: &str, name: &str) -> Option<String> {
    let entries = onetdns_config::toml::top_entries(text).ok()?;
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for block in toml_blocks(&entries) {
        if !(block.is_array && block.root == "clients") {
            continue;
        }
        let name_matches = entries.iter().any(|entry| {
            matches!(entry, TomlEntry::Assign { key, table: Some(header), value, .. }
                if key == "name" && *header == block.header_idx && value.as_str() == Some(name))
        });
        if name_matches {
            edits.push((block.start, block.end, String::new()));
        }
    }
    if edits.is_empty() {
        return None;
    }
    Some(splice_config_edits(text, edits))
}

/** @brief 이미 갱신 중이라는 문구. */
const LIST_REFRESH_BUSY: &str = "블록리스트 갱신 작업이 이미 실행 중";

/** @brief 목록 갱신을 한 번에 하나만 돌게 한다. */
fn try_list_refresh_lock(lock: &Mutex<()>) -> Result<std::sync::MutexGuard<'_, ()>, String> {
    match lock.try_lock() {
        Ok(guard) => Ok(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Ok(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => Err(LIST_REFRESH_BUSY.to_string()),
    }
}

/** @brief 내장 목록 주소가 어느 설정에서 왔는지. 화면이 켜고 끄는 곳을 안내할 때 쓴다. */
fn preset_list_kind(url: &str) -> &'static str {
    if onetdns_filter::presets::PARENTAL_LISTS.contains(&url) {
        "parental_control"
    } else {
        "safe_browsing"
    }
}

/** @brief 지금 쓰는 목록 주소들. 겹치지 않게 순서를 지켜 모은다. */
fn active_subscription_urls(
    urls: &[String],
    disabled: &[String],
    presets: &[String],
) -> Vec<String> {
    let mut active: Vec<String> = urls
        .iter()
        .filter(|url| !disabled.iter().any(|blocked| blocked == *url))
        .cloned()
        .collect();
    for preset in presets {
        active.push(preset.clone());
    }
    let mut seen = std::collections::HashSet::new();
    active.retain(|url| seen.insert(url.clone()));
    active
}

/** @brief 목록 구독 상태를 설정에 적는다. */
fn persist_subscription_state(
    path: Option<&std::path::Path>,
    urls: &[String],
    titles: &[String],
    disabled: &[String],
) -> Result<(), String> {
    let Some(p) = path else {
        return Err("설정 파일 경로가 없습니다".to_string());
    };
    let text =
        onetdns_core::SecretString::from(Config::read_text(p).map_err(|error| error.to_string())?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "blocklist_urls",
        &toml_string_array(urls),
    )?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "blocklist_titles",
        &toml_string_array(titles),
    )?);
    let text = onetdns_core::SecretString::from(rewrite_config_kv(
        &text,
        "disabled_blocklist_urls",
        &toml_string_array(disabled),
    )?);
    atomic_write(p, text.as_bytes()).map_err(|e| e.to_string())
}

/** @brief 클라이언트 설정을 설정 텍스트로. */
fn client_to_toml(client: &onetdns_config::ClientConfig) -> String {
    let mut out = String::from("\n[[clients]]\n");
    out.push_str(&format!("name = {}\n", toml_quote(&client.name)));
    let ids: Vec<String> = client.ids.iter().map(ToString::to_string).collect();
    for (key, values) in [
        ("ids", ids),
        ("client_ids", client.client_ids.clone()),
        ("mac", client.mac.clone()),
        ("tags", client.tags.clone()),
        ("block", client.block.clone()),
        ("allow", client.allow.clone()),
        ("blocked_services", client.blocked_services.clone()),
        ("upstreams", client.upstreams.clone()),
    ] {
        if !values.is_empty() {
            out.push_str(&format!("{key} = {}\n", toml_string_array(&values)));
        }
    }
    if client.disable_filtering {
        out.push_str("disable_filtering = true\n");
    }
    if let Some(value) = client.safe_search {
        out.push_str(&format!("safe_search = {value}\n"));
    }
    if client.ignore_querylog {
        out.push_str("ignore_querylog = true\n");
    }
    if client.ignore_stats {
        out.push_str("ignore_stats = true\n");
    }
    out
}

/** @brief 이 클라이언트를 켜거나 끈다. */
fn update_client_disable(text: &str, name: &str, disable: bool) -> Result<String, String> {
    let cfg = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
    let mut client = cfg
        .clients
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| format!("클라이언트를 찾을 수 없습니다: {name}"))?;
    client.disable_filtering = disable;
    let mut updated = remove_client_block(text, name)
        .ok_or_else(|| format!("클라이언트를 찾을 수 없습니다: {name}"))?;
    updated.push_str(&client_to_toml(&client));
    Ok(updated)
}

/** @brief 이 사용자의 암호 해시를 바꾼다. */
/**
 * @brief 이 설정이 DNS 영역을 응답에 쓰는지.
 *
 * @details 영역 원본이 하나도 없으면 권한 계층을 체인에 얹지 않는다. 제어 API로 영역을
 *          넣어도 그 영역은 응답에 쓰이지 않으므로, 이 판정은 계층을 얹는 곳과 그
 *          사실을 알려 주는 곳이 같은 것을 봐야 한다.
 */
fn authority_sources_configured(cfg: &Config) -> bool {
    !cfg.zones.is_empty()
        || cfg.zones_dir.is_some()
        || !cfg.secondary.is_empty()
        || !cfg.catalog.is_empty()
        || cfg.zones_db.is_some()
        || cfg.zones_etcd.is_some()
        || cfg.zones_postgres.is_some()
        || cfg.zones_mysql.is_some()
        || cfg.zones_lmdb.is_some()
}

/** @brief 첫 관리자 계정을 설정 텍스트 끝에 덧붙인다.
 *
 * @details 테이블 배열 항목은 글 끝에 붙여야 안전하다. 중간에 끼우면 뒤따르는 키들이 이
 *          테이블에 속하게 되어 다른 설정이 전부 옮겨 간다.
 * @return 이미 users 항목이 있으면 실패한다. 첫 계정 만들기 외의 용도로는 쓰지 않는다.
 */
fn append_user_block(text: &str, name: &str, hash: &str) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    if toml_blocks(&entries)
        .iter()
        .any(|block| block.is_array && block.root == "users")
    {
        return Err("이미 사용자 계정이 있습니다".to_string());
    }
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str("[[users]]\n");
    out.push_str(&format!("name = {}\n", toml_quote(name)));
    out.push_str(&format!("password_hash = {}\n", toml_quote(hash)));
    out.push_str("role = \"admin\"\n");
    Ok(out)
}

fn rewrite_user_password_hash(text: &str, name: &str, hash: &str) -> Result<String, String> {
    let entries = onetdns_config::toml::top_entries(text)?;
    let line = format!("password_hash = {}\n", toml_quote(hash));
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut found = false;
    for block in toml_blocks(&entries) {
        if !(block.is_array && block.root == "users") {
            continue;
        }
        let members = || {
            entries.iter().filter_map(|entry| match entry {
                TomlEntry::Assign {
                    key,
                    table: Some(header),
                    start,
                    end,
                    value,
                } if *header == block.header_idx => Some((key, *start, *end, value)),
                _ => None,
            })
        };
        if !members().any(|(key, _, _, value)| key == "name" && value.as_str() == Some(name)) {
            continue;
        }
        found = true;
        let mut wrote = false;
        for (key, start, end, _) in members() {
            if key == "password_hash" {
                edits.push((start, end, line.clone()));
                wrote = true;
            } else if key == "password" {
                edits.push((start, end, String::new()));
            }
        }
        if !wrote {
            edits.push((block.end, block.end, line.clone()));
        }
    }
    if !found {
        return Err(format!("사용자를 찾을 수 없습니다: {name}"));
    }
    Ok(splice_config_edits(text, edits))
}

/** @brief 문자열 목록을 설정 텍스트의 배열로. */
fn toml_string_array<T: AsRef<str>>(values: &[T]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| toml_quote(value.as_ref()))
        .collect();
    format!("[{}]", items.join(", "))
}

/** @brief 현재 Unix 초. */
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/** @brief 설정한 공유 키들을 만든다. */
fn build_tsig_keys(cfg: &Config) -> Result<Vec<onetdns_dnssec::tsig::TsigKey>, String> {
    let mut keys = Vec::new();
    for k in &cfg.tsig_keys {
        let key = onetdns_dnssec::tsig::TsigKey::from_base64(&k.name, k.secret.as_str())
            .ok_or_else(|| {
                format!(
                    "TSIG 키 '{}'의 이름 또는 Base64 비밀값 형식이 잘못되었습니다",
                    k.name
                )
            })?;
        keys.push(key);
    }
    Ok(keys)
}

/** @brief 이 하위 서버에 쓸 키. */
fn tsig_for_secondary<'a>(
    keys: &'a [onetdns_dnssec::tsig::TsigKey],
    name: &Option<String>,
) -> Option<&'a onetdns_dnssec::tsig::TsigKey> {
    let want = name.as_ref()?;
    let n = onetdns_proto::Name::from_str(want.trim()).ok()?;
    keys.iter().find(|k| k.name.eq_ignore_case(&n))
}

#[derive(Clone)]
/** @brief 알림을 보낼 곳 하나. */
struct NotifyRuntimeTarget {
    /** @brief 알림을 보낼 주소. */
    address: std::net::SocketAddr,
    /** @brief 알림에 쓸 공유 키. */
    tsig_key: Option<onetdns_dnssec::tsig::TsigKey>,
}

#[derive(Clone, Copy)]
/** @brief 답이 없을 때 다시 보내는 규칙. */
struct NotifyRetryPolicy {
    /** @brief 처음 다시 보내기까지 기다릴 시간. */
    initial: Duration,
    /** @brief 다시 보낼 횟수. */
    retransmissions: u8,
}

impl Default for NotifyRetryPolicy {
    /** @brief 기본 규칙. */
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            retransmissions: 5,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
/** @brief 알림 하나를 가리키는 키. */
struct NotifyJobKey {
    /** @brief 알릴 영역. */
    origin: Vec<u8>,
    /** @brief 알릴 대상. */
    target: usize,
}

/** @brief 보낼 알림 하나. */
struct NotifyJob {
    /** @brief 알릴 영역 이름. */
    origin: onetdns_proto::Name,
    /** @brief 알릴 시리얼. */
    serial: u32,
}

#[derive(Default)]
/** @brief 보낼 알림들. */
struct NotifyQueue {
    /** @brief 아직 보내지 못한 알림들. */
    pending: Mutex<std::collections::HashMap<NotifyJobKey, NotifyJob>>,
    /** @brief 보내는 쪽을 깨우는 곳. */
    wake: std::sync::Condvar,
}

#[derive(Clone)]
/** @brief 알림을 맡기는 곳. */
struct NotifySender {
    /** @brief 보낼 알림을 넣을 곳. 없으면 알리지 않는다. */
    queue: Option<Arc<NotifyQueue>>,
    /** @brief 알림을 보낼 곳들. 설정이 바뀌면 교체한다. */
    targets: Arc<onetdns_core::ArcSwap<Vec<NotifyRuntimeTarget>>>,
}

impl NotifySender {
    #[cfg(test)]
    /** @brief 알리지 않는 곳. 테스트에서만 쓴다. */
    fn disabled() -> Self {
        Self {
            queue: None,
            targets: Arc::new(onetdns_core::ArcSwap::new(Arc::new(Vec::new()))),
        }
    }

    /**
     * @brief 알림을 보낼 곳 목록을 교체한다.
     *
     * @details 설정에 적힌 대상과 그 TSIG 키를 다시 풀어 넣는다. 키를 찾지 못하면 아무것도
     *          바꾸지 않는다. 절반만 교체하면 서명 없이 알리게 된다.
     * @return 대상의 TSIG 키가 설정에 없으면 실패.
     */
    fn replace_targets(
        &self,
        configured: &[onetdns_config::NotifyTarget],
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    ) -> Result<(), String> {
        let next = notify_runtime_targets(configured, tsig_keys)?;
        self.targets.store(Arc::new(next));
        Ok(())
    }

    /** @brief 이 영역이 바뀌었다고 알릴 것을 맡긴다. 같은 영역의 알림은 하나로 합친다. */
    fn enqueue(&self, origin: &onetdns_proto::Name, serial: u32) {
        let Some(queue) = &self.queue else {
            return;
        };
        let origin_key = origin.canonical_key();
        let mut pending = queue.pending.lock_recover();
        for target in 0..self.targets.load().len() {
            pending.insert(
                NotifyJobKey {
                    origin: origin_key.clone(),
                    target,
                },
                NotifyJob {
                    origin: origin.clone(),
                    serial,
                },
            );
        }
        drop(pending);
        queue.wake.notify_one();
    }

    /** @brief 이 영역의 지금 판으로 알린다. */
    fn enqueue_zone(&self, zone: &onetdns_authority::Zone) {
        self.enqueue(zone.origin(), zone.soa().serial);
    }

    #[cfg(test)]
    /** @brief 보내는 쪽을 깨운다. */
    fn wake(&self) {
        if let Some(queue) = &self.queue {
            queue.wake.notify_one();
        }
    }
}

/** @brief 답을 기다리는 알림 하나. */
struct OutstandingNotify {
    /** @brief 알린 영역. */
    origin: onetdns_proto::Name,
    /** @brief 알린 시리얼. */
    serial: u32,
    /** @brief 이 서버가 보낸 질의 번호. */
    id: u16,
    /** @brief 보낸 바이트. 다시 보낼 때 그대로 쓴다. */
    wire: Vec<u8>,
    /** @brief 요청에 붙인 서명. */
    request_mac: Option<Vec<u8>>,
    /** @brief 지금까지 보낸 횟수. */
    transmissions: u8,
    /** @brief 다음에 보낼 시각. */
    next_send: std::time::Instant,
}

/** @brief 알림을 모으는 시간. 변경이 잇달아 오면 한 번만 보내려는 것이다. */
const NOTIFY_COALESCE_DELAY: Duration = Duration::from_millis(20);

/** @brief 알림 패킷 바이트. */
fn notify_wire(
    origin: &onetdns_proto::Name,
    id: u16,
    target: &NotifyRuntimeTarget,
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};
    let mut message = Message::default();
    message.header.id = id;
    message.header.opcode = 4;
    message.header.authoritative = true;
    message.questions.push(Question {
        name: origin.clone(),
        qtype: RecordType::SOA,
        qclass: DnsClass::IN,
    });
    let request_mac = target
        .tsig_key
        .as_ref()
        .map(|key| {
            onetdns_dnssec::tsig::sign_message(&mut message, key, unix_now(), None)
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    message
        .try_encode()
        .map(|wire| (wire, request_mac))
        .map_err(|error| error.to_string())
}

/** @brief 답을 기다리는 알림을 만든다. */
fn outstanding_notify(
    origin: onetdns_proto::Name,
    serial: u32,
    target: &NotifyRuntimeTarget,
    delay: Duration,
) -> Result<OutstandingNotify, String> {
    let id = u16::from_ne_bytes(onetdns_core::random_array());
    let (wire, request_mac) = notify_wire(&origin, id, target)?;
    Ok(OutstandingNotify {
        origin,
        serial,
        id,
        wire,
        request_mac,
        transmissions: 0,
        next_send: std::time::Instant::now() + delay,
    })
}

/** @brief 이 답이 이 서버가 보낸 알림에 대한 것인지. 확인하지 않으면 아무 패킷이나 답으로 세어 다시 보내기를 멈춘다. */
fn valid_notify_ack(
    wire: &[u8],
    source: std::net::SocketAddr,
    key: &NotifyJobKey,
    outstanding: &OutstandingNotify,
    targets: &[NotifyRuntimeTarget],
) -> bool {
    use onetdns_proto::{DnsClass, Message, RecordType};
    let Some(target) = targets.get(key.target) else {
        return false;
    };
    if source != target.address {
        return false;
    }
    let message = if let Some(tsig_key) = &target.tsig_key {
        let Some(request_mac) = outstanding.request_mac.as_deref() else {
            return false;
        };
        let Ok((stripped, _)) =
            onetdns_dnssec::tsig::verify_wire(wire, tsig_key, unix_now(), Some(request_mac))
        else {
            return false;
        };
        let Ok(message) = Message::parse(&stripped) else {
            return false;
        };
        message
    } else {
        let Ok(message) = Message::parse(wire) else {
            return false;
        };
        message
    };
    message.header.response
        && message.header.authoritative
        && message.header.id == outstanding.id
        && message.header.opcode == 4
        && message.questions.len() == 1
        && message.questions[0]
            .name
            .eq_ignore_case(&outstanding.origin)
        && message.questions[0].qtype == RecordType::SOA
        && message.questions[0].qclass == DnsClass::IN
}

/** @brief 온 답들을 거둔다. */
fn receive_notify_acks(
    socket: &std::net::UdpSocket,
    active: &mut std::collections::HashMap<NotifyJobKey, OutstandingNotify>,
    targets: &[NotifyRuntimeTarget],
) {
    let mut wire = [0u8; 65_535];
    loop {
        let (length, source) = match socket.recv_from(&mut wire) {
            Ok(received) => received,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => {
                onetdns_core::warn!(event = "authority.notify_receive_failed", %error, "DNS NOTIFY ACK를 받지 못했습니다");
                break;
            }
        };
        let matched = active.iter().find_map(|(job_key, outstanding)| {
            valid_notify_ack(&wire[..length], source, job_key, outstanding, targets)
                .then(|| job_key.clone())
        });
        if let Some(job_key) = matched {
            if let Some(done) = active.remove(&job_key) {
                let target = targets[job_key.target].address;
                onetdns_core::info!(event = "authority.notify_acknowledged", zone = %done.origin.to_ascii_lower(), serial = done.serial, %target, transmissions = done.transmissions, "DNS NOTIFY ACK를 확인했습니다");
            }
        }
    }
}

/** @brief 다시 보내기까지 기다릴 시간. */
fn retry_delay(policy: NotifyRetryPolicy, transmissions: u8) -> Duration {
    let shift = u32::from(transmissions.saturating_sub(1).min(20));
    policy
        .initial
        .checked_mul(1u32 << shift)
        .unwrap_or(Duration::MAX)
}

/** @brief 알림을 보내고 답을 기다리는 스레드를 시작한다. */
fn spawn_notify_worker(
    targets: Vec<NotifyRuntimeTarget>,
    policy: NotifyRetryPolicy,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(NotifySender, std::thread::JoinHandle<()>)> {
    // 두 계열 소켓을 모두 연다. 대상 목록을 교체할 수 있으므로 지금 목록에 없는 계열도
    // 나중에 들어올 수 있다.
    let socket4 = {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        Some(socket)
    };
    let socket6 = match std::net::UdpSocket::bind("[::]:0") {
        Ok(socket) => {
            socket.set_nonblocking(true)?;
            Some(socket)
        }
        Err(error) => {
            onetdns_core::warn!(event = "authority.notify_ipv6_unavailable", %error, "IPv6 NOTIFY 소켓을 열지 못했습니다. IPv6 대상에는 알리지 못합니다");
            None
        }
    };
    let queue = Arc::new(NotifyQueue::default());
    let targets = Arc::new(onetdns_core::ArcSwap::new(Arc::new(targets)));
    let sender = NotifySender {
        queue: Some(queue.clone()),
        targets: targets.clone(),
    };
    let thread = std::thread::Builder::new()
        .name("dns-notify".into())
        .spawn(move || {
            use std::sync::atomic::Ordering;
            let mut active = std::collections::HashMap::<
                NotifyJobKey,
                OutstandingNotify,
            >::new();
            while !shutdown.load(Ordering::Relaxed) {
                // 한 바퀴 동안은 같은 목록을 본다. 도중에 갈리면 인덱스가 어긋난다.
                let targets = targets.load();
                let pending = std::mem::take(&mut *queue.pending.lock_recover());
                for (job_key, job) in pending {
                    let Some(target) = targets.get(job_key.target) else {
                        continue;
                    };
                    if let Some(outstanding) = active.get_mut(&job_key) {
                        if outstanding.transmissions == 0 {
                            outstanding.serial = job.serial;
                            continue;
                        }
                    }
                    match outstanding_notify(
                        job.origin,
                        job.serial,
                        target,
                        NOTIFY_COALESCE_DELAY,
                    ) {
                        Ok(outstanding) => {
                            active.insert(job_key, outstanding);
                        }
                        Err(error) => onetdns_core::error!(event = "authority.notify_encode_failed", serial = job.serial, %error, "DNS NOTIFY를 인코딩하지 못했습니다"),
                    }
                }

                let now = std::time::Instant::now();
                let mut timed_out = Vec::new();
                for (job_key, outstanding) in &mut active {
                    if now < outstanding.next_send {
                        continue;
                    }
                    if outstanding.transmissions > policy.retransmissions {
                        timed_out.push(job_key.clone());
                        continue;
                    }
                    let target = &targets[job_key.target];
                    let socket = if target.address.is_ipv4() {
                        socket4.as_ref()
                    } else {
                        socket6.as_ref()
                    };
                    let Some(socket) = socket else {
                        timed_out.push(job_key.clone());
                        continue;
                    };
                    match socket.send_to(&outstanding.wire, target.address) {
                        Ok(length) if length == outstanding.wire.len() => {
                            outstanding.transmissions += 1;
                            outstanding.next_send =
                                now + retry_delay(policy, outstanding.transmissions);
                            onetdns_core::info!(event = "authority.notify_sent", zone = %outstanding.origin.to_ascii_lower(), serial = outstanding.serial, target = %target.address, transmission = outstanding.transmissions, "DNS NOTIFY를 전송했습니다");
                        }
                        Ok(_) => {
                            outstanding.next_send = now + Duration::from_millis(10);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            outstanding.next_send = now + Duration::from_millis(10);
                        }
                        Err(error) => {
                            outstanding.transmissions += 1;
                            outstanding.next_send =
                                now + retry_delay(policy, outstanding.transmissions);
                            onetdns_core::warn!(event = "authority.notify_send_failed", zone = %outstanding.origin.to_ascii_lower(), target = %target.address, transmission = outstanding.transmissions, %error, "DNS NOTIFY 전송에 실패했습니다");
                        }
                    }
                }
                for job_key in timed_out {
                    if let Some(expired) = active.remove(&job_key) {
                        onetdns_core::warn!(event = "authority.notify_timeout", zone = %expired.origin.to_ascii_lower(), serial = expired.serial, target = %targets[job_key.target].address, transmissions = expired.transmissions, "DNS NOTIFY가 ACK 없이 만료됐습니다");
                    }
                }
                if let Some(socket) = &socket4 {
                    receive_notify_acks(socket, &mut active, &targets);
                }
                if let Some(socket) = &socket6 {
                    receive_notify_acks(socket, &mut active, &targets);
                }

                let wait = if active.is_empty() {
                    Duration::from_millis(100)
                } else {
                    let until_retry = active
                        .values()
                        .map(|job| job.next_send.saturating_duration_since(std::time::Instant::now()))
                        .min()
                        .unwrap_or(Duration::from_millis(10));
                    until_retry.min(Duration::from_millis(10))
                };
                let pending = queue.pending.lock_recover();
                if pending.is_empty() && !shutdown.load(Ordering::Relaxed) {
                    drop(match queue.wake.wait_timeout(pending, wait) {
                        Ok((pending, _)) => pending,
                        Err(error) => error.into_inner().0,
                    });
                }
            }
        })?;
    Ok((sender, thread))
}

/** @brief 알림 보내기를 시작한다. */
fn start_notify_dispatcher(
    configured: &[onetdns_config::NotifyTarget],
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<(NotifySender, Option<std::thread::JoinHandle<()>>)> {
    let targets = notify_runtime_targets(configured, tsig_keys)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let (sender, thread) = spawn_notify_worker(targets, NotifyRetryPolicy::default(), shutdown)?;
    Ok((sender, Some(thread)))
}

/** @brief 설정에 적힌 알림 대상을 실행에 쓸 모양으로 푼다. */
fn notify_runtime_targets(
    configured: &[onetdns_config::NotifyTarget],
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
) -> Result<Vec<NotifyRuntimeTarget>, String> {
    configured
        .iter()
        .map(|target| {
            let tsig_key = match &target.tsig_key {
                Some(name) => Some(
                    tsig_for_secondary(tsig_keys, &Some(name.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "NOTIFY 대상 '{}'의 TSIG 키 '{}'를 찾을 수 없습니다",
                                target.address, name
                            )
                        })?,
                ),
                None => None,
            };
            Ok(NotifyRuntimeTarget {
                address: target.address,
                tsig_key,
            })
        })
        .collect()
}

/** @brief 설정대로 정책 엔진을 만든다. */
fn build_policy_engine(cfg: &Config) -> Result<onetdns_policy::PolicyEngine, String> {
    use onetdns_policy::{Action, Rule, RuleEngine, WasmPolicy};
    let mut rules = Vec::new();
    for (index, p) in cfg.policy.iter().enumerate() {
        let action = match p.action.as_str() {
            "block" => Action::Block,
            "allow" => Action::Allow,
            "refuse" => Action::Refuse,
            "rewrite" => match p.rewrite.as_ref().and_then(|s| s.parse().ok()) {
                Some(ip) => Action::Rewrite(ip),
                None => {
                    return Err(format!(
                        "policy[{index}].rewrite에는 올바른 IPv4 주소가 필요합니다"
                    ));
                }
            },
            other => {
                return Err(format!(
                    "policy[{index}].action에 허용되지 않은 값이 있습니다: '{other}'"
                ));
            }
        };
        let mut rule = Rule::new(action)
            .with_clients(&p.clients)
            .with_suffixes(&p.suffixes)
            .with_qtypes(&qtype_numbers(&p.qtypes));
        if !p.days.is_empty() || p.start.is_some() || p.end.is_some() {
            let window = parse_time_window(&p.days, &p.start, &p.end).ok_or_else(|| {
                format!("policy[{index}]의 요일 또는 시간 범위가 올바르지 않습니다")
            })?;
            rule = rule.with_window(window);
        }
        rules.push(rule);
    }

    let mut plugins = Vec::new();
    let global_mode = onetdns_policy::FailureMode::parse(&cfg.wasm_fail_mode)
        .map_err(|error| error.to_string())?;
    let mut specs: Vec<(
        std::path::PathBuf,
        Option<String>,
        onetdns_policy::FailureMode,
    )> = cfg
        .wasm_policy
        .iter()
        .map(|p| (p.clone(), None, global_mode))
        .collect();
    for plugin in &cfg.wasm_plugins {
        let mode = match &plugin.fail_mode {
            Some(mode) => onetdns_policy::FailureMode::parse(mode).map_err(|e| e.to_string())?,
            None => global_mode,
        };
        specs.push((plugin.path.clone(), plugin.name.clone(), mode));
    }
    for (path, name, fail_mode) in specs {
        match read_bytes_limited(&path, WASM_MODULE_MAX_BYTES) {
            Ok(bytes) => match WasmPolicy::from_wasm(&bytes) {
                Ok(w) => {
                    let name = name.unwrap_or_else(|| {
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("wasm")
                            .to_string()
                    });
                    onetdns_core::info!(event = "policy.wasm_loaded", path = %path.display(), fail_mode = ?fail_mode, "WASM 정책 플러그인을 불러왔습니다");
                    plugins.push(w.with_name(name).with_failure_mode(fail_mode));
                }
                Err(e) => {
                    let error = format!("WASM 정책을 준비하지 못했습니다({}): {e}", path.display());
                    if fail_mode != onetdns_policy::FailureMode::Open {
                        return Err(error);
                    }
                    onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM 정책을 적용하지 않았습니다")
                }
            },
            Err(e) => {
                let error = format!("WASM 정책 파일을 읽지 못했습니다({}): {e}", path.display());
                if fail_mode != onetdns_policy::FailureMode::Open {
                    return Err(error);
                }
                onetdns_core::error!(event = "policy.wasm_skipped", error = %error, "WASM 정책을 적용하지 않았습니다")
            }
        }
    }
    Ok(onetdns_policy::PolicyEngine::new(
        RuleEngine::new(rules),
        plugins,
    ))
}

/** @brief 대시보드가 쓰는 항목 식별자. 목록 순서가 바뀌어도 그대로다. */
fn stable_resource_id(namespace: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(namespace.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{namespace}-{short}")
}

/** @brief 로그에 원문을 담지 않으면서 프로세스 안에서 비밀 자원을 구분하는 식별자. */
fn private_resource_id(namespace: &str, value: &str) -> String {
    /** @brief 사전 대입으로 약한 비밀번호를 지문과 대조하지 못하게 하는 프로세스 키. */
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let mut digest = Sha256::new();
    digest.update(KEY.get_or_init(onetdns_core::random_array::<32>));
    digest.update((namespace.len() as u64).to_le_bytes());
    digest.update(namespace.as_bytes());
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
    let digest = digest.finalize();
    let short = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{namespace}-{short}")
}

/** @brief 적용 중인 설정을 한 번에 하나씩만 고치게 한다. */
fn runtime_config_update_lock() -> &'static Mutex<()> {
    /** @brief 적용 중인 설정 잠금. */
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/** @brief 적용 중인 설정을 고친다. 잠금 안에서 읽고 고쳐야 동시에 온 다른 변경이 사라지지 않는다. */
fn update_runtime_config(runtime: &Arc<ArcSwap<Config>>, update: impl FnOnce(&mut Config)) {
    use onetdns_core::MutexExt;
    let _guard = runtime_config_update_lock().lock_recover();
    let mut config = (*runtime.load()).clone();
    update(&mut config);
    runtime.store(Arc::new(config));
}

/** @brief 설정의 지문. */
fn config_fingerprint(config: &Config) -> [u8; 32] {
    /** @brief 프로세스 밖에서 비밀값 후보를 지문과 대조하지 못하게 하는 키. */
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let debug = Zeroizing::new(format!("{config:?}"));
    let mut digest = Sha256::new();
    digest.update(KEY.get_or_init(onetdns_core::random_array::<32>));
    digest.update((debug.len() as u64).to_le_bytes());
    digest.update(debug.as_bytes());

    // SecretString의 Debug는 반드시 가려져야 한다. 그렇다고 값 변화까지 숨기면 핫 리로드가
    // 비밀번호·토큰 교체를 놓치므로, 외부로 내보내지 않는 키드 지문에만 원문을 넣는다.
    let mut secret = |label: &str, value: &str| {
        digest.update((label.len() as u64).to_le_bytes());
        digest.update(label.as_bytes());
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    };
    secret("control_token", config.control_token.as_str());
    for value in &config.control_admin_tokens {
        secret("control_admin_token", value.as_str());
    }
    for value in &config.control_readonly_tokens {
        secret("control_readonly_token", value.as_str());
    }
    for user in &config.users {
        secret("user_password_hash", user.password_hash.as_str());
    }
    if let Some(value) = &config.zones_etcd_password {
        secret("zones_etcd_password", value.as_str());
    }
    if let Some(value) = &config.zones_postgres {
        secret("zones_postgres", value.as_str());
    }
    if let Some(value) = &config.zones_mysql {
        secret("zones_mysql", value.as_str());
    }
    for key in &config.tsig_keys {
        secret("tsig_secret", key.secret.as_str());
    }
    secret("cluster_raft_secret", config.cluster_raft_secret.as_str());
    secret(
        "cluster_raft_node_key",
        config.cluster_raft_node_key.as_str(),
    );
    digest.finalize().into()
}

/** @brief 비교 전에 기본값으로 채워진 것을 맞춘다. 안 맞추면 바뀌지 않은 것이 바뀐 것으로 보인다. */
fn normalize_config_for_comparison(runtime: &Config, desired: &Config) -> Config {
    let mut normalized = desired.clone();
    let dashboard_default = SocketAddr::from(([127, 0, 0, 1], 8553));
    if normalized.control_listen.is_none() && runtime.control_listen == Some(dashboard_default) {
        normalized.control_listen = Some(dashboard_default);
    }
    normalized
}

/**
 * @brief 두 설정에서 달라진 항목들.
 * @details 요약에 값이 드러나지 않는 항목은 지문을 비교해 찾는다. 요약에 드러난 항목이 같은
 *          요청에서 함께 바뀌었어도 이 탐색은 한다. 건너뛰면 토큰 교체나 일정 삭제가 적용
 *          목록에서 빠져 이전 값이 계속 쓰인다.
 * @note 요약에 드러난 항목이 바뀌었으면, 이름 붙일 수 없는 나머지 차이는 가려낼 수 없다.
 */
fn config_changed_keys(runtime: &Config, desired: &Config) -> Result<Vec<String>, String> {
    use onetdns_core::json::Json;
    let applied = onetdns_core::json::parse(&runtime.effective_json())
        .map_err(|error| format!("현재 실행 설정을 비교할 수 없습니다: {error}"))?;
    let wanted = onetdns_core::json::parse(&desired.effective_json())
        .map_err(|error| format!("파일에 저장된 설정을 비교할 수 없습니다: {error}"))?;
    let (Json::Obj(applied), Json::Obj(wanted)) = (applied, wanted) else {
        return Err("설정 비교 데이터가 JSON 객체가 아닙니다".to_string());
    };
    /** @brief 이 항목의 값. */
    fn lookup<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }
    let mut changed = Vec::new();
    for (key, value) in &wanted {
        if lookup(&applied, key) != Some(value) {
            changed.push(key.clone());
        }
    }
    for (key, _) in &applied {
        if lookup(&wanted, key).is_none() {
            changed.push(key.clone());
        }
    }

    let summary_changed = !changed.is_empty();
    if config_fingerprint(runtime) != config_fingerprint(desired) {
        // 요약에 개수만 담기거나 아예 빠지는 항목들이 있다. 개수가 같은 채로 값만 달라지면
        // 위 비교로는 드러나지 않는다. 그렇다고 뭉뚱그리면 무중단 대상인 줄 모르고 다시
        // 시작한다. 항목 하나씩 실행 중 값으로 되돌려 보고, 지문이 그대로면 그 항목이 범인이다.
        /** @brief 이 항목만 실행 중 값으로 되돌린다. */
        type Restore = fn(&mut Config, &Config);
        let opaque: &[(&str, Restore)] = &[
            ("users", |probe, live| probe.users = live.users.clone()),
            ("clients", |probe, live| {
                probe.clients = live.clients.clone()
            }),
            ("views", |probe, live| probe.views = live.views.clone()),
            ("policy", |probe, live| probe.policy = live.policy.clone()),
            ("rewrites", |probe, live| {
                probe.rewrites = live.rewrites.clone()
            }),
            ("local_zones", |probe, live| {
                probe.local_zones = live.local_zones.clone()
            }),
            ("local_a", |probe, live| {
                probe.local_a = live.local_a.clone()
            }),
            ("local_aaaa", |probe, live| {
                probe.local_aaaa = live.local_aaaa.clone()
            }),
            ("stub_zones", |probe, live| {
                probe.stub_zones = live.stub_zones.clone()
            }),
            ("dynamic_records", |probe, live| {
                probe.dynamic_records = live.dynamic_records.clone()
            }),
            ("update_policy", |probe, live| {
                probe.update_policy = live.update_policy.clone()
            }),
            ("service_schedule", |probe, live| {
                probe.service_schedule = live.service_schedule.clone()
            }),
            ("tsig_keys", |probe, live| {
                probe.tsig_keys = live.tsig_keys.clone()
            }),
            ("control_token", |probe, live| {
                probe.control_token = live.control_token.clone()
            }),
            ("control_admin_tokens", |probe, live| {
                probe.control_admin_tokens = live.control_admin_tokens.clone()
            }),
            ("control_readonly_tokens", |probe, live| {
                probe.control_readonly_tokens = live.control_readonly_tokens.clone()
            }),
            ("zones_etcd_password", |probe, live| {
                probe.zones_etcd_password = live.zones_etcd_password.clone()
            }),
            ("zones_postgres", |probe, live| {
                probe.zones_postgres = live.zones_postgres.clone()
            }),
            ("zones_mysql", |probe, live| {
                probe.zones_mysql = live.zones_mysql.clone()
            }),
            ("cluster_raft_secret", |probe, live| {
                probe.cluster_raft_secret = live.cluster_raft_secret.clone()
            }),
            ("cluster_raft_node_key", |probe, live| {
                probe.cluster_raft_node_key = live.cluster_raft_node_key.clone()
            }),
        ];
        let mut probe = desired.clone();
        for (name, restore) in opaque {
            let before = config_fingerprint(&probe);
            restore(&mut probe, runtime);
            if config_fingerprint(&probe) != before {
                changed.push((*name).to_string());
            }
        }
        // 하나씩 되돌려도 실행 중 설정과 같아지지 않으면 이름을 붙일 수 없다.
        if !summary_changed && config_fingerprint(&probe) != config_fingerprint(runtime) {
            changed.push("structured_or_secret_config".to_string());
        }
    }
    changed.sort();
    changed.dedup();
    Ok(changed)
}

/** @brief 상태 표시에 쓸 달라진 항목들. */
fn config_changed_keys_for_status(
    runtime: &Config,
    desired: &Config,
) -> Result<Vec<String>, String> {
    let normalized = normalize_config_for_comparison(runtime, desired);
    config_changed_keys(runtime, &normalized)
}

/** @brief 파일에 적힌 설정을 JSON으로. */
fn desired_config_json(path: Option<&std::path::Path>, runtime: &Config) -> String {
    let Some(path) = path else {
        return runtime.effective_json();
    };
    let text = match Config::read_text(path) {
        Ok(text) => onetdns_core::SecretString::from(text),
        Err(error) => {
            return format!(
                "{{\"_valid\":false,\"_source\":\"disk\",\"_error\":{}}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    match Config::from_toml_str(&text) {
        Ok(config) => config.effective_json(),
        Err(error) => format!(
            "{{\"_valid\":false,\"_source\":\"disk\",\"_error\":{}}}",
            onetdns_core::json::escape(&error.to_string())
        ),
    }
}

/** @brief 파일과 지금 적용 중인 설정이 어긋나는지 JSON으로. */
fn config_status_json(path: Option<&std::path::Path>, runtime: &Config) -> String {
    let Some(path) = path else {
        return "{\"in_sync\":true,\"source\":\"runtime\",\"changed_keys\":[]}".to_string();
    };
    let text = match Config::read_text(path) {
        Ok(text) => onetdns_core::SecretString::from(text),
        Err(error) => {
            return format!(
                "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    let desired = match Config::from_toml_str(&text) {
        Ok(config) => config,
        Err(error) => {
            return format!(
                "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
                onetdns_core::json::escape(&error.to_string())
            );
        }
    };
    match config_changed_keys_for_status(runtime, &desired) {
        Ok(changed) => {
            let keys: Vec<String> = changed
                .iter()
                .map(|key| onetdns_core::json::escape(key))
                .collect();
            format!(
                "{{\"in_sync\":{},\"source\":\"disk\",\"changed_keys\":[{}]}}",
                changed.is_empty(),
                keys.join(",")
            )
        }
        Err(error) => format!(
            "{{\"in_sync\":false,\"source\":\"disk\",\"error\":{},\"changed_keys\":[]}}",
            onetdns_core::json::escape(&error)
        ),
    }
}

/**
 * @brief 질의 종류 이름들을 번호로.
 *
 * @details 약칭은 RecordType::name 이 내는 것을 모두 받는다. 빠진 약칭은 걸러지고,
 *          호출자는 대개 A 로 되돌리므로 물어본 것과 다른 종류를 답하게 된다.
 *          약칭이 없는 종류는 RFC 3597 의 TYPE 표기로 적는다.
 */
fn qtype_numbers(names: &[String]) -> Vec<u16> {
    names
        .iter()
        .filter_map(|s| {
            let u = s.trim().to_ascii_uppercase();
            match u.as_str() {
                "A" => Some(1),
                "NS" => Some(2),
                "CNAME" => Some(5),
                "SOA" => Some(6),
                "PTR" => Some(12),
                "MX" => Some(15),
                "TXT" => Some(16),
                "AAAA" => Some(28),
                "SRV" => Some(33),
                "NAPTR" => Some(35),
                "DNAME" => Some(39),
                "OPT" => Some(41),
                "DS" => Some(43),
                "RRSIG" => Some(46),
                "NSEC" => Some(47),
                "DNSKEY" => Some(48),
                "NSEC3" => Some(50),
                "CDS" => Some(59),
                "CDNSKEY" => Some(60),
                "SVCB" => Some(64),
                "HTTPS" => Some(65),
                "CAA" => Some(257),
                "ANY" => Some(255),
                _ => u.strip_prefix("TYPE").unwrap_or(&u).parse::<u16>().ok(),
            }
        })
        .collect()
}

/** @brief 시간대 설정을 읽는다. */
fn parse_time_window(
    days: &[String],
    start: &Option<String>,
    end: &Option<String>,
) -> Option<onetdns_policy::TimeWindow> {
    if days.is_empty() && start.is_none() && end.is_none() {
        return None;
    }
    let mut mask = 0u8;
    if days.is_empty() {
        mask = 0x7f;
    } else {
        for d in days {
            let wd = match d.as_str() {
                "sun" => 0,
                "mon" => 1,
                "tue" => 2,
                "wed" => 3,
                "thu" => 4,
                "fri" => 5,
                "sat" => 6,
                _ => return None,
            };
            mask |= 1u8 << wd;
        }
    }
    let to_min = |s: &str| -> Option<u16> {
        let (hour, minute) = s.split_once(':')?;
        let hour = hour.parse::<u16>().ok()?;
        let minute = minute.parse::<u16>().ok()?;
        (hour < 24 && minute < 60).then_some(hour * 60 + minute)
    };
    let (start_min, end_min) = match (start.as_deref(), end.as_deref()) {
        (None, None) => (0, 1440),
        (Some(start), Some(end)) => {
            let start = to_min(start)?;
            let end = to_min(end)?;
            if start == end {
                return None;
            }
            (start, end)
        }
        _ => return None,
    };
    Some(onetdns_policy::TimeWindow {
        days: mask,
        start_min,
        end_min,
    })
}

/**
 * @brief 모은 통계와 질의 기록을 볼 수 있는 곳이 있는지.
 *
 * @details 관리 수신 주소가 있으면 대시보드와 REST가, 저장 파일이 있으면 그 파일이 본다.
 *          셋 다 없으면 질의마다 만드는 이벤트는 만들어지자마자 버려진다.
 * @return 볼 곳이 하나라도 있으면 참.
 */
fn telemetry_consumed(cfg: &Config) -> bool {
    let has_file = |path: &Option<PathBuf>| {
        path.as_ref()
            .is_some_and(|path| !path.as_os_str().is_empty())
    };
    cfg.control_listen.is_some() || has_file(&cfg.stats_file) || has_file(&cfg.querylog_file)
}

/** @brief 설정에서 DNS Cookie 정책과 서버 비밀을 만든다. */
fn build_cookie_policy(cfg: &Config) -> native::CookiePolicy {
    if !cfg.cookies.is_enabled() {
        return native::CookiePolicy::default();
    }

    let keeper = if cfg.cluster_raft && cfg.cluster_raft_secret.len() >= 32 {
        // Raft 인증과 쿠키가 같은 원시 키를 직접 공유하지 않도록 문맥을 붙여 별도 루트를
        // 만든다. 같은 클러스터 비밀을 가진 노드는 같은 루트와 epoch 키를 얻게 된다.
        let mut digest = Sha256::new();
        digest.update(b"OnetDNS DNS Cookie cluster master v1\0");
        digest.update(cfg.cluster_raft_secret.as_bytes());
        let digest = Zeroizing::new(<[u8; 32]>::from(digest.finalize()));
        let mut master = Zeroizing::new([0u8; 16]);
        master.copy_from_slice(&digest[..16]);
        CookieKeeper::from_master_secret(&master)
    } else {
        CookieKeeper::random()
    };

    native::CookiePolicy {
        keeper: Some(Arc::new(keeper)),
        strict: cfg.cookies.is_strict(),
    }
}

/** @brief 설정대로 기능 세트를 만든다. */
fn build_native_features(
    cfg: &Config,
    dns64_prefix: Option<[u8; 16]>,
    safe_search: Arc<std::sync::atomic::AtomicBool>,
    recorder: Option<onetdns_control::Recorder>,
    mac_cache: Option<Arc<mac::NeighborCache>>,
) -> Result<native::NativeFeatures, String> {
    let cookies = build_cookie_policy(cfg);
    Ok(native::NativeFeatures {
        block_aaaa: cfg.block_aaaa,
        dns64_prefix,
        dns64_synthall: cfg.dns64_synthall,
        rebind_protection: cfg.rebind_protection,
        rebind_allow: cfg
            .rebind_allow
            .iter()
            .filter_map(|s| {
                onetdns_proto::Name::from_str(
                    s.trim().trim_start_matches("*.").trim_end_matches('.'),
                )
                .ok()
            })
            .collect(),
        bogus_nxdomain: cfg.bogus_nxdomain.clone(),
        recurse_deny_answers: cfg.recurse_deny_answers.clone(),
        recurse_allow_answers: cfg.recurse_allow_answers.clone(),
        rrset_roundrobin: cfg.rrset_roundrobin,
        rotor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        safe_search,
        nsid: cfg.nsid.as_ref().map(|s| s.clone().into_bytes()),
        cookies,
        recorder,
        mac_cache,
        inflight_max: cfg.max_inflight,
        inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        dnstap: build_dnstap(cfg)?,
        edns_buffer: cfg.edns_buffer_size,
        hide_identity: cfg.hide_identity,
        hide_version: cfg.hide_version,
        server_identity: cfg
            .identity
            .clone()
            .or_else(|| cfg.nsid.clone())
            .unwrap_or_else(|| PRODUCT_NAME.to_string())
            .into_bytes(),
        server_version: cfg
            .version
            .clone()
            .unwrap_or_else(|| PRODUCT_NAME.to_string())
            .into_bytes(),
        allow_any: !cfg.deny_any,
        minimal_responses: cfg.minimal_responses,
        padding_block: cfg.edns_padding_block,
        tcp_keepalive_100ms: (cfg.edns_tcp_keepalive_secs > 0)
            .then(|| (cfg.edns_tcp_keepalive_secs.saturating_mul(10)).min(65535) as u16),
        ecs_in_use: cfg.ecs_mode == EcsMode::Send && cfg.ecs_custom_ip.is_some(),
        harden_large_queries: cfg.harden_large_queries,
        domain_needed: cfg.domain_needed,
        bogus_priv: cfg.bogus_priv,
        empty_zones: cfg.empty_zones,
        ddr_enabled: !cfg.ddr_name.is_empty(),
        lane_runtime: None,
    })
}

/** @brief 기능 세트를 교체한다. */
fn reconfigure_native_features(
    current: &native::NativeFeatures,
    cfg: &Config,
    changed: &[String],
) -> Result<native::NativeFeatures, String> {
    let mut next = current.clone();
    next.block_aaaa = cfg.block_aaaa;
    next.dns64_prefix = cfg.dns64_prefix.as_ref().and_then(|prefix| {
        let ip_part = prefix.split('/').next()?;
        let mut octets = ip_part.parse::<std::net::Ipv6Addr>().ok()?.octets();
        octets[12..16].fill(0);
        Some(octets)
    });
    next.dns64_synthall = cfg.dns64_synthall;
    next.rebind_protection = cfg.rebind_protection;
    next.rebind_allow = cfg
        .rebind_allow
        .iter()
        .filter_map(|name| {
            onetdns_proto::Name::from_str(
                name.trim().trim_start_matches("*.").trim_end_matches('.'),
            )
            .ok()
        })
        .collect();
    next.bogus_nxdomain = cfg.bogus_nxdomain.clone();
    next.recurse_deny_answers = cfg.recurse_deny_answers.clone();
    next.recurse_allow_answers = cfg.recurse_allow_answers.clone();
    next.rrset_roundrobin = cfg.rrset_roundrobin;

    next.nsid = cfg.nsid.as_ref().map(|value| value.clone().into_bytes());
    if changed.iter().any(|key| {
        matches!(
            key.as_str(),
            "cookies" | "cluster_raft" | "cluster_raft_secret"
        )
    }) {
        next.cookies = build_cookie_policy(cfg);
    }
    next.inflight_max = cfg.max_inflight;
    if changed
        .iter()
        .any(|key| matches!(key.as_str(), "dnstap_file" | "dnstap_identity"))
    {
        next.dnstap = match (current.dnstap.as_ref(), cfg.dnstap_file.as_ref()) {
            (Some(open), Some(path)) if open.path() == path.as_path() => {
                Some(Arc::new(open.with_identity(dnstap_identity(cfg))))
            }
            _ => build_dnstap(cfg)?,
        };
    }
    next.edns_buffer = cfg.edns_buffer_size;
    next.hide_identity = cfg.hide_identity;
    next.hide_version = cfg.hide_version;
    next.server_identity = cfg
        .identity
        .clone()
        .or_else(|| cfg.nsid.clone())
        .unwrap_or_else(|| PRODUCT_NAME.to_string())
        .into_bytes();
    next.server_version = cfg
        .version
        .clone()
        .unwrap_or_else(|| PRODUCT_NAME.to_string())
        .into_bytes();
    next.allow_any = !cfg.deny_any;
    next.minimal_responses = cfg.minimal_responses;
    next.padding_block = cfg.edns_padding_block;
    next.tcp_keepalive_100ms = (cfg.edns_tcp_keepalive_secs > 0)
        .then(|| (cfg.edns_tcp_keepalive_secs.saturating_mul(10)).min(65535) as u16);
    next.ecs_in_use = cfg.ecs_mode == EcsMode::Send && cfg.ecs_custom_ip.is_some();
    next.harden_large_queries = cfg.harden_large_queries;
    next.domain_needed = cfg.domain_needed;
    next.bogus_priv = cfg.bogus_priv;
    next.empty_zones = cfg.empty_zones;
    Ok(next)
}

/** @brief dnstap 기록에 적을 서버 이름. 따로 정하지 않으면 제품 이름이다. */
fn dnstap_identity(cfg: &Config) -> &str {
    if cfg.dnstap_identity.is_empty() {
        PRODUCT_NAME
    } else {
        &cfg.dnstap_identity
    }
}

/** @brief 질의 기록 파일을 연다. 열지 못하면 조용히 끄지 않고 실패로 알린다. */
fn build_dnstap(cfg: &Config) -> Result<Option<Arc<onetdns_control::DnstapWriter>>, String> {
    let Some(path) = cfg.dnstap_file.as_ref() else {
        return Ok(None);
    };
    let writer =
        onetdns_control::DnstapWriter::create(path, dnstap_identity(cfg)).map_err(|error| {
            format!(
                "dnstap 출력 파일을 열지 못했습니다({}): {error}",
                path.display()
            )
        })?;
    onetdns_core::info!(event = "dnstap.started", path = %path.display(), "질의 기록을 dnstap으로 내보냅니다");
    Ok(Some(Arc::new(writer)))
}

/** @brief 요일 이름들을 비트로. */
fn days_mask(days: &[String]) -> u8 {
    let mut m = 0u8;
    for d in days {
        let bit = match d.as_str() {
            "sun" => 0,
            "mon" => 1,
            "tue" => 2,
            "wed" => 3,
            "thu" => 4,
            "fri" => 5,
            "sat" => 6,
            "all" => {
                m = 0x7f;
                continue;
            }
            _ => return 0,
        };
        m |= 1 << bit;
    }
    m
}

/** @brief 시각 문자열을 분으로. */
fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.split_once(':')?;
    let h: u32 = h.trim().parse().ok()?;
    let m: u32 = m.trim().parse().ok()?;
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/** @brief 설정한 차단 방식. */
fn map_block(cfg: &Config) -> BlockResponse {
    match cfg.block_response {
        BlockResponseKind::Nxdomain => BlockResponse::NxDomain,
        BlockResponseKind::ZeroIp => BlockResponse::ZeroIp,
        BlockResponseKind::Refused => BlockResponse::Refused,
        BlockResponseKind::Custom => BlockResponse::Custom {
            v4: cfg.block_ipv4,
            v6: cfg.block_ipv6,
        },
    }
}

/** @brief 질의 종류 이름을 읽는다. */
fn parse_qtype(s: Option<&str>) -> BoxResult<onetdns_proto::RecordType> {
    use onetdns_proto::RecordType as Rt;
    let t = match s {
        None => return Ok(Rt::A),
        Some(t) => t.to_uppercase(),
    };
    Ok(match t.as_str() {
        "A" => Rt::A,
        "AAAA" => Rt::AAAA,
        "CNAME" => Rt::CNAME,
        "DNAME" => Rt::DNAME,
        "MX" => Rt::MX,
        "TXT" => Rt::TXT,
        "NS" => Rt::NS,
        "SOA" => Rt::SOA,
        "PTR" => Rt::PTR,
        "SRV" => Rt::SRV,
        "CAA" => Rt::CAA,
        other => crate::bail!("지원하지 않는 DNS 레코드 유형입니다: {other}"),
    })
}

/** @brief 로그를 켠다. */
fn init_tracing() {
    onetdns_core::log::init_from_env();
    onetdns_core::isolation::install_request_panic_hook();
}

#[cfg(test)]
/** @brief 설정이 조용히 넓어지거나 사라지지 않는지, 그리고 전송·클러스터·교체 판정. */
mod tests {
    use super::*;

    #[test]
    /**
     * @brief 주소가 이미 쓰이고 있을 때 점유자를 찾는 방법까지 알려 주는지.
     *
     * @details 포트를 잡고 있는 것이 다른 서비스면 오류 문구만으로는 설정을 의심하게 된다.
     *          와일드카드는 구체 주소가 다 비어 있어도 막히므로 특히 그렇다. 찾는 명령과
     *          구체 주소로 우회할 수 있다는 사실을 함께 내보내야 운영자가 다음 행동을
     *          정할 수 있다.
     */
    fn an_occupied_listen_address_says_how_to_find_what_holds_it() {
        let busy = std::io::Error::new(std::io::ErrorKind::AddrInUse, "이미 쓰는 중");
        let wildcard = listener_open_error("일반 DNS", "0.0.0.0:53".parse().unwrap(), &busy);
        assert!(
            wildcard.contains(":53"),
            "찾는 명령에 포트가 들어가야 합니다: {wildcard}"
        );
        assert!(
            wildcard.contains("와일드카드"),
            "와일드카드에는 우회 방법을 알려야 합니다: {wildcard}"
        );

        let specific = listener_open_error("DoT", "127.0.0.1:853".parse().unwrap(), &busy);
        assert!(
            specific.contains(":853"),
            "찾는 명령에 포트가 들어가야 합니다: {specific}"
        );
        assert!(
            !specific.contains("와일드카드"),
            "이미 구체 주소인데 우회하라고 하면 안 됩니다: {specific}"
        );

        let other = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "권한 없음");
        let denied = listener_open_error("일반 DNS", "0.0.0.0:53".parse().unwrap(), &other);
        assert!(
            !denied.contains("netstat") && !denied.contains("ss -lnup"),
            "점유 문제가 아닐 때 엉뚱한 명령을 알리면 안 됩니다: {denied}"
        );
    }

    #[test]
    /**
     * @brief 자체 서명일 때 네 암호화 전송이 같은 인증서를 내놓는지.
     *
     * @details 자체 서명 인증서는 클라이언트가 고정해 쓰는 것이다. 전송마다 다르면 한
     *          곳에서 받은 인증서로 다른 전송에 붙지 못한다. kdig 로 DoT 의 인증서를 꺼내
     *          DoQ 를 검증하면 0/10 이었고, 같은 인증서를 쓰게 하자 10/10 이 됐다.
     *          DDR 로 여러 암호화 주소를 알리는 배포에서 특히 드러난다.
     */
    fn every_encrypted_transport_presents_the_same_self_signed_certificate() {
        let cfg = Config {
            tls_self_signed_host: Some("localhost".to_string()),
            ..Config::default()
        };
        let material = native_tls_material(&cfg).expect("TLS 인증서를 읽지 못했습니다");
        let (dot, doh, doq, doh3) =
            tls_configs_from(&cfg, &material).expect("TLS 설정을 만들지 못했습니다");
        assert!(!dot.cert_chain.is_empty(), "인증서 체인이 비었습니다");
        assert_eq!(dot.cert_chain, doh.cert_chain, "DoH가 다른 인증서를 냅니다");
        assert_eq!(dot.cert_chain, doq.cert_chain, "DoQ가 다른 인증서를 냅니다");
        assert_eq!(
            dot.cert_chain, doh3.cert_chain,
            "DoH3가 다른 인증서를 냅니다"
        );
    }

    #[test]
    /**
     * @brief 편집된 영역 파일만 다시 읽을 대상이 되는지.
     *
     * @details 직렬 번호를 올려도 이 서버가 옛 영역을 답하면 세컨더리는 변경을 영영 받지
     *          못한다. 반대로 손대지 않은 영역까지 알리면 전송이 필요 없는 세컨더리를 깨운다.
     */
    fn only_the_edited_zone_file_is_reloaded() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-zone-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("시험용 디렉터리");
        let first = dir.join("one.test.zone");
        let second = dir.join("two.test.zone");
        std::fs::write(
            &first,
            "@ IN SOA ns admin 1 7200 3600 1209600 3600
",
        )
        .expect("영역 하나");
        std::fs::write(
            &second,
            "@ IN SOA ns admin 1 7200 3600 1209600 3600
",
        )
        .expect("영역 둘");
        let cfg = Config {
            zones: vec![
                onetdns_config::ZoneConfig {
                    origin: "one.test".to_string(),
                    file: Some(first.clone()),
                    ..Default::default()
                },
                onetdns_config::ZoneConfig {
                    origin: "two.test".to_string(),
                    file: Some(second.clone()),
                    ..Default::default()
                },
            ],
            ..Config::default()
        };

        let empty = std::collections::HashMap::new();
        let start = zone_file_mtimes(&cfg);
        assert_eq!(start.len(), 2, "설정에 적힌 영역 파일을 모두 봐야 합니다");
        assert_eq!(
            zones_with_edited_files(&cfg, &empty, &start).len(),
            2,
            "처음 보는 파일은 한 번 읽어야 합니다"
        );
        assert!(
            zones_with_edited_files(&cfg, &start, &start).is_empty(),
            "손대지 않은 영역까지 다시 읽었습니다"
        );

        // 같은 초 안에 다시 써도 알아채는지 보려고 수정 시각을 명시적으로 옮긴다.
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(&second)
            .expect("영역 둘 열기");
        handle
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)),
            )
            .expect("수정 시각 변경");
        let after = zone_file_mtimes(&cfg);
        let edited = zones_with_edited_files(&cfg, &start, &after);
        assert_eq!(edited.len(), 1, "편집한 영역 하나만 대상이어야 합니다");
        assert!(
            edited[0].eq_ignore_case(&onetdns_proto::Name::from_str("two.test").unwrap()),
            "편집하지 않은 영역을 다시 읽었습니다"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /**
     * @brief 경로가 그대로인 채 내용만 갱신된 인증서를 다시 적용하는지.
     *
     * @details 갱신 도구와 ACME 발급은 같은 경로에 새 인증서를 덮어쓴다. 설정 항목 비교만
     *          보면 바뀐 것이 없어 보이므로, 파일 내용을 근거로 삼지 않으면 다시 시작할
     *          때까지 만료된 인증서를 계속 내민다.
     */
    fn replacing_the_certificate_file_swaps_the_live_certificate() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-tls-refresh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("시험용 디렉터리");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let write = |host: &str| {
            let (cert, key) =
                onetdns_transport::generate_self_signed_pem(host).expect("자체 서명 인증서");
            std::fs::write(&cert_path, cert).expect("인증서 저장");
            std::fs::write(&key_path, key).expect("개인키 저장");
        };
        write("first.test");

        let cfg = Config {
            tls_cert: Some(cert_path.clone()),
            tls_key: Some(key_path.clone()),
            ..Config::default()
        };
        let slots = TlsSlots::from_config(&cfg).expect("슬롯 생성");
        let before = slots.dot.load().cert_chain.clone();

        assert!(
            slots
                .refresh_certificate_files(&cfg)
                .expect("같은 파일 재확인")
                .is_empty(),
            "내용이 그대로인데 인증서를 갈았습니다"
        );

        write("second.test");
        assert_eq!(
            slots
                .refresh_certificate_files(&cfg)
                .expect("바뀐 파일 재확인"),
            vec!["tls_cert"],
            "갱신된 인증서를 읽지 못했습니다"
        );
        let after = slots.dot.load().cert_chain.clone();
        assert_ne!(before, after, "수신 주소가 이전 인증서를 계속 내밉니다");
        for other in [&slots.doh, &slots.doq, &slots.doh3] {
            assert_eq!(
                other.load().cert_chain,
                after,
                "전송 하나만 새 인증서로 갈렸습니다"
            );
        }

        // 클라이언트 인증서를 확인하는 CA 번들도 경로가 그대로인 채 갈린다.
        let ca_path = dir.join("ca.pem");
        let (first_ca, _) =
            onetdns_transport::generate_self_signed_pem("ca-one.test").expect("CA 하나");
        std::fs::write(&ca_path, first_ca).expect("CA 저장");
        let mtls = Config {
            tls_client_ca: Some(ca_path.clone()),
            ..cfg.clone()
        };
        let mtls_slots = TlsSlots::from_config(&mtls).expect("mTLS 슬롯 생성");
        assert!(
            mtls_slots
                .refresh_certificate_files(&mtls)
                .expect("같은 CA 재확인")
                .is_empty(),
            "CA 번들이 그대로인데 교체했습니다"
        );
        let (second_ca, _) =
            onetdns_transport::generate_self_signed_pem("ca-two.test").expect("CA 둘");
        std::fs::write(&ca_path, second_ca).expect("CA 교체");
        assert_eq!(
            mtls_slots
                .refresh_certificate_files(&mtls)
                .expect("바뀐 CA 재확인"),
            vec!["tls_client_ca"],
            "갱신된 mTLS CA 번들을 읽지 못했습니다"
        );

        let self_signed = Config {
            tls_self_signed_host: Some("localhost".to_string()),
            ..cfg.clone()
        };
        assert!(
            slots
                .refresh_certificate_files(&self_signed)
                .expect("자체 서명 확인")
                .is_empty(),
            "자체 서명으로 도는 동안에는 파일이 근거가 아닙니다"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /**
     * @brief 화면에 내는 종류 약칭을 그대로 다시 읽어 같은 번호가 되는지.
     * @details 두 테이블이 어긋나면 물어본 종류가 조용히 걸러지고 호출자가 A 로 되돌린다.
     *          CAA 를 물었는데 A 를 설명하는 응답이 나가도 오류 하나 남지 않는다.
     */
    fn every_displayed_qtype_name_parses_back_to_its_own_number() {
        for number in 0u16..=u16::MAX {
            let rtype = onetdns_proto::RecordType(number);
            if rtype.name() == "UNKNOWN" {
                continue;
            }
            assert_eq!(
                qtype_numbers(&[rtype.name().to_string()]),
                vec![number],
                "{} 약칭이 자기 번호로 읽히지 않습니다",
                rtype.name()
            );
        }
        assert_eq!(qtype_numbers(&["TYPE99".to_string()]), vec![99]);
        assert_eq!(qtype_numbers(&["caa".to_string()]), vec![257]);
        assert!(qtype_numbers(&["NOSUCHTYPE".to_string()]).is_empty());
    }

    #[test]
    /**
     * @brief 설정에 적은 요일 이름이 지역 시각으로 바꾼 요일과 같은 위치를 가리키는지.
     * @details 비트를 정하는 곳과 그 비트를 읽는 위치가 갈라져 있어, 한쪽만 바꾸면 모든
     *          시간대 규칙이 하루씩 어긋난 채로도 각 단위 테스트는 그대로 통과한다.
     */
    fn policy_time_window_day_names_match_the_local_weekday_fold() {
        let window = parse_time_window(
            &["fri".to_string()],
            &Some("22:00".to_string()),
            &Some("02:00".to_string()),
        )
        .expect("금요일 밤 구간을 읽지 못했습니다");
        let engine = onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
            onetdns_policy::Action::Block,
        )
        .with_window(window)]);
        let at = |minute_of_week: u32| onetdns_policy::PolicyInput {
            client: "192.0.2.1".parse().unwrap(),
            qname: "x.example",
            qtype: 1,
            unix_time: 0,
            local_minute_of_week: minute_of_week,
            transport: onetdns_policy::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        };
        const THURSDAY: u32 = 4 * 1_440;
        const FRIDAY: u32 = 5 * 1_440;
        const SATURDAY: u32 = 6 * 1_440;

        assert_eq!(
            engine.evaluate(&at(FRIDAY + 23 * 60)),
            onetdns_policy::Action::Block,
            "금요일 23시가 금요일 밤 구간에 들어가지 않음"
        );

        assert_eq!(
            engine.evaluate(&at(SATURDAY + 60)),
            onetdns_policy::Action::Block,
            "자정을 넘긴 토요일 1시가 전날 구간에 들어가지 않음"
        );

        assert_eq!(
            engine.evaluate(&at(THURSDAY + 23 * 60)),
            onetdns_policy::Action::Continue,
            "목요일 23시가 금요일 구간에 걸림"
        );
    }

    #[test]
    /** @brief 서비스 시간표와 정책 규칙이 같은 요일 이름을 같은 비트로 옮기는지. */
    fn schedule_and_policy_day_masks_agree() {
        for (index, name) in ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
            .iter()
            .enumerate()
        {
            let schedule = days_mask(std::slice::from_ref(&(*name).to_string()));
            let policy = parse_time_window(
                std::slice::from_ref(&(*name).to_string()),
                &Some("09:00".to_string()),
                &Some("18:00".to_string()),
            )
            .expect("요일 하나짜리 구간을 읽지 못했습니다")
            .days;
            assert_eq!(
                schedule,
                1u8 << index,
                "{name}의 서비스 시간표 비트가 다릅니다"
            );
            assert_eq!(
                policy, schedule,
                "{name}의 정책 규칙 비트가 서비스 시간표와 다릅니다"
            );
        }
    }

    #[test]
    /**
     * @brief 영역 원본이 없는 설정을 권한 서버로 오인하지 않는지.
     * @details 이 판정이 틀리면 콘솔이 영역을 받아 놓고 성공이라 답하는데 그 영역으로는
     *          아무 질의도 풀리지 않는다. 계층을 얹는 곳과 사실을 알리는 곳이 같은
     *          함수를 봐야 한다.
     */
    fn a_config_without_zone_sources_is_not_an_authority_server() {
        let mut cfg = Config::default();
        assert!(
            !authority_sources_configured(&cfg),
            "영역 원본이 없는데 권한 서버로 판정함"
        );
        cfg.zones_dir = Some(std::path::PathBuf::from("zones"));
        assert!(
            authority_sources_configured(&cfg),
            "zones_dir를 영역 원본으로 세지 않음"
        );
    }

    #[test]
    /** @brief DHCP 동적 범위가 서버나 게이트웨이 주소를 삼키면 시작 전에 거부하는지. */
    fn dhcp_range_excludes_server_and_router_addresses() {
        let base = Config {
            dhcp_server_ip: Some("192.168.1.1".into()),
            dhcp_range_start: Some("192.168.1.10".into()),
            dhcp_range_end: Some("192.168.1.20".into()),
            dhcp_subnet_mask: Some("255.255.255.0".into()),
            dhcp_router: Some("192.168.1.2".into()),
            ..Config::default()
        };
        assert!(build_dhcp_config(&base).is_ok());

        let mut server_in_range = base.clone();
        server_in_range.dhcp_server_ip = Some("192.168.1.15".into());
        assert!(build_dhcp_config(&server_in_range)
            .unwrap_err()
            .contains("dhcp_server_ip"));

        let mut router_in_range = base;
        router_in_range.dhcp_router = Some("192.168.1.15".into());
        assert!(build_dhcp_config(&router_in_range)
            .unwrap_err()
            .contains("dhcp_router"));
    }

    #[test]
    /** @brief DHCP 임대 수명을 wire에서 자르지 않고 infinity를 JSON에서도 보존하는지. */
    fn dhcp_lease_lifetime_is_lossless_at_runtime_boundaries() {
        assert!(wire_dhcp_lease_secs(0).is_err());
        assert!(wire_dhcp_lease_secs(u64::from(u32::MAX) + 1).is_err());
        assert_eq!(wire_dhcp_lease_secs(u64::from(u32::MAX)), Ok(u32::MAX));
        assert_eq!(
            lease_time_json(u64::MAX, 123),
            "\"expires\":null,\"remaining\":null,\"infinite\":true"
        );
        assert_eq!(
            lease_time_json(200, 123),
            "\"expires\":200,\"remaining\":77,\"infinite\":false"
        );
    }

    #[test]
    /** @brief 저장된 서버 DUID도 RFC의 3..=130바이트 경계를 정확히 지키는지. */
    fn persisted_server_duid_uses_the_exact_wire_length_range() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let lease_path = std::env::temp_dir().join(format!(
            "onetdns-dhcp6-duid-{}-{unique}",
            std::process::id()
        ));
        let duid_path = std::path::PathBuf::from(format!("{}.duid", lease_path.display()));

        std::fs::write(&duid_path, "123456").unwrap();
        assert_eq!(
            load_or_create_server_duid6(lease_path.to_str()).unwrap(),
            vec![0x12, 0x34, 0x56]
        );

        std::fs::write(&duid_path, "00".repeat(131)).unwrap();
        let regenerated = load_or_create_server_duid6(lease_path.to_str()).unwrap();
        assert!((3..=130).contains(&regenerated.len()));
        assert_ne!(regenerated.len(), 131);

        std::fs::remove_file(duid_path).unwrap();
    }

    #[test]
    /** @brief DNSCrypt 장기 신원 키가 한 번 저장되고 재시작 뒤 같은 공개키로 복원되는지. */
    fn dnscrypt_provider_identity_survives_reload() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "onetdns-dnscrypt-identity-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let config_path = Some(dir.join(CONFIG_FILE_NAME));
        let cfg = Config::default();

        let first = load_or_create_dnscrypt_provider(&cfg, &config_path, 86_400).unwrap();
        let public_key = first.provider_public_key();
        let key_path = dnscrypt_provider_key_path(&config_path).unwrap();
        let persisted = zeroize::Zeroizing::new(std::fs::read_to_string(&key_path).unwrap());
        assert_eq!(persisted.len(), 64, "개인키 파일은 정확한 32바이트 hex");

        let restored = load_or_create_dnscrypt_provider(&cfg, &config_path, 86_400).unwrap();
        assert_eq!(restored.provider_public_key(), public_key);

        std::fs::remove_file(key_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    /** @brief DDR이 알리는 것이 실제로 열려 있는 암호화 수신 주소와 맞는지. */
    fn ddr_endpoints_follow_the_configured_encrypted_listeners() {
        let mut cfg = Config::default();
        assert!(
            ddr_endpoints_from(&cfg).is_empty(),
            "열린 암호화 수신 주소가 없으면 알릴 것도 없습니다"
        );

        cfg.doh_path = "/q".to_string();
        cfg.listen_doh = vec![
            "127.0.0.1:443".parse().unwrap(),
            "[::1]:443".parse().unwrap(),
            "127.0.0.1:8443".parse().unwrap(),
        ];
        cfg.listen_dot = vec!["127.0.0.1:853".parse().unwrap()];
        let endpoints = ddr_endpoints_from(&cfg);

        // 같은 포트를 여러 주소에서 듣는 것은 한 번만 알린다.
        let doh: Vec<_> = endpoints.iter().filter(|e| e.alpn == ["h2"]).collect();
        assert_eq!(doh.len(), 2);
        assert_eq!(doh[0].port, 443);
        assert_eq!(doh[1].port, 8443);
        assert!(doh.iter().all(|e| e.dohpath.as_deref() == Some("/q{?dns}")));

        let dot: Vec<_> = endpoints.iter().filter(|e| e.alpn == ["dot"]).collect();
        assert_eq!(dot.len(), 1);
        assert_eq!(dot[0].port, 853);
        assert!(dot[0].dohpath.is_none(), "DoT에는 dohpath가 없습니다");

        assert!(
            endpoints.iter().all(|e| e.priority != 0),
            "우선순위 0은 별칭 형식이라 승격 안내로 쓸 수 없습니다"
        );
        assert!(
            doh[0].priority < dot[0].priority,
            "지원 폭이 넓은 전송을 먼저 권합니다"
        );

        // DNSCrypt는 SVCB로 알릴 ALPN이 없어 대상이 아니다.
        cfg.listen_dnscrypt = vec!["127.0.0.1:5443".parse().unwrap()];
        assert_eq!(ddr_endpoints_from(&cfg).len(), endpoints.len());
    }

    #[test]
    /** @brief 외부 캐시가 서로 다른 TTL 정책의 응답을 같은 이름 공간에서 나누지 않는지. */
    fn external_cache_namespace_separates_ttl_policies() {
        let base = Config::default();
        let mut changed = base.clone();
        changed.min_ttl = base.min_ttl.saturating_add(1);
        assert_ne!(cache_namespace_base(&base), cache_namespace_base(&changed));

        changed = base.clone();
        changed.max_ttl = base.max_ttl.saturating_sub(1);
        assert_ne!(cache_namespace_base(&base), cache_namespace_base(&changed));
    }

    #[test]
    /** @brief 쓰다 실패해도 앞 파일이 그대로 남고 임시 파일이 치워지는지. */
    fn failed_streaming_atomic_write_keeps_previous_file_and_removes_temporary() {
        use std::io::Write as _;

        let path = std::env::temp_dir().join(format!(
            "onetdns-atomic-stream-failure-{}-{}.bin",
            std::process::id(),
            unix_now()
        ));
        atomic_write(&path, b"previous").unwrap();
        let result = atomic_write_with(&path, false, |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected streaming failure"))
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");

        let temporary_prefix = format!(
            ".{}.tmp.",
            path.file_name().and_then(|name| name.to_str()).unwrap()
        );
        let leaked = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&temporary_prefix)
            });
        assert!(!leaked, "실패한 스트리밍 임시 파일이 남으면 안 됩니다");
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    /** @brief Windows의 짧은 공유 충돌만 다시 시도하고 다른 오류는 즉시 돌려주는지. */
    fn windows_atomic_replace_retries_only_transient_file_conflicts() {
        for raw_error in [5, 32, 33] {
            let mut attempts = 0;
            retry_windows_replace(|| {
                attempts += 1;
                if attempts < 3 {
                    Err(std::io::Error::from_raw_os_error(raw_error))
                } else {
                    Ok(())
                }
            })
            .unwrap();
            assert_eq!(attempts, 3);
        }

        let mut exhausted_attempts = 0;
        let error = retry_windows_replace(|| {
            exhausted_attempts += 1;
            Err(std::io::Error::from_raw_os_error(32))
        })
        .unwrap_err();
        assert_eq!(exhausted_attempts, 9);
        assert_eq!(error.raw_os_error(), Some(32));

        let mut permanent_attempts = 0;
        let error = retry_windows_replace(|| {
            permanent_attempts += 1;
            Err(std::io::Error::from_raw_os_error(87))
        })
        .unwrap_err();
        assert_eq!(permanent_attempts, 1);
        assert_eq!(error.raw_os_error(), Some(87));
    }

    #[test]
    /** @brief 고정한 차단 엔진이 흘려 저장되고 다시 읽히는지. */
    fn compiled_filter_cache_streams_atomically_and_loads() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "onetdns-compiled-filter-cache-{}-{unique}",
            std::process::id()
        ));
        let path = dir.join("filters.bin");
        let fingerprint = [0x5a; 32];
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");

        save_compiled_filter_cache(&path, &mut parts, fingerprint);
        let restored = load_compiled_filter_cache(&path, fingerprint).unwrap();
        assert!(restored.block.matches("child.blocked.example"));
        assert!(!restored.block.matches("allowed.example"));
        assert!(load_compiled_filter_cache(&path, [0xa5; 32]).is_none());

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    /** @brief 테스트용 임대 기록. */
    fn lease_sync_pool() -> Arc<Mutex<dhcp::LeasePool>> {
        let dc = dhcp::DhcpConfig {
            server_ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
            range_start: std::net::Ipv4Addr::new(192, 168, 1, 100),
            range_end: std::net::Ipv4Addr::new(192, 168, 1, 102),
            subnet_mask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            router: std::net::Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![std::net::Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        };
        Arc::new(Mutex::new(dhcp::LeasePool::new(&dc)))
    }

    #[test]
    /** @brief 고정 할당 API가 새 식별자 형식만 받고 opaque ID를 그대로 관리하는지. */
    fn static_reservation_api_uses_one_identity_model() {
        let pool = lease_sync_pool();
        assert!(apply_static_add(
            &pool,
            "{\"identity\":\"id:0102\",\"ip\":\"192.168.1.90\",\"hostname\":\"printer\"}"
        )
        .is_ok());
        let listed = static_reservations_json(Some(&pool));
        assert!(listed.contains("\"available\":true"), "{listed}");
        assert!(listed.contains("\"identity\":\"id:0102\""), "{listed}");
        let absent = static_reservations_json(None);
        assert!(absent.contains("\"available\":false"), "{absent}");
        assert!(!listed.contains("\"mac\""), "{listed}");
        assert!(apply_static_add(
            &pool,
            "{\"mac\":\"aa:bb:cc:dd:ee:ff\",\"ip\":\"192.168.1.91\"}"
        )
        .is_err());
        assert!(apply_static_add(
            &pool,
            "{\"identity\":\"id:0304\",\"ip\":\"192.168.1.91\",\"hostname\":\"bad name\"}"
        )
        .is_err());
        assert!(apply_static_remove(&pool, "id:0102").is_ok());
    }

    #[test]
    /** @brief 임대를 배치로도 하나씩도 받는지. */
    fn lease_sync_accepts_batch_and_single() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;

        let batch = format!(
            "[{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\",\"hostname\":\"two\"}}]"
        );
        assert_eq!(
            apply_lease_sync(&pool, &batch).unwrap(),
            "{\"synced\":2}",
            "배열 스냅샷을 한 번에 반영해야"
        );
        assert_eq!(pool.lock_recover().snapshot().len(), 2);
        assert_eq!(
            pool.lock_recover().snapshot()[0].identity.to_text(),
            "id:0102"
        );

        let single = format!(
            "{{\"identity\":\"mac:aabbccddee03\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"ip\":\"192.168.1.102\",\"expiry\":\"{expiry}\"}}"
        );
        assert_eq!(apply_lease_sync(&pool, &single).unwrap(), "{\"synced\":1}");
        assert_eq!(pool.lock_recover().snapshot().len(), 3);

        assert_eq!(apply_lease_sync(&pool, &batch).unwrap(), "{\"synced\":0}");
    }

    #[test]
    /** @brief HA 동기화가 JSON 정밀도 밖의 infinity 만료 시각을 정확히 보존하는지. */
    fn lease_sync_preserves_infinite_expiry_exactly() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let body = format!(
            "{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{}\"}}",
            u64::MAX
        );

        assert_eq!(apply_lease_sync(&pool, &body).unwrap(), "{\"synced\":1}");
        assert_eq!(pool.lock_recover().snapshot()[0].expiry_unix, u64::MAX);
    }

    #[test]
    /** @brief 하나라도 어긋나면 배치 전체를 거부하는지. 반쯤 받으면 기록이 어긋난다. */
    fn lease_sync_rejects_whole_batch_on_any_bad_item() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;

        let mixed = format!(
            "[{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"nonsense\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\"}}]"
        );
        assert!(apply_lease_sync(&pool, &mixed).is_err());
        assert!(
            pool.lock_recover().snapshot().is_empty(),
            "한 항목이라도 틀리면 앞 항목도 반영하지 않아야"
        );

        assert!(apply_lease_sync(&pool, "[{\"ip\":\"192.168.1.100\"}]").is_err());
        assert!(apply_lease_sync(
            &pool,
            &format!("{{\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}")
        )
        .is_err());
        assert!(apply_lease_sync(
            &pool,
            &format!("{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\",\"hostname\":\"bad name\"}}")
        )
        .is_err());
        assert!(pool.lock_recover().snapshot().is_empty());
        assert!(apply_lease_sync(&pool, "not json").is_err());
        assert_eq!(apply_lease_sync(&pool, "[]").unwrap(), "{\"synced\":0}");
    }

    #[test]
    /** @brief 같은 IP나 식별자를 중복한 HA 배치를 일부도 반영하지 않는지. */
    fn lease_sync_rejects_duplicate_ip_batch_atomically() {
        use onetdns_core::MutexExt;
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;
        let duplicate = format!(
            "[{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"mac:aabbccddee02\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}]"
        );

        assert!(apply_lease_sync(&pool, &duplicate).is_err());
        assert!(
            pool.lock_recover().snapshot().is_empty(),
            "충돌 전 항목까지 반영하면 HA 노드의 임대 기록이 갈라집니다"
        );

        let duplicate_identity = format!(
            "[{{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}},\
              {{\"identity\":\"id:0102\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"ip\":\"192.168.1.101\",\"expiry\":\"{expiry}\"}}]"
        );
        assert!(apply_lease_sync(&pool, &duplicate_identity).is_err());
        assert!(pool.lock_recover().snapshot().is_empty());
    }

    #[test]
    /** @brief 한 번에 받는 임대 수에 상한이 있는지. */
    fn lease_sync_bounds_batch_size() {
        let pool = lease_sync_pool();
        let expiry = crate::unix_now() + 3_600;
        let one = format!(
            "{{\"identity\":\"mac:aabbccddee01\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"ip\":\"192.168.1.100\",\"expiry\":\"{expiry}\"}}"
        );
        let body = format!(
            "[{}]",
            std::iter::repeat_n(one.as_str(), MAX_SYNCED_LEASES + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(apply_lease_sync(&pool, &body).is_err());
    }

    #[test]
    /** @brief 재귀일 때 UDP 워커를 더 두는지. 재귀는 응답을 기다리는 시간이 길다. */
    fn automatic_plain_dns_workers_separate_recursive_udp_from_tcp() {
        assert_eq!(plain_dns_worker_counts(0, BackendKind::Forward, 1), (4, 1));
        assert_eq!(plain_dns_worker_counts(0, BackendKind::Forward, 4), (16, 4));
        assert_eq!(plain_dns_worker_counts(0, BackendKind::Recurse, 1), (5, 1));
        assert_eq!(plain_dns_worker_counts(0, BackendKind::Split, 4), (20, 4));
        assert_eq!(plain_dns_worker_counts(7, BackendKind::Recurse, 1), (7, 7));
        assert_eq!(
            plain_dns_worker_counts(0, BackendKind::Recurse, usize::MAX),
            (MAX_PLAIN_DNS_WORKERS, MAX_PLAIN_DNS_WORKERS)
        );
    }

    #[test]
    /** @brief 신뢰 루트를 시작 중에 읽고, 못 읽으면 시작하지 않는지. */
    fn configured_trust_anchor_loads_synchronously_and_fails_closed() {
        let root = onetdns_proto::Name::root();
        let signer = onetdns_dnssec::sign::ZoneSigner::generate(root.clone(), [73; 32]);
        let manager =
            onetdns_dnssec::anchor::AnchorManager::bootstrap(root, vec![signer.dnskey()], 0);
        let path = std::env::temp_dir().join(format!(
            "onetdns-static-anchor-test-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, manager.serialize()).expect("write anchor state");

        assert_eq!(
            load_configured_trust_anchors(&path).expect("load anchor state"),
            manager.active_ds()
        );

        let child = onetdns_proto::Name::from_str("child.example").unwrap();
        let child_signer = onetdns_dnssec::sign::ZoneSigner::generate(child.clone(), [74; 32]);
        let child_manager =
            onetdns_dnssec::anchor::AnchorManager::bootstrap(child, vec![child_signer.dnskey()], 0);
        std::fs::write(&path, child_manager.serialize()).expect("write child anchor state");
        assert!(load_configured_trust_anchors(&path).is_err());

        std::fs::write(&path, "damaged anchor state").expect("damage anchor state");
        assert!(load_configured_trust_anchors(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    /** @brief 관리 명령이 표시 없이 실행되지 않는지. 서버로 시작하려던 것이 엉뚱한 명령이 되면 안 된다. */
    fn management_commands_require_cli_prefix() {
        for command in [
            "query", "cert", "stats", "reload", "top", "block", "allow", "check", "services",
            "passwd",
        ] {
            assert!(parse_argv(&[command.to_string()]).is_err(), "{command}");
        }
        assert!(matches!(
            parse_argv(&[
                "--cli".to_string(),
                "query".to_string(),
                "example.test".to_string()
            ]),
            Ok(Command::Query { .. })
        ));
    }

    #[test]
    /**
     * @brief 도움말이 안내하는 옵션을 전부 받는지.
     *
     * @details 도움말과 COMMAND_FLAGS 가 따로 놀면, 안내를 보고 그대로 친 운영자가
     *          알 수 없는 옵션이라는 말을 듣는다. 주석은 부탁일 뿐이므로 여기서 판정한다.
     */
    fn every_documented_option_is_accepted() {
        // 하위 명령을 고르는 표시라서 명령별 목록에 들어갈 슬롯이 없다.
        const NOT_A_COMMAND_FLAG: &[&str] = &["--cli"];
        let accepted: Vec<&str> = COMMAND_FLAGS
            .iter()
            .flat_map(|(_, flags)| flags.iter().copied())
            .chain(NOT_A_COMMAND_FLAG.iter().copied())
            .collect();

        let mut documented: Vec<String> = Vec::new();
        let mut rest = HELP;
        while let Some(at) = rest.find("--") {
            rest = &rest[at..];
            let end = rest
                .find(|c: char| !(c.is_ascii_lowercase() || c == '-'))
                .unwrap_or(rest.len());
            let (flag, tail) = rest.split_at(end);
            rest = tail;
            if flag.len() > 2 && !documented.iter().any(|seen| seen == flag) {
                documented.push(flag.to_string());
            }
        }
        assert!(
            documented.len() > 5,
            "도움말에서 옵션을 읽어내지 못했습니다: {documented:?}"
        );

        for flag in &documented {
            assert!(
                accepted.contains(&flag.as_str()),
                "도움말은 {flag} 를 안내하는데 어느 명령도 받지 않습니다"
            );
        }
    }

    #[test]
    /** @brief 모르는 옵션이 조용히 무시되지 않는지. 무시되면 진단이 자신 있게 틀린다. */
    fn unknown_options_are_rejected_instead_of_ignored() {
        let unknown = parse_argv(&[
            "--cli".to_string(),
            "query".to_string(),
            "example.test".to_string(),
            "--server".to_string(),
            "127.0.0.1:15353".to_string(),
        ]);
        let Err(message) = unknown else {
            panic!("모르는 옵션은 거부되어야 합니다");
        };
        assert!(
            message.contains("--server"),
            "어느 옵션이 문제인지 알려야 합니다: {message}"
        );

        assert!(
            parse_argv(&["--no-wbe".to_string()]).is_err(),
            "서버로 시작하는 길에서도 오타를 잡아야 합니다"
        );

        assert!(
            matches!(
                parse_argv(&[
                    "--cli".to_string(),
                    "query".to_string(),
                    "example.test".to_string(),
                    "--type=AAAA".to_string(),
                ]),
                Ok(Command::Query { .. })
            ),
            "아는 옵션은 붙여 쓴 형태도 받아야 합니다"
        );

        assert!(
            matches!(
                parse_argv(&["--no-web".to_string(), "--no-supervisor".to_string()]),
                Ok(Command::Run { .. })
            ),
            "아는 옵션만 주면 서버로 떠야 합니다"
        );
    }

    #[test]
    /** @brief 잘못된 업데이트 정책 규칙이 조용히 사라지지 않는지. 사라지면 운영자는 걸린 줄 안다. */
    fn invalid_update_policy_name_cannot_disappear_silently() {
        let mut cfg = Config::default();
        cfg.update_policy.push(onetdns_config::UpdatePolicyRule {
            action: "grant".to_string(),
            identity: "bad..identity".to_string(),
            name: "*".to_string(),
            types: vec!["A".to_string()],
        });
        assert!(build_update_policy(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 정책 규칙이 건너뛰어지거나 더 넓게 해석되지 않는지. */
    fn invalid_policy_rule_cannot_be_skipped_or_broadened() {
        let mut cfg = Config::default();
        cfg.policy.push(onetdns_config::PolicyRule {
            action: "blokc".to_string(),
            ..Default::default()
        });
        assert!(build_policy_engine(&cfg).is_err());

        cfg.policy[0] = onetdns_config::PolicyRule {
            action: "block".to_string(),
            days: vec!["bogus".to_string()],
            start: Some("08:00".to_string()),
            end: Some("09:00".to_string()),
            ..Default::default()
        };
        assert!(build_policy_engine(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 배치 기록이 조용히 사라지지 않는지. */
    fn invalid_view_record_name_cannot_disappear_silently() {
        let mut cfg = Config::default();
        cfg.views.push(onetdns_config::ViewConfig {
            name: "office".to_string(),
            clients: vec!["192.0.2.0/24".to_string()],
            local_a: vec![("bad..name".to_string(), "192.0.2.1".parse().unwrap())],
            local_aaaa: vec![],
        });
        assert!(build_views(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 재작성과 영역 규칙이 조용히 사라지지 않는지. */
    fn invalid_rewrite_and_local_zone_cannot_disappear_silently() {
        let mut parts = EngineParts::default();
        let rewrites = vec![Rewrite {
            domain: "router.example".to_string(),
            answer: "bad..answer".to_string(),
        }];
        assert!(merge_config_filters(&mut parts, &rewrites, &[], &[], &[]).is_err());

        let zones = vec![LocalZone {
            name: "local".to_string(),
            kind: LocalZoneKind::Static,
            records: vec![
                "local 192.0.2.1".to_string(),
                "local target.example".to_string(),
            ],
        }];
        assert!(merge_config_filters(&mut parts, &[], &zones, &[], &[]).is_err());
    }

    #[test]
    /**
     * @brief 설정의 static 영역이 이름별 답을 엔진까지 그대로 옮기는지.
     * @details static을 redirect처럼 로드하면 적지 않은 이름까지 같은 주소로 답해, 없어야 할
     *          이름이 살아난다.
     */
    fn static_local_zone_from_config_answers_listed_names_only() {
        let zones = vec![LocalZone {
            name: "corp.example".to_string(),
            kind: LocalZoneKind::Static,
            records: vec![
                "www.corp.example 192.0.2.2".to_string(),
                "mail.corp.example www.corp.example".to_string(),
            ],
        }];
        let mut parts = EngineParts::default();
        merge_config_filters(&mut parts, &[], &zones, &[], &[]).unwrap();
        let engine = BlockEngine::new(parts, onetdns_core::BlockResponse::ZeroIp);
        let client = onetdns_core::ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };
        let verdict = |q: &str| {
            onetdns_core::FilterEngine::verdict(
                &engine,
                &onetdns_proto::Name::from_str(q).unwrap(),
                onetdns_proto::RecordType::A,
                &client,
            )
        };
        assert!(matches!(
            verdict("www.corp.example"),
            onetdns_core::FilterVerdict::Rewrite(RewriteTarget::Records(_))
        ));
        assert!(matches!(
            verdict("mail.corp.example"),
            onetdns_core::FilterVerdict::Rewrite(RewriteTarget::Cname(_))
        ));
        assert!(matches!(
            verdict("other.corp.example"),
            onetdns_core::FilterVerdict::Block(onetdns_core::BlockResponse::NxDomain)
        ));
        assert!(matches!(
            verdict("corp.example"),
            onetdns_core::FilterVerdict::Block(onetdns_core::BlockResponse::NoData)
        ));
    }

    #[test]
    /**
     * @brief 설정의 transparent 영역이 둘러싼 로컬 영역만 거두는지.
     * @details 이 값이 아무것도 하지 않으면 deny 영역 아래를 풀려는 설정이 조용히 무시되고,
     *          차단 목록까지 풀면 구독한 목록이 무력화된다.
     */
    fn transparent_local_zone_lifts_enclosing_local_zone_only() {
        let zone = |name: &str, kind| LocalZone {
            name: name.to_string(),
            kind,
            records: vec![],
        };
        let zones = vec![
            zone("corp.example", LocalZoneKind::Deny),
            zone("api.corp.example", LocalZoneKind::Transparent),
            zone("ads.api.corp.example", LocalZoneKind::Transparent),
        ];
        let no_lists: [PathBuf; 0] = [];
        let mut parts = onetdns_filter::load_parts_with_subscriptions(
            &no_lists,
            &no_lists,
            &[],
            &["||ads.api.corp.example^"],
            &[],
        )
        .unwrap();
        merge_config_filters(&mut parts, &[], &zones, &[], &[]).unwrap();
        let engine = BlockEngine::new(parts, onetdns_core::BlockResponse::NxDomain);
        let client = onetdns_core::ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };
        let verdict = |q: &str| {
            onetdns_core::FilterEngine::verdict(
                &engine,
                &onetdns_proto::Name::from_str(q).unwrap(),
                onetdns_proto::RecordType::A,
                &client,
            )
        };
        assert!(matches!(
            verdict("www.corp.example"),
            onetdns_core::FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict("v1.api.corp.example"),
            onetdns_core::FilterVerdict::Allow
        ));
        assert!(matches!(
            verdict("ads.api.corp.example"),
            onetdns_core::FilterVerdict::Block(_)
        ));
    }

    #[test]
    /** @brief 목록을 못 읽었을 때 차단이 전부 풀리지 않는지. */
    fn invalid_filter_sources_and_services_cannot_fail_open() {
        assert!(expand_services(&["unknown-service".to_string()]).is_err());

        let mut config = Config::default();
        config.blocklists.push(std::env::temp_dir().join(format!(
            "onetdns-missing-filter-{}-{}.list",
            std::process::id(),
            line!()
        )));
        let input = FilterBuildInputs {
            blocked_services: &[],
            subscriptions: &[],
            overlay_block: &[],
            overlay_allow: &[],
            refused_domains: &[],
            rpz_texts: &[],
            compiled_filter_cache: None,
            subscription_cache_dir: None,
        };
        assert!(build_filter_engine_for_config(&config, &input).is_err());

        config.blocklists.clear();
        config.clients.push(onetdns_config::ClientConfig {
            name: "restricted".to_string(),
            blocked_services: vec!["unknown-service".to_string()],
            ..Default::default()
        });
        assert!(build_filter_engine_for_config(&config, &input).is_err());
    }

    #[test]
    /**
     * @brief 서비스 차단 일정 구간에서는 서비스 규칙만 빠지고 다른 규칙은 남는지.
     * @details 구간 안에서 필터 전체를 건너뛰면 차단 목록과 사용자 규칙까지 풀린다.
     */
    fn service_schedule_pauses_only_service_rules() {
        let services = vec!["youtube".to_string()];
        let kept = vec!["||kept.example^".to_string()];
        let input = FilterBuildInputs {
            blocked_services: &services,
            subscriptions: &[],
            overlay_block: &kept,
            overlay_allow: &[],
            refused_domains: &[],
            rpz_texts: &[],
            compiled_filter_cache: None,
            subscription_cache_dir: None,
        };
        let mut config = Config::default();
        let blocking = build_filter_engine_for_config(&config, &input)
            .unwrap()
            .block_count();

        config.service_schedule = ["00:00", "12:00"]
            .iter()
            .zip(["12:00", "00:00"])
            .map(|(start, end)| onetdns_config::ScheduleWindow {
                days: vec!["all".to_string()],
                start: start.to_string(),
                end: end.to_string(),
            })
            .collect();
        assert!(service_blocking_paused(
            &config,
            std::time::SystemTime::now()
        ));
        let paused = build_filter_engine_for_config(&config, &input)
            .unwrap()
            .block_count();
        assert!(paused < blocking, "{paused} < {blocking}");
        assert!(paused >= 1, "사용자 규칙은 남아야 한다");
    }

    #[test]
    /** @brief 설정한 권한 영역이 조용히 빠지지 않는지. */
    fn configured_authority_zone_cannot_disappear_silently() {
        let mut config = Config::default();
        config.zones.push(onetdns_config::ZoneConfig {
            origin: "example.test".to_string(),
            ..Default::default()
        });
        assert!(build_zone_store(&config, &[], &[]).is_err());

        config.zones[0].file = Some(std::env::temp_dir().join(format!(
            "onetdns-missing-zone-{}-{}.zone",
            std::process::id(),
            line!()
        )));
        assert!(build_zone_store(&config, &[], &[]).is_err());
    }

    #[test]
    /** @brief 잘못된 클라이언트 경로가 기본 업스트림으로 새 나가지 않는지. */
    fn invalid_client_route_cannot_leak_to_default_upstream() {
        let mut cfg = Config::default();
        cfg.clients.push(onetdns_config::ClientConfig {
            name: "restricted".to_string(),
            ids: vec!["192.0.2.1/32".parse().unwrap()],
            upstreams: vec!["invalid-upstream".to_string()],
            ..Default::default()
        });
        assert!(build_client_upstream_routes(&cfg, Duration::from_secs(1)).is_err());
    }

    #[test]
    /** @brief 잘못된 권한 표기가 관리자로 읽히지 않는지. */
    fn invalid_user_role_cannot_become_admin() {
        let mut cfg = Config::default();
        cfg.users.push(onetdns_config::UserConfig {
            name: "ops".to_string(),
            password_hash: "hash".into(),
            role: "administrator".to_string(),
        });
        assert!(build_user_creds(&cfg).is_err());
    }

    #[test]
    /** @brief 잘못된 공유 키가 조용히 사라지지 않는지. */
    fn invalid_tsig_key_cannot_disappear_silently() {
        let mut cfg = Config::default();
        cfg.tsig_keys.push(onetdns_config::TsigKeyConfig {
            name: "bad..key".to_string(),
            secret: "AAAAAAAAAAAAAAAAAAAAAA==".to_string().into(),
        });
        assert!(build_tsig_keys(&cfg).is_err());
    }

    /** @brief 언제나 막는 테스트용 제한기. */
    struct AlwaysThrottle;

    impl RateLimiter for AlwaysThrottle {
        /** @brief 언제나 막는다. */
        fn check(&self, _client: &onetdns_core::ClientInfo) -> onetdns_core::RateDecision {
            onetdns_core::RateDecision::Throttle
        }
    }

    #[test]
    /** @brief 접근 제어를 교체하면 아무것도 막지 않는지 판정도 함께 바뀌는지. */
    fn dynamic_acl_trivial_gate_tracks_hot_reload() {
        let acl = DynamicAccessControl::new(Arc::new(IpAcl::allow_all()));
        let client = onetdns_core::ClientInfo {
            source_ip: "192.0.2.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };

        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Allow);

        acl.replace(Arc::new(IpAcl::new(vec![], vec![], false)));
        assert!(!acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Deny);

        acl.replace(Arc::new(IpAcl::allow_all()));
        assert!(acl.is_trivially_allow());
        assert_eq!(acl.check(&client), onetdns_core::AclDecision::Allow);
    }

    #[test]
    /** @brief 제한기를 교체하면 걸렸는지 판정도 함께 바뀌는지. */
    fn dynamic_rate_limiter_tracks_empty_hot_reload() {
        let limiter = DynamicRateLimiter::new(vec![]);
        let client = onetdns_core::ClientInfo {
            source_ip: "192.0.2.1".parse().unwrap(),
            client_id: None,
            transport: onetdns_core::Transport::Do53Udp,
            authenticated: false,
        };

        assert_eq!(limiter.layer_count(), 0);
        assert!(!limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Permit);

        limiter.replace(vec![Arc::new(AlwaysThrottle)]);
        assert_eq!(limiter.layer_count(), 1);
        assert!(limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Throttle);

        limiter.replace(vec![]);
        assert_eq!(limiter.layer_count(), 0);
        assert!(!limiter.is_active());
        assert_eq!(limiter.check(&client), onetdns_core::RateDecision::Permit);
    }

    #[test]
    /** @brief 목록 순서가 바뀌어도 식별자가 그대로인지. */
    fn stable_resource_ids_do_not_depend_on_array_position() {
        let a1 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let a2 = stable_resource_id("upstream", "https://dns.example/dns-query");
        let b = stable_resource_id("upstream", "1.1.1.1");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert!(a1.starts_with("upstream-"));
    }

    #[test]
    /** @brief 토큰 식별자가 토큰 자체를 드러내지 않는지. */
    fn token_ids_are_stable_without_exposing_token_contents() {
        let first = token_id("secret-token-value");
        let same = token_id("secret-token-value");
        let other = token_id("different-token-value");
        assert_eq!(first, same);
        assert_ne!(first, other);
        assert!(first.starts_with("token-"));
        assert!(!first.contains("secret"));
    }

    #[test]
    /** @brief 일치하는 토큰이 없으면 본문을 고치지 않고 오류를 내는지. */
    fn removing_an_unknown_token_id_fails_without_touching_the_config() {
        let admin = "a".repeat(24);
        let ro = "b".repeat(24);
        let text =
            format!("control_admin_tokens = [\"{admin}\"]\ncontrol_readonly_tokens = [\"{ro}\"]\n");

        assert!(remove_token_by_id(&text, "token-없는-지문").is_err());

        let (out, removed) = remove_token_by_id(&text, &token_id(&ro)).unwrap();
        assert_eq!(removed, 1);
        assert!(out.contains(&admin));
        assert!(!out.contains(&ro));
    }

    #[test]
    /** @brief 실패한 설정 편집이 파일, 이전 스냅샷, 재시작 표식을 건드리지 않는지. */
    fn failed_config_edit_leaves_file_snapshot_and_reload_untouched() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-edit-noop-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&file_path, "cache_size = 4096\n").unwrap();
        let path = Some(file_path.clone());
        let prev: ConfigTextSlot = Arc::new(Mutex::new(None));
        let reload = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let result = apply_config_edit(&path, &prev, &reload, |_| {
            Err("일치하는 항목이 없습니다".to_string())
        });

        assert!(result.is_err());
        assert!(prev.lock_recover().is_none());
        assert!(!reload.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "cache_size = 4096\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    /** @brief 가려서 보여 준 값을 그대로 되돌려받으면 거부하는지. 저장하면 진짜 비밀이 덮인다. */
    fn config_patch_rejects_redacted_or_destructive_secret_placeholders() {
        use onetdns_core::json::Json;
        for pair in [
            (
                "zones_postgres",
                Json::Str("postgres://dns:***@localhost/zones".into()),
            ),
            (
                "zones_mysql",
                Json::Str("mysql://dns:<redacted>@localhost/zones".into()),
            ),
            ("cluster_raft_secret", Json::Str(String::new())),
            ("control_admin_tokens", Json::Arr(Vec::new())),
        ] {
            assert!(validate_config_patch_values(&[(pair.0.to_string(), pair.1)]).is_err());
        }
        assert!(validate_config_patch_values(&[(
            "zones_postgres".to_string(),
            Json::Str("postgres://dns:new-secret@localhost/zones".into()),
        )])
        .is_ok());
    }

    #[test]
    /** @brief 동시에 온 다른 변경이 사라지지 않는지. */
    fn runtime_config_updates_preserve_other_recent_changes() {
        let runtime = Arc::new(ArcSwap::from_pointee(Config::default()));
        update_runtime_config(&runtime, |config| config.safe_search = true);
        update_runtime_config(&runtime, |config| {
            config.blocked_services = vec!["youtube".to_string()];
        });
        let current = runtime.load();
        assert!(current.safe_search);
        assert_eq!(current.blocked_services, vec!["youtube".to_string()]);
    }

    #[test]
    /** @brief 재시작해야 할 변경이 교체로 가려지지 않는지. 가려지면 반영된 줄 안다. */
    fn pending_non_hot_file_change_cannot_be_hidden_by_a_hot_edit() {
        let active = Config::default();
        let mut proposed = active.clone();
        proposed.safe_search = !active.safe_search;
        proposed.run_as_user = Some("onetdns".to_string());

        let changed = config_changed_keys(&active, &proposed).unwrap();
        assert!(changed.contains(&"safe_search".to_string()));
        assert!(changed.contains(&"run_as_user".to_string()));
        assert!(changed
            .iter()
            .any(|key| !is_hot_reload_config_change(&active, &proposed, key)));
    }

    #[test]
    /** @brief 파일과 적용 중인 설정이 어긋나면 알리는지. */
    fn stored_and_active_config_diff_reports_runtime_mismatch() {
        let applied = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\ncache_size = 1000\n",
        )
        .unwrap();
        let desired = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\ncache_size = 2000\n",
        )
        .unwrap();
        let changed = config_changed_keys(&applied, &desired).unwrap();
        assert!(changed.contains(&"upstreams".to_string()));
        assert!(changed.contains(&"cache_size".to_string()));
        assert_eq!(changed.iter().filter(|key| *key == "upstreams").count(), 1);
    }

    #[test]
    /** @brief 지금 형식의 온전한 백업만 받는지. */
    fn control_backup_accepts_only_the_complete_current_format() {
        let current = r#"{"version":1,"block":["ads.example"],"allow":[],"services":["youtube"],"refused_domains":["internal.example"],"safe_search":true}"#;
        let parsed = parse_control_backup(current).unwrap();
        assert_eq!(parsed.0, ["ads.example"]);
        assert!(parsed.1.is_empty());
        assert_eq!(parsed.2, ["youtube"]);
        assert_eq!(parsed.3, ["internal.example"]);
        assert!(parsed.4);

        assert!(
            parse_control_backup(&current.replacen("\"version\":1", "\"version\":2", 1)).is_err()
        );
        assert!(parse_control_backup(&current.replacen(",\"allow\":[]", "", 1)).is_err());
        assert!(parse_control_backup(&current.replacen(
            ",\"refused_domains\":[\"internal.example\"]",
            "",
            1
        ))
        .is_err());
        assert!(parse_control_backup(&current.replacen(
            "\"block\":[\"ads.example\"]",
            "\"block\":[1]",
            1
        ))
        .is_err());
        assert!(parse_control_backup(&current.replacen("}", ",\"extra\":0}", 1)).is_err());
    }

    #[test]
    /** @brief 업스트림 성적이 저장됐다 읽히는지. */
    fn upstream_stats_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-upstat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(UPSTREAM_STATS_FILE);
        let reports = vec![onetdns_forward::UpstreamStatReport {
            label: "tls://dns.example".to_string(),
            queries: 42,
            ok: 40,
            fail: 2,
            ewma_ms: 12.3,
        }];
        save_upstream_stats(&path, &reports);
        let loaded = load_upstream_stats(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].label, "tls://dns.example");
        assert_eq!(loaded[0].queries, 42);
        assert_eq!(loaded[0].ok, 40);
        assert_eq!(loaded[0].fail, 2);
        assert!((loaded[0].ewma_ms - 12.3).abs() < 0.05);

        let current = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, current.replacen("\"version\":1", "\"version\":2", 1)).unwrap();
        assert!(load_upstream_stats(&path).is_empty());
        std::fs::write(
            &path,
            r#"{"version":1,"reports":[{"label":"x","queries":1,"ok":1,"fail":0}]}"#,
        )
        .unwrap();
        assert!(load_upstream_stats(&path).is_empty());

        assert!(load_upstream_stats(&dir.join("없는파일.json")).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /** @brief 사용자 규칙이 검사되고 종류가 갈리는지. */
    fn user_rule_mutation_validates_and_classifies() {
        let overlay: Mutex<(Vec<String>, Vec<String>)> = Mutex::new((vec![], vec![]));
        let rebuild = || Ok((0usize, 0usize));

        mutate_user_rule(&overlay, None, &rebuild, "@@||ok.example.com^", false, true).unwrap();
        {
            let ov = overlay.lock().unwrap();
            assert!(ov.0.is_empty(), "차단 목록은 비어 있어야 함");
            assert_eq!(ov.1, vec!["@@||ok.example.com^".to_string()]);
        }

        mutate_user_rule(&overlay, None, &rebuild, "||ads.example.com^", false, true).unwrap();
        assert_eq!(
            overlay.lock().unwrap().0,
            vec!["||ads.example.com^".to_string()]
        );

        let e = mutate_user_rule(
            &overlay,
            None,
            &rebuild,
            "||x.example.com^$app=org.example",
            false,
            true,
        )
        .unwrap_err();
        assert!(e.contains("app"), "사유에 수식어 이름 포함: {e}");

        mutate_user_rule(
            &overlay,
            None,
            &rebuild,
            "@@||ok.example.com^",
            false,
            false,
        )
        .unwrap();
        assert!(overlay.lock().unwrap().1.is_empty());
    }

    #[test]
    /** @brief 세대가 끝날 때 스레드가 모두 정리되는지. 남으면 다음 세대가 포트를 못 묶는다. */
    fn service_cleanup_signals_and_joins_tracked_threads() {
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let late_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleanup = ServiceCleanup::new(shutdown.clone());
        let tracker = cleanup.tracker();
        let worker_shutdown = shutdown.clone();
        let worker_finished = finished.clone();
        let worker_late_finished = late_finished.clone();
        cleanup.track(std::thread::spawn(move || {
            while !worker_shutdown.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(50));
            worker_finished.store(true, std::sync::atomic::Ordering::SeqCst);
            track_service_thread(
                &tracker,
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    worker_late_finished.store(true, std::sync::atomic::Ordering::SeqCst);
                }),
            );
        }));

        let started = std::time::Instant::now();
        drop(cleanup);
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
        assert!(late_finished.load(std::sync::atomic::Ordering::SeqCst));
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    /** @brief 정책 플러그인을 못 올렸을 때 그냥 통과시키지 않는지. */
    fn closed_wasm_policy_rejects_load_failures() {
        let missing = std::env::temp_dir().join(format!(
            "onetdns-missing-policy-{}-{}.wasm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            wasm_policy: Some(missing),
            wasm_fail_mode: "closed-refuse".to_string(),
            ..Config::default()
        };
        assert!(build_policy_engine(&config).is_err());

        config.wasm_fail_mode = "open".to_string();
        let engine = build_policy_engine(&config).expect("open 모드는 로드 실패를 허용");
        assert!(engine.is_empty());
    }

    #[test]
    /**
     * @brief 가려진 사용자 정보의 변화를 계정 변경이라고 짚어 내는지.
     * @details 뭉뚱그린 이름으로 두면 비밀번호를 한 번 바꿀 때마다 DNS 처리가 끊긴다.
     */
    fn stored_and_active_diff_detects_masked_user_changes() {
        let mut applied = Config::default();
        applied.users = vec![onetdns_config::UserConfig {
            name: "admin".to_string(),
            password_hash: "hash-a".into(),
            role: "admin".to_string(),
        }];
        let mut desired = applied.clone();
        desired.users[0].password_hash = "hash-b".into();
        let changed = config_changed_keys(&applied, &desired).unwrap();
        assert_eq!(changed, vec!["users".to_string()]);
    }

    #[test]
    /**
     * @brief 요약에 드러난 항목과 가려진 항목이 한 요청에서 함께 바뀌어도 둘 다 짚는지.
     * @details 가려진 항목을 놓치면 토큰을 교체한 요청이 적용된 것으로 보고되고 이전 토큰이
     *          계속 통한다.
     */
    fn masked_change_is_reported_alongside_a_visible_change() {
        let applied = Config {
            control_token: "control-token-a".into(),
            ..Config::default()
        };
        let mut desired = applied.clone();
        desired.control_token = "control-token-b".into();
        desired.cache_size = applied.cache_size + 1;
        let changed = config_changed_keys(&applied, &desired).unwrap();
        assert!(
            changed.contains(&"control_token".to_string()),
            "{changed:?}"
        );
        assert!(changed.contains(&"cache_size".to_string()), "{changed:?}");
    }

    #[test]
    /** @brief URL 하나를 빼도 남은 URL이 제 본문과 짝지어지는지. */
    fn rpz_texts_follow_their_url_after_removal() {
        let old_urls = vec!["https://a/".to_string(), "https://b/".to_string()];
        let old_texts = vec!["A".to_string(), "B".to_string()];
        assert_eq!(
            rpz_texts_by_url(&old_urls, &old_texts, &["https://b/".to_string()]),
            vec!["B".to_string()]
        );
        assert_eq!(
            rpz_texts_by_url(&old_urls, &old_texts, &["https://c/".to_string()]),
            vec![String::new()]
        );
        assert!(rpz_texts_by_url(&old_urls, &old_texts, &[]).is_empty());
    }

    #[test]
    /**
     * @brief 개수로 요약된 항목이 늘거나 줄어도 무중단 적용 대상으로 분류되는지.
     * @details 요약에 설정 키와 다른 이름을 쓰면 적용 경로가 그 이름을 몰라 서비스를 전부
     *          재시작한다.
     */
    fn counted_summary_keys_map_to_their_hot_groups() {
        let applied = Config::default();
        let mut desired = applied.clone();
        desired.policy.push(onetdns_config::PolicyRule {
            action: "block".into(),
            suffixes: vec!["example.com".into()],
            ..Default::default()
        });
        let changed = config_changed_keys(&applied, &desired).unwrap();
        assert_eq!(changed, vec!["policy".to_string()]);
        assert_eq!(config_keys::hot_group("policy"), Some(ApplyGroup::Policy));
    }

    #[test]
    /**
     * @brief 폐기 확인 설정이 업스트림 쪽 훅을 다시 설치하는 그룹으로 가는지.
     * @details 수신 인증서 그룹은 인증서 슬롯만 다시 읽는다. 그리로 가면 값은 저장되어도
     *          업스트림 연결은 이전 폐기 정책으로 검증된다.
     */
    fn revocation_keys_reinstall_the_upstream_hook() {
        for key in ["tls_revocation", "tls_revocation_softfail"] {
            assert!(config_keys::is_hot(key), "{key}");
            assert_eq!(
                config_keys::hot_group(key),
                Some(ApplyGroup::Revocation),
                "{key}"
            );
        }
    }

    #[test]
    /**
     * @brief 설정을 바꾸는 API가 검증 API와 같은 시작 전 검사를 거치는지.
     * @details 이 검사를 건너뛰면 검증 API는 거절하는 값이 파일에 저장되고, 다음에 재시작할
     *          때 서버가 뜨지 않는다.
     */
    fn config_edit_runs_runtime_preflight_before_writing() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-preflight-edit-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        let original = "listen = [\"127.0.0.1:15399\"]\n";
        std::fs::write(&path, original).unwrap();
        let hot_apply: HotConfigApply = Arc::new(|_, _| panic!("검사에 걸린 설정을 적용했습니다"));
        let result = apply_config_edit_smart(
            &Some(path.clone()),
            &Arc::new(Mutex::new(None)),
            &Arc::new(Mutex::new(None)),
            &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            &hot_apply,
            |text| {
                Ok(format!(
                    "{text}zones_postgres = \"postgres://dns:pw@10.1.2.3/zones\"\n"
                ))
            },
        );
        let written = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let error = result.expect_err("원격 PostgreSQL 주소는 거절해야 합니다");
        assert!(error.contains("zones_postgres"), "{error}");
        assert_eq!(written, original);
    }

    #[test]
    /**
     * @brief 질의마다 읽는 기능 값이 체인 재구성으로 가로채이지 않는지.
     * @details 분류는 체인 목록을 먼저 본다. 체인 목록에도 있으면 기능 세트가 갱신되지 않아
     *          무중단 변경이 저장만 되고 적용되지 않는다.
     */
    fn native_feature_keys_reach_the_native_group() {
        let previous = Config::default();
        for (key, next) in [
            (
                "deny_any",
                Config {
                    deny_any: !previous.deny_any,
                    ..Config::default()
                },
            ),
            (
                "minimal_responses",
                Config {
                    minimal_responses: !previous.minimal_responses,
                    ..Config::default()
                },
            ),
        ] {
            assert_eq!(
                config_keys::hot_group(key),
                Some(ApplyGroup::Native),
                "{key}"
            );
            let features = reconfigure_native_features(
                &native::NativeFeatures::default(),
                &next,
                &[key.to_string()],
            )
            .unwrap();
            assert!(
                features.allow_any != next.deny_any
                    && features.minimal_responses == next.minimal_responses,
                "{key}"
            );
        }
    }

    #[test]
    /** @brief 가려진 관리 토큰 값만 바뀌어도 토큰 변경으로 분류하는지. */
    fn stored_and_active_diff_detects_masked_control_token_changes() {
        let mut applied = Config {
            control_token: "control-token-a".into(),
            ..Config::default()
        };
        let mut desired = applied.clone();
        desired.control_token = "control-token-b".into();

        assert_eq!(
            config_changed_keys(&applied, &desired).unwrap(),
            vec!["control_token".to_string()]
        );

        applied.control_token = desired.control_token.clone();
        assert!(config_changed_keys(&applied, &desired).unwrap().is_empty());
    }

    #[test]
    /** @brief SQL URL의 비밀번호만 바뀌어도 감시를 교체하되 식별 키에는 원문을 남기지 않는지. */
    fn sql_source_credentials_are_redacted_and_change_source_identity() {
        let mut applied = Config {
            zones_postgres: Some("postgres://dns:old-postgres-secret@127.0.0.1/zones".into()),
            zones_mysql: Some("mysql://dns:old-mysql-secret@127.0.0.1/zones".into()),
            ..Config::default()
        };
        let old_keys: Vec<String> = zone_source_specs(&applied)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        for key in &old_keys {
            assert!(!key.contains("old-postgres-secret"));
            assert!(!key.contains("old-mysql-secret"));
        }

        let mut desired = applied.clone();
        desired.zones_postgres = Some("postgres://dns:new-postgres-secret@127.0.0.1/zones".into());
        desired.zones_mysql = Some("mysql://dns:new-mysql-secret@127.0.0.1/zones".into());
        let new_keys: Vec<String> = zone_source_specs(&desired)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_ne!(old_keys, new_keys, "자격증명 변경은 감시자를 교체한다");
        assert_eq!(
            config_changed_keys(&applied, &desired).unwrap(),
            vec!["zones_mysql".to_string(), "zones_postgres".to_string()]
        );

        applied.zones_postgres = desired.zones_postgres.clone();
        applied.zones_mysql = desired.zones_mysql.clone();
        assert!(config_changed_keys(&applied, &desired).unwrap().is_empty());
    }

    #[test]
    /**
     * @brief 값만 바뀐 비밀 목록이 제 이름으로 불리는지.
     *
     * @details 이 항목들은 요약에 개수나 이름만 실려, 값을 갈아도 개수가 같으면 비교에
     *          드러나지 않는다. 되돌려보기 목록에 없으면 포괄 이름이 붙는데 그 이름은 어느
     *          무중단 그룹에도 없어, 무중단으로 갈 수 있는 키 교체가 재시작이 된다.
     */
    fn rotating_a_secret_list_names_the_key_it_changed() {
        let mut applied = Config {
            control_admin_tokens: vec!["admin-old".into()],
            control_readonly_tokens: vec!["ro-old".into()],
            tsig_keys: vec![onetdns_config::TsigKeyConfig {
                name: "key1".to_string(),
                secret: "tsig-old".into(),
            }],
            ..Config::default()
        };

        for (label, mutate) in [
            (
                "control_admin_tokens",
                (|c: &mut Config| c.control_admin_tokens = vec!["admin-new".into()])
                    as fn(&mut Config),
            ),
            ("control_readonly_tokens", |c: &mut Config| {
                c.control_readonly_tokens = vec!["ro-new".into()]
            }),
            ("tsig_keys", |c: &mut Config| {
                c.tsig_keys = vec![onetdns_config::TsigKeyConfig {
                    name: "key1".to_string(),
                    secret: "tsig-new".into(),
                }]
            }),
        ] {
            let mut desired = applied.clone();
            mutate(&mut desired);
            assert_eq!(
                config_changed_keys(&applied, &desired).unwrap(),
                vec![label.to_string()],
                "{label}을 갈았는데 그 이름으로 불리지 않았습니다"
            );
            assert!(
                config_keys::is_hot(label) || label == "tsig_keys",
                "{label}은 무중단 그룹에 있어야 합니다"
            );
            mutate(&mut applied);
            assert!(
                config_changed_keys(&applied, &desired).unwrap().is_empty(),
                "{label}을 맞춘 뒤에는 달라진 것이 없어야 합니다"
            );
        }
    }

    #[test]
    /** @brief 플러그인마다 정한 실패 처분이 전체 설정을 이기는지. */
    fn per_plugin_fail_mode_overrides_global() {
        let missing = std::env::temp_dir().join(format!(
            "onetdns-missing-plugin-{}-{}.wasm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            wasm_fail_mode: "closed-refuse".to_string(),
            ..Config::default()
        };
        config.wasm_plugins = vec![onetdns_config::WasmPluginConfig {
            path: missing,
            name: None,
            fail_mode: Some("open".to_string()),
        }];
        build_policy_engine(&config).expect("항목별 open이 전역 closed보다 우선");

        config.wasm_plugins[0].fail_mode = None;
        assert!(
            build_policy_engine(&config).is_err(),
            "항목별 미지정 시 전역 closed 적용"
        );
    }

    #[test]
    /** @brief 파일이 깨졌을 때 적용 중인 설정으로 대신 보여 주지 않는지. */
    fn desired_config_reports_invalid_disk_file_instead_of_runtime_fallback() {
        let suffix = format!("{}-{}", std::process::id(), unix_now());
        let path = std::env::temp_dir().join(format!("onetdns-invalid-config-{suffix}.toml"));
        std::fs::write(&path, "backend = [broken").unwrap();
        let runtime =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();

        let desired = desired_config_json(Some(&path), &runtime);

        assert!(desired.contains("\"_valid\":false"));
        assert!(desired.contains("\"_source\":\"disk\""));
        assert!(!desired.contains("\"upstreams\":[\"1.1.1.1\"]"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    /** @brief 기본값으로 채운 것이 어긋남으로 보이지 않는지. */
    fn web_dashboard_default_listener_does_not_create_false_config_drift() {
        let desired = Config::from_toml_str("cache_size = 4096\n").unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let changed = config_changed_keys_for_status(&runtime, &desired).unwrap();
        assert!(
            changed.is_empty(),
            "runtime-only dashboard default: {changed:?}"
        );
    }

    #[test]
    /** @brief 제어 리스너를 뺀 것이 가려지지 않는지. */
    fn runtime_change_comparison_does_not_hide_control_listener_removal() {
        let desired = Config::from_toml_str("cache_size = 4096\n").unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let changed = config_changed_keys(&runtime, &desired).unwrap();
        assert!(
            changed.contains(&"control_listen".to_string()),
            "{changed:?}"
        );
    }

    #[test]
    /** @brief 제어 리스너를 바꾼 것은 그대로 알리는지. */
    fn explicit_control_listener_change_is_still_reported() {
        let desired = Config::from_toml_str(
            "control_listen = \"127.0.0.1:9553\"\ncontrol_token = \"unit-test-token-0123456789\"\n",
        )
        .unwrap();
        let mut runtime = desired.clone();
        runtime.control_listen = Some(SocketAddr::from(([127, 0, 0, 1], 8553)));

        let changed = config_changed_keys_for_status(&runtime, &desired).unwrap();
        assert!(
            changed.contains(&"control_listen".to_string()),
            "{changed:?}"
        );
    }

    #[test]
    /** @brief 파일과 적용 중인 설정의 차이를 찾아내는지. */
    fn config_status_detects_disk_runtime_divergence() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-cfg-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CONFIG_FILE_NAME);
        let base = "upstreams = [\"1.1.1.1\"]\ncache_size = 4096\n";
        std::fs::write(&path, base).unwrap();
        let runtime = Config::from_toml_str(base).unwrap();

        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":true"), "{status}");

        std::fs::write(&path, "upstreams = [\"1.1.1.1\"]\ncache_size = 8192\n").unwrap();
        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":false"), "{status}");
        assert!(status.contains("cache_size"), "{status}");

        std::fs::write(&path, "cache_size = [broken").unwrap();
        let status = config_status_json(Some(&path), &runtime);
        assert!(status.contains("\"in_sync\":false"), "{status}");
        assert!(status.contains("error"), "{status}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    /** @brief 플러그인 실패 처분 표기가 정책 쪽에서도 읽히는지. */
    fn config_wasm_fail_modes_parse_in_policy_crate() {
        for mode in ["open", "closed-block", "closed-refuse"] {
            let toml = format!(
                "upstreams = [\"1.1.1.1\"]\nwasm_plugins = [{{ path = \"a.wasm\", fail_mode = \"{mode}\" }}]\n"
            );
            onetdns_config::Config::from_toml_str(&toml)
                .unwrap_or_else(|e| panic!("config가 {mode} 거부: {e:?}"));
            onetdns_policy::FailureMode::parse(mode)
                .unwrap_or_else(|e| panic!("policy가 {mode} 거부: {e}"));
        }
    }

    /**
     * @brief 보조 영역이 실제로 쓰는 논블로킹 리스너로 전송 하나를 끝까지 받는다.
     * @details 테스트 전용 수신 경로를 따로 두면 그 경로만 검증되고 실제 리스너의 데드라인과
     *          검증은 테스트 밖에 남는다.
     */
    fn admitted_xfr(
        address: std::net::SocketAddr,
        origin: &str,
        current: Option<onetdns_authority::Zone>,
        timeout: Duration,
    ) -> Result<PreparedXfrIo, String> {
        let job = SecondaryRefreshJob {
            entry: XferEntry {
                origin: origin.to_string(),
                file: None,
                primary: address.ip(),
                port: address.port(),
                tsig_key: None,
                is_catalog: false,
            },
            current_serial: None,
            had_zone: current.is_some(),
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr: false,
        };
        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job, 1, current, &[], timeout)
            .map_err(|error| error.1.clone())?;
        let limit = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (mut ready, failed) = admission.poll();
            if let Some((_, error)) = failed.into_iter().next() {
                return Err(error);
            }
            if let Some(ready) = ready.pop() {
                return Ok(ready.io);
            }
            assert!(
                std::time::Instant::now() < limit,
                "전송이 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /** @brief 실제 리스너로 영역 전체를 받아 기록을 돌려준다. */
    fn axfr_fetch(
        address: std::net::SocketAddr,
        origin: &onetdns_proto::Name,
        timeout: Duration,
    ) -> Result<Vec<onetdns_proto::Record>, String> {
        let io = admitted_xfr(address, &origin.to_ascii_lower(), None, timeout)?;
        axfr_fetch_prepared(origin, None, io)
    }

    /** @brief 실제 리스너로 바뀐 부분을 받는다. */
    fn ixfr_fetch(
        address: std::net::SocketAddr,
        current: &onetdns_authority::Zone,
        timeout: Duration,
    ) -> Result<IxfrFetchResult, String> {
        let io = admitted_xfr(
            address,
            &current.origin().to_ascii_lower(),
            Some(current.clone()),
            timeout,
        )?;
        ixfr_fetch_prepared(current, None, io)
    }

    /** @brief 보조 영역이 실제로 쓰는 시리얼 확인기로 시리얼을 묻는다. */
    fn probe_soa_serial(
        address: std::net::SocketAddr,
        origin: &str,
        key: Option<onetdns_dnssec::tsig::TsigKey>,
    ) -> Result<u32, String> {
        let entry = XferEntry {
            origin: origin.to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: key.as_ref().map(|key| key.name.to_ascii_lower()),
            is_catalog: false,
        };
        let keys: Vec<_> = key.into_iter().collect();
        let mut prober = SecondarySoaProber::new(std::slice::from_ref(&entry)).unwrap();
        prober
            .start(
                SecondaryRefreshJob {
                    entry,
                    current_serial: None,
                    had_zone: false,
                    last_ok: unix_now(),
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    priority: true,
                    force_axfr: false,
                },
                &keys,
                Duration::from_secs(1),
            )
            .map_err(|error| error.1.clone())?;
        let limit = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(result) = prober.poll(&keys).pop() {
                return result.result;
            }
            assert!(
                std::time::Instant::now() < limit,
                "시리얼 확인이 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /**
     * @brief 테스트용 영역 전송 서버.
     *
     * @details 소켓 오류로는 패닉하지 않는다. 데드라인을 지키는지 보는 테스트는 클라이언트가
     *          먼저 포기하고 연결을 끊게 만드는데, 그때 이쪽에 오는 연결 초기화는
     *          정상 경로다. 그것을 치명적 오류로 다루면 부하가 걸린 병렬 실행에서만
     *          이따금 붉어지는 테스트가 되어, 진짜 회귀와 구별할 수 없게 된다.
     * @param complete 영역을 닫는 SOA 를 하나 더 보낼지.
     * @param slow 응답을 한 바이트씩 흘려 보낼지.
     * @return 수신 주소와 서버 스레드.
     */
    fn axfr_test_server(
        complete: bool,
        slow: bool,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let _ = (|| -> std::io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut length = [0u8; 2];
                stream.read_exact(&mut length)?;
                let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
                stream.read_exact(&mut request_wire)?;
                let request = onetdns_proto::Message::parse(&request_wire).unwrap();
                let origin = request.questions[0].name.clone();
                let mut response = onetdns_proto::Message::default();
                response.header.id = request.header.id;
                response.header.response = true;
                response.header.authoritative = true;
                response.questions = request.questions;
                let soa = onetdns_proto::Record::new(
                    origin,
                    60,
                    onetdns_proto::RData::soa(onetdns_proto::Soa {
                        mname: onetdns_proto::Name::from_str("ns1.example.test").unwrap(),
                        rname: onetdns_proto::Name::from_str("hostmaster.example.test").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86_400,
                        minimum: 60,
                    }),
                );
                response.answers.push(soa.clone());
                if complete {
                    response.answers.push(soa);
                }
                let wire = response.try_encode().unwrap();
                stream.write_all(&(wire.len() as u16).to_be_bytes())?;
                if slow {
                    for byte in wire {
                        if stream.write_all(&[byte]).is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                } else {
                    stream.write_all(&wire)?;
                }
                Ok(())
            })();
        });
        (address, server)
    }

    /** @brief 정해진 기록들을 보내는 테스트용 전송 서버. */
    fn xfr_record_server(
        records: Vec<onetdns_proto::Record>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers = records;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&wire).unwrap();
        });
        (address, server)
    }

    /** @brief 유효한 전송을 제한된 처리율로 보내는 테스트용 서버. */
    fn xfr_throttled_record_server(
        records: Vec<onetdns_proto::Record>,
        chunk_bytes: usize,
        pause: Duration,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers = records;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            for chunk in wire.chunks(chunk_bytes) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
                std::thread::sleep(pause);
            }
        });
        (address, server)
    }

    #[test]
    /** @brief 끝맺음이 없는 전송을 거부하는지. 받아들이면 중간에 끊긴 영역을 온전한 것으로 쓴다. */
    fn axfr_rejects_transfer_without_closing_soa() {
        let (address, server) = axfr_test_server(false, false);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let error = axfr_fetch(address, &origin, Duration::from_secs(1)).unwrap_err();
        assert!(error.contains("종료 SOA"));
        server.join().unwrap();
    }

    #[test]
    /** @brief 한 바이트씩 흘려 보내는 상대가 데드라인을 늘리지 못하는지. */
    fn axfr_slow_drip_cannot_extend_transfer_deadline() {
        let (address, server) = axfr_test_server(false, true);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let started = std::time::Instant::now();
        assert!(axfr_fetch(address, &origin, Duration::from_millis(120)).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief 최소 처리율만큼 실제로 읽어야 정확히 그만큼 시간을 버는지. */
    fn xfr_progress_deadline_credits_only_received_bytes() {
        let started = std::time::Instant::now();
        let mut deadline = XfrProgressDeadline::new(started, Duration::from_millis(120));
        assert!(deadline.expired(started + Duration::from_millis(120)));

        deadline.record_response_bytes(SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC as usize);
        assert!(!deadline.expired(started + Duration::from_millis(1_119)));
        assert!(deadline.expired(started + Duration::from_millis(1_120)));
    }

    #[test]
    /**
     * @brief 충분히 진전하는 큰 전송은 최초 데드라인보다 오래 걸려도 끝낼 수 있는지.
     *
     * @details 숫자에는 각각 이유가 있다. 전송 초반에는 적립된 바이트가 없어 예산이
     *          사실상 기본 시간뿐이므로, 부하가 걸린 기계에서 첫 바이트가 늦어도 견디도록
     *          기본 시간을 400밀리초로 둔다. 4KB를 40밀리초마다 흘리면 초당 약 102KB로,
     *          예산이 쌓이는 하한인 초당 16KB의 여섯 배다. 느린 기계에서 sleep이 늘어져
     *          공급이 느려져도 예산이 경과 시간을 앞선다. 레코드 수는 한 메시지가
     *          65535바이트를 넘지 않는 선에서 전송이 기본 시간을 넘기도록 정했다.
     * @warning 숫자를 줄이면 시험이 기본 시간 안에 끝나 아무것도 증명하지 못한다.
     *          아래의 경과 시간 단언이 그 경우를 잡는다.
     */
    fn axfr_progress_extends_the_total_deadline() {
        use onetdns_proto::{Name, RData, Record, Soa};

        let origin = Name::from_str("progress-xfr.test").unwrap();
        let soa = Record::new(
            origin.clone(),
            60,
            RData::soa(Soa {
                mname: Name::from_str("ns.progress-xfr.test").unwrap(),
                rname: Name::from_str("hostmaster.progress-xfr.test").unwrap(),
                serial: 1,
                refresh: 300,
                retry: 60,
                expire: 86_400,
                minimum: 60,
            }),
        );
        let mut records = Vec::with_capacity(2_804);
        records.push(soa.clone());
        records.push(Record::new(
            origin.clone(),
            60,
            RData::Ns(Name::from_str("ns.progress-xfr.test").unwrap()),
        ));
        records.push(Record::new(
            Name::from_str("ns.progress-xfr.test").unwrap(),
            60,
            RData::A("192.0.2.53".parse().unwrap()),
        ));
        for index in 0..2_800 {
            records.push(Record::new(
                Name::from_str(&format!("r{index}.progress-xfr.test")).unwrap(),
                60,
                RData::A("192.0.2.1".parse().unwrap()),
            ));
        }
        records.push(soa);

        let (address, server) =
            xfr_throttled_record_server(records, 4_096, Duration::from_millis(40));
        let entry = XferEntry {
            origin: origin.to_ascii_lower(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let job = SecondaryRefreshJob {
            entry,
            current_serial: None,
            had_zone: false,
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr: false,
        };
        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job, 1, None, &[], Duration::from_millis(400))
            .map_err(|error| error.1.clone())
            .unwrap();
        let started = std::time::Instant::now();
        let prepared = loop {
            let (mut ready, failed) = admission.poll();
            if let Some((_, error)) = failed.into_iter().next() {
                panic!("진전 중인 XFR가 실패했습니다: {error}");
            }
            if let Some(ready) = ready.pop() {
                break ready;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "진전 중인 XFR가 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        server.join().unwrap();
        assert!(
            started.elapsed() > Duration::from_millis(400),
            "전송이 기본 시간 안에 끝나 진전 연장을 증명하지 못했습니다"
        );
        let PreparedSecondaryXfr {
            job,
            remote_serial,
            current,
            io,
            reservation,
        } = prepared;
        let outcome = run_prepared_secondary_transfer(
            &job.entry,
            current.as_ref(),
            remote_serial,
            &[],
            io,
            reservation,
        )
        .expect("실제 바이트가 충분히 들어오면 전체 데드라인이 진전에 비례해야 합니다");
        assert!(matches!(
            outcome,
            SecondaryXferOutcome::Zone(zone, SecondaryXferKind::Axfr)
                if zone.soa().serial == 1 && zone.axfr_records().len() == 2_804
        ));
    }

    #[test]
    /** @brief 처음과 끝이 맞는 전송을 받아들이는지. */
    fn axfr_accepts_matching_opening_and_closing_soa() {
        let (address, server) = axfr_test_server(true, false);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let records = axfr_fetch(address, &origin, Duration::from_secs(1)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records.first(), records.last());
        server.join().unwrap();
    }

    #[test]
    /** @brief 변경을 순서대로 적용하고, 없는 기록을 지우라면 거부하는지. */
    fn ixfr_client_applies_ordered_deltas_and_rejects_impossible_delete() {
        use onetdns_proto::{Name, RData, Record, Soa};
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-client.test.\n@ IN SOA ns admin 10 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nold IN A 192.0.2.10\n",
            "ix-client.test",
        )
        .unwrap();
        let origin = current.origin().clone();
        let soa = |serial| {
            Record::new(
                origin.clone(),
                300,
                RData::soa(Soa {
                    mname: Name::from_str("ns.ix-client.test").unwrap(),
                    rname: Name::from_str("admin.ix-client.test").unwrap(),
                    serial,
                    refresh: 300,
                    retry: 60,
                    expire: 86400,
                    minimum: 60,
                }),
            )
        };
        let old = Record::new(
            Name::from_str("old.ix-client.test").unwrap(),
            300,
            RData::A("192.0.2.10".parse().unwrap()),
        );
        let middle = Record::new(
            Name::from_str("middle.ix-client.test").unwrap(),
            120,
            RData::A("192.0.2.11".parse().unwrap()),
        );
        let final_record = Record::new(
            Name::from_str("final.ix-client.test").unwrap(),
            60,
            RData::A("192.0.2.12".parse().unwrap()),
        );
        let (address, server) = xfr_record_server(vec![
            soa(12),
            soa(10),
            old,
            soa(11),
            middle.clone(),
            soa(11),
            soa(12),
            final_record.clone(),
            soa(12),
        ]);
        let updated = match ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap() {
            IxfrFetchResult::Incremental(zone) => zone,
            _ => panic!("incremental IXFR 기대"),
        };
        server.join().unwrap();
        assert_eq!(updated.soa().serial, 12);
        assert!(updated
            .query(&middle.name, middle.rtype)
            .answers
            .iter()
            .any(|record| xfr_rr_equal(record, &middle)));
        assert!(updated
            .query(&final_record.name, final_record.rtype)
            .answers
            .iter()
            .any(|record| xfr_rr_equal(record, &final_record)));
        assert!(updated
            .query(
                &Name::from_str("old.ix-client.test").unwrap(),
                onetdns_proto::RecordType::A
            )
            .answers
            .is_empty());

        let missing = Record::new(
            Name::from_str("missing.ix-client.test").unwrap(),
            300,
            RData::A("192.0.2.99".parse().unwrap()),
        );
        let (address, server) =
            xfr_record_server(vec![soa(11), soa(10), missing, soa(11), soa(11)]);
        assert!(ixfr_fetch(address, &current, Duration::from_secs(1)).is_err());
        server.join().unwrap();
        assert_eq!(
            current.soa().serial,
            10,
            "실패한 delta는 원본 zone을 변경하지 않음"
        );
    }

    #[test]
    /** @brief 바뀐 것이 없을 때와 전체가 온 것을 모두 다루는지. */
    fn ixfr_client_handles_unchanged_and_full_fallback() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-fallback.test.\n@ IN SOA ns admin 20 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-fallback.test",
        )
        .unwrap();
        let current_soa = current.axfr_records()[0].clone();
        let (address, server) = xfr_record_server(vec![current_soa]);
        assert!(matches!(
            ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap(),
            IxfrFetchResult::Unchanged
        ));
        server.join().unwrap();

        let replacement = onetdns_authority::parse_zone(
            "$ORIGIN ix-fallback.test.\n@ IN SOA ns admin 21 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nnew IN A 192.0.2.21\n",
            "ix-fallback.test",
        )
        .unwrap();
        let (address, server) = xfr_record_server(replacement.axfr_records());
        let fetched = ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        assert!(matches!(fetched, IxfrFetchResult::Full(zone) if zone.soa().serial == 21));
    }

    /** @brief 정해진 응답 코드를 내는 테스트용 전송 서버. */
    fn xfr_rcode_server(rcode: u16) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.header.rcode = rcode;
            response.questions = request.questions;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&wire).unwrap();
        });
        (address, server)
    }

    /** @brief 응답 하나를 받아 둔 테스트용 전송. */
    fn prepared_xfr_io(
        address: std::net::SocketAddr,
        query: onetdns_proto::Message,
    ) -> (PreparedXfrIo, XfrBufferReservation) {
        use std::io::{Read, Write};
        let encoded = encode_xfr_request(query, None).unwrap();
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream.write_all(&encoded.framed_wire).unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).unwrap();
        let mut first_message = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut first_message).unwrap();
        let budget = Arc::new(XfrBufferBudget::new(usize::MAX));
        let mut reservation = budget.reservation();
        assert!(reservation.try_grow(first_message.len() + SECONDARY_XFR_FRAME_OVERHEAD_BYTES));
        (
            PreparedXfrIo {
                query: encoded.query,
                request_mac: encoded.request_mac,
                messages: vec![first_message.into_boxed_slice()],
            },
            reservation,
        )
    }

    #[test]
    /** @brief 사유를 만드는 쪽과 판별하는 쪽이 같은 문구를 보는지. 어긋나면 전체를 받아 오는 길이 막힌다. */
    fn ixfr_notimp_error_text_matches_the_axfr_fallback_predicate() {
        assert!(xfr_error_is_notimp(&xfr_rcode_error(
            onetdns_proto::ResponseCode::NotImp.0
        )));
        assert!(!xfr_error_is_notimp(&xfr_rcode_error(
            onetdns_proto::ResponseCode::Refused.0
        )));
    }

    #[test]
    /** @brief 바뀐 부분만 못 받으면 전체를 달라고 하는지. */
    fn ixfr_notimp_asks_the_coordinator_for_a_full_transfer() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-notimp.test.\n@ IN SOA ns admin 30 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-notimp.test",
        )
        .unwrap();
        let (address, server) = xfr_rcode_server(onetdns_proto::ResponseCode::NotImp.0);
        let entry = XferEntry {
            origin: "ix-notimp.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let (prepared, reservation) = prepared_xfr_io(address, build_ixfr_query(&current).unwrap());
        let outcome =
            run_prepared_secondary_transfer(&entry, Some(&current), 31, &[], prepared, reservation)
                .unwrap();
        server.join().unwrap();
        assert!(matches!(
            outcome,
            SecondaryXferOutcome::NeedsFullTransfer { remote_serial: 31 }
        ));
    }

    #[test]
    /** @brief 전부 다시 받을 때 이전 영역을 기준으로 삼지 않는지. */
    fn forced_axfr_retry_ignores_the_ixfr_base_zone() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-forced.test.\n@ IN SOA ns admin 40 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-forced.test",
        )
        .unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let entry = XferEntry {
            origin: "ix-forced.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let job = |force_axfr| SecondaryRefreshJob {
            entry: entry.clone(),
            current_serial: Some(40),
            had_zone: true,
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr,
        };

        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(
                job(false),
                41,
                Some(current.clone()),
                &[],
                Duration::from_millis(50),
            )
            .map_err(|error| error.1.clone())
            .unwrap();
        assert_eq!(
            admission.pending[0].query.questions[0].qtype,
            onetdns_proto::RecordType(251),
            "force_axfr가 없으면 IXFR로 묻는다"
        );
        assert!(admission.pending[0].current.is_some());

        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job(true), 41, Some(current), &[], Duration::from_millis(50))
            .map_err(|error| error.1.clone())
            .unwrap();
        assert_eq!(
            admission.pending[0].query.questions[0].qtype,
            onetdns_proto::RecordType(252),
            "force_axfr면 AXFR로 묻는다"
        );
        assert!(
            admission.pending[0].current.is_none(),
            "기준 영역을 버려야 응답 해석도 AXFR 경로로 간다"
        );
    }

    #[test]
    /** @brief 새 설정으로 못 뜨면 마지막으로 성공한 설정으로 한 번 되돌리는지. */
    fn failed_restart_restores_last_applied_config_once() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-config-recovery-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&path, "listen = [\"127.0.0.1:1\"]\n").unwrap();
        let shared = ServeShared::default();
        *shared.applied_config_text.lock_recover() = Some("listen = [\"127.0.0.1:0\"]\n".into());

        assert!(restore_last_applied_config(Some(&path), &shared).unwrap());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "listen = [\"127.0.0.1:0\"]\n"
        );
        assert!(!restore_last_applied_config(Some(&path), &shared).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    /** @brief 리스너 하나라도 못 묶으면 이미 묶은 포트를 놓아주는지. 안 놓으면 다음 시도도 실패한다. */
    fn partial_listener_failure_releases_previously_bound_port() {
        let first_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let first_addr = first_probe.local_addr().unwrap();
        drop(first_probe);

        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let mut cfg = Config::default();
        cfg.listen = vec![first_addr, occupied_addr];
        cfg.do_udp = false;
        cfg.do_tcp = true;
        cfg.workers = 1;

        let result = serve(cfg, None, None, Default::default(), None, None);
        assert!(result.is_err(), "second occupied listener must fail");
        let rebound = std::net::TcpListener::bind(first_addr)
            .expect("first listener must be released after partial startup failure");
        drop(rebound);
        drop(occupied);
    }

    #[test]
    /** @brief 제어 포트가 이미 쓰이면 준비됐다고 알리기 전에 실패하는지. */
    fn occupied_control_listener_fails_before_readiness() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let mut cfg = Config::default();
        cfg.control_listen = Some(occupied_addr);
        cfg.listen = vec!["127.0.0.1:0".parse().unwrap()];
        cfg.workers = 1;

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready_callback = ready.clone();
        let result = serve(
            cfg,
            None,
            None,
            Default::default(),
            None,
            Some(Box::new(move || {
                ready_callback.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        assert!(result.is_err());
        assert!(!ready.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    /** @brief 켜 둔 TFTP 포트가 이미 쓰이면 준비 전에 실패하는지. */
    fn occupied_enabled_tftp_listener_fails_before_readiness() {
        let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let root = std::env::temp_dir().join(format!(
            "onetdns-tftp-startup-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let mut cfg = Config::default();
        cfg.tftp_enable = true;
        cfg.tftp_root = Some(root.display().to_string());
        cfg.tftp_listen = occupied_addr;
        cfg.listen = vec!["127.0.0.1:0".parse().unwrap()];
        cfg.workers = 1;

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready_callback = ready.clone();
        let result = serve(
            cfg,
            None,
            None,
            Default::default(),
            None,
            Some(Box::new(move || {
                ready_callback.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        assert!(result.is_err());
        assert!(!ready.load(std::sync::atomic::Ordering::SeqCst));
        drop(occupied);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    /** @brief 클러스터로 비밀을 퍼뜨리지 못하는지. 퍼뜨리면 모든 노드가 같은 키를 쓴다. */
    fn raft_config_patch_rejects_secret_material() {
        for key in [
            "cluster_raft_secret",
            "control_token",
            "control_admin_tokens",
            "control_readonly_tokens",
            "tsig_keys",
            "users",
            "zones_etcd_password",
            "zones_postgres",
            "zones_mysql",
        ] {
            let patch =
                onetdns_core::json::parse(&format!(r#"{{"{key}":"secret"}}"#)).expect("valid JSON");
            assert!(validate_raft_patch_scope(&patch).is_err(), "{key}");
        }
        let safe = onetdns_core::json::parse(r#"{"cache_size":4096}"#).unwrap();
        assert!(validate_raft_patch_scope(&safe).is_ok());
    }

    #[test]
    /** @brief 노드마다 달라야 하는 설정을 퍼뜨리지 못하는지. */
    fn raft_config_patch_rejects_node_local_identity() {
        for key in [
            "cluster_node_id",
            "cluster_raft_listen",
            "cluster_raft_peers",
            "cluster_raft_node_key",
        ] {
            let patch = onetdns_core::json::Json::Obj(vec![(
                key.to_string(),
                onetdns_core::json::Json::Str("replacement".into()),
            )]);
            assert!(validate_raft_patch_scope(&patch).is_err(), "{key}");
        }
    }

    #[test]
    /** @brief 설정 스냅숏이 형을 지키며 작게 담기고, 나중 것이 이기는지. */
    fn raft_config_snapshot_is_compact_typed_and_last_write_wins() {
        let mut state = RaftConfigSnapshot::default();
        state
            .merge_command(br#"{"patch":{"cache_size":1024,"mode":"personal"}}"#)
            .unwrap();
        state
            .merge_command(
                br#"{"patch":{"cache_size":4096,"blocklist_urls":["https://example.test/a"]}}"#,
            )
            .unwrap();

        let encoded = state.encode().unwrap();
        assert!(encoded.len() < 512, "최신 값만 보유해 로그보다 작아야 함");
        let decoded = RaftConfigSnapshot::decode(&encoded).unwrap();
        assert_eq!(
            decoded.values.get("cache_size"),
            Some(&onetdns_core::json::Json::Num(4096.0))
        );
        assert!(decoded.values.contains_key("mode"));
        assert!(decoded.values.contains_key("acl_allow"));
        assert!(decoded.values.contains_key("blocklist_urls"));
        assert_eq!(
            decoded.encode().unwrap(),
            encoded,
            "정렬된 canonical 인코딩"
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(RaftConfigSnapshot::decode(&trailing).is_err());
    }

    /** @brief 테이블 배열과 노드별 설정이 섞인 설정 파일. 클러스터 복제 테스트가 함께 쓴다. */
    const CLUSTER_FIXTURE: &str = "listen = [\"127.0.0.1:53\"]\ncontrol_listen = \"127.0.0.1:8080\"\nblock_rules = [\"ads.example\"]\ncache_size = 4096\nsafe_browsing = true\n\n[[clients]]\nname = \"kid \\\"room\\\"\"\nids = [\"192.0.2.0/24\"]\nblock = [\"games.example\"]\nsafe_search = true\n\n[[local_zones]]\nname = \"lan\"\nkind = \"static\"\nrecords = [\"nas.lan 192.0.2.10\", \"lan 192.0.2.1\"]\n\n[[rewrites]]\ndomain = \"rw.example\"\nanswer = \"192.0.2.53\"\n";

    #[test]
    /**
     * @brief 공유 설정이 로그 항목과 스냅숏을 거쳐 다른 노드에 같은 값으로 기록되는지.
     * @details 테이블 배열은 인라인 테이블로 기록되므로 파일 모양은 달라지지만 파싱한 값은 같아야 한다.
     *          노드별 설정은 옮겨지지 않고 받는 노드의 값이 남아야 한다.
     */
    fn cluster_changes_replay_to_identical_values_on_another_node() {
        let changes = cluster_config_changes("", CLUSTER_FIXTURE).unwrap();
        let keys: Vec<&str> = changes.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "block_rules",
                "cache_size",
                "clients",
                "local_zones",
                "rewrites",
                "safe_browsing"
            ]
        );

        let command = onetdns_core::json::Json::Obj(vec![(
            "patch".to_string(),
            onetdns_core::json::Json::Obj(changes),
        )])
        .to_text();
        let patch = decode_raft_command_patch(command.as_bytes()).unwrap();
        let mut snapshot = RaftConfigSnapshot::default();
        snapshot.merge_command(command.as_bytes()).unwrap();
        let restored = RaftConfigSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(restored.patch(), snapshot.patch());

        let follower = "listen = [\"127.0.0.1:5353\"]\ncontrol_listen = \"127.0.0.1:9090\"\n";
        let mut replayed = follower.to_string();
        for (key, value) in &patch {
            replayed = rewrite_config_kv(
                &replayed,
                key,
                &json_to_raft_toml_literal(value, 0).unwrap(),
            )
            .unwrap();
        }
        Config::from_toml_str(&replayed).unwrap();
        assert!(cluster_config_changes(CLUSTER_FIXTURE, &replayed)
            .unwrap()
            .is_empty());
        let replayed = onetdns_config::toml::parse(&replayed).unwrap();
        assert_eq!(
            replayed
                .get("listen")
                .and_then(|v| v.as_array())
                .map(|v| v.len()),
            Some(1)
        );
        assert_eq!(
            replayed.get("control_listen").and_then(|v| v.as_str()),
            Some("127.0.0.1:9090")
        );
    }

    #[test]
    /** @brief 지운 설정이 null 로 합의되고, 받는 노드에서도 지워지는지. */
    fn cluster_changes_carry_removed_keys_as_null() {
        let after = CLUSTER_FIXTURE.replace("safe_browsing = true\n", "");
        let changes = cluster_config_changes(CLUSTER_FIXTURE, &after).unwrap();
        assert_eq!(
            changes,
            vec![("safe_browsing".to_string(), onetdns_core::json::Json::Null)]
        );
        let mut snapshot = RaftConfigSnapshot::default();
        snapshot
            .merge_command(br#"{"patch":{"safe_browsing":null}}"#)
            .unwrap();
        let restored = RaftConfigSnapshot::decode(&snapshot.encode().unwrap()).unwrap();
        assert_eq!(
            restored.values.get("safe_browsing"),
            Some(&onetdns_core::json::Json::Null)
        );
    }

    #[test]
    /** @brief 스냅숏이 null 을 값 안에 두거나 한도보다 깊은 값을 받지 않는지. */
    fn raft_snapshot_rejects_nested_null_and_excessive_depth() {
        use onetdns_core::json::Json;
        let mut out = Vec::new();
        assert!(encode_raft_snapshot_value(&Json::Arr(vec![Json::Null]), &mut out, 0).is_err());
        let mut deep = Json::Bool(true);
        for _ in 0..=MAX_RAFT_VALUE_DEPTH {
            deep = Json::Arr(vec![deep]);
        }
        assert!(encode_raft_snapshot_value(&deep, &mut Vec::new(), 0).is_err());
        assert!(json_to_raft_toml_literal(&deep, 0).is_err());

        let mut bytes = Vec::new();
        for _ in 0..=MAX_RAFT_VALUE_DEPTH {
            bytes.push(5);
            bytes.extend_from_slice(&1u32.to_be_bytes());
        }
        bytes.push(2);
        assert!(decode_raft_snapshot_value(&bytes, &mut 0, 0).is_err());
    }

    #[test]
    /** @brief 노드별 설정은 복제에서 빠지고, 서비스 동작을 정하는 설정은 복제되는지. */
    fn cluster_local_keys_cover_identity_secrets_and_paths_only() {
        for key in [
            "listen",
            "listen_doh",
            "control_token",
            "control_admin_tokens",
            "users",
            "tsig_keys",
            "cluster_raft_secret",
            "cluster_node_id",
            "tls_cert",
            "acme_domains",
            "dhcp_enable",
            "dhcp6_range_start",
            "ra_prefix",
            "tftp_root",
            "zones",
            "zones_postgres",
            "blocklists",
            "querylog_file",
            "nsid",
        ] {
            assert!(config_keys::node_local(key), "{key}");
        }
        for key in [
            "mode",
            "block_rules",
            "blocklist_urls",
            "clients",
            "local_zones",
            "rewrites",
            "upstreams",
            "safe_browsing",
            "block_response",
            "acl_allow",
        ] {
            assert!(!config_keys::node_local(key), "{key}");
        }
    }

    #[test]
    /** @brief 팔로워가 노드별 설정 편집만 받고 클러스터 설정 편집은 처리 전에 거절하는지. */
    fn cluster_follower_rejects_only_shared_config_writes() {
        assert!(cluster_follower_must_reject("/v1/block", ""));
        assert!(cluster_follower_must_reject(
            "/v1/config/set",
            r#"{"listen":["127.0.0.1:53"],"cache_size":1}"#
        ));
        assert!(!cluster_follower_must_reject(
            "/v1/config/set",
            r#"{"listen":["127.0.0.1:53"]}"#
        ));
        assert!(cluster_follower_must_reject(
            "/v1/config/apply",
            "[[clients]]\nname = \"a\"\n"
        ));
        assert!(!cluster_follower_must_reject(
            "/v1/config/apply",
            "tls_cert = \"a.pem\"\n"
        ));
        assert!(!cluster_follower_must_reject("/v1/cache/flush", ""));
        assert!(!cluster_follower_must_reject(
            "/v1/filter/subscriptions/refresh",
            ""
        ));
    }

    #[test]
    /** @brief 서명 키에서 구한 공개 키와 피어 항목이 상태 JSON에 담기는지. */
    fn cluster_status_shows_the_node_public_key_and_peer_entry() {
        let mut config = Config::default();
        config.cluster_node_id = 2;
        config.cluster_raft_listen = Some("10.0.0.2:7100".into());
        /* Ed25519 표준 테스트 벡터의 첫 번째 시드와 공개 키다. */
        config.cluster_raft_node_key =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60".into();
        let status = with_raft_identity(&standalone_cluster_status_json("forward", 1), &config);
        let json = onetdns_core::json::parse(&status).unwrap();
        let identity = json.get("identity").unwrap();
        let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert_eq!(
            identity.get("public_key").and_then(|v| v.as_str()),
            Some(key)
        );
        assert_eq!(
            identity.get("peer_entry").and_then(|v| v.as_str()),
            Some(format!("2@10.0.0.2:7100#{key}").as_str())
        );
        assert!(json.get("self").is_some());

        config.cluster_raft_node_key = "not-hex".into();
        let status = with_raft_identity(&standalone_cluster_status_json("forward", 1), &config);
        let json = onetdns_core::json::parse(&status).unwrap();
        assert_eq!(
            json.get("identity").and_then(|v| v.get("public_key")),
            Some(&onetdns_core::json::Json::Null)
        );
    }

    #[test]
    /** @brief 지금 형식의 제안만 받는지. */
    fn cluster_proposal_accepts_only_the_current_patch_envelope() {
        assert!(parse_cluster_proposal(r#"{"patch":{"cache_size":4096}}"#).is_ok());
        for invalid in [
            r#"{"cache_size":4096}"#,
            r#"{"op":"config_set","patch":{"cache_size":4096}}"#,
            r#"{"patch":{}}"#,
            r#"{"patch":[],"extra":true}"#,
            r#"{"patch":{"cache_size":4096},"extra":true}"#,
        ] {
            assert!(parse_cluster_proposal(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    /** @brief 클러스터가 정한 설정도 교체로 반영되는지. */
    fn raft_config_patch_uses_hot_apply_without_restart() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-hot-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&file_path, "blocked_response_ttl = 10\n").unwrap();
        let path = Some(file_path.clone());
        let previous = Arc::new(Mutex::new(None));
        let applied = Arc::new(Mutex::new(None));
        let reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hot_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = hot_called.clone();
        let hot_apply: HotConfigApply = Arc::new(move |next, changed| {
            assert_eq!(next.blocked_response_ttl, 11);
            assert_eq!(changed, ["blocked_response_ttl"]);
            called.store(true, std::sync::atomic::Ordering::Release);
            Ok((true, changed.to_vec()))
        });

        let context = RaftApplyContext::new(
            path,
            previous,
            applied.clone(),
            RaftGenerationApply {
                reload: reload.clone(),
                hot_apply: Some(hot_apply),
            },
        );
        context
            .apply_command(br#"{"patch":{"blocked_response_ttl":11}}"#)
            .unwrap();

        assert!(hot_called.load(std::sync::atomic::Ordering::Acquire));
        assert!(!reload.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            applied.lock().unwrap().as_deref(),
            Some("blocked_response_ttl = 11\n")
        );
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "blocked_response_ttl = 11\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    /** @brief 세대가 바뀌는 사이 온 변경이 사라지지 않는지. */
    fn raft_generation_switch_cannot_lose_a_concurrent_restart_change() {
        let file_path = std::env::temp_dir().join(format!(
            "onetdns-raft-generation-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        /** @brief 테스트 시작 설정. */
        const INITIAL: &str = "cache_size = 4096\n";
        std::fs::write(&file_path, INITIAL).unwrap();
        let old_reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let new_reload = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let restart_apply: HotConfigApply = Arc::new(|_, changed| Ok((false, changed.to_vec())));
        let context = Arc::new(RaftApplyContext::new(
            Some(file_path.clone()),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            RaftGenerationApply {
                reload: old_reload,
                hot_apply: Some(restart_apply.clone()),
            },
        ));
        let applier = {
            let context = context.clone();
            std::thread::spawn(move || context.apply_command(br#"{"patch":{"cache_size":8192}}"#))
        };

        context
            .install_generation(
                Some(INITIAL),
                RaftGenerationApply {
                    reload: new_reload.clone(),
                    hot_apply: Some(restart_apply),
                },
            )
            .unwrap();
        applier.join().unwrap().unwrap();

        assert!(
            new_reload.load(std::sync::atomic::Ordering::Acquire),
            "적용이 전환 전이면 파일 차이를 감지하고, 전환 후면 새 콜백을 깨워야 합니다"
        );
        assert_eq!(
            std::fs::read_to_string(&file_path).unwrap(),
            "cache_size = 8192\n"
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    /** @brief 영역 이름으로 경로를 벗어나지 못하는지. 벗어나면 아무 파일이나 덮는다. */
    fn safe_zone_key_rejects_path_traversal() {
        assert_eq!(safe_zone_key("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            safe_zone_key("1.0.0.127.in-addr.arpa").unwrap(),
            "1.0.0.127.in-addr.arpa"
        );
        assert_eq!(
            safe_zone_key("xn--80ak6aa92e.com").unwrap(),
            "xn--80ak6aa92e.com"
        );

        for bad in [
            "/tmp/pwn",
            "..",
            "../../etc/passwd",
            "a/b",
            "a\\b",
            "c:\\windows\\temp\\x",
            "evil/../zone",
            "%2e%2e",
            "a/.zone",
            "",
            ".",
        ] {
            assert!(safe_zone_key(bad).is_err(), "{bad} 는 거부되어야 함");
        }
    }

    #[test]
    /** @brief 목록 주소가 겹치지 않고 순서를 지키는지. */
    fn active_subscription_urls_are_unique_and_keep_order() {
        let urls = vec![
            "https://big.oisd.nl".to_string(),
            "https://big.oisd.nl".to_string(),
            "https://example.test/list.txt".to_string(),
        ];
        let disabled = vec!["https://example.test/list.txt".to_string()];
        let presets = vec![
            "https://big.oisd.nl".to_string(),
            "https://preset.test/list.txt".to_string(),
        ];
        assert_eq!(
            active_subscription_urls(&urls, &disabled, &presets),
            vec![
                "https://big.oisd.nl".to_string(),
                "https://preset.test/list.txt".to_string(),
            ]
        );
    }

    #[test]
    /** @brief 목록을 받을 때 자기 자신에게 묻지 않는지. 물으면 시작 중 순환이 된다. */
    fn blocklist_bootstrap_never_uses_loopback_dns() {
        let mut config = Config::default();
        config.bootstrap = vec![
            "127.0.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        assert_eq!(
            blocklist_bootstrap(&config),
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    /**
     * @brief 목록 다운로드용 이름 리졸버를 만드는 키가 모두 리졸버를 다시 만드는 그룹에 드는지.
     * @details 그룹에서 빠지면 그 키를 실행 중에 바꿔도 목록과 인증서 폐기 정보는 계속 이전
     *          서버로 이름을 찾는다.
     */
    fn blocklist_resolver_inputs_rebuild_the_resolver_when_changed() {
        for key in ["bootstrap", "upstreams", "root_hints", "max_ttl"] {
            assert!(
                matches!(
                    config_keys::hot_group(key),
                    Some(ApplyGroup::Chain | ApplyGroup::Forward)
                ),
                "{key}"
            );
        }
    }

    #[test]
    /** @brief 모든 주소에 묶었을 때 이 기계를 가리키는 이름 해석 출처를 거부하는지. */
    fn wildcard_listener_rejects_local_interface_resolution_sources() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if socket.connect("192.0.2.1:9").is_err() {
            return;
        }
        let local_ip = socket.local_addr().unwrap().ip();
        if local_ip.is_loopback() || local_ip.is_unspecified() {
            return;
        }

        let mut config = Config::default();
        config.listen = vec!["0.0.0.0:53".parse().unwrap()];
        config.bootstrap = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());

        config.bootstrap.clear();
        config.root_hints = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());

        config.root_hints.clear();
        config.upstreams = vec![local_ip];
        assert!(ensure_resolution_sources_not_self(&config).is_err());
        assert!(blocklist_bootstrap(&config).is_empty());
    }

    #[test]
    /** @brief 담아 둔 목록에서 제목이 되살아나는지. */
    fn blocklist_cache_restores_title_from_content() {
        let dir = std::env::temp_dir().join(format!("onetdns-blcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://example.test/list.txt".to_string();
        let item = SubMeta {
            url: url.clone(),
            title: "예시 차단 목록".to_string(),
            rules: 2,
            updated_unix: 12345,
            lines: vec![
                "! Title: 예시 차단 목록".to_string(),
                "||ads.example.com^".to_string(),
                "||track.example.net^".to_string(),
            ]
            .into(),
        };
        save_blocklist_cache_text(
            &item.url,
            item.updated_unix,
            &item.lines.join(
                "
",
            ),
            Some(&dir),
        )
        .expect("cache 저장");
        let loaded = load_blocklist_cache(std::slice::from_ref(&url), Some(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(loaded.len(), 1);

        assert_eq!(loaded[0].title, "예시 차단 목록");
        assert_eq!(loaded[0].rules, 2);
        assert_eq!(loaded[0].updated_unix, 12345);

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(blocklist_cache_key(&url)),
            format!("# onetdns-url:{url}\n||ads.example.com^\n"),
        )
        .unwrap();
        assert!(load_blocklist_cache(std::slice::from_ref(&url), Some(&dir)).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /** @brief 담아 둔 영역 형식 목록의 헤더를 확인하는지. */
    fn rpz_cache_requires_the_complete_current_header() {
        let dir = std::env::temp_dir().join(format!("onetdns-rpzcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://example.test/policy.rpz".to_string();
        save_rpz_cache(&url, "bad.example CNAME .\n", Some(&dir)).unwrap();
        let loaded = load_rpz_cache(std::slice::from_ref(&url), Some(&dir));
        assert!(loaded[0].contains("bad.example"));

        std::fs::write(
            dir.join(rpz_cache_key(&url)),
            format!("# onetdns-rpz-url:{url}\nbad.example CNAME .\n"),
        )
        .unwrap();
        assert!(load_rpz_cache(std::slice::from_ref(&url), Some(&dir))[0].is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /** @brief 원본 줄을 놓아준 뒤에도 지문이 그대로인지. 달라지면 매 시작마다 다시 고정한다. */
    fn compiled_fingerprint_survives_releasing_subscription_lines() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-compiled-fingerprint-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let item = SubMeta {
            url: "https://example.test/large.txt".into(),
            title: "large".into(),
            rules: 2,
            updated_unix: 42,
            lines: vec!["||ads.example^".to_string(), "||track.example^".to_string()].into(),
        };
        save_blocklist_cache_text(
            &item.url,
            item.updated_unix,
            &item.lines.join(
                "
",
            ),
            Some(&dir),
        )
        .unwrap();
        let meta = Mutex::new(vec![item]);
        let calculate = |subscriptions: &[SubMeta]| {
            compiled_filter_fingerprint(&CompiledFilterInputs {
                blocklists: &[],
                allowlists: &[],
                service_rules: &[],
                subscriptions,
                subscription_cache_dir: Some(&dir),
                overlay_block: &[],
                overlay_allow: &[],
                rewrites: &[],
                local_zones: &[],
                refused_domains: &[],
                rpz_files: &[],
                rpz_texts: &[],
            })
        };
        let before = calculate(&meta.lock_recover());
        release_subscription_lines(&meta, &dir);
        let after = calculate(&meta.lock_recover());

        let guard = meta.lock_recover();
        assert!(guard[0].lines.is_empty());
        assert_eq!(guard[0].rules, 2);
        assert_eq!(before, after);
        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /** @brief 너무 크거나 글자가 어긋난 파일을 거부하는지. */
    fn bounded_text_reader_rejects_oversized_and_invalid_utf8_files() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-bounded-text-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::write(&path, b"12345").unwrap();
        assert!(read_text_limited(&path, 4).is_err());
        assert_eq!(read_text_limited(&path, 5).unwrap(), "12345");
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_text_limited(&path, 5).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    /** @brief 키를 못 읽었을 때 조용히 새로 만들지 않는지. 만들면 서명이 전부 바뀐다. */
    fn unreadable_dnssec_key_is_not_silently_replaced() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-oversized-key-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let original = vec![b'x'; LOCAL_KEY_MAX_BYTES as usize + 1];
        std::fs::write(&path, &original).unwrap();

        assert!(load_or_create_key_pem(&path, "test key", Default::default()).is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            original.len() as u64
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    /** @brief 작업이 시작되고 끝나는 흐름. */
    fn job_registry_lifecycle() {
        let reg = JobRegistry::new(4);
        let id = reg.create("refresh-lists").unwrap();

        assert!(reg.get_json(id).unwrap().contains("\"status\":\"running\""));

        reg.finish(id, true, "block=10".to_string());
        let j = reg.get_json(id).unwrap();
        assert!(j.contains("\"status\":\"done\""));
        assert!(j.contains("block=10"));

        assert!(reg.list_json().contains(&format!("\"id\":{id}")));
        assert!(reg.get_json(9999).is_none());

        for _ in 0..10 {
            let x = reg.create("x").unwrap();
            reg.finish(x, true, String::new());
        }
        assert!(reg.list_json().matches("\"id\":").count() <= 4);

        let full = JobRegistry::new(2);
        assert!(full.create("a").is_some());
        assert!(full.create("b").is_some());
        assert!(full.create("c").is_none());
    }

    #[test]
    /** @brief 구독 항목만 고치고 나머지 설정은 그대로 두는지. */
    fn persist_subscriptions_rewrites_key_preserving_rest() {
        let dir = std::env::temp_dir();

        let stamp = format!("{}-{}", std::process::id(), unix_now());

        let p = dir.join(format!("onetdns-persist-a-{stamp}.toml"));
        std::fs::write(
            &p,
            "# my config\nlisten = [\"0.0.0.0:53\"]\nblocklist_urls = [\"https://old/list.txt\"]\nupstreams = [\"1.1.1.1\"]\n\n[[clients]]\nname = \"kid\"\n",
        )
        .unwrap();
        persist_config_string_array(
            &p,
            "blocklist_urls",
            &[
                "https://new/a.txt".to_string(),
                "https://new/b.txt".to_string(),
            ],
        )
        .unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("blocklist_urls = [\"https://new/a.txt\", \"https://new/b.txt\"]"));
        assert!(!after.contains("old/list.txt"), "기존 값 제거");
        assert!(after.contains("# my config") && after.contains("upstreams = [\"1.1.1.1\"]"));
        assert!(after.contains("[[clients]]") && after.contains("name = \"kid\""));

        assert!(onetdns_config::Config::from_toml_str(&after).is_ok());
        let _ = std::fs::remove_file(&p);

        let p2 = dir.join(format!("onetdns-persist-b-{stamp}.toml"));
        std::fs::write(
            &p2,
            "listen = [\"0.0.0.0:53\"]\n\n[[clients]]\nname = \"x\"\n",
        )
        .unwrap();
        persist_config_string_array(&p2, "blocklist_urls", &["https://x/y.txt".to_string()])
            .unwrap();
        let after2 = std::fs::read_to_string(&p2).unwrap();
        assert!(after2.contains("blocklist_urls = [\"https://x/y.txt\"]"));
        let urls_at = after2.find("blocklist_urls").unwrap();
        let clients_at = after2.find("[[clients]]").unwrap();
        assert!(urls_at < clients_at, "키는 테이블 헤더 앞에 위치");
        assert!(onetdns_config::Config::from_toml_str(&after2).is_ok());
        let _ = std::fs::remove_file(&p2);

        let p3 = dir.join(format!("onetdns-persist-c-{stamp}.toml"));
        std::fs::write(
            &p3,
            "blocklist_urls = [\n  \"https://a\",\n  \"https://b\"\n]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        persist_config_string_array(&p3, "blocklist_urls", &["https://only.txt".to_string()])
            .unwrap();
        let after3 = std::fs::read_to_string(&p3).unwrap();
        assert!(after3.contains("blocklist_urls = [\"https://only.txt\"]"));
        assert!(
            !after3.contains("https://a") && !after3.contains("https://b"),
            "이전 다중 줄 값 제거"
        );
        assert!(after3.contains("upstreams = [\"9.9.9.9\"]"));
        assert!(onetdns_config::Config::from_toml_str(&after3).is_ok());
        let _ = std::fs::remove_file(&p3);
    }

    #[test]
    /** @brief 설정 파일이 없을 때 새로 만들지 않는지. */
    fn persist_config_array_does_not_create_missing_config() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-persist-missing-{}-{}.toml",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_file(&path);

        let result =
            persist_config_string_array(&path, "block_rules", &["blocked.example".to_string()]);

        assert!(result.is_err());
        assert!(
            !path.exists(),
            "읽지 못한 설정 파일을 새로 만들면 안 됩니다"
        );
    }

    #[test]
    /** @brief 클라이언트 구간을 넣고 빼는 도구들. */
    fn client_block_crud_helpers() {
        let (block, name) = client_block_from_json(
            "{\"name\":\"kid\",\"ids\":[\"192.168.1.5/32\"],\"tags\":[\"child\"],\"disable_filtering\":false}",
        )
        .unwrap();
        assert_eq!(name, "kid");
        assert!(block.contains("[[clients]]"));
        assert!(block.contains("name = \"kid\""));
        assert!(block.contains("ids = [\"192.168.1.5/32\"]"));
        assert!(block.contains("tags = [\"child\"]"));
        assert!(!block.contains("disable_filtering"), "false 필드는 생략");
        assert!(
            client_block_from_json("{\"ids\":[]}").is_err(),
            "name 없으면 에러"
        );

        let base = "listen = [\"0.0.0.0:53\"]\n";
        let full = format!("{base}{block}");
        assert!(onetdns_config::Config::from_toml_str(&full).is_ok());
        let removed = remove_client_block(&full, "kid").unwrap();
        assert!(!removed.contains("name = \"kid\""));
        assert!(removed.contains("listen"));
        assert!(onetdns_config::Config::from_toml_str(&removed).is_ok());
        assert!(
            remove_client_block(base, "ghost").is_none(),
            "없는 이름 → None"
        );
    }

    #[test]
    /** @brief 특수 문자가 든 이름의 구간도 정확히 빼는지. */
    fn remove_client_block_matches_escaped_name() {
        let name = "a\"b\\c";
        let block = format!("[[clients]]\nname = {}\n", toml_quote(name));
        let full = format!("listen = [\"0.0.0.0:53\"]\n{block}");
        assert!(onetdns_config::Config::from_toml_str(&full).is_ok());
        let removed = remove_client_block(&full, name).expect("escape된 이름 삭제");
        assert!(!removed.contains("[[clients]]"));
        assert!(removed.contains("listen"));
    }

    #[test]
    /**
     * @brief 질의 설명이 실제 응답과 같은 응답 코드와 경로를 말하는지.
     * @details 차단 응답 코드는 설정한 차단 방식을 따르고, 로컬 영역에 든 이름은 전달하지
     *          않고 영역이 답한다. 설명이 이와 다르면 같은 화면의 실제 응답과 어긋난다.
     */
    fn explain_matches_block_response_and_local_zone() {
        let policy =
            onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![]);
        let filter = |response| {
            onetdns_filter::SharedFilter::from_pointee(onetdns_filter::build_from_str(
                "||ads.example^",
                "",
                response,
            ))
        };
        let dir = std::env::temp_dir().to_string_lossy().replace('\\', "/");
        let cfg = |backend: &str| {
            Config::from_toml_str(&format!(
                "backend = \"{backend}\"\nupstreams = [\"192.0.2.1\"]\nzones_dir = \"{dir}\"\n"
            ))
            .unwrap()
        };
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                "$ORIGIN d.test.\n@ 300 IN SOA ns1 h 1 3600 600 86400 300\n@ 300 IN NS ns1\nwww 300 IN A 192.0.2.10\n",
                "d.test",
            )
            .unwrap(),
        );
        let ask = |flt: &onetdns_filter::SharedFilter, cfg: &Config, qname: &str| {
            let out = explain_query(
                &policy,
                flt,
                cfg,
                &zones,
                &format!("{{\"qname\":\"{qname}\"}}"),
            );
            let j = onetdns_core::json::parse(&out).unwrap();
            let field = |k: &str| j.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            (field("rcode"), field("route"))
        };
        let forward = cfg("forward");

        let zero = filter(onetdns_core::BlockResponse::ZeroIp);
        assert_eq!(
            ask(&zero, &forward, "ads.example"),
            ("NOERROR".to_string(), "blocked".to_string())
        );
        let nx = filter(onetdns_core::BlockResponse::NxDomain);
        assert_eq!(
            ask(&nx, &forward, "ads.example"),
            ("NXDOMAIN".to_string(), "blocked".to_string())
        );
        assert_eq!(ask(&nx, &forward, "www.d.test").1, "authority");
        assert_eq!(ask(&nx, &forward, "other.example").1, "forward");
        assert_eq!(ask(&nx, &cfg("recurse"), "other.example").1, "recurse");
    }

    #[test]
    /** @brief 미리 보기가 실제 경로와 같은 방식으로 이름을 다루는지. 다르면 미리 보기가 거짓말이 된다. */
    fn simulate_policy_normalizes_qname_like_live_path() {
        let policy = onetdns_policy::PolicyEngine::new(
            onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
                onetdns_policy::Action::Block,
            )
            .with_suffixes(&["blocked.example".to_string()])]),
            vec![],
        );
        let filter = onetdns_filter::SharedFilter::from_pointee(
            onetdns_filter::BlockEngine::empty(onetdns_core::BlockResponse::NxDomain),
        );
        let out = simulate_policy(&policy, &filter, "{\"qname\":\"Sub.Blocked.EXAMPLE\"}");
        assert!(
            out.contains("\"policy\":\"block\""),
            "대소문자 섞인 입력도 실경로처럼 소문자 정규화 후 평가: {out}"
        );
    }

    #[test]
    /** @brief 미리 보기가 클라이언트 식별자도 실제처럼 보는지. */
    fn simulate_policy_honors_client_id_like_explain() {
        let policy =
            onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![]);
        let filter = onetdns_filter::SharedFilter::from_pointee(
            onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain)
                .with_clients(vec![onetdns_filter::ClientPolicy::with_options(
                    vec![],
                    vec!["kid".to_string()],
                    vec![],
                    &["tracker.example".to_string()],
                    &[],
                    false,
                    None,
                )]),
        );
        let without = simulate_policy(&policy, &filter, "{\"qname\":\"tracker.example\"}");
        let with_id = simulate_policy(
            &policy,
            &filter,
            "{\"qname\":\"tracker.example\",\"client_id\":\"kid\"}",
        );
        assert!(
            !without.contains("\"filter\":\"block"),
            "클라이언트 ID가 없으면 그 클라이언트 규칙은 적용되지 않는다: {without}"
        );
        assert!(
            with_id.contains("\"filter\":\"block"),
            "클라이언트 ID를 주면 그 클라이언트 규칙이 반영돼야 한다: {with_id}"
        );
    }

    #[test]
    /**
     * @brief 통계를 볼 수 있는 곳을 빠짐없이 세는지.
     *
     * @details 하나라도 빠뜨리면 그 설정을 쓰는 사람은 대시보드나 저장 파일이 비는 것을
     *          보게 되고, 거꾸로 넓게 잡으면 헤드리스 배포가 아무도 읽지 않는 통계에
     *          해석당 CPU의 4분의 1을 낸다.
     */
    fn telemetry_is_collected_only_where_something_reads_it() {
        let mut cfg = Config::default();
        cfg.control_listen = None;
        cfg.stats_file = None;
        cfg.querylog_file = None;
        assert!(
            !telemetry_consumed(&cfg),
            "볼 곳이 하나도 없는데 모으기로 했습니다"
        );

        cfg.control_listen = Some("127.0.0.1:8553".parse().unwrap());
        assert!(
            telemetry_consumed(&cfg),
            "관리 수신 주소가 있으면 모아야 합니다"
        );
        cfg.control_listen = None;

        cfg.stats_file = Some(PathBuf::from("/var/lib/onetdns/stats.json"));
        assert!(
            telemetry_consumed(&cfg),
            "통계 저장 파일이 있으면 모아야 합니다"
        );
        cfg.stats_file = None;

        cfg.querylog_file = Some(PathBuf::from("/var/lib/onetdns/querylog.jsonl"));
        assert!(
            telemetry_consumed(&cfg),
            "질의 기록 파일이 있으면 모아야 합니다"
        );

        // 빈 경로는 끈 것이다. 설정 파일에 키만 남기고 값을 지운 경우가 실제로 있다.
        cfg.querylog_file = Some(PathBuf::new());
        assert!(
            !telemetry_consumed(&cfg),
            "빈 경로를 저장 파일이 있는 것으로 셌습니다"
        );
    }

    #[test]
    /** @brief 문자열 안의 괄호를 값 경계로 오해하지 않는지. */
    fn removing_a_key_leaves_the_rest_alone() {
        let text = "listen = [\"0.0.0.0:53\"]
control_listen = \"127.0.0.1:8553\"
querylog = true

[[users]]
name = \"admin\"
";
        let out = remove_config_key(text, "control_listen").unwrap();
        assert!(!out.contains("control_listen"), "지운 항목이 남았습니다");
        assert!(out.contains("listen = "), "다른 항목이 함께 지워졌습니다");
        assert!(out.contains("querylog = true"));
        assert!(out.contains("[[users]]"), "테이블이 함께 지워졌습니다");

        // 원래 없던 항목을 지우는 것은 실패가 아니다.
        let same = remove_config_key(&out, "control_listen").unwrap();
        assert_eq!(same, out);

        // 테이블 안의 같은 이름은 건드리지 않는다.
        let nested = "[[zones]]
name = \"a\"
";
        assert_eq!(remove_config_key(nested, "name").unwrap(), nested);
    }

    #[test]
    /** @brief 값 검사가 지우기를 막지 않는지. */
    fn deleting_a_key_skips_value_checks() {
        use onetdns_core::json::Json;
        let pairs = vec![("control_token".to_string(), Json::Null)];
        assert!(
            validate_config_patch_values(&pairs).is_ok(),
            "지우기는 넣기 규칙에 걸리면 안 됩니다"
        );
    }

    #[test]
    /** @brief 배열 안의 대괄호에 속지 않는지. */
    fn rewrite_config_kv_handles_bracket_in_string() {
        let text = "blocklist_urls = [\n  \"https://x/a]b.txt\",  # note ] here\n  \"https://x/c.txt\",\n]\nupstreams = [\"1.1.1.1\"]\n";
        let out = rewrite_config_kv(text, "blocklist_urls", "[\"https://new.txt\"]").unwrap();
        assert!(out.contains("blocklist_urls = [\"https://new.txt\"]"));
        assert!(!out.contains("a]b.txt"), "기존 배열 완전 제거");
        assert!(!out.contains("c.txt"));
        assert!(out.contains("upstreams = [\"1.1.1.1\"]"), "다른 키 보존");
    }

    #[test]
    /** @brief 합칠 때 건드리지 않은 항목과 주석이 그대로인지. */
    fn merge_config_snippet_preserves_unrelated_keys_and_comments() {
        let cur = "# 헤더 주석\ncontrol_token = \"0123456789abcdef01234567\"\ncache_size = 8192\nupstreams = [\"1.1.1.1\", \"1.0.0.1\"]\n";
        let out = merge_config_snippet(
            cur,
            "list_refresh_secs = 3600\nupstream_strategy = \"round_robin\"\n",
        )
        .unwrap();
        assert!(
            out.contains("control_token = \"0123456789abcdef01234567\""),
            "토큰 보존: {out}"
        );
        assert!(out.contains("# 헤더 주석"));
        assert!(out.contains("cache_size = 8192"));
        assert!(out.contains("upstreams = [\"1.1.1.1\", \"1.0.0.1\"]"));
        assert!(out.contains("list_refresh_secs = 3600"));
        assert!(out.contains("upstream_strategy = \"round_robin\""));
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    /** @brief 여러 줄에 걸친 배열도 전부 갈리는지. */
    fn merge_config_snippet_replaces_existing_and_multiline_arrays() {
        let cur = "cache_size = 1024\nblocklist_urls = [\n  \"https://a.txt\",\n  \"https://b.txt\",\n]\nmin_ttl = 5\n";
        let out = merge_config_snippet(
            cur,
            "blocklist_urls = [\n  \"https://c.txt\",\n]\ncache_size = 2048\n",
        )
        .unwrap();
        assert!(out.contains("cache_size = 2048"));
        assert!(!out.contains("cache_size = 1024"));
        assert!(out.contains("https://c.txt"));
        assert!(!out.contains("a.txt"), "기존 배열 완전 교체: {out}");
        assert!(out.contains("min_ttl = 5"));
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    /** @brief 테이블 구간이 루트 이름 기준으로 갈리는지. */
    fn merge_config_snippet_replaces_table_blocks_by_root() {
        let cur =
            "cache_size = 8192\n[[clients]]\nname = \"old\"\nids = [\"10.0.0.1\"]\nupstreams = [\"9.9.9.9\"]\n";
        let out = merge_config_snippet(
            cur,
            "[[clients]]\nname = \"new\"\nids = [\"10.0.0.2\"]\nupstreams = [\"8.8.8.8\"]\n",
        )
        .unwrap();
        assert!(out.contains("cache_size = 8192"));
        assert!(out.contains("10.0.0.2"));
        assert!(!out.contains("10.0.0.1"), "기존 블록 전부 교체: {out}");
        Config::from_toml_str(&out).unwrap();
    }

    #[test]
    /** @brief 빈 조각이 지금 설정을 지우지 않는지. */
    fn merge_config_snippet_empty_or_comment_only_keeps_current() {
        let cur = "cache_size = 8192\n";
        assert_eq!(merge_config_snippet(cur, "").unwrap(), cur);
        assert_eq!(merge_config_snippet(cur, "# 주석뿐\n\n").unwrap(), cur);
    }

    #[test]
    /** @brief 업스트림 표기가 어느 설정 항목에 속하는지 구분하는지. */
    fn upstream_key_classifies() {
        assert_eq!(upstream_key("1.1.1.1"), "upstreams");
        assert_eq!(upstream_key("tls://1.1.1.1#cf"), "upstream_urls");
        assert_eq!(upstream_key("https://8.8.8.8/dns-query"), "upstream_urls");
    }

    #[test]
    /**
     * @brief 테이블 배열의 마지막 항목을 빈 배열로 지울 수 있는지.
     * @details 대시보드는 테이블 키를 조각으로만 고친다. 빈 배열이 테이블 블록을 대체하지 않으면
     *          마지막 NOTIFY 대상이나 보조 영역을 지울 방법이 없다.
     */
    fn empty_array_replaces_the_last_table_entry() {
        let current = "listen = [\"127.0.0.1:5300\"]\n\n[[notify]]\naddress = \"192.0.2.9:53\"\n";
        let merged = merge_config_snippet(current, "notify = []\n").unwrap();
        assert!(
            Config::from_toml_str(&merged).unwrap().notify.is_empty(),
            "{merged}"
        );
        let set = rewrite_config_kv(current, "notify", "[]").unwrap();
        assert!(
            Config::from_toml_str(&set).unwrap().notify.is_empty(),
            "{set}"
        );
        let removed = remove_config_key(current, "notify").unwrap();
        assert!(
            Config::from_toml_str(&removed).unwrap().notify.is_empty(),
            "{removed}"
        );
        assert!(merged.contains("listen"), "{merged}");
    }

    #[test]
    /**
     * @brief 관리 API가 지금 설정으로 고칠 수 있는 영역만 고치는지.
     * @details 나중에 더한 보조 영역과 외부 저장소에서 온 영역은 거절하고, 바꾼 영역
     *          디렉터리에 쓴다.
     */
    fn zone_api_follows_live_config() {
        let dir = std::env::temp_dir().join(format!("onetdns-zone-api-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_text = dir.to_string_lossy().replace('\\', "/");
        let mut store = onetdns_authority::ZoneStore::new();
        store.add(
            onetdns_authority::parse_zone(
                "$ORIGIN db.test.\n@ 300 IN SOA ns1 h 1 3600 600 86400 300\n@ 300 IN NS ns1\n",
                "db.test",
            )
            .unwrap(),
        );
        let cfg = Config::from_toml_str(&format!(
            "zones_dir = \"{dir_text}\"\nzones_db = \"{dir_text}/zones.sqlite\"\n\n[[secondary]]\norigin = \"sec.test\"\nprimary = \"192.0.2.53\"\n"
        ))
        .unwrap();

        assert!(zone_api_target(&cfg, &store, "sec.test", "수정").is_err());
        assert!(
            zone_api_target(&cfg, &store, "db.test", "수정").is_err(),
            "외부 저장소에서 온 영역은 고치면 되돌아간다"
        );
        let fresh = zone_api_target(&cfg, &store, "new.test", "수정").unwrap();
        assert_eq!(fresh.path, Some(dir.join("new.test.zone")));

        std::fs::write(dir.join("db.test.zone"), "").unwrap();
        assert!(
            zone_api_target(&cfg, &store, "db.test", "수정").is_ok(),
            "파일로 관리되는 영역은 고칠 수 있다"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /**
     * @brief 영역 목록이 내보낸 이름을 삭제 API가 같은 레코드로 읽는지.
     * @details 대시보드는 목록에서 받은 이름을 그대로 삭제 요청에 담는다.
     */
    fn listed_zone_record_name_resolves_to_the_same_owner() {
        use onetdns_proto::{DnsClass, Name, RData, Record, RecordType};
        for owner in ["api.d.test", "d.test"] {
            let record = Record {
                name: Name::from_str(owner).unwrap(),
                rtype: RecordType::A,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 77)),
            };
            let json = onetdns_core::json::parse(&zone_record_json(&record)).unwrap();
            let listed = json.get("name").and_then(|v| v.as_str()).unwrap();
            let resolved = resolve_zone_name(listed, "d.test").unwrap();
            assert!(
                resolved.eq_ignore_case(&record.name),
                "목록 이름 {listed} 이 {} 로 읽혔습니다",
                resolved.to_ascii_lower()
            );
        }
    }

    #[test]
    /** @brief 상대·절대·꼭대기 이름이 모두 풀리는지. */
    fn resolve_zone_name_relative_absolute_apex() {
        use onetdns_proto::Name;
        let lc = |n: Name| n.to_ascii_lower();

        assert_eq!(
            lc(resolve_zone_name("www", "example.com").unwrap()),
            "www.example.com"
        );

        assert_eq!(
            lc(resolve_zone_name("ns.other.net.", "example.com").unwrap()),
            "ns.other.net"
        );

        assert_eq!(
            lc(resolve_zone_name("@", "example.com").unwrap()),
            "example.com"
        );

        assert_eq!(
            lc(resolve_zone_name("a", "example.com.").unwrap()),
            "a.example.com"
        );
    }

    #[test]
    /** @brief 목록 영역을 내보내고 받아 오는 왕복. */
    fn catalog_producer_consumer_roundtrip() {
        use onetdns_proto::Name;
        let origin = Name::from_str("catalog.example").unwrap();
        let members = vec!["a.example.".to_string(), "b.test.".to_string()];
        let zone = build_catalog_zone(&origin, &members, 1).unwrap();
        let recs = zone.axfr_records();
        assert_eq!(
            catalog_members(&recs, "catalog.example"),
            vec!["a.example".to_string(), "b.test".to_string()]
        );

        assert!(recs.iter().any(|r| {
            r.name.to_ascii_lower() == "version.catalog.example"
                && matches!(&r.rdata, onetdns_proto::RData::Txt(t) if t == &vec![b"2".to_vec()])
        }));
    }

    #[test]
    /** @brief 목록 영역에서 회원 영역들을 추출하는지. */
    fn catalog_members_extracts_ptr_under_zones() {
        use onetdns_proto::{Name, RData, Record};
        let recs = vec![
            Record::new(
                Name::from_str("a1.zones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("alpha.test").unwrap()),
            ),
            Record::new(
                Name::from_str("b2.zones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("beta.test").unwrap()),
            ),
            Record::new(
                Name::from_str("other.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("nope.test").unwrap()),
            ),
            Record::new(
                Name::from_str("evilzones.catalog.example").unwrap(),
                0,
                RData::Ptr(Name::from_str("suffix-bypass.test").unwrap()),
            ),
        ];
        let m = catalog_members(&recs, "CATALOG.EXAMPLE.");
        assert_eq!(m, vec!["alpha.test".to_string(), "beta.test".to_string()]);
    }

    #[test]
    /** @brief 시리얼 비교가 한 바퀴 도는 것을 제대로 다루는지. */
    fn serial_gt_rfc1982() {
        assert!(serial_gt(2, 1));
        assert!(!serial_gt(1, 2));
        assert!(!serial_gt(5, 5));
        assert!(serial_gt(0, u32::MAX), "랩어라운드: 0 > MAX");
    }

    #[test]
    /** @brief 맞는 답이 올 때까지 다시 보내는지. */
    fn notify_dispatcher_retries_until_a_matching_ack_arrives() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 알림과 재전송을 기다리는 읽기 제한 시간이다. 재전송 간격보다 짧으면 재전송이
         * 오기 전에 읽기가 먼저 끝난다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let target = NotifyRuntimeTarget {
            address: receiver.local_addr().unwrap(),
            tsig_key: None,
        };
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![target],
            NotifyRetryPolicy {
                initial: Duration::from_millis(300),
                retransmissions: 3,
            },
            shutdown.clone(),
        )
        .unwrap();
        let origin = onetdns_proto::Name::from_str("notify.test").unwrap();
        sender.enqueue(&origin, 7);

        let mut wire = [0u8; 2048];
        let (first_len, source) = receiver.recv_from(&mut wire).unwrap();
        let first = onetdns_proto::Message::parse(&wire[..first_len]).unwrap();
        assert_eq!(first.header.opcode, 4);
        assert!(!first.header.response);

        let mut wrong = onetdns_proto::Message::default();
        wrong.header.id = first.header.id.wrapping_add(1);
        wrong.header.response = true;
        wrong.header.opcode = 4;
        wrong.header.authoritative = true;
        wrong.questions = first.questions.clone();
        receiver
            .send_to(&wrong.try_encode().unwrap(), source)
            .unwrap();

        let (retry_len, retry_source) = receiver.recv_from(&mut wire).unwrap();
        let retry = onetdns_proto::Message::parse(&wire[..retry_len]).unwrap();
        assert_eq!(retry.header.id, first.header.id, "동일 transaction 재전송");
        let mut ack = onetdns_proto::Message::default();
        ack.header.id = retry.header.id;
        ack.header.response = true;
        ack.header.opcode = 4;
        ack.header.authoritative = true;
        ack.questions = retry.questions;
        receiver
            .send_to(&ack.try_encode().unwrap(), retry_source)
            .unwrap();

        /*
         * 재전송 간격은 두 배씩 늘어나므로 다음 재전송은 첫 재전송의 600밀리초 뒤다.
         * 침묵을 기다리는 구간은 그보다 길어야 재전송이 멈췄는지 실제로 확인할 수 있고,
         * 동시에 보내는 쪽이 ACK 를 처리할 시간도 그만큼 확보된다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_millis(900)))
            .unwrap();
        assert!(
            receiver.recv_from(&mut wire).is_err(),
            "일치하는 ACK 뒤에는 재전송을 중단해야 함"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
    }

    #[test]
    /** @brief 키를 걸었으면 서명된 답만 답으로 세는지. */
    fn notify_dispatcher_requires_a_valid_tsig_ack_when_configured() {
        use onetdns_dnssec::tsig::{self, WireVerification};

        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 알림과 재전송을 기다리는 읽기 제한 시간이다. 재전송 간격보다 짧으면 재전송이
         * 오기 전에 읽기가 먼저 끝난다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = tsig::TsigKey::new(
            onetdns_proto::Name::from_str("notify-key.test").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![NotifyRuntimeTarget {
                address: receiver.local_addr().unwrap(),
                tsig_key: Some(key.clone()),
            }],
            NotifyRetryPolicy {
                initial: Duration::from_millis(300),
                retransmissions: 2,
            },
            shutdown.clone(),
        )
        .unwrap();
        let origin = onetdns_proto::Name::from_str("signed-notify.test").unwrap();
        sender.enqueue(&origin, 9);

        let mut wire = [0u8; 2048];
        let (first_len, source) = receiver.recv_from(&mut wire).unwrap();
        let (stripped, verified) =
            match tsig::verify_wire_detailed(&wire[..first_len], &key, unix_now(), None).unwrap() {
                WireVerification::Valid { stripped, tsig } => (stripped, tsig),
                WireVerification::BadTime { .. } => panic!("fresh NOTIFY TSIG"),
            };
        let request = onetdns_proto::Message::parse(&stripped).unwrap();

        let mut unsigned_ack = onetdns_proto::Message::default();
        unsigned_ack.header.id = request.header.id;
        unsigned_ack.header.response = true;
        unsigned_ack.header.opcode = 4;
        unsigned_ack.header.authoritative = true;
        unsigned_ack.questions = request.questions.clone();
        receiver
            .send_to(&unsigned_ack.try_encode().unwrap(), source)
            .unwrap();

        let (retry_len, retry_source) = receiver.recv_from(&mut wire).unwrap();
        let retry_verified =
            match tsig::verify_wire_detailed(&wire[..retry_len], &key, unix_now(), None).unwrap() {
                WireVerification::Valid { tsig, .. } => tsig,
                WireVerification::BadTime { .. } => panic!("fresh retry TSIG"),
            };
        let mut signed_ack = unsigned_ack;
        tsig::sign_response_message(&mut signed_ack, &key, unix_now(), &retry_verified).unwrap();
        receiver
            .send_to(&signed_ack.try_encode().unwrap(), retry_source)
            .unwrap();

        /* 위 시험과 같은 이유로 다음 재전송 시점보다 길게 기다린다. */
        receiver
            .set_read_timeout(Some(Duration::from_millis(900)))
            .unwrap();
        assert!(receiver.recv_from(&mut wire).is_err());
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
        assert_eq!(verified.mac().len(), 32);
    }

    #[test]
    /** @brief 같은 영역과 대상의 알림이 하나로 합쳐지는지. */
    fn notify_pending_work_is_coalesced_per_zone_and_target() {
        let queue = Arc::new(NotifyQueue::default());
        let sender = NotifySender {
            queue: Some(queue.clone()),
            targets: Arc::new(onetdns_core::ArcSwap::new(Arc::new(vec![
                NotifyRuntimeTarget {
                    address: "127.0.0.1:5353".parse().unwrap(),
                    tsig_key: None,
                },
            ]))),
        };
        let origin = onetdns_proto::Name::from_str("coalesce.test").unwrap();
        for serial in 1..=10_000 {
            sender.enqueue(&origin, serial);
        }
        let pending = queue.pending.lock_recover();
        assert_eq!(
            pending.len(),
            1,
            "중복 변경 폭주가 큐 메모리를 늘리면 안 됨"
        );
        assert_eq!(pending.values().next().unwrap().serial, 10_000);
    }

    #[test]
    /** @brief IPv6 대상에 IPv6 소켓을 쓰는지. */
    fn notify_dispatcher_uses_an_ipv6_socket_for_ipv6_targets() {
        let Ok(receiver) = std::net::UdpSocket::bind("[::1]:0") else {
            return;
        };
        /*
         * 재전송 횟수를 0으로 두어 첫 알림을 놓치면 다시 오지 않는다. 느린 기계에서도
         * 받을 수 있도록 읽기 제한 시간을 넉넉히 둔다.
         */
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sender, worker) = spawn_notify_worker(
            vec![NotifyRuntimeTarget {
                address: receiver.local_addr().unwrap(),
                tsig_key: None,
            }],
            NotifyRetryPolicy {
                initial: Duration::from_millis(100),
                retransmissions: 0,
            },
            shutdown.clone(),
        )
        .unwrap();
        sender.enqueue(&onetdns_proto::Name::from_str("notify-v6.test").unwrap(), 1);
        let mut wire = [0u8; 2048];
        let (length, _) = receiver.recv_from(&mut wire).unwrap();
        let request = onetdns_proto::Message::parse(&wire[..length]).unwrap();
        assert_eq!(request.questions[0].name.to_ascii_lower(), "notify-v6.test");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        sender.wake();
        worker.join().unwrap();
    }

    #[test]
    /** @brief 시리얼을 물을 때 권한 있는 답만 믿고 서명을 확인하는지. */
    fn secondary_soa_probe_requires_authority_and_verifies_tsig() {
        use onetdns_dnssec::tsig;
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let key = tsig::TsigKey::new(
            onetdns_proto::Name::from_str("secondary-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let server_key = key.clone();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let (stripped, request_mac) =
                tsig::verify_wire(&wire[..length], &server_key, unix_now(), None).unwrap();
            let request = Message::parse(&stripped).unwrap();
            let origin = request.questions[0].name.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers.push(Record {
                name: origin.clone(),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: onetdns_proto::Name::from_str("ns.probe.test").unwrap(),
                    rname: onetdns_proto::Name::from_str("admin.probe.test").unwrap(),
                    serial: 42,
                    refresh: 300,
                    retry: 60,
                    expire: 86400,
                    minimum: 60,
                }),
            });
            tsig::sign_message(&mut response, &server_key, unix_now(), Some(&request_mac)).unwrap();
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        assert_eq!(
            probe_soa_serial(address, "probe.test", Some(key.clone())).unwrap(),
            42
        );
        server.join().unwrap();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let request = Message::parse(&wire[..length]).unwrap();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions;
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
        });
        assert!(probe_soa_serial(address, "probe.test", None).is_err());
        server.join().unwrap();
    }

    /** @brief 시리얼을 답하는 테스트용 서버. */
    fn secondary_soa_test_server(
        delay: Duration,
        observed: Option<std::sync::mpsc::Sender<std::time::Instant>>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            if let Some(observed) = observed {
                observed.send(std::time::Instant::now()).unwrap();
            }
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            let request = Message::parse(&wire[..length]).unwrap();
            let origin = request.questions[0].name.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers.push(Record {
                name: origin.clone(),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: onetdns_proto::Name::from_str("ns.secondary.test").unwrap(),
                    rname: onetdns_proto::Name::from_str("admin.secondary.test").unwrap(),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    minimum: 60,
                }),
            });
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
        });
        (address, server)
    }

    #[test]
    /** @brief 번호만 같고 질문이 다른 답을 무시하는지. 안 그러면 남이 끼워 넣은 시리얼을 믿는다. */
    fn multiplexed_soa_probe_ignores_same_id_wrong_question() {
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let request = Message::parse(&wire[..length]).unwrap();
            let answer = |origin: onetdns_proto::Name| {
                Record::new(
                    origin,
                    300,
                    RData::soa(Soa {
                        mname: onetdns_proto::Name::from_str("ns.secondary.test").unwrap(),
                        rname: onetdns_proto::Name::from_str("admin.secondary.test").unwrap(),
                        serial: 42,
                        refresh: 300,
                        retry: 60,
                        expire: 86_400,
                        minimum: 60,
                    }),
                )
            };
            let mut wrong = Message::default();
            wrong.header.id = request.header.id;
            wrong.header.response = true;
            wrong.header.authoritative = true;
            let wrong_name = onetdns_proto::Name::from_str("wrong.secondary.test").unwrap();
            wrong.questions.push(onetdns_proto::Question {
                name: wrong_name.clone(),
                qtype: RecordType::SOA,
                qclass: DnsClass::IN,
            });
            wrong.answers.push(answer(wrong_name));
            socket.send_to(&wrong.try_encode().unwrap(), peer).unwrap();

            let origin = request.questions[0].name.clone();
            let mut correct = Message::default();
            correct.header.id = request.header.id;
            correct.header.response = true;
            correct.header.authoritative = true;
            correct.questions = request.questions;
            correct.answers.push(answer(origin));
            socket
                .send_to(&correct.try_encode().unwrap(), peer)
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let entry = XferEntry {
            origin: "probe.secondary.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let mut prober = SecondarySoaProber::new(std::slice::from_ref(&entry)).unwrap();
        let started = prober.start(
            SecondaryRefreshJob {
                entry,
                current_serial: None,
                had_zone: false,
                last_ok: unix_now(),
                refresh: 300,
                retry: 60,
                expire: 86_400,
                priority: true,
                force_axfr: false,
            },
            &[],
            Duration::from_secs(1),
        );
        assert!(started.is_ok());
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let serial = loop {
            if let Some(result) = prober.poll(&[]).pop() {
                break result.result.unwrap();
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(serial, 42);
        assert_eq!(prober.len(), 0);
        server.join().unwrap();
    }

    #[test]
    /** @brief 답 없는 상대 여럿이 멀쩡한 영역의 갱신을 막지 않는지. */
    fn eight_stalled_secondaries_do_not_block_another_zone_refresh() {
        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let (fast_addr, fast_server) = secondary_soa_test_server(Duration::ZERO, Some(observed_tx));
        let zone = |origin: &str| {
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap()
        };
        let mut zones = onetdns_authority::ZoneStore::new();
        let secondary =
            |origin: &str, address: std::net::SocketAddr| onetdns_config::SecondaryZone {
                origin: origin.to_string(),
                file: None,
                primary: Some(address.ip()),
                primary_port: Some(address.port()),
                tsig_key: None,
            };
        let mut config = Config::default();
        let mut slow_servers = Vec::new();
        for index in 0..8 {
            let origin = format!("slow-{index}.secondary.test");
            let (address, server) = secondary_soa_test_server(Duration::from_millis(1_500), None);
            zones.add(zone(&origin));
            config.secondary.push(secondary(&origin, address));
            slow_servers.push(server);
        }
        zones.add(zone("fast-secondary.test"));
        config
            .secondary
            .push(secondary("fast-secondary.test", fast_addr));
        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let started = std::time::Instant::now();
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store,
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(2),
        )
        .unwrap();

        let observed = observed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            observed.duration_since(started) < Duration::from_millis(750),
            "8개 느린 primary의 1.5초 대기가 정상 영역의 SOA 확인을 막았습니다"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push("fast-secondary.test".to_string());
        coordinator.join().unwrap();
        for server in slow_servers {
            server.join().unwrap();
        }
        fast_server.join().unwrap();

        assert_eq!(secondary_refresh_parallelism(0), 1);
        assert_eq!(secondary_refresh_parallelism(2), 2);
        assert_eq!(secondary_refresh_parallelism(usize::MAX), 4);
    }

    /**
     * @brief TCP와 UDP가 같은 포트를 쓰는 테스트용 소켓 쌍.
     *
     * @details 임시 포트 하나가 TCP 에서 비어도 UDP 에서는 못 열 수 있다. 남이 잡고
     *          있으면 주소 사용 중이지만, Windows 는 Hyper-V 가 예약한 대역이면 권한
     *          거부를 준다. 둘 다 그 포트만의 사정이므로 다음 번호로 넘어간다.
     * @note 어긋난 TCP 소켓은 성공할 때까지 잡고 있는다. 놓아 버리면 운영체제가 같은
     *       번호를 다시 줘서 같은 위치를 맴돌 수 있다.
     * @warning 임시 포트는 번호순으로 나오고 예약 대역은 이어져 있다. 잡은 채로 다시 걸면
     *          대역을 걸어서 지나가므로, 시도 수가 가장 긴 대역보다 넉넉해야 빠져나온다.
     */
    fn tcp_udp_test_listeners() -> (
        std::net::TcpListener,
        std::net::UdpSocket,
        std::net::SocketAddr,
    ) {
        use std::io::ErrorKind;

        /** @brief 이어진 예약 대역을 걸어서 지나가고도 남을 시도 수. */
        const ATTEMPTS: usize = 512;

        let mut taken = Vec::new();
        for _ in 0..ATTEMPTS {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            match std::net::UdpSocket::bind(address) {
                Ok(udp) => return (listener, udp, address),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                    ) =>
                {
                    taken.push(listener)
                }
                Err(error) => panic!("TCP와 함께 쓸 UDP 소켓을 열지 못했습니다: {error}"),
            }
        }
        panic!("TCP와 UDP가 함께 빈 테스트용 포트를 찾지 못했습니다");
    }

    /** @brief 접속 진행을 테스트할 서버. */
    fn secondary_xfr_admission_test_server(
        origin: String,
        stall_after_query: bool,
        observed: std::sync::mpsc::Sender<(String, std::time::Instant)>,
        soa_gate: Option<std::sync::mpsc::Receiver<()>>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::Message;
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let soa_request = Message::parse(&wire[..length]).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            if let Some(gate) = soa_gate {
                gate.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query_wire = vec![0; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut query_wire).unwrap();
            observed
                .send((origin.clone(), std::time::Instant::now()))
                .unwrap();
            if stall_after_query {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte);
                return;
            }

            let query = Message::parse(&query_wire).unwrap();
            let mut response = Message::default();
            response.header.id = query.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = query.questions;
            response.answers = zone.axfr_records();
            let response_wire = response.try_encode().unwrap();
            stream
                .write_all(&(response_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response_wire).unwrap();
        });
        (address, server)
    }

    /** @brief 바뀐 부분만 보내기를 지원하지 않는 테스트용 업스트림 서버. */
    fn ixfr_notimp_primary(
        origin: String,
        seen: std::sync::mpsc::Sender<onetdns_proto::RecordType>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::{Message, RecordType};
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let soa_request = Message::parse(&wire[..length]).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query_wire = vec![0; u16::from_be_bytes(length) as usize];
                stream.read_exact(&mut query_wire).unwrap();
                let query = Message::parse(&query_wire).unwrap();
                let qtype = query.questions[0].qtype;
                seen.send(qtype).unwrap();

                let mut response = Message::default();
                response.header.id = query.header.id;
                response.header.response = true;
                response.header.authoritative = true;
                response.questions = query.questions;
                if qtype == RecordType(251) {
                    response.header.rcode = onetdns_proto::ResponseCode::NotImp.0;
                } else {
                    response.answers = zone.axfr_records();
                }
                let response_wire = response.try_encode().unwrap();
                stream
                    .write_all(&(response_wire.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&response_wire).unwrap();
                if qtype != RecordType(251) {
                    return;
                }
            }
        });
        (address, server)
    }

    /** @brief 첫 청크 뒤로 멈추는 테스트용 업스트림 서버. */
    fn stalls_after_first_frame_primary(
        origin: String,
        sent: std::sync::mpsc::Sender<()>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::Message;
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let soa_request = Message::parse(&wire[..length]).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query_wire = vec![0; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut query_wire).unwrap();
            let query = Message::parse(&query_wire).unwrap();

            let mut response = Message::default();
            response.header.id = query.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = query.questions;
            response.answers = vec![zone.axfr_records_iter().next().unwrap()];
            let response_wire = response.try_encode().unwrap();
            stream
                .write_all(&(response_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response_wire).unwrap();
            sent.send(()).unwrap();

            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
        });
        (address, server)
    }

    /** @brief SOA와 두 XFR frame을 모두 올바른 TSIG 체인으로 보내는 테스트용 업스트림 서버. */
    fn signed_secondary_xfr_primary(
        origin: String,
        key: onetdns_dnssec::tsig::TsigKey,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_dnssec::tsig;
        use onetdns_proto::Message;
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ 120 IN SOA ns admin 2 300 60 86400 60\n@ 120 IN NS ns\nns 120 IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let (soa_wire, soa_request_mac) =
                tsig::verify_wire(&wire[..length], &key, unix_now(), None).unwrap();
            let soa_request = Message::parse(&soa_wire).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            tsig::sign_message(&mut soa_response, &key, unix_now(), Some(&soa_request_mac))
                .unwrap();
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut request_length = [0u8; 2];
            stream.read_exact(&mut request_length).unwrap();
            let mut request_wire = vec![0; u16::from_be_bytes(request_length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let (query_wire, request_mac) =
                tsig::verify_wire(&request_wire, &key, unix_now(), None).unwrap();
            let query = Message::parse(&query_wire).unwrap();
            let records = zone.axfr_records();

            let mut first = Message::default();
            first.header.id = query.header.id;
            first.header.response = true;
            first.header.authoritative = true;
            first.questions = query.questions;
            first
                .answers
                .extend_from_slice(&records[..records.len() - 1]);
            let first_mac =
                tsig::sign_message(&mut first, &key, unix_now(), Some(&request_mac)).unwrap();
            let first_wire = first.try_encode().unwrap();
            stream
                .write_all(&(first_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&first_wire).unwrap();

            let mut last = Message::default();
            last.header.id = query.header.id;
            last.header.response = true;
            last.header.authoritative = true;
            last.answers.push(records.last().unwrap().clone());
            tsig::sign_subsequent(&mut last, &key, unix_now(), &first_mac).unwrap();
            let last_wire = last.try_encode().unwrap();
            stream
                .write_all(&(last_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&last_wire).unwrap();
        });
        (address, server)
    }

    #[test]
    /** @brief 여러 전송이 하나의 수신 버퍼 상한을 공유하고 반환하는지. */
    fn xfr_response_buffer_budget_is_global_and_released_on_drop() {
        let budget = Arc::new(XfrBufferBudget::new(64));
        let mut first = budget.reservation();
        let mut second = budget.reservation();
        assert!(first.try_grow(40));
        assert!(!second.try_grow(25));
        assert!(second.try_grow(24));
        assert_eq!(budget.used(), 64);

        drop(first);
        assert_eq!(budget.used(), 24);
        assert!(second.try_grow(40));
        assert_eq!(budget.used(), 64);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    /** @brief nonblocking 다중 frame 수신 뒤에도 요청 MAC부터 이어진 TSIG 체인을 검증하는지. */
    fn secondary_nonblocking_xfr_preserves_multi_frame_tsig_chain() {
        let origin = "signed-secondary.test";
        let key = onetdns_dnssec::tsig::TsigKey::new(
            onetdns_proto::Name::from_str("secondary-xfr-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let (address, server) = signed_secondary_xfr_primary(origin.to_string(), key.clone());

        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ 120 IN SOA ns admin 1 300 60 86400 60\n@ 120 IN NS ns\nns 120 IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap(),
        );
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: origin.to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: Some("secondary-xfr-key".to_string()),
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            vec![key],
            store.clone(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(2),
        )
        .unwrap();

        let name = onetdns_proto::Name::from_str(origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if store
                .load()
                .zone_exact(&name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "TSIG 다중 frame XFR가 검증·적용되지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            store
                .load()
                .zone_exact(&name)
                .unwrap()
                .axfr_records_iter()
                .next()
                .unwrap()
                .ttl,
            120
        );

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push(origin.to_string());
        coordinator.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    /** @brief 첫 청크 뒤로 멈춘 상대가 워커를 계속 붙잡지 않는지. */
    fn primaries_that_stall_after_the_first_frame_release_their_parser_slot() {
        let mut config = Config::default();
        let mut zones = onetdns_authority::ZoneStore::new();
        let mut servers = Vec::new();
        let stalled = SECONDARY_REFRESH_MAX_IN_FLIGHT * 2;
        let (stalled_tx, stalled_rx) = std::sync::mpsc::channel();
        for index in 0..stalled {
            let origin = format!("frame-stall-{index}.secondary.test");
            let (address, server) =
                stalls_after_first_frame_primary(origin.clone(), stalled_tx.clone());
            zones.add(
                onetdns_authority::parse_zone(
                    &format!(
                        "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                    ),
                    &origin,
                )
                .unwrap(),
            );
            config.secondary.push(onetdns_config::SecondaryZone {
                origin: origin.clone(),
                file: None,
                primary: Some(address.ip()),
                primary_port: Some(address.port()),
                tsig_key: None,
            });
            servers.push(server);
        }
        drop(stalled_tx);

        let fast_origin = "frame-fast.secondary.test";
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (observed_tx, _observed_rx) = std::sync::mpsc::channel();
        let (fast_address, fast_server) = secondary_xfr_admission_test_server(
            fast_origin.to_string(),
            false,
            observed_tx,
            Some(gate_rx),
        );
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {fast_origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                fast_origin,
            )
            .unwrap(),
        );
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: fast_origin.to_string(),
            file: None,
            primary: Some(fast_address.ip()),
            primary_port: Some(fast_address.port()),
            tsig_key: None,
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let started = std::time::Instant::now();
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store.clone(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(10),
        )
        .unwrap();

        for _ in 0..stalled {
            stalled_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        gate_tx.send(()).unwrap();

        let fast_name = onetdns_proto::Name::from_str(fast_origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(750);
        loop {
            if store
                .load()
                .zone_exact(&fast_name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "첫 frame 뒤 멈춘 8개 원본이 정상 영역의 parser 진입을 막았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "정상 영역은 stalled 원본의 2초 idle timeout 전에 수렴해야 합니다"
        );

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push(fast_origin.to_string());
        coordinator.join().unwrap();
        for server in servers {
            server.join().unwrap();
        }
        fast_server.join().unwrap();
    }

    #[test]
    /** @brief 바뀐 부분만 못 받는 상대에게서도 결국 받아 오는지. */
    fn secondary_recovers_from_an_ixfr_only_notimp_primary() {
        let origin = "notimp.secondary.test";
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (address, server) = ixfr_notimp_primary(origin.to_string(), seen_tx);

        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap(),
        );
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: origin.to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: None,
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store.clone(),
            Arc::new(native::NotifyKick::default()),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_millis(1_500),
        )
        .unwrap();

        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            onetdns_proto::RecordType(251),
            "기준 영역이 있으면 먼저 IXFR로 묻는다"
        );
        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            onetdns_proto::RecordType(252),
            "NOTIMP 뒤에는 AXFR로 다시 물어야 한다"
        );

        let name = onetdns_proto::Name::from_str(origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if store
                .load()
                .zone_exact(&name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "IXFR를 지원하지 않는 primary에서 영역을 받지 못했습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = coordinator.join();
        let _ = server.join();
    }

    #[test]
    /** @brief 접속만 걸고 멈춘 상대들이 전송 워커를 차지하지 않는지. */
    fn eight_tcp_stalled_secondaries_do_not_consume_xfr_workers() {
        let zone = |origin: &str| {
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap()
        };
        let secondary =
            |origin: &str, address: std::net::SocketAddr| onetdns_config::SecondaryZone {
                origin: origin.to_string(),
                file: None,
                primary: Some(address.ip()),
                primary_port: Some(address.port()),
                tsig_key: None,
            };
        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let mut zones = onetdns_authority::ZoneStore::new();
        let mut config = Config::default();
        let mut servers = Vec::new();
        for index in 0..8 {
            let origin = format!("tcp-stall-{index}.secondary.test");
            let (address, server) = secondary_xfr_admission_test_server(
                origin.clone(),
                true,
                observed_tx.clone(),
                None,
            );
            zones.add(zone(&origin));
            config.secondary.push(secondary(&origin, address));
            servers.push(server);
        }
        let fast_origin = "tcp-fast.secondary.test";
        let (fast_address, fast_server) =
            secondary_xfr_admission_test_server(fast_origin.to_string(), false, observed_tx, None);
        zones.add(zone(fast_origin));
        config.secondary.push(secondary(fast_origin, fast_address));

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let started = std::time::Instant::now();
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store.clone(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_millis(1_500),
        )
        .unwrap();

        let mut observed = Vec::new();
        for _ in 0..9 {
            observed.push(observed_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        }
        assert!(
            observed
                .iter()
                .all(|(_, at)| at.duration_since(started) < Duration::from_millis(750)),
            "8개 TCP 무응답 원본 뒤의 정상 원본까지 즉시 admission되어야 합니다"
        );
        let fast_name = onetdns_proto::Name::from_str(fast_origin).unwrap();
        let deadline = started + Duration::from_millis(750);
        loop {
            if store
                .load()
                .zone_exact(&fast_name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "TCP에서 멈춘 8개 원본이 정상 영역 전송을 막았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push(fast_origin.to_string());
        coordinator.join().unwrap();
        for server in servers {
            server.join().unwrap();
        }
        fast_server.join().unwrap();
    }

    #[test]
    /** @brief 받아 둔 것이 없어도 시작이 망을 기다리며 멈추지 않는지. */
    fn missing_secondary_cache_never_blocks_service_startup_on_network() {
        let primary = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        primary
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let address = primary.local_addr().unwrap();
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: "startup-secondary.test".to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: None,
        });

        let started = std::time::Instant::now();
        let store = build_zone_store(&config, &[], &[]).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(store.zones().is_empty());
        let mut wire = [0u8; 512];
        let error = primary.recv_from(&mut wire).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    /** @brief 알림에 쓰는 이름과 일정에 쓰는 이름이 같은 형태인지. 다르면 알림이 그 영역을 못 찾는다. */
    fn secondary_scheduler_key_matches_notify_name_canonical_form() {
        let config = onetdns_config::SecondaryZone {
            origin: "MiXeD.Secondary.Test.".to_string(),
            file: None,
            primary: Some("192.0.2.53".parse().unwrap()),
            primary_port: Some(53),
            tsig_key: None,
        };
        assert_eq!(
            XferEntry::from_cfg(&config, false).unwrap().origin,
            "mixed.secondary.test"
        );
    }

    #[test]
    /** @brief 설정이 바뀐 뒤 이전 전송 결과를 반영하지 않는지. */
    fn stale_secondary_job_requires_an_exact_configuration_match() {
        let entry = XferEntry {
            origin: "exact.secondary.test".to_string(),
            file: Some(std::path::PathBuf::from("secondary.zone")),
            primary: "192.0.2.53".parse().unwrap(),
            port: 53,
            tsig_key: Some("transfer-key".to_string()),
            is_catalog: false,
        };
        let job = SecondaryRefreshJob {
            entry: entry.clone(),
            current_serial: Some(1),
            had_zone: true,
            last_ok: 0,
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: false,
            force_axfr: false,
        };
        assert!(secondary_entry_is_current(
            std::slice::from_ref(&entry),
            &job
        ));

        let mut changed_key = entry.clone();
        changed_key.tsig_key = Some("replacement-key".to_string());
        assert!(!secondary_entry_is_current(&[changed_key], &job));

        let mut changed_file = entry;
        changed_file.file = Some(std::path::PathBuf::from("replacement.zone"));
        assert!(!secondary_entry_is_current(&[changed_file], &job));
    }

    #[test]
    /** @brief 너무 오래된 것은 되살리지 않는지. */
    fn secondary_cache_restores_only_with_unexpired_refresh_state() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-secondary-cache-{}-{}.zone",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let zone = onetdns_authority::parse_zone(
            "$ORIGIN cached-secondary.test.\n@ IN SOA ns admin 7 300 60 120 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "cached-secondary.test",
        )
        .unwrap();
        atomic_write(&path, zone.to_master_file().as_bytes()).unwrap();
        mark_secondary_refresh(&path, unix_now().saturating_sub(30)).unwrap();
        let config = onetdns_config::SecondaryZone {
            origin: "cached-secondary.test".into(),
            file: Some(path.clone()),
            primary: Some("192.0.2.53".parse().unwrap()),
            primary_port: Some(53),
            tsig_key: None,
        };
        let origin = onetdns_proto::Name::from_str("cached-secondary.test").unwrap();
        assert_eq!(
            load_secondary_cache(&config, &Config::default(), &origin)
                .unwrap()
                .soa()
                .serial,
            7
        );

        std::fs::remove_file(secondary_refresh_state_path(&path)).unwrap();
        assert!(load_secondary_cache(&config, &Config::default(), &origin).is_none());
        mark_secondary_refresh(&path, unix_now().saturating_sub(121)).unwrap();
        assert!(load_secondary_cache(&config, &Config::default(), &origin).is_none());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(secondary_refresh_state_path(&path));
    }

    #[test]
    /** @brief 저장에 실패하면 저장소와 변경 기록을 되돌리는지. 안 되돌리면 파일과 메모리가 어긋난다. */
    fn failed_zone_persistence_keeps_store_and_ixfr_journal_unchanged() {
        let old = onetdns_authority::parse_zone(
            "$ORIGIN atomic.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "atomic.test",
        )
        .unwrap();
        let replacement = onetdns_authority::parse_zone(
            "$ORIGIN atomic.test.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nnew IN A 192.0.2.2\n",
            "atomic.test",
        )
        .unwrap();
        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(old);
        let store = onetdns_core::ArcSwap::new(Arc::new(zones));
        let journal = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let missing_parent = std::env::temp_dir().join(format!(
            "onetdns-no-parent-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let path = missing_parent.join("atomic.test.zone");

        let result = apply_zone_mutation(
            &store,
            replacement,
            &[],
            &journal,
            Some(&path),
            &NotifySender::disabled(),
            "test",
        );
        assert!(result.is_err());
        assert_eq!(store.load().zones()[0].soa().serial, 1);
        assert!(journal.lock_recover().is_empty());
    }

    #[test]
    /** @brief 설정 텍스트에 못 쓰는 문자를 제대로 감싸는지. */
    fn toml_quote_escapes_control_characters() {
        assert_eq!(toml_quote("a\n\tb\u{7f}"), "\"a\\n\\tb\\u007F\"");
        assert_eq!(
            toml_string_array(&["a\nb".to_string(), "c\"d".to_string()]),
            "[\"a\\nb\", \"c\\\"d\"]"
        );
    }

    #[test]
    /** @brief 신뢰 앵커 신호가 내장 앵커가 아니라 실제로 쓰는 앵커의 키 태그를 담는지. */
    fn ta_signal_label_uses_the_configured_anchors() {
        let anchor = |key_tag| onetdns_dnssec::Ds {
            key_tag,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0; 32],
        };
        assert_eq!(ta_signal_label(&[]), None);
        assert_eq!(
            ta_signal_label(&[anchor(0x1234), anchor(0x00ab), anchor(0x1234)]).as_deref(),
            Some("_ta-00ab-1234")
        );
        let builtin = onetdns_dnssec::root_trust_anchors();
        assert_ne!(
            ta_signal_label(&[anchor(0x1234)]),
            ta_signal_label(&builtin),
            "사용자 앵커를 쓰면 내장 앵커와 다른 신호가 나가야 한다"
        );
    }

    #[test]
    /** @brief 어떤 설정을 재시작하지 않고 바꿀 수 있는지 구분하는지. */
    fn hot_reload_key_classification() {
        assert!(config_keys::is_hot("block_rules"));
        assert!(config_keys::is_hot("clients"));
        assert!(config_keys::is_hot("acl_allow"));
        assert!(config_keys::is_hot("querylog"));
        assert!(config_keys::is_hot("listen"));
        assert!(config_keys::is_hot("upstream_urls"));
        for key in [
            "block_aaaa",
            "dns64_prefix",
            "policy",
            "views",
            "querylog_file",
            "stats_file",
        ] {
            assert!(config_keys::is_hot(key), "{key} must remain hot-reloadable");
        }
        let mut cold_keys: Vec<_> = onetdns_config::known_keys()
            .iter()
            .copied()
            .filter(|key| !config_keys::is_hot(key))
            .collect();
        cold_keys.sort_unstable();
        assert_eq!(cold_keys, ["run_as_group", "run_as_user"]);
        assert!(config_keys::is_hot("tls_cert"));
    }

    #[test]
    /** @brief 사용자가 DHCPv6 임대 수명을 바꾸면 실행 중 서버가 새 설정으로 교체되는지. */
    fn dhcp6_lease_lifetime_changes_edge_service_identity() {
        let mut cfg = Config {
            dhcp6_enable: true,
            dhcp6_range_start: Some("2001:db8::100".to_string()),
            dhcp6_range_end: Some("2001:db8::1ff".to_string()),
            ..Config::default()
        };
        let before = edge_service_keys(&cfg);

        cfg.dhcp_lease_secs = cfg.dhcp_lease_secs.saturating_add(1);

        assert_ne!(before, edge_service_keys(&cfg));
    }

    #[test]
    /** @brief DHCPv6 multicast 링크를 바꾸면 이전 socket을 새 인터페이스로 교체하는지. */
    fn dhcp6_interface_changes_edge_service_identity() {
        let mut cfg = Config {
            dhcp6_enable: true,
            dhcp6_range_start: Some("2001:db8::100".to_string()),
            dhcp6_range_end: Some("2001:db8::1ff".to_string()),
            ..Config::default()
        };
        let before = edge_service_keys(&cfg);

        cfg.dhcp6_interface_index = 17;

        assert_ne!(before, edge_service_keys(&cfg));
    }

    #[test]
    /**
     * @brief 무중단으로 바뀌는 설정이 빠른 경로 조건을 깨면 그 경로가 닫히는지.
     *
     * @details 빠른 경로는 지어질 때의 설정을 전제로 답한다. 조건을 깨는 설정을 무중단으로
     *          받아 놓고 경로를 열어 두면 캐시를 껐는데 이전 답이 나가고, 켠 기능이 없는 것
     *          처럼 답한다. 여기서 걸리면 그 설정을 무중단 목록에서 빼거나 조건에 넣어야
     *          한다.
     */
    fn hot_settings_that_break_a_lane_close_that_lane() {
        let facts = LaneFacts {
            dhcp_pool: true,
            views_present: false,
            policy_present: false,
        };
        let base = {
            let mut cfg = Config::default();
            cfg.cache_enabled = true;
            cfg.cache_size = 1000;
            cfg.min_ttl = 0;
            cfg.dhcp_local_domain = String::new();
            cfg
        };
        assert!(
            evaluate_lane_gates(&base, &facts).wire,
            "기본 설정에서 빠른 경로가 열려 있어야 이 테스트가 뜻을 가집니다"
        );

        let breakers: Vec<(&str, fn(&mut Config))> = vec![
            ("cache_enabled", |c| c.cache_enabled = false),
            ("cache_size", |c| c.cache_size = 0),
            ("min_ttl", |c| c.min_ttl = 60),
            ("prefetch", |c| c.prefetch = true),
            ("ecs_mode", |c| c.ecs_mode = EcsMode::Strip),
            ("dns64_prefix", |c| {
                c.dns64_prefix = Some("64:ff9b::/96".to_string())
            }),
            ("rrset_roundrobin", |c| c.rrset_roundrobin = true),
            ("dhcp_local_domain", |c| {
                c.dhcp_local_domain = "lan".to_string()
            }),
            ("name_ratelimit_per_sec", |c| c.name_ratelimit_per_sec = 10),
            ("block_aaaa", |c| c.block_aaaa = true),
            ("domain_needed", |c| c.domain_needed = true),
            ("bogus_priv", |c| c.bogus_priv = true),
            ("empty_zones", |c| c.empty_zones = true),
            ("edns_padding_block", |c| c.edns_padding_block = 128),
            ("cookies", |c| c.cookies = CookieMode::Strict),
            ("dnstap_file", |c| {
                c.dnstap_file = Some(std::path::PathBuf::from("dnstap.log"))
            }),
            ("acme_directory_url", |c| {
                c.acme_directory_url = Some("https://acme.test/dir".to_string())
            }),
            ("dynamic_records", |c| {
                c.dynamic_records.push(onetdns_config::DynamicRecord {
                    name: "www.example.test".to_string(),
                    ..Default::default()
                })
            }),
            ("secondary", |c| {
                c.secondary.push(onetdns_config::SecondaryZone {
                    origin: "slave.test".to_string(),
                    ..Default::default()
                })
            }),
            ("catalog", |c| {
                c.catalog.push(onetdns_config::SecondaryZone {
                    origin: "catalog.test".to_string(),
                    ..Default::default()
                })
            }),
            ("clients", |c| {
                c.clients.push(onetdns_config::ClientConfig {
                    name: "kid".to_string(),
                    upstreams: vec!["9.9.9.9".parse().unwrap()],
                    ..Default::default()
                })
            }),
        ];
        for (key, break_it) in breakers {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            break_it(&mut cfg);
            assert!(
                !evaluate_lane_gates(&cfg, &facts).wire,
                "{key}를 무중단으로 켜면 wire 빠른 경로가 닫혀야 합니다"
            );
        }

        let ipset_breakers: [(&str, fn(&mut Config)); 2] = [
            ("ipset_name_v4", |c| {
                c.ipset_name_v4 = Some("blocked4".to_string())
            }),
            ("ipset_name_v6", |c| {
                c.ipset_name_v6 = Some("blocked6".to_string())
            }),
        ];
        for (key, name_it) in ipset_breakers {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            name_it(&mut cfg);
            assert!(
                evaluate_lane_gates(&cfg, &facts).wire,
                "{key}만 있고 ipset_domains가 비면 ipset 계층이 없으므로 wire 빠른 경로가 열려 있어야 합니다"
            );
            cfg.ipset_domains = vec!["ads.example".to_string()];
            assert_eq!(
                evaluate_lane_gates(&cfg, &facts).wire,
                !cfg!(target_os = "linux"),
                "{key}와 ipset_domains를 함께 켜면 ipset 계층이 서는 Linux에서만 wire 빠른 경로가 닫혀야 합니다"
            );
        }

        for (key, break_it) in [
            (
                "cachedb_redis_host",
                (|c: &mut Config| c.cachedb_redis_host = Some("127.0.0.1".to_string()))
                    as fn(&mut Config),
            ),
            ("serve_stale_secs", |c: &mut Config| c.serve_stale_secs = 60),
            ("aggressive_nsec", |c: &mut Config| c.aggressive_nsec = true),
            ("harden_below_nxdomain", |c: &mut Config| {
                c.harden_below_nxdomain = true
            }),
            ("stub_zones", |c: &mut Config| {
                c.stub_zones.push(onetdns_config::StubZone {
                    suffix: "corp.test".to_string(),
                    servers: vec!["10.0.0.1".to_string()],
                })
            }),
            ("backend", |c: &mut Config| c.backend = BackendKind::Forward),
        ] {
            assert!(
                config_keys::is_hot(key),
                "{key}가 무중단 목록에서 빠졌습니다. 테스트를 함께 고치십시오"
            );
            let mut cfg = base.clone();
            cfg.backend = BackendKind::Recurse;
            break_it(&mut cfg);
            assert!(
                !evaluate_lane_gates(&cfg, &facts).reactor,
                "{key}를 무중단으로 켜면 리액터 레인이 닫혀야 합니다"
            );
        }
    }

    #[test]
    /** @brief 기본 설정이 실제 질의 기능 세트에도 lenient 쿠키를 만드는지. */
    fn default_native_features_enable_lenient_cookies() {
        let features = build_native_features(
            &Config::default(),
            None,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
            None,
        )
        .unwrap();

        assert!(
            features.cookies.keeper.is_some(),
            "기본 서버 쿠키 비밀 생성"
        );
        assert!(
            !features.cookies.strict,
            "기본값은 쿠키 없는 클라이언트를 거부하지 않음"
        );
    }

    #[test]
    /** @brief 같은 Raft 비밀의 노드는 쿠키를 공유하고 비밀 hot-reload는 즉시 갈리는지. */
    fn raft_nodes_share_cookie_keys_and_secret_reload_rotates_them() {
        let mut first_cfg = Config {
            cluster_raft: true,
            cluster_node_id: 1,
            cluster_raft_secret: "shared-cluster-secret-at-least-32-bytes".into(),
            ..Config::default()
        };
        let mut second_cfg = first_cfg.clone();
        second_cfg.cluster_node_id = 2;
        let build = |cfg: &Config| {
            build_native_features(
                cfg,
                None,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                None,
                None,
            )
            .unwrap()
        };
        let cookie = |features: &native::NativeFeatures| {
            features.cookies.keeper.as_ref().unwrap().server_cookie_at(
                &[1, 2, 3, 4, 5, 6, 7, 8],
                "192.0.2.53".parse().unwrap(),
                1_800_000_000,
            )
        };

        let first = build(&first_cfg);
        let second = build(&second_cfg);
        assert_eq!(cookie(&first), cookie(&second), "노드 ID와 무관한 공유 키");

        first_cfg.cluster_raft_secret = "replacement-cluster-secret-at-least-32".into();
        let changed = vec!["cluster_raft_secret".to_string()];
        let reloaded = reconfigure_native_features(&first, &first_cfg, &changed).unwrap();
        assert_ne!(
            cookie(&first),
            cookie(&reloaded),
            "공용 비밀 변경은 새 Cookie 루트를 원자적으로 교체합니다"
        );
    }

    #[test]
    /** @brief Raft 쿠키 루트 입력이 바뀌면 cluster와 native 그룹을 함께 준비하는지. */
    fn raft_cookie_root_changes_rebuild_native_features() {
        let previous = Config::default();
        let mut staged = previous.clone();
        staged.cluster_raft_secret = "shared-cluster-secret-at-least-32-bytes".into();
        assert_eq!(
            hot_reload_groups(&previous, &staged, &["cluster_raft_secret".to_string()]),
            vec![ApplyGroup::Cluster],
            "Raft를 켜기 전 비밀 준비는 독립 실행 Cookie를 무효화하지 않습니다"
        );

        let mut next = staged.clone();
        next.cluster_raft = true;

        assert_eq!(
            hot_reload_groups(&staged, &next, &["cluster_raft".to_string()]),
            vec![ApplyGroup::Cluster, ApplyGroup::Native]
        );
    }

    #[test]
    /** @brief DDR은 특수 이름 하나만 가로채므로 나머지 cache-hit·cold-miss 레인을 닫지 않는지. */
    fn ddr_keeps_general_udp_lanes_open() {
        let mut cfg = Config {
            backend: BackendKind::Recurse,
            cache_enabled: true,
            cache_size: 1_000,
            min_ttl: 0,
            ddr_name: "dns.example".to_string(),
            ..Config::default()
        };
        cfg.acme_directory_url = None;
        let gates = evaluate_lane_gates(
            &cfg,
            &LaneFacts {
                dhcp_pool: false,
                views_present: false,
                policy_present: false,
            },
        );
        assert!(gates.wire);
        if cfg!(unix) {
            assert!(gates.reactor);
        }
    }

    #[test]
    /** @brief DDR이 광고하는 수신 주소가 바뀌면 해석 체인도 반드시 다시 만들어지는지. */
    fn encrypted_listener_change_rebuilds_ddr_chain_only_when_needed() {
        let plain = Config::default();
        let mut changed = plain.clone();
        changed.listen_doh = vec!["127.0.0.1:8443".parse().unwrap()];
        let keys = vec!["listen_doh".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &changed, &keys),
            vec![ApplyGroup::Listeners]
        );

        let mut with_ddr = plain;
        with_ddr.ddr_name = "dns.example".to_string();
        let mut next = changed;
        next.ddr_name = with_ddr.ddr_name.clone();
        assert_eq!(
            hot_reload_groups(&with_ddr, &next, &keys),
            vec![ApplyGroup::Chain, ApplyGroup::Listeners]
        );
    }

    #[test]
    /** @brief 전달 설정은 체인이 그 값을 쓰는 전달기가 있을 때만 체인을 다시 만드는지. */
    fn forward_settings_rebuild_the_chain_only_when_the_chain_uses_them() {
        let plain = Config::default();
        let mut slower = plain.clone();
        slower.query_timeout_secs = plain.query_timeout_secs + 3;
        let timeout = vec!["query_timeout_secs".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &slower, &timeout),
            vec![ApplyGroup::Forward]
        );

        let mut with_stub = plain.clone();
        with_stub.stub_zones.push(onetdns_config::StubZone {
            suffix: "corp.test".to_string(),
            servers: vec!["192.0.2.53".to_string()],
        });
        let mut stub_slower = with_stub.clone();
        stub_slower.query_timeout_secs = slower.query_timeout_secs;
        assert_eq!(
            hot_reload_groups(&with_stub, &stub_slower, &timeout),
            vec![ApplyGroup::Chain, ApplyGroup::Forward]
        );

        let mut with_fallback = plain;
        with_fallback.fallback_upstreams = vec!["192.0.2.54".to_string()];
        let mut fallback_parallel = with_fallback.clone();
        fallback_parallel.upstream_strategy = UpstreamStrategy::Parallel;
        assert_eq!(
            hot_reload_groups(
                &with_fallback,
                &fallback_parallel,
                &["upstream_strategy".to_string()]
            ),
            vec![ApplyGroup::Chain, ApplyGroup::Forward]
        );
    }

    #[test]
    /** @brief 영역이 생기거나 사라질 때만 체인을 다시 만들고, 영역 편집은 저장소 교체로 끝나는지. */
    fn zone_edits_rebuild_the_chain_only_when_the_authority_layer_appears() {
        let zone = |origin: &str| onetdns_config::ZoneConfig {
            origin: origin.to_string(),
            ..Default::default()
        };
        let plain = Config::default();
        let mut one = plain.clone();
        one.zones.push(zone("a.test"));
        let mut two = one.clone();
        two.zones.push(zone("b.test"));
        let keys = vec!["zones".to_string()];
        assert_eq!(
            hot_reload_groups(&plain, &one, &keys),
            vec![ApplyGroup::Authority, ApplyGroup::Chain]
        );
        assert_eq!(
            hot_reload_groups(&one, &two, &keys),
            vec![ApplyGroup::Authority]
        );
        assert_eq!(
            hot_reload_groups(&one, &plain, &keys),
            vec![ApplyGroup::Authority, ApplyGroup::Chain]
        );
    }

    #[test]
    /** @brief 권한 빠른 경로도 무중단 설정에 따라 닫히는지. */
    fn hot_settings_that_break_the_authority_lane_close_it() {
        let facts = LaneFacts {
            dhcp_pool: false,
            views_present: false,
            policy_present: false,
        };
        let mut base = Config::default();
        base.zones.push(onetdns_config::ZoneConfig {
            origin: "example.test".to_string(),
            ..Default::default()
        });
        assert!(evaluate_lane_gates(&base, &facts).authority);

        let mut with_acme = base.clone();
        with_acme.acme_directory_url = Some("https://acme.test/dir".to_string());
        assert!(!evaluate_lane_gates(&with_acme, &facts).authority);

        let mut with_dynamic = base;
        with_dynamic
            .dynamic_records
            .push(onetdns_config::DynamicRecord {
                name: "www.example.test".to_string(),
                ..Default::default()
            });
        assert!(!evaluate_lane_gates(&with_dynamic, &facts).authority);
    }

    #[test]
    /** @brief 목록 출처가 바뀌어도 재시작하지 않는지. */
    fn subscription_source_changes_stay_hot() {
        for key in [
            "blocklist_urls",
            "blocklist_titles",
            "disabled_blocklist_urls",
            "list_refresh_secs",
            "rpz_urls",
            "safe_browsing",
            "parental_control",
        ] {
            assert!(config_keys::is_hot(key), "{key}는 무중단이어야 합니다");
            assert_eq!(config_keys::hot_group(key), Some(ApplyGroup::Subscriptions));
        }
    }

    #[test]
    /** @brief 서로 다른 그룹이 따로 판정되는지. */
    fn unrelated_hot_reload_groups_remain_independently_classified() {
        let mut groups = ["block_rules", "acl_allow"]
            .iter()
            .filter_map(|key| config_keys::hot_group(key))
            .collect::<Vec<_>>();
        groups.sort_unstable();
        groups.dedup();
        assert_eq!(groups, [ApplyGroup::Acl, ApplyGroup::Filter]);
    }

    #[test]
    /** @brief 기록 파일을 못 열었을 때 조용히 끄지 않는지. */
    fn configured_dnstap_open_failure_is_not_silently_disabled() {
        let mut config = Config::default();
        config.dnstap_file = Some(std::env::temp_dir());
        assert!(build_dnstap(&config).is_err());
    }

    #[test]
    /** @brief 업스트림을 바꾸는 것은 재시작하지 않아도 되는지. */
    fn forward_upstream_change_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"8.8.8.8\"]\n").unwrap();
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
    }

    #[test]
    /**
     * @brief 전달을 쓰지 않던 backend에서 전달을 쓰는 backend로 바꾸며 업스트림을 함께 고쳐도
     *        재시작하지 않는지.
     * @details 전달 리졸버 슬롯은 backend와 상관없이 시작할 때 만들어지고, 설정 반영이 새
     *          업스트림으로 만든 리졸버를 그 슬롯에 넣는다.
     */
    fn forward_keys_follow_a_backend_switch_without_restart() {
        let current = Config::from_toml_str(
            "backend = \"recurse\"
upstreams = [\"1.1.1.1\"]
",
        )
        .unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"split\"
upstreams = [\"8.8.8.8\"]
",
        )
        .unwrap();
        assert!(is_hot_reload_config_change(&current, &proposed, "backend"));
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
        assert!(!backend_uses_forward(current.backend));
        assert!(backend_uses_forward(proposed.backend));
    }

    #[test]
    /** @brief 전달 세부 설정이 재시작하지 않아도 되는지. */
    fn forward_runtime_tuning_is_hot_reload() {
        let current =
            Config::from_toml_str("backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nupstream_concurrency = 4\nquery_timeout_secs = 2\n",
        )
        .unwrap();
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstream_concurrency"
        ));
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "query_timeout_secs"
        ));
    }

    #[test]
    /** @brief 클라이언트별 업스트림 설정은 재시작해야 하는지. 체인을 다시 지어야 한다. */
    fn client_specific_upstream_tuning_requires_service_restart() {
        let current = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\n[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"forward\"\nupstreams = [\"1.1.1.1\"]\nupstream_strategy = \"parallel\"\nupstream_concurrency = 4\nquery_timeout_secs = 2\n[[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\nupstreams = [\"9.9.9.9\"]\n",
        )
        .unwrap();
        for key in [
            "upstream_strategy",
            "upstream_concurrency",
            "query_timeout_secs",
        ] {
            assert!(!is_hot_reload_config_change(&current, &proposed, key));
        }
        assert!(is_hot_reload_config_change(
            &current,
            &proposed,
            "upstreams"
        ));
    }

    #[test]
    /** @brief 가름 데드라인 설정은 체인을 다시 지어야 하는지. */
    fn split_timeout_still_requires_resolver_restart() {
        let current =
            Config::from_toml_str("backend = \"split\"\nupstreams = [\"1.1.1.1\"]\n").unwrap();
        let proposed = Config::from_toml_str(
            "backend = \"split\"\nupstreams = [\"1.1.1.1\"]\nquery_timeout_secs = 2\n",
        )
        .unwrap();
        assert!(!is_hot_reload_config_change(
            &current,
            &proposed,
            "query_timeout_secs"
        ));
    }

    #[test]
    /** @brief 정책만 바뀌면 교체하고, 경로가 바뀌면 재시작하는지. */
    fn client_policy_change_is_hot_reload_but_route_change_is_not() {
        let current = Config::from_toml_str(
            "[[clients]]
name = \"desktop\"
ids = [\"192.0.2.10/32\"]
disable_filtering = false
",
        )
        .unwrap();
        let policy_only = Config::from_toml_str(
            "[[clients]]
name = \"desktop\"
ids = [\"192.0.2.10/32\"]
disable_filtering = true
",
        )
        .unwrap();
        assert!(is_hot_reload_config_change(
            &current,
            &policy_only,
            "clients"
        ));

        let routed = Config::from_toml_str(
            "[[clients]]
name = \"desktop\"
ids = [\"192.0.2.10/32\"]
upstreams = [\"1.1.1.1\"]
",
        )
        .unwrap();
        assert!(!is_hot_reload_config_change(&current, &routed, "clients"));
    }

    #[test]
    /** @brief 하드웨어 주소 기준 클라이언트를 처음 넣으면 재시작하는지. */
    fn first_mac_client_requires_service_restart() {
        let current = Config::from_toml_str("").unwrap();
        let proposed = Config::from_toml_str(
            "[[clients]]
name = \"phone\"
mac = [\"00:11:22:33:44:55\"]
",
        )
        .unwrap();
        assert!(!is_hot_reload_config_change(&current, &proposed, "clients"));
    }

    #[test]
    /** @brief 달라진 항목 목록이 정렬되고 겹치지 않는지. */
    fn changed_config_keys_are_sorted_and_deduplicated() {
        let cur = "block_rules = [\"a.example\"]\nlisten = [\"127.0.0.1:53\"]\n";
        let new = "block_rules = [\"b.example\"]\nlisten = [\"127.0.0.1:5353\"]\n";
        let keys = changed_config_keys(cur, new).unwrap();
        assert_eq!(keys, vec!["block_rules".to_string(), "listen".to_string()]);
    }

    #[test]
    /** @brief 설정 비교가 맨 위 항목 기준인지. */
    fn config_diff_top_level_keys() {
        let cur = "cache_size = 1000\nmin_ttl = 5\n";
        let new = "cache_size = 2000\nmax_ttl = 60\n";
        let (added, removed, changed) = Config::diff_toml(cur, new).unwrap();
        assert_eq!(added, vec!["max_ttl".to_string()]);
        assert_eq!(removed, vec!["min_ttl".to_string()]);
        assert_eq!(changed, vec!["cache_size".to_string()]);

        assert!(Config::diff_toml(cur, "no_such_key = 1").is_err());
    }
}
