#[macro_use]
/** @brief 오류에 맥락을 붙이는 것. */
mod error;
/** @brief 인증서 자동 발급. */
mod acme;
/** @brief 파일의 원자적 교체와 되돌리기. */
mod atomic_file;
/** @brief 응답 캐시와 같은 질의 합치기. */
mod cache;
/** @brief 명령줄 인자 해석. */
mod cli;
/** @brief Raft 클러스터와 클러스터를 거치는 설정 쓰기. */
mod cluster;
/** @brief 설정 변경의 분류와 적용. */
mod config_apply;
/** @brief 설정 파일 TOML 편집. */
mod config_edit;
/** @brief 설정 키마다 교체 방법, 클러스터 공유 여부, 빠른 경로 영향을 정한 표. */
mod config_keys;
/** @brief 주소별 연결 수 제한. */
mod connection_limit;
/** @brief 관리 API 콜백을 실행 중 서버 상태에 연결한다. */
mod control_api;
/** @brief 관리 API를 부르는 ctl 명령. */
mod ctl;
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
/** @brief DHCP, RA, PXE 서비스 구성과 임대 동기화. */
mod edge;
/** @brief 한 세대 동안의 차단 엔진 상태와 목록 갱신 작업. */
mod filter_runtime;
/** @brief 차단 목록 수집과 필터 엔진 구성. */
mod filters;
#[cfg(test)]
/** @brief 파서 훑기 테스트 도구. */
mod fuzzutil;
/** @brief HTTP 클라이언트. */
/** @brief 재시작 없는 설정 교체. */
mod hot_apply;
mod http;
/** @brief 해석 체인을 이루는 계층들. */
mod layers;
/** @brief 수신 소켓과 암호화 리스너의 교체. */
mod listeners;
/** @brief 지역 시각 계산. */
mod localtime;
/** @brief 하드웨어 주소와 제조사 조회. */
mod mac;
/** @brief 모든 전송이 모이는 질의 핸들러. */
mod native;
/** @brief 질의 처리기 구성 요소를 설정에서 만든다. */
mod native_config;
/** @brief 비차단 TCP 접속. */
mod nonblocking_tcp;
/** @brief 세컨더리에 보내는 NOTIFY. */
mod notify;
/** @brief 운영체제 DNS 설정과 방화벽 조작. */
mod osnet;
#[cfg(target_os = "linux")]
/** @brief 권한 내려놓기. */
mod privdrop;
/** @brief 질의 판정 미리 보기와 설명. */
mod query_explain;
/** @brief DoQ·DoH3 가 함께 쓰는 연결 테이블과 수신 반복. */
mod quic_listener;
/** @brief DoQ·DoH3 전역 연결 메모리 예산. */
mod quic_memory;
/** @brief 질의 처리 워커 풀. */
mod qworker;
/** @brief IPv6 라우터 광고. */
mod ra;
/** @brief 재귀 해석기 준비와 신뢰 앵커. */
mod recursion;
mod redis;
/** @brief 외부 공유 캐시 클라이언트. */
/** @brief 설정에서 해석 체인을 조립한다. */
mod resolver_chain;
/** @brief 업스트림 인증서 폐기 확인. */
mod revoke;
/** @brief 서명 키 교체. */
mod rollover;
/** @brief 세컨더리 영역 전송과 갱신. */
mod secondary;
#[cfg(windows)]
/** @brief Windows 서비스 등록과 실행. */
mod service;
/** @brief 프로세스 감독자. */
mod supervisor;
/** @brief PXE 부팅용 TFTP 서버. */
mod tftp;
/** @brief TLS 인증서 읽기, 검사, 교체. */
mod tls_material;
/** @brief 전송별 지표 관측. */
mod transport_observe;
/** @brief 새 릴리스 확인, 실행 파일 교체, 시험 실행과 되돌림. */
mod update;
/** @brief 업스트림 주소 해석. */
mod upstream;
/** @brief 업스트림 통계의 저장과 복원. */
mod upstream_stats;
/** @brief UDP 고속 경로가 쓰는 저장 형태. */
mod wirecache;
/** @brief 권한 영역 서명 키와 ZSK 교체. */
mod zone_signing;
/** @brief 권한 영역 저장소, 원본 감시, 영역 편집. */
mod zones;

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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Mutex;

use crate::error::{BoxResult, Context};
use config_keys::ApplyGroup;
use onetdns_core::ArcSwap;
use onetdns_core::MutexExt;

use onetdns_config::SplitTarget;
use onetdns_config::{
    BackendKind, BlockResponseKind, Config, CookieMode, EcsMode, Mode, UpstreamStrategy,
};
use onetdns_core::{AccessControl, RateLimiter};
use onetdns_filter::SharedFilter;

use cluster::{raft_restart, spawn_resign_timer, RaftProcessCleanup};
use secondary::refresh_restart;
use zone_signing::rollover_restart;
use zones::{configured_zone_files, spawn_zone_file_watch, zone_source_specs, ZoneState};

use atomic_file::{atomic_write, atomic_write_secret};
use cli::{parse_args, Command, ServiceAction};
use config_apply::{
    backend_uses_forward, install_restart, ChainRebuild, RestartHooks, SecondaryRestart,
};
use config_edit::{rewrite_config_kv, toml_quote};
use ctl::{ctl_add, ctl_reload, ctl_stats, ctl_top};
use edge::{edge_service_preflight, lease_sync_restart, reconcile_edge_services, EdgeServices};
use filters::blocklist_host_resolver;
use listeners::{
    reconcile_dnscrypt, reconcile_listeners, spawn_tls_cert_watch, ListenerSet, TlsSlots,
};
use native_config::{
    build_authority_settings, build_native_features, build_policy_engine, build_views,
    evaluate_lane_gates, parse_qtype, qtype_numbers, recursion_offered_by, runtime_access_control,
    runtime_rate_limiters, telemetry_consumed, DynamicAccessControl, DynamicRateLimiter, LaneFacts,
    NativeHotState,
};
use recursion::load_configured_trust_anchors;
use tls_material::{gen_cert, load_client_ca};
use upstream_stats::{load_upstream_stats, upstream_stats_path};

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

/** @brief 진입점. 인수를 읽어 해당 동작으로 간다. */
fn main() -> BoxResult<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    update::install::init();
    init_tracing();
    let cmd = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let mut rng_probe = [0u8; 32];
    onetdns_core::try_fill_random(&mut rng_probe).map_err(|error| {
        crate::anyhow!("The operating system secure random source is unavailable: {error}")
    })?;

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
            serve_directly(config, no_web)
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
        Command::Update { action, config } => {
            update::task::run_cli(action, config.as_deref()).map_err(|error| crate::anyhow!(error))
        }
        Command::Top { ctl } => ctl_top(&ctl),
        Command::Services => {
            println!("Services that can be blocked:");
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
        return Err(crate::anyhow!("The login name must be 1 to 64 characters"));
    }

    eprintln!("Type the password for dashboard account '{login}' and press Enter.");
    eprintln!("(The characters you type are shown on screen. Use at least 12 characters.)");

    /**
     * @brief 읽어들일 입력 길이 상한.
     * @details 최대 1024자를 모두 4바이트 문자로 채운 4096바이트에 줄 끝 CRLF 와 한 바이트를 더한
     *          값이다. 이만큼 읽고도 줄이 끝나지 않았으면 상한을 넘은 것이고, 길이 판정은
     *          hash_password 가 한다.
     */
    const MAX_PASSWORD_INPUT: u64 = 4096 + 2 + 1;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD_INPUT)
        .read_line(&mut line)
        .with_context(|| "Could not read the password")?;
    let pw = line.trim_end_matches(['\n', '\r']);
    let hash = onetdns_control::hash_password(pw).map_err(|error| crate::anyhow!("{error}"))?;

    eprintln!();
    eprintln!(
        "Paste the three lines below at the end of the configuration file ({CONFIG_FILE_NAME}) and restart the server."
    );
    eprintln!("If you can open the dashboard, you can create the account on its first screen without this command.");
    eprintln!();
    println!("[[users]]");
    println!("name = \"{login}\"");
    println!("password_hash = \"{hash}\"");
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
        Mode::Personal => "personal (private network)",
        Mode::Public => "public service",
    };
    let backend_label = match cfg.backend {
        BackendKind::Forward => "forward to upstream DNS servers",
        BackendKind::Recurse => "resolve recursively",
        BackendKind::Split => "split by domain",
    };
    let cookie_label = match cfg.cookies {
        CookieMode::Off => "off",
        CookieMode::Lenient => "only for clients that support it",
        CookieMode::Strict => "required for every client",
    };

    println!("The configuration file is valid.");
    println!("  Mode: {mode_label}");
    println!("  Query resolution: {backend_label}");
    println!("  Plain DNS listening addresses: {:?}", cfg.listen);
    if cfg.tls_enabled() {
        println!(
            "  Encrypted DNS listening addresses: DoT {}, DoH {}, DoQ {}, DoH3 {}",
            cfg.listen_dot.len(),
            cfg.listen_doh.len(),
            cfg.listen_doq.len(),
            cfg.listen_doh3.len()
        );
        println!(
            "  Client certificate verification: {}",
            if cfg.tls_authenticated() { "on" } else { "off" }
        );
    }
    if !cfg.listen_dnscrypt.is_empty() {
        println!("  DNSCrypt listening addresses: {:?}", cfg.listen_dnscrypt);
    }
    println!(
        "  Access control: {} allowed ranges, {} denied ranges",
        cfg.acl_allow.len(),
        cfg.acl_deny.len()
    );
    /* 한도 설정의 0은 끔을 뜻한다. 0건으로 적으면 모든 요청을 막는 것처럼 읽힌다. */
    if cfg.rate_limit_per_sec == 0 {
        println!("  Per-client rate limit: off");
    } else {
        println!(
            "  Per-client rate limit: {} per second, burst {}",
            cfg.rate_limit_per_sec, cfg.rate_limit_burst
        );
    }
    if cfg.subnet_rrl_per_sec == 0 {
        println!("  Per-subnet response limit: off");
    } else {
        println!(
            "  Per-subnet response limit: {} per second",
            cfg.subnet_rrl_per_sec
        );
    }
    println!("  DNS cookies: {cookie_label}");
    let inflight = if cfg.max_inflight == 0 {
        "unlimited".to_string()
    } else {
        format!("{}", cfg.max_inflight)
    };
    println!(
        "  Resources: cache {} entries, concurrent queries {inflight}, query timeout {} s",
        cfg.cache_size, cfg.query_timeout_secs
    );
    if let Some(c) = cfg.control_listen {
        println!("  Dashboard listening address: {c}");
    }

    let mut ext: Vec<String> = Vec::new();
    if cfg.block_response == BlockResponseKind::Custom {
        ext.push("custom address for blocked responses".into());
    }
    if cfg.block_aaaa {
        ext.push("AAAA responses disabled".into());
    }
    if !cfg.upstream_urls.is_empty() {
        // 섞여 있으면 "암호화 N개"만 보여 주는 것이 사실을 가린다. 실제로 나가는 질의는
        // 대부분 평문 쪽이다.
        if cfg.mixes_plain_and_encrypted_upstreams() {
            ext.push(format!(
                "{} encrypted + {} plain upstream DNS servers",
                cfg.upstream_urls.len(),
                cfg.upstreams.len()
            ));
        } else {
            ext.push(format!(
                "{} encrypted upstream DNS servers",
                cfg.upstream_urls.len()
            ));
        }
    }
    if !cfg.fallback_upstreams.is_empty() {
        ext.push("fallback upstream DNS servers".into());
    }
    if cfg.ecs_mode != EcsMode::Off {
        ext.push(match cfg.ecs_mode {
            EcsMode::Off => unreachable!(),
            EcsMode::Strip => "remove client subnet".into(),
            EcsMode::Send => "send client subnet".into(),
        });
    }
    if !cfg.stub_zones.is_empty() {
        ext.push(format!(
            "{} stub zones sent to separate DNS servers",
            cfg.stub_zones.len()
        ));
    }
    if !cfg.local_zones.is_empty() {
        ext.push(format!("{} local zones", cfg.local_zones.len()));
    }
    if !cfg.rewrites.is_empty() {
        ext.push(format!("{} rewrite rules", cfg.rewrites.len()));
    }
    if !cfg.rpz_files.is_empty() || !cfg.rpz_urls.is_empty() {
        ext.push(format!(
            "response policy zones: {} files, {} remote lists",
            cfg.rpz_files.len(),
            cfg.rpz_urls.len()
        ));
    }
    if cfg.dnssec_validation_active() {
        ext.push("DNSSEC validation".into());
    }
    if cfg.safe_browsing {
        ext.push("dangerous-site blocking".into());
    }
    if cfg.parental_control {
        ext.push("parental control".into());
    }
    if !cfg.service_schedule.is_empty() {
        ext.push("scheduled pauses of service blocking".into());
    }
    if cfg.anonymize_client_ip {
        ext.push("query log anonymization".into());
    }
    if cfg.clients.iter().any(|c| !c.mac.is_empty()) {
        ext.push("MAC-based client identification".into());
    }
    if !ext.is_empty() {
        println!("  Additional features: {}", ext.join(", "));
    }
    for warning in cfg.open_resolver_warnings().iter().chain(&cfg.advisories()) {
        println!("  Warning: {warning}");
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
        crate::bail!("The service command is available only on Windows")
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
 * @brief 감독자 없이 이 프로세스에서 서버를 돌린다.
 * @details 감독받는 자식이 아니면 업데이트 기록을 처리하고, 시험 중인 새 버전이 준비 전에
 *          오류로 끝나면 되돌린다. 적용을 마치고 멈췄으면 맞바꾼 실행 파일을 띄운다.
 */
fn serve_directly(config: Option<PathBuf>, no_web: bool) -> BoxResult<()> {
    if !update::install::supervised_child() {
        match update::trial::on_start(&mut || {}) {
            update::trial::Startup::Normal => {}
            update::trial::Startup::Trial(trial) => update::trial::watch(trial),
            update::trial::Startup::Reverted => update::launch::start_reverted(),
        }
    }
    let result = run(config, no_web);
    if let Err(error) = &result {
        if update::trial::revert_after_error(error) {
            update::launch::start_reverted();
        }
    }
    #[cfg(unix)]
    if result.is_ok() && update::launch::restart_requested() {
        return Err(crate::anyhow!(update::launch::start_installed()));
    }
    result
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
    update::launch::register(stop.clone());

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
                        "Could not apply the new configuration, and could not recover the service with the last working configuration either: new configuration error={first_error}; recovery configuration error={error}"
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
            update::trial::commit_active();
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
                    "Restarted the DNS service after reloading the configuration"
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
                        "Could not apply the new configuration, and could not recover the service with the last working configuration either: new configuration error={first_error}; recovery configuration error={error}"
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
            "Could not start the service with the new configuration, and then could not restore the last working configuration: {}",
            path.display()
        )
    })?;
    onetdns_core::warn!(
        event = "config.start_failed_rollback",
        path = %path.display(),
        "Could not start with the new configuration; restoring the last working configuration"
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
            "Starting DNS without the dashboard"
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
                    "Could not save the management token to the configuration file; using a temporary token for this run only"
                ),
            }
        }
    }
    // 토큰을 설정에 적어 둔 사람은 그 값을 이미 안다. 그때는 주소만 알려 준다.
    println!();
    println!("  Dashboard: http://{addr}/");
    if auto_token {
        println!("  Token: {}", cfg.control_token.as_str());
        if persisted {
            println!(
                "  The token is saved in the configuration file, so it stays the same next time."
            );
        } else {
            println!("  This token is for this run only. To keep it, set control_token in the configuration file.");
        }
        println!("  Pass --no-web to run DNS without the dashboard.");
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
            onetdns_core::error!(event = "config.autocreate_dir_failed", path = %parent.display(), %error, "Could not create the configuration directory");
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                onetdns_core::error!(event = "config.autocreate_dir_acl_failed", path = %parent.display(), %error, "Could not set permissions on the configuration directory");
                return None;
            }
        }
    }
    if !path.exists() {
        let body = format!(
            "# Configuration file created automatically by OnetDNS. Edit it in the dashboard or a text editor.\n# Each setting is described in the documentation and on the dashboard's full settings page.\ncontrol_token = \"{}\"\n",
            gen_token()
        );

        if let Err(error) = atomic_write_secret(&path, body.as_bytes()) {
            onetdns_core::error!(event = "config.autocreate_file_failed", path = %path.display(), %error, "Could not create the configuration file");
            return None;
        }
        onetdns_core::info!(event = "config.autocreated", path = %path.display(), "Created a default configuration file");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            {
                onetdns_core::error!(event = "config.autocreate_chmod_failed", path = %path.display(), %error, "Could not fix permissions on the configuration file");
                return None;
            }
        }
    }
    #[cfg(windows)]
    if let Err(error) = atomic_file::harden_windows_secret_acl(&path) {
        onetdns_core::error!(event = "config.autocreate_acl_failed", path = %path.display(), %error, "Could not fix the Windows access control list on the configuration file");
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

/**
 * @brief 설정이 바뀌면 멈추고 새 설정으로 다시 띄우는 작업들. 묶음마다 종료 신호를 따로 가진다.
 * @invariant 세대가 끝나면 spawn_retire 의 스레드가 모든 묶음에 신호를 보낸다. 묶음을 더하면서
 *            그 스레드에 넣지 않으면 그 작업이 다음 세대까지 남는다.
 */
#[derive(Clone)]
struct GenerationJobs {
    /** @brief DHCP, DHCPv6, 라우터 광고, TFTP. */
    edge: Arc<EdgeServices>,
    /** @brief 재귀 리졸버에 딸린 보조 작업들. 재귀 리졸버를 다시 만들 때 이전 것을 멈춘다. */
    recursor: Arc<EdgeServices>,
    /**
     * @brief 웹 관리 리스너. 주소가 바뀌면 새로 시작하고 이전 것을 멈춘다.
     * @details 세대를 넘어 이어지므로 재시작하는 동안에도 이전 스레드가 계속 연결을 받는다.
     */
    control: Arc<EdgeServices>,
    /** @brief 세컨더리 영역 갱신 작업. */
    secondary: Arc<EdgeServices>,
    /** @brief DHCP 임대 동기화. */
    lease_sync: Arc<EdgeServices>,
    /** @brief ZSK 교체 작업. 영역 목록이나 주기가 바뀌면 멈추고 재시작한다. */
    zsk_rollover: Arc<EdgeServices>,
}

impl GenerationJobs {
    /** @brief 관리 리스너 작업만 앞 세대 것을 이어받고 나머지는 새로 만든다. */
    fn new(control: Arc<EdgeServices>) -> Self {
        Self {
            edge: Arc::default(),
            recursor: Arc::default(),
            control,
            secondary: Arc::default(),
            lease_sync: Arc::default(),
            zsk_rollover: Arc::default(),
        }
    }

    /**
     * @brief 세대가 끝나면 등록된 서비스 신호를 모두 보내는 스레드를 띄운다.
     * @details 이것이 없으면 그 스레드들이 남아 포트를 잡은 채로 다음 세대가 뜬다.
     */
    fn spawn_retire(
        &self,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        reload: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        use std::sync::atomic::Ordering;
        let jobs = self.clone();
        std::thread::Builder::new()
            .name("edge-retire".into())
            .spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                }
                jobs.edge.retire_all();
                jobs.recursor.retire_all();
                /*
                 * 재시작하는 중이면 관리 수신 스레드는 그대로 둔다. 여기서 멈추면 새 세대가 자기
                 * 것을 시작할 때까지 웹 화면에 닿을 길이 없다. 이전 스레드는 새 세대의 관리
                 * 리스너 재시작 함수가 자기 것을 시작한 뒤에 멈춘다.
                 */
                if !reload.load(Ordering::Relaxed) {
                    jobs.control.retire_all();
                }
                jobs.secondary.retire_all();
                jobs.lease_sync.retire_all();
                jobs.zsk_rollover.retire_all();
            })
    }
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
    /**
     * @brief 오래 걸리는 작업들의 진행 상황. 세대가 바뀌어도 이어진다.
     * @details 업데이트 작업은 세대와 상관없이 끝까지 돈다. 세대마다 새로 만들면 그 결과가 버려진 목록에
     *          남고, 작업 번호가 다시 1부터 매겨져 관리 화면이 다른 작업의 결과를 읽는다.
     */
    jobs: Arc<JobRegistry>,

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

impl ServeShared {
    /**
     * @brief 지표 기록기와 저장소를 이 세대 설정으로 연다.
     * @details 앞 세대가 연 것이 있으면 설정만 바꿔 이어 쓴다. 통계와 질의 기록이 다시 읽기를
     *          넘어 이어지는 것은 이 때문이다.
     */
    fn open_metrics(
        &self,
        cfg: &Config,
    ) -> BoxResult<(onetdns_control::Recorder, onetdns_control::Stats)> {
        let persist_opts = hot_apply::persist_opts(cfg);
        let mut slot = self.metrics.lock_recover();
        if let Some((recorder, stats)) = slot.as_ref() {
            onetdns_core::info!(
                event = "stats.channel_reused",
                "Applying the new configuration while keeping existing statistics and query log"
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
                "Could not start the DNS service because the new statistics or query log storage settings cannot be used"
            })?;
            onetdns_core::info!(
                event = "stats.persistence_reconfigured",
                querylog_file = ?persist_opts.querylog_file,
                stats_file = ?persist_opts.stats_file,
                flush_secs = persist_opts.flush_secs,
                "Updated storage settings for statistics and the query log"
            );
            return Ok((recorder.clone(), stats.clone()));
        }
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
            persist_opts,
        );
        pair.1.flush_persisted().with_context(|| {
            "Could not start management because the statistics or query log file cannot be used"
        })?;
        onetdns_core::debug!(
            event = "stats.channel_created",
            querylog_capacity = cfg.querylog_size.max(1),
            history_retention_secs = cfg.stats_retention_secs,
            "Started collecting statistics"
        );
        *slot = Some((pair.0.clone(), pair.1.clone()));
        Ok(pair)
    }

    /**
     * @brief 이 세대의 관리 API 상태를 만든다.
     * @details 토큰과 계정은 이 세대 설정으로 만들고, 로그인 상태와 감사 기록은 앞 세대 것을
     *          이어 쓴다.
     */
    fn control_state(
        &self,
        cfg: &Config,
        stats: onetdns_control::Stats,
        controls: onetdns_control::Controls,
        readiness: Arc<std::sync::atomic::AtomicBool>,
        proxy: Arc<ArcSwap<onetdns_control::ProxyPolicy>>,
    ) -> BoxResult<onetdns_control::AppState> {
        let mut admin = cfg.control_admin_tokens.clone();
        if !cfg.control_token.is_empty() {
            admin.push(cfg.control_token.clone());
        }
        let auth = onetdns_control::Auth::new(admin, cfg.control_readonly_tokens.clone())
            .with_users(build_user_creds(cfg).map_err(|error| crate::anyhow!(error))?)
            .with_sessions(self.sessions.clone());
        let audit = self
            .audit
            .lock_recover()
            .get_or_insert_with(|| onetdns_control::AuditLog::new(1000))
            .clone();
        Ok(onetdns_control::AppState {
            stats,
            auth: Arc::new(auth),
            audit,
            controls: Arc::new(controls),
            readiness,
            proxy,
        })
    }

    /**
     * @brief 관리 리스너를 설정에 맞추는 함수를 만든다.
     * @details 만들 때 이 세대의 이름표를 하나 받는다. 주소가 같아도 세대가 다르면 새로 시작해야
     *          한다. 이전 스레드는 앞 세대의 데이터 플레인을 가지고 있기 때문이다.
     */
    fn control_restart(&self, state: onetdns_control::AppState) -> SecondaryRestart {
        let jobs = self.control_jobs.clone();
        let shared_slot = self.control_listener.clone();
        let generation = CONTROL_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Arc::new(move |next: &Config| -> Result<(), String> {
            let Some(addr) = next.control_listen else {
                /* 주소를 지웠으면 리스너를 세우기만 한다. 재시작할 이유가 없다. */
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
                        "control_listen was removed; closed the dashboard and API"
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
                onetdns_core::warn!(event = "control.non_loopback_bind", %addr, "Management API is listening on a non-loopback address; check your firewall and access control");
            }
            let listener = match reuse_control_listener(&shared_slot, addr) {
                Some(listener) => listener,
                None => TcpListener::bind(addr).map_err(|error| {
                    format!("Could not open the dashboard listening address: {addr}: {error}")
                })?,
            };
            *shared_slot.lock_recover() = match listener.try_clone() {
                Ok(clone) => Some(clone),
                Err(error) => {
                    onetdns_core::warn!(event = "control.listener_share_failed", %addr, %error, "Could not hand the management socket over to the next configuration; the port must be reopened on reload");
                    None
                }
            };
            let bound = listener.local_addr().map_err(|error| {
                format!("Could not read the dashboard listening address: {addr}: {error}")
            })?;
            /*
             * 새 리스너를 시작한 뒤에 이전 것을 멈춘다. 지금 처리 중인 응답은 이전 리스너가
             * 끝까지 보낸다.
             */
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let state = state.clone();
            let listener_stop = stop.clone();
            let thread = std::thread::Builder::new()
                .name("onetdns-control".into())
                .spawn(move || {
                    if let Err(error) =
                        onetdns_control::serve_listener(listener, state, listener_stop)
                    {
                        onetdns_core::error!(event = "control.stopped", %error, "Stopped the dashboard service");
                    }
                })
                .map_err(|error| format!("Could not start the dashboard thread: {error}"))?;
            /*
             * 이 세대의 정리 목록에 넣지 않는다. 재시작하는 동안 살아 있어야 하므로 여기서
             * 기다리면 세대 정리가 끝나지 않는다. 멈추는 일은 다음 세대나 종료 전파가 맡는다.
             */
            drop(thread);
            let mut running = jobs.running.lock_recover();
            for (_, old) in running.iter() {
                old.store(true, std::sync::atomic::Ordering::Release);
            }
            running.clear();
            running.push((key, stop));
            onetdns_core::info!(event = "control.started", addr = %bound, "Opened the dashboard and API");
            Ok(())
        })
    }
}

/** @brief 재귀일 때 코어당 UDP 워커 수. */
const RECURSIVE_UDP_WORKERS_PER_CPU: usize = 5;

/** @brief 전달일 때 코어당 UDP 워커 수. */
const FORWARD_UDP_WORKERS_PER_CPU: usize = 4;
/** @brief 일반 DNS 워커 수 상한. */
const MAX_PLAIN_DNS_WORKERS: usize = 256;

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

    let restarts = RestartHooks::default();
    /*
     * 인증서는 교체 가능한 슬롯에 넣는다. 인증서를 갈아도 수신 소켓은 그대로 두고 다음 연결부터
     * 새 인증서를 쓴다.
     */
    let tls_slot_handle: Arc<Mutex<Option<Arc<TlsSlots>>>> = Arc::new(Mutex::new(None));
    let jobs = GenerationJobs::new(shared.control_jobs.clone());
    onetdns_core::info!(event = "serve.starting", mode = ?cfg.mode, backend = ?cfg.backend, "Starting DNS server");

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
        service_cleanup.track(
            upstream_stats::spawn_flush(
                stats_path,
                forward_stats.clone(),
                cfg.persist_flush_secs,
                shutdown.clone(),
            )
            .with_context(|| "Could not start the upstream DNS server statistics writer thread")?,
        );
    }

    /*
     * 이름을 푸는 데 쓰는 업스트림 서버와 루트 힌트는 무중단으로 바뀐다. 시작할 때 만든 것을
     * 그대로 계속 가지고 있으면 주소를 바꿔도 목록은 계속 이전 서버에서 받아 온다. 겉은 그대로 두고
     * 속만 교체한다.
     */
    let blocklist_resolver_slot: Arc<Mutex<http::HostResolver>> =
        Arc::new(Mutex::new(blocklist_host_resolver(&cfg)));
    let blocklist_resolver: http::HostResolver = {
        let slot = blocklist_resolver_slot.clone();
        Arc::new(move |host: &str, timeout: Duration| {
            let inner = slot.lock_recover().clone();
            inner(host, timeout)
        })
    };
    let filters = filter_runtime::FilterState::start(
        &cfg,
        &runtime_cfg,
        config_path.as_deref(),
        &blocklist_resolver,
        &shutdown,
        &service_cleanup,
    )?;

    let vendor_db = Arc::new(onetdns_core::ArcSwap::new(Arc::new(mac::VendorDb::load(
        cfg.mac_vendor_db.as_deref(),
    ))));
    if cfg.dhcp_enable || cfg.dhcp6_enable {
        onetdns_core::info!(
            event = "dhcp.vendor_db_ready",
            oui_entries = vendor_db.load().len(),
            "Prepared the MAC vendor database for DHCP leases"
        );
    }

    let dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>> = Arc::new(Mutex::new(None));
    let dhcp6_slot: Arc<Mutex<Option<Arc<Mutex<dhcp6::Lease6Pool>>>>> = Arc::new(Mutex::new(None));
    reconcile_edge_services(&cfg, &jobs.edge, &dhcp_slot, &dhcp6_slot)
        .map_err(std::io::Error::other)?;
    service_cleanup.track(
        jobs.spawn_retire(shutdown.clone(), reload.clone())
            .with_context(|| {
                "Could not start the task that propagates shutdown to edge services"
            })?,
    );

    install_restart(
        &restarts.lease_sync,
        lease_sync_restart(
            jobs.lease_sync.clone(),
            dhcp_slot.clone(),
            blocklist_resolver.clone(),
            service_cleanup.tracker(),
        ),
        &cfg,
    )
    .map_err(std::io::Error::other)?;

    install_revocation_policy(&cfg, &blocklist_resolver);

    let acl_state = Arc::new(DynamicAccessControl::new(runtime_access_control(&cfg)));
    let acl: Arc<dyn AccessControl> = acl_state.clone();
    let rate_state = Arc::new(DynamicRateLimiter::new(runtime_rate_limiters(&cfg)));
    let rate_limiters: Vec<Arc<dyn RateLimiter>> = vec![rate_state.clone()];
    log_generation_settings(&cfg, &rate_state);

    let tsig_keys = build_tsig_keys(&cfg).map_err(|error| crate::anyhow!(error))?;

    let native_hot_state: Arc<Mutex<Option<NativeHotState>>> = Arc::new(Mutex::new(None));
    let zones = ZoneState::start(&cfg, &tsig_keys, &shutdown, &service_cleanup)?;
    service_cleanup.track(
        spawn_tls_cert_watch(
            runtime_cfg.clone(),
            tls_slot_handle.clone(),
            shutdown.clone(),
        )
        .with_context(|| "Could not start the TLS certificate watch task")?,
    );
    let resign_zone_files = configured_zone_files(&cfg).map_err(|error| crate::anyhow!(error))?;
    if let Some(thread) = spawn_resign_timer(
        zones.signers.clone(),
        zones.store.clone(),
        zones.journal.clone(),
        resign_zone_files,
        zones.notify.clone(),
        shutdown.clone(),
    )
    .with_context(|| "Could not start the DNSSEC re-signing thread")?
    {
        service_cleanup.track(thread);
    }
    let reload_zone_keys = zones.reload_from_config(&runtime_cfg, &native_hot_state);
    service_cleanup.track(
        spawn_zone_file_watch(
            runtime_cfg.clone(),
            reload_zone_keys.clone(),
            shutdown.clone(),
        )
        .with_context(|| "Could not start the DNS zone file watch task")?,
    );
    install_restart(
        &restarts.zsk_rollover,
        rollover_restart(
            jobs.zsk_rollover.clone(),
            reload_zone_keys,
            service_cleanup.tracker(),
        ),
        &cfg,
    )
    .map_err(std::io::Error::other)?;
    let notify_kick = Arc::new(native::NotifyKick::default());
    install_restart(
        &restarts.secondary,
        refresh_restart(
            jobs.secondary.clone(),
            &zones,
            notify_kick.clone(),
            service_cleanup.tracker(),
        ),
        &cfg,
    )
    .map_err(|error| crate::anyhow!(error))?;
    let policy_engine = Arc::new(native::GatedSwap::new(Arc::new(
        build_policy_engine(&cfg).map_err(std::io::Error::other)?,
    )));

    let cache_slot: Arc<Mutex<Option<cache::CacheHandle>>> = Arc::new(Mutex::new(None));

    let config_prev = shared.previous_config_text.clone();
    let applied_config_text = shared.applied_config_text.clone();

    let (recorder, stats) = shared.open_metrics(&cfg)?;
    recorder.set_collecting(telemetry_consumed(&cfg));

    /*
     * 컨트롤 플레인 인증은 이 뒤에서 만들어진다. 계정만 바뀌었을 때 DNS를 건드리지 않고
     * 목록만 교체하려면 그 핸들이 필요하므로 슬롯을 먼저 잡아 둔다.
     */
    let console_auth: Arc<Mutex<Option<Arc<onetdns_control::Auth>>>> = Arc::new(Mutex::new(None));
    let control_proxy = Arc::new(ArcSwap::from_pointee(control_proxy_policy(&cfg)));

    let hot_config_apply = hot_apply::build(hot_apply::HotApplyDeps {
        restarts: restarts.clone(),
        zones: zones.clone(),
        filters: filters.clone(),
        console_auth: console_auth.clone(),
        control_proxy: control_proxy.clone(),
        runtime_cfg: runtime_cfg.clone(),
        acl_state: acl_state.clone(),
        rate_state: rate_state.clone(),
        recorder: recorder.clone(),
        forward_slot: forward_slot.clone(),
        forward_stats: forward_stats.clone(),
        native_hot_state: native_hot_state.clone(),
        stats: stats.clone(),
        zone_shutdown: shutdown.clone(),
        zone_threads: service_cleanup.tracker(),
        edge_services: jobs.edge.clone(),
        dhcp_slot: dhcp_slot.clone(),
        dhcp6_slot: dhcp6_slot.clone(),
        tls_slots: tls_slot_handle.clone(),
        vendor_db: vendor_db.clone(),
        blocklist_resolver_slot: blocklist_resolver_slot.clone(),
        blocklist_resolver: blocklist_resolver.clone(),
        cache_slot: cache_slot.clone(),
    });

    /*
     * 컨트롤 플레인은 수신 주소가 없어도 만들어 둔다. 주소를 나중에 넣어도 그때 리스너만 열면
     * 되도록 하기 위해서다. 주소가 없으면 리스너를 시작하지 않을 뿐이다.
     */
    let controls = control_api::build(control_api::ControlDeps {
        zones: zones.clone(),
        filters: filters.clone(),
        runtime_cfg: runtime_cfg.clone(),
        config_path: config_path.clone(),
        cfg_text: cfg_text.clone(),
        reload: reload.clone(),
        config_prev: config_prev.clone(),
        applied_config_text: applied_config_text.clone(),
        hot_config_apply: hot_config_apply.clone(),
        policy_engine: policy_engine.clone(),
        blocklist_resolver: blocklist_resolver.clone(),
        dhcp_slot: dhcp_slot.clone(),
        dhcp6_slot: dhcp6_slot.clone(),
        vendor_db: vendor_db.clone(),
        cache_slot: cache_slot.clone(),
        forward_stats: forward_stats.clone(),
        listener_reg: listener_reg.clone(),
        tls_slot_handle: tls_slot_handle.clone(),
        jobs: shared.jobs.clone(),
        service_threads: service_cleanup.tracker(),
    });
    let state = shared.control_state(&cfg, stats, controls, readiness.clone(), control_proxy)?;
    *console_auth.lock_recover() = Some(state.auth.clone());
    issue_setup_code(&state.auth, config_path.as_deref());
    install_restart(&restarts.control, shared.control_restart(state), &cfg)
        .map_err(std::io::Error::other)?;

    let restart_raft = raft_restart(
        config_path.clone(),
        config_prev,
        applied_config_text,
        reload.clone(),
        hot_config_apply,
    );
    *restarts.raft.lock_recover() = Some({
        let restart_raft = restart_raft.clone();
        Arc::new(move |next: &Config| restart_raft(next, None)) as SecondaryRestart
    });
    restart_raft(&cfg, cfg_text.as_deref()).map_err(std::io::Error::other)?;

    let mac_cache = if cfg.clients.iter().any(|c| !c.mac.is_empty()) {
        let cache = mac::NeighborCache::new();
        let thread = cache
            .clone()
            .spawn_refresh(Duration::from_secs(30), shutdown.clone())
            .with_context(|| "Could not start the MAC neighbor refresh thread")?;
        service_cleanup.track(thread);
        onetdns_core::info!(
            event = "mac.neighbor_scan_started",
            "Started identifying devices by MAC address from the neighbor table (every 30 seconds)"
        );
        Some(cache)
    } else {
        None
    };

    let (native_handler, native_state) = build_native_server(NativeDeps {
        cfg: &cfg,
        chain_restart: &restarts.chain,
        forward_slot,
        filters: &filters,
        zones: &zones,
        dhcp_slot,
        cache_slot,
        recursor_jobs: jobs.recursor.clone(),
        recorder: Some(recorder),
        acl,
        rate_limiters,
        mac_cache,
        policy_engine,
        notify_kick,
        shutdown: shutdown.clone(),
        threads: service_cleanup.tracker(),
    })?;
    *native_hot_state.lock_recover() = Some(native_state);

    let listeners = Arc::new(ListenerSet::default());
    install_restart(
        &restarts.listeners,
        {
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
        },
        &cfg,
    )
    .map_err(std::io::Error::other)?;

    onetdns_core::info!(event = "server.ready", "Now answering queries");

    #[cfg(target_os = "linux")]
    if let Some(user) = cfg.run_as_user.as_deref() {
        /*
         * 세대마다 확인한다. 한 번만 하면 첫 시도가 실패한 뒤 다시 띄운 세대는 내려가지 않은
         * 채로, run_as_user 를 바꾼 세대는 이전 사용자로 오류 없이 돈다.
         */
        if let Err(e) = privdrop::drop_privileges(user, cfg.run_as_group.as_deref()) {
            return Err(crate::anyhow!(format!(
                "Stopping the service because process privileges could not be dropped: {e}"
            )));
        }
        onetdns_core::info!(
            event = "privdrop.applied",
            user,
            "Running with user and group privileges dropped and further privilege gain blocked"
        );
    }

    if !reload.load(Ordering::Acquire) {
        if let Some(text) = cfg_text.as_ref() {
            *shared.applied_config_text.lock_recover() = Some(text.clone());
        }
    } else {
        onetdns_core::info!(
            event = "config.changed_during_start",
            "Configuration changed again during startup; not using this configuration as the recovery baseline"
        );
    }
    readiness.store(true, Ordering::Release);
    if let Some(cb) = on_ready {
        cb();
    }
    update::task::schedule(
        {
            let runtime = runtime_cfg.clone();
            move || runtime.load().release_check
        },
        blocklist_resolver.clone(),
    );

    let reloaded = wait_for_stop_or_reload(&reload, external_stop.as_deref());

    readiness.store(false, Ordering::Release);
    shutdown.store(true, Ordering::Relaxed);
    listeners.close_all();

    service_cleanup.shutdown_and_join();
    std::thread::sleep(Duration::from_millis(500));
    onetdns_core::info!(
        event = "server.configuration_stopped",
        reload = reloaded,
        "Shutting down the current configuration"
    );
    Ok(reloaded)
}

/**
 * @brief 종료 신호나 다시 읽기 요청이 올 때까지 기다린다.
 * @return 다시 읽어야 하면 참, 끝내야 하면 거짓.
 */
fn wait_for_stop_or_reload(
    reload: &std::sync::atomic::AtomicBool,
    external_stop: Option<&std::sync::atomic::AtomicBool>,
) -> bool {
    use std::sync::atomic::Ordering;
    loop {
        if external_stop.is_some_and(|s| s.load(Ordering::Relaxed)) {
            onetdns_core::info!(
                event = "server.shutdown_requested",
                reason = "external_signal",
                "Received an external shutdown signal"
            );
            return false;
        }
        if reload.load(Ordering::Relaxed) {
            onetdns_core::info!(
                event = "server.restart_requested",
                reason = "config_change",
                "Restarting the DNS service to apply configuration changes"
            );
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/** @brief 이 세대의 보호 설정을 요약하고, 위험하거나 효과가 없는 설정을 경고로 남긴다. */
fn log_generation_settings(cfg: &Config, rate_state: &DynamicRateLimiter) {
    if cfg.dns64_prefix.is_some() {
        onetdns_core::info!(event = "dns64.enabled", prefix = ?cfg.dns64_prefix, "Synthesizing AAAA from A for IPv6-only networks");
    }
    if cfg.rebind_protection {
        onetdns_core::info!(
            event = "rebind.protection_enabled",
            "DNS rebinding protection is on; private addresses in outside answers are filtered"
        );
    }
    if cfg.safe_search {
        onetdns_core::info!(
            event = "safesearch.forced",
            "Enforcing SafeSearch on search engines"
        );
    }
    onetdns_core::info!(event = "serve.protections_summary",
        acl_allow = cfg.acl_allow.len(),
        acl_deny = cfg.acl_deny.len(),
        rate_layers = rate_state.layer_count(),
        cookies = ?cfg.cookies,
        mtls = cfg.tls_authenticated(),
        "Applied access control and rate limits"
    );

    for warning in cfg.open_resolver_warnings() {
        onetdns_core::warn!(
            event = "security.open_resolver_warning",
            security = "open-resolver",
            detail = %warning,
            "Check the configuration of this publicly reachable recursive resolver"
        );
    }
    /* 조건이 맞지 않아 동작하지 않을 항목들. 설정을 막지 않고 알리기만 한다. */
    for advisory in cfg.advisories() {
        onetdns_core::warn!(
            event = "config.advisory",
            detail = %advisory,
            "Setting saved, but it has no effect under the current conditions"
        );
    }
}

/** @brief 질의 처리기를 조립하는 데 드는 이 세대의 핸들. */
struct NativeDeps<'a> {
    /** @brief 이 세대의 설정. */
    cfg: &'a Config,
    /** @brief 기본 체인을 다시 만드는 핸들을 넣을 슬롯. */
    chain_restart: &'a Mutex<Option<ChainRebuild>>,
    /** @brief 전달 리졸버 슬롯. */
    forward_slot: native::ResolverSlot,
    /** @brief 차단 엔진과 그 재료. */
    filters: &'a filter_runtime::FilterState,
    /** @brief 권한 영역 상태. */
    zones: &'a ZoneState,
    /** @brief DHCPv4 임대 풀. 서비스가 꺼져 있으면 없다. */
    dhcp_slot: Arc<Mutex<Option<Arc<Mutex<dhcp::LeasePool>>>>>,
    /** @brief 응답 캐시. 기본 체인을 설치하면 채워진다. */
    cache_slot: Arc<Mutex<Option<cache::CacheHandle>>>,
    /** @brief 재귀 리졸버에 딸린 보조 작업. */
    recursor_jobs: Arc<EdgeServices>,
    /** @brief 질의 기록. */
    recorder: Option<onetdns_control::Recorder>,
    /** @brief 접근 제어. */
    acl: Arc<dyn AccessControl>,
    /** @brief 속도 제한. */
    rate_limiters: Vec<Arc<dyn RateLimiter>>,
    /** @brief MAC 주소로 기기를 찾는 이웃 표. MAC 으로 고른 클라이언트가 없으면 없다. */
    mac_cache: Option<Arc<mac::NeighborCache>>,
    /** @brief 정책 엔진. */
    policy_engine: Arc<native::GatedSwap<onetdns_policy::PolicyEngine>>,
    /** @brief 들어온 NOTIFY 로 세컨더리 갱신을 깨운다. */
    notify_kick: Arc<native::NotifyKick>,
    /** @brief 이 세대의 종료 플래그. */
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /** @brief 이 세대가 끝날 때 기다릴 스레드. */
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

/**
 * @brief 이 세대의 질의 처리기를 조립한다.
 * @details 기본 체인을 설치하고, 클라이언트별 업스트림 경로를 같은 공통 계층으로 감싼 뒤 빠른
 *          경로와 기능 세트를 붙인다.
 * @return 질의 처리기와, 핫 적용이 그 처리기와 함께 교체할 상태.
 */
fn build_native_server(
    deps: NativeDeps<'_>,
) -> BoxResult<(Arc<native::NativeServer>, NativeHotState)> {
    let NativeDeps {
        cfg,
        chain_restart,
        forward_slot,
        filters,
        zones,
        dhcp_slot,
        cache_slot,
        recursor_jobs,
        recorder,
        acl,
        rate_limiters,
        mac_cache,
        policy_engine,
        notify_kick,
        shutdown,
        threads,
    } = deps;
    let local_only_names = Arc::new(layers::LocalOnlyNames::new(
        cfg.domain_needed,
        cfg.bogus_priv,
        cfg.empty_zones,
    ));
    let timeout = Duration::from_secs(cfg.query_timeout_secs);
    let block_ttl = Arc::new(std::sync::atomic::AtomicU32::new(cfg.blocked_response_ttl));
    let local_ttl = Arc::new(std::sync::atomic::AtomicU32::new(cfg.local_ttl));
    let split_local_wire_cache = Arc::new(std::sync::OnceLock::new());

    let plan = resolver_chain::ChainPlan::new(cfg);

    let default_chain = Arc::new(resolver_chain::DefaultChain {
        base: resolver_chain::ResolverBase {
            forward_slot,
            recurse: resolver_chain::RecursiveBase {
                block_ttl: block_ttl.clone(),
                filter: filters.filter.clone(),
                local_ttl: local_ttl.clone(),
                thread_tracker: threads,
                shutdown: shutdown.clone(),
            },
        },
        layers: resolver_chain::ChainLayers {
            block_ttl: block_ttl.clone(),
            dhcp_slot: dhcp_slot.clone(),
            local_ttl: local_ttl.clone(),
            local_only_names: local_only_names.clone(),
            recorder: recorder.clone(),
            shutdown,
            split_local_wire_cache: split_local_wire_cache.clone(),
            zone_store: zones.store.clone(),
        },
        cache_slot: cache_slot.clone(),
        recursor_jobs,
    });
    let resolver_chain::InstalledChain {
        resolver: chain,
        recursor: lane_recursor,
        anchors: recursor_anchors,
        shared_cache,
        ..
    } = default_chain.install(
        default_chain
            .prepare(&plan)
            .map_err(|error| crate::anyhow!(error))?,
    );

    let client_upstreams: Vec<native::ClientUpstream> = build_client_upstream_routes(cfg, timeout)
        .map_err(|e| crate::anyhow!(e))?
        .into_iter()
        .map(|mut route| {
            let kind = resolver_chain::ChainBase::Route {
                upstreams: route.namespace_key(),
                anchors: recursor_anchors.clone(),
            };
            route.resolver = default_chain
                .layers
                .wrap_common_layers(
                    &plan,
                    route.resolver,
                    false,
                    false,
                    kind,
                    shared_cache.as_ref(),
                )?
                .0;
            Ok(route)
        })
        .collect::<Result<_, String>>()
        .map_err(|e| crate::anyhow!(e))?;

    let views = build_views(cfg).map_err(|error| crate::anyhow!(error))?;

    /*
     * 빠른 경로 구조는 조건과 무관하게 만들어 둔다. 조건은 기능 세트에 담기므로 설정이
     * 바뀌면 그 세트만 교체하면 되고, 소켓과 스레드는 그대로 둔다.
     */
    let authority_wire_path = Some(zones.store.clone());

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
    let lane_gates = evaluate_lane_gates(cfg, &lane_facts);
    onetdns_core::debug!(
        event = "do53.lane_switch",
        wire = lane_gates.wire,
        authority = lane_gates.authority,
        reactor = lane_gates.reactor,
        "Decided fast-path eligibility"
    );
    let mut features = build_native_features(cfg, None)?;
    features.lanes = lane_gates;

    /*
     * 해석 체인을 교체 가능한 슬롯에 넣어 넘긴다. 설정이 바뀌면 체인만 새로 만들어
     * 교체하면 되므로 스레드와 소켓을 내렸다 올릴 이유가 없어진다.
     */
    let chain_slot = Arc::new(native::ResolverSlot::new(chain));
    *chain_restart.lock_recover() = Some(ChainRebuild {
        chain: default_chain,
        slot: (*chain_slot).clone(),
    });

    let mut native_server = native::NativeServer::new(
        filters.filter.clone(),
        acl,
        rate_limiters,
        chain_slot.clone(),
        cfg.blocked_response_ttl,
    )
    .with_ttl_sources(block_ttl, local_ttl)
    .with_client_upstreams(client_upstreams)
    .with_features(features)
    .with_recorder(recorder)
    .with_mac_cache(mac_cache)
    .with_safe_search(filters.safe_search.clone())
    .with_policy(policy_engine)
    .with_xfr(zones.store.clone(), Vec::new())
    .with_notify_kick(notify_kick)
    .with_journal(zones.journal.clone())
    .with_views(views)
    .with_authority_wire_path(authority_wire_path, recursion_offered_by(cfg))
    .with_wire_fast_path(wire_fast_path);
    native_server
        .replace_authority(build_authority_settings(cfg).map_err(|error| crate::anyhow!(error))?);
    {
        let notify = zones.notify.clone();
        native_server = native_server.with_update_notify(Arc::new(move |origin, serial| {
            notify.enqueue(origin, serial)
        }));
    }
    if let Some(ch) = cache_slot.lock_recover().clone() {
        native_server = native_server.with_reactor_lane_runtime(lane_recursor, ch, 32);
    }
    let native_server = Arc::new(native_server);
    let hot_state = NativeHotState {
        features: native_server.features.clone(),
        policy: native_server.policy.clone(),
        views: native_server.views.clone(),
        block_ttl: native_server.block_ttl.clone(),
        local_ttl: native_server.local_ttl.clone(),
        local_only_names,
        authority: native_server.authority.clone(),
    };
    Ok((native_server, hot_state))
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
        crate::bail!("No upstream DNS servers are set in `upstreams`");
    }
    let fwd = onetdns_forward::Forwarder::with_upstreams(
        ups,
        Duration::from_secs(cfg.query_timeout_secs),
    )
    .with_strategy(forward_strategy(cfg.upstream_strategy))
    .with_parallel_limit(cfg.upstream_concurrency);
    let qtype = parse_qtype(qtype.as_deref())?;
    let qname = onetdns_proto::Name::from_str(&name)
        .map_err(|_| crate::anyhow!("Invalid domain name: {name}"))?;
    let req = onetdns_proto::Message::query(0x4242, qname, qtype);
    let resp = fwd
        .resolve(&req)
        .map_err(|e| crate::anyhow!("Could not resolve the DNS query: {e}"))?;

    println!(
        "Response code: {} ({})",
        native::rcode_str(onetdns_proto::ResponseCode(resp.header.rcode)),
        resp.header.rcode
    );
    if resp.answers.is_empty() {
        println!("No answer records");
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
        .map_err(|error| format!("Invalid JSON request body: {error}"))?;
    let qname = j
        .get("qname")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or("`qname` must contain the domain to look up")?;
    let name = onetdns_proto::Name::from_str(qname)
        .map_err(|_| format!("Invalid domain name: {qname}"))?;
    let qtype_text = j
        .get("qtype")
        .and_then(|v| v.as_str())
        .unwrap_or("A")
        .to_string();
    let qtype = onetdns_proto::RecordType(
        *qtype_numbers(&[qtype_text.clone()])
            .first()
            .ok_or("Unknown query type")?,
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
        .ok_or("There is no plain DNS listening address to query")?;

    let request = onetdns_proto::Message::query(
        u16::from_be_bytes(onetdns_core::ephemeral_random_array::<2>()),
        name,
        qtype,
    );
    let started = std::time::Instant::now();
    let response = onetdns_forward::query_server(target, &request, timeout)
        .map_err(|error| format!("Could not query this server: {error}"))?;
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
            return Err(format!("DNS zone source '{key}' has an invalid address"));
        }
    }
    if let Some(host) = &cfg.cachedb_redis_host {
        cachedb_redis_addr(host, cfg.cachedb_redis_port, &cfg.bootstrap)?;
        if let Some(ca) = cfg.cachedb_redis_tls_ca.as_deref() {
            tls_material::cachedb_redis_roots(Some(ca))?;
        }
    }
    edge_service_preflight(cfg)?;
    if let Some(url) = &cfg.zones_postgres {
        onetdns_authority::PostgresZoneSource::from_url(url, &cfg.zones_sql_table)
            .ok_or("Could not parse the zones_postgres connection string")?
            .check()
            .map_err(|error| format!("zones_postgres: {error}"))?;
    }
    if let Some(url) = &cfg.zones_mysql {
        onetdns_authority::MysqlZoneSource::from_url(url, &cfg.zones_sql_table)
            .ok_or("Could not parse the zones_mysql connection string")?
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
            return Err(format!("Unknown blocked service: {service}"));
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
                "Client '{}' has no usable dedicated upstream DNS servers",
                c.name
            ));
        }
        ensure_upstreams_not_self(
            cfg,
            &ups,
            &format!("dedicated upstream DNS servers for client '{}'", c.name),
        )?;
        let mut ids = c.client_ids.clone();
        ids.extend(c.mac.iter().map(|m| mac::normalize_mac(m)));
        let fwd = onetdns_forward::Forwarder::with_upstreams(ups, timeout)
            .with_strategy(forward_strategy(cfg.upstream_strategy))
            .with_parallel_limit(cfg.upstream_concurrency);
        let backend: Arc<dyn native::Resolver> = Arc::new(native::NativeBackend::Forward(fwd));
        routes.push(native::ClientUpstream::new(
            c.ids.clone(),
            ids,
            c.upstreams.clone(),
            backend,
        ));
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
                " (upstream DNS servers given by host name need bootstrap, or give an IP address together with the TLS server name, for example h3://1.1.1.1/dns-query#cloudflare-dns.com)"
            } else if has_hostname {
                " (could not resolve the upstream DNS server host name; check that `bootstrap` is reachable, or give an IP address together with the TLS server name, for example h3://1.1.1.1/dns-query#cloudflare-dns.com)"
            } else {
                " (check the upstream DNS server address format)"
            };
            return Err(format!(
                "None of the {configured} configured upstream DNS servers could be resolved{hint}"
            ));
        }
        return Err(
            "Forwarding and split resolution need at least one upstream DNS server".to_string(),
        );
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

/** @brief 컨트롤 플레인이 만든 백업을 읽는다. 형식이 다르면 거부한다. */
fn parse_control_backup(
    body: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>, Vec<String>, bool), String> {
    use onetdns_core::json::Json;

    let root = onetdns_core::json::parse(body)
        .map_err(|error| format!("Could not parse the backup JSON: {error}"))?;
    let Json::Obj(fields) = &root else {
        return Err("The top-level value of the backup JSON must be an object".to_string());
    };
    if fields.len() != 6
        || fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "version" | "block" | "allow" | "services" | "refused_domains" | "safe_search"
            )
        })
    {
        return Err("The backup JSON fields do not match the current format".to_string());
    }
    if root.get("version").and_then(Json::as_u64) != Some(1) {
        return Err("The backup JSON version must be 1, the current format".to_string());
    }
    let strings = |key: &str| -> Result<Vec<String>, String> {
        root.get(key)
            .and_then(Json::as_array)
            .ok_or_else(|| {
                format!("The {key} field of the backup JSON must be an array of strings")
            })?
            .iter()
            .map(|item| {
                item.as_str().map(String::from).ok_or_else(|| {
                    format!("The {key} field of the backup JSON must be an array of strings")
                })
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
        .ok_or_else(|| "The safe_search field of the backup JSON must be a boolean".to_string())?;
    Ok((block, allow, services, refused_domains, safe_search))
}

/** @brief 읽어들일 인증 기관 파일 크기 상한. */
const LOCAL_CA_MAX_BYTES: u64 = 4 * 1024 * 1024;
/** @brief 읽어들일 키 파일 크기 상한. */
const LOCAL_KEY_MAX_BYTES: u64 = 1024 * 1024;
/** @brief 읽어들일 상태 파일 크기 상한. */
const LOCAL_STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/** @brief 읽어들일 정책 플러그인 크기 상한. */
const WASM_MODULE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/** @brief 크기 상한을 걸어 파일을 읽는다. */
fn read_bytes_limited(path: &std::path::Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "File exceeds the size limit",
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

/** @brief 담아 두는 작업 수. 넘치면 끝난 작업 중 가장 오래된 것부터 지운다. */
const JOB_HISTORY: usize = 64;

impl Default for JobRegistry {
    /** @brief 기본 개수만큼 담아 두도록 만든다. */
    fn default() -> Self {
        JobRegistry::new(JOB_HISTORY)
    }
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

/** @brief 문자열 목록을 JSON 배열로. */
fn json_str_array(items: &[String]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|s| onetdns_core::json::escape(s))
        .collect();
    format!("[{}]", parts.join(","))
}

/** @brief 첫 관리자 계정용 일회용 설정 코드를 적는 파일 이름. 설정 파일과 같은 폴더에 둔다. */
const SETUP_CODE_FILE_NAME: &str = "setup-code.txt";

/**
 * @brief 설정 코드 파일 경로. 설정 파일이 없으면 없다.
 * @details 실행 파일 옆이 아니라 설정 파일 옆에 둔다. 실행 파일이 있는 폴더는 다른 사용자도
 *          읽거나 쓸 수 있는 경우가 많고, 설정 파일 폴더는 이미 제어 토큰 같은 비밀을 담는
 *          곳이라 서비스 계정만 읽도록 되어 있다. 같은 실행 파일로 설정을 달리해 띄운 인스턴스도
 *          서로의 코드를 덮어쓰지 않는다.
 */
fn setup_code_path(config_path: Option<&std::path::Path>) -> Option<PathBuf> {
    let dir = config_path?.parent()?;
    let dir = if dir.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        dir
    };
    Some(dir.join(SETUP_CODE_FILE_NAME))
}

/**
 * @brief 계정이 없으면 첫 관리자 계정용 일회용 설정 코드를 발급해 파일에 적는다.
 * @details 계정이 이미 있으면 남아 있는 코드 파일을 지운다. 로그에는 코드가 아니라 파일 경로만
 *          남긴다. 로그는 설정 폴더보다 넓게 읽히는 경우가 많다.
 */
fn issue_setup_code(auth: &onetdns_control::Auth, config_path: Option<&std::path::Path>) {
    let path = setup_code_path(config_path);
    if auth.has_users() {
        auth.clear_setup_code();
        if let Some(path) = path {
            remove_setup_code_file(&path);
        }
        return;
    }
    let Some(path) = path else {
        auth.clear_setup_code();
        onetdns_core::warn!(
            event = "console.setup_code_unavailable",
            "No configuration file, so there is nowhere to write a setup code. Add a [[users]] entry to create the first dashboard account"
        );
        return;
    };
    let code: String = gen_token().chars().take(32).collect();
    match atomic_write_secret(&path, format!("{code}\n").as_bytes()) {
        Ok(()) => {
            auth.set_setup_code(&code, path.display().to_string());
            onetdns_core::warn!(
                event = "console.setup_code_issued",
                path = %path.display(),
                "No dashboard account exists yet. Open the dashboard and enter the setup code from this file to create the first administrator"
            );
        }
        Err(error) => {
            auth.clear_setup_code();
            onetdns_core::error!(
                event = "console.setup_code_write_failed",
                path = %path.display(),
                %error,
                "Could not write the setup code, so the dashboard cannot create the first account"
            );
        }
    }
}

/** @brief 쓴 설정 코드 파일을 지운다. 없으면 할 일이 없다. */
fn remove_setup_code_file(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => onetdns_core::warn!(
            event = "console.setup_code_remove_failed",
            path = %path.display(),
            %error,
            "Could not delete the used setup code file. It no longer works; delete it by hand"
        ),
    }
}

/** @brief 관리 화면 앞의 리버스 프록시 정책을 설정에서 만든다. */
fn control_proxy_policy(cfg: &Config) -> onetdns_control::ProxyPolicy {
    onetdns_control::ProxyPolicy {
        trusted: cfg.control_trusted_proxies.clone(),
        origins: cfg.control_public_origins.clone(),
    }
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
                    "users[{index}] needs a non-empty name and password_hash"
                ));
            }
            if !names.insert(user.name.clone()) {
                return Err(format!("users[{index}] has a duplicate name"));
            }
            let role = match user.role.as_str() {
                "admin" => onetdns_control::Role::Admin,
                "readonly" => onetdns_control::Role::ReadOnly,
                other => {
                    return Err(format!(
                        "users[{index}].role has a value that is not allowed: '{other}'"
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

/**
 * @brief 공유 캐시로 쓸 Redis 주소를 찾는다.
 *
 * @details 체인을 만들 때마다 다시 찾는다. 한 번 찾아 두면 주소를 바꿔도 이전 서버를 계속
 *          바라본다.
 * @return 이름을 주소로 바꾸지 못하면 실패.
 */
fn cachedb_redis_addr(host: &str, port: u16, bootstrap: &[IpAddr]) -> Result<SocketAddr, String> {
    let ip = upstream::resolve_host_via_bootstrap(host, bootstrap).ok_or_else(|| {
        format!("Could not resolve cachedb_redis_host={host}; host names need bootstrap")
    })?;
    Ok(SocketAddr::new(ip, port))
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
        "Checking revocation of upstream TLS server certificates (OCSP/CRL)"
    );
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
            .ok_or_else(|| format!("TSIG key '{}' has an invalid name or Base64 secret", k.name))?;
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

/** @brief 로그를 켠다. */
fn init_tracing() {
    onetdns_core::log::init_from_env();
    onetdns_core::isolation::install_request_panic_hook();
}

#[cfg(test)]
/** @brief 설정이 조용히 넓어지거나 사라지지 않는지, 그리고 전송·클러스터·교체 판정. */
mod tests {
    use super::*;
    use crate::listeners::tls_configs_from;
    use crate::notify::NotifySender;
    use crate::secondary::spawn_secondary_refresh_with_timeout;
    use crate::tls_material::native_tls_material;
    use std::net::UdpSocket;

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

    #[cfg(target_os = "linux")]
    #[test]
    /**
     * @brief 권한을 내려놓지 못하면 다음 세대도 준비 전에 실패하는지.
     * @details 실행 루프는 실패한 세대를 마지막 설정으로 다시 띄우므로 한 프로세스에서 세대가
     *          여럿 뜬다. 없는 사용자를 지정해 실제 권한은 바꾸지 않는다.
     */
    fn every_generation_fails_when_privileges_cannot_be_dropped() {
        for generation in 1..=2 {
            let mut cfg = Config::default();
            cfg.listen = vec![UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()];
            cfg.do_tcp = false;
            cfg.workers = 1;
            cfg.run_as_user = Some("onetdns-missing-test-user".into());

            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ready_stop = stop.clone();
            let result = serve(
                cfg,
                None,
                None,
                Default::default(),
                Some(stop),
                Some(Box::new(move || {
                    ready_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                })),
            );
            let error = match result {
                Ok(_) => panic!("{generation}번째 세대가 권한을 내려놓지 않은 채 준비를 마쳤다"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("privileges could not be dropped"),
                "{generation}번째 세대가 권한과 무관한 이유로 실패했다: {error}"
            );
        }
    }

    /** @brief 관리 API 에 요청 하나를 보내고 응답 전체를 돌려준다. */
    fn control_request(addr: SocketAddr, method: &str, path: &str, body: &str) -> String {
        use std::io::{Read, Write};
        let content_type = if matches!(path, "/v1/config/apply" | "/v1/config/diff") {
            "application/toml"
        } else {
            "application/json"
        };
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n\
             Authorization: Bearer hot-apply-test-token-0123456789\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    /**
     * @brief 영역을 읽지 못해 교체가 실패하면 같이 바꾸려던 차단 규칙과 실행 중 설정이 그대로인지.
     * @details 설정 파일은 이전 것으로 돌아간다. 차단 규칙만 먼저 바뀌어 있으면 파일에 없는 규칙으로
     *          답하고, 다음 재시작 때 말없이 풀린다. 영역 파일의 내용은 사전 검사가 읽지 않으므로
     *          이 설정은 교체 경로에 들어와서야 거절된다.
     */
    fn failed_hot_apply_leaves_the_running_configuration_alone() {
        let dns = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "onetdns-hot-apply-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("OnetDNS.toml");
        let text = format!(
            "listen = [\"{dns}\"]\n\
             do_tcp = false\n\
             workers = 1\n\
             backend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\n\
             control_listen = \"{control}\"\n\
             control_token = \"hot-apply-test-token-0123456789\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::from_toml_str(&text).unwrap();

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = {
            let ready = ready.clone();
            let stop = stop.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                serve(
                    cfg,
                    Some(onetdns_core::SecretString::from(text)),
                    Some(path),
                    Default::default(),
                    Some(stop),
                    Some(Box::new(move || {
                        ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    })),
                )
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "server did not start");
            assert!(!server.is_finished(), "server stopped before it was ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        let before = std::fs::read_to_string(&path).unwrap();

        let zone = root.join("broken.zone");
        std::fs::write(&zone, "this is not a zone file\n").unwrap();
        let snippet = format!(
            "block_rules = [\"||blocked.test^\"]\n\
             [[zones]]\norigin = \"broken.test\"\nfile = \"{}\"\n",
            zone.display().to_string().replace('\\', "/")
        );
        let applied = control_request(control, "POST", "/v1/config/apply", &snippet);
        assert!(!applied.starts_with("HTTP/1.1 200"), "{applied}");
        assert!(
            applied.contains("Could not parse DNS zone file"),
            "{applied}"
        );

        let explained = control_request(
            control,
            "POST",
            "/v1/explain",
            "{\"qname\":\"blocked.test\"}",
        );
        assert!(explained.starts_with("HTTP/1.1 200"), "{explained}");
        assert!(!explained.contains("\"filter\":\"block"), "{explained}");
        let effective = control_request(control, "GET", "/v1/config/effective", "");
        assert!(!effective.contains("blocked.test"), "{effective}");
        assert!(!effective.contains("broken.test"), "{effective}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    /**
     * @brief 효과 단계의 뒤쪽 효과가 실패하면 앞에서 이미 일으킨 효과까지 되돌리는지.
     * @details 수신 주소를 하나 더 여는 효과는 성공하고, 그 뒤에 관리 주소를 이미 쓰이는 포트로
     *          옮기는 효과가 실패한다. 새로 연 주소가 남아 있으면 설정 파일에 없는 주소로 답한다.
     *          원래 수신 주소는 이전 차단 규칙으로 계속 답해야 한다.
     */
    fn failed_hot_apply_effect_undoes_the_effects_that_already_ran() {
        let dns = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let added = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let root = std::env::temp_dir().join(format!(
            "onetdns-hot-apply-effects-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("OnetDNS.toml");
        let text = format!(
            "listen = [\"{dns}\"]\n\
             do_tcp = false\n\
             workers = 1\n\
             backend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\n\
             block_rules = [\"||old.test^\"]\n\
             control_listen = \"{control}\"\n\
             control_token = \"hot-apply-test-token-0123456789\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::from_toml_str(&text).unwrap();

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = {
            let ready = ready.clone();
            let stop = stop.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                serve(
                    cfg,
                    Some(onetdns_core::SecretString::from(text)),
                    Some(path),
                    Default::default(),
                    Some(stop),
                    Some(Box::new(move || {
                        ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    })),
                )
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "server did not start");
            assert!(!server.is_finished(), "server stopped before it was ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        let before = std::fs::read_to_string(&path).unwrap();

        let snippet = format!(
            "listen = [\"{dns}\", \"{added}\"]\n\
             block_rules = [\"||old.test^\", \"||new.test^\"]\n\
             control_listen = \"{occupied_addr}\"\n"
        );
        let applied = control_request(control, "POST", "/v1/config/apply", &snippet);
        assert!(!applied.starts_with("HTTP/1.1 200"), "{applied}");
        assert!(
            applied.contains("Could not open the dashboard listening address"),
            "{applied}"
        );
        assert!(!applied.contains("also failed"), "{applied}");

        // 되돌리기가 소켓을 닫았으면 이 주소를 다시 열 수 있다.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match UdpSocket::bind(added) {
                Ok(_) => break,
                Err(error) => assert!(
                    std::time::Instant::now() < deadline,
                    "the listener opened by the failed apply is still bound: {error}"
                ),
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut query = vec![0x4f, 0x4e, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["old", "test"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        client.send_to(&query, dns).unwrap();
        let mut reply = [0u8; 512];
        let (len, _) = client.recv_from(&mut reply).unwrap();
        assert!(len >= 12 && reply[..2] == [0x4f, 0x4e] && reply[2] & 0x80 != 0);

        let explained = control_request(control, "POST", "/v1/explain", "{\"qname\":\"old.test\"}");
        assert!(explained.contains("\"filter\":\"block"), "{explained}");
        let explained = control_request(control, "POST", "/v1/explain", "{\"qname\":\"new.test\"}");
        assert!(explained.starts_with("HTTP/1.1 200"), "{explained}");
        assert!(!explained.contains("\"filter\":\"block"), "{explained}");
        let effective = control_request(control, "GET", "/v1/config/effective", "");
        assert!(!effective.contains("new.test"), "{effective}");
        assert!(!effective.contains(&added.to_string()), "{effective}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap().unwrap();
        drop(occupied);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    /**
     * @brief 해석 체인 그룹의 키를 무중단으로 바꿔도 질의마다 읽는 기능 값이 새 설정을 따르는지.
     * @details ecs_mode 와 ecs_custom_ip 는 체인을 다시 만드는 키지만, 클라이언트가 보낸 ECS
     *          옵션을 응답에 되돌려 줄지도 정한다. 기능 세트가 이전 설정에 머물면 ECS 를 켠 뒤에도
     *          RFC 7871 이 요구하는 에코가 나가지 않는다.
     */
    fn hot_applied_chain_keys_reach_the_response_features() {
        let dns = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "onetdns-hot-apply-features-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("OnetDNS.toml");
        let text = format!(
            "listen = [\"{dns}\"]\n\
             do_tcp = false\n\
             workers = 1\n\
             backend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\n\
             block_rules = [\"||blocked.test^\"]\n\
             control_listen = \"{control}\"\n\
             control_token = \"hot-apply-test-token-0123456789\"\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::from_toml_str(&text).unwrap();

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = {
            let ready = ready.clone();
            let stop = stop.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                serve(
                    cfg,
                    Some(onetdns_core::SecretString::from(text)),
                    Some(path),
                    Default::default(),
                    Some(stop),
                    Some(Box::new(move || {
                        ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    })),
                )
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "server did not start");
            assert!(!server.is_finished(), "server stopped before it was ready");
            std::thread::sleep(Duration::from_millis(20));
        }

        /* 주소 계열 1(IPv4), 원본 접두사 24, 범위 접두사 0, 주소 192.0.2 */
        let subnet = vec![0, 1, 24, 0, 192, 0, 2];
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let echoed = |id: u16| {
            let mut query = onetdns_proto::Message::query(
                id,
                onetdns_proto::Name::from_str("blocked.test").unwrap(),
                onetdns_proto::RecordType::A,
            );
            let mut edns = onetdns_proto::Edns::default();
            edns.set_client_subnet(subnet.clone());
            query.additionals.push(edns.try_to_record().unwrap());
            client.send_to(&query.try_encode().unwrap(), dns).unwrap();
            let mut reply = [0u8; 512];
            let (len, _) = client.recv_from(&mut reply).unwrap();
            let response = onetdns_proto::Message::parse(&reply[..len]).unwrap();
            assert_eq!(response.header.id, id);
            response
                .opt()
                .and_then(onetdns_proto::Edns::from_record)
                .and_then(|edns| edns.client_subnet().map(<[u8]>::to_vec))
        };
        assert_eq!(
            echoed(1),
            None,
            "ECS 를 쓰지 않는 동안에는 되돌려 줄 옵션이 없습니다"
        );

        let applied = control_request(
            control,
            "POST",
            "/v1/config/apply",
            "ecs_mode = \"send\"\necs_custom_ip = \"203.0.113.1\"\n",
        );
        assert!(applied.contains("\"mode\":\"hot_reload\""), "{applied}");
        assert_eq!(
            echoed(2),
            Some(subnet.clone()),
            "ECS 를 켠 뒤에는 클라이언트가 보낸 옵션을 SCOPE 0 으로 되돌려 줘야 합니다"
        );

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    /**
     * @brief 클라이언트 경로가 있을 때 관리 화면과 변경 미리보기가 체인 설정의 재시작을 알리는지.
     * @details 경로의 체인은 세대를 시작할 때만 만들어지므로 체인 설정을 바꾸면 서비스를 다시
     *          시작한다. 관리 화면은 원문 편집기에서는 /v1/config/diff 의 판정으로, 설정 항목
     *          화면에서는 /v1/config/set/diff 의 판정으로, 저장된 파일을 반영할 때는
     *          /v1/config/status 의 판정으로 묻고, 항목 표시는 스키마와 상태의 분류를 따른다.
     *          어느 하나라도 무중단이라고 답하면 묻지 않고 적용하므로, 모두 실제 적용 결과와 같아야
     *          한다.
     */
    fn client_routes_make_chain_changes_announce_a_restart() {
        let dns = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let control = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "onetdns-route-restart-{}-{}",
            std::process::id(),
            unix_now()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("OnetDNS.toml");
        let text = format!(
            "listen = [\"{dns}\"]\n\
             do_tcp = false\n\
             workers = 1\n\
             backend = \"forward\"\n\
             upstream_urls = [\"udp://192.0.2.1:53\"]\n\
             control_listen = \"{control}\"\n\
             control_token = \"hot-apply-test-token-0123456789\"\n\
             [[clients]]\nname = \"office\"\nids = [\"192.0.2.0/24\"]\n\
             upstreams = [\"192.0.2.9\"]\n"
        );
        std::fs::write(&path, &text).unwrap();
        let cfg = Config::from_toml_str(&text).unwrap();

        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = {
            let ready = ready.clone();
            let stop = stop.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                serve(
                    cfg,
                    Some(onetdns_core::SecretString::from(text)),
                    Some(path),
                    Default::default(),
                    Some(stop),
                    Some(Box::new(move || {
                        ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    })),
                )
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(std::time::Instant::now() < deadline, "server did not start");
            assert!(!server.is_finished(), "server stopped before it was ready");
            std::thread::sleep(Duration::from_millis(20));
        }

        let keys = |response: &str, name: &str| -> Vec<String> {
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            let (_, body) = response.split_once("\r\n\r\n").unwrap();
            onetdns_core::json::parse(body)
                .unwrap()
                .get(name)
                .and_then(|value| value.as_array())
                .unwrap_or_else(|| panic!("{name} is missing: {body}"))
                .iter()
                .map(|key| key.as_str().unwrap().to_string())
                .collect()
        };
        let schema = control_request(control, "GET", "/v1/config/schema", "");
        let hot = keys(&schema, "hot_reload_keys");
        let conditional = keys(&schema, "conditional_hot_reload_keys");
        assert!(!hot.contains(&"min_ttl".to_string()), "{hot:?}");
        assert!(
            conditional.contains(&"min_ttl".to_string()),
            "{conditional:?}"
        );
        assert!(hot.contains(&"block_rules".to_string()), "{hot:?}");

        let preview = control_request(control, "POST", "/v1/config/diff", "min_ttl = 120\n");
        assert_eq!(keys(&preview, "service_restart"), ["min_ttl"]);
        assert!(preview.contains("\"restart_required\":true"), "{preview}");
        let preview = control_request(
            control,
            "POST",
            "/v1/config/diff",
            "block_rules = [\"||blocked.test^\"]\n",
        );
        assert_eq!(keys(&preview, "hot_reload"), ["block_rules"]);
        assert!(preview.contains("\"restart_required\":false"), "{preview}");

        let preview = control_request(control, "POST", "/v1/config/set/diff", "{\"min_ttl\":120}");
        assert_eq!(keys(&preview, "service_restart"), ["min_ttl"]);
        assert!(preview.contains("\"restart_required\":true"), "{preview}");
        let preview = control_request(
            control,
            "POST",
            "/v1/config/set/diff",
            "{\"block_rules\":[\"||blocked.test^\"]}",
        );
        assert_eq!(keys(&preview, "hot_reload"), ["block_rules"]);
        assert!(preview.contains("\"restart_required\":false"), "{preview}");
        let preview = control_request(control, "POST", "/v1/config/set/diff", "{\"min_ttl\":null}");
        assert!(preview.contains("\"restart_required\":false"), "{preview}");
        let rejected = control_request(control, "POST", "/v1/config/set/diff", "{\"no_such\":1}");
        assert!(rejected.starts_with("HTTP/1.1 400"), "{rejected}");

        let saved = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("min_ttl = 120\n{saved}")).unwrap();
        let status = control_request(control, "GET", "/v1/config/status", "");
        assert_eq!(keys(&status, "changed_keys"), ["min_ttl"]);
        assert_eq!(keys(&status, "service_restart"), ["min_ttl"]);
        assert!(status.contains("\"restart_required\":true"), "{status}");
        assert_eq!(keys(&status, "conditional_hot_reload_keys"), conditional);
        let preview = control_request(control, "POST", "/v1/config/set/diff", "{\"min_ttl\":120}");
        assert!(keys(&preview, "effective_changed").is_empty(), "{preview}");
        assert!(preview.contains("\"restart_required\":false"), "{preview}");
        let applied = control_request(control, "POST", "/v1/config/set", "{\"min_ttl\":120}");
        assert!(applied.contains("\"mode\":\"no_change\""), "{applied}");
        let preview = control_request(
            control,
            "POST",
            "/v1/config/set/diff",
            "{\"block_rules\":[\"||blocked.test^\"]}",
        );
        assert_eq!(keys(&preview, "hot_reload"), ["block_rules"]);
        assert_eq!(keys(&preview, "service_restart"), ["min_ttl"]);
        assert!(preview.contains("\"restart_required\":true"), "{preview}");
        std::fs::write(&path, saved).unwrap();

        let applied = control_request(control, "POST", "/v1/config/apply", "min_ttl = 120\n");
        assert!(
            applied.contains("\"mode\":\"service_restart\""),
            "{applied}"
        );

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        server.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).unwrap();
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
            "cachedb_redis_secret",
            "cachedb_redis_password",
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
    pub(crate) fn tcp_udp_test_listeners() -> (
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
    pub(crate) fn secondary_xfr_admission_test_server(
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
            Arc::default(),
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
