/*!
 * @brief DNS 수신 소켓과 암호화 전송 리스너를 설정에 맞춰 열고 닫는다.
 */

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::atomic_file::atomic_write_secret;
use crate::edge::parse_hex_bytes;
use crate::tls_material::{native_tls_config, native_tls_material};
use crate::{
    connection_limit, dnscrypt, doh, doh3, doq, dot, native, plain_dns_worker_counts,
    quic_listener, quic_memory, read_bytes_limited, read_text_limited, sleep_or_shutdown,
    track_service_thread, LOCAL_CA_MAX_BYTES,
};

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
        "There is no configuration file path to store the DNSCrypt provider key, so DNSCrypt is not started; this keeps the public key from changing on restart".to_string()
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
                "DNSCrypt provider key file is corrupted ({}); it is not replaced automatically so that clients that trust the current public key keep working",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Could not read the DNSCrypt provider key file ({}): {error}",
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
            "Could not save the DNSCrypt provider key to a file ({}): {error}. DNSCrypt is not started because the public key could not be kept across restarts",
            path.display()
        )
    })?;
    Ok(provider)
}

/**
 * @brief 전송별 TLS 설정을 담는 교체 가능한 슬롯들.
 *
 * @details 인증서를 갈 때 수신 소켓을 다시 열지 않기 위해 있다. 이미 맺힌 연결은 이전
 *          인증서로 이어지고, 다음 연결부터 새 인증서를 쓴다.
 * @invariant 네 슬롯은 항상 같은 인증서에서 나온다. ALPN만 다르다.
 */
pub(crate) struct TlsSlots {
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
                    "Could not read the mTLS CA file ({}): {error}",
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
    pub(crate) fn refresh_certificate_files(
        &self,
        cfg: &Config,
    ) -> Result<Vec<&'static str>, String> {
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
     * @brief 설정에 적힌 인증서를 읽어 네 슬롯에 넣을 설정을 만든다. 슬롯은 건드리지 않는다.
     * @return 인증서나 개인키가 올바르지 않으면 실패.
     */
    pub(crate) fn prepare(cfg: &Config) -> Result<PreparedTls, String> {
        let material = native_tls_material(cfg)?;
        let files = live_tls_files(cfg, material.0.clone())?;
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material)?;
        Ok(PreparedTls {
            dot,
            doh,
            doq,
            doh3,
            files,
        })
    }

    /** @brief 준비한 설정으로 네 슬롯을 한꺼번에 교체한다. 절반만 바꾸면 전송마다 다른 인증서를 내민다. */
    pub(crate) fn install(&self, prepared: PreparedTls) {
        let mut live = self.live_files.lock_recover();
        self.dot.store(prepared.dot);
        self.doh.store(prepared.doh);
        self.doq.store(prepared.doq);
        self.doh3.store(prepared.doh3);
        *live = prepared.files;
    }
}

/** @brief 읽어 두었지만 아직 슬롯에 넣지 않은 TLS 설정. */
pub(crate) struct PreparedTls {
    /** @brief DoT 설정. */
    dot: Arc<onetdns_tls::ServerConfig>,
    /** @brief DoH 설정. */
    doh: Arc<onetdns_tls::ServerConfig>,
    /** @brief DoQ 설정. */
    doq: Arc<onetdns_tls::ServerConfig>,
    /** @brief DoH3 설정. */
    doh3: Arc<onetdns_tls::ServerConfig>,
    /** @brief 이 설정을 만든 인증서 파일 내용. */
    files: LiveTlsFiles,
}

/** @brief 이미 읽어 둔 인증서로 전송 넷에 쓸 TLS 설정을 만든다. ALPN만 다르다. */
#[allow(clippy::type_complexity)]
pub(crate) fn tls_configs_from(
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
pub(crate) struct ListenerSet {
    /** @brief 일반 DNS. */
    plain: Mutex<Vec<(String, onetdns_runtime::Server)>>,
    /** @brief DoT. */
    dot: Mutex<Vec<(String, dot::DotListener)>>,
    /** @brief DoH. */
    doh: Mutex<Vec<(String, doh::DohListener)>>,
    /** @brief DoQ. */
    doq: Mutex<Vec<(String, quic_listener::QuicListener)>>,
    /** @brief DoH3. */
    doh3: Mutex<Vec<(String, quic_listener::QuicListener)>>,
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

impl ListenerSet {
    /** @brief 모든 수신 주소를 닫는다. 세대를 끝낼 때 부른다. */
    pub(crate) fn close_all(&self) {
        for (_, server) in self.plain.lock_recover().drain(..) {
            server.shutdown();
        }
        self.dot.lock_recover().clear();
        self.doh.lock_recover().clear();
        self.doq.lock_recover().clear();
        self.doh3.lock_recover().clear();
        for (_, stop, tcp) in self.dnscrypt.lock_recover().drain(..) {
            stop.store(true, std::sync::atomic::Ordering::Release);
            drop(tcp);
        }
    }
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
    let mut text = format!("Could not open the {role} listening address: {addr}: {error}");
    if error.kind() != std::io::ErrorKind::AddrInUse {
        return text;
    }
    let port = addr.port();
    text.push_str(&format!(". Another process is using port {port}."));
    if cfg!(windows) {
        text.push_str(&format!(
            " Check with: netstat -ano | findstr :{port}, tasklist /svc /FI \"PID eq <PID>\"."
        ));
    } else {
        text.push_str(&format!(" Check with: ss -lnup sport = :{port}."));
    }
    if addr.ip().is_unspecified() {
        text.push_str(" A wildcard address is blocked even when every specific address is free.");
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
pub(crate) fn reconcile_listeners(
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
        .map_err(|error| listener_open_error("Plain DNS", *addr, &error))?;
        onetdns_core::info!(event = "do53.started", %addr, udp_workers, tcp_acceptors, udp = cfg.do_udp, tcp = cfg.do_tcp, backend = ?cfg.backend, "Listening for plain DNS");
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
    const NEED_TLS: &str = "Encrypted DNS needs queries to be forwarded to upstream servers or resolved recursively, plus an ECDSA P-256 certificate and private key";

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
                    "Opened encrypted DNS listener"
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
pub(crate) const TLS_CERT_WATCH_SECS: u64 = 300;

/**
 * @brief 인증서 파일을 주기마다 다시 읽는 스레드를 띄운다.
 * @details 인증서 갱신은 설정을 건드리지 않고 같은 경로의 내용만 바꾼다. 갱신 도구가 이 서버에
 *          아무것도 알리지 않아도 다음 연결부터 새 인증서를 쓰게 하려는 것이다.
 */
pub(crate) fn spawn_tls_cert_watch(
    runtime_cfg: Arc<onetdns_core::ArcSwap<Config>>,
    slots: Arc<Mutex<Option<Arc<TlsSlots>>>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("tls-cert-watch".into())
        .spawn(move || {
            let mut last_error: Option<String> = None;
            loop {
                if sleep_or_shutdown(TLS_CERT_WATCH_SECS, &shutdown) {
                    break;
                }
                let Some(current) = slots.lock_recover().clone() else {
                    continue;
                };
                match current.refresh_certificate_files(&runtime_cfg.load()) {
                    Ok(swapped) => {
                        last_error = None;
                        if !swapped.is_empty() {
                            onetdns_core::info!(
                                event = "tls.certificate_reloaded",
                                changed = %swapped.join(","),
                                "Replaced the TLS certificate without closing listening addresses"
                            );
                        }
                    }
                    /*
                     * 갱신 도구가 파일을 쓰는 중이면 한두 번은 읽기에 실패한다. 같은 실패를 반복해
                     * 적으면 기록이 그것으로 덮인다.
                     */
                    Err(error) => {
                        if last_error.as_deref() != Some(error.as_str()) {
                            onetdns_core::warn!(
                                event = "tls.certificate_reload_failed",
                                %error,
                                "Could not read the renewed TLS certificate; keeping the previous one"
                            );
                            last_error = Some(error);
                        }
                    }
                }
            }
        })
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

pub(crate) fn reconcile_dnscrypt(
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
        "Loaded DNSCrypt provider key; clients must trust this public key"
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
                        "Renewed the DNSCrypt resolver certificate before it expired"
                    );
                })
                .map_err(|error| {
                    format!("Could not start the DNSCrypt certificate renewal task: {error}")
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
                    onetdns_core::error!(event = "dnscrypt.stopped", %error, "Stopped DNSCrypt listener");
                }
            })
            .map_err(|error| format!("Could not start the DNSCrypt listener thread: {bound}: {error}"))?;
        track_service_thread(tracker, thread);
        onetdns_core::info!(event = "dnscrypt.started", %addr, "Accepting DNSCrypt queries (UDP and TCP)");
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

#[cfg(test)]
/** @brief 리스너 교체와 인증서 슬롯. */
mod tests {
    use super::*;
    use onetdns_config::Config;

    use crate::CONFIG_FILE_NAME;

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
            wildcard.contains("wildcard"),
            "와일드카드에는 우회 방법을 알려야 합니다: {wildcard}"
        );

        let specific = listener_open_error("DoT", "127.0.0.1:853".parse().unwrap(), &busy);
        assert!(
            specific.contains(":853"),
            "찾는 명령에 포트가 들어가야 합니다: {specific}"
        );
        assert!(
            !specific.contains("wildcard"),
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
}
