//! Opens and closes DNS sockets and encrypted listeners to match the config.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;
use zeroize::Zeroizing;

use crate::atomic_file::atomic_write_secret;
use crate::connection_limit::EncryptedTcpListener;
use crate::edge::parse_hex_bytes;
use crate::handoff::{ListeningSocket, SocketPool, SocketRole};
use crate::tls_material::{native_tls_config, native_tls_material};
use crate::{
    connection_limit, dnscrypt, doh, doh3, doq, dot, native, plain_dns_worker_counts,
    quic_listener, quic_memory, read_bytes_limited, read_text_limited, sleep_or_shutdown,
    track_service_thread, LOCAL_CA_MAX_BYTES,
};

/// The provider name and public key DNSCrypt clients must trust; `None` while no DNSCrypt listener
/// is open.
#[derive(Clone)]
pub(crate) struct DnscryptIdentity {
    pub(crate) provider_name: String,
    pub(crate) public_key: [u8; 32],
}

pub(crate) type DnscryptIdentitySlot = Arc<Mutex<Option<DnscryptIdentity>>>;

fn dnscrypt_provider_key_path(
    config_path: &Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    let p = config_path.as_ref()?;
    let dir = p.parent()?;
    Some(dir.join("dnscrypt-provider.key"))
}

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

/// Swappable per-transport TLS configs, so a certificate change needs no listener reopen:
/// established connections keep the old certificate, and new ones get the new one.
///
/// All four slots always come from the same certificate; only ALPN differs.
pub(crate) struct TlsSlots {
    dot: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    doh: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    doq: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    doh3: Arc<onetdns_core::ArcSwap<onetdns_tls::ServerConfig>>,
    /// The file-based material the slots use now, which tells whether contents changed under an
    /// unchanged path. Public values only; the private key stays in the slots, with no copy here.
    live_files: Mutex<LiveTlsFiles>,
}

#[derive(PartialEq, Eq)]
struct LiveTlsFiles {
    certs: Vec<Vec<u8>>,
    /// None without mTLS.
    client_ca: Option<Vec<u8>>,
}

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

/// The key each transport seals TLS session tickets with; None where resumption is off.
#[derive(Default)]
pub(crate) struct TicketKeys {
    dot: Option<Zeroizing<[u8; 32]>>,
    doh: Option<Zeroizing<[u8; 32]>>,
    doq: Option<Zeroizing<[u8; 32]>>,
    doh3: Option<Zeroizing<[u8; 32]>>,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl TicketKeys {
    /// DoT, DoH, DoQ, DoH3.
    pub(crate) fn each(&self) -> [Option<&Zeroizing<[u8; 32]>>; 4] {
        [&self.dot, &self.doh, &self.doq, &self.doh3].map(Option::as_ref)
    }

    pub(crate) fn from_each([dot, doh, doq, doh3]: [Option<Zeroizing<[u8; 32]>>; 4]) -> Self {
        Self {
            dot,
            doh,
            doq,
            doh3,
        }
    }
}

impl TlsSlots {
    /// Built from the current config if absent, so slots appear when a certificate and an encrypted
    /// address are added later. Building them up front would fail startup without a certificate.
    /// Fails when the certificate cannot be read.
    fn get_or_build(
        handle: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
        cfg: &Config,
        self_signed_file: Option<&std::path::Path>,
        tickets: impl FnOnce() -> TicketKeys,
    ) -> Result<Arc<TlsSlots>, String> {
        if let Some(slots) = handle.lock_recover().clone() {
            return Ok(slots);
        }
        let slots = Arc::new(TlsSlots::from_config(cfg, self_signed_file, tickets())?);
        *handle.lock_recover() = Some(slots.clone());
        Ok(slots)
    }

    fn from_config(
        cfg: &Config,
        self_signed_file: Option<&std::path::Path>,
        tickets: TicketKeys,
    ) -> Result<Self, String> {
        let material = native_tls_material(cfg, self_signed_file)?;
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material, tickets)?;
        Ok(TlsSlots {
            dot: Arc::new(onetdns_core::ArcSwap::new(dot)),
            doh: Arc::new(onetdns_core::ArcSwap::new(doh)),
            doq: Arc::new(onetdns_core::ArcSwap::new(doq)),
            doh3: Arc::new(onetdns_core::ArcSwap::new(doh3)),
            live_files: Mutex::new(live_tls_files(cfg, material.0)?),
        })
    }

    /// Reloads certificates whose contents changed under the same path. Renewal tools overwrite the
    /// certificate in place; the config keys stay the same, so comparing keys sees no change, and
    /// without this the expired certificate would keep being presented until restart.
    ///
    /// Returns the config keys whose material was swapped; empty when nothing changed or when
    /// running self-signed, which does not read files.
    pub(crate) fn refresh_certificate_files(
        &self,
        cfg: &Config,
    ) -> Result<Vec<&'static str>, String> {
        if cfg.tls_self_signed_host.is_some() || cfg.tls_cert.is_none() || cfg.tls_key.is_none() {
            return Ok(Vec::new());
        }
        // The whole swap happens under this lock. With a reapply and the watcher overlapping, slots
        // filled from different certificates would present a different one per transport.
        let mut live = self.live_files.lock_recover();
        let material = native_tls_material(cfg, None)?;
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
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material, TicketKeys::default())?;
        self.dot.store(dot);
        self.doh.store(doh);
        self.doq.store(doq);
        self.doh3.store(doh3);
        *live = fresh;
        Ok(changed)
    }

    /// Leaves the slots alone. Fails on an invalid certificate or private key.
    pub(crate) fn prepare(
        cfg: &Config,
        self_signed_file: Option<&std::path::Path>,
    ) -> Result<PreparedTls, String> {
        let material = native_tls_material(cfg, self_signed_file)?;
        let files = live_tls_files(cfg, material.0.clone())?;
        let (dot, doh, doq, doh3) = tls_configs_from(cfg, &material, TicketKeys::default())?;
        Ok(PreparedTls {
            dot,
            doh,
            doq,
            doh3,
            files,
        })
    }

    /// All four at once; swapping half would present different certificates per transport.
    pub(crate) fn install(&self, prepared: PreparedTls) {
        let mut live = self.live_files.lock_recover();
        self.dot.store(prepared.dot);
        self.doh.store(prepared.doh);
        self.doq.store(prepared.doq);
        self.doh3.store(prepared.doh3);
        *live = prepared.files;
    }

    /// The chain every encrypted transport presents now, leaf first.
    pub(crate) fn served_chain(&self) -> Vec<Vec<u8>> {
        self.dot.load().cert_chain.clone()
    }

    pub(crate) fn ticket_keys(&self) -> TicketKeys {
        let key = |slot: &onetdns_core::ArcSwap<onetdns_tls::ServerConfig>| {
            slot.load()
                .resumption
                .as_ref()
                .map(|resumption| resumption.ticketer.key())
        };
        TicketKeys {
            dot: key(&self.dot),
            doh: key(&self.doh),
            doq: key(&self.doq),
            doh3: key(&self.doh3),
        }
    }
}

/// Read but not yet installed.
pub(crate) struct PreparedTls {
    dot: Arc<onetdns_tls::ServerConfig>,
    doh: Arc<onetdns_tls::ServerConfig>,
    doq: Arc<onetdns_tls::ServerConfig>,
    doh3: Arc<onetdns_tls::ServerConfig>,
    files: LiveTlsFiles,
}

/// One certificate shared by all four transports; only ALPN differs.
#[allow(clippy::type_complexity)]
pub(crate) fn tls_configs_from(
    cfg: &Config,
    material: &(Vec<Vec<u8>>, Vec<u8>),
    tickets: TicketKeys,
) -> Result<
    (
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
        Arc<onetdns_tls::ServerConfig>,
    ),
    String,
> {
    let TicketKeys {
        dot,
        doh,
        doq,
        doh3,
    } = tickets;
    Ok((
        native_tls_config(cfg, vec![b"dot".to_vec()], material, dot)?,
        native_tls_config(
            cfg,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            material,
            doh,
        )?,
        native_tls_config(cfg, vec![b"doq".to_vec()], material, doq)?,
        native_tls_config(cfg, vec![b"h3".to_vec()], material, doh3)?,
    ))
}

/// Open listen addresses, each with a key naming the config it was opened with. An unchanged key
/// leaves that listener alone, so not one query to it is cut.
///
/// New listeners all open before the old ones close; the other way around would leave a gap with
/// nobody receiving. On Linux, SO_REUSEPORT lets the same address be opened twice.
#[derive(Default)]
pub(crate) struct ListenerSet {
    plain: Mutex<Vec<(String, onetdns_runtime::Server)>>,
    dot: Mutex<Vec<(String, EncryptedTcpListener)>>,
    doh: Mutex<Vec<(String, EncryptedTcpListener)>>,
    doq: Mutex<Vec<(String, quic_listener::QuicListener)>>,
    doh3: Mutex<Vec<(String, quic_listener::QuicListener)>>,
    /// Shared by DoQ and DoH3 connections on every address.
    quic_memory: Arc<quic_memory::QuicMemoryBudget>,
    /// Admission shared by DoH, DoT, and DNSCrypt TCP connections on every address.
    encrypted_tcp_admission: Arc<connection_limit::ConnectionLimiter>,
    dnscrypt: Mutex<Vec<DnscryptListener>>,
    /// Open sockets that listeners take before binding their address.
    inherited: Mutex<SocketPool>,
}

/// UDP is served by a thread of its own, TCP by an encrypted TCP listener on the same address.
struct DnscryptListener {
    key: String,
    /// Ends the UDP thread and the certificate renewal.
    stop: Arc<std::sync::atomic::AtomicBool>,
    udp_thread: Option<std::thread::JoinHandle<()>>,
    /// Kept so `export` can hand it on; closed when the listener stops reading.
    udp: Option<UdpSocket>,
    tcp: EncryptedTcpListener,
    /// Kept so `export` can hand its resolver key on.
    provider: onetdns_dnscrypt::Provider,
}

impl DnscryptListener {
    fn stop_reading(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.udp_thread.take() {
            let _ = thread.join();
        }
        self.udp = None;
        self.tcp.stop_reading();
    }
}

impl Drop for DnscryptListener {
    fn drop(&mut self) {
        self.stop_reading();
    }
}

impl ListenerSet {
    /// Every listener stops reading its listening sockets and closes its handles to them; returns
    /// once none reads them. Connections already accepted are served until `close_all`.
    pub(crate) fn stop_reading(&self) {
        self.stop_reading_quic();
        for (_, server) in self.plain.lock_recover().iter_mut() {
            server.stop_reading();
        }
        for listeners in [&self.dot, &self.doh] {
            for (_, listener) in listeners.lock_recover().iter_mut() {
                listener.stop_reading();
            }
        }
        for listener in self.dnscrypt.lock_recover().iter_mut() {
            listener.stop_reading();
        }
    }

    /// QUIC connection state lives in this process, so a successor reads these sockets only after
    /// this returns. Every QUIC listener drains at the same time.
    pub(crate) fn stop_reading_quic(&self) {
        for listeners in [&self.doq, &self.doh3] {
            for (_, listener) in listeners.lock_recover().iter() {
                listener.signal_stop();
            }
        }
        for listeners in [&self.doq, &self.doh3] {
            for (_, listener) in listeners.lock_recover().iter_mut() {
                listener.stop_reading();
            }
        }
    }

    /// Called when a generation ends. Connections already accepted answer what they receive until
    /// idle, for at most DRAIN_LIMIT.
    pub(crate) fn close_all(&self) {
        self.stop_reading();
        self.plain.lock_recover().clear();
        self.dot.lock_recover().clear();
        self.doh.lock_recover().clear();
        self.doq.lock_recover().clear();
        self.doh3.lock_recover().clear();
        self.dnscrypt.lock_recover().clear();
    }

    /// Listeners opened from now on take their sockets from `pool` where role and address match.
    pub(crate) fn adopt(&self, pool: SocketPool) {
        *self.inherited.lock_recover() = pool;
    }

    /// Closes the adopted sockets no listener took, after the listeners for the config are open.
    pub(crate) fn drop_unclaimed(&self) {
        let unclaimed = std::mem::take(&mut *self.inherited.lock_recover());
        if !unclaimed.is_empty() {
            onetdns_core::info!(
                event = "listener.handover_unclaimed",
                sockets = %unclaimed.describe(),
                "Closed handed-over listening sockets that the configuration no longer uses"
            );
        }
    }

    /// Duplicates of every listening socket. They stay open after the listeners close, so the next
    /// listeners, in this process or another, can take them over.
    pub(crate) fn export(&self) -> std::io::Result<SocketPool> {
        let mut pool = SocketPool::default();
        for (_, server) in self.plain.lock_recover().iter() {
            let sockets = server.sockets()?;
            for socket in sockets.udp {
                let addr = socket.local_addr()?;
                pool.put(SocketRole::Do53, addr, ListeningSocket::Udp(socket));
            }
            for socket in sockets.tcp {
                let addr = socket.local_addr()?;
                pool.put(SocketRole::Do53, addr, ListeningSocket::Tcp(socket));
            }
        }
        for (role, listeners) in [(SocketRole::Dot, &self.dot), (SocketRole::Doh, &self.doh)] {
            for (_, listener) in listeners.lock_recover().iter() {
                pool.put(
                    role,
                    listener.addr(),
                    ListeningSocket::Tcp(listener.socket()?),
                );
            }
        }
        for (role, listeners) in [(SocketRole::Doq, &self.doq), (SocketRole::Doh3, &self.doh3)] {
            for (_, listener) in listeners.lock_recover().iter() {
                pool.put(
                    role,
                    listener.addr(),
                    ListeningSocket::Udp(listener.socket()?),
                );
            }
        }
        for listener in self.dnscrypt.lock_recover().iter() {
            let udp = match &listener.udp {
                Some(udp) => udp.try_clone()?,
                None => return Err(std::io::Error::other("the listener has stopped reading")),
            };
            let addr = udp.local_addr()?;
            pool.put(SocketRole::Dnscrypt, addr, ListeningSocket::Udp(udp));
            pool.put_dnscrypt_key(addr, listener.provider.resolver_secret());
            pool.put(
                SocketRole::Dnscrypt,
                listener.tcp.addr(),
                ListeningSocket::Tcp(listener.tcp.socket()?),
            );
        }
        Ok(pool)
    }

    fn take_udp(&self, role: SocketRole, addr: SocketAddr) -> Option<UdpSocket> {
        self.inherited.lock_recover().take_udp(role, addr).pop()
    }

    fn take_tcp(&self, role: SocketRole, addr: SocketAddr) -> Option<TcpListener> {
        self.inherited.lock_recover().take_tcp(role, addr).pop()
    }

    fn take_dnscrypt_key(&self, addr: SocketAddr) -> Option<Zeroizing<[u8; 32]>> {
        self.inherited.lock_recover().take_dnscrypt_key(addr)
    }

    fn take_ticket_keys(&self) -> TicketKeys {
        self.inherited.lock_recover().take_ticket_keys()
    }
}

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

/// "Address in use" alone does not say who holds it, so the operator cannot fix it. A wildcard
/// address is blocked even when every specific address looks free, which makes the config look
/// wrong. The message adds a command that finds the holder.
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

/// Removes the first entry whose configured or actual address matches. A new listener on the same
/// address opens before the old one closes, so removing every match would also drop the one just
/// opened.
///
/// Without this, an address removed from the config would stay listed as listening in the
/// dashboard.
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

/// Startup and every swap go through this. Addresses whose config is unchanged are left alone, so
/// their queries are never cut. New listeners open before old ones close.
///
/// Fails when an address cannot be opened; the old listeners then stay up and keep answering.
pub(crate) fn reconcile_listeners(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    tls: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
    self_signed_file: Option<&std::path::Path>,
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
        // The old listener must release the port before the same address reopens; its drop waits
        // for the workers to join.
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
        let server = plain_sockets(cfg, set, *addr, udp_workers, tcp_acceptors)
            .and_then(|sockets| {
                onetdns_runtime::Server::serve(
                    sockets,
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
            })
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
    // Old listeners close, through Drop, only after all new ones are open.
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

    reconcile_encrypted(cfg, set, handler, tls, shutdown, registry, self_signed_file)
}

/// Adopted sockets first, so a socket handed over keeps the queries queued on it.
fn plain_sockets(
    cfg: &Config,
    set: &ListenerSet,
    addr: SocketAddr,
    udp_workers: usize,
    tcp_acceptors: usize,
) -> std::io::Result<onetdns_runtime::ServerSockets> {
    let mut sockets = onetdns_runtime::ServerSockets::default();
    if cfg.do_udp {
        sockets.udp = set
            .inherited
            .lock_recover()
            .take_udp(SocketRole::Do53, addr);
        if sockets.udp.is_empty() {
            sockets.udp = onetdns_runtime::bind_udp(addr, udp_workers)?;
        }
    }
    if cfg.do_tcp {
        sockets.tcp = set
            .inherited
            .lock_recover()
            .take_tcp(SocketRole::Do53, addr);
        if sockets.tcp.is_empty() {
            sockets.tcp = onetdns_runtime::bind_tcp(addr, tcp_acceptors)?;
        }
    }
    Ok(sockets)
}

fn tcp_socket(
    set: &ListenerSet,
    role: SocketRole,
    addr: SocketAddr,
) -> std::io::Result<TcpListener> {
    match set.take_tcp(role, addr) {
        Some(socket) => Ok(socket),
        None => TcpListener::bind(addr),
    }
}

fn quic_socket(
    set: &ListenerSet,
    role: SocketRole,
    addr: SocketAddr,
) -> std::io::Result<UdpSocket> {
    match set.take_udp(role, addr) {
        Some(socket) => Ok(socket),
        None => onetdns_core::udp::bind(addr),
    }
}

/// Plain DNS is left alone.
fn reconcile_encrypted(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    tls: &Arc<Mutex<Option<Arc<TlsSlots>>>>,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
    self_signed_file: Option<&std::path::Path>,
) -> Result<(), String> {
    const NEED_TLS: &str = "Encrypted DNS needs queries to be forwarded to upstream servers or resolved recursively, plus an ECDSA P-256 certificate and private key";

    // The DoH path is fixed when the listener opens. The same address reopens only after the old
    // listener is taken down.
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
        TlsSlots::get_or_build(tls, cfg, self_signed_file, || set.take_ticket_keys())
            .map(|slots| pick(&slots))
            .map_err(|error| format!("{NEED_TLS}: {error}"))
    };

    if !cfg.listen_dot.is_empty() || !set.dot.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.dot.clone())?;
        sync_one!(dot, cfg.listen_dot, "dot", |addr| tcp_socket(
            set,
            SocketRole::Dot,
            addr
        )
        .and_then(|socket| dot::serve_dot(
            socket,
            tls_cfg.clone(),
            handler.clone(),
            set.encrypted_tcp_admission.clone(),
            shutdown.clone()
        ))
        .map_err(|error| listener_open_error("DoT", addr, &error)));
    }
    if !cfg.listen_doh.is_empty() || !set.doh.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doh.clone())?;
        sync_one!(doh, cfg.listen_doh, "doh", |addr| tcp_socket(
            set,
            SocketRole::Doh,
            addr
        )
        .and_then(|socket| doh::serve_doh(
            socket,
            tls_cfg.clone(),
            handler.clone(),
            cfg.doh_path.clone(),
            set.encrypted_tcp_admission.clone(),
            shutdown.clone()
        ))
        .map_err(|error| listener_open_error("DoH", addr, &error)));
    }
    if !cfg.listen_doq.is_empty() || !set.doq.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doq.clone())?;
        sync_one!(doq, cfg.listen_doq, "doq", |addr| quic_socket(
            set,
            SocketRole::Doq,
            addr
        )
        .and_then(|socket| doq::serve_doq(
            socket,
            tls_cfg.clone(),
            handler.clone(),
            shutdown.clone(),
            set.quic_memory.clone()
        ))
        .map_err(|error| listener_open_error("DoQ", addr, &error)));
    }
    if !cfg.listen_doh3.is_empty() || !set.doh3.lock_recover().is_empty() {
        let tls_cfg = need(|s| s.doh3.clone())?;
        sync_one!(doh3, cfg.listen_doh3, "doh3", |addr| quic_socket(
            set,
            SocketRole::Doh3,
            addr
        )
        .and_then(|socket| doh3::serve_doh3(
            socket,
            tls_cfg.clone(),
            handler.clone(),
            cfg.doh_path.clone(),
            shutdown.clone(),
            set.quic_memory.clone()
        ))
        .map_err(|error| listener_open_error("DoH3", addr, &error)));
    }
    Ok(())
}

const DNSCRYPT_CERT_VALID_SECS: u32 = 24 * 60 * 60;

/// Renewals are rare and a few minutes' delay is fine; a shorter period only adds reads while
/// nothing happens.
pub(crate) const TLS_CERT_WATCH_SECS: u64 = 300;

/// A renewal changes only the file contents at the same path, not the config. This lets new
/// connections use the new certificate even though the renewal tool tells this server nothing.
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
                    // A read or two fail while a renewal tool is writing the file; logging the same
                    // failure repeatedly would drown the log.
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

/// A listener closed just before releases its socket only after its loop sees the stop signal;
/// without waiting, reopening the address fails as in use. Returns the error if it never frees.
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

/// Keyed by address and provider name; a listener whose key is unchanged is left alone.
/// Fails when the provider key cannot be read or an address cannot be opened.
pub(crate) fn reconcile_dnscrypt(
    cfg: &Config,
    set: &ListenerSet,
    handler: &Arc<native::NativeServer>,
    config_path: &Option<PathBuf>,
    tracker: &Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    registry: &Arc<Mutex<Vec<(&'static str, String, String)>>>,
    identity: &DnscryptIdentitySlot,
) -> Result<(), String> {
    use std::sync::atomic::AtomicBool;

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
        .any(|(key, _)| !live.iter().any(|listener| listener.key == *key));
    if !need_new {
        live.retain(|listener| {
            let keep = wanted.iter().any(|(want, _)| *want == listener.key);
            if !keep {
                if let Some(addr) = listener.key.split('|').nth(1) {
                    forget_listener(registry, "dnscrypt", addr);
                }
            }
            keep
        });
        if live.is_empty() {
            *identity.lock_recover() = None;
        }
        return Ok(());
    }

    let provider = load_or_create_dnscrypt_provider(cfg, config_path, DNSCRYPT_CERT_VALID_SECS)?;
    *identity.lock_recover() = Some(DnscryptIdentity {
        provider_name: cfg.dnscrypt_provider_name.clone(),
        public_key: provider.provider_public_key(),
    });
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
        if live.iter().any(|listener| listener.key == *key) {
            continue;
        }
        // The address is unchanged but its config changed, so the old listener closes first;
        // reopening while it holds the address would fail as in use.
        let prefix = format!("dnscrypt|{addr}|");
        let mut index = 0;
        while index < live.len() {
            if live[index].key != *key && live[index].key.starts_with(&prefix) {
                drop(live.swap_remove(index));
                forget_listener(registry, "dnscrypt", &addr.to_string());
            } else {
                index += 1;
            }
        }
        // Clients that fetched the handed-over listener's certificate seal to its resolver key.
        let provider = match set.take_dnscrypt_key(*addr) {
            Some(secret) => provider.with_resolver_secret(&secret, DNSCRYPT_CERT_VALID_SECS),
            None => provider.clone(),
        };
        let socket = open_when_free(|| match set.take_udp(SocketRole::Dnscrypt, *addr) {
            Some(socket) => Ok(socket),
            None => UdpSocket::bind(addr),
        })
        .map_err(|error| listener_open_error("DNSCrypt", *addr, &error))?;
        let kept = socket
            .try_clone()
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
        // The spec sends certificate lookups and truncated-response retries over TCP, and UDP alone
        // would break them, so the same address listens on both.
        let tcp = open_when_free(|| {
            tcp_socket(set, SocketRole::Dnscrypt, *addr).and_then(|socket| {
                dnscrypt::serve_tcp(
                    socket,
                    handler.clone(),
                    provider.clone(),
                    set.encrypted_tcp_admission.clone(),
                )
            })
        })
        .map_err(|error| listener_open_error("DNSCrypt TCP", *addr, &error))?;
        let handler = handler.clone();
        let udp_provider = provider.clone();
        let listener_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name(format!("dnscrypt-{bound}"))
            .spawn(move || {
                if let Err(error) = dnscrypt::serve(handler, socket, udp_provider, listener_stop) {
                    onetdns_core::error!(event = "dnscrypt.stopped", %error, "Stopped DNSCrypt listener");
                }
            })
            .map_err(|error| format!("Could not start the DNSCrypt listener thread: {bound}: {error}"))?;
        onetdns_core::info!(event = "dnscrypt.started", %addr, "Accepting DNSCrypt queries (UDP and TCP)");
        fresh.push(DnscryptListener {
            key: key.clone(),
            stop,
            udp_thread: Some(thread),
            udp: Some(kept),
            tcp,
            provider,
        });
    }
    live.retain(|listener| wanted.iter().any(|(want, _)| *want == listener.key));
    live.extend(fresh);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use onetdns_config::Config;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::CONFIG_FILE_NAME;

    /// Answers every A query with `answer`, so a reply shows which handler produced it.
    pub(crate) fn upstream_answering(answer: Ipv4Addr) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let Ok(request) = onetdns_proto::Message::parse(&buf[..n]) else {
                    continue;
                };
                let mut reply = onetdns_proto::Message::default();
                reply.header.id = request.header.id;
                reply.header.response = true;
                reply.header.recursion_available = true;
                reply.questions = request.questions.clone();
                if let Some(question) = request.questions.first() {
                    reply.answers.push(onetdns_proto::Record::new(
                        question.name.clone(),
                        60,
                        onetdns_proto::RData::A(answer),
                    ));
                }
                let _ = socket.send_to(&reply.try_encode().unwrap(), from);
            }
        });
        addr
    }

    fn handler_answering(answer: Ipv4Addr) -> Arc<native::NativeServer> {
        let engine = onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain);
        Arc::new(native::NativeServer::new(
            Arc::new(onetdns_filter::SharedFilter::from_pointee(engine)),
            Arc::new(onetdns_security::IpAcl::allow_all()),
            vec![],
            Arc::new(native::NativeBackend::Forward(
                onetdns_forward::Forwarder::new(
                    vec![upstream_answering(answer)],
                    Duration::from_secs(2),
                ),
            )),
            60,
        ))
    }

    pub(crate) fn query(id: u16, name: &str) -> Vec<u8> {
        onetdns_proto::Message::query(
            id,
            onetdns_proto::Name::from_str(name).unwrap(),
            onetdns_proto::RecordType::A,
        )
        .try_encode()
        .unwrap()
    }

    fn answered_address(wire: &[u8], id: u16) -> Option<Ipv4Addr> {
        let reply = onetdns_proto::Message::parse(wire).ok()?;
        if reply.header.id != id {
            return None;
        }
        reply.answers.iter().find_map(|record| match record.rdata {
            onetdns_proto::RData::A(addr) => Some(addr),
            _ => None,
        })
    }

    pub(crate) fn ask_udp(server: SocketAddr, id: u16, name: &str) -> Option<Ipv4Addr> {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.send_to(&query(id, name), server).ok()?;
        let mut buf = [0u8; 4096];
        let (n, _) = client.recv_from(&mut buf).ok()?;
        answered_address(&buf[..n], id)
    }

    pub(crate) fn ask_tcp(server: SocketAddr, id: u16, name: &str) -> Option<Ipv4Addr> {
        let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(5)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let wire = query(id, name);
        let mut framed = (wire.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&wire);
        stream.write_all(&framed).ok()?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).ok()?;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).ok()?;
        answered_address(&reply, id)
    }

    struct Generation {
        set: ListenerSet,
        handler: Arc<native::NativeServer>,
        shutdown: Arc<AtomicBool>,
    }

    impl Generation {
        fn new(answer: Ipv4Addr) -> Self {
            Self {
                set: ListenerSet::default(),
                handler: handler_answering(answer),
                shutdown: Arc::new(AtomicBool::new(false)),
            }
        }

        fn open(&self, cfg: &Config, pool: SocketPool) {
            self.set.adopt(pool);
            reconcile_listeners(
                cfg,
                &self.set,
                &self.handler,
                &Arc::new(Mutex::new(None)),
                &self.shutdown,
                &Arc::new(Mutex::new(Vec::new())),
                None,
            )
            .expect("수신 주소 열기");
            self.set.drop_unclaimed();
        }

        fn close(&self) {
            self.shutdown.store(true, Ordering::Release);
            self.set.close_all();
        }
    }

    #[test]
    /// Queries keep being answered while the listeners of one handler give their sockets to the
    /// next: on Unix the next starts reading before the first stops, on Windows after, and either
    /// way a query waiting on the socket is answered by whoever reads it next.
    fn listeners_hand_their_sockets_over_without_dropping_queries() {
        let udp = onetdns_core::udp::bind(([127, 0, 0, 1], 0)).unwrap();
        let addr = udp.local_addr().unwrap();
        let Ok(tcp) = TcpListener::bind(addr) else {
            return;
        };
        let mut first_pool = SocketPool::default();
        first_pool.put(SocketRole::Do53, addr, ListeningSocket::Udp(udp));
        first_pool.put(SocketRole::Do53, addr, ListeningSocket::Tcp(tcp));
        let cfg = Config {
            listen: vec![addr],
            workers: 2,
            ..Config::default()
        };

        let old_answer = Ipv4Addr::new(192, 0, 2, 1);
        let new_answer = Ipv4Addr::new(192, 0, 2, 2);
        let old = Generation::new(old_answer);
        old.open(&cfg, first_pool);

        let stop = Arc::new(AtomicBool::new(false));
        let failed_udp = Arc::new(AtomicUsize::new(0));
        let failed_tcp = Arc::new(AtomicUsize::new(0));
        let by_new = Arc::new(AtomicUsize::new(0));
        let clients: Vec<_> = (0..4u16)
            .map(|client| {
                let (stop, by_new) = (stop.clone(), by_new.clone());
                let (failed_udp, failed_tcp) = (failed_udp.clone(), failed_tcp.clone());
                std::thread::spawn(move || {
                    let mut sent = 0u16;
                    while !stop.load(Ordering::Acquire) {
                        sent = sent.wrapping_add(1);
                        let id = client * 10_000 + sent % 10_000;
                        let name = format!("q{id}.handover.test");
                        let over_udp = sent % 2 == 0;
                        let answer = if over_udp {
                            ask_udp(addr, id, &name)
                        } else {
                            ask_tcp(addr, id, &name)
                        };
                        match answer {
                            Some(answer) if answer == new_answer => {
                                by_new.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(_) => {}
                            None if over_udp => {
                                failed_udp.fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                failed_tcp.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                })
            })
            .collect();

        std::thread::sleep(Duration::from_millis(300));
        let handed = old.set.export().expect("소켓 복제");
        let new = Generation::new(new_answer);
        if cfg!(windows) {
            old.set.stop_reading();
            // Nobody reads meanwhile; queries sent now must wait on the socket, not be refused.
            std::thread::sleep(Duration::from_millis(200));
            new.open(&cfg, handed);
        } else {
            new.open(&cfg, handed);
        }
        old.close();
        std::thread::sleep(Duration::from_millis(500));
        stop.store(true, Ordering::Release);
        for client in clients {
            client.join().unwrap();
        }
        new.close();

        let failed = (
            failed_udp.load(Ordering::Relaxed),
            failed_tcp.load(Ordering::Relaxed),
        );
        assert_eq!(
            failed,
            (0, 0),
            "넘기는 동안 답을 받지 못한 질의가 있습니다 (UDP, TCP)"
        );
        assert!(
            by_new.load(Ordering::Relaxed) > 0,
            "넘겨받은 쪽이 답하지 않았습니다"
        );
    }

    #[test]
    /// When another service holds the port, the error alone points at the config, especially for a
    /// wildcard address that is blocked while every specific address is free. The message must name
    /// a command to find the holder and mention binding a specific address instead.
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
        let slots = TlsSlots::from_config(&cfg, None, TicketKeys::default()).expect("슬롯 생성");
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

        // The client CA bundle is also replaced under the same path.
        let ca_path = dir.join("ca.pem");
        let (first_ca, _) =
            onetdns_transport::generate_self_signed_pem("ca-one.test").expect("CA 하나");
        std::fs::write(&ca_path, first_ca).expect("CA 저장");
        let mtls = Config {
            tls_client_ca: Some(ca_path.clone()),
            ..cfg.clone()
        };
        let mtls_slots =
            TlsSlots::from_config(&mtls, None, TicketKeys::default()).expect("mTLS 슬롯 생성");
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

    /// The resolver public key and client magic in the certificate served at `addr`.
    pub(crate) fn dnscrypt_resolver_key(addr: SocketAddr, provider_name: &str) -> Vec<u8> {
        let mut question = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in provider_name.split('.') {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.extend_from_slice(&[0, 0, 16, 0, 1]);
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.send_to(&question, addr).unwrap();
        let mut reply = [0u8; 4096];
        let (n, _) = client.recv_from(&mut reply).expect("no certificate");
        // The answer repeats the question, then a name pointer, type, class, TTL, length and the
        // string length come before the certificate; its signed part starts 72 bytes in.
        let signed = question.len() + 13 + 72;
        assert!(n >= signed + 40, "the certificate is cut short");
        reply[signed..signed + 40].to_vec()
    }

    #[test]
    /// Reopened from the sockets it exported, after a handoff or when one fails, a DNSCrypt address
    /// answers with the same resolver key, so clients holding its certificate keep working.
    fn a_dnscrypt_address_keeps_its_resolver_key_when_reopened_from_its_export() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-dnscrypt-handover-{}-{}",
            std::process::id(),
            crate::unix_now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = Some(dir.join(CONFIG_FILE_NAME));
        let addr = crate::tests::tcp_udp_test_listeners().2;
        let cfg = Config {
            listen_dnscrypt: vec![addr],
            ..Config::default()
        };
        let open = |generation: &Generation| {
            reconcile_dnscrypt(
                &cfg,
                &generation.set,
                &generation.handler,
                &config_path,
                &Arc::new(Mutex::new(Vec::new())),
                &Arc::new(Mutex::new(Vec::new())),
                &Arc::new(Mutex::new(None)),
            )
            .expect("could not open the DNSCrypt address");
        };

        let old = Generation::new(Ipv4Addr::new(192, 0, 2, 1));
        open(&old);
        let served = dnscrypt_resolver_key(addr, &cfg.dnscrypt_provider_name);
        let pool = old.set.export().unwrap();
        old.close();

        let new = Generation::new(Ipv4Addr::new(192, 0, 2, 2));
        new.set.adopt(pool);
        open(&new);
        assert_eq!(
            dnscrypt_resolver_key(addr, &cfg.dnscrypt_provider_name),
            served
        );
        new.close();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
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
