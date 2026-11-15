//! Client for the external shared cache, implementing only the commands this server uses.
//! Connections are pooled and each command borrows one; the lock is held only to check connections
//! out and in and to read or change the circuit state, while connecting and round trips happen
//! outside it.
//!
//! A slow or dead cache must never stall query handling: a query waits only on a read, and stores
//! and deletes go to workers. Each command has a short deadline, a slow reply counts as a failure,
//! a command that finds no free connection is skipped rather than waiting, and after a failure the
//! cache is skipped for a while.

use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_core::{MutexExt, SecretString};
use onetdns_tls::{client_handshake, ClientConfig, TlsStream, TrustStore};
use zeroize::Zeroizing;

const MAX_RESP_LINE: usize = 4 * 1024;
/// Values this server stores are one DNS message plus its envelope, just over 64 KiB. Each
/// connection may hold this much at once, so this times the connection count bounds the memory for
/// reply values.
const MAX_BULK_REPLY: usize = 128 * 1024;
/// Covers connecting, TLS, authentication, and resending on a new connection after an idle one
/// dropped.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
/// Send-to-reply limit on an established connection; past it the command fails and the circuit
/// opens. Without it, a cache that answers slowly would never open the circuit, and every query
/// would wait that long. The shared cache is only useful if faster than asking upstream again, so
/// this is far shorter than a connect, which takes several trips.
const ROUNDTRIP_TIMEOUT: Duration = Duration::from_millis(100);
/// Trying a dead cache on every query is slower than skipping it.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
/// With every connection busy, the next command is skipped rather than waiting; waiting would turn
/// shared cache latency into query latency. The cap also bounds the sockets each server opens to
/// the shared cache.
const MAX_CONNECTIONS: usize = 64;
/// Writes occupy only this many connections, leaving the rest for the reads queries wait on.
const WRITE_WORKERS: usize = 8;
/// Holds writes while every worker is busy and drops the overflow. Each write holds a response, so
/// an unbounded queue would grow without limit while the cache lags.
const WRITE_QUEUE: usize = 64;
type WriteJob = Box<dyn FnOnce() + Send + 'static>;
/// Shared by every client.
static WRITE_EXECUTOR: OnceLock<mpsc::SyncSender<WriteJob>> = OnceLock::new();

/// Started on first use.
fn write_executor() -> &'static mpsc::SyncSender<WriteJob> {
    WRITE_EXECUTOR.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<WriteJob>(WRITE_QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..WRITE_WORKERS {
            let rx = rx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("onetdns-cachedb-write-{index}"))
                .spawn(move || loop {
                    let job = rx.lock_recover().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
            {
                onetdns_core::warn!(event = "cachedb.write_worker_start_failed", %error, index, "Could not start a shared cache write thread; answers this server resolves may not reach the shared cache");
                break;
            }
        }
        tx
    })
}

enum Connection {
    /// Reply lines are read a byte at a time, so without buffering every byte would be a socket
    /// read. TLS buffers decrypted records already.
    Plain(BufReader<DeadlineTcp>),
    Tls(Box<TlsStream<DeadlineTcp>>),
}

impl Connection {
    fn set_deadline(&mut self, deadline: Instant) {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().set_deadline(deadline),
            Connection::Tls(tls) => tls.inner_mut().set_deadline(deadline),
        }
    }
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(tcp) => tcp.read(buf),
            Connection::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().write(buf),
            Connection::Tls(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Connection::Plain(tcp) => tcp.get_mut().flush(),
            Connection::Tls(tls) => tls.flush(),
        }
    }
}

pub struct RedisTls {
    /// The Redis host from the config.
    pub server_name: String,
    pub roots: TrustStore,
}

/// Sent with AUTH after connecting.
pub struct RedisAuth {
    /// ACL user; None authenticates as the default user.
    pub username: Option<String>,
    pub password: SecretString,
}

pub struct RedisOptions {
    pub addr: SocketAddr,
    /// None connects in plain text.
    pub tls: Option<RedisTls>,
    /// None skips authentication.
    pub auth: Option<RedisAuth>,
}

/// Opens on failure; after the cooldown, only one command probes, and only its success closes it
/// again. If every query tried to connect when the cooldown ended, all of them would pay a dead
/// cache's connect timeout together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Circuit {
    Closed,
    /// Skipped until this instant.
    Open(Instant),
    /// One command is probing; the rest are skipped.
    Probing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    /// Sent while the circuit was closed.
    Normal,
    /// Decides whether the circuit closes.
    Probe,
}

enum Exchange {
    /// Every connection was busy, so nothing was sent; not a cache failure.
    Busy,
    Failed(std::io::Error),
}

/// A place under the connection cap, returned on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// None at the cap.
    fn acquire(open: &Arc<AtomicUsize>) -> Option<Slot> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_CONNECTIONS).then_some(count + 1)
        })
        .ok()?;
        Some(Slot(open.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A connection with its slot; they drop together so the count stays right.
struct Pooled {
    connection: Connection,
    _slot: Slot,
}

pub struct RedisClient {
    addr: SocketAddr,
    /// Built once and shared by every connection, so the trust store is not cloned or reread per
    /// connection. None connects in plain text.
    tls: Option<ClientConfig>,
    auth: Option<RedisAuth>,
    idle: Mutex<Vec<Pooled>>,
    /// Idle and checked-out connections alike.
    open: Arc<AtomicUsize>,
    circuit: Mutex<Circuit>,
    /// Error replies from the server; logged at powers of two.
    rejected: AtomicU64,
    /// Writes dropped on a full queue; logged at powers of two.
    dropped_writes: AtomicU64,
    #[cfg(test)]
    /// Queued writes not yet finished, for tests waiting on them.
    pending_writes: AtomicUsize,
}

/// Applies one command's result to the circuit. If a probe vanished without a result, the circuit
/// would stay probing and never use the shared cache again, so an unsettled outcome counts as a
/// failure.
struct Outcome<'a> {
    client: &'a RedisClient,
    admission: Admission,
    settled: bool,
}

impl Outcome<'_> {
    fn succeeded(mut self) {
        self.settled = true;
        self.client.on_success(self.admission);
    }

    /// No connection was free.
    fn skipped(mut self) {
        self.settled = true;
        self.client.on_skip(self.admission);
    }

    fn failed(mut self, error: &std::io::Error) {
        self.settled = true;
        self.client.on_failure(self.admission, error);
    }
}

impl Drop for Outcome<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.client.on_failure(
                self.admission,
                &std::io::Error::other("The shared cache command did not finish"),
            );
        }
    }
}

impl RedisClient {
    /// Connects on first use.
    pub fn new(options: RedisOptions) -> Self {
        let RedisOptions { addr, tls, auth } = options;
        let tls = tls.map(|tls| ClientConfig {
            server_name: tls.server_name,
            verify_name: true,
            roots: Some(tls.roots),
            insecure_verifier: None,
            alpn: Vec::new(),
            client_cert: None,
            session: None,
            enable_early_data: false,
            send_key_share: true,
        });
        RedisClient {
            addr,
            tls,
            auth,
            idle: Mutex::new(Vec::new()),
            open: Arc::new(AtomicUsize::new(0)),
            circuit: Mutex::new(Circuit::Closed),
            rejected: AtomicU64::new(0),
            dropped_writes: AtomicU64::new(0),
            #[cfg(test)]
            pending_writes: AtomicUsize::new(0),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// None means do not send.
    fn admit(&self) -> Option<Admission> {
        let mut circuit = self.circuit.lock_recover();
        match *circuit {
            Circuit::Closed => Some(Admission::Normal),
            Circuit::Open(until) if Instant::now() < until => None,
            Circuit::Open(_) => {
                *circuit = Circuit::Probing;
                Some(Admission::Probe)
            }
            Circuit::Probing => None,
        }
    }

    /// Only a successful probe closes the circuit.
    fn on_success(&self, admission: Admission) {
        if admission != Admission::Probe {
            return;
        }
        *self.circuit.lock_recover() = Circuit::Closed;
        onetdns_core::info!(event = "cachedb.recovered", addr = %self.addr, "Shared cache is answering again; resumed using it");
    }

    /// A probe that could not be sent leaves probing to the next command.
    fn on_skip(&self, admission: Admission) {
        if admission == Admission::Probe {
            *self.circuit.lock_recover() = Circuit::Open(Instant::now());
        }
    }

    /// Only a command sent while the circuit was closed opens it; a command finishing after it
    /// opened was sent earlier and does not hold off the probe. Opening also drops idle
    /// connections, which are already dead by the time the cache returns.
    fn on_failure(&self, admission: Admission, error: &std::io::Error) {
        let opened = {
            let mut circuit = self.circuit.lock_recover();
            let opened = match (admission, *circuit) {
                (Admission::Probe, _) => false,
                (Admission::Normal, Circuit::Closed) => true,
                (Admission::Normal, _) => return,
            };
            *circuit = Circuit::Open(Instant::now() + FAILURE_COOLDOWN);
            opened
        };
        drop(std::mem::take(&mut *self.idle.lock_recover()));
        if opened {
            self.note_unavailable(error);
        }
    }

    /// Logged only when the circuit opens. Without it, a completely dead shared cache would go
    /// unnoticed, since queries keep being answered.
    fn note_unavailable(&self, error: &std::io::Error) {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            onetdns_core::warn!(event = "cachedb.credentials_rejected", addr = %self.addr, error = %error, cooldown_secs = FAILURE_COOLDOWN.as_secs(), "Shared cache rejected the configured user name or password; skipping it for now. Queries are still answered but the cache is not shared");
        } else {
            onetdns_core::warn!(event = "cachedb.unavailable", addr = %self.addr, error = %error, cooldown_secs = FAILURE_COOLDOWN.as_secs(), "Cannot reach the shared cache; skipping it for now. Queries are still answered but the cache is not shared");
        }
    }

    /// Includes TLS and authentication.
    fn connect(&self, deadline: Instant) -> std::io::Result<Connection> {
        let mut tcp = DeadlineTcp::connect(self.addr, deadline)?;
        // A command is one small write followed by a wait for the reply, so Nagle delay would
        // become query delay.
        let _ = tcp.get_ref().set_nodelay(true);
        let mut connection = match &self.tls {
            None => Connection::Plain(BufReader::new(tcp)),
            Some(config) => {
                let session = client_handshake(&mut tcp, config).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("TLS handshake with the shared cache failed: {error}"),
                    )
                })?;
                Connection::Tls(Box::new(TlsStream::new(session, tcp)))
            }
        };
        if let Some(auth) = &self.auth {
            authenticate(&mut connection, auth)?;
        }
        Ok(connection)
    }

    /// `fresh` skips idle connections and connects anew. Returns the connection and whether it was
    /// idle.
    fn checkout(&self, deadline: Instant, fresh: bool) -> Result<(Pooled, bool), Exchange> {
        if !fresh {
            if let Some(pooled) = self.idle.lock_recover().pop() {
                return Ok((pooled, true));
            }
        }
        let slot = Slot::acquire(&self.open).ok_or(Exchange::Busy)?;
        let connection = self.connect(deadline).map_err(Exchange::Failed)?;
        Ok((
            Pooled {
                connection,
                _slot: slot,
            },
            false,
        ))
    }

    /// When an idle connection fails, the command is sent once more on a new one: after the cache
    /// restarts, or when the peer closed it while idle, the idle connection is already dead. All
    /// three commands are safe to resend.
    ///
    /// A failed connection is never returned to the pool: reusing an out-of-step connection would
    /// read the previous command's reply as the next one's.
    fn exchange(&self, args: &[&[u8]]) -> Result<RespValue, Exchange> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let (mut pooled, reused) = self.checkout(deadline, false)?;
        match roundtrip(&mut pooled.connection, args, deadline) {
            Ok(value) => {
                self.idle.lock_recover().push(pooled);
                return Ok(value);
            }
            Err(error) if !reused => return Err(Exchange::Failed(error)),
            Err(_) => drop(pooled),
        }
        let (mut pooled, _) = self.checkout(deadline, true)?;
        let value = roundtrip(&mut pooled.connection, args, deadline).map_err(Exchange::Failed)?;
        self.idle.lock_recover().push(pooled);
        Ok(value)
    }

    /// None when not sent or failed.
    fn command(&self, args: &[&[u8]]) -> Option<RespValue> {
        let outcome = Outcome {
            client: self,
            admission: self.admit()?,
            settled: false,
        };
        match self.exchange(args) {
            Ok(value) => {
                outcome.succeeded();
                Some(value)
            }
            Err(Exchange::Busy) => {
                outcome.skipped();
                None
            }
            Err(Exchange::Failed(error)) => {
                outcome.failed(&error);
                None
            }
        }
    }

    /// Logs error replies. Connecting and the round trip succeeded, so the circuit stays closed;
    /// this is the only place a cache stuck doing nothing, out of memory for example, shows up.
    fn note_reply(&self, command: &str, value: &RespValue) {
        let RespValue::Error(message) = value else {
            return;
        };
        let count = self.rejected.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.command_rejected", addr = %self.addr, command = command, count = count, reply = %message, "Shared cache server rejected a command; the cache is not being shared");
        }
    }

    /// A failure reads as absent.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let value = self.command(&[b"GET", key])?;
        self.note_reply("GET", &value);
        match value {
            RespValue::Bulk(b) => Some(b),
            _ => None,
        }
    }

    /// Queued; the reply is not awaited and failures are ignored.
    pub fn setex(self: &Arc<Self>, key: Vec<u8>, secs: u64, value: Vec<u8>) {
        let secs = secs.max(1).to_string().into_bytes();
        self.write_later("SETEX", vec![b"SETEX".to_vec(), key, secs, value]);
    }

    /// Queued; the reply is not awaited and failures are ignored.
    pub fn del(self: &Arc<Self>, key: Vec<u8>) {
        self.write_later("DEL", vec![b"DEL".to_vec(), key]);
    }

    /// Query answers never depend on a store or delete, so queries have no reason to wait on the
    /// round trip. Dropped when the queue is full.
    ///
    /// Workers send queued writes in parallel, so they finish out of order: a query must queue at
    /// most one write per key, since a delete queued with a store could remove the newly stored
    /// value.
    fn write_later(self: &Arc<Self>, name: &'static str, args: Vec<Vec<u8>>) {
        #[cfg(test)]
        self.pending_writes.fetch_add(1, Ordering::AcqRel);
        let client = Arc::clone(self);
        let job: WriteJob = Box::new(move || {
            let args: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
            if let Some(value) = client.command(&args) {
                client.note_reply(name, &value);
            }
            #[cfg(test)]
            client.pending_writes.fetch_sub(1, Ordering::AcqRel);
        });
        if write_executor().try_send(job).is_err() {
            #[cfg(test)]
            self.pending_writes.fetch_sub(1, Ordering::AcqRel);
            self.note_write_dropped();
        }
    }

    /// Writes pile up faster than the shared cache takes them; answers still go out but are not
    /// shared with other servers.
    fn note_write_dropped(&self) {
        let count = self.dropped_writes.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            onetdns_core::warn!(event = "cachedb.write_dropped", addr = %self.addr, count = count, "Shared cache write queue is full, so an answer was not shared; the shared cache accepts writes more slowly than this server produces them");
        }
    }

    #[cfg(test)]
    pub(crate) fn wait_for_writes(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.pending_writes.load(Ordering::Acquire) > 0 {
            assert!(
                Instant::now() < deadline,
                "shared cache writes did not finish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Fails with PermissionDenied when the server answers with an error.
fn authenticate(connection: &mut Connection, auth: &RedisAuth) -> std::io::Result<()> {
    let password = auth.password.as_bytes();
    let reply = match &auth.username {
        Some(username) => write_and_read(connection, &[b"AUTH", username.as_bytes(), password]),
        None => write_and_read(connection, &[b"AUTH", password]),
    }?;
    match reply {
        RespValue::Simple(_) => Ok(()),
        RespValue::Error(message) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("The shared cache rejected the credentials: {message}"),
        )),
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

enum RespValue {
    Simple(#[allow(dead_code)] String),
    Bulk(Vec<u8>),
    Nil,
    Int(#[allow(dead_code)] i64),
    Error(String),
}

/// `deadline` is for the whole command; the round trip itself is cut earlier at
/// `ROUNDTRIP_TIMEOUT`.
fn roundtrip(
    connection: &mut Connection,
    args: &[&[u8]],
    deadline: Instant,
) -> std::io::Result<RespValue> {
    connection.set_deadline(deadline.min(Instant::now() + ROUNDTRIP_TIMEOUT));
    write_and_read(connection, args)
}

/// The request buffer is wiped after writing, since AUTH carries the password. It is sized to the
/// full length up front: a growing buffer would leave unwiped earlier copies behind.
fn write_and_read<S: Read + Write>(stream: &mut S, args: &[&[u8]]) -> std::io::Result<RespValue> {
    let capacity = 32 + args.iter().map(|a| a.len() + 32).sum::<usize>();
    let mut req = Zeroizing::new(Vec::with_capacity(capacity));
    req.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        req.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        req.extend_from_slice(a);
        req.extend_from_slice(b"\r\n");
    }
    stream.write_all(&req)?;
    stream.flush()?;
    read_reply(stream)
}

/// With a length cap.
fn read_line<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if stream.read(&mut b)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if b[0] == b'\r' {
            stream.read_exact(&mut b)?;
            if b[0] != b'\n' {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            break;
        }
        out.push(b[0]);
        if out.len() > MAX_RESP_LINE {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
    Ok(out)
}

/// Array replies must be consumed to the end; stopping midway would leave bytes read as the next
/// command's reply.
fn read_reply<R: Read>(stream: &mut R) -> std::io::Result<RespValue> {
    let line = read_line(stream)?;
    if line.is_empty() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let rest = &line[1..];
    match line[0] {
        b'+' => Ok(RespValue::Simple(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        b'-' => Ok(RespValue::Error(String::from_utf8_lossy(rest).into_owned())),
        b':' => Ok(RespValue::Int(parse_i64(rest)?)),
        b'$' => {
            let len = parse_i64(rest)?;
            if len == -1 {
                return Ok(RespValue::Nil);
            }
            if len < 0 {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let len = usize::try_from(len).map_err(|_| std::io::ErrorKind::InvalidData)?;
            if len > MAX_BULK_REPLY {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf)?;
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            Ok(RespValue::Bulk(buf))
        }
        b'*' => {
            let count = parse_i64(rest)?;
            if count == -1 {
                Ok(RespValue::Nil)
            } else {
                Err(std::io::ErrorKind::InvalidData.into())
            }
        }
        _ => Err(std::io::ErrorKind::InvalidData.into()),
    }
}

fn parse_i64(b: &[u8]) -> std::io::Result<i64> {
    std::str::from_utf8(b)
        .map_err(|_| std::io::ErrorKind::InvalidData)?
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
/// Fake Redis for tests, handling only GET, SETEX, DEL, and AUTH.
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use onetdns_core::MutexExt;

    #[derive(Clone, Default)]
    pub(crate) struct Behavior {
        /// Before every reply.
        pub(crate) delay: Duration,
        /// Username and password AUTH must carry; None accepts without authentication.
        pub(crate) credentials: Option<(Option<String>, String)>,
        pub(crate) tls: Option<Arc<onetdns_tls::ServerConfig>>,
        /// Close the connection after one reply.
        pub(crate) close_after_reply: bool,
        /// Data commands get no reply until this turns true.
        pub(crate) hold: Option<Arc<AtomicBool>>,
    }

    /// Stops accepting when dropped.
    pub(crate) struct FakeRedis {
        pub(crate) addr: SocketAddr,
        /// Tests read and write it directly.
        pub(crate) store: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        pub(crate) connections: Arc<AtomicUsize>,
        /// Data commands handled; AUTH is not counted.
        pub(crate) commands: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl FakeRedis {
        pub(crate) fn start(behavior: Behavior) -> FakeRedis {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let store = Arc::new(Mutex::new(HashMap::new()));
            let connections = Arc::new(AtomicUsize::new(0));
            let commands = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            {
                let store = store.clone();
                let connections = connections.clone();
                let commands = commands.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        let Ok(stream) = stream else {
                            continue;
                        };
                        connections.fetch_add(1, Ordering::AcqRel);
                        let store = store.clone();
                        let commands = commands.clone();
                        let behavior = behavior.clone();
                        std::thread::spawn(move || serve(stream, &store, &commands, &behavior));
                    }
                });
            }
            FakeRedis {
                addr,
                store,
                connections,
                commands,
                stop,
            }
        }

        pub(crate) fn value(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.store.lock_recover().get(key).cloned()
        }

        pub(crate) fn keys(&self) -> Vec<Vec<u8>> {
            self.store.lock_recover().keys().cloned().collect()
        }

        /// What anyone able to write to Redis can do.
        pub(crate) fn insert(&self, key: Vec<u8>, value: Vec<u8>) {
            self.store.lock_recover().insert(key, value);
        }
    }

    impl Drop for FakeRedis {
        /// Connects once to wake the blocked accept.
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.addr);
        }
    }

    fn serve(
        mut stream: TcpStream,
        store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        commands: &AtomicUsize,
        behavior: &Behavior,
    ) {
        match &behavior.tls {
            None => handle(&mut stream, store, commands, behavior),
            Some(config) => {
                let Ok(session) = onetdns_tls::server_handshake(&mut stream, config) else {
                    return;
                };
                let mut tls = onetdns_tls::TlsStream::new(session, stream);
                handle(&mut tls, store, commands, behavior);
            }
        }
    }

    fn handle<S: Read + Write>(
        stream: &mut S,
        store: &Mutex<HashMap<Vec<u8>, Vec<u8>>>,
        commands: &AtomicUsize,
        behavior: &Behavior,
    ) {
        let mut authenticated = behavior.credentials.is_none();
        while let Some(args) = read_command(stream) {
            std::thread::sleep(behavior.delay);
            let name = args[0].to_ascii_uppercase();
            if let Some(release) = behavior.hold.as_ref().filter(|_| name != b"AUTH") {
                while !release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            let reply = if name == b"AUTH" {
                let (username, password) = match args.as_slice() {
                    [_, password] => (None, password.clone()),
                    [_, username, password] => (Some(username.clone()), password.clone()),
                    _ => (None, Vec::new()),
                };
                let accepted = behavior.credentials.as_ref().is_some_and(|(user, pass)| {
                    user.as_ref().map(|user| user.as_bytes().to_vec()) == username
                        && pass.as_bytes() == password.as_slice()
                });
                authenticated |= accepted;
                if accepted {
                    b"+OK\r\n".to_vec()
                } else {
                    b"-WRONGPASS invalid username-password pair\r\n".to_vec()
                }
            } else if !authenticated {
                b"-NOAUTH Authentication required.\r\n".to_vec()
            } else {
                commands.fetch_add(1, Ordering::AcqRel);
                match (name.as_slice(), args.as_slice()) {
                    (b"GET", [_, key]) => match store.lock_recover().get(key) {
                        Some(value) => {
                            let mut reply = format!("${}\r\n", value.len()).into_bytes();
                            reply.extend_from_slice(value);
                            reply.extend_from_slice(b"\r\n");
                            reply
                        }
                        None => b"$-1\r\n".to_vec(),
                    },
                    (b"SETEX", [_, key, _, value]) => {
                        store.lock_recover().insert(key.clone(), value.clone());
                        b"+OK\r\n".to_vec()
                    }
                    (b"DEL", [_, key]) => {
                        let removed = store.lock_recover().remove(key).is_some();
                        format!(":{}\r\n", u8::from(removed)).into_bytes()
                    }
                    _ => b"-ERR unknown command\r\n".to_vec(),
                }
            };
            if stream.write_all(&reply).is_err() || behavior.close_after_reply {
                return;
            }
        }
    }

    fn read_line<S: Read>(stream: &mut S) -> Option<Vec<u8>> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).ok()?;
            if byte[0] == b'\n' && line.last() == Some(&b'\r') {
                line.pop();
                return Some(line);
            }
            line.push(byte[0]);
        }
    }

    fn read_command<S: Read>(stream: &mut S) -> Option<Vec<Vec<u8>>> {
        let header = read_line(stream)?;
        let count: usize = std::str::from_utf8(header.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            let length = read_line(stream)?;
            let length: usize = std::str::from_utf8(length.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            let mut value = vec![0u8; length + 2];
            stream.read_exact(&mut value).ok()?;
            value.truncate(length);
            args.push(value);
        }
        (!args.is_empty()).then_some(args)
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{Behavior, FakeRedis};
    use super::*;
    use std::net::TcpListener;

    fn plain_client(addr: SocketAddr) -> Arc<RedisClient> {
        Arc::new(RedisClient::new(RedisOptions {
            addr,
            tls: None,
            auth: None,
        }))
    }

    #[test]
    fn connection_failure_opens_fast_fail_circuit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = plain_client(addr);

        assert!(client.get(b"missing").is_none());
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));

        let started = Instant::now();
        assert!(client.get(b"missing-again").is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    /// Sharing one connection under a lock would make each command wait for the previous round
    /// trip, and since that is not a failure, the circuit would not open and every query would pay
    /// the delay. Commands prefer idle connections, so had they waited for each other, the fake
    /// would accept only one connection.
    ///
    /// Not judged by elapsed time or circuit state: a brief stall of the test machine could push
    /// concurrent commands past the round-trip deadline, open the circuit, and stretch the time.
    fn slow_cache_does_not_serialize_concurrent_commands() {
        let fake = FakeRedis::start(Behavior {
            delay: ROUNDTRIP_TIMEOUT / 4,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let client = client.clone();
                std::thread::spawn(move || client.get(format!("key-{index}").as_bytes()))
            })
            .collect();
        for worker in workers {
            assert!(worker.join().unwrap().is_none());
        }
        let connections = fake.connections.load(Ordering::Acquire);
        assert!(
            connections > 1,
            "commands waited for each other: the cache accepted {connections} connection(s)"
        );
    }

    #[test]
    /// Skips without waiting and does not count it as a failure. Holding slots up to the cap mimics
    /// other commands having borrowed every connection.
    fn exhausted_pool_skips_instead_of_waiting() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        let held: Vec<Slot> = (0..MAX_CONNECTIONS)
            .map(|_| Slot::acquire(&client.open).unwrap())
            .collect();
        assert!(Slot::acquire(&client.open).is_none());

        let started = Instant::now();
        assert!(client.get(b"busy").is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.connections.load(Ordering::Acquire), 0);

        drop(held);
        assert_eq!(client.open.load(Ordering::Acquire), 0);
        client.setex(b"busy".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        assert_eq!(client.get(b"busy").as_deref(), Some(b"v".as_slice()));
        assert_eq!(client.open.load(Ordering::Acquire), 1);
    }

    #[test]
    fn idle_connections_are_reused() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        for _ in 0..5 {
            assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
        }
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
    }

    #[test]
    fn closed_idle_connection_is_replaced_without_opening_the_circuit() {
        let fake = FakeRedis::start(Behavior {
            close_after_reply: true,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.connections.load(Ordering::Acquire), 2);
    }

    #[test]
    /// Slowness within the command deadline alone would not count as failure, so the circuit would
    /// not open and every query would wait that long.
    fn slow_replies_open_the_circuit() {
        let fake = FakeRedis::start(Behavior {
            delay: ROUNDTRIP_TIMEOUT * 5,
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        let started = Instant::now();
        assert!(client.get(b"k").is_none());
        let waited = started.elapsed();
        assert!(
            waited < ROUNDTRIP_TIMEOUT * 3,
            "the lookup waited for the slow reply: {waited:?}"
        );
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));

        let started = Instant::now();
        assert!(client.get(b"k").is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    /// The fake holds replies until the test releases them; a write waiting on the reply would hit
    /// its deadline first, fail, and store nothing.
    fn writes_do_not_wait_for_the_reply() {
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fake = FakeRedis::start(Behavior {
            hold: Some(release.clone()),
            ..Behavior::default()
        });
        let client = plain_client(fake.addr);
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.del(b"gone".to_vec());
        release.store(true, Ordering::Release);
        client.wait_for_writes();
        assert_eq!(fake.value(b"k").as_deref(), Some(b"v".as_slice()));
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(fake.commands.load(Ordering::Acquire), 2);
    }

    #[test]
    /// A probe vanishing without a result opens the circuit as a failure; otherwise it would stay
    /// probing and never use the shared cache again.
    fn only_one_command_probes_and_only_it_closes_the_circuit() {
        let client = plain_client(SocketAddr::from(([127, 0, 0, 1], 1)));
        *client.circuit.lock_recover() = Circuit::Open(Instant::now());

        assert_eq!(client.admit(), Some(Admission::Probe));
        assert_eq!(client.admit(), None, "a second command must not probe too");

        drop(Outcome {
            client: &client,
            admission: Admission::Probe,
            settled: false,
        });
        assert!(
            matches!(*client.circuit.lock_recover(), Circuit::Open(until) if until > Instant::now())
        );

        *client.circuit.lock_recover() = Circuit::Open(Instant::now());
        assert_eq!(client.admit(), Some(Admission::Probe));
        client.on_success(Admission::Normal);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Probing);
        client.on_success(Admission::Probe);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        assert_eq!(client.admit(), Some(Admission::Normal));
    }

    #[test]
    fn late_failure_of_an_earlier_command_leaves_the_open_circuit_alone() {
        let client = plain_client(SocketAddr::from(([127, 0, 0, 1], 1)));
        let error = std::io::Error::from(std::io::ErrorKind::TimedOut);
        client.on_failure(Admission::Normal, &error);
        let Circuit::Open(first) = *client.circuit.lock_recover() else {
            panic!("the first failure must open the circuit");
        };
        std::thread::sleep(Duration::from_millis(20));
        client.on_failure(Admission::Normal, &error);
        assert_eq!(*client.circuit.lock_recover(), Circuit::Open(first));
    }

    #[test]
    /// Without a username, it authenticates as the default user.
    fn every_new_connection_authenticates() {
        for username in [Some("dns".to_string()), None] {
            let fake = FakeRedis::start(Behavior {
                credentials: Some((username.clone(), "correct-password".into())),
                ..Behavior::default()
            });
            let client = Arc::new(RedisClient::new(RedisOptions {
                addr: fake.addr,
                tls: None,
                auth: Some(RedisAuth {
                    username,
                    password: "correct-password".into(),
                }),
            }));
            client.setex(b"k".to_vec(), 60, b"v".to_vec());
            client.wait_for_writes();
            assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));
            assert_eq!(*client.circuit.lock_recover(), Circuit::Closed);
        }
    }

    #[test]
    fn rejected_credentials_open_the_circuit_before_any_command() {
        let fake = FakeRedis::start(Behavior {
            credentials: Some((Some("dns".into()), "correct-password".into())),
            ..Behavior::default()
        });
        fake.insert(b"k".to_vec(), b"v".to_vec());
        let client = RedisClient::new(RedisOptions {
            addr: fake.addr,
            tls: None,
            auth: Some(RedisAuth {
                username: Some("dns".into()),
                password: "wrong-password".into(),
            }),
        });
        assert!(client.get(b"k").is_none());
        assert!(matches!(*client.circuit.lock_recover(), Circuit::Open(_)));
        assert_eq!(fake.commands.load(Ordering::Acquire), 0);
    }

    #[test]
    fn tls_connection_checks_the_certificate_name() {
        let (certs, key) = onetdns_transport::self_signed_material("redis.test").unwrap();
        let roots = TrustStore::from_ders([certs[0].as_slice()]);
        let server =
            Arc::new(onetdns_tls::ServerConfig::from_pkcs8(certs[0].clone(), &key).unwrap());
        let fake = FakeRedis::start(Behavior {
            tls: Some(server),
            ..Behavior::default()
        });
        let tls_client = |server_name: &str| {
            Arc::new(RedisClient::new(RedisOptions {
                addr: fake.addr,
                tls: Some(RedisTls {
                    server_name: server_name.to_string(),
                    roots: roots.clone(),
                }),
                auth: None,
            }))
        };

        let client = tls_client("redis.test");
        client.setex(b"k".to_vec(), 60, b"v".to_vec());
        client.wait_for_writes();
        assert_eq!(client.get(b"k").as_deref(), Some(b"v".as_slice()));

        let impostor = tls_client("other.test");
        assert!(impostor.get(b"k").is_none());
        assert!(matches!(*impostor.circuit.lock_recover(), Circuit::Open(_)));
    }

    #[test]
    /// A large value is read partly from the buffer and the rest straight from the socket; losing
    /// or rereading bytes at that boundary would make the next command read the previous reply.
    fn large_reply_keeps_the_pooled_connection_in_step() {
        let fake = FakeRedis::start(Behavior::default());
        let client = plain_client(fake.addr);
        let large: Vec<u8> = (0..=u8::MAX).cycle().take(MAX_BULK_REPLY).collect();
        fake.insert(b"large".to_vec(), large.clone());
        fake.insert(b"small".to_vec(), b"v".to_vec());
        for _ in 0..3 {
            assert_eq!(client.get(b"large").as_deref(), Some(large.as_slice()));
            assert_eq!(client.get(b"small").as_deref(), Some(b"v".as_slice()));
            assert!(client.get(b"missing").is_none());
        }
        assert_eq!(fake.connections.load(Ordering::Acquire), 1);
    }

    #[test]
    fn resp_numeric_fields_are_strict_and_arrays_cannot_desync_connection() {
        assert!(parse_i64(b"12").is_ok());
        assert!(parse_i64(b"").is_err());
        assert!(parse_i64(b"12x").is_err());

        let read = |reply: &[u8]| read_reply(&mut &reply[..]);
        assert!(read(b"$wat\r\n").is_err());
        assert!(read(b"$-2\r\n").is_err());
        assert!(read(b"*1\r\n$3\r\nfoo\r\n").is_err());
        assert!(matches!(read(b"$-1\r\n"), Ok(RespValue::Nil)));
        assert!(matches!(read(b"$3\r\nfoo\r\n"), Ok(RespValue::Bulk(value)) if value == b"foo"));
    }

    #[test]
    fn resp_reader_survives_mutated_replies() {
        use crate::fuzzutil::{havoc, Rng};
        let seeds: [&[u8]; 5] = [
            b"+OK\r\n",
            b"-ERR wrong\r\n",
            b":42\r\n",
            b"$5\r\nhello\r\n",
            b"*-1\r\n",
        ];
        let mut rng = Rng::new(0x5245_4449_535f_5245);
        for round in 0..20_000 {
            let input = if round % 3 == 0 {
                rng.rand_bytes(64)
            } else {
                havoc(&mut rng, seeds[round % seeds.len()])
            };
            let _ = read_reply(&mut input.as_slice());
        }
    }
}
