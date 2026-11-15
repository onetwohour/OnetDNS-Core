//! Raft RPC transport over authenticated, encrypted frames. Each frame is sealed with
//! XChaCha20-Poly1305 with the sender ID in the AAD, so no node can impersonate another, and leader
//! and candidate fields in a message are checked against the authenticated sender.
//!
//! The cluster secret is the whole of the authentication: whoever has it can join the cluster and
//! inject configuration through replication.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use onetdns_core::tcp::DeadlineTcp;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::raft::{
    LogEntry, Msg, NodeId, Output, RaftNode, MAX_APPEND_BYTES, MAX_APPEND_ENTRIES, MAX_ENTRY_BYTES,
    SNAPSHOT_CHUNK_BYTES,
};

/// Holds the session ID and the sequence number.
const RAFT_NONCE_LEN: usize = 24;

const RAFT_AEAD_TAG_LEN: usize = 16;

const RAFT_SIG_LEN: usize = 64;

/// Snapshot chunks fit inside it too.
const MAX_RAFT_FRAME: usize = 1024 * 1024;

const MAX_RAFT_CONNECTIONS: usize = 64;

/// So one node cannot take every slot.
const MAX_RAFT_CONNS_PER_IP: usize = 8;

const MAX_RAFT_ENTRIES: usize = 4096;

const MAX_RAFT_ENTRY_BYTES: usize = 256 * 1024;

/// When full, the oldest messages are dropped: only the latest heartbeat matters.
const PEER_QUEUE: usize = 256;

const PROPOSAL_QUEUE: usize = 64;

/// Short enough not to add latency; proposals arriving within it share one fsync.
const PROPOSAL_BATCH_WINDOW: Duration = Duration::from_millis(2);

/// Term (8), index (8) and length (4).
const LOG_ENTRY_WIRE_OVERHEAD: usize = 8 + 8 + 4;

const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(5);

const RAFT_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Bump when the header or sealed body layout changes. Frames with another number are dropped
/// before authentication, so nodes on different numbers cannot even see each other's product
/// version.
const RAFT_FRAME_VERSION: u8 = 2;

/// The length is one byte, so it cannot exceed 255.
const MAX_PRODUCT_VERSION_LEN: usize = 64;

/// Frames reordered within this many sequence numbers are still accepted; without a window, network
/// reordering alone would drop good frames.
const REPLAY_WINDOW_BITS: u64 = 128;

static REPLAY_REJECTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A new session (the peer restarted) opens a fresh window; within a session the sequence number
/// and bitmap filter out frames already seen.
#[derive(Debug, Clone, Copy)]
struct PeerReplayWindow {
    session: [u8; 16],
    highest_sequence: u64,
    seen_bitmap: u128,
}

#[derive(Default)]
struct ReplayCache {
    peers: HashMap<NodeId, PeerReplayWindow>,
}

impl ReplayCache {
    /// Allowing a replay would let an old AppendEntries be pushed again and roll back committed
    /// entries, so anything older than the window or already seen is rejected.
    fn accept(&mut self, sender: NodeId, nonce: [u8; RAFT_NONCE_LEN]) -> bool {
        let mut session = [0u8; 16];
        session.copy_from_slice(&nonce[..16]);
        let sequence = u64::from_be_bytes(nonce[16..].try_into().expect("Fixed nonce length"));

        let Some(window) = self.peers.get_mut(&sender) else {
            self.peers.insert(
                sender,
                PeerReplayWindow {
                    session,
                    highest_sequence: sequence,
                    seen_bitmap: 1,
                },
            );
            return true;
        };

        if session > window.session {
            *window = PeerReplayWindow {
                session,
                highest_sequence: sequence,
                seen_bitmap: 1,
            };
            return true;
        }
        if session < window.session {
            return false;
        }

        if sequence > window.highest_sequence {
            let shift = sequence - window.highest_sequence;
            window.seen_bitmap = if shift >= REPLAY_WINDOW_BITS {
                1
            } else {
                (window.seen_bitmap << shift) | 1
            };
            window.highest_sequence = sequence;
            return true;
        }

        let distance = window.highest_sequence - sequence;
        if distance >= REPLAY_WINDOW_BITS {
            return false;
        }
        let bit = 1u128 << distance;
        if window.seen_bitmap & bit != 0 {
            return false;
        }
        window.seen_bitmap |= bit;
        true
    }
}

type RuntimeThreads = Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>;

fn track_thread(threads: &RuntimeThreads, thread: std::thread::JoinHandle<()>) {
    let mut guard = lock(threads);

    guard.retain(|handle| !handle.is_finished());
    guard.push(thread);
}

/// Must finish on reload: a thread left behind keeps the next generation from opening the same
/// port.
fn join_threads(threads: &RuntimeThreads) {
    loop {
        let batch = {
            let mut threads = lock(threads);
            std::mem::take(&mut *threads)
        };
        if batch.is_empty() {
            break;
        }
        for thread in batch {
            let _ = thread.join();
        }
    }
}

/// Cleans up threads already started when startup fails. Call `disarm` on success, or cleanup runs
/// after a good start too.
struct RuntimeStartupGuard {
    shutdown: Arc<AtomicBool>,
    threads: RuntimeThreads,
    armed: bool,
}

impl RuntimeStartupGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RuntimeStartupGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shutdown.store(true, Ordering::Relaxed);
            join_threads(&self.threads);
        }
    }
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn get_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u64::from_be_bytes(slice.try_into().ok()?))
}

fn get_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

/// Empty when the message cannot be represented.
pub fn encode_msg(message: &Msg) -> Vec<u8> {
    try_encode_msg(message).unwrap_or_default()
}

/// `None` over the size limits.
fn try_encode_msg(message: &Msg) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match message {
        Msg::RequestVote {
            term,
            candidate,
            last_log_index,
            last_log_term,
        } => {
            out.push(1);
            put_u64(&mut out, *term);
            put_u64(&mut out, *candidate);
            put_u64(&mut out, *last_log_index);
            put_u64(&mut out, *last_log_term);
        }
        Msg::RequestVoteResp { term, granted } => {
            out.push(2);
            put_u64(&mut out, *term);
            out.push(u8::from(*granted));
        }
        Msg::AppendEntries {
            term,
            leader,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit,
        } => {
            if entries.len() > MAX_RAFT_ENTRIES {
                return None;
            }
            out.push(3);
            put_u64(&mut out, *term);
            put_u64(&mut out, *leader);
            put_u64(&mut out, *prev_log_index);
            put_u64(&mut out, *prev_log_term);
            put_u64(&mut out, *leader_commit);
            out.extend_from_slice(&u32::try_from(entries.len()).ok()?.to_be_bytes());
            for entry in entries {
                if entry.data.len() > MAX_RAFT_ENTRY_BYTES {
                    return None;
                }
                put_u64(&mut out, entry.term);
                put_u64(&mut out, entry.index);
                out.extend_from_slice(&u32::try_from(entry.data.len()).ok()?.to_be_bytes());
                out.extend_from_slice(&entry.data);
                if out.len() > MAX_RAFT_FRAME.saturating_sub(64) {
                    return None;
                }
            }
        }
        Msg::AppendEntriesResp {
            term,
            success,
            match_index,
        } => {
            out.push(4);
            put_u64(&mut out, *term);
            out.push(u8::from(*success));
            put_u64(&mut out, *match_index);
        }
        Msg::InstallSnapshot {
            term,
            leader,
            last_included_index,
            last_included_term,
            offset,
            data,
            done,
        } => {
            if data.len() > SNAPSHOT_CHUNK_BYTES {
                return None;
            }
            out.push(5);
            put_u64(&mut out, *term);
            put_u64(&mut out, *leader);
            put_u64(&mut out, *last_included_index);
            put_u64(&mut out, *last_included_term);
            put_u64(&mut out, *offset);
            out.push(u8::from(*done));
            out.extend_from_slice(&u32::try_from(data.len()).ok()?.to_be_bytes());
            out.extend_from_slice(data);
        }
        Msg::InstallSnapshotResp {
            term,
            last_included_index,
            next_offset,
            installed,
        } => {
            out.push(6);
            put_u64(&mut out, *term);
            put_u64(&mut out, *last_included_index);
            put_u64(&mut out, *next_offset);
            out.push(u8::from(*installed));
        }
    }
    Some(out)
}

/// The bytes come from an authenticated frame but are still untrusted: a node holding the cluster
/// secret may be faulty or compromised. Every count and size limit is checked and trailing bytes
/// are rejected.
pub fn decode_msg(bytes: &[u8]) -> Option<Msg> {
    if bytes.len() > MAX_RAFT_FRAME {
        return None;
    }
    let tag = *bytes.first()?;
    let mut pos = 1usize;
    let message = match tag {
        1 => Msg::RequestVote {
            term: get_u64(bytes, &mut pos)?,
            candidate: get_u64(bytes, &mut pos)?,
            last_log_index: get_u64(bytes, &mut pos)?,
            last_log_term: get_u64(bytes, &mut pos)?,
        },
        2 => {
            let term = get_u64(bytes, &mut pos)?;
            let raw = *bytes.get(pos)?;
            pos += 1;
            let granted = match raw {
                0 => false,
                1 => true,
                _ => return None,
            };
            Msg::RequestVoteResp { term, granted }
        }
        3 => {
            let term = get_u64(bytes, &mut pos)?;
            let leader = get_u64(bytes, &mut pos)?;
            let prev_log_index = get_u64(bytes, &mut pos)?;
            let prev_log_term = get_u64(bytes, &mut pos)?;
            let leader_commit = get_u64(bytes, &mut pos)?;
            let count = get_u32(bytes, &mut pos)? as usize;
            if count > MAX_RAFT_ENTRIES || count > bytes.len().saturating_sub(pos) / 20 {
                return None;
            }
            let mut entries = Vec::with_capacity(count.min(256));
            let mut expected = prev_log_index.checked_add(1)?;
            for _ in 0..count {
                let entry_term = get_u64(bytes, &mut pos)?;
                let index = get_u64(bytes, &mut pos)?;
                let len = get_u32(bytes, &mut pos)? as usize;
                if len > MAX_RAFT_ENTRY_BYTES || index != expected {
                    return None;
                }
                expected = expected.checked_add(1)?;
                let end = pos.checked_add(len)?;
                let data = bytes.get(pos..end)?.to_vec();
                pos = end;
                entries.push(LogEntry {
                    term: entry_term,
                    index,
                    data,
                });
            }
            Msg::AppendEntries {
                term,
                leader,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            }
        }
        4 => {
            let term = get_u64(bytes, &mut pos)?;
            let raw = *bytes.get(pos)?;
            pos += 1;
            let success = match raw {
                0 => false,
                1 => true,
                _ => return None,
            };
            Msg::AppendEntriesResp {
                term,
                success,
                match_index: get_u64(bytes, &mut pos)?,
            }
        }
        5 => {
            let term = get_u64(bytes, &mut pos)?;
            let leader = get_u64(bytes, &mut pos)?;
            let last_included_index = get_u64(bytes, &mut pos)?;
            let last_included_term = get_u64(bytes, &mut pos)?;
            let offset = get_u64(bytes, &mut pos)?;
            let raw_done = *bytes.get(pos)?;
            pos += 1;
            let done = match raw_done {
                0 => false,
                1 => true,
                _ => return None,
            };
            let len = get_u32(bytes, &mut pos)? as usize;
            if len > SNAPSHOT_CHUNK_BYTES {
                return None;
            }
            let end = pos.checked_add(len)?;
            let data = bytes.get(pos..end)?.to_vec();
            pos = end;
            Msg::InstallSnapshot {
                term,
                leader,
                last_included_index,
                last_included_term,
                offset,
                data,
                done,
            }
        }
        6 => {
            let term = get_u64(bytes, &mut pos)?;
            let last_included_index = get_u64(bytes, &mut pos)?;
            let next_offset = get_u64(bytes, &mut pos)?;
            let raw_installed = *bytes.get(pos)?;
            pos += 1;
            let installed = match raw_installed {
                0 => false,
                1 => true,
                _ => return None,
            };
            Msg::InstallSnapshotResp {
                term,
                last_included_index,
                next_offset,
                installed,
            }
        }
        _ => return None,
    };
    (pos == bytes.len()).then_some(message)
}

#[derive(Clone)]
/// One queue and thread per node: with a single one, a slow node would also hold up heartbeats to
/// the others.
struct Dispatcher {
    senders: Arc<HashMap<NodeId, SyncSender<Msg>>>,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    fn new(
        self_id: NodeId,
        version: &'static str,
        peers: &HashMap<NodeId, String>,
        cipher: Arc<XChaCha20Poly1305>,
        signing_key: Arc<SigningKey>,
        cluster_context: [u8; 32],
        session_prefix: u64,
        shutdown: Arc<AtomicBool>,
        threads: &RuntimeThreads,
    ) -> Result<Self, String> {
        let mut senders = HashMap::new();
        for (&peer_id, address) in peers {
            let socket: SocketAddr = address
                .parse()
                .map_err(|_| format!("Invalid Raft peer address: {peer_id}@{address}"))?;
            let (tx, rx) = mpsc::sync_channel(PEER_QUEUE);
            let cipher = cipher.clone();
            let signing_key = signing_key.clone();
            let shutdown = shutdown.clone();
            let thread = std::thread::Builder::new()
                .name(format!("raft-send-{peer_id}"))
                .spawn(move || {
                    peer_sender(
                        self_id,
                        version,
                        peer_id,
                        socket,
                        cipher,
                        signing_key,
                        cluster_context,
                        session_prefix,
                        &shutdown,
                        rx,
                    )
                })
                .map_err(|error| format!("Could not create the Raft peer sender: {error}"))?;
            track_thread(threads, thread);
            senders.insert(peer_id, tx);
        }
        Ok(Self {
            senders: Arc::new(senders),
        })
    }

    /// A full queue drops the message: Raft already expects lost messages and retries, while
    /// waiting here would block with the state machine lock held.
    fn dispatch(&self, outputs: Vec<Output>) {
        for output in outputs {
            let Some(sender) = self.senders.get(&output.to) else {
                onetdns_core::warn!(
                    event = "raft.unknown_peer",
                    peer = output.to,
                    "Dropped a message addressed to a node not in the configuration"
                );
                continue;
            };
            match sender.try_send(output.msg) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    onetdns_core::error!(
                        event = "raft.sender_gone",
                        peer = output.to,
                        "Sender thread for this node has exited; no more messages can be sent to it"
                    );
                }
            }
        }
    }
}

/// Connections from non-nodes are a misconfiguration or a port scan; either way the operator should
/// know. They can keep coming, so only every power-of-two rejection is logged.
fn reject_raft_connection(ip: IpAddr, reason: &str) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "raft.connection_rejected", peer_ip = %ip, reason = reason, count = count, "Did not accept a connection on the cluster port");
    }
}

#[allow(clippy::too_many_arguments)]
/// Reconnects whenever the connection drops. The nonce carries the session prefix and an increasing
/// sequence number so the peer's replay defence works.
fn peer_sender(
    self_id: NodeId,
    version: &'static str,
    peer_id: NodeId,
    address: SocketAddr,
    cipher: Arc<XChaCha20Poly1305>,
    signing_key: Arc<SigningKey>,
    cluster_context: [u8; 32],
    session_prefix: u64,
    shutdown: &AtomicBool,
    receiver: Receiver<Msg>,
) {
    let Some(sealer) = FrameSealer::new(
        cipher,
        signing_key,
        cluster_context,
        session_prefix,
        version,
    ) else {
        onetdns_core::error!(
            event = "raft.sealer_init_failed",
            peer = peer_id,
            "Could not set up cluster frame sealing; not communicating with this node"
        );
        return;
    };
    let mut stream: Option<TcpStream> = None;
    let mut reachable = true;
    while !shutdown.load(Ordering::Relaxed) {
        let message = match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(message) => message,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let Some(encoded) = try_encode_msg(&message) else {
            onetdns_core::warn!(
                event = "raft.message_too_large",
                peer = peer_id,
                "Cluster message exceeds the size limit and was not sent; replication to this node falls behind"
            );
            continue;
        };
        let Some(framed) = sealer.frame(self_id, peer_id, &encoded) else {
            onetdns_core::warn!(
                event = "raft.frame_seal_failed",
                peer = peer_id,
                bytes = encoded.len(),
                "Could not seal a cluster message; not sent"
            );
            continue;
        };
        let mut delivered = false;
        for _ in 0..2 {
            if stream.is_none() {
                stream = TcpStream::connect_timeout(&address, Duration::from_millis(300)).ok();
                if let Some(conn) = stream.as_mut() {
                    if let Err(error) = conn
                        .set_write_timeout(Some(Duration::from_millis(300)))
                        .and_then(|()| conn.set_read_timeout(Some(Duration::from_secs(5))))
                        .and_then(|()| conn.set_nodelay(true))
                    {
                        onetdns_core::warn!(event = "raft.socket_options_failed", peer = peer_id, %error, "Could not set a timeout on the cluster connection");
                    }
                }
            }
            let Some(conn) = stream.as_mut() else {
                break;
            };
            if conn.write_all(&framed).is_ok() {
                delivered = true;
                break;
            }
            stream = None;
        }
        if !delivered {
            stream = None;
        }
        match (delivered, reachable) {
            (false, true) => {
                reachable = false;
                onetdns_core::warn!(event = "raft.peer_unreachable", peer = peer_id, address = %address, "Cannot reach cluster node; it falls behind in replication");
            }
            (true, false) => {
                reachable = true;
                onetdns_core::info!(event = "raft.peer_reachable", peer = peer_id, address = %address, "Reconnected to cluster node");
            }
            _ => {}
        }
    }
}

/// Frames flow one way and replies come as separate frames, so round-trip time cannot be measured.
/// A frame that passed signature and decryption still proves the node is alive and uses the same
/// cluster key. Frames dropped for a version mismatch passed authentication too and are recorded as
/// well.
struct PeerContact {
    origin: Instant,
    /// Milliseconds since `origin` plus one; 0 means never.
    last: HashMap<NodeId, AtomicU64>,
    versions: HashMap<NodeId, Mutex<Option<String>>>,
}

impl PeerContact {
    fn new(peers: &HashMap<NodeId, String>) -> Self {
        Self {
            origin: Instant::now(),
            last: peers.keys().map(|id| (*id, AtomicU64::new(0))).collect(),
            versions: peers.keys().map(|id| (*id, Mutex::new(None))).collect(),
        }
    }

    /// Returns true when the version differs from the recorded one, including on the first frame.
    fn note_version(&self, from: NodeId, version: &str) -> bool {
        let Some(slot) = self.versions.get(&from) else {
            return false;
        };
        let mut seen = lock(slot);
        if seen.as_deref() == Some(version) {
            return false;
        }
        *seen = Some(version.to_string());
        true
    }

    fn version(&self, peer: NodeId) -> Option<String> {
        lock(self.versions.get(&peer)?).clone()
    }

    fn record(&self, from: NodeId) {
        if let Some(slot) = self.last.get(&from) {
            let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
            slot.store(elapsed.saturating_add(1), Ordering::Relaxed);
        }
    }

    fn since(&self, peer: NodeId) -> Option<Duration> {
        let stamp = self.last.get(&peer)?.load(Ordering::Relaxed);
        let at = Duration::from_millis(stamp.checked_sub(1)?);
        Some(self.origin.elapsed().saturating_sub(at))
    }
}

#[derive(Clone)]
/// The data plane proposes config changes and checks leadership through this.
pub struct RaftHandle {
    node: Arc<Mutex<RaftNode>>,
    peers: Arc<HashMap<NodeId, String>>,
    contact: Arc<PeerContact>,
    /// A frame within this time means the peer is alive. Equal to the longest wait before a
    /// follower starts an election.
    contact_window: Duration,
    self_id: NodeId,
    version: &'static str,
    shutdown: Arc<AtomicBool>,
    progress: Arc<(Mutex<u64>, Condvar)>,
    accepting_proposals: Arc<AtomicBool>,
    proposal_tx: SyncSender<ProposalRequest>,
    pending_proposals: Arc<AtomicUsize>,
    threads: RuntimeThreads,
}

struct ProposalRequest {
    data: Vec<u8>,
    response: mpsc::Sender<Result<(u64, u64), String>>,
}

/// Counts a proposal in flight and releases it on every path, failures included.
struct PendingProposal {
    count: Arc<AtomicUsize>,
    progress: Arc<(Mutex<u64>, Condvar)>,
}

impl Drop for PendingProposal {
    /// The last one wakes the apply thread.
    fn drop(&mut self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            signal_progress(&self.progress);
        }
    }
}

/// Batches proposals that arrive within a short window into one log append: an fsync per proposal
/// would tie throughput to disk latency.
fn run_proposal_worker(
    receiver: Receiver<ProposalRequest>,
    node: Arc<Mutex<RaftNode>>,
    dispatcher: Dispatcher,
    progress: Arc<(Mutex<u64>, Condvar)>,
    shutdown: Arc<AtomicBool>,
) {
    let mut carry = None;
    loop {
        let first = match carry.take() {
            Some(request) => request,
            None => match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(request) => request,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            },
        };
        let mut bytes = LOG_ENTRY_WIRE_OVERHEAD + first.data.len();
        let mut batch = vec![first];
        let batch_deadline = Instant::now() + PROPOSAL_BATCH_WINDOW;

        while batch.len() < MAX_APPEND_ENTRIES {
            let Some(remaining) = batch_deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            match receiver.recv_timeout(remaining) {
                Ok(request) => {
                    let request_bytes = LOG_ENTRY_WIRE_OVERHEAD + request.data.len();
                    if bytes + request_bytes > MAX_APPEND_BYTES {
                        carry = Some(request);
                        break;
                    }
                    bytes += request_bytes;
                    batch.push(request);
                }
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }

        let data = batch
            .iter_mut()
            .map(|request| std::mem::take(&mut request.data))
            .collect();
        let result = {
            let mut node = lock(&node);
            node.propose_batch(data).map(|indexes| {
                let term = node.term();
                (indexes, term, node.force_replicate())
            })
        };
        match result {
            Ok((indexes, term, outputs)) => {
                dispatcher.dispatch(outputs);

                signal_progress(&progress);
                for (request, index) in batch.into_iter().zip(indexes) {
                    let _ = request.response.send(Ok((index, term)));
                }
            }
            Err(error) => {
                for request in batch {
                    let _ = request.response.send(Err(error.clone()));
                }
            }
        }
    }
}

/// Other nodes list this key in `cluster_raft_peers`; the management API shows it so operators need
/// no external tool.
pub fn node_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The caller decides from this what to do with state it changed alongside the proposal. An entry
/// in the log may still commit after the caller gave up waiting, so answering that it will not
/// apply would be false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalError {
    /// Never entered the log; will not apply.
    Rejected(String),
    /// Entered the log but was overwritten after a leader change; will not apply.
    Discarded,
    /// May be in the log, but the commit was not confirmed; if it commits later, every node applies
    /// it.
    Undetermined(String),
}

impl std::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) | Self::Undetermined(reason) => f.write_str(reason),
            Self::Discarded => f.write_str("The proposal was discarded because the leader changed"),
        }
    }
}

impl From<ProposalError> for String {
    fn from(error: ProposalError) -> Self {
        error.to_string()
    }
}

impl RaftHandle {
    /// Waits until the entry commits and returns its index. On failure the error says whether the
    /// entry might still apply.
    pub fn propose(&self, data: Vec<u8>) -> Result<u64, ProposalError> {
        let rejected = |reason: &str| Err(ProposalError::Rejected(reason.to_string()));
        let undetermined = |reason: &str| Err(ProposalError::Undetermined(reason.to_string()));
        if data.is_empty() || data.len() > MAX_ENTRY_BYTES {
            return Err(ProposalError::Rejected(format!(
                "A Raft entry must be 1..={MAX_ENTRY_BYTES} bytes"
            )));
        }
        if self.shutdown.load(Ordering::Acquire)
            || !self.accepting_proposals.load(Ordering::Acquire)
        {
            return rejected("Cannot propose a change to a stopped Raft node");
        }
        let deadline = Instant::now() + PROPOSAL_TIMEOUT;
        self.pending_proposals.fetch_add(1, Ordering::AcqRel);
        let _pending = PendingProposal {
            count: self.pending_proposals.clone(),
            progress: self.progress.clone(),
        };
        if self.shutdown.load(Ordering::Acquire)
            || !self.accepting_proposals.load(Ordering::Acquire)
        {
            return rejected("Cannot propose a change to a stopped Raft node");
        }

        let (response, result) = mpsc::channel();
        match self
            .proposal_tx
            .try_send(ProposalRequest { data, response })
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return rejected("The Raft proposal queue is full; try again shortly");
            }
            Err(TrySendError::Disconnected(_)) => {
                return rejected("The Raft proposal handler has stopped");
            }
        }
        // Once handed to the handler it may already be in the log, so any later failure is
        // undetermined.
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return undetermined("The Raft change request timed out");
        };
        let (index, proposal_term) = match result.recv_timeout(remaining) {
            Ok(Ok(appended)) => appended,
            Ok(Err(reason)) => return Err(ProposalError::Rejected(reason)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return undetermined("The Raft change request timed out");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return undetermined("The Raft proposal handler stopped before replying");
            }
        };

        let (guard, condition) = &*self.progress;
        let mut generation = lock(guard);
        loop {
            {
                let node = lock(&self.node);
                if node.last_applied() >= index {
                    if node.entry_term(index) == proposal_term {
                        return Ok(index);
                    }
                    return Err(ProposalError::Discarded);
                }
                if let Some(error) = node.fatal_error() {
                    return undetermined(error);
                }
                if !node.is_leader() {
                    return undetermined("Lost leadership before the proposal was committed");
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return undetermined("The Raft change request was not agreed and applied in time");
            }
            let timeout = deadline.saturating_duration_since(now);
            let observed = *generation;
            let result = condition
                .wait_timeout_while(generation, timeout, |value| *value == observed)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            generation = result.0;
            if result.1.timed_out() {
                return undetermined("The Raft change request was not agreed and applied in time");
            }
        }
    }

    pub fn status_json(&self, backend: &str, listeners: usize) -> String {
        let node = lock(&self.node);
        let role = match node.role() {
            crate::raft::Role::Leader => "leader",
            crate::raft::Role::Candidate => "candidate",
            crate::raft::Role::Follower => "follower",
        };
        let fatal = node
            .fatal_error()
            .map(onetdns_core::json::escape)
            .unwrap_or_else(|| "null".into());
        let healthy = node.fatal_error().is_none();
        let leader = node.leader();
        let leading = node.is_leader();
        let mut peers: Vec<(NodeId, &str)> = self
            .peers
            .iter()
            .map(|(id, url)| (*id, url.as_str()))
            .collect();
        peers.sort_unstable_by_key(|(id, _)| *id);
        let peers = peers
            .into_iter()
            .map(|(id, url)| {
                let peer_healthy = peer_health(
                    self.contact.since(id),
                    self.contact_window,
                    leading || leader == Some(id),
                );
                let peer_role = if leader == Some(id) {
                    "leader"
                } else {
                    "member"
                };
                format!(
                    "{{\"id\":{id},\"url\":{},\"healthy\":{},\"role\":\"{peer_role}\",\"rtt_ms\":null,\"version\":{}}}",
                    onetdns_core::json::escape(url),
                    peer_healthy.map_or("null", |value| if value { "true" } else { "false" }),
                    self.contact
                        .version(id)
                        .map_or_else(|| "null".to_string(), |version| onetdns_core::json::escape(&version))
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"self\":{{\"id\":{},\"role\":\"{}\",\"backend\":{},\"listeners\":{listeners},\"leader\":{},\"term\":{},\"commit_index\":{},\"last_applied\":{},\"last_index\":{},\"snapshot_index\":{},\"retained_log_entries\":{},\"fatal\":{},\"healthy\":{healthy},\"version\":{}}},\"peers\":[{peers}]}}",
            self.self_id,
            role,
            onetdns_core::json::escape(backend),
            node.leader().map(|id| id.to_string()).unwrap_or("null".into()),
            node.term(),
            node.commit_index(),
            node.last_applied(),
            node.last_index(),
            node.snapshot_index(),
            node.retained_log_len(),
            fatal,
            onetdns_core::json::escape(self.version),
        )
    }

    /// Only the leader accepts config changes.
    pub fn is_leader(&self) -> bool {
        lock(&self.node).is_leader()
    }

    /// `None` during an election.
    pub fn leader(&self) -> Option<u64> {
        lock(&self.node).leader()
    }

    /// Stops new proposals first, finishes those in flight, then stops the threads; in another
    /// order a waiting proposal would never get an answer.
    pub fn shutdown(&self) {
        self.accepting_proposals.store(false, Ordering::Release);
        let deadline = Instant::now() + PROPOSAL_TIMEOUT;
        loop {
            let pending = self.pending_proposals.load(Ordering::Acquire);
            let (log_drained, fatal, applied, last) = {
                let node = lock(&self.node);
                (
                    node.last_applied() >= node.last_index(),
                    node.fatal_error().is_some(),
                    node.last_applied(),
                    node.last_index(),
                )
            };
            if (pending == 0 && log_drained) || fatal {
                break;
            }
            if Instant::now() >= deadline {
                onetdns_core::warn!(
                    event = "raft.shutdown_drain_timeout",
                    node = self.self_id,
                    pending,
                    applied,
                    last,
                    "Timed out waiting for pending proposals to apply before Raft shutdown"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.shutdown.store(true, Ordering::Relaxed);
        signal_progress(&self.progress);
        join_threads(&self.threads);
    }
}

/// `expected` says whether the peer should be sending to us steadily: the leader hears from every
/// follower, a follower only from the leader. Returns `None` when a silent peer has no reason to
/// send, so nothing can be told.
fn peer_health(since: Option<Duration>, window: Duration, expected: bool) -> Option<bool> {
    match since {
        Some(age) if age <= window => Some(true),
        _ if expected => Some(false),
        _ => None,
    }
}

/// Recovers poisoned locks so one thread's panic does not stall the cluster.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/// Sleeps in short steps so shutdown is noticed promptly. Returns true when shutdown was requested.
fn wait_for_shutdown(duration: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now().checked_add(duration);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let Some(remaining) = deadline.and_then(|end| end.checked_duration_since(Instant::now()))
        else {
            return false;
        };
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

fn signal_progress(progress: &Arc<(Mutex<u64>, Condvar)>) {
    let (generation, condition) = &**progress;
    let mut value = lock(generation);
    *value = value.wrapping_add(1);
    condition.notify_all();
}

/// Removes entries that reach zero so the map does not grow.
fn release_ip_slot(per_ip: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr) {
    let mut counts = lock(per_ip);
    if let Some(c) = counts.get_mut(&ip) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            counts.remove(&ip);
        }
    }
}

/// Seals the sender in with the frame; otherwise someone could relay another node's frame and pass
/// as that node.
struct FrameSealer {
    cipher: Arc<XChaCha20Poly1305>,
    /// Changes on restart.
    session_id: [u8; 16],
    sequence: AtomicU64,
    signing_key: Arc<SigningKey>,
    /// Binds frames to this cluster so they cannot be replayed into another.
    cluster_context: [u8; 32],
    version: &'static str,
}

impl FrameSealer {
    fn new(
        cipher: Arc<XChaCha20Poly1305>,
        signing_key: Arc<SigningKey>,
        cluster_context: [u8; 32],
        session_prefix: u64,
        version: &'static str,
    ) -> Option<Self> {
        let session_id = new_session_id(session_prefix)?;
        Some(Self {
            cipher,
            session_id,
            sequence: AtomicU64::new(0),
            signing_key,
            cluster_context,
            version,
        })
    }

    /// The sender ID goes into the AAD so a frame cannot be relabelled with another sender, and the
    /// signature binds the node identity on top. The product version travels inside the sealed body
    /// with a one-byte length: the receiver reads it only after decrypting, and in the header it
    /// would show the build version to anyone watching cluster traffic. The nonce is the session ID
    /// plus an increasing sequence number, so nonces never repeat within a session.
    fn frame(&self, from: NodeId, to: NodeId, message: &[u8]) -> Option<Vec<u8>> {
        let version_len = u8::try_from(self.version.len()).ok()?;
        let mut plaintext = Vec::with_capacity(1 + self.version.len() + message.len());
        plaintext.push(version_len);
        plaintext.extend_from_slice(self.version.as_bytes());
        plaintext.extend_from_slice(message);
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |s| s.checked_add(1))
            .ok()?;
        let mut nonce = [0u8; RAFT_NONCE_LEN];
        nonce[..16].copy_from_slice(&self.session_id);
        nonce[16..].copy_from_slice(&sequence.to_be_bytes());
        let mut header = Vec::with_capacity(1 + 8 + 8 + RAFT_NONCE_LEN);
        header.push(RAFT_FRAME_VERSION);
        header.extend_from_slice(&from.to_be_bytes());
        header.extend_from_slice(&to.to_be_bytes());
        header.extend_from_slice(&nonce);
        let aad = frame_aad(&self.cluster_context, &header);
        let encrypted = self
            .cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .ok()?;
        let payload_len = header
            .len()
            .checked_add(encrypted.len())?
            .checked_add(RAFT_SIG_LEN)?;
        if payload_len > MAX_RAFT_FRAME || payload_len > u32::MAX as usize {
            return None;
        }

        let mut signed = Vec::with_capacity(header.len() + encrypted.len());
        signed.extend_from_slice(&header);
        signed.extend_from_slice(&encrypted);
        let mut signature_input = Vec::with_capacity(self.cluster_context.len() + signed.len());
        signature_input.extend_from_slice(&self.cluster_context);
        signature_input.extend_from_slice(&signed);
        let signature = self.signing_key.sign(&signature_input).to_bytes();
        let mut framed = Vec::with_capacity(4 + payload_len);
        framed.extend_from_slice(&(payload_len as u32).to_be_bytes());
        framed.extend_from_slice(&signed);
        framed.extend_from_slice(&signature);
        Some(framed)
    }
}

/// Uses the starting session number as the prefix, which never rewinds across restarts, so frames
/// from an earlier session cannot pass in a new one.
fn new_session_id(session_prefix: u64) -> Option<[u8; 16]> {
    let mut random = [0u8; 8];
    onetdns_core::try_fill_random(&mut random).ok()?;
    let mut session = [0u8; 16];
    session[..8].copy_from_slice(&session_prefix.to_be_bytes());
    session[8..].copy_from_slice(&random);
    Some(session)
}

/// Binds the cluster context and the header (version, sender, receiver), so a frame cannot be
/// reused in another cluster or for another receiver.
fn frame_aad(cluster_context: &[u8; 32], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(cluster_context.len() + header.len());
    aad.extend_from_slice(cluster_context);
    aad.extend_from_slice(header);
    aad
}

/// ASCII without spaces or control characters, 1 to 64 bytes. Received versions go into logs and
/// status responses as they are. The sender checks the same rule, so it never starts with a version
/// receivers would refuse.
fn product_version_valid(version: &[u8]) -> bool {
    (1..=MAX_PRODUCT_VERSION_LEN).contains(&version.len())
        && version.iter().all(u8::is_ascii_graphic)
}

fn split_versioned(plaintext: &[u8]) -> Option<(&str, &[u8])> {
    let (&length, rest) = plaintext.split_first()?;
    let (version, message) = rest.split_at_checked(usize::from(length))?;
    if !product_version_valid(version) {
        return None;
    }
    Some((std::str::from_utf8(version).ok()?, message))
}

/// Different cluster configurations give different contexts, so two clusters that share a secret by
/// mistake still cannot exchange frames.
fn derive_cluster_context(
    secret: &[u8],
    self_id: NodeId,
    own_key: &VerifyingKey,
    peer_keys: &HashMap<NodeId, VerifyingKey>,
) -> [u8; 32] {
    let mut identities: Vec<(NodeId, [u8; 32])> = peer_keys
        .iter()
        .map(|(&id, key)| (id, key.to_bytes()))
        .collect();
    identities.push((self_id, own_key.to_bytes()));
    identities.sort_unstable_by_key(|(id, _)| *id);

    let mut hash = Sha256::new();
    hash.update(b"onetdns-raft-frame-v1");
    let secret_digest: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(secret).into());
    hash.update(secret_digest.as_slice());
    for (id, key) in identities {
        hash.update(id.to_be_bytes());
        hash.update(key);
    }
    hash.finalize().into()
}

/// `None` when the secret is too short.
fn raft_cipher(secret: &[u8]) -> Option<XChaCha20Poly1305> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(secret).into());
    XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()
}

pub struct RaftServer;

impl RaftServer {
    #[allow(clippy::too_many_arguments)]
    /// Starts the listener, tick, apply and per-node sender threads.
    ///
    /// `version` is this node's product version. Only nodes on the same version exchange messages,
    /// since the replicated config keys and their meaning, the log and snapshot formats and the RPC
    /// messages may all change between versions. `listener` is already bound: binding again after
    /// announcing a port-0 address would let another socket take the port in between. `on_apply`
    /// applies committed entries; it is where config replication lands.
    ///
    /// A cluster secret shorter than 32 bytes is refused: a weak secret is as good as none. On a
    /// startup failure the threads already started are cleaned up.
    pub fn spawn(
        self_id: NodeId,
        version: &'static str,
        listener: TcpListener,
        peers: HashMap<NodeId, String>,
        node: RaftNode,
        tick_ms: u64,
        secret: Vec<u8>,
        node_signing_seed: [u8; 32],
        peer_keys: HashMap<NodeId, [u8; 32]>,
        on_apply: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>,
        on_snapshot: Box<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>,
        on_install_snapshot: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>,
    ) -> Result<RaftHandle, String> {
        let secret = Zeroizing::new(secret);
        let node_signing_seed = Zeroizing::new(node_signing_seed);
        if secret.len() < 32 {
            return Err("The Raft secret must be at least 32 bytes".into());
        }
        if tick_ms == 0 {
            return Err("Raft tick_ms cannot be 0".into());
        }
        if !product_version_valid(version.as_bytes()) {
            return Err(format!(
                "The product version must be 1..={MAX_PRODUCT_VERSION_LEN} visible ASCII characters"
            ));
        }
        if let Some(error) = node.fatal_error() {
            return Err(error.to_string());
        }

        if peers.contains_key(&self_id) {
            return Err("Raft peers cannot include this node's own ID".into());
        }
        if peer_keys.contains_key(&self_id) {
            return Err("Raft peer_keys cannot include this node's own ID".into());
        }
        if peers.len() != peer_keys.len()
            || peers.keys().any(|id| !peer_keys.contains_key(id))
            || peer_keys.keys().any(|id| !peers.contains_key(id))
        {
            return Err("Raft peers and peer_keys must list exactly the same node IDs".into());
        }

        let signing_key = Arc::new(SigningKey::from_bytes(&node_signing_seed));
        drop(node_signing_seed);
        let mut verifying = HashMap::new();
        for (&id, pk) in &peer_keys {
            let vk = VerifyingKey::from_bytes(pk).map_err(|_| {
                format!("The public key of Raft peer {id} is not a valid Ed25519 key")
            })?;
            verifying.insert(id, vk);
        }

        let own_public = signing_key.verifying_key();
        let mut unique_keys = HashSet::new();
        unique_keys.insert(own_public.to_bytes());
        for (&id, vk) in &verifying {
            if !unique_keys.insert(vk.to_bytes()) {
                return Err(format!(
                    "The public key of Raft node {id} is the same as another node's; use a different key on every node"
                ));
            }
        }

        let cluster_context = derive_cluster_context(&secret, self_id, &own_public, &verifying);
        let cipher = Arc::new(
            raft_cipher(&secret)
                .ok_or("Could not derive the frame encryption key from the Raft shared secret")?,
        );
        drop(secret);

        let mut node = node;
        let session_prefix = node
            .next_boot_session()
            .map_err(|error| format!("Could not prepare the Raft session counter: {error}"))?;
        let node = Arc::new(Mutex::new(node));
        let peers = Arc::new(peers);
        for id in peers.keys() {
            if !verifying.contains_key(id) {
                return Err(format!(
                    "Raft peer {id} has no public key; per-node authentication requires one"
                ));
            }
        }
        let peer_keys = Arc::new(verifying);
        let shutdown = Arc::new(AtomicBool::new(false));
        let progress = Arc::new((Mutex::new(0), Condvar::new()));
        let accepting_proposals = Arc::new(AtomicBool::new(true));
        let pending_proposals = Arc::new(AtomicUsize::new(0));
        let (proposal_tx, proposal_rx) = mpsc::sync_channel(PROPOSAL_QUEUE);
        let threads: RuntimeThreads = Arc::new(Mutex::new(Vec::new()));
        let mut startup = RuntimeStartupGuard {
            shutdown: shutdown.clone(),
            threads: threads.clone(),
            armed: true,
        };
        let dispatcher = Dispatcher::new(
            self_id,
            version,
            &peers,
            cipher.clone(),
            signing_key.clone(),
            cluster_context,
            session_prefix,
            shutdown.clone(),
            &threads,
        )?;
        let contact = Arc::new(PeerContact::new(&peers));
        let contact_window = Duration::from_millis(
            tick_ms.saturating_mul(u64::from(lock(&node).election_timeout_ceiling())),
        );
        let handle = RaftHandle {
            node: node.clone(),
            peers: peers.clone(),
            contact: contact.clone(),
            contact_window,
            self_id,
            version,
            shutdown: shutdown.clone(),
            progress: progress.clone(),
            accepting_proposals,
            proposal_tx,
            pending_proposals: pending_proposals.clone(),
            threads: threads.clone(),
        };

        listener
            .set_nonblocking(true)
            .map_err(|error| format!("Could not make the Raft socket non-blocking: {error}"))?;

        {
            let node = node.clone();
            let dispatcher = dispatcher.clone();
            let progress = progress.clone();
            let shutdown = shutdown.clone();
            let proposal_thread = std::thread::Builder::new()
                .name("raft-propose".into())
                .spawn(move || {
                    run_proposal_worker(proposal_rx, node, dispatcher, progress, shutdown);
                })
                .map_err(|error| error.to_string())?;
            track_thread(&threads, proposal_thread);
        }

        let peer_ips: Arc<std::collections::HashSet<IpAddr>> = Arc::new(
            peers
                .values()
                .filter_map(|a| a.parse::<SocketAddr>().ok().map(|s| s.ip()))
                .collect(),
        );
        let per_ip: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));

        {
            let node = node.clone();
            let peers = peers.clone();
            let peer_keys = peer_keys.clone();
            let shutdown = shutdown.clone();
            let cipher = cipher.clone();
            let dispatcher = dispatcher.clone();
            let progress = progress.clone();
            let active = Arc::new(AtomicUsize::new(0));
            let replay = Arc::new(Mutex::new(ReplayCache::default()));
            let contact = contact.clone();
            let listener_threads = threads.clone();
            let peer_ips = peer_ips.clone();
            let per_ip = per_ip.clone();
            let listener_thread = std::thread::Builder::new()
                .name("raft-listen".into())
                .spawn(move || loop {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    match listener.accept() {
                        Ok((stream, remote)) => {
                            let ip = remote.ip();

                            if !peer_ips.contains(&ip) {
                                reject_raft_connection(ip, "not_a_peer");
                                drop(stream);
                                continue;
                            }

                            {
                                let mut counts = lock(&per_ip);
                                let entry = counts.entry(ip).or_insert(0);
                                if *entry >= MAX_RAFT_CONNS_PER_IP {
                                    drop(counts);
                                    reject_raft_connection(ip, "per_ip_limit");
                                    drop(stream);
                                    continue;
                                }
                                *entry += 1;
                            }
                            if active.fetch_add(1, Ordering::AcqRel) >= MAX_RAFT_CONNECTIONS {
                                active.fetch_sub(1, Ordering::Release);
                                release_ip_slot(&per_ip, ip);
                                reject_raft_connection(ip, "connection_limit");
                                drop(stream);
                                continue;
                            }
                            let node = node.clone();
                            let peers = peers.clone();
                            let peer_keys = peer_keys.clone();
                            let cipher = cipher.clone();
                            let dispatcher = dispatcher.clone();
                            let progress = progress.clone();
                            let active_connection = active.clone();
                            let replay = replay.clone();
                            let contact = contact.clone();
                            let connection_shutdown = shutdown.clone();
                            let conn_per_ip = per_ip.clone();
                            let spawned = std::thread::Builder::new()
                                .name("raft-connection".into())
                                .spawn(move || {
                                    /// Releases the connection's slots when it ends.
                                    struct Guard {
                                        active: Arc<AtomicUsize>,
                                        per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
                                        ip: IpAddr,
                                    }
                                    impl Drop for Guard {
                                        fn drop(&mut self) {
                                            self.active.fetch_sub(1, Ordering::Release);
                                            release_ip_slot(&self.per_ip, self.ip);
                                        }
                                    }
                                    let _guard = Guard {
                                        active: active_connection,
                                        per_ip: conn_per_ip,
                                        ip,
                                    };
                                    handle_conn(
                                        self_id,
                                        version,
                                        stream,
                                        &node,
                                        &peers,
                                        &peer_keys,
                                        &cipher,
                                        &cluster_context,
                                        &dispatcher,
                                        &progress,
                                        &replay,
                                        &contact,
                                        connection_shutdown,
                                    );
                                });
                            match spawned {
                                Ok(thread) => track_thread(&listener_threads, thread),
                                Err(_) => {
                                    active.fetch_sub(1, Ordering::Release);
                                    release_ip_slot(&per_ip, ip);
                                }
                            }
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                })
                .map_err(|error| error.to_string())?;
            track_thread(&threads, listener_thread);
        }

        {
            let node = node.clone();
            let shutdown = shutdown.clone();
            let dispatcher = dispatcher.clone();
            let tick_thread = std::thread::Builder::new()
                .name("raft-tick".into())
                .spawn(move || loop {
                    if wait_for_shutdown(Duration::from_millis(tick_ms), &shutdown) {
                        break;
                    }
                    let outputs = {
                        let mut node = lock(&node);
                        node.tick()
                    };
                    dispatcher.dispatch(outputs);
                })
                .map_err(|error| error.to_string())?;
            track_thread(&threads, tick_thread);
        }

        {
            let node = node.clone();
            let shutdown = shutdown.clone();
            let progress = progress.clone();
            let dispatcher = dispatcher.clone();
            let pending_proposals = pending_proposals.clone();
            let apply_thread = std::thread::Builder::new()
                .name("raft-apply".into())
                .spawn(move || {
                    let (generation, condition) = &*progress;
                    let mut observed = *lock(generation);
                    loop {
                        'apply: loop {
                            let pending_snapshot = { lock(&node).pending_snapshot() };
                            if let Some(snapshot) = pending_snapshot {
                                if let Err(error) = on_install_snapshot(&snapshot.data) {
                                    lock(&node).fail_stop(format!(
                                        "Could not install Raft snapshot {} into the state machine: {error}",
                                        snapshot.index
                                    ));
                                    signal_progress(&progress);
                                    break 'apply;
                                }
                                let install_result =
                                    { lock(&node).finish_snapshot_install(snapshot.index) };
                                match install_result {
                                    Ok(response) => dispatcher.dispatch(vec![response]),
                                    Err(error) => {
                                        lock(&node).fail_stop(error);
                                        signal_progress(&progress);
                                        break 'apply;
                                    }
                                }
                                signal_progress(&progress);
                                continue;
                            }
                            if pending_proposals.load(Ordering::Acquire) == 0
                                && lock(&node).snapshot_due()
                            {
                                let snapshot = match on_snapshot() {
                                    Ok(snapshot) => snapshot,
                                    Err(error) => {
                                        lock(&node).fail_stop(format!(
                                            "Could not create a Raft state machine snapshot: {error}"
                                        ));
                                        signal_progress(&progress);
                                        break 'apply;
                                    }
                                };
                                let compact_result = { lock(&node).compact(snapshot) };
                                if let Err(error) = compact_result {
                                    lock(&node).fail_stop(error);
                                    signal_progress(&progress);
                                    break 'apply;
                                }
                                signal_progress(&progress);
                                continue;
                            }
                            let entries = { lock(&node).next_committed_batch(MAX_APPEND_ENTRIES) };
                            let Some(first) = entries.first().map(|entry| entry.index) else {
                                break;
                            };
                            for entry in &entries {
                                let apply_result = if entry.data.is_empty() {
                                    Ok(())
                                } else {
                                    on_apply(&entry.data)
                                };
                                if let Err(error) = apply_result {
                                    lock(&node).fail_stop(format!(
                                        "Could not apply Raft log entry {}: {error}",
                                        entry.index
                                    ));
                                    signal_progress(&progress);
                                    break 'apply;
                                }
                            }
                            let last = entries.last().expect("The apply batch is not empty").index;
                            let mark_result = { lock(&node).mark_applied_batch(first, last) };
                            if let Err(error) = mark_result {
                                lock(&node).fail_stop(error);
                                signal_progress(&progress);
                                break;
                            }
                            signal_progress(&progress);
                        }
                        if shutdown.load(Ordering::Acquire) {
                            break;
                        }
                        let mut current = lock(generation);
                        if *current == observed {
                            current = condition
                                .wait_timeout(current, Duration::from_millis(tick_ms))
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .0;
                        }
                        observed = *current;
                    }
                })
                .map_err(|error| error.to_string())?;
            track_thread(&threads, apply_thread);
        }

        startup.disarm();
        Ok(handle)
    }
}

#[allow(clippy::too_many_arguments)]
/// Opens the frame and checks the sender's signature and the replay window before anything reaches
/// the state machine; any failure closes the connection. A frame from a node on another product
/// version is dropped but the connection stays, or the sender would reconnect for every message.
///
/// The state machine gets the authenticated sender ID: trusting the leader and candidate fields in
/// the message body would let any node pose as leader.
fn handle_conn(
    self_id: NodeId,
    version: &'static str,
    stream: TcpStream,
    node: &Arc<Mutex<RaftNode>>,
    peers: &HashMap<NodeId, String>,
    peer_keys: &HashMap<NodeId, VerifyingKey>,
    cipher: &XChaCha20Poly1305,
    cluster_context: &[u8; 32],
    dispatcher: &Dispatcher,
    progress: &Arc<(Mutex<u64>, Condvar)>,
    replay: &Arc<Mutex<ReplayCache>>,
    contact: &PeerContact,
    shutdown: Arc<AtomicBool>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    let mut stream = DeadlineTcp::new(stream, Instant::now()).stop_on(shutdown.clone());
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        stream.set_deadline(Instant::now() + RAFT_FRAME_TIMEOUT);
        let mut length_bytes = [0u8; 4];
        if stream.read_exact(&mut length_bytes).is_err() {
            return;
        }
        let length = u32::from_be_bytes(length_bytes) as usize;
        let minimum = 1 + 8 + 8 + RAFT_NONCE_LEN + RAFT_AEAD_TAG_LEN + RAFT_SIG_LEN;
        if !(minimum..=MAX_RAFT_FRAME).contains(&length) {
            return;
        }
        let mut body = vec![0u8; length];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        if body.first().copied() != Some(RAFT_FRAME_VERSION) {
            return;
        }
        let sender_bytes: [u8; 8] = match body.get(1..9).and_then(|value| value.try_into().ok()) {
            Some(value) => value,
            None => return,
        };
        let receiver_bytes: [u8; 8] = match body.get(9..17).and_then(|value| value.try_into().ok())
        {
            Some(value) => value,
            None => return,
        };
        let from = u64::from_be_bytes(sender_bytes);
        let to = u64::from_be_bytes(receiver_bytes);
        if to != self_id || from == self_id || !peers.contains_key(&from) {
            return;
        }

        let Some(verifying) = peer_keys.get(&from) else {
            return;
        };
        let sig_start = body.len() - RAFT_SIG_LEN;
        let signed = &body[..sig_start];
        let sig_bytes: [u8; RAFT_SIG_LEN] = match body[sig_start..].try_into() {
            Ok(value) => value,
            Err(_) => return,
        };
        let mut signature_input = Vec::with_capacity(cluster_context.len() + signed.len());
        signature_input.extend_from_slice(cluster_context);
        signature_input.extend_from_slice(signed);
        if verifying
            .verify(&signature_input, &Signature::from_bytes(&sig_bytes))
            .is_err()
        {
            return;
        }
        let nonce_start = 17;
        let nonce: [u8; RAFT_NONCE_LEN] = match body
            .get(nonce_start..nonce_start + RAFT_NONCE_LEN)
            .and_then(|value| value.try_into().ok())
        {
            Some(value) => value,
            None => return,
        };
        let ciphertext = &body[nonce_start + RAFT_NONCE_LEN..sig_start];
        let header = &body[..nonce_start + RAFT_NONCE_LEN];
        let aad = frame_aad(cluster_context, header);
        let plaintext = match cipher.decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            Ok(value) => value,
            Err(_) => return,
        };
        if !lock(replay).accept(from, nonce) {
            let count = REPLAY_REJECTS.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                onetdns_core::warn!(
                    event = "raft.replay_rejected",
                    peer = from,
                    count,
                    "Rejected a frame in the Raft replay check"
                );
            }
            return;
        }
        let Some((peer_version, encoded)) = split_versioned(&plaintext) else {
            return;
        };
        if contact.note_version(from, peer_version) {
            if peer_version == version {
                onetdns_core::info!(
                    event = "raft.peer_version",
                    peer = from,
                    version = peer_version,
                    "A cluster node runs the same OnetDNS version"
                );
            } else {
                onetdns_core::warn!(
                    event = "raft.peer_version_mismatch",
                    peer = from,
                    version = peer_version,
                    own_version = version,
                    "A cluster node runs a different OnetDNS version; its cluster messages are ignored until both run the same version"
                );
            }
        }
        if peer_version != version {
            contact.record(from);
            continue;
        }
        let Some(message) = decode_msg(encoded) else {
            return;
        };
        match &message {
            Msg::RequestVote { candidate, .. } if *candidate != from => return,
            Msg::AppendEntries { leader, .. } if *leader != from => return,
            _ => {}
        }
        let outputs = {
            let mut node = lock(node);
            node.step(from, message)
        };
        contact.record(from);
        dispatcher.dispatch(outputs);
        signal_progress(progress);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VERSION: &str = "1.0.0";

    fn peer_entry(status: &str, id: NodeId) -> String {
        let marker = format!("{{\"id\":{id},");
        let start = status.rfind(&marker).expect("노드 항목");
        let end = status[start..].find('}').expect("항목 끝") + start;
        status[start..=end].to_string()
    }

    fn wait_for_progress(
        handle: &RaftHandle,
        timeout: Duration,
        condition: impl Fn() -> bool,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        let (generation, notifier) = &*handle.progress;
        let mut observed = lock(generation);
        loop {
            if condition() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let current = *observed;
            observed = notifier
                .wait_timeout_while(observed, remaining, |value| *value == current)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    #[test]
    fn last_pending_proposal_wakes_apply_progress() {
        let count = Arc::new(AtomicUsize::new(2));
        let progress = Arc::new((Mutex::new(0), Condvar::new()));
        let first = PendingProposal {
            count: count.clone(),
            progress: progress.clone(),
        };
        let last = PendingProposal {
            count: count.clone(),
            progress: progress.clone(),
        };

        drop(first);
        assert_eq!(count.load(Ordering::Acquire), 1);
        assert_eq!(*lock(&progress.0), 0, "아직 제안이 남으면 깨우지 않습니다");
        drop(last);
        assert_eq!(count.load(Ordering::Acquire), 0);
        assert_eq!(*lock(&progress.0), 1, "마지막 제안이 apply를 깨웁니다");
    }

    #[test]
    fn shutdown_drains_an_already_appended_proposal() {
        let applied = Arc::new(AtomicBool::new(false));
        let applied_in_callback = applied.clone();
        let handle = RaftServer::spawn(
            1,
            TEST_VERSION,
            TcpListener::bind("127.0.0.1:0").unwrap(),
            HashMap::new(),
            RaftNode::new(
                1,
                vec![1],
                crate::raft::Config {
                    election_base: 2,
                    heartbeat: 1,
                },
            ),
            10,
            vec![7; 32],
            [9; 32],
            HashMap::new(),
            Box::new(move |_| {
                std::thread::sleep(Duration::from_millis(200));
                applied_in_callback.store(true, Ordering::Release);
                Ok(())
            }),
            Box::new(|| Ok(b"test-snapshot".to_vec())),
            Box::new(|_| Ok(())),
        )
        .unwrap();
        let election_deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_leader() && Instant::now() < election_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handle.is_leader());

        let proposer = handle.clone();
        let proposal = std::thread::spawn(move || proposer.propose(b"change".to_vec()));
        let append_deadline = Instant::now() + Duration::from_secs(1);
        while lock(&handle.node).last_index() < 2 && Instant::now() < append_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        handle.shutdown();

        assert_eq!(proposal.join().unwrap(), Ok(2));
        assert!(applied.load(Ordering::Acquire));
        assert_eq!(lock(&handle.node).last_applied(), 2);
    }

    #[test]
    fn concurrent_proposals_keep_distinct_contiguous_results() {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let applied_in_callback = applied.clone();
        let handle = RaftServer::spawn(
            1,
            TEST_VERSION,
            TcpListener::bind("127.0.0.1:0").unwrap(),
            HashMap::new(),
            RaftNode::new(
                1,
                vec![1],
                crate::raft::Config {
                    election_base: 2,
                    heartbeat: 1,
                },
            ),
            10,
            vec![7; 32],
            [9; 32],
            HashMap::new(),
            Box::new(move |data| {
                lock(&applied_in_callback).push(data.to_vec());
                Ok(())
            }),
            Box::new(|| Ok(b"test-snapshot".to_vec())),
            Box::new(|_| Ok(())),
        )
        .unwrap();
        let election_deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_leader() && Instant::now() < election_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handle.is_leader());

        let start = Arc::new(std::sync::Barrier::new(33));
        let mut proposals = Vec::new();
        for id in 0..32 {
            let handle = handle.clone();
            let start = start.clone();
            proposals.push(std::thread::spawn(move || {
                start.wait();
                handle.propose(format!("change-{id}").into_bytes())
            }));
        }
        start.wait();
        let mut indexes: Vec<u64> = proposals
            .into_iter()
            .map(|proposal| proposal.join().unwrap().unwrap())
            .collect();
        indexes.sort_unstable();

        assert_eq!(indexes, (2..=33).collect::<Vec<_>>());
        assert_eq!(lock(&applied).len(), 32);
        handle.shutdown();
    }

    #[test]
    fn applied_state_is_snapshotted_and_log_prefix_is_reclaimed() {
        let applied = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let apply_state = applied.clone();
        let snapshot_state = applied.clone();
        let handle = RaftServer::spawn(
            1,
            TEST_VERSION,
            TcpListener::bind("127.0.0.1:0").unwrap(),
            HashMap::new(),
            RaftNode::new(
                1,
                vec![1],
                crate::raft::Config {
                    election_base: 2,
                    heartbeat: 1,
                },
            ),
            10,
            vec![7; 32],
            [9; 32],
            HashMap::new(),
            Box::new(move |data| {
                lock(&apply_state).push(data.to_vec());
                Ok(())
            }),
            Box::new(move || {
                let state = lock(&snapshot_state);
                let mut snapshot = Vec::new();
                for value in state.iter() {
                    snapshot.extend_from_slice(value);
                    snapshot.push(0);
                }
                Ok(snapshot)
            }),
            Box::new(|_| Ok(())),
        )
        .unwrap();
        let election_deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_leader() && Instant::now() < election_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handle.is_leader());

        for index in 0..10 {
            handle
                .propose(format!("change-{index}").into_bytes())
                .unwrap();
        }
        let compact_deadline = Instant::now() + Duration::from_secs(1);
        while lock(&handle.node).snapshot().is_none() && Instant::now() < compact_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let node = lock(&handle.node);
        let snapshot = node.snapshot().expect("적용 임계치에서 자동 스냅샷");
        assert!(snapshot.index >= crate::raft::SNAPSHOT_LOG_THRESHOLD);
        assert!(!snapshot.data.is_empty());
        assert!(
            node.retained_log_len() < node.last_index() as usize,
            "적용된 접두사 메모리 회수"
        );
        drop(node);
        let status = handle.status_json("Native", 1);
        assert!(status.contains("\"snapshot_index\":"));
        assert!(status.contains("\"retained_log_entries\":"));
        handle.shutdown();
    }

    #[test]
    /// A silent peer with no reason to send is not dead and must stay unknown.
    fn peer_health_follows_authenticated_contact() {
        let window = Duration::from_millis(400);
        assert_eq!(
            peer_health(Some(Duration::from_millis(50)), window, true),
            Some(true)
        );
        assert_eq!(
            peer_health(Some(Duration::from_millis(50)), window, false),
            Some(true)
        );
        assert_eq!(
            peer_health(Some(Duration::from_secs(5)), window, true),
            Some(false)
        );
        assert_eq!(peer_health(None, window, true), Some(false));
        assert_eq!(
            peer_health(Some(Duration::from_secs(5)), window, false),
            None
        );
        assert_eq!(peer_health(None, window, false), None);

        let peers = HashMap::from([(2, "127.0.0.1:1".to_string())]);
        let contact = PeerContact::new(&peers);
        assert_eq!(contact.since(2), None);
        contact.record(2);
        contact.record(9);
        assert!(contact.since(2).expect("기록") < window);
        assert_eq!(contact.since(9), None, "설정에 없는 노드는 적지 않는다");
    }

    #[test]
    fn offline_follower_recovers_state_through_authenticated_snapshot_transport() {
        let stop_all = |handles: &[RaftHandle]| {
            for handle in handles {
                handle.accepting_proposals.store(false, Ordering::Release);
                handle.shutdown.store(true, Ordering::Release);
                signal_progress(&handle.progress);
            }
            for handle in handles {
                join_threads(&handle.threads);
            }
        };
        // Node 3 starts late, but its listener is bound up front so no other socket takes the
        // announced address. Frames that arrive before node 3 starts wait in the backlog.
        let listeners = [(); 3].map(|()| TcpListener::bind("127.0.0.1:0").unwrap());
        let addresses = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap());
        let [first, second, third] = listeners;

        let ids = vec![1, 2, 3];
        let seeds = [[41u8; 32], [42u8; 32], [43u8; 32]];
        let public = seeds.map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let states: Vec<_> = (0..3)
            .map(|_| Arc::new(Mutex::new(Vec::<u8>::new())))
            .collect();
        let spawn_node = |index: usize, listener: TcpListener| {
            let self_id = ids[index];
            let peers = ids
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(peer, id)| (*id, addresses[peer].to_string()))
                .collect();
            let peer_keys = ids
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(peer, id)| (*id, public[peer]))
                .collect();
            let apply_state = states[index].clone();
            let snapshot_state = states[index].clone();
            let install_state = states[index].clone();
            RaftServer::spawn(
                self_id,
                TEST_VERSION,
                listener,
                peers,
                RaftNode::new(
                    self_id,
                    ids.clone(),
                    crate::raft::Config {
                        election_base: 20,
                        heartbeat: 2,
                    },
                ),
                10,
                vec![7; 32],
                seeds[index],
                peer_keys,
                Box::new(move |data| {
                    lock(&apply_state).extend_from_slice(data);
                    Ok(())
                }),
                Box::new(move || Ok(lock(&snapshot_state).clone())),
                Box::new(move |snapshot| {
                    *lock(&install_state) = snapshot.to_vec();
                    Ok(())
                }),
            )
            .unwrap()
        };

        let mut handles = vec![spawn_node(0, first), spawn_node(1, second)];
        let election_deadline = Instant::now() + Duration::from_secs(5);
        let leader = loop {
            if let Some(index) = handles.iter().position(RaftHandle::is_leader) {
                break Some(index);
            }
            if Instant::now() >= election_deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let Some(leader) = leader else {
            stop_all(&handles);
            panic!("2/3 정족수 리더 선출 실패");
        };
        let follower = 1 - leader;
        let observed_deadline = Instant::now() + Duration::from_secs(2);
        let (leader_view, follower_view) = loop {
            let leader_view = handles[leader].status_json("Native", 1);
            let follower_view = handles[follower].status_json("Native", 1);
            let settled = peer_entry(&leader_view, ids[follower]).contains("\"healthy\":true")
                && peer_entry(&follower_view, ids[leader]).contains("\"healthy\":true")
                && peer_entry(&follower_view, ids[leader]).contains("\"role\":\"leader\"");
            if settled || Instant::now() >= observed_deadline {
                break (leader_view, follower_view);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let expectations = [
            (peer_entry(&leader_view, ids[follower]), "\"healthy\":true"),
            (peer_entry(&leader_view, ids[2]), "\"healthy\":false"),
            (peer_entry(&follower_view, ids[leader]), "\"healthy\":true"),
            (
                peer_entry(&follower_view, ids[leader]),
                "\"role\":\"leader\"",
            ),
            (peer_entry(&follower_view, ids[2]), "\"healthy\":null"),
        ];
        if let Some((entry, wanted)) = expectations
            .iter()
            .find(|(entry, wanted)| !entry.contains(wanted))
        {
            let message = format!("{entry}에 {wanted}가 있어야 합니다");
            stop_all(&handles);
            panic!("{message}");
        }
        let start = Arc::new(std::sync::Barrier::new(13));
        let proposals: Vec<_> = (0..12)
            .map(|index| {
                let handle = handles[leader].clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    handle.propose(format!("change-{index};").into_bytes())
                })
            })
            .collect();
        start.wait();
        let proposal_results: Vec<_> = proposals
            .into_iter()
            .map(|proposal| proposal.join().unwrap())
            .collect();
        if proposal_results.iter().any(Result::is_err) {
            stop_all(&handles);
            panic!("스냅샷 전 동시 제안 실패: {proposal_results:?}");
        }
        let expected = lock(&states[leader]).clone();
        assert!(!expected.is_empty());
        if !wait_for_progress(&handles[leader], Duration::from_secs(2), || {
            lock(&handles[leader].node).snapshot().is_some()
        }) {
            stop_all(&handles);
            panic!("리더 로그 스냅샷 생성 실패");
        }

        handles.push(spawn_node(2, third));
        let caught_up = wait_for_progress(&handles[2], Duration::from_secs(5), || {
            lock(&states[2]).as_slice() == expected.as_slice()
                && lock(&handles[2].node).last_applied()
                    == lock(&handles[leader].node).last_applied()
        });
        let follower_snapshot = lock(&handles[2].node).snapshot_index();
        let follower_state = lock(&states[2]).clone();

        stop_all(&handles);
        assert!(caught_up, "offline follower 스냅샷 catch-up 제한 시간 초과");
        assert!(follower_snapshot > 0);
        assert_eq!(follower_state.as_slice(), expected.as_slice());
    }

    #[test]
    /// Otherwise a healthy cluster would elect a new leader.
    fn slow_state_machine_application_does_not_starve_heartbeats() {
        let listeners = [(); 3].map(|()| TcpListener::bind("127.0.0.1:0").unwrap());
        let addresses = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap());

        let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
        let public = seeds.map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let ids = vec![1, 2, 3];
        let apply_started = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for (index, listener) in listeners.into_iter().enumerate() {
            let self_id = ids[index];
            let peers = ids
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(peer, id)| (*id, addresses[peer].to_string()))
                .collect();
            let peer_keys = ids
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(peer, id)| (*id, public[peer]))
                .collect();
            let started = apply_started.clone();
            handles.push(
                RaftServer::spawn(
                    self_id,
                    TEST_VERSION,
                    listener,
                    peers,
                    RaftNode::new(
                        self_id,
                        ids.clone(),
                        crate::raft::Config {
                            election_base: 10,
                            heartbeat: 1,
                        },
                    ),
                    10,
                    vec![7; 32],
                    seeds[index],
                    peer_keys,
                    Box::new(move |_| {
                        started.store(true, Ordering::Release);
                        std::thread::sleep(Duration::from_millis(300));
                        Ok(())
                    }),
                    Box::new(|| Ok(b"test-snapshot".to_vec())),
                    Box::new(|_| Ok(())),
                )
                .unwrap(),
            );
        }

        let election_deadline = Instant::now() + Duration::from_secs(3);
        let leader_index = loop {
            let leaders: Vec<_> = handles
                .iter()
                .enumerate()
                .filter(|(_, handle)| handle.is_leader())
                .map(|(index, _)| index)
                .collect();
            if leaders.len() == 1 {
                let leader = ids[leaders[0]];
                if handles
                    .iter()
                    .all(|handle| lock(&handle.node).leader() == Some(leader))
                {
                    break Some(leaders[0]);
                }
            }
            if Instant::now() >= election_deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let Some(leader_index) = leader_index else {
            for handle in &handles {
                handle.shutdown();
            }
            panic!("3노드 리더가 수렴하지 않았습니다");
        };
        let initial_term = lock(&handles[leader_index].node).term();
        let proposer = handles[leader_index].clone();
        let proposal = std::thread::spawn(move || proposer.propose(b"slow-apply".to_vec()));
        let apply_deadline = Instant::now() + Duration::from_secs(2);
        while !apply_started.load(Ordering::Acquire) && Instant::now() < apply_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(220));

        let terms: Vec<_> = handles
            .iter()
            .map(|handle| lock(&handle.node).term())
            .collect();
        let leaders: Vec<_> = handles
            .iter()
            .map(|handle| lock(&handle.node).leader())
            .collect();
        let proposal_result = proposal.join().unwrap();
        for handle in &handles {
            handle.shutdown();
        }

        assert!(apply_started.load(Ordering::Acquire));
        assert!(proposal_result.is_ok(), "{proposal_result:?}");
        assert!(terms.iter().all(|term| *term == initial_term), "{terms:?}");
        assert!(
            leaders
                .iter()
                .all(|leader| *leader == Some(ids[leader_index])),
            "{leaders:?}"
        );
    }

    #[test]
    fn proposal_after_shutdown_is_rejected_immediately() {
        let handle = RaftServer::spawn(
            1,
            TEST_VERSION,
            TcpListener::bind("127.0.0.1:0").unwrap(),
            HashMap::new(),
            RaftNode::new(
                1,
                vec![1],
                crate::raft::Config {
                    election_base: 2,
                    heartbeat: 1,
                },
            ),
            10,
            vec![7; 32],
            [9; 32],
            HashMap::new(),
            Box::new(|_| Ok(())),
            Box::new(|| Ok(b"test-snapshot".to_vec())),
            Box::new(|_| Ok(())),
        )
        .unwrap();
        handle.shutdown();

        let started = Instant::now();
        assert_eq!(
            handle.propose(b"change".to_vec()),
            Err(ProposalError::Rejected(
                "Cannot propose a change to a stopped Raft node".into()
            ))
        );
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn codec_roundtrip_all_variants() {
        let messages = vec![
            Msg::RequestVote {
                term: 7,
                candidate: 3,
                last_log_index: 5,
                last_log_term: 6,
            },
            Msg::RequestVoteResp {
                term: 7,
                granted: true,
            },
            Msg::AppendEntries {
                term: 9,
                leader: 1,
                prev_log_index: 2,
                prev_log_term: 8,
                entries: vec![
                    LogEntry {
                        term: 9,
                        index: 3,
                        data: b"hello".to_vec(),
                    },
                    LogEntry {
                        term: 9,
                        index: 4,
                        data: Vec::new(),
                    },
                ],
                leader_commit: 2,
            },
            Msg::AppendEntriesResp {
                term: 9,
                success: false,
                match_index: 0,
            },
            Msg::InstallSnapshot {
                term: 10,
                leader: 1,
                last_included_index: 4_096,
                last_included_term: 9,
                offset: 262_144,
                data: b"snapshot-chunk".to_vec(),
                done: true,
            },
            Msg::InstallSnapshotResp {
                term: 10,
                last_included_index: 4_096,
                next_offset: 262_158,
                installed: false,
            },
        ];
        for message in messages {
            let encoded = encode_msg(&message);
            assert_eq!(decode_msg(&encoded), Some(message));
        }
    }

    #[test]
    fn decode_rejects_garbage_and_non_boolean_flags() {
        assert_eq!(decode_msg(&[]), None);
        assert_eq!(decode_msg(&[99]), None);
        assert_eq!(decode_msg(&[1, 0, 0]), None);
        let mut invalid = encode_msg(&Msg::RequestVoteResp {
            term: 1,
            granted: true,
        });
        *invalid.last_mut().unwrap() = 2;
        assert_eq!(decode_msg(&invalid), None);
    }

    #[test]
    /// Senders must not copy the AEAD and private key bytes once per node.
    fn frame_sealer_shares_cipher_and_signing_key() {
        let cipher = Arc::new(raft_cipher(&[7u8; 32]).unwrap());
        let signing = Arc::new(SigningKey::from_bytes(&[5u8; 32]));
        let sealer =
            FrameSealer::new(cipher.clone(), signing.clone(), [3u8; 32], 77, TEST_VERSION).unwrap();

        assert!(Arc::ptr_eq(&cipher, &sealer.cipher));
        assert!(Arc::ptr_eq(&signing, &sealer.signing_key));
    }

    #[test]
    fn raft_frame_encrypts_and_authenticates_payload() {
        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let verifying = signing.verifying_key();
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(signing),
            [3u8; 32],
            77,
            TEST_VERSION,
        )
        .unwrap();
        let message = encode_msg(&Msg::RequestVoteResp {
            term: 3,
            granted: true,
        });
        let framed = sealer.frame(9, 10, &message).unwrap();
        assert!(!framed
            .windows(message.len())
            .any(|window| window == message));
        assert!(
            !framed
                .windows(TEST_VERSION.len())
                .any(|window| window == TEST_VERSION.as_bytes()),
            "제품 버전은 봉한 본문 안에만 있어야 합니다"
        );

        let length = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(length, framed.len() - 4);
        let body = &framed[4..];
        assert_eq!(body[0], RAFT_FRAME_VERSION);
        let sender: [u8; 8] = body[1..9].try_into().unwrap();
        let receiver: [u8; 8] = body[9..17].try_into().unwrap();
        assert_eq!(u64::from_be_bytes(sender), 9);
        assert_eq!(u64::from_be_bytes(receiver), 10);
        let nonce: [u8; RAFT_NONCE_LEN] = body[17..17 + RAFT_NONCE_LEN].try_into().unwrap();

        let sig_start = body.len() - RAFT_SIG_LEN;
        let sig: [u8; RAFT_SIG_LEN] = body[sig_start..].try_into().unwrap();
        let mut signature_input = Vec::from([3u8; 32]);
        signature_input.extend_from_slice(&body[..sig_start]);
        verifying
            .verify(&signature_input, &Signature::from_bytes(&sig))
            .expect("노드 서명이 유효해야");

        let header_end = 17 + RAFT_NONCE_LEN;
        let aad = frame_aad(&[3u8; 32], &body[..header_end]);
        let cipher = raft_cipher(&secret).unwrap();
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &body[header_end..sig_start],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(usize::from(plain[0]), TEST_VERSION.len());
        assert_eq!(
            split_versioned(&plain),
            Some((TEST_VERSION, message.as_slice()))
        );
    }

    #[test]
    fn versioned_plaintext_rejects_malformed_versions() {
        assert_eq!(
            split_versioned(b"\x051.0.0rest"),
            Some(("1.0.0", &b"rest"[..]))
        );
        assert_eq!(split_versioned(b"\x051.0.0"), Some(("1.0.0", &b""[..])));
        assert_eq!(split_versioned(&[]), None);
        assert_eq!(split_versioned(&[0, 1, 2]), None, "빈 버전");
        assert_eq!(split_versioned(b"\x051.0."), None, "잘린 버전");
        assert_eq!(split_versioned(b"\x031 0rest"), None, "공백");
        assert_eq!(split_versioned(b"\x031\n0rest"), None, "제어 문자");
        assert_eq!(
            split_versioned(&[2, 0xc3, 0xa9, 1]),
            None,
            "ASCII 밖의 글자"
        );
        let mut longest = vec![64u8];
        longest.extend([b'1'; 64]);
        assert!(split_versioned(&longest).is_some());
        let mut long = vec![65u8];
        long.extend([b'1'; 65]);
        assert_eq!(split_versioned(&long), None, "64바이트를 넘는 버전");
    }

    #[test]
    fn spawn_rejects_versions_peers_would_refuse() {
        let long: &'static str = "1".repeat(65).leak();
        for version in ["", "1.0 0", "1.0\n0", "1.0.0é", long] {
            let started = RaftServer::spawn(
                1,
                version,
                TcpListener::bind("127.0.0.1:0").unwrap(),
                HashMap::new(),
                RaftNode::new(
                    1,
                    vec![1],
                    crate::raft::Config {
                        election_base: 2,
                        heartbeat: 1,
                    },
                ),
                10,
                vec![7; 32],
                [9; 32],
                HashMap::new(),
                Box::new(|_| Ok(())),
                Box::new(|| Ok(Vec::new())),
                Box::new(|_| Ok(())),
            );
            if let Ok(handle) = started {
                handle.shutdown();
                panic!("{version:?} 로는 시작하지 않아야 합니다");
            }
        }
    }

    #[test]
    /// The version log fires only on a change, which relies on this.
    fn peer_version_is_noted_only_when_it_changes() {
        let peers = HashMap::from([(2, "127.0.0.1:1".to_string())]);
        let contact = PeerContact::new(&peers);
        assert_eq!(contact.version(2), None);
        assert!(contact.note_version(2, "1.0.0"), "처음 받은 버전");
        assert!(!contact.note_version(2, "1.0.0"));
        assert!(contact.note_version(2, "1.1.0"));
        assert_eq!(contact.version(2).as_deref(), Some("1.1.0"));
        assert!(
            !contact.note_version(9, "1.0.0"),
            "설정에 없는 노드는 적지 않는다"
        );
        assert_eq!(contact.version(9), None);
    }

    #[test]
    /// Nodes 1 and 2 share a version, elect a leader and commit a change. Node 3 runs another
    /// version: its frames pass authentication but are dropped, so it learns no leader and applies
    /// nothing. Each side still records the other's version.
    fn nodes_with_a_different_version_are_kept_out_of_the_cluster() {
        let listeners = [(); 3].map(|()| TcpListener::bind("127.0.0.1:0").unwrap());
        let addresses = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap());

        let ids: Vec<NodeId> = vec![1, 2, 3];
        let versions = [TEST_VERSION, TEST_VERSION, "2.0.0"];
        let seeds = [[51u8; 32], [52u8; 32], [53u8; 32]];
        let public = seeds.map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let states: Vec<_> = (0..3)
            .map(|_| Arc::new(Mutex::new(Vec::<u8>::new())))
            .collect();
        let handles: Vec<RaftHandle> = listeners
            .into_iter()
            .enumerate()
            .map(|(index, listener)| {
                let peers = ids
                    .iter()
                    .enumerate()
                    .filter(|(peer, _)| *peer != index)
                    .map(|(peer, id)| (*id, addresses[peer].to_string()))
                    .collect();
                let peer_keys = ids
                    .iter()
                    .enumerate()
                    .filter(|(peer, _)| *peer != index)
                    .map(|(peer, id)| (*id, public[peer]))
                    .collect();
                let apply_state = states[index].clone();
                RaftServer::spawn(
                    ids[index],
                    versions[index],
                    listener,
                    peers,
                    RaftNode::new(
                        ids[index],
                        ids.clone(),
                        crate::raft::Config {
                            election_base: 10,
                            heartbeat: 1,
                        },
                    ),
                    10,
                    vec![7; 32],
                    seeds[index],
                    peer_keys,
                    Box::new(move |data| {
                        lock(&apply_state).extend_from_slice(data);
                        Ok(())
                    }),
                    Box::new(|| Ok(Vec::new())),
                    Box::new(|_| Ok(())),
                )
                .unwrap()
            })
            .collect();
        let stop_all = || {
            for handle in &handles {
                handle.shutdown();
            }
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        let leader = loop {
            if let Some(leader) = handles[..2].iter().position(RaftHandle::is_leader) {
                let follower = 1 - leader;
                let settled = handles[follower].leader() == Some(ids[leader])
                    && peer_entry(&handles[leader].status_json("Native", 1), 3)
                        .contains("\"version\":\"2.0.0\"")
                    && peer_entry(&handles[follower].status_json("Native", 1), 3)
                        .contains("\"version\":\"2.0.0\"")
                    && peer_entry(&handles[2].status_json("Native", 1), ids[leader])
                        .contains("\"version\":\"1.0.0\"");
                if settled {
                    break Some(leader);
                }
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let Some(leader) = leader else {
            let views: Vec<_> = handles
                .iter()
                .map(|handle| handle.status_json("Native", 1))
                .collect();
            stop_all();
            panic!("같은 버전의 두 노드가 리더를 뽑고 서로의 버전을 알아야 합니다: {views:?}");
        };
        let follower = 1 - leader;

        let proposal = handles[leader].propose(b"change".to_vec());
        let applied = wait_for_progress(&handles[follower], Duration::from_secs(2), || {
            lock(&states[follower]).as_slice() == b"change"
        });
        let leader_view = handles[leader].status_json("Native", 1);
        let outsider_view = handles[2].status_json("Native", 1);
        let outsider_leader = handles[2].leader();
        let outsider_applied = lock(&handles[2].node).last_applied();
        let outsider_state = lock(&states[2]).clone();
        stop_all();

        assert_eq!(proposal, Ok(2));
        assert!(applied, "같은 버전의 팔로워에 적용되어야 합니다");
        assert_eq!(outsider_leader, None, "버전이 다른 노드는 리더를 모릅니다");
        assert_eq!(outsider_applied, 0);
        assert!(outsider_state.is_empty());
        assert!(
            leader_view.contains("\"version\":\"1.0.0\"},\"peers\""),
            "{leader_view}"
        );
        assert!(
            peer_entry(&leader_view, ids[follower]).contains("\"version\":\"1.0.0\""),
            "{leader_view}"
        );
        assert!(
            peer_entry(&leader_view, 3).contains("\"version\":\"2.0.0\""),
            "{leader_view}"
        );
        assert!(
            outsider_view.contains("\"version\":\"2.0.0\"},\"peers\""),
            "{outsider_view}"
        );
    }

    #[test]
    fn raft_frame_signature_rejects_impersonation() {
        let secret = [7u8; 32];
        let attacker = SigningKey::from_bytes(&[1u8; 32]);
        let victim_vk = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(attacker),
            [3u8; 32],
            77,
            TEST_VERSION,
        )
        .unwrap();
        let framed = sealer
            .frame(
                9,
                10,
                &encode_msg(&Msg::RequestVoteResp {
                    term: 1,
                    granted: true,
                }),
            )
            .unwrap();
        let body = &framed[4..];
        let sig_start = body.len() - RAFT_SIG_LEN;
        let sig: [u8; RAFT_SIG_LEN] = body[sig_start..].try_into().unwrap();

        let mut signature_input = Vec::from([3u8; 32]);
        signature_input.extend_from_slice(&body[..sig_start]);
        assert!(victim_vk
            .verify(&signature_input, &Signature::from_bytes(&sig))
            .is_err());
    }

    #[test]
    fn session_ids_preserve_the_epoch_and_randomize_the_suffix() {
        let first = new_session_id(0x0102_0304_0506_0708).expect("OS CSPRNG");
        let second = new_session_id(0x1112_1314_1516_1718).expect("OS CSPRNG");

        assert_eq!(&first[..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&second[..8], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_ne!(&first[8..], &second[8..]);
    }

    #[test]
    /// Wrapping around would let earlier frames be reused.
    fn frame_seq_exhaustion_is_permanent() {
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&[7u8; 32]).unwrap()),
            Arc::new(SigningKey::from_bytes(&[5u8; 32])),
            [3u8; 32],
            77,
            TEST_VERSION,
        )
        .unwrap();
        sealer.sequence.store(u64::MAX, Ordering::Relaxed);

        assert!(sealer.frame(1, 2, b"x").is_none());
        assert!(sealer.frame(1, 2, b"x").is_none());
    }

    #[test]
    fn oversized_entry_is_not_encoded() {
        let message = Msg::AppendEntries {
            term: 1,
            leader: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![LogEntry {
                term: 1,
                index: 1,
                data: vec![0; MAX_RAFT_ENTRY_BYTES + 1],
            }],
            leader_commit: 0,
        };
        assert!(try_encode_msg(&message).is_none());
    }

    #[test]
    fn snapshot_codec_rejects_oversized_chunks_and_non_boolean_flags() {
        let oversized = Msg::InstallSnapshot {
            term: 1,
            leader: 1,
            last_included_index: 8,
            last_included_term: 1,
            offset: 0,
            data: vec![0; SNAPSHOT_CHUNK_BYTES + 1],
            done: true,
        };
        assert!(try_encode_msg(&oversized).is_none());

        let mut invalid_done = encode_msg(&Msg::InstallSnapshot {
            term: 1,
            leader: 1,
            last_included_index: 8,
            last_included_term: 1,
            offset: 0,
            data: b"state".to_vec(),
            done: true,
        });
        invalid_done[1 + 8 * 5] = 2;
        assert_eq!(decode_msg(&invalid_done), None);

        let mut invalid_installed = encode_msg(&Msg::InstallSnapshotResp {
            term: 1,
            last_included_index: 8,
            next_offset: 5,
            installed: true,
        });
        *invalid_installed.last_mut().unwrap() = 2;
        assert_eq!(decode_msg(&invalid_installed), None);
    }

    fn replay_nonce(session: u128, sequence: u64) -> [u8; RAFT_NONCE_LEN] {
        let mut nonce = [0u8; RAFT_NONCE_LEN];
        nonce[..16].copy_from_slice(&session.to_be_bytes());
        nonce[16..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    #[test]
    fn replay_window_rejects_duplicates_old_sessions_and_evicted_sequences() {
        let mut replay = ReplayCache::default();
        assert!(replay.accept(1, replay_nonce(10, 10)));
        assert!(!replay.accept(1, replay_nonce(10, 10)));
        assert!(replay.accept(1, replay_nonce(10, 12)));
        assert!(
            replay.accept(1, replay_nonce(10, 11)),
            "윈도 안의 순서 뒤바뀜은 1회 허용"
        );
        assert!(!replay.accept(1, replay_nonce(10, 11)));
        assert!(replay.accept(1, replay_nonce(11, 0)), "새 세션 epoch 허용");
        assert!(
            !replay.accept(1, replay_nonce(10, u64::MAX)),
            "과거 세션 복귀 거부"
        );
        assert!(replay.accept(2, replay_nonce(10, 10)), "peer별 독립 윈도");

        assert!(replay.accept(3, replay_nonce(20, REPLAY_WINDOW_BITS + 5)));
        assert!(
            !replay.accept(3, replay_nonce(20, 0)),
            "윈도 밖 sequence 거부"
        );
    }

    #[test]
    fn frame_signature_binds_destination_and_cluster_context() {
        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let verifying = signing.verifying_key();
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(signing),
            [3u8; 32],
            77,
            TEST_VERSION,
        )
        .unwrap();
        let mut framed = sealer.frame(9, 10, b"message").unwrap();

        framed[4 + 9 + 7] ^= 1;
        let body = &framed[4..];
        let sig_start = body.len() - RAFT_SIG_LEN;
        let sig: [u8; RAFT_SIG_LEN] = body[sig_start..].try_into().unwrap();
        let mut signature_input = Vec::from([3u8; 32]);
        signature_input.extend_from_slice(&body[..sig_start]);
        assert!(verifying
            .verify(&signature_input, &Signature::from_bytes(&sig))
            .is_err());

        let original = sealer.frame(9, 10, b"message2").unwrap();
        let body = &original[4..];
        let sig_start = body.len() - RAFT_SIG_LEN;
        let sig: [u8; RAFT_SIG_LEN] = body[sig_start..].try_into().unwrap();
        let mut wrong_context = Vec::from([4u8; 32]);
        wrong_context.extend_from_slice(&body[..sig_start]);
        assert!(verifying
            .verify(&wrong_context, &Signature::from_bytes(&sig))
            .is_err());
    }
}
