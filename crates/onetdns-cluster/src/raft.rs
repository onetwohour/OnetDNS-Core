//! Raft consensus state machine. It does no I/O apart from persisting the state file and the
//! WAL: votes and terms must reach disk before any reply goes out, or after a restart the node
//! could vote twice in one term and the cluster could elect two leaders.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

pub type NodeId = u64;

/// The last byte versions the format.
const STATE_MAGIC: &[u8; 12] = b"ONETRAFT\0\0\0\x01";

const WAL_MAGIC: &[u8; 12] = b"ONETRAFTWAL1";

/// Magic, then a 32-byte integrity hash.
const WAL_HEADER_LEN: usize = 12 + 32;

/// A shorter frame body is truncated.
const MIN_WAL_FRAME_BODY: usize = 8 + 1 + 8 + 8 + 8 + 8 + 8 + 4;

/// Past this the WAL folds into the state file.
const MAX_WAL_BYTES: usize = 4 * 1024 * 1024;

/// Keeps a damaged file from forcing a huge allocation.
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

const MAX_LOG_ENTRIES: usize = 100_000;

/// Log length at which a snapshot is taken; small under test to exercise compaction.
#[cfg(not(test))]
pub(crate) const SNAPSHOT_LOG_THRESHOLD: u64 = 4_096;
#[cfg(test)]
pub(crate) const SNAPSHOT_LOG_THRESHOLD: u64 = 8;

/// Keeps a large snapshot from going out as one message.
pub(crate) const SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;

pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

/// Checked when an entry is proposed.
pub(crate) const MAX_ENTRY_BYTES: usize = 256 * 1024;

pub(crate) const MAX_APPEND_ENTRIES: usize = 256;

pub(crate) const MAX_APPEND_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub data: Vec<u8>,
}

/// State applied up to a point; the result of log compaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Last index the snapshot covers.
    pub index: u64,
    pub term: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    RequestVote {
        term: u64,
        candidate: NodeId,
        last_log_index: u64,
        last_log_term: u64,
    },
    RequestVoteResp {
        term: u64,
        granted: bool,
    },
    /// Replicates the log; with no entries it is a heartbeat.
    AppendEntries {
        term: u64,
        leader: NodeId,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    AppendEntriesResp {
        term: u64,
        success: bool,
        match_index: u64,
    },
    /// Sends a snapshot chunk to a follower whose next entries were compacted away.
    InstallSnapshot {
        term: u64,
        leader: NodeId,
        last_included_index: u64,
        last_included_term: u64,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    },
    /// `next_offset` tells the leader where to resume.
    InstallSnapshotResp {
        term: u64,
        last_included_index: u64,
        next_offset: u64,
        installed: bool,
    },
}

/// A message the state machine asks the caller to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub to: NodeId,
    pub msg: Msg,
}

/// Timing, in ticks. The election timeout must stay well above the heartbeat; otherwise
/// followers start elections under a healthy leader and terms climb without progress.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base election timeout; each node adds random jitter.
    pub election_base: u32,
    pub heartbeat: u32,
}

impl Default for Config {
    /// Elections take at least three heartbeats.
    fn default() -> Self {
        Self {
            election_base: 10,
            heartbeat: 3,
        }
    }
}

/// State that must survive a restart.
#[derive(Default)]
struct StableState {
    current_term: u64,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    commit_index: u64,
    last_applied: u64,

    /// Grows on every start; the transport's replay window builds on it.
    boot_counter: u64,
    snapshot: Option<Snapshot>,
}

/// Borrows the stable state without copying it.
struct StableView<'a> {
    current_term: u64,
    voted_for: Option<NodeId>,
    log: &'a [LogEntry],
    commit_index: u64,
    last_applied: u64,
    boot_counter: u64,
    snapshot: Option<&'a Snapshot>,
}

impl StableState {
    #[cfg(test)]
    fn view(&self) -> StableView<'_> {
        StableView {
            current_term: self.current_term,
            voted_for: self.voted_for,
            log: &self.log,
            commit_index: self.commit_index,
            last_applied: self.last_applied,
            boot_counter: self.boot_counter,
            snapshot: self.snapshot.as_ref(),
        }
    }
}

/// A snapshot arriving in chunks. Remembers the leader and term so chunks from different
/// snapshots never mix when the leader changes.
#[derive(Debug, Clone)]
struct IncomingSnapshot {
    leader: NodeId,
    leader_term: u64,
    index: u64,
    term: u64,
    data: Vec<u8>,
    complete: bool,
}

struct LoadedState {
    state: StableState,
    /// Hash of the state file body; the WAL frame chain starts from it.
    base_digest: Option<[u8; 32]>,

    /// WAL length that produced this state.
    wal_len: u64,
}

/// Invariant: `commit_index >= last_applied`, and committed entries are on a majority.
pub struct RaftNode {
    id: NodeId,
    /// Other nodes, not this one.
    peers: Vec<NodeId>,
    role: Role,
    current_term: u64,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    commit_index: u64,
    last_applied: u64,
    leader_id: Option<NodeId>,

    next_index: HashMap<NodeId, u64>,
    match_index: HashMap<NodeId, u64>,
    votes: HashSet<NodeId>,

    /// Ticks since the leader was last heard from.
    election_elapsed: u32,
    heartbeat_elapsed: u32,
    /// Randomized per node so nodes do not all stand at once.
    election_timeout: u32,
    rng_state: u64,
    cfg: Config,
    storage_path: Option<PathBuf>,
    /// An unrecoverable error; the node stops making progress.
    fatal: Option<String>,
    /// Boot epoch; never goes back across restarts.
    boot_counter: u64,
    snapshot: Option<Snapshot>,
    incoming_snapshot: Option<IncomingSnapshot>,
    /// How far the snapshot has been sent to each node.
    snapshot_offsets: HashMap<NodeId, u64>,
    snapshot_dirty: bool,

    /// Log length known to be on disk.
    durable_log_len: usize,

    /// Fingerprint of the current state file; WAL frames must chain from it.
    base_digest: Option<[u8; 32]>,
    /// Valid length of the WAL.
    wal_len: u64,
    wal_file: Option<File>,
}

impl RaftNode {
    /// In memory only, for tests and non-persistent setups.
    pub fn new(id: NodeId, peers: Vec<NodeId>, cfg: Config) -> Self {
        Self::from_stable(id, peers, cfg, None, StableState::default())
    }

    /// Restores the state file and WAL when present. A damaged tail is cut back to the last
    /// complete frame: accepting a half-written frame would corrupt the log.
    pub fn new_persistent(
        id: NodeId,
        peers: Vec<NodeId>,
        cfg: Config,
        storage_path: PathBuf,
    ) -> Result<Self, String> {
        let loaded = load_state(&storage_path)?;
        let durable_log_len = loaded.state.log.len();
        let mut node = Self::from_stable(id, peers, cfg, Some(storage_path), loaded.state);
        node.durable_log_len = durable_log_len;
        node.base_digest = loaded.base_digest;
        node.wal_len = loaded.wal_len;
        Ok(node)
    }

    fn from_stable(
        id: NodeId,
        mut peers: Vec<NodeId>,
        cfg: Config,
        storage_path: Option<PathBuf>,
        stable: StableState,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);

        peers.retain(|peer| *peer != id);
        peers.sort_unstable();
        peers.dedup();
        let mut node = Self {
            id,
            peers,
            role: Role::Follower,
            current_term: stable.current_term,
            voted_for: stable.voted_for,
            log: stable.log,
            commit_index: stable.commit_index,
            last_applied: stable.last_applied,
            leader_id: None,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            votes: HashSet::new(),
            election_elapsed: 0,
            heartbeat_elapsed: 0,
            election_timeout: 0,
            rng_state: now ^ id.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15,
            cfg,
            storage_path,
            fatal: None,
            boot_counter: stable.boot_counter,
            snapshot: stable.snapshot,
            incoming_snapshot: None,
            snapshot_offsets: HashMap::new(),
            snapshot_dirty: false,
            durable_log_len: 0,
            base_digest: None,
            wal_len: 0,
            wal_file: None,
        };
        node.reset_election_timeout();
        node
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    /// The longest election timeout: a follower that hears nothing from the leader for this
    /// long always starts an election. Peer liveness checks use the same bound so the two never
    /// disagree.
    pub fn election_timeout_ceiling(&self) -> u32 {
        self.cfg.election_base.max(2).saturating_mul(2)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn term(&self) -> u64 {
        self.current_term
    }

    /// `None` during an election.
    pub fn leader(&self) -> Option<NodeId> {
        self.leader_id
    }

    /// After full compaction, the snapshot index.
    pub fn last_index(&self) -> u64 {
        self.log.last().map_or_else(
            || self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index),
            |entry| entry.index,
        )
    }

    pub fn commit_index(&self) -> u64 {
        self.commit_index
    }

    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }

    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// 0 without a snapshot.
    pub fn snapshot_index(&self) -> u64 {
        self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index)
    }

    /// Log entries left after compaction.
    pub fn retained_log_len(&self) -> usize {
        self.log.len()
    }

    /// Whether entries applied since the snapshot passed the threshold.
    pub fn snapshot_due(&self) -> bool {
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        self.last_applied.saturating_sub(base) >= SNAPSHOT_LOG_THRESHOLD
    }

    /// Entries applied since the snapshot; the caller builds the next snapshot from them.
    pub fn applied_entries_after_snapshot(&self) -> Vec<LogEntry> {
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        let count = usize::try_from(self.last_applied.saturating_sub(base))
            .unwrap_or(usize::MAX)
            .min(self.log.len());
        self.log[..count].to_vec()
    }

    /// Compacts the log into `data`, the caller's snapshot of the applied state. The snapshot point
    /// must be applied already: compacting past it would drop entries that were never applied.
    pub fn compact(&mut self, data: Vec<u8>) -> Result<(), String> {
        if data.is_empty() || data.len() > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "Raft snapshot size must be 1..={MAX_SNAPSHOT_BYTES} bytes"
            ));
        }
        let previous = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        let included_index = self.last_applied;
        if included_index <= previous || included_index > self.commit_index {
            return Err("Raft snapshot index is outside the applied range".into());
        }
        let included_term = self.term_at(included_index);
        if included_term == 0 {
            return Err("Could not find the term at the Raft snapshot index".into());
        }
        let remove = usize::try_from(included_index - previous)
            .map_err(|_| "Could not compute the Raft snapshot log range")?;
        if remove > self.log.len() {
            return Err("Raft snapshot log range is outside the retained log".into());
        }
        self.log.drain(..remove);
        self.snapshot = Some(Snapshot {
            index: included_index,
            term: included_term,
            data,
        });
        self.snapshot_offsets.clear();
        self.durable_log_len = 0;
        self.snapshot_dirty = true;
        if !self.persist() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "Could not save the Raft snapshot to disk".into()));
        }
        Ok(())
    }

    /// False under a fatal error even in the leader role: a leader that cannot persist would lose
    /// what it committed on restart.
    pub fn is_leader(&self) -> bool {
        self.role == Role::Leader && self.fatal.is_none()
    }

    pub fn fatal_error(&self) -> Option<&str> {
        self.fatal.as_deref()
    }

    /// Called when persistence fails. Continuing would break Raft's safety, so this node drops out
    /// and the rest form the quorum.
    pub fn fail_stop(&mut self, error: impl Into<String>) {
        let error = error.into();
        onetdns_core::error!(
            event = "raft.fail_stop",
            node = self.id,
            term = self.current_term,
            error = %error,
            "Stopping the Raft node on an unrecoverable error"
        );
        self.fatal = Some(error);
        self.role = Role::Follower;
        self.leader_id = None;
    }

    /// A majority of the nodes, this one included.
    fn quorum(&self) -> usize {
        self.peers.len().div_ceil(2) + 1
    }

    /// Election jitter only; not for cryptography.
    fn next_random(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x == 0 {
            x = 0xa076_1d64_78bd_642f ^ self.id;
        }
        self.rng_state = x;
        x
    }

    /// The jitter is required: nodes that start elections together split the vote, and terms climb
    /// without a leader.
    fn reset_election_timeout(&mut self) {
        let base = self.cfg.election_base.max(2);
        let jitter = (self.next_random() % u64::from(base)) as u32;
        self.election_timeout = base.saturating_add(jitter).max(2);
        self.election_elapsed = 0;
    }

    /// 0 for a compacted index, meaning unknown.
    fn term_at(&self, index: u64) -> u64 {
        if index == 0 {
            return 0;
        }
        if let Some(snapshot) = &self.snapshot {
            if index == snapshot.index {
                return snapshot.term;
            }
            if index < snapshot.index {
                return 0;
            }
        }
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        usize::try_from(index.saturating_sub(base).saturating_sub(1))
            .ok()
            .and_then(|offset| self.log.get(offset))
            .map_or(0, |entry| entry.term)
    }

    pub fn entry_term(&self, index: u64) -> u64 {
        self.term_at(index)
    }

    /// After full compaction this is the snapshot term; returning 0 would let a node that missed
    /// committed entries win this node's vote.
    fn last_log_term(&self) -> u64 {
        self.term_at(self.last_index())
    }

    /// On failure stops the node and returns false: a node that cannot keep its state must not
    /// take part.
    fn persist(&mut self) -> bool {
        let Some(path) = self.storage_path.clone() else {
            return true;
        };
        if let Err(error) = self.persist_at(&path) {
            self.fail_stop(format!("Could not save Raft state to disk: {error}"));
            return false;
        }
        true
    }

    fn stable_view(&self) -> StableView<'_> {
        StableView {
            current_term: self.current_term,
            voted_for: self.voted_for,
            log: &self.log,
            commit_index: self.commit_index,
            last_applied: self.last_applied,
            boot_counter: self.boot_counter,
            snapshot: self.snapshot.as_ref(),
        }
    }

    /// Appends the change to the WAL, or rewrites the whole state file once the WAL is over budget
    /// or the snapshot changed. Rewriting the full log every time would cost in proportion to its
    /// length.
    fn persist_at(&mut self, path: &Path) -> Result<(), String> {
        let truncate_to = self.durable_log_len.min(self.log.len());
        let frame = encode_wal_frame(&self.stable_view(), truncate_to)?;
        let compact = self.snapshot_dirty
            || self.base_digest.is_none()
            || self.wal_len.saturating_add(frame.len() as u64) > MAX_WAL_BYTES as u64;
        if compact {
            self.wal_file = None;
            let digest = store_state(path, &self.stable_view())?;

            reset_wal(&wal_path(path), &digest)?;
            self.wal_len = WAL_HEADER_LEN as u64;
            self.base_digest = Some(digest);
            self.snapshot_dirty = false;
        } else {
            self.append_wal_frame(path, &frame)?;
        }
        self.durable_log_len = self.log.len();
        Ok(())
    }

    /// Cuts the file back to the known length first, dropping a half frame left by a crash before
    /// fsync.
    fn append_wal_frame(&mut self, path: &Path, frame: &[u8]) -> Result<(), String> {
        let wal = wal_path(path);
        if self.wal_file.is_none() {
            if self.wal_len < WAL_HEADER_LEN as u64 {
                let digest = self
                    .base_digest
                    .ok_or("Creating the Raft log file needs the fingerprint of the base state")?;
                reset_wal(&wal, &digest)?;
                self.wal_len = WAL_HEADER_LEN as u64;
            }

            let on_disk = fs::metadata(&wal)
                .map_err(|error| format!("Could not read Raft WAL metadata: {error}"))?
                .len();
            if on_disk > self.wal_len {
                let repair = OpenOptions::new()
                    .write(true)
                    .open(&wal)
                    .map_err(|error| format!("Could not open the Raft WAL: {error}"))?;
                repair.set_len(self.wal_len).map_err(|error| {
                    format!("Could not truncate the end of the Raft WAL: {error}")
                })?;
                repair.sync_all().map_err(|error| {
                    format!("Could not fsync the Raft WAL after truncation: {error}")
                })?;
            }
            let file = OpenOptions::new()
                .append(true)
                .open(&wal)
                .map_err(|error| format!("Could not open the Raft WAL for appending: {error}"))?;
            self.wal_file = Some(file);
        }
        let file = self.wal_file.as_mut().ok_or("No Raft WAL file handle")?;
        let write = file
            .write_all(frame)
            .map_err(|error| format!("Could not write the Raft WAL: {error}"))
            .and_then(|()| {
                file.sync_all()
                    .map_err(|error| format!("Could not fsync the Raft WAL: {error}"))
            });
        if let Err(error) = write {
            self.wal_file = None;
            return Err(error);
        }
        self.wal_len = self.wal_len.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// The transport's replay window keys on this number; it must never go back across restarts,
    /// or frames from an old session would be accepted again.
    pub fn next_boot_session(&mut self) -> Result<u64, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let next = self
            .boot_counter
            .max(now)
            .checked_add(1)
            .ok_or("Raft session counter overflowed")?;
        self.boot_counter = next;
        if !self.persist() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "Could not save the Raft session counter to disk".into()));
        }
        Ok(next)
    }

    /// Counts heartbeat or election time. The caller ticks at a fixed interval; the state machine
    /// never reads the clock.
    pub fn tick(&mut self) -> Vec<Output> {
        if self.fatal.is_some() {
            return Vec::new();
        }
        match self.role {
            Role::Leader => {
                self.heartbeat_elapsed = self.heartbeat_elapsed.saturating_add(1);
                if self.heartbeat_elapsed >= self.cfg.heartbeat.max(1) {
                    self.heartbeat_elapsed = 0;
                    self.broadcast_append()
                } else {
                    Vec::new()
                }
            }
            Role::Follower | Role::Candidate => {
                self.election_elapsed = self.election_elapsed.saturating_add(1);
                if self.election_elapsed >= self.election_timeout {
                    self.start_election()
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Persists the new term and self-vote before asking: otherwise a restarted node could vote for
    /// another candidate in the same term.
    fn start_election(&mut self) -> Vec<Output> {
        let Some(next_term) = self.current_term.checked_add(1) else {
            self.fail_stop("Raft term overflowed");
            return Vec::new();
        };
        self.current_term = next_term;
        self.role = Role::Candidate;
        onetdns_core::info!(
            event = "raft.election_started",
            node = self.id,
            term = self.current_term,
            "Starting Raft leader election"
        );
        self.voted_for = Some(self.id);
        self.leader_id = None;
        self.votes.clear();
        self.votes.insert(self.id);
        self.reset_election_timeout();
        if !self.persist() {
            return Vec::new();
        }

        if self.quorum() == 1 {
            self.become_leader();
            return self.broadcast_append();
        }
        let msg = Msg::RequestVote {
            term: self.current_term,
            candidate: self.id,
            last_log_index: self.last_index(),
            last_log_term: self.last_log_term(),
        };
        self.peers
            .iter()
            .map(|peer| Output {
                to: *peer,
                msg: msg.clone(),
            })
            .collect()
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        onetdns_core::info!(
            event = "raft.leader_elected",
            node = self.id,
            term = self.current_term,
            "Elected Raft leader"
        );
        self.leader_id = Some(self.id);
        self.heartbeat_elapsed = self.cfg.heartbeat.max(1);
        if self.log.len() >= MAX_LOG_ENTRIES {
            self.fail_stop("The Raft log limit prevents writing the leader no-op entry");
            return;
        }
        let Some(noop_index) = self.last_index().checked_add(1) else {
            self.fail_stop("Raft leader no-op index overflowed");
            return;
        };

        self.log.push(LogEntry {
            term: self.current_term,
            index: noop_index,
            data: Vec::new(),
        });
        self.advance_commit();
        if !self.persist() {
            return;
        }
        let next = self.last_index().saturating_add(1);
        self.next_index.clear();
        self.match_index.clear();
        self.snapshot_offsets.clear();
        for peer in &self.peers {
            self.next_index.insert(*peer, next);
            self.match_index.insert(*peer, 0);
        }
    }

    /// Heartbeats when there is nothing to send.
    fn broadcast_append(&self) -> Vec<Output> {
        self.peers
            .iter()
            .map(|peer| self.append_for(*peer))
            .collect()
    }

    /// Falls back to a snapshot when the follower needs compacted entries. Caps entries and bytes
    /// per message so catching up a lagging follower does not build a huge one.
    fn append_for(&self, peer: NodeId) -> Output {
        let next = self.next_index.get(&peer).copied().unwrap_or(1);
        if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| next <= snapshot.index)
        {
            return self.snapshot_for(peer);
        }
        let prev_log_index = next.saturating_sub(1);
        let prev_log_term = self.term_at(prev_log_index);
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        for entry in self.log.iter().filter(|entry| entry.index >= next) {
            let encoded = 8usize
                .saturating_add(8)
                .saturating_add(4)
                .saturating_add(entry.data.len());
            if !entries.is_empty()
                && (entries.len() >= MAX_APPEND_ENTRIES
                    || bytes.saturating_add(encoded) > MAX_APPEND_BYTES)
            {
                break;
            }
            if encoded > MAX_APPEND_BYTES {
                break;
            }
            bytes = bytes.saturating_add(encoded);
            entries.push(entry.clone());
        }
        Output {
            to: peer,
            msg: Msg::AppendEntries {
                term: self.current_term,
                leader: self.id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit: self.commit_index,
            },
        }
    }

    /// Tracks progress per node.
    fn snapshot_for(&self, peer: NodeId) -> Output {
        let snapshot = self
            .snapshot
            .as_ref()
            .expect("A snapshot exists for replication before the snapshot index");
        let requested = self.snapshot_offsets.get(&peer).copied().unwrap_or(0);
        let offset = usize::try_from(requested)
            .ok()
            .filter(|offset| *offset <= snapshot.data.len())
            .unwrap_or(0);
        let end = offset
            .saturating_add(SNAPSHOT_CHUNK_BYTES)
            .min(snapshot.data.len());
        Output {
            to: peer,
            msg: Msg::InstallSnapshot {
                term: self.current_term,
                leader: self.id,
                last_included_index: snapshot.index,
                last_included_term: snapshot.term,
                offset: offset as u64,
                data: snapshot.data[offset..end].to_vec(),
                done: end == snapshot.data.len(),
            },
        }
    }

    /// Replicates now instead of waiting for the next heartbeat.
    pub fn force_replicate(&mut self) -> Vec<Output> {
        if self.is_leader() {
            self.heartbeat_elapsed = 0;
            self.broadcast_append()
        } else {
            Vec::new()
        }
    }

    /// Leader only. Returns the assigned index.
    pub fn propose(&mut self, data: Vec<u8>) -> Result<u64, String> {
        Ok(self.propose_batch(vec![data])?[0])
    }

    /// Persists once for the whole batch: an fsync per entry ties throughput to disk latency.
    /// Rejects the whole batch if any entry is over the limit, so a caller never has to guess how
    /// much went in.
    pub fn propose_batch(&mut self, entries: Vec<Vec<u8>>) -> Result<Vec<u64>, String> {
        if !self.is_leader() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "This node is not the leader".to_string()));
        }
        if entries.is_empty() || entries.len() > MAX_APPEND_ENTRIES {
            return Err(format!(
                "A Raft proposal batch must have 1..={MAX_APPEND_ENTRIES} entries"
            ));
        }
        if entries
            .iter()
            .any(|data| data.is_empty() || data.len() > MAX_ENTRY_BYTES)
        {
            return Err(format!("A Raft entry must be 1..={MAX_ENTRY_BYTES} bytes"));
        }
        let encoded_bytes = entries.iter().fold(0usize, |total, data| {
            total
                .saturating_add(8)
                .saturating_add(8)
                .saturating_add(4)
                .saturating_add(data.len())
        });
        if encoded_bytes > MAX_APPEND_BYTES {
            return Err(format!(
                "The encoded size of a Raft proposal batch must be at most {MAX_APPEND_BYTES} bytes"
            ));
        }
        if self.log.len().saturating_add(entries.len()) > MAX_LOG_ENTRIES {
            return Err(
                "Raft log limit reached; a snapshot or operator compaction is needed".into(),
            );
        }
        let first_index = self
            .last_index()
            .checked_add(1)
            .ok_or_else(|| "Raft log index overflowed".to_string())?;
        let last_offset = u64::try_from(entries.len() - 1)
            .map_err(|_| "Raft proposal batch size overflowed".to_string())?;
        first_index
            .checked_add(last_offset)
            .ok_or_else(|| "Raft log index overflowed".to_string())?;

        let mut indexes = Vec::with_capacity(entries.len());
        for (offset, data) in entries.into_iter().enumerate() {
            let index = first_index + offset as u64;
            indexes.push(index);
            self.log.push(LogEntry {
                term: self.current_term,
                index,
                data,
            });
        }
        self.advance_commit();
        if !self.persist() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "Could not save Raft state to disk".into()));
        }
        Ok(indexes)
    }

    /// `from` is the sender the transport authenticated; a message naming another leader or
    /// candidate is refused, or any node could impersonate the leader. A higher term turns this
    /// node into a follower, which is also how a partitioned old leader steps down.
    pub fn step(&mut self, from: NodeId, msg: Msg) -> Vec<Output> {
        if self.fatal.is_some() || !self.peers.contains(&from) {
            return Vec::new();
        }
        if matches!(&msg, Msg::RequestVote { candidate, .. } if *candidate != from)
            || matches!(&msg, Msg::AppendEntries { leader, .. } if *leader != from)
            || matches!(&msg, Msg::InstallSnapshot { leader, .. } if *leader != from)
        {
            return Vec::new();
        }
        let msg_term = match &msg {
            Msg::RequestVote { term, .. }
            | Msg::RequestVoteResp { term, .. }
            | Msg::AppendEntries { term, .. }
            | Msg::AppendEntriesResp { term, .. }
            | Msg::InstallSnapshot { term, .. }
            | Msg::InstallSnapshotResp { term, .. } => *term,
        };
        if msg_term > self.current_term {
            if self.role == Role::Leader {
                onetdns_core::warn!(
                    event = "raft.stepped_down",
                    node = self.id,
                    term = msg_term,
                    "Saw a higher term; stepping down as Raft leader"
                );
            }
            self.current_term = msg_term;
            self.role = Role::Follower;
            self.voted_for = None;
            self.leader_id = None;
            self.incoming_snapshot = None;
            self.reset_election_timeout();
            if !self.persist() {
                return Vec::new();
            }
        }

        match msg {
            Msg::RequestVote {
                term,
                candidate,
                last_log_index,
                last_log_term,
            } => self.handle_request_vote(term, candidate, last_log_index, last_log_term),
            Msg::RequestVoteResp { term, granted } => self.handle_vote_resp(from, term, granted),
            Msg::AppendEntries {
                term,
                leader,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => self.handle_append(
                term,
                leader,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            ),
            Msg::AppendEntriesResp {
                term,
                success,
                match_index,
            } => self.handle_append_resp(from, term, success, match_index),
            Msg::InstallSnapshot {
                term,
                leader,
                last_included_index,
                last_included_term,
                offset,
                data,
                done,
            } => self.handle_install_snapshot(
                term,
                leader,
                last_included_index,
                last_included_term,
                offset,
                data,
                done,
            ),
            Msg::InstallSnapshotResp {
                term,
                last_included_index,
                next_offset,
                installed,
            } => self.handle_install_snapshot_resp(
                from,
                term,
                last_included_index,
                next_offset,
                installed,
            ),
        }
    }

    /// Votes only for a candidate whose log is at least as up to date; this keeps committed entries
    /// from being lost.
    fn handle_request_vote(
        &mut self,
        term: u64,
        candidate: NodeId,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Vec<Output> {
        let mut granted = false;
        if term == self.current_term
            && self.voted_for.is_none_or(|voted| voted == candidate)
            && log_up_to_date(
                last_log_term,
                last_log_index,
                self.last_log_term(),
                self.last_index(),
            )
        {
            granted = true;
            self.voted_for = Some(candidate);
            self.reset_election_timeout();
            if !self.persist() {
                return Vec::new();
            }
        }
        vec![Output {
            to: candidate,
            msg: Msg::RequestVoteResp {
                term: self.current_term,
                granted,
            },
        }]
    }

    fn handle_vote_resp(&mut self, from: NodeId, term: u64, granted: bool) -> Vec<Output> {
        if self.role != Role::Candidate || term != self.current_term {
            return Vec::new();
        }
        if granted {
            self.votes.insert(from);
            if self.votes.len() >= self.quorum() {
                self.become_leader();
                return self.broadcast_append();
            }
        }
        Vec::new()
    }

    #[allow(clippy::too_many_arguments)]
    /// Accepts only when the previous index and term match this log; otherwise the leader steps
    /// back to find where they agree. Conflicting entries after that point are cut; only
    /// uncommitted entries can conflict.
    fn handle_append(
        &mut self,
        term: u64,
        leader: NodeId,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    ) -> Vec<Output> {
        if term < self.current_term {
            return vec![self.append_response(leader, false, self.last_index())];
        }
        if term != self.current_term || entries.len() > MAX_APPEND_ENTRIES {
            return vec![self.append_response(leader, false, self.last_index())];
        }
        if entries
            .iter()
            .any(|entry| entry.data.len() > MAX_ENTRY_BYTES)
            || entries.iter().fold(0usize, |total, entry| {
                total.saturating_add(entry.data.len())
            }) > MAX_APPEND_BYTES
        {
            return vec![self.append_response(leader, false, self.last_index())];
        }
        if self.leader_id != Some(leader) {
            onetdns_core::info!(
                event = "raft.leader_observed",
                node = self.id,
                leader = leader,
                term = self.current_term,
                "Confirmed Raft leader"
            );
        }
        if self
            .incoming_snapshot
            .as_ref()
            .is_some_and(|incoming| incoming.leader != leader || incoming.leader_term != term)
        {
            self.incoming_snapshot = None;
        }
        self.role = Role::Follower;
        self.leader_id = Some(leader);
        self.reset_election_timeout();

        if prev_log_index > self.last_index() || self.term_at(prev_log_index) != prev_log_term {
            return vec![self.append_response(leader, false, self.last_index())];
        }
        let mut expected = prev_log_index.saturating_add(1);
        for entry in &entries {
            if entry.index != expected {
                return vec![self.append_response(leader, false, self.last_index())];
            }
            expected = expected.saturating_add(1);
        }

        let mut log_changed = false;
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        for entry in entries.iter().cloned() {
            let Some(relative) = entry.index.checked_sub(base.saturating_add(1)) else {
                return vec![self.append_response(leader, false, self.last_index())];
            };
            let Ok(offset) = usize::try_from(relative) else {
                return vec![self.append_response(leader, false, self.last_index())];
            };
            if offset < self.log.len() {
                if self.log[offset].term != entry.term || self.log[offset].data != entry.data {
                    if entry.index <= self.commit_index {
                        self.fail_stop(format!(
                            "Raft committed log rewrite attempt at index {}",
                            entry.index
                        ));
                        return Vec::new();
                    }
                    self.log.truncate(offset);

                    self.durable_log_len = self.durable_log_len.min(offset);
                    self.log.push(entry);
                    log_changed = true;
                }
            } else if offset == self.log.len() {
                self.log.push(entry);
                log_changed = true;
            } else {
                return vec![self.append_response(leader, false, self.last_index())];
            }
        }
        if self.log.len() > MAX_LOG_ENTRIES {
            self.fail_stop("Too many Raft log entries");
            return Vec::new();
        }
        if leader_commit > self.commit_index {
            self.commit_index = leader_commit.min(self.last_index());
        }

        if log_changed && !self.persist() {
            return Vec::new();
        }
        let last_new = entries.last().map_or(prev_log_index, |entry| entry.index);
        vec![self.append_response(leader, true, last_new)]
    }

    fn append_response(&self, leader: NodeId, success: bool, match_index: u64) -> Output {
        Output {
            to: leader,
            msg: Msg::AppendEntriesResp {
                term: self.current_term,
                success,
                match_index,
            },
        }
    }

    /// On success moves the follower's progress forward and recomputes the commit index.
    fn handle_append_resp(
        &mut self,
        from: NodeId,
        term: u64,
        success: bool,
        match_index: u64,
    ) -> Vec<Output> {
        if self.role != Role::Leader || term != self.current_term {
            return Vec::new();
        }
        if success {
            let bounded = match_index
                .min(self.last_index())
                .max(self.match_index.get(&from).copied().unwrap_or(0));
            self.match_index.insert(from, bounded);
            self.next_index.insert(from, bounded.saturating_add(1));
            self.advance_commit();
            if bounded < self.last_index() {
                vec![self.append_for(from)]
            } else {
                Vec::new()
            }
        } else {
            let next = self.next_index.get(&from).copied().unwrap_or(1);

            let fallback = next.saturating_sub(1).max(1);
            let hinted = match_index.saturating_add(1).max(1);
            self.next_index.insert(from, fallback.min(hinted));
            vec![self.append_for(from)]
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Refuses a chunk at any offset but the expected one, and checks the total size: writing at
    /// any offset would let mixed chunks inject a chosen state.
    fn handle_install_snapshot(
        &mut self,
        term: u64,
        leader: NodeId,
        last_included_index: u64,
        last_included_term: u64,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    ) -> Vec<Output> {
        if term != self.current_term
            || last_included_index == 0
            || last_included_term == 0
            || data.len() > SNAPSHOT_CHUNK_BYTES
        {
            return vec![self.snapshot_response(leader, last_included_index, 0, false)];
        }
        self.role = Role::Follower;
        self.leader_id = Some(leader);
        self.reset_election_timeout();

        if last_included_index <= self.last_applied {
            self.incoming_snapshot = None;
            return vec![self.snapshot_response(leader, last_included_index, 0, true)];
        }

        let same = self.incoming_snapshot.as_ref().is_some_and(|incoming| {
            incoming.leader == leader
                && incoming.leader_term == term
                && incoming.index == last_included_index
                && incoming.term == last_included_term
        });
        if !same {
            if offset != 0 {
                self.incoming_snapshot = None;
                return vec![self.snapshot_response(leader, last_included_index, 0, false)];
            }
            self.incoming_snapshot = Some(IncomingSnapshot {
                leader,
                leader_term: term,
                index: last_included_index,
                term: last_included_term,
                data: Vec::new(),
                complete: false,
            });
        }

        let incoming = self
            .incoming_snapshot
            .as_mut()
            .expect("The same snapshot receive state was created");
        let expected = incoming.data.len() as u64;
        if offset < expected {
            let Ok(start) = usize::try_from(offset) else {
                self.incoming_snapshot = None;
                return vec![self.snapshot_response(leader, last_included_index, 0, false)];
            };
            let end = start.saturating_add(data.len());
            if incoming.data.get(start..end) != Some(data.as_slice()) {
                self.incoming_snapshot = None;
                return vec![self.snapshot_response(leader, last_included_index, 0, false)];
            }
            return vec![self.snapshot_response(leader, last_included_index, expected, false)];
        }
        if offset != expected
            || (data.is_empty() && !(done && offset > 0))
            || incoming.data.len().saturating_add(data.len()) > MAX_SNAPSHOT_BYTES
        {
            return vec![self.snapshot_response(leader, last_included_index, expected, false)];
        }
        incoming.data.extend_from_slice(&data);
        incoming.complete = done;
        let received = incoming.data.len() as u64;
        if done {
            Vec::new()
        } else {
            vec![self.snapshot_response(leader, last_included_index, received, false)]
        }
    }

    fn snapshot_response(
        &self,
        leader: NodeId,
        last_included_index: u64,
        next_offset: u64,
        installed: bool,
    ) -> Output {
        Output {
            to: leader,
            msg: Msg::InstallSnapshotResp {
                term: self.current_term,
                last_included_index,
                next_offset,
                installed,
            },
        }
    }

    /// Fully received but not yet applied; the caller applies it and then reports back.
    pub fn pending_snapshot(&self) -> Option<Snapshot> {
        self.incoming_snapshot
            .as_ref()
            .filter(|incoming| {
                incoming.complete
                    && incoming.leader_term == self.current_term
                    && self.leader_id == Some(incoming.leader)
            })
            .map(|incoming| Snapshot {
                index: incoming.index,
                term: incoming.term,
                data: incoming.data.clone(),
            })
    }

    /// Discards the log up to the snapshot and moves the applied index only now: moving them before
    /// the caller applies the snapshot would leave it unapplied after a crash.
    pub fn finish_snapshot_install(&mut self, index: u64) -> Result<Output, String> {
        let incoming = self
            .incoming_snapshot
            .as_ref()
            .filter(|incoming| {
                incoming.complete
                    && incoming.index == index
                    && incoming.leader_term == self.current_term
                    && self.leader_id == Some(incoming.leader)
            })
            .cloned()
            .ok_or_else(|| "No completed Raft snapshot receive state".to_string())?;

        let retain_suffix = self.term_at(incoming.index) == incoming.term;
        let old_base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        if retain_suffix {
            let remove = usize::try_from(incoming.index.saturating_sub(old_base))
                .map_err(|_| "Could not compute the Raft snapshot suffix range")?;
            if remove <= self.log.len() {
                self.log.drain(..remove);
            } else {
                self.log.clear();
            }
        } else {
            self.log.clear();
        }
        self.snapshot = Some(Snapshot {
            index: incoming.index,
            term: incoming.term,
            data: incoming.data,
        });
        self.commit_index = self.commit_index.max(incoming.index);
        self.last_applied = incoming.index;
        self.durable_log_len = 0;
        self.snapshot_dirty = true;
        if !self.persist() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "Could not save the Raft snapshot install state".into()));
        }
        self.incoming_snapshot = None;
        Ok(self.snapshot_response(incoming.leader, incoming.index, 0, true))
    }

    fn handle_install_snapshot_resp(
        &mut self,
        from: NodeId,
        term: u64,
        last_included_index: u64,
        next_offset: u64,
        installed: bool,
    ) -> Vec<Output> {
        if self.role != Role::Leader || term != self.current_term {
            return Vec::new();
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            return Vec::new();
        };
        if snapshot.index != last_included_index {
            return Vec::new();
        }
        if installed {
            self.snapshot_offsets.remove(&from);
            let bounded = last_included_index
                .min(self.last_index())
                .max(self.match_index.get(&from).copied().unwrap_or(0));
            self.match_index.insert(from, bounded);
            self.next_index.insert(from, bounded.saturating_add(1));
            self.advance_commit();
            return (bounded < self.last_index())
                .then(|| self.append_for(from))
                .into_iter()
                .collect();
        }

        let offset = usize::try_from(next_offset)
            .ok()
            .filter(|offset| *offset <= snapshot.data.len())
            .unwrap_or(0);
        self.snapshot_offsets.insert(from, offset as u64);
        vec![self.snapshot_for(from)]
    }

    /// Only an entry from the current term commits by count: counting replicas of an older term's
    /// entry can commit something a later leader overwrites.
    fn advance_commit(&mut self) {
        for index in (self.commit_index.saturating_add(1)..=self.last_index()).rev() {
            if self.term_at(index) != self.current_term {
                continue;
            }
            let replicated = 1 + self
                .peers
                .iter()
                .filter(|peer| self.match_index.get(peer).copied().unwrap_or(0) >= index)
                .count();
            if replicated >= self.quorum() {
                self.commit_index = index;
                break;
            }
        }
    }

    pub fn next_committed(&self) -> Option<LogEntry> {
        if self.last_applied >= self.commit_index {
            return None;
        }
        let index = self.last_applied.checked_add(1)?;
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        usize::try_from(index.checked_sub(base)?.checked_sub(1)?)
            .ok()
            .and_then(|offset| self.log.get(offset))
            .cloned()
    }

    pub fn next_committed_batch(&self, limit: usize) -> Vec<LogEntry> {
        if limit == 0 || self.last_applied >= self.commit_index {
            return Vec::new();
        }
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        let Ok(start) = usize::try_from(self.last_applied.saturating_sub(base)) else {
            return Vec::new();
        };
        let committed = self.commit_index - self.last_applied;
        let count = usize::try_from(committed).unwrap_or(usize::MAX).min(limit);
        self.log
            .get(start..start.saturating_add(count))
            .unwrap_or_default()
            .to_vec()
    }

    pub fn mark_applied(&mut self, index: u64) -> Result<(), String> {
        self.mark_applied_batch(index, index)
    }

    /// Persists once for the range.
    pub fn mark_applied_batch(&mut self, first: u64, last: u64) -> Result<(), String> {
        if first != self.last_applied.saturating_add(1) || last < first || last > self.commit_index
        {
            return Err("Raft applied index went backwards".into());
        }
        self.last_applied = last;
        if !self.persist() {
            return Err(self
                .fatal
                .clone()
                .unwrap_or_else(|| "Could not save Raft state to disk".into()));
        }
        Ok(())
    }
}

/// Compares terms first, then length; the other order would call a short log with a newer term
/// out of date.
fn log_up_to_date(candidate_term: u64, candidate_index: u64, my_term: u64, my_index: u64) -> bool {
    candidate_term > my_term || (candidate_term == my_term && candidate_index >= my_index)
}

fn encode_state(state: &StableView) -> Result<Vec<u8>, String> {
    let snapshot_index = state.snapshot.map_or(0, |snapshot| snapshot.index);
    let snapshot_term = state.snapshot.map_or(0, |snapshot| snapshot.term);
    let snapshot_data = state
        .snapshot
        .map_or_else(|| [].as_slice(), |snapshot| snapshot.data.as_slice());
    let Some(last_index) = snapshot_index.checked_add(state.log.len() as u64) else {
        return Err("Raft persistent state log index is out of range".into());
    };
    if state.log.len() > MAX_LOG_ENTRIES
        || state.commit_index > last_index
        || state.last_applied < snapshot_index
        || snapshot_data.len() > MAX_SNAPSHOT_BYTES
        || (snapshot_index == 0) != snapshot_data.is_empty()
        || (snapshot_index == 0) != (snapshot_term == 0)
    {
        return Err("Raft persistent state has an invalid value range".into());
    }
    if state.last_applied > state.commit_index {
        return Err("The last applied Raft log index is greater than the committed index".into());
    }
    let mut out = Vec::new();
    out.extend_from_slice(STATE_MAGIC);
    out.extend_from_slice(&state.current_term.to_be_bytes());
    match state.voted_for {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id.to_be_bytes());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&0u64.to_be_bytes());
        }
    }
    out.extend_from_slice(&state.commit_index.to_be_bytes());
    out.extend_from_slice(&state.last_applied.to_be_bytes());
    out.extend_from_slice(&state.boot_counter.to_be_bytes());
    out.extend_from_slice(&snapshot_index.to_be_bytes());
    out.extend_from_slice(&snapshot_term.to_be_bytes());
    out.extend_from_slice(&(snapshot_data.len() as u32).to_be_bytes());
    out.extend_from_slice(snapshot_data);
    out.extend_from_slice(&(state.log.len() as u32).to_be_bytes());
    for (position, entry) in state.log.iter().enumerate() {
        let expected = snapshot_index + position as u64 + 1;
        if entry.index != expected || entry.data.len() > MAX_ENTRY_BYTES {
            return Err("Invalid Raft log index or entry size".into());
        }
        out.extend_from_slice(&entry.term.to_be_bytes());
        out.extend_from_slice(&entry.index.to_be_bytes());
        out.extend_from_slice(&(entry.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&entry.data);
        if out.len() > MAX_STATE_BYTES.saturating_sub(32) {
            return Err("Raft state file exceeds the size limit".into());
        }
    }
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

/// Treats the file as untrusted: every length is checked against a cap, so a damaged or edited
/// file cannot force a huge allocation or a panic.
fn decode_state(bytes: &[u8]) -> Result<StableState, String> {
    if bytes.len() < STATE_MAGIC.len() + 8 + 9 + 8 + 8 + 8 + 8 + 8 + 4 + 4 + 32
        || bytes.len() > MAX_STATE_BYTES
    {
        return Err("Invalid Raft state file size".into());
    }
    let (body, stored_digest) = bytes.split_at(bytes.len() - 32);
    let actual = Sha256::digest(body);
    if actual.as_slice() != stored_digest {
        return Err("Raft state file checksum mismatch".into());
    }
    let mut pos = 0usize;
    if body.get(..STATE_MAGIC.len()) != Some(STATE_MAGIC.as_slice()) {
        return Err(
            "Raft state file identifier or version does not match the current format".into(),
        );
    }
    pos += STATE_MAGIC.len();
    let current_term = take_u64(body, &mut pos)?;
    let vote_flag = *body.get(pos).ok_or("Raft vote state is missing")?;
    pos += 1;
    let vote_id = take_u64(body, &mut pos)?;
    let voted_for = match vote_flag {
        0 => None,
        1 => Some(vote_id),
        _ => return Err("Invalid Raft vote state".into()),
    };
    let commit_index = take_u64(body, &mut pos)?;
    let last_applied = take_u64(body, &mut pos)?;
    let boot_counter = take_u64(body, &mut pos)?;
    let snapshot_index = take_u64(body, &mut pos)?;
    let snapshot_term = take_u64(body, &mut pos)?;
    let snapshot_len = take_u32(body, &mut pos)? as usize;
    if snapshot_len > MAX_SNAPSHOT_BYTES
        || (snapshot_index == 0) != (snapshot_len == 0)
        || (snapshot_index == 0) != (snapshot_term == 0)
    {
        return Err("Malformed Raft snapshot".into());
    }
    let snapshot_end = pos
        .checked_add(snapshot_len)
        .ok_or("Could not compute the Raft snapshot length")?;
    let snapshot_data = body
        .get(pos..snapshot_end)
        .ok_or("Raft snapshot data is truncated")?
        .to_vec();
    pos = snapshot_end;
    let count = take_u32(body, &mut pos)? as usize;
    if count > MAX_LOG_ENTRIES {
        return Err("Raft log entry exceeds the size limit".into());
    }
    let mut log = Vec::with_capacity(count.min(4096));
    for position in 0..count {
        let term = take_u64(body, &mut pos)?;
        let index = take_u64(body, &mut pos)?;
        let len = take_u32(body, &mut pos)? as usize;
        if index != snapshot_index + position as u64 + 1 || len > MAX_ENTRY_BYTES {
            return Err("Malformed Raft log".into());
        }
        let end = pos
            .checked_add(len)
            .ok_or("Could not compute the Raft log entry length")?;
        let data = body
            .get(pos..end)
            .ok_or("Raft log data is truncated")?
            .to_vec();
        pos = end;
        log.push(LogEntry { term, index, data });
    }
    let last_index = snapshot_index
        .checked_add(count as u64)
        .ok_or("Last Raft log index is out of range")?;
    if pos != body.len()
        || commit_index > last_index
        || last_applied > commit_index
        || last_applied < snapshot_index
    {
        return Err("Raft state file has trailing data or an out-of-range value".into());
    }
    Ok(StableState {
        current_term,
        voted_for,
        log,
        commit_index,
        last_applied,
        boot_counter,
        snapshot: (snapshot_index != 0).then_some(Snapshot {
            index: snapshot_index,
            term: snapshot_term,
            data: snapshot_data,
        }),
    })
}

fn take_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let end = pos
        .checked_add(8)
        .ok_or("Could not compute where to read a 64-bit value in the Raft state file")?;
    let slice = bytes.get(*pos..end).ok_or("Raft state data is truncated")?;
    *pos = end;
    Ok(u64::from_be_bytes(slice.try_into().map_err(|_| {
        "Malformed 64-bit value in the Raft state file"
    })?))
}

fn take_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, String> {
    let end = pos
        .checked_add(4)
        .ok_or("Could not compute where to read a 32-bit value in the Raft state file")?;
    let slice = bytes.get(*pos..end).ok_or("Raft state data is truncated")?;
    *pos = end;
    Ok(u32::from_be_bytes(slice.try_into().map_err(|_| {
        "Malformed 32-bit value in the Raft state file"
    })?))
}

fn wal_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("raft.state");
    path.with_file_name(format!("{name}.wal"))
}

/// Only entries past `truncate_to` go into the frame; the rest are already written.
fn encode_wal_frame(state: &StableView, truncate_to: usize) -> Result<Vec<u8>, String> {
    if truncate_to > state.log.len() || state.log.len() > MAX_LOG_ENTRIES {
        return Err("Invalid Raft WAL frame range".into());
    }
    let mut body = Vec::new();
    body.extend_from_slice(&state.current_term.to_be_bytes());
    match state.voted_for {
        Some(id) => {
            body.push(1);
            body.extend_from_slice(&id.to_be_bytes());
        }
        None => {
            body.push(0);
            body.extend_from_slice(&0u64.to_be_bytes());
        }
    }
    body.extend_from_slice(&state.commit_index.to_be_bytes());
    body.extend_from_slice(&state.last_applied.to_be_bytes());
    body.extend_from_slice(&state.boot_counter.to_be_bytes());
    body.extend_from_slice(&(truncate_to as u64).to_be_bytes());
    let entries = &state.log[truncate_to..];
    let snapshot_index = state.snapshot.map_or(0, |snapshot| snapshot.index);
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (position, entry) in entries.iter().enumerate() {
        let expected = snapshot_index + truncate_to as u64 + position as u64 + 1;
        if entry.index != expected || entry.data.len() > MAX_ENTRY_BYTES {
            return Err("Invalid Raft WAL entry index or size".into());
        }
        body.extend_from_slice(&entry.term.to_be_bytes());
        body.extend_from_slice(&entry.index.to_be_bytes());
        body.extend_from_slice(&(entry.data.len() as u32).to_be_bytes());
        body.extend_from_slice(&entry.data);
    }
    let mut out = Vec::with_capacity(4 + body.len() + 32);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&Sha256::digest(&body));
    Ok(out)
}

/// Called in order while restoring.
fn apply_wal_frame(state: &mut StableState, body: &[u8]) -> Result<(), String> {
    let mut pos = 0usize;
    let current_term = take_u64(body, &mut pos)?;
    let vote_flag = *body.get(pos).ok_or("Raft WAL vote state is missing")?;
    pos += 1;
    let vote_id = take_u64(body, &mut pos)?;
    let voted_for = match vote_flag {
        0 => None,
        1 => Some(vote_id),
        _ => return Err("Invalid vote state in the Raft log file".into()),
    };
    let commit_index = take_u64(body, &mut pos)?;
    let last_applied = take_u64(body, &mut pos)?;
    let boot_counter = take_u64(body, &mut pos)?;
    let truncate_to = take_u64(body, &mut pos)? as usize;
    let count = take_u32(body, &mut pos)? as usize;

    if current_term < state.current_term
        || commit_index < state.commit_index
        || last_applied < state.last_applied
        || last_applied > commit_index
        || boot_counter < state.boot_counter
    {
        return Err("Raft WAL is not monotonic".into());
    }

    if current_term == state.current_term {
        if let Some(prev) = state.voted_for {
            if voted_for != Some(prev) {
                return Err("Raft WAL changed the vote within the same term".into());
            }
        }
    }
    let snapshot_index = state.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
    let truncate_index = snapshot_index.saturating_add(truncate_to as u64);
    if truncate_to > state.log.len() || truncate_index < state.commit_index {
        return Err("Invalid Raft WAL truncate range".into());
    }
    let final_len = truncate_to
        .checked_add(count)
        .ok_or("Raft WAL log length overflowed")?;
    let final_index = snapshot_index
        .checked_add(final_len as u64)
        .ok_or("Last Raft WAL log index is out of range")?;
    if final_len > MAX_LOG_ENTRIES || commit_index > final_index || last_applied < snapshot_index {
        return Err("Invalid Raft WAL log range".into());
    }
    state.log.truncate(truncate_to);
    for position in 0..count {
        let term = take_u64(body, &mut pos)?;
        let index = take_u64(body, &mut pos)?;
        let len = take_u32(body, &mut pos)? as usize;
        if index != snapshot_index + truncate_to as u64 + position as u64 + 1
            || len > MAX_ENTRY_BYTES
        {
            return Err("Malformed Raft WAL entry".into());
        }
        let end = pos.checked_add(len).ok_or("Raft WAL length overflowed")?;
        let data = body
            .get(pos..end)
            .ok_or("Raft WAL data is truncated")?
            .to_vec();
        pos = end;
        state.log.push(LogEntry { term, index, data });
    }
    if pos != body.len() {
        return Err("Trailing data remains at the end of the Raft log file".into());
    }
    state.current_term = current_term;
    state.voted_for = voted_for;
    state.commit_index = commit_index;
    state.last_applied = last_applied;
    state.boot_counter = boot_counter;
    Ok(())
}

/// Each frame carries the hash of everything before it. Replay stops where the chain breaks and
/// keeps what came before, which drops partial and forged frames. A WAL whose chain does not
/// start at `base_digest` belongs to another state file and is ignored. Returns the valid length;
/// the caller cuts the rest.
fn load_wal(path: &Path, base_digest: &[u8; 32], state: &mut StableState) -> Result<u64, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("Could not open {}: {error}", path.display())),
    };
    let len = file
        .metadata()
        .map_err(|error| format!("Could not read Raft WAL metadata: {error}"))?
        .len();
    if len > MAX_WAL_BYTES as u64 {
        return Err("Raft WAL file is too large".into());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_WAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read the Raft WAL: {error}"))?;

    if bytes.len() < WAL_HEADER_LEN || &bytes[..WAL_MAGIC.len()] != WAL_MAGIC {
        return Err("Raft WAL header is corrupted".into());
    }
    if &bytes[WAL_MAGIC.len()..WAL_HEADER_LEN] != base_digest {
        return Ok(0);
    }
    let mut pos = WAL_HEADER_LEN;
    let mut valid = pos as u64;
    while pos < bytes.len() {
        let length_end = pos
            .checked_add(4)
            .ok_or("Raft WAL frame length offset overflowed")?;
        let Some(len_bytes) = bytes.get(pos..length_end) else {
            break;
        };
        let body_len =
            u32::from_be_bytes(len_bytes.try_into().map_err(|_| "Raft WAL length")?) as usize;
        if !(MIN_WAL_FRAME_BODY..=MAX_WAL_BYTES).contains(&body_len) {
            return Err("Invalid Raft WAL frame length".into());
        }
        let body_start = length_end;
        let digest_start = body_start
            .checked_add(body_len)
            .ok_or("Raft WAL frame end overflowed")?;
        let frame_end = digest_start
            .checked_add(32)
            .ok_or("Raft WAL checksum end overflowed")?;
        let Some(body) = bytes.get(body_start..digest_start) else {
            break;
        };
        let Some(digest) = bytes.get(digest_start..frame_end) else {
            break;
        };
        if Sha256::digest(body).as_slice() != digest {
            if frame_end < bytes.len() {
                return Err("Checksum mismatch in a middle Raft WAL frame".into());
            }
            break;
        }
        apply_wal_frame(state, body)?;
        pos = frame_end;
        valid = pos as u64;
    }
    Ok(valid)
}

fn load_state(path: &Path) -> Result<LoadedState, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LoadedState {
                state: StableState::default(),
                base_digest: None,
                wal_len: 0,
            })
        }
        Err(error) => return Err(format!("Could not open {}: {error}", path.display())),
    };
    let len = file
        .metadata()
        .map_err(|error| format!("Could not read Raft state file metadata: {error}"))?
        .len();
    if len > MAX_STATE_BYTES as u64 {
        return Err("Raft state file exceeds the size limit".into());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read the Raft state file: {error}"))?;
    let mut state = decode_state(&bytes)?;
    let base_digest: [u8; 32] = bytes[bytes.len() - 32..]
        .try_into()
        .map_err(|_| "Invalid hash length in the Raft state file")?;
    let wal_len = load_wal(&wal_path(path), &base_digest, &mut state)?;
    Ok(LoadedState {
        state,
        base_digest: Some(base_digest),
        wal_len,
    })
}

fn reset_wal(path: &Path, base_digest: &[u8; 32]) -> Result<(), String> {
    let mut header = Vec::with_capacity(WAL_HEADER_LEN);
    header.extend_from_slice(WAL_MAGIC);
    header.extend_from_slice(base_digest);
    write_state_file_atomic(path, &header)
}

/// Returns the hash of what it wrote; the WAL chain restarts from it.
fn store_state(path: &Path, state: &StableView) -> Result<[u8; 32], String> {
    let bytes = encode_state(state)?;
    let digest: [u8; 32] = bytes[bytes.len() - 32..]
        .try_into()
        .map_err(|_| "Invalid hash length in the Raft state file")?;
    write_state_file_atomic(path, &bytes)?;
    Ok(digest)
}

/// A bare file name has an empty parent rather than none; an empty path cannot be opened for the
/// directory fsync, so it becomes the current directory.
fn state_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Writes a private temporary file, fsyncs it and renames it over `path`: writing in place could
/// leave a half-written state file that keeps the node from starting. The directory fsync makes
/// the rename durable.
fn write_state_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = state_parent(path);
    fs::create_dir_all(parent).map_err(|error| {
        format!("Could not create the directory for the Raft state file: {error}")
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Invalid Raft state file name".to_string())?;
    let nonce = u64::from_le_bytes(onetdns_core::random_array::<8>());
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{nonce:016x}",
        std::process::id()
    ));
    let write_result = (|| -> Result<(), String> {
        let mut file =
            onetdns_core::fs::open_private(&tmp, onetdns_core::fs::PrivateOpen::CreateNew)
                .map_err(|error| {
                    format!("Could not open a temporary file for Raft state: {error}")
                })?;
        file.write_all(bytes)
            .map_err(|error| format!("Could not write the Raft state file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Could not sync the Raft state file to disk: {error}"))?;
        drop(file);
        replace_state_file(&tmp, path).map_err(|error| {
            format!("Could not atomically replace the Raft state file: {error}")
        })?;
        sync_state_parent(parent)
            .map_err(|error| format!("Could not sync the Raft state directory to disk: {error}"))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

#[cfg(unix)]
/// Fsyncs the parent directory so the rename is durable.
fn sync_state_parent(parent: &Path) -> std::io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_state_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_state_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn replace_state_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

#[cfg(windows)]
/// Returns once the move reached the disk.
fn replace_state_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(once(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(once(0)).collect();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_parent_of_bare_file_name_is_current_dir() {
        assert_eq!(
            state_parent(Path::new("n1.toml.raft-1.state")),
            Path::new(".")
        );
        assert_eq!(
            state_parent(Path::new("dir/n1.toml.raft-1.state")),
            Path::new("dir")
        );
        assert!(sync_state_parent(state_parent(Path::new("bare.state"))).is_ok());
    }

    struct Cluster {
        nodes: Vec<RaftNode>,
    }

    impl Cluster {
        fn new(count: u64) -> Self {
            let ids: Vec<u64> = (1..=count).collect();
            Self {
                nodes: ids
                    .iter()
                    .map(|id| RaftNode::new(*id, ids.clone(), Config::default()))
                    .collect(),
            }
        }

        fn idx(&self, id: NodeId) -> usize {
            (id - 1) as usize
        }

        fn step_all(&mut self, dropped: &HashSet<NodeId>) {
            let mut queue = Vec::new();
            for node in &mut self.nodes {
                if !dropped.contains(&node.id()) {
                    queue.extend(node.tick().into_iter().map(|out| (node.id(), out)));
                }
            }
            for _ in 0..100 {
                if queue.is_empty() {
                    break;
                }
                let mut next = Vec::new();
                for (from, output) in queue.drain(..) {
                    if dropped.contains(&from) || dropped.contains(&output.to) {
                        continue;
                    }
                    let index = self.idx(output.to);
                    next.extend(
                        self.nodes[index]
                            .step(from, output.msg)
                            .into_iter()
                            .map(|out| (output.to, out)),
                    );
                }
                queue = next;
            }
        }

        fn leader(&self) -> Option<NodeId> {
            let leaders: Vec<_> = self
                .nodes
                .iter()
                .filter(|node| node.is_leader())
                .map(RaftNode::id)
                .collect();
            if leaders.len() == 1 {
                Some(leaders[0])
            } else {
                None
            }
        }

        fn step_partitioned(&mut self, groups: &[Vec<NodeId>]) {
            let group_of = |id: NodeId| groups.iter().position(|g| g.contains(&id));
            let mut queue = Vec::new();
            for node in &mut self.nodes {
                queue.extend(node.tick().into_iter().map(|out| (node.id(), out)));
            }
            for _ in 0..100 {
                if queue.is_empty() {
                    break;
                }
                let mut next = Vec::new();
                for (from, output) in queue.drain(..) {
                    if group_of(from) != group_of(output.to) {
                        continue;
                    }
                    let index = self.idx(output.to);
                    next.extend(
                        self.nodes[index]
                            .step(from, output.msg)
                            .into_iter()
                            .map(|out| (output.to, out)),
                    );
                }
                queue = next;
            }
        }

        fn node(&self, id: NodeId) -> &RaftNode {
            &self.nodes[self.idx(id)]
        }

        fn node_mut(&mut self, id: NodeId) -> &mut RaftNode {
            let index = self.idx(id);
            &mut self.nodes[index]
        }

        fn leaders_in(&self, ids: &[NodeId]) -> Vec<NodeId> {
            ids.iter()
                .copied()
                .filter(|id| self.node(*id).is_leader())
                .collect()
        }
    }

    #[test]
    /// A minority committing would give two answers.
    fn minority_partition_cannot_commit_and_converges_after_heal() {
        let mut cluster = Cluster::new(5);
        let dropped = HashSet::new();
        for _ in 0..200 {
            cluster.step_all(&dropped);
            if cluster.leader().is_some() {
                break;
            }
        }
        let old_leader = cluster.leader().expect("초기 리더 선출");

        let all: Vec<NodeId> = (1..=5).collect();
        let mut minority = vec![old_leader];
        let companion = all
            .iter()
            .copied()
            .find(|id| *id != old_leader)
            .expect("동반 노드");
        minority.push(companion);
        let majority: Vec<NodeId> = all
            .iter()
            .copied()
            .filter(|id| !minority.contains(id))
            .collect();
        let groups = vec![minority.clone(), majority.clone()];

        let committed_before = cluster.node(old_leader).commit_index();
        let term_before = cluster.node(old_leader).term();

        let _ = cluster.node_mut(old_leader).propose(b"minority".to_vec());
        for _ in 0..200 {
            cluster.step_partitioned(&groups);
        }
        assert_eq!(
            cluster.node(old_leader).commit_index(),
            committed_before,
            "소수파는 커밋을 전진시킬 수 없다"
        );

        let new_leaders = cluster.leaders_in(&majority);
        assert_eq!(new_leaders.len(), 1, "다수파에 리더 1명");
        let new_leader = new_leaders[0];
        assert!(
            cluster.node(new_leader).term() > term_before,
            "새 리더의 term은 분단 이전보다 높다"
        );
        cluster
            .node_mut(new_leader)
            .propose(b"majority".to_vec())
            .expect("다수파 제안");
        for _ in 0..200 {
            cluster.step_partitioned(&groups);
        }
        let majority_committed = cluster.node(new_leader).commit_index();
        assert!(
            majority_committed > committed_before,
            "다수파는 커밋을 전진시킨다"
        );

        for _ in 0..400 {
            cluster.step_all(&dropped);
        }
        assert!(
            !cluster.node(old_leader).is_leader(),
            "이전 리더는 치유 후 강등된다"
        );
        assert_eq!(cluster.leaders_in(&all).len(), 1, "치유 후 리더는 1명뿐");
        assert!(
            cluster.node(old_leader).commit_index() >= majority_committed,
            "이전 리더가 다수파 커밋을 따라잡는다"
        );
    }

    #[test]
    fn elects_and_replicates_in_batches() {
        let mut cluster = Cluster::new(3);
        let dropped = HashSet::new();
        for _ in 0..100 {
            cluster.step_all(&dropped);
            if cluster.leader().is_some() {
                break;
            }
        }
        let leader = cluster.leader().expect("리더 선출");
        let leader_index = cluster.idx(leader);
        for n in 0..600 {
            cluster.nodes[leader_index]
                .propose(format!("entry-{n}").into_bytes())
                .unwrap();
        }
        for _ in 0..100 {
            cluster.step_all(&dropped);
        }
        for node in &cluster.nodes {
            assert_eq!(node.last_index(), 601);
            assert_eq!(node.commit_index(), 601);
        }
    }

    #[test]
    fn applied_index_only_moves_after_mark() {
        let mut node = RaftNode::new(1, vec![1], Config::default());
        for _ in 0..20 {
            node.tick();
        }
        assert!(node.next_committed().unwrap().data.is_empty());
        node.mark_applied(1).unwrap();
        node.propose(b"x".to_vec()).unwrap();
        assert_eq!(node.next_committed().unwrap().data, b"x");
        assert_eq!(node.last_applied(), 1);
        node.mark_applied(2).unwrap();
        assert_eq!(node.last_applied(), 2);
    }

    #[test]
    fn proposal_batch_appends_contiguous_entries_atomically() {
        let mut node = RaftNode::new(1, vec![1], Config::default());
        for _ in 0..20 {
            node.tick();
        }
        node.mark_applied(1).unwrap();

        let indexes = node
            .propose_batch(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()])
            .unwrap();
        assert_eq!(indexes, vec![2, 3, 4]);
        let committed = node.next_committed_batch(8);
        assert_eq!(committed.len(), 3);
        for (entry, (index, expected)) in committed
            .iter()
            .zip(indexes.into_iter().zip([b"a", b"b", b"c"]))
        {
            assert_eq!(entry.index, index);
            assert_eq!(entry.data, expected);
        }
        node.mark_applied_batch(2, 4).unwrap();
        assert_eq!(node.last_applied(), 4);
        assert!(node.mark_applied_batch(6, 6).is_err());

        let before = node.last_index();
        assert!(node
            .propose_batch(vec![b"valid".to_vec(), Vec::new()])
            .is_err());
        assert_eq!(node.last_index(), before);
    }

    #[test]
    /// Otherwise the inherited entry would never commit.
    fn new_leader_noop_commits_inherited_entry_without_client_proposal() {
        let mut candidate = RaftNode::new(1, vec![1, 2, 3], Config::default());
        candidate.current_term = 1;
        candidate.log.push(LogEntry {
            term: 1,
            index: 1,
            data: b"inherited".to_vec(),
        });
        let mut voter = RaftNode::new(2, vec![1, 2, 3], Config::default());

        let request = candidate
            .start_election()
            .into_iter()
            .find(|output| output.to == 2)
            .unwrap();
        let vote = voter.step(1, request.msg).pop().unwrap();
        let mut queue: Vec<(NodeId, Output)> = candidate
            .step(2, vote.msg)
            .into_iter()
            .map(|output| (1, output))
            .filter(|(_, output)| output.to == 2)
            .collect();
        for _ in 0..10 {
            let Some((from, output)) = queue.pop() else {
                break;
            };
            let responses = if output.to == 2 {
                voter.step(from, output.msg)
            } else {
                candidate.step(from, output.msg)
            };
            let sender = output.to;
            queue.extend(
                responses
                    .into_iter()
                    .map(|response| (sender, response))
                    .filter(|(_, response)| response.to == 1 || response.to == 2),
            );
        }

        assert!(candidate.is_leader());
        assert_eq!(candidate.last_index(), 2);
        assert_eq!(candidate.commit_index(), 2);
        assert_eq!(candidate.next_committed().unwrap().data, b"inherited");
        candidate.mark_applied(1).unwrap();
        assert!(candidate.next_committed().unwrap().data.is_empty());
    }

    #[test]
    fn stable_state_roundtrip_and_checksum() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"persisted".to_vec()).unwrap();
        node.mark_applied(1).unwrap();
        node.mark_applied(2).unwrap();
        drop(node);
        let restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(restored.last_index(), 2);
        assert_eq!(restored.last_applied(), 2);
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(RaftNode::new_persistent(1, vec![1], Config::default(), path).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn state_and_log_files_are_readable_only_by_the_owner() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-access-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"persisted".to_vec()).unwrap();
        drop(node);
        for file in [path.clone(), wal_path(&path)] {
            #[cfg(windows)]
            assert_eq!(
                onetdns_core::fs::access_rules(&file).unwrap(),
                "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&file).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{}", file.display());
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn boot_session_is_monotonic_and_survives_restart() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-boot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        let first = node.next_boot_session().unwrap();
        drop(node);
        let mut restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        let second = restored.next_boot_session().unwrap();

        assert!(
            second > first,
            "재시작 후 세션 카운터는 반드시 증가: {first} -> {second}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn commit_only_progress_is_recovered_from_the_leader_after_restart() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-commit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1, 2], Config::default(), path.clone()).unwrap();
        let append = Msg::AppendEntries {
            term: 1,
            leader: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![LogEntry {
                term: 1,
                index: 1,
                data: b"change".to_vec(),
            }],
            leader_commit: 0,
        };
        assert!(matches!(
            node.step(2, append).as_slice(),
            [Output {
                msg: Msg::AppendEntriesResp { success: true, .. },
                ..
            }]
        ));
        let commit = Msg::AppendEntries {
            term: 1,
            leader: 2,
            prev_log_index: 1,
            prev_log_term: 1,
            entries: Vec::new(),
            leader_commit: 1,
        };
        node.step(2, commit.clone());
        assert_eq!(node.commit_index(), 1);
        drop(node);

        let mut restored =
            RaftNode::new_persistent(1, vec![1, 2], Config::default(), path.clone()).unwrap();
        assert_eq!(
            restored.last_index(),
            1,
            "ACK한 로그는 재시작 후에도 남는다"
        );
        assert_eq!(restored.commit_index(), 0, "commit-only 진전은 재통지된다");
        restored.step(2, commit);
        assert_eq!(restored.next_committed().unwrap().data, b"change");
        restored.mark_applied(1).unwrap();
        drop(restored);

        let applied =
            RaftNode::new_persistent(1, vec![1, 2], Config::default(), path.clone()).unwrap();
        assert_eq!(applied.commit_index(), 1);
        assert_eq!(applied.last_applied(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wal_appends_without_rewriting_base() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-wal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"one".to_vec()).unwrap();
        let base_snapshot = fs::read(&path).unwrap();
        let wal = wal_path(&path);
        let wal_before = fs::metadata(&wal).unwrap().len();
        node.propose(b"two".to_vec()).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            base_snapshot,
            "append 경로는 베이스를 재기록하지 않는다"
        );
        assert!(fs::metadata(&wal).unwrap().len() > wal_before);
        drop(node);
        let restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(restored.last_index(), 3);
        assert_eq!(restored.commit_index(), 3);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wal_replays_conflict_truncation() {
        let dir =
            std::env::temp_dir().join(format!("onetdns-raft-conflict-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1, 2, 3], Config::default(), path.clone()).unwrap();
        node.step(
            2,
            Msg::AppendEntries {
                term: 1,
                leader: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![LogEntry {
                    term: 1,
                    index: 1,
                    data: b"old".to_vec(),
                }],
                leader_commit: 0,
            },
        );
        node.step(
            3,
            Msg::AppendEntries {
                term: 2,
                leader: 3,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![LogEntry {
                    term: 2,
                    index: 1,
                    data: b"new".to_vec(),
                }],
                leader_commit: 1,
            },
        );
        drop(node);
        let mut restored =
            RaftNode::new_persistent(1, vec![1, 2, 3], Config::default(), path).unwrap();
        assert_eq!(restored.last_index(), 1);
        let committed = restored.next_committed().expect("committed entry");
        assert_eq!(committed.data, b"new", "충돌로 덮인 항목이 재생돼야 한다");
        restored.mark_applied(committed.index).unwrap();
        assert!(restored.next_committed().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wal_compacts_when_over_budget() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-compact-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        let big = vec![0xAB_u8; 200 * 1024];
        for _ in 0..25 {
            node.propose(big.clone()).unwrap();
        }
        let wal_len = fs::metadata(wal_path(&path)).unwrap().len();
        assert!(
            wal_len <= MAX_WAL_BYTES as u64,
            "컴팩션이 WAL을 상한 아래로 유지해야 한다: {wal_len}"
        );
        drop(node);
        let restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(restored.last_index(), 26);
        assert_eq!(restored.commit_index(), 26);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn state_machine_snapshot_compacts_prefix_and_survives_restart() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-raft-state-snapshot-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("raft.state");

        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        assert!(node.is_leader());
        node.mark_applied(1).unwrap();
        for value in [b"one".as_slice(), b"two", b"three"] {
            let index = node.propose(value.to_vec()).unwrap();
            node.mark_applied(index).unwrap();
        }
        let included_index = node.last_applied();
        let included_term = node.entry_term(included_index);
        node.compact(b"materialized-config".to_vec()).unwrap();

        assert_eq!(node.snapshot().unwrap().index, included_index);
        assert_eq!(node.snapshot().unwrap().term, included_term);
        assert_eq!(
            node.retained_log_len(),
            0,
            "적용된 접두사는 메모리에서 제거"
        );
        assert_eq!(node.last_index(), included_index, "절대 index는 유지");

        let next = node.propose(b"after-snapshot".to_vec()).unwrap();
        assert_eq!(next, included_index + 1);
        node.mark_applied(next).unwrap();
        drop(node);

        let restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        let snapshot = restored.snapshot().expect("스냅샷 영속 복구");
        assert_eq!(snapshot.index, included_index);
        assert_eq!(snapshot.term, included_term);
        assert_eq!(snapshot.data, b"materialized-config");
        assert_eq!(restored.last_index(), next);
        assert_eq!(restored.entry_term(included_index), included_term);
        assert_eq!(restored.entry_term(next), restored.term());
        assert_eq!(
            restored.applied_entries_after_snapshot()[0].data,
            b"after-snapshot"
        );

        let _ = fs::remove_dir_all(dir);
    }

    /// Ticks until the node starts an election and returns its vote request.
    fn tick_until_vote_request(node: &mut RaftNode) -> Msg {
        for _ in 0..=node.election_timeout_ceiling() {
            if let Some(output) = node
                .tick()
                .into_iter()
                .find(|output| matches!(output.msg, Msg::RequestVote { .. }))
            {
                return output.msg;
            }
        }
        panic!("선거 타임아웃 안에 투표 요청을 보내지 않았다");
    }

    #[test]
    /// Otherwise a node that missed committed entries could win the compacted node's vote and lead
    /// without them, while the compacted node, though more up to date, could not win.
    fn compacted_nodes_compare_logs_by_snapshot_term() {
        let mut cluster = Cluster::new(3);
        let mut dropped = HashSet::new();
        for _ in 0..200 {
            cluster.step_all(&dropped);
            if cluster.leader().is_some() {
                break;
            }
        }
        let leader = cluster.leader().expect("리더 선출");
        for _ in 0..20 {
            cluster.step_all(&dropped);
        }
        let lagging = (1..=3).find(|id| *id != leader).expect("뒤처질 노드");
        let follower = (1..=3)
            .find(|id| *id != leader && *id != lagging)
            .expect("따라가는 노드");
        assert!(
            cluster.node(lagging).last_index() >= 1,
            "뒤처질 노드도 새 리더의 첫 항목은 받았다"
        );

        dropped.insert(lagging);
        for value in [b"one".as_slice(), b"two", b"three"] {
            cluster.node_mut(leader).propose(value.to_vec()).unwrap();
        }
        for _ in 0..20 {
            cluster.step_all(&dropped);
        }
        for id in [leader, follower] {
            let node = cluster.node_mut(id);
            let committed = node.commit_index();
            assert_eq!(
                node.last_index(),
                committed,
                "다수파는 모든 항목을 커밋했다"
            );
            node.mark_applied_batch(node.last_applied() + 1, committed)
                .unwrap();
            node.compact(b"state".to_vec()).unwrap();
            assert_eq!(node.retained_log_len(), 0, "적용한 항목을 모두 압축했다");
        }
        assert!(cluster.node(lagging).last_index() < cluster.node(follower).last_index());

        let stale_request = tick_until_vote_request(cluster.node_mut(lagging));
        let replies = cluster.node_mut(follower).step(lagging, stale_request);
        assert!(
            matches!(
                replies.as_slice(),
                [Output {
                    msg: Msg::RequestVoteResp { granted: false, .. },
                    ..
                }]
            ),
            "커밋된 항목을 놓친 후보에게 표를 주면 안 된다: {replies:?}"
        );

        let request = tick_until_vote_request(cluster.node_mut(follower));
        let replies = cluster.node_mut(lagging).step(follower, request);
        assert!(
            matches!(
                replies.as_slice(),
                [Output {
                    msg: Msg::RequestVoteResp { granted: true, .. },
                    ..
                }]
            ),
            "압축한 노드도 로그가 더 최신이면 표를 받아야 한다: {replies:?}"
        );
    }

    #[test]
    fn restarted_compacted_node_requests_votes_with_snapshot_term() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-raft-compacted-restart-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("raft.state");

        let mut node =
            RaftNode::new_persistent(1, vec![1, 2, 3], Config::default(), path.clone()).unwrap();
        node.current_term = 3;
        node.log = (1..=4)
            .map(|index| LogEntry {
                term: 3,
                index,
                data: vec![index as u8],
            })
            .collect();
        node.commit_index = 4;
        node.last_applied = 4;
        node.compact(b"state".to_vec()).unwrap();
        drop(node);

        let mut restored =
            RaftNode::new_persistent(1, vec![1, 2, 3], Config::default(), path).unwrap();
        assert_eq!(
            restored.retained_log_len(),
            0,
            "압축한 항목은 다시 읽지 않는다"
        );
        let request = tick_until_vote_request(&mut restored);
        assert!(
            matches!(
                request,
                Msg::RequestVote {
                    last_log_index: 4,
                    last_log_term: 3,
                    ..
                }
            ),
            "투표 요청에 스냅숏의 위치와 임기가 실려야 한다: {request:?}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn lagging_follower_installs_chunked_snapshot_before_log_suffix() {
        let mut leader = RaftNode::new(1, vec![1, 2], Config::default());
        leader.current_term = 3;
        leader.role = Role::Leader;
        leader.leader_id = Some(1);
        leader.log = (1..=4)
            .map(|index| LogEntry {
                term: 3,
                index,
                data: vec![index as u8],
            })
            .collect();
        leader.commit_index = 4;
        leader.last_applied = 3;
        let snapshot_data = vec![0x5a; SNAPSHOT_CHUNK_BYTES * 2 + 17];
        leader.compact(snapshot_data.clone()).unwrap();
        leader.next_index.insert(2, 1);
        leader.match_index.insert(2, 0);

        let mut follower = RaftNode::new(2, vec![1, 2], Config::default());
        let mut outbound = vec![leader.append_for(2)];
        let mut installed = false;
        for _ in 0..16 {
            let mut next = Vec::new();
            for output in outbound {
                assert_eq!(output.to, 2);
                let responses = follower.step(1, output.msg);
                if let Some(snapshot) = follower.pending_snapshot() {
                    assert_eq!(snapshot.data, snapshot_data);
                    let response = follower
                        .finish_snapshot_install(snapshot.index)
                        .expect("상태머신 적용 뒤 설치 완료 ACK");
                    next.extend(leader.step(2, response.msg));
                    installed = true;
                }
                for response in responses {
                    next.extend(leader.step(2, response.msg));
                }
            }
            outbound = next;
            if installed
                && follower.last_index() == leader.last_index()
                && follower.commit_index() == leader.commit_index()
            {
                break;
            }
        }

        assert!(installed, "로그가 잘린 follower에는 InstallSnapshot이 필요");
        assert_eq!(follower.snapshot().unwrap().index, 3);
        assert_eq!(follower.snapshot().unwrap().data, snapshot_data);
        assert_eq!(follower.last_index(), 4, "스냅샷 뒤 로그 suffix도 복제");
        assert_eq!(follower.commit_index(), 4);
        assert_eq!(follower.entry_term(4), 3);
    }

    #[test]
    /// Mixing chunks from two snapshots would corrupt the state.
    fn pending_snapshot_is_discarded_when_a_new_term_leader_arrives() {
        let mut follower = RaftNode::new(2, vec![1, 2, 3], Config::default());
        let responses = follower.step(
            1,
            Msg::InstallSnapshot {
                term: 1,
                leader: 1,
                last_included_index: 10,
                last_included_term: 1,
                offset: 0,
                data: b"old-leader-state".to_vec(),
                done: true,
            },
        );
        assert!(responses.is_empty(), "상태머신 설치 전에는 ACK하지 않음");
        assert!(follower.pending_snapshot().is_some());

        follower.step(
            3,
            Msg::AppendEntries {
                term: 2,
                leader: 3,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: Vec::new(),
                leader_commit: 0,
            },
        );

        assert!(follower.pending_snapshot().is_none());
        assert!(follower.finish_snapshot_install(10).is_err());
        assert_eq!(follower.term(), 2);
        assert_eq!(follower.leader(), Some(3));
    }

    #[test]
    fn snapshot_receiver_rejects_out_of_order_and_over_budget_chunks() {
        let mut follower = RaftNode::new(2, vec![1, 2], Config::default());
        let out_of_order = follower.step(
            1,
            Msg::InstallSnapshot {
                term: 1,
                leader: 1,
                last_included_index: 10,
                last_included_term: 1,
                offset: 1,
                data: vec![1],
                done: false,
            },
        );
        assert!(matches!(
            out_of_order.first().map(|output| &output.msg),
            Some(Msg::InstallSnapshotResp {
                next_offset: 0,
                installed: false,
                ..
            })
        ));
        assert!(follower.incoming_snapshot.is_none());

        for chunk in 0..(MAX_SNAPSHOT_BYTES / SNAPSHOT_CHUNK_BYTES) {
            let offset = chunk * SNAPSHOT_CHUNK_BYTES;
            let responses = follower.step(
                1,
                Msg::InstallSnapshot {
                    term: 1,
                    leader: 1,
                    last_included_index: 10,
                    last_included_term: 1,
                    offset: offset as u64,
                    data: vec![2; SNAPSHOT_CHUNK_BYTES],
                    done: false,
                },
            );
            assert!(matches!(
                responses.first().map(|output| &output.msg),
                Some(Msg::InstallSnapshotResp {
                    installed: false,
                    ..
                })
            ));
        }
        let rejected = follower.step(
            1,
            Msg::InstallSnapshot {
                term: 1,
                leader: 1,
                last_included_index: 10,
                last_included_term: 1,
                offset: MAX_SNAPSHOT_BYTES as u64,
                data: vec![3],
                done: true,
            },
        );
        assert!(matches!(
            rejected.first().map(|output| &output.msg),
            Some(Msg::InstallSnapshotResp {
                next_offset,
                installed: false,
                ..
            }) if *next_offset == MAX_SNAPSHOT_BYTES as u64
        ));
        assert_eq!(
            follower
                .incoming_snapshot
                .as_ref()
                .map(|incoming| incoming.data.len()),
            Some(MAX_SNAPSHOT_BYTES)
        );
        assert!(follower.pending_snapshot().is_none());
    }

    #[test]
    fn stale_wal_from_interrupted_compaction_is_discarded() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"a".to_vec()).unwrap();
        node.propose(b"b".to_vec()).unwrap();
        drop(node);

        let loaded = load_state(&path).unwrap();
        store_state(&path, &loaded.state.view()).unwrap();
        let restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(restored.last_index(), 3, "베이스가 상위집합이므로 무손실");
        assert_eq!(restored.commit_index(), 3);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn torn_wal_tail_is_ignored_and_repaired() {
        let dir = std::env::temp_dir().join(format!("onetdns-raft-torn-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"a".to_vec()).unwrap();
        node.propose(b"b".to_vec()).unwrap();
        let torn_frame = encode_wal_frame(&node.stable_view(), node.log.len()).unwrap();
        drop(node);

        let mut wal_file = OpenOptions::new()
            .append(true)
            .open(wal_path(&path))
            .unwrap();
        wal_file.write_all(&torn_frame[..10]).unwrap();
        drop(wal_file);
        let mut restored =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(restored.last_index(), 3, "잘린 끝부분은 무시된다");
        for _ in 0..20 {
            restored.tick();
        }
        restored.propose(b"c".to_vec()).unwrap();
        drop(restored);
        let after = RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        assert_eq!(
            after.last_index(),
            5,
            "끝부분 절단 복구 후 append가 이어진다"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupted_wal_frame_before_a_valid_frame_is_rejected() {
        let dir =
            std::env::temp_dir().join(format!("onetdns-raft-wal-corrupt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.state");
        let mut node =
            RaftNode::new_persistent(1, vec![1], Config::default(), path.clone()).unwrap();
        for _ in 0..20 {
            node.tick();
        }
        node.propose(b"first".to_vec()).unwrap();
        node.propose(b"second".to_vec()).unwrap();
        drop(node);

        let wal = wal_path(&path);
        let mut bytes = fs::read(&wal).unwrap();
        let body_len = u32::from_be_bytes(
            bytes[WAL_HEADER_LEN..WAL_HEADER_LEN + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let first_frame_end = WAL_HEADER_LEN + 4 + body_len + 32;
        assert!(
            first_frame_end < bytes.len(),
            "뒤에 유효한 프레임이 필요하다"
        );
        bytes[WAL_HEADER_LEN + 4] ^= 1;
        fs::write(&wal, bytes).unwrap();

        let error = match RaftNode::new_persistent(1, vec![1], Config::default(), path) {
            Ok(_) => panic!("중간 WAL 손상을 잘린 끝부분처럼 무시하면 안 된다"),
            Err(error) => error,
        };
        assert!(error.contains("middle Raft WAL frame"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn non_current_state_version_is_rejected() {
        let state = StableState {
            current_term: 7,
            voted_for: Some(2),
            log: vec![LogEntry {
                term: 7,
                index: 1,
                data: b"entry".to_vec(),
            }],
            commit_index: 1,
            last_applied: 1,
            boot_counter: 0,
            snapshot: None,
        };
        let mut bytes = encode_state(&state.view()).unwrap();

        bytes.truncate(bytes.len() - 32);
        bytes[STATE_MAGIC.len() - 1] = 2;
        let digest = Sha256::digest(&bytes);
        bytes.extend_from_slice(&digest);
        assert!(decode_state(&bytes).is_err());
    }

    #[test]
    fn entry_term_reveals_overwritten_proposal() {
        let mut node = RaftNode::new(1, vec![1, 2, 3], Config::default());
        for _ in 0..20 {
            node.tick();
        }

        node.step(
            2,
            Msg::RequestVoteResp {
                term: node.term(),
                granted: true,
            },
        );
        assert!(node.is_leader());
        let proposal_term = node.term();
        let index = node.propose(b"mine".to_vec()).unwrap();
        assert_eq!(node.entry_term(index), proposal_term);

        node.step(
            2,
            Msg::AppendEntries {
                term: proposal_term + 1,
                leader: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![
                    LogEntry {
                        term: proposal_term + 1,
                        index: 1,
                        data: Vec::new(),
                    },
                    LogEntry {
                        term: proposal_term + 1,
                        index,
                        data: b"theirs".to_vec(),
                    },
                ],
                leader_commit: index,
            },
        );
        assert_eq!(node.commit_index(), index);
        assert_ne!(
            node.entry_term(index),
            proposal_term,
            "덮인 항목의 term은 제안 term과 달라야 허위 커밋 감지가 가능"
        );
    }

    #[test]
    fn failed_append_uses_follower_tail_hint_without_skipping_backtracking() {
        let mut node = RaftNode::new(
            1,
            vec![1, 2, 3],
            Config {
                election_base: 2,
                heartbeat: 1,
            },
        );
        let entries = (1..=100)
            .map(|index| LogEntry {
                term: 1,
                index,
                data: vec![index as u8],
            })
            .collect();
        node.step(
            3,
            Msg::AppendEntries {
                term: 1,
                leader: 3,
                prev_log_index: 0,
                prev_log_term: 0,
                entries,
                leader_commit: 0,
            },
        );
        for _ in 0..4 {
            node.tick();
        }
        let term = node.term();
        node.step(
            2,
            Msg::RequestVoteResp {
                term,
                granted: true,
            },
        );
        assert!(node.is_leader());
        assert_eq!(node.last_index(), 101, "새 term no-op 포함");

        let output = node.step(
            2,
            Msg::AppendEntriesResp {
                term,
                success: false,
                match_index: 5,
            },
        );
        let [Output {
            msg:
                Msg::AppendEntries {
                    prev_log_index,
                    entries,
                    ..
                },
            ..
        }] = output.as_slice()
        else {
            panic!("즉시 재복제 메시지가 필요하다: {output:?}");
        };
        assert_eq!(*prev_log_index, 5, "follower 마지막 index 다음부터 재개");
        assert_eq!(entries.first().map(|entry| entry.index), Some(6));
    }

    #[test]
    fn stale_term_append_rejected() {
        let mut node = RaftNode::new(1, vec![1, 2, 3], Config::default());
        node.step(
            2,
            Msg::AppendEntries {
                term: 5,
                leader: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: Vec::new(),
                leader_commit: 0,
            },
        );
        let out = node.step(
            3,
            Msg::AppendEntries {
                term: 2,
                leader: 3,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: Vec::new(),
                leader_commit: 0,
            },
        );
        assert!(matches!(
            out.first().map(|output| &output.msg),
            Some(Msg::AppendEntriesResp {
                term: 5,
                success: false,
                ..
            })
        ));
    }

    #[test]
    /// Otherwise a node could impersonate another.
    fn message_identity_must_match_transport_sender() {
        let mut node = RaftNode::new(1, vec![1, 2, 3], Config::default());

        assert!(node
            .step(
                2,
                Msg::RequestVote {
                    term: 99,
                    candidate: 3,
                    last_log_index: 0,
                    last_log_term: 0,
                },
            )
            .is_empty());
        assert_eq!(node.term(), 0);
    }

    #[test]
    fn committed_log_conflict_fails_before_mutation() {
        let mut node = RaftNode::new(1, vec![1, 2], Config::default());
        node.current_term = 1;
        node.log.push(LogEntry {
            term: 1,
            index: 1,
            data: b"committed".to_vec(),
        });
        node.commit_index = 1;
        let term = node.term().saturating_add(1);

        let output = node.step(
            2,
            Msg::AppendEntries {
                term,
                leader: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![LogEntry {
                    term,
                    index: 1,
                    data: b"replacement".to_vec(),
                }],
                leader_commit: 1,
            },
        );

        assert!(output.is_empty());
        assert!(node.fatal_error().is_some());
        assert_eq!(node.log[0].data, b"committed");
        assert_eq!(node.commit_index(), 1);
    }

    #[test]
    fn stale_success_response_cannot_regress_peer_progress() {
        let mut node = RaftNode::new(1, vec![1, 2, 3], Config::default());
        node.role = Role::Leader;
        node.current_term = 1;
        node.log = vec![
            LogEntry {
                term: 1,
                index: 1,
                data: vec![1],
            },
            LogEntry {
                term: 1,
                index: 2,
                data: vec![2],
            },
        ];
        node.match_index.insert(2, 2);
        node.next_index.insert(2, 3);

        node.handle_append_resp(2, 1, true, 1);

        assert_eq!(node.match_index.get(&2), Some(&2));
        assert_eq!(node.next_index.get(&2), Some(&3));
    }
}
