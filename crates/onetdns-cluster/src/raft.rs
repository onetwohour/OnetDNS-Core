/*!
 * @brief Raft 합의 상태 기계.
 *
 * @details 입출력을 하지 않는다. 메시지와 틱을 받아 내보낼 메시지를 돌려줄 뿐이다.
 *          영속화(상태 파일과 WAL)만 예외이며, 그것은 Raft의 안전성 조건이라 상태 기계와
 *          분리할 수 없다.
 * @invariant 투표와 임기는 응답을 내보내기 전에 디스크에 남아야 한다. 순서가 뒤집히면
 *            재시작 후 같은 임기에 두 번 투표해 리더가 둘 생길 수 있다.
 */

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/** @brief 클러스터 노드 식별자. */
pub type NodeId = u64;

/** @brief 상태 파일 식별자. 끝의 버전 바이트로 형식 변경을 구분한다. */
const STATE_MAGIC: &[u8; 12] = b"ONETRAFT\0\0\0\x01";

/** @brief 선행 기록 로그 파일 식별자. */
const WAL_MAGIC: &[u8; 12] = b"ONETRAFTWAL1";

/** @brief WAL 헤더 길이: 매직 12 + 무결성 해시 32. */
const WAL_HEADER_LEN: usize = 12 + 32;

/** @brief WAL 프레임 본문의 최소 길이. 이보다 짧으면 잘린 프레임이다. */
const MIN_WAL_FRAME_BODY: usize = 8 + 1 + 8 + 8 + 8 + 8 + 8 + 4;

/** @brief WAL 파일 크기 상한. 넘으면 상태 파일로 접고 WAL을 비운다. */
const MAX_WAL_BYTES: usize = 4 * 1024 * 1024;

/** @brief 상태 파일 크기 상한. 손상된 파일이 거대한 할당을 유발하지 못하게 막는다. */
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

/** @brief 로그에 담을 수 있는 항목 수 상한. */
const MAX_LOG_ENTRIES: usize = 100_000;

/**
 * @brief 스냅숏을 뜰 로그 길이 기준.
 * @note 테스트에서는 작게 잡아 압축 경로를 빠르게 지나가게 한다.
 */
#[cfg(not(test))]
pub(crate) const SNAPSHOT_LOG_THRESHOLD: u64 = 4_096;
#[cfg(test)]
/** @brief 테스트용 기준. 압축 경로를 빨리 지나가게 한다. */
pub(crate) const SNAPSHOT_LOG_THRESHOLD: u64 = 8;

/** @brief 스냅숏 전송을 나눌 조각 크기. 큰 스냅숏이 메시지 하나로 나가지 않게 한다. */
pub(crate) const SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;

/** @brief 받아들일 스냅숏 전체 크기 상한. */
pub const MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

/** @brief 로그 항목 하나의 크기 상한. 제안 시점에 검사한다. */
pub(crate) const MAX_ENTRY_BYTES: usize = 256 * 1024;

/** @brief 한 번의 AppendEntries에 담을 항목 수 상한. */
pub(crate) const MAX_APPEND_ENTRIES: usize = 256;

/** @brief 한 번의 AppendEntries에 담을 바이트 상한. */
pub(crate) const MAX_APPEND_BYTES: usize = 512 * 1024;

/** @brief 노드의 역할. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /** @brief 리더를 따른다. */
    Follower,
    /** @brief 리더가 되려고 표를 모은다. */
    Candidate,
    /** @brief 리더다. */
    Leader,
}

/** @brief 복제 로그 항목 하나. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /** @brief 이 항목이 만들어진 임기. */
    pub term: u64,
    /** @brief 기록에서의 곳. */
    pub index: u64,
    /** @brief 이 항목이 담은 명령. */
    pub data: Vec<u8>,
}

/** @brief 특정 지점까지 적용한 상태의 스냅숏. 로그 압축의 결과물이다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /** @brief 이 스냅숏이 포함하는 마지막 인덱스. */
    pub index: u64,
    /** @brief 그곳 항목의 임기. */
    pub term: u64,
    /** @brief 묶어 담은 상태. */
    pub data: Vec<u8>,
}

/** @brief 노드 사이에 오가는 Raft 메시지. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /** @brief 후보가 표를 요청한다. 로그 최신성을 함께 담아 보낸다. */
    RequestVote {
        /** @brief 표를 달라는 임기. */
        term: u64,
        /** @brief 표를 달라는 노드. */
        candidate: NodeId,
        /** @brief 그 노드의 마지막 기록 곳. */
        last_log_index: u64,
        /** @brief 그곳 항목의 임기. 이것이 뒤처지면 표를 주지 않는다. */
        last_log_term: u64,
    },
    /** @brief 투표 응답. */
    RequestVoteResp { term: u64, granted: bool },
    /** @brief 리더가 로그를 복제한다. 항목이 비면 심박이다. */
    AppendEntries {
        /** @brief 리더의 임기. */
        term: u64,
        /** @brief 보내는 리더. */
        leader: NodeId,
        /** @brief 이 스냅숏 바로 앞 항목의 인덱스. */
        prev_log_index: u64,
        /** @brief 그곳 항목의 임기. 맞지 않으면 되짚는다. */
        prev_log_term: u64,
        /** @brief 붙일 기록들. 비면 심장 박동이다. */
        entries: Vec<LogEntry>,
        /** @brief 리더가 확정한 곳. */
        leader_commit: u64,
    },
    /** @brief 복제 응답. match_index로 리더가 진행 상황을 안다. */
    AppendEntriesResp {
        /** @brief 답하는 노드의 임기. */
        term: u64,
        /** @brief 붙이기가 됐는지. */
        success: bool,
        /** @brief 이 노드가 확인한 마지막 위치. */
        match_index: u64,
    },
    /**
     * @brief 스냅숏 조각을 보낸다.
     * @details 따라가야 할 로그가 이미 압축돼 사라진 팔로워에게 쓴다.
     */
    InstallSnapshot {
        /** @brief 리더의 임기. */
        term: u64,
        /** @brief 보내는 리더. */
        leader: NodeId,
        /** @brief 이 스냅숏이 포함하는 마지막 인덱스. */
        last_included_index: u64,
        /** @brief 그곳 항목의 임기. */
        last_included_term: u64,
        /** @brief 이 조각이 시작하는 위치. */
        offset: u64,
        /** @brief 이 조각의 내용. */
        data: Vec<u8>,
        /** @brief 마지막 조각인지. */
        done: bool,
    },
    /** @brief 스냅숏 조각 응답. next_offset으로 이어 보낼 위치를 알린다. */
    InstallSnapshotResp {
        /** @brief 답하는 노드의 임기. */
        term: u64,
        /** @brief 받고 있는 스냅숏이 포함하는 마지막 인덱스. */
        last_included_index: u64,
        /** @brief 다음에 보낼 조각의 곳. */
        next_offset: u64,
        /** @brief 스냅숏을 다 받아 적용했는지. */
        installed: bool,
    },
}

/** @brief 상태 기계가 내보내라고 지시하는 메시지. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /** @brief 이 메시지를 보낼 노드. */
    pub to: NodeId,
    /** @brief 보낼 메시지. */
    pub msg: Msg,
}

/**
 * @brief 타이밍 설정. 단위는 틱이다.
 * @warning 선거 시간이 심박보다 충분히 커야 한다. 가까우면 정상 리더가 있는데도 팔로워가
 *          선거를 시작해 임기만 올라가고 진전이 없다.
 */
#[derive(Debug, Clone)]
pub struct Config {
    /** @brief 선거 타임아웃의 기준값. 실제 값은 여기에 무작위 편차를 더한다. */
    pub election_base: u32,
    /** @brief 리더가 심박을 보내는 간격. */
    pub heartbeat: u32,
}

impl Default for Config {
    /** @brief 기본 타이밍. 선거가 심박의 세 배 이상 되도록 잡혀 있다. */
    fn default() -> Self {
        Self {
            election_base: 10,
            heartbeat: 3,
        }
    }
}

/**
 * @brief 재시작을 넘어 살아남아야 하는 상태.
 * @warning 임기와 투표는 Raft의 안전성 전제다. 이걸 잃으면 같은 임기에 두 번 투표해
 *          리더가 둘 생길 수 있다.
 */
#[derive(Default)]
struct StableState {
    /** @brief 지금 임기. */
    current_term: u64,
    /** @brief 이 임기에 표를 준 노드. */
    voted_for: Option<NodeId>,
    /** @brief 기록 항목들. */
    log: Vec<LogEntry>,
    /** @brief 여기까지는 확정됐다. */
    commit_index: u64,
    /** @brief 여기까지는 실제로 적용했다. */
    last_applied: u64,

    /** @brief 시작 횟수. 재시작마다 늘어 재생 공격 방어의 재료가 된다. */
    boot_counter: u64,
    /** @brief 묶어 담은 앞부분. */
    snapshot: Option<Snapshot>,
}

/** @brief 영속 상태를 복사 없이 들여다보는 형태. */
struct StableView<'a> {
    /** @brief 지금 임기. */
    current_term: u64,
    /** @brief 이 임기에 표를 준 노드. */
    voted_for: Option<NodeId>,
    /** @brief 기록 항목들. 복제하지 않고 빌려 본다. */
    log: &'a [LogEntry],
    /** @brief 여기까지는 확정됐다. */
    commit_index: u64,
    /** @brief 여기까지는 실제로 적용했다. */
    last_applied: u64,
    /** @brief 부팅 epoch. 재시작해도 되돌아가지 않는다. */
    boot_counter: u64,
    /** @brief 묶어 담은 앞부분. */
    snapshot: Option<&'a Snapshot>,
}

impl StableState {
    /** @brief 이 상태를 빌린 형태로 본다. */
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

/**
 * @brief 조각으로 받는 중인 스냅숏.
 * @note 보낸 리더와 임기를 함께 기억한다. 중간에 리더가 바뀌면 이어 붙이던 조각을 버려야
 *       서로 다른 스냅숏의 조각이 섞이지 않는다.
 */
#[derive(Debug, Clone)]
struct IncomingSnapshot {
    /** @brief 이 스냅숏을 보내는 리더. */
    leader: NodeId,
    /** @brief 그 리더의 임기. */
    leader_term: u64,
    /** @brief 이 스냅숏이 포함하는 마지막 인덱스. */
    index: u64,
    /** @brief 그곳 항목의 임기. */
    term: u64,
    /** @brief 지금까지 받은 바이트. */
    data: Vec<u8>,
    /** @brief 끝까지 다 받았는지. */
    complete: bool,
}

/** @brief 디스크에서 복원한 상태와 그 무결성 정보. */
struct LoadedState {
    /** @brief 읽어 낸 상태. */
    state: StableState,
    /** @brief 상태 파일 본문의 해시. WAL 프레임 체인의 기점이 된다. */
    base_digest: Option<[u8; 32]>,

    /** @brief 그 상태를 만드는 데 쓴 덧붙임 기록의 길이. */
    wal_len: u64,
}

/**
 * @brief Raft 노드 하나의 전체 상태.
 * @invariant commit_index >= last_applied이고, 커밋된 항목은 다수 노드에 이미 복제돼 있다.
 */
pub struct RaftNode {
    /** @brief 이 노드 번호. */
    id: NodeId,
    /** @brief 다른 노드들. 자기 자신은 빠져 있다. */
    peers: Vec<NodeId>,
    /** @brief 지금 무슨 역할인지. */
    role: Role,
    /** @brief 지금 임기. */
    current_term: u64,
    /** @brief 이 임기에 표를 준 노드. */
    voted_for: Option<NodeId>,
    /** @brief 기록 항목들. */
    log: Vec<LogEntry>,
    /** @brief 여기까지는 확정됐다. */
    commit_index: u64,
    /** @brief 여기까지는 실제로 적용했다. */
    last_applied: u64,
    /** @brief 지금 리더. */
    leader_id: Option<NodeId>,

    /** @brief 노드마다 다음에 보낼 곳. */
    next_index: HashMap<NodeId, u64>,
    /** @brief 노드마다 확인된 마지막 위치. */
    match_index: HashMap<NodeId, u64>,
    /** @brief 이 임기에 이 노드에게 표를 준 노드들. */
    votes: HashSet<NodeId>,

    /** @brief 리더 소식을 못 들은 시간. */
    election_elapsed: u32,
    /** @brief 심장 박동을 보낸 지 지난 시간. */
    heartbeat_elapsed: u32,
    /** @brief 이번에 기다릴 시간. 노드마다 무작위로 달리해 동시에 나서지 않게 한다. */
    election_timeout: u32,
    /** @brief 그 시간을 무작위로 정하는 데 쓰는 난수 상태. */
    rng_state: u64,
    /** @brief 이 노드의 설정. */
    cfg: Config,
    /** @brief 상태를 담아 둘 파일. */
    storage_path: Option<PathBuf>,
    /** @brief 되돌릴 수 없는 오류. 나면 더 나아가지 않는다. */
    fatal: Option<String>,
    /** @brief 부팅 epoch. 재시작해도 되돌아가지 않는다. */
    boot_counter: u64,
    /** @brief 묶어 담은 앞부분. */
    snapshot: Option<Snapshot>,
    /** @brief 받고 있는 스냅숏. */
    incoming_snapshot: Option<IncomingSnapshot>,
    /** @brief 노드마다 스냅숏을 어디까지 보냈는지. */
    snapshot_offsets: HashMap<NodeId, u64>,
    /** @brief 스냅숏을 다시 저장해야 하는지. */
    snapshot_dirty: bool,

    /** @brief 디스크와 맞음이 보장된 기록 길이. */
    durable_log_len: usize,

    /** @brief 지금 기준 파일의 지문. 덧붙임 기록이 이것과 맞아야 쓴다. */
    base_digest: Option<[u8; 32]>,
    /** @brief 덧붙임 기록의 유효 길이. */
    wal_len: u64,
    /** @brief 덧붙임 기록 파일. */
    wal_file: Option<File>,
}

impl RaftNode {
    /** @brief 메모리 전용 노드. 테스트와 비영속 구성에 쓴다. */
    pub fn new(id: NodeId, peers: Vec<NodeId>, cfg: Config) -> Self {
        Self::from_stable(id, peers, cfg, None, StableState::default())
    }

    /**
     * @brief 디스크에 상태를 남기는 노드를 만든다.
     * @details 기존 상태 파일과 WAL이 있으면 복원한다. 손상된 끝부분은 잘라 내고 온전한
     *          지점까지만 살린다. 반쯤 쓰인 프레임을 받아들이면 로그가 어긋난다.
     */
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

    /** @brief 복원된 영속 상태 위에 노드를 조립한다. */
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

    /** @brief 이 노드의 식별자. */
    pub fn id(&self) -> NodeId {
        self.id
    }

    /**
     * @brief 선거 타임아웃이 가질 수 있는 가장 긴 틱 수.
     * @details 팔로워는 리더에게서 이만큼 아무것도 받지 못하면 반드시 선거를 시작한다.
     *          상대 노드가 살아 있는지 판단할 때 같은 기준을 써야 두 판단이 어긋나지 않는다.
     */
    pub fn election_timeout_ceiling(&self) -> u32 {
        self.cfg.election_base.max(2).saturating_mul(2)
    }

    /** @brief 현재 역할. */
    pub fn role(&self) -> Role {
        self.role
    }

    /** @brief 현재 임기. */
    pub fn term(&self) -> u64 {
        self.current_term
    }

    /** @brief 아는 리더. 선거 중이면 None. */
    pub fn leader(&self) -> Option<NodeId> {
        self.leader_id
    }

    /** @brief 마지막 로그 인덱스. 로그가 압축돼 비었으면 스냅숏 위치다. */
    pub fn last_index(&self) -> u64 {
        self.log.last().map_or_else(
            || self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index),
            |entry| entry.index,
        )
    }

    /** @brief 커밋된 마지막 인덱스. 여기까지는 다수 노드에 복제돼 있다. */
    pub fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /** @brief 상태 기계에 적용된 마지막 인덱스. */
    pub fn last_applied(&self) -> u64 {
        self.last_applied
    }

    /** @brief 보유 중인 스냅숏. */
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /** @brief 스냅숏이 포함하는 마지막 인덱스. 없으면 0이다. */
    pub fn snapshot_index(&self) -> u64 {
        self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index)
    }

    /** @brief 압축 후 남아 있는 로그 길이. */
    pub fn retained_log_len(&self) -> usize {
        self.log.len()
    }

    /** @brief 스냅숏을 뜰 때가 됐는지. 적용된 항목이 기준을 넘었는지로 본다. */
    pub fn snapshot_due(&self) -> bool {
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        self.last_applied.saturating_sub(base) >= SNAPSHOT_LOG_THRESHOLD
    }

    /** @brief 스냅숏 이후 적용된 항목들. 상위 계층이 새 스냅숏을 만들 재료로 쓴다. */
    pub fn applied_entries_after_snapshot(&self) -> Vec<LogEntry> {
        let base = self.snapshot.as_ref().map_or(0, |snapshot| snapshot.index);
        let count = usize::try_from(self.last_applied.saturating_sub(base))
            .unwrap_or(usize::MAX)
            .min(self.log.len());
        self.log[..count].to_vec()
    }

    /**
     * @brief 스냅숏으로 로그를 압축한다.
     *
     * @param data 상위 계층이 만든 상태 스냅숏.
     * @warning 스냅숏 위치는 반드시 적용 완료 범위 안이어야 한다. 아직 적용되지 않은
     *          지점에서 압축하면 그 항목들이 영영 적용되지 않고 사라진다.
     * @return 위치가 범위를 벗어나거나 디스크 저장에 실패하면 오류.
     */
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

    /**
     * @brief 리더로서 동작할 수 있는지.
     * @note 치명적 오류가 있으면 역할이 리더여도 false다. 상태를 남기지 못하는 노드가
     *       계속 리더 노릇을 하면 커밋한 것을 재시작 후 잃는다.
     */
    pub fn is_leader(&self) -> bool {
        self.role == Role::Leader && self.fatal.is_none()
    }

    /** @brief 치명적 오류가 있으면 그 사유. */
    pub fn fatal_error(&self) -> Option<&str> {
        self.fatal.as_deref()
    }

    /**
     * @brief 노드를 정지 상태로 만든다.
     * @details 영속화가 실패했을 때 부른다. 계속 참여하면 안전성 전제가 깨지므로,
     *          조용히 진행하는 대신 이 노드만 빠지고 나머지가 정족수를 이루게 한다.
     */
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

    /** @brief 정족수. 자기 자신을 포함한 노드 수의 과반이다. */
    fn quorum(&self) -> usize {
        self.peers.len().div_ceil(2) + 1
    }

    /** @brief 선거 타임아웃 편차용 의사난수. 암호용이 아니다. */
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

    /**
     * @brief 선거 타임아웃을 다시 정한다.
     * @warning 무작위 편차가 필수다. 모든 노드가 같은 시점에 선거를 시작하면 표가 갈려
     *          아무도 정족수를 못 얻고, 임기만 계속 올라가며 리더가 정해지지 않는다.
     */
    fn reset_election_timeout(&mut self) {
        let base = self.cfg.election_base.max(2);
        let jitter = (self.next_random() % u64::from(base)) as u32;
        self.election_timeout = base.saturating_add(jitter).max(2);
        self.election_elapsed = 0;
    }

    /**
     * @brief 인덱스 위치의 임기. 스냅숏 경계와 압축된 구간을 함께 처리한다.
     * @return 압축돼 사라진 구간이면 0: 알 수 없다는 뜻이다.
     */
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

    /** @brief 인덱스 위치의 임기를 밖으로 노출한다. */
    pub fn entry_term(&self, index: u64) -> u64 {
        self.term_at(index)
    }

    /** @brief 마지막 로그 항목의 임기. 투표 시 최신성 비교에 쓴다. */
    fn last_log_term(&self) -> u64 {
        self.log.last().map_or(0, |entry| entry.term)
    }

    /**
     * @brief 상태를 디스크에 남긴다.
     * @return 실패하면 노드를 정지시키고 false. 안전성을 지킬 수 없는 노드는 참여하면 안 된다.
     */
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

    /** @brief 지금 영속화할 상태를 빌린 형태로 모은다. */
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

    /**
     * @brief 상태를 WAL에 덧붙이거나, 필요하면 전체 상태 파일로 바꾼다.
     * @details 보통은 변경분만 WAL에 덧붙인다. 로그 전체를 매번 다시 쓰면 항목 수에
     *          비례해 비용이 커진다. WAL이 상한을 넘거나 스냅숏이 바뀌면 전부 스냅숏으로 합친다.
     */
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

    /**
     * @brief WAL에 프레임 하나를 덧붙이고 fsync한다.
     * @note 파일을 다시 열 때 이 노드가 아는 길이보다 파일이 길면 잘라 낸다. 지난 실행에서
     *       fsync 전에 죽어 남은 반쪽 프레임을 지우는 절차다.
     */
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

    /**
     * @brief 시작 세션 번호를 하나 올려 영속화한다.
     * @details 전송 계층의 재생 방어가 이 값을 쓴다. 재시작 뒤에도 번호가 되감기지 않아야
     *          예전 세션의 프레임이 다시 받아들여지지 않는다.
     */
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

    /**
     * @brief 시간을 한 틱 진행시킨다.
     * @details 리더면 심박을, 그 밖이면 선거 타임아웃을 센다. 상위 계층이 일정 간격으로
     *          부르며, 이 함수가 시계를 대신한다. 상태 기계가 시각을 직접 읽지 않는다.
     */
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

    /**
     * @brief 임기를 올리고 자신에게 투표한 뒤 표를 요청한다.
     * @warning 새 임기와 자기 투표를 디스크에 남긴 뒤 요청을 보낸다. 순서가 뒤집히면
     *          재시작 후 같은 임기에 다른 후보에게 또 투표할 수 있다.
     */
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

    /** @brief 리더로 전환하며 팔로워별 복제 위치를 초기화한다. */
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

    /** @brief 모든 팔로워에게 복제 메시지를 만든다. 항목이 없으면 심박이 된다. */
    fn broadcast_append(&self) -> Vec<Output> {
        self.peers
            .iter()
            .map(|peer| self.append_for(*peer))
            .collect()
    }

    /**
     * @brief 팔로워 하나에게 보낼 복제 메시지를 만든다.
     * @details 그 팔로워가 필요로 하는 로그가 이미 압축됐으면 스냅숏 전송으로 바꾼다.
     * @note 한 번에 담을 항목 수와 바이트를 모두 제한한다. 뒤처진 팔로워를 따라잡히려다
     *       거대한 메시지를 만들면 그 자체가 부하가 된다.
     */
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

    /** @brief 팔로워에게 보낼 스냅숏 조각을 만든다. 진행 위치는 노드별로 기억한다. */
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

    /** @brief 심박 주기를 기다리지 않고 즉시 복제를 밀어낸다. */
    pub fn force_replicate(&mut self) -> Vec<Output> {
        if self.is_leader() {
            self.heartbeat_elapsed = 0;
            self.broadcast_append()
        } else {
            Vec::new()
        }
    }

    /**
     * @brief 로그에 항목을 제안한다. 리더만 할 수 있다.
     * @return 배정된 인덱스. 리더가 아니거나 항목이 상한을 넘으면 오류.
     */
    pub fn propose(&mut self, data: Vec<u8>) -> Result<u64, String> {
        Ok(self.propose_batch(vec![data])?[0])
    }

    /**
     * @brief 여러 항목을 한 번에 제안한다.
     * @details 영속화를 한 번만 한다. 항목마다 fsync하면 처리량이 디스크 지연에 묶인다.
     * @warning 하나라도 상한을 넘으면 아무것도 넣지 않는다. 일부만 들어가면 호출자가
     *          어디까지 성공했는지 알 수 없다.
     */
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

    /**
     * @brief 들어온 메시지를 처리한다. RPC 진입점이다.
     *
     * @param from 전송 계층이 인증한 발신자. 메시지 본문의 리더·후보 필드와 다르면
     *             거부한다. 그러지 않으면 아무 노드나 리더를 사칭할 수 있다.
     * @details 더 높은 임기를 보면 즉시 팔로워로 내려간다. 이것이 Raft의 기본 규칙이며,
     *          분할된 이전 리더가 스스로 물러나는 경로이기도 하다.
     */
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

    /**
     * @brief 투표 요청을 처리한다.
     * @details 후보의 로그가 이 노드의 것만큼 최신이어야 표를 준다. 이 조건이 커밋된 항목을
     *          가진 노드만 리더가 되게 해, 커밋된 내용이 사라지지 않도록 보장한다.
     */
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

    /** @brief 투표 응답을 센다. 정족수를 채우면 리더가 된다. */
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
    /**
     * @brief 복제 메시지를 처리한다.
     * @details 직전 항목의 인덱스·임기가 이 노드의 로그와 맞아야 받아들인다. 어긋나면 거부하고,
     *          리더가 뒤로 물러가며 일치점을 찾는다. 이 대조가 로그 일관성의 근거다.
     * @note 충돌하는 항목이 있으면 그 뒤를 잘라 낸다. 커밋되지 않은 항목만 잘리므로 안전하다.
     */
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

    /** @brief 복제 응답을 만든다. */
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

    /** @brief 복제 응답을 반영한다. 성공하면 진행 위치를 올리고 커밋을 재계산한다. */
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
    /**
     * @brief 스냅숏 조각을 받아 이어 붙인다.
     * @warning 오프셋이 기대한 위치와 다르면 거부한다. 임의 위치 쓰기를 허용하면 조각을
     *          섞어 원하는 상태를 주입할 수 있다. 누적 크기 상한도 함께 본다.
     */
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

    /** @brief 스냅숏 조각 응답을 만든다. */
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

    /** @brief 다 받았지만 아직 적용하지 않은 스냅숏. 상위 계층이 적용한 뒤 알려 준다. */
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

    /**
     * @brief 상위 계층이 스냅숏을 적용했음을 알린다.
     * @details 이 시점에 로그를 스냅숏 지점까지 버리고 적용 위치를 옮긴다. 상위 계층이
     *          실제로 적용하기 전에 옮기면, 중간에 죽었을 때 적용되지 않은 상태로 남는다.
     */
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

    /** @brief 스냅숏 조각 응답을 받아 다음 조각을 보내거나 복제로 되돌아간다. */
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

    /**
     * @brief 커밋 위치를 앞으로 옮긴다.
     * @warning 현재 임기의 항목만 개수로 커밋할 수 있다(Raft 논문 5.4.2). 이전 임기의
     *          항목을 개수만 보고 커밋하면, 나중에 뒤집힐 수 있는 항목을 커밋으로 확정하게 된다.
     */
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

    /** @brief 아직 적용하지 않은 커밋 항목 중 다음 것. */
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

    /** @brief 적용할 커밋 항목을 한 번에 여러 개 가져온다. */
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

    /** @brief 항목을 적용 완료로 표시하고 영속화한다. */
    pub fn mark_applied(&mut self, index: u64) -> Result<(), String> {
        self.mark_applied_batch(index, index)
    }

    /** @brief 연속된 구간을 적용 완료로 표시한다. 영속화를 한 번만 한다. */
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

/**
 * @brief 후보의 로그가 이 노드의 것만큼 최신인지.
 * @details 임기를 먼저 보고 같으면 길이를 본다(Raft 5.4.1). 이 순서가 뒤바뀌면 짧지만
 *          최신 임기를 가진 로그가 뒤처진 것으로 판정된다.
 */
fn log_up_to_date(candidate_term: u64, candidate_index: u64, my_term: u64, my_index: u64) -> bool {
    candidate_term > my_term || (candidate_term == my_term && candidate_index >= my_index)
}

/** @brief 영속 상태를 상태 파일 형식으로 직렬화한다. */
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

/**
 * @brief 상태 파일을 해석한다.
 * @warning 디스크 파일도 신뢰할 수 없는 입력으로 다룬다. 손상되거나 조작된 파일이 거대한
 *          할당이나 패닉을 유발하지 않도록 모든 길이를 상한과 대조한다.
 */
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

/** @brief 커서에서 빅엔디언 64비트를 읽는다. 범위를 넘으면 오류다. */
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

/** @brief 커서에서 빅엔디언 32비트를 읽는다. */
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

/** @brief 상태 파일에 대응하는 WAL 경로. */
fn wal_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("raft.state");
    path.with_file_name(format!("{name}.wal"))
}

/**
 * @brief 상태 변경분을 WAL 프레임으로 만든다.
 * @param truncate_to 이 길이까지는 이미 기록돼 있다. 그 뒤 항목만 프레임에 담는다.
 */
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

/** @brief WAL 프레임을 상태에 다시 적용한다. 복원 시 순서대로 부른다. */
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

/**
 * @brief WAL을 재생해 상태를 최신으로 만든다.
 *
 * @details 프레임마다 이전 내용까지의 해시를 담아 체인을 이룬다. 체인이 끊기는 지점에서
 *          멈추고 그 앞까지만 살린다. 부분 기록이나 조작된 프레임을 걸러 내는 장치다.
 * @param base_digest 상태 파일의 해시. 체인의 기점이며, 이게 맞지 않으면 다른 상태 파일에
 *                    딸린 WAL이므로 전부 무시한다.
 * @return 유효한 WAL 길이. 그 뒤는 잘라 낸다.
 */
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

/** @brief 상태 파일과 WAL을 읽어 노드 상태를 복원한다. */
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

/** @brief WAL을 비우고 새 기준 해시로 헤더를 다시 쓴다. */
fn reset_wal(path: &Path, base_digest: &[u8; 32]) -> Result<(), String> {
    let mut header = Vec::with_capacity(WAL_HEADER_LEN);
    header.extend_from_slice(WAL_MAGIC);
    header.extend_from_slice(base_digest);
    write_state_file_atomic(path, &header)
}

/**
 * @brief 상태 전체를 파일에 쓴다.
 * @return 쓴 내용의 해시. WAL 체인의 새 기점이 된다.
 */
fn store_state(path: &Path, state: &StableView) -> Result<[u8; 32], String> {
    let bytes = encode_state(state)?;
    let digest: [u8; 32] = bytes[bytes.len() - 32..]
        .try_into()
        .map_err(|_| "Invalid hash length in the Raft state file")?;
    write_state_file_atomic(path, &bytes)?;
    Ok(digest)
}

/**
 * @brief 상태 파일이 놓일 디렉터리.
 *
 * @details 디렉터리 없이 파일 이름만 적힌 상대 경로는 parent 가 None 이 아니라 빈 경로를
 *          돌려준다. 빈 경로는 열 수 없어서 디렉터리 fsync 가 실패하고 노드가 시작하지
 *          못하므로 현재 디렉터리로 바꾼다.
 */
fn state_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/**
 * @brief 임시 파일에 쓰고 fsync한 뒤 제자리로 옮긴다.
 * @warning 제자리에 바로 쓰면 중간에 죽었을 때 반쯤 쓰인 상태 파일이 남아 노드가 기동조차
 *          못 한다. 디렉터리도 함께 fsync해야 이름 바꾸기가 실제로 남는다.
 */
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
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| format!("Could not open a temporary file for Raft state: {error}"))?;

        restrict_state_file(&tmp).map_err(|error| {
            format!("Could not restrict permissions on the temporary Raft state file: {error}")
        })?;
        file.write_all(bytes)
            .map_err(|error| format!("Could not write the Raft state file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Could not sync the Raft state file to disk: {error}"))?;
        /*
         * 연 채로 이름을 바꾸면 WSL 의 Windows 드라이브(9p)에서는 새 이름으로 권한을 바꿀 때
         * 파일을 찾지 못한다. 이름을 바꾸기 전에 닫는다.
         */
        drop(file);
        replace_state_file(&tmp, path).map_err(|error| {
            format!("Could not atomically replace the Raft state file: {error}")
        })?;
        restrict_state_file(path).map_err(|error| {
            format!("Could not restrict permissions on the Raft state file: {error}")
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
/** @brief 부모 디렉터리를 fsync해 이름 바꾸기를 확정한다. 지원하지 않는 플랫폼은 무시한다. */
fn sync_state_parent(parent: &Path) -> std::io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
/** @brief 부모 디렉터리를 fsync해 이름 바꾸기를 확정한다. 지원하지 않는 플랫폼은 무시한다. */
fn sync_state_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
/** @brief 부모 디렉터리를 fsync해 이름 바꾸기를 확정한다. 지원하지 않는 플랫폼은 무시한다. */
fn sync_state_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
/** @brief 상태 파일을 전부 교체한다. */
fn replace_state_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

#[cfg(windows)]
/** @brief 상태 파일을 전부 교체한다. 디스크에 닿은 뒤에 돌아온다. */
fn replace_state_file(src: &Path, dst: &Path) -> std::io::Result<()> {
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

#[cfg(unix)]
/** @brief 상태 파일을 남이 읽지 못하게 한다. */
fn restrict_state_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
/** @brief 상태 파일 권한을 좁힌다. */
fn restrict_state_file(path: &Path) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    /** @brief 접근 목록만 바꾼다는 표시. */
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    /** @brief 권한 문자열 버전. */
    const SDDL_REVISION_1: u32 = 1;
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
            security_descriptor: *const c_void,
        ) -> i32;
    }
    #[link(name = "Kernel32")]
    extern "system" {
        /** @brief 받은 메모리를 돌려준다. */
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
        .encode_utf16()
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
    if converted == 0 || descriptor.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let applied = unsafe {
        SetFileSecurityW(
            path_w.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor as *const c_void,
        )
    };
    unsafe {
        let _ = LocalFree(descriptor);
    }
    if applied == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
/** @brief 이 플랫폼에서는 할 일이 없다. */
fn restrict_state_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
/** @brief 갈라진 망에서의 합의, 기록 복구, 그리고 묶어 저장하기. */
mod tests {
    use super::*;

    #[test]
    /** @brief 파일 이름만 적은 상태 경로도 현재 디렉터리에 저장되는지. */
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

    /** @brief 테스트용 노드 집합. */
    struct Cluster {
        /** @brief 테스트용 노드들. */
        nodes: Vec<RaftNode>,
    }

    impl Cluster {
        /** @brief 이만큼의 노드로 만든다. */
        fn new(count: u64) -> Self {
            let ids: Vec<u64> = (1..=count).collect();
            Self {
                nodes: ids
                    .iter()
                    .map(|id| RaftNode::new(*id, ids.clone(), Config::default()))
                    .collect(),
            }
        }

        /** @brief 이 노드의 곳. */
        fn idx(&self, id: NodeId) -> usize {
            (id - 1) as usize
        }

        /** @brief 모든 노드를 한 번씩 굴린다. */
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

        /** @brief 지금 리더. 없으면 없다. */
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

        /** @brief 망이 갈라진 상태로 굴린다. */
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

        /** @brief 이 노드. */
        fn node(&self, id: NodeId) -> &RaftNode {
            &self.nodes[self.idx(id)]
        }

        /** @brief 이 노드를 고칠 수 있게. */
        fn node_mut(&mut self, id: NodeId) -> &mut RaftNode {
            let index = self.idx(id);
            &mut self.nodes[index]
        }

        /** @brief 이 집합 안의 리더들. */
        fn leaders_in(&self, ids: &[NodeId]) -> Vec<NodeId> {
            ids.iter()
                .copied()
                .filter(|id| self.node(*id).is_leader())
                .collect()
        }
    }

    #[test]
    /** @brief 소수 쪽이 확정하지 못하고, 망이 붙으면 하나로 모이는지. 확정하면 두 답이 생긴다. */
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
    /** @brief 리더를 뽑고 기록을 묶어 퍼뜨리는지. */
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
    /** @brief 실제로 적용한 뒤에만 진도가 나가는지. */
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
    /** @brief 묶어 올린 기록이 끊기지 않고 이어 붙는지. */
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
    /** @brief 새 리더가 물려받은 기록을 스스로 확정하는지. 안 하면 그 기록이 영영 확정되지 않는다. */
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
    /** @brief 저장한 상태가 되읽히고 검사합이 맞는지. */
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
    /** @brief 부팅 epoch가 재시작 뒤에도 되돌아가지 않는지. */
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
    /** @brief 재시작 뒤 확정 진도를 리더에게서 되찾는지. */
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
    /** @brief 기록을 덧붙일 때 앞부분을 다시 쓰지 않는지. */
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
    /** @brief 어긋난 기록을 잘라 내고 다시 읽는지. */
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
    /** @brief 기록이 예산을 넘으면 묶어 줄이는지. */
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
    /** @brief 묶어 저장한 뒤 앞부분을 버리고도 재시작이 되는지. */
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

    #[test]
    /** @brief 뒤처진 노드가 스냅숏을 먼저 받고 나머지를 이어받는지. */
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
    /** @brief 새 리더가 오면 받던 스냅숏을 버리는지. 섞으면 상태가 깨진다. */
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
    /** @brief 순서가 어긋나거나 너무 큰 조각을 거부하는지. */
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
    /** @brief 줄이다 끊긴 이전 기록을 버리는지. */
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
    /** @brief 끝이 잘린 기록을 무시하고 고치는지. */
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
    /** @brief 깨진 기록 뒤의 멀쩡한 기록을 그냥 쓰지 않는지. */
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
    /** @brief 형식이 다른 상태 파일을 거부하는지. */
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
    /** @brief 덮어써진 제안을 알아볼 수 있는지. */
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
    /** @brief 붙이기에 실패했을 때 상대가 준 힌트로 되짚되 건너뛰지 않는지. */
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
    /** @brief 이전 리더가 보낸 기록을 거부하는지. */
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
    /** @brief 메시지에 적힌 보낸 이가 실제 보낸 이와 같아야 하는지. 다르면 남을 사칭할 수 있다. */
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
    /** @brief 확정된 기록과 어긋나면 고치기 전에 실패하는지. */
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
    /** @brief 늦게 온 성공 응답이 진도를 되돌리지 못하는지. */
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
