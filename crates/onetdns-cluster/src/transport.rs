/*!
 * @brief Raft RPC 전송: 인증·암호화된 노드 간 통신.
 *
 * @details 프레임마다 XChaCha20-Poly1305로 봉인하고 발신자 ID를 AAD에 넣는다. 그래서
 *          어떤 노드도 다른 노드를 사칭할 수 없고, 메시지 안의 리더·후보 필드는 인증된
 *          발신자와 대조된다.
 * @warning 클러스터 비밀이 곧 인증의 전부다. 노출되면 아무나 클러스터에 합류해 설정을
 *          복제 경로로 주입할 수 있다.
 */

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
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::raft::{
    LogEntry, Msg, NodeId, Output, RaftNode, MAX_APPEND_BYTES, MAX_APPEND_ENTRIES, MAX_ENTRY_BYTES,
    SNAPSHOT_CHUNK_BYTES,
};

/** @brief XChaCha20 논스 길이. 세션 식별자와 일련번호를 함께 담는다. */
const RAFT_NONCE_LEN: usize = 24;

/** @brief Poly1305 인증 태그 길이. */
const RAFT_AEAD_TAG_LEN: usize = 16;

/** @brief Ed25519 서명 길이. 노드 신원 증명에 쓴다. */
const RAFT_SIG_LEN: usize = 64;

/** @brief 프레임 크기 상한. 스냅숏 조각도 이 안에 들어간다. */
const MAX_RAFT_FRAME: usize = 1024 * 1024;

/** @brief 동시에 받아들일 클러스터 연결 수. */
const MAX_RAFT_CONNECTIONS: usize = 64;

/** @brief 한 출발지 IP가 열 수 있는 연결 수. 한 노드가 슬롯을 다 차지하지 못하게 한다. */
const MAX_RAFT_CONNS_PER_IP: usize = 8;

/** @brief 한 메시지에 담긴 로그 항목 수의 수신 상한. */
const MAX_RAFT_ENTRIES: usize = 4096;

/** @brief 로그 항목 하나의 수신 크기 상한. */
const MAX_RAFT_ENTRY_BYTES: usize = 256 * 1024;

/** @brief 노드별 송신 큐 길이. 넘치면 오래된 메시지를 버린다. 심박은 최신만 의미가 있다. */
const PEER_QUEUE: usize = 256;

/** @brief 제안 큐 길이. */
const PROPOSAL_QUEUE: usize = 64;

/**
 * @brief 제안을 모아 한 번에 처리할 시간 구간.
 * @details 짧게 잡아야 지연이 안 늘고, 그래도 이 구간 안에 들어온 제안은 fsync 한 번을 나눠 쓴다.
 */
const PROPOSAL_BATCH_WINDOW: Duration = Duration::from_millis(2);

/** @brief 로그 항목 하나의 와이어 부가 길이: 임기 8 + 인덱스 8 + 길이 4. */
const LOG_ENTRY_WIRE_OVERHEAD: usize = 8 + 8 + 4;

/** @brief 제안이 커밋되기를 기다릴 시간. */
const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(5);

/** @brief 프레임 하나를 다 읽을 때까지 기다릴 시간. */
const RAFT_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/** @brief 프레임 형식 버전. */
const RAFT_FRAME_VERSION: u8 = 1;

/**
 * @brief 재생 방어 구간의 폭(비트).
 * @details 순서가 뒤바뀐 프레임을 이 폭만큼은 받아 준다. 구간이 없으면 네트워크 재정렬만으로
 *          정상 프레임이 버려진다.
 */
const REPLAY_WINDOW_BITS: u64 = 128;

/** @brief 재생으로 거부한 프레임 수. 진단 지표로 노출된다. */
static REPLAY_REJECTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/**
 * @brief 노드 하나에 대한 재생 방어 상태.
 * @details 세션이 바뀌면(상대가 재시작하면) 구간을 새로 연다. 같은 세션 안에서는 일련번호와
 *          비트맵으로 이미 본 프레임을 걸러 낸다.
 */
#[derive(Debug, Clone, Copy)]
struct PeerReplayWindow {
    /** @brief 이 상대의 현재 epoch. */
    session: [u8; 16],
    /** @brief 그 epoch에서 본 가장 큰 일련번호. */
    highest_sequence: u64,
    /** @brief 그 언저리에서 무엇을 봤는지 나타내는 비트. */
    seen_bitmap: u128,
}

/** @brief 노드별 재생 방어 구간 모음. */
#[derive(Default)]
struct ReplayCache {
    /** @brief 상대별 재사용 방지 상태. */
    peers: HashMap<NodeId, PeerReplayWindow>,
}

impl ReplayCache {
    /**
     * @brief 이 논스를 처음 보는지 판정하고 구간을 갱신한다.
     * @warning 재생을 허용하면 이전 AppendEntries를 다시 밀어 넣어 커밋된 로그를 되돌릴 수
     *          있다. 창보다 오래된 것과 이미 본 것은 모두 거부한다.
     * @return 받아들일 프레임이면 true.
     */
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

/**
 * @brief 절대 데드라인과 종료 신호를 함께 보는 읽기 어댑터.
 * @details 소켓 타임아웃만으로는 조금씩 보내는 상대를 막지 못한다. 부분 읽기마다 데드라인을
 *          다시 확인해 총 시간을 유계로 만든다.
 */
struct DeadlineReader {
    /** @brief 이어진 연결. */
    stream: TcpStream,
    /** @brief 프레임 하나의 데드라인. */
    deadline: Instant,
    /** @brief 서버 전체가 끝나고 있다는 표시. */
    shutdown: Arc<AtomicBool>,
}

impl DeadlineReader {
    /** @brief 어댑터를 만든다. 데드라인은 프레임마다 다시 잡는다. */
    fn new(stream: TcpStream, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            stream,
            deadline: Instant::now(),
            shutdown,
        }
    }

    /** @brief 데드라인을 다시 잡는다. 새 프레임을 읽기 시작할 때 부른다. */
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    /** @brief 데드라인까지 남은 시간. 지났으면 타임아웃 오류다. */
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}

impl Read for DeadlineReader {
    /** @brief 남은 시간을 걸고 읽는다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return Err(std::io::ErrorKind::ConnectionAborted.into());
            }
            let timeout = self.remaining()?.min(Duration::from_millis(250));
            self.stream.set_read_timeout(Some(timeout))?;
            match self.stream.read(buf) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && Instant::now() < self.deadline => {}
                result => return result,
            }
        }
    }
}

/** @brief 이 Raft 런타임이 시작한 스레드 목록. 종료 시 전부 합류시킨다. */
type RuntimeThreads = Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>;

/** @brief 스레드를 추적 목록에 넣는다. */
fn track_thread(threads: &RuntimeThreads, thread: std::thread::JoinHandle<()>) {
    let mut guard = lock(threads);

    guard.retain(|handle| !handle.is_finished());
    guard.push(thread);
}

/**
 * @brief 추적 중인 스레드를 전부 합류시킨다.
 * @note 재로드 때 반드시 끝나야 한다. 남으면 다음 세대가 같은 포트를 열지 못한다.
 */
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

/**
 * @brief 시작 중 실패했을 때 이미 뜬 스레드를 정리하는 가드.
 * @details 성공 시 disarm으로 무장을 푼다. 그러지 않으면 정상 시작에서도 정리가 돈다.
 */
struct RuntimeStartupGuard {
    /** @brief 시작한 것들에 끝나라고 알릴 표시. */
    shutdown: Arc<AtomicBool>,
    /** @brief 시작한 스레드들. */
    threads: RuntimeThreads,
    /** @brief 끝까지 잘 떴는지. 그러면 정리하지 않는다. */
    armed: bool,
}

impl RuntimeStartupGuard {
    /** @brief 시작에 성공했음을 알려 정리를 건너뛰게 한다. */
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RuntimeStartupGuard {
    /** @brief 정리한다. */
    fn drop(&mut self) {
        if self.armed {
            self.shutdown.store(true, Ordering::Relaxed);
            join_threads(&self.threads);
        }
    }
}

/** @brief 빅엔디언 64비트를 덧붙인다. */
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/** @brief 빅엔디언 64비트를 읽는다. 범위를 넘으면 None. */
fn get_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u64::from_be_bytes(slice.try_into().ok()?))
}

/** @brief 빅엔디언 32비트를 읽는다. */
fn get_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = bytes.get(*pos..end)?;
    *pos = end;
    Some(u32::from_be_bytes(slice.try_into().ok()?))
}

/** @brief Raft 메시지를 와이어 바이트로 만든다. 표현할 수 없으면 빈 결과다. */
pub fn encode_msg(message: &Msg) -> Vec<u8> {
    try_encode_msg(message).unwrap_or_default()
}

/** @brief 메시지 인코딩. 크기 상한을 넘기면 None이다. */
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

/**
 * @brief 와이어 바이트를 Raft 메시지로 해석한다.
 * @warning 인증된 프레임에서 나온 바이트지만 여전히 신뢰할 수 없다. 클러스터 비밀을 가진
 *          노드가 결함이 있거나 침해됐을 수 있다. 항목 수·크기 상한을 모두 검사하고,
 *          잔여 바이트가 남으면 거부한다.
 */
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
/**
 * @brief 상태 기계가 내보낸 메시지를 노드별 송신 스레드로 나눠 보낸다.
 * @details 노드마다 큐와 스레드를 따로 둔다. 하나로 묶으면 느린 노드 하나가 다른 노드로
 *          가는 심박까지 막는다.
 */
struct Dispatcher {
    /** @brief 노드마다 보낼 것을 넣는 곳. */
    senders: Arc<HashMap<NodeId, SyncSender<Msg>>>,
}

impl Dispatcher {
    #[allow(clippy::too_many_arguments)]
    /** @brief 노드마다 송신 스레드를 시작하고 분배기를 만든다. */
    fn new(
        self_id: NodeId,
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

    /**
     * @brief 메시지를 해당 노드 큐에 넣는다.
     * @note 큐가 가득 차면 버린다. Raft는 메시지 유실을 전제로 설계돼 있어 재시도가
     *       내장돼 있고, 여기서 기다리면 상태 기계 잠금을 잡은 채 막힌다.
     */
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

/**
 * @brief 들어온 클러스터 연결을 받지 않았음을 알린다.
 * @details 노드가 아닌 곳에서 오는 접속은 잘못된 설정이거나 이 포트를 훑는 것이다. 어느
 *          쪽이든 알아야 한다. 계속 들어올 수 있어 2의 거듭제곱 번째만 남긴다.
 */
fn reject_raft_connection(ip: IpAddr, reason: &str) {
    /** @brief 누적 거절 수. */
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "raft.connection_rejected", peer_ip = %ip, reason = reason, count = count, "Did not accept a connection on the cluster port");
    }
}

#[allow(clippy::too_many_arguments)]
/**
 * @brief 노드 하나로 가는 송신 루프.
 * @details 연결이 끊기면 다시 맺으며 계속 시도한다. 프레임마다 봉인하고, 논스에 세션
 *          접두사와 증가하는 일련번호를 담아 상대의 재생 방어가 동작하게 한다.
 */
fn peer_sender(
    self_id: NodeId,
    peer_id: NodeId,
    address: SocketAddr,
    cipher: Arc<XChaCha20Poly1305>,
    signing_key: Arc<SigningKey>,
    cluster_context: [u8; 32],
    session_prefix: u64,
    shutdown: &AtomicBool,
    receiver: Receiver<Msg>,
) {
    let Some(sealer) = FrameSealer::new(cipher, signing_key, cluster_context, session_prefix)
    else {
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

/**
 * @brief 노드마다 인증을 통과한 프레임을 마지막으로 받은 시각.
 * @details 클러스터 프레임은 한 방향으로만 흐르고 응답도 별도 프레임으로 오므로, 요청과
 *          응답을 짝지어 왕복 시간을 측정할 수 없다. 대신 서명과 암호를 모두 통과한 프레임을
 *          받았다는 사실은 그 노드가 살아 있고 같은 클러스터 키를 쓴다는 증거가 된다.
 */
struct PeerContact {
    /** @brief 시각을 측정할 기준점. */
    origin: Instant,
    /** @brief 노드별 마지막 수신 시각. 기준점부터 지난 밀리초에 1을 더한 값이고, 0은 받은 적 없음이다. */
    last: HashMap<NodeId, AtomicU64>,
}

impl PeerContact {
    /** @brief 설정된 노드마다 빈 기록을 만든다. */
    fn new(peers: &HashMap<NodeId, String>) -> Self {
        Self {
            origin: Instant::now(),
            last: peers.keys().map(|id| (*id, AtomicU64::new(0))).collect(),
        }
    }

    /** @brief 이 노드에게서 방금 프레임을 받았다고 적는다. */
    fn record(&self, from: NodeId) {
        if let Some(slot) = self.last.get(&from) {
            let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
            slot.store(elapsed.saturating_add(1), Ordering::Relaxed);
        }
    }

    /**
     * @brief 이 노드에게서 마지막으로 받은 뒤 지난 시간.
     * @return 받은 적이 없으면 없다.
     */
    fn since(&self, peer: NodeId) -> Option<Duration> {
        let stamp = self.last.get(&peer)?.load(Ordering::Relaxed);
        let at = Duration::from_millis(stamp.checked_sub(1)?);
        Some(self.origin.elapsed().saturating_sub(at))
    }
}

#[derive(Clone)]
/**
 * @brief 실행 중인 Raft 런타임을 가리키는 핸들.
 * @details 데이터 평면이 이걸로 설정 변경을 제안하고 리더 여부를 확인한다.
 */
pub struct RaftHandle {
    /** @brief 합의 상태. */
    node: Arc<Mutex<RaftNode>>,
    /** @brief 노드마다의 주소. */
    peers: Arc<HashMap<NodeId, String>>,
    /** @brief 노드마다 마지막으로 프레임을 받은 시각. */
    contact: Arc<PeerContact>,
    /**
     * @brief 이 시간 안에 프레임을 받았으면 살아 있다고 본다.
     * @details 팔로워가 선거를 시작하는 가장 긴 대기 시간과 같다.
     */
    contact_window: Duration,
    /** @brief 이 노드 번호. */
    self_id: NodeId,
    /** @brief 끝나라는 표시. */
    shutdown: Arc<AtomicBool>,
    /** @brief 적용 진도와 그것을 기다리는 곳. */
    progress: Arc<(Mutex<u64>, Condvar)>,
    /** @brief 새 제안을 받는지. */
    accepting_proposals: Arc<AtomicBool>,
    /** @brief 제안을 넣는 곳. */
    proposal_tx: SyncSender<ProposalRequest>,
    /** @brief 아직 답을 못 준 제안 수. */
    pending_proposals: Arc<AtomicUsize>,
    /** @brief 시작한 스레드들. */
    threads: RuntimeThreads,
}

/** @brief 제안 하나와 결과를 돌려줄 채널. */
struct ProposalRequest {
    /** @brief 제안할 명령. */
    data: Vec<u8>,
    /** @brief 결과를 돌려줄 곳. */
    response: mpsc::Sender<Result<(u64, u64), String>>,
}

/** @brief 진행 중인 제안 수를 세는 RAII 가드. 실패 경로에서도 반드시 줄어든다. */
struct PendingProposal {
    /** @brief 아직 끝나지 않은 제안 수. */
    count: Arc<AtomicUsize>,
    /** @brief 마지막 제안이 끝날 때 apply 스레드를 깨울 진행 신호. */
    progress: Arc<(Mutex<u64>, Condvar)>,
}

impl Drop for PendingProposal {
    /** @brief 제안 수를 돌려주고 마지막이면 apply 스레드를 깨운다. */
    fn drop(&mut self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            signal_progress(&self.progress);
        }
    }
}

/**
 * @brief 제안을 모아 한 번에 로그에 올리는 작업 스레드.
 * @details 짧은 시간 구간 안에 들어온 제안을 묶는다. 제안마다 fsync하면 처리량이 디스크
 *          지연에 그대로 묶이므로, 구간 하나에 fsync 한 번을 나눠 쓴다.
 */
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

/**
 * @brief 노드 서명 키 시드에서 공개 키를 구한다.
 * @details 다른 노드의 cluster_raft_peers 에는 이 공개 키를 적어야 한다. 운영자가 외부 도구
 *          없이 확인할 수 있도록 관리 API가 이 값을 보여 준다.
 */
pub fn node_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/**
 * @brief 제안이 실패한 방식.
 * @details 부른 쪽이 제안과 함께 바꾼 자기 상태를 어떻게 다룰지가 여기에 달렸다. 로그에
 *          들어간 항목은 기다리다 포기해도 나중에 커밋될 수 있으므로, 적용되지 않는다고
 *          답하면 거짓이 된다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalError {
    /** @brief 로그에 들어가지 않았다. 적용되지 않는다. */
    Rejected(String),
    /** @brief 로그에 들어갔지만 리더 교체로 다른 항목에 덮였다. 적용되지 않는다. */
    Discarded,
    /** @brief 로그에 들어갔을 수 있으나 커밋되는지 확인하지 못했다. 나중에 커밋되면 모든 노드에 적용된다. */
    Undetermined(String),
}

impl std::fmt::Display for ProposalError {
    /** @brief 사람이 읽을 문구로 적는다. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) | Self::Undetermined(reason) => f.write_str(reason),
            Self::Discarded => f.write_str("The proposal was discarded because the leader changed"),
        }
    }
}

impl From<ProposalError> for String {
    /** @brief 문구만 필요한 쪽을 위해 문자열로 바꾼다. */
    fn from(error: ProposalError) -> Self {
        error.to_string()
    }
}

impl RaftHandle {
    /**
     * @brief 항목을 제안하고 커밋될 때까지 기다린다.
     * @return 커밋된 인덱스. 실패하면 그 항목이 적용될 수 있는지를 함께 알린다.
     */
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
        /* 핸들러에 넘긴 뒤로는 로그에 들어갔는지 모른다. 그때부터의 실패는 확정할 수 없다. */
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

    /** @brief 클러스터 현황을 JSON으로 만든다. 제어 API가 그대로 내보낸다. */
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
                    "{{\"id\":{id},\"url\":{},\"healthy\":{},\"role\":\"{peer_role}\",\"rtt_ms\":null}}",
                    onetdns_core::json::escape(url),
                    peer_healthy.map_or("null", |value| if value { "true" } else { "false" })
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"self\":{{\"id\":{},\"role\":\"{}\",\"backend\":{},\"listeners\":{listeners},\"leader\":{},\"term\":{},\"commit_index\":{},\"last_applied\":{},\"last_index\":{},\"snapshot_index\":{},\"retained_log_entries\":{},\"fatal\":{},\"healthy\":{healthy}}},\"peers\":[{peers}]}}",
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
        )
    }

    /** @brief 이 노드가 리더인지. 설정 변경을 받을 수 있는지의 판단 기준이다. */
    pub fn is_leader(&self) -> bool {
        lock(&self.node).is_leader()
    }

    /** @brief 이 노드가 아는 리더의 번호. 선거 중이면 None. */
    pub fn leader(&self) -> Option<u64> {
        lock(&self.node).leader()
    }

    /**
     * @brief 런타임을 멈추고 모든 스레드를 합류시킨다.
     * @note 새 제안을 먼저 막고 진행 중인 것을 마친 뒤 스레드를 멈춘다. 순서를 바꾸면
     *       응답을 기다리던 제안이 영영 답을 받지 못한다.
     */
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

/**
 * @brief 상대 노드가 살아 있는지 판정한다.
 * @param since     그 노드에게서 마지막으로 프레임을 받은 뒤 지난 시간.
 * @param window    이 시간 안에 받았으면 살아 있다고 본다.
 * @param expected  그 노드가 이쪽으로 꾸준히 보내야 하는지. 리더는 모든 팔로워에게서
 *                  응답을 받고, 팔로워는 리더에게서만 심박을 받는다.
 * @return 받을 까닭이 없는 노드라서 조용한 것이면 알 수 없으므로 없다.
 */
fn peer_health(since: Option<Duration>, window: Duration, expected: bool) -> Option<bool> {
    match since {
        Some(age) if age <= window => Some(true),
        _ if expected => Some(false),
        _ => None,
    }
}

/** @brief 포이즌을 복구하며 잠근다. 스레드 하나의 패닉이 클러스터를 멎게 하지 않는다. */
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/**
 * @brief 종료 신호를 확인하며 대기한다.
 * @return 종료가 요청됐으면 true. 잘게 나눠 자므로 반응이 즉각적이다.
 */
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

/** @brief 적용 진행을 알려 기다리던 제안을 깨운다. */
fn signal_progress(progress: &Arc<(Mutex<u64>, Condvar)>) {
    let (generation, condition) = &**progress;
    let mut value = lock(generation);
    *value = value.wrapping_add(1);
    condition.notify_all();
}

/** @brief IP별 연결 슬롯을 반납한다. 계수가 0이 된 항목은 지워 맵이 커지지 않게 한다. */
fn release_ip_slot(per_ip: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr) {
    let mut counts = lock(per_ip);
    if let Some(c) = counts.get_mut(&ip) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            counts.remove(&ip);
        }
    }
}

/**
 * @brief 프레임을 암호화하고 복호화하는 것.
 * @warning 보낸 이를 함께 묶어 봉한다. 묶지 않으면 남의 프레임을 그대로 옮겨 붙여
 *          다른 노드인 척할 수 있다.
 */
struct FrameSealer {
    /** @brief 프레임을 봉하는 것. */
    cipher: Arc<XChaCha20Poly1305>,
    /** @brief 이 epoch 번호. 재시작하면 바뀐다. */
    session_id: [u8; 16],
    /** @brief 다음 프레임의 일련번호. */
    sequence: AtomicU64,
    /** @brief 보낸 이를 증명하는 키. */
    signing_key: Arc<SigningKey>,
    /** @brief 이 클러스터를 가리키는 값. 다른 클러스터로 옮겨 붙이지 못하게 묶는다. */
    cluster_context: [u8; 32],
}

impl FrameSealer {
    /** @brief 봉인기를 만든다. 세션 식별자를 추출해 논스 접두사로 쓴다. */
    fn new(
        cipher: Arc<XChaCha20Poly1305>,
        signing_key: Arc<SigningKey>,
        cluster_context: [u8; 32],
        session_prefix: u64,
    ) -> Option<Self> {
        let session_id = new_session_id(session_prefix)?;
        Some(Self {
            cipher,
            session_id,
            sequence: AtomicU64::new(0),
            signing_key,
            cluster_context,
        })
    }

    /**
     * @brief 메시지를 인증·암호화된 프레임으로 봉인한다.
     *
     * @details 발신자 ID를 AAD에 넣는다. 그래서 프레임을 다른 발신자 이름으로 옮겨 붙일
     *          수 없다. 서명은 그 위에 노드 신원을 한 겹 더 묶는다.
     * @note 논스는 세션 식별자 + 증가하는 일련번호다. 무작위가 아니라 결정적이므로,
     *       같은 세션 안에서 논스가 겹칠 수 없다.
     */
    fn frame(&self, from: NodeId, to: NodeId, message: &[u8]) -> Option<Vec<u8>> {
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
                    msg: message,
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

/**
 * @brief 이번 연결의 세션 식별자를 만든다.
 * @details 시작 세션 번호를 접두사로 쓴다. 재시작 뒤에도 번호가 되감기지 않아 이전 세션의
 *          프레임이 새 세션으로 통과하지 못한다.
 */
fn new_session_id(session_prefix: u64) -> Option<[u8; 16]> {
    let mut random = [0u8; 8];
    onetdns_core::try_fill_random(&mut random).ok()?;
    let mut session = [0u8; 16];
    session[..8].copy_from_slice(&session_prefix.to_be_bytes());
    session[8..].copy_from_slice(&random);
    Some(session)
}

/**
 * @brief 프레임의 인증 부가 데이터를 만든다.
 * @details 클러스터 문맥과 헤더(버전·발신자·수신자)을 묶는다. 그래서 다른 클러스터나
 *          다른 수신자에게 프레임을 재사용할 수 없다.
 */
fn frame_aad(cluster_context: &[u8; 32], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(cluster_context.len() + header.len());
    aad.extend_from_slice(cluster_context);
    aad.extend_from_slice(header);
    aad
}

/**
 * @brief 클러스터 구성에서 문맥 해시를 유도한다.
 * @details 구성이 다르면 문맥도 다르다. 실수로 두 클러스터가 같은 비밀을 써도 프레임이
 *          서로 통하지 않는다.
 */
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

/** @brief 클러스터 비밀에서 AEAD 암호를 만든다. 비밀이 짧으면 None. */
fn raft_cipher(secret: &[u8]) -> Option<XChaCha20Poly1305> {
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(secret).into());
    XChaCha20Poly1305::new_from_slice(key.as_slice()).ok()
}

/** @brief Raft 런타임 시작 진입점. */
pub struct RaftServer;

impl RaftServer {
    #[allow(clippy::too_many_arguments)]
    /**
     * @brief Raft 런타임을 시작한다. 리스너, 틱 스레드, 적용 스레드, 노드별 송신 스레드.
     *
     * @param on_apply 커밋된 항목을 상태 기계에 반영하는 콜백. 설정 복제의 착지점이다.
     * @warning 클러스터 비밀은 32바이트 이상이어야 한다. 짧으면 시작을 거부한다. 약한
     *          비밀은 인증이 없는 것과 다름없다.
     * @return 시작 중 실패하면 이미 뜬 스레드를 정리하고 오류를 낸다.
     */
    pub fn spawn(
        self_id: NodeId,
        listen: String,
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
        if let Some(error) = node.fatal_error() {
            return Err(error.to_string());
        }
        let listen_addr: SocketAddr = listen.parse().map_err(|_| {
            format!("Invalid Raft listen address (numeric IP:port required): {listen}")
        })?;

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
            shutdown: shutdown.clone(),
            progress: progress.clone(),
            accepting_proposals,
            proposal_tx,
            pending_proposals: pending_proposals.clone(),
            threads: threads.clone(),
        };

        let listener = TcpListener::bind(listen_addr).map_err(|error| {
            format!("Could not open the Raft listening address {listen_addr}: {error}")
        })?;
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
                                    /** @brief 끝날 때 진행 표시를 지우는 것. */
                                    struct Guard {
                                        /** @brief 지금 열린 연결 수. */
                                        active: Arc<AtomicUsize>,
                                        /** @brief 주소별 연결 수. */
                                        per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
                                        /** @brief 이 연결의 상대 주소. */
                                        ip: IpAddr,
                                    }
                                    impl Drop for Guard {
                                        /** @brief 진행 표시를 지운다. */
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
/**
 * @brief 들어온 클러스터 연결 하나를 처리한다.
 *
 * @details 프레임을 열고, 서명으로 발신자를 확인하고, 재생 구간을 통과시킨 뒤에야 상태
 *          기계에 넘긴다. 세 검사 중 하나라도 실패하면 연결을 끊는다.
 * @warning 인증된 발신자 ID를 상태 기계에 넘긴다. 메시지 본문의 리더·후보 필드를
 *          그대로 믿으면 아무 노드나 리더를 사칭할 수 있다.
 */
fn handle_conn(
    self_id: NodeId,
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
    let mut stream = DeadlineReader::new(stream, shutdown.clone());
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
        let Some(message) = decode_msg(&plaintext) else {
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
/** @brief 프레임 봉하기와 사칭 거부, 그리고 재시작 뒤 상태 복구. */
mod tests {
    use super::*;

    /** @brief Raft 진행 신호를 기다리며 상태 조건을 확인한다. */
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
    /** @brief 마지막 제안 가드가 사라질 때만 apply 진행 신호를 보내는지. */
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
    /** @brief 한 바이트씩 흘려 보내는 상대가 데드라인을 늘리지 못하는지. */
    fn frame_deadline_rejects_slow_drip_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in 0..10 {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });

        let started = Instant::now();
        let stream = TcpStream::connect(addr).unwrap();
        let mut reader = DeadlineReader::new(stream, Arc::new(AtomicBool::new(false)));
        reader.set_deadline(started + Duration::from_millis(120));
        let mut frame = [0u8; 10];
        let error = reader.read_exact(&mut frame).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /** @brief 종료 신호에 곧바로 멈추는지. */
    fn frame_reader_stops_promptly_on_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        let stream = TcpStream::connect(addr).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut reader = DeadlineReader::new(stream, shutdown.clone());
        reader.set_deadline(Instant::now() + Duration::from_secs(5));
        shutdown.store(true, Ordering::Relaxed);
        let started = Instant::now();
        let error = reader.read_exact(&mut [0u8; 1]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_millis(100));
        server.join().unwrap();
    }

    #[test]
    /** @brief 이미 올라온 제안을 마저 처리하고 끝내는지. */
    fn shutdown_drains_an_already_appended_proposal() {
        let applied = Arc::new(AtomicBool::new(false));
        let applied_in_callback = applied.clone();
        let handle = RaftServer::spawn(
            1,
            "127.0.0.1:0".into(),
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
    /** @brief 동시에 올린 제안들이 서로 섞이지 않는지. */
    fn concurrent_proposals_keep_distinct_contiguous_results() {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let applied_in_callback = applied.clone();
        let handle = RaftServer::spawn(
            1,
            "127.0.0.1:0".into(),
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
    /** @brief 묶어 저장한 뒤 앞부분을 놓아주는지. */
    fn applied_state_is_snapshotted_and_log_prefix_is_reclaimed() {
        let applied = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let apply_state = applied.clone();
        let snapshot_state = applied.clone();
        let handle = RaftServer::spawn(
            1,
            "127.0.0.1:0".into(),
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
    /**
     * @brief 상대 노드 상태를 받은 프레임으로만 판정하는지.
     * @details 이쪽으로 보낼 까닭이 없는 노드가 조용한 것은 죽었다는 뜻이 아니므로 알 수
     *          없음으로 남겨야 한다.
     */
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
    /** @brief 떨어져 있던 노드가 인증된 채널로 상태를 되찾는지. */
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
        let mut reserved = Vec::new();
        let mut addresses = Vec::new();
        for _ in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            addresses.push(listener.local_addr().unwrap());
            reserved.push(listener);
        }
        drop(reserved);

        let ids = vec![1, 2, 3];
        let seeds = [[41u8; 32], [42u8; 32], [43u8; 32]];
        let public = seeds.map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let states: Vec<_> = (0..3)
            .map(|_| Arc::new(Mutex::new(Vec::<u8>::new())))
            .collect();
        let spawn_node = |index: usize| {
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
                addresses[index].to_string(),
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

        let mut handles = vec![spawn_node(0), spawn_node(1)];
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
        let peer_entry = |status: &str, id: NodeId| -> String {
            let marker = format!("{{\"id\":{id},");
            let start = status.rfind(&marker).expect("노드 항목");
            let end = status[start..].find('}').expect("항목 끝") + start;
            status[start..=end].to_string()
        };
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

        handles.push(spawn_node(2));
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
    /** @brief 적용이 느려도 심장 박동이 끊기지 않는지. 끊기면 멀쩡한데도 리더를 다시 정한다. */
    fn slow_state_machine_application_does_not_starve_heartbeats() {
        let mut reserved = Vec::new();
        let mut addresses = Vec::new();
        for _ in 0..3 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            addresses.push(listener.local_addr().unwrap());
            reserved.push(listener);
        }
        drop(reserved);

        let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
        let public = seeds.map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let ids = vec![1, 2, 3];
        let apply_started = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for index in 0..3 {
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
                    addresses[index].to_string(),
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
    /** @brief 끝난 뒤 올린 제안을 곧바로 거절하는지. */
    fn proposal_after_shutdown_is_rejected_immediately() {
        let handle = RaftServer::spawn(
            1,
            "127.0.0.1:0".into(),
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
    /** @brief 모든 메시지 종류의 왕복. */
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
    /** @brief 쓰레기와 참거짓이 아닌 값을 거부하는지. */
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
    /** @brief 송신기가 노드 수만큼 AEAD·개인 키 바이트를 복제하지 않는지. */
    fn frame_sealer_shares_cipher_and_signing_key() {
        let cipher = Arc::new(raft_cipher(&[7u8; 32]).unwrap());
        let signing = Arc::new(SigningKey::from_bytes(&[5u8; 32]));
        let sealer = FrameSealer::new(cipher.clone(), signing.clone(), [3u8; 32], 77).unwrap();

        assert!(Arc::ptr_eq(&cipher, &sealer.cipher));
        assert!(Arc::ptr_eq(&signing, &sealer.signing_key));
    }

    #[test]
    /** @brief 프레임이 봉해지고 위조를 알아채는지. */
    fn raft_frame_encrypts_and_authenticates_payload() {
        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let verifying = signing.verifying_key();
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(signing),
            [3u8; 32],
            77,
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
        assert_eq!(plain, message);
    }

    #[test]
    /** @brief 남의 프레임을 옮겨 붙여 사칭하지 못하는지. */
    fn raft_frame_signature_rejects_impersonation() {
        let secret = [7u8; 32];
        let attacker = SigningKey::from_bytes(&[1u8; 32]);
        let victim_vk = SigningKey::from_bytes(&[2u8; 32]).verifying_key();

        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(attacker),
            [3u8; 32],
            77,
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
    /** @brief epoch가 유지되면서 뒷부분은 예측할 수 없는지. */
    fn session_ids_preserve_the_epoch_and_randomize_the_suffix() {
        let first = new_session_id(0x0102_0304_0506_0708).expect("OS CSPRNG");
        let second = new_session_id(0x1112_1314_1516_1718).expect("OS CSPRNG");

        assert_eq!(&first[..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&second[..8], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_ne!(&first[8..], &second[8..]);
    }

    #[test]
    /** @brief 일련번호를 다 쓰면 되돌아가지 않는지. 되돌아가면 이전 프레임을 다시 쓸 수 있다. */
    fn frame_seq_exhaustion_is_permanent() {
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&[7u8; 32]).unwrap()),
            Arc::new(SigningKey::from_bytes(&[5u8; 32])),
            [3u8; 32],
            77,
        )
        .unwrap();
        sealer.sequence.store(u64::MAX, Ordering::Relaxed);

        assert!(sealer.frame(1, 2, b"x").is_none());
        assert!(sealer.frame(1, 2, b"x").is_none());
    }

    #[test]
    /** @brief 너무 큰 기록을 적어 내보내지 않는지. */
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
    /** @brief 스냅숏 조각의 크기와 형식을 확인하는지. */
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

    /** @brief 테스트용 nonce. */
    fn replay_nonce(session: u128, sequence: u64) -> [u8; RAFT_NONCE_LEN] {
        let mut nonce = [0u8; RAFT_NONCE_LEN];
        nonce[..16].copy_from_slice(&session.to_be_bytes());
        nonce[16..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    #[test]
    /** @brief 이미 본 프레임과 이전 epoch를 거부하는지. 안 그러면 가로챈 프레임을 그대로 다시 보낼 수 있다. */
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
    /** @brief 프레임이 받는 이와 클러스터에 묶이는지. 안 묶이면 다른 클러스터로 옮겨 붙일 수 있다. */
    fn frame_signature_binds_destination_and_cluster_context() {
        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let verifying = signing.verifying_key();
        let sealer = FrameSealer::new(
            Arc::new(raft_cipher(&secret).unwrap()),
            Arc::new(signing),
            [3u8; 32],
            77,
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
