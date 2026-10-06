use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use onetdns_tls::engine::{ClientHandshake, Level, SecretPair, ServerHandshake};
use onetdns_tls::{ClientConfig, ServerConfig};

use crate::frame::{self, Frame};
use crate::packet::{self, ptype};
use crate::params::TransportParams;
use crate::protect::Aead;
use crate::{
    derive_packet_keys, derive_updated_kv, initial_secrets, next_key_update_secret, PacketKeys,
};

/** @brief Initial 번호 공간. 핸드셰이크 초반에 쓴다. */
const INITIAL: usize = 0;
/** @brief Handshake 번호 공간. */
const HANDSHAKE: usize = 1;
/** @brief 응용 데이터 번호 공간. 핸드셰이크 뒤의 모든 통신이 여기 속한다. */
const APP: usize = 2;

/** @brief 내보낼 데이터그램 크기. 흔한 경로에서 조각나지 않는 값으로 잡는다. */
/**
 * @brief Initial 을 담은 데이터그램의 최소 크기.
 * @details RFC 9000이 정한 값이다. 받는 쪽은 이보다 작은 데이터그램의 Initial 을
 *          버려도 되므로, 채우지 않으면 상대 구현에 따라 핸드셰이크가 조용히 멈춘다.
 */
const MIN_INITIAL_DATAGRAM: usize = 1200;

const MAX_DATAGRAM: usize = 1350;

/**
 * @brief 받아들일 데이터그램 크기.
 *
 * @details 이 값을 그대로 max_udp_payload_size로 알린다. 실제로 읽는 버퍼보다 큰 값을
 *          알리면 상대가 그 크기로 보내도 되는데 이쪽은 잘라 읽게 되고, 잘린 패킷은 인증에
 *          실패해 조용히 버려져 핸드셰이크가 멈춘다. 소켓에서 읽는 쪽도 이 상수를 써야 한다.
 * @invariant RFC 9000이 정한 하한 1200 이상이고, 이쪽이 내보내는 크기보다 작지 않아야 한다.
 */
pub const MAX_RECV_UDP_PAYLOAD: u64 = MAX_DATAGRAM as u64;

/** @brief 위 두 하한을 어기면 컴파일이 멈춘다. */
const _: [(); 0] = [(); (MAX_RECV_UDP_PAYLOAD < 1200) as usize];
const _: [(); 0] = [(); (MAX_RECV_UDP_PAYLOAD < MAX_DATAGRAM as u64) as usize];

/** @brief 패킷 하나에 담을 프레임 바이트. 헤더와 태그 몫을 뺀 값이다. */
const MAX_PACKET_PAYLOAD: usize = 1000;
/** @brief 스트림 프레임 하나에 담을 데이터 크기. */
const STREAM_FRAME_CHUNK: usize = 900;
/** @brief 받아들일 Retry 토큰 길이. */
const MAX_RETRY_TOKEN: usize = 256;

/** @brief 핸드셰이크 데이터 프레임 하나에 담을 크기. */
const CRYPTO_CHUNK: usize = 900;
/** @brief 순서가 어긋난 핸드셰이크 데이터를 모아 둘 상한. 없으면 큰 오프셋 하나로 메모리를 잡아 둘 수 있다. */
const MAX_CRYPTO_REASSEMBLY: u64 = 1 << 20;
/** @brief 스트림 하나에 모아 둘 상한. */
const MAX_STREAM_REASSEMBLY: u64 = 1 << 18;
/** @brief 연결 전체에 모아 둘 상한. 스트림당 상한만으로는 스트림을 많이 열어 우회된다. */
const MAX_CONNECTION_REASSEMBLY: u64 = 1 << 20;
/** @brief 보내려고 쌓아 둘 바이트 상한. */
const MAX_CONNECTION_SEND_BUFFER: usize = 1 << 20;
/** @brief 대기 중인 전송 요청 수 상한. */
const MAX_PENDING_SEND_OPS: usize = 512;
/** @brief 대기 중인 조각 수 상한. */
const MAX_PENDING_FRAGMENTS: usize = 256;
/** @brief 설정과 무관하게 넘길 수 없는 스트림 수. */
const MAX_STREAMS_HARD: usize = 256;
/** @brief 확인 프레임에 담을 구간 수. */
const MAX_ACK_RANGES: usize = 32;
/** @brief 중복 판정을 위해 기억할 패킷 번호 범위. 비트맵 하나에 담기는 크기다. */
const MAX_RECV_PACKET_HISTORY: usize = u128::BITS as usize;
/** @brief 흐름 제어 값의 상한. 상대가 부른 값을 여기서 자른다. */
const MAX_FLOW_CONTROL: u64 = 1 << 60;
/**
 * @brief PTO 한 번에 혼잡 윈도우를 넘겨 보낼 수 있는 패킷 수.
 * @details RFC 9002 가 허용하는 두 개다. 데이터그램 하나를 잃었다고 바로 다음 PTO 까지
 *          기다리지 않게 하되, 윈도우를 무시하는 양은 이만큼으로 묶는다.
 */
const PROBE_PACKETS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 패킷 종류. 확인 처리 방식이 갈린다. */
enum PacketKind {
    /** @brief 핸드셰이크를 시작하는 패킷. */
    Initial,
    /** @brief 핸드셰이크 중의 패킷. */
    Handshake,
    /** @brief 왕복 없이 보내는 자료. */
    ZeroRtt,
    /** @brief 핸드셰이크를 마친 뒤의 패킷. */
    OneRtt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * @brief QUIC 연결의 오류.
 * @details StreamClosed 만 스트림 하나에 그치는 오류라서 연결은 계속 쓸 수 있다.
 */
pub enum QuicError {
    /** @brief TLS 쪽에서 실패했다. */
    Tls,
    /** @brief 프레임이 프로토콜에 맞지 않는다. */
    Frame,
    /** @brief 상대가 허락한 양을 넘겼다. */
    FlowControl,
    /** @brief 상대가 허락한 스트림 수를 넘겼다. */
    StreamLimit,
    /** @brief 연결이 이미 닫혔다. */
    Closed,
    /**
     * @brief 이 스트림으로는 더 보낼 수 없다.
     * @details 상대가 STOP_SENDING 으로 답을 거절했거나 이쪽이 이미 끝을 보낸 스트림이다.
     */
    StreamClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 연결이 왜 실패했는지 알려 주는 진단. 로그에만 쓴다. */
pub enum QuicDiagnostic {
    /** @brief 긴 패킷의 보호를 풀지 못했다. */
    LongPacketProtection,
    /** @brief 상대가 알린 전송 설정이 어긋났다. */
    TransportParameters,
}

impl QuicDiagnostic {
    /** @brief 어느 단계에서 실패했는지. */
    pub const fn stage(self) -> &'static str {
        match self {
            Self::LongPacketProtection => "long_packet_protection",
            Self::TransportParameters => "transport_parameters",
        }
    }
}

impl std::fmt::Display for QuicDiagnostic {
    /** @brief 사람이 읽을 설명. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LongPacketProtection => {
                "Could not verify header protection or authentication of a QUIC long-header packet"
            }
            Self::TransportParameters => "Peer QUIC transport parameters are invalid",
        })
    }
}

impl std::fmt::Display for QuicError {
    /** @brief 사람이 읽을 설명. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            QuicError::Tls => "TLS handshake error",
            QuicError::Frame => "Could not encode a QUIC frame",
            QuicError::FlowControl => "Flow control violation",
            QuicError::StreamLimit => "QUIC stream limit exceeded",
            QuicError::Closed => "Connection closed",
            QuicError::StreamClosed => "Stream no longer accepts data",
        };
        f.write_str(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 이 연결에서 이쪽이 클라이언트인지 서버인지. */
pub enum Role {
    /** @brief 연결을 받는 쪽. */
    Server,
    /** @brief 연결을 거는 쪽. */
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 상대가 알린 종료 사유. */
pub struct PeerClose {
    /** @brief 상대가 알린 오류 번호. */
    pub error_code: u64,
    /** @brief 그 오류를 일으킨 프레임 종류. */
    pub frame_type: Option<u64>,
    /** @brief 상대가 적은 사유. */
    pub reason: Vec<u8>,
}

/**
 * @brief 이쪽이 알릴 매개변수를 안전한 범위로 자른다.
 * @warning 설정으로 지나치게 큰 값을 넣어도 여기서 막힌다. 흐름 제어 윈도우가 크면 상대가
 *          그만큼 이쪽 메모리를 잡아 둘 수 있다.
 */
fn normalize_local_transport_params(mut tp: TransportParams) -> TransportParams {
    tp.max_udp_payload_size = MAX_RECV_UDP_PAYLOAD;
    tp.initial_max_data = tp.initial_max_data.min(MAX_CONNECTION_REASSEMBLY);
    tp.initial_max_stream_data_bidi_local = tp
        .initial_max_stream_data_bidi_local
        .clamp(1, MAX_STREAM_REASSEMBLY);
    tp.initial_max_stream_data_bidi_remote = tp
        .initial_max_stream_data_bidi_remote
        .clamp(1, MAX_STREAM_REASSEMBLY);
    tp.initial_max_stream_data_uni = tp
        .initial_max_stream_data_uni
        .clamp(1, MAX_STREAM_REASSEMBLY);
    tp.initial_max_streams_bidi = tp.initial_max_streams_bidi.min(MAX_STREAMS_HARD as u64);
    tp.initial_max_streams_uni = tp.initial_max_streams_uni.min(MAX_STREAMS_HARD as u64);
    tp
}

/** @brief 암호화 수준에 대응하는 번호 공간. */
fn level_space(level: Level) -> usize {
    match level {
        Level::Initial => INITIAL,
        Level::Handshake => HANDSHAKE,
        Level::Application => APP,
    }
}

/** @brief 번호 공간에 대응하는 암호화 수준. */
fn space_level(space: usize) -> Level {
    match space {
        INITIAL => Level::Initial,
        HANDSHAKE => Level::Handshake,
        _ => Level::Application,
    }
}

/** @brief 암호 스위트에 맞는 AEAD와 키 길이. */
fn suite_aead(suite: u16) -> (Aead, usize) {
    match suite {
        0x1302 => (Aead::Aes256Gcm, 32),
        0x1303 => (Aead::ChaCha20Poly1305, 32),
        _ => (Aead::Aes128Gcm, 16),
    }
}

#[derive(Default)]
/**
 * @brief 순서가 어긋나 온 데이터를 이어 붙이는 버퍼.
 * @details 오프셋이 띄엄띄엄 올 수 있어, 이어지는 부분만 꺼내고 나머지는 모아 둔다.
 */
struct Reasm {
    /** @brief 여기까지는 빈틈없이 받았다. */
    recv_offset: u64,
    /** @brief 아직 앞이 비어 이어 붙이지 못한 조각들. */
    pending: Vec<(u64, Vec<u8>)>,
    /** @brief 그 조각들이 차지한 바이트. 상한을 세는 데 쓴다. */
    pending_bytes: usize,
}

impl Reasm {
    /** @brief 조각 목록의 예약 슬롯과 각 조각 버퍼가 실제로 보유한 바이트. */
    fn retained_payload_bytes(&self) -> usize {
        self.pending
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, Vec<u8>)>())
            .saturating_add(self.pending.iter().fold(0usize, |total, (_, fragment)| {
                total.saturating_add(fragment.capacity())
            }))
    }

    /**
     * @brief 조각을 넣고 이어진 만큼 꺼낸다.
     * @warning 모아 둔 양에 상한이 있다. 없으면 큰 오프셋에 한 바이트를 보내는 것만으로
     *          이쪽 메모리를 잡아 둘 수 있다.
     */
    fn push(&mut self, offset: u64, data: Vec<u8>, max_offset: u64) -> Result<Vec<u8>, QuicError> {
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| QuicError::FlowControl)?)
            .ok_or(QuicError::FlowControl)?;
        let max_bytes = usize::try_from(max_offset).map_err(|_| QuicError::FlowControl)?;
        if end > max_offset || data.len() > max_bytes {
            return Err(QuicError::FlowControl);
        }
        if end <= self.recv_offset {
            return Ok(Vec::new());
        }

        let start = offset.max(self.recv_offset);
        let trim = usize::try_from(start - offset).map_err(|_| QuicError::FlowControl)?;
        let data = if trim == 0 {
            data
        } else {
            data[trim..].to_vec()
        };

        let mut overlap_bytes = 0usize;
        let mut touches_existing = false;
        for (existing_offset, existing) in &self.pending {
            let existing_end = existing_offset
                .checked_add(existing.len() as u64)
                .ok_or(QuicError::FlowControl)?;
            if existing_end < start || *existing_offset > end {
                continue;
            }
            touches_existing = true;
            let overlap_start = start.max(*existing_offset);
            let overlap_end = end.min(existing_end);
            if overlap_start < overlap_end {
                let incoming_start =
                    usize::try_from(overlap_start - start).map_err(|_| QuicError::FlowControl)?;
                let existing_start = usize::try_from(overlap_start - *existing_offset)
                    .map_err(|_| QuicError::FlowControl)?;
                let overlap_len = usize::try_from(overlap_end - overlap_start)
                    .map_err(|_| QuicError::FlowControl)?;
                if data[incoming_start..incoming_start + overlap_len]
                    != existing[existing_start..existing_start + overlap_len]
                {
                    return Err(QuicError::Frame);
                }
                overlap_bytes = overlap_bytes.saturating_add(overlap_len);
            }
        }

        let additional = data.len().saturating_sub(overlap_bytes);
        if self.pending_bytes.saturating_add(additional) > max_bytes
            || (self.pending.len() >= MAX_PENDING_FRAGMENTS && !touches_existing)
        {
            return Err(QuicError::FlowControl);
        }

        let mut fragments = std::mem::take(&mut self.pending);
        fragments.push((start, data));
        fragments.sort_unstable_by_key(|(fragment_offset, _)| *fragment_offset);
        let mut merged: Vec<(u64, Vec<u8>)> = Vec::with_capacity(fragments.len());
        for (fragment_offset, fragment) in fragments {
            let Some((last_offset, last)) = merged.last_mut() else {
                merged.push((fragment_offset, fragment));
                continue;
            };
            let last_end = last_offset
                .checked_add(last.len() as u64)
                .ok_or(QuicError::FlowControl)?;
            if fragment_offset > last_end {
                merged.push((fragment_offset, fragment));
                continue;
            }
            let covered =
                usize::try_from(last_end - fragment_offset).map_err(|_| QuicError::FlowControl)?;
            if covered < fragment.len() {
                last.extend_from_slice(&fragment[covered..]);
            }
        }

        let mut out = Vec::new();
        let mut remaining = Vec::with_capacity(merged.len());
        let mut fragments = merged.into_iter();
        while let Some((fragment_offset, fragment)) = fragments.next() {
            if fragment_offset > self.recv_offset {
                remaining.push((fragment_offset, fragment));
                remaining.extend(fragments);
                break;
            }
            let fragment_end = fragment_offset
                .checked_add(fragment.len() as u64)
                .ok_or(QuicError::FlowControl)?;
            if fragment_end <= self.recv_offset {
                continue;
            }
            let start = usize::try_from(self.recv_offset - fragment_offset)
                .map_err(|_| QuicError::FlowControl)?;
            out.extend_from_slice(&fragment[start..]);
            self.recv_offset = fragment_end;
        }
        self.pending_bytes = remaining.iter().fold(0usize, |total, (_, fragment)| {
            total.saturating_add(fragment.len())
        });
        self.pending = remaining;
        Ok(out)
    }
}

/** @brief 프레임 하나가 별도 힙 버퍼에 보유한 payload 바이트. */
fn frame_retained_payload_bytes(frame: &Frame) -> usize {
    match frame {
        Frame::Ack { ranges, .. } => ranges
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, u64)>()),
        Frame::Crypto { data, .. } | Frame::Stream { data, .. } => data.capacity(),
        Frame::ConnectionClose { reason, .. } => reason.capacity(),
        _ => 0,
    }
}

/** @brief 프레임 목록의 예약 슬롯과 중첩 버퍼가 실제로 보유한 바이트. */
fn frames_retained_payload_bytes(frames: &[Frame], capacity: usize) -> usize {
    capacity
        .saturating_mul(std::mem::size_of::<Frame>())
        .saturating_add(frames.iter().fold(0usize, |total, frame| {
            total.saturating_add(frame_retained_payload_bytes(frame))
        }))
}

/** @brief 스트림 번호 구간 목록이 보유한 바이트. */
fn stream_ranges_retained_bytes(ranges: &[Vec<(u64, u64)>; 4]) -> usize {
    ranges.iter().fold(0usize, |total, range| {
        total.saturating_add(
            range
                .capacity()
                .saturating_mul(std::mem::size_of::<(u64, u64)>()),
        )
    })
}

/**
 * @brief 표준 HashMap의 예약 bucket을 보수적으로 charge한다.
 * @details capacity는 다시 할당하지 않고 넣을 수 있는 항목 수라 실제 bucket 수보다 작다.
 *          항목+control byte의 두 배와 작은 고정 여유를 잡아 현재 SwissTable 배치를
 *          과소계상하지 않는다. 정확한 RSS 추정이 아니라 공격자가 쓸 수 있는 상한이다.
 */
fn hash_map_retained_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    if map.capacity() == 0 {
        return 0;
    }
    map.capacity()
        .saturating_mul(std::mem::size_of::<(K, V)>().saturating_add(1))
        .saturating_mul(2)
        .saturating_add(64)
}

/** @brief 전송 설정 안의 연결 식별자 버퍼가 보유한 바이트. */
fn transport_params_retained_bytes(params: &TransportParams) -> usize {
    params
        .original_destination_connection_id
        .as_ref()
        .map_or(0, Vec::capacity)
        .saturating_add(
            params
                .initial_source_connection_id
                .as_ref()
                .map_or(0, Vec::capacity),
        )
        .saturating_add(
            params
                .retry_source_connection_id
                .as_ref()
                .map_or(0, Vec::capacity),
        )
}

/** @brief 패킷 보호 키 세트의 세 비밀 버퍼가 보유한 바이트. */
fn packet_keys_retained_bytes(keys: &PacketKeys) -> usize {
    keys.key
        .capacity()
        .saturating_add(keys.iv.capacity())
        .saturating_add(keys.hp.capacity())
}

#[derive(Default)]
/** @brief 받는 쪽 스트림 하나의 상태. */
struct StreamRecv {
    /** @brief 빈틈을 메우는 슬롯. */
    asm: Reasm,
    /** @brief 이어 붙인 자료. */
    buf: Vec<u8>,
    /** @brief 상대가 알린 끝 위치. 아직이면 없다. */
    fin_offset: Option<u64>,
    /** @brief 끝까지 다 받았는지. */
    done: bool,
    /** @brief 지금까지 본 가장 먼 위치. 흐름 제어를 세는 데 쓴다. */
    highest_offset: u64,
    /** @brief 위에서 가져간 바이트. */
    app_consumed: u64,
}

#[derive(Default)]
/** @brief 번호 공간 하나의 상태. 키와 패킷 번호 추적이 여기 있다. */
struct SpaceState {
    /** @brief 이 단계에서 보낼 때 쓰는 키. */
    send_keys: Option<(Aead, PacketKeys)>,
    /** @brief 이 단계에서 받을 때 쓰는 키. */
    recv_keys: Option<(Aead, PacketKeys)>,
    /** @brief 다음에 붙일 패킷 번호. */
    next_pn: u64,
    /** @brief 지금까지 받은 가장 큰 패킷 번호. */
    largest_recv: Option<u64>,
    /** @brief 그 언저리에서 무엇을 받았는지 나타내는 비트. */
    recv_mask: u128,
    /** @brief 아직 받았다고 알리지 않은 패킷 번호들. */
    recv_pns: Vec<u64>,
    /** @brief 알릴 것이 밀려 있는지. */
    ack_pending: bool,
    /** @brief 핸드셰이크 자료를 어디까지 보냈는지. */
    send_crypto_offset: u64,
    /** @brief 아직 보내지 못한 핸드셰이크 자료. */
    out_crypto: Vec<u8>,
    /** @brief 받은 핸드셰이크 자료의 빈틈을 메우는 슬롯. */
    crypto_asm: Reasm,

    /** @brief 보냈지만 아직 받았다는 답이 없는 패킷들. */
    sent: Vec<SentPacket>,

    /** @brief 다시 보내야 할 프레임들. */
    rtx: Vec<Frame>,

    /** @brief 상대가 확인한 가장 큰 패킷 번호. 손실 판정의 기준이다. */
    largest_acked: Option<u64>,
    /**
     * @brief 확인을 끌어내는 패킷을 이 공간에서 마지막으로 보낸 시각.
     * @details PTO 는 가장 오래된 미확인 패킷이 아니라 이 시각에서 잰다. 오래된 패킷에서 재면
     *          프로브를 보낸 직후에도 데드라인이 이미 지나 있어 지수 증가가 먹히지 않는다.
     */
    last_ack_eliciting_ms: u64,
    /** @brief 시간 기준으로 아직 잃었다고 볼 수 없는 패킷이 잃은 것으로 바뀌는 시각. */
    loss_time_ms: Option<u64>,
    /**
     * @brief 이 공간의 키와 상태를 버렸는지.
     * @details 버린 공간은 다시 살리지 않는다. 늦게 온 Initial 로 키를 다시 만들면 끝난
     *          핸드셰이크 상태가 되살아난다.
     */
    discarded: bool,
}

impl SpaceState {
    /**
     * @brief 이 패킷 번호를 처음 보는지 확인하고 기록한다.
     * @warning 중복을 받아들이면 재생 공격이 성립한다. 비트맵으로 최근 범위를 기억하고,
     *          그보다 오래된 번호는 아예 거부한다.
     */
    fn accept_packet_number(&mut self, pn: u64) -> bool {
        let Some(largest) = self.largest_recv else {
            self.largest_recv = Some(pn);
            self.recv_mask = 1;
            return true;
        };
        if pn > largest {
            let shift = pn - largest;
            self.recv_mask = if shift >= u128::BITS as u64 {
                1
            } else {
                (self.recv_mask << shift) | 1
            };
            self.largest_recv = Some(pn);
            return true;
        }

        let distance = largest - pn;
        if distance >= u128::BITS as u64 {
            return false;
        }
        let bit = 1u128 << distance;
        if self.recv_mask & bit != 0 {
            return false;
        }
        self.recv_mask |= bit;
        true
    }
}

/** @brief 보낸 패킷 하나. 확인이나 손실 판정 때까지 가지고 있는다. */
struct SentPacket {
    /** @brief 이 패킷의 번호. */
    pn: u64,
    /** @brief 보낸 시각. */
    time_ms: u64,
    /** @brief 상대가 받았다고 알려야 하는 패킷인지. */
    ack_eliciting: bool,

    /** @brief 이 패킷의 크기. 흐르는 양을 세는 데 쓴다. */
    size: u64,

    /** @brief 이 패킷에 담은 프레임들. 잃으면 다시 보낸다. */
    frames: Vec<Frame>,
}

/** @brief 윈도우가 열리기를 기다리는 전송 요청. */
struct PendingStreamSend {
    /** @brief 보낼 스트림. */
    id: u64,
    /** @brief 이 조각이 시작하는 위치. */
    offset: u64,
    /** @brief 보낼 자료. */
    data: Vec<u8>,
    /** @brief 어디까지 보냈는지. */
    cursor: usize,
    /** @brief 이것이 마지막 조각인지. */
    fin: bool,
    /** @brief 이 조각을 몇 번 담아 보냈는지. */
    copies: usize,
}

/**
 * @brief QUIC 연결 하나. 소켓을 모르는 순수 상태 기계다.
 *
 * @details 데이터그램을 넣으면 상태가 바뀌고, 내보낼 데이터그램을 꺼내 간다. 시간도
 *          밖에서 넣어 준다.
 * @note 이 설계 덕분에 네트워크나 실제 시간 없이 프로토콜 전체를 결정적으로 테스트할 수 있다.
 */
pub struct Connection {
    /** @brief 이쪽이 받는 쪽인지 거는 쪽인지. */
    role: Role,

    /** @brief 받는 쪽 TLS 상태 기계. */
    tls_server: Option<ServerHandshake>,
    /** @brief 받는 쪽 공유 설정. Initial 전에도 큰 인증 자료를 연결마다 복제하지 않는다. */
    cfg_server: Option<Arc<ServerConfig>>,
    /** @brief 이쪽이 알릴 전송 설정. */
    base_tp: TransportParams,
    /** @brief 거는 쪽 TLS 상태 기계. */
    tls_client: Option<ClientHandshake>,
    /** @brief 단계별 패킷 상태. */
    spaces: [SpaceState; 3],
    /** @brief 상대가 이쪽을 부를 때 쓰는 식별자. */
    local_cid: Vec<u8>,
    /** @brief 이쪽이 상대를 부를 때 쓰는 식별자. */
    remote_cid: Vec<u8>,
    /** @brief 처음 받은 식별자. 첫 키를 여기서 이끌어 낸다. */
    initial_dcid: Vec<u8>,
    /** @brief 핸드셰이크가 끝났는지. */
    handshake_complete: bool,
    /**
     * @brief 핸드셰이크가 확정됐는지.
     * @details 서버는 핸드셰이크가 끝나는 순간, 클라이언트는 HANDSHAKE_DONE 을 받았을 때
     *          확정된다. 확정되면 Initial 과 Handshake 공간을 버리고 응용 데이터 PTO 를 건다.
     */
    handshake_confirmed: bool,
    /** @brief 핸드셰이크 결과가 앞선 세션을 재개한 것인지. 서버 TLS 상태를 버린 뒤에도 남긴다. */
    handshake_resumed: bool,
    /** @brief 핸드셰이크 결과가 조기 데이터를 받아들였는지. */
    handshake_early_accepted: bool,
    /** @brief 연결이 닫혔는지. */
    closed: bool,
    /** @brief 어디서 실패했는지. 로그에 남긴다. */
    diagnostic: Option<QuicDiagnostic>,
    /** @brief 상대가 알린 종료 사유. */
    peer_close: Option<PeerClose>,
    /** @brief 상대가 알린 전송 설정. */
    peer_tp: Option<TransportParams>,
    /** @brief 협상한 ALPN. */
    alpn: Option<Vec<u8>>,
    /** @brief 상대가 인증서로 자신을 증명했는지. */
    client_authenticated: bool,
    /** @brief 그 인증서에 적힌 신원. */
    client_auth_identity: Option<String>,
    /** @brief 내보낼 데이터그램들. */
    out_datagrams: VecDeque<Vec<u8>>,

    /** @brief 핸드셰이크 뒤 단계에서 보낼 프레임들. */
    out_frames_app: Vec<Frame>,
    /**
     * @brief 이쪽이 알릴 종료 프레임. 한 번만 보내고 비운다.
     * @details 혼잡 윈도우와 무관하게 나가야 한다. 못 보내면 상대는 자기 유휴 데드라인까지 기다린다.
     */
    close_frame: Option<Frame>,
    /** @brief 받는 중인 스트림들. */
    streams: HashMap<u64, StreamRecv>,
    /** @brief 이미 끝난 스트림 번호 구간들. 같은 번호를 다시 열지 못하게 한다. */
    closed_recv_ranges: [Vec<(u64, u64)>; 4],
    /** @brief 상대가 끊은 스트림들. */
    reset_streams: Vec<(u64, u64)>,
    /** @brief 다 받은 스트림과 그 자료. */
    completed_streams: Vec<(u64, Vec<u8>)>,
    /** @brief 모든 스트림에서 본 가장 먼 위치의 합. 흐름 제어를 센다. */
    recv_total_highest: u64,
    /** @brief 아직 위로 넘기지 못하고 잡은 바이트. */
    recv_buffered: u64,
    /** @brief 이쪽이 상대에게 허락한 전체 양. */
    local_max_data: u64,
    /** @brief 스트림마다 허락한 양. */
    local_stream_max: HashMap<u64, u64>,
    /** @brief 이쪽이 허락한 양방향 스트림 수. */
    local_max_streams_bidi: u64,
    /** @brief 이쪽이 허락한 단방향 스트림 수. */
    local_max_streams_uni: u64,

    /** @brief 위로 넘길 준비가 된 자료들. */
    readable: Vec<(u64, Vec<u8>, bool)>,
    /** @brief 스트림마다 어디까지 보냈는지. */
    send_offsets: HashMap<u64, u64>,
    /** @brief 아직 보내지 못한 스트림 자료들. */
    pending_stream_sends: VecDeque<PendingStreamSend>,
    /** @brief 이미 다 보낸 스트림 번호 구간들. */
    sealed_send_ranges: [Vec<(u64, u64)>; 4],
    /** @brief 이쪽이 연 스트림 번호 구간들. */
    opened_send_ranges: [Vec<(u64, u64)>; 4],
    /** @brief 이쪽이 닫은 스트림 번호 구간들. */
    closed_send_ranges: [Vec<(u64, u64)>; 4],
    /** @brief 상대가 그만 보내라고 한 스트림 구간들. */
    stopped_send_ranges: [Vec<(u64, u64)>; 4],
    /** @brief 지금까지 보낸 전체 바이트. */
    send_total: u64,
    /** @brief 상대가 이쪽에 허락한 전체 양. */
    peer_max_data: u64,
    /** @brief 상대가 스트림마다 허락한 양. */
    peer_stream_max: HashMap<u64, u64>,
    /** @brief 상대가 허락한 양방향 스트림 수. */
    peer_max_streams_bidi: u64,
    /** @brief 상대가 허락한 단방향 스트림 수. */
    peer_max_streams_uni: u64,

    /** @brief 앞선 연결에서 기억해 둔 상대 설정. 왕복 없이 보낼 때 쓴다. */
    early_peer_tp: Option<TransportParams>,
    /** @brief 다음에 열 단방향 스트림 번호. */
    next_uni: u64,

    /** @brief 상대가 준 재시도 토큰. */
    retry_token: Vec<u8>,

    /** @brief 재시도를 이미 한 번 했는지. 되풀이하면 무한히 돈다. */
    retry_done: bool,

    /**
     * @brief 상대가 보낸 Retry 패킷의 출발지 식별자.
     * @details 매개변수 대조는 이 값과 해야 한다. 상대는 Retry 뒤에 보내는 첫 Initial에서
     *          다른 식별자를 골라도 되므로, 지금 쓰는 remote_cid와 같다고 볼 수 없다.
     */
    retry_scid: Option<Vec<u8>>,

    /** @brief 처음 보낸 핸드셰이크 자료. 재시도할 때 그대로 다시 쓴다. */
    initial_crypto: Vec<u8>,

    /** @brief 지금 시각. */
    now_ms: u64,

    /** @brief 마지막으로 무언가 오간 시각. */
    last_activity_ms: u64,

    /** @brief 부드럽게 다듬은 왕복 시간. */
    srtt_ms: u64,

    /** @brief 왕복 시간의 흔들림. */
    rttvar_ms: u64,

    /** @brief 왕복 시간을 한 번이라도 쟀는지. */
    have_rtt: bool,

    /** @brief 지금까지 본 가장 짧은 왕복 시간. */
    min_rtt_ms: u64,

    /** @brief 마지막으로 잰 왕복 시간. 부하로 튄 표본이 손실 판정을 앞당기지 않게 함께 본다. */
    latest_rtt_ms: u64,

    /** @brief 연달아 데드라인을 넘긴 횟수. 다음 데드라인을 늘리는 데 쓴다. */
    pto_count: u32,

    /** @brief 한 번에 흘려보낼 수 있는 양. */
    cwnd: u64,

    /** @brief 이 값을 넘으면 천천히 늘린다. */
    ssthresh: u64,

    /** @brief 지금 답을 기다리는 바이트. */
    bytes_in_flight: u64,

    /** @brief 혼잡을 겪기 시작한 시각. 그 전에 보낸 것은 다시 줄이지 않는다. */
    recovery_start_ms: Option<u64>,

    /** @brief 핸드셰이크 뒤 보낼 때 쓰는 비밀. */
    app_send_secret: Vec<u8>,
    /** @brief 핸드셰이크 뒤 받을 때 쓰는 비밀. */
    app_recv_secret: Vec<u8>,
    /** @brief 쓰는 암호 스위트. */
    app_suite: u16,

    /** @brief 보낼 때의 키 세대. */
    send_key_phase: bool,
    /** @brief 받을 때의 키 세대. */
    recv_key_phase: bool,

    /** @brief 키를 교체해도 되는지. 교체하자마자 또 교체하면 상대가 따라오지 못한다. */
    key_update_allowed: bool,

    /** @brief 상대가 준 상태 없는 초기화 토큰. */
    peer_reset_token: Option<[u8; 16]>,

    /** @brief 그 초기화를 받았는지. */
    reset_received: bool,

    /** @brief 유휴 데드라인이 지나 닫혔는지. */
    idle_timed_out: bool,

    /** @brief 보내야 할 경로 확인 값. */
    path_challenge_pending: Option<[u8; 8]>,

    /** @brief 지금 경로가 확인됐는지. */
    path_validated: bool,

    /** @brief 왕복 없이 보낼 때 쓰는 키. */
    early_send_keys: Option<(Aead, PacketKeys)>,

    /** @brief 왕복 없이 받을 때 쓰는 키. */
    early_recv_keys: Option<(Aead, PacketKeys)>,

    /** @brief 왕복 없이 보낼 프레임들. */
    out_frames_early: Vec<Frame>,

    /** @brief 그 프레임들의 사본. 상대가 거절하면 정식으로 다시 보낸다. */
    early_backup: Vec<Frame>,

    /** @brief 왕복 없이 이미 보냈는지. */
    early_sent: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.app_send_secret.zeroize();
        self.app_recv_secret.zeroize();
    }
}

impl Connection {
    /** @brief 서버 쪽 연결을 만든다. */
    pub fn new_server(cfg: Arc<ServerConfig>, local_cid: Vec<u8>, tp: TransportParams) -> Self {
        let tp = normalize_local_transport_params(tp);
        let cid_valid = (1..=20).contains(&local_cid.len());
        let local_max_data = tp.initial_max_data;
        let local_max_streams_bidi = tp.initial_max_streams_bidi;
        let local_max_streams_uni = tp.initial_max_streams_uni;
        Connection {
            role: Role::Server,
            tls_server: None,
            cfg_server: Some(cfg),
            base_tp: tp,
            tls_client: None,
            spaces: Default::default(),
            local_cid,
            remote_cid: Vec::new(),
            initial_dcid: Vec::new(),
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_resumed: false,
            handshake_early_accepted: false,
            closed: !cid_valid,
            diagnostic: None,
            peer_close: None,
            peer_tp: None,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            out_datagrams: VecDeque::new(),
            out_frames_app: Vec::new(),
            close_frame: None,
            streams: HashMap::new(),
            closed_recv_ranges: Default::default(),
            reset_streams: Vec::new(),
            completed_streams: Vec::new(),
            recv_total_highest: 0,
            recv_buffered: 0,
            local_max_data,
            local_stream_max: HashMap::new(),
            local_max_streams_bidi,
            local_max_streams_uni,
            readable: Vec::new(),
            send_offsets: HashMap::new(),
            pending_stream_sends: VecDeque::new(),
            sealed_send_ranges: Default::default(),
            opened_send_ranges: Default::default(),
            closed_send_ranges: Default::default(),
            stopped_send_ranges: Default::default(),
            send_total: 0,
            peer_max_data: 0,
            peer_stream_max: HashMap::new(),
            peer_max_streams_bidi: 0,
            peer_max_streams_uni: 0,
            early_peer_tp: None,
            next_uni: 0,
            retry_token: Vec::new(),
            retry_done: false,
            retry_scid: None,
            initial_crypto: Vec::new(),
            now_ms: 0,
            last_activity_ms: 0,
            srtt_ms: 333,
            rttvar_ms: 166,
            have_rtt: false,
            min_rtt_ms: u64::MAX,
            latest_rtt_ms: 0,
            pto_count: 0,
            cwnd: 10 * MAX_DATAGRAM as u64,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_ms: None,
            app_send_secret: Vec::new(),
            app_recv_secret: Vec::new(),
            app_suite: 0,
            send_key_phase: false,
            recv_key_phase: false,
            key_update_allowed: false,
            peer_reset_token: None,
            reset_received: false,
            idle_timed_out: false,
            path_challenge_pending: None,
            path_validated: false,
            early_send_keys: None,
            early_recv_keys: None,
            out_frames_early: Vec::new(),
            early_backup: Vec::new(),
            early_sent: false,
        }
    }

    /** @brief 클라이언트 쪽 연결을 만든다. */
    pub fn new_client(
        cfg: ClientConfig,
        dcid: Vec<u8>,
        scid: Vec<u8>,
        tp: TransportParams,
    ) -> Result<Self, QuicError> {
        if !(1..=20).contains(&dcid.len()) || scid.len() > 20 {
            return Err(QuicError::Frame);
        }
        let mut local_tp = normalize_local_transport_params(tp);
        local_tp.initial_source_connection_id = Some(scid.clone());

        let remembered_tp = cfg
            .session
            .as_ref()
            .and_then(|s| TransportParams::decode(&s.server_transport_params));
        let engine = ClientHandshake::new(cfg, local_tp.encode()).map_err(|_| QuicError::Tls)?;
        let local_base_tp = local_tp.clone();
        let local_max_data = local_base_tp.initial_max_data;
        let local_max_streams_bidi = local_base_tp.initial_max_streams_bidi;
        let local_max_streams_uni = local_base_tp.initial_max_streams_uni;
        let mut c = Connection {
            role: Role::Client,
            tls_server: None,
            cfg_server: None,
            base_tp: local_base_tp,
            tls_client: Some(engine),
            spaces: Default::default(),
            local_cid: scid,
            remote_cid: dcid.clone(),
            initial_dcid: dcid.clone(),
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_resumed: false,
            handshake_early_accepted: false,
            closed: false,
            diagnostic: None,
            peer_close: None,
            peer_tp: None,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            out_datagrams: VecDeque::new(),
            out_frames_app: Vec::new(),
            close_frame: None,
            streams: HashMap::new(),
            closed_recv_ranges: Default::default(),
            reset_streams: Vec::new(),
            completed_streams: Vec::new(),
            recv_total_highest: 0,
            recv_buffered: 0,
            local_max_data,
            local_stream_max: HashMap::new(),
            local_max_streams_bidi,
            local_max_streams_uni,
            readable: Vec::new(),
            send_offsets: HashMap::new(),
            pending_stream_sends: VecDeque::new(),
            sealed_send_ranges: Default::default(),
            opened_send_ranges: Default::default(),
            closed_send_ranges: Default::default(),
            stopped_send_ranges: Default::default(),
            send_total: 0,
            peer_max_data: remembered_tp.as_ref().map_or(0, |tp| tp.initial_max_data),
            peer_stream_max: HashMap::new(),
            peer_max_streams_bidi: remembered_tp
                .as_ref()
                .map_or(0, |tp| tp.initial_max_streams_bidi),
            peer_max_streams_uni: remembered_tp
                .as_ref()
                .map_or(0, |tp| tp.initial_max_streams_uni),
            early_peer_tp: remembered_tp,
            next_uni: 0,
            retry_token: Vec::new(),
            retry_done: false,
            retry_scid: None,
            initial_crypto: Vec::new(),
            now_ms: 0,
            last_activity_ms: 0,
            srtt_ms: 333,
            rttvar_ms: 166,
            have_rtt: false,
            min_rtt_ms: u64::MAX,
            latest_rtt_ms: 0,
            pto_count: 0,
            cwnd: 10 * MAX_DATAGRAM as u64,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_ms: None,
            app_send_secret: Vec::new(),
            app_recv_secret: Vec::new(),
            app_suite: 0,
            send_key_phase: false,
            recv_key_phase: false,
            key_update_allowed: false,
            peer_reset_token: None,
            reset_received: false,
            idle_timed_out: false,
            path_challenge_pending: None,
            path_validated: false,
            early_send_keys: None,
            early_recv_keys: None,
            out_frames_early: Vec::new(),
            early_backup: Vec::new(),
            early_sent: false,
        };
        c.install_initial_keys(&dcid);
        c.pump_tls();
        c.initial_crypto = c.spaces[INITIAL].out_crypto.clone();
        c.flush();
        Ok(c)
    }

    /**
     * @brief 목적지 식별자에서 Initial 키를 만들어 건다.
     * @note 이 키는 식별자만 알면 누구나 만들 수 있다. 기밀이 아니라 경로상 장비의
     *       간섭을 막는 것이 목적이다.
     */
    fn install_initial_keys(&mut self, dcid: &[u8]) {
        let (client_secret, server_secret) = initial_secrets(dcid);
        let (send, recv) = match self.role {
            Role::Server => (server_secret, client_secret),
            Role::Client => (client_secret, server_secret),
        };
        self.spaces[INITIAL].send_keys = Some((Aead::Aes128Gcm, derive_packet_keys(&send, 16)));
        self.spaces[INITIAL].recv_keys = Some((Aead::Aes128Gcm, derive_packet_keys(&recv, 16)));
    }

    /** @brief 핸드셰이크가 내놓은 비밀로 그 수준의 키를 건다. */
    fn install_secrets(&mut self, sp: SecretPair) {
        let space = level_space(sp.level);
        if self.spaces[space].discarded {
            return;
        }
        let (aead, klen) = suite_aead(sp.client.suite);
        let (send, recv) = match self.role {
            Role::Server => (&sp.server.secret, &sp.client.secret),
            Role::Client => (&sp.client.secret, &sp.server.secret),
        };
        self.spaces[space].send_keys = Some((aead, derive_packet_keys(send, klen)));
        self.spaces[space].recv_keys = Some((aead, derive_packet_keys(recv, klen)));

        if space == APP {
            use zeroize::Zeroize;
            self.app_send_secret.zeroize();
            self.app_recv_secret.zeroize();
            self.app_send_secret = send.clone();
            self.app_recv_secret = recv.clone();
            self.app_suite = sp.client.suite;
        }
    }

    /**
     * @brief 키 갱신을 시작한다.
     * @details 오래된 키로 너무 많은 패킷을 보내지 않게 한다. 갱신 중에도 이전 키로 온
     *          패킷을 잠시 더 받아야 하므로 두 세대를 함께 가지고 있는다.
     */
    pub fn initiate_key_update(&mut self) -> bool {
        if !self.key_update_allowed || self.app_send_secret.is_empty() {
            return false;
        }
        let (_, klen) = suite_aead(self.app_suite);
        let (aead, hp) = match &self.spaces[APP].send_keys {
            Some((aead, keys)) => (*aead, keys.hp.clone()),
            None => return false,
        };
        let next = next_key_update_secret(&self.app_send_secret);
        self.spaces[APP].send_keys = Some((aead, derive_updated_kv(&next, klen, hp)));
        use zeroize::Zeroize;
        self.app_send_secret.zeroize();
        self.app_send_secret = next;
        self.send_key_phase = !self.send_key_phase;
        true
    }

    /** @brief 갱신을 확정하고 이전 세대 키를 버린다. */
    fn commit_key_update(&mut self) {
        let (_, klen) = suite_aead(self.app_suite);

        if let Some((aead, keys)) = self.spaces[APP].recv_keys.clone() {
            let next = next_key_update_secret(&self.app_recv_secret);
            self.spaces[APP].recv_keys =
                Some((aead, derive_updated_kv(&next, klen, keys.hp.clone())));
            use zeroize::Zeroize;
            self.app_recv_secret.zeroize();
            self.app_recv_secret = next;
            self.recv_key_phase = !self.recv_key_phase;
        }

        if self.send_key_phase != self.recv_key_phase {
            if let Some((aead, keys)) = self.spaces[APP].send_keys.clone() {
                let next = next_key_update_secret(&self.app_send_secret);
                self.spaces[APP].send_keys =
                    Some((aead, derive_updated_kv(&next, klen, keys.hp.clone())));
                use zeroize::Zeroize;
                self.app_send_secret.zeroize();
                self.app_send_secret = next;
                self.send_key_phase = !self.send_key_phase;
            }
        }
    }

    /** @brief 상대의 재설정 토큰을 기억한다. */
    pub fn set_peer_reset_token(&mut self, token: [u8; 16]) {
        self.peer_reset_token = Some(token);
    }

    /** @brief 상태 없는 재설정을 받았는지. */
    pub fn reset_received(&self) -> bool {
        self.reset_received
    }

    /**
     * @brief 새 경로가 살아 있는지 확인을 시작한다.
     * @warning 확인 전에는 그 경로로 많이 보내지 않는다. 출발지를 속인 이동 하나로 이쪽이
     *          남에게 트래픽을 쏟는 증폭이 되기 때문이다.
     */
    pub fn initiate_path_validation(&mut self) -> bool {
        if !self.handshake_complete {
            return false;
        }
        let mut data = [0u8; 8];
        onetdns_tls::sys::fill_random(&mut data);
        self.path_challenge_pending = Some(data);
        self.path_validated = false;
        self.out_frames_app.push(Frame::PathChallenge(data));
        self.flush();
        true
    }

    /** @brief 경로 확인이 끝났는지. */
    pub fn path_validated(&self) -> bool {
        self.path_validated
    }

    /**
     * @brief Retry 패킷을 처리해 토큰을 받고 핸드셰이크를 다시 시작한다.
     * @warning 무결성 태그를 확인한다. 확인하지 않으면 중간자가 Retry를 지어내 연결을
     *          자기 쪽으로 돌릴 수 있다. Retry는 연결당 한 번만 받는다.
     */
    fn handle_retry(&mut self, pkt: &[u8]) {
        if self.role != Role::Client || self.retry_done {
            return;
        }

        /*
         * 서버의 Initial 을 처리한 뒤에는 Retry 를 받지 않는다. Initial 공간을 버린 뒤에는
         * Handshake 키도 곧 버리므로 키가 있는지만 보면 끝난 연결이 Retry 로 처음부터 다시
         * 시작한다.
         */
        if self.spaces[HANDSHAKE].recv_keys.is_some() || self.spaces[INITIAL].discarded {
            return;
        }
        let Some((scid, token)) = parse_retry(pkt) else {
            return;
        };
        if token.is_empty()
            || token.len() > MAX_RETRY_TOKEN
            || scid.is_empty()
            || scid.len() > 20
            || !verify_retry_integrity(&self.initial_dcid, pkt)
        {
            return;
        }

        self.remote_cid = scid.clone();
        self.retry_scid = Some(scid.clone());
        self.retry_token = token;

        for sp in &self.spaces[INITIAL].sent {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sp.size);
        }
        self.spaces[INITIAL] = SpaceState::default();

        self.install_initial_keys(&scid);
        self.spaces[INITIAL].out_crypto = self.initial_crypto.clone();
        self.retry_done = true;
        self.flush();
    }

    /** @brief 핸드셰이크를 한 단계 진행시키고 나온 데이터와 비밀을 옮긴다. */
    fn pump_tls(&mut self) {
        let (
            outs,
            secrets,
            complete,
            peer_tp,
            alpn,
            early_secret,
            resumed,
            early_accepted,
            client_auth,
            client_identity,
        ) = match self.role {
            Role::Server => {
                let Some(e) = self.tls_server.as_mut() else {
                    return;
                };
                (
                    e.take_crypto(),
                    e.take_secrets(),
                    e.is_complete(),
                    e.peer_transport_params().map(|t| t.to_vec()),
                    e.alpn().map(|a| a.to_vec()),
                    e.take_early_secret(),
                    e.is_resumed(),
                    e.early_data_accepted(),
                    e.client_authenticated(),
                    e.client_auth_identity(),
                )
            }
            Role::Client => {
                let Some(e) = self.tls_client.as_mut() else {
                    return;
                };
                (
                    e.take_crypto(),
                    e.take_secrets(),
                    e.is_complete(),
                    e.peer_transport_params().map(|t| t.to_vec()),
                    e.alpn().map(|a| a.to_vec()),
                    e.take_early_secret(),
                    e.is_resumed(),
                    e.early_data_accepted(),
                    false,
                    None,
                )
            }
        };
        for sp in secrets {
            self.install_secrets(sp);
        }

        if let Some(sec) = early_secret {
            let (aead, klen) = suite_aead(sec.suite);
            let keys = derive_packet_keys(&sec.secret, klen);
            match self.role {
                Role::Client => self.early_send_keys = Some((aead, keys)),
                Role::Server => self.early_recv_keys = Some((aead, keys)),
            }
        }
        for (level, data) in outs {
            let space = &mut self.spaces[level_space(level)];
            if !space.discarded {
                space.out_crypto.extend_from_slice(&data);
            }
        }
        if self.peer_tp.is_none() {
            if let Some(raw) = peer_tp {
                match self.decode_peer_transport_params(&raw) {
                    Some(tp) => {
                        let cid_valid = match self.role {
                            Role::Client => {
                                tp.original_destination_connection_id.as_deref()
                                    == Some(self.initial_dcid.as_slice())
                                    && tp.initial_source_connection_id.as_deref()
                                        == Some(self.remote_cid.as_slice())
                                    && match &self.retry_scid {
                                        Some(expected) => {
                                            tp.retry_source_connection_id.as_deref()
                                                == Some(expected.as_slice())
                                        }
                                        None => tp.retry_source_connection_id.is_none(),
                                    }
                            }
                            Role::Server => {
                                tp.initial_source_connection_id.as_deref()
                                    == Some(self.remote_cid.as_slice())
                                    && tp.original_destination_connection_id.is_none()
                                    && tp.retry_source_connection_id.is_none()
                                    && tp.stateless_reset_token.is_none()
                            }
                        };
                        if !cid_valid {
                            self.note_diagnostic(QuicDiagnostic::TransportParameters);
                            self.closed = true;
                            self.discard_send_output();
                            return;
                        }
                        self.peer_max_data = tp.initial_max_data;
                        self.peer_max_streams_bidi = tp.initial_max_streams_bidi;
                        self.peer_max_streams_uni = tp.initial_max_streams_uni;
                        self.peer_reset_token = tp.stateless_reset_token;
                        self.peer_tp = Some(tp);
                    }
                    None => {
                        self.note_diagnostic(QuicDiagnostic::TransportParameters);
                        self.closed = true;
                        self.discard_send_output();
                        return;
                    }
                }
            }
        }
        if self.alpn.is_none() {
            self.alpn = alpn;
        }
        if complete && !self.handshake_complete {
            self.handshake_complete = true;
            self.handshake_resumed = resumed;
            self.handshake_early_accepted = early_accepted;
            self.client_authenticated = client_auth;
            self.client_auth_identity = client_identity;
            if self.local_max_data < MAX_CONNECTION_REASSEMBLY {
                self.local_max_data = MAX_CONNECTION_REASSEMBLY;
                self.out_frames_app
                    .push(Frame::MaxData(self.local_max_data));
            }

            self.key_update_allowed = true;
            if self.role == Role::Server {
                /*
                 * RFC 9001 에서 서버의 핸드셰이크는 끝나는 순간 확정된다. 클라이언트는 이
                 * 서버가 보내는 HANDSHAKE_DONE 을 받아야 확정된다.
                 */
                self.handshake_confirmed = true;
                self.out_frames_app.push(Frame::HandshakeDone);
                /*
                 * QUIC 서버는 TLS KeyUpdate 를 쓰지 않고, NewSessionTicket 을 포함한 출력과
                 * 핸드셰이크 결과는 위에서 모두 옮겼다. transcript, ClientHello, mTLS 인증서까지
                 * 든 상태 기계를 연결 유휴 수명 동안 남겨 둘 이유가 없다.
                 */
                self.tls_server = None;
            }
            if self.role == Role::Client {
                if self.early_sent && !early_accepted {
                    let sent = std::mem::take(&mut self.spaces[APP].sent);
                    for sp in &sent {
                        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sp.size);
                    }
                    self.spaces[APP].rtx.clear();
                    self.out_frames_early.clear();
                    let backup = std::mem::take(&mut self.early_backup);
                    self.out_frames_app.extend(backup);
                } else {
                    let rest = std::mem::take(&mut self.out_frames_early);
                    self.out_frames_app.extend(rest);
                    self.early_backup.clear();
                }
                self.early_send_keys = None;
            }
        }
    }

    /** @brief 받은 핸드셰이크 데이터를 TLS에 넣는다. */
    fn tls_provide(&mut self, level: Level, data: &[u8]) -> Result<(), QuicError> {
        match self.role {
            Role::Server => self
                .tls_server
                .as_mut()
                .ok_or(QuicError::Tls)?
                .provide(level, data)
                .map_err(|_| QuicError::Tls)?,
            Role::Client => self
                .tls_client
                .as_mut()
                .ok_or(QuicError::Tls)?
                .provide(level, data)
                .map_err(|_| QuicError::Tls)?,
        }
        self.pump_tls();
        Ok(())
    }

    /** @brief 진단을 기록한다. 처음 것만 남긴다. 뒤의 것은 대개 그 여파다. */
    fn note_diagnostic(&mut self, diagnostic: QuicDiagnostic) {
        if self.diagnostic.is_none() {
            self.diagnostic = Some(diagnostic);
        }
    }

    /** @brief 상대의 전송 매개변수를 읽는다. */
    fn decode_peer_transport_params(&mut self, raw: &[u8]) -> Option<TransportParams> {
        let decoded = TransportParams::decode(raw);
        if decoded.is_none() {
            self.note_diagnostic(QuicDiagnostic::TransportParameters);
        }
        decoded
    }

    /** @brief 기록된 진단을 가져간다. */
    pub fn take_diagnostic(&mut self) -> Option<QuicDiagnostic> {
        self.diagnostic.take()
    }

    /**
     * @brief 데이터그램 하나를 받아 상태를 진행시킨다.
     * @details 데이터그램에는 패킷이 여러 개 붙어 올 수 있다. 소비한 길이를 따라가며
     *          끝까지 처리한다.
     * @warning 아직 인증되지 않은 바이트다. 길이와 식별자를 모두 검사하고, 풀리지 않는
     *          패킷은 조용히 버린다. 오류를 내면 그것이 곧 탐색 신호가 된다.
     */
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        if self.closed {
            return Ok(());
        }
        if let Some(token) = self.peer_reset_token {
            if dg.len() >= 16 && ct_eq(&dg[dg.len() - 16..], &token) {
                self.reset_received = true;
                self.closed = true;
                self.discard_send_output();
                return Ok(());
            }
        }
        let mut pos = 0usize;
        while pos < dg.len() {
            let rest = &dg[pos..];
            let first = rest[0];
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                /*
                 * 서버는 핸드셰이크를 끝내기 전에 1-RTT 패킷을 처리하지 않는다(RFC 9001). 이
                 * 패킷에 확인을 보내면 클라이언트는 핸드셰이크가 확정됐다고 보고 Handshake 키를
                 * 버릴 수 있다. 그 뒤 클라이언트의 Finished 를 잃으면 클라이언트는 그것을 다시
                 * 보내지 않고, 서버는 핸드셰이크를 끝내지 못해 응답에 PTO 도 걸지 못한 채
                 * 멈춘다. 버린 패킷은 핸드셰이크가 확정된 뒤 클라이언트가 다시 보낸다.
                 */
                if self.role == Role::Server && !self.handshake_complete {
                    break;
                }
                let keys = match self.spaces[APP].recv_keys.clone() {
                    Some(k) => k,
                    None => break,
                };
                let largest = self.spaces[APP].largest_recv.unwrap_or(0);

                let alt = if self.key_update_allowed && !self.app_recv_secret.is_empty() {
                    let (_, klen) = suite_aead(self.app_suite);
                    let next = next_key_update_secret(&self.app_recv_secret);
                    Some(derive_updated_kv(&next, klen, keys.1.hp.clone()))
                } else {
                    None
                };
                let res = packet::unprotect_short(
                    keys.0,
                    &keys.1,
                    alt.as_ref(),
                    self.recv_key_phase,
                    rest,
                    self.local_cid.len(),
                    largest,
                );
                let (sp, phase_changed) = match res {
                    Some(v) => v,
                    None => break,
                };
                if phase_changed {
                    self.commit_key_update();
                }
                pos = dg.len();
                self.process_packet_kind(APP, sp.pn, &sp.payload, PacketKind::OneRtt)?;
            } else {
                if first & 0x40 == 0 {
                    break;
                }
                let ptype_val = (first & 0x30) >> 4;
                if ptype_val == ptype::RETRY {
                    self.handle_retry(rest);
                    break;
                }
                /*
                 * 풀 수 없는 패킷은 길이만큼 건너뛰고 뒤에 합쳐진 패킷을 계속 처리한다. 버린
                 * Initial 공간의 패킷 뒤에 Handshake 패킷이 붙어 오는 일이 흔하다.
                 */
                let Some(packet_len) = packet::long_packet_len(rest) else {
                    break;
                };
                let space = match ptype_val {
                    ptype::INITIAL => INITIAL,
                    ptype::HANDSHAKE => HANDSHAKE,

                    ptype::ZERO_RTT if self.role == Role::Server => APP,
                    _ => {
                        pos += packet_len;
                        continue;
                    }
                };

                if self.role == Role::Server && space == INITIAL && self.cfg_server.is_some() {
                    if let Some(dcid) = long_header_dcid(rest) {
                        self.initial_dcid = dcid.clone();
                        self.install_initial_keys(&dcid);
                        if let Some(cfg) = self.cfg_server.take() {
                            let mut tp = self.base_tp.clone();
                            if tp.original_destination_connection_id.is_none() {
                                tp.original_destination_connection_id = Some(dcid);
                            }
                            tp.initial_source_connection_id = Some(self.local_cid.clone());
                            self.tls_server = Some(ServerHandshake::new(cfg, tp.encode()));
                        }
                    }
                }
                let keys = if ptype_val == ptype::ZERO_RTT {
                    self.early_recv_keys.clone()
                } else {
                    self.spaces[space].recv_keys.clone()
                };
                let Some(keys) = keys else {
                    pos += packet_len;
                    continue;
                };
                let largest = self.spaces[space].largest_recv.unwrap_or(0);
                let Some(lp) = packet::unprotect_long(keys.0, &keys.1, rest, largest) else {
                    self.note_diagnostic(QuicDiagnostic::LongPacketProtection);
                    pos += packet_len;
                    continue;
                };
                pos += lp.consumed;

                if space == INITIAL && self.remote_cid != lp.scid {
                    self.remote_cid = lp.scid.clone();
                }
                let kind = match ptype_val {
                    ptype::INITIAL => PacketKind::Initial,
                    ptype::HANDSHAKE => PacketKind::Handshake,
                    ptype::ZERO_RTT => PacketKind::ZeroRtt,
                    _ => unreachable!(),
                };
                self.process_packet_kind(space, lp.pn, &lp.payload, kind)?;
            }
        }
        self.discard_finished_spaces();
        self.flush();
        Ok(())
    }

    /**
     * @brief 더는 쓰지 않는 Initial 과 Handshake 공간을 RFC 9001 이 정한 시점에 버린다.
     * @details 서버는 Handshake 패킷을 처음 처리하면 Initial 을 버린다. 핸드셰이크가 확정되면
     *          양쪽 모두 Handshake 를 버린다. 클라이언트가 Initial 을 버리는 시점은 첫
     *          Handshake 패킷을 보낼 때라 flush 가 맡는다.
     */
    fn discard_finished_spaces(&mut self) {
        if self.role == Role::Server
            && !self.spaces[INITIAL].discarded
            && self.spaces[HANDSHAKE].largest_recv.is_some()
        {
            self.discard_space(INITIAL);
        }
        if self.handshake_confirmed {
            for space in [INITIAL, HANDSHAKE] {
                if !self.spaces[space].discarded {
                    self.discard_space(space);
                }
            }
        }
    }

    /**
     * @brief 번호 공간 하나의 키와 복구 상태를 버린다.
     * @details 남은 패킷은 확인도 손실 판정도 받지 않으므로 흐르는 양에서 빼고 PTO 횟수도
     *          처음으로 돌린다. 그대로 두면 끝난 핸드셰이크의 재전송이 응용 데이터의 PTO 를
     *          앞질러 차지한다.
     */
    fn discard_space(&mut self, space: usize) {
        let dropped = std::mem::take(&mut self.spaces[space]);
        let in_flight = dropped
            .sent
            .iter()
            .fold(0u64, |sum, packet| sum.saturating_add(packet.size));
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(in_flight);
        self.spaces[space].discarded = true;
        self.pto_count = 0;
    }

    #[cfg(test)]
    /** @brief 푼 패킷 하나의 프레임들을 처리한다. */
    fn process_packet(&mut self, space: usize, pn: u64, payload: &[u8]) -> Result<(), QuicError> {
        let kind = match space {
            INITIAL => PacketKind::Initial,
            HANDSHAKE => PacketKind::Handshake,
            _ => PacketKind::OneRtt,
        };
        self.process_packet_kind(space, pn, payload, kind)
    }

    /** @brief 프레임을 하나씩 처리하고 이 패킷이 확인을 끌어내는지 판정한다. */
    fn process_packet_kind(
        &mut self,
        space: usize,
        pn: u64,
        payload: &[u8],
        kind: PacketKind,
    ) -> Result<(), QuicError> {
        if !self.spaces[space].accept_packet_number(pn) {
            return Ok(());
        }
        let frames = frame::parse(payload).ok_or(QuicError::Frame)?;
        let mut ack_eliciting = false;
        for f in frames {
            match f {
                Frame::Padding(_) => {}
                Frame::Ack {
                    largest,
                    delay,
                    first_range,
                    ranges,
                } => {
                    if kind == PacketKind::ZeroRtt {
                        return Err(QuicError::Frame);
                    }
                    self.on_ack(space, largest, delay, first_range, &ranges)?;
                }
                Frame::Ping => ack_eliciting = true,
                Frame::Crypto { offset, data } => {
                    if kind == PacketKind::ZeroRtt {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;

                    let post_hs_app = self.handshake_complete && space == APP;
                    if !post_hs_app || self.role == Role::Client {
                        let contiguous = self.spaces[space].crypto_asm.push(
                            offset,
                            data,
                            MAX_CRYPTO_REASSEMBLY,
                        )?;
                        if !contiguous.is_empty() {
                            self.tls_provide(space_level(space), &contiguous)?;
                        }
                    }
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.on_stream(id, offset, fin, data)?;
                }
                Frame::ResetStream {
                    id,
                    error_code,
                    final_size,
                } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.on_reset_stream(id, error_code, final_size)?;
                }
                Frame::StopSending { id, error_code } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.on_stop_sending(id, error_code)?;
                }
                Frame::HandshakeDone => {
                    if kind != PacketKind::OneRtt || self.role != Role::Client {
                        return Err(QuicError::Frame);
                    }
                    /*
                     * ACK 와 PADDING, CONNECTION_CLOSE 말고는 모두 확인을 끌어낸다. 이 프레임만
                     * 담은 패킷에 답하지 않으면 서버는 그 패킷을 영영 확인받지 못해 PTO 가
                     * 계속 커진다.
                     */
                    ack_eliciting = true;
                    self.handshake_confirmed = true;
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    self.peer_close = Some(PeerClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                    self.closed = true;
                    self.discard_send_output();
                    break;
                }
                Frame::PathChallenge(data) => {
                    if kind != PacketKind::OneRtt {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.out_frames_app.push(Frame::PathResponse(data));
                }
                Frame::PathResponse(data) => {
                    if kind != PacketKind::OneRtt {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    if self.path_challenge_pending == Some(data) {
                        self.path_validated = true;
                        self.path_challenge_pending = None;
                    }
                }
                Frame::MaxData(max) => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.peer_max_data = self.peer_max_data.max(max);
                }
                Frame::MaxStreamData { id, max } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.on_max_stream_data(id, max)?;
                }
                Frame::MaxStreams { uni, max } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    if max > (1u64 << 60) {
                        return Err(QuicError::FlowControl);
                    }
                    if uni {
                        self.peer_max_streams_uni = self.peer_max_streams_uni.max(max);
                    } else {
                        self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max);
                    }
                }
                Frame::Other(frame_type) => {
                    let one_rtt_only = matches!(
                        frame_type,
                        frame::ftype::NEW_TOKEN
                            | frame::ftype::NEW_CONNECTION_ID
                            | frame::ftype::RETIRE_CONNECTION_ID
                    );
                    if one_rtt_only && kind != PacketKind::OneRtt {
                        return Err(QuicError::Frame);
                    }
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    if frame_type == frame::ftype::NEW_TOKEN && self.role != Role::Client {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                }
            }
        }
        let st = &mut self.spaces[space];
        st.recv_pns.push(pn);
        if st.recv_pns.len() > MAX_RECV_PACKET_HISTORY {
            if let Some((oldest, _)) = st.recv_pns.iter().enumerate().min_by_key(|(_, pn)| *pn) {
                st.recv_pns.swap_remove(oldest);
            }
        }
        if ack_eliciting {
            st.ack_pending = true;
        }
        self.last_activity_ms = self.now_ms;
        Ok(())
    }

    /** @brief 이 스트림 번호가 받기에 유효한지 보고 초기 윈도우를 알려 준다. */
    fn recv_stream_properties(&self, id: u64) -> Result<(bool, bool, u64), QuicError> {
        let peer_initiator = match self.role {
            Role::Server => 0u64,
            Role::Client => 1u64,
        };
        let initiated_by_peer = id & 0x01 == peer_initiator;
        let unidirectional = id & 0x02 != 0;
        let stream_number = id >> 2;

        if initiated_by_peer {
            let advertised = if unidirectional {
                self.local_max_streams_uni
            } else {
                self.local_max_streams_bidi
            };
            if stream_number >= advertised {
                return Err(QuicError::StreamLimit);
            }
        } else if unidirectional || !stream_range_contains(&self.opened_send_ranges, id) {
            return Err(QuicError::StreamLimit);
        }

        let initial_stream_limit = if unidirectional {
            self.base_tp.initial_max_stream_data_uni
        } else if initiated_by_peer {
            self.base_tp.initial_max_stream_data_bidi_remote
        } else {
            self.base_tp.initial_max_stream_data_bidi_local
        }
        .min(MAX_STREAM_REASSEMBLY);
        let stream_limit = self
            .local_stream_max
            .get(&id)
            .copied()
            .unwrap_or(initial_stream_limit)
            .max(initial_stream_limit);
        Ok((initiated_by_peer, unidirectional, stream_limit))
    }

    /** @brief 이 스트림이 이미 닫혔는지. */
    fn recv_stream_closed(&self, id: u64) -> bool {
        stream_range_contains(&self.closed_recv_ranges, id)
    }

    /** @brief 스트림을 닫힌 것으로 표시한다. */
    fn mark_recv_stream_closed(&mut self, id: u64) {
        mark_stream_range(&mut self.closed_recv_ranges, id);
    }

    /** @brief 스트림의 흐름 제어 윈도우를 초기값으로 설정한다. */
    fn ensure_recv_stream_credit(&mut self, id: u64, initial_limit: u64) {
        if self.local_stream_max.contains_key(&id) {
            return;
        }
        let target = initial_limit.max(MAX_STREAM_REASSEMBLY);
        self.local_stream_max.insert(id, target);
        if target > initial_limit {
            self.out_frames_app
                .push(Frame::MaxStreamData { id, max: target });
        }
    }

    /** @brief 상대가 스트림을 끊었다. 모아 둔 데이터를 버리고 윈도우를 정리한다. */
    fn on_reset_stream(
        &mut self,
        id: u64,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), QuicError> {
        if self.recv_stream_closed(id) {
            return Ok(());
        }
        let (initiated_by_peer, unidirectional, stream_limit) = self.recv_stream_properties(id)?;
        if final_size > stream_limit {
            return Err(QuicError::FlowControl);
        }
        if self.reset_streams.len() >= MAX_STREAMS_HARD {
            return Err(QuicError::StreamLimit);
        }

        let (previous_highest, app_consumed) = self.streams.get(&id).map_or((0, 0), |stream| {
            if stream.fin_offset.is_some_and(|fin| fin != final_size)
                || final_size < stream.highest_offset
            {
                (u64::MAX, 0)
            } else {
                (stream.highest_offset, stream.app_consumed)
            }
        });
        if previous_highest == u64::MAX {
            return Err(QuicError::Frame);
        }
        let delta = final_size - previous_highest;
        let next_total = self
            .recv_total_highest
            .checked_add(delta)
            .ok_or(QuicError::FlowControl)?;
        if next_total > self.local_max_data {
            return Err(QuicError::FlowControl);
        }
        self.recv_total_highest = next_total;
        self.recv_buffered = self
            .recv_buffered
            .saturating_sub(previous_highest.saturating_sub(app_consumed));
        self.streams.remove(&id);
        self.local_stream_max.remove(&id);
        self.readable.retain(|(stream_id, _, _)| *stream_id != id);
        self.completed_streams
            .retain(|(stream_id, _)| *stream_id != id);
        self.mark_recv_stream_closed(id);
        self.replenish_recv_credit(
            final_size.saturating_sub(app_consumed),
            initiated_by_peer,
            unidirectional,
        );
        self.reset_streams.push((id, error_code));
        Ok(())
    }

    /** @brief 상대가 그만 보내라고 했다. 대기 중인 전송을 버린다. */
    fn on_stop_sending(&mut self, id: u64, error_code: u64) -> Result<(), QuicError> {
        let local_initiator = match self.role {
            Role::Client => 0u64,
            Role::Server => 1u64,
        };
        let initiated_locally = id & 0x01 == local_initiator;
        let unidirectional = id & 0x02 != 0;
        if unidirectional && !initiated_locally {
            return Err(QuicError::StreamLimit);
        }
        if stream_range_contains(&self.stopped_send_ranges, id)
            || stream_range_contains(&self.closed_send_ranges, id)
        {
            return Ok(());
        }
        let known = if initiated_locally {
            stream_range_contains(&self.opened_send_ranges, id)
        } else {
            self.streams.contains_key(&id) || self.recv_stream_closed(id)
        };
        if !known {
            return Err(QuicError::Frame);
        }
        let final_size = self.send_offsets.remove(&id).unwrap_or(0);
        let remove_stream = |frame: &Frame| !matches!(frame, Frame::Stream { id: stream_id, .. } if *stream_id == id);
        self.pending_stream_sends.retain(|pending| pending.id != id);
        self.out_frames_app.retain(remove_stream);
        self.out_frames_early.retain(remove_stream);
        self.early_backup.retain(remove_stream);
        for space in &mut self.spaces {
            space.rtx.retain(remove_stream);
            for packet in &mut space.sent {
                packet.frames.retain(remove_stream);
            }
        }
        self.peer_stream_max.remove(&id);
        mark_stream_range(&mut self.stopped_send_ranges, id);
        self.out_frames_app.push(Frame::ResetStream {
            id,
            error_code,
            final_size,
        });
        Ok(())
    }

    /** @brief 스트림 윈도우가 늘었다. 막혀 있던 전송을 다시 시도한다. */
    fn on_max_stream_data(&mut self, id: u64, max: u64) -> Result<(), QuicError> {
        let local_initiator = match self.role {
            Role::Client => 0u64,
            Role::Server => 1u64,
        };
        let initiated_locally = id & 0x01 == local_initiator;
        let unidirectional = id & 0x02 != 0;
        let known = if initiated_locally {
            stream_range_contains(&self.opened_send_ranges, id)
        } else {
            !unidirectional && (self.streams.contains_key(&id) || self.recv_stream_closed(id))
        };
        if !known {
            return Err(QuicError::Frame);
        }
        if stream_range_contains(&self.closed_send_ranges, id)
            || stream_range_contains(&self.stopped_send_ranges, id)
        {
            return Ok(());
        }
        if !self.peer_stream_max.contains_key(&id) && self.peer_stream_max.len() >= MAX_STREAMS_HARD
        {
            return Err(QuicError::StreamLimit);
        }
        self.peer_stream_max
            .entry(id)
            .and_modify(|current| *current = (*current).max(max))
            .or_insert(max);
        Ok(())
    }

    /**
     * @brief 스트림 데이터를 받는다.
     * @warning 흐름 제어 윈도우를 넘는 데이터는 연결 오류다. 받아들이면 윈도우를 알리는 의미가 없어진다.
     */
    fn on_stream(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    ) -> Result<(), QuicError> {
        if self.recv_stream_closed(id) {
            return Ok(());
        }
        let (_initiated_by_peer, _unidirectional, stream_limit) =
            self.recv_stream_properties(id)?;
        let end = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| QuicError::FlowControl)?)
            .ok_or(QuicError::FlowControl)?;
        if end > stream_limit {
            return Err(QuicError::FlowControl);
        }
        if !self.streams.contains_key(&id) && self.streams.len() >= MAX_STREAMS_HARD {
            return Err(QuicError::StreamLimit);
        }

        let (newly, fin_now, doq_buf) = {
            let sr = self.streams.entry(id).or_default();

            if let Some(f) = sr.fin_offset {
                if end > f {
                    return Err(QuicError::Frame);
                }
            }
            if end > sr.highest_offset {
                let delta = end - sr.highest_offset;
                let next_total = self
                    .recv_total_highest
                    .checked_add(delta)
                    .ok_or(QuicError::FlowControl)?;
                let next_buffered = self
                    .recv_buffered
                    .checked_add(delta)
                    .ok_or(QuicError::FlowControl)?;
                if next_total > self.local_max_data || next_buffered > MAX_CONNECTION_REASSEMBLY {
                    return Err(QuicError::FlowControl);
                }
                self.recv_total_highest = next_total;
                self.recv_buffered = next_buffered;
                sr.highest_offset = end;
            }
            let newly = sr.asm.push(offset, data, stream_limit)?;
            if sr.buf.len().saturating_add(newly.len()) > stream_limit as usize {
                return Err(QuicError::FlowControl);
            }
            sr.buf.extend_from_slice(&newly);
            if fin {
                if end < sr.highest_offset || end < sr.asm.recv_offset {
                    return Err(QuicError::Frame);
                }
                if let Some(existing) = sr.fin_offset {
                    if existing != end {
                        return Err(QuicError::Frame);
                    }
                }
                sr.fin_offset = Some(end);
            }
            let fin_now = matches!(sr.fin_offset, Some(f) if sr.asm.recv_offset == f);
            let doq_buf = if fin_now && !sr.done {
                sr.done = true;
                Some(std::mem::take(&mut sr.buf))
            } else {
                None
            };
            (newly, fin_now, doq_buf)
        };

        self.ensure_recv_stream_credit(id, stream_limit);

        if !newly.is_empty() || fin_now {
            self.readable.push((id, newly, fin_now));
        }
        if let Some(p) = doq_buf {
            self.completed_streams.push((id, p));
        }
        Ok(())
    }

    /** @brief 받은 패킷을 알리는 확인 프레임을 만든다. */
    fn build_ack(&mut self, space: usize) -> Option<Frame> {
        let mut sorted = std::mem::take(&mut self.spaces[space].recv_pns);
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        sorted.dedup();
        let &largest = sorted.last()?;

        let mut first_range = 0u64;
        let mut i = sorted.len() - 1;
        while i > 0 && sorted[i - 1] + 1 == sorted[i] {
            first_range += 1;
            i -= 1;
        }
        let mut ranges = Vec::new();
        let mut previous_low = sorted[i];
        while i > 0 && ranges.len() < MAX_ACK_RANGES {
            let next_high = sorted[i - 1];
            i -= 1;
            while i > 0 && sorted[i - 1] + 1 == sorted[i] {
                i -= 1;
            }
            let next_low = sorted[i];
            ranges.push((previous_low - next_high - 2, next_high - next_low));
            previous_low = next_low;
        }
        Some(Frame::Ack {
            largest,
            delay: 0,
            first_range,
            ranges,
        })
    }

    /**
     * @brief 긴 헤더 패킷 하나를 만든다. 핸드셰이크 중에 쓴다.
     * @param probe 혼잡 윈도우가 막혀도 보낼 수 있는 남은 프로브 패킷 수. 윈도우를 넘겨
     *              보냈으면 하나 줄인다.
     */
    fn build_long_packet(
        &mut self,
        space: usize,
        pad_to: usize,
        probe: &mut u8,
    ) -> Option<Vec<u8>> {
        let (aead, keys) = self.spaces[space].send_keys.clone()?;
        let mut payload = Vec::new();
        let mut rtx_frames: Vec<Frame> = Vec::new();
        let mut ack_eliciting = false;

        if self.spaces[space].ack_pending {
            if let Some(ack) = self.build_ack(space) {
                frame::encode(&mut payload, &ack);
            }
            self.spaces[space].ack_pending = false;
        }

        let window_open = self.can_send_new();
        if window_open || *probe > 0 {
            append_queued_frames(
                &mut self.spaces[space].rtx,
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                MAX_PACKET_PAYLOAD,
            );

            append_crypto_chunk(
                &mut self.spaces[space],
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                MAX_PACKET_PAYLOAD,
            );
        }
        if payload.is_empty() {
            return None;
        }
        let ptype_val = if space == INITIAL {
            ptype::INITIAL
        } else {
            ptype::HANDSHAKE
        };
        let pn = self.spaces[space].next_pn;
        let dcid = self.remote_cid.clone();
        let scid = self.local_cid.clone();

        let token: &[u8] = if space == INITIAL {
            &self.retry_token
        } else {
            &[]
        };
        let mut pkt =
            packet::protect_long(aead, &keys, ptype_val, &dcid, &scid, token, pn, 4, &payload);

        if pad_to > 0 && pkt.len() < pad_to {
            let deficit = pad_to - pkt.len();
            payload.extend(std::iter::repeat_n(0u8, deficit));
            pkt =
                packet::protect_long(aead, &keys, ptype_val, &dcid, &scid, token, pn, 4, &payload);
        }
        self.spaces[space].next_pn += 1;
        if ack_eliciting && !window_open {
            *probe = probe.saturating_sub(1);
        }
        self.track_sent(space, pn, ack_eliciting, pkt.len() as u64, rtx_frames);
        Some(pkt)
    }

    /**
     * @brief 짧은 헤더 패킷 하나를 만든다. 핸드셰이크 뒤에 쓴다.
     * @param probe 혼잡 윈도우가 막혀도 보낼 수 있는 남은 프로브 패킷 수.
     */
    fn build_short_packet(&mut self, probe: &mut u8) -> Option<Vec<u8>> {
        let (aead, keys) = self.spaces[APP].send_keys.clone()?;
        let mut payload = Vec::new();
        let mut rtx_frames: Vec<Frame> = Vec::new();
        let mut ack_eliciting = false;

        if self.spaces[APP].ack_pending {
            if let Some(ack) = self.build_ack(APP) {
                frame::encode(&mut payload, &ack);
            }
            self.spaces[APP].ack_pending = false;
        }

        // 종료 알림은 혼잡 윈도우를 보지 않는다. 알리지 못하면 상대가 데드라인까지 기다리게 되고,
        // 재전송 목록에도 넣지 않는다. 이 프레임은 ack를 끌어내지 않는다.
        if let Some(close) = self.close_frame.take() {
            frame::encode(&mut payload, &close);
        }

        let window_open = self.can_send_new();
        if window_open || *probe > 0 {
            append_queued_frames(
                &mut self.spaces[APP].rtx,
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                MAX_PACKET_PAYLOAD,
            );

            append_crypto_chunk(
                &mut self.spaces[APP],
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                MAX_PACKET_PAYLOAD,
            );

            append_queued_frames(
                &mut self.out_frames_app,
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                MAX_PACKET_PAYLOAD,
            );
        }
        if payload.is_empty() {
            return None;
        }
        let pn = self.spaces[APP].next_pn;
        self.spaces[APP].next_pn += 1;
        let pkt = packet::protect_short(
            aead,
            &keys,
            &self.remote_cid,
            pn,
            4,
            &payload,
            self.send_key_phase,
        );
        if ack_eliciting && !window_open {
            *probe = probe.saturating_sub(1);
        }
        self.track_sent(APP, pn, ack_eliciting, pkt.len() as u64, rtx_frames);
        Some(pkt)
    }

    /** @brief 보낸 패킷을 기억한다. 확인이나 손실 판정에 쓴다. */
    fn track_sent(
        &mut self,
        space: usize,
        pn: u64,
        ack_eliciting: bool,
        size: u64,
        frames: Vec<Frame>,
    ) {
        if !ack_eliciting {
            return;
        }
        self.bytes_in_flight += size;
        self.last_activity_ms = self.now_ms;
        self.spaces[space].last_ack_eliciting_ms = self.now_ms;
        self.spaces[space].sent.push(SentPacket {
            pn,
            time_ms: self.now_ms,
            ack_eliciting,
            size,
            frames,
        });
    }

    /** @brief 확인을 처리한다. 왕복 시간을 갱신하고 혼잡 윈도우를 늘린다. */
    fn on_ack(
        &mut self,
        space: usize,
        largest: u64,
        delay: u64,
        first_range: u64,
        ranges: &[(u64, u64)],
    ) -> Result<(), QuicError> {
        if largest >= self.spaces[space].next_pn {
            return Err(QuicError::Frame);
        }
        let acked = ack_ranges(largest, first_range, ranges).ok_or(QuicError::Frame)?;
        let now = self.now_ms;
        let mut newly_largest_time: Option<u64> = None;
        let mut acked_bytes = 0u64;
        let mut congestion_acked_bytes = 0u64;
        let sent = std::mem::take(&mut self.spaces[space].sent);
        let mut remaining = Vec::with_capacity(sent.len());
        for sp in sent {
            let range = acked
                .get(acked.partition_point(|&(lo, _)| lo > sp.pn))
                .copied();
            if range.is_some_and(|(lo, hi)| (lo..=hi).contains(&sp.pn)) {
                acked_bytes += sp.size;
                if self
                    .recovery_start_ms
                    .is_none_or(|recovery_start| sp.time_ms > recovery_start)
                {
                    congestion_acked_bytes += sp.size;
                }
                if sp.pn == largest && sp.ack_eliciting {
                    newly_largest_time = Some(sp.time_ms);
                }
            } else {
                remaining.push(sp);
            }
        }
        self.spaces[space].sent = remaining;
        let state = &mut self.spaces[space];
        let largest_advanced = state.largest_acked.is_none_or(|prev| largest > prev);
        state.largest_acked = Some(
            state
                .largest_acked
                .map_or(largest, |prev| prev.max(largest)),
        );
        /*
         * ACK 만 담은 패킷은 기록하지 않으므로, 확인받은 바이트가 없어도 새로 확인된 패킷이
         * 있을 수 있다. 가장 큰 확인 번호가 앞으로 갔다면 그렇다. 이때 손실 판정을 건너뛰면,
         * 상대가 ACK 만 담은 패킷을 계속 확인해 줘도 그보다 앞서 잃은 패킷은 PTO 로만 다시
         * 나가고 그 간격은 매번 두 배로 는다.
         */
        if acked_bytes == 0 && !largest_advanced {
            return Ok(());
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        if let Some(t) = newly_largest_time {
            let ack_delay_ms = if space == APP {
                self.peer_tp.as_ref().map_or(0, |tp| {
                    delay
                        .checked_shl(tp.ack_delay_exponent as u32)
                        .unwrap_or(u64::MAX)
                        .saturating_add(999)
                        .saturating_div(1000)
                        .min(tp.max_ack_delay)
                })
            } else {
                0
            };
            self.update_rtt(now.saturating_sub(t), ack_delay_ms);
        }
        self.pto_count = 0;
        if congestion_acked_bytes > 0 {
            self.on_cc_ack(congestion_acked_bytes);
        }
        self.detect_lost(space);
        Ok(())
    }

    /**
     * @brief 손실된 패킷을 찾아 다시 보낼 것을 표시한다.
     * @details 확인된 가장 큰 번호보다 충분히 앞섰거나, 그보다 앞서 보냈고 왕복 시간의 9/8 이
     *          지난 패킷을 잃은 것으로 본다. 아직 시간이 차지 않은 패킷은 그 시각을 loss_time_ms
     *          에 남겨, 새 확인이 오지 않아도 on_timeout 이 그때 판정하게 한다.
     */
    fn detect_lost(&mut self, space: usize) {
        /** @brief 이만큼 뒤의 패킷이 먼저 확인되면 잃은 것으로 본다. */
        const PACKET_THRESHOLD: u64 = 3;
        let Some(largest_acked) = self.spaces[space].largest_acked else {
            return;
        };
        let now = self.now_ms;
        let loss_delay = (self.srtt_ms.max(self.latest_rtt_ms) * 9 / 8).max(1);
        let sent = std::mem::take(&mut self.spaces[space].sent);
        let mut remaining = Vec::with_capacity(sent.len());
        let mut lost_frames = Vec::new();
        let mut lost_bytes = 0u64;
        let mut newest_lost_time = None;
        let mut loss_time: Option<u64> = None;
        for sp in sent {
            if sp.pn > largest_acked {
                remaining.push(sp);
                continue;
            }
            let lost_by_pn = sp.pn + PACKET_THRESHOLD <= largest_acked;
            let lost_by_time = now.saturating_sub(sp.time_ms) >= loss_delay;
            if lost_by_pn || lost_by_time {
                lost_bytes += sp.size;
                newest_lost_time =
                    Some(newest_lost_time.map_or(sp.time_ms, |t: u64| t.max(sp.time_ms)));
                lost_frames.extend(sp.frames);
            } else {
                let due = sp.time_ms.saturating_add(loss_delay);
                loss_time = Some(loss_time.map_or(due, |t| t.min(due)));
                remaining.push(sp);
            }
        }
        self.spaces[space].sent = remaining;
        self.spaces[space].loss_time_ms = loss_time;
        /*
         * 프레임이 없는 패킷도 흐르는 양에는 들어 있다. PING 만 실었거나 PTO 가 프레임을
         * 이미 옮겨 간 패킷이 그렇다. 프레임 유무로 거르면 그 크기가 영영 빠지지 않아 혼잡
         * 윈도우가 닫힌 채로 남는다.
         */
        if lost_bytes == 0 {
            return;
        }
        self.spaces[space].rtx.extend(lost_frames);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if newest_lost_time.is_some_and(|lost_time| {
            self.recovery_start_ms
                .is_none_or(|recovery_start| lost_time > recovery_start)
        }) {
            self.on_cc_loss();
            self.recovery_start_ms = Some(now);
        }
    }

    /**
     * @brief 이 공간에 PTO 를 걸어야 하는지.
     * @details 확인을 기다리는 패킷이 있어야 한다. 응용 데이터 공간은 핸드셰이크가 확정된
     *          뒤에만 건다. 그 전에는 상대에게 그 패킷을 풀 키가 없거나 이쪽에 확인을 풀 키가
     *          없을 수 있다.
     */
    fn pto_armed(&self, space: usize) -> bool {
        !self.spaces[space].sent.is_empty() && (space != APP || self.handshake_confirmed)
    }

    /** @brief PTO 가 걸린 공간들 가운데 가장 이른 데드라인. */
    fn pto_deadline(&self) -> Option<u64> {
        let period = self.pto_ms();
        [INITIAL, HANDSHAKE, APP]
            .into_iter()
            .filter(|&space| self.pto_armed(space))
            .map(|space| {
                self.spaces[space]
                    .last_ack_eliciting_ms
                    .saturating_add(period)
            })
            .min()
    }

    /**
     * @brief 이 공간에서 확인받지 못한 프레임을 오래된 것부터 프로브가 실을 만큼 다시 보낼
     *        차례에 넣는다.
     * @details 가장 오래된 패킷 하나만 다시 보내면, 확인받지 못한 패킷이 여럿일 때 PTO 마다
     *          하나씩 돌아가며 보내게 되고 간격은 매번 두 배로 는다. 그 사이 한쪽 사본만 계속
     *          잃으면 그 데이터는 끝내 가지 않는다. 반대로 전부 옮기면 꼬리 하나를 잃어도 PTO
     *          한 번에 윈도우 전체를 다시 보낸다. 나머지는 프로브의 확인이 오면 손실 판정이
     *          맡는다. 원래 패킷은 확인과 왕복 시간 측정에 쓰도록 남겨 두고 프레임만 옮긴다.
     *          다시 보낼 것이 없으면 PING 을 보낸다.
     */
    fn queue_probe(&mut self, space: usize) {
        let state = &mut self.spaces[space];
        let mut budget = usize::from(PROBE_PACKETS) * MAX_PACKET_PAYLOAD;
        let mut requeued = false;
        for packet in state
            .sent
            .iter_mut()
            .filter(|packet| !packet.frames.is_empty())
        {
            let size = usize::try_from(packet.size).unwrap_or(usize::MAX);
            if requeued && size > budget {
                break;
            }
            budget = budget.saturating_sub(size);
            state.rtx.extend(std::mem::take(&mut packet.frames));
            requeued = true;
        }
        if state.rtx.is_empty() {
            state.rtx.push(Frame::Ping);
        }
    }

    /**
     * @brief 시각을 넘겨 손실 판정과 PTO 를 돌리고 유휴 데드라인이 지나면 닫는다.
     * @return 연결이 닫혔거나 기다리는 데드라인이 없으면 false.
     */
    pub fn on_timeout(&mut self, now_ms: u64) -> bool {
        self.now_ms = now_ms;
        let peer_idle = self.peer_tp.as_ref().map_or(0, |tp| tp.max_idle_timeout);
        let idle_timeout = match (self.base_tp.max_idle_timeout, peer_idle) {
            (0, 0) => 0,
            (0, peer) => peer,
            (local, 0) => local,
            (local, peer) => local.min(peer),
        };
        if idle_timeout > 0 && now_ms.saturating_sub(self.last_activity_ms) >= idle_timeout {
            self.closed = true;
            self.idle_timed_out = true;
            self.discard_send_output();
            return false;
        }

        let mut lost_by_time = false;
        for space in [INITIAL, HANDSHAKE, APP] {
            if self.spaces[space]
                .loss_time_ms
                .is_some_and(|due| due <= now_ms)
            {
                self.detect_lost(space);
                lost_by_time = true;
            }
        }
        if lost_by_time {
            self.flush();
            return true;
        }

        let Some(deadline) = self.pto_deadline() else {
            return false;
        };
        if now_ms < deadline {
            return true;
        }
        /*
         * RFC 9002 는 PTO 가 난 공간 말고도 확인을 기다리는 다른 공간에 함께 프로브를
         * 보내라고 권한다. 핸드셰이크 중 Initial 과 Handshake 가 함께 남아 있을 때, 한쪽 PTO 가
         * 횟수를 올려 다른 쪽 데드라인까지 두 배로 밀어내지 않게 한다.
         */
        for space in [INITIAL, HANDSHAKE, APP] {
            if self.pto_armed(space) {
                self.queue_probe(space);
            }
        }
        self.pto_count = (self.pto_count + 1).min(8);
        self.flush_packets(PROBE_PACKETS);
        true
    }

    /** @brief 지금 시각을 알린다. 이 상태 기계는 시계를 직접 읽지 않는다. */
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /** @brief 평활 왕복 시간. */
    pub fn srtt_ms(&self) -> u64 {
        self.srtt_ms
    }

    /** @brief 확인을 기다리는 바이트 양. */
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /**
     * @brief 연결이 지금 별도 버퍼에 보유한 가변 payload 바이트.
     * @details 서버 리스너가 전역 예산을 계산할 때 쓴다. 연결 구조와 map bucket 같은 고정·
     *          개수 기반 비용은 리스너의 연결당 기본 charge가 별도로 덮는다.
     */
    pub fn retained_payload_bytes(&self) -> usize {
        let mut total = self
            .tls_server
            .as_ref()
            .map_or(0, ServerHandshake::retained_payload_bytes)
            .saturating_add(transport_params_retained_bytes(&self.base_tp))
            .saturating_add(
                self.peer_tp
                    .as_ref()
                    .map_or(0, transport_params_retained_bytes),
            )
            .saturating_add(
                self.early_peer_tp
                    .as_ref()
                    .map_or(0, transport_params_retained_bytes),
            )
            .saturating_add(self.local_cid.capacity())
            .saturating_add(self.remote_cid.capacity())
            .saturating_add(self.initial_dcid.capacity())
            .saturating_add(
                self.peer_close
                    .as_ref()
                    .map_or(0, |close| close.reason.capacity()),
            )
            .saturating_add(self.alpn.as_ref().map_or(0, Vec::capacity))
            .saturating_add(
                self.client_auth_identity
                    .as_ref()
                    .map_or(0, String::capacity),
            )
            .saturating_add(
                self.out_datagrams
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Vec<u8>>()),
            )
            .saturating_add(self.out_datagrams.iter().fold(0usize, |sum, datagram| {
                sum.saturating_add(datagram.capacity())
            }))
            .saturating_add(frames_retained_payload_bytes(
                &self.out_frames_app,
                self.out_frames_app.capacity(),
            ))
            .saturating_add(
                self.close_frame
                    .as_ref()
                    .map_or(0, frame_retained_payload_bytes),
            )
            .saturating_add(hash_map_retained_bytes(&self.streams))
            .saturating_add(
                self.reset_streams
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u64, u64)>()),
            )
            .saturating_add(stream_ranges_retained_bytes(&self.closed_recv_ranges))
            .saturating_add(
                self.completed_streams
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u64, Vec<u8>)>()),
            )
            .saturating_add(
                self.completed_streams
                    .iter()
                    .fold(0usize, |sum, (_, data)| sum.saturating_add(data.capacity())),
            )
            .saturating_add(hash_map_retained_bytes(&self.local_stream_max))
            .saturating_add(
                self.readable
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u64, Vec<u8>, bool)>()),
            )
            .saturating_add(self.readable.iter().fold(0usize, |sum, (_, data, _)| {
                sum.saturating_add(data.capacity())
            }))
            .saturating_add(hash_map_retained_bytes(&self.send_offsets))
            .saturating_add(
                self.pending_stream_sends
                    .capacity()
                    .saturating_mul(std::mem::size_of::<PendingStreamSend>()),
            )
            .saturating_add(
                self.pending_stream_sends
                    .iter()
                    .fold(0usize, |sum, pending| {
                        sum.saturating_add(pending.data.capacity())
                    }),
            )
            .saturating_add(stream_ranges_retained_bytes(&self.sealed_send_ranges))
            .saturating_add(stream_ranges_retained_bytes(&self.opened_send_ranges))
            .saturating_add(stream_ranges_retained_bytes(&self.closed_send_ranges))
            .saturating_add(stream_ranges_retained_bytes(&self.stopped_send_ranges))
            .saturating_add(hash_map_retained_bytes(&self.peer_stream_max))
            .saturating_add(self.retry_token.capacity())
            .saturating_add(self.retry_scid.as_ref().map_or(0, Vec::capacity))
            .saturating_add(self.initial_crypto.capacity())
            .saturating_add(self.app_send_secret.capacity())
            .saturating_add(self.app_recv_secret.capacity())
            .saturating_add(
                self.early_send_keys
                    .as_ref()
                    .map_or(0, |(_, keys)| packet_keys_retained_bytes(keys)),
            )
            .saturating_add(
                self.early_recv_keys
                    .as_ref()
                    .map_or(0, |(_, keys)| packet_keys_retained_bytes(keys)),
            )
            .saturating_add(frames_retained_payload_bytes(
                &self.out_frames_early,
                self.out_frames_early.capacity(),
            ))
            .saturating_add(frames_retained_payload_bytes(
                &self.early_backup,
                self.early_backup.capacity(),
            ));

        for space in &self.spaces {
            total = total
                .saturating_add(
                    space
                        .recv_pns
                        .capacity()
                        .saturating_mul(std::mem::size_of::<u64>()),
                )
                .saturating_add(space.out_crypto.capacity())
                .saturating_add(space.crypto_asm.retained_payload_bytes())
                .saturating_add(
                    space
                        .send_keys
                        .as_ref()
                        .map_or(0, |(_, keys)| packet_keys_retained_bytes(keys)),
                )
                .saturating_add(
                    space
                        .recv_keys
                        .as_ref()
                        .map_or(0, |(_, keys)| packet_keys_retained_bytes(keys)),
                )
                .saturating_add(
                    space
                        .sent
                        .capacity()
                        .saturating_mul(std::mem::size_of::<SentPacket>()),
                )
                .saturating_add(frames_retained_payload_bytes(
                    &space.rtx,
                    space.rtx.capacity(),
                ));
            for packet in &space.sent {
                total = total.saturating_add(frames_retained_payload_bytes(
                    &packet.frames,
                    packet.frames.capacity(),
                ));
            }
        }
        for stream in self.streams.values() {
            total = total
                .saturating_add(stream.asm.retained_payload_bytes())
                .saturating_add(stream.buf.capacity());
        }
        total
    }

    /** @brief 재전송 대기 시간의 기준값. */
    pub fn base_pto_ms(&self) -> u64 {
        self.srtt_ms + (4 * self.rttvar_ms).max(1) + 25
    }

    /** @brief 지금 재전송 대기 시간. 연속 실패마다 배로 늘어난다. */
    fn pto_ms(&self) -> u64 {
        self.base_pto_ms()
            .saturating_mul(1u64 << self.pto_count.min(6))
    }

    /** @brief 왕복 시간 표본을 반영한다. 상대가 알린 확인 지연을 빼고 측정한다. */
    fn update_rtt(&mut self, sample_ms: u64, ack_delay_ms: u64) {
        let sample = sample_ms.max(1);
        self.latest_rtt_ms = sample;
        self.min_rtt_ms = self.min_rtt_ms.min(sample);
        let adjusted = if sample > self.min_rtt_ms.saturating_add(ack_delay_ms) {
            sample - ack_delay_ms
        } else {
            sample
        };
        if !self.have_rtt {
            self.srtt_ms = adjusted;
            self.rttvar_ms = adjusted / 2;
            self.have_rtt = true;
        } else {
            let var_sample = self.srtt_ms.abs_diff(adjusted);
            self.rttvar_ms = (3 * self.rttvar_ms + var_sample) / 4;
            self.srtt_ms = (7 * self.srtt_ms + adjusted) / 8;
        }
    }

    /** @brief 확인을 받아 혼잡 윈도우를 늘린다. */
    fn on_cc_ack(&mut self, acked: u64) {
        let mss = MAX_DATAGRAM as u64;
        if self.cwnd < self.ssthresh {
            self.cwnd += acked;
        } else {
            self.cwnd += (mss * acked / self.cwnd).max(1);
        }
    }

    /** @brief 손실을 감지해 혼잡 윈도우를 줄인다. */
    fn on_cc_loss(&mut self) {
        let mss = MAX_DATAGRAM as u64;
        self.ssthresh = (self.cwnd / 2).max(2 * mss);
        self.cwnd = self.ssthresh;
    }

    /** @brief 혼잡 윈도우에 여유가 있는지. */
    fn can_send_new(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /** @brief 조기 데이터 패킷을 만든다. 핸드셰이크 완료 전에 보낼 수 있다. */
    fn build_zero_rtt_packet(&mut self) -> Option<Vec<u8>> {
        if self.out_frames_early.is_empty() || !self.can_send_new() {
            return None;
        }
        let (aead, keys) = self.early_send_keys.clone()?;
        let mut payload = Vec::new();
        let mut rtx_frames: Vec<Frame> = Vec::new();
        let mut ack_eliciting = false;
        append_queued_frames(
            &mut self.out_frames_early,
            &mut payload,
            &mut rtx_frames,
            &mut ack_eliciting,
            MAX_PACKET_PAYLOAD,
        );
        if payload.is_empty() {
            return None;
        }
        let pn = self.spaces[APP].next_pn;
        self.spaces[APP].next_pn += 1;
        let pkt = packet::protect_long(
            aead,
            &keys,
            ptype::ZERO_RTT,
            &self.remote_cid,
            &self.local_cid,
            &[],
            pn,
            4,
            &payload,
        );
        self.early_sent = true;
        self.track_sent(APP, pn, ack_eliciting, pkt.len() as u64, rtx_frames);
        Some(pkt)
    }

    /** @brief 만들다 만 출력을 버린다. */
    fn discard_send_output(&mut self) {
        self.out_datagrams.clear();
        self.out_frames_app.clear();
        self.out_frames_early.clear();
        self.early_backup.clear();
        self.pending_stream_sends.clear();
        self.send_offsets.clear();
        self.peer_stream_max.clear();
        for space in &mut self.spaces {
            space.rtx.clear();
            space.sent.clear();
        }
        self.bytes_in_flight = 0;
    }

    /** @brief 보낼 것들을 패킷으로 묶어 내보낼 큐에 넣는다. */
    fn flush(&mut self) {
        self.flush_packets(0);
    }

    /**
     * @brief 보낼 것들을 패킷으로 묶어 내보낼 큐에 넣는다.
     * @param probe 혼잡 윈도우를 넘겨서라도 보낼 수 있는 패킷 수. PTO 프로브만 0 이 아닌 값을
     *              준다. 프로브가 윈도우에 막히면, 윈도우는 확인이 와야 열리는데 확인은 프로브가
     *              가야 오므로 회복이 멈춘다.
     */
    fn flush_packets(&mut self, mut probe: u8) {
        if self.closed {
            return;
        }
        self.schedule_pending_stream_sends();
        /* 짧은 헤더인지, Initial 인지, 패킷 바이트. */
        let mut packets: Vec<(bool, bool, Vec<u8>)> = Vec::new();

        let pad = if self.role == Role::Client && self.spaces[INITIAL].next_pn == 0 {
            1200
        } else {
            0
        };
        let mut client_first_flight = false;
        if let Some(p) = self.build_long_packet(INITIAL, pad, &mut probe) {
            client_first_flight = pad > 0;
            packets.push((false, true, p));
        }

        while let Some(p) = self.build_zero_rtt_packet() {
            packets.push((false, false, p));
        }
        let mut sent_handshake = false;
        while let Some(p) = self.build_long_packet(HANDSHAKE, 0, &mut probe) {
            sent_handshake = true;
            packets.push((false, false, p));
        }
        /*
         * RFC 9001 에서 클라이언트는 Handshake 패킷을 처음 보낼 때 Initial 을 버린다. 이미 만든
         * Initial 패킷은 이 데이터그램에 함께 나간다.
         */
        if sent_handshake && self.role == Role::Client && !self.spaces[INITIAL].discarded {
            self.discard_space(INITIAL);
        }
        while let Some(p) = self.build_short_packet(&mut probe) {
            packets.push((true, false, p));
        }
        if packets.is_empty() {
            return;
        }

        /*
         * RFC 9000 에서 Initial 을 담은 데이터그램은 1200바이트 이상이어야 한다. 받는 쪽은
         * 그보다 작은 것을 버려도 되므로, 채우지 않으면 상대에 따라 핸드셰이크가 조용히 멈춘다.
         */
        let mut dg = Vec::new();
        let mut dg_has_initial = false;
        for (is_short, is_initial, p) in packets {
            if !dg.is_empty() && dg.len() + p.len() > MAX_DATAGRAM {
                self.out_datagrams.push_back(std::mem::take(&mut dg));
                dg_has_initial = false;
            }
            dg.extend_from_slice(&p);
            dg_has_initial |= is_initial;
            if is_short {
                self.out_datagrams.push_back(std::mem::take(&mut dg));
                dg_has_initial = false;
            }
        }
        if !dg.is_empty() {
            if (dg_has_initial || client_first_flight) && dg.len() < MIN_INITIAL_DATAGRAM {
                dg.resize(MIN_INITIAL_DATAGRAM, 0);
            }
            self.out_datagrams.push_back(dg);
        }
    }

    /** @brief 내보낼 데이터그램을 꺼낸다. 소비하는 쪽이 실제로 보낸다. */
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.out_datagrams.pop_front()
    }

    /** @brief 완성된 스트림 요청들을 가져간다. */
    pub fn take_stream_requests(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let completed = std::mem::take(&mut self.completed_streams);
        let completed_ids: std::collections::HashSet<u64> =
            completed.iter().map(|(id, _)| *id).collect();
        self.readable
            .retain(|(id, _, _)| !completed_ids.contains(id));
        for (id, raw) in completed {
            self.release_recv_stream(id);
            if raw.len() < 2 {
                continue;
            }
            let len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
            if len == 0 || raw.len() != 2 + len {
                continue;
            }
            out.push((id, raw[2..].to_vec()));
        }
        // recv_datagram이 확인은 이미 내보냈다. 여기서 흐름 제어 갱신만 따로 보내지 말고,
        // 이어지는 응답이나 다음 질의와 묶어 불필요한 ACK-eliciting 패킷을 만들지 않는다.
        out
    }

    /** @brief DNS 메시지 하나를 스트림에 보낸다. */
    pub fn send_dns_message(&mut self, id: u64, dns: &[u8]) -> Result<(), QuicError> {
        self.send_dns_message_owned(id, dns.to_vec())
    }

    /** @brief 소유권을 넘겨받아 DNS 메시지를 보낸다. 복사를 줄인다. */
    pub fn send_dns_message_owned(&mut self, id: u64, mut dns: Vec<u8>) -> Result<(), QuicError> {
        if dns.is_empty() || dns.len() > u16::MAX as usize {
            return Err(QuicError::Frame);
        }
        let length = dns.len();
        dns.reserve(2);
        dns.resize(length + 2, 0);
        dns.copy_within(..length, 2);
        dns[..2].copy_from_slice(&(length as u16).to_be_bytes());
        self.send_stream_owned(id, dns, true)
    }

    /** @brief DNS 메시지 여럿을 한 스트림에 보낸다. */
    pub fn send_dns_messages(&mut self, id: u64, msgs: &[Vec<u8>]) -> Result<(), QuicError> {
        if msgs.len() != 1 {
            return Err(QuicError::Frame);
        }
        self.send_dns_message(id, &msgs[0])
    }

    /** @brief 응용 수준 프레임을 보낼 큐에 넣는다. */
    fn queue_app_frame(&mut self, f: Frame) {
        if !self.handshake_complete && self.early_send_keys.is_some() {
            self.early_backup.push(f.clone());
            self.out_frames_early.push(f);
        } else {
            self.out_frames_app.push(f);
        }
    }

    #[cfg(test)]
    /**
     * @brief 상대에게 STOP_SENDING 을 보낸다.
     * @note 이 구현은 스트림을 스스로 취소하지 않는다. 상대가 취소하는 상황을 시험에서 만들 때만 쓴다.
     */
    pub(crate) fn send_stop_sending_for_test(&mut self, id: u64, error_code: u64) {
        self.queue_app_frame(Frame::StopSending { id, error_code });
        self.flush();
    }

    /** @brief 보내려고 쌓아 둔 바이트. 연결 상한 판정에 쓴다. */
    fn buffered_stream_send_bytes(&self) -> usize {
        /** @brief 이 프레임이 차지하는 바이트. */
        fn frame_bytes(frame: &Frame) -> usize {
            match frame {
                Frame::Stream { data, .. } => data.len(),
                _ => 0,
            }
        }

        let framed = self
            .out_frames_app
            .iter()
            .chain(&self.out_frames_early)
            .chain(&self.early_backup)
            .chain(self.spaces.iter().flat_map(|space| space.rtx.iter()))
            .chain(
                self.spaces
                    .iter()
                    .flat_map(|space| space.sent.iter())
                    .flat_map(|packet| packet.frames.iter()),
            )
            .map(frame_bytes)
            .sum::<usize>();
        self.pending_stream_sends
            .iter()
            .fold(framed, |total, pending| {
                total.saturating_add(
                    pending
                        .data
                        .len()
                        .saturating_sub(pending.cursor)
                        .saturating_mul(pending.copies),
                )
            })
    }

    /** @brief 조기 데이터를 보낼 수 있는 상태인지. */
    pub fn can_send_early(&self) -> bool {
        !self.handshake_complete && self.early_send_keys.is_some()
    }

    /** @brief 읽을 수 있게 된 스트림 데이터를 가져간다. */
    pub fn take_readable(&mut self) -> Vec<(u64, Vec<u8>, bool)> {
        let events = std::mem::take(&mut self.readable);
        let finished: std::collections::HashSet<u64> = events
            .iter()
            .filter_map(|(id, _, fin)| fin.then_some(*id))
            .collect();
        let mut consumed_by_stream: HashMap<u64, u64> = HashMap::new();
        for (id, data, _) in &events {
            let consumed = data.len() as u64;
            consumed_by_stream
                .entry(*id)
                .and_modify(|total| *total = total.saturating_add(consumed))
                .or_insert(consumed);
        }
        for (id, consumed) in consumed_by_stream {
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.buf.clear();
                stream.app_consumed = stream
                    .app_consumed
                    .saturating_add(consumed)
                    .min(stream.highest_offset);
            }
            self.recv_buffered = self.recv_buffered.saturating_sub(consumed);
            self.replenish_connection_credit(consumed);
            if !finished.contains(&id) {
                self.extend_recv_stream_credit(id, consumed);
            }
        }
        for id in &finished {
            self.release_recv_stream(*id);
        }
        if !finished.is_empty() {
            self.completed_streams
                .retain(|(id, _)| !finished.contains(id));
            self.flush();
        }
        events
    }

    /** @brief 끊긴 스트림 목록을 가져간다. */
    pub fn take_resets(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.reset_streams)
    }

    /** @brief 다 쓴 받기 스트림의 자원을 놓는다. */
    fn release_recv_stream(&mut self, id: u64) {
        let Some(stream) = self.streams.remove(&id) else {
            return;
        };
        let remaining = stream.highest_offset.saturating_sub(stream.app_consumed);
        self.recv_buffered = self.recv_buffered.saturating_sub(remaining);
        self.local_stream_max.remove(&id);
        self.mark_recv_stream_closed(id);
        let peer_initiator = match self.role {
            Role::Server => 0u64,
            Role::Client => 1u64,
        };
        self.replenish_recv_credit(remaining, id & 0x01 == peer_initiator, id & 0x02 != 0);
    }

    /**
     * @brief 소비한 만큼 연결 윈도우를 다시 채워 상대에게 알린다.
     * @note 윈도우를 채우지 않으면 상대가 곧 막힌다. 매번 알리면 프레임이 너무 잦으니 일정
     *       분량이 쌓였을 때만 보낸다.
     */
    fn replenish_connection_credit(&mut self, consumed: u64) {
        if consumed == 0 {
            return;
        }
        self.local_max_data = self
            .local_max_data
            .saturating_add(consumed)
            .min(MAX_FLOW_CONTROL);
        self.out_frames_app
            .push(Frame::MaxData(self.local_max_data));
    }

    /** @brief 스트림 윈도우를 다시 채운다. */
    fn extend_recv_stream_credit(&mut self, id: u64, consumed: u64) {
        if consumed == 0 || self.recv_stream_closed(id) {
            return;
        }
        let Some(current) = self.local_stream_max.get_mut(&id) else {
            return;
        };
        let next = current.saturating_add(consumed).min(MAX_FLOW_CONTROL);
        if next > *current {
            *current = next;
            self.out_frames_app
                .push(Frame::MaxStreamData { id, max: next });
        }
    }

    /** @brief 연결과 스트림 윈도우를 함께 채운다. */
    fn replenish_recv_credit(
        &mut self,
        consumed: u64,
        initiated_by_peer: bool,
        unidirectional: bool,
    ) {
        self.replenish_connection_credit(consumed);
        if !initiated_by_peer {
            return;
        }
        if unidirectional {
            self.local_max_streams_uni = self
                .local_max_streams_uni
                .saturating_add(1)
                .min(MAX_FLOW_CONTROL);
            self.out_frames_app.push(Frame::MaxStreams {
                uni: true,
                max: self.local_max_streams_uni,
            });
        } else {
            self.local_max_streams_bidi = self
                .local_max_streams_bidi
                .saturating_add(1)
                .min(MAX_FLOW_CONTROL);
            self.out_frames_app.push(Frame::MaxStreams {
                uni: false,
                max: self.local_max_streams_bidi,
            });
        }
    }

    /** @brief 이 스트림 번호가 보내기에 유효한지 보고 윈도우를 알려 준다. */
    fn send_stream_properties(&self, id: u64) -> Result<(bool, bool, u64), QuicError> {
        if id >= (1u64 << 62) {
            return Err(QuicError::Frame);
        }
        let local_initiator = match self.role {
            Role::Client => 0u64,
            Role::Server => 1u64,
        };
        let initiated_locally = id & 0x01 == local_initiator;
        let unidirectional = id & 0x02 != 0;
        if unidirectional && !initiated_locally {
            return Err(QuicError::Frame);
        }
        if !initiated_locally && !self.streams.contains_key(&id) && !self.recv_stream_closed(id) {
            return Err(QuicError::StreamLimit);
        }
        let initial_stream_limit = self
            .peer_tp
            .as_ref()
            .or(self.early_peer_tp.as_ref())
            .map_or(0, |tp| {
                if unidirectional {
                    tp.initial_max_stream_data_uni
                } else if initiated_locally {
                    tp.initial_max_stream_data_bidi_remote
                } else {
                    tp.initial_max_stream_data_bidi_local
                }
            });
        Ok((initiated_locally, unidirectional, initial_stream_limit))
    }

    /** @brief 대기 중인 전송 하나를 윈도우가 허락하는 만큼 내보낸다. */
    fn schedule_one_pending(&mut self, pending: &mut PendingStreamSend) -> (bool, bool) {
        let Ok((initiated_locally, unidirectional, initial_stream_limit)) =
            self.send_stream_properties(pending.id)
        else {
            return (false, true);
        };
        if initiated_locally {
            let stream_number = pending.id >> 2;
            let allowed = if unidirectional {
                self.peer_max_streams_uni
            } else {
                self.peer_max_streams_bidi
            };
            if stream_number >= allowed {
                return (false, false);
            }
        }
        let stream_limit = self
            .peer_stream_max
            .get(&pending.id)
            .copied()
            .unwrap_or(initial_stream_limit)
            .max(initial_stream_limit);
        let cursor = pending.cursor as u64;
        let Some(offset) = pending.offset.checked_add(cursor) else {
            return (false, true);
        };
        let remaining = pending.data.len().saturating_sub(pending.cursor);
        let send_len = if remaining == 0 {
            if offset > stream_limit {
                return (false, false);
            }
            0
        } else {
            let stream_credit = stream_limit.saturating_sub(offset);
            let connection_credit = self.peer_max_data.saturating_sub(self.send_total);
            let available = stream_credit
                .min(connection_credit)
                .min(STREAM_FRAME_CHUNK as u64);
            if available == 0 {
                return (false, false);
            }
            remaining.min(available as usize)
        };

        let end_cursor = pending.cursor + send_len;
        let done = end_cursor == pending.data.len();
        let fin = done && pending.fin;
        mark_stream_range(&mut self.opened_send_ranges, pending.id);
        self.queue_app_frame(Frame::Stream {
            id: pending.id,
            offset,
            fin,
            data: pending.data[pending.cursor..end_cursor].to_vec(),
        });
        pending.cursor = end_cursor;
        self.send_total = self.send_total.saturating_add(send_len as u64);
        if done && pending.fin {
            self.send_offsets.remove(&pending.id);
            self.peer_stream_max.remove(&pending.id);
            mark_stream_range(&mut self.closed_send_ranges, pending.id);
        }
        (true, done)
    }

    /** @brief 윈도우가 열린 대기 전송들을 내보낸다. */
    fn schedule_pending_stream_sends(&mut self) {
        let mut blocked_streams = std::collections::HashSet::new();
        loop {
            let count = self.pending_stream_sends.len();
            if count == 0 {
                return;
            }
            let mut progressed = false;
            blocked_streams.clear();
            for _ in 0..count {
                let Some(mut pending) = self.pending_stream_sends.pop_front() else {
                    break;
                };
                if blocked_streams.contains(&pending.id) {
                    self.pending_stream_sends.push_back(pending);
                    continue;
                }
                let id = pending.id;
                let (made_progress, done) = self.schedule_one_pending(&mut pending);
                progressed |= made_progress;
                if !done {
                    blocked_streams.insert(id);
                    self.pending_stream_sends.push_back(pending);
                }
            }
            if !progressed {
                return;
            }
        }
    }

    /** @brief 스트림에 데이터를 보낸다. 윈도우가 모자라면 대기 큐에 넣는다. */
    pub fn send_stream(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), QuicError> {
        self.send_stream_owned(id, data.to_vec(), fin)
    }

    /** @brief 소유권을 넘겨받아 스트림에 보낸다. */
    pub fn send_stream_owned(
        &mut self,
        id: u64,
        data: Vec<u8>,
        fin: bool,
    ) -> Result<(), QuicError> {
        if self.closed {
            return Err(QuicError::Closed);
        }
        if data.len() > MAX_STREAM_REASSEMBLY as usize {
            return Err(QuicError::FlowControl);
        }
        if stream_range_contains(&self.stopped_send_ranges, id)
            || stream_range_contains(&self.closed_send_ranges, id)
            || stream_range_contains(&self.sealed_send_ranges, id)
        {
            return Err(QuicError::StreamClosed);
        }
        let copies = if !self.handshake_complete && self.early_send_keys.is_some() {
            2
        } else {
            1
        };
        let additional = data.len().saturating_mul(copies);
        if self.pending_stream_sends.len() >= MAX_PENDING_SEND_OPS
            || self.buffered_stream_send_bytes().saturating_add(additional)
                > MAX_CONNECTION_SEND_BUFFER
        {
            return Err(QuicError::FlowControl);
        }
        let offset = *self.send_offsets.get(&id).unwrap_or(&0);
        let data_len = u64::try_from(data.len()).map_err(|_| QuicError::FlowControl)?;
        let end = offset.checked_add(data_len).ok_or(QuicError::FlowControl)?;
        self.send_stream_properties(id)?;
        self.send_offsets.insert(id, end);
        if fin {
            mark_stream_range(&mut self.sealed_send_ranges, id);
        }
        self.pending_stream_sends.push_back(PendingStreamSend {
            id,
            offset,
            data,
            cursor: 0,
            fin,
            copies,
        });
        self.flush();
        Ok(())
    }

    /** @brief 단방향 스트림을 연다. */
    pub fn open_uni_stream(&mut self) -> Result<u64, QuicError> {
        if self.closed {
            return Err(QuicError::Closed);
        }
        if self.next_uni >= (1u64 << 60) {
            return Err(QuicError::StreamLimit);
        }
        let suffix = if self.role == Role::Client {
            0x02
        } else {
            0x03
        };
        let id = (self.next_uni << 2) | suffix;
        self.next_uni += 1;
        Ok(id)
    }

    /** @brief 응용 데이터를 보낼 수 있는 상태인지. */
    pub fn can_send_app(&self) -> bool {
        self.spaces[APP].send_keys.is_some()
    }

    /** @brief 핸드셰이크가 끝났는지. */
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /**
     * @brief 핸드셰이크가 확정됐는지.
     * @details 서버는 핸드셰이크가 끝나는 순간, 클라이언트는 HANDSHAKE_DONE 을 받았을 때
     *          확정된다.
     */
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    /** @brief 연결이 닫혔는지. */
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /**
     * @brief 이쪽이 먼저 연결을 닫고 그 까닭을 상대에게 알린다.
     *
     * @details 알리지 않고 상태만 지우면 상대는 아무것도 받지 못한 채 자기 유휴 데드라인까지
     *          기다린다. 응용 계층 종료(frame_type 없음)로 보내므로 error_code 의 뜻은
     *          그 계층이 정한다. DoQ 는 RFC 9250 의 값을 쓴다.
     * @param error_code 응용 계층이 정한 사유 코드.
     * @param reason 사람이 읽을 짧은 설명. 빈 문자열도 된다.
     * @note 1-RTT 키가 서기 전에는 알릴 방법이 없으므로 조용히 닫기만 한다.
     */
    pub fn close(&mut self, error_code: u64, reason: &str) {
        if self.closed {
            return;
        }
        if self.spaces[APP].send_keys.is_some() {
            self.close_frame = Some(Frame::ConnectionClose {
                error_code,
                frame_type: None,
                reason: reason.as_bytes().to_vec(),
            });
            // flush 는 closed 를 보고 바로 반환하므로 닫기 표시보다 먼저 부른다.
            self.flush();
        }
        self.closed = true;
    }

    /** @brief 상대가 알린 종료 사유. */
    pub fn peer_close(&self) -> Option<&PeerClose> {
        self.peer_close.as_ref()
    }

    /**
     * @brief 연결이 닫힌 까닭을 사람이 읽을 문구로.
     *
     * @details 닫힘은 상대의 CONNECTION_CLOSE만으로 생기지 않는다. stateless reset, 유휴
     *          데드라인, 상대 transport parameters 거부도 같은 상태를 만든다. 갈라 두지 않으면
     *          진단이 무슨 일이 있었든 늘 상대를 지목한다.
     * @return 닫히지 않았으면 없다.
     */
    pub fn close_detail(&self) -> Option<String> {
        if !self.closed {
            return None;
        }
        if let Some(close) = &self.peer_close {
            return Some(format!(
                "Peer closed the connection: code=0x{:x} frame={:?} reason={}",
                close.error_code,
                close.frame_type,
                String::from_utf8_lossy(&close.reason)
            ));
        }
        if self.reset_received {
            return Some("Peer sent a stateless reset".to_string());
        }
        if self.idle_timed_out {
            return Some("Connection timed out with no traffic".to_string());
        }
        if let Some(diagnostic) = self.diagnostic {
            return Some(diagnostic.to_string());
        }
        Some("Closed without a reason".to_string())
    }

    /** @brief 합의된 응용 프로토콜. */
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /** @brief 클라이언트 인증서를 확인했는지. */
    pub fn client_authenticated(&self) -> bool {
        self.client_authenticated
    }

    /** @brief 확인된 클라이언트 신원. */
    pub fn client_auth_identity(&self) -> Option<&str> {
        self.client_auth_identity.as_deref()
    }

    /** @brief 상대가 알린 전송 매개변수. */
    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_tp.as_ref()
    }

    /** @brief 이쪽 연결 식별자. */
    pub fn local_connection_id(&self) -> &[u8] {
        &self.local_cid
    }

    /** @brief 상대 연결 식별자. */
    pub fn remote_connection_id(&self) -> &[u8] {
        &self.remote_cid
    }

    /** @brief 이쪽 역할. */
    pub fn role(&self) -> Role {
        self.role
    }

    /** @brief 세션 재개로 맺어진 연결인지. */
    pub fn is_resumed(&self) -> bool {
        if self.handshake_complete {
            self.handshake_resumed
        } else {
            match self.role {
                Role::Client => self.tls_client.as_ref().is_some_and(|e| e.is_resumed()),
                Role::Server => self.tls_server.as_ref().is_some_and(|e| e.is_resumed()),
            }
        }
    }

    /** @brief 조기 데이터가 받아들여졌는지. 거부되면 다시 보내야 한다. */
    pub fn early_data_accepted(&self) -> bool {
        if self.handshake_complete {
            self.handshake_early_accepted
        } else {
            match self.role {
                Role::Client => self
                    .tls_client
                    .as_ref()
                    .is_some_and(|e| e.early_data_accepted()),
                Role::Server => self
                    .tls_server
                    .as_ref()
                    .is_some_and(|e| e.early_data_accepted()),
            }
        }
    }

    /** @brief 새로 받은 세션 티켓을 가져간다. 다음 연결의 재개에 쓴다. */
    pub fn take_new_sessions(&mut self) -> Vec<onetdns_tls::TlsSession> {
        self.tls_client
            .as_mut()
            .map(|e| e.take_sessions())
            .unwrap_or_default()
    }

    /** @brief 상대가 보낸 인증서 체인. */
    pub fn peer_chain(&self) -> &[Vec<u8>] {
        match self.tls_client.as_ref() {
            Some(e) => e.peer_chain(),
            None => &[],
        }
    }
}

/** @brief Retry 패킷에서 출발지 식별자와 토큰을 추출한다. */
fn parse_retry(pkt: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut pos = 1 + 4;
    let dcid_len = *pkt.get(pos)? as usize;
    if dcid_len > 20 {
        return None;
    }
    pos = pos.checked_add(1 + dcid_len)?;
    let scid_len = *pkt.get(pos)? as usize;
    if scid_len == 0 || scid_len > 20 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let scid = pkt.get(pos..pos.checked_add(scid_len)?)?.to_vec();
    pos = pos.checked_add(scid_len)?;
    if pkt.len() < pos.checked_add(16)? {
        return None;
    }
    let token = pkt.get(pos..pkt.len() - 16)?.to_vec();
    if token.is_empty() || token.len() > MAX_RETRY_TOKEN {
        return None;
    }
    Some((scid, token))
}

/** @brief Retry 무결성 태그를 확인한다. 원래 목적지 식별자에 묶여 있다. */
fn verify_retry_integrity(odcid: &[u8], retry_pkt: &[u8]) -> bool {
    crate::retry::verify_integrity(odcid, retry_pkt)
}

/** @brief 대기 중인 프레임을 패킷 크기가 허락하는 만큼 담는다. */
fn append_queued_frames(
    queue: &mut Vec<Frame>,
    payload: &mut Vec<u8>,
    retransmittable: &mut Vec<Frame>,
    ack_eliciting: &mut bool,
    max_payload: usize,
) {
    if payload.len() >= max_payload || queue.is_empty() {
        return;
    }
    let frames = std::mem::take(queue);
    let mut iter = frames.into_iter();
    while let Some(frame_value) = iter.next() {
        let mut encoded = Vec::new();
        frame::encode(&mut encoded, &frame_value);
        if encoded.len() > max_payload || payload.len().saturating_add(encoded.len()) > max_payload
        {
            queue.push(frame_value);
            queue.extend(iter);
            break;
        }
        payload.extend_from_slice(&encoded);
        if is_ack_eliciting(&frame_value) {
            *ack_eliciting = true;
        }
        if is_retransmittable(&frame_value) {
            retransmittable.push(frame_value);
        }
    }
}

/** @brief 핸드셰이크 데이터를 조각내어 담는다. */
fn append_crypto_chunk(
    space: &mut SpaceState,
    payload: &mut Vec<u8>,
    retransmittable: &mut Vec<Frame>,
    ack_eliciting: &mut bool,
    max_payload: usize,
) {
    if space.out_crypto.is_empty() || payload.len() >= max_payload {
        return;
    }
    let available = max_payload.saturating_sub(payload.len());
    let mut n = space.out_crypto.len().min(CRYPTO_CHUNK).min(available);
    while n > 0 {
        let frame_value = Frame::Crypto {
            offset: space.send_crypto_offset,
            data: space.out_crypto[..n].to_vec(),
        };
        let mut encoded = Vec::new();
        frame::encode(&mut encoded, &frame_value);
        if payload.len().saturating_add(encoded.len()) <= max_payload {
            space.out_crypto.drain(..n);
            space.send_crypto_offset = space.send_crypto_offset.saturating_add(n as u64);
            payload.extend_from_slice(&encoded);
            *ack_eliciting = true;
            retransmittable.push(frame_value);
            return;
        }
        n -= 1;
    }
}

/** @brief 이 프레임이 상대의 확인을 끌어내는지. 채움과 확인 자체는 끌어내지 않는다. */
fn is_ack_eliciting(f: &Frame) -> bool {
    !matches!(f, Frame::Padding(_) | Frame::Ack { .. })
}

/**
 * @brief 상수 시간 비교.
 * @warning 재설정 토큰 비교에 쓴다. 걸린 시간이 새면 토큰을 한 바이트씩 알아낼 수 있다.
 */
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/** @brief 손실 시 다시 보내야 하는 프레임인지. 확인과 채움은 다시 보내지 않는다. */
fn is_retransmittable(f: &Frame) -> bool {
    matches!(
        f,
        Frame::Crypto { .. }
            | Frame::Stream { .. }
            | Frame::ResetStream { .. }
            | Frame::StopSending { .. }
            | Frame::MaxData(_)
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreams { .. }
            | Frame::HandshakeDone
            | Frame::PathChallenge(_)
    )
}

/** @brief 이 스트림 번호가 기록된 구간에 들어 있는지. */
fn stream_range_contains(ranges: &[Vec<(u64, u64)>; 4], id: u64) -> bool {
    let number = id >> 2;
    ranges[(id & 0x03) as usize]
        .iter()
        .any(|&(low, high)| (low..=high).contains(&number))
}

/**
 * @brief 스트림 번호를 구간으로 압축해 기록한다.
 * @details 번호마다 항목을 두면 스트림을 많이 여는 상대에게 메모리가 그대로 끌려간다.
 *          이어지는 번호를 하나의 구간으로 합쳐 둔다.
 */
fn mark_stream_range(ranges: &mut [Vec<(u64, u64)>; 4], id: u64) {
    let number = id >> 2;
    let ranges = &mut ranges[(id & 0x03) as usize];
    let mut low = number;
    let mut high = number;
    let mut index = 0usize;
    while index < ranges.len() {
        let (range_low, range_high) = ranges[index];
        if range_high.saturating_add(1) < low {
            index += 1;
            continue;
        }
        if high.saturating_add(1) < range_low {
            break;
        }
        low = low.min(range_low);
        high = high.max(range_high);
        ranges.remove(index);
    }
    ranges.insert(index, (low, high));
}

/** @brief 확인 프레임의 구간 표현을 실제 번호 구간으로 편다. 형식이 깨졌으면 None. */
fn ack_ranges(largest: u64, first_range: u64, ranges: &[(u64, u64)]) -> Option<Vec<(u64, u64)>> {
    let lo = largest.checked_sub(first_range)?;
    let mut out = Vec::with_capacity(ranges.len().saturating_add(1));
    out.push((lo, largest));
    let mut cur = lo;
    for &(gap, len) in ranges {
        let next_hi = cur.checked_sub(gap.checked_add(2)?)?;
        let next_lo = next_hi.checked_sub(len)?;
        out.push((next_lo, next_hi));
        cur = next_lo;
    }
    Some(out)
}

/** @brief 긴 헤더에서 목적지 식별자를 추출한다. */
fn long_header_dcid(pkt: &[u8]) -> Option<Vec<u8>> {
    let dcid_len = *pkt.get(5)? as usize;
    pkt.get(6..6 + dcid_len).map(|s| s.to_vec())
}

#[cfg(test)]
/** @brief 핸드셰이크, 흐름 제어, 손실 복구, 키 갱신, 그리고 재생과 조작 거부. */
mod tests {
    use super::*;
    use onetdns_tls::ServerConfig;
    use p256::pkcs8::DecodePrivateKey;
    use std::sync::Arc;

    #[test]
    /**
     * @brief 알리는 데이터그램 크기가 실제로 읽는 버퍼를 넘지 않는지.
     * @details 넘겨 알리면 상대가 그 크기로 보내도 되는데 이쪽은 잘라 읽고, 잘린 패킷은
     *          인증에 실패해 조용히 버려진다. 핸드셰이크 도중이면 그대로 멈춘다.
     */
    fn advertised_datagram_size_never_exceeds_the_buffer_we_read() {
        let asked = TransportParams {
            max_udp_payload_size: 65_527,
            ..TransportParams::server_defaults()
        };
        let normalized = normalize_local_transport_params(asked);
        assert_eq!(normalized.max_udp_payload_size, MAX_RECV_UDP_PAYLOAD);
        assert_eq!(MAX_RECV_UDP_PAYLOAD, MAX_DATAGRAM as u64);
    }

    /** @brief 테스트용 서버 설정. 자체 서명 인증서를 쓴다. */
    fn server_cfg(alpn: Vec<Vec<u8>>) -> Arc<ServerConfig> {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.example".to_string()]).unwrap();
        let cert_der = ck.cert.der().as_ref().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let signing =
            p256::ecdsa::SigningKey::from(p256::SecretKey::from_pkcs8_der(&key_der).unwrap());
        Arc::new(ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: 0x0403,
            sign: Arc::new(move |content| {
                use p256::ecdsa::{signature::Signer, Signature};
                let sig: Signature = signing.sign(content);
                sig.to_der().as_bytes().to_vec()
            }),
            alpn,
            client_ca: None,
            resumption: None,
        })
    }

    #[test]
    /** @brief 수신 연결이 Initial 전후 모두 같은 TLS 설정 Arc를 소유하는지. */
    fn server_connection_keeps_tls_config_shared_through_initial() {
        let config = server_cfg(vec![b"doq".to_vec()]);
        let certificate = config.cert_chain[0].as_ptr();
        let mut server = Connection::new_server(
            config.clone(),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        assert!(Arc::ptr_eq(server.cfg_server.as_ref().unwrap(), &config));
        assert_eq!(
            server.cfg_server.as_ref().unwrap().cert_chain[0].as_ptr(),
            certificate
        );

        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let initial = client.next_datagram().unwrap();
        server.recv_datagram(&initial).unwrap();

        assert!(
            server.cfg_server.is_none(),
            "설정은 핸드셰이크 상태기로 이동합니다"
        );
        assert_eq!(
            Arc::strong_count(&config),
            2,
            "Initial 처리 뒤에도 공유 Arc 하나만 연결이 소유해야 합니다"
        );
    }

    #[test]
    /** @brief 끝난 서버 핸드셰이크 상태를 버리되 외부에서 읽는 결과는 보존하는지. */
    fn server_releases_completed_tls_state_and_config_generation() {
        let config = server_cfg(vec![b"doq".to_vec()]);
        let mut server = Connection::new_server(
            config.clone(),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        pump(&mut client, &mut server);

        assert!(server.is_handshake_complete());
        assert!(server.tls_server.is_none());
        assert_eq!(server.alpn(), Some(b"doq".as_slice()));
        assert!(!server.is_resumed());
        assert!(!server.early_data_accepted());
        assert_eq!(
            Arc::strong_count(&config),
            1,
            "핸드셰이크가 끝나면 연결이 TLS 설정 세대까지 놓아야 합니다"
        );
    }

    #[test]
    /** @brief 논리 길이가 0이어도 Vec가 돌려주지 않은 예약 메모리를 계속 세는지. */
    fn retained_memory_counts_capacity_after_clear() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let baseline = server.retained_payload_bytes();

        server.retry_token = vec![0; 4 * 1024];
        server.reset_streams = Vec::with_capacity(64);
        server.reset_streams.push((0, 0));
        let retained = server.retained_payload_bytes();
        let minimum_growth = server.retry_token.capacity().saturating_add(
            server
                .reset_streams
                .capacity()
                .saturating_mul(std::mem::size_of::<(u64, u64)>()),
        );
        assert!(retained >= baseline.saturating_add(minimum_growth));

        server.retry_token.clear();
        server.reset_streams.clear();
        assert_eq!(server.retained_payload_bytes(), retained);
    }

    /** @brief 테스트용 클라이언트 설정. */
    fn client_cfg(alpn: Vec<Vec<u8>>) -> ClientConfig {
        ClientConfig {
            server_name: "dns.example".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn,
            ..Default::default()
        }
    }

    /** @brief 양쪽 데이터그램을 서로 전달해 진행시킨다. */
    fn pump(client: &mut Connection, server: &mut Connection) {
        for _ in 0..20 {
            let mut moved = false;
            while let Some(dg) = client.next_datagram() {
                server.recv_datagram(&dg).expect("server recv");
                moved = true;
            }
            while let Some(dg) = server.next_datagram() {
                client.recv_datagram(&dg).expect("client recv");
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    #[test]
    /** @brief 풀리지 않는 패킷을 버리되 연결은 유지하는지. 끊으면 그것이 탐색 신호가 된다. */
    fn reports_long_packet_protection_drop_without_closing_connection() {
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .expect("client");
        let mut datagram = client.next_datagram().expect("initial datagram");
        *datagram.last_mut().expect("protected payload") ^= 1;

        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        server.recv_datagram(&datagram).expect("silent packet drop");

        assert_eq!(
            server.take_diagnostic(),
            Some(QuicDiagnostic::LongPacketProtection)
        );
        assert_eq!(
            server.take_diagnostic(),
            None,
            "diagnostic is consumed once"
        );
        assert!(
            !server.is_closed(),
            "invalid packet must not close connection"
        );
    }

    #[test]
    /** @brief 허용 범위 밖 매개변수를 거부하고 사유를 남기는지. */
    fn reports_rejected_peer_transport_parameters() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );

        assert!(server.decode_peer_transport_params(&[0x01]).is_none());
        assert_eq!(
            server.take_diagnostic(),
            Some(QuicDiagnostic::TransportParameters)
        );
        assert_eq!(
            server.take_diagnostic(),
            None,
            "diagnostic is consumed once"
        );
    }

    #[test]
    /** @brief Retry를 거친 핸드셰이크가 정상 경로와 같게 끝나는지. */
    fn retry_path_handshake_completes_like_doq_listener() {
        use crate::retry::{build_retry, parse_initial_header, RetryKey};

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let retry_key = RetryKey::generate();

        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"ORIGDCID".to_vec(),
            b"CLNTSCID".to_vec(),
            TransportParams::server_defaults(),
        )
        .expect("client");

        let initial1 = client.next_datagram().expect("무토큰 Initial");
        let header = parse_initial_header(&initial1).expect("Initial 파싱");
        assert!(header.token.is_empty(), "첫 Initial에는 토큰이 없어야");

        let retry_scid = b"RETRYCID".to_vec();
        let token = retry_key.issue(ip, header.dcid, &retry_scid, 1_000);
        let retry = build_retry(header.dcid, header.scid, &retry_scid, &token);
        client.recv_datagram(&retry).expect("클라이언트 Retry 수용");

        let initial2 = client.next_datagram().expect("토큰 포함 Initial 재전송");
        let header2 = parse_initial_header(&initial2).expect("두 번째 Initial 파싱");
        assert!(
            !header2.token.is_empty(),
            "Retry 후 Initial에는 토큰이 실려야"
        );
        assert_eq!(header2.dcid, retry_scid.as_slice(), "새 DCID는 retry_scid");

        let original_dcid = retry_key
            .validate(header2.token, ip, header2.dcid, 1_010)
            .expect("토큰 검증");
        assert_eq!(original_dcid, b"ORIGDCID".to_vec());
        let mut tp = TransportParams::server_defaults();
        tp.original_destination_connection_id = Some(original_dcid);
        tp.retry_source_connection_id = Some(retry_scid.clone());

        // Retry를 보낸 서버는 그 뒤 첫 Initial에서 다른 식별자를 골라도 된다. 실제 공개
        // 서버가 그렇게 하므로, 여기서도 Retry 것과 다른 값을 쓴다. 같은 값을 쓰면 두 매개
        // 변수를 한 값으로 대조하는 잘못을 이 테스트가 놓친다.
        let server_scid = b"AFTERRTY".to_vec();
        assert_ne!(server_scid, retry_scid);
        let mut server =
            Connection::new_server(server_cfg(vec![b"doq".to_vec()]), server_scid.clone(), tp);

        server
            .recv_datagram(&initial2)
            .expect("서버가 post-Retry Initial 수용");

        pump(&mut client, &mut server);
        assert!(
            server.is_handshake_complete(),
            "서버 핸드셰이크 완료(post-Retry Initial 무응답이면 실패)"
        );
        assert!(
            client.is_handshake_complete(),
            "클라이언트 핸드셰이크 완료(Retry 식별자와 Initial 식별자를 한 값으로 대조하면 여기서 걸린다)"
        );
        assert!(!client.is_closed(), "클라이언트가 매개변수를 거부했습니다");
    }

    #[test]
    /** @brief 이쪽이 알린 윈도우가 실제 버퍼 상한과 맞는지. 어긋나면 상대를 굶기거나 이쪽이 넘친다. */
    fn local_transport_params_match_receive_resource_limits() {
        let mut tp = TransportParams::server_defaults();
        tp.initial_max_data = MAX_CONNECTION_REASSEMBLY + 1;
        tp.initial_max_stream_data_bidi_local = 0;
        tp.initial_max_stream_data_bidi_remote = MAX_STREAM_REASSEMBLY + 1;
        tp.initial_max_stream_data_uni = u64::MAX;
        tp.initial_max_streams_bidi = MAX_STREAMS_HARD as u64 + 1;
        tp.initial_max_streams_uni = u64::MAX;

        let conn =
            Connection::new_server(server_cfg(vec![b"doq".to_vec()]), b"SERVERID".to_vec(), tp);

        assert_eq!(conn.base_tp.initial_max_data, MAX_CONNECTION_REASSEMBLY);
        assert_eq!(conn.base_tp.initial_max_stream_data_bidi_local, 1);
        assert_eq!(
            conn.base_tp.initial_max_stream_data_bidi_remote,
            MAX_STREAM_REASSEMBLY
        );
        assert_eq!(
            conn.base_tp.initial_max_stream_data_uni,
            MAX_STREAM_REASSEMBLY
        );
        assert_eq!(
            conn.base_tp.initial_max_streams_bidi,
            MAX_STREAMS_HARD as u64
        );
        assert_eq!(
            conn.base_tp.initial_max_streams_uni,
            MAX_STREAMS_HARD as u64
        );
    }

    #[test]
    /** @brief 다시 온 같은 조각을 중복으로 쌓지 않는지. */
    fn reassembly_deduplicates_retransmitted_future_fragment() {
        let mut reasm = Reasm::default();
        for _ in 0..(MAX_PENDING_FRAGMENTS * 4) {
            assert!(reasm
                .push(100, b"future".to_vec(), 1024)
                .unwrap()
                .is_empty());
        }
        assert_eq!(reasm.pending.len(), 1);
        assert_eq!(reasm.pending_bytes, 6);
    }

    #[test]
    /** @brief 겹치는 조각을 합치고 한 번만 전달하는지. */
    fn reassembly_merges_consistent_overlaps_and_delivers_once() {
        let mut reasm = Reasm::default();
        assert!(reasm.push(3, b"def".to_vec(), 1024).unwrap().is_empty());
        assert_eq!(reasm.push(0, b"abcdef".to_vec(), 1024).unwrap(), b"abcdef");
        assert!(reasm.pending.is_empty());
        assert_eq!(reasm.pending_bytes, 0);
        assert_eq!(reasm.recv_offset, 6);
    }

    #[test]
    /** @brief 같은 위치에 다른 내용이 오면 거부하고 상태를 지키는지. */
    fn reassembly_rejects_conflicting_overlap_without_corrupting_state() {
        let mut reasm = Reasm::default();
        assert!(reasm.push(3, b"def".to_vec(), 1024).unwrap().is_empty());
        assert_eq!(reasm.push(4, b"XX".to_vec(), 1024), Err(QuicError::Frame));
        assert_eq!(reasm.push(0, b"abc".to_vec(), 1024).unwrap(), b"abcdef");
        assert!(reasm.pending.is_empty());
    }

    #[test]
    /** @brief 실제 소켓 위에서 핸드셰이크가 끝나는지. */
    fn loopback_quic_handshake_completes() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        pump(&mut client, &mut server);

        assert!(server.is_handshake_complete(), "서버 핸드셰이크 완료");
        assert!(client.is_handshake_complete(), "클라 핸드셰이크 완료");
        assert!(client.is_handshake_confirmed(), "클라 HANDSHAKE_DONE 수신");
        assert_eq!(server.alpn(), Some(b"doq".as_slice()));
        assert_eq!(client.alpn(), Some(b"doq".as_slice()));

        assert!(server.peer_transport_params().is_some());
        assert!(client.peer_transport_params().is_some());
    }

    #[test]
    /**
     * @brief 서버가 핸드셰이크를 끝내기 전에 온 1-RTT 패킷을 처리하지도 확인하지도 않는지.
     * @details 확인을 보내면 클라이언트는 그것으로 핸드셰이크가 확정됐다고 보고 Handshake 키를
     *          버릴 수 있다. 그 뒤 클라이언트의 Finished 를 잃으면 어느 쪽도 다시 보내지 않아
     *          연결이 멈춘다. 버린 질의는 핸드셰이크가 확정된 뒤 클라이언트가 다시 보낸다.
     */
    fn server_ignores_one_rtt_before_handshake_completes() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        while let Some(datagram) = client.next_datagram() {
            server.recv_datagram(&datagram).unwrap();
        }
        while let Some(datagram) = server.next_datagram() {
            client.recv_datagram(&datagram).unwrap();
        }
        assert!(client.is_handshake_complete());
        let finished: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        assert!(
            !finished.is_empty(),
            "클라이언트가 Finished 를 보내야 합니다"
        );

        client.send_dns_message(0, b"\x00\x00 QUERY").unwrap();
        let early: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        assert!(
            !early.is_empty() && early.iter().all(|datagram| datagram[0] & 0x80 == 0),
            "질의가 1-RTT 패킷으로만 나가야 이 시험이 의미가 있습니다"
        );
        for datagram in &early {
            server.recv_datagram(datagram).unwrap();
        }
        assert!(!server.is_handshake_complete());
        assert!(
            server.take_stream_requests().is_empty(),
            "핸드셰이크를 끝내기 전에 1-RTT 질의를 처리했습니다"
        );
        assert!(
            server.next_datagram().is_none(),
            "핸드셰이크를 끝내기 전에 1-RTT 패킷에 답했습니다"
        );

        for datagram in &finished {
            server.recv_datagram(datagram).unwrap();
        }
        pump(&mut client, &mut server);
        assert!(server.is_handshake_complete() && client.is_handshake_confirmed());
        client.on_timeout(5_000);
        while let Some(datagram) = client.next_datagram() {
            server.recv_datagram(&datagram).unwrap();
        }
        assert_eq!(
            server.take_stream_requests().len(),
            1,
            "버린 질의가 다시 오지 않았습니다"
        );
    }

    #[test]
    /** @brief 재설정 토큰이 매개변수에서 제대로 들어오는지. */
    fn server_reset_token_is_installed_from_transport_parameters() {
        let token = [0xa5; 16];
        let mut server_tp = TransportParams::server_defaults();
        server_tp.stateless_reset_token = Some(token);
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            server_tp,
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        assert_eq!(client.peer_reset_token, Some(token));
        client.recv_datagram(&token).unwrap();
        assert!(client.reset_received());
        assert!(client.is_closed());
    }

    #[test]
    /**
     * @brief Initial 을 담은 데이터그램이 최소 크기를 채우는지.
     *
     * @details RFC 9000은 그 데이터그램이 1200바이트 이상이어야 한다고 정하고, 받는
     *          쪽은 그보다 작은 데이터그램의 Initial 을 버려도 된다. 채우지 않으면 상대
     *          구현에 따라 핸드셰이크가 아무 오류 없이 멈춘다. 서버가 보내는 쪽도 같은 규칙이다.
     */
    fn datagrams_carrying_initial_packets_are_padded_to_the_minimum() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        let mut checked = 0usize;
        for _ in 0..8 {
            let mut moved = false;
            while let Some(dg) = client.next_datagram() {
                if carries_initial(&dg) {
                    assert!(
                        dg.len() >= MIN_INITIAL_DATAGRAM,
                        "클라이언트가 Initial 을 {}바이트 데이터그램으로 보냈습니다",
                        dg.len()
                    );
                    checked += 1;
                }
                server.recv_datagram(&dg).expect("server recv");
                moved = true;
            }
            while let Some(dg) = server.next_datagram() {
                if carries_initial(&dg) {
                    assert!(
                        dg.len() >= MIN_INITIAL_DATAGRAM,
                        "서버가 Initial 을 {}바이트 데이터그램으로 보냈습니다",
                        dg.len()
                    );
                    checked += 1;
                }
                client.recv_datagram(&dg).expect("client recv");
                moved = true;
            }
            if !moved {
                break;
            }
        }
        assert!(
            checked >= 2,
            "양쪽의 Initial 을 보지 못해 이 테스트가 재려던 것을 측정하지 못했습니다"
        );
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
    }

    /** @brief 이 데이터그램이 Initial 패킷으로 시작하는지. */
    fn carries_initial(dg: &[u8]) -> bool {
        !dg.is_empty() && dg[0] & 0x80 != 0 && (dg[0] & 0x30) == 0x00
    }

    #[test]
    /**
     * @brief 이쪽이 닫으면 상대가 그 사유를 실제로 받는지.
     *
     * @details 상태만 지우고 알리지 않으면 상대는 아무것도 받지 못한 채 자기 유휴 데드라인까지
     *          기다린다. DoQ 는 RFC 9250이 규격 위반에 CONNECTION_CLOSE 를 보내게
     *          하므로, 보낼 수단이 없으면 그 요구를 지킬 방법이 없다.
     */
    fn closing_tells_the_peer_why() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert!(!client.is_closed());

        server.close(0x2, "malformed DNS message");
        assert!(server.is_closed());
        let mut delivered = false;
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).expect("client recv");
            delivered = true;
        }
        assert!(delivered, "닫으면서 아무것도 내보내지 않았습니다");
        assert!(client.is_closed(), "상대가 닫힌 것을 알지 못했습니다");
        let peer = client.peer_close().expect("종료 사유가 오지 않았습니다");
        assert_eq!(peer.error_code, 0x2);
        assert_eq!(peer.frame_type, None, "응용 계층 종료여야 합니다");
        assert_eq!(peer.reason, b"malformed DNS message");

        // 두 번 불러도 한 번만 알린다.
        server.close(0x2, "again");
        assert!(server.next_datagram().is_none());
    }

    #[test]
    /**
     * @brief 혼잡 윈도우가 가득 차 있어도 종료 사유가 나가는지.
     *
     * @details 종료 알림을 보통 프레임과 같은 조건에 두면, 정작 알려야 할 때(상대가 답을
     *          받지 못해 윈도우가 찬 때)에 조용해진다. 그 상태가 바로 상대가 데드라인까지 기다리는
     *          경우다.
     */
    fn closing_is_not_held_back_by_the_congestion_window() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(server.is_handshake_complete());

        // 윈도우가 찬 상태를 직접 만든다. 트래픽으로 채우면 스트림 흐름 제어가 먼저 걸려
        // 재려던 조건에 닿지 못한다.
        server.bytes_in_flight = server.cwnd;
        assert!(
            !server.can_send_new(),
            "윈도우를 채우지 못해 이 테스트가 재려던 것을 측정하지 못했습니다"
        );

        server.close(0x2, "closed while blocked");
        let mut delivered = false;
        while let Some(dg) = server.next_datagram() {
            let _ = client.recv_datagram(&dg);
            delivered = true;
        }
        assert!(delivered, "윈도우가 찼다고 종료 사유를 삼켰습니다");
        assert_eq!(
            client.peer_close().map(|close| close.error_code),
            Some(0x2),
            "상대가 사유를 받지 못했습니다"
        );
    }

    #[test]
    /** @brief 상대가 알린 종료 사유가 보존되는지. */
    fn peer_connection_close_detail_is_retained() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut payload = Vec::new();
        frame::encode(
            &mut payload,
            &Frame::ConnectionClose {
                error_code: 0x10a,
                frame_type: None,
                reason: b"bad settings".to_vec(),
            },
        );

        conn.process_packet(APP, 0, &payload).unwrap();

        assert!(conn.is_closed());
        assert_eq!(
            conn.peer_close(),
            Some(&PeerClose {
                error_code: 0x10a,
                frame_type: None,
                reason: b"bad settings".to_vec(),
            })
        );
    }

    #[test]
    /** @brief 클라이언트가 재설정 토큰을 보내면 거부하는지. 규격상 서버만 보낸다. */
    fn client_cannot_send_stateless_reset_token_parameter() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client_tp = TransportParams::server_defaults();
        client_tp.stateless_reset_token = Some([0x5a; 16]);
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            client_tp,
        )
        .unwrap();

        pump(&mut client, &mut server);

        assert!(server.is_closed());
    }

    #[test]
    /** @brief 확인을 만든 뒤 기록을 놓아 주는지. */
    fn ack_build_releases_received_packet_history() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut ping = Vec::new();
        frame::encode(&mut ping, &Frame::Ping);
        for pn in 1..=32 {
            conn.process_packet(APP, pn, &ping).unwrap();
        }

        assert_eq!(conn.spaces[APP].recv_pns.len(), 32);
        assert!(conn.build_ack(APP).is_some());
        assert!(conn.spaces[APP].recv_pns.is_empty());
    }

    #[test]
    /** @brief 끊어진 수신 구간이 제대로 인코딩되는지. */
    fn ack_build_encodes_disjoint_received_ranges() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.spaces[APP].recv_pns = vec![1, 2, 5, 8, 9];

        let Frame::Ack {
            largest,
            first_range,
            ranges,
            ..
        } = conn.build_ack(APP).unwrap()
        else {
            panic!("ACK frame expected");
        };
        assert_eq!((largest, first_range), (9, 1));
        assert_eq!(ranges, vec![(1, 0), (1, 1)]);
        assert_eq!(
            ack_ranges(largest, first_range, &ranges),
            Some(vec![(8, 9), (5, 5), (1, 2)])
        );
    }

    #[test]
    /** @brief 구간이 흩어져도 확인 프레임이 패킷 크기를 넘지 않는지. */
    fn ack_build_caps_sparse_ranges_and_packet_size() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.spaces[APP].recv_pns = (0..100u64).step_by(2).collect();
        let ack = conn.build_ack(APP).unwrap();
        let Frame::Ack { ranges, .. } = &ack else {
            panic!("ACK frame expected");
        };
        assert_eq!(ranges.len(), MAX_ACK_RANGES);
        let mut encoded = Vec::new();
        frame::encode(&mut encoded, &ack);
        assert!(encoded.len() <= MAX_PACKET_PAYLOAD);
    }

    #[test]
    /** @brief 거대한 구간도 작게 담기고, 형식이 깨진 구간은 거부되는지. */
    fn huge_ack_range_stays_compact_and_malformed_ranges_are_rejected() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let largest = 1u64 << 60;
        conn.spaces[APP].next_pn = largest + 1;

        assert_eq!(conn.on_ack(APP, largest, 0, largest, &[]), Ok(()));
        assert_eq!(ack_ranges(largest, largest, &[]), Some(vec![(0, largest)]));
        assert_eq!(conn.on_ack(APP, 0, 0, 1, &[]), Err(QuicError::Frame));
        assert_eq!(conn.on_ack(APP, 10, 0, 0, &[(9, 0)]), Err(QuicError::Frame));
    }

    #[test]
    /** @brief 보낸 적 없는 패킷을 확인했다고 하면 거부하는지. 받아들이면 왕복 시간이 조작된다. */
    fn ack_cannot_claim_an_unsent_packet() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.spaces[APP].next_pn = 1;

        assert_eq!(conn.on_ack(APP, 1, 0, 0, &[]), Err(QuicError::Frame));
    }

    #[test]
    /** @brief 조기 데이터에 허용되지 않는 프레임을 거부하는지. */
    fn zero_rtt_rejects_ack_and_crypto_frames() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut ack = Vec::new();
        frame::encode(
            &mut ack,
            &Frame::Ack {
                largest: 0,
                delay: 0,
                first_range: 0,
                ranges: Vec::new(),
            },
        );
        let mut crypto = Vec::new();
        frame::encode(
            &mut crypto,
            &Frame::Crypto {
                offset: 0,
                data: vec![1],
            },
        );

        assert_eq!(
            conn.process_packet_kind(APP, 0, &ack, PacketKind::ZeroRtt),
            Err(QuicError::Frame)
        );
        assert_eq!(
            conn.process_packet_kind(APP, 1, &crypto, PacketKind::ZeroRtt),
            Err(QuicError::Frame)
        );
    }

    #[test]
    /** @brief 프레임이 허용된 암호화 수준과 방향에서만 오는지. 어기면 핸드셰이크를 우회할 수 있다. */
    fn frame_encryption_level_and_sender_are_enforced() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut stream = Vec::new();
        frame::encode(
            &mut stream,
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: vec![1],
            },
        );
        let mut done = Vec::new();
        frame::encode(&mut done, &Frame::HandshakeDone);

        assert_eq!(
            server.process_packet_kind(INITIAL, 0, &stream, PacketKind::Initial),
            Err(QuicError::Frame)
        );
        assert_eq!(
            server.process_packet_kind(APP, 0, &done, PacketKind::OneRtt),
            Err(QuicError::Frame)
        );

        let data_blocked = [frame::ftype::DATA_BLOCKED as u8, 0];
        assert_eq!(
            server.process_packet_kind(INITIAL, 1, &data_blocked, PacketKind::Initial),
            Err(QuicError::Frame)
        );
        let new_token = [frame::ftype::NEW_TOKEN as u8, 1, 0xa5];
        assert_eq!(
            server.process_packet_kind(APP, 1, &new_token, PacketKind::OneRtt),
            Err(QuicError::Frame)
        );
    }

    #[test]
    /** @brief 확인 키가 생기기 전에도 수신 기록이 상한 안에 머무는지. */
    fn receive_packet_history_is_bounded_before_ack_keys_exist() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut ping = Vec::new();
        frame::encode(&mut ping, &Frame::Ping);

        for pn in 0..(MAX_RECV_PACKET_HISTORY as u64 * 4) {
            conn.process_packet_kind(APP, pn, &ping, PacketKind::ZeroRtt)
                .unwrap();
        }

        assert_eq!(conn.spaces[APP].recv_pns.len(), MAX_RECV_PACKET_HISTORY);
        assert_eq!(
            conn.spaces[APP].recv_pns.iter().copied().min(),
            Some(MAX_RECV_PACKET_HISTORY as u64 * 3)
        );
    }

    #[test]
    /** @brief 재전송도 혼잡 윈도우를 지키는지. 지키지 않으면 손실 구간에서 상황이 더 나빠진다. */
    fn retransmissions_respect_congestion_window() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.spaces[APP].send_keys = Some((Aead::Aes128Gcm, derive_packet_keys(&[7; 32], 16)));
        conn.remote_cid = b"CLIENTID".to_vec();
        conn.cwnd = MAX_DATAGRAM as u64;
        conn.spaces[APP].rtx = (0..32)
            .map(|i| Frame::Stream {
                id: 0,
                offset: i * STREAM_FRAME_CHUNK as u64,
                fin: false,
                data: vec![0; STREAM_FRAME_CHUNK],
            })
            .collect();

        conn.flush();

        assert!(conn.bytes_in_flight <= conn.cwnd + MAX_DATAGRAM as u64);
        assert!(conn.spaces[APP].sent.len() <= 2);
        let outstanding = conn.spaces[APP].rtx.len()
            + conn.spaces[APP]
                .sent
                .iter()
                .map(|packet| packet.frames.len())
                .sum::<usize>();
        assert_eq!(outstanding, 32);
    }

    #[test]
    /** @brief 윈도우 갱신 상태가 연결 단위로 묶이는지. */
    fn max_stream_data_state_is_connection_bounded() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        for number in 0..MAX_STREAMS_HARD as u64 {
            let id = (number << 2) | 1;
            mark_stream_range(&mut conn.opened_send_ranges, id);
            conn.on_max_stream_data(id, 1).unwrap();
        }
        let next = (MAX_STREAMS_HARD as u64) << 2 | 1;
        mark_stream_range(&mut conn.opened_send_ranges, next);

        assert_eq!(
            conn.on_max_stream_data(next, 1),
            Err(QuicError::StreamLimit)
        );
        assert_eq!(conn.peer_stream_max.len(), MAX_STREAMS_HARD);
    }

    #[test]
    /** @brief 쌓아 둔 전송 데이터가 연결 단위로 묶이는지. */
    fn queued_stream_data_is_connection_bounded() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.peer_max_data = MAX_FLOW_CONTROL;
        conn.peer_max_streams_bidi = 1;
        conn.peer_stream_max.insert(1, MAX_FLOW_CONTROL);
        conn.out_frames_app.push(Frame::Stream {
            id: 1,
            offset: 0,
            fin: false,
            data: vec![0; MAX_CONNECTION_SEND_BUFFER],
        });

        assert_eq!(conn.send_stream(1, &[1], true), Err(QuicError::FlowControl));

        assert!(!conn.is_closed());
        assert_eq!(
            conn.buffered_stream_send_bytes(),
            MAX_CONNECTION_SEND_BUFFER
        );
    }

    #[test]
    /** @brief 한계에 닿았을 때 데이터를 버리지 않고 미루는지. */
    fn local_stream_and_flow_limits_are_non_destructive_backpressure() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut peer_tp = TransportParams::server_defaults();
        peer_tp.initial_max_stream_data_bidi_remote = 1024;
        conn.peer_tp = Some(peer_tp);

        assert_eq!(conn.open_uni_stream(), Ok(3));
        assert_eq!(conn.send_stream(1, b"response", true), Ok(()));
        assert_eq!(conn.pending_stream_sends.len(), 1);
        assert!(!conn
            .out_frames_app
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { id: 1, .. })));
        assert!(!conn.is_closed());

        conn.peer_max_streams_uni = 1;
        assert_eq!(conn.open_uni_stream(), Ok(7));

        let mut credit = Vec::new();
        frame::encode(&mut credit, &Frame::MaxStreams { uni: false, max: 1 });
        frame::encode(&mut credit, &Frame::MaxData(1024));
        conn.process_packet(APP, 1, &credit).unwrap();
        conn.flush();
        assert!(conn.pending_stream_sends.is_empty());
        assert!(conn.out_frames_app.iter().any(|frame| matches!(
            frame,
            Frame::Stream {
                id: 1,
                fin: true,
                data,
                ..
            } if data == b"response"
        )));
        assert!(!conn.is_closed());
    }

    #[test]
    /** @brief 윈도우가 조금 열렸을 때 한 스트림이 독차지하지 않는지. */
    fn pending_sends_resume_partially_without_starving_other_streams() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.peer_max_streams_bidi = 2;
        conn.peer_stream_max.insert(1, 16);
        conn.peer_stream_max.insert(5, 16);
        conn.peer_max_data = 4;

        conn.send_stream(1, b"abcdef", true).unwrap();
        conn.send_stream(5, b"uvwxyz", true).unwrap();
        assert_eq!(conn.pending_stream_sends.len(), 2);
        assert_eq!(conn.send_total, 4);

        conn.peer_max_data = 8;
        conn.flush();
        assert_eq!(conn.send_total, 8);
        assert_eq!(conn.pending_stream_sends.len(), 1);
        assert_eq!(conn.pending_stream_sends[0].id, 5);
        assert_eq!(conn.pending_stream_sends[0].cursor, 2);

        conn.peer_max_data = 12;
        conn.flush();
        assert!(conn.pending_stream_sends.is_empty());
        assert_eq!(conn.send_total, 12);
        let stream_five: Vec<u8> = conn
            .out_frames_app
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stream { id: 5, data, .. } => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert_eq!(stream_five, b"uvwxyz");
    }

    #[test]
    /** @brief 중단 요청 뒤 안 보낸 부분을 버리고 최종 크기를 맞게 알리는지. */
    fn stop_sending_discards_unscheduled_tail_and_uses_accepted_final_size() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.peer_max_streams_bidi = 1;
        conn.peer_stream_max.insert(1, 16);
        conn.peer_max_data = 3;

        conn.send_stream(1, b"abcdef", true).unwrap();
        assert_eq!(conn.pending_stream_sends.len(), 1);
        assert_eq!(conn.send_offsets.get(&1), Some(&6));

        conn.on_stop_sending(1, 0x42).unwrap();
        assert!(conn.pending_stream_sends.is_empty());
        assert!(!conn
            .out_frames_app
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { id: 1, .. })));
        assert!(conn.out_frames_app.iter().any(|frame| matches!(
            frame,
            Frame::ResetStream {
                id: 1,
                error_code: 0x42,
                final_size: 6
            }
        )));
    }

    #[test]
    /** @brief 빈 전송 요청도 개수 상한에 잡히는지. 안 잡으면 그것만으로 큐를 채울 수 있다. */
    fn zero_length_pending_operations_are_count_bounded() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        for number in 0..MAX_PENDING_SEND_OPS as u64 {
            let id = (number << 2) | 1;
            assert_eq!(conn.send_stream(id, &[], true), Ok(()));
        }
        assert_eq!(conn.pending_stream_sends.len(), MAX_PENDING_SEND_OPS);
        let next = (MAX_PENDING_SEND_OPS as u64) << 2 | 1;
        assert_eq!(
            conn.send_stream(next, &[], true),
            Err(QuicError::FlowControl)
        );
        assert!(!conn.is_closed());
    }

    #[test]
    /** @brief 실제 소켓 위에서 DoQ 질의와 응답이 오가는지. */
    fn loopback_doq_query_response() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());

        let dns_query = b"\xAB\xCD QUERY-DNS-MESSAGE-BYTES";
        client.send_dns_message(0, dns_query).unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }

        let reqs = server.take_stream_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, 0);
        assert_eq!(reqs[0].1, dns_query);

        let dns_resp = b"\xAB\xCD RESPONSE-DNS-MESSAGE";
        server.send_dns_message(0, dns_resp).unwrap();
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let resps = client.take_stream_requests();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].0, 0);
        assert_eq!(resps[0].1, dns_resp);
    }

    #[test]
    /** @brief 요청 소비로 생긴 흐름 제어 갱신을 작은 응답과 한 패킷에 묶는지. */
    fn completed_doq_request_batches_flow_credit_with_response() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        client.send_dns_message(0, b"query").unwrap();
        while let Some(datagram) = client.next_datagram() {
            server.recv_datagram(&datagram).unwrap();
        }
        while server.next_datagram().is_some() {}

        assert_eq!(server.take_stream_requests(), vec![(0, b"query".to_vec())]);
        assert!(
            server.next_datagram().is_none(),
            "흐름 제어 갱신만 든 별도 패킷을 보내지 않아야 한다"
        );

        server.send_dns_message(0, b"response").unwrap();
        let datagrams: Vec<_> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert_eq!(
            datagrams.len(),
            1,
            "작은 응답과 흐름 제어 갱신은 한 패킷이어야 한다"
        );
    }

    #[test]
    /** @brief 같은 패킷을 다시 보내도 데이터가 한 번만 전달되는지. */
    fn replayed_protected_packet_delivers_stream_only_once() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        client.send_dns_message(0, b"one-query").unwrap();
        let datagram = client.next_datagram().expect("protected query datagram");
        assert!(client.next_datagram().is_none());
        server.recv_datagram(&datagram).unwrap();
        server.recv_datagram(&datagram).unwrap();

        assert_eq!(
            server.take_stream_requests(),
            vec![(0, b"one-query".to_vec())]
        );
        assert!(server.take_stream_requests().is_empty());
    }

    #[test]
    /** @brief 순서가 바뀐 패킷은 받되 오래된 것은 버리는지. */
    fn packet_number_window_accepts_reordering_once_and_drops_stale_packets() {
        let mut space = SpaceState::default();
        assert!(space.accept_packet_number(10));
        assert!(space.accept_packet_number(8));
        assert!(!space.accept_packet_number(8));
        assert!(space.accept_packet_number(200));
        assert!(space.accept_packet_number(199));
        assert!(!space.accept_packet_number(10));
    }

    #[test]
    /** @brief 끝난 스트림이 윈도우를 돌려주는지. 돌려주지 않으면 곧 막힌다. */
    fn completed_stream_replenishes_stream_and_connection_credit() {
        let mut server_tp = TransportParams::server_defaults();
        server_tp.initial_max_streams_bidi = 1;
        server_tp.initial_max_data = 32;
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            server_tp,
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        for (stream_id, query) in [(0, b"first-query-contents"), (4, b"second-query-content")] {
            client.send_dns_message(stream_id, query).unwrap();
            pump(&mut client, &mut server);
            let requests = server.take_stream_requests();
            assert_eq!(requests, vec![(stream_id, query.to_vec())]);
            server.send_dns_message(stream_id, b"response").unwrap();
            pump(&mut client, &mut server);
            assert_eq!(
                client.take_stream_requests(),
                vec![(stream_id, b"response".to_vec())]
            );
        }

        assert_eq!(server.local_max_streams_bidi, 3);
        assert!(server.local_max_data > 32);
        assert_eq!(server.recv_buffered, 0);
    }

    #[test]
    /** @brief 응용이 읽으면 버퍼가 풀리고 윈도우가 밀리는지. */
    fn application_reads_release_buffer_and_slide_flow_control_windows() {
        let mut tp = TransportParams::server_defaults();
        tp.initial_max_data = 4;
        tp.initial_max_stream_data_bidi_remote = 2;
        let mut conn =
            Connection::new_server(server_cfg(vec![b"h3".to_vec()]), b"SERVERID".to_vec(), tp);

        conn.on_stream(0, 0, false, b"ab".to_vec()).unwrap();
        assert_eq!(conn.recv_buffered, 2);
        assert_eq!(conn.streams[&0].buf, b"ab");

        assert_eq!(conn.take_readable(), vec![(0, b"ab".to_vec(), false)]);
        assert_eq!(conn.recv_buffered, 0);
        assert!(conn.streams[&0].buf.is_empty());
        assert_eq!(conn.streams[&0].app_consumed, 2);
        assert_eq!(conn.local_max_data, 6);
        assert_eq!(conn.local_stream_max[&0], MAX_STREAM_REASSEMBLY + 2);

        conn.on_stream(0, 2, false, b"cdef".to_vec()).unwrap();
        assert_eq!(conn.take_readable(), vec![(0, b"cdef".to_vec(), false)]);
        assert_eq!(conn.recv_buffered, 0);
        assert_eq!(conn.streams[&0].app_consumed, 6);
        assert_eq!(conn.local_max_data, 10);
    }

    #[test]
    /** @brief 읽은 뒤 끊기면 남은 몫만 돌려주는지. 두 번 돌려주면 윈도우가 부풀어 오른다. */
    fn reset_after_application_read_releases_only_unconsumed_credit() {
        let mut tp = TransportParams::server_defaults();
        tp.initial_max_data = 4;
        tp.initial_max_stream_data_bidi_remote = 2;
        let mut conn =
            Connection::new_server(server_cfg(vec![b"h3".to_vec()]), b"SERVERID".to_vec(), tp);

        conn.on_stream(0, 0, false, b"ab".to_vec()).unwrap();
        conn.take_readable();
        assert_eq!(conn.local_max_data, 6);

        conn.on_reset_stream(0, 0x10, 5).unwrap();
        assert_eq!(conn.local_max_data, 9);
        assert_eq!(conn.recv_buffered, 0);
        assert!(!conn.local_stream_max.contains_key(&0));
        assert_eq!(conn.take_resets(), vec![(0, 0x10)]);
    }

    #[test]
    /** @brief 윈도우가 1바이트여도 큰 메시지가 끝까지 가는지. */
    fn one_byte_initial_stream_window_progresses_large_doq_message() {
        let mut server_tp = TransportParams::server_defaults();
        server_tp.initial_max_stream_data_bidi_remote = 1;
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            server_tp,
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        let query = vec![0x5a; 4096];
        client.send_dns_message(0, &query).unwrap();
        pump(&mut client, &mut server);

        assert_eq!(server.take_stream_requests(), vec![(0, query)]);
        assert!(!client.is_closed());
        assert!(!server.is_closed());
    }

    #[test]
    /** @brief 이미 읽어 간 데이터가 재전송으로 다시 전달되지 않는지. */
    fn retransmitted_stream_after_application_release_is_not_delivered_twice() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut payload = Vec::new();
        frame::encode(
            &mut payload,
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"\x00\x03dns".to_vec(),
            },
        );

        conn.process_packet(APP, 1, &payload).unwrap();
        assert_eq!(conn.take_stream_requests(), vec![(0, b"dns".to_vec())]);
        let max_data_after_release = conn.local_max_data;

        conn.process_packet(APP, 2, &payload).unwrap();
        assert!(conn.take_stream_requests().is_empty());
        assert_eq!(conn.local_max_data, max_data_after_release);
    }

    #[test]
    /** @brief 스트림을 끊으면 윈도우가 한 번만 돌아가고 취소가 알려지는지. */
    fn reset_stream_releases_credit_once_and_reports_cancellation() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let initial_data = conn.local_max_data;
        let initial_streams = conn.local_max_streams_bidi;

        conn.on_stream(0, 0, false, b"partial".to_vec()).unwrap();
        conn.on_reset_stream(0, 0x10, 12).unwrap();

        assert_eq!(conn.take_resets(), vec![(0, 0x10)]);
        assert_eq!(conn.recv_buffered, 0);
        assert_eq!(conn.local_max_data, initial_data + 12);
        assert_eq!(conn.local_max_streams_bidi, initial_streams + 1);

        conn.on_reset_stream(0, 0x10, 12).unwrap();
        assert!(conn.take_resets().is_empty());
        assert_eq!(conn.local_max_data, initial_data + 12);
        assert!(conn.on_stream(0, 0, true, b"duplicate".to_vec()).is_ok());
        assert!(conn.take_stream_requests().is_empty());
    }

    #[test]
    /** @brief 중단 요청이 대기 데이터를 취소하고 끊기 프레임을 넣는지. */
    fn stop_sending_cancels_pending_stream_data_and_queues_reset() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.peer_max_data = 1024;
        conn.peer_max_streams_bidi = 1;
        conn.peer_stream_max.insert(1, 1024);
        conn.send_stream(1, b"pending", false).unwrap();
        assert!(conn
            .out_frames_app
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { id: 1, .. })));

        conn.on_stop_sending(1, 0x20).unwrap();

        assert!(!conn
            .out_frames_app
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { id: 1, .. })));
        assert!(conn.out_frames_app.iter().any(|frame| matches!(
            frame,
            Frame::ResetStream {
                id: 1,
                error_code: 0x20,
                final_size: 7
            }
        )));
    }

    #[test]
    /** @brief 중단 요청 뒤에는 늦은 전송이 나가지 않는지. */
    fn stop_sending_before_response_prevents_late_stream_send() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.on_stream(0, 0, false, b"request".to_vec()).unwrap();
        conn.on_stop_sending(0, 0x21).unwrap();
        assert!(conn.out_frames_app.iter().any(|frame| matches!(
            frame,
            Frame::ResetStream {
                id: 0,
                error_code: 0x21,
                final_size: 0
            }
        )));

        conn.peer_max_data = 1024;
        conn.peer_stream_max.insert(0, 1024);
        assert_eq!(
            conn.send_stream(0, b"late response", true),
            Err(QuicError::StreamClosed)
        );
        assert!(!conn
            .out_frames_app
            .iter()
            .any(|frame| matches!(frame, Frame::Stream { id: 0, .. })));
        assert!(!conn.is_closed());
    }

    #[test]
    /** @brief 모르는 스트림에 대한 중단 요청을 거부하는지. */
    fn stop_sending_for_unknown_stream_is_rejected() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        assert_eq!(conn.on_stop_sending(0, 0), Err(QuicError::Frame));
        assert_eq!(conn.on_stop_sending(3, 0), Err(QuicError::Frame));
    }

    #[test]
    /** @brief 상대가 이쪽 스트림 번호를 열거나 윈도우를 주지 못하는지. 번호 공간이 역할별로 나뉘어 있다. */
    fn peer_cannot_open_or_grant_credit_to_local_stream_ids() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );

        assert_eq!(
            conn.on_stream(1, 0, false, b"forged".to_vec()),
            Err(QuicError::StreamLimit)
        );
        assert_eq!(conn.on_max_stream_data(1, 10), Err(QuicError::Frame));
        assert_eq!(conn.on_max_stream_data(2, 10), Err(QuicError::Frame));
        assert!(conn.streams.is_empty());
        assert!(conn.peer_stream_max.is_empty());
    }

    #[test]
    /** @brief 이미 끝난 스트림의 윈도우 갱신이 상태를 되살리지 않는지. */
    fn max_stream_data_after_send_fin_does_not_recreate_state() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.peer_max_data = 1024;
        conn.peer_max_streams_bidi = 1;
        conn.peer_stream_max.insert(1, 1024);
        conn.send_stream(1, b"done", true).unwrap();
        assert!(conn.peer_stream_max.is_empty());

        conn.on_max_stream_data(1, 2048).unwrap();
        assert!(conn.peer_stream_max.is_empty());
    }

    #[test]
    /** @brief 윈도우 갱신이 손실되면 다시 보내지는지. 잃으면 상대가 영영 막힌다. */
    fn flow_control_updates_are_retransmittable() {
        assert!(is_retransmittable(&Frame::MaxData(10)));
        assert!(is_retransmittable(&Frame::MaxStreamData { id: 0, max: 10 }));
        assert!(is_retransmittable(&Frame::MaxStreams {
            uni: false,
            max: 10
        }));
        assert!(is_retransmittable(&Frame::ResetStream {
            id: 0,
            error_code: 0,
            final_size: 0
        }));
    }

    #[test]
    /** @brief 큰 스트림이 데이터그램 크기 안에서 나뉘는지. */
    fn large_stream_is_packetized_within_datagram_limit() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());

        let dns_query = vec![0x5a; 60_000];
        client.send_dns_message(0, &dns_query).unwrap();

        let mut total_datagrams = 0usize;
        for _ in 0..100 {
            let mut moved = false;
            while let Some(datagram) = client.next_datagram() {
                assert!(
                    datagram.len() <= MAX_DATAGRAM,
                    "모든 UDP 데이터그램이 로컬 상한 이하"
                );
                total_datagrams += 1;
                server.recv_datagram(&datagram).unwrap();
                moved = true;
            }
            while let Some(datagram) = server.next_datagram() {
                client.recv_datagram(&datagram).unwrap();
                moved = true;
            }
            if !moved {
                break;
            }
        }
        assert!(total_datagrams > 1, "큰 메시지는 여러 패킷으로 분할");
        let requests = server.take_stream_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1, dns_query);
    }

    #[test]
    /** @brief 키 갱신 중에도 데이터가 끊기지 않는지. */
    fn key_update_rotates_and_keeps_data_flowing() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert!(client.key_update_allowed && server.key_update_allowed);

        client.send_dns_message(0, b"\xAB\xCD Q1").unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        assert_eq!(server.take_stream_requests().len(), 1);

        let before = client.send_key_phase;
        assert!(client.initiate_key_update(), "확인 후 키 업데이트 허용");
        assert_ne!(client.send_key_phase, before, "송신 페이즈 토글");

        client.send_dns_message(4, b"\xAB\xCD Q2-after-KU").unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        let reqs = server.take_stream_requests();
        assert_eq!(reqs.len(), 1, "키 업데이트 후에도 질의 도착");
        assert_eq!(reqs[0].1, b"\xAB\xCD Q2-after-KU");
        assert_eq!(
            server.recv_key_phase, client.send_key_phase,
            "서버 수신 페이즈가 따라옴"
        );

        server.send_dns_message(4, b"\xAB\xCD R2").unwrap();
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let resps = client.take_stream_requests();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].1, b"\xAB\xCD R2");
    }

    #[test]
    /** @brief 경로 확인 문답이 오가는지. */
    fn path_validation_challenge_response() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());

        assert!(
            client.initiate_path_validation(),
            "핸드셰이크 후 검증 시작 가능"
        );
        assert!(!client.path_validated());
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        assert!(
            client.path_validated(),
            "PATH_RESPONSE 수신 → 경로 검증 완료"
        );
    }

    #[test]
    /** @brief 상태 없는 재설정을 받으면 연결을 닫는지. */
    fn stateless_reset_closes_connection() {
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let token = [0x5Au8; 16];
        client.set_peer_reset_token(token);
        assert!(!client.is_closed());

        let mut dg = vec![0x40u8; 30];
        dg.extend_from_slice(&token);
        client.recv_datagram(&dg).unwrap();
        assert!(
            client.reset_received() && client.is_closed(),
            "리셋 인지 → 종료"
        );
    }

    #[test]
    /** @brief 잃은 질의가 다시 보내지는지. */
    fn loss_recovery_retransmits_dropped_query() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());

        client.set_now(1000);
        let dns_query = b"\xAB\xCD QUERY";
        client.send_dns_message(0, dns_query).unwrap();
        let dropped: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        assert!(!dropped.is_empty(), "질의 데이터그램 생성됨");

        assert!(
            client.bytes_in_flight() > 0,
            "손실된 패킷이 비행 중으로 남음"
        );

        client.on_timeout(1000 + 10_000);
        let retransmitted: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        assert!(!retransmitted.is_empty(), "PTO로 질의가 재전송됨");

        for dg in &retransmitted {
            server.recv_datagram(dg).unwrap();
        }
        let reqs = server.take_stream_requests();
        assert_eq!(reqs.len(), 1, "재전송으로 질의가 결국 도착");
        assert_eq!(reqs[0].1, dns_query);
    }

    #[test]
    /** @brief 확인이 왕복 시간을 갱신하고 대기 바이트를 줄이는지. */
    fn ack_processing_updates_rtt_and_clears_inflight() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);

        assert_eq!(client.bytes_in_flight(), 0, "핸드셰이크 패킷 모두 ACK됨");
        assert!(client.srtt_ms() > 0, "RTT 추정값 존재");
    }

    #[test]
    /** @brief 확인 지연을 빼되 최소 왕복 시간 아래로 내려가지 않는지. 내려가면 재전송이 너무 빨라진다. */
    fn ack_delay_is_removed_without_going_below_minimum_rtt() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );

        conn.update_rtt(50, 0);
        conn.update_rtt(100, 20);

        assert_eq!(conn.min_rtt_ms, 50);
        assert_eq!(conn.srtt_ms, 53);
    }

    #[test]
    /** @brief 한 회복 구간에 윈도우가 한 번만 줄어드는지. 여러 번 줄이면 지나치게 보수적이 된다. */
    fn congestion_window_is_reduced_once_per_recovery_period() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.cwnd = 16 * MAX_DATAGRAM as u64;
        conn.now_ms = 200;
        conn.spaces[APP].sent.push(SentPacket {
            pn: 0,
            time_ms: 100,
            ack_eliciting: true,
            size: 1000,
            frames: vec![Frame::Ping],
        });
        conn.spaces[APP].largest_acked = Some(3);
        conn.detect_lost(APP);
        let once = conn.cwnd;
        assert!(
            once < 16 * MAX_DATAGRAM as u64,
            "첫 손실에 윈도우가 줄어야 합니다"
        );

        conn.now_ms = 201;
        conn.spaces[APP].sent.push(SentPacket {
            pn: 1,
            time_ms: 150,
            ack_eliciting: true,
            size: 1000,
            frames: vec![Frame::Ping],
        });
        conn.spaces[APP].largest_acked = Some(4);
        conn.detect_lost(APP);

        assert_eq!(conn.cwnd, once);
    }

    /** @brief 핸드셰이크를 끝낸 DoQ 클라이언트와 서버. */
    fn established_doq_pair() -> (Connection, Connection) {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_confirmed() && server.is_handshake_complete());
        (client, server)
    }

    /** @brief 클라이언트가 보낸 질의를 서버가 받고, 서버의 확인까지 클라이언트에 전한다. */
    fn deliver_query(client: &mut Connection, server: &mut Connection, stream: u64) {
        client.send_dns_message(stream, b"\x00\x00 QUERY").unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        assert_eq!(server.take_stream_requests().len(), 1);
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
    }

    #[test]
    /**
     * @brief HANDSHAKE_DONE 만 담은 패킷에도 클라이언트가 확인을 보내는지.
     * @details 답하지 않으면 서버는 그 패킷을 영영 확인받지 못한다. 서버가 기다리는 확인이
     *          오지 않으니 PTO 는 계속 두 배로 늘고, 그 뒤에 잃은 응답을 알아챌 길도 없다.
     */
    fn handshake_done_alone_is_acknowledged() {
        let (mut client, mut server) = established_doq_pair();
        server.out_frames_app.push(Frame::HandshakeDone);
        server.flush();
        let datagram = server.next_datagram().expect("HANDSHAKE_DONE 데이터그램");
        assert_eq!(server.spaces[APP].sent.len(), 1);

        client.recv_datagram(&datagram).unwrap();
        let ack = client
            .next_datagram()
            .expect("HANDSHAKE_DONE 을 받고도 확인을 보내지 않았습니다");
        server.recv_datagram(&ack).unwrap();
        assert!(server.spaces[APP].sent.is_empty());
    }

    #[test]
    /**
     * @brief ACK 만 담은 패킷을 확인받아도 그보다 앞서 잃은 패킷을 손실로 판정하는지.
     * @details ACK 만 담은 패킷은 기록하지 않으므로 이 확인이 알려 주는 바이트는 없다. 그렇다고
     *          판정을 건너뛰면 상대가 그런 패킷을 계속 확인해 줘도 잃은 데이터는 PTO 로만 다시
     *          나간다. 핸드셰이크 중 ServerHello 를 잃으면 클라이언트는 같은 Initial 을 거듭
     *          보내며 서버의 ACK 를 확인해 주는데, 서버는 그 사이 PTO 만 기다리다 멈췄다.
     */
    fn ack_of_ack_only_packets_detects_earlier_loss() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);

        server.set_now(1_000);
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        while server.next_datagram().is_some() {}
        let lost = server.spaces[APP].sent.last().expect("응답 패킷").pn;

        for _ in 0..3 {
            client.out_frames_app.push(Frame::Ping);
            client.flush();
            while let Some(datagram) = client.next_datagram() {
                server.recv_datagram(&datagram).unwrap();
            }
            while server.next_datagram().is_some() {}
        }
        let largest = server.spaces[APP].next_pn - 1;
        assert!(
            server.spaces[APP]
                .sent
                .iter()
                .all(|packet| packet.pn <= lost),
            "PING 에 대한 답은 ACK 만 담아야 이 시험이 의미가 있습니다"
        );
        assert!(lost + 3 <= largest);

        let mut ack = Vec::new();
        frame::encode(
            &mut ack,
            &Frame::Ack {
                largest,
                delay: 0,
                first_range: largest - lost - 1,
                ranges: Vec::new(),
            },
        );
        server.process_packet(APP, 1_000, &ack).unwrap();
        server.flush();
        while let Some(datagram) = server.next_datagram() {
            client.recv_datagram(&datagram).unwrap();
        }
        let responses = client.take_stream_requests();
        assert_eq!(
            responses.len(),
            1,
            "PTO 전에 잃은 응답을 다시 보내지 않았습니다"
        );
        assert_eq!(responses[0].1, b"\x00\x00 RESPONSE");
    }

    #[test]
    /**
     * @brief 첫 PTO 프로브가 가장 오래된 패킷 뒤의 데이터까지 싣는지.
     * @details 서버가 HANDSHAKE_DONE 과 응답을 따로 보냈고 둘 다 잃은 상태다. 프로브마다 가장
     *          오래된 패킷 하나만 실으면 응답 사본은 PTO 한 번 걸러 나가고 간격은 두 배씩 늘어,
     *          그 사본만 계속 잃으면 아무것도 보내지 않는 클라이언트는 응답을 끝내 받지 못한다.
     */
    fn first_probe_carries_data_behind_the_oldest_packet() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);

        server.set_now(1_000);
        server.out_frames_app.push(Frame::HandshakeDone);
        server.flush();
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        let lost: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert_eq!(
            lost.len(),
            2,
            "HANDSHAKE_DONE 과 응답이 따로 나가야 이 모양이 됩니다"
        );

        server.on_timeout(1_000 + server.base_pto_ms());
        let probes: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert!(!probes.is_empty(), "PTO 에 프로브가 나가야 합니다");
        for datagram in &probes {
            client.recv_datagram(datagram).unwrap();
        }
        let responses = client.take_stream_requests();
        assert_eq!(responses.len(), 1, "첫 프로브가 응답을 싣지 않았습니다");
        assert_eq!(responses[0].1, b"\x00\x00 RESPONSE");
    }

    #[test]
    /**
     * @brief PTO 가 프로브에 실을 만큼만 다시 보낼 차례에 넣는지.
     * @details 확인받지 못한 프레임을 전부 옮기면 꼬리 하나를 잃어도 PTO 한 번에 윈도우 전체를
     *          다시 보낸다. 나머지는 프로브가 확인받은 뒤 손실 판정이 골라 다시 보낸다.
     */
    fn pto_requeues_only_what_its_probes_carry() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);

        server.set_now(1_000);
        server.send_dns_message(0, &[0x5a; 8_000]).unwrap();
        while server.next_datagram().is_some() {}
        let carrying = |conn: &Connection| {
            conn.spaces[APP]
                .sent
                .iter()
                .filter(|packet| packet.time_ms == 1_000 && !packet.frames.is_empty())
                .count()
        };
        let outstanding = carrying(&server);
        assert!(
            outstanding > 2 * usize::from(PROBE_PACKETS),
            "프로브보다 훨씬 많은 패킷이 남아 있어야 이 시험이 의미가 있습니다"
        );

        server.on_timeout(1_000 + server.base_pto_ms());
        let requeued = outstanding - carrying(&server);
        assert!(
            (1..=usize::from(PROBE_PACKETS)).contains(&requeued),
            "PTO 가 원래 패킷 {requeued}개의 프레임을 옮겼습니다"
        );
    }

    #[test]
    /**
     * @brief 다음 PTO 가 마지막 프로브를 보낸 때부터 두 배를 기다리는지.
     * @details 원래 패킷은 확인을 받으려고 남겨 두므로, 가장 오래된 패킷의 나이로 재면 프로브를
     *          보낸 직후에도 데드라인이 이미 지나 있어 PTO 마다 프로브가 몰려 나간다.
     */
    fn next_pto_waits_twice_as_long_after_the_latest_probe() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);

        server.set_now(1_000);
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        while server.next_datagram().is_some() {}

        let base = server.base_pto_ms();
        let first_probe_at = 1_000 + base;
        server.on_timeout(first_probe_at - 1);
        assert!(
            server.next_datagram().is_none(),
            "PTO 가 너무 일찍 났습니다"
        );
        server.on_timeout(first_probe_at);
        assert!(
            server.next_datagram().is_some(),
            "첫 PTO 에 프로브가 나가야 합니다"
        );
        while server.next_datagram().is_some() {}

        server.on_timeout(first_probe_at + 2 * base - 1);
        assert!(
            server.next_datagram().is_none(),
            "다음 PTO 는 마지막 프로브로부터 두 배를 기다려야 합니다"
        );
        server.on_timeout(first_probe_at + 2 * base);
        let probes: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert!(!probes.is_empty(), "두 번째 PTO 에 프로브가 나가야 합니다");
        for datagram in &probes {
            client.recv_datagram(datagram).unwrap();
        }
        assert_eq!(client.take_stream_requests().len(), 1);
    }

    #[test]
    /**
     * @brief 혼잡 윈도우가 차 있어도 PTO 프로브가 나가는지.
     * @details PTO 는 원래 패킷을 흐르는 양에 남겨 둔다. 프로브까지 윈도우에 막히면 윈도우는
     *          확인이 와야 열리는데 확인은 프로브가 가야 오므로 회복이 멈춘다.
     */
    fn probe_is_sent_when_congestion_window_is_full() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);

        server.set_now(1_000);
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        while server.next_datagram().is_some() {}
        server.bytes_in_flight = server.cwnd;
        assert!(!server.can_send_new());

        server.on_timeout(1_000 + server.base_pto_ms());
        let probes: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert!(
            !probes.is_empty(),
            "윈도우가 찼다고 프로브를 보내지 않았습니다"
        );
        for datagram in &probes {
            client.recv_datagram(datagram).unwrap();
        }
        assert_eq!(client.take_stream_requests().len(), 1);
    }

    #[test]
    /**
     * @brief 시간 기준 손실을 새 확인 없이 타이머로 판정하는지.
     * @details 뒤에 보낸 패킷이 확인됐지만 앞의 패킷이 아직 시간 기준에 못 미치면, 그 시각에
     *          다시 확인해야 한다. 판정을 확인이 올 때만 하면 다음 확인이 없는 한 PTO 까지
     *          기다리게 된다.
     */
    fn time_threshold_loss_fires_without_another_ack() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);
        deliver_query(&mut client, &mut server, 4);
        server.srtt_ms = 80;
        server.latest_rtt_ms = 80;
        server.rttvar_ms = 0;

        server.set_now(1_000);
        server.send_dns_message(0, b"\x00\x00 FIRST").unwrap();
        while server.next_datagram().is_some() {}
        server.set_now(1_010);
        server.send_dns_message(4, b"\x00\x00 SECOND").unwrap();
        while let Some(datagram) = server.next_datagram() {
            client.recv_datagram(&datagram).unwrap();
        }
        server.set_now(1_020);
        while let Some(datagram) = client.next_datagram() {
            server.recv_datagram(&datagram).unwrap();
        }
        while server.next_datagram().is_some() {}

        let due = server.spaces[APP]
            .loss_time_ms
            .expect("시간 기준을 기다리는 패킷에 판정 시각이 걸려야 합니다");
        assert!(
            due < server.pto_deadline().expect("PTO 데드라인"),
            "손실 판정이 PTO 보다 먼저 와야 이 시험이 의미가 있습니다"
        );
        server.on_timeout(due - 1);
        assert!(server.next_datagram().is_none());

        server.on_timeout(due);
        let resent: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        assert!(!resent.is_empty(), "판정 시각에 다시 보내지 않았습니다");
        for datagram in &resent {
            client.recv_datagram(datagram).unwrap();
        }
        let responses = client.take_stream_requests();
        assert!(responses
            .iter()
            .any(|(stream, body)| *stream == 0 && body == b"\x00\x00 FIRST"));
    }

    #[test]
    /**
     * @brief 핸드셰이크가 확정되면 양쪽이 Initial 과 Handshake 공간을 버리는지.
     * @details 남겨 두면 끝난 핸드셰이크의 재전송이 응용 데이터보다 먼저 PTO 를 차지하고,
     *          키와 재조립 버퍼가 연결 수명 내내 메모리에 남는다.
     */
    fn confirmed_handshake_discards_initial_and_handshake_spaces() {
        let (client, server) = established_doq_pair();
        for conn in [&client, &server] {
            for space in [INITIAL, HANDSHAKE] {
                let state = &conn.spaces[space];
                assert!(state.discarded, "{:?} 쪽 {space} 공간", conn.role);
                assert!(state.send_keys.is_none() && state.recv_keys.is_none());
                assert!(state.sent.is_empty() && state.rtx.is_empty());
            }
            let app_in_flight: u64 = conn.spaces[APP].sent.iter().map(|packet| packet.size).sum();
            assert_eq!(conn.bytes_in_flight, app_in_flight);
        }
    }

    #[test]
    /** @brief 늦게 온 Initial 이 버린 키를 되살리지 않는지. */
    fn late_initial_does_not_restore_discarded_keys() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let first_flight = client.next_datagram().expect("첫 Initial");
        server.recv_datagram(&first_flight).unwrap();
        pump(&mut client, &mut server);
        assert!(server.spaces[INITIAL].discarded);

        server.recv_datagram(&first_flight).unwrap();
        assert!(server.spaces[INITIAL].recv_keys.is_none());
        assert!(server.spaces[INITIAL].send_keys.is_none());
        assert!(!server.is_closed());
        assert!(server.next_datagram().is_none());
    }

    #[test]
    /**
     * @brief 풀 수 없는 긴 헤더 패킷 뒤에 합쳐진 패킷을 계속 처리하는지.
     * @details Initial 공간을 버린 뒤에도 상대는 Initial 과 다른 패킷을 한 데이터그램에 합쳐
     *          보낼 수 있다. 앞 패킷에서 처리를 멈추면 뒤에 붙은 패킷까지 잃는다.
     */
    fn packet_after_undecryptable_long_packet_is_processed() {
        let (mut client, mut server) = established_doq_pair();
        deliver_query(&mut client, &mut server, 0);
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        let response = server.next_datagram().expect("응답 데이터그램");

        let stale_keys = derive_packet_keys(&[9; 32], 16);
        let mut datagram = packet::protect_long(
            Aead::Aes128Gcm,
            &stale_keys,
            ptype::INITIAL,
            b"CLIENTID",
            b"SERVERID",
            &[],
            7,
            4,
            &[0u8; 40],
        );
        datagram.extend_from_slice(&response);
        client.recv_datagram(&datagram).unwrap();

        let responses = client.take_stream_requests();
        assert_eq!(responses.len(), 1, "앞의 Initial 에서 처리를 멈췄습니다");
    }

    #[test]
    /**
     * @brief 핸드셰이크가 끝난 클라이언트가 Retry 를 무시하는지.
     * @details Handshake 키를 버린 뒤에도 Retry 를 받으면 연결이 ClientHello 부터 다시
     *          시작한다. RFC 9000 은 서버의 Initial 을 처리한 뒤의 Retry 를 버리게 한다.
     */
    fn retry_after_handshake_is_ignored() {
        let (mut client, _server) = established_doq_pair();
        let remote_before = client.remote_connection_id().to_vec();
        let retry = crate::retry::build_retry(b"INITDCID", b"CLIENTID", b"NEWSCID1", b"token");

        client.recv_datagram(&retry).unwrap();
        assert_eq!(client.remote_connection_id(), remote_before.as_slice());
        assert!(client.spaces[INITIAL].send_keys.is_none());
        assert!(client.next_datagram().is_none());
        assert!(!client.is_closed());
    }

    #[test]
    /**
     * @brief 길이 0인 연결 식별자를 쓰는 클라이언트와 질의를 주고받는지.
     * @details 서버는 그런 클라이언트에게 목적지 식별자 없이 짧은 헤더 패킷을 보내고, 전송
     *          파라미터의 initial_source_connection_id 도 길이 0으로 맞춰 본다.
     */
    fn client_with_zero_length_connection_id_exchanges_query() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            Vec::new(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_confirmed() && server.is_handshake_complete());
        assert!(server.remote_cid.is_empty());

        deliver_query(&mut client, &mut server, 0);
        server.send_dns_message(0, b"\x00\x00 RESPONSE").unwrap();
        while let Some(datagram) = server.next_datagram() {
            client.recv_datagram(&datagram).unwrap();
        }
        let responses = client.take_stream_requests();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].1, b"\x00\x00 RESPONSE");
    }

    #[test]
    /** @brief 유휴 데드라인에 연결이 닫히고 남은 출력이 버려지는지. */
    fn negotiated_idle_timeout_closes_and_discards_pending_output() {
        let mut tp = TransportParams::server_defaults();
        tp.max_idle_timeout = 100;
        let mut conn =
            Connection::new_server(server_cfg(vec![b"doq".to_vec()]), b"SERVERID".to_vec(), tp);
        conn.out_datagrams.push_back(vec![1, 2, 3]);
        conn.out_frames_app.push(Frame::Ping);
        conn.send_stream(1, b"pending", true).unwrap();
        assert!(!conn.pending_stream_sends.is_empty());

        assert!(!conn.on_timeout(100));
        assert!(conn.is_closed());
        assert!(conn.next_datagram().is_none());
        assert!(conn.out_frames_app.is_empty());
        assert!(conn.pending_stream_sends.is_empty());
    }

    /** @brief 세션 재개를 지원하는 테스트용 서버 설정. */
    fn server_cfg_resumable(res: &onetdns_tls::conn::ServerResumption) -> Arc<ServerConfig> {
        let mut config = server_cfg(vec![b"doq".to_vec()]);
        Arc::make_mut(&mut config).resumption = Some(res.clone());
        config
    }

    /** @brief 재개에 쓸 세션 티켓을 하나 받아 온다. */
    fn obtain_session(res: &onetdns_tls::conn::ServerResumption) -> onetdns_tls::TlsSession {
        let mut server = Connection::new_server(
            server_cfg_resumable(res),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        let sessions = client.take_new_sessions();
        assert!(!sessions.is_empty(), "NewSessionTicket로 세션을 받아야");
        sessions.into_iter().next().unwrap()
    }

    #[test]
    /** @brief 규격 밖 길이의 연결 식별자를 거부하는지. */
    fn constructors_reject_unsupported_connection_id_lengths() {
        let client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            vec![0u8; 21],
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        );
        assert!(matches!(client, Err(QuicError::Frame)));

        let server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            vec![0u8; 21],
            TransportParams::server_defaults(),
        );
        assert!(server.is_closed());
    }

    #[test]
    /** @brief 조기 데이터 질의가 핸드셰이크 완료 전에 전달되는지. 왕복 하나를 아낀다. */
    fn zero_rtt_query_delivered_before_handshake_completes() {
        let mut res = onetdns_tls::conn::ServerResumption::secure_default();
        res.max_early_data = 0xffff_ffff;
        let session = obtain_session(&res);
        assert_eq!(session.max_early_data, 0xffff_ffff);

        let mut server2 = Connection::new_server(
            server_cfg_resumable(&res),
            b"SERVERI2".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut cfg = client_cfg(vec![b"doq".to_vec()]);
        cfg.session = Some(session);
        cfg.enable_early_data = true;
        let mut client2 = Connection::new_client(
            cfg,
            b"INITDCI2".to_vec(),
            b"CLIENTI2".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        assert!(client2.can_send_early(), "재개 세션이면 0-RTT 송신 가능");

        let dns_query = b"\x00\x00 ZERO-RTT-DNS-QUERY";
        client2.send_dns_message(0, dns_query).unwrap();

        while let Some(dg) = client2.next_datagram() {
            server2.recv_datagram(&dg).unwrap();
        }
        assert!(
            !server2.is_handshake_complete(),
            "클라 Finished 전: 서버 핸드셰이크 미완 상태여야"
        );
        let reqs = server2.take_stream_requests();
        assert_eq!(
            reqs.len(),
            1,
            "0-RTT로 질의가 핸드셰이크 완료 전에 도착해야"
        );
        assert_eq!(reqs[0].1, dns_query);

        pump(&mut client2, &mut server2);
        assert!(server2.is_handshake_complete() && client2.is_handshake_complete());
        assert!(server2.tls_server.is_none());
        assert!(server2.is_resumed(), "PSK 재개");
        assert!(client2.is_resumed());
        assert!(server2.early_data_accepted() && client2.early_data_accepted());

        let dns_resp = b"\x00\x00 ZERO-RTT-RESPONSE";
        server2.send_dns_message(0, dns_resp).unwrap();
        while let Some(dg) = server2.next_datagram() {
            client2.recv_datagram(&dg).unwrap();
        }
        let resps = client2.take_stream_requests();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].1, dns_resp);
    }

    #[test]
    /** @brief 조기 데이터가 거부되면 핸드셰이크 뒤 다시 보내지는지. */
    fn zero_rtt_rejected_replays_in_1rtt() {
        let mut res_a = onetdns_tls::conn::ServerResumption::secure_default();
        res_a.max_early_data = 0xffff_ffff;
        let session = obtain_session(&res_a);

        let res_b = onetdns_tls::conn::ServerResumption::secure_default();
        let mut server2 = Connection::new_server(
            server_cfg_resumable(&res_b),
            b"SERVERI3".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut cfg = client_cfg(vec![b"doq".to_vec()]);
        cfg.session = Some(session);
        cfg.enable_early_data = true;
        let mut client2 = Connection::new_client(
            cfg,
            b"INITDCI3".to_vec(),
            b"CLIENTI3".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        assert!(client2.can_send_early());

        let dns_query = b"\x00\x00 REJECTED-EARLY-QUERY";
        client2.send_dns_message(0, dns_query).unwrap();

        pump(&mut client2, &mut server2);
        assert!(server2.is_handshake_complete() && client2.is_handshake_complete());
        assert!(!server2.is_resumed(), "모르는 티켓 → 전체 핸드셰이크");
        assert!(!client2.early_data_accepted(), "0-RTT 거부");

        let reqs = server2.take_stream_requests();
        assert_eq!(reqs.len(), 1, "거부된 0-RTT 질의가 1-RTT로 재전송돼야");
        assert_eq!(reqs[0].1, dns_query);

        server2.send_dns_message(0, b"\x00\x00 OK").unwrap();
        while let Some(dg) = server2.next_datagram() {
            client2.recv_datagram(&dg).unwrap();
        }
        assert_eq!(client2.take_stream_requests().len(), 1);
    }

    #[test]
    /** @brief 조기 데이터 없이 재개만 하는 경우. */
    fn resumed_connection_without_early_data() {
        let res = onetdns_tls::conn::ServerResumption::secure_default();
        let session = obtain_session(&res);

        let mut server2 = Connection::new_server(
            server_cfg_resumable(&res),
            b"SERVERI4".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut cfg = client_cfg(vec![b"doq".to_vec()]);
        cfg.session = Some(session);
        cfg.enable_early_data = false;
        let mut client2 = Connection::new_client(
            cfg,
            b"INITDCI4".to_vec(),
            b"CLIENTI4".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        assert!(
            !client2.can_send_early(),
            "0-RTT 미제안이면 early 송신 불가"
        );

        pump(&mut client2, &mut server2);
        assert!(client2.is_handshake_complete() && server2.is_handshake_complete());
        assert!(
            client2.is_resumed() && server2.is_resumed(),
            "PSK 재개는 수락"
        );
        assert!(!client2.early_data_accepted());

        client2
            .send_dns_message(0, b"\x00\x00 RESUMED-1RTT")
            .unwrap();
        while let Some(dg) = client2.next_datagram() {
            server2.recv_datagram(&dg).unwrap();
        }
        assert_eq!(server2.take_stream_requests().len(), 1);
    }
}
