use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use onetdns_tls::engine::{ClientHandshake, Level, SecretPair, ServerHandshake};
use onetdns_tls::{ClientConfig, ServerConfig, TlsError};

use crate::frame::{self, Frame};
use crate::packet::{self, ptype};
use crate::params::TransportParams;
use crate::protect::Aead;
use crate::{
    derive_packet_keys, derive_updated_kv, initial_secrets, next_key_update_secret, PacketKeys,
};

const INITIAL: usize = 0;
const HANDSHAKE: usize = 1;
const APP: usize = 2;

/// RFC 9000 lets a receiver drop Initial packets in smaller datagrams, so without padding the
/// handshake stalls silently with some peers.
const MIN_INITIAL_DATAGRAM: usize = 1200;

/// RFC 9000 keeps an endpoint that does no path MTU discovery at or below 1200 bytes, and this side
/// does none. A peer cannot advertise a max_udp_payload_size below 1200, so this also fits what the
/// peer accepts.
///
/// Raising it needs path MTU discovery and must respect the peer's max_udp_payload_size.
const MAX_DATAGRAM: usize = 1200;

/// Advertised as max_udp_payload_size, and the socket read buffer must use it too: advertising more
/// lets the peer send datagrams that get truncated, fail authentication, and are dropped, stalling
/// the handshake. Peers doing path MTU discovery may send more than 1200 bytes, so this goes up to
/// a size common internet paths carry unfragmented.
///
/// At least the RFC 9000 minimum of 1200, and no smaller than what this side sends.
pub const MAX_RECV_UDP_PAYLOAD: u64 = 1350;

/// Build-time checks of the two bounds.
const _: [(); 0] = [(); (MAX_RECV_UDP_PAYLOAD < 1200) as usize];
const _: [(); 0] = [(); (MAX_RECV_UDP_PAYLOAD < MAX_DATAGRAM as u64) as usize];

/// Frame bytes per packet, after header and tag.
const MAX_PACKET_PAYLOAD: usize = 1000;
const STREAM_FRAME_CHUNK: usize = 900;
const MAX_RETRY_TOKEN: usize = 256;

/// Most non-frame bytes in a long header packet, not counting an Initial token: first byte,
/// version, two length-prefixed connection IDs of up to 20 bytes, a 2-byte length, a 4-byte packet
/// number, and a 16-byte tag.
const MAX_LONG_HEADER_OVERHEAD: usize = 1 + 4 + (1 + 20) + (1 + 20) + 2 + 4 + 16;
const MAX_SHORT_HEADER_OVERHEAD: usize = 1 + 20 + 4 + 16;

/// A full long header packet without a token must fit one datagram; the 1 is the empty token length
/// of an Initial.
const _: [(); 0] =
    [(); (MAX_LONG_HEADER_OVERHEAD + 1 + MAX_PACKET_PAYLOAD > MAX_DATAGRAM) as usize];

/// Frame type, error code, offending frame type, and reason length.
const MAX_CLOSE_FRAME_OVERHEAD: usize = 1 + 8 + 8 + 2;

/// Before the handshake is confirmed, a close datagram carries a close frame in each of an Initial,
/// a Handshake, and a 1-RTT packet. This keeps it within MAX_DATAGRAM even with the longest Retry
/// token in the Initial.
const MAX_CLOSE_REASON: usize = (MAX_DATAGRAM
    - (MAX_LONG_HEADER_OVERHEAD + 2 + MAX_RETRY_TOKEN)
    - MAX_LONG_HEADER_OVERHEAD
    - MAX_SHORT_HEADER_OVERHEAD)
    / 3
    - MAX_CLOSE_FRAME_OVERHEAD;

const CRYPTO_CHUNK: usize = 900;
/// Without it, one large offset could hold memory.
const MAX_CRYPTO_REASSEMBLY: u64 = 1 << 20;
const MAX_STREAM_REASSEMBLY: u64 = 1 << 18;
/// Per-stream caps alone could be bypassed by opening many streams.
const MAX_CONNECTION_REASSEMBLY: u64 = 1 << 20;
const MAX_CONNECTION_SEND_BUFFER: usize = 1 << 20;
const MAX_PENDING_SEND_OPS: usize = 512;
const MAX_PENDING_FRAGMENTS: usize = 256;
/// Applies whatever the configuration says.
const MAX_STREAMS_HARD: usize = 256;
const MAX_ACK_RANGES: usize = 32;
/// Packet numbers remembered for duplicate detection; one u128 bitmap.
const MAX_RECV_PACKET_HISTORY: usize = u128::BITS as usize;
/// Peer flow control values are clamped to this.
const MAX_FLOW_CONTROL: u64 = 1 << 60;
/// Packets a PTO may send beyond the congestion window, the two RFC 9002 allows: one lost datagram
/// need not wait for the next PTO, and the overshoot stays bounded.
const PROBE_PACKETS: u8 = 2;

const INTERNAL_ERROR: u64 = 0x1;
const FLOW_CONTROL_ERROR: u64 = 0x3;
const STREAM_LIMIT_ERROR: u64 = 0x4;
const STREAM_STATE_ERROR: u64 = 0x5;
const FINAL_SIZE_ERROR: u64 = 0x6;
const FRAME_ENCODING_ERROR: u64 = 0x7;
const TRANSPORT_PARAMETER_ERROR: u64 = 0x8;
const CONNECTION_ID_LIMIT_ERROR: u64 = 0x9;
const PROTOCOL_VIOLATION: u64 = 0xa;
const CRYPTO_BUFFER_EXCEEDED: u64 = 0xd;
/// Replaces an application close carried in Initial or Handshake packets. Those can travel before
/// the peer is authenticated, so RFC 9000 has the application code and reason replaced by this code
/// and an empty reason.
const APPLICATION_ERROR: u64 = 0xc;
/// TLS alerts are sent as this plus the alert code, as RFC 9001 specifies.
const CRYPTO_ERROR: u64 = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketKind {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Only StreamClosed is limited to one stream; the connection stays usable. Each connection error
/// the peer causes has its own RFC 9000 transport error code.
pub enum QuicError {
    /// The error decides the TLS alert sent to the peer.
    Tls(TlsError),
    Frame,
    FrameEncoding,
    StreamState,
    FinalSize,
    CryptoBufferExceeded,
    FlowControl,
    StreamLimit,
    ConnectionIdLimit,
    /// A layer above QUIC found a violation of its own protocol and closed the connection; the
    /// close frame carried this code and reason as an application close.
    Application {
        code: u64,
        reason: &'static str,
    },
    Closed,
    /// The peer refused the reply with STOP_SENDING, or this side already sent the end of the
    /// stream.
    StreamClosed,
    /// The peer announced shutdown, as after an HTTP/3 server's GOAWAY. The connection is still
    /// open, and replies to earlier requests can still arrive.
    GoingAway,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Why a connection failed; for logs only.
pub enum QuicDiagnostic {
    LongPacketProtection,
    TransportParameters,
}

impl QuicDiagnostic {
    pub const fn stage(self) -> &'static str {
        match self {
            Self::LongPacketProtection => "long_packet_protection",
            Self::TransportParameters => "transport_parameters",
        }
    }
}

impl std::fmt::Display for QuicDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LongPacketProtection => {
                "Could not verify header protection or authentication of a QUIC long-header packet"
            }
            Self::TransportParameters => "Peer QUIC transport parameters are invalid",
        })
    }
}

impl QuicError {
    /// TLS errors are sent as CRYPTO_ERROR plus the alert code, as RFC 9001 specifies. TLS errors
    /// without an alert, and Application, Closed, StreamClosed and GoingAway, which the receive
    /// path never produces, are sent as internal errors.
    fn transport_code(&self) -> u64 {
        match self {
            QuicError::Tls(error) => error
                .alert()
                .map_or(INTERNAL_ERROR, |alert| CRYPTO_ERROR + u64::from(alert)),
            QuicError::Frame => PROTOCOL_VIOLATION,
            QuicError::FrameEncoding => FRAME_ENCODING_ERROR,
            QuicError::StreamState => STREAM_STATE_ERROR,
            QuicError::FinalSize => FINAL_SIZE_ERROR,
            QuicError::CryptoBufferExceeded => CRYPTO_BUFFER_EXCEEDED,
            QuicError::FlowControl => FLOW_CONTROL_ERROR,
            QuicError::StreamLimit => STREAM_LIMIT_ERROR,
            QuicError::ConnectionIdLimit => CONNECTION_ID_LIMIT_ERROR,
            QuicError::Application { .. }
            | QuicError::Closed
            | QuicError::StreamClosed
            | QuicError::GoingAway => INTERNAL_ERROR,
        }
    }
}

impl std::fmt::Display for QuicError {
    /// This text goes to the peer as the CONNECTION_CLOSE reason.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            QuicError::Tls(error) => return write!(f, "TLS handshake failed: {error}"),
            QuicError::Application { code, reason } => {
                return write!(f, "Application protocol error 0x{code:x}: {reason}")
            }
            QuicError::Frame => "QUIC protocol violation",
            QuicError::FrameEncoding => "Malformed QUIC frame",
            QuicError::StreamState => "Frame not allowed in the stream's state",
            QuicError::FinalSize => "QUIC stream final size violation",
            QuicError::CryptoBufferExceeded => "Too much out-of-order handshake data",
            QuicError::FlowControl => "Flow control violation",
            QuicError::StreamLimit => "QUIC stream limit exceeded",
            QuicError::ConnectionIdLimit => "QUIC connection ID limit exceeded",
            QuicError::Closed => "Connection closed",
            QuicError::StreamClosed => "Stream no longer accepts data",
            QuicError::GoingAway => "Peer is shutting the connection down",
        };
        f.write_str(reason)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerClose {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason: Vec<u8>,
}

/// Clamps what this side advertises, whatever the configuration says: a large flow control window
/// lets the peer hold that much of this side's memory.
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

fn level_space(level: Level) -> usize {
    match level {
        Level::Initial => INITIAL,
        Level::Handshake => HANDSHAKE,
        Level::Application => APP,
    }
}

fn suite_aead(suite: u16) -> (Aead, usize) {
    match suite {
        0x1302 => (Aead::Aes256Gcm, 32),
        0x1303 => (Aead::ChaCha20Poly1305, 32),
        _ => (Aead::Aes128Gcm, 16),
    }
}

#[derive(Default)]
/// Reassembles data that arrives out of order: the contiguous prefix comes out, the rest waits.
struct Reasm {
    /// Contiguous up to here.
    recv_offset: u64,
    pending: Vec<(u64, Vec<u8>)>,
    pending_bytes: usize,
}

impl Reasm {
    /// Includes the spare capacity of the list and of each piece.
    fn retained_payload_bytes(&self) -> usize {
        self.pending
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, Vec<u8>)>())
            .saturating_add(self.pending.iter().fold(0usize, |total, (_, fragment)| {
                total.saturating_add(fragment.capacity())
            }))
    }

    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Takes a piece and returns what became contiguous. The buffered amount is capped; otherwise
    /// one byte at a large offset could hold memory.
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

fn frame_retained_payload_bytes(frame: &Frame) -> usize {
    match frame {
        Frame::Ack { ranges, .. } => ranges
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, u64)>()),
        Frame::Crypto { data, .. } | Frame::Stream { data, .. } => data.capacity(),
        Frame::ConnectionClose { reason, .. } => reason.capacity(),
        Frame::NewConnectionId { cid, .. } => cid.capacity(),
        _ => 0,
    }
}

/// Includes the list's spare capacity and nested buffers.
fn frames_retained_payload_bytes(frames: &[Frame], capacity: usize) -> usize {
    capacity
        .saturating_mul(std::mem::size_of::<Frame>())
        .saturating_add(frames.iter().fold(0usize, |total, frame| {
            total.saturating_add(frame_retained_payload_bytes(frame))
        }))
}

fn stream_ranges_retained_bytes(ranges: &[Vec<(u64, u64)>; 4]) -> usize {
    ranges.iter().fold(0usize, |total, range| {
        total.saturating_add(
            range
                .capacity()
                .saturating_mul(std::mem::size_of::<(u64, u64)>()),
        )
    })
}

/// A conservative charge for HashMap's reserved buckets. `capacity` counts entries that fit without
/// reallocating, which is fewer than the buckets, so this takes twice entry plus control byte, plus
/// a small constant, to stay above the current SwissTable layout. An upper bound an attacker can
/// drive, not an RSS estimate.
fn hash_map_retained_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    if map.capacity() == 0 {
        return 0;
    }
    map.capacity()
        .saturating_mul(std::mem::size_of::<(K, V)>().saturating_add(1))
        .saturating_mul(2)
        .saturating_add(64)
}

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
        .saturating_add(
            params
                .preferred_address
                .as_ref()
                .map_or(0, |address| address.cid.capacity()),
        )
}

fn packet_keys_retained_bytes(keys: &PacketKeys) -> usize {
    keys.key
        .capacity()
        .saturating_add(keys.iv.capacity())
        .saturating_add(keys.hp.capacity())
}

#[derive(Default)]
struct StreamRecv {
    asm: Reasm,
    buf: Vec<u8>,
    fin_offset: Option<u64>,
    done: bool,
    /// Counted for flow control.
    highest_offset: u64,
    /// Bytes the caller has taken.
    app_consumed: u64,
}

#[derive(Default)]
struct SpaceState {
    send_keys: Option<(Aead, PacketKeys)>,
    recv_keys: Option<(Aead, PacketKeys)>,
    next_pn: u64,
    largest_recv: Option<u64>,
    /// Bits for packets received just below largest_recv.
    recv_mask: u128,
    /// Not yet acknowledged.
    recv_pns: Vec<u64>,
    ack_pending: bool,
    send_crypto_offset: u64,
    out_crypto: Vec<u8>,
    crypto_asm: Reasm,
    /// In order, but TLS does not read this level yet. RFC 9001 has data above TLS's current level
    /// buffered until TLS reaches it.
    crypto_ready: Vec<u8>,

    sent: Vec<SentPacket>,

    rtx: Vec<Frame>,

    /// The reference point for loss detection.
    largest_acked: Option<u64>,
    /// The PTO is measured from here, not from the oldest unacknowledged packet: measured from
    /// that, the deadline would already be past right after a probe, and the exponential backoff
    /// would do nothing.
    last_ack_eliciting_ms: u64,
    /// When packets not yet lost by the time threshold become lost.
    loss_time_ms: Option<u64>,
    /// A discarded space is never revived: rebuilding keys from a late Initial would bring a
    /// finished handshake state back.
    discarded: bool,
}

impl SpaceState {
    /// Accepting a duplicate would allow replay. A bitmap covers the recent range, and older
    /// numbers are rejected outright.
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

/// Kept until acknowledged or declared lost.
struct SentPacket {
    pn: u64,
    time_ms: u64,
    ack_eliciting: bool,

    /// Counted as bytes in flight.
    size: u64,

    /// Resent if the packet is lost.
    frames: Vec<Frame>,
}

/// Waits for the window to open.
struct PendingStreamSend {
    id: u64,
    offset: u64,
    data: Vec<u8>,
    cursor: usize,
    fin: bool,
    /// Times this piece went into a packet.
    copies: usize,
}

/// A connection ID the peer issued; this side sends to it.
struct PeerCid {
    /// The handshake connection ID is 0.
    sequence: u64,
    cid: Vec<u8>,
    /// A client cannot send a reset token in its transport parameters, so the server's entry for
    /// sequence 0 has none.
    reset_token: Option<[u8; 16]>,
}

/// The closing or draining period of RFC 9000, before the state is dropped. Closing when this side
/// closed: the close frame may have been lost, so late packets get the same close datagram again.
/// Draining when the peer closed: nothing is sent. Either way the connection stays for the period
/// so late packets cannot start a new connection or draw a wrong reply. Keys and buffers are not
/// needed meanwhile, so only this state need stay.
pub struct ClosePeriod {
    /// The close datagram to resend while closing; None while draining.
    datagram: Option<Vec<u8>>,
    until_ms: u64,
    received: u64,
    received_bytes: u64,
    resent_bytes: u64,
}

impl ClosePeriod {
    /// Resends the close datagram only when the received count is a power of two, as RFC 9000
    /// suggests, so replies thin out. Packets are answered without decryption, so resent bytes are
    /// capped at three times the bytes received in the period, the limit RFC 9000 sets for a
    /// closing state without keys; otherwise a spoofed source could use it as an amplifier.
    ///
    /// `len` is the received datagram's size. None while draining, or when this one gets no reply.
    pub fn answer(&mut self, len: usize) -> Option<Vec<u8>> {
        let datagram = self.datagram.as_ref()?;
        self.received = self.received.saturating_add(1);
        self.received_bytes = self.received_bytes.saturating_add(len as u64);
        let resent = self.resent_bytes.saturating_add(datagram.len() as u64);
        if !self.received.is_power_of_two() || resent > self.received_bytes.saturating_mul(3) {
            return None;
        }
        self.resent_bytes = resent;
        Some(datagram.clone())
    }

    pub fn is_over(&self, now_ms: u64) -> bool {
        now_ms >= self.until_ms
    }

    pub fn retained_bytes(&self) -> usize {
        self.datagram.as_ref().map_or(0, Vec::capacity)
    }
}

/// One QUIC connection, sans-IO: datagrams and the current time come in, datagrams to send come
/// out.
pub struct Connection {
    role: Role,

    tls_server: Option<ServerHandshake>,
    /// Shared, so large certificate material is not copied per connection, even before the Initial.
    cfg_server: Option<Arc<ServerConfig>>,
    base_tp: TransportParams,
    tls_client: Option<ClientHandshake>,
    spaces: [SpaceState; 3],
    local_cid: Vec<u8>,
    /// Entry peer_cid_in_use of peer_cids.
    remote_cid: Vec<u8>,
    /// Initial keys derive from it.
    initial_dcid: Vec<u8>,
    /// The source connection ID of the peer's first Initial. RFC 9000 sets the destination from it
    /// alone and drops later Initials with another source ID; initial_source_connection_id is
    /// checked against it too.
    peer_initial_scid: Option<Vec<u8>>,
    /// Connection IDs from the peer not yet retired, in sequence order. Sequence 0, and 1 when the
    /// server sent a preferred address, are filled in when the peer's transport parameters are
    /// accepted; after that NEW_CONNECTION_ID adds and retire_prior_to removes.
    peer_cids: Vec<PeerCid>,
    peer_cid_in_use: u64,
    /// Everything below it has been retired.
    peer_retire_prior_to: u64,
    /// Retired, but the packet that said so is not acknowledged yet.
    retiring_peer_cids: Vec<u64>,
    handshake_complete: bool,
    /// A server confirms when the handshake completes, a client when it receives HANDSHAKE_DONE.
    /// Confirmation drops the Initial and Handshake spaces and arms the application PTO.
    handshake_confirmed: bool,
    /// Kept after the server TLS state is dropped.
    handshake_resumed: bool,
    handshake_early_accepted: bool,
    closed: bool,
    /// None means a closed connection can be dropped at once.
    close_period: Option<ClosePeriod>,
    diagnostic: Option<QuicDiagnostic>,
    peer_close: Option<PeerClose>,
    peer_tp: Option<TransportParams>,
    alpn: Option<Vec<u8>>,
    client_authenticated: bool,
    client_auth_identity: Option<String>,
    out_datagrams: VecDeque<Vec<u8>>,

    out_frames_app: Vec<Frame>,
    streams: HashMap<u64, StreamRecv>,
    /// Finished stream ID ranges, so an ID cannot be reopened.
    closed_recv_ranges: [Vec<(u64, u64)>; 4],
    reset_streams: Vec<(u64, u64)>,
    completed_streams: Vec<(u64, Vec<u8>)>,
    /// Sum of the highest offsets across streams, for flow control.
    recv_total_highest: u64,
    /// Held and not yet taken by the caller.
    recv_buffered: u64,
    local_max_data: u64,
    local_stream_max: HashMap<u64, u64>,
    local_max_streams_bidi: u64,
    local_max_streams_uni: u64,
    /// The stream limits the peer has been sent, which RFC 9000 holds it to. They trail the
    /// local ones while a MAX_STREAMS frame waits behind a full congestion window.
    sent_max_streams_bidi: u64,
    sent_max_streams_uni: u64,

    readable: Vec<(u64, Vec<u8>, bool)>,
    send_offsets: HashMap<u64, u64>,
    pending_stream_sends: VecDeque<PendingStreamSend>,
    sealed_send_ranges: [Vec<(u64, u64)>; 4],
    opened_send_ranges: [Vec<(u64, u64)>; 4],
    closed_send_ranges: [Vec<(u64, u64)>; 4],
    /// Streams the peer sent STOP_SENDING for.
    stopped_send_ranges: [Vec<(u64, u64)>; 4],
    send_total: u64,
    peer_max_data: u64,
    peer_stream_max: HashMap<u64, u64>,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,

    /// Remembered from the previous connection, for 0-RTT.
    early_peer_tp: Option<TransportParams>,
    next_uni: u64,

    retry_token: Vec<u8>,

    /// A second Retry would loop forever.
    retry_done: bool,

    /// Transport parameters are checked against this, not remote_cid: the peer may pick another ID
    /// in its first Initial after the Retry.
    retry_scid: Option<Vec<u8>>,

    /// Resent unchanged after a Retry.
    initial_crypto: Vec<u8>,

    now_ms: u64,

    last_activity_ms: u64,

    srtt_ms: u64,

    rttvar_ms: u64,

    have_rtt: bool,

    min_rtt_ms: u64,

    /// Taken with the smoothed RTT, so a sample inflated by load does not trigger early loss
    /// detection.
    latest_rtt_ms: u64,

    /// Consecutive PTO expirations; each doubles the next deadline.
    pto_count: u32,

    cwnd: u64,

    ssthresh: u64,

    bytes_in_flight: u64,

    /// Packets sent before it do not shrink the window again.
    recovery_start_ms: Option<u64>,

    app_send_secret: Vec<u8>,
    app_recv_secret: Vec<u8>,
    app_suite: u16,

    send_key_phase: bool,
    recv_key_phase: bool,

    /// Updating again right after an update would leave the peer behind.
    key_update_allowed: bool,

    /// Bound to the peer connection ID in use. RFC 9000 forbids recognizing a reset by a retired
    /// ID's token, so it changes along with the destination.
    peer_reset_token: Option<[u8; 16]>,

    reset_received: bool,

    idle_timed_out: bool,

    path_challenge_pending: Option<[u8; 8]>,

    path_validated: bool,

    early_send_keys: Option<(Aead, PacketKeys)>,

    early_recv_keys: Option<(Aead, PacketKeys)>,

    out_frames_early: Vec<Frame>,

    /// A copy, resent as 1-RTT if the peer rejects 0-RTT.
    early_backup: Vec<Frame>,

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
            peer_initial_scid: None,
            peer_cids: Vec::new(),
            peer_cid_in_use: 0,
            peer_retire_prior_to: 0,
            retiring_peer_cids: Vec::new(),
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_resumed: false,
            handshake_early_accepted: false,
            closed: !cid_valid,
            close_period: None,
            diagnostic: None,
            peer_close: None,
            peer_tp: None,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            out_datagrams: VecDeque::new(),
            out_frames_app: Vec::new(),
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
            sent_max_streams_bidi: local_max_streams_bidi,
            sent_max_streams_uni: local_max_streams_uni,
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
        let engine = ClientHandshake::new(cfg, local_tp.encode()).map_err(QuicError::Tls)?;
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
            peer_initial_scid: None,
            peer_cids: Vec::new(),
            peer_cid_in_use: 0,
            peer_retire_prior_to: 0,
            retiring_peer_cids: Vec::new(),
            handshake_complete: false,
            handshake_confirmed: false,
            handshake_resumed: false,
            handshake_early_accepted: false,
            closed: false,
            close_period: None,
            diagnostic: None,
            peer_close: None,
            peer_tp: None,
            alpn: None,
            client_authenticated: false,
            client_auth_identity: None,
            out_datagrams: VecDeque::new(),
            out_frames_app: Vec::new(),
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
            sent_max_streams_bidi: local_max_streams_bidi,
            sent_max_streams_uni: local_max_streams_uni,
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

    fn install_initial_keys(&mut self, dcid: &[u8]) {
        let (client_secret, server_secret) = initial_secrets(dcid);
        let (send, recv) = match self.role {
            Role::Server => (server_secret, client_secret),
            Role::Client => (client_secret, server_secret),
        };
        self.spaces[INITIAL].send_keys = Some((Aead::Aes128Gcm, derive_packet_keys(&send, 16)));
        self.spaces[INITIAL].recv_keys = Some((Aead::Aes128Gcm, derive_packet_keys(&recv, 16)));
    }

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

    /// Both generations are kept for a while, since packets under the old key can still arrive.
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

    pub fn set_peer_reset_token(&mut self, token: [u8; 16]) {
        self.peer_reset_token = Some(token);
    }

    pub fn reset_received(&self) -> bool {
        self.reset_received
    }

    /// Little is sent on an unvalidated path; otherwise a spoofed migration could point this side's
    /// traffic at someone else.
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

    pub fn path_validated(&self) -> bool {
        self.path_validated
    }

    /// The integrity tag is checked, and only one Retry is accepted per connection.
    fn handle_retry(&mut self, pkt: &[u8]) {
        if self.role != Role::Client || self.retry_done {
            return;
        }

        // RFC 9000 drops a Retry once any server Initial has been processed; accepting one even
        // after an Initial without a ServerHello would throw away all Initial state and start over.
        if self.peer_initial_scid.is_some() {
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

        // Under RFC 9002 a client that receives a Retry resets loss recovery and congestion
        // control. Packet numbers are the exception: RFC 9000 forbids reusing them in any space,
        // and 0-RTT keys survive a Retry, so reusing a number would protect different content with
        // the same nonce.
        let abandoned: u64 = self.spaces[INITIAL]
            .sent
            .iter()
            .chain(&self.spaces[APP].sent)
            .map(|sent| sent.size)
            .sum();
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(abandoned);
        self.pto_count = 0;
        self.spaces[INITIAL] = SpaceState {
            next_pn: self.spaces[INITIAL].next_pn,
            ..SpaceState::default()
        };
        // A server that sent a Retry dropped the 0-RTT it got. Before the server's Initial the
        // application space holds only 0-RTT packets, so their records are cleared and early frames
        // are resent from the start; left to loss detection, the application PTO would arm only
        // after the handshake is confirmed.
        self.spaces[APP].sent.clear();
        self.spaces[APP].rtx.clear();
        self.spaces[APP].loss_time_ms = None;
        self.out_frames_early = self.early_backup.clone();

        self.install_initial_keys(&scid);
        self.spaces[INITIAL].out_crypto = self.initial_crypto.clone();
        self.retry_done = true;
        self.flush();
    }

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
                        let initial_scid_valid = tp.initial_source_connection_id.is_some()
                            && tp.initial_source_connection_id == self.peer_initial_scid;
                        // RFC 9000 lets only a server send a preferred address, and not a server
                        // using a zero-length connection ID.
                        let preferred_address_valid = tp.preferred_address.is_none()
                            || (self.role == Role::Client
                                && tp
                                    .initial_source_connection_id
                                    .as_ref()
                                    .is_some_and(|scid| !scid.is_empty()));
                        let cid_valid = initial_scid_valid
                            && preferred_address_valid
                            && match self.role {
                                Role::Client => {
                                    tp.original_destination_connection_id.as_deref()
                                        == Some(self.initial_dcid.as_slice())
                                        && match &self.retry_scid {
                                            Some(expected) => {
                                                tp.retry_source_connection_id.as_deref()
                                                    == Some(expected.as_slice())
                                            }
                                            None => tp.retry_source_connection_id.is_none(),
                                        }
                                }
                                Role::Server => {
                                    tp.original_destination_connection_id.is_none()
                                        && tp.retry_source_connection_id.is_none()
                                        && tp.stateless_reset_token.is_none()
                                }
                            };
                        if !cid_valid {
                            self.note_diagnostic(QuicDiagnostic::TransportParameters);
                            self.close_on_error(
                                TRANSPORT_PARAMETER_ERROR,
                                QuicDiagnostic::TransportParameters,
                            );
                            return;
                        }
                        self.peer_max_data = tp.initial_max_data;
                        self.peer_max_streams_bidi = tp.initial_max_streams_bidi;
                        self.peer_max_streams_uni = tp.initial_max_streams_uni;
                        self.peer_reset_token = tp.stateless_reset_token;
                        self.peer_cids = vec![PeerCid {
                            sequence: 0,
                            cid: self.remote_cid.clone(),
                            reset_token: tp.stateless_reset_token,
                        }];
                        if let Some(address) = &tp.preferred_address {
                            self.peer_cids.push(PeerCid {
                                sequence: 1,
                                cid: address.cid.clone(),
                                reset_token: Some(address.reset_token),
                            });
                        }
                        self.peer_tp = Some(tp);
                    }
                    None => {
                        self.note_diagnostic(QuicDiagnostic::TransportParameters);
                        self.close_on_error(
                            TRANSPORT_PARAMETER_ERROR,
                            QuicDiagnostic::TransportParameters,
                        );
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
                // Under RFC 9001 a server's handshake is confirmed when it completes; the client's
                // is confirmed when it receives this HANDSHAKE_DONE.
                self.handshake_confirmed = true;
                self.out_frames_app.push(Frame::HandshakeDone);
                // A QUIC server does not use TLS KeyUpdate, and the output, including
                // NewSessionTicket, and the handshake result have been moved out above. There is no
                // reason to keep a state machine holding the transcript, the ClientHello, and mTLS
                // certificates for the connection's idle lifetime.
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

    /// Tls when TLS refuses the data. The server drops its state machine once the handshake ends,
    /// so handshake data after that is an unexpected message.
    ///
    /// Frame when bytes of the same level remain after a message that changes the receive level,
    /// the PROTOCOL_VIOLATION of RFC 9001. Checked here because the server drops its state machine
    /// in pump_tls.
    fn tls_provide(&mut self, level: Level, data: &[u8]) -> Result<(), QuicError> {
        let provided = match self.role {
            Role::Server => self.tls_server.as_mut().map(|e| e.provide(level, data)),
            Role::Client => self.tls_client.as_mut().map(|e| e.provide(level, data)),
        };
        provided
            .unwrap_or(Err(TlsError::UnexpectedMessage))
            .map_err(QuicError::Tls)?;
        if self.tls_receive_level() != level && self.tls_has_unconsumed_input() {
            return Err(QuicError::Frame);
        }
        self.pump_tls();
        Ok(())
    }

    fn has_tls_engine(&self) -> bool {
        match self.role {
            Role::Server => self.tls_server.is_some(),
            Role::Client => self.tls_client.is_some(),
        }
    }

    /// The server creates its TLS state machine at the first Initial and drops it when the
    /// handshake ends: before that it waits for a ClientHello, after it sits at the application
    /// level.
    fn tls_receive_level(&self) -> Level {
        match self.role {
            Role::Server => match &self.tls_server {
                Some(engine) => engine.receive_level(),
                None if self.handshake_complete => Level::Application,
                None => Level::Initial,
            },
            Role::Client => self
                .tls_client
                .as_ref()
                .map_or(Level::Application, ClientHandshake::receive_level),
        }
    }

    fn tls_has_unconsumed_input(&self) -> bool {
        match self.role {
            Role::Server => self
                .tls_server
                .as_ref()
                .is_some_and(ServerHandshake::has_unconsumed_input),
            Role::Client => self
                .tls_client
                .as_ref()
                .is_some_and(ClientHandshake::has_unconsumed_input),
        }
    }

    /// Routes CRYPTO data by the level rules of RFC 9001: data at TLS's current level is ordered
    /// and passed on, data at a higher level waits until TLS reaches it, and data at a past level
    /// is accepted only as a retransmission. A server that finished the handshake has dropped TLS,
    /// so a handshake message from the client is unexpected.
    ///
    /// Frame when past-level data goes beyond what was received; CryptoBufferExceeded when buffered
    /// data exceeds the limit.
    fn on_crypto(&mut self, space: usize, offset: u64, data: Vec<u8>) -> Result<(), QuicError> {
        if data.is_empty() {
            return Ok(());
        }
        let current = level_space(self.tls_receive_level());
        if space < current {
            let end = offset.saturating_add(data.len() as u64);
            if end > self.spaces[space].crypto_asm.recv_offset {
                return Err(QuicError::Frame);
            }
            return Ok(());
        }
        if space == current && !self.has_tls_engine() {
            return Err(QuicError::Tls(TlsError::UnexpectedMessage));
        }
        let state = &mut self.spaces[space];
        let contiguous = state
            .crypto_asm
            .push(offset, data, MAX_CRYPTO_REASSEMBLY)
            .map_err(|error| match error {
                QuicError::FlowControl => QuicError::CryptoBufferExceeded,
                other => other,
            })?;
        state.crypto_ready.extend_from_slice(&contiguous);
        self.deliver_crypto()
    }

    /// When TLS moves up a level, the data buffered for that level follows. A piece with a gap
    /// before it, left at a level TLS has left, can never be processed: the PROTOCOL_VIOLATION of
    /// RFC 9001.
    fn deliver_crypto(&mut self) -> Result<(), QuicError> {
        while !self.closed {
            let level = self.tls_receive_level();
            let space = level_space(level);
            if self.spaces[space].crypto_ready.is_empty() {
                break;
            }
            let ready = std::mem::take(&mut self.spaces[space].crypto_ready);
            self.tls_provide(level, &ready)?;
            if self.tls_receive_level() == level {
                break;
            }
            if self.spaces[space].crypto_asm.has_pending() {
                return Err(QuicError::Frame);
            }
        }
        Ok(())
    }

    /// Keeps only the first; later ones are usually its fallout.
    fn note_diagnostic(&mut self, diagnostic: QuicDiagnostic) {
        if self.diagnostic.is_none() {
            self.diagnostic = Some(diagnostic);
        }
    }

    fn decode_peer_transport_params(&mut self, raw: &[u8]) -> Option<TransportParams> {
        let decoded = TransportParams::decode(raw);
        if decoded.is_none() {
            self.note_diagnostic(QuicDiagnostic::TransportParameters);
        }
        decoded
    }

    pub fn take_diagnostic(&mut self) -> Option<QuicDiagnostic> {
        self.diagnostic.take()
    }

    /// When a connection error is returned, the close frame for it is already queued and the
    /// connection closed: RFC 9000 has connection errors reported with CONNECTION_CLOSE, so the
    /// caller still sends the queued datagrams. A closed connection does not decrypt packets;
    /// during the closing period it only decides whether to resend the close datagram.
    pub fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        if self.closed {
            self.answer_while_closing(dg.len());
            return Ok(());
        }
        let received = self.recv_packets(dg);
        if let Err(error) = &received {
            self.close_on_error(error.transport_code(), error);
        }
        received
    }

    fn answer_while_closing(&mut self, len: usize) {
        if let Some(datagram) = self
            .close_period
            .as_mut()
            .and_then(|period| period.answer(len))
        {
            self.out_datagrams.push_back(datagram);
        }
    }

    /// A datagram can carry several coalesced packets; each is processed by its consumed length.
    /// Once an earlier packet closes the connection, later packets' frames are not processed, since
    /// closing ends every stream; a later 1-RTT packet is read only for the close reason.
    ///
    /// The bytes are unauthenticated: lengths and IDs are all checked, and a packet that fails to
    /// decrypt is dropped silently, since an error would be a probing signal.
    fn recv_packets(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        if let Some(token) = self.peer_reset_token {
            if dg.len() >= 16 && ct_eq(&dg[dg.len() - 16..], &token) {
                self.reset_received = true;
                self.enter_draining();
                return Ok(());
            }
        }
        let mut pos = 0usize;
        while pos < dg.len() && !self.closed {
            let rest = &dg[pos..];
            let first = rest[0];
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                // A server does not process 1-RTT packets before its handshake completes, as RFC
                // 9001 requires. Acknowledging one would let the client consider the handshake
                // confirmed and drop its Handshake keys; if the client's Finished were then lost,
                // it would never be resent, and the server would stall without completing and with
                // no PTO on its responses. The client resends dropped packets after confirmation.
                if self.role == Role::Server && !self.handshake_complete {
                    break;
                }
                let Some((sp, phase_changed)) = self.unprotect_one_rtt(rest) else {
                    break;
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
                // An undecryptable packet is skipped by its length and the coalesced packets after
                // it are processed. A Handshake packet after one from the discarded Initial space
                // is common.
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

                if space == INITIAL {
                    // RFC 9000 sets the destination from the peer's first Initial only and drops
                    // later Initials with another source ID. Anyone who knows the destination ID
                    // can derive Initial keys, so switching on every Initial would let one forged
                    // packet redirect this side's traffic.
                    match &self.peer_initial_scid {
                        None => {
                            self.remote_cid = lp.scid.clone();
                            self.peer_initial_scid = Some(lp.scid.clone());
                        }
                        Some(first) if *first != lp.scid => continue,
                        Some(_) => {}
                    }
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
        if self.closed && pos < dg.len() {
            self.take_one_rtt_close(&dg[pos..]);
        }
        self.discard_finished_spaces();
        self.flush();
        Ok(())
    }

    /// Returns the packet and whether the peer changed keys; None without 1-RTT keys or on
    /// authentication failure.
    fn unprotect_one_rtt(&self, pkt: &[u8]) -> Option<(packet::ShortPacket, bool)> {
        let (aead, keys) = self.spaces[APP].recv_keys.as_ref()?;
        let largest = self.spaces[APP].largest_recv.unwrap_or(0);
        let alt = if self.key_update_allowed && !self.app_recv_secret.is_empty() {
            let (_, klen) = suite_aead(self.app_suite);
            let next = next_key_update_secret(&self.app_recv_secret);
            Some(derive_updated_kv(&next, klen, keys.hp.clone()))
        } else {
            None
        };
        packet::unprotect_short(
            *aead,
            keys,
            alt.as_ref(),
            self.recv_key_phase,
            pkt,
            self.local_cid.len(),
            largest,
        )
    }

    /// Before the handshake is confirmed, the closing side does not know which keys this side has
    /// and puts the same close in every space. RFC 9000 hides the application code and reason in
    /// the Initial and Handshake copies, so the real reason is only in the 1-RTT copy. The
    /// connection is already closed, so the packet's other frames are ignored.
    ///
    /// `rest` is the bytes after the packet that carried the close.
    fn take_one_rtt_close(&mut self, mut rest: &[u8]) {
        loop {
            let Some(&first) = rest.first() else {
                return;
            };
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    return;
                }
                break;
            }
            let Some(len) = packet::long_packet_len(rest) else {
                return;
            };
            rest = &rest[len..];
        }
        let Some((packet, _)) = self.unprotect_one_rtt(rest) else {
            return;
        };
        let close = frame::parse(&packet.payload)
            .into_iter()
            .flatten()
            .find_map(|f| match f {
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => Some(PeerClose {
                    error_code,
                    frame_type,
                    reason,
                }),
                _ => None,
            });
        if close.is_some() {
            self.peer_close = close;
        }
    }

    /// At the points RFC 9001 sets: a server drops Initial when it processes its first Handshake
    /// packet, and both sides drop Handshake once the handshake is confirmed. A client drops
    /// Initial when it sends its first Handshake packet, which flush handles.
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

    /// Its remaining packets will never be acknowledged or declared lost, so they leave bytes in
    /// flight and the PTO count resets. Otherwise retransmissions of a finished handshake would get
    /// ahead of the application PTO.
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
    fn process_packet(&mut self, space: usize, pn: u64, payload: &[u8]) -> Result<(), QuicError> {
        let kind = match space {
            INITIAL => PacketKind::Initial,
            HANDSHAKE => PacketKind::Handshake,
            _ => PacketKind::OneRtt,
        };
        self.process_packet_kind(space, pn, payload, kind)
    }

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
        let frames = frame::parse(payload).ok_or(QuicError::FrameEncoding)?;
        if frames.is_empty() {
            return Err(QuicError::Frame);
        }
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
                    self.on_crypto(space, offset, data)?;
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
                    // Everything except ACK, PADDING and CONNECTION_CLOSE elicits an
                    // acknowledgment. Ignoring a packet with only this frame would leave the
                    // server's packet unacknowledged forever and its PTO growing.
                    ack_eliciting = true;
                    self.handshake_confirmed = true;
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason,
                } => {
                    // An application close belongs only in the application space; RFC 9000 makes
                    // one in an Initial or Handshake packet a protocol violation.
                    if frame_type.is_none()
                        && matches!(kind, PacketKind::Initial | PacketKind::Handshake)
                    {
                        return Err(QuicError::Frame);
                    }
                    self.peer_close = Some(PeerClose {
                        error_code,
                        frame_type,
                        reason,
                    });
                    self.enter_draining();
                    break;
                }
                Frame::PathChallenge(data) => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.queue_superseding(Frame::PathResponse(data));
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
                    if uni {
                        self.peer_max_streams_uni = self.peer_max_streams_uni.max(max);
                    } else {
                        self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max);
                    }
                }
                Frame::StreamDataBlocked { id, .. } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    if !self.recv_stream_closed(id) {
                        self.recv_stream_properties(id)?;
                    }
                }
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    cid,
                    reset_token,
                } => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    ack_eliciting = true;
                    self.on_new_connection_id(sequence, retire_prior_to, cid, reset_token)?;
                }
                Frame::RetireConnectionId(_) => {
                    // This side issues only the handshake connection ID, and the peer sends every
                    // packet to it. Retiring sequence 0 names the destination of the packet
                    // carrying the request, a larger sequence was never issued, and a side that
                    // issued a zero-length ID cannot receive this frame. RFC 9000 allows
                    // PROTOCOL_VIOLATION for the first case and requires it for the other two.
                    return Err(QuicError::Frame);
                }
                Frame::Other(frame_type) => {
                    if matches!(kind, PacketKind::Initial | PacketKind::Handshake) {
                        return Err(QuicError::Frame);
                    }
                    if frame_type == frame::ftype::NEW_TOKEN
                        && (kind != PacketKind::OneRtt || self.role != Role::Client)
                    {
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

    /// Follows RFC 9000: a larger retire_prior_to retires earlier IDs before the new one is added,
    /// and if the ID in use was retired, the smallest remaining sequence takes over. An ID arriving
    /// late with an already retired sequence is not added, only retired. The same frame again, as a
    /// retransmission, is not an error.
    ///
    /// Frame when this side sends with a zero-length ID, or when the same sequence or ID comes with
    /// different content. ConnectionIdLimit when live IDs exceed the advertised limit or too many
    /// retirements are pending.
    fn on_new_connection_id(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: Vec<u8>,
        reset_token: [u8; 16],
    ) -> Result<(), QuicError> {
        if self.remote_cid.is_empty() {
            return Err(QuicError::Frame);
        }
        if let Some(known) = self
            .peer_cids
            .iter()
            .find(|known| known.sequence == sequence || known.cid == cid)
        {
            let repeated = known.sequence == sequence
                && known.cid == cid
                && known.reset_token == Some(reset_token);
            return if repeated {
                Ok(())
            } else {
                Err(QuicError::Frame)
            };
        }
        if sequence < self.peer_retire_prior_to {
            return self.retire_peer_cid(sequence);
        }
        if retire_prior_to > self.peer_retire_prior_to {
            self.peer_retire_prior_to = retire_prior_to;
            let mut retired = Vec::new();
            self.peer_cids.retain(|known| {
                let keep = known.sequence >= retire_prior_to;
                if !keep {
                    retired.push(known.sequence);
                }
                keep
            });
            for retired_sequence in retired {
                self.retire_peer_cid(retired_sequence)?;
            }
        }
        let index = self
            .peer_cids
            .partition_point(|known| known.sequence < sequence);
        self.peer_cids.insert(
            index,
            PeerCid {
                sequence,
                cid,
                reset_token: Some(reset_token),
            },
        );
        if self.peer_cid_in_use < self.peer_retire_prior_to {
            let next = &self.peer_cids[0];
            self.peer_cid_in_use = next.sequence;
            self.remote_cid = next.cid.clone();
            self.peer_reset_token = next.reset_token;
        }
        if self.peer_cids.len() as u64 > self.base_tp.active_connection_id_limit {
            return Err(QuicError::ConnectionIdLimit);
        }
        Ok(())
    }

    /// The sequence is remembered until the packet carrying the retirement is acknowledged, so the
    /// same notice is not queued again. RFC 9000 asks to handle unacknowledged retirements up to
    /// twice this side's limit and allows CONNECTION_ID_LIMIT_ERROR beyond that; without a cap, a
    /// peer that never acknowledges could keep issuing IDs and grow this side's notices without
    /// end.
    fn retire_peer_cid(&mut self, sequence: u64) -> Result<(), QuicError> {
        if self.retiring_peer_cids.contains(&sequence) {
            return Ok(());
        }
        let limit = self.base_tp.active_connection_id_limit.saturating_mul(2);
        if self.retiring_peer_cids.len() as u64 >= limit {
            return Err(QuicError::ConnectionIdLimit);
        }
        self.retiring_peer_cids.push(sequence);
        self.out_frames_app
            .push(Frame::RetireConnectionId(sequence));
        Ok(())
    }

    /// Returns the initial window.
    ///
    /// StreamLimit when the peer opened more streams than allowed; StreamState for a send-only
    /// stream of this side or one of this side's streams not yet opened.
    fn recv_stream_properties(&self, id: u64) -> Result<(bool, bool, u64), QuicError> {
        let peer_initiator = match self.role {
            Role::Server => 0u64,
            Role::Client => 1u64,
        };
        let initiated_by_peer = id & 0x01 == peer_initiator;
        let unidirectional = id & 0x02 != 0;

        if initiated_by_peer {
            self.check_peer_stream_limit(id)?;
        } else if unidirectional || !stream_range_contains(&self.opened_send_ranges, id) {
            return Err(QuicError::StreamState);
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

    fn check_peer_stream_limit(&self, id: u64) -> Result<(), QuicError> {
        let advertised = if id & 0x02 != 0 {
            self.sent_max_streams_uni
        } else {
            self.sent_max_streams_bidi
        };
        if id >> 2 >= advertised {
            return Err(QuicError::StreamLimit);
        }
        Ok(())
    }

    fn recv_stream_closed(&self, id: u64) -> bool {
        stream_range_contains(&self.closed_recv_ranges, id)
    }

    fn mark_recv_stream_closed(&mut self, id: u64) {
        mark_stream_range(&mut self.closed_recv_ranges, id);
    }

    fn ensure_recv_stream_credit(&mut self, id: u64, initial_limit: u64) {
        if self.local_stream_max.contains_key(&id) {
            return;
        }
        let target = initial_limit.max(MAX_STREAM_REASSEMBLY);
        self.local_stream_max.insert(id, target);
        if target > initial_limit {
            self.queue_superseding(Frame::MaxStreamData { id, max: target });
        }
    }

    /// Drops buffered data and settles flow control.
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
            return Err(QuicError::FinalSize);
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

    /// Drops pending sends and answers with RESET_STREAM, even for a peer stream that has carried
    /// no data yet.
    fn on_stop_sending(&mut self, id: u64, error_code: u64) -> Result<(), QuicError> {
        self.check_send_stream_frame(id)?;
        if stream_range_contains(&self.stopped_send_ranges, id)
            || stream_range_contains(&self.closed_send_ranges, id)
        {
            return Ok(());
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

    /// Whether STOP_SENDING or MAX_STREAM_DATA, which refer to this side's sending part, may arrive
    /// for this stream. Under RFC 9000 those frames can also open a peer's bidirectional stream, so
    /// for a peer stream with no data yet only the stream limit is checked.
    ///
    /// StreamState for a stream this side only receives on, or one of this side's streams not yet
    /// opened; StreamLimit for a peer stream above the limit.
    fn check_send_stream_frame(&self, id: u64) -> Result<(), QuicError> {
        let local_initiator = match self.role {
            Role::Client => 0u64,
            Role::Server => 1u64,
        };
        if id & 0x01 == local_initiator {
            if stream_range_contains(&self.opened_send_ranges, id) {
                return Ok(());
            }
            return Err(QuicError::StreamState);
        }
        if id & 0x02 != 0 {
            return Err(QuicError::StreamState);
        }
        self.check_peer_stream_limit(id)
    }

    /// Retries sends blocked on the window.
    fn on_max_stream_data(&mut self, id: u64, max: u64) -> Result<(), QuicError> {
        self.check_send_stream_frame(id)?;
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

    /// Data beyond the flow control window is a connection error; accepting it would make the
    /// advertised window meaningless.
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
                    return Err(QuicError::FinalSize);
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
                    return Err(QuicError::FinalSize);
                }
                if let Some(existing) = sr.fin_offset {
                    if existing != end {
                        return Err(QuicError::FinalSize);
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

    /// `probe` counts the probe packets left that may exceed the congestion window; one is used
    /// when this packet does.
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
        let budget = if space == INITIAL {
            initial_payload_budget(&self.retry_token)
        } else {
            MAX_PACKET_PAYLOAD
        };

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
                budget,
            );

            append_crypto_chunk(
                &mut self.spaces[space],
                &mut payload,
                &mut rtx_frames,
                &mut ack_eliciting,
                budget,
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
        let pkt = seal_padded(&mut payload, pad_to, |payload| {
            packet::protect_long(aead, &keys, ptype_val, &dcid, &scid, token, pn, 4, payload)
        });
        self.spaces[space].next_pn += 1;
        if ack_eliciting && !window_open {
            *probe = probe.saturating_sub(1);
        }
        self.track_sent(space, pn, ack_eliciting, pkt.len() as u64, rtx_frames);
        Some(pkt)
    }

    /// `probe` works as in build_long_packet.
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
        for frame in &rtx_frames {
            if let Frame::MaxStreams { uni, max } = *frame {
                let sent = if uni {
                    &mut self.sent_max_streams_uni
                } else {
                    &mut self.sent_max_streams_bidi
                };
                *sent = (*sent).max(max);
            }
        }
        self.track_sent(APP, pn, ack_eliciting, pkt.len() as u64, rtx_frames);
        Some(pkt)
    }

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
        let acked = ack_ranges(largest, first_range, ranges).ok_or(QuicError::FrameEncoding)?;
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
                for frame_value in &sp.frames {
                    if let Frame::RetireConnectionId(sequence) = frame_value {
                        self.retiring_peer_cids
                            .retain(|retiring| retiring != sequence);
                    }
                }
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
        // ACK-only packets are not tracked, so new packets can be acknowledged with no acknowledged
        // bytes; an advanced largest acknowledged number shows it. Skipping loss detection then
        // would leave packets lost before it to the PTO, whose interval doubles each time, even
        // while the peer keeps acknowledging.
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

    /// A packet is lost when it is far enough behind the largest acknowledged number, or was sent
    /// before it more than 9/8 RTT ago. For one not yet past the time threshold, that time goes
    /// into loss_time_ms so on_timeout decides then without a new ACK.
    fn detect_lost(&mut self, space: usize) {
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
        // Packets without frames still count in flight: PING-only ones, or those whose frames a PTO
        // already moved. Filtering by frames would never subtract their size, and the congestion
        // window would stay shut.
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

    /// Needs packets awaiting acknowledgment. The application space arms only after the handshake
    /// is confirmed; before that the peer may lack keys for those packets, or this side for the
    /// acknowledgments.
    fn pto_armed(&self, space: usize) -> bool {
        !self.spaces[space].sent.is_empty() && (space != APP || self.handshake_confirmed)
    }

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

    /// Queues this space's unacknowledged frames, oldest first, as many as the probes carry.
    /// Resending only the oldest packet would rotate through several unacknowledged packets one per
    /// PTO with the interval doubling each time, and data whose copies keep getting lost would
    /// never arrive; moving everything would resend the whole window on one lost tail. Loss
    /// detection handles the rest once a probe is acknowledged. The original packets stay for
    /// acknowledgment and RTT; only their frames move. With nothing to resend, a PING goes out.
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

    /// Runs loss detection and the PTO, and closes after the idle deadline. A closed connection
    /// only checks whether its closing or draining period has ended.
    ///
    /// False when closed or when no deadline is pending.
    pub fn on_timeout(&mut self, now_ms: u64) -> bool {
        self.now_ms = now_ms;
        if self.closed {
            if self
                .close_period
                .as_ref()
                .is_some_and(|period| period.is_over(now_ms))
            {
                self.close_period = None;
            }
            return false;
        }
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
        // RFC 9002 suggests probing every space awaiting acknowledgment, not just the one whose PTO
        // fired. With Initial and Handshake both pending during the handshake, one space's PTO then
        // cannot double the other's deadline.
        for space in [INITIAL, HANDSHAKE, APP] {
            if self.pto_armed(space) {
                self.queue_probe(space);
            }
        }
        self.pto_count = (self.pto_count + 1).min(8);
        self.flush_packets(PROBE_PACKETS);
        true
    }

    /// This state machine never reads a clock.
    pub fn set_now(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    pub fn srtt_ms(&self) -> u64 {
        self.srtt_ms
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Mutable payload bytes the connection holds in separate buffers, for the server listener's
    /// global budget. Fixed and count-based costs, such as the struct and map buckets, are covered
    /// by the listener's per-connection base charge.
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
            .saturating_add(self.peer_initial_scid.as_ref().map_or(0, Vec::capacity))
            .saturating_add(
                self.peer_cids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<PeerCid>()),
            )
            .saturating_add(self.peer_cids.iter().fold(0usize, |sum, known| {
                sum.saturating_add(known.cid.capacity())
            }))
            .saturating_add(
                self.retiring_peer_cids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<u64>()),
            )
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
            ))
            .saturating_add(
                self.close_period
                    .as_ref()
                    .map_or(0, ClosePeriod::retained_bytes),
            );

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
                .saturating_add(space.crypto_ready.capacity())
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

    /// Without the exponential backoff.
    pub fn base_pto_ms(&self) -> u64 {
        self.srtt_ms + (4 * self.rttvar_ms).max(1) + 25
    }

    /// Doubles with each consecutive PTO.
    fn pto_ms(&self) -> u64 {
        self.base_pto_ms()
            .saturating_mul(1u64 << self.pto_count.min(6))
    }

    /// The peer's reported ACK delay is subtracted.
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

    fn on_cc_ack(&mut self, acked: u64) {
        let mss = MAX_DATAGRAM as u64;
        if self.cwnd < self.ssthresh {
            self.cwnd += acked;
        } else {
            self.cwnd += (mss * acked / self.cwnd).max(1);
        }
    }

    fn on_cc_loss(&mut self) {
        let mss = MAX_DATAGRAM as u64;
        self.ssthresh = (self.cwnd / 2).max(2 * mss);
        self.cwnd = self.ssthresh;
    }

    fn can_send_new(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

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

    /// Also drops unsent handshake data.
    fn discard_send_output(&mut self) {
        self.out_datagrams.clear();
        self.discard_unsent_frames();
    }

    /// A closed connection sends nothing but the close datagram; kept, these would only hold the
    /// listener's memory budget through the closing period.
    fn discard_unsent_frames(&mut self) {
        self.out_frames_app.clear();
        self.out_frames_early.clear();
        self.early_backup.clear();
        self.pending_stream_sends.clear();
        self.send_offsets.clear();
        self.peer_stream_max.clear();
        for space in &mut self.spaces {
            space.rtx.clear();
            space.sent.clear();
            space.out_crypto.clear();
        }
        self.bytes_in_flight = 0;
    }

    fn flush(&mut self) {
        self.flush_packets(0);
    }

    /// `probe` is how many packets may exceed the congestion window; only PTO probes pass a nonzero
    /// value. A probe blocked by the window would stall recovery: the window opens only on
    /// acknowledgments, which come only after a probe goes out.
    fn flush_packets(&mut self, mut probe: u8) {
        if self.closed {
            return;
        }
        self.schedule_pending_stream_sends();
        // Short header, Initial, packet bytes.
        let mut packets: Vec<(bool, bool, Vec<u8>)> = Vec::new();

        // Packet numbers continue after a Retry, so the connection's first Initial and the first
        // one after a Retry are told apart by whether they carry the ClientHello from the start,
        // not by number.
        let pad = if self.role == Role::Client && self.spaces[INITIAL].send_crypto_offset == 0 {
            MIN_INITIAL_DATAGRAM
        } else {
            0
        };
        if let Some(p) = self.build_long_packet(INITIAL, pad, &mut probe) {
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
        // Under RFC 9001 a client drops Initial when it first sends a Handshake packet. Initial
        // packets already built still go in this datagram.
        if sent_handshake && self.role == Role::Client && !self.spaces[INITIAL].discarded {
            self.discard_space(INITIAL);
        }
        while let Some(p) = self.build_short_packet(&mut probe) {
            packets.push((true, false, p));
        }
        if packets.is_empty() {
            return;
        }

        // A short header packet has no length field and reads to the end of the datagram, so it
        // goes last and no padding can follow it. A datagram carrying an Initial therefore gets no
        // short header packet; that goes separately.
        let mut dg = Vec::new();
        let mut dg_has_initial = false;
        for (is_short, is_initial, p) in packets {
            let full = dg.len() + p.len() > MAX_DATAGRAM;
            if !dg.is_empty() && (full || (is_short && dg_has_initial)) {
                self.queue_datagram(std::mem::take(&mut dg), dg_has_initial);
                dg_has_initial = false;
            }
            dg.extend_from_slice(&p);
            dg_has_initial |= is_initial;
            if is_short {
                self.queue_datagram(std::mem::take(&mut dg), false);
            }
        }
        if !dg.is_empty() {
            self.queue_datagram(dg, dg_has_initial);
        }
    }

    /// Pads a datagram carrying an Initial to MIN_INITIAL_DATAGRAM. Padding goes only after long
    /// header packets; receivers drop those bytes, whose fixed bit is 0, as not a packet.
    fn queue_datagram(&mut self, mut dg: Vec<u8>, carries_initial: bool) {
        if carries_initial && dg.len() < MIN_INITIAL_DATAGRAM {
            dg.resize(MIN_INITIAL_DATAGRAM, 0);
        }
        self.out_datagrams.push_back(dg);
    }

    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        self.out_datagrams.pop_front()
    }

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
        // recv_datagram already sent the acknowledgments. The flow control update is not sent alone
        // here; it rides with the next response or query, avoiding an extra ack-eliciting packet.
        out
    }

    pub fn send_dns_message(&mut self, id: u64, dns: &[u8]) -> Result<(), QuicError> {
        self.send_dns_message_owned(id, dns.to_vec())
    }

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

    pub fn send_dns_messages(&mut self, id: u64, msgs: &[Vec<u8>]) -> Result<(), QuicError> {
        if msgs.len() != 1 {
            return Err(QuicError::Frame);
        }
        self.send_dns_message(id, &msgs[0])
    }

    /// Replaces a queued frame the new one supersedes: a newer limit of the same kind, or a newer
    /// PATH_RESPONSE on this connection's single path. While a peer withholds acknowledgments the
    /// queue does not drain, and appending would grow it with every frame the peer sends.
    fn queue_superseding(&mut self, frame: Frame) {
        let index = self
            .out_frames_app
            .iter()
            .position(|queued| match (queued, &frame) {
                (Frame::MaxData(_), Frame::MaxData(_))
                | (Frame::PathResponse(_), Frame::PathResponse(_)) => true,
                (Frame::MaxStreams { uni: a, .. }, Frame::MaxStreams { uni: b, .. }) => a == b,
                (Frame::MaxStreamData { id: a, .. }, Frame::MaxStreamData { id: b, .. }) => a == b,
                _ => false,
            });
        match index {
            Some(index) => self.out_frames_app[index] = frame,
            None => self.out_frames_app.push(frame),
        }
    }

    fn queue_app_frame(&mut self, f: Frame) {
        if !self.handshake_complete && self.early_send_keys.is_some() {
            self.early_backup.push(f.clone());
            self.out_frames_early.push(f);
        } else {
            self.out_frames_app.push(f);
        }
    }

    /// The peer then resets its sending part with RESET_STREAM. Data it sent before that still
    /// arrives, and the caller drops it. Not sent for a stream already fully received or reset.
    pub fn stop_sending(&mut self, id: u64, error_code: u64) {
        if self.closed || self.recv_stream_closed(id) {
            return;
        }
        self.queue_app_frame(Frame::StopSending { id, error_code });
        self.flush();
    }

    #[cfg(test)]
    /// This implementation never resets its own sending streams; tests use this to simulate a peer
    /// that does. The final size is the bytes queued on the stream so far.
    pub(crate) fn send_reset_stream_for_test(&mut self, id: u64, error_code: u64) {
        let final_size = self.send_offsets.get(&id).copied().unwrap_or(0);
        self.queue_app_frame(Frame::ResetStream {
            id,
            error_code,
            final_size,
        });
        self.flush();
    }

    fn buffered_stream_send_bytes(&self) -> usize {
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

    pub fn can_send_early(&self) -> bool {
        !self.handshake_complete && self.early_send_keys.is_some()
    }

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

    pub fn take_resets(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.reset_streams)
    }

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

    /// Sent only once enough has accumulated; updating on every read would send too many frames.
    fn replenish_connection_credit(&mut self, consumed: u64) {
        if consumed == 0 {
            return;
        }
        self.local_max_data = self
            .local_max_data
            .saturating_add(consumed)
            .min(MAX_FLOW_CONTROL);
        self.queue_superseding(Frame::MaxData(self.local_max_data));
    }

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
            self.queue_superseding(Frame::MaxStreamData { id, max: next });
        }
    }

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
            self.queue_superseding(Frame::MaxStreams {
                uni: true,
                max: self.local_max_streams_uni,
            });
        } else {
            self.local_max_streams_bidi = self
                .local_max_streams_bidi
                .saturating_add(1)
                .min(MAX_FLOW_CONTROL);
            self.queue_superseding(Frame::MaxStreams {
                uni: false,
                max: self.local_max_streams_bidi,
            });
        }
    }

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

    /// Queued when the window is short.
    pub fn send_stream(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), QuicError> {
        self.send_stream_owned(id, data.to_vec(), fin)
    }

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

    pub fn can_send_app(&self) -> bool {
        self.spaces[APP].send_keys.is_some()
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// A server confirms when the handshake completes, a client when it receives HANDSHAKE_DONE.
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Even after closing, the connection must receive late packets during the closing or draining
    /// period, which on_timeout ends. A caller closing the socket as well may drop it without
    /// waiting, as RFC 9000 allows, since late packets then have nowhere to arrive.
    pub fn is_terminated(&self) -> bool {
        self.closed && self.close_period.is_none()
    }

    /// Detaches only what the closing or draining period needs: resending the close to late packets
    /// and keeping the end time, which needs no keys or buffers. Lets a holder of many connections
    /// free a closed one's memory during the period. Datagrams not yet taken are dropped too.
    ///
    /// None for an open connection or when the period has ended.
    pub fn into_close_period(mut self) -> Option<ClosePeriod> {
        if !self.closed {
            return None;
        }
        self.close_period.take()
    }

    /// Closes first and tells the peer why; dropping state without a word would leave the peer
    /// waiting until its idle deadline. Sent as an application close with no frame type, so the
    /// application defines `error_code`; DoQ uses RFC 9250 values. `reason` may be empty.
    ///
    /// The code and reason go only in 1-RTT packets. Before the handshake is confirmed, the copies
    /// in Initial and Handshake packets carry APPLICATION_ERROR and an empty reason.
    pub fn close(&mut self, error_code: u64, reason: &str) {
        let application = Frame::ConnectionClose {
            error_code,
            frame_type: None,
            reason: close_reason(reason),
        };
        let concealed = Frame::ConnectionClose {
            error_code: APPLICATION_ERROR,
            frame_type: Some(0),
            reason: Vec::new(),
        };
        self.send_close(application, concealed);
    }

    /// For policy outside TLS validation, such as revocation checks. Closes like a TLS rejection:
    /// the certificate_unknown alert as CRYPTO_ERROR.
    pub fn reject_peer_certificate(&mut self, reason: &str) {
        let error = QuicError::Tls(TlsError::CertificateUnknown);
        self.close_on_error(error.transport_code(), reason);
    }

    /// Pending output is dropped first, since nothing else will be sent. The offending frame type
    /// is not tracked, so it sends 0, as RFC 9000 allows when it is unknown.
    fn close_on_error(&mut self, error_code: u64, reason: impl std::fmt::Display) {
        if self.closed {
            return;
        }
        self.discard_send_output();
        let close = Frame::ConnectionClose {
            error_code,
            frame_type: Some(0),
            reason: close_reason(&reason.to_string()),
        };
        self.send_close(close.clone(), close);
    }

    /// Datagrams already queued go before the close datagram; output not yet packetized is dropped,
    /// since an immediate close under RFC 9000 ends every stream. With no send keys at all there is
    /// no way to tell the peer, so the period starts with nothing to resend.
    ///
    /// `in_app` goes in 1-RTT packets, `in_handshake` in Initial and Handshake packets.
    fn send_close(&mut self, in_app: Frame, in_handshake: Frame) {
        if self.closed {
            return;
        }
        let datagram = self.build_close_datagram(&in_app, &in_handshake);
        self.discard_unsent_frames();
        let datagram = if datagram.is_empty() {
            None
        } else {
            self.out_datagrams.push_back(datagram.clone());
            Some(datagram)
        };
        self.enter_close_period(datagram);
    }

    /// After the peer closed or a stateless reset. RFC 9000 forbids sending anything in this
    /// period, so queued output is dropped.
    fn enter_draining(&mut self) {
        self.discard_send_output();
        self.enter_close_period(None);
    }

    fn enter_close_period(&mut self, datagram: Option<Vec<u8>>) {
        self.closed = true;
        self.close_period = Some(ClosePeriod {
            datagram,
            until_ms: self.close_period_end(),
            received: 0,
            received_bytes: 0,
            resent_bytes: 0,
        });
    }

    /// Three PTOs, as RFC 9000 suggests, measured without the exponential backoff: with it, a
    /// connection that failed repeatedly would hold a listener slot for minutes after closing.
    fn close_period_end(&self) -> u64 {
        self.now_ms
            .saturating_add(self.base_pto_ms().saturating_mul(3))
    }

    /// Before confirmation this side cannot know which keys the peer has, so one close goes in each
    /// space with send keys; after it, RFC 9000 has it only in 1-RTT. The same bytes are resent
    /// during the closing period, so no ACK frame goes in. A client must pad a datagram carrying an
    /// Initial, but a trailing 1-RTT packet reads to the datagram's end, so the padding goes inside
    /// the Initial packet.
    fn build_close_datagram(&mut self, in_app: &Frame, in_handshake: &Frame) -> Vec<u8> {
        let spaces: &[usize] = if self.handshake_confirmed {
            &[APP]
        } else {
            &[HANDSHAKE, APP]
        };
        let mut tail = Vec::new();
        for &space in spaces {
            let close = if space == APP { in_app } else { in_handshake };
            if let Some(packet) = self.build_close_packet(space, close, 0) {
                tail.extend_from_slice(&packet);
            }
        }
        if self.handshake_confirmed {
            return tail;
        }
        let pad_to = if self.role == Role::Client {
            MIN_INITIAL_DATAGRAM.saturating_sub(tail.len())
        } else {
            0
        };
        let Some(mut datagram) = self.build_close_packet(INITIAL, in_handshake, pad_to) else {
            return tail;
        };
        datagram.extend_from_slice(&tail);
        datagram
    }

    /// None without send keys. `pad_to` pads the packet with PADDING frames to that size.
    fn build_close_packet(
        &mut self,
        space: usize,
        close: &Frame,
        pad_to: usize,
    ) -> Option<Vec<u8>> {
        let (aead, keys) = self.spaces[space].send_keys.clone()?;
        let mut payload = Vec::new();
        frame::encode(&mut payload, close);
        let pn = self.spaces[space].next_pn;
        self.spaces[space].next_pn += 1;
        if space == APP {
            return Some(packet::protect_short(
                aead,
                &keys,
                &self.remote_cid,
                pn,
                4,
                &payload,
                self.send_key_phase,
            ));
        }
        let ptype_val = if space == INITIAL {
            ptype::INITIAL
        } else {
            ptype::HANDSHAKE
        };
        let token: &[u8] = if space == INITIAL {
            &self.retry_token
        } else {
            &[]
        };
        let dcid = &self.remote_cid;
        let scid = &self.local_cid;
        Some(seal_padded(&mut payload, pad_to, |payload| {
            packet::protect_long(aead, &keys, ptype_val, dcid, scid, token, pn, 4, payload)
        }))
    }

    pub fn peer_close(&self) -> Option<&PeerClose> {
        self.peer_close.as_ref()
    }

    /// A closed state comes not only from the peer's CONNECTION_CLOSE but also from a stateless
    /// reset, the idle deadline, or rejected peer transport parameters; without telling them apart,
    /// diagnostics would always blame the peer.
    ///
    /// None while open.
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

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn client_authenticated(&self) -> bool {
        self.client_authenticated
    }

    pub fn client_auth_identity(&self) -> Option<&str> {
        self.client_auth_identity.as_deref()
    }

    pub fn peer_transport_params(&self) -> Option<&TransportParams> {
        self.peer_tp.as_ref()
    }

    pub fn local_connection_id(&self) -> &[u8] {
        &self.local_cid
    }

    pub fn remote_connection_id(&self) -> &[u8] {
        &self.remote_cid
    }

    pub fn role(&self) -> Role {
        self.role
    }

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

    /// Rejected early data has to be resent.
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

    /// For resuming the next connection.
    pub fn take_new_sessions(&mut self) -> Vec<onetdns_tls::TlsSession> {
        self.tls_client
            .as_mut()
            .map(|e| e.take_sessions())
            .unwrap_or_default()
    }

    /// Empty on a server-side connection.
    pub fn verified_chain(&self) -> &[onetdns_tls::X509] {
        match self.tls_client.as_ref() {
            Some(e) => e.verified_chain(),
            None => &[],
        }
    }
}

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

fn verify_retry_integrity(odcid: &[u8], retry_pkt: &[u8]) -> bool {
    crate::retry::verify_integrity(odcid, retry_pkt)
}

/// Frame bytes for an Initial carrying this token; without the reduction, an Initial after a Retry
/// would exceed MAX_DATAGRAM.
fn initial_payload_budget(token: &[u8]) -> usize {
    let token_field = crate::varint::len(token.len() as u64) + token.len();
    MAX_DATAGRAM
        .saturating_sub(MAX_LONG_HEADER_OVERHEAD + token_field)
        .min(MAX_PACKET_PAYLOAD)
}

/// Protects a long header packet and, when it is below `pad_to`, pads the payload to fit. The
/// length field is written in its shortest form, so if padding makes it a byte longer the packet
/// would exceed `pad_to`; then it pads that much less.
///
/// `seal` takes a payload and returns the protected packet.
fn seal_padded(payload: &mut Vec<u8>, pad_to: usize, seal: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let packet = seal(payload);
    if packet.len() >= pad_to {
        return packet;
    }
    payload.resize(payload.len() + (pad_to - packet.len()), 0);
    let packet = seal(payload);
    if packet.len() <= pad_to {
        return packet;
    }
    payload.truncate(payload.len() - (packet.len() - pad_to));
    seal(payload)
}

/// Truncated to MAX_CLOSE_REASON bytes, never inside a UTF-8 character.
fn close_reason(reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(MAX_CLOSE_REASON);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason.as_bytes()[..end].to_vec()
}

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

/// PADDING, ACK and CONNECTION_CLOSE are not, per RFC 9002.
fn is_ack_eliciting(f: &Frame) -> bool {
    !matches!(
        f,
        Frame::Padding(_) | Frame::Ack { .. } | Frame::ConnectionClose { .. }
    )
}

/// Constant time, for reset tokens; a timing leak would reveal a token byte by byte.
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

/// ACK and PADDING are never resent.
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
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId(_)
            | Frame::PathChallenge(_)
    )
}

fn stream_range_contains(ranges: &[Vec<(u64, u64)>; 4], id: u64) -> bool {
    let number = id >> 2;
    ranges[(id & 0x03) as usize]
        .iter()
        .any(|&(low, high)| (low..=high).contains(&number))
}

/// Contiguous IDs merge into one range; an entry per ID would let a peer that opens many streams
/// drag memory along.
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

/// Expands ACK frame ranges into packet number ranges; None when malformed.
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

fn long_header_dcid(pkt: &[u8]) -> Option<Vec<u8>> {
    let dcid_len = *pkt.get(5)? as usize;
    pkt.get(6..6 + dcid_len).map(|s| s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_tls::ServerConfig;
    use p256::pkcs8::DecodePrivateKey;
    use std::sync::Arc;

    #[test]
    /// Advertising more would let the peer send datagrams that get truncated, fail authentication,
    /// and are dropped silently, stalling a handshake in progress.
    fn advertised_datagram_size_never_exceeds_the_buffer_we_read() {
        let asked = TransportParams {
            max_udp_payload_size: 65_527,
            ..TransportParams::server_defaults()
        };
        let normalized = normalize_local_transport_params(asked);
        assert_eq!(normalized.max_udp_payload_size, MAX_RECV_UDP_PAYLOAD);
    }

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
    /// Results read from outside must survive the release.
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
    /// Closing would give a probing signal.
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

        // A server that sent a Retry may pick another ID in its first Initial after it, and real
        // public servers do. A different value here catches checking both parameters against one
        // value.
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
    /// A mismatch starves the peer or overflows this side.
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
    fn reassembly_merges_consistent_overlaps_and_delivers_once() {
        let mut reasm = Reasm::default();
        assert!(reasm.push(3, b"def".to_vec(), 1024).unwrap().is_empty());
        assert_eq!(reasm.push(0, b"abcdef".to_vec(), 1024).unwrap(), b"abcdef");
        assert!(reasm.pending.is_empty());
        assert_eq!(reasm.pending_bytes, 0);
        assert_eq!(reasm.recv_offset, 6);
    }

    #[test]
    fn reassembly_rejects_conflicting_overlap_without_corrupting_state() {
        let mut reasm = Reasm::default();
        assert!(reasm.push(3, b"def".to_vec(), 1024).unwrap().is_empty());
        assert_eq!(reasm.push(4, b"XX".to_vec(), 1024), Err(QuicError::Frame));
        assert_eq!(reasm.push(0, b"abc".to_vec(), 1024).unwrap(), b"abcdef");
        assert!(reasm.pending.is_empty());
    }

    #[test]
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
    /// Acknowledging would let the client drop its Handshake keys; a lost client Finished would
    /// then never be resent and the connection would stall. The client resends dropped queries
    /// after confirmation.
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
    /// RFC 9000 requires datagrams carrying an Initial to be at least 1200 bytes, and a receiver
    /// may drop smaller ones, stalling the handshake without an error. The rule applies to the
    /// server's datagrams too.
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

    fn carries_initial(dg: &[u8]) -> bool {
        !dg.is_empty() && dg[0] & 0x80 != 0 && (dg[0] & 0x30) == 0x00
    }

    #[test]
    /// Without it the peer waits until its idle deadline. RFC 9250 has DoQ send CONNECTION_CLOSE on
    /// protocol violations, which needs a way to send it.
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

        // A second call sends nothing more.
        server.close(0x2, "again");
        assert!(server.next_datagram().is_none());
    }

    #[test]
    /// Under the same conditions as other frames, the close would go silent exactly when it
    /// matters: when the window is full because the peer got no replies, which is when the peer
    /// waits until its deadline.
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

        // Sets a full window directly: traffic would hit stream flow control before reaching this
        // condition.
        server.bytes_in_flight = server.cwnd;
        assert!(
            !server.can_send_new(),
            "윈도우를 채우지 못해 이 테스트가 재려던 것을 측정하지 못했습니다"
        );

        server.out_frames_app.push(Frame::Ping);
        server.spaces[APP].rtx.push(Frame::Ping);
        server.close(0x2, "closed while blocked");
        assert!(
            server.out_frames_app.is_empty() && server.spaces[APP].rtx.is_empty(),
            "닫은 연결이 다시는 보내지 못할 출력을 붙들고 있습니다"
        );
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
    /// Only a server may send one. A server that decided to close but still sent its handshake
    /// reply would hand its certificate chain to the rejected peer and spend what it may send
    /// before address validation. The close must be readable with the client's Initial keys.
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

        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        assert!(server.is_closed());
        let closing: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        let frames: Vec<Frame> = closing
            .iter()
            .flat_map(|dg| sent_frames(&server, dg))
            .collect();
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, Frame::ConnectionClose { .. })),
            "거부한 서버가 종료 프레임을 보내지 않았습니다"
        );
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, Frame::Crypto { .. })),
            "거부한 서버가 자기 핸드셰이크 응답까지 보냈습니다"
        );

        for dg in &closing {
            client.recv_datagram(dg).unwrap();
        }
        assert_eq!(
            client.peer_close(),
            Some(&PeerClose {
                error_code: TRANSPORT_PARAMETER_ERROR,
                frame_type: Some(0),
                reason: b"Peer QUIC transport parameters are invalid".to_vec(),
            })
        );
    }

    /// Stops at padding.
    fn packet_kinds(dg: &[u8]) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        let mut rest = dg;
        while let Some(&first) = rest.first() {
            if first & 0x40 == 0 {
                break;
            }
            if first & 0x80 == 0 {
                kinds.push("1-RTT");
                break;
            }
            kinds.push(match (first & 0x30) >> 4 {
                ptype::INITIAL => "Initial",
                ptype::HANDSHAKE => "Handshake",
                _ => "other",
            });
            let Some(len) = packet::long_packet_len(rest) else {
                break;
            };
            rest = &rest[len..];
        }
        kinds
    }

    /// Decrypts with the sender's keys and lists each packet's space and frames in order. A
    /// receiver stops reading a packet after CONNECTION_CLOSE, so what went out with the close
    /// shows only with the sender's keys.
    fn sent_packets(sender: &Connection, dg: &[u8]) -> Vec<(usize, Vec<Frame>)> {
        let mut packets = Vec::new();
        let mut rest = dg;
        while let Some(&first) = rest.first() {
            if first & 0x40 == 0 {
                break;
            }
            let (space, payload) = if first & 0x80 == 0 {
                let (aead, keys) = sender.spaces[APP]
                    .send_keys
                    .clone()
                    .expect("1-RTT 송신 키가 없습니다");
                let (pkt, _) = packet::unprotect_short(
                    aead,
                    &keys,
                    None,
                    sender.send_key_phase,
                    rest,
                    sender.remote_cid.len(),
                    0,
                )
                .expect("1-RTT 패킷을 풀지 못했습니다");
                rest = &[];
                (APP, pkt.payload)
            } else {
                let space = if (first & 0x30) >> 4 == ptype::INITIAL {
                    INITIAL
                } else {
                    HANDSHAKE
                };
                let len = packet::long_packet_len(rest).expect("긴 헤더 길이를 읽지 못했습니다");
                let (aead, keys) = sender.spaces[space]
                    .send_keys
                    .clone()
                    .expect("긴 헤더 송신 키가 없습니다");
                let pkt = packet::unprotect_long(aead, &keys, &rest[..len], 0)
                    .expect("긴 헤더 패킷을 풀지 못했습니다");
                rest = &rest[len..];
                (space, pkt.payload)
            };
            let frames = frame::parse(&payload).expect("프레임을 읽지 못했습니다");
            packets.push((space, frames));
        }
        packets
    }

    fn sent_frames(sender: &Connection, dg: &[u8]) -> Vec<Frame> {
        sent_packets(sender, dg)
            .into_iter()
            .flat_map(|(_, frames)| frames)
            .collect()
    }

    /// Assumes the sender sent in offset order and panics otherwise.
    fn sent_crypto(sender: &Connection, dgs: &[Vec<u8>]) -> [Vec<u8>; 2] {
        let mut streams = [Vec::new(), Vec::new()];
        for dg in dgs {
            for (space, frames) in sent_packets(sender, dg) {
                for frame in frames {
                    let Frame::Crypto { offset, data } = frame else {
                        continue;
                    };
                    let stream: &mut Vec<u8> = &mut streams[space];
                    assert_eq!(
                        offset,
                        stream.len() as u64,
                        "핸드셰이크 데이터의 순서가 어긋났습니다"
                    );
                    stream.extend_from_slice(&data);
                }
            }
        }
        streams
    }

    /// The sender's state machine never builds frames that break the rules, so raw bytes go in
    /// directly.
    fn forge_packet(sender: &mut Connection, space: usize, payload: &[u8]) -> Vec<u8> {
        let (aead, keys) = sender.spaces[space]
            .send_keys
            .clone()
            .expect("송신 키가 없습니다");
        let pn = sender.spaces[space].next_pn;
        sender.spaces[space].next_pn += 1;
        if space == APP {
            return packet::protect_short(
                aead,
                &keys,
                &sender.remote_cid,
                pn,
                4,
                payload,
                sender.send_key_phase,
            );
        }
        let ptype_val = if space == INITIAL {
            ptype::INITIAL
        } else {
            ptype::HANDSHAKE
        };
        packet::protect_long(
            aead,
            &keys,
            ptype_val,
            &sender.remote_cid,
            &sender.local_cid,
            &[],
            pn,
            4,
            payload,
        )
    }

    fn encode_frames(frames: &[Frame]) -> Vec<u8> {
        let mut payload = Vec::new();
        for frame in frames {
            frame::encode(&mut payload, frame);
        }
        payload
    }

    #[test]
    /// Dropping silently would leave the peer waiting until its idle deadline. RFC 9001 sends the
    /// TLS alert plus 0x100 in CONNECTION_CLOSE.
    fn tls_rejection_reaches_the_peer_as_a_crypto_error() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            ClientConfig {
                server_name: "other.example".to_string(),
                ..client_cfg(vec![b"doq".to_vec()])
            },
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        let mut rejected = None;
        while let Some(dg) = server.next_datagram() {
            if let Err(error) = client.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(rejected, Some(QuicError::Tls(TlsError::BadCert)));
        assert!(client.is_closed());

        let mut delivered = false;
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
            delivered = true;
        }
        assert!(delivered, "TLS 가 거부한 뒤 아무것도 내보내지 않았습니다");
        assert_eq!(
            server.peer_close(),
            Some(&PeerClose {
                error_code: CRYPTO_ERROR + 42,
                frame_type: Some(0),
                reason: b"TLS handshake failed: Invalid certificate or public key".to_vec(),
            })
        );
    }

    #[test]
    /// The server does not know which keys the client has, and the client drops its Initial keys
    /// after sending a Handshake packet, so a close only in Initial would never reach it. Other
    /// pending output must not go out with it.
    fn closing_before_confirmation_uses_every_space_with_keys() {
        let ca = rcgen::generate_simple_self_signed(vec!["client.example".to_string()]).unwrap();
        let mut cfg = (*server_cfg(vec![b"doq".to_vec()])).clone();
        cfg.client_ca = Some(onetdns_tls::TrustStore::from_ders([ca.cert.der().as_ref()]));
        let mut server = Connection::new_server(
            Arc::new(cfg),
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        assert!(
            client.spaces[INITIAL].discarded,
            "클라이언트가 Initial 키를 버리지 않아 이 테스트가 재려던 것을 측정하지 못했습니다"
        );

        let mut rejected = None;
        while let Some(dg) = client.next_datagram() {
            if let Err(error) = server.recv_datagram(&dg) {
                rejected = Some(error);
                break;
            }
        }
        assert_eq!(
            rejected,
            Some(QuicError::Tls(TlsError::CertificateRequired))
        );
        // Whether the server still has Initial keys depends on how many datagrams the client's
        // reply took, so the expectation comes from the keys the server actually holds.
        let expected: Vec<&str> = [
            (INITIAL, "Initial"),
            (HANDSHAKE, "Handshake"),
            (APP, "1-RTT"),
        ]
        .into_iter()
        .filter(|(space, _)| server.spaces[*space].send_keys.is_some())
        .map(|(_, kind)| kind)
        .collect();
        assert!(
            expected.contains(&"Handshake") && expected.contains(&"1-RTT"),
            "서버가 Handshake 와 1-RTT 키를 갖추지 않아 이 테스트가 재려던 것을 측정하지 못했습니다"
        );
        let closing: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        let kinds: Vec<&str> = closing.iter().flat_map(|dg| packet_kinds(dg)).collect();
        assert_eq!(kinds, expected);
        let stray: Vec<Frame> = closing
            .iter()
            .flat_map(|dg| sent_frames(&server, dg))
            .filter(|frame| {
                !matches!(
                    frame,
                    Frame::Ack { .. } | Frame::ConnectionClose { .. } | Frame::Padding(_)
                )
            })
            .collect();
        assert!(
            stray.is_empty(),
            "닫는 연결이 종료와 확인 말고 다른 프레임도 보냈습니다: {stray:?}"
        );

        for dg in &closing {
            client.recv_datagram(dg).unwrap();
        }
        assert_eq!(
            client.peer_close().map(|close| close.error_code),
            Some(CRYPTO_ERROR + 116)
        );
    }

    #[test]
    /// Initial packets travel before the peer is authenticated; RFC 9000 replaces an application
    /// close there with APPLICATION_ERROR and an empty reason. Staying silent for lack of 1-RTT
    /// keys would leave the peer waiting until its idle deadline.
    fn closing_before_the_handshake_conceals_the_application_reason() {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }

        client.close(0x2, "application detail");
        assert!(client.is_closed());
        let mut delivered = false;
        while let Some(dg) = client.next_datagram() {
            assert_eq!(packet_kinds(&dg), ["Initial"]);
            assert!(
                dg.len() >= MIN_INITIAL_DATAGRAM,
                "클라이언트가 Initial 종료를 {}바이트 데이터그램으로 보냈습니다",
                dg.len()
            );
            server.recv_datagram(&dg).unwrap();
            delivered = true;
        }
        assert!(delivered, "1-RTT 키가 없다고 종료를 알리지 않았습니다");
        assert_eq!(
            server.peer_close(),
            Some(&PeerClose {
                error_code: APPLICATION_ERROR,
                frame_type: Some(0),
                reason: Vec::new(),
            })
        );
    }

    #[test]
    /// A lost close datagram leaves the peer sending. RFC 9000's closing state answers such packets
    /// with the close, here only when the received count is a power of two.
    fn closing_endpoint_repeats_its_close_to_late_packets() {
        let (mut client, mut server) = established_doq_pair();
        server.close(0x2, "bye");
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");
        assert!(server.next_datagram().is_none());

        let late = vec![0x40; 100];
        let mut answered = Vec::new();
        for _ in 0..8 {
            server.recv_datagram(&late).unwrap();
            let replies: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
            assert!(
                replies.iter().all(|reply| *reply == close),
                "처음과 다른 데이터그램으로 답했습니다"
            );
            answered.push(replies.len());
        }
        assert_eq!(answered, [1, 1, 0, 1, 0, 0, 0, 1]);

        client.recv_datagram(&close).unwrap();
        assert_eq!(client.peer_close().map(|close| close.error_code), Some(0x2));
    }

    #[test]
    /// Replies are sent without decryption, so without the cap small spoofed packets could use the
    /// connection as an amplifier.
    fn closing_replies_stay_within_three_times_the_received_bytes() {
        let (_client, mut server) = established_doq_pair();
        server.close(0x2, "bye");
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");
        for _ in 0..3 {
            server.recv_datagram(&[0x40]).unwrap();
            assert!(
                server.next_datagram().is_none(),
                "받은 양의 세 배보다 많이 보냈습니다"
            );
        }
        server.recv_datagram(&vec![0x40; close.len()]).unwrap();
        assert_eq!(server.next_datagram(), Some(close));
    }

    #[test]
    /// RFC 9000's draining state; pending output goes too. Answering a close could make both sides
    /// answer each other's close forever.
    fn draining_endpoint_sends_nothing() {
        let (mut client, mut server) = established_doq_pair();
        server.close(0x2, "bye");
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");

        client.send_dns_message(0, b"\x00\x00 QUERY").unwrap();
        client.recv_datagram(&close).unwrap();
        assert!(client.is_closed() && !client.is_terminated());
        assert!(
            client.next_datagram().is_none(),
            "쌓여 있던 출력을 보냈습니다"
        );
        for _ in 0..4 {
            client.recv_datagram(&[0x40; 100]).unwrap();
            assert!(
                client.next_datagram().is_none(),
                "draining 상태에서 답했습니다"
            );
        }
    }

    #[test]
    /// During the period the connection must stay, so late packets are not taken for a new
    /// connection; after it, reporting it as droppable keeps closed connections from holding
    /// resources.
    fn close_period_ends_after_three_probe_timeouts() {
        let (mut client, mut server) = established_doq_pair();
        server.set_now(1_000);
        let closing = server.base_pto_ms() * 3;
        server.close(0x2, "bye");
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");
        assert!(!server.is_terminated());
        assert!(!server.on_timeout(1_000 + closing - 1));
        assert!(!server.is_terminated());
        assert!(!server.on_timeout(1_000 + closing));
        assert!(server.is_terminated());
        server.recv_datagram(&[0x40; 100]).unwrap();
        assert!(
            server.next_datagram().is_none(),
            "기간이 끝난 뒤에도 종료로 답했습니다"
        );

        client.set_now(1_000);
        let draining = client.base_pto_ms() * 3;
        client.recv_datagram(&close).unwrap();
        assert!(!client.is_terminated());
        client.on_timeout(1_000 + draining - 1);
        assert!(!client.is_terminated());
        client.on_timeout(1_000 + draining);
        assert!(client.is_terminated());
    }

    /// The client has finished the handshake; the server has not confirmed it. The server holds
    /// Handshake and 1-RTT keys and can coalesce both packets in one datagram, and the client can
    /// decrypt both. Returns the client and the server.
    fn unconfirmed_pair() -> (Connection, Connection) {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        assert!(
            client.is_handshake_complete()
                && client.spaces[HANDSHAKE].recv_keys.is_some()
                && server.spaces[HANDSHAKE].send_keys.is_some()
                && server.spaces[APP].send_keys.is_some(),
            "Handshake 와 1-RTT 패킷을 함께 주고받을 수 없어 이 테스트가 재려던 것을 측정하지 못했습니다"
        );
        (client, server)
    }

    #[test]
    /// Closing ends every stream, so stream data after it would hand a finished connection's data
    /// to the application. The close after it carries the real reason the Handshake copy hid.
    fn only_the_close_is_read_from_packets_coalesced_after_a_close() {
        let (mut client, mut server) = unconfirmed_pair();
        let concealed = Frame::ConnectionClose {
            error_code: APPLICATION_ERROR,
            frame_type: Some(0),
            reason: Vec::new(),
        };
        let mut datagram = forge_packet(&mut server, HANDSHAKE, &encode_frames(&[concealed]));
        datagram.extend(forge_packet(
            &mut server,
            APP,
            &encode_frames(&[
                Frame::Stream {
                    id: 1,
                    offset: 0,
                    fin: true,
                    data: b"\x00\x07 ANSWER".to_vec(),
                },
                Frame::ConnectionClose {
                    error_code: 0x2,
                    frame_type: None,
                    reason: b"detail".to_vec(),
                },
            ]),
        ));
        client.recv_datagram(&datagram).unwrap();

        assert!(client.is_closed());
        assert_eq!(
            client.peer_close(),
            Some(&PeerClose {
                error_code: 0x2,
                frame_type: None,
                reason: b"detail".to_vec(),
            })
        );
        assert!(
            client.take_stream_requests().is_empty(),
            "닫힌 뒤에 붙어 온 스트림 데이터를 받았습니다"
        );
    }

    #[test]
    /// The closing side puts the close in both Handshake and 1-RTT packets and hides the code and
    /// reason in the Handshake copy. Keeping only the Handshake copy, which decrypts first, would
    /// show every application reason as APPLICATION_ERROR.
    fn application_close_before_confirmation_keeps_its_reason() {
        let (mut client, mut server) = unconfirmed_pair();
        server.close(0x2, "application detail");
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");
        assert!(
            packet_kinds(&close).ends_with(&["Handshake", "1-RTT"]),
            "종료를 Handshake 와 1-RTT 패킷에 함께 싣지 않았습니다: {:?}",
            packet_kinds(&close)
        );
        client.recv_datagram(&close).unwrap();
        assert_eq!(
            client.peer_close(),
            Some(&PeerClose {
                error_code: 0x2,
                frame_type: None,
                reason: b"application detail".to_vec(),
            })
        );
    }

    #[test]
    /// RFC 9000 forbids an application close in those packets and has the receiver treat it as a
    /// protocol violation; a transport close is still accepted.
    fn application_close_in_handshake_packets_is_a_protocol_violation() {
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let application = encode_frames(&[Frame::ConnectionClose {
            error_code: 0x2,
            frame_type: None,
            reason: b"application".to_vec(),
        }]);
        assert_eq!(
            server.process_packet_kind(INITIAL, 0, &application, PacketKind::Initial),
            Err(QuicError::Frame)
        );
        assert_eq!(
            server.process_packet_kind(HANDSHAKE, 0, &application, PacketKind::Handshake),
            Err(QuicError::Frame)
        );
        assert!(server.peer_close().is_none());

        let transport = encode_frames(&[Frame::ConnectionClose {
            error_code: PROTOCOL_VIOLATION,
            frame_type: Some(0),
            reason: Vec::new(),
        }]);
        assert_eq!(
            server.process_packet_kind(HANDSHAKE, 1, &transport, PacketKind::Handshake),
            Ok(())
        );
        assert!(server.is_closed());
    }

    /// The transport error code the client gets when the server rejects this payload sent in a
    /// 1-RTT packet.
    fn transport_code_for(payload: &[u8]) -> u64 {
        let (mut client, mut server) = established_doq_pair();
        let datagram = forge_packet(&mut client, APP, payload);
        assert!(
            server.recv_datagram(&datagram).is_err(),
            "서버가 페이로드를 받아들였습니다"
        );
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let close = client.peer_close().expect("종료 사유가 오지 않았습니다");
        assert!(close.frame_type.is_some(), "전송 계층 종료여야 합니다");
        close.error_code
    }

    #[test]
    /// One code for everything would not tell the peer what it sent wrong.
    fn peer_errors_reach_the_peer_with_their_transport_codes() {
        let count_frame = |frame_type: u64, count: u64| {
            let mut payload = Vec::new();
            crate::varint::write(&mut payload, frame_type);
            crate::varint::write(&mut payload, count);
            payload
        };
        let cases = [
            ("빈 패킷", Vec::new(), PROTOCOL_VIOLATION),
            ("모르는 프레임 종류", vec![0x21], FRAME_ENCODING_ERROR),
            (
                "값이 잘린 프레임",
                vec![frame::ftype::MAX_DATA as u8],
                FRAME_ENCODING_ERROR,
            ),
            (
                "2^60 을 넘는 MAX_STREAMS",
                count_frame(frame::ftype::MAX_STREAMS_BIDI, frame::MAX_STREAM_COUNT + 1),
                FRAME_ENCODING_ERROR,
            ),
            (
                "2^60 을 넘는 STREAMS_BLOCKED",
                count_frame(
                    frame::ftype::STREAMS_BLOCKED_UNI,
                    frame::MAX_STREAM_COUNT + 1,
                ),
                FRAME_ENCODING_ERROR,
            ),
            (
                "열지 않은 서버 스트림의 데이터",
                encode_frames(&[Frame::Stream {
                    id: 1,
                    offset: 0,
                    fin: false,
                    data: vec![1],
                }]),
                STREAM_STATE_ERROR,
            ),
            (
                "받기만 하는 스트림의 STOP_SENDING",
                encode_frames(&[Frame::StopSending {
                    id: 2,
                    error_code: 0,
                }]),
                STREAM_STATE_ERROR,
            ),
            (
                "보내기만 하는 스트림의 STREAM_DATA_BLOCKED",
                encode_frames(&[Frame::StreamDataBlocked { id: 3, limit: 0 }]),
                STREAM_STATE_ERROR,
            ),
            (
                "최종 크기를 넘는 데이터",
                encode_frames(&[
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"abc".to_vec(),
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 3,
                        fin: false,
                        data: b"d".to_vec(),
                    },
                ]),
                FINAL_SIZE_ERROR,
            ),
            (
                "핸드셰이크를 마친 서버에 보낸 핸드셰이크 데이터",
                encode_frames(&[Frame::Crypto {
                    offset: 0,
                    data: vec![4, 0, 0, 0],
                }]),
                CRYPTO_ERROR + 10,
            ),
            (
                "핸드셰이크를 마친 서버에 순서가 어긋나게 보낸 핸드셰이크 데이터",
                encode_frames(&[Frame::Crypto {
                    offset: 4,
                    data: vec![0],
                }]),
                CRYPTO_ERROR + 10,
            ),
            (
                "이쪽 상한을 넘는 연결 식별자",
                encode_frames(&[new_cid(1, 0), new_cid(2, 0)]),
                CONNECTION_ID_LIMIT_ERROR,
            ),
            (
                "확인받지 못한 버림 알림이 상한의 두 배를 넘게 하는 식별자",
                encode_frames(
                    &(1..=5)
                        .map(|sequence| new_cid(sequence, sequence))
                        .collect::<Vec<_>>(),
                ),
                CONNECTION_ID_LIMIT_ERROR,
            ),
            (
                "같은 순번에 다른 식별자",
                encode_frames(&[
                    new_cid(1, 0),
                    Frame::NewConnectionId {
                        sequence: 1,
                        retire_prior_to: 0,
                        cid: issued_cid(9),
                        reset_token: issued_token(1),
                    },
                ]),
                PROTOCOL_VIOLATION,
            ),
            (
                "이쪽이 주지 않은 식별자의 RETIRE_CONNECTION_ID",
                encode_frames(&[Frame::RetireConnectionId(1)]),
                PROTOCOL_VIOLATION,
            ),
        ];
        for (case, payload, code) in cases {
            assert_eq!(transport_code_for(&payload), code, "{case}");
        }
    }

    #[test]
    fn handshake_data_beyond_the_reassembly_limit_is_reported() {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let far = encode_frames(&[Frame::Crypto {
            offset: MAX_CRYPTO_REASSEMBLY,
            data: vec![0],
        }]);
        let datagram = forge_packet(&mut client, HANDSHAKE, &far);
        assert_eq!(
            server.recv_datagram(&datagram),
            Err(QuicError::CryptoBufferExceeded)
        );
        while let Some(dg) = server.next_datagram() {
            let _ = client.recv_datagram(&dg);
        }
        assert_eq!(
            client.peer_close().map(|close| close.error_code),
            Some(CRYPTO_BUFFER_EXCEEDED)
        );
    }

    #[test]
    /// Data inside the received range is dropped. New data past its end comes after TLS left that
    /// level and cannot be processed: the PROTOCOL_VIOLATION of RFC 9001.
    fn handshake_data_at_a_finished_level_is_only_accepted_as_retransmission() {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        assert_eq!(server.tls_receive_level(), Level::Handshake);
        let received = server.spaces[INITIAL].crypto_asm.recv_offset;
        assert!(received > 0, "ClientHello 를 받지 못했습니다");

        let retransmission = encode_frames(&[Frame::Crypto {
            offset: 0,
            data: vec![0; received as usize],
        }]);
        assert_eq!(server.process_packet(INITIAL, 100, &retransmission), Ok(()));
        let beyond = encode_frames(&[Frame::Crypto {
            offset: received,
            data: vec![0],
        }]);
        assert_eq!(
            server.process_packet(INITIAL, 101, &beyond),
            Err(QuicError::Frame)
        );
    }

    #[test]
    /// Initial bytes after ServerHello cannot be processed once TLS has moved to the Handshake
    /// level; RFC 9001 makes this PROTOCOL_VIOLATION.
    fn bytes_left_behind_a_level_change_are_a_protocol_violation() {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        let flight: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        let [mut hello, _] = sent_crypto(&server, &flight);
        hello.extend_from_slice(&[8, 0]);

        assert_eq!(client.on_crypto(INITIAL, 0, hello), Err(QuicError::Frame));
    }

    #[test]
    /// RFC 9001 has such data kept until TLS reaches the level. Dropping it means waiting for a
    /// retransmission; passing it at the current level makes TLS reject it.
    fn handshake_data_ahead_of_the_tls_level_waits_for_it() {
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        let flight: Vec<Vec<u8>> = std::iter::from_fn(|| server.next_datagram()).collect();
        let [hello, handshake] = sent_crypto(&server, &flight);
        assert!(!hello.is_empty() && !handshake.is_empty());

        // Data goes in without packets, so update the peer IDs as receiving the server's Initial
        // would; otherwise the transport parameter ID check closes the connection.
        client.remote_cid = server.local_cid.clone();
        client.peer_initial_scid = Some(server.local_cid.clone());
        assert_eq!(client.on_crypto(HANDSHAKE, 0, handshake), Ok(()));
        assert_eq!(client.tls_receive_level(), Level::Initial);
        assert_eq!(client.on_crypto(INITIAL, 0, hello), Ok(()));
        assert!(
            client.is_handshake_complete() && !client.is_closed(),
            "모아 둔 Handshake 데이터가 TLS 로 넘어가지 않았습니다"
        );
    }

    #[test]
    /// A 1-RTT packet reads to the datagram's end, so no padding can follow it; it must go
    /// separately for the Initial datagram to be padded.
    fn initial_datagram_is_padded_when_one_rtt_data_is_ready() {
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
        client.send_dns_message(0, b"\x00\x00 QUERY").unwrap();
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let answer: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        let kinds: Vec<Vec<&str>> = answer.iter().map(|dg| packet_kinds(dg)).collect();
        assert!(
            kinds.iter().flatten().any(|kind| *kind == "Initial")
                && kinds.iter().flatten().any(|kind| *kind == "1-RTT"),
            "Initial 과 1-RTT 를 함께 보내지 않아 이 테스트가 재려던 것을 측정하지 못했습니다: {kinds:?}"
        );
        for (dg, kinds) in answer.iter().zip(&kinds) {
            if kinds.contains(&"Initial") {
                assert!(
                    dg.len() >= MIN_INITIAL_DATAGRAM && !kinds.contains(&"1-RTT"),
                    "Initial 을 담은 {}바이트 데이터그램: {kinds:?}",
                    dg.len()
                );
            }
        }

        for dg in &answer {
            server.recv_datagram(dg).unwrap();
        }
        assert!(server.is_handshake_complete());
    }

    #[test]
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
        assert_eq!(
            conn.on_ack(APP, 0, 0, 1, &[]),
            Err(QuicError::FrameEncoding)
        );
        assert_eq!(
            conn.on_ack(APP, 10, 0, 0, &[(9, 0)]),
            Err(QuicError::FrameEncoding)
        );
    }

    #[test]
    /// Accepting it would let the peer manipulate the RTT.
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
    /// Counting a close-only packet as awaiting acknowledgment would make a closing connection run
    /// loss recovery for acknowledgments that never come.
    fn only_padding_ack_and_close_do_not_elicit_acks() {
        let ack = Frame::Ack {
            largest: 0,
            delay: 0,
            first_range: 0,
            ranges: Vec::new(),
        };
        let close = Frame::ConnectionClose {
            error_code: 0,
            frame_type: Some(0),
            reason: Vec::new(),
        };
        assert!(!is_ack_eliciting(&Frame::Padding(1)));
        assert!(!is_ack_eliciting(&ack));
        assert!(!is_ack_eliciting(&close));
        assert!(is_ack_eliciting(&Frame::Ping));
        assert!(is_ack_eliciting(&Frame::HandshakeDone));
    }

    #[test]
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
    /// Breaking that would allow bypassing the handshake.
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
    /// Otherwise loss would make congestion worse.
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
    /// Otherwise empty requests alone could fill the queue.
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
    /// Returning credit twice would inflate the window.
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
    /// A fully received stream has nothing to refuse, and RFC 9000 says not to send STOP_SENDING on
    /// a stream that got RESET_STREAM.
    fn stop_sending_skips_streams_that_already_ended() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        conn.on_stream(0, 0, true, b"request".to_vec()).unwrap();
        conn.take_readable();
        conn.on_stream(4, 0, false, b"partial".to_vec()).unwrap();
        conn.on_reset_stream(4, 0x010c, 7).unwrap();
        conn.on_stream(8, 0, false, b"partial".to_vec()).unwrap();
        for id in [0, 4, 8] {
            conn.stop_sending(id, 0x010c);
        }
        let stopped: Vec<u64> = conn
            .out_frames_app
            .iter()
            .filter_map(|frame| match frame {
                Frame::StopSending { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(stopped, [8]);
    }

    #[test]
    /// These frames can also open a peer's bidirectional stream. STOP_SENDING is answered with
    /// RESET_STREAM.
    fn send_side_frames_follow_stream_direction_and_limits() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        assert_eq!(conn.on_stop_sending(0, 7), Ok(()));
        assert!(conn.out_frames_app.iter().any(|frame| matches!(
            frame,
            Frame::ResetStream {
                id: 0,
                error_code: 7,
                final_size: 0
            }
        )));
        assert_eq!(conn.on_max_stream_data(4, 2048), Ok(()));
        assert_eq!(conn.peer_stream_max.get(&4), Some(&2048));

        for id in [1, 2, 3] {
            assert_eq!(conn.on_stop_sending(id, 0), Err(QuicError::StreamState));
            assert_eq!(conn.on_max_stream_data(id, 10), Err(QuicError::StreamState));
        }
        let beyond = conn.local_max_streams_bidi << 2;
        assert_eq!(conn.on_stop_sending(beyond, 0), Err(QuicError::StreamLimit));
        assert_eq!(
            conn.on_max_stream_data(beyond, 10),
            Err(QuicError::StreamLimit)
        );
    }

    #[test]
    /// Stream ID spaces are split by role.
    fn peer_cannot_open_or_grant_credit_to_local_stream_ids() {
        let mut conn = Connection::new_server(
            server_cfg(vec![b"h3".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );

        assert_eq!(
            conn.on_stream(1, 0, false, b"forged".to_vec()),
            Err(QuicError::StreamState)
        );
        assert_eq!(conn.on_max_stream_data(1, 10), Err(QuicError::StreamState));
        assert_eq!(conn.on_max_stream_data(2, 10), Err(QuicError::StreamState));
        assert!(conn.streams.is_empty());
        assert!(conn.peer_stream_max.is_empty());
    }

    #[test]
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
    /// A lost update would leave the peer blocked for good.
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
    /// This side does no path MTU discovery, so RFC 9000 keeps it at 1200 bytes; the peer's
    /// max_udp_payload_size is what the peer can receive, not what the path carries. A Handshake
    /// packet in a datagram the path drops would be resent at the same size on every PTO and never
    /// arrive.
    fn coalesced_datagrams_stay_within_the_unprobed_path_limit() {
        // Uses the RFC 9000 value instead of MAX_DATAGRAM; tied to that constant, the test would
        // loosen along with it and miss the regression.
        let unprobed_path_limit = 1200;
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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while let Some(dg) = server.next_datagram() {
            client.recv_datagram(&dg).unwrap();
        }
        let advertised = client.peer_tp.as_ref().map(|tp| tp.max_udp_payload_size);
        assert!(
            advertised.is_some_and(|limit| limit > unprobed_path_limit as u64),
            "상대가 1200바이트보다 큰 크기를 알리지 않아 재려던 것을 재지 못했습니다: {advertised:?}"
        );
        while client.next_datagram().is_some() {}

        client.spaces[HANDSHAKE]
            .out_crypto
            .extend_from_slice(&[0; 250]);
        client.send_stream(0, &[0x5a; 900], true).unwrap();
        client.flush();
        let sizes: Vec<usize> = std::iter::from_fn(|| client.next_datagram())
            .map(|dg| dg.len())
            .collect();
        let total: usize = sizes.iter().sum();
        assert!(
            total > unprobed_path_limit && total as u64 <= MAX_RECV_UDP_PAYLOAD,
            "두 패킷을 합친 크기가 두 한도 사이에 있지 않아 재려던 것을 재지 못했습니다: {sizes:?}"
        );
        assert!(
            sizes.iter().all(|&size| size <= unprobed_path_limit),
            "1200바이트보다 큰 데이터그램을 보냈습니다: {sizes:?}"
        );
    }

    /// A client that received a Retry with the longest token. Returns the client and the token; the
    /// Initial resent after the Retry has not been taken yet.
    fn client_after_longest_retry() -> (Connection, Vec<u8>) {
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"ORIGDCID".to_vec(),
            b"CLNTSCID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let first = client.next_datagram().expect("첫 Initial 이 없습니다");
        let header = crate::retry::parse_initial_header(&first).expect("Initial 파싱");
        let token = vec![0xab; MAX_RETRY_TOKEN];
        let retry = crate::retry::build_retry(header.dcid, header.scid, b"RETRYCID", &token);
        client.recv_datagram(&retry).unwrap();
        (client, token)
    }

    #[test]
    /// The token rides in every Initial packet, so the frame room must shrink by that much;
    /// otherwise an Initial full of handshake data would exceed the limit.
    fn initial_with_the_longest_retry_token_fits_the_datagram_limit() {
        let (mut client, token) = client_after_longest_retry();
        client.spaces[INITIAL]
            .out_crypto
            .extend_from_slice(&[0; 2 * MAX_DATAGRAM]);
        // Each flush builds only one Initial packet.
        let mut datagrams = Vec::new();
        for _ in 0..8 {
            client.flush();
            datagrams.extend(std::iter::from_fn(|| client.next_datagram()));
        }
        assert!(
            datagrams.len() > 2,
            "Initial 이 여러 데이터그램으로 나뉘지 않아 재려던 것을 재지 못했습니다: {}",
            datagrams.len()
        );
        for datagram in &datagrams {
            let header = crate::retry::parse_initial_header(datagram).expect("Initial 파싱");
            assert_eq!(header.token, token.as_slice());
            assert!(
                datagram.len() <= MAX_DATAGRAM,
                "토큰을 실은 Initial 을 {}바이트 데이터그램으로 보냈습니다",
                datagram.len()
            );
        }
    }

    #[test]
    /// Before confirmation the same reason goes in each space with send keys, and the client's
    /// Initial also carries the Retry token, so an untruncated reason would exceed the limit.
    fn close_datagrams_stay_within_the_datagram_limit() {
        let long_reason = "x".repeat(4 * MAX_DATAGRAM);

        let (mut client, _) = client_after_longest_retry();
        while client.next_datagram().is_some() {}
        client.close_on_error(PROTOCOL_VIOLATION, &long_reason);
        let close = client.next_datagram().expect("종료 데이터그램이 없습니다");
        assert_eq!(packet_kinds(&close), ["Initial"]);
        assert!(
            (MIN_INITIAL_DATAGRAM..=MAX_DATAGRAM).contains(&close.len()),
            "클라이언트가 {}바이트 종료 데이터그램을 보냈습니다",
            close.len()
        );

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
        while let Some(dg) = client.next_datagram() {
            server.recv_datagram(&dg).unwrap();
        }
        while server.next_datagram().is_some() {}
        server.close_on_error(PROTOCOL_VIOLATION, &long_reason);
        let close = server.next_datagram().expect("종료 데이터그램이 없습니다");
        assert_eq!(packet_kinds(&close), ["Initial", "Handshake", "1-RTT"]);
        assert!(
            close.len() <= MAX_DATAGRAM,
            "서버가 {}바이트 종료 데이터그램을 보냈습니다",
            close.len()
        );
        client.recv_datagram(&close).unwrap();
        let reason = client.peer_close().map(|close| close.reason.clone());
        assert_eq!(reason, Some(vec![b'x'; MAX_CLOSE_REASON]));
    }

    #[test]
    /// When padding pushes the Initial's length value to 64 or more, the field grows by a byte;
    /// without padding that much less, the datagram would be 1201 bytes.
    fn short_client_close_is_padded_to_exactly_the_minimum() {
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        while client.next_datagram().is_some() {}
        client.close(0x2, "");
        let close = client.next_datagram().expect("종료 데이터그램이 없습니다");
        assert_eq!(close.len(), MIN_INITIAL_DATAGRAM);
    }

    #[test]
    /// The truncated reason must still be UTF-8.
    fn close_reason_is_cut_on_a_character_boundary() {
        let reason = "가".repeat(MAX_CLOSE_REASON);
        let cut = close_reason(&reason);
        assert!(cut.len() <= MAX_CLOSE_REASON && cut.len() > MAX_CLOSE_REASON - 3);
        assert!(std::str::from_utf8(&cut).is_ok());
        assert_eq!(close_reason("bye"), b"bye");
    }

    #[test]
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
        assert!(
            client.next_datagram().is_none() && !client.is_terminated(),
            "상태 없는 재설정을 받으면 아무것도 보내지 않는 draining 기간에 들어가야 합니다"
        );
    }

    #[test]
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
    /// Going below would make retransmission too eager.
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
    /// Reducing it more than once would be overly conservative.
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

    #[test]
    /// A peer that never acknowledges keeps the congestion window full, so nothing queued leaves.
    /// Each PATH_CHALLENGE must not add a PATH_RESPONSE to that queue; the newest one is enough.
    fn unacknowledged_path_challenges_queue_one_response() {
        let (mut client, mut server) = established_doq_pair();
        server.bytes_in_flight = server.cwnd;
        let mut newest = [0u8; 8];
        for round in 0..20u8 {
            let mut payload = Vec::new();
            for index in 0..100u8 {
                newest = [round, index, 0, 0, 0, 0, 0, 0];
                frame::encode(&mut payload, &Frame::PathChallenge(newest));
            }
            server
                .recv_datagram(&forge_packet(&mut client, APP, &payload))
                .unwrap();
            while server.next_datagram().is_some() {}
        }
        assert_eq!(
            server.out_frames_app.len(),
            1,
            "보내지 못한 PATH_RESPONSE 가 쌓였습니다"
        );
        assert_eq!(
            server.out_frames_app[0],
            Frame::PathResponse(newest),
            "가장 최근 도전에 답해야 합니다"
        );
    }

    #[test]
    /// RFC 9000 holds the peer to the stream limit this side has sent. Credit for closed streams
    /// still queued behind a full window does not count yet; otherwise a peer that never
    /// acknowledges could open and close streams without end, each leaving a frame queued.
    fn peer_streams_are_held_to_the_limit_actually_sent() {
        let (mut client, mut server) = established_doq_pair();
        let limit = TransportParams::server_defaults().initial_max_streams_bidi;
        let churn = |client: &mut Connection,
                     server: &mut Connection,
                     numbers: std::ops::Range<u64>|
         -> Result<(), QuicError> {
            for number in numbers {
                let id = number << 2;
                let mut payload = Vec::new();
                frame::encode(&mut payload, &Frame::StopSending { id, error_code: 0 });
                frame::encode(
                    &mut payload,
                    &Frame::ResetStream {
                        id,
                        error_code: 0,
                        final_size: 0,
                    },
                );
                server.recv_datagram(&forge_packet(client, APP, &payload))?;
                server.take_resets();
            }
            Ok(())
        };
        let max_streams_queued = |server: &Connection| {
            server
                .out_frames_app
                .iter()
                .filter(|frame| matches!(frame, Frame::MaxStreams { .. }))
                .count()
        };

        server.bytes_in_flight = server.cwnd;
        churn(&mut client, &mut server, 0..limit).unwrap();
        assert_eq!(
            max_streams_queued(&server),
            1,
            "새 스트림 한도는 가장 최근 것 하나만 기다려야 합니다"
        );

        server.bytes_in_flight = 0;
        server.flush();
        while server.next_datagram().is_some() {}
        assert_eq!(
            max_streams_queued(&server),
            0,
            "대조군이 무효입니다. 윈도우를 열었는데 새 스트림 한도를 보내지 않았습니다"
        );
        server.bytes_in_flight = server.cwnd;
        churn(&mut client, &mut server, limit..limit * 2)
            .expect("보낸 한도 안의 스트림을 거절했습니다");
        assert_eq!(
            churn(&mut client, &mut server, limit * 2..limit * 2 + 1),
            Err(QuicError::StreamLimit),
            "아직 보내지 않은 한도로 스트림을 열게 했습니다"
        );
    }

    /// Also relays the server's acknowledgment back to the client.
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
    /// Without an acknowledgment the server never gets that packet acknowledged: its PTO keeps
    /// doubling, and a response lost later goes unnoticed.
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
    /// ACK-only packets are not tracked, so this acknowledgment reports no bytes; skipping loss
    /// detection then would resend lost data only by PTO even while the peer keeps acknowledging.
    /// With ServerHello lost during the handshake, the client keeps resending its Initial and
    /// acknowledging the server's ACK, and a server waiting only on the PTO stalls.
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
    /// The server sent HANDSHAKE_DONE and the response separately and lost both. Carrying only the
    /// oldest packet per probe would send the response copy every other PTO with the interval
    /// doubling, and if those copies kept getting lost, a client that sends nothing would never get
    /// the response.
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
    /// Moving every unacknowledged frame would resend the whole window on one lost tail; the rest
    /// is resent by loss detection once a probe is acknowledged.
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
    /// The original packets stay for acknowledgment, so measuring from the oldest one's age would
    /// put the deadline in the past right after a probe and send probes on every PTO.
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
    /// A PTO leaves the original packets in flight. A probe blocked by the window would stall
    /// recovery: the window opens only on acknowledgments, which come only after a probe goes out.
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
    /// When a later packet is acknowledged but an earlier one has not reached the time threshold,
    /// it must be checked again at that time; deciding only on ACKs would wait for the PTO unless
    /// another ACK comes.
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
    /// Kept, retransmissions of the finished handshake would take the PTO ahead of application
    /// data, and keys and reassembly buffers would stay for the connection's lifetime.
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
    /// Even after the Initial space is dropped, the peer may coalesce an Initial with other
    /// packets; stopping at the first would lose the ones after it.
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
    /// Accepting a Retry after the Handshake keys are gone would restart the connection from the
    /// ClientHello. RFC 9000 drops a Retry once a server Initial has been processed.
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

    /// An Initial datagram, padded to the minimum, carrying only PING under this connection's
    /// Initial send keys.
    fn ping_initial(sender: &Connection, dcid: &[u8], scid: &[u8], pn: u64) -> Vec<u8> {
        let (aead, keys) = sender.spaces[INITIAL]
            .send_keys
            .clone()
            .expect("Initial 송신 키가 없습니다");
        let payload = encode_frames(&[Frame::Ping]);
        let mut datagram = packet::protect_long(
            aead,
            &keys,
            ptype::INITIAL,
            dcid,
            scid,
            &[],
            pn,
            4,
            &payload,
        );
        datagram.resize(MIN_INITIAL_DATAGRAM, 0);
        datagram
    }

    #[test]
    /// Anyone who knows the destination ID can derive Initial keys, so accepting it would let one
    /// forged packet redirect this side's traffic. A client that processed a server Initial must
    /// drop a Retry as well.
    fn later_initial_with_another_source_id_is_discarded() {
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
        let first = client.next_datagram().unwrap();
        server.recv_datagram(&first).unwrap();
        let largest = server.spaces[INITIAL].largest_recv;

        let forged = ping_initial(&client, b"INITDCID", b"OTHERCID", 5);
        server.recv_datagram(&forged).unwrap();
        assert_eq!(
            server.spaces[INITIAL].largest_recv, largest,
            "다른 출발지 식별자로 온 Initial 을 처리했습니다"
        );
        assert_eq!(server.remote_cid, b"CLIENTID");

        client
            .recv_datagram(&ping_initial(&server, b"CLIENTID", b"SERVERID", 10))
            .unwrap();
        assert_eq!(client.remote_cid, b"SERVERID");
        client
            .recv_datagram(&ping_initial(&server, b"CLIENTID", b"OTHERSID", 11))
            .unwrap();
        assert_eq!(
            client.remote_cid, b"SERVERID",
            "두 번째 서버 Initial 이 목적지를 바꿨습니다"
        );
        assert_eq!(client.spaces[INITIAL].largest_recv, Some(10));

        let retry = crate::retry::build_retry(b"INITDCID", b"CLIENTID", b"NEWSCID1", b"token");
        client.recv_datagram(&retry).unwrap();
        assert_eq!(
            client.remote_cid, b"SERVERID",
            "서버 Initial 을 처리한 뒤의 Retry 를 받아들였습니다"
        );
        assert!(client.retry_scid.is_none());
    }

    /// 8 bytes, distinct per sequence; the peer reads short headers with the same length.
    fn issued_cid(sequence: u64) -> Vec<u8> {
        let mut cid = b"PEERCID".to_vec();
        cid.push(sequence as u8);
        cid
    }

    fn issued_token(sequence: u64) -> [u8; 16] {
        [0x40 | sequence as u8; 16]
    }

    fn new_cid(sequence: u64, retire_prior_to: u64) -> Frame {
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            cid: issued_cid(sequence),
            reset_token: issued_token(sequence),
        }
    }

    fn deliver_frames(
        client: &mut Connection,
        server: &mut Connection,
        frames: &[Frame],
    ) -> Result<(), QuicError> {
        let datagram = forge_packet(client, APP, &encode_frames(frames));
        server.recv_datagram(&datagram)
    }

    fn peer_sequences(conn: &Connection) -> Vec<u64> {
        conn.peer_cids.iter().map(|known| known.sequence).collect()
    }

    #[test]
    /// RFC 9000 says to stop using such an ID and send RETIRE_CONNECTION_ID. Using it would send
    /// packets the peer no longer accepts, and a reset token is not checked against a retired ID.
    /// An ID arriving late with a retired sequence is retired at once.
    fn peer_connection_ids_are_retired_as_the_peer_asks() {
        let (mut client, mut server) = established_doq_pair();
        assert_eq!(peer_sequences(&server), [0]);

        deliver_frames(&mut client, &mut server, &[new_cid(1, 0)]).unwrap();
        deliver_frames(&mut client, &mut server, &[new_cid(1, 0)])
            .expect("재전송으로 다시 온 같은 프레임을 오류로 처리했습니다");
        assert_eq!(peer_sequences(&server), [0, 1]);
        assert_eq!(server.remote_cid, b"CLIENTID");
        while server.next_datagram().is_some() {}

        deliver_frames(&mut client, &mut server, &[new_cid(2, 2)]).unwrap();
        assert_eq!(peer_sequences(&server), [2]);
        assert_eq!(server.remote_cid, issued_cid(2));
        assert_eq!(server.peer_reset_token, Some(issued_token(2)));
        assert_eq!(server.retiring_peer_cids, [0, 1]);
        let mut announced: Vec<u64> = server.spaces[APP]
            .sent
            .iter()
            .flat_map(|packet| &packet.frames)
            .filter_map(|frame_value| match frame_value {
                Frame::RetireConnectionId(sequence) => Some(*sequence),
                _ => None,
            })
            .collect();
        announced.sort_unstable();
        assert_eq!(
            announced,
            [0, 1],
            "버린 식별자를 상대에게 알리지 않았습니다"
        );
        let datagram = server.next_datagram().expect("버림 알림 데이터그램");
        assert_eq!(
            &datagram[1..9],
            issued_cid(2).as_slice(),
            "버린 식별자로 계속 보냈습니다"
        );

        let largest = server.spaces[APP].next_pn - 1;
        let ack = Frame::Ack {
            largest,
            delay: 0,
            first_range: largest,
            ranges: Vec::new(),
        };
        deliver_frames(&mut client, &mut server, &[ack]).unwrap();
        assert!(server.retiring_peer_cids.is_empty());

        deliver_frames(&mut client, &mut server, &[new_cid(1, 0)]).unwrap();
        assert_eq!(peer_sequences(&server), [2]);
        assert_eq!(
            server.retiring_peer_cids,
            [1],
            "이미 버린 순번으로 온 식별자를 버린다고 알리지 않았습니다"
        );

        let mut stale = vec![0x40u8; 30];
        stale.extend_from_slice(&issued_token(1));
        server.recv_datagram(&stale).unwrap();
        assert!(
            !server.reset_received(),
            "버린 식별자의 토큰으로 재설정을 받아들였습니다"
        );
        let mut current = vec![0x40u8; 30];
        current.extend_from_slice(&issued_token(2));
        server.recv_datagram(&current).unwrap();
        assert!(server.reset_received());
    }

    #[test]
    /// NEW_CONNECTION_ID and PATH_CHALLENGE may travel in 0-RTT. RETIRE_CONNECTION_ID may not, and
    /// receiving it there may be treated as a protocol violation; none of them may appear in
    /// Initial or Handshake packets.
    fn zero_rtt_carries_connection_id_and_path_challenge_frames() {
        let (_client, mut server) = established_doq_pair();
        let allowed = encode_frames(&[Frame::PathChallenge([7; 8]), new_cid(1, 0)]);
        assert_eq!(
            server.process_packet_kind(APP, 100, &allowed, PacketKind::ZeroRtt),
            Ok(())
        );
        assert_eq!(peer_sequences(&server), [0, 1]);
        assert!(server.out_frames_app.contains(&Frame::PathResponse([7; 8])));

        let retire = encode_frames(&[Frame::RetireConnectionId(0)]);
        assert_eq!(
            server.process_packet_kind(APP, 101, &retire, PacketKind::ZeroRtt),
            Err(QuicError::Frame)
        );
        let handshake = encode_frames(&[new_cid(2, 0)]);
        assert_eq!(
            server.process_packet_kind(HANDSHAKE, 0, &handshake, PacketKind::Handshake),
            Err(QuicError::Frame)
        );
    }

    #[test]
    /// RFC 9000 requires PROTOCOL_VIOLATION when a sender using a zero-length destination ID
    /// receives this frame.
    fn new_connection_id_is_refused_by_a_zero_length_sender() {
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
        assert!(server.is_handshake_complete() && server.remote_cid.is_empty());
        assert_eq!(
            deliver_frames(&mut client, &mut server, &[new_cid(1, 0)]),
            Err(QuicError::Frame)
        );
    }

    fn preferred_address(cid: &[u8]) -> crate::params::PreferredAddress {
        crate::params::PreferredAddress {
            ipv4: "192.0.2.1:853".parse().unwrap(),
            ipv6: "[2001:db8::1]:853".parse().unwrap(),
            cid: cid.to_vec(),
            reset_token: [0x3c; 16],
        }
    }

    #[test]
    /// That ID is issued by the peer too and counts toward this side's limit; leaving it out would
    /// miss a server over the limit. Announcing the same ID again with NEW_CONNECTION_ID is not an
    /// error.
    fn preferred_address_connection_id_counts_as_sequence_one() {
        let mut tp = TransportParams::server_defaults();
        tp.preferred_address = Some(preferred_address(b"PREFERID"));
        let mut server =
            Connection::new_server(server_cfg(vec![b"doq".to_vec()]), b"SERVERID".to_vec(), tp);
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_handshake_confirmed());
        assert_eq!(peer_sequences(&client), [0, 1]);

        let repeated = Frame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            cid: b"PREFERID".to_vec(),
            reset_token: [0x3c; 16],
        };
        let datagram = forge_packet(&mut server, APP, &encode_frames(&[repeated]));
        client.recv_datagram(&datagram).unwrap();

        let datagram = forge_packet(&mut server, APP, &encode_frames(&[new_cid(2, 0)]));
        assert_eq!(
            client.recv_datagram(&datagram),
            Err(QuicError::ConnectionIdLimit)
        );
    }

    #[test]
    /// RFC 9000 lets only a server send a preferred address, and not one using a zero-length
    /// connection ID.
    fn misplaced_preferred_address_is_a_transport_parameter_error() {
        let mut client_tp = TransportParams::server_defaults();
        client_tp.preferred_address = Some(preferred_address(b"PREFERID"));
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            TransportParams::server_defaults(),
        );
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            client_tp,
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert_eq!(
            client.peer_close().map(|close| close.error_code),
            Some(TRANSPORT_PARAMETER_ERROR),
            "클라이언트가 보낸 선호 주소를 받아들였습니다"
        );

        let mut server_tp = TransportParams::server_defaults();
        server_tp.preferred_address = Some(preferred_address(b"PREFERID"));
        let mut server = Connection::new_server(
            server_cfg(vec![b"doq".to_vec()]),
            b"SERVERID".to_vec(),
            server_tp,
        );
        server.local_cid.clear();
        let mut client = Connection::new_client(
            client_cfg(vec![b"doq".to_vec()]),
            b"INITDCID".to_vec(),
            b"CLIENTID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert_eq!(
            server.peer_close().map(|close| close.error_code),
            Some(TRANSPORT_PARAMETER_ERROR),
            "길이 0 식별자를 고른 서버의 선호 주소를 받아들였습니다"
        );
    }

    #[test]
    /// The server sends such a client short header packets with no destination ID and checks
    /// initial_source_connection_id as zero length.
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
        assert!(
            conn.is_terminated(),
            "유휴 종료는 RFC 9000 대로 기다릴 기간 없이 상태를 버려야 합니다"
        );
        assert!(conn.next_datagram().is_none());
        assert!(conn.out_frames_app.is_empty());
        assert!(conn.pending_stream_sends.is_empty());
    }

    fn server_cfg_resumable(res: &onetdns_tls::conn::ServerResumption) -> Arc<ServerConfig> {
        let mut config = server_cfg(vec![b"doq".to_vec()]);
        Arc::make_mut(&mut config).resumption = Some(res.clone());
        config
    }

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
    /// RFC 9000 forbids rolling back packet numbers in any space after a Retry; 0-RTT keys survive
    /// a Retry, so a rollback would protect different content with the same nonce. A server that
    /// sent a Retry dropped its 0-RTT, so waiting for loss detection would delay the query by a
    /// PTO.
    fn retry_keeps_packet_numbers_and_resends_early_data() {
        use crate::retry::{build_retry, parse_initial_header, RetryKey};

        let mut res = onetdns_tls::conn::ServerResumption::secure_default();
        res.max_early_data = 0xffff_ffff;
        let mut cfg = client_cfg(vec![b"doq".to_vec()]);
        cfg.session = Some(obtain_session(&res));
        cfg.enable_early_data = true;
        let mut client = Connection::new_client(
            cfg,
            b"ORIGDCID".to_vec(),
            b"CLNTSCID".to_vec(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let query = b"\x00\x00 QUERY-BEFORE-RETRY";
        client.send_dns_message(0, query).unwrap();
        let first_flight: Vec<Vec<u8>> = std::iter::from_fn(|| client.next_datagram()).collect();
        let used = [client.spaces[INITIAL].next_pn, client.spaces[APP].next_pn];
        assert!(
            used.iter().all(|&next| next > 0),
            "Initial 과 0-RTT 를 모두 보내지 않아 재려던 것을 재지 못했습니다: {used:?}"
        );

        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let header = parse_initial_header(&first_flight[0]).expect("Initial 파싱");
        let retry_scid = b"RETRYCID".to_vec();
        let token = RetryKey::generate().issue(ip, header.dcid, &retry_scid, 1_000);
        let retry = build_retry(header.dcid, header.scid, &retry_scid, &token);
        client.recv_datagram(&retry).unwrap();

        let mut tp = TransportParams::server_defaults();
        tp.original_destination_connection_id = Some(b"ORIGDCID".to_vec());
        tp.retry_source_connection_id = Some(retry_scid);
        let mut server =
            Connection::new_server(server_cfg_resumable(&res), b"AFTERRTY".to_vec(), tp);
        for dg in std::iter::from_fn(|| client.next_datagram()) {
            if packet_kinds(&dg).contains(&"Initial") {
                assert_eq!(
                    dg.len(),
                    MIN_INITIAL_DATAGRAM,
                    "Retry 뒤 Initial 의 데이터그램 크기"
                );
            }
            server.recv_datagram(&dg).unwrap();
        }
        assert!(!server.is_handshake_complete());
        assert_eq!(
            server.take_stream_requests(),
            vec![(0, query.to_vec())],
            "Retry 앞에 보낸 0-RTT 질의를 곧바로 다시 보내지 않았습니다"
        );
        for (space, first_unused) in [INITIAL, APP].into_iter().zip(used) {
            let state = &server.spaces[space];
            // Bit i of recv_mask is packet largest_recv - i.
            let lowest = state.largest_recv.map(|largest| {
                largest - u64::from(u128::BITS - 1 - state.recv_mask.leading_zeros())
            });
            assert!(
                lowest.is_some_and(|pn| pn >= first_unused),
                "Retry 뒤에 {first_unused} 보다 작은 패킷 번호를 다시 썼습니다: {lowest:?}"
            );
        }

        pump(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert!(client.early_data_accepted() && server.early_data_accepted());
        assert!(
            server.take_stream_requests().is_empty(),
            "같은 질의가 두 번 전달됐습니다"
        );
    }

    #[test]
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
