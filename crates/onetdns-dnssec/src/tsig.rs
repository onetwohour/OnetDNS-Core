//! TSIG authenticates the DNS transaction with a shared key: where DNSSEC vouches for data, TSIG
//! binds the two parties exchanging messages. It is used for zone transfers, NOTIFY and dynamic
//! updates, where the peer must be identified. A response MAC covers the request MAC, so a response
//! cannot be detached and replayed.
//!
//! MAC comparison must be constant time: stopping at the first difference would reveal the correct
//! MAC byte by byte.

use std::borrow::Cow;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use onetdns_proto::wire::MAX_DNS_WIRE_LEN;
use onetdns_proto::{DnsClass, Message, Name, ProtoError, RData, Record, RecordType, Writer};

pub const TSIG_TYPE: u16 = 250;

/// The only algorithm accepted; weaker ones are refused outright.
pub const ALG_HMAC_SHA256: &str = "hmac-sha256";

pub const TSIG_ERROR_BADSIG: u16 = 16;

pub const TSIG_ERROR_BADKEY: u16 = 17;

pub const TSIG_ERROR_BADTIME: u16 = 18;

/// The peer chooses fudge, so trusting it would widen the replay window without bound. The MAC is
/// still checked with the peer's value; this cap applies to the time check.
const MAX_FUDGE_SECONDS: u16 = 300;

const ALG_HMAC_SHA256_WIRE: &[u8] = b"\x0bhmac-sha256\0";

#[derive(Clone)]
pub struct TsigKey {
    pub name: Name,
    /// Clones share one buffer, wiped by the last owner.
    secret: Arc<Zeroizing<Vec<u8>>>,
}

impl TsigKey {
    /// Shorter secrets come within reach of brute force.
    pub const MIN_SECRET_BYTES: usize = 16;

    /// `None` when the secret is shorter than `MIN_SECRET_BYTES`.
    pub fn new(name: Name, secret: Vec<u8>) -> Option<TsigKey> {
        let secret = Zeroizing::new(secret);
        if secret.len() < Self::MIN_SECRET_BYTES {
            return None;
        }
        Some(TsigKey {
            name,
            secret: Arc::new(secret),
        })
    }

    pub fn from_base64(name: &str, secret_b64: &str) -> Option<TsigKey> {
        Self::new(Name::from_str(name).ok()?, b64_decode(secret_b64)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsigError {
    Missing,

    BadKey,

    BadSig,

    BadTime,

    BadAlg,

    InvalidMessage,
}

/// Parsed but not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecordData {
    key_name: Name,
    algorithm: Name,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    /// Keeps the MAC valid when a forwarder changes the ID.
    original_id: u16,
    /// Nonzero when the peer reports a verification failure.
    error: u16,
    /// Carries the peer's time on BADTIME.
    other: Vec<u8>,
}

impl TsigRecordData {
    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    pub fn algorithm(&self) -> &Name {
        &self.algorithm
    }

    pub fn time_signed(&self) -> u64 {
        self.time_signed
    }

    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    pub fn original_id(&self) -> u16 {
        self.original_id
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn other(&self) -> &[u8] {
        &self.other
    }
}

/// A separate type from unverified data: a boolean carried around leaves room for a path that
/// forgets to check, while a type makes that a compile error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTsig(TsigRecordData);

impl VerifiedTsig {
    /// The chain input for signing the response.
    pub fn mac(&self) -> &[u8] {
        self.0.mac()
    }

    /// End of the replay window; callers must reject the same MAC until then.
    pub fn valid_until(&self) -> u64 {
        self.0.time_signed.saturating_add(u64::from(self.0.fudge))
    }
}

/// BADTIME still means the MAC matched, so the response can be signed and the peer learns our time
/// from it to resync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireVerification {
    Valid {
        /// The wire with the TSIG removed, used from here on.
        stripped: Vec<u8>,
        tsig: VerifiedTsig,
    },
    /// The MAC matches but the time is outside the window.
    BadTime {
        stripped: Vec<u8>,
        /// Needed to sign the response.
        tsig: VerifiedTsig,
    },
}

/// Errors returned unsigned: an unknown key or a wrong MAC means there is no shared secret to sign
/// with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsignedTsigError {
    BadSig,
    BadKey,
}

impl UnsignedTsigError {
    fn code(self) -> u16 {
        match self {
            Self::BadSig => TSIG_ERROR_BADSIG,
            Self::BadKey => TSIG_ERROR_BADKEY,
        }
    }
}

/// The key name is the record owner, so it is held separately.
struct TsigData {
    algorithm: Name,
    time_signed: u64,
    fudge: u16,
    mac: Vec<u8>,
    original_id: u16,
    error: u16,
    other: Vec<u8>,
}

/// `request_mac` is the request's MAC when signing a response; it forms the chain. Returns this
/// message's MAC for signing the next message.
pub fn sign_message(
    msg: &mut Message,
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, ProtoError> {
    let original_id = msg.header.id;
    sign_message_fields(msg, key, now, 300, 0, &[], request_mac, original_id)
}

/// Uses the request's original ID: a forwarder may change the ID, but the peer computes the MAC
/// with the ID it sent.
pub fn sign_response_message(
    msg: &mut Message,
    key: &TsigKey,
    now: u64,
    request: &VerifiedTsig,
) -> Result<Vec<u8>, ProtoError> {
    sign_message_fields(
        msg,
        key,
        now,
        300,
        0,
        &[],
        Some(request.0.mac()),
        request.0.original_id,
    )
}

/// Carries our time in the other data and reuses the request's time signed and fudge: the MAC of
/// this response verifies only inside the peer's window, and only then can the peer resync.
pub fn sign_badtime_response(
    msg: &mut Message,
    key: &TsigKey,
    request: &VerifiedTsig,
    server_now: u64,
) -> Result<Vec<u8>, ProtoError> {
    let other = time48(server_now);
    sign_message_fields(
        msg,
        key,
        request.0.time_signed,
        request.0.fudge,
        TSIG_ERROR_BADTIME,
        &other,
        Some(request.0.mac()),
        request.0.original_id,
    )
}

/// For an unknown key or a wrong MAC: with no shared secret there is no MAC, so an empty MAC
/// carries only the reason. Echoing the request's values lets the peer match the answer to its
/// request.
pub fn append_unsigned_error(
    msg: &mut Message,
    request: &TsigRecordData,
    error: UnsignedTsigError,
) {
    msg.additionals.push(tsig_record_fields(
        request.key_name.clone(),
        request.algorithm.clone(),
        request.time_signed,
        request.fudge,
        &[],
        request.original_id,
        error.code(),
        &[],
    ));
}

/// For the second and later messages of a multi-message transfer the MAC covers only the previous
/// MAC and the timers. The chain fixes the message order, so messages cannot be dropped or
/// reordered.
pub fn sign_subsequent(
    msg: &mut Message,
    key: &TsigKey,
    now: u64,
    prior_mac: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    let wire = msg.try_encode()?;
    let mac = compute_mac_timers(&wire, key, now, 300, prior_mac);
    msg.additionals
        .push(tsig_record(key, now, 300, &mac, msg.header.id, 0));
    Ok(mac)
}

/// Restores the ID to the request's original ID.
pub fn sign_response_subsequent(
    msg: &mut Message,
    key: &TsigKey,
    now: u64,
    prior_mac: &[u8],
    request: &VerifiedTsig,
) -> Result<Vec<u8>, ProtoError> {
    let mut wire = msg.try_encode()?;
    wire[0..2].copy_from_slice(&request.0.original_id.to_be_bytes());
    let mac = compute_mac_timers(&wire, key, now, 300, prior_mac);
    msg.additionals
        .push(tsig_record(key, now, 300, &mac, request.0.original_id, 0));
    Ok(mac)
}

/// For paths that do not rebuild the message: re-encoding can change name compression and break the
/// MAC the peer computes.
pub fn sign_wire(
    writer: &mut Writer,
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, ProtoError> {
    let mac = compute_mac(&writer.buf, key, now, 300, 0, &[], request_mac);
    let original_id = writer
        .buf
        .get(0..2)
        .map(|id| u16::from_be_bytes([id[0], id[1]]))
        .unwrap_or(0);
    append_tsig_wire(writer, key, now, 300, &mac, original_id, 0, &[])?;
    Ok(mac)
}

/// Swaps in the request's ID only for the MAC computation.
pub fn sign_response_wire(
    writer: &mut Writer,
    key: &TsigKey,
    now: u64,
    request: &VerifiedTsig,
) -> Result<Vec<u8>, ProtoError> {
    let digest_wire = original_id_wire(&writer.buf, request.0.original_id);
    let mac = compute_mac(&digest_wire, key, now, 300, 0, &[], Some(request.0.mac()));
    append_tsig_wire(writer, key, now, 300, &mac, request.0.original_id, 0, &[])?;
    Ok(mac)
}

pub fn sign_wire_subsequent(
    writer: &mut Writer,
    key: &TsigKey,
    now: u64,
    prior_mac: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    let mac = compute_mac_timers(&writer.buf, key, now, 300, prior_mac);
    let original_id = writer
        .buf
        .get(0..2)
        .map(|id| u16::from_be_bytes([id[0], id[1]]))
        .unwrap_or(0);
    append_tsig_wire(writer, key, now, 300, &mac, original_id, 0, &[])?;
    Ok(mac)
}

pub fn sign_response_wire_subsequent(
    writer: &mut Writer,
    key: &TsigKey,
    now: u64,
    prior_mac: &[u8],
    request: &VerifiedTsig,
) -> Result<Vec<u8>, ProtoError> {
    let digest_wire = original_id_wire(&writer.buf, request.0.original_id);
    let mac = compute_mac_timers(&digest_wire, key, now, 300, prior_mac);
    append_tsig_wire(writer, key, now, 300, &mac, request.0.original_id, 0, &[])?;
    Ok(mac)
}

/// Cuts the bytes before the TSIG as they are instead of parsing and re-encoding, which would
/// change name compression. After cutting, the ID goes back to the original ID and ARCOUNT drops by
/// one, so the bytes match what the peer signed. Returns the stripped wire and this message's MAC
/// for verifying the next one.
pub fn verify_wire_subsequent(
    wire: &[u8],
    key: &TsigKey,
    now: u64,
    prior_mac: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), TsigError> {
    let (tsig_off, owner, class, ttl, rdata) =
        scan_last_additional(wire).ok_or(TsigError::Missing)?;
    if class != DnsClass(255) || ttl != 0 {
        return Err(TsigError::InvalidMessage);
    }
    if !owner.eq_ignore_case(&key.name) {
        return Err(TsigError::BadKey);
    }
    let data =
        parse_tsig_rdata(&RData::Unknown(TSIG_TYPE, rdata)).ok_or(TsigError::InvalidMessage)?;
    validate_tsig_data(&data, wire[2] & 0x80 != 0)?;
    let alg = Name::from_str(ALG_HMAC_SHA256).map_err(|_| TsigError::BadAlg)?;
    if !data.algorithm.eq_ignore_case(&alg) {
        return Err(TsigError::BadAlg);
    }
    validate_hmac_sha256_mac(&data, wire[2] & 0x80 != 0)?;
    let mut digest_wire = wire[..tsig_off].to_vec();
    digest_wire[0..2].copy_from_slice(&data.original_id.to_be_bytes());
    let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_sub(1);
    digest_wire[10..12].copy_from_slice(&ar.to_be_bytes());
    let expect = compute_mac_timers(&digest_wire, key, data.time_signed, data.fudge, prior_mac);
    if !mac_matches(&expect, &data.mac) {
        return Err(TsigError::BadSig);
    }
    if data.fudge > MAX_FUDGE_SECONDS || now.abs_diff(data.time_signed) > u64::from(data.fudge) {
        return Err(TsigError::BadTime);
    }
    Ok((digest_wire, data.mac))
}

/// Checks class and TTL, key name, algorithm and RDATA consistency, then computes the MAC and
/// compares it in constant time. Time is judged only after the MAC matches: a peer that cannot
/// produce the MAC has no business learning our clock state. Returns the message with the TSIG
/// removed and the ID restored, and the MAC.
pub fn verify_message(
    msg: &Message,
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<(Message, Vec<u8>), TsigError> {
    let (pos, rec) = find_tsig(msg).ok_or(TsigError::Missing)?;
    if rec.class != DnsClass(255) || rec.ttl != 0 {
        return Err(TsigError::InvalidMessage);
    }
    if !rec.name.eq_ignore_case(&key.name) {
        return Err(TsigError::BadKey);
    }
    let data = parse_tsig_rdata(&rec.rdata).ok_or(TsigError::InvalidMessage)?;
    validate_tsig_data(&data, msg.header.response)?;
    let alg = Name::from_str(ALG_HMAC_SHA256).map_err(|_| TsigError::BadAlg)?;
    if !data.algorithm.eq_ignore_case(&alg) {
        return Err(TsigError::BadAlg);
    }
    validate_hmac_sha256_mac(&data, msg.header.response)?;

    let mut stripped = msg.clone();
    stripped.additionals.remove(pos);
    stripped.header.id = data.original_id;
    let wire = stripped
        .try_encode()
        .map_err(|_| TsigError::InvalidMessage)?;
    let expect = compute_mac(
        &wire,
        key,
        data.time_signed,
        data.fudge,
        data.error,
        &data.other,
        request_mac,
    );
    if !mac_matches(&expect, &data.mac) {
        return Err(TsigError::BadSig);
    }
    if data.fudge > MAX_FUDGE_SECONDS || now.abs_diff(data.time_signed) > u64::from(data.fudge) {
        return Err(TsigError::BadTime);
    }
    Ok((stripped, data.mac))
}

/// Succeeds only when the time is right too; BADTIME becomes an error.
pub fn verify_wire(
    wire: &[u8],
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), TsigError> {
    match verify_wire_detailed(wire, key, now, request_mac)? {
        WireVerification::Valid { stripped, tsig } => Ok((stripped, tsig.0.mac)),
        WireVerification::BadTime { .. } => Err(TsigError::BadTime),
    }
}

/// Reports a matching MAC with a bad time as BADTIME, so a signed BADTIME response can tell the
/// peer our time. Folding it into an error would leave a peer with a skewed clock unable to
/// recover.
pub fn verify_wire_detailed(
    wire: &[u8],
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<WireVerification, TsigError> {
    let (tsig_off, owner, class, ttl, rdata) =
        scan_last_additional(wire).ok_or(TsigError::Missing)?;
    if class != DnsClass(255) || ttl != 0 {
        return Err(TsigError::InvalidMessage);
    }
    if !owner.eq_ignore_case(&key.name) {
        return Err(TsigError::BadKey);
    }
    let data =
        parse_tsig_rdata(&RData::Unknown(TSIG_TYPE, rdata)).ok_or(TsigError::InvalidMessage)?;
    validate_tsig_data(&data, wire[2] & 0x80 != 0)?;
    let alg = Name::from_str(ALG_HMAC_SHA256).map_err(|_| TsigError::BadAlg)?;
    if !data.algorithm.eq_ignore_case(&alg) {
        return Err(TsigError::BadAlg);
    }
    validate_hmac_sha256_mac(&data, wire[2] & 0x80 != 0)?;

    let mut digest_wire = wire[..tsig_off].to_vec();
    digest_wire[0..2].copy_from_slice(&data.original_id.to_be_bytes());
    let ar = u16::from_be_bytes([wire[10], wire[11]]).saturating_sub(1);
    digest_wire[10..12].copy_from_slice(&ar.to_be_bytes());
    let expect = compute_mac(
        &digest_wire,
        key,
        data.time_signed,
        data.fudge,
        data.error,
        &data.other,
        request_mac,
    );
    if !mac_matches(&expect, &data.mac) {
        return Err(TsigError::BadSig);
    }
    let time_valid =
        data.fudge <= MAX_FUDGE_SECONDS && now.abs_diff(data.time_signed) <= u64::from(data.fudge);
    let tsig = VerifiedTsig(record_data(owner, data));
    if time_valid {
        Ok(WireVerification::Valid {
            stripped: digest_wire,
            tsig,
        })
    } else {
        Ok(WireVerification::BadTime {
            stripped: digest_wire,
            tsig,
        })
    }
}

/// Picks the key to verify with; does not verify.
pub fn peek_key_name(msg: &Message) -> Option<Name> {
    find_tsig(msg).map(|(_, r)| r.name.clone())
}

/// Also looks where the standard forbids a TSIG: treating a misplaced TSIG as absent would pass a
/// signed message as unsigned.
pub fn contains_tsig(msg: &Message) -> bool {
    msg.answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
        .any(|record| record.rtype.0 == TSIG_TYPE)
}

pub fn request_data(msg: &Message) -> Result<TsigRecordData, TsigError> {
    message_tsig_data(msg, false)
}

pub fn response_data(msg: &Message) -> Result<TsigRecordData, TsigError> {
    message_tsig_data(msg, true)
}

/// Rejects a QR bit that does not match `response`, so a request cannot be reflected as a response.
fn message_tsig_data(msg: &Message, response: bool) -> Result<TsigRecordData, TsigError> {
    if msg.header.response != response {
        return Err(TsigError::InvalidMessage);
    }
    let (_, record) = find_tsig(msg).ok_or(TsigError::Missing)?;
    if record.class != DnsClass(255) || record.ttl != 0 {
        return Err(TsigError::InvalidMessage);
    }
    let data = parse_tsig_rdata(&record.rdata).ok_or(TsigError::InvalidMessage)?;
    validate_tsig_data(&data, response)?;
    Ok(record_data(record.name.clone(), data))
}

fn record_data(key_name: Name, data: TsigData) -> TsigRecordData {
    TsigRecordData {
        key_name,
        algorithm: data.algorithm,
        time_signed: data.time_signed,
        fudge: data.fudge,
        mac: data.mac,
        original_id: data.original_id,
        error: data.error,
        other: data.other,
    }
}

/// A TSIG in the answer or authority section counts as absent; in the additional section there must
/// be exactly one, and it must be last. A free position would make the MAC coverage movable and let
/// an attacker choose which parts are signed.
fn find_tsig(msg: &Message) -> Option<(usize, &Record)> {
    if msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .any(|record| record.rtype.0 == TSIG_TYPE)
    {
        return None;
    }
    let mut records = msg
        .additionals
        .iter()
        .enumerate()
        .filter(|(_, record)| record.rtype.0 == TSIG_TYPE);
    let found = records.next()?;
    if records.next().is_some() || found.0 + 1 != msg.additionals.len() {
        return None;
    }
    Some(found)
}

/// Checks the length of every field and rejects trailing bytes: allowing them would give one TSIG
/// several byte forms, and the difference lies outside the MAC.
fn parse_tsig_rdata(rdata: &RData) -> Option<TsigData> {
    let raw = match rdata {
        RData::Unknown(t, raw) if *t == TSIG_TYPE => raw,
        _ => return None,
    };
    let (algorithm, mut i) = read_uncompressed_name(raw, 0)?;
    if raw.len() < i + 10 {
        return None;
    }
    let time_signed = (u64::from(raw[i]) << 40)
        | (u64::from(raw[i + 1]) << 32)
        | (u64::from(raw[i + 2]) << 24)
        | (u64::from(raw[i + 3]) << 16)
        | (u64::from(raw[i + 4]) << 8)
        | u64::from(raw[i + 5]);
    let fudge = u16::from_be_bytes([raw[i + 6], raw[i + 7]]);
    let mac_len = u16::from_be_bytes([raw[i + 8], raw[i + 9]]) as usize;
    i += 10;
    if raw.len() < i + mac_len + 6 {
        return None;
    }
    let mac = raw[i..i + mac_len].to_vec();
    i += mac_len;
    let original_id = u16::from_be_bytes([raw[i], raw[i + 1]]);
    let error = u16::from_be_bytes([raw[i + 2], raw[i + 3]]);
    let other_len = u16::from_be_bytes([raw[i + 4], raw[i + 5]]) as usize;
    i += 6;
    if raw.len() != i + other_len {
        return None;
    }
    let other = raw[i..i + other_len].to_vec();
    Some(TsigData {
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
    })
}

/// A request cannot carry an error code. A response may carry other data only on BADTIME, and only
/// the 6-byte time; otherwise this MAC-covered field could smuggle arbitrary bytes.
fn validate_tsig_data(data: &TsigData, response: bool) -> Result<(), TsigError> {
    if !response && data.error != 0 {
        return Err(TsigError::InvalidMessage);
    }
    if response {
        if data.error == 18 {
            if data.other.len() != 6 {
                return Err(TsigError::InvalidMessage);
            }
        } else if !data.other.is_empty() {
            return Err(TsigError::InvalidMessage);
        }
    }
    Ok(())
}

/// A MAC may be truncated to half (16 bytes) and cannot exceed 32. Without an upper bound a longer
/// MAC raises the comparison cost; without a lower bound a short one is easier to guess. Responses
/// with BADSIG or BADKEY may carry an empty MAC, since there is no secret to sign with.
fn validate_hmac_sha256_mac(data: &TsigData, response: bool) -> Result<(), TsigError> {
    let len = data.mac.len();
    if response && len == 0 && matches!(data.error, TSIG_ERROR_BADSIG | TSIG_ERROR_BADKEY) {
        return Ok(());
    }
    if !(16..=32).contains(&len) {
        return Err(TsigError::InvalidMessage);
    }
    Ok(())
}

/// The MAC is computed over the wire with the ID restored to `original_id`, and the record must
/// carry the same ID so the peer rebuilds the same bytes.
#[allow(clippy::too_many_arguments)]
fn sign_message_fields(
    msg: &mut Message,
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
    request_mac: Option<&[u8]>,
    original_id: u16,
) -> Result<Vec<u8>, ProtoError> {
    let mut wire = msg.try_encode()?;
    wire[0..2].copy_from_slice(&original_id.to_be_bytes());
    let mac = compute_mac(&wire, key, time_signed, fudge, error, other, request_mac);
    msg.additionals.push(tsig_record_fields(
        key.name.clone(),
        Name::from_str(ALG_HMAC_SHA256).expect("TSIG algorithm name must be a valid DNS name"),
        time_signed,
        fudge,
        &mac,
        original_id,
        error,
        other,
    ));
    Ok(mac)
}

fn tsig_record(
    key: &TsigKey,
    now: u64,
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: u16,
) -> Record {
    tsig_record_fields(
        key.name.clone(),
        Name::from_str(ALG_HMAC_SHA256).expect("TSIG algorithm name must be a valid DNS name"),
        now,
        fudge,
        mac,
        original_id,
        error,
        &[],
    )
}

/// Class ANY (255) and TTL 0 are fixed: verifiers check both, and other values would get our
/// messages rejected.
#[allow(clippy::too_many_arguments)]
fn tsig_record_fields(
    key_name: Name,
    algorithm: Name,
    now: u64,
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: u16,
    other: &[u8],
) -> Record {
    let mut rdata = Vec::new();
    push_canonical_name(&mut rdata, &algorithm);
    rdata.extend_from_slice(&time48(now));
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(mac);
    rdata.extend_from_slice(&original_id.to_be_bytes());
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&(other.len() as u16).to_be_bytes());
    rdata.extend_from_slice(other);
    Record {
        name: key_name,
        rtype: RecordType(TSIG_TYPE),
        class: DnsClass(255),
        ttl: 0,
        rdata: RData::Unknown(TSIG_TYPE, rdata),
    }
}

/// Measures the needed length up front and checks the limit: rolling back afterwards would leave a
/// broken message whose ARCOUNT was already raised. The owner name is not compressed because the
/// MAC input uses the uncompressed form.
#[allow(clippy::too_many_arguments)]
fn append_tsig_wire(
    writer: &mut Writer,
    key: &TsigKey,
    now: u64,
    fudge: u16,
    mac: &[u8],
    original_id: u16,
    error: u16,
    other: &[u8],
) -> Result<(), ProtoError> {
    if writer.buf.len() < 12 {
        return Err(ProtoError::Message("No DNS header to add TSIG to".into()));
    }
    let arcount = u16::from_be_bytes([writer.buf[10], writer.buf[11]]);
    let Some(next_arcount) = arcount.checked_add(1) else {
        return Err(ProtoError::Message("No section space to add TSIG".into()));
    };
    let owner_len = key
        .name
        .labels()
        .iter()
        .fold(1usize, |sum, label| sum.saturating_add(1 + label.len()));
    let rdata_len = ALG_HMAC_SHA256_WIRE
        .len()
        .saturating_add(6 + 2 + 2 + mac.len() + 2 + 2 + 2 + other.len());
    let additional = owner_len.saturating_add(10).saturating_add(rdata_len);
    if writer.buf.len().saturating_add(additional) > MAX_DNS_WIRE_LEN {
        return Err(ProtoError::Message(
            "Adding TSIG would exceed the DNS message size limit".into(),
        ));
    }

    writer.buf[10..12].copy_from_slice(&next_arcount.to_be_bytes());
    push_canonical_name_writer(writer, &key.name);
    writer.push_u16(TSIG_TYPE);
    writer.push_u16(255);
    writer.push_u32(0);
    writer.push_u16(rdata_len as u16);
    writer.push_bytes(ALG_HMAC_SHA256_WIRE);
    writer.push_bytes(&time48(now));
    writer.push_u16(fudge);
    writer.push_u16(mac.len() as u16);
    writer.push_bytes(mac);
    writer.push_u16(original_id);
    writer.push_u16(error);
    writer.push_u16(other.len() as u16);
    writer.push_bytes(other);
    if writer.is_failed() {
        return Err(ProtoError::Message("Could not append TSIG".into()));
    }
    Ok(())
}

/// Does not copy when the ID already matches, sparing a full copy per response.
fn original_id_wire(wire: &[u8], original_id: u16) -> Cow<'_, [u8]> {
    let id = original_id.to_be_bytes();
    if wire.get(0..2) == Some(id.as_slice()) {
        Cow::Borrowed(wire)
    } else if wire.len() >= 2 {
        let mut patched = wire.to_vec();
        patched[0..2].copy_from_slice(&id);
        Cow::Owned(patched)
    } else {
        Cow::Borrowed(wire)
    }
}

/// Input order: request MAC, message wire, TSIG variables. The request MAC with its length in front
/// is the chain that binds the response to the request; without the length the boundary would be
/// ambiguous and different combinations could produce the same input. The variables never include
/// the MAC itself.
fn compute_mac(
    digest_wire: &[u8],
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
    request_mac: Option<&[u8]>,
) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key.secret.as_slice())
        .expect("HMAC key length must match the algorithm");
    if let Some(rm) = request_mac {
        h.update(&(rm.len() as u16).to_be_bytes());
        h.update(rm);
    }
    h.update(digest_wire);

    let mut vars = Vec::new();
    push_canonical_name(&mut vars, &key.name);
    vars.extend_from_slice(&255u16.to_be_bytes());
    vars.extend_from_slice(&0u32.to_be_bytes());
    vars.extend_from_slice(ALG_HMAC_SHA256_WIRE);
    vars.extend_from_slice(&time48(time_signed));
    vars.extend_from_slice(&fudge.to_be_bytes());
    vars.extend_from_slice(&error.to_be_bytes());
    vars.extend_from_slice(&(other.len() as u16).to_be_bytes());
    vars.extend_from_slice(other);
    h.update(&vars);
    h.finalize().into_bytes().to_vec()
}

/// Only the time and fudge go in as variables; key name, class and algorithm were fixed by the
/// first message.
fn compute_mac_timers(
    digest_wire: &[u8],
    key: &TsigKey,
    time_signed: u64,
    fudge: u16,
    prior_mac: &[u8],
) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key.secret.as_slice())
        .expect("HMAC key length must match the algorithm");
    h.update(&(prior_mac.len() as u16).to_be_bytes());
    h.update(prior_mac);
    h.update(digest_wire);
    h.update(&time48(time_signed));
    h.update(&fudge.to_be_bytes());
    h.finalize().into_bytes().to_vec()
}

/// Lowercase and uncompressed: the canonical form for the MAC input.
fn push_canonical_name(out: &mut Vec<u8>, name: &Name) {
    for label in name.labels() {
        out.push(label.len() as u8);
        out.extend(label.iter().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
}

/// Avoids the Writer's name writer, which would add the name to the compression table.
fn push_canonical_name_writer(out: &mut Writer, name: &Name) {
    for label in name.labels() {
        out.push_u8(label.len() as u8);
        for byte in label {
            out.push_u8(byte.to_ascii_lowercase());
        }
    }
    out.push_u8(0);
}

/// TSIG uses 48-bit time, not 32.
fn time48(t: u64) -> [u8; 6] {
    [
        (t >> 40) as u8,
        (t >> 32) as u8,
        (t >> 24) as u8,
        (t >> 16) as u8,
        (t >> 8) as u8,
        t as u8,
    ]
}

/// Do not add an early return: stopping at a different position reveals the correct MAC byte by
/// byte through timing. The length check is fine; lengths are not secret.
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

/// Accepts a truncated MAC but rejects an empty one or one longer than expected; an empty MAC would
/// let any message through. The minimum length was checked earlier.
fn mac_matches(expected: &[u8], received: &[u8]) -> bool {
    !received.is_empty()
        && received.len() <= expected.len()
        && ct_eq(&expected[..received.len()], received)
}

/// A compression pointer fails: RDATA can move within a message, so a pointer inside it would point
/// somewhere else.
fn read_uncompressed_name(buf: &[u8], mut i: usize) -> Option<(Name, usize)> {
    let start = i;
    loop {
        let len = *buf.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        i += 1 + len;
        if i > buf.len() {
            return None;
        }
    }
    let name = parse_name_bytes(&buf[start..i])?;
    Some((name, i))
}

fn parse_name_bytes(b: &[u8]) -> Option<Name> {
    let mut s = String::new();
    let mut i = 0;
    while i < b.len() {
        let len = b[i] as usize;
        if len == 0 {
            break;
        }
        if !s.is_empty() {
            s.push('.');
        }
        s.push_str(std::str::from_utf8(b.get(i + 1..i + 1 + len)?).ok()?);
        i += 1 + len;
    }
    if s.is_empty() {
        return Some(Name::root());
    }
    Name::from_str(&s).ok()
}

/// Skips record boundaries without parsing the whole message: parsing and re-encoding would change
/// name compression and break the MAC. Fails if an earlier record is a TSIG, since two TSIGs leave
/// it unclear which one sets the signed range and let unsigned data slip in; RDATA that does not
/// end exactly at the end of the message is rejected for the same reason. Returns the TSIG offset,
/// owner name, class, TTL and RDATA.
fn scan_last_additional(wire: &[u8]) -> Option<(usize, Name, DnsClass, u32, Vec<u8>)> {
    if wire.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([wire[4], wire[5]]) as usize;
    let an = u16::from_be_bytes([wire[6], wire[7]]) as usize;
    let ns = u16::from_be_bytes([wire[8], wire[9]]) as usize;
    let ar = u16::from_be_bytes([wire[10], wire[11]]) as usize;
    if ar == 0 {
        return None;
    }
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(wire, i)?;
        i += 4;
    }
    for _ in 0..(an + ns + ar - 1) {
        let name_end = skip_name(wire, i)?;
        let rtype = u16::from_be_bytes([*wire.get(name_end)?, *wire.get(name_end + 1)?]);
        if rtype == TSIG_TYPE {
            return None;
        }
        i = skip_record(wire, i)?;
    }
    let tsig_off = i;

    let name_end = skip_name(wire, i)?;
    let rtype = u16::from_be_bytes([*wire.get(name_end)?, *wire.get(name_end + 1)?]);
    if rtype != TSIG_TYPE {
        return None;
    }
    let class = DnsClass(u16::from_be_bytes([
        *wire.get(name_end + 2)?,
        *wire.get(name_end + 3)?,
    ]));
    let ttl = u32::from_be_bytes([
        *wire.get(name_end + 4)?,
        *wire.get(name_end + 5)?,
        *wire.get(name_end + 6)?,
        *wire.get(name_end + 7)?,
    ]);
    let rdlen = u16::from_be_bytes([*wire.get(name_end + 8)?, *wire.get(name_end + 9)?]) as usize;
    let rdata_start = name_end + 10;
    let rdata_end = rdata_start.checked_add(rdlen)?;
    if rdata_end != wire.len() {
        return None;
    }
    let rdata = wire.get(rdata_start..rdata_end)?.to_vec();
    let owner = owner_name(wire, i)?;
    Some((tsig_off, owner, class, ttl, rdata))
}

/// Follows compression pointers, but only backwards and a limited number of times: both together
/// stop loops and long chains.
fn owner_name(wire: &[u8], mut i: usize) -> Option<Name> {
    let mut labels: Vec<String> = Vec::new();
    let mut hops = 0;
    loop {
        let len = *wire.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *wire.get(i + 1)? as usize;
            if ptr >= i || hops > 32 {
                return None;
            }
            i = ptr;
            hops += 1;
            continue;
        }
        labels.push(
            std::str::from_utf8(wire.get(i + 1..i + 1 + len)?)
                .ok()?
                .to_string(),
        );
        i += 1 + len;
    }
    if labels.is_empty() {
        return Some(Name::root());
    }
    Name::from_str(&labels.join(".")).ok()
}

fn skip_name(wire: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *wire.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + len;
    }
}

fn skip_record(wire: &[u8], i: usize) -> Option<usize> {
    let i = skip_name(wire, i)?;
    let rdlen = u16::from_be_bytes([*wire.get(i + 8)?, *wire.get(i + 9)?]) as usize;
    Some(i + 10 + rdlen)
}

/// Standard alphabet with padding, so values interoperate with other tools.
pub fn b64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Ignores whitespace and stops at padding. `None` on characters outside the alphabet or a single
/// leftover character, which cannot form an octet.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Zeroizing::new(Vec::new());
    let mut chunk = [0u32; 4];
    let mut n = 0;
    for &b in &bytes {
        if b == b'=' {
            break;
        }
        chunk[n] = val(b)?;
        n += 1;
        if n == 4 {
            let v = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6) | chunk[3];
            out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => {
            let v = (chunk[0] << 18) | (chunk[1] << 12);
            out.push((v >> 16) as u8);
        }
        3 => {
            let v = (chunk[0] << 18) | (chunk[1] << 12) | (chunk[2] << 6);
            out.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8]);
        }
        _ => return None,
    }
    Some(std::mem::take(&mut *out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::{Header, Question};

    fn key() -> TsigKey {
        TsigKey::new(
            Name::from_str("transfer-key").unwrap(),
            b"super-secret-bytes-32-chars-xxxx".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn cloned_key_shares_one_zeroizing_secret() {
        let original = key();
        let cloned = original.clone();
        assert!(Arc::ptr_eq(&original.secret, &cloned.secret));
    }

    fn axfr_query() -> Message {
        Message {
            header: Header {
                id: 0x1234,
                ..Default::default()
            },
            questions: vec![Question {
                name: Name::from_str("example.com").unwrap(),
                qtype: RecordType(252),
                qclass: DnsClass::IN,
            }],
            ..Default::default()
        }
    }

    /// Both paths must produce the same MAC.
    #[test]
    fn sign_verify_roundtrip_message_and_wire() {
        let k = key();
        let mut q = axfr_query();
        sign_message(&mut q, &k, 1_700_000_000, None).unwrap();
        assert_eq!(q.additionals.len(), 1, "TSIG RR 추가됨");

        let (stripped, mac) = verify_message(&q, &k, 1_700_000_000, None).expect("verify");
        assert!(stripped.additionals.is_empty());
        assert!(!mac.is_empty());

        let wire = q.try_encode().unwrap();
        let parsed = Message::parse(&wire).unwrap();
        let (_, mac2) = verify_message(&parsed, &k, 1_700_000_000, None).expect("re-parse verify");
        assert_eq!(mac, mac2);
        let (_, mac3) = verify_wire(&wire, &k, 1_700_000_010, None).expect("wire verify");
        assert_eq!(mac, mac3);
    }

    #[test]
    fn wrong_key_or_time_fails() {
        let k = key();
        let mut q = axfr_query();
        sign_message(&mut q, &k, 1_700_000_000, None).unwrap();

        let bad = TsigKey::new(k.name.clone(), b"wrong-wrong-wrong!".to_vec()).unwrap();
        assert_eq!(
            verify_message(&q, &bad, 1_700_000_000, None).unwrap_err(),
            TsigError::BadSig
        );

        let renamed = TsigKey {
            name: Name::from_str("other-key").unwrap(),
            secret: k.secret.clone(),
        };
        assert_eq!(
            verify_message(&q, &renamed, 1_700_000_000, None).unwrap_err(),
            TsigError::BadKey
        );

        assert_eq!(
            verify_message(&q, &k, 1_700_000_000 + 301, None).unwrap_err(),
            TsigError::BadTime
        );
    }

    #[test]
    fn hmac_sha256_truncation_follows_rfc_8945_bounds() {
        fn truncate_mac(message: &mut Message, new_len: usize) {
            let raw = match &mut message.additionals.last_mut().unwrap().rdata {
                RData::Unknown(TSIG_TYPE, raw) => raw,
                _ => panic!("TSIG RDATA가 아닙니다"),
            };
            let (_, fields) = read_uncompressed_name(raw, 0).unwrap();
            let old_len = u16::from_be_bytes([raw[fields + 8], raw[fields + 9]]) as usize;
            assert!(new_len <= old_len);
            raw[fields + 8..fields + 10].copy_from_slice(&(new_len as u16).to_be_bytes());
            raw.drain(fields + 10 + new_len..fields + 10 + old_len);
        }

        let key = key();
        let now = 1_700_000_000;
        let mut full = axfr_query();
        sign_message(&mut full, &key, now, None).unwrap();

        let mut minimum = full.clone();
        truncate_mac(&mut minimum, 16);
        verify_message(&minimum, &key, now, None).expect("SHA-256 절반 길이 MAC");
        verify_wire(&minimum.try_encode().unwrap(), &key, now, None)
            .expect("wire SHA-256 절반 길이 MAC");

        let mut too_short = full;
        truncate_mac(&mut too_short, 15);
        assert_eq!(
            verify_message(&too_short, &key, now, None).unwrap_err(),
            TsigError::InvalidMessage
        );
        assert_eq!(
            verify_wire(&too_short.try_encode().unwrap(), &key, now, None).unwrap_err(),
            TsigError::InvalidMessage
        );
    }

    #[test]
    fn verified_replay_window_ends_at_signed_time_plus_fudge() {
        let key = key();
        let now = 1_700_000_000;
        let client_time = now + 300;
        let mut request = axfr_query();
        sign_message(&mut request, &key, client_time, None).unwrap();
        let verified =
            match verify_wire_detailed(&request.try_encode().unwrap(), &key, now, None).unwrap() {
                WireVerification::Valid { tsig, .. } => tsig,
                WireVerification::BadTime { .. } => panic!("fudge 경계의 요청은 유효합니다"),
            };
        assert_eq!(verified.valid_until(), client_time + 300);
    }

    #[test]
    fn request_fudge_above_local_ceiling_is_badtime_after_mac_validation() {
        let key = key();
        let now = 1_700_000_000;
        let mut request = axfr_query();
        let wire = request.try_encode().unwrap();
        let mac = compute_mac(&wire, &key, now, 301, 0, &[], None);
        let original_id = request.header.id;
        request
            .additionals
            .push(tsig_record(&key, now, 301, &mac, original_id, 0));
        assert!(matches!(
            verify_wire_detailed(&request.try_encode().unwrap(), &key, now, None).unwrap(),
            WireVerification::BadTime { .. }
        ));
    }

    #[test]
    fn rejects_tsig_metadata_and_rdata_malleability() {
        let k = key();
        let mut q = axfr_query();
        sign_message(&mut q, &k, 1_700_000_000, None).unwrap();

        let mut wrong_class = q.clone();
        wrong_class.additionals.last_mut().unwrap().class = DnsClass::IN;
        assert!(verify_message(&wrong_class, &k, 1_700_000_000, None).is_err());
        assert!(verify_wire(&wrong_class.try_encode().unwrap(), &k, 1_700_000_000, None).is_err());

        let mut wrong_ttl = q.clone();
        wrong_ttl.additionals.last_mut().unwrap().ttl = 1;
        assert!(verify_message(&wrong_ttl, &k, 1_700_000_000, None).is_err());
        assert!(verify_wire(&wrong_ttl.try_encode().unwrap(), &k, 1_700_000_000, None).is_err());

        let mut trailing_rdata = q;
        match &mut trailing_rdata.additionals.last_mut().unwrap().rdata {
            RData::Unknown(TSIG_TYPE, raw) => raw.push(0),
            _ => panic!("TSIG RDATA가 아닙니다"),
        }
        assert!(verify_message(&trailing_rdata, &k, 1_700_000_000, None).is_err());
        assert!(verify_wire(
            &trailing_rdata.try_encode().unwrap(),
            &k,
            1_700_000_000,
            None
        )
        .is_err());
    }

    #[test]
    fn response_mac_chains_request_mac() {
        let k = key();
        let mut q = axfr_query();
        sign_message(&mut q, &k, 1_700_000_000, None).unwrap();
        let (_, req_mac) = verify_message(&q, &k, 1_700_000_000, None).unwrap();

        let mut resp = axfr_query();
        resp.header.response = true;
        sign_message(&mut resp, &k, 1_700_000_000, Some(&req_mac)).unwrap();

        assert_eq!(
            verify_message(&resp, &k, 1_700_000_000, None).unwrap_err(),
            TsigError::BadSig
        );
        verify_message(&resp, &k, 1_700_000_000, Some(&req_mac)).expect("연쇄 검증");
        let wire = resp.try_encode().unwrap();
        verify_wire(&wire, &k, 1_700_000_000, Some(&req_mac)).expect("와이어 연쇄 검증");
    }

    #[test]
    fn response_preserves_forwarded_request_original_id() {
        let key = key();
        let now = 1_700_000_000;
        let mut request = axfr_query();
        let request_mac = sign_message(&mut request, &key, now, None).unwrap();
        let original_id = request.header.id;
        request.header.id = 0x9876;
        let request_wire = request.try_encode().unwrap();
        let verified = match verify_wire_detailed(&request_wire, &key, now, None).unwrap() {
            WireVerification::Valid { tsig, .. } => tsig,
            WireVerification::BadTime { .. } => panic!("요청 시간이 유효합니다"),
        };

        let mut response = axfr_query();
        response.header.id = request.header.id;
        response.header.response = true;
        sign_response_message(&mut response, &key, now, &verified).unwrap();
        assert_eq!(response_data(&response).unwrap().original_id(), original_id);
        verify_wire(
            &response.try_encode().unwrap(),
            &key,
            now,
            Some(&request_mac),
        )
        .expect("forwarded ID 응답 MAC");
    }

    #[test]
    fn b64_roundtrip() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("aGVsbG8h").unwrap(), b"hello!");
        assert!(b64_decode("!!!").is_none());
    }

    #[test]
    fn multi_envelope_chain_sign_verify() {
        let key = TsigKey::new(
            Name::from_str("xfer-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let now = 1_700_000_000u64;

        let mut req = Message::query(7, Name::from_str("big.test").unwrap(), RecordType(252));
        let req_mac = sign_message(&mut req, &key, now, None).unwrap();

        let mk = |ttl: u32| {
            let mut m = Message::default();
            m.header.id = 7;
            m.header.response = true;
            m.answers.push(Record::new(
                Name::from_str("a.big.test").unwrap(),
                ttl,
                RData::A(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            ));
            m
        };
        let mut e1 = mk(1);
        let mac1 = sign_message(&mut e1, &key, now, Some(&req_mac)).unwrap();
        let mut e2 = mk(2);
        let mac2 = sign_subsequent(&mut e2, &key, now, &mac1).unwrap();
        let mut e3 = mk(3);
        let _mac3 = sign_subsequent(&mut e3, &key, now, &mac2).unwrap();

        let (_, v1) =
            verify_wire(&e1.try_encode().unwrap(), &key, now, Some(&req_mac)).expect("e1");
        let (_, v2) =
            verify_wire_subsequent(&e2.try_encode().unwrap(), &key, now, &v1).expect("e2");
        let (_, v3) =
            verify_wire_subsequent(&e3.try_encode().unwrap(), &key, now, &v2).expect("e3");
        assert_eq!(v1, mac1);
        assert_eq!(v2, mac2);

        assert!(matches!(
            verify_wire_subsequent(&e3.try_encode().unwrap(), &key, now, &v1),
            Err(TsigError::BadSig)
        ));
        let _ = v3;
    }
}
