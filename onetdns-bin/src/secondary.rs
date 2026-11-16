//! Secondary zones: transferred from the primary by AXFR and IXFR, refreshed when the SOA serial
//! says so.

use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;

use crate::atomic_file::atomic_write;
use crate::config_apply::SecondaryRestart;
use crate::edge::EdgeServices;
use crate::notify::NotifySender;
use crate::zones::{
    catalog_members, remove_zone, serial_gt, swap_zone, zonemd_ok, ZoneJournals, ZoneState,
    ZonemdPolicy,
};
use crate::{
    build_tsig_keys, native, nonblocking_tcp, read_text_limited, tsig_for_secondary, unix_now,
};

/// Reads the copy saved by the last transfer, so the zone is served before the first transfer
/// succeeds. None when the copy is past its SOA expire, belongs to another origin, or fails ZONEMD.
pub(crate) fn load_secondary_cache(
    config: &onetdns_config::SecondaryZone,
    global: &Config,
    origin: &onetdns_proto::Name,
) -> Option<onetdns_authority::Zone> {
    let path = config.file.as_ref()?;
    let last_ok = secondary_last_refresh(path)?;
    let age = unix_now().checked_sub(last_ok)?;
    let text = read_text_limited(path, MAX_AXFR_WIRE_BYTES as u64).ok()?;
    let zone = onetdns_authority::parse_zone(&text, &config.origin).ok()?;
    if !zone.origin().eq_ignore_case(origin)
        || age > zone.soa().expire as u64
        || !zonemd_ok(&zone, ZonemdPolicy::of(global))
    {
        return None;
    }
    Some(zone)
}

fn secondary_refresh_state_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".state");
    std::path::PathBuf::from(value)
}

fn secondary_last_refresh(path: &std::path::Path) -> Option<u64> {
    let now = unix_now();
    let text = read_text_limited(&secondary_refresh_state_path(path), 64).ok()?;
    let timestamp = text.trim().parse::<u64>().ok()?;
    (timestamp <= now).then_some(timestamp)
}

fn mark_secondary_refresh(path: &std::path::Path, timestamp: u64) -> std::io::Result<()> {
    atomic_write(
        &secondary_refresh_state_path(path),
        timestamp.to_string().as_bytes(),
    )
}

const MAX_AXFR_WIRE_BYTES: usize = 64 * 1024 * 1024;

const MAX_AXFR_RECORDS: usize = 1_000_000;

const MAX_AXFR_MESSAGES: usize = 10_000;

/// Without a byte from the peer for this long, the transfer is cut.
const SECONDARY_XFR_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Throughput a transfer must keep to extend its total deadline.
const SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC: u64 = 16 * 1024;

/// Grows only with response bytes actually received, so a peer dripping bytes cannot stretch it.
struct XfrProgressDeadline {
    started: std::time::Instant,
    /// Allowed even without progress, for connecting and sending the request.
    base_timeout: Duration,
    response_bytes: u64,
}

impl XfrProgressDeadline {
    fn new(started: std::time::Instant, base_timeout: Duration) -> Self {
        Self {
            started,
            base_timeout,
            response_bytes: 0,
        }
    }

    fn record_response_bytes(&mut self, bytes: usize) {
        self.response_bytes = self
            .response_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn allowed(&self) -> Duration {
        let seconds = self.response_bytes / SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        let remainder = self.response_bytes % SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        let nanos =
            remainder.saturating_mul(1_000_000_000) / SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC;
        self.base_timeout
            .saturating_add(Duration::from_secs(seconds))
            .saturating_add(Duration::from_nanos(nanos))
    }

    fn expired(&self, now: std::time::Instant) -> bool {
        now.saturating_duration_since(self.started) >= self.allowed()
    }
}

/// Kept to verify the response's TSIG.
struct EncodedXfrRequest {
    query: onetdns_proto::Message,
    framed_wire: Box<[u8]>,
    request_mac: Option<Vec<u8>>,
}

/// Request sent and every frame received through the closing SOA.
struct PreparedXfrIo {
    query: onetdns_proto::Message,
    request_mac: Option<Vec<u8>>,
    messages: Vec<Box<[u8]>>,
}

/// Tracks only the opening and closing SOA and the record count.
struct AxfrSequence {
    origin: onetdns_proto::Name,
    opening_soa: Option<onetdns_proto::Record>,
    record_count: usize,
}

impl AxfrSequence {
    fn new(origin: &onetdns_proto::Name) -> Self {
        Self {
            origin: origin.clone(),
            opening_soa: None,
            record_count: 0,
        }
    }

    /// Whether the closing SOA has arrived.
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        use onetdns_proto::RecordType;

        let answer_count = message.answers.len();
        for (index, record) in message.answers.iter().enumerate() {
            if self.record_count >= MAX_AXFR_RECORDS {
                return Err("AXFR response has too many records".to_string());
            }
            if self.record_count == 0
                && (record.rtype != RecordType::SOA || !record.name.eq_ignore_case(&self.origin))
            {
                return Err(
                    "The first record of an AXFR response must be the zone apex SOA".to_string(),
                );
            }
            if record.rtype == RecordType::SOA && record.name.eq_ignore_case(&self.origin) {
                if let Some(opening) = &self.opening_soa {
                    if !xfr_rr_equal(record, opening) {
                        return Err(
                            "The closing AXFR SOA does not match the opening SOA".to_string()
                        );
                    }
                    if index + 1 != answer_count {
                        return Err("Records follow the closing AXFR SOA".to_string());
                    }
                    self.record_count += 1;
                    return Ok(true);
                }
                self.opening_soa = Some(record.clone());
            }
            self.record_count += 1;
        }
        Ok(false)
    }
}

fn encode_xfr_request(
    mut query: onetdns_proto::Message,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
) -> Result<EncodedXfrRequest, String> {
    let request_mac = tsig
        .map(|key| onetdns_dnssec::tsig::sign_message(&mut query, key, unix_now(), None))
        .transpose()
        .map_err(|error| format!("Could not sign the XFR query: {error}"))?;
    let wire = query
        .try_encode()
        .map_err(|error| format!("Could not encode the XFR query: {error}"))?;
    let length = u16::try_from(wire.len())
        .map_err(|_| "XFR query exceeds the DNS/TCP frame size".to_string())?;
    let mut framed_wire = Vec::with_capacity(wire.len() + 2);
    framed_wire.extend_from_slice(&length.to_be_bytes());
    framed_wire.extend_from_slice(&wire);
    Ok(EncodedXfrRequest {
        query,
        framed_wire: framed_wire.into_boxed_slice(),
        request_mac,
    })
}

fn build_axfr_query(origin: &onetdns_proto::Name) -> onetdns_proto::Message {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};

    let mut query = Message::default();
    query.header.id = 0x4242;
    query.questions = vec![Question {
        name: origin.clone(),
        qtype: RecordType(252),
        qclass: DnsClass::IN,
    }];
    query
}

fn axfr_fetch_prepared(
    origin: &onetdns_proto::Name,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    prepared: PreparedXfrIo,
) -> Result<Vec<onetdns_proto::Record>, String> {
    collect_axfr(origin, |accept| {
        xfr_exchange_prepared(prepared, tsig, accept)
    })
}

/// Done only when the opening and closing SOAs match; otherwise a transfer cut midway would be
/// taken as a whole zone.
fn collect_axfr(
    origin: &onetdns_proto::Name,
    exchange: impl FnOnce(
        &mut dyn FnMut(&onetdns_proto::Message) -> Result<bool, String>,
    ) -> Result<(), String>,
) -> Result<Vec<onetdns_proto::Record>, String> {
    let mut records = Vec::new();
    let mut sequence = AxfrSequence::new(origin);
    exchange(&mut |msg| {
        let complete = sequence.accept(msg)?;
        records.extend(msg.answers.iter().cloned());
        Ok(complete)
    })?;
    Ok(records)
}

/// Verifies the frames the nonblocking listener collected to the end.
fn xfr_exchange_prepared(
    prepared: PreparedXfrIo,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    mut accept: impl FnMut(&onetdns_proto::Message) -> Result<bool, String>,
) -> Result<(), String> {
    let mut transferred_bytes = 0usize;
    let mut previous_mac = prepared.request_mac;
    for (message_index, message) in prepared.messages.into_iter().enumerate() {
        if accept_xfr_message(
            &prepared.query,
            &mut previous_mac,
            &mut transferred_bytes,
            message_index,
            &message,
            tsig,
            &mut accept,
        )? {
            return Ok(());
        }
    }
    Err("Zone transfer response has no closing SOA".to_string())
}

/// Checks one frame's size, TSIG, and envelope, then hands it to the content consumer.
#[allow(clippy::too_many_arguments)]
fn accept_xfr_message(
    query: &onetdns_proto::Message,
    previous_mac: &mut Option<Vec<u8>>,
    transferred_bytes: &mut usize,
    message_index: usize,
    buffer: &[u8],
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    accept: &mut impl FnMut(&onetdns_proto::Message) -> Result<bool, String>,
) -> Result<bool, String> {
    if message_index >= MAX_AXFR_MESSAGES {
        return Err("Zone transfer response has no closing SOA".to_string());
    }
    *transferred_bytes = transferred_bytes
        .checked_add(2 + buffer.len())
        .ok_or_else(|| "AXFR transfer size calculation overflowed".to_string())?;
    if *transferred_bytes > MAX_AXFR_WIRE_BYTES {
        return Err("AXFR response exceeds the total size limit".to_string());
    }

    let stripped_wire;
    let effective = if let Some(key) = tsig {
        let verified = if message_index == 0 {
            onetdns_dnssec::tsig::verify_wire(buffer, key, unix_now(), previous_mac.as_deref())
        } else {
            onetdns_dnssec::tsig::verify_wire_subsequent(
                buffer,
                key,
                unix_now(),
                previous_mac.as_deref().unwrap_or(&[]),
            )
        };
        match verified {
            Ok((wire, mac)) => {
                *previous_mac = Some(mac);
                stripped_wire = wire;
                stripped_wire.as_slice()
            }
            Err(error) => {
                return Err(format!(
                    "TSIG verification of the zone transfer response failed: {error:?}"
                ));
            }
        }
    } else {
        buffer
    };
    let message = onetdns_proto::Message::parse(effective)
        .map_err(|_| "Could not parse the zone transfer response".to_string())?;
    let question_ok = if message_index == 0 {
        message.questions.len() == 1
            && message.questions[0]
                .name
                .eq_ignore_case(&query.questions[0].name)
            && message.questions[0].qtype == query.questions[0].qtype
            && message.questions[0].qclass == query.questions[0].qclass
    } else {
        message.questions.is_empty()
    };
    if message.header.rcode != 0 {
        return Err(xfr_rcode_error(message.header.rcode));
    }
    if !message.header.response
        || message.header.id != query.header.id
        || message.header.opcode != 0
        || !message.header.authoritative
        || message.header.truncated
        || !question_ok
        || !message.authorities.is_empty()
    {
        return Err(
            "Zone transfer response header or question does not match the request".to_string(),
        );
    }
    accept(&message)
}

fn xfr_rcode_error(rcode: u16) -> String {
    format!("Zone transfer response code: {rcode}")
}

/// Must check the same text `xfr_rcode_error` builds; if the two drift apart, the fallback to a
/// full transfer silently stops.
fn xfr_error_is_notimp(error: &str) -> bool {
    error == xfr_rcode_error(onetdns_proto::ResponseCode::NotImp.0)
}

fn xfr_rr_equal(left: &onetdns_proto::Record, right: &onetdns_proto::Record) -> bool {
    left.name.eq_ignore_case(&right.name)
        && left.rtype == right.rtype
        && left.class == right.class
        && onetdns_dnssec::canonical_rdata(&left.rdata)
            == onetdns_dnssec::canonical_rdata(&right.rdata)
}

enum IxfrFetchResult {
    Unchanged,
    Incremental(onetdns_authority::Zone),
    Full(onetdns_authority::Zone),
}

#[derive(Clone, Copy)]
enum IxfrWireMode {
    Undecided,
    Full,
    /// Carries the serial of that change.
    Delete,
    Add(u32),
}

/// Tracks only the shape, continuity, and end of the IXFR stream.
struct IxfrSequence {
    origin: onetdns_proto::Name,
    client_serial: u32,
    record_count: usize,
    mode: IxfrWireMode,
    server_serial: Option<u32>,
    /// A single SOA saying nothing changed.
    unchanged: bool,
    opening_soa: Option<onetdns_proto::Record>,
}

impl IxfrSequence {
    fn new(current: &onetdns_authority::Zone) -> Self {
        Self {
            origin: current.origin().clone(),
            client_serial: current.soa().serial,
            record_count: 0,
            mode: IxfrWireMode::Undecided,
            server_serial: None,
            unchanged: false,
            opening_soa: None,
        }
    }

    /// Whether the IXFR stream has ended.
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        use onetdns_proto::{DnsClass, RecordType};

        let answer_count = message.answers.len();
        for (index, record) in message.answers.iter().enumerate() {
            if self.record_count >= MAX_AXFR_RECORDS {
                return Err("IXFR response has too many records".to_string());
            }
            let last_in_message = index + 1 == answer_count;
            let is_apex_soa = record.rtype == RecordType::SOA
                && record.class == DnsClass::IN
                && record.name.eq_ignore_case(&self.origin);
            if record.rtype == RecordType::SOA && !is_apex_soa {
                return Err("IXFR contains an SOA outside the apex".to_string());
            }
            if self.record_count == 0 {
                if !is_apex_soa {
                    return Err(
                        "The first record of an IXFR response must be the zone apex SOA"
                            .to_string(),
                    );
                }
                let serial = record_soa_serial(record).ok_or_else(|| {
                    "Could not parse the first SOA of the IXFR response".to_string()
                })?;
                if serial != self.client_serial && !serial_gt(serial, self.client_serial) {
                    return Err(
                        "The IXFR response serial is older than the requesting client's serial"
                            .to_string(),
                    );
                }
                self.server_serial = Some(serial);
                self.opening_soa = Some(record.clone());
                self.record_count += 1;
                continue;
            }

            match self.mode {
                IxfrWireMode::Undecided => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "Could not parse an SOA in the IXFR response".to_string()
                        })?;
                        if serial == self.client_serial
                            && self
                                .server_serial
                                .is_some_and(|current| current != self.client_serial)
                        {
                            self.mode = IxfrWireMode::Delete;
                        } else {
                            self.mode = IxfrWireMode::Full;
                        }
                    } else {
                        self.mode = IxfrWireMode::Full;
                    }
                }
                IxfrWireMode::Full => {}
                IxfrWireMode::Delete => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "Could not parse the new SOA in the IXFR response".to_string()
                        })?;
                        self.mode = IxfrWireMode::Add(serial);
                    }
                }
                IxfrWireMode::Add(latest) => {
                    if is_apex_soa {
                        let serial = record_soa_serial(record).ok_or_else(|| {
                            "Could not parse the SOA of an IXFR change section".to_string()
                        })?;
                        if Some(latest) == self.server_serial {
                            let opening = self
                                .opening_soa
                                .as_ref()
                                .expect("The first IXFR record was stored above");
                            if Some(serial) != self.server_serial
                                || !xfr_rr_equal(record, opening)
                                || !last_in_message
                            {
                                return Err(
                                    "The last SOA of the IXFR response does not match the opening SOA"
                                        .to_string(),
                                );
                            }
                            self.record_count += 1;
                            return Ok(true);
                        }
                        if serial != latest {
                            return Err(
                                "The serial of an IXFR change does not follow the previous change"
                                    .to_string(),
                            );
                        }
                        self.mode = IxfrWireMode::Delete;
                    }
                }
            }

            if matches!(self.mode, IxfrWireMode::Full) && is_apex_soa {
                let opening = self
                    .opening_soa
                    .as_ref()
                    .expect("The first IXFR record was stored above");
                if xfr_rr_equal(record, opening) {
                    if !last_in_message {
                        return Err("Records remain after the last SOA of an IXFR response that fell back to a full transfer".to_string());
                    }
                    self.record_count += 1;
                    return Ok(true);
                }
            }
            self.record_count += 1;
        }

        if self.record_count == 1 && self.server_serial == Some(self.client_serial) {
            self.unchanged = true;
            return Ok(true);
        }
        Ok(false)
    }
}

fn record_soa_serial(record: &onetdns_proto::Record) -> Option<u32> {
    match &record.rdata {
        onetdns_proto::RData::Soa(soa) => Some(soa.serial),
        _ => None,
    }
}

fn ixfr_fetch_prepared(
    current: &onetdns_authority::Zone,
    tsig: Option<&onetdns_dnssec::tsig::TsigKey>,
    prepared: PreparedXfrIo,
) -> Result<IxfrFetchResult, String> {
    collect_ixfr(current, |accept| {
        xfr_exchange_prepared(prepared, tsig, accept)
    })
}

fn build_ixfr_query(current: &onetdns_authority::Zone) -> Result<onetdns_proto::Message, String> {
    use onetdns_proto::{DnsClass, Message, Question, RecordType};

    let origin = current.origin();
    let mut query = Message::default();
    query.header.id = 0x4946;
    query.questions.push(Question {
        name: origin.clone(),
        qtype: RecordType(251),
        qclass: DnsClass::IN,
    });
    let client_soa = current
        .axfr_records_iter()
        .next()
        .ok_or_else(|| "The IXFR request has no client SOA record".to_string())?;
    query.authorities.push(client_soa);
    Ok(query)
}

/// The primary may send the whole zone instead of changes; the shape tells which.
fn collect_ixfr(
    current: &onetdns_authority::Zone,
    exchange: impl FnOnce(
        &mut dyn FnMut(&onetdns_proto::Message) -> Result<bool, String>,
    ) -> Result<(), String>,
) -> Result<IxfrFetchResult, String> {
    let origin = current.origin();
    let mut records = Vec::new();
    let mut sequence = IxfrSequence::new(current);
    exchange(&mut |message| {
        let complete = sequence.accept(message)?;
        records.extend(message.answers.iter().cloned());
        Ok(complete)
    })?;

    if sequence.unchanged {
        return Ok(IxfrFetchResult::Unchanged);
    }
    if matches!(sequence.mode, IxfrWireMode::Full) {
        let zone = onetdns_authority::Zone::from_records(records)
            .map_err(|error| format!("Zone data was invalid while handling the IXFR response as a full transfer: {error}"))?;
        if !zone.origin().eq_ignore_case(origin)
            || zone.soa().serial != sequence.server_serial.unwrap_or(0)
        {
            return Err("The zone name or serial of an IXFR response that fell back to a full transfer does not match the request".to_string());
        }
        return Ok(IxfrFetchResult::Full(zone));
    }
    apply_ixfr_records(current, &records).map(IxfrFetchResult::Incremental)
}

/// Applies the changes in order. A delete of a record that does not exist is refused: it means this
/// zone has drifted from the primary, and applying the rest would widen the drift.
fn apply_ixfr_records(
    current: &onetdns_authority::Zone,
    transfer: &[onetdns_proto::Record],
) -> Result<onetdns_authority::Zone, String> {
    use onetdns_proto::{RData, RecordType};

    let current_soa = transfer
        .first()
        .and_then(record_soa_serial)
        .ok_or_else(|| "IXFR response has no current SOA".to_string())?;
    if transfer.len() < 4
        || !xfr_rr_equal(
            &transfer[0],
            transfer
                .last()
                .expect("The response length was checked above"),
        )
    {
        return Err("The opening and closing SOA of the IXFR response do not match".to_string());
    }
    let mut records = current.axfr_records();
    records.pop();
    let mut working_serial = current.soa().serial;
    let mut index = 1usize;
    while index + 1 < transfer.len() {
        let old_serial = record_soa_serial(&transfer[index])
            .ok_or_else(|| "An IXFR change section has no old SOA".to_string())?;
        if old_serial != working_serial {
            return Err(
                "IXFR changes do not continue from the client's current serial".to_string(),
            );
        }
        index += 1;
        while index + 1 < transfer.len() && transfer[index].rtype != RecordType::SOA {
            let deleted = &transfer[index];
            let Some(position) = records
                .iter()
                .position(|record| xfr_rr_equal(record, deleted))
            else {
                return Err("IXFR asks to delete an RR that does not exist".to_string());
            };
            records.remove(position);
            index += 1;
        }
        if index + 1 >= transfer.len() {
            return Err("An IXFR change section has no new SOA".to_string());
        }
        let new_soa = transfer[index].clone();
        let new_serial = record_soa_serial(&new_soa)
            .ok_or_else(|| "The new SOA of an IXFR change section is invalid".to_string())?;
        if !serial_gt(new_serial, working_serial) {
            return Err("The serial of an IXFR change section did not increase".to_string());
        }
        let soa_position = records
            .iter()
            .position(|record| record.rtype == RecordType::SOA)
            .ok_or_else(|| "The client DNS zone has no SOA record".to_string())?;
        records[soa_position] = new_soa;
        working_serial = new_serial;
        index += 1;
        while index + 1 < transfer.len() && transfer[index].rtype != RecordType::SOA {
            let added = transfer[index].clone();
            if matches!(added.rdata, RData::Soa(_)) {
                return Err("The SOA of an IXFR addition section is misplaced".to_string());
            }
            if let Some(existing) = records
                .iter_mut()
                .find(|record| xfr_rr_equal(record, &added))
            {
                existing.ttl = added.ttl;
            } else {
                records.push(added);
            }
            index += 1;
        }
        if working_serial == current_soa {
            if index + 1 != transfer.len() {
                return Err("IXFR response has extra changes after the current serial".to_string());
            }
            break;
        }
    }
    if working_serial != current_soa {
        return Err(
            "After applying IXFR, the zone serial does not match the final serial of the response"
                .to_string(),
        );
    }
    let zone = onetdns_authority::Zone::from_records(records).map_err(|error| {
        format!("Zone data validation failed after applying IXFR changes: {error}")
    })?;
    if !zone.origin().eq_ignore_case(current.origin()) || zone.soa().serial != current_soa {
        return Err(
            "After applying IXFR, the zone name or serial does not match the expected values"
                .to_string(),
        );
    }
    Ok(zone)
}

#[derive(Clone, PartialEq, Eq)]
struct XferEntry {
    origin: String,
    file: Option<std::path::PathBuf>,
    primary: std::net::IpAddr,
    port: u16,
    tsig_key: Option<String>,

    /// Holds the member zones.
    is_catalog: bool,
}

impl XferEntry {
    fn from_cfg(s: &onetdns_config::SecondaryZone, is_catalog: bool) -> Option<XferEntry> {
        Some(XferEntry {
            origin: onetdns_proto::Name::from_str(&s.origin)
                .ok()?
                .to_ascii_lower(),
            file: s.file.clone(),
            primary: s.primary?,
            port: s.primary_port.unwrap_or(53),
            tsig_key: s.tsig_key.clone(),
            is_catalog,
        })
    }
}

/// Transfers parsed at once.
const SECONDARY_REFRESH_MAX_IN_FLIGHT: usize = 4;

/// Connections in progress at once; more than the parsers, since waiting on the network takes no
/// thread.
const SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT: usize = 64;

/// Conservative per-frame bookkeeping outside the payload.
const SECONDARY_XFR_FRAME_OVERHEAD_BYTES: usize = 2 + 2 * std::mem::size_of::<Box<[u8]>>();

/// Shared by the response buffers of every transfer in flight.
const SECONDARY_XFR_BUFFER_BUDGET_BYTES: usize =
    MAX_AXFR_WIRE_BYTES + MAX_AXFR_MESSAGES * (SECONDARY_XFR_FRAME_OVERHEAD_BYTES - 2);

const _: () = assert!(SECONDARY_XFR_BUFFER_BUDGET_BYTES < 65 * 1024 * 1024);

/// Per connection in one coordinator pass.
const SECONDARY_XFR_FRAMES_PER_POLL: usize = 4;

/// Per connection in one coordinator pass.
const SECONDARY_XFR_BYTES_PER_POLL: usize = 256 * 1024;

const SECONDARY_XFER_STACK_BYTES: usize = 1024 * 1024;

/// Exact response buffer count shared by every transfer listener.
struct XfrBufferBudget {
    limit: usize,
    used: std::sync::atomic::AtomicUsize,
}

impl XfrBufferBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn reservation(self: &Arc<Self>) -> XfrBufferReservation {
        XfrBufferReservation {
            budget: self.clone(),
            bytes: 0,
        }
    }

    #[cfg(test)]
    /// For tests.
    fn used(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// One transfer's share of the global response buffer, returned on drop.
struct XfrBufferReservation {
    budget: Arc<XfrBufferBudget>,
    bytes: usize,
}

impl XfrBufferReservation {
    /// Only within the global limit.
    fn try_grow(&mut self, additional: usize) -> bool {
        let mut used = self.budget.used.load(std::sync::atomic::Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(additional) else {
                return false;
            };
            if next > self.budget.limit {
                return false;
            }
            match self.budget.used.compare_exchange_weak(
                used,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bytes += additional;
                    return true;
                }
                Err(actual) => used = actual,
            }
        }
    }
}

impl Drop for XfrBufferReservation {
    fn drop(&mut self) {
        self.budget
            .used
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

struct SecondaryRefreshJob {
    entry: XferEntry,
    current_serial: Option<u32>,
    had_zone: bool,
    last_ok: u64,
    refresh: u64,
    retry: u64,
    /// The held zone is dropped past this.
    expire: u64,
    /// Set by NOTIFY.
    priority: bool,

    force_axfr: bool,
}

#[derive(Clone, Copy)]
enum SecondaryXferKind {
    Axfr,
    Ixfr,
    IxfrFull,
}

enum SecondaryXferOutcome {
    UpToDate,
    Zone(Box<onetdns_authority::Zone>, SecondaryXferKind),
    Catalog {
        serial: u32,
        members: Vec<String>,
    },

    /// Changes alone cannot get there.
    NeedsFullTransfer {
        remote_serial: u32,
    },
}

struct ActiveSecondaryXfer {
    job: SecondaryRefreshJob,
    handle: std::thread::JoinHandle<Result<SecondaryXferOutcome, String>>,
}

enum SecondaryXfrBoundary {
    Axfr(AxfrSequence),
    Ixfr(IxfrSequence),
}

impl SecondaryXfrBoundary {
    fn accept(&mut self, message: &onetdns_proto::Message) -> Result<bool, String> {
        match self {
            Self::Axfr(sequence) => sequence.accept(message),
            Self::Ixfr(sequence) => sequence.accept(message),
        }
    }
}

enum SecondaryXfrAdmissionState {
    Connecting,
    Writing { offset: usize },
    ReadingLength { bytes: [u8; 2], offset: usize },
    ReadingMessage { bytes: Vec<u8>, offset: usize },
}

/// Transfer received without a thread from connect to the closing SOA. Slow peers holding transfer
/// workers would keep healthy zones from refreshing, so only complete transfers reach the parser.
struct PendingSecondaryXfrAdmission {
    job: SecondaryRefreshJob,
    remote_serial: u32,
    current: Option<onetdns_authority::Zone>,
    stream: std::net::TcpStream,
    query: onetdns_proto::Message,
    framed_wire: Box<[u8]>,
    request_mac: Option<Vec<u8>>,
    messages: Vec<Box<[u8]>>,
    boundary: SecondaryXfrBoundary,
    reservation: XfrBufferReservation,
    /// Includes the length prefixes.
    wire_bytes: usize,
    progress_deadline: XfrProgressDeadline,
    /// Since the last progress.
    idle_deadline: std::time::Instant,
    state: SecondaryXfrAdmissionState,
}

/// Received through the closing SOA, ready for verification and zone building.
struct PreparedSecondaryXfr {
    job: SecondaryRefreshJob,
    remote_serial: u32,
    current: Option<onetdns_authority::Zone>,
    io: PreparedXfrIo,
    /// Held until the zone is built.
    reservation: XfrBufferReservation,
}

struct SecondaryXfrAdmission {
    pending: Vec<PendingSecondaryXfrAdmission>,
    budget: Arc<XfrBufferBudget>,
}

impl PendingSecondaryXfrAdmission {
    /// Advances a bounded amount; true when done.
    fn advance(&mut self) -> Result<bool, String> {
        use std::io::{Read, Write};

        let mut frames = 0usize;
        let mut bytes_this_poll = 0usize;
        loop {
            match &mut self.state {
                SecondaryXfrAdmissionState::Connecting => {
                    if let Some(error) = self.stream.take_error().map_err(|e| e.to_string())? {
                        return Err(format!("XFR TCP connection failed: {error}"));
                    }
                    match self.stream.peer_addr() {
                        Ok(_) => {
                            self.state = SecondaryXfrAdmissionState::Writing { offset: 0 };
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::NotConnected
                                    | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!(
                                "Could not check the XFR TCP connection state: {error}"
                            ));
                        }
                    }
                }
                SecondaryXfrAdmissionState::Writing { offset } => {
                    match self.stream.write(&self.framed_wire[*offset..]) {
                        Ok(0) => {
                            return Err(
                                "The connection closed while sending the XFR query".to_string()
                            )
                        }
                        Ok(written) => {
                            *offset += written;
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if *offset == self.framed_wire.len() {
                                self.state = SecondaryXfrAdmissionState::ReadingLength {
                                    bytes: [0; 2],
                                    offset: 0,
                                };
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => return Err(format!("Could not send the XFR query: {error}")),
                    }
                }
                SecondaryXfrAdmissionState::ReadingLength { bytes, offset } => {
                    if *offset == bytes.len() {
                        let length = u16::from_be_bytes(*bytes) as usize;
                        if length == 0 {
                            return Err("XFR response frame length is zero".to_string());
                        }
                        if self.messages.len() >= MAX_AXFR_MESSAGES {
                            return Err("Zone transfer response has no closing SOA".to_string());
                        }
                        let wire_bytes =
                            self.wire_bytes.checked_add(2 + length).ok_or_else(|| {
                                "AXFR transfer size calculation overflowed".to_string()
                            })?;
                        if wire_bytes > MAX_AXFR_WIRE_BYTES {
                            return Err("AXFR response exceeds the total size limit".to_string());
                        }
                        let charge = length
                            .checked_add(SECONDARY_XFR_FRAME_OVERHEAD_BYTES)
                            .ok_or_else(|| {
                                "XFR response buffer size calculation overflowed".to_string()
                            })?;
                        if !self.reservation.try_grow(charge) {
                            return Err(
                                "Concurrent XFR response buffers reached the total memory limit"
                                    .to_string(),
                            );
                        }
                        self.wire_bytes = wire_bytes;
                        self.state = SecondaryXfrAdmissionState::ReadingMessage {
                            bytes: vec![0; length],
                            offset: 0,
                        };
                        continue;
                    }
                    match self.stream.read(&mut bytes[*offset..]) {
                        Ok(0) => {
                            return Err(
                                "The connection closed before the closing XFR SOA".to_string()
                            );
                        }
                        Ok(read) => {
                            *offset += read;
                            bytes_this_poll += read;
                            self.progress_deadline.record_response_bytes(read);
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL {
                                return Ok(false);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!("Could not read the XFR response length: {error}"));
                        }
                    }
                }
                SecondaryXfrAdmissionState::ReadingMessage { bytes, offset } => {
                    if *offset == bytes.len() {
                        let wire = std::mem::take(bytes);
                        let message = onetdns_proto::Message::parse(&wire).map_err(|_| {
                            "Could not parse the zone transfer response".to_string()
                        })?;
                        let complete = if message.header.rcode != 0 {
                            true
                        } else {
                            self.boundary.accept(&message)?
                        };
                        self.messages.push(wire.into_boxed_slice());
                        frames += 1;
                        self.state = SecondaryXfrAdmissionState::ReadingLength {
                            bytes: [0; 2],
                            offset: 0,
                        };
                        if complete {
                            return Ok(true);
                        }
                        if frames >= SECONDARY_XFR_FRAMES_PER_POLL
                            || bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL
                        {
                            return Ok(false);
                        }
                        continue;
                    }
                    match self.stream.read(&mut bytes[*offset..]) {
                        Ok(0) => {
                            return Err(
                                "The connection closed before the closing XFR SOA".to_string()
                            );
                        }
                        Ok(read) => {
                            *offset += read;
                            bytes_this_poll += read;
                            self.progress_deadline.record_response_bytes(read);
                            self.idle_deadline =
                                std::time::Instant::now() + SECONDARY_XFR_IDLE_TIMEOUT;
                            if bytes_this_poll >= SECONDARY_XFR_BYTES_PER_POLL {
                                return Ok(false);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            return Ok(false);
                        }
                        Err(error) => {
                            return Err(format!("Could not read the XFR response body: {error}"));
                        }
                    }
                }
            }
        }
    }

    fn into_prepared(self) -> PreparedSecondaryXfr {
        let Self {
            job,
            remote_serial,
            current,
            query,
            request_mac,
            messages,
            reservation,
            ..
        } = self;
        PreparedSecondaryXfr {
            job,
            remote_serial,
            current,
            io: PreparedXfrIo {
                query,
                request_mac,
                messages,
            },
            reservation,
        }
    }
}

impl Default for SecondaryXfrAdmission {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            budget: Arc::new(XfrBufferBudget::new(SECONDARY_XFR_BUFFER_BUDGET_BYTES)),
        }
    }
}

impl SecondaryXfrAdmission {
    fn len(&self) -> usize {
        self.pending.len()
    }

    fn retain_current(&mut self, entries: &[XferEntry]) {
        self.pending
            .retain(|pending| secondary_entry_is_current(entries, &pending.job));
    }

    fn start(
        &mut self,
        job: SecondaryRefreshJob,
        remote_serial: u32,
        current: Option<onetdns_authority::Zone>,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        timeout: Duration,
    ) -> Result<(), Box<(SecondaryRefreshJob, String)>> {
        if self.pending.len() >= SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT {
            return Err(Box::new((
                job,
                "XFR admission connection limit reached".to_string(),
            )));
        }
        let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
            Ok(origin) => origin,
            Err(_) => {
                return Err(Box::new((
                    job,
                    "Invalid secondary DNS zone name".to_string(),
                )));
            }
        };
        let key = tsig_for_secondary(tsig_keys, &job.entry.tsig_key);
        if job.entry.tsig_key.is_some() && key.is_none() {
            return Err(Box::new((
                job,
                "Could not find the TSIG key for the secondary zone".to_string(),
            )));
        }

        let current = if job.force_axfr { None } else { current };
        let boundary = match current.as_ref() {
            Some(current) if !job.entry.is_catalog => {
                SecondaryXfrBoundary::Ixfr(IxfrSequence::new(current))
            }
            _ => SecondaryXfrBoundary::Axfr(AxfrSequence::new(&origin)),
        };
        let mut query = match current.as_ref() {
            Some(current) if !job.entry.is_catalog => match build_ixfr_query(current) {
                Ok(query) => query,
                Err(error) => return Err(Box::new((job, error))),
            },
            _ => build_axfr_query(&origin),
        };
        query.header.id = u16::from_ne_bytes(onetdns_core::random_array());
        let encoded = match encode_xfr_request(query, key) {
            Ok(encoded) => encoded,
            Err(error) => return Err(Box::new((job, error))),
        };
        let address = std::net::SocketAddr::new(job.entry.primary, job.entry.port);
        let stream = match nonblocking_tcp::connect(address) {
            Ok(stream) => stream,
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("Could not start the XFR TCP connection: {error}"),
                )));
            }
        };
        let _ = stream.set_nodelay(true);
        let now = std::time::Instant::now();
        self.pending.push(PendingSecondaryXfrAdmission {
            job,
            remote_serial,
            current,
            stream,
            query: encoded.query,
            framed_wire: encoded.framed_wire,
            request_mac: encoded.request_mac,
            messages: Vec::new(),
            boundary,
            reservation: self.budget.reservation(),
            wire_bytes: 0,
            progress_deadline: XfrProgressDeadline::new(now, timeout),
            // Connecting has no bytes to credit, so the base total time applies; after connecting,
            // each read or write moves a short no-progress deadline.
            idle_deadline: now + timeout,
            state: SecondaryXfrAdmissionState::Connecting,
        });
        Ok(())
    }

    /// Gives each connection a fair share of work.
    fn poll(
        &mut self,
    ) -> (
        Vec<PreparedSecondaryXfr>,
        Vec<(SecondaryRefreshJob, String)>,
    ) {
        let now = std::time::Instant::now();
        let mut ready = Vec::new();
        let mut failed = Vec::new();
        let mut index = self.pending.len();
        while index > 0 {
            index -= 1;
            let result = if self.pending[index].progress_deadline.expired(now) {
                Err("XFR transfer exceeded its total time limit".to_string())
            } else if now >= self.pending[index].idle_deadline {
                Err("Timed out waiting for the XFR response".to_string())
            } else {
                self.pending[index].advance()
            };
            match result {
                Ok(false) => {}
                Ok(true) => {
                    let pending = self.pending.swap_remove(index);
                    ready.push(pending.into_prepared());
                }
                Err(error) => {
                    let pending = self.pending.swap_remove(index);
                    failed.push((pending.job, error));
                }
            }
        }
        (ready, failed)
    }
}

fn secondary_refresh_parallelism(entries: usize) -> usize {
    entries.clamp(1, SECONDARY_REFRESH_MAX_IN_FLIGHT)
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct SecondarySoaProbeKey {
    /// The response is matched by this socket and the query ID.
    source: std::net::SocketAddr,
    id: u16,
}

struct PendingSecondarySoa {
    job: SecondaryRefreshJob,
    origin: onetdns_proto::Name,
    tsig_key: Option<usize>,
    request_mac: Option<Vec<u8>>,
    deadline: std::time::Instant,
}

struct SecondarySoaProbeResult {
    job: SecondaryRefreshJob,
    result: Result<u32, String>,
}

/// Asks the serials of many zones over a few sockets; a socket per zone would run out of handles
/// with many zones.
struct SecondarySoaProber {
    ipv4: Option<std::net::UdpSocket>,
    ipv6: Option<std::net::UdpSocket>,
    pending: std::collections::HashMap<SecondarySoaProbeKey, PendingSecondarySoa>,
    /// So one zone is not asked twice at once.
    pending_origins: std::collections::HashSet<String>,
}

impl SecondarySoaProber {
    fn new(entries: &[XferEntry]) -> std::io::Result<Self> {
        let ipv4 = if entries.iter().any(|entry| entry.primary.is_ipv4()) {
            let socket = onetdns_core::udp::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
            socket.set_nonblocking(true)?;
            Some(socket)
        } else {
            None
        };
        let ipv6 = if entries.iter().any(|entry| entry.primary.is_ipv6()) {
            let socket = onetdns_core::udp::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))?;
            socket.set_nonblocking(true)?;
            Some(socket)
        } else {
            None
        };
        Ok(Self {
            ipv4,
            ipv6,
            pending: std::collections::HashMap::new(),
            pending_origins: std::collections::HashSet::new(),
        })
    }

    fn contains(&self, origin: &str) -> bool {
        self.pending_origins.contains(origin)
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn retain_current(&mut self, entries: &[XferEntry]) {
        self.pending
            .retain(|_, probe| secondary_entry_is_current(entries, &probe.job));
        self.pending_origins.clear();
        self.pending_origins.extend(
            self.pending
                .values()
                .map(|probe| probe.job.entry.origin.clone()),
        );
    }

    fn start(
        &mut self,
        job: SecondaryRefreshJob,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        timeout: Duration,
    ) -> Result<(), Box<(SecondaryRefreshJob, String)>> {
        use onetdns_proto::RecordType;

        if self.contains(&job.entry.origin) {
            return Err(Box::new((
                job,
                "An SOA query for the same zone is already in progress".to_string(),
            )));
        }
        let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
            Ok(origin) => origin,
            Err(_) => {
                return Err(Box::new((
                    job,
                    "Invalid secondary DNS zone name".to_string(),
                )));
            }
        };
        let tsig_key = tsig_for_secondary(tsig_keys, &job.entry.tsig_key)
            .and_then(|wanted| tsig_keys.iter().position(|key| std::ptr::eq(key, wanted)));
        if job.entry.tsig_key.is_some() && tsig_key.is_none() {
            return Err(Box::new((
                job,
                "Could not find the TSIG key for the secondary zone".to_string(),
            )));
        }
        let source = std::net::SocketAddr::new(job.entry.primary, job.entry.port);
        let start_id = u16::from_ne_bytes(onetdns_core::random_array());
        let Some(key) = (0..=u16::MAX).find_map(|offset| {
            let key = SecondarySoaProbeKey {
                source,
                id: start_id.wrapping_add(offset),
            };
            (!self.pending.contains_key(&key)).then_some(key)
        }) else {
            return Err(Box::new((
                job,
                "No free SOA query IDs left for this primary".to_string(),
            )));
        };

        let mut query = onetdns_proto::Message::query(key.id, origin.clone(), RecordType::SOA);
        query.header.recursion_desired = false;
        let request_mac = match tsig_key.and_then(|index| tsig_keys.get(index)) {
            Some(tsig_key) => {
                match onetdns_dnssec::tsig::sign_message(&mut query, tsig_key, unix_now(), None) {
                    Ok(mac) => Some(mac),
                    Err(error) => {
                        return Err(Box::new((
                            job,
                            format!("Could not sign the SOA query: {error}"),
                        )));
                    }
                }
            }
            None => None,
        };
        let wire = match query.try_encode() {
            Ok(wire) => wire,
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("Could not encode the SOA query: {error}"),
                )));
            }
        };
        let socket = if source.is_ipv4() {
            self.ipv4.as_ref()
        } else {
            self.ipv6.as_ref()
        };
        let Some(socket) = socket else {
            return Err(Box::new((job, "No UDP socket for SOA queries".to_string())));
        };
        match socket.send_to(&wire, source) {
            Ok(written) if written == wire.len() => {}
            Ok(_) => {
                return Err(Box::new((
                    job,
                    "SOA UDP query was only partly sent".to_string(),
                )));
            }
            Err(error) => {
                return Err(Box::new((
                    job,
                    format!("Could not send the SOA query: {error}"),
                )));
            }
        }
        self.pending_origins.insert(job.entry.origin.clone());
        self.pending.insert(
            key,
            PendingSecondarySoa {
                job,
                origin,
                tsig_key,
                request_mac,
                deadline: std::time::Instant::now() + timeout,
            },
        );
        Ok(())
    }

    fn receive_socket(
        socket: &std::net::UdpSocket,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
        pending: &mut std::collections::HashMap<SecondarySoaProbeKey, PendingSecondarySoa>,
        pending_origins: &mut std::collections::HashSet<String>,
        completed: &mut Vec<SecondarySoaProbeResult>,
    ) {
        let mut wire = [0u8; 65_535];
        loop {
            let (length, source) = match socket.recv_from(&mut wire) {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    onetdns_core::warn!(event = "authority.secondary_soa_receive_failed", %error, "Failed to read from the secondary SOA response socket");
                    break;
                }
            };
            if length < 2 {
                continue;
            }
            let id = u16::from_be_bytes([wire[0], wire[1]]);
            let key = SecondarySoaProbeKey { source, id };
            let Some(probe) = pending.get(&key) else {
                continue;
            };
            let message =
                if let Some(tsig_key) = probe.tsig_key.and_then(|index| tsig_keys.get(index)) {
                    onetdns_dnssec::tsig::verify_wire(
                        &wire[..length],
                        tsig_key,
                        unix_now(),
                        probe.request_mac.as_deref(),
                    )
                    .ok()
                    .and_then(|(stripped, _)| onetdns_proto::Message::parse(&stripped).ok())
                } else {
                    onetdns_proto::Message::parse(&wire[..length]).ok()
                };
            let Some(message) = message else { continue };
            if !soa_response_matches_question(&message, key.id, &probe.origin) {
                continue;
            }
            let result = soa_serial_from_response(&message, key.id, &probe.origin);
            let Some(probe) = pending.remove(&key) else {
                continue;
            };
            pending_origins.remove(&probe.job.entry.origin);
            completed.push(SecondarySoaProbeResult {
                job: probe.job,
                result,
            });
        }
    }

    /// Collects responses and drops queries past their deadline.
    fn poll(
        &mut self,
        tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    ) -> Vec<SecondarySoaProbeResult> {
        let mut completed = Vec::new();
        if let Some(socket) = &self.ipv4 {
            Self::receive_socket(
                socket,
                tsig_keys,
                &mut self.pending,
                &mut self.pending_origins,
                &mut completed,
            );
        }
        if let Some(socket) = &self.ipv6 {
            Self::receive_socket(
                socket,
                tsig_keys,
                &mut self.pending,
                &mut self.pending_origins,
                &mut completed,
            );
        }
        let now = std::time::Instant::now();
        let expired: Vec<SecondarySoaProbeKey> = self
            .pending
            .iter()
            .filter_map(|(key, probe)| (probe.deadline <= now).then_some(*key))
            .collect();
        for key in expired {
            if let Some(probe) = self.pending.remove(&key) {
                self.pending_origins.remove(&probe.job.entry.origin);
                completed.push(SecondarySoaProbeResult {
                    job: probe.job,
                    result: Err("SOA query timed out".to_string()),
                });
            }
        }
        completed
    }
}

fn run_prepared_secondary_transfer(
    entry: &XferEntry,
    current: Option<&onetdns_authority::Zone>,
    remote_serial: u32,
    tsig_keys: &[onetdns_dnssec::tsig::TsigKey],
    prepared: PreparedXfrIo,
    _reservation: XfrBufferReservation,
) -> Result<SecondaryXferOutcome, String> {
    let origin = onetdns_proto::Name::from_str(&entry.origin)
        .map_err(|_| "Invalid secondary DNS zone name".to_string())?;
    let key = tsig_for_secondary(tsig_keys, &entry.tsig_key);
    if entry.tsig_key.is_some() && key.is_none() {
        return Err("Could not find the TSIG key for the secondary zone".to_string());
    }
    if entry.is_catalog {
        let records = axfr_fetch_prepared(&origin, key, prepared)?;
        return Ok(SecondaryXferOutcome::Catalog {
            serial: remote_serial,
            members: catalog_members(&records, &entry.origin),
        });
    }

    if let Some(current) = current {
        return match ixfr_fetch_prepared(current, key, prepared) {
            Ok(IxfrFetchResult::Unchanged) => Ok(SecondaryXferOutcome::UpToDate),
            Ok(IxfrFetchResult::Incremental(zone)) => Ok(SecondaryXferOutcome::Zone(
                Box::new(zone),
                SecondaryXferKind::Ixfr,
            )),
            Ok(IxfrFetchResult::Full(zone)) => Ok(SecondaryXferOutcome::Zone(
                Box::new(zone),
                SecondaryXferKind::IxfrFull,
            )),
            Err(error) if xfr_error_is_notimp(&error) => {
                Ok(SecondaryXferOutcome::NeedsFullTransfer { remote_serial })
            }
            Err(error) => Err(error),
        };
    }

    let records = axfr_fetch_prepared(&origin, key, prepared)?;
    let zone = onetdns_authority::Zone::from_records(records)
        .map_err(|error| format!("Invalid AXFR zone data: {error}"))?;
    Ok(SecondaryXferOutcome::Zone(
        Box::new(zone),
        SecondaryXferKind::Axfr,
    ))
}

fn secondary_needs_transfer(job: &SecondaryRefreshJob, remote_serial: u32) -> bool {
    job.current_serial
        .is_none_or(|serial| serial_gt(remote_serial, serial))
}

fn secondary_entry_is_current(entries: &[XferEntry], job: &SecondaryRefreshJob) -> bool {
    entries.iter().any(|entry| entry == &job.entry)
}

#[allow(clippy::too_many_arguments)]
/// Installs the result and schedules the next refresh. ZONEMD is checked as for zones read from
/// files; otherwise a transferred secondary would be served tampered even with `zonemd_check` on.
fn complete_secondary_refresh(
    job: SecondaryRefreshJob,
    result: Result<SecondaryXferOutcome, String>,
    entries: &mut Vec<XferEntry>,
    sched: &mut std::collections::HashMap<String, (u64, u64)>,
    cat_state: &mut std::collections::HashMap<String, (u32, Vec<String>)>,
    ready: &mut std::collections::VecDeque<(SecondaryRefreshJob, u32)>,
    xfr_origins: &mut std::collections::HashSet<String>,
    urgent: &mut std::collections::HashSet<String>,
    store: &onetdns_core::ArcSwap<onetdns_authority::ZoneStore>,
    journal: &ZoneJournals,
    notify: &NotifySender,
    cfg: &Config,
) {
    xfr_origins.remove(&job.entry.origin);
    if !secondary_entry_is_current(entries, &job) {
        return;
    }

    if let Ok(SecondaryXferOutcome::NeedsFullTransfer { remote_serial }) = &result {
        let remote_serial = *remote_serial;
        if !job.force_axfr {
            onetdns_core::info!(event = "authority.secondary_ixfr_notimp", origin = %job.entry.origin, primary = %job.entry.primary, "Primary does not support IXFR; falling back to AXFR");
            let mut job = job;
            job.force_axfr = true;
            xfr_origins.insert(job.entry.origin.clone());
            if job.priority {
                ready.push_front((job, remote_serial));
            } else {
                ready.push_back((job, remote_serial));
            }
            return;
        }
    }
    let completed = unix_now();
    let mut ok = false;
    let mut refresh = job.refresh;
    match result {
        Ok(SecondaryXferOutcome::UpToDate) => ok = true,
        Ok(SecondaryXferOutcome::Zone(zone, _)) if !zonemd_ok(&zone, ZonemdPolicy::of(cfg)) => {
            onetdns_core::warn!(event = "authority.secondary_zonemd_rejected", origin = %job.entry.origin, serial = zone.soa().serial, "Transferred secondary zone failed ZONEMD verification and was not applied; retrying next refresh");
        }
        Ok(SecondaryXferOutcome::Zone(zone, kind)) => {
            refresh = zone.soa().refresh as u64;
            let serial = zone.soa().serial;
            let zone_origin = zone.origin().clone();
            let persisted = job.entry.file.as_ref().is_none_or(|path| {
                match atomic_write(path, zone.to_master_file().as_bytes()) {
                    Ok(()) => true,
                    Err(error) => {
                        onetdns_core::warn!(event = "authority.secondary_cache_save_failed", origin = %job.entry.origin, path = %path.display(), %error, "Could not save the secondary zone cache; not applying the new data");
                        false
                    }
                }
            });
            if persisted {
                match kind {
                    SecondaryXferKind::Axfr => {
                        onetdns_core::info!(event = "authority.secondary_axfr_done", origin = %job.entry.origin, serial, primary = %job.entry.primary, "Applied full transfer of secondary zone")
                    }
                    SecondaryXferKind::Ixfr => {
                        onetdns_core::info!(event = "authority.secondary_ixfr_applied", origin = %job.entry.origin, serial, "Applied incremental update of secondary zone")
                    }
                    SecondaryXferKind::IxfrFull => {
                        onetdns_core::info!(event = "authority.secondary_ixfr_fallback_axfr", origin = %job.entry.origin, serial, "IXFR response was a full transfer; handled it as AXFR")
                    }
                }
                {
                    let mut journals = journal.lock_recover();
                    journals.remove(&zone_origin.canonical_key());
                    swap_zone(store, &mut journals, *zone);
                }
                notify.enqueue(&zone_origin, serial);
                ok = true;
            }
        }
        Ok(SecondaryXferOutcome::Catalog { serial, members }) => {
            let old = cat_state
                .get(&job.entry.origin)
                .map(|(_, members)| members.clone())
                .unwrap_or_default();
            for gone in old.iter().filter(|member| !members.contains(member)) {
                entries.retain(|entry| entry.origin != *gone);
                sched.remove(gone);
                urgent.remove(gone);
                xfr_origins.remove(gone);
                ready.retain(|(ready_job, _)| ready_job.entry.origin != *gone);
                if let Ok(origin) = onetdns_proto::Name::from_str(gone) {
                    remove_zone(store, &mut journal.lock_recover(), &origin);
                }
                onetdns_core::info!(event = "authority.catalog_zone_removed", catalog = %job.entry.origin, member = %gone, "Removed a DNS zone that left the catalog");
            }
            for added in members.iter().filter(|member| !old.contains(member)) {
                if entries.iter().any(|entry| entry.origin == *added) {
                    continue;
                }
                entries.push(XferEntry {
                    origin: added.clone(),
                    file: None,
                    primary: job.entry.primary,
                    port: job.entry.port,
                    tsig_key: job.entry.tsig_key.clone(),
                    is_catalog: false,
                });
                sched.insert(added.clone(), (completed, completed));
                onetdns_core::info!(event = "authority.catalog_zone_added", catalog = %job.entry.origin, member = %added, "Found a new DNS zone in the catalog");
            }
            cat_state.insert(job.entry.origin.clone(), (serial, members));
            ok = true;
        }
        Ok(SecondaryXferOutcome::NeedsFullTransfer { .. }) => {
            onetdns_core::warn!(event = "authority.secondary_axfr_refused", origin = %job.entry.origin, primary = %job.entry.primary, "AXFR retry was also refused with NOTIMP; retrying next refresh");
        }
        Err(error) => {
            let event = if job.entry.is_catalog {
                "authority.catalog_axfr_failed"
            } else {
                "authority.secondary_transfer_failed"
            };
            onetdns_core::warn!(event = event, origin = %job.entry.origin, %error, "Secondary zone transfer failed; retrying next refresh");
        }
    }

    if ok {
        if let Some(path) = &job.entry.file {
            if let Err(error) = mark_secondary_refresh(path, completed) {
                onetdns_core::warn!(event = "authority.secondary_state_save_failed", origin = %job.entry.origin, path = %path.display(), %error, "Could not save secondary zone refresh state");
            }
        }
    } else if job.had_zone && completed.saturating_sub(job.last_ok) > job.expire {
        if let Ok(origin) = onetdns_proto::Name::from_str(&job.entry.origin) {
            remove_zone(store, &mut journal.lock_recover(), &origin);
        }
        onetdns_core::warn!(event = "authority.secondary_expired", origin = %job.entry.origin, "Secondary zone expired; no longer answering for it");
    }
    let next_check = if urgent.contains(&job.entry.origin) {
        completed
    } else {
        let delay = if ok {
            refresh.clamp(15, 86_400)
        } else {
            job.retry.clamp(15, 3_600)
        };
        completed.saturating_add(delay)
    };
    let last_ok = if ok { completed } else { job.last_ok };
    sched.insert(job.entry.origin, (next_check, last_ok));
}

pub(crate) fn spawn_secondary_refresh(
    cfg: Config,
    tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: ZoneJournals,
    kick: Arc<native::NotifyKick>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn_secondary_refresh_with_timeout(
        cfg,
        tsig_keys,
        store,
        journal,
        kick,
        notify,
        shutdown,
        Duration::from_secs(10),
    )
}

/// Stops the previous task, waiting for a transfer in progress, and starts one on the new config;
/// with no secondaries or catalogs, only stops.
pub(crate) fn refresh_restart(
    jobs: Arc<EdgeServices>,
    zones: &ZoneState,
    kick: Arc<native::NotifyKick>,
) -> SecondaryRestart {
    let store = zones.store.clone();
    let journal = zones.journal.clone();
    let sender = zones.notify.clone();
    Arc::new(move |next: &Config| -> Result<(), String> {
        jobs.retire_all();
        let stop = jobs.restart_all();
        if next.secondary.is_empty() && next.catalog.is_empty() {
            return Ok(());
        }
        let keys = build_tsig_keys(next)?;
        let thread = spawn_secondary_refresh(
            next.clone(),
            keys,
            store.clone(),
            journal.clone(),
            kick.clone(),
            sender.clone(),
            stop,
        )
        .map_err(|error| format!("Could not start the secondary zone refresh task: {error}"))?;
        jobs.keep("secondary-refresh", thread);
        Ok(())
    })
}

/// Asks the serial first and transfers only when it is newer. Connect through the closing SOA runs
/// without threads, so a slow or stalled peer cannot hold a worker.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_secondary_refresh_with_timeout(
    cfg: Config,
    tsig_keys: Vec<onetdns_dnssec::tsig::TsigKey>,
    store: Arc<onetdns_core::ArcSwap<onetdns_authority::ZoneStore>>,
    journal: ZoneJournals,
    kick: Arc<native::NotifyKick>,
    notify: NotifySender,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    timeout: Duration,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let entries: Vec<XferEntry> = cfg
        .secondary
        .iter()
        .filter_map(|secondary| XferEntry::from_cfg(secondary, false))
        .chain(
            cfg.catalog
                .iter()
                .filter_map(|catalog| XferEntry::from_cfg(catalog, true)),
        )
        .collect();
    let prober = SecondarySoaProber::new(&entries)?;
    std::thread::Builder::new()
        .name("secondary-refresh".into())
        .spawn(move || {
        use std::collections::{HashMap, HashSet};
        let mut entries = entries;
        let mut prober = prober;
        let mut sched: HashMap<String, (u64, u64)> = HashMap::new();
        let mut cat_state: HashMap<String, (u32, Vec<String>)> = HashMap::new();
        let mut active: Vec<ActiveSecondaryXfer> = Vec::new();
        let mut admission = SecondaryXfrAdmission::default();
        let mut prepared = std::collections::VecDeque::<PreparedSecondaryXfr>::new();
        let mut ready: std::collections::VecDeque<(SecondaryRefreshJob, u32)> =
            std::collections::VecDeque::new();
        let mut xfr_origins: HashSet<String> = HashSet::new();
        let mut urgent: HashSet<String> = HashSet::new();
        let tsig_keys = Arc::new(tsig_keys);
        let now0 = unix_now();
        for e in &entries {
            let last_ok = e
                .file
                .as_ref()
                .and_then(|path| secondary_last_refresh(path))
                .unwrap_or(now0);
            sched.insert(e.origin.clone(), (now0, last_ok));
        }
        let max_in_flight = secondary_refresh_parallelism(entries.len());
        onetdns_core::info!(event = "authority.secondary_refresh_started", zones = entries.len(), parser_max_in_flight = max_in_flight, admission_max_in_flight = SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT, "Started secondary zone refresh with bounded parallelism");

        loop {
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let mut completed = Vec::<(
                SecondaryRefreshJob,
                Result<SecondaryXferOutcome, String>,
            )>::new();
            for probe in prober.poll(&tsig_keys) {
                let mut job = probe.job;
                job.priority |= urgent.contains(&job.entry.origin);
                match probe.result {
                    Ok(remote_serial)
                        if secondary_entry_is_current(&entries, &job)
                            && secondary_needs_transfer(&job, remote_serial) =>
                    {
                        xfr_origins.insert(job.entry.origin.clone());
                        if job.priority {
                            ready.push_front((job, remote_serial));
                        } else {
                            ready.push_back((job, remote_serial));
                        }
                    }
                    Ok(_) => completed.push((job, Ok(SecondaryXferOutcome::UpToDate))),
                    Err(error) => completed.push((job, Err(error))),
                }
            }

            let (admitted, failed) = admission.poll();
            for transfer in admitted {
                if transfer.job.priority || urgent.contains(&transfer.job.entry.origin) {
                    prepared.push_front(transfer);
                } else {
                    prepared.push_back(transfer);
                }
            }
            completed.extend(
                failed
                    .into_iter()
                    .map(|(job, error)| (job, Err(error))),
            );

            let mut index = active.len();
            while index > 0 {
                index -= 1;
                if !active[index].handle.is_finished() {
                    continue;
                }
                let finished = active.swap_remove(index);
                let result = finished
                    .handle
                    .join()
                    .map_err(|_| "The secondary zone transfer task panicked".to_string())
                    .and_then(|result| result);
                completed.push((finished.job, result));
            }

            let now = unix_now();
            let current_store = store.load();
            for entry in entries.clone() {
                let due = sched
                    .get(&entry.origin)
                    .is_some_and(|(next_check, _)| *next_check <= now);
                let busy = prober.contains(&entry.origin)
                    || xfr_origins.contains(&entry.origin)
                    || active
                        .iter()
                        .any(|active| active.job.entry.origin == entry.origin);
                if !due || busy {
                    continue;
                }
                let Some((_, last_ok)) = sched.get(&entry.origin).copied() else {
                    continue;
                };
                let origin = match onetdns_proto::Name::from_str(&entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        sched.insert(entry.origin.clone(), (now.saturating_add(3_600), last_ok));
                        continue;
                    }
                };
                let current = current_store.zone_exact(&origin);
                let (refresh, retry, expire) = current
                    .as_ref()
                    .map(|zone| {
                        (
                            zone.soa().refresh as u64,
                            zone.soa().retry as u64,
                            zone.soa().expire as u64,
                        )
                    })
                    .unwrap_or((300, 60, 86_400));
                let catalog_serial = cat_state.get(&entry.origin).map(|(serial, _)| *serial);
                let current_serial = if entry.is_catalog {
                    catalog_serial
                } else {
                    current.map(|zone| zone.soa().serial)
                };
                let initial = current_serial.is_none();
                let priority = urgent.remove(&entry.origin) || initial;
                let job = SecondaryRefreshJob {
                    entry,
                    current_serial,
                    had_zone: current.is_some(),
                    last_ok,
                    refresh,
                    retry,
                    expire,
                    priority,
                    force_axfr: false,
                };
                if let Err(error) = prober.start(job, &tsig_keys, timeout) {
                    let (job, error) = *error;
                    completed.push((job, Err(error)));
                }
            }
            drop(current_store);

            for (job, result) in completed {
                complete_secondary_refresh(
                    job,
                    result,
                    &mut entries,
                    &mut sched,
                    &mut cat_state,
                    &mut ready,
                    &mut xfr_origins,
                    &mut urgent,
                    &store,
                    &journal,
                    &notify,
                    &cfg,
                );
            }
            prober.retain_current(&entries);
            admission.retain_current(&entries);
            prepared.retain(|transfer| secondary_entry_is_current(&entries, &transfer.job));

            loop {
                let admission_load = admission.len().saturating_add(prepared.len());
                if admission_load >= SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT || ready.is_empty() {
                    break;
                }
                let background_limit = SECONDARY_XFR_ADMISSION_MAX_IN_FLIGHT - 1;
                let candidate = ready
                    .iter()
                    .position(|(job, _)| job.priority || urgent.contains(&job.entry.origin))
                    .or_else(|| (admission_load < background_limit).then_some(0));
                let Some(candidate) = candidate else { break };
                let Some((mut job, remote_serial)) = ready.remove(candidate) else {
                    continue;
                };
                if !secondary_entry_is_current(&entries, &job) {
                    xfr_origins.remove(&job.entry.origin);
                    continue;
                }
                job.priority |= urgent.contains(&job.entry.origin);
                let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        complete_secondary_refresh(
                            job,
                            Err("Invalid secondary DNS zone name".to_string()),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &journal,
                            &notify,
                            &cfg,
                        );
                        continue;
                    }
                };
                let current = if job.entry.is_catalog {
                    None
                } else {
                    store.load().zone_exact(&origin).cloned()
                };
                job.current_serial = if job.entry.is_catalog {
                    cat_state
                        .get(&job.entry.origin)
                        .map(|(serial, _)| *serial)
                } else {
                    current.as_ref().map(|zone| zone.soa().serial)
                };
                job.had_zone = current.is_some();
                if let Some(zone) = &current {
                    job.refresh = zone.soa().refresh as u64;
                    job.retry = zone.soa().retry as u64;
                    job.expire = zone.soa().expire as u64;
                }
                if !secondary_needs_transfer(&job, remote_serial) {
                    complete_secondary_refresh(
                        job,
                        Ok(SecondaryXferOutcome::UpToDate),
                        &mut entries,
                        &mut sched,
                        &mut cat_state,
                        &mut ready,
                        &mut xfr_origins,
                        &mut urgent,
                        &store,
                        &journal,
                        &notify,
                        &cfg,
                    );
                    continue;
                }
                if let Err(error) =
                    admission.start(job, remote_serial, current, &tsig_keys, timeout)
                {
                    let (job, error) = *error;
                    complete_secondary_refresh(
                        job,
                        Err(error),
                        &mut entries,
                        &mut sched,
                        &mut cat_state,
                        &mut ready,
                        &mut xfr_origins,
                        &mut urgent,
                        &store,
                        &journal,
                        &notify,
                        &cfg,
                    );
                }
            }

            let max_active = secondary_refresh_parallelism(entries.len());
            loop {
                if active.len() >= max_active || prepared.is_empty() {
                    break;
                }
                let background_limit = if max_active > 1 { max_active - 1 } else { 1 };
                let candidate = prepared
                    .iter()
                    .position(|transfer| {
                        transfer.job.priority || urgent.contains(&transfer.job.entry.origin)
                    })
                    .or_else(|| (active.len() < background_limit).then_some(0));
                let Some(candidate) = candidate else { break };
                let Some(transfer) = prepared.remove(candidate) else {
                    continue;
                };
                let mut job = transfer.job;
                if !secondary_entry_is_current(&entries, &job) {
                    xfr_origins.remove(&job.entry.origin);
                    continue;
                }
                job.priority |= urgent.contains(&job.entry.origin);
                let origin = match onetdns_proto::Name::from_str(&job.entry.origin) {
                    Ok(origin) => origin,
                    Err(_) => {
                        complete_secondary_refresh(
                            job,
                            Err("Invalid secondary DNS zone name".to_string()),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &journal,
                            &notify,
                            &cfg,
                        );
                        continue;
                    }
                };
                let latest_current = if job.entry.is_catalog {
                    None
                } else {
                    store.load().zone_exact(&origin).cloned()
                };
                let latest_serial = if job.entry.is_catalog {
                    cat_state
                        .get(&job.entry.origin)
                        .map(|(serial, _)| *serial)
                } else {
                    latest_current.as_ref().map(|zone| zone.soa().serial)
                };
                if latest_serial != job.current_serial {
                    job.current_serial = latest_serial;
                    job.had_zone = latest_current.is_some();
                    if let Some(zone) = &latest_current {
                        job.refresh = zone.soa().refresh as u64;
                        job.retry = zone.soa().retry as u64;
                        job.expire = zone.soa().expire as u64;
                    }
                    if secondary_needs_transfer(&job, transfer.remote_serial) {
                        if job.priority {
                            ready.push_front((job, transfer.remote_serial));
                        } else {
                            ready.push_back((job, transfer.remote_serial));
                        }
                    } else {
                        complete_secondary_refresh(
                            job,
                            Ok(SecondaryXferOutcome::UpToDate),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &journal,
                            &notify,
                            &cfg,
                        );
                    }
                    continue;
                }
                let task_entry = job.entry.clone();
                let task_keys = tsig_keys.clone();
                let handle = std::thread::Builder::new()
                    .name("secondary-xfer".into())
                    .stack_size(SECONDARY_XFER_STACK_BYTES)
                    .spawn(move || {
                        run_prepared_secondary_transfer(
                            &task_entry,
                            transfer.current.as_ref(),
                            transfer.remote_serial,
                            &task_keys,
                            transfer.io,
                            transfer.reservation,
                        )
                    });
                match handle {
                    Ok(handle) => {
                        active.push(ActiveSecondaryXfer { job, handle });
                    }
                    Err(error) => {
                        let origin = job.entry.origin.clone();
                        complete_secondary_refresh(
                            job,
                            Err(format!("Could not start the secondary DNS zone transfer task: {error}")),
                            &mut entries,
                            &mut sched,
                            &mut cat_state,
                            &mut ready,
                            &mut xfr_origins,
                            &mut urgent,
                            &store,
                            &journal,
                            &notify,
                            &cfg,
                        );
                        onetdns_core::warn!(event = "authority.secondary_worker_spawn_failed", origin = %origin, %error, "Could not start the secondary zone transfer task");
                        break;
                    }
                }
            }

            let wait = if active.is_empty()
                && admission.len() == 0
                && prepared.is_empty()
                && ready.is_empty()
                && prober.len() == 0
            {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(20)
            };
            let now = unix_now();
            for origin in kick.wait_take(wait) {
                if let Some(schedule) = sched.get_mut(&origin) {
                    schedule.0 = now;
                    urgent.insert(origin);
                }
            }
        }

        for transfer in active {
            let _ = transfer.handle.join();
        }
        })
}

fn soa_serial_from_response(
    response: &onetdns_proto::Message,
    request_id: u16,
    origin: &onetdns_proto::Name,
) -> Result<u32, String> {
    use onetdns_proto::{DnsClass, RData, RecordType, ResponseCode};

    if !soa_response_matches_question(response, request_id, origin)
        || !response.header.response
        || response.header.opcode != 0
        || response.header.rcode != ResponseCode::NoError.0
        || !response.header.authoritative
        || response.header.truncated
    {
        return Err("SOA response header or question does not match the request".to_string());
    }
    let mut serials = response.answers.iter().filter_map(|record| {
        if record.name.eq_ignore_case(origin)
            && record.rtype == RecordType::SOA
            && record.class == DnsClass::IN
        {
            match &record.rdata {
                RData::Soa(soa) => Some(soa.serial),
                _ => None,
            }
        } else {
            None
        }
    });
    let serial = serials
        .next()
        .ok_or_else(|| "SOA response has no zone apex SOA".to_string())?;
    if serials.next().is_some() {
        return Err("SOA response has a duplicate apex SOA".to_string());
    }
    Ok(serial)
}

/// Otherwise a serial injected by someone else would be trusted.
fn soa_response_matches_question(
    response: &onetdns_proto::Message,
    request_id: u16,
    origin: &onetdns_proto::Name,
) -> bool {
    use onetdns_proto::{DnsClass, RecordType};

    response.header.id == request_id
        && response.questions.len() == 1
        && response.questions[0].name.eq_ignore_case(origin)
        && response.questions[0].qtype == RecordType::SOA
        && response.questions[0].qclass == DnsClass::IN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{secondary_xfr_admission_test_server, tcp_udp_test_listeners};
    use std::sync::Arc;
    use std::time::Duration;

    use onetdns_config::Config;

    use crate::atomic_file::atomic_write;
    use crate::notify::NotifySender;
    use crate::{native, unix_now};

    /// Uses the real nonblocking listener; a test-only receive path would test only itself and
    /// leave the real listener's deadlines and checks untested.
    fn admitted_xfr(
        address: std::net::SocketAddr,
        origin: &str,
        current: Option<onetdns_authority::Zone>,
        timeout: Duration,
    ) -> Result<PreparedXfrIo, String> {
        let job = SecondaryRefreshJob {
            entry: XferEntry {
                origin: origin.to_string(),
                file: None,
                primary: address.ip(),
                port: address.port(),
                tsig_key: None,
                is_catalog: false,
            },
            current_serial: None,
            had_zone: current.is_some(),
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr: false,
        };
        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job, 1, current, &[], timeout)
            .map_err(|error| error.1.clone())?;
        let limit = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (mut ready, failed) = admission.poll();
            if let Some((_, error)) = failed.into_iter().next() {
                return Err(error);
            }
            if let Some(ready) = ready.pop() {
                return Ok(ready.io);
            }
            assert!(
                std::time::Instant::now() < limit,
                "전송이 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn axfr_fetch(
        address: std::net::SocketAddr,
        origin: &onetdns_proto::Name,
        timeout: Duration,
    ) -> Result<Vec<onetdns_proto::Record>, String> {
        let io = admitted_xfr(address, &origin.to_ascii_lower(), None, timeout)?;
        axfr_fetch_prepared(origin, None, io)
    }

    fn ixfr_fetch(
        address: std::net::SocketAddr,
        current: &onetdns_authority::Zone,
        timeout: Duration,
    ) -> Result<IxfrFetchResult, String> {
        let io = admitted_xfr(
            address,
            &current.origin().to_ascii_lower(),
            Some(current.clone()),
            timeout,
        )?;
        ixfr_fetch_prepared(current, None, io)
    }

    /// Uses the real serial prober.
    fn probe_soa_serial(
        address: std::net::SocketAddr,
        origin: &str,
        key: Option<onetdns_dnssec::tsig::TsigKey>,
    ) -> Result<u32, String> {
        let entry = XferEntry {
            origin: origin.to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: key.as_ref().map(|key| key.name.to_ascii_lower()),
            is_catalog: false,
        };
        let keys: Vec<_> = key.into_iter().collect();
        let mut prober = SecondarySoaProber::new(std::slice::from_ref(&entry)).unwrap();
        prober
            .start(
                SecondaryRefreshJob {
                    entry,
                    current_serial: None,
                    had_zone: false,
                    last_ok: unix_now(),
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    priority: true,
                    force_axfr: false,
                },
                &keys,
                Duration::from_secs(1),
            )
            .map_err(|error| error.1.clone())?;
        let limit = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(result) = prober.poll(&keys).pop() {
                return result.result;
            }
            assert!(
                std::time::Instant::now() < limit,
                "시리얼 확인이 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Never panics on socket errors: deadline tests make the client give up and close first, and
    /// the reset that arrives here is the normal path. Treating it as fatal would make tests fail
    /// only now and then under parallel load, indistinguishable from a real regression.
    ///
    /// `complete` sends the closing SOA; `slow` drips the response a byte at a time. Returns the
    /// listen address and the server thread.
    fn axfr_test_server(
        complete: bool,
        slow: bool,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let _ = (|| -> std::io::Result<()> {
                let (mut stream, _) = listener.accept()?;
                let mut length = [0u8; 2];
                stream.read_exact(&mut length)?;
                let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
                stream.read_exact(&mut request_wire)?;
                let request = onetdns_proto::Message::parse(&request_wire).unwrap();
                let origin = request.questions[0].name.clone();
                let mut response = onetdns_proto::Message::default();
                response.header.id = request.header.id;
                response.header.response = true;
                response.header.authoritative = true;
                response.questions = request.questions;
                let soa = onetdns_proto::Record::new(
                    origin,
                    60,
                    onetdns_proto::RData::soa(onetdns_proto::Soa {
                        mname: onetdns_proto::Name::from_str("ns1.example.test").unwrap(),
                        rname: onetdns_proto::Name::from_str("hostmaster.example.test").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86_400,
                        minimum: 60,
                    }),
                );
                response.answers.push(soa.clone());
                if complete {
                    response.answers.push(soa);
                }
                let wire = response.try_encode().unwrap();
                stream.write_all(&(wire.len() as u16).to_be_bytes())?;
                if slow {
                    for byte in wire {
                        if stream.write_all(&[byte]).is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                } else {
                    stream.write_all(&wire)?;
                }
                Ok(())
            })();
        });
        (address, server)
    }

    fn xfr_record_server(
        records: Vec<onetdns_proto::Record>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers = records;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&wire).unwrap();
        });
        (address, server)
    }

    /// Sends a valid transfer at a limited throughput.
    fn xfr_throttled_record_server(
        records: Vec<onetdns_proto::Record>,
        chunk_bytes: usize,
        pause: Duration,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers = records;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            for chunk in wire.chunks(chunk_bytes) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
                std::thread::sleep(pause);
            }
        });
        (address, server)
    }

    #[test]
    /// Accepting it would use a transfer cut midway as a whole zone.
    fn axfr_rejects_transfer_without_closing_soa() {
        let (address, server) = axfr_test_server(false, false);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let error = axfr_fetch(address, &origin, Duration::from_secs(1)).unwrap_err();
        assert!(
            error.contains("closing") && error.contains("SOA"),
            "{error}"
        );
        server.join().unwrap();
    }

    #[test]
    fn axfr_slow_drip_cannot_extend_transfer_deadline() {
        let (address, server) = axfr_test_server(false, true);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let started = std::time::Instant::now();
        assert!(axfr_fetch(address, &origin, Duration::from_millis(120)).is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    /// Exactly the time earned by the bytes read at the minimum throughput.
    fn xfr_progress_deadline_credits_only_received_bytes() {
        let started = std::time::Instant::now();
        let mut deadline = XfrProgressDeadline::new(started, Duration::from_millis(120));
        assert!(deadline.expired(started + Duration::from_millis(120)));

        deadline.record_response_bytes(SECONDARY_XFR_MIN_PROGRESS_BYTES_PER_SEC as usize);
        assert!(!deadline.expired(started + Duration::from_millis(1_119)));
        assert!(deadline.expired(started + Duration::from_millis(1_120)));
    }

    #[test]
    /// Early in a transfer no bytes are credited, so the budget is nearly just the base time, which
    /// is set long enough for a late first byte on a loaded machine. The server sends at several
    /// times the throughput floor, so the budget stays ahead of elapsed time even when sleeps
    /// stretch. The record count makes the transfer outlast the base time while keeping each
    /// message under 65535 bytes.
    ///
    /// With smaller numbers the test would finish within the base time and prove nothing; the
    /// elapsed-time assertion below catches that.
    fn axfr_progress_extends_the_total_deadline() {
        use onetdns_proto::{Name, RData, Record, Soa};

        let origin = Name::from_str("progress-xfr.test").unwrap();
        let soa = Record::new(
            origin.clone(),
            60,
            RData::soa(Soa {
                mname: Name::from_str("ns.progress-xfr.test").unwrap(),
                rname: Name::from_str("hostmaster.progress-xfr.test").unwrap(),
                serial: 1,
                refresh: 300,
                retry: 60,
                expire: 86_400,
                minimum: 60,
            }),
        );
        let mut records = Vec::with_capacity(2_804);
        records.push(soa.clone());
        records.push(Record::new(
            origin.clone(),
            60,
            RData::Ns(Name::from_str("ns.progress-xfr.test").unwrap()),
        ));
        records.push(Record::new(
            Name::from_str("ns.progress-xfr.test").unwrap(),
            60,
            RData::A("192.0.2.53".parse().unwrap()),
        ));
        for index in 0..2_800 {
            records.push(Record::new(
                Name::from_str(&format!("r{index}.progress-xfr.test")).unwrap(),
                60,
                RData::A("192.0.2.1".parse().unwrap()),
            ));
        }
        records.push(soa);

        let (address, server) =
            xfr_throttled_record_server(records, 4_096, Duration::from_millis(40));
        let entry = XferEntry {
            origin: origin.to_ascii_lower(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let job = SecondaryRefreshJob {
            entry,
            current_serial: None,
            had_zone: false,
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr: false,
        };
        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job, 1, None, &[], Duration::from_millis(400))
            .map_err(|error| error.1.clone())
            .unwrap();
        let started = std::time::Instant::now();
        let prepared = loop {
            let (mut ready, failed) = admission.poll();
            if let Some((_, error)) = failed.into_iter().next() {
                panic!("진전 중인 XFR가 실패했습니다: {error}");
            }
            if let Some(ready) = ready.pop() {
                break ready;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "진전 중인 XFR가 끝나지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        server.join().unwrap();
        assert!(
            started.elapsed() > Duration::from_millis(400),
            "전송이 기본 시간 안에 끝나 진전 연장을 증명하지 못했습니다"
        );
        let PreparedSecondaryXfr {
            job,
            remote_serial,
            current,
            io,
            reservation,
        } = prepared;
        let outcome = run_prepared_secondary_transfer(
            &job.entry,
            current.as_ref(),
            remote_serial,
            &[],
            io,
            reservation,
        )
        .expect("실제 바이트가 충분히 들어오면 전체 데드라인이 진전에 비례해야 합니다");
        assert!(matches!(
            outcome,
            SecondaryXferOutcome::Zone(zone, SecondaryXferKind::Axfr)
                if zone.soa().serial == 1 && zone.axfr_records().len() == 2_804
        ));
    }

    #[test]
    fn axfr_accepts_matching_opening_and_closing_soa() {
        let (address, server) = axfr_test_server(true, false);
        let origin = onetdns_proto::Name::from_str("example.test").unwrap();
        let records = axfr_fetch(address, &origin, Duration::from_secs(1)).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records.first(), records.last());
        server.join().unwrap();
    }

    #[test]
    fn ixfr_client_applies_ordered_deltas_and_rejects_impossible_delete() {
        use onetdns_proto::{Name, RData, Record, Soa};
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-client.test.\n@ IN SOA ns admin 10 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nold IN A 192.0.2.10\n",
            "ix-client.test",
        )
        .unwrap();
        let origin = current.origin().clone();
        let soa = |serial| {
            Record::new(
                origin.clone(),
                300,
                RData::soa(Soa {
                    mname: Name::from_str("ns.ix-client.test").unwrap(),
                    rname: Name::from_str("admin.ix-client.test").unwrap(),
                    serial,
                    refresh: 300,
                    retry: 60,
                    expire: 86400,
                    minimum: 60,
                }),
            )
        };
        let old = Record::new(
            Name::from_str("old.ix-client.test").unwrap(),
            300,
            RData::A("192.0.2.10".parse().unwrap()),
        );
        let middle = Record::new(
            Name::from_str("middle.ix-client.test").unwrap(),
            120,
            RData::A("192.0.2.11".parse().unwrap()),
        );
        let final_record = Record::new(
            Name::from_str("final.ix-client.test").unwrap(),
            60,
            RData::A("192.0.2.12".parse().unwrap()),
        );
        let (address, server) = xfr_record_server(vec![
            soa(12),
            soa(10),
            old,
            soa(11),
            middle.clone(),
            soa(11),
            soa(12),
            final_record.clone(),
            soa(12),
        ]);
        let updated = match ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap() {
            IxfrFetchResult::Incremental(zone) => zone,
            _ => panic!("incremental IXFR 기대"),
        };
        server.join().unwrap();
        assert_eq!(updated.soa().serial, 12);
        assert!(updated
            .query(&middle.name, middle.rtype)
            .answers
            .iter()
            .any(|record| xfr_rr_equal(record, &middle)));
        assert!(updated
            .query(&final_record.name, final_record.rtype)
            .answers
            .iter()
            .any(|record| xfr_rr_equal(record, &final_record)));
        assert!(updated
            .query(
                &Name::from_str("old.ix-client.test").unwrap(),
                onetdns_proto::RecordType::A
            )
            .answers
            .is_empty());

        let missing = Record::new(
            Name::from_str("missing.ix-client.test").unwrap(),
            300,
            RData::A("192.0.2.99".parse().unwrap()),
        );
        let (address, server) =
            xfr_record_server(vec![soa(11), soa(10), missing, soa(11), soa(11)]);
        assert!(ixfr_fetch(address, &current, Duration::from_secs(1)).is_err());
        server.join().unwrap();
        assert_eq!(
            current.soa().serial,
            10,
            "실패한 delta는 원본 zone을 변경하지 않음"
        );
    }

    #[test]
    fn ixfr_client_handles_unchanged_and_full_fallback() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-fallback.test.\n@ IN SOA ns admin 20 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-fallback.test",
        )
        .unwrap();
        let current_soa = current.axfr_records()[0].clone();
        let (address, server) = xfr_record_server(vec![current_soa]);
        assert!(matches!(
            ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap(),
            IxfrFetchResult::Unchanged
        ));
        server.join().unwrap();

        let replacement = onetdns_authority::parse_zone(
            "$ORIGIN ix-fallback.test.\n@ IN SOA ns admin 21 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nnew IN A 192.0.2.21\n",
            "ix-fallback.test",
        )
        .unwrap();
        let (address, server) = xfr_record_server(replacement.axfr_records());
        let fetched = ixfr_fetch(address, &current, Duration::from_secs(1)).unwrap();
        server.join().unwrap();
        assert!(matches!(fetched, IxfrFetchResult::Full(zone) if zone.soa().serial == 21));
    }

    fn xfr_rcode_server(rcode: u16) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut request_wire = vec![0u8; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let request = onetdns_proto::Message::parse(&request_wire).unwrap();
            let mut response = onetdns_proto::Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.header.rcode = rcode;
            response.questions = request.questions;
            let wire = response.try_encode().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&wire).unwrap();
        });
        (address, server)
    }

    fn prepared_xfr_io(
        address: std::net::SocketAddr,
        query: onetdns_proto::Message,
    ) -> (PreparedXfrIo, XfrBufferReservation) {
        use std::io::{Read, Write};
        let encoded = encode_xfr_request(query, None).unwrap();
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream.write_all(&encoded.framed_wire).unwrap();
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).unwrap();
        let mut first_message = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut first_message).unwrap();
        let budget = Arc::new(XfrBufferBudget::new(usize::MAX));
        let mut reservation = budget.reservation();
        assert!(reservation.try_grow(first_message.len() + SECONDARY_XFR_FRAME_OVERHEAD_BYTES));
        (
            PreparedXfrIo {
                query: encoded.query,
                request_mac: encoded.request_mac,
                messages: vec![first_message.into_boxed_slice()],
            },
            reservation,
        )
    }

    #[test]
    /// If they drift apart, the full transfer fallback stops.
    fn ixfr_notimp_error_text_matches_the_axfr_fallback_predicate() {
        assert!(xfr_error_is_notimp(&xfr_rcode_error(
            onetdns_proto::ResponseCode::NotImp.0
        )));
        assert!(!xfr_error_is_notimp(&xfr_rcode_error(
            onetdns_proto::ResponseCode::Refused.0
        )));
    }

    #[test]
    fn ixfr_notimp_asks_the_coordinator_for_a_full_transfer() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-notimp.test.\n@ IN SOA ns admin 30 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-notimp.test",
        )
        .unwrap();
        let (address, server) = xfr_rcode_server(onetdns_proto::ResponseCode::NotImp.0);
        let entry = XferEntry {
            origin: "ix-notimp.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let (prepared, reservation) = prepared_xfr_io(address, build_ixfr_query(&current).unwrap());
        let outcome =
            run_prepared_secondary_transfer(&entry, Some(&current), 31, &[], prepared, reservation)
                .unwrap();
        server.join().unwrap();
        assert!(matches!(
            outcome,
            SecondaryXferOutcome::NeedsFullTransfer { remote_serial: 31 }
        ));
    }

    #[test]
    fn forced_axfr_retry_ignores_the_ixfr_base_zone() {
        let current = onetdns_authority::parse_zone(
            "$ORIGIN ix-forced.test.\n@ IN SOA ns admin 40 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "ix-forced.test",
        )
        .unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let entry = XferEntry {
            origin: "ix-forced.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let job = |force_axfr| SecondaryRefreshJob {
            entry: entry.clone(),
            current_serial: Some(40),
            had_zone: true,
            last_ok: unix_now(),
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: true,
            force_axfr,
        };

        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(
                job(false),
                41,
                Some(current.clone()),
                &[],
                Duration::from_millis(50),
            )
            .map_err(|error| error.1.clone())
            .unwrap();
        assert_eq!(
            admission.pending[0].query.questions[0].qtype,
            onetdns_proto::RecordType(251),
            "force_axfr가 없으면 IXFR로 묻는다"
        );
        assert!(admission.pending[0].current.is_some());

        let mut admission = SecondaryXfrAdmission::default();
        admission
            .start(job(true), 41, Some(current), &[], Duration::from_millis(50))
            .map_err(|error| error.1.clone())
            .unwrap();
        assert_eq!(
            admission.pending[0].query.questions[0].qtype,
            onetdns_proto::RecordType(252),
            "force_axfr면 AXFR로 묻는다"
        );
        assert!(
            admission.pending[0].current.is_none(),
            "기준 영역을 버려야 응답 해석도 AXFR 경로로 간다"
        );
    }

    #[test]
    fn secondary_soa_probe_requires_authority_and_verifies_tsig() {
        use onetdns_dnssec::tsig;
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let key = tsig::TsigKey::new(
            onetdns_proto::Name::from_str("secondary-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let server_key = key.clone();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let (stripped, request_mac) =
                tsig::verify_wire(&wire[..length], &server_key, unix_now(), None).unwrap();
            let request = Message::parse(&stripped).unwrap();
            let origin = request.questions[0].name.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers.push(Record {
                name: origin.clone(),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: onetdns_proto::Name::from_str("ns.probe.test").unwrap(),
                    rname: onetdns_proto::Name::from_str("admin.probe.test").unwrap(),
                    serial: 42,
                    refresh: 300,
                    retry: 60,
                    expire: 86400,
                    minimum: 60,
                }),
            });
            tsig::sign_message(&mut response, &server_key, unix_now(), Some(&request_mac)).unwrap();
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        assert_eq!(
            probe_soa_serial(address, "probe.test", Some(key.clone())).unwrap(),
            42
        );
        server.join().unwrap();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let request = Message::parse(&wire[..length]).unwrap();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.questions = request.questions;
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
        });
        assert!(probe_soa_serial(address, "probe.test", None).is_err());
        server.join().unwrap();
    }

    fn secondary_soa_test_server(
        delay: Duration,
        observed: Option<std::sync::mpsc::Sender<std::time::Instant>>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            if let Some(observed) = observed {
                observed.send(std::time::Instant::now()).unwrap();
            }
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            let request = Message::parse(&wire[..length]).unwrap();
            let origin = request.questions[0].name.clone();
            let mut response = Message::default();
            response.header.id = request.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = request.questions;
            response.answers.push(Record {
                name: origin.clone(),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: onetdns_proto::Name::from_str("ns.secondary.test").unwrap(),
                    rname: onetdns_proto::Name::from_str("admin.secondary.test").unwrap(),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    minimum: 60,
                }),
            });
            socket
                .send_to(&response.try_encode().unwrap(), peer)
                .unwrap();
        });
        (address, server)
    }

    #[test]
    /// Otherwise a serial injected by someone else would be trusted.
    fn multiplexed_soa_probe_ignores_same_id_wrong_question() {
        use onetdns_proto::{DnsClass, Message, RData, Record, RecordType, Soa};

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut wire).unwrap();
            let request = Message::parse(&wire[..length]).unwrap();
            let answer = |origin: onetdns_proto::Name| {
                Record::new(
                    origin,
                    300,
                    RData::soa(Soa {
                        mname: onetdns_proto::Name::from_str("ns.secondary.test").unwrap(),
                        rname: onetdns_proto::Name::from_str("admin.secondary.test").unwrap(),
                        serial: 42,
                        refresh: 300,
                        retry: 60,
                        expire: 86_400,
                        minimum: 60,
                    }),
                )
            };
            let mut wrong = Message::default();
            wrong.header.id = request.header.id;
            wrong.header.response = true;
            wrong.header.authoritative = true;
            let wrong_name = onetdns_proto::Name::from_str("wrong.secondary.test").unwrap();
            wrong.questions.push(onetdns_proto::Question {
                name: wrong_name.clone(),
                qtype: RecordType::SOA,
                qclass: DnsClass::IN,
            });
            wrong.answers.push(answer(wrong_name));
            socket.send_to(&wrong.try_encode().unwrap(), peer).unwrap();

            let origin = request.questions[0].name.clone();
            let mut correct = Message::default();
            correct.header.id = request.header.id;
            correct.header.response = true;
            correct.header.authoritative = true;
            correct.questions = request.questions;
            correct.answers.push(answer(origin));
            socket
                .send_to(&correct.try_encode().unwrap(), peer)
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        let entry = XferEntry {
            origin: "probe.secondary.test".to_string(),
            file: None,
            primary: address.ip(),
            port: address.port(),
            tsig_key: None,
            is_catalog: false,
        };
        let mut prober = SecondarySoaProber::new(std::slice::from_ref(&entry)).unwrap();
        let started = prober.start(
            SecondaryRefreshJob {
                entry,
                current_serial: None,
                had_zone: false,
                last_ok: unix_now(),
                refresh: 300,
                retry: 60,
                expire: 86_400,
                priority: true,
                force_axfr: false,
            },
            &[],
            Duration::from_secs(1),
        );
        assert!(started.is_ok());
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let serial = loop {
            if let Some(result) = prober.poll(&[]).pop() {
                break result.result.unwrap();
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(serial, 42);
        assert_eq!(prober.len(), 0);
        server.join().unwrap();
    }

    #[test]
    fn eight_stalled_secondaries_do_not_block_another_zone_refresh() {
        let (observed_tx, observed_rx) = std::sync::mpsc::channel();
        let (fast_addr, fast_server) = secondary_soa_test_server(Duration::ZERO, Some(observed_tx));
        let zone = |origin: &str| {
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap()
        };
        let mut zones = onetdns_authority::ZoneStore::new();
        let secondary =
            |origin: &str, address: std::net::SocketAddr| onetdns_config::SecondaryZone {
                origin: origin.to_string(),
                file: None,
                primary: Some(address.ip()),
                primary_port: Some(address.port()),
                tsig_key: None,
            };
        let mut config = Config::default();
        let mut slow_servers = Vec::new();
        for index in 0..8 {
            let origin = format!("slow-{index}.secondary.test");
            let (address, server) = secondary_soa_test_server(Duration::from_millis(1_500), None);
            zones.add(zone(&origin));
            config.secondary.push(secondary(&origin, address));
            slow_servers.push(server);
        }
        zones.add(zone("fast-secondary.test"));
        config
            .secondary
            .push(secondary("fast-secondary.test", fast_addr));
        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let started = std::time::Instant::now();
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store,
            Arc::default(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(2),
        )
        .unwrap();

        let observed = observed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            observed.duration_since(started) < Duration::from_millis(750),
            "8개 느린 primary의 1.5초 대기가 정상 영역의 SOA 확인을 막았습니다"
        );
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push("fast-secondary.test".to_string());
        coordinator.join().unwrap();
        for server in slow_servers {
            server.join().unwrap();
        }
        fast_server.join().unwrap();

        assert_eq!(secondary_refresh_parallelism(0), 1);
        assert_eq!(secondary_refresh_parallelism(2), 2);
        assert_eq!(secondary_refresh_parallelism(usize::MAX), 4);
    }

    fn ixfr_notimp_primary(
        origin: String,
        seen: std::sync::mpsc::Sender<onetdns_proto::RecordType>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::{Message, RecordType};
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let soa_request = Message::parse(&wire[..length]).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query_wire = vec![0; u16::from_be_bytes(length) as usize];
                stream.read_exact(&mut query_wire).unwrap();
                let query = Message::parse(&query_wire).unwrap();
                let qtype = query.questions[0].qtype;
                seen.send(qtype).unwrap();

                let mut response = Message::default();
                response.header.id = query.header.id;
                response.header.response = true;
                response.header.authoritative = true;
                response.questions = query.questions;
                if qtype == RecordType(251) {
                    response.header.rcode = onetdns_proto::ResponseCode::NotImp.0;
                } else {
                    response.answers = zone.axfr_records();
                }
                let response_wire = response.try_encode().unwrap();
                stream
                    .write_all(&(response_wire.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&response_wire).unwrap();
                if qtype != RecordType(251) {
                    return;
                }
            }
        });
        (address, server)
    }

    fn stalls_after_first_frame_primary(
        origin: String,
        sent: std::sync::mpsc::Sender<()>,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_proto::Message;
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let soa_request = Message::parse(&wire[..length]).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query_wire = vec![0; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut query_wire).unwrap();
            let query = Message::parse(&query_wire).unwrap();

            let mut response = Message::default();
            response.header.id = query.header.id;
            response.header.response = true;
            response.header.authoritative = true;
            response.questions = query.questions;
            response.answers = vec![zone.axfr_records_iter().next().unwrap()];
            let response_wire = response.try_encode().unwrap();
            stream
                .write_all(&(response_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response_wire).unwrap();
            sent.send(()).unwrap();

            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
        });
        (address, server)
    }

    /// SOA and two transfer frames, all under a valid TSIG chain.
    fn signed_secondary_xfr_primary(
        origin: String,
        key: onetdns_dnssec::tsig::TsigKey,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use onetdns_dnssec::tsig;
        use onetdns_proto::Message;
        use std::io::{Read, Write};

        let (listener, udp, address) = tcp_udp_test_listeners();
        let zone = onetdns_authority::parse_zone(
            &format!(
                "$ORIGIN {origin}.\n@ 120 IN SOA ns admin 2 300 60 86400 60\n@ 120 IN NS ns\nns 120 IN A 192.0.2.2\n"
            ),
            &origin,
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let mut wire = [0u8; 4096];
            let (length, peer) = udp.recv_from(&mut wire).unwrap();
            let (soa_wire, soa_request_mac) =
                tsig::verify_wire(&wire[..length], &key, unix_now(), None).unwrap();
            let soa_request = Message::parse(&soa_wire).unwrap();
            let mut soa_response = Message::default();
            soa_response.header.id = soa_request.header.id;
            soa_response.header.response = true;
            soa_response.header.authoritative = true;
            soa_response.questions = soa_request.questions;
            soa_response
                .answers
                .push(zone.axfr_records_iter().next().unwrap());
            tsig::sign_message(&mut soa_response, &key, unix_now(), Some(&soa_request_mac))
                .unwrap();
            udp.send_to(&soa_response.try_encode().unwrap(), peer)
                .unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let mut request_length = [0u8; 2];
            stream.read_exact(&mut request_length).unwrap();
            let mut request_wire = vec![0; u16::from_be_bytes(request_length) as usize];
            stream.read_exact(&mut request_wire).unwrap();
            let (query_wire, request_mac) =
                tsig::verify_wire(&request_wire, &key, unix_now(), None).unwrap();
            let query = Message::parse(&query_wire).unwrap();
            let records = zone.axfr_records();

            let mut first = Message::default();
            first.header.id = query.header.id;
            first.header.response = true;
            first.header.authoritative = true;
            first.questions = query.questions;
            first
                .answers
                .extend_from_slice(&records[..records.len() - 1]);
            let first_mac =
                tsig::sign_message(&mut first, &key, unix_now(), Some(&request_mac)).unwrap();
            let first_wire = first.try_encode().unwrap();
            stream
                .write_all(&(first_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&first_wire).unwrap();

            let mut last = Message::default();
            last.header.id = query.header.id;
            last.header.response = true;
            last.header.authoritative = true;
            last.answers.push(records.last().unwrap().clone());
            tsig::sign_subsequent(&mut last, &key, unix_now(), &first_mac).unwrap();
            let last_wire = last.try_encode().unwrap();
            stream
                .write_all(&(last_wire.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&last_wire).unwrap();
        });
        (address, server)
    }

    #[test]
    fn xfr_response_buffer_budget_is_global_and_released_on_drop() {
        let budget = Arc::new(XfrBufferBudget::new(64));
        let mut first = budget.reservation();
        let mut second = budget.reservation();
        assert!(first.try_grow(40));
        assert!(!second.try_grow(25));
        assert!(second.try_grow(24));
        assert_eq!(budget.used(), 64);

        drop(first);
        assert_eq!(budget.used(), 24);
        assert!(second.try_grow(40));
        assert_eq!(budget.used(), 64);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    /// The TSIG chain starts from the request MAC.
    fn secondary_nonblocking_xfr_preserves_multi_frame_tsig_chain() {
        let origin = "signed-secondary.test";
        let key = onetdns_dnssec::tsig::TsigKey::new(
            onetdns_proto::Name::from_str("secondary-xfr-key").unwrap(),
            b"0123456789abcdef0123456789abcdef".to_vec(),
        )
        .unwrap();
        let (address, server) = signed_secondary_xfr_primary(origin.to_string(), key.clone());

        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ 120 IN SOA ns admin 1 300 60 86400 60\n@ 120 IN NS ns\nns 120 IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap(),
        );
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: origin.to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: Some("secondary-xfr-key".to_string()),
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            vec![key],
            store.clone(),
            Arc::default(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(2),
        )
        .unwrap();

        let name = onetdns_proto::Name::from_str(origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if store
                .load()
                .zone_exact(&name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "TSIG 다중 frame XFR가 검증·적용되지 않았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            store
                .load()
                .zone_exact(&name)
                .unwrap()
                .axfr_records_iter()
                .next()
                .unwrap()
                .ttl,
            120
        );

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push(origin.to_string());
        coordinator.join().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn primaries_that_stall_after_the_first_frame_release_their_parser_slot() {
        let mut config = Config::default();
        let mut zones = onetdns_authority::ZoneStore::new();
        let mut servers = Vec::new();
        let stalled = SECONDARY_REFRESH_MAX_IN_FLIGHT * 2;
        let (stalled_tx, stalled_rx) = std::sync::mpsc::channel();
        for index in 0..stalled {
            let origin = format!("frame-stall-{index}.secondary.test");
            let (address, server) =
                stalls_after_first_frame_primary(origin.clone(), stalled_tx.clone());
            zones.add(
                onetdns_authority::parse_zone(
                    &format!(
                        "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                    ),
                    &origin,
                )
                .unwrap(),
            );
            config.secondary.push(onetdns_config::SecondaryZone {
                origin: origin.clone(),
                file: None,
                primary: Some(address.ip()),
                primary_port: Some(address.port()),
                tsig_key: None,
            });
            servers.push(server);
        }
        drop(stalled_tx);

        let fast_origin = "frame-fast.secondary.test";
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (observed_tx, _observed_rx) = std::sync::mpsc::channel();
        let (fast_address, fast_server) = secondary_xfr_admission_test_server(
            fast_origin.to_string(),
            false,
            observed_tx,
            Some(gate_rx),
        );
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {fast_origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                fast_origin,
            )
            .unwrap(),
        );
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: fast_origin.to_string(),
            file: None,
            primary: Some(fast_address.ip()),
            primary_port: Some(fast_address.port()),
            tsig_key: None,
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let kick = Arc::new(native::NotifyKick::default());
        let started = std::time::Instant::now();
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store.clone(),
            Arc::default(),
            kick.clone(),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_secs(10),
        )
        .unwrap();

        for _ in 0..stalled {
            stalled_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        std::thread::sleep(Duration::from_millis(100));
        gate_tx.send(()).unwrap();

        let fast_name = onetdns_proto::Name::from_str(fast_origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(750);
        loop {
            if store
                .load()
                .zone_exact(&fast_name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "첫 frame 뒤 멈춘 8개 원본이 정상 영역의 parser 진입을 막았습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "정상 영역은 stalled 원본의 2초 idle timeout 전에 수렴해야 합니다"
        );

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        kick.push(fast_origin.to_string());
        coordinator.join().unwrap();
        for server in servers {
            server.join().unwrap();
        }
        fast_server.join().unwrap();
    }

    #[test]
    fn secondary_recovers_from_an_ixfr_only_notimp_primary() {
        let origin = "notimp.secondary.test";
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (address, server) = ixfr_notimp_primary(origin.to_string(), seen_tx);

        let mut zones = onetdns_authority::ZoneStore::new();
        zones.add(
            onetdns_authority::parse_zone(
                &format!(
                    "$ORIGIN {origin}.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\n"
                ),
                origin,
            )
            .unwrap(),
        );
        let mut config = Config::default();
        config.secondary.push(onetdns_config::SecondaryZone {
            origin: origin.to_string(),
            file: None,
            primary: Some(address.ip()),
            primary_port: Some(address.port()),
            tsig_key: None,
        });

        let store = Arc::new(onetdns_core::ArcSwap::from_pointee(zones));
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let coordinator = spawn_secondary_refresh_with_timeout(
            config,
            Vec::new(),
            store.clone(),
            Arc::default(),
            Arc::new(native::NotifyKick::default()),
            NotifySender::disabled(),
            shutdown.clone(),
            Duration::from_millis(1_500),
        )
        .unwrap();

        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            onetdns_proto::RecordType(251),
            "기준 영역이 있으면 먼저 IXFR로 묻는다"
        );
        assert_eq!(
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            onetdns_proto::RecordType(252),
            "NOTIMP 뒤에는 AXFR로 다시 물어야 한다"
        );

        let name = onetdns_proto::Name::from_str(origin).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if store
                .load()
                .zone_exact(&name)
                .is_some_and(|zone| zone.soa().serial == 2)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "IXFR를 지원하지 않는 primary에서 영역을 받지 못했습니다"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = coordinator.join();
        let _ = server.join();
    }

    #[test]
    /// Otherwise NOTIFY would not find the zone.
    fn secondary_scheduler_key_matches_notify_name_canonical_form() {
        let config = onetdns_config::SecondaryZone {
            origin: "MiXeD.Secondary.Test.".to_string(),
            file: None,
            primary: Some("192.0.2.53".parse().unwrap()),
            primary_port: Some(53),
            tsig_key: None,
        };
        assert_eq!(
            XferEntry::from_cfg(&config, false).unwrap().origin,
            "mixed.secondary.test"
        );
    }

    #[test]
    fn stale_secondary_job_requires_an_exact_configuration_match() {
        let entry = XferEntry {
            origin: "exact.secondary.test".to_string(),
            file: Some(std::path::PathBuf::from("secondary.zone")),
            primary: "192.0.2.53".parse().unwrap(),
            port: 53,
            tsig_key: Some("transfer-key".to_string()),
            is_catalog: false,
        };
        let job = SecondaryRefreshJob {
            entry: entry.clone(),
            current_serial: Some(1),
            had_zone: true,
            last_ok: 0,
            refresh: 300,
            retry: 60,
            expire: 86_400,
            priority: false,
            force_axfr: false,
        };
        assert!(secondary_entry_is_current(
            std::slice::from_ref(&entry),
            &job
        ));

        let mut changed_key = entry.clone();
        changed_key.tsig_key = Some("replacement-key".to_string());
        assert!(!secondary_entry_is_current(&[changed_key], &job));

        let mut changed_file = entry;
        changed_file.file = Some(std::path::PathBuf::from("replacement.zone"));
        assert!(!secondary_entry_is_current(&[changed_file], &job));
    }

    #[test]
    fn secondary_cache_restores_only_with_unexpired_refresh_state() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-secondary-cache-{}-{}.zone",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let zone = onetdns_authority::parse_zone(
            "$ORIGIN cached-secondary.test.\n@ IN SOA ns admin 7 300 60 120 60\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "cached-secondary.test",
        )
        .unwrap();
        atomic_write(&path, zone.to_master_file().as_bytes()).unwrap();
        mark_secondary_refresh(&path, unix_now().saturating_sub(30)).unwrap();
        let config = onetdns_config::SecondaryZone {
            origin: "cached-secondary.test".into(),
            file: Some(path.clone()),
            primary: Some("192.0.2.53".parse().unwrap()),
            primary_port: Some(53),
            tsig_key: None,
        };
        let origin = onetdns_proto::Name::from_str("cached-secondary.test").unwrap();
        assert_eq!(
            load_secondary_cache(&config, &Config::default(), &origin)
                .unwrap()
                .soa()
                .serial,
            7
        );

        std::fs::remove_file(secondary_refresh_state_path(&path)).unwrap();
        assert!(load_secondary_cache(&config, &Config::default(), &origin).is_none());
        mark_secondary_refresh(&path, unix_now().saturating_sub(121)).unwrap();
        assert!(load_secondary_cache(&config, &Config::default(), &origin).is_none());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(secondary_refresh_state_path(&path));
    }
}
