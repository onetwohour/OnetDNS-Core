//! DHCPv4 server. The protocol has no authentication, so a request never binds an address that
//! another client owns or that this server did not hand out.

use std::collections::HashMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

/// The DHCP magic cookie, which starts the options.
const MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Length of the fixed BOOTP header.
const FIXED_LEN: usize = 236;
/// Largest UDP payload a standard IPv4 datagram carries.
const MAX_STANDARD_IPV4_UDP_PAYLOAD: usize = u16::MAX as usize - 20 - 8;
/// One byte over the limit, so an oversized datagram is seen as such instead of cut to fit.
const DHCP4_RECV_CAPACITY: usize = MAX_STANDARD_IPV4_UDP_PAYLOAD + 1;
const BROADCAST_FLAG: u16 = 0x8000;
const SNAME_RANGE: std::ops::Range<usize> = 44..108;
const FILE_RANGE: std::ops::Range<usize> = 108..236;
const MAX_PERSIST_FILE: u64 = 16 * 1024 * 1024;
/// Cap on entries held in memory and in the state files.
const MAX_STATE_ENTRIES: usize = 100_000;
/// A lease file that does not start with this line is not read.
const LEASE_HEADER: &str = "ONETDNS-DHCP4-LEASES-V1\n";
const RESERVATION_HEADER: &str = "ONETDNS-DHCP4-RESERVATIONS-V1\n";

/// An infinite lease on the wire stays infinite here.
fn lease_expiry(now: u64, lease: u32) -> u64 {
    if lease == u32::MAX {
        u64::MAX
    } else {
        now.saturating_add(u64::from(lease))
    }
}

/// On failure the pool starts empty.
fn read_persist_text(path: &std::path::Path) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp4.restore_open_failed",
                path = %path.display(),
                %error,
                "Could not open saved DHCP state; starting empty"
            );
            return None;
        }
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_PERSIST_FILE + 1).read_to_end(&mut bytes) {
        onetdns_core::warn!(
            event = "dhcp4.restore_read_failed",
            path = %path.display(),
            %error,
            "Could not read saved DHCP state; starting empty"
        );
        return None;
    }
    if bytes.len() as u64 > MAX_PERSIST_FILE {
        onetdns_core::warn!(
            event = "dhcp4.restore_too_large",
            path = %path.display(),
            bytes = bytes.len(),
            limit = MAX_PERSIST_FILE,
            "Saved DHCP file exceeds the size limit; not restoring it"
        );
        return None;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(error) => {
            onetdns_core::warn!(
                event = "dhcp4.restore_invalid_utf8",
                path = %path.display(),
                %error,
                "Saved DHCP file is not valid text; not restoring it"
            );
            None
        }
    }
}

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const DECLINE: u8 = 4;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;
pub const RELEASE: u8 = 7;

pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_LEASE_TIME: u8 = 51;
const OPT_OVERLOAD: u8 = 52;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_DOMAIN_NAME: u8 = 15;
pub const OPT_TFTP_SERVER_NAME: u8 = 66;
pub const OPT_BOOTFILE: u8 = 67;
pub const OPT_END: u8 = 255;

fn standard_dhcp4_datagram_len(received: usize) -> Option<usize> {
    (received <= MAX_STANDARD_IPV4_UDP_PAYLOAD).then_some(received)
}

/// Longest value, after joining fragments, of an option this server uses; `None` for the rest.
fn retained_option_limit(code: u8) -> Option<usize> {
    match code {
        OPT_OVERLOAD | OPT_MSG_TYPE => Some(1),
        OPT_REQUESTED_IP | OPT_SERVER_ID => Some(4),
        OPT_HOSTNAME | OPT_CLIENT_ID => Some(255),
        _ => None,
    }
}

/// Appends an RFC 3396 fragment to the single buffer kept per option code.
fn append_option_fragment(
    options: &mut Vec<(u8, Vec<u8>)>,
    code: u8,
    value: &[u8],
    limit: usize,
) -> Option<()> {
    if let Some((_, aggregate)) = options.iter_mut().find(|(stored, _)| *stored == code) {
        let new_len = aggregate.len().checked_add(value.len())?;
        if new_len > limit {
            return None;
        }
        aggregate.extend_from_slice(value);
    } else {
        if value.len() > limit {
            return None;
        }
        options.push((code, value.to_vec()));
    }
    Some(())
}

/// Checks a whole option field and keeps only the supported options, in RFC 3396 order.
fn scan_option_field(
    field: &[u8],
    allow_overload: bool,
    options: &mut Vec<(u8, Vec<u8>)>,
) -> Option<()> {
    let mut offset = 0usize;
    while offset < field.len() {
        let code = field[offset];
        if code == OPT_END {
            return field[offset + 1..]
                .iter()
                .all(|byte| *byte == 0)
                .then_some(());
        }
        if code == 0 {
            offset += 1;
            continue;
        }
        let len = usize::from(*field.get(offset + 1)?);
        let end = offset.checked_add(2)?.checked_add(len)?;
        let value = field.get(offset + 2..end)?;
        if code == OPT_OVERLOAD && !allow_overload {
            return None;
        }
        if let Some(limit) = retained_option_limit(code) {
            append_option_fragment(options, code, value, limit)?;
        }
        offset = end;
    }
    None
}

/// Checks each kept option's length once its fragments are joined.
fn retained_options_are_valid(options: &[(u8, Vec<u8>)]) -> bool {
    options.iter().all(|(code, value)| match *code {
        OPT_REQUESTED_IP | OPT_SERVER_ID => value.len() == 4,
        OPT_HOSTNAME => !value.is_empty(),
        OPT_CLIENT_ID => (2..=255).contains(&value.len()),
        OPT_OVERLOAD => value.len() == 1 && matches!(value[0], 1..=3),
        OPT_MSG_TYPE => value.len() == 1,
        _ => false,
    })
}

#[derive(Debug, Clone)]
pub struct DhcpMessage {
    pub op: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    /// Next server, for network boot.
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,

    pub chaddr: [u8; 6],
    /// Option 61. When absent, `chaddr` identifies the client.
    client_identifier: Option<std::sync::Arc<[u8]>>,
    pub options: Vec<(u8, Vec<u8>)>,
}

impl DhcpMessage {
    /// Rejects the whole message when an option runs past the end: accepting what came before
    /// would treat a truncated request as complete.
    pub fn parse(buf: &[u8]) -> Option<DhcpMessage> {
        if buf.len() < FIXED_LEN + 4
            || buf.len() > MAX_STANDARD_IPV4_UDP_PAYLOAD
            || !matches!(buf[0], 1 | 2)
            || buf[1] != 1
            || buf[2] != 6
            || buf[FIXED_LEN..FIXED_LEN + 4] != MAGIC
        {
            return None;
        }
        let v4 = |o: usize| Ipv4Addr::new(buf[o], buf[o + 1], buf[o + 2], buf[o + 3]);
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&buf[28..34]);
        let op = buf[0];
        let mut options = Vec::with_capacity(4);
        scan_option_field(&buf[FIXED_LEN + 4..], true, &mut options)?;

        let overload = options
            .iter()
            .find(|(code, _)| *code == OPT_OVERLOAD)
            .and_then(|(_, value)| (value.len() == 1).then_some(value[0]))
            .unwrap_or(0);
        if overload & 1 != 0 {
            scan_option_field(&buf[FILE_RANGE], false, &mut options)?;
        }
        if overload & 2 != 0 {
            scan_option_field(&buf[SNAME_RANGE], false, &mut options)?;
        }
        if !retained_options_are_valid(&options)
            || !options.iter().any(|(code, _)| *code == OPT_MSG_TYPE)
        {
            return None;
        }
        options.retain(|(code, _)| *code != OPT_OVERLOAD);
        let client_identifier = options
            .iter()
            .position(|(code, _)| *code == OPT_CLIENT_ID)
            .map(|index| std::sync::Arc::from(options.remove(index).1));
        Some(DhcpMessage {
            op,
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: v4(12),
            yiaddr: v4(16),
            siaddr: v4(20),
            giaddr: v4(24),
            chaddr,
            client_identifier,
            options,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; FIXED_LEN];
        b[0] = self.op;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        b[10..12].copy_from_slice(&self.flags.to_be_bytes());
        b[12..16].copy_from_slice(&self.ciaddr.octets());
        b[16..20].copy_from_slice(&self.yiaddr.octets());
        b[20..24].copy_from_slice(&self.siaddr.octets());
        b[24..28].copy_from_slice(&self.giaddr.octets());
        b[28..34].copy_from_slice(&self.chaddr);
        b.extend_from_slice(&MAGIC);
        if let Some(client_identifier) = &self.client_identifier {
            b.push(OPT_CLIENT_ID);
            b.push(
                u8::try_from(client_identifier.len())
                    .expect("The parser has already validated DHCP option lengths"),
            );
            b.extend_from_slice(client_identifier);
        }
        for (code, val) in &self.options {
            let Ok(len) = u8::try_from(val.len()) else {
                continue;
            };
            b.push(*code);
            b.push(len);
            b.extend_from_slice(val);
        }
        b.push(OPT_END);
        b
    }

    pub fn option(&self, code: u8) -> Option<&[u8]> {
        if code == OPT_CLIENT_ID {
            return self.client_identifier.as_deref();
        }
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    pub fn msg_type(&self) -> Option<u8> {
        let value = self.option(OPT_MSG_TYPE)?;
        (value.len() == 1).then_some(value[0])
    }

    /// Option 12 without control characters and whitespace.
    pub fn hostname(&self) -> Option<String> {
        let raw = self.option(OPT_HOSTNAME)?;
        let s: String = std::str::from_utf8(raw)
            .ok()?
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace())
            .collect();
        (!s.is_empty()).then_some(s)
    }

    fn client_identity(&self) -> ClientIdentity {
        match &self.client_identifier {
            Some(value) => ClientIdentity::Opaque(value.clone()),
            None => ClientIdentity::Hardware(self.chaddr),
        }
    }
}

/// Only BOOTREQUESTs reach the option parser.
fn parse_client_request(buf: &[u8]) -> Option<DhcpMessage> {
    if buf.first().copied() != Some(1) {
        return None;
    }
    DhcpMessage::parse(buf)
}

fn opt_ipv4(v: &[u8]) -> Option<Ipv4Addr> {
    (v.len() == 4).then(|| Ipv4Addr::new(v[0], v[1], v[2], v[3]))
}

/// Safe to store in the space-separated state files.
pub fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// The one key a DHCPv4 binding belongs to.
pub enum ClientIdentity {
    /// `chaddr`, used when option 61 is absent.
    Hardware([u8; 6]),
    /// Option 61, kept as received.
    Opaque(std::sync::Arc<[u8]>),
}

impl ClientIdentity {
    /// Lossless form shared by the state files, HA and the management API.
    pub fn to_text(&self) -> String {
        match self {
            Self::Hardware(mac) => format!("mac:{}", mac_hex(mac)),
            Self::Opaque(value) => format!("id:{}", bytes_hex(value)),
        }
    }

    pub fn from_text(text: &str) -> Option<Self> {
        if let Some(value) = text.strip_prefix("mac:") {
            return mac_from_hex(value).map(Self::Hardware);
        }
        let value = text.strip_prefix("id:")?;
        let bytes = bytes_from_hex(value)?;
        (2..=255)
            .contains(&bytes.len())
            .then(|| Self::Opaque(std::sync::Arc::from(bytes)))
    }

    pub fn hardware(&self) -> Option<[u8; 6]> {
        match self {
            Self::Hardware(mac) => Some(*mac),
            Self::Opaque(_) => None,
        }
    }
}

#[derive(Clone)]
struct Lease {
    /// Hardware address last seen for this client.
    mac: [u8; 6],
    ip: u32,
    expiry: u64,
    hostname: Option<String>,
}

pub struct LeaseInfo {
    pub identity: ClientIdentity,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub expiry_unix: u64,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DhcpConfig {
    /// Sent as the server identifier.
    pub server_ip: Ipv4Addr,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,

    pub tftp_server: Option<Ipv4Addr>,

    pub boot_file: Option<String>,

    pub domain_name: Option<String>,

    pub lease_file: Option<PathBuf>,

    /// Where static assignments are saved.
    pub static_file: Option<PathBuf>,
}

pub struct ReservationInfo {
    pub identity: ClientIdentity,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
}

/// Leases, plus offers not yet confirmed and declined addresses: an offered address must not go
/// to another client before the offer expires.
pub struct LeasePool {
    start: u32,
    end: u32,
    lease_secs: u32,
    leases: HashMap<ClientIdentity, Lease>,
    persist: Option<PathBuf>,

    /// Offered but not yet confirmed: address, transaction ID, expiry.
    offers: HashMap<ClientIdentity, (u32, u32, u64)>,

    /// Addresses a client reported in use, held back until the given time.
    declined: HashMap<u32, u64>,

    reservations: HashMap<ClientIdentity, (u32, Option<String>)>,
    /// References per address from leases, offers, declines and static assignments, so picking a
    /// free address does not copy the tables.
    address_use: HashMap<u32, u32>,
    static_persist: Option<PathBuf>,

    subnet_mask: u32,
    server_ip: u32,
    router: u32,
    /// Whether the exhausted-range warning was logged, so it is not repeated per request.
    exhausted: bool,
    /// Whether reaching the dynamic state cap was logged.
    dynamic_limited: bool,
    /// Whether reaching the static assignment cap was logged.
    reservations_limited: bool,
    /// Where the next free-address search starts.
    allocation_cursor: u32,
    /// Earliest expiry among leases, offers and declines.
    next_expiry: u64,
}

impl LeasePool {
    /// Rechecks what it reads against the current config: an address from an old range reaches
    /// nothing.
    pub fn new(cfg: &DhcpConfig) -> Self {
        let leases = cfg
            .lease_file
            .as_deref()
            .map(load_leases)
            .unwrap_or_default();
        let mut static_persist = cfg.static_file.clone();
        let reservations = match cfg.static_file.as_deref().map(read_reservations) {
            Some(Ok(reservations)) => reservations,
            Some(Err(error)) => {
                onetdns_core::warn!(event = "dhcp4.reservations_restore_invalid", error = %error, "Could not read the DHCP static lease file; starting without saving static leases so the operator's file is not overwritten");
                static_persist = None;
                HashMap::new()
            }
            None => HashMap::new(),
        };
        let mut pool = LeasePool {
            start: u32::from(cfg.range_start),
            end: u32::from(cfg.range_end),
            lease_secs: cfg.lease_secs,
            leases,
            persist: cfg.lease_file.clone(),
            offers: HashMap::new(),
            declined: HashMap::new(),
            reservations,
            address_use: HashMap::new(),
            static_persist,
            subnet_mask: u32::from(cfg.subnet_mask),
            server_ip: u32::from(cfg.server_ip),
            router: u32::from(cfg.router),
            exhausted: false,
            dynamic_limited: false,
            reservations_limited: false,
            allocation_cursor: u32::from(cfg.range_start),
            next_expiry: u64::MAX,
        };
        pool.revalidate_loaded_state();
        pool.rebuild_address_use();

        pool.save_static();
        pool.save();
        pool
    }

    /// Keeps the leases across a service restart: a new pool would hand out addresses already in
    /// use. Reads the new static assignment file if it exists, else writes the current assignments
    /// to it. On failure the pool is unchanged.
    pub fn reconfigure(&mut self, cfg: &DhcpConfig) -> Result<(), String> {
        if cfg.static_file != self.static_persist {
            if let Some(path) = cfg.static_file.as_deref() {
                if path.exists() {
                    self.reservations = read_reservations(path)?;
                }
            }
            self.static_persist = cfg.static_file.clone();
        }
        self.start = u32::from(cfg.range_start);
        self.end = u32::from(cfg.range_end);
        self.lease_secs = cfg.lease_secs;
        self.persist = cfg.lease_file.clone();
        self.subnet_mask = u32::from(cfg.subnet_mask);
        self.server_ip = u32::from(cfg.server_ip);
        self.router = u32::from(cfg.router);
        self.offers.clear();
        self.exhausted = false;
        self.allocation_cursor = self.start;
        self.revalidate_loaded_state();
        self.rebuild_address_use();
        self.save_static();
        self.save();
        Ok(())
    }

    /// Keeps state under its cap and logs reaching and leaving the cap once each.
    fn admit_state(limited: &mut bool, kind: &'static str, entries: usize) -> bool {
        if entries < MAX_STATE_ENTRIES {
            if std::mem::replace(limited, false) {
                onetdns_core::info!(
                    event = "dhcp4.state_available",
                    kind = kind,
                    entries,
                    limit = MAX_STATE_ENTRIES,
                    "DHCPv4 state is back under its limit"
                );
            }
            true
        } else {
            if !std::mem::replace(limited, true) {
                onetdns_core::warn!(
                    event = "dhcp4.state_limit",
                    kind = kind,
                    entries,
                    limit = MAX_STATE_ENTRIES,
                    "DHCPv4 state reached its limit; not accepting new entries"
                );
            }
            false
        }
    }

    /// Leases, offers and declines share one budget for remote input.
    fn dynamic_entries(&self) -> usize {
        self.leases
            .len()
            .saturating_add(self.offers.len())
            .saturating_add(self.declined.len())
    }

    /// Reserves one dynamic slot, not counting the entries this transition removes.
    fn admit_dynamic_after_removing(&mut self, removing: usize) -> bool {
        let entries = self.dynamic_entries().saturating_sub(removing);
        Self::admit_state(&mut self.dynamic_limited, "dynamic", entries)
    }

    fn occupy_in(address_use: &mut HashMap<u32, u32>, ip: u32) {
        let count = address_use.entry(ip).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn vacate_in(address_use: &mut HashMap<u32, u32>, ip: u32) {
        let Some(count) = address_use.get_mut(&ip) else {
            return;
        };
        if *count <= 1 {
            address_use.remove(&ip);
        } else {
            *count -= 1;
        }
    }

    /// How many of this client's leases, offers and static assignments point at `ip`.
    fn own_address_references(&self, identity: &ClientIdentity, ip: u32) -> u32 {
        u32::from(
            self.leases
                .get(identity)
                .is_some_and(|lease| lease.ip == ip),
        )
        .saturating_add(u32::from(
            self.offers
                .get(identity)
                .is_some_and(|(offered, _, _)| *offered == ip),
        ))
        .saturating_add(u32::from(
            self.reservations
                .get(identity)
                .is_some_and(|(reserved, _)| *reserved == ip),
        ))
    }

    /// Expects the caller to have cleaned up expired state.
    fn address_used_by_other_inner(&self, identity: &ClientIdentity, ip: u32) -> bool {
        self.address_use.get(&ip).copied().unwrap_or(0) > self.own_address_references(identity, ip)
    }

    fn has_record(&mut self, identity: &ClientIdentity) -> bool {
        self.cleanup_expired(crate::unix_now());
        self.leases.contains_key(identity)
    }

    fn address_used_by_other(&mut self, identity: &ClientIdentity, ip: u32) -> bool {
        self.cleanup_expired(crate::unix_now());
        self.address_used_by_other_inner(identity, ip)
    }

    /// Shrinks a map left sparse by mass expiry or release.
    fn shrink_map_if_sparse<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
        let len = map.len();
        if len == 0 {
            *map = HashMap::new();
        } else if map.capacity() > len.saturating_mul(4).max(16) {
            map.shrink_to(len.saturating_mul(2));
        }
    }

    fn rebuild_address_use(&mut self) {
        let mut address_use = HashMap::with_capacity(
            self.dynamic_entries()
                .saturating_add(self.reservations.len())
                .saturating_add(4),
        );
        let net = self.server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        for ip in [self.server_ip, self.router, net, bcast] {
            if ip >= self.start && ip <= self.end {
                Self::occupy_in(&mut address_use, ip);
            }
        }
        for lease in self.leases.values() {
            Self::occupy_in(&mut address_use, lease.ip);
        }
        for (ip, _, _) in self.offers.values() {
            Self::occupy_in(&mut address_use, *ip);
        }
        for ip in self.declined.keys() {
            Self::occupy_in(&mut address_use, *ip);
        }
        for (ip, _) in self.reservations.values() {
            Self::occupy_in(&mut address_use, *ip);
        }
        self.address_use = address_use;
        self.next_expiry = self
            .leases
            .values()
            .map(|lease| lease.expiry)
            .chain(self.offers.values().map(|(_, _, expiry)| *expiry))
            .chain(self.declined.values().copied())
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Constant time until the earliest expiry; then sweeps expired state once.
    fn cleanup_expired(&mut self, now: u64) {
        if now < self.next_expiry {
            return;
        }
        let mut next_expiry = u64::MAX;
        let address_use = &mut self.address_use;
        self.leases.retain(|_, lease| {
            if lease.expiry <= now {
                Self::vacate_in(address_use, lease.ip);
                false
            } else {
                next_expiry = next_expiry.min(lease.expiry);
                true
            }
        });
        self.offers.retain(|_, (ip, _, expiry)| {
            if *expiry <= now {
                Self::vacate_in(address_use, *ip);
                false
            } else {
                next_expiry = next_expiry.min(*expiry);
                true
            }
        });
        self.declined.retain(|ip, expiry| {
            if *expiry <= now {
                Self::vacate_in(address_use, *ip);
                false
            } else {
                next_expiry = next_expiry.min(*expiry);
                true
            }
        });
        self.next_expiry = next_expiry;
        Self::shrink_map_if_sparse(&mut self.leases);
        Self::shrink_map_if_sparse(&mut self.offers);
        Self::shrink_map_if_sparse(&mut self.declined);
        Self::shrink_map_if_sparse(&mut self.address_use);
    }

    /// Picks a free address from the use index and a rotating cursor.
    fn pick_available(&mut self) -> Option<u32> {
        if self.start > self.end {
            return None;
        }
        let span = u64::from(self.end) - u64::from(self.start) + 1;
        let probes = span.min(self.address_use.len().saturating_add(1) as u64);
        let mut candidate =
            if self.allocation_cursor >= self.start && self.allocation_cursor <= self.end {
                self.allocation_cursor
            } else {
                self.start
            };
        for _ in 0..probes {
            let next = if candidate == self.end {
                self.start
            } else {
                candidate + 1
            };
            if !self.address_use.contains_key(&candidate) {
                self.allocation_cursor = next;
                return Some(candidate);
            }
            candidate = next;
        }
        self.allocation_cursor = candidate;
        None
    }

    /// Refuses addresses outside the subnet, the network and broadcast addresses, and the server
    /// and gateway addresses: the client could not talk, or would disturb the whole network.
    fn validate_reservation_ip(&self, ip: u32) -> Result<(), String> {
        let net = self.server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        if (ip & self.subnet_mask) != net {
            return Err(format!(
                "{} is outside the server subnet",
                Ipv4Addr::from(ip)
            ));
        }
        if ip == net || ip == bcast {
            return Err(format!(
                "{} is the network or broadcast address",
                Ipv4Addr::from(ip)
            ));
        }
        if ip == self.server_ip || ip == self.router {
            return Err(format!(
                "{} is the server or gateway address",
                Ipv4Addr::from(ip)
            ));
        }
        Ok(())
    }

    /// Drops overlapping static assignments, leases outside the range, and leases on another
    /// client's static address.
    fn revalidate_loaded_state(&mut self) {
        let now = crate::unix_now();
        let mut seen = std::collections::HashSet::new();
        let invalid_reservations: Vec<ClientIdentity> = self
            .reservations
            .iter()
            .filter_map(|(identity, (ip, _))| {
                let invalid = self.validate_reservation_ip(*ip).is_err() || !seen.insert(*ip);
                invalid.then(|| identity.clone())
            })
            .collect();
        for identity in invalid_reservations {
            self.reservations.remove(&identity);
            onetdns_core::warn!(event = "dhcp4.static_entry_invalid", identity = %identity.to_text(), "Skipped an invalid DHCP static lease entry");
        }
        let reservation_owners: std::collections::HashMap<u32, ClientIdentity> = self
            .reservations
            .iter()
            .map(|(identity, (ip, _))| (*ip, identity.clone()))
            .collect();
        let reservations = &self.reservations;
        let start = self.start;
        let end = self.end;
        let server_ip = self.server_ip;
        let router = self.router;
        let net = server_ip & self.subnet_mask;
        let bcast = net | !self.subnet_mask;
        let mut lease_ips = std::collections::HashSet::new();
        self.leases.retain(|identity, lease| {
            let reserved_by_other = reservation_owners
                .get(&lease.ip)
                .is_some_and(|owner| owner != identity);
            let address_allowed = match reservations.get(identity) {
                Some((reserved, _)) => *reserved == lease.ip,
                None => {
                    lease.ip >= start
                        && lease.ip <= end
                        && lease.ip != server_ip
                        && lease.ip != router
                        && lease.ip != net
                        && lease.ip != bcast
                }
            };
            let valid = lease.expiry > now
                && address_allowed
                && !reserved_by_other
                && lease_ips.insert(lease.ip);
            if !valid {
                onetdns_core::warn!(event = "dhcp4.stale_lease_dropped", identity = %identity.to_text(), ip = %Ipv4Addr::from(lease.ip), "Removed saved leases outside the current DHCP address range");
            }
            valid
        });
    }

    pub fn hold_offer(&mut self, identity: &ClientIdentity, xid: u32, ip: u32) -> bool {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if !self.offers.contains_key(identity) && !self.admit_dynamic_after_removing(0) {
            return false;
        }
        let expiry = now.saturating_add(60);
        match self.offers.insert(identity.clone(), (ip, xid, expiry)) {
            Some((old_ip, _, _)) if old_ip != ip => {
                Self::vacate_in(&mut self.address_use, old_ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry);
        true
    }

    /// Both the transaction ID and the address must match; otherwise this server would confirm an
    /// address another server offered.
    fn consume_offer(&mut self, identity: &ClientIdentity, xid: u32, ip: u32) -> bool {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let valid = matches!(
            self.offers.get(identity),
            Some((held, held_xid, expiry)) if *held == ip && *held_xid == xid && *expiry > now
        );
        if valid {
            if let Some((removed_ip, _, _)) = self.offers.remove(identity) {
                Self::vacate_in(&mut self.address_use, removed_ip);
            }
        }
        valid
    }

    /// Only the address's holder can decline it; otherwise a few messages would empty the range.
    pub fn decline(&mut self, identity: &ClientIdentity, ip: u32) {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let owns = self
            .offers
            .get(identity)
            .map(|(oip, ..)| *oip == ip)
            .unwrap_or(false)
            || self
                .leases
                .get(identity)
                .is_some_and(|lease| lease.ip == ip && lease.expiry > now);
        if owns && !self.declined.contains_key(&ip) {
            let removing = usize::from(self.leases.contains_key(identity))
                .saturating_add(usize::from(self.offers.contains_key(identity)));
            if !self.admit_dynamic_after_removing(removing) {
                return;
            }
        }
        if let Some(lease) = self.leases.remove(identity) {
            Self::vacate_in(&mut self.address_use, lease.ip);
            self.save();
        }
        if let Some((removed_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, removed_ip);
        }
        if owns && ip >= self.start && ip <= self.end {
            let expiry = now.saturating_add(600);
            if self.declined.insert(ip, expiry).is_none() {
                Self::occupy_in(&mut self.address_use, ip);
            }
            self.next_expiry = self.next_expiry.min(expiry);
        }
    }

    /// The static address, else the address already held, else the first free one. Offered and
    /// declined addresses are skipped.
    pub fn allocate(&mut self, identity: &ClientIdentity) -> Option<u32> {
        if let Some((ip, _)) = self.reservations.get(identity) {
            return Some(*ip);
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if let Some((ip, _, expiry)) = self.offers.get(identity) {
            if *expiry > now {
                return Some(*ip);
            }
        }
        if let Some(l) = self.leases.get(identity) {
            if l.expiry > now {
                return Some(l.ip);
            }
        }
        if !self.admit_dynamic_after_removing(0) {
            return None;
        }

        let picked = self.pick_available();
        match (picked, self.exhausted) {
            (None, false) => {
                self.exhausted = true;
                onetdns_core::warn!(event = "dhcp4.pool_exhausted", range_start = %Ipv4Addr::from(self.start), range_end = %Ipv4Addr::from(self.end), indexed_addresses = self.address_use.len(), "DHCP address range is full; new devices cannot get an address");
            }
            (Some(_), true) => {
                self.exhausted = false;
                onetdns_core::info!(event = "dhcp4.pool_available", range_start = %Ipv4Addr::from(self.start), range_end = %Ipv4Addr::from(self.end), "DHCP address range has free addresses again");
            }
            _ => {}
        }
        picked
    }

    pub fn reservation_ip(&self, identity: &ClientIdentity) -> Option<u32> {
        self.reservations.get(identity).map(|(ip, _)| *ip)
    }

    pub fn is_reserved_by_other(&self, ip: u32, identity: &ClientIdentity) -> bool {
        self.reservations
            .iter()
            .any(|(owner, (reserved, _))| *reserved == ip && owner != identity)
    }

    /// Removes another client's lease on that address; otherwise two clients share it.
    pub fn add_reservation(
        &mut self,
        identity: ClientIdentity,
        ip: u32,
        hostname: Option<String>,
    ) -> Result<(), String> {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return Err(
                "hostname must be 1 to 255 bytes and cannot contain spaces or control characters"
                    .to_string(),
            );
        }
        self.validate_reservation_ip(ip)?;
        if self.is_reserved_by_other(ip, &identity) {
            return Err(format!(
                "IP {} is already reserved for another client identifier",
                Ipv4Addr::from(ip)
            ));
        }
        if !self.reservations.contains_key(&identity)
            && !Self::admit_state(
                &mut self.reservations_limited,
                "reservations",
                self.reservations.len(),
            )
        {
            return Err(format!(
                "At most {MAX_STATE_ENTRIES} DHCPv4 static assignments are allowed"
            ));
        }
        let now = crate::unix_now();
        let stale: Vec<ClientIdentity> = self
            .leases
            .iter()
            .filter(|(owner, lease)| lease.ip == ip && lease.expiry > now && *owner != &identity)
            .map(|(owner, _)| owner.clone())
            .collect();
        let freed = !stale.is_empty();
        for owner in stale {
            if let Some(lease) = self.leases.remove(&owner) {
                Self::vacate_in(&mut self.address_use, lease.ip);
            }
        }
        match self.reservations.insert(identity, (ip, hostname)) {
            Some((old_ip, _)) if old_ip != ip => {
                Self::vacate_in(&mut self.address_use, old_ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.save_static();
        if freed {
            Self::shrink_map_if_sparse(&mut self.leases);
            self.save();
        }
        Ok(())
    }

    pub fn remove_reservation(&mut self, identity: &ClientIdentity) -> bool {
        if let Some((ip, _)) = self.reservations.remove(identity) {
            Self::vacate_in(&mut self.address_use, ip);
            Self::shrink_map_if_sparse(&mut self.reservations);
            Self::shrink_map_if_sparse(&mut self.address_use);
            self.save_static();
            true
        } else {
            false
        }
    }

    pub fn reservations(&self) -> Vec<ReservationInfo> {
        let mut out: Vec<ReservationInfo> = self
            .reservations
            .iter()
            .map(|(identity, (ip, h))| ReservationInfo {
                identity: identity.clone(),
                ip: Ipv4Addr::from(*ip),
                hostname: h.clone(),
            })
            .collect();
        out.sort_by_key(|r| u32::from(r.ip));
        out
    }

    /// Lease names become DNS names, so a client cannot take one another client holds or an
    /// operator reserved, nor one that other hosts look up to configure a proxy or a tunnel.
    fn client_may_use(&self, identity: &ClientIdentity, name: &str, now: u64) -> bool {
        const DISCOVERY_NAMES: [&str; 2] = ["wpad", "isatap"];
        let held_by_other = |owner: &ClientIdentity, held: Option<&str>| {
            owner != identity && held.is_some_and(|held| held.eq_ignore_ascii_case(name))
        };
        !DISCOVERY_NAMES
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(name))
            && !self
                .reservations
                .iter()
                .any(|(owner, (_, held))| held_by_other(owner, held.as_deref()))
            && !self.leases.iter().any(|(owner, lease)| {
                lease.expiry > now && held_by_other(owner, lease.hostname.as_deref())
            })
    }

    pub fn commit(
        &mut self,
        identity: &ClientIdentity,
        mac: [u8; 6],
        ip: u32,
        hostname: Option<String>,
    ) -> bool {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return false;
        }
        let now = crate::unix_now();
        let previous = self
            .leases
            .get(identity)
            .and_then(|lease| lease.hostname.clone());
        let hostname = self
            .reservations
            .get(identity)
            .and_then(|(_, reserved)| reserved.clone())
            .or_else(|| {
                [hostname, previous]
                    .into_iter()
                    .flatten()
                    .find(|name| self.client_may_use(identity, name, now))
            });
        self.cleanup_expired(now);
        if !self.leases.contains_key(identity) {
            let removing = usize::from(self.offers.contains_key(identity));
            if !self.admit_dynamic_after_removing(removing) {
                return false;
            }
        }
        let expiry = lease_expiry(now, self.lease_secs);
        if let Some((offer_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, offer_ip);
        }
        match self.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry,
                hostname,
            },
        ) {
            Some(old) if old.ip != ip => {
                Self::vacate_in(&mut self.address_use, old.ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry);
        self.save();
        true
    }

    /// Whether an address received over HA can belong to this identity.
    fn validate_synced_lease_inner(
        &self,
        identity: &ClientIdentity,
        ip: u32,
    ) -> Result<(), String> {
        match self.reservations.get(identity) {
            Some((reserved, _)) if *reserved != ip => {
                return Err(format!(
                    "Client {} is assigned to IP {}",
                    identity.to_text(),
                    Ipv4Addr::from(*reserved)
                ));
            }
            None if ip < self.start || ip > self.end => {
                return Err(format!(
                    "IP {} is outside the DHCP dynamic range",
                    Ipv4Addr::from(ip)
                ));
            }
            _ => {}
        }

        if self.address_used_by_other_inner(identity, ip) {
            return Err(format!(
                "IP {} is already used by another DHCP entry",
                Ipv4Addr::from(ip)
            ));
        }
        Ok(())
    }

    /// Checks a whole HA batch, address ownership and state budget, before applying any of it.
    pub fn validate_synced_batch(
        &mut self,
        entries: impl IntoIterator<Item = (ClientIdentity, u32, u64)>,
    ) -> Result<(), String> {
        let now = crate::unix_now();
        self.cleanup_expired(now);
        let mut projected = self.dynamic_entries();
        for (identity, ip, expiry) in entries {
            if expiry <= now {
                return Err(format!(
                    "The lease for client {} has already expired",
                    identity.to_text()
                ));
            }
            self.validate_synced_lease_inner(&identity, ip)?;

            let lease = self.leases.get(&identity);
            if lease.is_some_and(|existing| existing.ip == ip && existing.expiry >= expiry) {
                continue;
            }
            if lease.is_some() {
                projected =
                    projected.saturating_sub(usize::from(self.offers.contains_key(&identity)));
            } else if !self.offers.contains_key(&identity) {
                if projected >= MAX_STATE_ENTRIES {
                    return Err(format!(
                        "At most {MAX_STATE_ENTRIES} DHCPv4 dynamic entries are allowed"
                    ));
                }
                projected += 1;
            }
        }
        Ok(())
    }

    /// Takes a lease from HA unless a newer one is already held.
    pub fn insert(
        &mut self,
        identity: &ClientIdentity,
        mac: [u8; 6],
        ip: u32,
        expiry_unix: u64,
        hostname: Option<String>,
    ) -> bool {
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
        {
            return false;
        }
        let now = crate::unix_now();
        self.cleanup_expired(now);
        if expiry_unix <= now {
            return false;
        }
        if self.validate_synced_lease_inner(identity, ip).is_err() {
            return false;
        }
        if let Some(existing) = self.leases.get(identity) {
            if existing.expiry >= expiry_unix && existing.ip == ip {
                return false;
            }
        }
        if !self.leases.contains_key(identity) {
            let removing = usize::from(self.offers.contains_key(identity));
            if !self.admit_dynamic_after_removing(removing) {
                return false;
            }
        }
        if let Some((offer_ip, _, _)) = self.offers.remove(identity) {
            Self::vacate_in(&mut self.address_use, offer_ip);
        }
        match self.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry: expiry_unix,
                hostname,
            },
        ) {
            Some(old) if old.ip != ip => {
                Self::vacate_in(&mut self.address_use, old.ip);
                Self::occupy_in(&mut self.address_use, ip);
            }
            None => Self::occupy_in(&mut self.address_use, ip),
            _ => {}
        }
        self.next_expiry = self.next_expiry.min(expiry_unix);
        true
    }

    /// Removes the lease only when the client holds that address.
    pub fn release(&mut self, identity: &ClientIdentity, ip: u32) {
        if self
            .leases
            .get(identity)
            .is_some_and(|lease| lease.ip == ip)
        {
            if let Some(lease) = self.leases.remove(identity) {
                Self::vacate_in(&mut self.address_use, lease.ip);
                Self::shrink_map_if_sparse(&mut self.leases);
                Self::shrink_map_if_sparse(&mut self.address_use);
                self.save();
            }
        }
    }

    pub fn active(&self) -> usize {
        let now = crate::unix_now();
        self.leases.values().filter(|l| l.expiry > now).count()
    }

    /// Live leases, by address. The dashboard shows them.
    pub fn snapshot(&self) -> Vec<LeaseInfo> {
        let now = crate::unix_now();
        let mut out: Vec<LeaseInfo> = self
            .leases
            .iter()
            .filter(|(_, l)| l.expiry > now)
            .map(|(identity, l)| LeaseInfo {
                identity: identity.clone(),
                mac: l.mac,
                ip: Ipv4Addr::from(l.ip),
                expiry_unix: l.expiry,
                hostname: l.hostname.clone(),
            })
            .collect();
        out.sort_by_key(|i| u32::from(i.ip));
        out
    }

    pub fn save(&self) {
        let Some(path) = &self.persist else { return };
        let now = crate::unix_now();
        let mut text = String::from(LEASE_HEADER);
        for (identity, l) in self.leases.iter().filter(|(_, l)| l.expiry > now) {
            text.push_str(&format!(
                "{} {} {} {}",
                identity.to_text(),
                mac_hex(&l.mac),
                Ipv4Addr::from(l.ip),
                l.expiry
            ));
            if let Some(h) = &l.hostname {
                text.push(' ');
                text.push_str(h);
            }
            text.push('\n');
        }
        if let Err(e) = crate::atomic_file::atomic_write(path, text.as_bytes()) {
            onetdns_core::warn!(event = "dhcp4.lease_save_failed", path = ?path, error = %e, "Could not save DHCP leases to file");
        }
    }

    fn save_static(&self) {
        let Some(path) = &self.static_persist else {
            return;
        };
        let mut text = String::from(RESERVATION_HEADER);
        for (identity, (ip, h)) in &self.reservations {
            text.push_str(&format!("{} {}", identity.to_text(), Ipv4Addr::from(*ip)));
            if let Some(h) = h {
                text.push(' ');
                text.push_str(h);
            }
            text.push('\n');
        }
        if let Err(e) = crate::atomic_file::atomic_write(path, text.as_bytes()) {
            onetdns_core::warn!(event = "dhcp4.static_save_failed", path = ?path, error = %e, "Could not save DHCP static leases");
        }
    }
}

/// Fails on any malformed line instead of skipping it: operators edit this file, and saving an
/// empty table over it would erase their assignments. A missing file reads as empty.
pub fn read_reservations(
    path: &std::path::Path,
) -> Result<HashMap<ClientIdentity, (u32, Option<String>)>, String> {
    let shown = path.display();
    let bytes = match std::fs::File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(MAX_PERSIST_FILE + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    format!("Could not read the DHCP static assignment file ({shown}): {error}")
                })?;
            bytes
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(format!(
                "Could not open the DHCP static assignment file ({shown}): {error}"
            ));
        }
    };
    if bytes.len() as u64 > MAX_PERSIST_FILE {
        return Err(format!(
            "DHCP static assignment file exceeds the {MAX_PERSIST_FILE}-byte limit ({shown})"
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("DHCP static assignment file is not UTF-8 text ({shown})"))?;
    let body = text.strip_prefix(RESERVATION_HEADER).ok_or_else(|| {
        format!(
            "The first line of the DHCP static assignment file ({shown}) must be {}",
            RESERVATION_HEADER.trim_end()
        )
    })?;
    let mut out = HashMap::new();
    for (index, line) in body.lines().enumerate() {
        let line_no = index + 2;
        if out.len() >= MAX_STATE_ENTRIES {
            return Err(format!(
                "DHCP static assignment file ({shown}) has more than {MAX_STATE_ENTRIES} entries"
            ));
        }
        let bad =
            || format!("Line {line_no} of the DHCP static assignment file ({shown}) is malformed");
        let mut toks = line.split_whitespace();
        let (Some(identity_s), Some(ip_s)) = (toks.next(), toks.next()) else {
            return Err(bad());
        };
        let (Some(identity), Ok(ip)) = (
            ClientIdentity::from_text(identity_s),
            ip_s.parse::<Ipv4Addr>(),
        ) else {
            return Err(bad());
        };
        let hostname = toks.next().map(|s| s.to_string());
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
            || toks.next().is_some()
        {
            return Err(bad());
        }
        if out.insert(identity, (u32::from(ip), hostname)).is_some() {
            return Err(format!(
                "Line {line_no} of the DHCP static assignment file ({shown}) repeats a client listed earlier"
            ));
        }
    }
    Ok(out)
}

fn mac_hex(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

fn mac_from_hex(s: &str) -> Option<[u8; 6]> {
    if s.len() != 12 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// Lossless lowercase hex.
fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Even-length hex up to the option 61 size.
fn bytes_from_hex(text: &str) -> Option<Vec<u8>> {
    if !(4..=510).contains(&text.len())
        || text.len() % 2 != 0
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[index..index + 2], 16).ok()?);
    }
    Some(out)
}

/// Drops the whole file on any malformed line: a partial read loses which addresses are out,
/// and the same address goes to two clients.
fn load_leases(path: &std::path::Path) -> HashMap<ClientIdentity, Lease> {
    let mut out = HashMap::new();
    let mut seen_ips = std::collections::HashSet::new();
    let Some(text) = read_persist_text(path) else {
        return out;
    };
    let Some(text) = text.strip_prefix(LEASE_HEADER) else {
        onetdns_core::warn!(event = "dhcp4.leases_restore_invalid", path = %path.display(), "DHCP lease file does not match the current format; starting empty");
        return out;
    };
    let now = crate::unix_now();
    let mut malformed = 0u64;
    for line in text.lines() {
        if out.len() >= MAX_STATE_ENTRIES {
            malformed = malformed.saturating_add(1);
            continue;
        }
        let mut toks = line.split_whitespace();
        let (Some(identity_s), Some(mac_s), Some(ip_s), Some(exp_s)) =
            (toks.next(), toks.next(), toks.next(), toks.next())
        else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let (Some(identity), Some(mac), Ok(ip), Ok(expiry)) = (
            ClientIdentity::from_text(identity_s),
            mac_from_hex(mac_s),
            ip_s.parse::<Ipv4Addr>(),
            exp_s.parse::<u64>(),
        ) else {
            malformed = malformed.saturating_add(1);
            continue;
        };
        let hostname = toks.next().map(|s| s.to_string());
        if hostname
            .as_deref()
            .is_some_and(|value| !valid_hostname(value))
            || toks.next().is_some()
        {
            malformed = malformed.saturating_add(1);
            continue;
        }
        if expiry <= now {
            continue;
        }
        let ip = u32::from(ip);
        if identity
            .hardware()
            .is_some_and(|identity_mac| identity_mac != mac)
            || out.contains_key(&identity)
            || !seen_ips.insert(ip)
        {
            malformed = malformed.saturating_add(1);
            continue;
        }
        out.insert(
            identity,
            Lease {
                mac,
                ip,
                expiry,
                hostname,
            },
        );
    }
    if malformed > 0 {
        onetdns_core::warn!(
            event = "dhcp4.leases_restore_invalid",
            path = %path.display(),
            malformed,
            "DHCP lease file is corrupted; starting empty"
        );
        return HashMap::new();
    }
    out
}

/// What a client asked for, settled before any state changes.
enum ClientAction {
    Discover,
    Request { target: Ipv4Addr, selecting: bool },
    Decline { target: Ipv4Addr },
    Release { target: Ipv4Addr },
}

/// `Some(None)` when absent, `None` when present but not 4 bytes.
fn optional_ipv4_option(req: &DhcpMessage, code: u8) -> Option<Option<Ipv4Addr>> {
    match req.option(code) {
        Some(raw) => Some(Some(opt_ipv4(raw)?)),
        None => Some(None),
    }
}

/// Checks the RFC 2131 field combination for each client state before any state changes.
fn classify_client_action(req: &DhcpMessage, server_ip: Ipv4Addr) -> Option<ClientAction> {
    if req.flags & !BROADCAST_FLAG != 0
        || req.yiaddr != Ipv4Addr::UNSPECIFIED
        || req.siaddr != Ipv4Addr::UNSPECIFIED
    {
        return None;
    }
    let requested = optional_ipv4_option(req, OPT_REQUESTED_IP)?;
    let server = optional_ipv4_option(req, OPT_SERVER_ID)?;

    match req.msg_type()? {
        DISCOVER if req.ciaddr == Ipv4Addr::UNSPECIFIED && server.is_none() => {
            Some(ClientAction::Discover)
        }
        REQUEST => match (server, requested, req.ciaddr) {
            (Some(selected), Some(target), ciaddr)
                if selected == server_ip && ciaddr == Ipv4Addr::UNSPECIFIED =>
            {
                Some(ClientAction::Request {
                    target,
                    selecting: true,
                })
            }
            (None, Some(target), ciaddr) if ciaddr == Ipv4Addr::UNSPECIFIED => {
                Some(ClientAction::Request {
                    target,
                    selecting: false,
                })
            }
            (None, None, ciaddr) if ciaddr != Ipv4Addr::UNSPECIFIED => {
                Some(ClientAction::Request {
                    target: ciaddr,
                    selecting: false,
                })
            }
            _ => None,
        },
        DECLINE
            if req.flags == 0
                && req.ciaddr == Ipv4Addr::UNSPECIFIED
                && server == Some(server_ip) =>
        {
            Some(ClientAction::Decline { target: requested? })
        }
        RELEASE
            if req.flags == 0
                && req.ciaddr != Ipv4Addr::UNSPECIFIED
                && requested.is_none()
                && server == Some(server_ip) =>
        {
            Some(ClientAction::Release { target: req.ciaddr })
        }
        _ => None,
    }
}

/// Stays out of requests for another server, and refuses addresses another client holds or has
/// reserved; confirming them puts two clients on one address.
pub fn handle(req: &DhcpMessage, pool: &mut LeasePool, cfg: &DhcpConfig) -> Option<DhcpMessage> {
    let identity = req.client_identity();
    match classify_client_action(req, cfg.server_ip)? {
        ClientAction::Discover => {
            let ip = pool.allocate(&identity)?;
            if !pool.hold_offer(&identity, req.xid, ip) {
                return None;
            }
            Some(build_reply(req, OFFER, Ipv4Addr::from(ip), cfg))
        }
        ClientAction::Request { target, selecting } => {
            let want_u = u32::from(target);
            if selecting && !pool.consume_offer(&identity, req.xid, want_u) {
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = "no_matching_offer", "Declined a request to confirm an address this server never offered");
                return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
            }
            if let Some(rip) = pool.reservation_ip(&identity) {
                if rip != want_u {
                    onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reserved = %Ipv4Addr::from(rip), reason = "reserved_address_mismatch", "Declined a request for an address other than the static lease");
                    return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
                }
                if !pool.address_used_by_other(&identity, rip)
                    && pool.commit(&identity, req.chaddr, rip, req.hostname())
                {
                    return Some(build_reply(req, ACK, Ipv4Addr::from(rip), cfg));
                }
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %Ipv4Addr::from(rip), reason = "reserved_address_unavailable", "Declined because the static lease address cannot be confirmed safely");
                return Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg));
            }
            let used_by_other = pool.address_used_by_other(&identity, want_u);
            if want_u >= pool.start && want_u <= pool.end && !used_by_other {
                if pool.commit(&identity, req.chaddr, want_u, req.hostname()) {
                    Some(build_reply(req, ACK, target, cfg))
                } else {
                    onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = "lease_state_limit", "Not confirming a new address because the lease table is full");
                    Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg))
                }
            } else {
                // A client unknown here that asks for an address on this subnet but outside
                // this pool got it from another server. RFC 2131 says not to answer clients
                // without a record; a NAK would make it drop that address. Addresses in this
                // pool are ours to refuse, and one off the subnet means the client moved
                // networks: both get a NAK.
                let outside_pool = want_u < pool.start || want_u > pool.end;
                if !selecting
                    && outside_pool
                    && in_served_subnet(target, cfg)
                    && !pool.has_record(&identity)
                {
                    onetdns_core::debug!(event = "dhcp4.request_ignored", identity = %identity.to_text(), requested = %target, reason = "unknown_client", "Not answering a same-network address request from an unknown client");
                    return None;
                }
                let reason = if want_u < pool.start || want_u > pool.end {
                    "out_of_range"
                } else {
                    "used_by_other"
                };
                onetdns_core::debug!(event = "dhcp4.request_rejected", identity = %identity.to_text(), requested = %target, reason = reason, "Declined because the requested address cannot be given");
                Some(build_reply(req, NAK, Ipv4Addr::UNSPECIFIED, cfg))
            }
        }
        ClientAction::Release { target } => {
            pool.release(&identity, u32::from(target));
            None
        }
        ClientAction::Decline { target } => {
            pool.decline(&identity, u32::from(target));
            None
        }
    }
}

fn in_served_subnet(ip: Ipv4Addr, cfg: &DhcpConfig) -> bool {
    let mask = u32::from(cfg.subnet_mask);
    u32::from(ip) & mask == u32::from(cfg.server_ip) & mask
}

/// Refusals carry no configuration values.
fn build_reply(req: &DhcpMessage, mtype: u8, yiaddr: Ipv4Addr, cfg: &DhcpConfig) -> DhcpMessage {
    let mut options = vec![
        (OPT_MSG_TYPE, vec![mtype]),
        (OPT_SERVER_ID, cfg.server_ip.octets().to_vec()),
    ];
    if mtype != NAK {
        options.push((OPT_LEASE_TIME, cfg.lease_secs.to_be_bytes().to_vec()));
        options.push((OPT_SUBNET_MASK, cfg.subnet_mask.octets().to_vec()));
        options.push((OPT_ROUTER, cfg.router.octets().to_vec()));
        let dns: Vec<u8> = cfg.dns.iter().flat_map(|d| d.octets()).collect();
        if !dns.is_empty() {
            options.push((OPT_DNS, dns));
        }

        if let Some(domain) = &cfg.domain_name {
            options.push((OPT_DOMAIN_NAME, domain.as_bytes().to_vec()));
        }
        if let Some(tftp) = cfg.tftp_server {
            options.push((OPT_TFTP_SERVER_NAME, tftp.to_string().into_bytes()));
        }
        if let Some(bf) = &cfg.boot_file {
            options.push((OPT_BOOTFILE, bf.as_bytes().to_vec()));
        }
    }
    DhcpMessage {
        op: 2,
        xid: req.xid,
        flags: if mtype == NAK && req.giaddr != Ipv4Addr::UNSPECIFIED {
            req.flags | BROADCAST_FLAG
        } else {
            req.flags
        },
        ciaddr: if mtype == ACK {
            req.ciaddr
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        yiaddr,

        siaddr: if mtype != NAK {
            cfg.tftp_server.unwrap_or(cfg.server_ip)
        } else {
            Ipv4Addr::UNSPECIFIED
        },
        giaddr: req.giaddr,
        chaddr: req.chaddr,
        client_identifier: None,
        options,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Whether a reply can go through the IP stack or needs a direct link-layer send.
enum ReplyTarget {
    Udp(std::net::SocketAddr),
    /// A client with no address yet: its `yiaddr` and Ethernet destination.
    InitialUnicast {
        ip: Ipv4Addr,
        mac: [u8; 6],
    },
}

fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/// Picks the RFC 2131 IP and link-layer destination from the request and the reply.
fn reply_target(req: &DhcpMessage, reply: &DhcpMessage) -> ReplyTarget {
    if req.giaddr != Ipv4Addr::UNSPECIFIED {
        ReplyTarget::Udp(std::net::SocketAddr::from((req.giaddr, 67)))
    } else if reply.msg_type() == Some(NAK) {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    } else if req.ciaddr != Ipv4Addr::UNSPECIFIED {
        ReplyTarget::Udp(std::net::SocketAddr::from((req.ciaddr, 68)))
    } else if req.flags & BROADCAST_FLAG != 0 {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    } else if unicast_mac(req.chaddr) {
        ReplyTarget::InitialUnicast {
            ip: reply.yiaddr,
            mac: req.chaddr,
        }
    } else {
        ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
    }
}

/// When the link-layer unicast fails, sends once more by broadcast, as RFC 2131 allows.
fn send_initial_with_fallback<U, B>(unicast: U, broadcast: B) -> std::io::Result<bool>
where
    U: FnOnce() -> std::io::Result<()>,
    B: FnOnce() -> std::io::Result<()>,
{
    if unicast().is_ok() {
        Ok(true)
    } else {
        broadcast()?;
        Ok(false)
    }
}

/// Relayed requests come to the server address directly, whatever the interface. Accepts the
/// request when either interface is unknown.
fn from_served_link(giaddr: Ipv4Addr, arrival: Option<u32>, served: Option<u32>) -> bool {
    if giaddr != Ipv4Addr::UNSPECIFIED {
        return true;
    }
    match (arrival, served) {
        (Some(arrival), Some(served)) => arrival == served,
        _ => true,
    }
}

pub fn spawn_dhcp(
    cfg: DhcpConfig,
    port: u16,
    pool: std::sync::Arc<std::sync::Mutex<LeasePool>>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use onetdns_core::MutexExt;
    let sock = crate::dhcp_l2::bind_server_socket(cfg.server_ip, port)?;
    sock.set_broadcast(true)?;
    let wait = onetdns_core::udp::RecvWait::new(Duration::from_millis(500));
    wait.install(&sock)?;
    std::thread::Builder::new().name("dhcp".into()).spawn(move || {
        let mut buf = vec![0u8; DHCP4_RECV_CAPACITY];
        let mut served = crate::dhcp_l2::served_interface(cfg.server_ip);
        while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            let (n, arrival) = match crate::dhcp_l2::recv_request(&sock, wait, &mut buf) {
                Ok(received) => received,
                Err(error) => {
                    if !matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) {
                        onetdns_core::warn!(event = "dhcp4.recv_failed", %error, "Failed to receive a DHCP request");
                    }
                    continue;
                }
            };
            let Some(n) = standard_dhcp4_datagram_len(n) else {
                continue;
            };
            let Some(req) = parse_client_request(&buf[..n]) else { continue };
            if !from_served_link(req.giaddr, arrival, served) {
                // Interface indexes change when an interface is recreated, so look it up
                // once more first.
                served = crate::dhcp_l2::served_interface(cfg.server_ip);
                if !from_served_link(req.giaddr, arrival, served) {
                    continue;
                }
            }
            let reply = handle(&req, &mut pool.lock_recover(), &cfg);
            if let Some(reply) = reply {
                if reply.msg_type() == Some(ACK) {
                    onetdns_core::debug!(event = "dhcp4.lease_issued", ip = %reply.yiaddr, active = pool.lock_recover().active(), "Issued a DHCP lease");
                }
                let wire = reply.encode();
                let target = reply_target(&req, &reply);
                let sent = match target {
                    ReplyTarget::Udp(destination) if destination.ip() == std::net::IpAddr::V4(Ipv4Addr::BROADCAST) => {
                        crate::dhcp_l2::send_broadcast(&sock, cfg.server_ip, destination.port(), &wire).map(|_| true)
                    }
                    ReplyTarget::Udp(destination) => {
                        sock.send_to(&wire, destination).map(|_| true)
                    }
                    ReplyTarget::InitialUnicast { ip, mac } => send_initial_with_fallback(
                        || {
                            crate::dhcp_l2::send_initial_unicast(
                                &sock,
                                cfg.server_ip,
                                port,
                                ip,
                                mac,
                                &wire,
                            )
                            .map_err(|error| {
                                onetdns_core::warn!(event = "dhcp4.initial_unicast_fallback", ip = %ip, mac = %mac_hex(&mac), %error, "Cannot send L2 unicast to a client without an address; resending as broadcast");
                                error
                            })
                        },
                        || crate::dhcp_l2::send_broadcast(&sock, cfg.server_ip, 68, &wire),
                    ),
                };
                if let Err(error) = sent {
                    onetdns_core::warn!(event = "dhcp4.send_failed", target = ?target, mac = %mac_hex(&req.chaddr), %error, "Failed to send a DHCP reply; the device will not get an address");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> DhcpConfig {
        DhcpConfig {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 102),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            lease_secs: 3600,
            tftp_server: None,
            boot_file: None,
            domain_name: None,
            lease_file: None,
            static_file: None,
        }
    }

    #[test]
    fn infinite_lease_stays_infinite_in_the_pool() {
        let mut c = cfg();
        c.lease_secs = u32::MAX;
        let mut pool = LeasePool::new(&c);
        let mac = [1, 2, 3, 4, 5, 6];
        let identity = ClientIdentity::Hardware(mac);
        assert!(pool.commit(&identity, mac, u32::from(c.range_start), None));
        assert_eq!(pool.leases.get(&identity).unwrap().expiry, u64::MAX);
    }

    fn name_of(pool: &LeasePool, identity: &ClientIdentity) -> Option<String> {
        pool.leases
            .get(identity)
            .and_then(|lease| lease.hostname.clone())
    }

    #[test]
    fn a_client_cannot_take_a_name_another_client_holds() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let (owner, other) = (identity_for(1), identity_for(2));
        assert!(pool.commit(
            &owner,
            mac_for(1),
            u32::from(c.range_end),
            Some("nas".into())
        ));
        // A lower address would win a lookup that goes by address order.
        assert!(pool.commit(
            &other,
            mac_for(2),
            u32::from(c.range_start),
            Some("NAS".into())
        ));
        assert_eq!(name_of(&pool, &owner).as_deref(), Some("nas"));
        assert_eq!(name_of(&pool, &other), None);

        pool.release(&owner, u32::from(c.range_end));
        assert!(pool.commit(
            &other,
            mac_for(2),
            u32::from(c.range_start),
            Some("nas".into())
        ));
        assert_eq!(name_of(&pool, &other).as_deref(), Some("nas"));
    }

    #[test]
    fn a_client_cannot_take_a_reserved_name_or_a_proxy_discovery_name() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.add_reservation(
            identity_for(1),
            u32::from(Ipv4Addr::new(192, 168, 1, 50)),
            Some("printer".into()),
        )
        .unwrap();
        for name in ["printer", "WPAD", "isatap"] {
            assert!(pool.commit(
                &identity_for(2),
                mac_for(2),
                u32::from(c.range_start),
                Some(name.into()),
            ));
            assert_eq!(name_of(&pool, &identity_for(2)), None, "{name}");
        }
    }

    fn mac_for(index: usize) -> [u8; 6] {
        let bytes = (index as u64).to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    fn identity_for(index: usize) -> ClientIdentity {
        ClientIdentity::Hardware(mac_for(index))
    }

    #[test]
    fn pxe_boot_options_in_ack() {
        let mut c = cfg();
        c.tftp_server = Some(Ipv4Addr::new(192, 168, 1, 5));
        c.boot_file = Some("pxelinux.0".to_string());
        let mut pool = LeasePool::new(&c);
        let mut req = discover([1, 2, 3, 4, 5, 6]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, [192, 168, 1, 100].to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));

        assert_eq!(ack.siaddr, Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(ack.option(OPT_BOOTFILE), Some(b"pxelinux.0".as_slice()));
    }

    #[test]
    fn allocate_prunes_expired_leases() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let expired_mac = [1, 2, 3, 4, 5, 6];
        pool.leases.insert(
            ClientIdentity::Hardware(expired_mac),
            Lease {
                mac: expired_mac,
                ip: u32::from(Ipv4Addr::new(192, 168, 1, 100)),
                expiry: crate::unix_now(),
                hostname: None,
            },
        );
        pool.rebuild_address_use();

        assert!(pool
            .allocate(&ClientIdentity::Hardware([6, 5, 4, 3, 2, 1]))
            .is_some());
        assert!(pool.leases.is_empty());
    }

    #[test]
    fn allocation_never_uses_server_or_router_address() {
        let mut c = cfg();
        c.range_start = Ipv4Addr::new(192, 168, 1, 1);
        c.range_end = Ipv4Addr::new(192, 168, 1, 3);
        c.router = Ipv4Addr::new(192, 168, 1, 2);
        let mut pool = LeasePool::new(&c);

        assert_eq!(
            pool.allocate(&ClientIdentity::Hardware([1, 2, 3, 4, 5, 6])),
            Some(u32::from(Ipv4Addr::new(192, 168, 1, 3)))
        );
    }

    #[test]
    fn address_index_releases_high_water_capacity_after_expiry() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let now = crate::unix_now();
        for index in 0..20_000 {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: u32::try_from(index).unwrap(),
                    expiry: now,
                    hostname: None,
                },
            );
        }
        pool.rebuild_address_use();
        assert!(pool.address_use.capacity() >= 20_000);

        pool.cleanup_expired(now);
        assert!(pool.leases.is_empty());
        assert_eq!(
            pool.leases.capacity(),
            0,
            "만료된 공격 임대의 기록 버킷도 함께 반환해야 합니다"
        );
        assert_eq!(pool.address_use.len(), 0);
        assert_eq!(
            pool.address_use.capacity(),
            0,
            "만료된 공격 상태의 점유 인덱스 버킷을 프로세스 수명 동안 붙들면 안 됩니다"
        );
    }

    #[test]
    fn runtime_offer_state_has_a_hard_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.offers.reserve(MAX_STATE_ENTRIES);
        for index in 0..MAX_STATE_ENTRIES {
            pool.offers.insert(
                identity_for(index),
                (u32::try_from(index).unwrap(), 1, u64::MAX),
            );
        }
        pool.rebuild_address_use();

        assert!(!pool.hold_offer(
            &identity_for(MAX_STATE_ENTRIES),
            2,
            u32::try_from(MAX_STATE_ENTRIES).unwrap(),
        ));
        assert_eq!(
            pool.offers.len(),
            MAX_STATE_ENTRIES,
            "공격자가 고른 식별자 수만큼 DHCPv4 제안 상태가 계속 자라면 안 됩니다"
        );
        assert!(pool.hold_offer(&identity_for(0), 3, 7));
        assert_eq!(pool.offers.len(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.offers.get(&identity_for(0)).map(|offer| offer.1),
            Some(3)
        );
    }

    #[test]
    fn runtime_dynamic_state_has_one_shared_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let lease_count = MAX_STATE_ENTRIES / 2;
        pool.leases.reserve(lease_count);
        for index in 0..lease_count {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: if index == 0 {
                        u32::from(Ipv4Addr::new(192, 168, 1, 100))
                    } else {
                        u32::try_from(index).unwrap()
                    },
                    expiry: u64::MAX,
                    hostname: None,
                },
            );
        }
        pool.offers.reserve(MAX_STATE_ENTRIES - lease_count);
        for index in lease_count..MAX_STATE_ENTRIES {
            pool.offers.insert(
                identity_for(index),
                (u32::try_from(index).unwrap(), 1, u64::MAX),
            );
        }
        pool.rebuild_address_use();

        let mut renewal = discover(mac_for(0));
        renewal.flags = 0;
        renewal.ciaddr = Ipv4Addr::new(192, 168, 1, 100);
        renewal.options = vec![(OPT_MSG_TYPE, vec![REQUEST])];
        let renewal_ack = handle(&renewal, &mut pool, &c).unwrap();
        assert_eq!(renewal_ack.msg_type(), Some(ACK));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);

        let extra = mac_for(MAX_STATE_ENTRIES);
        let nak = handle(&request(extra, [192, 168, 1, 101], None), &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert!(!pool.insert(&ClientIdentity::Hardware(extra), extra, 1, u64::MAX, None,));

        assert!(pool.commit(&identity_for(0), mac_for(0), 7, Some("renewed".into())));
        assert!(pool.commit(
            &identity_for(lease_count),
            mac_for(lease_count),
            8,
            Some("offered".into()),
        ));
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.leases.get(&identity_for(0)).map(|lease| lease.ip),
            Some(7)
        );
    }

    #[test]
    fn runtime_reservation_state_has_a_hard_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.reservations.reserve(MAX_STATE_ENTRIES);
        for index in 0..MAX_STATE_ENTRIES {
            pool.reservations.insert(
                identity_for(index),
                (u32::from(Ipv4Addr::new(10, 0, 0, 1)), None),
            );
        }
        pool.rebuild_address_use();

        let valid_ip = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        assert!(pool
            .add_reservation(identity_for(MAX_STATE_ENTRIES), valid_ip, None)
            .is_err());
        assert_eq!(pool.reservations.len(), MAX_STATE_ENTRIES);

        assert!(pool
            .add_reservation(identity_for(0), valid_ip, Some("updated".into()))
            .is_ok());
        assert_eq!(pool.reservations.len(), MAX_STATE_ENTRIES);
    }

    #[test]
    fn decline_transition_stays_inside_shared_cardinality_limit() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.declined.reserve(MAX_STATE_ENTRIES - 1);
        for index in 0..MAX_STATE_ENTRIES - 1 {
            pool.declined
                .insert(u32::try_from(index).unwrap(), u64::MAX);
        }
        let mac = mac_for(MAX_STATE_ENTRIES);
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        pool.leases.insert(
            identity.clone(),
            Lease {
                mac,
                ip,
                expiry: u64::MAX,
                hostname: None,
            },
        );
        pool.rebuild_address_use();

        pool.decline(&identity, ip);
        assert_eq!(pool.declined.len(), MAX_STATE_ENTRIES);
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert!(!pool.leases.contains_key(&identity));
        assert_eq!(pool.allocate(&identity_for(MAX_STATE_ENTRIES + 1)), None);
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_new_client_allocation_scaling -- --ignored --nocapture"]
    /// Measures whether picking an address for a new client scales with the state size.
    fn bench_dhcp4_new_client_allocation_scaling() {
        const OPS: usize = 256;
        const ROUNDS: usize = 6;

        for preload in [1_000usize, 20_000] {
            for round in 0..ROUNDS {
                let mut c = cfg();
                c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
                c.range_start = Ipv4Addr::new(10, 0, 0, 10);
                c.range_end = Ipv4Addr::new(10, 255, 255, 254);
                c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
                c.router = c.server_ip;
                c.dns = vec![c.server_ip];
                let mut pool = LeasePool::new(&c);
                pool.leases.reserve(preload);
                let first = u32::from(c.range_start);
                for index in 0..preload {
                    assert!(pool.commit(
                        &identity_for(index),
                        mac_for(index),
                        first + u32::try_from(index).unwrap(),
                        None,
                    ));
                }
                let address_slots = pool.address_use.capacity();

                let started = std::time::Instant::now();
                for index in preload..preload + OPS {
                    let mac = mac_for(index);
                    let identity = ClientIdentity::Hardware(mac);
                    let ip = std::hint::black_box(pool.allocate(&identity).unwrap());
                    assert!(pool.hold_offer(&identity, u32::try_from(index).unwrap(), ip));
                }
                let ns_per_op = started.elapsed().as_nanos() / OPS as u128;
                println!(
                    "dhcp4_allocate preload={preload} round={} ns_per_op={ns_per_op} address_slots={address_slots}",
                    round + 1
                );
            }
        }
    }

    fn discover(mac: [u8; 6]) -> DhcpMessage {
        DhcpMessage {
            op: 1,
            xid: 0x1234,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            client_identifier: None,
            options: vec![(OPT_MSG_TYPE, vec![DISCOVER])],
        }
    }

    fn request(mac: [u8; 6], ip: [u8; 4], server_id: Option<[u8; 4]>) -> DhcpMessage {
        let mut opts = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, ip.to_vec()),
        ];
        if let Some(sid) = server_id {
            opts.push((OPT_SERVER_ID, sid.to_vec()));
        }
        let mut m = discover(mac);
        m.options = opts;
        m
    }

    fn with_client_id(mut req: DhcpMessage, client_id: &[u8]) -> DhcpMessage {
        req.options.push((OPT_CLIENT_ID, client_id.to_vec()));
        DhcpMessage::parse(&req.encode()).expect("유효한 client identifier 요청")
    }

    #[test]
    fn client_identifier_requires_type_and_value() {
        let mut req = discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]);
        req.options.push((OPT_CLIENT_ID, vec![1]));
        assert!(DhcpMessage::parse(&req.encode()).is_none());

        let valid = with_client_id(discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]), &[7; 255]);
        assert_eq!(valid.option(OPT_CLIENT_ID).map(<[u8]>::len), Some(255));

        let mut too_long = discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1]);
        too_long.options.push((OPT_CLIENT_ID, vec![7; 128]));
        too_long.options.push((OPT_CLIENT_ID, vec![8; 128]));
        assert!(DhcpMessage::parse(&too_long.encode()).is_none());
    }

    #[test]
    fn distinct_client_identifiers_on_one_mac_get_distinct_bindings() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let first_id = [0, b'f', b'i', b'r', b's', b't'];
        let second_id = [0, b's', b'e', b'c', b'o', b'n', b'd'];

        let first_discover = with_client_id(discover(mac), &first_id);
        let first_offer = handle(&first_discover, &mut pool, &c).unwrap();
        assert!(first_offer.option(OPT_CLIENT_ID).is_none());
        let first_request = with_client_id(
            request(mac, first_offer.yiaddr.octets(), Some(c.server_ip.octets())),
            &first_id,
        );
        let first_ack = handle(&first_request, &mut pool, &c).unwrap();
        assert_eq!(first_ack.msg_type(), Some(ACK));
        assert!(first_ack.option(OPT_CLIENT_ID).is_none());

        let second_offer = handle(&with_client_id(discover(mac), &second_id), &mut pool, &c)
            .expect("두 번째 식별자에도 주소를 제안해야");
        assert_ne!(second_offer.yiaddr, first_offer.yiaddr);
    }

    #[test]
    fn one_client_identifier_across_macs_keeps_one_binding() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let client_id = [0, b's', b't', b'a', b'b', b'l', b'e'];
        let first_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let second_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 2];

        let first_discover = with_client_id(discover(first_mac), &client_id);
        let first_offer = handle(&first_discover, &mut pool, &c).unwrap();
        let first_request = with_client_id(
            request(
                first_mac,
                first_offer.yiaddr.octets(),
                Some(c.server_ip.octets()),
            ),
            &client_id,
        );
        assert_eq!(
            handle(&first_request, &mut pool, &c).unwrap().msg_type(),
            Some(ACK)
        );

        let moved_offer = handle(
            &with_client_id(discover(second_mac), &client_id),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(moved_offer.yiaddr, first_offer.yiaddr);
    }

    #[test]
    fn release_uses_client_identifier_instead_of_mac() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 1];
        let owner = [0, b'o', b'w', b'n', b'e', b'r'];
        let other = [0, b'o', b't', b'h', b'e', b'r'];
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        let owner_discover = with_client_id(discover(mac), &owner);
        let offer = handle(&owner_discover, &mut pool, &c).unwrap();
        let owner_request = with_client_id(
            request(mac, offer.yiaddr.octets(), Some(c.server_ip.octets())),
            &owner,
        );
        assert_eq!(
            handle(&owner_request, &mut pool, &c).unwrap().msg_type(),
            Some(ACK)
        );

        let mut release = discover(mac);
        release.options[0].1[0] = RELEASE;
        release
            .options
            .push((OPT_SERVER_ID, c.server_ip.octets().to_vec()));
        release.ciaddr = ip;
        let release = with_client_id(release, &other);
        assert!(handle(&release, &mut pool, &c).is_none());
        assert_eq!(
            pool.active(),
            1,
            "다른 식별자가 기존 임대를 지우면 안 됩니다"
        );

        let renew = with_client_id(request(mac, ip.octets(), None), &owner);
        assert_eq!(handle(&renew, &mut pool, &c).unwrap().msg_type(), Some(ACK));
    }

    #[test]
    fn contradictory_client_state_fields_are_silently_discarded() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut cases = Vec::new();

        let mut discover_with_ciaddr = discover(mac);
        discover_with_ciaddr.ciaddr = ip;
        cases.push(discover_with_ciaddr);

        let mut request_with_both = request(mac, ip.octets(), None);
        request_with_both.ciaddr = ip;
        cases.push(request_with_both);

        let mut request_with_neither = discover(mac);
        request_with_neither.options = vec![(OPT_MSG_TYPE, vec![REQUEST])];
        cases.push(request_with_neither);

        let mut selecting_with_ciaddr = request(mac, ip.octets(), Some(c.server_ip.octets()));
        selecting_with_ciaddr.ciaddr = ip;
        cases.push(selecting_with_ciaddr);

        let mut reserved_flag = discover(mac);
        reserved_flag.flags |= 1;
        cases.push(reserved_flag);

        let mut nonzero_yiaddr = discover(mac);
        nonzero_yiaddr.yiaddr = ip;
        cases.push(nonzero_yiaddr);

        for req in cases {
            let mut pool = LeasePool::new(&c);
            assert!(handle(&req, &mut pool, &c).is_none());
            assert!(pool.leases.is_empty());
            assert!(pool.offers.is_empty());
            assert!(pool.declined.is_empty());
        }
    }

    #[test]
    fn release_requires_our_server_and_the_owned_client_address() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);

        let mut release = discover(mac);
        release.flags = 0;
        release.ciaddr = ip;
        release.options = vec![(OPT_MSG_TYPE, vec![RELEASE])];
        assert!(pool.commit(&identity, mac, u32::from(ip), None));
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(pool.leases.contains_key(&identity));

        release
            .options
            .push((OPT_SERVER_ID, c.server_ip.octets().to_vec()));
        release.ciaddr = Ipv4Addr::new(192, 168, 1, 101);
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(pool.leases.contains_key(&identity));

        release.ciaddr = ip;
        assert!(handle(&release, &mut pool, &c).is_none());
        assert!(!pool.leases.contains_key(&identity));
    }

    #[test]
    fn decline_requires_our_server_and_the_owned_requested_address() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);
        assert!(pool.hold_offer(&identity, 7, ip));

        let mut decline = discover(mac);
        decline.flags = 0;
        decline.options = vec![
            (OPT_MSG_TYPE, vec![DECLINE]),
            (OPT_REQUESTED_IP, Ipv4Addr::from(ip).octets().to_vec()),
        ];
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(pool.offers.contains_key(&identity));
        assert!(!pool.declined.contains_key(&ip));

        decline.options.push((
            OPT_SERVER_ID,
            Ipv4Addr::new(192, 168, 1, 2).octets().to_vec(),
        ));
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(pool.offers.contains_key(&identity));

        decline.options.last_mut().unwrap().1 = c.server_ip.octets().to_vec();
        assert!(handle(&decline, &mut pool, &c).is_none());
        assert!(!pool.offers.contains_key(&identity));
        assert!(pool.declined.contains_key(&ip));
    }

    #[test]
    fn reservation_does_not_override_a_conflicting_request_target() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let reserved = Ipv4Addr::new(192, 168, 1, 100);
        let requested = Ipv4Addr::new(192, 168, 1, 101);
        let mut pool = LeasePool::new(&c);
        let identity = ClientIdentity::Hardware(mac);
        pool.add_reservation(identity.clone(), u32::from(reserved), None)
            .unwrap();

        let reply = handle(&request(mac, requested.octets(), None), &mut pool, &c).unwrap();
        assert_eq!(reply.msg_type(), Some(NAK));
        assert_eq!(reply.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert!(!pool.leases.contains_key(&identity));
    }

    #[test]
    fn selecting_request_cannot_substitute_an_existing_lease_for_its_offer() {
        let c = cfg();
        let mac = [1, 2, 3, 4, 5, 6];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let mut pool = LeasePool::new(&c);
        assert!(pool.commit(&ClientIdentity::Hardware(mac), mac, u32::from(ip), None,));

        let reply = handle(
            &request(mac, ip.octets(), Some(c.server_ip.octets())),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(reply.msg_type(), Some(NAK));
    }

    #[test]
    fn reply_ip_destination_follows_the_rfc_matrix() {
        let c = cfg();
        let mut req = discover([0x02, 2, 3, 4, 5, 6]);
        let mut reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);

        req.giaddr = Ipv4Addr::new(192, 168, 2, 1);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((req.giaddr, 67)))
        );

        req.giaddr = Ipv4Addr::UNSPECIFIED;
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 42);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((req.ciaddr, 68)))
        );

        req.ciaddr = Ipv4Addr::UNSPECIFIED;
        req.flags = BROADCAST_FLAG;
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
        );

        req.flags = 0;
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::InitialUnicast {
                ip: reply.yiaddr,
                mac: req.chaddr,
            }
        );

        req.ciaddr = Ipv4Addr::new(192, 168, 1, 42);
        reply = build_reply(&req, NAK, Ipv4Addr::UNSPECIFIED, &c);
        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
        );
    }

    #[test]
    fn initial_client_reply_requires_link_layer_delivery() {
        let c = cfg();
        let mac = [0x02, 0, 0, 0, 0, 1];
        let mut req = discover(mac);
        req.flags = 0;
        let reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);

        assert_eq!(
            reply_target(&req, &reply),
            ReplyTarget::InitialUnicast {
                ip: reply.yiaddr,
                mac,
            }
        );
    }

    #[test]
    fn initial_unicast_failure_falls_back_to_broadcast() {
        let attempts = std::cell::RefCell::new(Vec::new());
        let used_unicast = send_initial_with_fallback(
            || {
                attempts.borrow_mut().push("unicast");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "neighbor pin denied",
                ))
            },
            || {
                attempts.borrow_mut().push("broadcast");
                Ok(())
            },
        )
        .unwrap();

        assert!(!used_unicast);
        assert_eq!(*attempts.borrow(), ["unicast", "broadcast"]);
    }

    #[test]
    fn invalid_initial_client_mac_uses_broadcast() {
        let c = cfg();
        for mac in [[0; 6], [0x01, 0, 0, 0, 0, 1], [0xff; 6]] {
            let mut req = discover(mac);
            req.flags = 0;
            let reply = build_reply(&req, OFFER, Ipv4Addr::new(192, 168, 1, 100), &c);
            assert_eq!(
                reply_target(&req, &reply),
                ReplyTarget::Udp(std::net::SocketAddr::from((Ipv4Addr::BROADCAST, 68)))
            );
        }
    }

    #[test]
    fn reply_envelope_preserves_ack_address_and_hardens_relay_nak() {
        let c = cfg();
        let mut req = request([1, 2, 3, 4, 5, 6], [192, 168, 1, 100], None);
        req.ciaddr = Ipv4Addr::new(192, 168, 1, 100);

        let ack = build_reply(&req, ACK, req.ciaddr, &c);
        assert_eq!(ack.ciaddr, req.ciaddr);

        req.giaddr = Ipv4Addr::new(192, 168, 2, 1);
        req.flags = 0;
        let nak = build_reply(&req, NAK, Ipv4Addr::UNSPECIFIED, &c);
        assert_eq!(nak.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(nak.siaddr, Ipv4Addr::UNSPECIFIED);
        assert_ne!(nak.flags & BROADCAST_FLAG, 0);
    }

    #[test]
    /// An address from another server on this subnet gets no reply; one off the subnet, or a client
    /// with a record here, gets a NAK.
    fn unknown_client_on_same_subnet_outside_pool_gets_no_reply() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let stranger = [3, 3, 3, 3, 3, 3];
        assert!(
            handle(&request(stranger, [192, 168, 1, 50], None), &mut pool, &c).is_none(),
            "같은 망의 다른 서버가 준 주소에 NAK를 보내면 그 기기가 주소를 버립니다"
        );
        let wrong_network = handle(&request(stranger, [172, 30, 1, 6], None), &mut pool, &c)
            .expect("망 밖의 주소는 잘못된 망이라고 알려야 합니다");
        assert_eq!(wrong_network.msg_type(), Some(NAK));

        let known = [4, 4, 4, 4, 4, 4];
        let ack = handle(&request(known, [192, 168, 1, 100], None), &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        let moved = handle(&request(known, [192, 168, 1, 50], None), &mut pool, &c)
            .expect("기록이 있는 클라이언트에게는 거절을 알려야 합니다");
        assert_eq!(moved.msg_type(), Some(NAK));
    }

    #[test]
    fn requests_from_other_links_are_dropped() {
        let direct = Ipv4Addr::UNSPECIFIED;
        let relay = Ipv4Addr::new(10, 0, 0, 1);
        assert!(from_served_link(direct, Some(3), Some(3)));
        assert!(!from_served_link(direct, Some(2), Some(3)));
        assert!(from_served_link(relay, Some(2), Some(3)));
        assert!(from_served_link(direct, None, Some(3)));
        assert!(from_served_link(direct, Some(2), None));
    }

    #[test]
    /// Granting it would put two clients on one address.
    fn request_for_ip_leased_to_other_mac_is_nak() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let a = [1, 1, 1, 1, 1, 1];
        let b = [2, 2, 2, 2, 2, 2];
        let ip = [192, 168, 1, 100];
        let ack_a = handle(&request(a, ip, None), &mut pool, &c).unwrap();
        assert_eq!(ack_a.msg_type(), Some(ACK));
        let reply_b = handle(&request(b, ip, None), &mut pool, &c).unwrap();
        assert_eq!(reply_b.msg_type(), Some(NAK));
    }

    #[test]
    fn request_rejects_other_offer_and_declined_address() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let offer_owner = [1, 1, 1, 1, 1, 1];
        let decline_owner = [3, 3, 3, 3, 3, 3];
        let intruder = [2, 2, 2, 2, 2, 2];
        let offered = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let declined = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        let offer_identity = ClientIdentity::Hardware(offer_owner);
        let decline_identity = ClientIdentity::Hardware(decline_owner);
        assert!(pool.hold_offer(&offer_identity, 1, offered));
        assert!(pool.hold_offer(&decline_identity, 2, declined));
        pool.decline(&decline_identity, declined);

        let offered_reply = handle(
            &request(intruder, Ipv4Addr::from(offered).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(offered_reply.msg_type(), Some(NAK));

        let declined_reply = handle(
            &request(intruder, Ipv4Addr::from(declined).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(declined_reply.msg_type(), Some(NAK));

        let reserved_client = [4, 4, 4, 4, 4, 4];
        let conflict_owner = [5, 5, 5, 5, 5, 5];
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 102));
        pool.add_reservation(ClientIdentity::Hardware(reserved_client), reserved, None)
            .unwrap();
        let conflict_identity = ClientIdentity::Hardware(conflict_owner);
        assert!(pool.hold_offer(&conflict_identity, 3, reserved));
        pool.decline(&conflict_identity, reserved);
        let reserved_reply = handle(
            &request(reserved_client, Ipv4Addr::from(reserved).octets(), None),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(reserved_reply.msg_type(), Some(NAK));
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_init_reboot_request_scaling -- --ignored --nocapture"]
    /// Measures whether checking a REQUEST without an offer scales with the leases and assignments.
    fn bench_dhcp4_init_reboot_request_scaling() {
        const OPS: usize = 256;
        const ROUNDS: usize = 6;

        for preload in [1_000usize, 20_000] {
            for round in 0..ROUNDS {
                let mut c = cfg();
                c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
                c.range_start = Ipv4Addr::new(10, 0, 0, 10);
                c.range_end = Ipv4Addr::new(10, 127, 255, 254);
                c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
                c.router = c.server_ip;
                c.dns = vec![c.server_ip];
                let mut pool = LeasePool::new(&c);
                let first = u32::from(c.range_start);
                let reserved_first = u32::from(Ipv4Addr::new(10, 200, 0, 1));
                let expiry = crate::unix_now() + 3_600;
                for index in 0..preload {
                    let lease_mac = mac_for(index);
                    pool.leases.insert(
                        ClientIdentity::Hardware(lease_mac),
                        Lease {
                            mac: lease_mac,
                            ip: first + u32::try_from(index).unwrap(),
                            expiry,
                            hostname: None,
                        },
                    );
                    pool.reservations.insert(
                        identity_for(preload + index),
                        (reserved_first + u32::try_from(index).unwrap(), None),
                    );
                }
                pool.rebuild_address_use();
                let target_first = first + u32::try_from(preload).unwrap();

                let started = std::time::Instant::now();
                for index in 0..OPS {
                    let ip = Ipv4Addr::from(target_first + u32::try_from(index).unwrap());
                    let reply = std::hint::black_box(handle(
                        &request(mac_for(preload * 2 + index), ip.octets(), None),
                        &mut pool,
                        &c,
                    ))
                    .unwrap();
                    assert_eq!(reply.msg_type(), Some(ACK));
                }
                let ns_per_op = started.elapsed().as_nanos() / OPS as u128;
                println!(
                    "dhcp4_request preload={preload} round={} ns_per_op={ns_per_op}",
                    round + 1
                );
            }
        }
    }

    #[test]
    fn request_with_foreign_server_id_is_ignored() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [3, 3, 3, 3, 3, 3];

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        let offered = offer.yiaddr.octets();

        let foreign = handle(&request(mac, offered, Some([10, 0, 0, 9])), &mut pool, &c);
        assert!(foreign.is_none());

        let mine = handle(
            &request(mac, offered, Some([192, 168, 1, 1])),
            &mut pool,
            &c,
        )
        .unwrap();
        assert_eq!(mine.msg_type(), Some(ACK));
    }

    #[test]
    fn static_reservation_rejects_out_of_subnet_and_special() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [9, 9, 9, 9, 9, 9];
        let identity = ClientIdentity::Hardware(mac);
        for bad in [
            [10, 0, 0, 5],
            [192, 168, 1, 0],
            [192, 168, 1, 255],
            [192, 168, 1, 1],
        ] {
            assert!(
                pool.add_reservation(identity.clone(), u32::from(Ipv4Addr::from(bad)), None)
                    .is_err(),
                "{bad:?} 예약은 거부되어야 함"
            );
        }

        assert!(pool
            .add_reservation(identity, u32::from(Ipv4Addr::new(192, 168, 1, 50)), None,)
            .is_ok());
    }

    #[test]
    fn wire_roundtrip() {
        let m = discover([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let back = DhcpMessage::parse(&m.encode()).unwrap();
        assert_eq!(back.xid, 0x1234);
        assert_eq!(back.chaddr, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(back.msg_type(), Some(DISCOVER));
    }

    #[test]
    fn receive_capacity_covers_tail_option_validation() {
        assert_eq!(MAX_STANDARD_IPV4_UDP_PAYLOAD, 65_507);
        assert_eq!(DHCP4_RECV_CAPACITY, 65_508);
        assert_eq!(standard_dhcp4_datagram_len(65_507), Some(65_507));
        assert_eq!(standard_dhcp4_datagram_len(65_508), None);

        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        wire.extend_from_slice(&[200, 1, 0]);
        while wire.len() < 1_500 {
            wire.extend_from_slice(&[200, 0]);
        }
        assert_eq!(wire.len(), 1_500);

        wire.extend_from_slice(&[OPT_MSG_TYPE, 1, REQUEST, OPT_END]);
        assert!(DhcpMessage::parse(&wire[..1_500]).is_none());
        assert!(DhcpMessage::parse(&wire).is_none());
    }

    #[test]
    fn unknown_option_flood_is_ignored_without_storage_amplification() {
        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        while wire.len() + 3 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.extend_from_slice(&[200, 1, 0]);
        }
        while wire.len() + 1 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.push(0);
        }
        wire.push(OPT_END);
        assert_eq!(wire.len(), MAX_STANDARD_IPV4_UDP_PAYLOAD);

        let parsed = DhcpMessage::parse(&wire).unwrap();
        assert_eq!(parsed.options.len(), 1);
        assert_eq!(parsed.msg_type(), Some(DISCOVER));

        wire.push(0);
        assert!(DhcpMessage::parse(&wire).is_none());
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns --release bench_dhcp4_unknown_option_flood_parse -- --ignored --nocapture"]
    /// Measures validating a 64 KiB unknown-option flood without keeping it.
    fn bench_dhcp4_unknown_option_flood_parse() {
        const OPS: usize = 64;
        const ROUNDS: usize = 12;
        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        while wire.len() + 3 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.extend_from_slice(&[200, 1, 0]);
        }
        while wire.len() + 1 < MAX_STANDARD_IPV4_UDP_PAYLOAD {
            wire.push(0);
        }
        wire.push(OPT_END);

        for round in 0..ROUNDS {
            let started = std::time::Instant::now();
            for _ in 0..OPS {
                let parsed = DhcpMessage::parse(std::hint::black_box(&wire)).unwrap();
                assert_eq!(parsed.options.len(), 1);
                std::hint::black_box(parsed);
            }
            let ns_per_parse = started.elapsed().as_nanos() / OPS as u128;
            println!(
                "dhcp4_unknown_flood round={} ns_per_parse={ns_per_parse}",
                round + 1
            );
        }
    }

    #[test]
    fn split_options_are_concatenated_in_aggregate_buffer_order() {
        const OPT_OVERLOAD_CODE: u8 = 52;

        let mut wire = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(wire.pop(), Some(OPT_END));
        wire.extend_from_slice(&[OPT_HOSTNAME, 5]);
        wire.extend_from_slice(b"alpha");
        wire.extend_from_slice(&[OPT_OVERLOAD_CODE, 1, 3, OPT_END]);

        wire[108..113].copy_from_slice(&[OPT_HOSTNAME, 1, b'-', OPT_END, 0]);
        wire[44..51].copy_from_slice(&[OPT_HOSTNAME, 4, b'h', b'o', b's', b't', OPT_END]);

        let parsed = DhcpMessage::parse(&wire).unwrap();
        assert_eq!(parsed.hostname().as_deref(), Some("alpha-host"));
        assert_eq!(parsed.options.len(), 2);

        let mut split_controls = discover([1, 2, 3, 4, 5, 6]);
        split_controls.options = vec![
            (OPT_MSG_TYPE, Vec::new()),
            (OPT_MSG_TYPE, vec![DISCOVER]),
            (OPT_REQUESTED_IP, vec![192, 168]),
            (OPT_REQUESTED_IP, vec![1, 100]),
        ];
        let parsed = DhcpMessage::parse(&split_controls.encode()).unwrap();
        assert_eq!(parsed.msg_type(), Some(DISCOVER));
        assert_eq!(
            parsed.option(OPT_REQUESTED_IP).and_then(opt_ipv4),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
        assert_eq!(parsed.options.len(), 2);
    }

    #[test]
    fn consumed_option_lengths_are_validated_after_concatenation() {
        for options in [
            vec![(OPT_MSG_TYPE, vec![DISCOVER, REQUEST])],
            vec![
                (OPT_MSG_TYPE, vec![REQUEST]),
                (OPT_REQUESTED_IP, vec![192, 168, 1, 100, 0]),
            ],
            vec![
                (OPT_MSG_TYPE, vec![REQUEST]),
                (OPT_SERVER_ID, vec![192, 168, 1, 1, 0]),
            ],
            vec![(OPT_MSG_TYPE, vec![DISCOVER]), (OPT_HOSTNAME, Vec::new())],
        ] {
            let mut message = discover([1, 2, 3, 4, 5, 6]);
            message.options = options;
            assert!(DhcpMessage::parse(&message.encode()).is_none());
        }

        let mut split_type = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(split_type.pop(), Some(OPT_END));
        split_type.extend_from_slice(&[OPT_MSG_TYPE, 1, REQUEST, OPT_END]);
        assert!(DhcpMessage::parse(&split_type).is_none());
    }

    #[test]
    fn request_header_and_end_marker_are_required() {
        let mut no_end = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(no_end.pop(), Some(OPT_END));
        assert!(DhcpMessage::parse(&no_end).is_none());

        let mut wrong_htype = discover([1, 2, 3, 4, 5, 6]).encode();
        wrong_htype[1] = 2;
        assert!(DhcpMessage::parse(&wrong_htype).is_none());

        let mut wrong_hlen = discover([1, 2, 3, 4, 5, 6]).encode();
        wrong_hlen[2] = 5;
        assert!(DhcpMessage::parse(&wrong_hlen).is_none());

        let mut reply = discover([1, 2, 3, 4, 5, 6]);
        reply.op = 2;
        let reply = reply.encode();
        assert!(DhcpMessage::parse(&reply).is_some());
        assert!(parse_client_request(&reply).is_none());

        let mut data_after_end = discover([1, 2, 3, 4, 5, 6]).encode();
        data_after_end.extend_from_slice(&[200, 0]);
        assert!(DhcpMessage::parse(&data_after_end).is_none());

        let mut missing_overload_end = discover([1, 2, 3, 4, 5, 6]).encode();
        assert_eq!(missing_overload_end.pop(), Some(OPT_END));
        missing_overload_end.extend_from_slice(&[OPT_OVERLOAD, 1, 1, OPT_END]);
        missing_overload_end[108..111].copy_from_slice(&[OPT_HOSTNAME, 1, b'a']);
        assert!(DhcpMessage::parse(&missing_overload_end).is_none());
    }

    #[test]
    /// Accepting the part before the bad option would let a truncated request through.
    fn malformed_option_is_rejected_instead_of_partially_applied() {
        let mut truncated = discover([1, 2, 3, 4, 5, 6]).encode();
        truncated.truncate(truncated.len() - 2);
        assert!(DhcpMessage::parse(&truncated).is_none());

        let mut missing_length = discover([1, 2, 3, 4, 5, 6]).encode();
        let last = missing_length.len() - 1;
        missing_length[last] = OPT_MSG_TYPE;
        assert!(DhcpMessage::parse(&missing_length).is_none());
    }

    #[test]
    fn discover_offers_request_acks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [1, 2, 3, 4, 5, 6];

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(offer.option(OPT_ROUTER), Some([192, 168, 1, 1].as_slice()));

        let mut req = discover(mac);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, offer.yiaddr.octets().to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(pool.active(), 1);
    }

    #[test]
    fn mismatched_request_does_not_consume_offer() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [4, 3, 2, 1, 0, 9];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.hold_offer(&identity, 0x1234, ip));

        assert!(!pool.consume_offer(&identity, 0x9999, ip));
        assert!(pool.consume_offer(&identity, 0x1234, ip));
        assert!(!pool.consume_offer(&identity, 0x1234, ip));
    }

    #[test]
    fn pool_distinct_ips_and_exhaustion() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let first_mac = [0, 0, 0, 0, 0, 1];
        let second_mac = [0, 0, 0, 0, 0, 2];
        let third_mac = [0, 0, 0, 0, 0, 3];
        let first = ClientIdentity::Hardware(first_mac);
        let second = ClientIdentity::Hardware(second_mac);
        let third = ClientIdentity::Hardware(third_mac);
        let a = pool.allocate(&first).unwrap();
        assert!(pool.commit(&first, first_mac, a, None));
        let b = pool.allocate(&second).unwrap();
        assert!(pool.commit(&second, second_mac, b, None));
        let cc = pool.allocate(&third).unwrap();
        assert!(pool.commit(&third, third_mac, cc, None));
        assert_ne!(a, b);
        assert_ne!(b, cc);

        assert!(pool
            .allocate(&ClientIdentity::Hardware([0, 0, 0, 0, 0, 4]))
            .is_none());

        assert_eq!(pool.allocate(&first), Some(a));
    }

    #[test]
    fn out_of_range_request_naks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mut req = discover([9, 9, 9, 9, 9, 9]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (
                OPT_REQUESTED_IP,
                Ipv4Addr::new(10, 0, 0, 5).octets().to_vec(),
            ),
        ];
        let nak = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
    }

    #[test]
    fn hostname_option_parsed() {
        let mut req = discover([1, 2, 3, 4, 5, 6]);
        req.options.push((OPT_HOSTNAME, b"my-laptop".to_vec()));
        assert_eq!(req.hostname().as_deref(), Some("my-laptop"));

        let mut req2 = discover([1, 2, 3, 4, 5, 6]);
        req2.options.push((OPT_HOSTNAME, vec![0u8]));
        assert!(req2.hostname().is_none());

        let mut invalid = discover([1, 2, 3, 4, 5, 6]);
        invalid.options.push((OPT_HOSTNAME, vec![0xff]));
        assert!(
            invalid.hostname().is_none(),
            "invalid UTF-8 is not repaired"
        );
    }

    #[test]
    fn persistence_roundtrip_and_snapshot() {
        let path =
            std::env::temp_dir().join(format!("onetdns-lease-persist-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.lease_file = Some(path.clone());
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let identity = ClientIdentity::Hardware(mac);
        {
            let mut pool = LeasePool::new(&c);
            let ip = pool.allocate(&identity).unwrap();
            assert!(pool.commit(&identity, mac, ip, Some("host1".to_string())));
            let snap = pool.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].identity, identity);
            assert_eq!(snap[0].mac, mac);
            assert_eq!(snap[0].ip, Ipv4Addr::new(192, 168, 1, 100));
            assert_eq!(snap[0].hostname.as_deref(), Some("host1"));
        }

        let pool2 = LeasePool::new(&c);
        let snap = pool2.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(snap[0].hostname.as_deref(), Some("host1"));

        std::fs::write(
            &path,
            format!(
                "aabbccddeeff 192.168.1.100 {} host1\n",
                crate::unix_now() + 60
            ),
        )
        .unwrap();
        assert!(LeasePool::new(&c).snapshot().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mac_hex_roundtrip() {
        let mac = [0x00, 0x1a, 0x2b, 0xff, 0xcc, 0x01];
        assert_eq!(mac_hex(&mac), "001a2bffcc01");
        assert_eq!(mac_from_hex("001a2bffcc01"), Some(mac));
        assert!(mac_from_hex("zz").is_none());
    }

    #[test]
    fn client_identity_text_roundtrip_and_namespaces_are_distinct() {
        let hardware = ClientIdentity::from_text("mac:001a2bffcc01").unwrap();
        let opaque = ClientIdentity::from_text("id:001a2bffcc01").unwrap();
        assert_eq!(hardware.to_text(), "mac:001a2bffcc01");
        assert_eq!(opaque.to_text(), "id:001a2bffcc01");
        assert_ne!(hardware, opaque);
        assert!(ClientIdentity::from_text("id:01").is_none());
        assert!(ClientIdentity::from_text("id:xyz0").is_none());
        assert!(ClientIdentity::from_text("mac:00:1a:2b:ff:cc:01").is_none());
    }

    #[test]
    fn opaque_client_identity_persistence_roundtrip() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-client-id-persist-{}-{}.txt",
            std::process::id(),
            crate::unix_now()
        ));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.lease_file = Some(path.clone());
        let identity = ClientIdentity::from_text("id:0102030405").unwrap();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ip = u32::from(c.range_start);
        {
            let mut pool = LeasePool::new(&c);
            assert!(pool.insert(
                &identity,
                mac,
                ip,
                crate::unix_now() + 3_600,
                Some("opaque".into()),
            ));
            pool.save();
        }

        let snapshot = LeasePool::new(&c).snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].identity, identity);
        assert_eq!(snapshot[0].mac, mac);
        assert_eq!(snapshot[0].hostname.as_deref(), Some("opaque"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn insert_takes_newer_only() {
        let mut pool = LeasePool::new(&cfg());
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let now = crate::unix_now();

        assert!(pool.insert(&identity, mac, ip, now + 1000, Some("peer".into())));
        let s = pool.snapshot();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ip, Ipv4Addr::new(192, 168, 1, 100));

        assert!(
            !pool.insert(&identity, mac, ip, now + 10, None),
            "같은 주소의 더 이른 만료는 무시한다"
        );
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("peer"));

        assert!(pool.insert(&identity, mac, ip, now + 5000, Some("newer".into())));
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("newer"));

        let moved = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        assert!(pool.insert(&identity, mac, moved, now + 20, None));
        assert_eq!(pool.snapshot()[0].ip, Ipv4Addr::new(192, 168, 1, 101));
    }

    #[test]
    fn synced_lease_rejects_out_of_range_and_duplicate_ip() {
        let mut pool = LeasePool::new(&cfg());
        let now = crate::unix_now();
        let first = [0xaa, 0, 0, 0, 0, 1];
        let second = [0xbb, 0, 0, 0, 0, 2];
        let first_identity = ClientIdentity::Hardware(first);
        let second_identity = ClientIdentity::Hardware(second);
        let in_range = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let out_of_range = u32::from(Ipv4Addr::new(192, 168, 1, 99));

        assert!(!pool.insert(&first_identity, first, out_of_range, now + 3_600, None));
        assert!(pool.insert(&first_identity, first, in_range, now + 3_600, None));
        assert!(!pool.insert(&second_identity, second, in_range, now + 3_600, None));
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 101));
        pool.add_reservation(first_identity.clone(), reserved, None)
            .unwrap();
        assert!(!pool.insert(&second_identity, second, reserved, now + 3_600, None));
        assert_eq!(pool.snapshot().len(), 1);
        assert_eq!(
            pool.leases.get(&first_identity).map(|lease| lease.ip),
            Some(in_range)
        );
    }

    #[test]
    fn synced_batch_preflights_the_whole_state_budget() {
        let mut c = cfg();
        c.server_ip = Ipv4Addr::new(10, 0, 0, 1);
        c.range_start = Ipv4Addr::new(10, 0, 0, 10);
        c.range_end = Ipv4Addr::new(10, 255, 255, 254);
        c.subnet_mask = Ipv4Addr::new(255, 0, 0, 0);
        c.router = c.server_ip;
        let mut pool = LeasePool::new(&c);
        let now = crate::unix_now();
        let first = u32::from(c.range_start);
        for index in 0..MAX_STATE_ENTRIES {
            let mac = mac_for(index);
            pool.leases.insert(
                ClientIdentity::Hardware(mac),
                Lease {
                    mac,
                    ip: first + u32::try_from(index).unwrap(),
                    expiry: now + 3_600,
                    hostname: None,
                },
            );
        }
        pool.rebuild_address_use();

        assert!(pool
            .validate_synced_batch([
                (identity_for(0), first, now + 7_200),
                (
                    identity_for(MAX_STATE_ENTRIES),
                    first + u32::try_from(MAX_STATE_ENTRIES).unwrap(),
                    now + 7_200,
                ),
            ])
            .is_err());
        assert_eq!(pool.dynamic_entries(), MAX_STATE_ENTRIES);
        assert_eq!(
            pool.leases.get(&identity_for(0)).unwrap().expiry,
            now + 3_600
        );
    }

    #[test]
    fn reserved_lease_outside_dynamic_range_survives_revalidation() {
        let mut pool = LeasePool::new(&cfg());
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let identity = ClientIdentity::Hardware(mac);
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        pool.add_reservation(identity.clone(), reserved, None)
            .unwrap();
        assert!(pool.insert(&identity, mac, reserved, crate::unix_now() + 3_600, None,));

        pool.revalidate_loaded_state();

        assert_eq!(pool.snapshot().len(), 1);
        assert_eq!(
            pool.leases.get(&identity).map(|lease| lease.ip),
            Some(reserved)
        );
    }

    #[test]
    fn persisted_duplicate_ip_rejects_the_whole_lease_file() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-duplicate-lease-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let expiry = crate::unix_now() + 3_600;
        std::fs::write(
            &path,
            format!(
                "{LEASE_HEADER}mac:aabbccddee01 aabbccddee01 192.168.1.100 {expiry}\n\
                 mac:aabbccddee02 aabbccddee02 192.168.1.100 {expiry}\n"
            ),
        )
        .unwrap();

        assert!(load_leases(&path).is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reservation_honored_in_offer_and_request() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0, 0, 0, 0, 0x10];
        let identity = ClientIdentity::Hardware(mac);

        let pinned = u32::from(Ipv4Addr::new(192, 168, 1, 200));
        pool.add_reservation(identity, pinned, Some("printer".into()))
            .unwrap();

        let offer = handle(&discover(mac), &mut pool, &c).unwrap();
        assert_eq!(offer.msg_type(), Some(OFFER));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(192, 168, 1, 200));

        let mut req = discover(mac);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, offer.yiaddr.octets().to_vec()),
            (OPT_SERVER_ID, c.server_ip.octets().to_vec()),
        ];
        let ack = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(ack.msg_type(), Some(ACK));
        assert_eq!(ack.yiaddr, Ipv4Addr::new(192, 168, 1, 200));
    }

    #[test]
    fn dynamic_client_skips_reserved_ip() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let reserved = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        pool.add_reservation(
            ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]),
            reserved,
            None,
        )
        .unwrap();

        let got = pool
            .allocate(&ClientIdentity::Hardware([0xbb, 0, 0, 0, 0, 2]))
            .unwrap();
        assert_ne!(got, reserved);
        assert!(got >= u32::from(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn other_client_requesting_reserved_ip_naks() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        pool.add_reservation(
            ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]),
            u32::from(Ipv4Addr::new(192, 168, 1, 101)),
            None,
        )
        .unwrap();
        let mut req = discover([0xbb, 0, 0, 0, 0, 2]);
        req.options = vec![
            (OPT_MSG_TYPE, vec![REQUEST]),
            (OPT_REQUESTED_IP, [192, 168, 1, 101].to_vec()),
        ];
        let nak = handle(&req, &mut pool, &c).unwrap();
        assert_eq!(nak.msg_type(), Some(NAK));
    }

    #[test]
    fn add_reservation_reclaims_conflicting_dynamic_lease() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        let dynamic_mac = [0xbb, 0, 0, 0, 0, 2];
        assert!(pool.commit(
            &ClientIdentity::Hardware(dynamic_mac),
            dynamic_mac,
            ip,
            None,
        ));
        assert_eq!(pool.active(), 1);

        pool.add_reservation(ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 1]), ip, None)
            .unwrap();
        assert_eq!(pool.active(), 0);

        assert!(pool
            .add_reservation(ClientIdentity::Hardware([0xcc, 0, 0, 0, 0, 3]), ip, None)
            .is_err());
    }

    #[test]
    fn reservation_persistence_roundtrip() {
        let path = std::env::temp_dir().join(format!("onetdns-static-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut c = cfg();
        c.static_file = Some(path.clone());
        let identity = ClientIdentity::from_text("id:deadbeef0001").unwrap();
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 250));
        {
            let mut pool = LeasePool::new(&c);
            pool.add_reservation(identity.clone(), ip, Some("nas".into()))
                .unwrap();
            assert_eq!(pool.reservations().len(), 1);
        }
        let pool2 = LeasePool::new(&c);
        let r = pool2.reservations();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].identity, identity);
        assert_eq!(r[0].ip, Ipv4Addr::new(192, 168, 1, 250));
        assert_eq!(r[0].hostname.as_deref(), Some("nas"));

        {
            let mut pool = LeasePool::new(&c);
            assert!(pool.remove_reservation(&identity));
            assert!(!pool.remove_reservation(&identity));
        }
        assert!(LeasePool::new(&c).reservations().is_empty());

        let operator_text = "deadbeef0001 192.168.1.250 nas\n";
        std::fs::write(&path, operator_text).unwrap();
        assert!(read_reservations(&path).is_err());
        assert!(LeasePool::new(&c).reservations().is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), operator_text);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    /// Without a lease file, a fresh pool would hand the first device's address to the next one.
    fn reconfigure_keeps_issued_leases_without_a_lease_file() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let first = [0xaa, 0, 0, 0, 0, 1];
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.commit(&ClientIdentity::Hardware(first), first, ip, None));

        let mut changed = c.clone();
        changed.dns = vec![Ipv4Addr::new(192, 168, 1, 9)];
        changed.lease_secs = 600;
        pool.reconfigure(&changed).unwrap();

        let second = ClientIdentity::Hardware([0xbb, 0, 0, 0, 0, 2]);
        assert_ne!(pool.allocate(&second), Some(ip));
        assert_eq!(pool.active(), 1);
    }

    #[test]
    fn reconfigure_reads_the_new_reservation_file() {
        let path =
            std::env::temp_dir().join(format!("onetdns-static-switch-{}.txt", std::process::id()));
        let identity = ClientIdentity::Hardware([0xaa, 0, 0, 0, 0, 7]);
        std::fs::write(
            &path,
            format!(
                "{RESERVATION_HEADER}{} 192.168.1.50 printer\n",
                identity.to_text()
            ),
        )
        .unwrap();
        let mut pool = LeasePool::new(&cfg());
        let mut changed = cfg();
        changed.static_file = Some(path.clone());
        pool.reconfigure(&changed).unwrap();
        assert_eq!(
            pool.reservation_ip(&identity),
            Some(u32::from(Ipv4Addr::new(192, 168, 1, 50)))
        );

        let broken =
            std::env::temp_dir().join(format!("onetdns-static-broken-{}.txt", std::process::id()));
        std::fs::write(&broken, format!("{RESERVATION_HEADER}not-an-entry\n")).unwrap();
        let mut bad = cfg();
        bad.static_file = Some(broken.clone());
        assert!(pool.reconfigure(&bad).is_err());
        assert!(pool.reservation_ip(&identity).is_some());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&broken);
    }

    #[test]
    fn commit_keeps_hostname_and_prefers_the_reserved_one() {
        let c = cfg();
        let mut pool = LeasePool::new(&c);
        let mac = [0xaa, 0, 0, 0, 0, 1];
        let identity = ClientIdentity::Hardware(mac);
        let ip = u32::from(Ipv4Addr::new(192, 168, 1, 100));
        assert!(pool.commit(&identity, mac, ip, Some("alpha".into())));
        assert!(pool.commit(&identity, mac, ip, None));
        assert_eq!(pool.snapshot()[0].hostname.as_deref(), Some("alpha"));

        let reserved_mac = [0xcc, 0, 0, 0, 0, 3];
        let reserved = ClientIdentity::Hardware(reserved_mac);
        let reserved_ip = u32::from(Ipv4Addr::new(192, 168, 1, 50));
        pool.add_reservation(reserved.clone(), reserved_ip, Some("printer".into()))
            .unwrap();
        assert!(pool.commit(&reserved, reserved_mac, reserved_ip, Some("npi1234".into())));
        let names: Vec<_> = pool
            .snapshot()
            .into_iter()
            .filter(|lease| lease.identity == reserved)
            .map(|lease| lease.hostname)
            .collect();
        assert_eq!(names, vec![Some("printer".to_string())]);
    }

    #[test]
    fn ack_carries_domain_and_tftp_server_name() {
        let mut c = cfg();
        c.domain_name = Some("lan".into());
        c.tftp_server = Some(Ipv4Addr::new(192, 168, 1, 5));
        let mut pool = LeasePool::new(&c);
        let offer = handle(&discover([1, 2, 3, 4, 5, 6]), &mut pool, &c).unwrap();
        assert_eq!(offer.option(OPT_DOMAIN_NAME), Some(b"lan".as_slice()));
        assert_eq!(
            offer.option(OPT_TFTP_SERVER_NAME),
            Some(b"192.168.1.5".as_slice())
        );
    }

    #[test]
    fn parse_never_panics_on_malformed_bytes() {
        use crate::fuzzutil::{havoc, Rng};

        let seed = discover([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).encode();
        let mut rng = Rng::new(0xD11C_0DE5_1234_5678);
        for i in 0..20_000u32 {
            let bytes = if i % 3 == 0 {
                rng.rand_bytes(300)
            } else {
                havoc(&mut rng, &seed)
            };
            let _ = DhcpMessage::parse(&bytes);
        }
    }
}
