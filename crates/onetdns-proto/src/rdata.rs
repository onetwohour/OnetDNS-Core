//! Record types and RDATA: per-type parsing, validation, and encoding. Unknown types keep their raw
//! bytes in RData::Unknown and are relayed as is, except obsolete types that can carry compressed
//! names: rewriting their raw bytes would leave pointers into the old message aimed at the wrong
//! place in the new one.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::name::Name;
use crate::wire::{Reader, Writer};
use crate::ProtoError;

/// A newtype rather than an enum, so unknown types are carried as values and caching and relaying
/// need no code change for each new type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordType(pub u16);

#[allow(non_upper_case_globals)]
impl RecordType {
    pub const A: RecordType = RecordType(1);
    pub const NS: RecordType = RecordType(2);
    pub const CNAME: RecordType = RecordType(5);
    pub const SOA: RecordType = RecordType(6);
    pub const PTR: RecordType = RecordType(12);
    pub const MX: RecordType = RecordType(15);
    pub const TXT: RecordType = RecordType(16);
    pub const AAAA: RecordType = RecordType(28);
    pub const NAPTR: RecordType = RecordType(35);
    pub const DNAME: RecordType = RecordType(39);
    pub const SRV: RecordType = RecordType(33);
    pub const SSHFP: RecordType = RecordType(44);
    pub const TLSA: RecordType = RecordType(52);
    pub const URI: RecordType = RecordType(256);
    pub const OPT: RecordType = RecordType(41);
    pub const DS: RecordType = RecordType(43);
    pub const RRSIG: RecordType = RecordType(46);
    pub const NSEC: RecordType = RecordType(47);
    pub const DNSKEY: RecordType = RecordType(48);
    pub const NSEC3: RecordType = RecordType(50);
    pub const CDS: RecordType = RecordType(59);
    pub const CDNSKEY: RecordType = RecordType(60);
    pub const SVCB: RecordType = RecordType(64);
    pub const HTTPS: RecordType = RecordType(65);
    pub const CAA: RecordType = RecordType(257);
    pub const ANY: RecordType = RecordType(255);

    /// Display name: the mnemonic, or "UNKNOWN". For logs and the dashboard only; never parse it
    /// back.
    pub fn name(self) -> &'static str {
        match self.0 {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            35 => "NAPTR",
            39 => "DNAME",
            41 => "OPT",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            50 => "NSEC3",
            59 => "CDS",
            60 => "CDNSKEY",
            64 => "SVCB",
            65 => "HTTPS",
            257 => "CAA",
            255 => "ANY",
            _ => "UNKNOWN",
        }
    }
}

/// OPT uses this field for the UDP payload size, and UPDATE (RFC 2136) uses 254 and 255 as
/// operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsClass(pub u16);

#[allow(non_upper_case_globals)]
impl DnsClass {
    pub const IN: DnsClass = DnsClass(1);
}

/// Size directly sets cache cost: the largest variant prices every cached record, so rare large
/// variants are boxed (SOA, NAPTR). The layout assertion in typed_rdata_tests pins the size.
///
/// record_type() always matches the variant; the message encoder compares it with each record's
/// TYPE field and refuses to encode on a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(Name),
    Cname(Name),
    Dname(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Txt(Vec<Vec<u8>>),

    Soa(Box<Soa>),
    Srv {
        /// Lower is tried first.
        priority: u16,
        /// Share among records of equal priority.
        weight: u16,
        port: u16,
        target: Name,
    },

    Caa {
        /// Holds the critical bit: whether this entry must be understood.
        flags: u8,
        tag: Box<[u8]>,
        value: Box<[u8]>,
    },

    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: Vec<u8>,
    },

    Sshfp {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },

    Naptr(Box<Naptr>),

    Uri {
        priority: u16,
        weight: u16,
        target: Vec<u8>,
    },

    Svcb {
        /// 0 means AliasMode, which hands off to another name.
        priority: u16,
        target: Name,
        params: Box<[(u16, Box<[u8]>)]>,
    },

    Https {
        /// 0 means AliasMode, which hands off to another name.
        priority: u16,
        target: Name,
        params: Box<[(u16, Box<[u8]>)]>,
    },

    /// A type this server does not interpret; the bytes are relayed as is.
    Unknown(u16, Vec<u8>),
}

/// NAPTR RDATA (RFC 3403); boxed in RData because of its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naptr {
    pub order: u16,
    pub preference: u16,
    pub flags: Vec<u8>,
    pub services: Vec<u8>,
    pub regexp: Vec<u8>,
    pub replacement: Name,
}

/// Compare `serial` with RFC 1982 serial arithmetic; a plain comparison would keep a wrapped serial
/// newest forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub mname: Name,
    pub rname: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// Length-prefixed character-string, at most 255 octets.
fn read_char_string(r: &mut Reader) -> Result<Vec<u8>, ProtoError> {
    let n = r.u8()? as usize;
    Ok(r.bytes(n)?.to_vec())
}

/// Longer than 255 octets fails the encoding instead of truncating.
fn write_char_string(w: &mut Writer, s: &[u8]) {
    let Ok(n) = u8::try_from(s.len()) else {
        w.fail("DNS character string exceeds 255 bytes");
        return;
    };
    w.push_u8(n);
    w.push_bytes(s);
}

/// Obsolete types whose RDATA can carry compressed names that this server does not interpret (MD,
/// MF, MB, MG, MR, MINFO, RP, AFSDB, RT, SIG, PX, NXT). Kept as raw bytes and written into another
/// message, their compression pointers would aim at the wrong place and alter names, so parsing
/// refuses them.
fn is_unsupported_name_bearing(rtype: RecordType) -> bool {
    matches!(
        rtype.0,
        3 | 4 | 7 | 8 | 9 | 14 | 17 | 18 | 21 | 23 | 26 | 30 | 36
    )
}

/// SVCB/HTTPS parameter syntax (RFC 9460). Keys must be strictly increasing and 65535 is reserved;
/// the ordering also lets the mandatory self-reference check use binary search. Priority 0 is
/// AliasMode, where parameters have no defined meaning, so only the order is checked.
fn validate_svcb_params(priority: u16, params: &[(u16, Box<[u8]>)]) -> Result<(), ProtoError> {
    if params.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(ProtoError::Message(
            "SVCB parameter keys are not strictly increasing".into(),
        ));
    }
    if params.last().is_some_and(|(key, _)| *key == u16::MAX) {
        return Err(ProtoError::Message(
            "SVCB parameter key 65535 is reserved".into(),
        ));
    }

    if priority == 0 {
        return Ok(());
    }

    let has = |key| params.binary_search_by_key(&key, |(key, _)| *key).is_ok();
    for (key, value) in params {
        match *key {
            0 => {
                if value.is_empty() || value.len() % 2 != 0 {
                    return Err(ProtoError::Message(
                        "SVCB mandatory value must be a non-empty list of u16 keys".into(),
                    ));
                }
                let mut previous = None;
                for bytes in value.chunks_exact(2) {
                    let listed = u16::from_be_bytes([bytes[0], bytes[1]]);
                    if listed == 0
                        || previous.is_some_and(|previous| listed <= previous)
                        || !has(listed)
                    {
                        return Err(ProtoError::Message(
                            "SVCB mandatory key list is not self-consistent".into(),
                        ));
                    }
                    previous = Some(listed);
                }
            }
            1 => {
                let mut position = 0usize;
                while position < value.len() {
                    let len = usize::from(value[position]);
                    position += 1;
                    if len == 0 || position.saturating_add(len) > value.len() {
                        return Err(ProtoError::Message(
                            "Invalid length prefix in SVCB alpn value".into(),
                        ));
                    }
                    position += len;
                }
                if position == 0 {
                    return Err(ProtoError::Message("SVCB alpn value is empty".into()));
                }
            }
            2 if !value.is_empty() || !has(1) => {
                return Err(ProtoError::Message(
                    "SVCB no-default-alpn must be empty and requires alpn".into(),
                ));
            }
            3 if value.len() != 2 => {
                return Err(ProtoError::Message(
                    "SVCB port value must be exactly 2 bytes".into(),
                ));
            }
            4 if value.is_empty() || value.len() % 4 != 0 => {
                return Err(ProtoError::Message("Invalid SVCB ipv4hint length".into()));
            }
            6 if value.is_empty() || value.len() % 16 != 0 => {
                return Err(ProtoError::Message("Invalid SVCB ipv6hint length".into()));
            }
            _ => {}
        }
    }
    Ok(())
}

impl RData {
    pub fn soa(soa: Soa) -> Self {
        Self::Soa(Box::new(soa))
    }

    /// The encoder checks this against the TYPE field.
    pub fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::Aaaa(_) => RecordType::AAAA,
            RData::Ns(_) => RecordType::NS,
            RData::Cname(_) => RecordType::CNAME,
            RData::Dname(_) => RecordType::DNAME,
            RData::Ptr(_) => RecordType::PTR,
            RData::Mx { .. } => RecordType::MX,
            RData::Txt(_) => RecordType::TXT,
            RData::Soa(_) => RecordType::SOA,
            RData::Srv { .. } => RecordType::SRV,
            RData::Caa { .. } => RecordType::CAA,
            RData::Tlsa { .. } => RecordType::TLSA,
            RData::Sshfp { .. } => RecordType::SSHFP,
            RData::Naptr(_) => RecordType::NAPTR,
            RData::Uri { .. } => RecordType::URI,
            RData::Svcb { .. } => RecordType::SVCB,
            RData::Https { .. } => RecordType::HTTPS,
            RData::Unknown(t, _) => RecordType(*t),
        }
    }

    /// Checks internal RDATA constraints before encoding; only SVCB/HTTPS have any. Keeps
    /// hand-built values from going out in a form the parser would refuse.
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            RData::Svcb {
                priority, params, ..
            }
            | RData::Https {
                priority, params, ..
            } => validate_svcb_params(*priority, params),
            _ => Ok(()),
        }
    }

    /// `rdlen` is the declared RDATA length. Variable-length tails (CAA value, TLSA data) are sized
    /// from it, and checked_sub catches one shorter than the fixed part. The caller
    /// (Record::parse_inner) has already narrowed Reader::limit to the end of the RDATA, so name
    /// parsing cannot read past its own record.
    ///
    /// Obsolete name-bearing types are an error; other unknown types are kept as Unknown.
    pub fn parse(rtype: RecordType, r: &mut Reader, rdlen: usize) -> Result<RData, ProtoError> {
        Ok(match rtype {
            RecordType::A => {
                let b = r.bytes(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            RecordType::AAAA => {
                let b = r.bytes(16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                RData::Aaaa(Ipv6Addr::from(a))
            }
            RecordType::NS => RData::Ns(Name::parse(r)?),
            RecordType::CNAME => RData::Cname(Name::parse(r)?),
            RecordType::DNAME => RData::Dname(Name::parse(r)?),
            RecordType::PTR => RData::Ptr(Name::parse(r)?),
            RecordType::MX => RData::Mx {
                preference: r.u16()?,
                exchange: Name::parse(r)?,
            },
            RecordType::TXT => {
                let end = r.pos + rdlen;
                let mut chunks = vec![];
                while r.pos < end {
                    let n = r.u8()? as usize;
                    chunks.push(r.bytes(n)?.to_vec());
                }
                RData::Txt(chunks)
            }
            RecordType::SOA => RData::Soa(Box::new(Soa {
                mname: Name::parse(r)?,
                rname: Name::parse(r)?,
                serial: r.u32()?,
                refresh: r.u32()?,
                retry: r.u32()?,
                expire: r.u32()?,
                minimum: r.u32()?,
            })),
            RecordType::SRV => RData::Srv {
                priority: r.u16()?,
                weight: r.u16()?,
                port: r.u16()?,
                target: Name::parse(r)?,
            },
            RecordType::CAA => {
                let flags = r.u8()?;
                let tag_len = r.u8()? as usize;
                let tag = Box::from(r.bytes(tag_len)?);
                let vlen = rdlen.checked_sub(2 + tag_len).ok_or(ProtoError::Eof)?;
                let value = Box::from(r.bytes(vlen)?);
                RData::Caa { flags, tag, value }
            }
            RecordType::TLSA => {
                let usage = r.u8()?;
                let selector = r.u8()?;
                let matching = r.u8()?;
                let dlen = rdlen.checked_sub(3).ok_or(ProtoError::Eof)?;
                RData::Tlsa {
                    usage,
                    selector,
                    matching,
                    data: r.bytes(dlen)?.to_vec(),
                }
            }
            RecordType::SSHFP => {
                let algorithm = r.u8()?;
                let fp_type = r.u8()?;
                let flen = rdlen.checked_sub(2).ok_or(ProtoError::Eof)?;
                RData::Sshfp {
                    algorithm,
                    fp_type,
                    fingerprint: r.bytes(flen)?.to_vec(),
                }
            }
            RecordType::NAPTR => {
                let order = r.u16()?;
                let preference = r.u16()?;
                let flags = read_char_string(r)?;
                let services = read_char_string(r)?;
                let regexp = read_char_string(r)?;
                let replacement = Name::parse(r)?;
                RData::Naptr(Box::new(Naptr {
                    order,
                    preference,
                    flags,
                    services,
                    regexp,
                    replacement,
                }))
            }
            RecordType::URI => {
                let priority = r.u16()?;
                let weight = r.u16()?;
                let tlen = rdlen.checked_sub(4).ok_or(ProtoError::Eof)?;
                RData::Uri {
                    priority,
                    weight,
                    target: r.bytes(tlen)?.to_vec(),
                }
            }
            RecordType::SVCB | RecordType::HTTPS => {
                let end = r.pos + rdlen;
                let priority = r.u16()?;
                let target = Name::parse_uncompressed(r)?;
                let mut params = Vec::new();
                while r.pos < end {
                    let key = r.u16()?;
                    let plen = r.u16()? as usize;
                    params.push((key, Box::from(r.bytes(plen)?)));
                }
                validate_svcb_params(priority, &params)?;
                if rtype == RecordType::SVCB {
                    RData::Svcb {
                        priority,
                        target,
                        params: params.into_boxed_slice(),
                    }
                } else {
                    RData::Https {
                        priority,
                        target,
                        params: params.into_boxed_slice(),
                    }
                }
            }
            other if is_unsupported_name_bearing(other) => {
                return Err(ProtoError::Message(format!(
                    "Unsupported RDATA type {} that may contain compressed names",
                    other.0
                )))
            }
            other => RData::Unknown(other.0, r.bytes(rdlen)?.to_vec()),
        })
    }

    /// Writes the RDATA body; the caller backpatches the length. Only types defined in RFC 1035 may
    /// compress names in RDATA. RFC 3597 forbids it elsewhere because a pointer means something
    /// only inside its message, so a party copying the RDATA whole would produce names pointing at
    /// the wrong place. SRV, NAPTR, DNAME, SVCB, and HTTPS fall under this.
    pub fn encode(&self, w: &mut Writer) {
        match self {
            RData::A(ip) => w.push_bytes(&ip.octets()),
            RData::Aaaa(ip) => w.push_bytes(&ip.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => n.encode(w),
            RData::Dname(n) => n.encode_uncompressed(w),
            RData::Mx {
                preference,
                exchange,
            } => {
                w.push_u16(*preference);
                exchange.encode(w);
            }
            RData::Txt(chunks) => {
                for c in chunks {
                    let Ok(len) = u8::try_from(c.len()) else {
                        w.fail("TXT string exceeds 255 bytes");
                        return;
                    };
                    w.push_u8(len);
                    w.push_bytes(c);
                }
            }
            RData::Soa(s) => {
                s.mname.encode(w);
                s.rname.encode(w);
                w.push_u32(s.serial);
                w.push_u32(s.refresh);
                w.push_u32(s.retry);
                w.push_u32(s.expire);
                w.push_u32(s.minimum);
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                w.push_u16(*priority);
                w.push_u16(*weight);
                w.push_u16(*port);
                target.encode_uncompressed(w);
            }
            RData::Caa { flags, tag, value } => {
                w.push_u8(*flags);
                let Ok(tag_len) = u8::try_from(tag.len()) else {
                    w.fail("CAA tag exceeds 255 bytes");
                    return;
                };
                w.push_u8(tag_len);
                w.push_bytes(tag);
                w.push_bytes(value);
            }
            RData::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => {
                w.push_u8(*usage);
                w.push_u8(*selector);
                w.push_u8(*matching);
                w.push_bytes(data);
            }
            RData::Sshfp {
                algorithm,
                fp_type,
                fingerprint,
            } => {
                w.push_u8(*algorithm);
                w.push_u8(*fp_type);
                w.push_bytes(fingerprint);
            }
            RData::Naptr(naptr) => {
                w.push_u16(naptr.order);
                w.push_u16(naptr.preference);
                write_char_string(w, &naptr.flags);
                write_char_string(w, &naptr.services);
                write_char_string(w, &naptr.regexp);
                naptr.replacement.encode_uncompressed(w);
            }
            RData::Uri {
                priority,
                weight,
                target,
            } => {
                w.push_u16(*priority);
                w.push_u16(*weight);
                w.push_bytes(target);
            }
            RData::Svcb {
                priority,
                target,
                params,
            }
            | RData::Https {
                priority,
                target,
                params,
            } => {
                if let Err(error) = validate_svcb_params(*priority, params) {
                    w.fail(error.to_string());
                    return;
                }
                w.push_u16(*priority);
                target.encode_uncompressed(w);
                for (key, val) in params {
                    w.push_u16(*key);
                    let Ok(len) = u16::try_from(val.len()) else {
                        w.fail("SVCB parameter exceeds 65,535 bytes");
                        return;
                    };
                    w.push_u16(len);
                    w.push_bytes(val);
                }
            }
            RData::Unknown(_, bytes) => w.push_bytes(bytes),
        }
    }
}

/// `rtype` must equal `rdata.record_type()`; the message encoder checks this and refuses mismatched
/// records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Name,
    pub rtype: RecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: RData,
}

impl Record {
    /// An IN-class record whose type comes from the RDATA, so the two cannot disagree.
    pub fn new(name: Name, ttl: u32, rdata: RData) -> Self {
        Self {
            rtype: rdata.record_type(),
            name,
            class: DnsClass::IN,
            ttl,
            rdata,
        }
    }

    /// Empty RDATA is accepted only where the type allows it.
    pub fn parse(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, None)
    }

    /// Prerequisite-section records of UPDATE. Classes NONE (254) and ANY (255) only ask whether a
    /// name exists, so an empty RDATA is normal there.
    pub(crate) fn parse_update_empty(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, Some(&[254, 255]))
    }

    /// Update-section records. Class ANY (255) is a delete, so an empty RDATA is normal; NONE must
    /// carry the data to delete and is not accepted empty.
    pub(crate) fn parse_update_operation(r: &mut Reader) -> Result<Record, ProtoError> {
        Self::parse_inner(r, Some(&[255]))
    }

    /// Narrows Reader::limit to the declared end while reading the RDATA, then restores it, so name
    /// parsing cannot cross the record boundary. Afterwards the cursor must sit exactly at that
    /// end, which refuses records whose declared length disagrees with what was consumed.
    /// `empty_rdata_classes` lists the classes allowed an empty RDATA; only UPDATE sections pass
    /// any.
    fn parse_inner(
        r: &mut Reader,
        empty_rdata_classes: Option<&[u16]>,
    ) -> Result<Record, ProtoError> {
        let name = Name::parse(r)?;
        let rtype = RecordType(r.u16()?);
        let class = DnsClass(r.u16()?);
        let ttl = r.u32()?;
        let rdlen = r.u16()? as usize;
        let start = r.pos;
        let end = start.checked_add(rdlen).ok_or(ProtoError::Eof)?;
        if end > r.limit {
            return Err(ProtoError::Eof);
        }
        let previous_limit = r.limit;
        r.limit = end;
        let parsed = if rdlen == 0
            && empty_rdata_classes.is_some_and(|classes| classes.contains(&class.0))
        {
            Ok(RData::Unknown(rtype.0, Vec::new()))
        } else {
            RData::parse(rtype, r, rdlen)
        };
        r.limit = previous_limit;
        let rdata = parsed?;
        if r.pos != end {
            return Err(ProtoError::Name("RDATA length does not match".into()));
        }
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    pub fn encode(&self, w: &mut Writer) {
        self.encode_with_ttl(w, self.ttl);
    }

    /// Writes the record with another TTL field value. Only for OPT, whose TTL field carries
    /// extended rcode, version, and DO; the extended rcode merged into the header goes back into
    /// this field.
    pub(crate) fn encode_with_ttl(&self, w: &mut Writer, ttl: u32) {
        self.name.encode(w);
        w.push_u16(self.rtype.0);
        w.push_u16(self.class.0);
        w.push_u32(ttl);
        let at = w.placeholder_u16();
        self.rdata.encode(w);
        w.backpatch_len(at);
    }
}

/// TTL ceiling from RFC 2181; larger values count as 0.
pub const MAX_TTL: u32 = 0x7fff_ffff;

/// Meta types whose TTL field means something else: OPT carries extended rcode and DO, and TSIG and
/// TKEY fix it at 0.
fn ttl_field_is_not_a_lifetime(rtype: RecordType) -> bool {
    matches!(rtype.0, 41 | 249 | 250)
}

/// Key identifying an RRset. The owner name compares case-insensitively. RRSIGs covering different
/// types are different RRsets, each sharing the TTL of the RRset it covers, so the first 2 bytes
/// (type covered) are part of the key.
fn rrset_key(record: &Record) -> (Vec<u8>, u16, u16, u16) {
    let covered = if record.rtype == RecordType::RRSIG {
        match &record.rdata {
            RData::Unknown(_, raw) if raw.len() >= 2 => u16::from_be_bytes([raw[0], raw[1]]),
            _ => 0,
        }
    } else {
        0
    };
    (
        record.name.canonical_key(),
        record.rtype.0,
        record.class.0,
        covered,
    )
}

/// Applies the RFC 2181 TTL rules to one section. A TTL with the high bit set counts as 0 in full.
/// All TTLs in an RRset must be equal and a server must not send them differing, so each RRset
/// takes its smallest value. Values only go down, so the result never tells a client to keep data
/// longer than the upstream said.
///
/// Different sections are different RRsets; the caller calls this per section.
pub fn normalize_ttls(records: &mut [Record]) {
    for record in records.iter_mut() {
        if !ttl_field_is_not_a_lifetime(record.rtype) && record.ttl > MAX_TTL {
            record.ttl = 0;
        }
    }

    let mut lowest: HashMap<(Vec<u8>, u16, u16, u16), u32> = HashMap::new();
    for record in records.iter() {
        if ttl_field_is_not_a_lifetime(record.rtype) {
            continue;
        }
        lowest
            .entry(rrset_key(record))
            .and_modify(|ttl| *ttl = (*ttl).min(record.ttl))
            .or_insert(record.ttl);
    }
    if lowest.len() == records.len() {
        return;
    }
    for record in records.iter_mut() {
        if ttl_field_is_not_a_lifetime(record.rtype) {
            continue;
        }
        if let Some(ttl) = lowest.get(&rrset_key(record)) {
            record.ttl = *ttl;
        }
    }
}

#[cfg(test)]
mod typed_rdata_tests {
    use super::*;

    fn roundtrip(rd: RData) -> RData {
        let rec = Record::new(Name::from_str("svc.example.com").unwrap(), 300, rd);
        let mut w = Writer::new();
        rec.encode(&mut w);
        let mut r = Reader::new(&w.buf);
        Record::parse(&mut r).unwrap().rdata
    }

    fn boxed_params(params: Vec<(u16, Vec<u8>)>) -> Box<[(u16, Box<[u8]>)]> {
        params
            .into_iter()
            .map(|(key, value)| (key, value.into_boxed_slice()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    /// The largest variant sets the cost of every record.
    fn rdata_layout_stays_cache_compact() {
        assert_eq!(
            std::mem::size_of::<RData>(),
            48,
            "RData grew. Check that a new variant was added inline, and Box rare large variants"
        );
        assert_eq!(std::mem::size_of::<Record>(), 72);
        assert_eq!(std::mem::size_of::<(u16, Box<[u8]>)>(), 24);
    }

    #[test]
    fn typed_rdata_wire_roundtrip() {
        let tlsa = RData::Tlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            data: vec![0xab, 0xcd, 0xef],
        };
        assert_eq!(roundtrip(tlsa.clone()), tlsa);
        assert_eq!(tlsa.record_type(), RecordType::TLSA);

        let sshfp = RData::Sshfp {
            algorithm: 4,
            fp_type: 2,
            fingerprint: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(roundtrip(sshfp.clone()), sshfp);
        assert_eq!(sshfp.record_type(), RecordType::SSHFP);

        let naptr = RData::Naptr(Box::new(Naptr {
            order: 100,
            preference: 10,
            flags: b"U".to_vec(),
            services: b"E2U+sip".to_vec(),
            regexp: b"!^.*$!sip:info@example.com!".to_vec(),
            replacement: Name::root(),
        }));
        assert_eq!(roundtrip(naptr.clone()), naptr);
        assert_eq!(naptr.record_type(), RecordType::NAPTR);

        let uri = RData::Uri {
            priority: 10,
            weight: 1,
            target: b"https://example.com/".to_vec(),
        };
        assert_eq!(roundtrip(uri.clone()), uri);
        assert_eq!(uri.record_type(), RecordType::URI);

        let svcb = RData::Svcb {
            priority: 1,
            target: Name::from_str("svc.example.net").unwrap(),
            params: boxed_params(vec![(1, vec![2, b'h', b'2']), (3, vec![0x01, 0xbb])]),
        };
        assert_eq!(roundtrip(svcb.clone()), svcb);
        assert_eq!(svcb.record_type(), RecordType::SVCB);

        let https = RData::Https {
            priority: 0,
            target: Name::from_str("svc.example.net").unwrap(),
            params: Box::default(),
        };
        assert_eq!(roundtrip(https.clone()), https);
        assert_eq!(https.record_type(), RecordType::HTTPS);

        let dname = RData::Dname(Name::from_str("target.example.net").unwrap());
        assert_eq!(roundtrip(dname.clone()), dname);
        assert_eq!(dname.record_type(), RecordType::DNAME);
    }

    #[test]
    /// Rewritten as is, their compression pointers break.
    fn rejects_unknown_name_bearing_rdata() {
        const NAME_BEARING: [u16; 13] = [3, 4, 7, 8, 9, 14, 17, 18, 21, 23, 26, 30, 36];
        for rtype in NAME_BEARING {
            let [high, low] = rtype.to_be_bytes();
            let wire = [0, high, low, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 0x00];
            let mut reader = Reader::new(&wire);
            let Err(error) = Record::parse(&mut reader) else {
                panic!("type {rtype} must be rejected. Rewriting RDATA that contains compressed names as raw bytes corrupts the response");
            };
            assert!(
                error.to_string().contains("Unsupported RDATA type"),
                "type {rtype}: {error}"
            );
        }
    }

    #[test]
    fn svcb_wire_rejects_compressed_target_and_non_increasing_keys() {
        let compressed = [0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 4, 0, 1, 0xc0, 0x00];
        assert!(Record::parse(&mut Reader::new(&compressed)).is_err());

        let mut reversed = vec![0, 0, 64, 0, 1, 0, 0, 0, 0, 0, 15, 0, 1, 0];
        reversed.extend_from_slice(&[0, 3, 0, 2, 1, 187]);
        reversed.extend_from_slice(&[0, 1, 0, 2, 1, b'h']);
        assert!(Record::parse(&mut Reader::new(&reversed)).is_err());
    }

    #[test]
    /// RFC 3597 limits compression to RFC 1035 types: a pointer means something only inside its
    /// message, so a party copying RDATA whole would produce names pointing at the wrong place. The
    /// owner name is written first so the shared suffix is already in the message and compression
    /// has somewhere to happen.
    ///
    /// MX in the same message is an RFC 1035 type and must be compressed; turning compression off
    /// entirely would grow responses, so both sides are pinned.
    fn rdata_names_outside_rfc1035_are_never_compressed() {
        /// Walks the name field in RDATA looking for a compression pointer. The pointer comes after
        /// some literal labels, not at the first byte, and searching the whole buffer for 0xC0 bits
        /// would also hit ordinary values like ports or TTLs.
        fn name_is_compressed(rdata: &[u8], mut at: usize) -> bool {
            while at < rdata.len() {
                let len = rdata[at];
                if len & 0xC0 == 0xC0 {
                    return true;
                }
                if len == 0 {
                    return false;
                }
                at += 1 + usize::from(len);
            }
            false
        }

        let apex = Name::from_str("wire.test").unwrap();
        let target = Name::from_str("t.wire.test").unwrap();
        // NAPTR's name field starts at 15: after order 2, preference 2, and three strings.
        let cases: Vec<(&str, RData, usize, bool)> = vec![
            (
                "SRV",
                RData::Srv {
                    priority: 1,
                    weight: 2,
                    port: 5060,
                    target: target.clone(),
                },
                6,
                false,
            ),
            ("DNAME", RData::Dname(target.clone()), 0, false),
            (
                "NAPTR",
                RData::Naptr(Box::new(Naptr {
                    order: 1,
                    preference: 2,
                    flags: b"u".to_vec(),
                    services: b"E2U+sip".to_vec(),
                    regexp: Vec::new(),
                    replacement: target.clone(),
                })),
                15,
                false,
            ),
            (
                "SVCB",
                RData::Svcb {
                    priority: 1,
                    target: target.clone(),
                    params: Box::default(),
                },
                2,
                false,
            ),
            (
                "MX",
                RData::Mx {
                    preference: 10,
                    exchange: target.clone(),
                },
                2,
                true,
            ),
            ("CNAME", RData::Cname(target.clone()), 0, true),
            ("NS", RData::Ns(target.clone()), 0, true),
        ];

        for (label, rdata, name_at, compressible) in cases {
            let mut writer = Writer::new();
            // The suffix must already be in the message for compression to have somewhere to
            // happen.
            apex.encode(&mut writer);
            let start = writer.buf.len();
            rdata.encode(&mut writer);
            assert!(writer.error().is_none(), "Encoding {label} failed");
            let body = &writer.buf[start..];
            assert_eq!(
                name_is_compressed(body, name_at),
                compressible,
                "{label} compression does not match the spec: {body:02x?}"
            );
        }
    }

    #[test]
    fn svcb_encoder_never_compresses_target_name() {
        let name = Name::from_str("svc.example").unwrap();
        let record = Record::new(
            name.clone(),
            60,
            RData::Svcb {
                priority: 1,
                target: name,
                params: Box::default(),
            },
        );
        let mut writer = Writer::new();
        record.encode(&mut writer);
        assert!(writer.error().is_none());
        assert_eq!(writer.buf[25], 3, "First TargetName label is not a pointer");
        assert_eq!(&writer.buf[25..], b"\x03svc\x07example\x00");
    }

    #[test]
    fn svcb_known_parameter_formats_are_strict() {
        let invalid = [
            vec![(3, vec![0, 53]), (3, vec![0, 54])],
            vec![(3, vec![0])],
            vec![(1, vec![])],
            vec![(2, vec![])],
            vec![(4, vec![])],
            vec![(6, vec![0; 15])],
            vec![(u16::MAX, vec![])],
        ];
        for params in invalid {
            let rdata = RData::Https {
                priority: 1,
                target: Name::root(),
                params: boxed_params(params),
            };
            assert!(rdata.validate().is_err(), "{rdata:?}");
        }

        let valid = RData::Https {
            priority: 1,
            target: Name::root(),
            params: boxed_params(vec![
                (0, vec![0, 1, 0, 3]),
                (1, vec![2, b'h', b'2']),
                (2, vec![]),
                (3, 443u16.to_be_bytes().to_vec()),
            ]),
        };
        assert!(valid.validate().is_ok());
    }
}

#[cfg(test)]
mod ttl_normalization_tests {
    use super::*;

    fn a(name: &str, ttl: u32, last: u8) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, last)),
        )
    }

    #[test]
    fn a_ttl_above_the_ceiling_becomes_zero() {
        let mut records = vec![
            a("x.example.com", 0x8000_0000, 1),
            a("y.example.com", 300, 2),
        ];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, 0);
        assert_eq!(records[1].ttl, 300, "Values below the cap are unchanged");

        let mut edge = vec![a("z.example.com", MAX_TTL, 3)];
        normalize_ttls(&mut edge);
        assert_eq!(edge[0].ttl, MAX_TTL, "The cap itself is a valid value");
    }

    #[test]
    fn one_rrset_leaves_with_one_ttl() {
        let mut records = vec![
            a("host.example.com", 900, 10),
            a("host.example.com", 100, 11),
            a("other.example.com", 700, 12),
        ];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, 100);
        assert_eq!(records[1].ttl, 100);
        assert_eq!(records[2].ttl, 700, "Other names are not grouped");
    }

    #[test]
    /// Case-insensitive, per RFC 4343.
    fn case_does_not_split_an_rrset() {
        let mut records = vec![
            a("Host.Example.COM", 900, 10),
            a("host.example.com", 100, 11),
        ];
        normalize_ttls(&mut records);
        assert_eq!((records[0].ttl, records[1].ttl), (100, 100));
    }

    #[test]
    /// A value zeroed by the ceiling pulls its whole RRset to 0.
    fn the_ceiling_rule_runs_before_the_rrset_rule() {
        let mut records = vec![
            a("host.example.com", 0x8000_0000, 10),
            a("host.example.com", 300, 11),
        ];
        normalize_ttls(&mut records);
        assert_eq!((records[0].ttl, records[1].ttl), (0, 0));
    }

    #[test]
    /// OPT's TTL field holds extended rcode and DO, not a lifetime.
    fn the_opt_pseudo_record_is_left_alone() {
        let flags = 0x8000_0000u32;
        let mut records = vec![Record {
            name: Name::root(),
            rtype: RecordType::OPT,
            class: DnsClass(1232),
            ttl: flags,
            rdata: RData::Unknown(RecordType::OPT.0, Vec::new()),
        }];
        normalize_ttls(&mut records);
        assert_eq!(records[0].ttl, flags);
    }

    #[test]
    fn signatures_over_different_types_are_different_rrsets() {
        let sig = |covered: u16, ttl: u32| {
            let mut raw = covered.to_be_bytes().to_vec();
            raw.extend_from_slice(&[13, 2, 0, 0, 0, 0, 0]);
            Record {
                name: Name::from_str("host.example.com").unwrap(),
                rtype: RecordType::RRSIG,
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(RecordType::RRSIG.0, raw),
            }
        };
        let mut records = vec![sig(1, 900), sig(28, 100), sig(1, 500)];
        normalize_ttls(&mut records);
        assert_eq!(
            records[0].ttl, 500,
            "Only signatures covering A are grouped"
        );
        assert_eq!(
            records[1].ttl, 100,
            "Signatures covering AAAA are unchanged"
        );
        assert_eq!(records[2].ttl, 500);
    }
}
