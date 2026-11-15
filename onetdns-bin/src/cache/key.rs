//! Cache keys: every request byte that can change the response. The ID, name case, and empty
//! padding cannot, so they are removed. A key holding less would give one query another's answer;
//! one holding more would miss.

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

use onetdns_proto::{Message, RData, RecordType};

pub(crate) const MAX_CACHED_REQUEST_WIRE: usize = 4_096;

pub(crate) const INLINE_REQUEST_KEY_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
/// An owned normalized request; also the cache and failure key.
pub(crate) struct FlightKey {
    normalized_wire: Box<[u8]>,
}

impl FlightKey {
    pub(crate) fn from_request(request: &Message) -> Option<Self> {
        NormalizedRequestKey::from_request(request).map(NormalizedRequestKey::into_owned)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.normalized_wire
    }
}

#[cfg(test)]
impl FlightKey {
    pub(crate) fn from_normalized_bytes(normalized_wire: Box<[u8]>) -> Self {
        Self { normalized_wire }
    }
}

impl Borrow<[u8]> for FlightKey {
    /// Lets lookups use the bytes without building a key.
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Hash for FlightKey {
    /// Must hash like `[u8]` for the `Borrow` lookups to find it.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

/// A key being built: on the stack up to the inline capacity, on the heap past it. Most lookups end
/// here and never need an owned key.
pub(crate) enum NormalizedRequestKey {
    Inline {
        bytes: [u8; INLINE_REQUEST_KEY_CAPACITY],
        len: usize,
    },
    Heap(Vec<u8>),
}

impl NormalizedRequestKey {
    fn with_capacity(capacity: usize) -> Self {
        if capacity <= INLINE_REQUEST_KEY_CAPACITY {
            Self::Inline {
                bytes: [0; INLINE_REQUEST_KEY_CAPACITY],
                len: 0,
            }
        } else {
            Self::Heap(Vec::with_capacity(capacity))
        }
    }

    fn push(&mut self, value: u8) {
        match self {
            Self::Inline { bytes, len } => {
                debug_assert!(*len < bytes.len());
                bytes[*len] = value;
                *len += 1;
            }
            Self::Heap(bytes) => bytes.push(value),
        }
    }

    fn extend_from_slice(&mut self, value: &[u8]) {
        match self {
            Self::Inline { bytes, len } => {
                let end = *len + value.len();
                debug_assert!(end <= bytes.len());
                bytes[*len..end].copy_from_slice(value);
                *len = end;
            }
            Self::Heap(bytes) => bytes.extend_from_slice(value),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { bytes, len } => &bytes[..*len],
            Self::Heap(bytes) => bytes,
        }
    }

    /// Call only when storing.
    pub(crate) fn into_owned(self) -> FlightKey {
        let normalized_wire = match self {
            Self::Inline { bytes, len } => bytes[..len].into(),
            Self::Heap(bytes) => bytes.into_boxed_slice(),
        };
        FlightKey { normalized_wire }
    }

    /// None for a request that cannot be cached.
    pub(crate) fn from_request(request: &Message) -> Option<Self> {
        if request.header.response
            || request.header.opcode != 0
            || request.header.authoritative
            || request.header.truncated
            || request.header.recursion_available
            || request.header.rcode != 0
            || request.questions.len() != 1
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || request.additionals.len() > 1
            || request
                .additionals
                .iter()
                .any(|record| record.rtype != RecordType::OPT)
        {
            return None;
        }
        let question = &request.questions[0];
        let mut canonical_name = [0u8; 255];
        let canonical_name = question.name.canonical_key_into(&mut canonical_name)?;

        let opt = request.additionals.first();
        let mut option_count = 0u16;
        let mut semantic_option_bytes = 0usize;
        let edns = if let Some(record) = opt {
            if !record.name.is_root() {
                return None;
            }
            let raw = match &record.rdata {
                RData::Unknown(_, raw) => raw.as_slice(),
                _ => return None,
            };
            let mut offset = 0usize;
            while offset < raw.len() {
                let header = raw.get(offset..offset.checked_add(4)?)?;
                let code = u16::from_be_bytes([header[0], header[1]]);
                let len = u16::from_be_bytes([header[2], header[3]]) as usize;
                offset = offset.checked_add(4)?;
                let end = offset.checked_add(len)?;
                raw.get(offset..end)?;
                if code == onetdns_proto::EDNS_PADDING {
                    offset = end;
                    continue;
                }
                option_count = option_count.checked_add(1)?;
                semantic_option_bytes = semantic_option_bytes.checked_add(4 + len)?;
                offset = end;
            }
            Some((
                raw,
                record.class.0,
                ((record.ttl >> 16) & 0xff) as u8,
                (record.ttl & 0x0000_8000) != 0,
            ))
        } else {
            None
        };

        let base_len = 1usize
            .checked_add(2)?
            .checked_add(canonical_name.len())?
            .checked_add(4)?
            .checked_add(1)?;
        let key_len = base_len.checked_add(if edns.is_some() {
            6usize.checked_add(semantic_option_bytes)?
        } else {
            0
        })?;
        if key_len > MAX_CACHED_REQUEST_WIRE {
            return None;
        }

        let mut normalized_wire = Self::with_capacity(key_len);
        normalized_wire.push(1);
        let semantic_flags = (u16::from(request.header.recursion_desired) << 8)
            | (u16::from(request.header.authentic_data) << 5)
            | (u16::from(request.header.checking_disabled) << 4);
        normalized_wire.extend_from_slice(&semantic_flags.to_be_bytes());
        normalized_wire.extend_from_slice(canonical_name);
        normalized_wire.extend_from_slice(&question.qtype.0.to_be_bytes());
        normalized_wire.extend_from_slice(&question.qclass.0.to_be_bytes());
        normalized_wire.push(u8::from(edns.is_some()));
        if let Some((raw, udp_payload, version, dnssec_ok)) = edns {
            normalized_wire.extend_from_slice(&udp_payload.to_be_bytes());
            normalized_wire.push(version);
            normalized_wire.push(u8::from(dnssec_ok));
            normalized_wire.extend_from_slice(&option_count.to_be_bytes());
            let mut offset = 0usize;
            while offset < raw.len() {
                let code = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
                let len = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
                let end = offset + 4 + len;

                if code == onetdns_proto::EDNS_PADDING {
                    offset = end;
                    continue;
                }
                normalized_wire.extend_from_slice(&code.to_be_bytes());
                normalized_wire.extend_from_slice(&(len as u16).to_be_bytes());
                normalized_wire.extend_from_slice(&raw[offset + 4..end]);
                offset = end;
            }
        }
        debug_assert_eq!(normalized_wire.as_slice().len(), key_len);

        Some(normalized_wire)
    }
}

pub(crate) type CacheKey = FlightKey;
pub(crate) type FailureKey = FlightKey;
