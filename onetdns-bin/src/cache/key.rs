/*!
 * @brief 응답을 달라지게 하는 모든 것을 담은 캐시 키와 그 정규화.
 *
 * @details 질의 번호와 이름 대소문자, 내용 없는 채우기 옵션은 응답을 바꾸지 않으므로 키에서
 *          지운다. 덜 담으면 다른 질의에 같은 답을 주고, 무관한 것까지 담으면 캐시가 맞지 않는다.
 */

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};

use onetdns_proto::{Message, RData, RecordType};

/** @brief 캐시할 키 길이 상한. */
pub(crate) const MAX_CACHED_REQUEST_WIRE: usize = 4_096;

/** @brief 이 길이까지는 할당 없이 담는다. */
pub(crate) const INLINE_REQUEST_KEY_CAPACITY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 정규화한 질의를 담은 키. */
pub(crate) struct FlightKey {
    /** @brief 정규화한 질의 바이트. */
    normalized_wire: Box<[u8]>,
}

impl FlightKey {
    /** @brief 요청에서 키를 만든다. */
    pub(crate) fn from_request(request: &Message) -> Option<Self> {
        NormalizedRequestKey::from_request(request).map(NormalizedRequestKey::into_owned)
    }

    /** @brief 키 바이트. */
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.normalized_wire
    }
}

#[cfg(test)]
impl FlightKey {
    /** @brief 테스트에서 임의의 정규화 바이트로 키를 만든다. */
    pub(crate) fn from_normalized_bytes(normalized_wire: Box<[u8]>) -> Self {
        Self { normalized_wire }
    }
}

impl Borrow<[u8]> for FlightKey {
    /** @brief 바이트로 빌려 조회에 쓴다. 조회할 때마다 키를 새로 만들지 않으려는 것이다. */
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Hash for FlightKey {
    /** @brief 바이트를 그대로 해시값으로 쓴다. */
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

/**
 * @brief 만드는 중인 키.
 * @details 흔한 길이는 스택에 담고 넘칠 때만 할당한다. 조회는 대개 여기서 끝나 소유권을
 *          가질 일이 없다.
 */
pub(crate) enum NormalizedRequestKey {
    /** @brief 짧아서 스택에 담은 것. */
    Inline {
        /** @brief 스택에 담은 키 바이트. */
        bytes: [u8; INLINE_REQUEST_KEY_CAPACITY],
        /** @brief 그중 실제로 쓴 길이. */
        len: usize,
    },
    /** @brief 길어서 따로 잡은 것. */
    Heap(Vec<u8>),
}

impl NormalizedRequestKey {
    /** @brief 예상 길이에 맞는 저장소를 고른다. */
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

    /** @brief 한 바이트 붙인다. */
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

    /** @brief 여러 바이트 붙인다. */
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

    /** @brief 지금까지 담긴 바이트. */
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { bytes, len } => &bytes[..*len],
            Self::Heap(bytes) => bytes,
        }
    }

    /** @brief 소유권 있는 키로. 실제로 저장할 때만 부른다. */
    pub(crate) fn into_owned(self) -> FlightKey {
        let normalized_wire = match self {
            Self::Inline { bytes, len } => bytes[..len].into(),
            Self::Heap(bytes) => bytes.into_boxed_slice(),
        };
        FlightKey { normalized_wire }
    }

    /**
     * @brief 요청을 정규화해 키를 만든다.
     * @details 질의 번호와 이름 대소문자, 내용 없는 채우기 옵션은 응답을 바꾸지 않으므로
     *          지운다. 나머지는 그대로 담는다.
     * @return 키. 캐시할 수 없는 모양의 요청이면 없다.
     */
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

/** @brief 캐시 키. */
pub(crate) type CacheKey = FlightKey;
/** @brief 실패 기억 키. */
pub(crate) type FailureKey = FlightKey;
