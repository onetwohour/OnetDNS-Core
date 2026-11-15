//! QUIC transport parameters. The peer's values are untrusted: values that would cost this side are
//! capped, and a repeated parameter or a non-canonical encoding is rejected.

use std::collections::HashSet;

use crate::varint;

/// Parameter IDs from RFC 9000.
pub mod id {
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// This side never moves to the preferred address. Its connection ID is still the server's sequence
/// number 1, so it counts toward the peer's connection ID limit and sequence collisions.
pub struct PreferredAddress {
    /// All zeros when unused.
    pub ipv4: std::net::SocketAddrV4,
    /// All zeros when unused.
    pub ipv6: std::net::SocketAddrV6,
    /// 1 to 20 bytes.
    pub cid: Vec<u8>,
    pub reset_token: [u8; 16],
}

impl PreferredAddress {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.cid.len());
        out.extend_from_slice(&self.ipv4.ip().octets());
        out.extend_from_slice(&self.ipv4.port().to_be_bytes());
        out.extend_from_slice(&self.ipv6.ip().octets());
        out.extend_from_slice(&self.ipv6.port().to_be_bytes());
        out.push(self.cid.len() as u8);
        out.extend_from_slice(&self.cid);
        out.extend_from_slice(&self.reset_token);
        out
    }

    /// None on a wrong length or a connection ID outside 1 to 20 bytes; RFC 9000 makes a
    /// zero-length one a TRANSPORT_PARAMETER_ERROR.
    fn decode(value: &[u8]) -> Option<Self> {
        let ipv4: [u8; 4] = value.get(..4)?.try_into().ok()?;
        let port4 = u16::from_be_bytes(value.get(4..6)?.try_into().ok()?);
        let ipv6: [u8; 16] = value.get(6..22)?.try_into().ok()?;
        let port6 = u16::from_be_bytes(value.get(22..24)?.try_into().ok()?);
        let cid_len = usize::from(*value.get(24)?);
        if !(1..=20).contains(&cid_len) || value.len() != 41 + cid_len {
            return None;
        }
        Some(Self {
            ipv4: std::net::SocketAddrV4::new(ipv4.into(), port4),
            ipv6: std::net::SocketAddrV6::new(ipv6.into(), port6, 0, 0),
            cid: value[25..25 + cid_len].to_vec(),
            reset_token: value[25 + cid_len..].try_into().ok()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParams {
    pub original_destination_connection_id: Option<Vec<u8>>,
    pub initial_source_connection_id: Option<Vec<u8>>,
    pub retry_source_connection_id: Option<Vec<u8>>,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
    /// Only a server may send it.
    pub preferred_address: Option<PreferredAddress>,
}

impl Default for TransportParams {
    /// RFC 9000 defaults, used for parameters the peer omits.
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            stateless_reset_token: None,
            max_idle_timeout: 0,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            active_connection_id_limit: 2,
            disable_active_migration: false,
            preferred_address: None,
        }
    }
}

fn put_int(out: &mut Vec<u8>, pid: u64, value: u64) {
    varint::write(out, pid);
    varint::write(out, varint::len(value) as u64);
    varint::write(out, value);
}

fn put_bytes(out: &mut Vec<u8>, pid: u64, value: &[u8]) {
    varint::write(out, pid);
    varint::write(out, value.len() as u64);
    out.extend_from_slice(value);
}

impl TransportParams {
    pub fn server_defaults() -> Self {
        Self {
            max_idle_timeout: 30_000,
            max_udp_payload_size: 65527,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 18,
            initial_max_stream_data_bidi_remote: 1 << 18,
            initial_max_stream_data_uni: 1 << 18,
            initial_max_streams_bidi: 128,
            initial_max_streams_uni: 16,
            active_connection_id_limit: 2,
            disable_active_migration: true,
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(c) = &self.original_destination_connection_id {
            put_bytes(&mut out, id::ORIGINAL_DESTINATION_CONNECTION_ID, c);
        }
        if let Some(c) = &self.initial_source_connection_id {
            put_bytes(&mut out, id::INITIAL_SOURCE_CONNECTION_ID, c);
        }
        if let Some(c) = &self.retry_source_connection_id {
            put_bytes(&mut out, id::RETRY_SOURCE_CONNECTION_ID, c);
        }
        if let Some(token) = &self.stateless_reset_token {
            put_bytes(&mut out, id::STATELESS_RESET_TOKEN, token);
        }
        put_int(&mut out, id::MAX_IDLE_TIMEOUT, self.max_idle_timeout);
        put_int(
            &mut out,
            id::MAX_UDP_PAYLOAD_SIZE,
            self.max_udp_payload_size,
        );
        put_int(&mut out, id::INITIAL_MAX_DATA, self.initial_max_data);
        put_int(
            &mut out,
            id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put_int(
            &mut out,
            id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        put_int(
            &mut out,
            id::INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        put_int(
            &mut out,
            id::INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        );
        put_int(
            &mut out,
            id::INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        );
        put_int(&mut out, id::ACK_DELAY_EXPONENT, self.ack_delay_exponent);
        put_int(&mut out, id::MAX_ACK_DELAY, self.max_ack_delay);
        put_int(
            &mut out,
            id::ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        );
        if self.disable_active_migration {
            varint::write(&mut out, id::DISABLE_ACTIVE_MIGRATION);
            varint::write(&mut out, 0);
        }
        if let Some(address) = &self.preferred_address {
            put_bytes(&mut out, id::PREFERRED_ADDRESS, &address.encode());
        }
        out
    }

    /// A repeated parameter is rejected: which value applies is undefined, and implementations that
    /// pick differently can be played against each other. Non-canonical integers are rejected for
    /// the same reason.
    ///
    /// None on malformed input or an out-of-range value.
    pub fn decode(buf: &[u8]) -> Option<TransportParams> {
        const MAX_CID_LEN: usize = 20;
        /// Peer stream limits above this are clamped.
        const MAX_STREAMS: u64 = 1 << 20;
        /// Peer flow control limits above this are clamped.
        const MAX_FLOW_CREDIT: u64 = 1 << 40;

        /// RFC 9000 makes a stream limit above 2^60 an error.
        const MAX_STREAMS_LIMIT: u64 = 1 << 60;

        let mut tp = TransportParams::default();
        let mut pos = 0usize;
        let mut seen = HashSet::new();
        while pos < buf.len() {
            let (pid, n) = varint::read(buf.get(pos..)?)?;
            pos = pos.checked_add(n)?;
            if !seen.insert(pid) {
                return None;
            }
            let (len, n) = varint::read(buf.get(pos..)?)?;
            pos = pos.checked_add(n)?;
            let len = usize::try_from(len).ok()?;
            let end = pos.checked_add(len)?;
            let value = buf.get(pos..end)?;
            pos = end;

            let as_int = || -> Option<u64> {
                let (value_int, consumed) = varint::read(value)?;
                (consumed == value.len()).then_some(value_int)
            };
            let cid =
                || -> Option<Vec<u8>> { (value.len() <= MAX_CID_LEN).then(|| value.to_vec()) };
            match pid {
                id::ORIGINAL_DESTINATION_CONNECTION_ID => {
                    tp.original_destination_connection_id = Some(cid()?)
                }
                id::INITIAL_SOURCE_CONNECTION_ID => tp.initial_source_connection_id = Some(cid()?),
                id::RETRY_SOURCE_CONNECTION_ID => tp.retry_source_connection_id = Some(cid()?),
                id::STATELESS_RESET_TOKEN => {
                    tp.stateless_reset_token = Some(value.try_into().ok()?);
                }
                id::MAX_IDLE_TIMEOUT => tp.max_idle_timeout = as_int()?,
                id::MAX_UDP_PAYLOAD_SIZE => {
                    // RFC 9000 rejects only values below 1200; larger ones are clamped to the UDP
                    // maximum, 65527.
                    let v = as_int()?;
                    if v < 1200 {
                        return None;
                    }
                    tp.max_udp_payload_size = v.min(65527);
                }

                id::INITIAL_MAX_DATA => {
                    tp.initial_max_data = as_int()?.min(MAX_FLOW_CREDIT);
                }
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    tp.initial_max_stream_data_bidi_local = as_int()?.min(MAX_FLOW_CREDIT);
                }
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    tp.initial_max_stream_data_bidi_remote = as_int()?.min(MAX_FLOW_CREDIT);
                }
                id::INITIAL_MAX_STREAM_DATA_UNI => {
                    tp.initial_max_stream_data_uni = as_int()?.min(MAX_FLOW_CREDIT);
                }
                id::INITIAL_MAX_STREAMS_BIDI => {
                    let v = as_int()?;
                    if v > MAX_STREAMS_LIMIT {
                        return None;
                    }
                    tp.initial_max_streams_bidi = v.min(MAX_STREAMS);
                }
                id::INITIAL_MAX_STREAMS_UNI => {
                    let v = as_int()?;
                    if v > MAX_STREAMS_LIMIT {
                        return None;
                    }
                    tp.initial_max_streams_uni = v.min(MAX_STREAMS);
                }
                id::ACK_DELAY_EXPONENT => {
                    let v = as_int()?;
                    if v > 20 {
                        return None;
                    }
                    tp.ack_delay_exponent = v;
                }
                id::MAX_ACK_DELAY => {
                    let v = as_int()?;
                    if v >= (1 << 14) {
                        return None;
                    }
                    tp.max_ack_delay = v;
                }
                id::ACTIVE_CONNECTION_ID_LIMIT => {
                    // RFC 9000 rejects only values below 2. This side issues just the handshake
                    // connection ID, so a large limit costs nothing.
                    let v = as_int()?;
                    if v < 2 {
                        return None;
                    }
                    tp.active_connection_id_limit = v;
                }
                id::DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return None;
                    }
                    tp.disable_active_migration = true;
                }
                id::PREFERRED_ADDRESS => {
                    tp.preferred_address = Some(PreferredAddress::decode(value)?);
                }
                _ => {}
            }
        }
        Some(tp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_server_defaults() {
        let mut tp = TransportParams::server_defaults();
        tp.original_destination_connection_id = Some(vec![0xde, 0xad, 0xbe, 0xef]);
        tp.initial_source_connection_id = Some(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let bytes = tp.encode();
        let back = TransportParams::decode(&bytes).unwrap();
        assert_eq!(back, tp);
    }

    #[test]
    fn accepts_and_clamps_max_flow_control_advertisement() {
        let unlimited = (1u64 << 62) - 1;
        let mut bytes = Vec::new();
        put_bytes(
            &mut bytes,
            id::INITIAL_SOURCE_CONNECTION_ID,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        );
        put_int(&mut bytes, id::INITIAL_MAX_DATA, unlimited);
        put_int(
            &mut bytes,
            id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            unlimited,
        );
        put_int(
            &mut bytes,
            id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            unlimited,
        );
        put_int(&mut bytes, id::INITIAL_MAX_STREAM_DATA_UNI, unlimited);

        let stream_max = 1u64 << 60;
        put_int(&mut bytes, id::INITIAL_MAX_STREAMS_BIDI, stream_max);
        put_int(&mut bytes, id::INITIAL_MAX_STREAMS_UNI, stream_max);

        let tp = TransportParams::decode(&bytes).expect("2^62-1 흐름제어 + 2^60 스트림 수용");

        assert_eq!(tp.initial_max_data, 1 << 40);
        assert_eq!(tp.initial_max_stream_data_bidi_local, 1 << 40);
        assert_eq!(tp.initial_max_stream_data_bidi_remote, 1 << 40);
        assert_eq!(tp.initial_max_stream_data_uni, 1 << 40);

        assert_eq!(tp.initial_max_streams_bidi, 1 << 20);
        assert_eq!(tp.initial_max_streams_uni, 1 << 20);

        let mut over = Vec::new();
        put_int(&mut over, id::INITIAL_MAX_STREAMS_BIDI, (1u64 << 60) + 1);
        assert!(
            TransportParams::decode(&over).is_none(),
            "2^60 초과 스트림 수는 프로토콜 위반이라 거부해야"
        );
    }

    #[test]
    fn unknown_params_ignored() {
        let mut tp = TransportParams::default();
        tp.initial_max_data = 12345;
        let mut bytes = tp.encode();

        varint::write(&mut bytes, 0x4242);
        varint::write(&mut bytes, 2);
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let back = TransportParams::decode(&bytes).unwrap();
        assert_eq!(back.initial_max_data, 12345);
    }

    #[test]
    fn disable_active_migration_flag() {
        let mut tp = TransportParams::default();
        tp.disable_active_migration = true;
        let back = TransportParams::decode(&tp.encode()).unwrap();
        assert!(back.disable_active_migration);

        let tp2 = TransportParams::default();
        let back2 = TransportParams::decode(&tp2.encode()).unwrap();
        assert!(!back2.disable_active_migration);
    }

    #[test]
    fn truncated_input_returns_none() {
        let tp = TransportParams::server_defaults();
        let bytes = tp.encode();

        assert!(TransportParams::decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn empty_is_defaults() {
        assert_eq!(
            TransportParams::decode(&[]).unwrap(),
            TransportParams::default()
        );
    }

    #[test]
    fn duplicate_and_noncanonical_integer_are_rejected() {
        let mut duplicate = Vec::new();
        put_int(&mut duplicate, id::INITIAL_MAX_DATA, 10);
        put_int(&mut duplicate, id::INITIAL_MAX_DATA, 20);
        assert!(TransportParams::decode(&duplicate).is_none());

        let mut trailing = Vec::new();
        varint::write(&mut trailing, id::INITIAL_MAX_DATA);
        varint::write(&mut trailing, 2);
        trailing.extend_from_slice(&[10, 0]);
        assert!(TransportParams::decode(&trailing).is_none());
    }

    #[test]
    fn transport_parameter_ranges_are_enforced() {
        let mut bad = Vec::new();
        put_int(&mut bad, id::MAX_UDP_PAYLOAD_SIZE, 1199);
        assert!(TransportParams::decode(&bad).is_none());

        let mut bad = Vec::new();
        put_int(&mut bad, id::ACK_DELAY_EXPONENT, 21);
        assert!(TransportParams::decode(&bad).is_none());

        let mut bad = Vec::new();
        varint::write(&mut bad, id::DISABLE_ACTIVE_MIGRATION);
        varint::write(&mut bad, 1);
        bad.push(1);
        assert!(TransportParams::decode(&bad).is_none());

        let mut bad = Vec::new();
        put_bytes(&mut bad, id::STATELESS_RESET_TOKEN, &[0; 15]);
        assert!(TransportParams::decode(&bad).is_none());

        let mut bad = Vec::new();
        put_int(&mut bad, id::ACTIVE_CONNECTION_ID_LIMIT, 1);
        assert!(TransportParams::decode(&bad).is_none());
    }

    #[test]
    /// RFC 9000 rejects only max_udp_payload_size below 1200 and active_connection_id_limit below
    /// 2; rejecting more would fail handshakes with conforming peers.
    fn large_values_the_rfc_allows_are_accepted() {
        let unlimited = (1u64 << 62) - 1;
        let mut bytes = Vec::new();
        put_int(&mut bytes, id::MAX_UDP_PAYLOAD_SIZE, unlimited);
        put_int(&mut bytes, id::ACTIVE_CONNECTION_ID_LIMIT, unlimited);
        let tp = TransportParams::decode(&bytes).expect("규격이 허용한 값을 거부했습니다");
        assert_eq!(tp.max_udp_payload_size, 65527);
        assert_eq!(tp.active_connection_id_limit, unlimited);
    }

    fn preferred_address(cid: Vec<u8>) -> PreferredAddress {
        PreferredAddress {
            ipv4: "192.0.2.1:853".parse().unwrap(),
            ipv6: "[2001:db8::1]:853".parse().unwrap(),
            cid,
            reset_token: [0x3c; 16],
        }
    }

    #[test]
    fn preferred_address_roundtrips() {
        let mut tp = TransportParams::server_defaults();
        tp.preferred_address = Some(preferred_address(vec![7; 8]));
        assert_eq!(TransportParams::decode(&tp.encode()).unwrap(), tp);
    }

    #[test]
    fn malformed_preferred_address_is_rejected() {
        let mut empty_cid = Vec::new();
        put_bytes(
            &mut empty_cid,
            id::PREFERRED_ADDRESS,
            &preferred_address(Vec::new()).encode(),
        );
        assert!(TransportParams::decode(&empty_cid).is_none());

        let mut value = preferred_address(vec![7; 8]).encode();
        value.push(0);
        let mut trailing = Vec::new();
        put_bytes(&mut trailing, id::PREFERRED_ADDRESS, &value);
        assert!(TransportParams::decode(&trailing).is_none());

        value.truncate(value.len() - 2);
        let mut short = Vec::new();
        put_bytes(&mut short, id::PREFERRED_ADDRESS, &value);
        assert!(TransportParams::decode(&short).is_none());
    }

    #[test]
    fn stateless_reset_token_roundtrips() {
        let mut tp = TransportParams::default();
        tp.stateless_reset_token = Some([0xa5; 16]);
        assert_eq!(
            TransportParams::decode(&tp.encode())
                .unwrap()
                .stateless_reset_token,
            Some([0xa5; 16])
        );
    }
}
