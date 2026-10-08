/*!
 * @brief QUIC 전송 매개변수.
 *
 * @details 핸드셰이크 중에 서로의 한계를 알린다. 흐름 제어 윈도우, 유휴 데드라인, 연결 식별자 같은 것들이다.
 * @warning 상대가 보내는 값은 신뢰 입력이다. 이쪽에 부담이 되는 값에는 상한을 걸고,
 *          같은 매개변수가 두 번 오거나 비정규 인코딩이면 거부한다.
 */

use std::collections::HashSet;

use crate::varint;

/** @brief 매개변수 번호들. 규격이 정한 값이다. */
pub mod id {
    /** @brief 클라이언트가 처음 쓴 목적지 식별자. Retry 검증에 쓴다. */
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    /** @brief 아무것도 오가지 않을 때 연결을 닫는 시간. */
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    /** @brief 상태 없는 재설정 토큰. */
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    /** @brief 받아들일 수 있는 데이터그램 크기. */
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    /** @brief 연결 전체의 초기 흐름 제어 윈도우. */
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    /** @brief 이쪽이 연 양방향 스트림의 초기 윈도우. */
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    /** @brief 상대가 연 양방향 스트림의 초기 윈도우. */
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    /** @brief 단방향 스트림의 초기 윈도우. */
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    /** @brief 열 수 있는 양방향 스트림 수. */
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    /** @brief 열 수 있는 단방향 스트림 수. */
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    /** @brief 확인 지연 값의 자릿수 이동 폭. */
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    /** @brief 확인을 미룰 수 있는 최대 시간. */
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    /** @brief 경로 이동을 막을지. 값 없는 표시다. */
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    /** @brief 동시에 살아 있을 수 있는 식별자 수. */
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    /** @brief 최초 출발지 식별자. 핸드셰이크 중 교체를 막는다. */
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    /** @brief Retry에 쓴 출발지 식별자. */
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    /** @brief 서버가 옮겨 가 달라고 알리는 주소와 그 주소에서 쓸 연결 식별자. */
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/**
 * @brief 서버가 알린 선호 주소.
 * @details 이쪽은 이 주소로 옮겨 가지 않는다. 그래도 여기 실린 식별자는 서버가 순번 1 로 준
 *          식별자라서, 상대가 준 식별자 수와 순번 충돌을 셀 때 들어간다.
 */
pub struct PreferredAddress {
    /** @brief IPv4 주소와 포트. 그 주소족을 쓰지 않으면 모두 0 이다. */
    pub ipv4: std::net::SocketAddrV4,
    /** @brief IPv6 주소와 포트. 그 주소족을 쓰지 않으면 모두 0 이다. */
    pub ipv6: std::net::SocketAddrV6,
    /** @brief 그 주소에서 쓸 연결 식별자. 길이는 1 에서 20 바이트다. */
    pub cid: Vec<u8>,
    /** @brief 그 식별자를 쓰는 동안 상태 없는 재설정을 알아볼 토큰. */
    pub reset_token: [u8; 16],
}

impl PreferredAddress {
    /** @brief 매개변수 값을 와이어 형태로 쓴다. */
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

    /**
     * @brief 매개변수 값을 읽는다.
     * @return 길이가 맞지 않거나 식별자 길이가 1 에서 20 바이트 밖이면 None. RFC 9000 은 길이
     *         0 식별자를 담은 선호 주소를 TRANSPORT_PARAMETER_ERROR 로 정한다.
     */
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
/** @brief 해석한 전송 매개변수. */
pub struct TransportParams {
    /** @brief 클라이언트가 처음 보낸 연결 식별자. 중간에서 바뀌지 않았는지 본다. */
    pub original_destination_connection_id: Option<Vec<u8>>,
    /** @brief 이 핸드셰이크에서 보내는 쪽 연결 식별자. */
    pub initial_source_connection_id: Option<Vec<u8>>,
    /** @brief 재시도할 때 쓴 연결 식별자. */
    pub retry_source_connection_id: Option<Vec<u8>>,
    /** @brief 상태 없이 연결을 끊을 때 쓸 토큰. */
    pub stateless_reset_token: Option<[u8; 16]>,
    /** @brief 아무것도 오가지 않을 때 끊는 시간. */
    pub max_idle_timeout: u64,
    /** @brief 받아들일 데이터그램 크기. */
    pub max_udp_payload_size: u64,
    /** @brief 전체로 허락하는 양. */
    pub initial_max_data: u64,
    /** @brief 이쪽이 연 양방향 스트림에 허락하는 양. */
    pub initial_max_stream_data_bidi_local: u64,
    /** @brief 상대가 연 양방향 스트림에 허락하는 양. */
    pub initial_max_stream_data_bidi_remote: u64,
    /** @brief 단방향 스트림에 허락하는 양. */
    pub initial_max_stream_data_uni: u64,
    /** @brief 허락하는 양방향 스트림 수. */
    pub initial_max_streams_bidi: u64,
    /** @brief 허락하는 단방향 스트림 수. */
    pub initial_max_streams_uni: u64,
    /** @brief 받았다고 알릴 때 시간을 줄여 적는 자릿수. */
    pub ack_delay_exponent: u64,
    /** @brief 받았다고 알리기까지 미룰 수 있는 시간. */
    pub max_ack_delay: u64,
    /** @brief 동시에 잡을 수 있는 연결 식별자 수. */
    pub active_connection_id_limit: u64,
    /** @brief 경로를 옮기지 못하게 할지. */
    pub disable_active_migration: bool,
    /** @brief 서버가 알린 선호 주소. 서버만 보낼 수 있다. */
    pub preferred_address: Option<PreferredAddress>,
}

impl Default for TransportParams {
    /** @brief 규격이 정한 기본값. 상대가 보내지 않은 매개변수에 쓴다. */
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

/** @brief 정수 매개변수를 쓴다. */
fn put_int(out: &mut Vec<u8>, pid: u64, value: u64) {
    varint::write(out, pid);
    varint::write(out, varint::len(value) as u64);
    varint::write(out, value);
}

/** @brief 바이트열 매개변수를 쓴다. */
fn put_bytes(out: &mut Vec<u8>, pid: u64, value: &[u8]) {
    varint::write(out, pid);
    varint::write(out, value.len() as u64);
    out.extend_from_slice(value);
}

impl TransportParams {
    /** @brief 서버로서 알릴 기본값. */
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

    /** @brief 매개변수를 와이어 형태로 쓴다. */
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

    /**
     * @brief 상대의 매개변수를 읽는다.
     * @warning 같은 매개변수가 두 번 오면 거부한다. 어느 값을 쓸지 정해지지 않고, 구현마다
     *          다르게 고르면 그 차이를 노릴 수 있다. 비정규 정수 인코딩도 같은 이유로 거부한다.
     * @return 형식이 어긋나거나 값이 허용 범위 밖이면 None.
     */
    pub fn decode(buf: &[u8]) -> Option<TransportParams> {
        /** @brief 연결 식별자 길이 상한. */
        const MAX_CID_LEN: usize = 20;
        /** @brief 이쪽이 열어 줄 스트림 수 상한. */
        const MAX_STREAMS: u64 = 1 << 20;
        /** @brief 흐름 제어로 허락할 바이트 상한. */
        const MAX_FLOW_CREDIT: u64 = 1 << 40;

        /** @brief 상대가 요구할 수 있는 스트림 수 상한. */
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
                    /*
                     * RFC 9000 은 1200 미만만 잘못된 값으로 정한다. 그보다 큰 값은 UDP 가 담을 수
                     * 있는 65527 로 자른다.
                     */
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
                    /*
                     * RFC 9000 은 2 미만만 잘못된 값으로 정한다. 이쪽은 핸드셰이크에서 정한
                     * 식별자 하나만 주므로 상대가 받겠다는 수가 크다고 부담이 늘지 않는다.
                     */
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
/** @brief 왕복, 상한 적용, 그리고 중복과 비정규 인코딩 거부. */
mod tests {
    use super::*;

    #[test]
    /** @brief 서버 기본값이 왕복에서 보존되는지. */
    fn roundtrip_server_defaults() {
        let mut tp = TransportParams::server_defaults();
        tp.original_destination_connection_id = Some(vec![0xde, 0xad, 0xbe, 0xef]);
        tp.initial_source_connection_id = Some(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let bytes = tp.encode();
        let back = TransportParams::decode(&bytes).unwrap();
        assert_eq!(back, tp);
    }

    #[test]
    /** @brief 큰 흐름 제어 값을 받아들이되 이쪽 상한으로 자르는지. */
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
    /** @brief 모르는 매개변수를 무시하고 넘어가는지. 앞으로 늘어날 수 있다. */
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
    /** @brief 값 없는 표시 매개변수가 제대로 읽히는지. */
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
    /** @brief 잘린 입력을 거부하는지. */
    fn truncated_input_returns_none() {
        let tp = TransportParams::server_defaults();
        let bytes = tp.encode();

        assert!(TransportParams::decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    /** @brief 빈 입력이 기본값으로 해석되는지. */
    fn empty_is_defaults() {
        assert_eq!(
            TransportParams::decode(&[]).unwrap(),
            TransportParams::default()
        );
    }

    #[test]
    /** @brief 중복 매개변수와 비정규 정수를 거부하는지. */
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
    /** @brief 허용 범위를 벗어난 값을 거부하는지. */
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
    /**
     * @brief 규격이 막지 않은 큰 값을 받아들이는지.
     * @details RFC 9000 은 max_udp_payload_size 의 1200 미만과 active_connection_id_limit 의 2
     *          미만만 잘못된 값으로 정한다. 그 위를 거부하면 규격을 지킨 상대와 핸드셰이크를
     *          끝내지 못한다.
     */
    fn large_values_the_rfc_allows_are_accepted() {
        let unlimited = (1u64 << 62) - 1;
        let mut bytes = Vec::new();
        put_int(&mut bytes, id::MAX_UDP_PAYLOAD_SIZE, unlimited);
        put_int(&mut bytes, id::ACTIVE_CONNECTION_ID_LIMIT, unlimited);
        let tp = TransportParams::decode(&bytes).expect("규격이 허용한 값을 거부했습니다");
        assert_eq!(tp.max_udp_payload_size, 65527);
        assert_eq!(tp.active_connection_id_limit, unlimited);
    }

    /** @brief 테스트용 선호 주소. */
    fn preferred_address(cid: Vec<u8>) -> PreferredAddress {
        PreferredAddress {
            ipv4: "192.0.2.1:853".parse().unwrap(),
            ipv6: "[2001:db8::1]:853".parse().unwrap(),
            cid,
            reset_token: [0x3c; 16],
        }
    }

    #[test]
    /** @brief 선호 주소가 식별자와 토큰까지 보존하며 왕복하는지. */
    fn preferred_address_roundtrips() {
        let mut tp = TransportParams::server_defaults();
        tp.preferred_address = Some(preferred_address(vec![7; 8]));
        assert_eq!(TransportParams::decode(&tp.encode()).unwrap(), tp);
    }

    #[test]
    /**
     * @brief 길이 0 식별자를 담았거나 길이가 맞지 않는 선호 주소를 거부하는지.
     * @details RFC 9000 은 길이 0 식별자를 담은 선호 주소를 TRANSPORT_PARAMETER_ERROR 로 정한다.
     */
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
    /** @brief 재설정 토큰이 왕복에서 보존되는지. */
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
