/*!
 * @brief TSIG: 대칭키로 DNS 트랜잭션 자체를 인증한다.
 *
 * @details DNSSEC이 데이터의 진위를 보증한다면 TSIG는 메시지를 주고받는 두 당사자를
 *          묶는다. zone 전송과 NOTIFY, 동적 갱신처럼 상대를 특정해야 하는 경로에 쓴다.
 *          응답의 MAC은 요청의 MAC을 재료로 삼아 체인을 이루므로, 응답만 떼어 재생할 수 없다.
 * @warning MAC 비교는 반드시 상수 시간이어야 한다. 앞에서부터 다른 곳에서 멈추면 옳은
 *          MAC을 한 바이트씩 알아낼 수 있다.
 */

use std::borrow::Cow;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use onetdns_proto::wire::MAX_DNS_WIRE_LEN;
use onetdns_proto::{DnsClass, Message, Name, ProtoError, RData, Record, RecordType, Writer};

/** @brief TSIG RR 타입 번호. */
pub const TSIG_TYPE: u16 = 250;

/** @brief 이 서버가 지원하는 유일한 알고리즘. 약한 알고리즘은 아예 받지 않는다. */
pub const ALG_HMAC_SHA256: &str = "hmac-sha256";

/** @brief MAC이 맞지 않는다. */
pub const TSIG_ERROR_BADSIG: u16 = 16;

/** @brief 모르는 키 이름이다. */
pub const TSIG_ERROR_BADKEY: u16 = 17;

/** @brief 서명 시각이 허용 구간을 벗어났다. */
pub const TSIG_ERROR_BADTIME: u16 = 18;

/**
 * @brief 이 서버가 받아들일 fudge 상한.
 * @details fudge는 상대가 정하는 값이라 그대로 믿으면 재생 구간을 무한정 늘릴 수 있다.
 *          MAC 검증은 통과시키되 시각 판정에서 이 상한을 적용한다.
 */
const MAX_FUDGE_SECONDS: u16 = 300;

/** @brief 알고리즘 이름의 와이어 형태. MAC 계산 입력에 그대로 들어간다. */
const ALG_HMAC_SHA256_WIRE: &[u8] = b"\x0bhmac-sha256\0";

/** @brief TSIG 키 하나: 이름과 비밀값. */
#[derive(Clone)]
pub struct TsigKey {
    /** @brief 키 이름. 상대가 어느 키로 서명했는지 알리는 식별자다. */
    pub name: Name,
    /** @brief HMAC 비밀값. 복제해도 바이트 사본은 늘지 않고 마지막 소유자가 지운다. */
    secret: Arc<Zeroizing<Vec<u8>>>,
}

impl TsigKey {
    /** @brief 비밀값 최소 길이. 이보다 짧으면 전수 탐색이 현실적인 범위로 들어온다. */
    pub const MIN_SECRET_BYTES: usize = 16;

    /** @brief 키를 만든다. 비밀값이 최소 길이에 못 미치면 만들지 않는다. */
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

    /** @brief 설정 파일에 흔한 base64 형태에서 키를 만든다. */
    pub fn from_base64(name: &str, secret_b64: &str) -> Option<TsigKey> {
        Self::new(Name::from_str(name).ok()?, b64_decode(secret_b64)?)
    }
}

/** @brief TSIG 검증 실패 사유. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsigError {
    /** @brief TSIG 레코드가 아예 없다. */
    Missing,

    /** @brief 키 이름이 이 서버가 아는 것과 다르다. */
    BadKey,

    /** @brief MAC이 맞지 않는다. */
    BadSig,

    /** @brief 서명 시각이 허용 구간 밖이다. */
    BadTime,

    /** @brief 알고리즘이 hmac-sha256이 아니다. */
    BadAlg,

    /** @brief TSIG 레코드의 위치나 형식이 규격에 맞지 않는다. */
    InvalidMessage,
}

/** @brief 파싱한 TSIG 레코드의 내용. 검증 전 상태다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecordData {
    /** @brief 상대가 주장하는 키 이름. */
    key_name: Name,
    /** @brief 알고리즘 이름. */
    algorithm: Name,
    /** @brief 상대가 서명한 시각. */
    time_signed: u64,
    /** @brief 상대가 허용하겠다고 밝힌 시각 오차. */
    fudge: u16,
    /** @brief MAC. */
    mac: Vec<u8>,
    /** @brief 원래 트랜잭션 ID. 중계로 ID가 바뀌어도 MAC이 유지되게 한다. */
    original_id: u16,
    /** @brief TSIG 오류 코드. 0이 아니면 상대가 검증 실패를 알리는 것이다. */
    error: u16,
    /** @brief BADTIME일 때 상대의 시각이 들어가는 부가 데이터. */
    other: Vec<u8>,
}

impl TsigRecordData {
    /** @brief 키 이름. */
    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    /** @brief 알고리즘 이름. */
    pub fn algorithm(&self) -> &Name {
        &self.algorithm
    }

    /** @brief 서명 시각. */
    pub fn time_signed(&self) -> u64 {
        self.time_signed
    }

    /** @brief 상대가 밝힌 허용 오차. */
    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    /** @brief MAC. */
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /** @brief 원래 트랜잭션 ID. */
    pub fn original_id(&self) -> u16 {
        self.original_id
    }

    /** @brief TSIG 오류 코드. */
    pub fn error(&self) -> u16 {
        self.error
    }

    /** @brief 부가 데이터. */
    pub fn other(&self) -> &[u8] {
        &self.other
    }
}

/**
 * @brief MAC 검증을 통과한 TSIG. 검증 전 데이터와 타입으로 구분한다.
 * @details 검증 여부를 불리언으로 계속 가지고 있으면 확인을 빠뜨린 경로가 생긴다. 타입이 다르면
 *          그런 실수가 컴파일에서 막힌다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTsig(TsigRecordData);

impl VerifiedTsig {
    /** @brief 이 메시지의 MAC. 응답 서명에 체인 재료로 들어간다. */
    pub fn mac(&self) -> &[u8] {
        self.0.mac()
    }

    /** @brief 재생 방지 구간의 끝. 호출자는 이 시각까지 같은 MAC을 거부해야 한다. */
    pub fn valid_until(&self) -> u64 {
        self.0.time_signed.saturating_add(u64::from(self.0.fudge))
    }
}

/**
 * @brief 와이어 검증 결과.
 * @details BADTIME도 MAC은 맞은 것이다. 그래서 응답을 서명해 돌려줄 수 있고, 상대는
 *          그 응답에서 이 서버의 시각을 알아 다시 맞출 수 있다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireVerification {
    /** @brief MAC과 시각이 모두 맞다. */
    Valid {
        /** @brief TSIG를 떼어 낸 와이어. 이후 처리는 이것을 쓴다. */
        stripped: Vec<u8>,
        /** @brief 검증된 TSIG. */
        tsig: VerifiedTsig,
    },
    /** @brief MAC은 맞으나 시각이 구간 밖이다. */
    BadTime {
        /** @brief TSIG를 떼어 낸 와이어. */
        stripped: Vec<u8>,
        /** @brief 검증된 TSIG. 응답 서명에 필요하다. */
        tsig: VerifiedTsig,
    },
}

/**
 * @brief 서명 없이 돌려보내야 하는 오류.
 * @details 키를 모르거나 MAC이 틀리면 공유 비밀이 없다는 뜻이라 응답에 MAC을 붙일 수 없다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsignedTsigError {
    /** @brief MAC 불일치. */
    BadSig,
    /** @brief 모르는 키. */
    BadKey,
}

impl UnsignedTsigError {
    /** @brief TSIG RDATA에 담을 오류 코드. */
    fn code(self) -> u16 {
        match self {
            Self::BadSig => TSIG_ERROR_BADSIG,
            Self::BadKey => TSIG_ERROR_BADKEY,
        }
    }
}

/** @brief TSIG RDATA를 푼 내부 형태. 키 이름은 레코드 소유자라 따로 가지고 있다. */
struct TsigData {
    /** @brief 알고리즘 이름. */
    algorithm: Name,
    /** @brief 서명 시각. */
    time_signed: u64,
    /** @brief 허용 오차. */
    fudge: u16,
    /** @brief MAC. */
    mac: Vec<u8>,
    /** @brief 원래 트랜잭션 ID. */
    original_id: u16,
    /** @brief 오류 코드. */
    error: u16,
    /** @brief 부가 데이터. */
    other: Vec<u8>,
}

/**
 * @brief 메시지에 TSIG를 붙여 서명한다.
 * @param request_mac 응답을 서명할 때 요청의 MAC. 이것이 체인을 만든다.
 * @return 이 메시지의 MAC. 후속 메시지 서명에 이어 쓴다.
 */
pub fn sign_message(
    msg: &mut Message,
    key: &TsigKey,
    now: u64,
    request_mac: Option<&[u8]>,
) -> Result<Vec<u8>, ProtoError> {
    let original_id = msg.header.id;
    sign_message_fields(msg, key, now, 300, 0, &[], request_mac, original_id)
}

/**
 * @brief 검증된 요청에 대한 응답을 서명한다.
 * @details 요청의 original_id를 그대로 쓴다. 중계가 ID를 바꿔도 상대는 자기가 보낸 ID로
 *          MAC을 계산하기 때문이다.
 */
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

/**
 * @brief BADTIME 응답을 서명한다.
 * @details 부가 데이터에 이 서버의 시각을 담고, 서명 시각과 fudge는 요청 것을 그대로 쓴다.
 *          상대의 구간 안에 들어가야 이 응답의 MAC이 검증되고, 그래야 시각을 맞출 수 있다.
 */
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

/**
 * @brief MAC 없는 오류 TSIG를 응답에 붙인다.
 * @details 키를 모르거나 MAC이 틀린 경우다. 공유 비밀이 없으니 MAC을 만들 수 없고, 빈
 *          MAC으로 상대에게 사유만 알린다. 상대가 요청에 쓴 값들을 되비춰야 어느 요청에
 *          대한 답인지 짝지을 수 있다.
 */
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

/**
 * @brief 다중 엔벨로프 전송의 두 번째 이후 메시지를 서명한다.
 * @details 첫 메시지와 달리 MAC 계산에 앞 메시지의 MAC과 타이머만 들어간다. 이 체인이
 *          엔벨로프 순서를 고정해, 중간 엔벨로프를 빼거나 순서를 바꾸는 것을 막는다.
 */
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

/** @brief 응답 쪽 다중 엔벨로프 후속 메시지를 서명한다. ID는 요청의 original_id로 되돌린다. */
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

/**
 * @brief 이미 인코딩된 와이어에 TSIG를 이어 붙인다.
 * @details 메시지를 다시 만들지 않는 경로용이다. 재인코딩하면 이름 압축이 달라져 상대가
 *          계산한 MAC과 어긋날 수 있다.
 */
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

/** @brief 와이어 형태의 응답을 서명한다. MAC 계산 전에만 ID를 요청 것으로 바꿔 놓는다. */
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

/** @brief 와이어 형태의 다중 엔벨로프 후속 메시지를 서명한다. */
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

/** @brief 와이어 형태 응답의 다중 엔벨로프 후속 메시지를 서명한다. */
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

/**
 * @brief 다중 엔벨로프 후속 메시지의 TSIG를 검증한다.
 *
 * @details 와이어를 다시 파싱해 인코딩하지 않고 TSIG 앞부분을 그대로 잘라 쓴다. 재인코딩은
 *          이름 압축을 바꿔 MAC을 어긋나게 한다. 자른 뒤 ID를 original_id로 되돌리고
 *          additional 수를 하나 줄여야 상대가 서명한 바이트와 같아진다.
 * @return TSIG를 뗀 와이어와 이 메시지의 MAC. 다음 엔벨로프 검증에 이어 쓴다.
 */
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

/**
 * @brief 파싱된 메시지의 TSIG를 검증한다.
 *
 * @details 순서를 지킨다. 클래스와 TTL, 키 이름, 알고리즘, RDATA 정합성을 먼저 보고
 *          MAC을 계산해 상수 시간으로 비교한다. 시각 판정은 MAC이 맞은 뒤에야 한다.
 *          MAC도 모르는 상대에게 이 서버의 시각 상태를 알려 줄 이유가 없다.
 * @return TSIG를 떼고 ID를 되돌린 메시지와 MAC.
 */
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

/** @brief 와이어 TSIG를 검증하고 시각까지 맞아야 성공으로 본다. BADTIME은 오류로 바꾼다. */
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

/**
 * @brief 와이어 TSIG를 검증하고 시각 불일치를 따로 알려 준다.
 *
 * @details MAC이 맞고 시각만 어긋난 경우를 BADTIME으로 구분해 돌려준다. 그래야 서명된
 *          BADTIME 응답으로 이 서버의 시각을 알려 상대가 맞출 수 있다. 오류로 바꿔 버리면
 *          시계가 어긋난 상대는 영영 복구하지 못한다.
 * @return TSIG를 뗀 와이어와 검증된 TSIG. 키·알고리즘·형식이 틀리면 오류.
 */
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

/** @brief 검증하지 않고 키 이름만 본다. 어느 키로 검증할지 고르는 데 쓴다. */
pub fn peek_key_name(msg: &Message) -> Option<Name> {
    find_tsig(msg).map(|(_, r)| r.name.clone())
}

/**
 * @brief 메시지 어디에든 TSIG가 있는지.
 * @note 규격상 있어야 할 위치가 아닌 곳까지 본다. 잘못 놓인 TSIG를 없는 것으로 취급하면
 *       서명된 메시지를 서명되지 않은 것처럼 흘려보낼 수 있다.
 */
pub fn contains_tsig(msg: &Message) -> bool {
    msg.answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
        .any(|record| record.rtype.0 == TSIG_TYPE)
}

/** @brief 요청에서 TSIG 내용을 꺼낸다. 검증은 하지 않는다. */
pub fn request_data(msg: &Message) -> Result<TsigRecordData, TsigError> {
    message_tsig_data(msg, false)
}

/** @brief 응답에서 TSIG 내용을 꺼낸다. 검증은 하지 않는다. */
pub fn response_data(msg: &Message) -> Result<TsigRecordData, TsigError> {
    message_tsig_data(msg, true)
}

/**
 * @brief TSIG 내용을 꺼내며 형식과 방향까지 확인한다.
 * @param response 응답이어야 하는지. QR 비트가 기대와 다르면 거부한다. 요청을 응답으로
 *                 되비추는 반사 공격을 막는다.
 */
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

/** @brief 내부 형태에 소유자 이름을 합쳐 공개 형태로 만든다. */
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

/**
 * @brief 규격에 맞게 놓인 TSIG를 찾는다.
 * @details 답변이나 권한 절에 있으면 없는 것으로 본다. additional에도 정확히 하나,
 *          그것도 마지막이어야 한다. 위치가 자유로우면 MAC 계산 범위가 흔들려, 서명된
 *          부분과 서명되지 않은 부분을 공격자가 고를 수 있게 된다.
 */
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

/**
 * @brief TSIG RDATA를 푼다.
 * @details 길이 검사를 모든 필드마다 한다. 마지막에 남은 바이트가 있어도 거부한다.
 *          뒤에 남는 바이트를 허용하면 같은 TSIG를 여러 바이트열로 표현할 수 있고, 그 차이가
 *          MAC 계산 범위 밖이라 조작 여지가 된다.
 */
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

/**
 * @brief TSIG 필드가 방향에 맞는 값인지 본다.
 * @details 요청에는 오류 코드가 있을 수 없다. 응답의 부가 데이터는 BADTIME일 때만, 그것도
 *          시각 6바이트만 허용한다. 자유롭게 두면 MAC에 들어가는 이 필드로 임의 바이트를
 *          흘려보낼 수 있다.
 */
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

/**
 * @brief MAC 길이가 hmac-sha256에 허용된 범위인지 본다.
 * @details 절반인 16바이트까지만 잘라 쓸 수 있고 32바이트를 넘을 수 없다. 상한이 없으면
 *          더 긴 MAC을 보내 비교 비용을 늘릴 수 있고, 하한이 없으면 짧게 잘라 맞히기가
 *          쉬워진다.
 * @note 응답의 BADSIG·BADKEY는 예외로 빈 MAC을 허용한다. 그 경우 서명할 비밀이 없다.
 */
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

/**
 * @brief 모든 TSIG 필드를 지정해 메시지를 서명한다. 나머지 서명 함수의 공통 몸통이다.
 * @note MAC은 original_id로 되돌린 와이어에 대해 계산한다. 레코드에 담기는 ID도 같은
 *       값이어야 상대가 같은 바이트를 재구성할 수 있다.
 */
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

/** @brief 오류 없이 부가 데이터도 없는 보통의 TSIG 레코드를 만든다. */
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

/**
 * @brief 모든 필드를 지정해 TSIG 레코드를 만든다.
 * @note 클래스는 ANY(255), TTL은 0으로 고정이다. 검증 쪽이 이 두 값을 확인하므로 다르게
 *       쓰면 이 서버의 메시지를 상대가 받지 않는다.
 */
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

/**
 * @brief 인코딩된 와이어 뒤에 TSIG 레코드를 직접 이어 붙인다.
 * @details 붙이기 전에 필요한 길이를 미리 측정해서 상한을 넘는지 본다. 넘긴 뒤에 되돌리면
 *          헤더의 additional 수만 늘어난 깨진 메시지가 남는다.
 * @note 소유자 이름은 압축하지 않는다. MAC 계산 입력이 압축되지 않은 형태이기 때문이다.
 */
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

/**
 * @brief MAC 계산용으로 트랜잭션 ID만 original_id로 바꾼 와이어.
 * @note 이미 같으면 복사하지 않는다. 응답마다 전체 복사가 붙는 것을 피한다.
 */
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

/**
 * @brief 첫 메시지의 MAC을 계산한다.
 *
 * @details 입력 순서는 요청 MAC, 메시지 와이어, 그리고 TSIG 변수들이다. 요청 MAC을 길이와
 *          함께 앞에 넣는 것이 응답을 요청에 묶는 체인이다. 길이 없이 이어 붙이면 경계가
 *          모호해져 서로 다른 조합이 같은 입력을 만들 수 있다.
 * @note 변수 부분에는 MAC 자체가 들어가지 않는다. 자기 자신을 재료로 쓸 수 없기 때문이다.
 */
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

/**
 * @brief 다중 엔벨로프 후속 메시지의 MAC을 계산한다.
 * @details 첫 메시지와 달리 변수는 시각과 fudge만 들어간다. 키 이름·클래스·알고리즘은
 *          첫 엔벨로프에서 이미 고정됐다.
 */
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

/** @brief 이름을 소문자 비압축 형태로 이어 붙인다. MAC 입력의 정규형이다. */
fn push_canonical_name(out: &mut Vec<u8>, name: &Name) {
    for label in name.labels() {
        out.push(label.len() as u8);
        out.extend(label.iter().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
}

/** @brief 같은 일을 Writer에 한다. 압축 테이블에 넣지 않으려고 Writer의 이름 쓰기를 쓰지 않는다. */
fn push_canonical_name_writer(out: &mut Writer, name: &Name) {
    for label in name.labels() {
        out.push_u8(label.len() as u8);
        for byte in label {
            out.push_u8(byte.to_ascii_lowercase());
        }
    }
    out.push_u8(0);
}

/** @brief 시각을 48비트 빅엔디언으로. TSIG는 32비트가 아니라 48비트를 쓴다. */
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

/**
 * @brief 상수 시간 비교.
 * @warning 조기 반환을 넣지 마라. 다른 위치에서 멈추는 순간 걸린 시간으로 옳은 MAC을
 *          한 바이트씩 알아낼 수 있다. 길이 비교는 비밀이 아니라 괜찮다.
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

/**
 * @brief 받은 MAC이 기대값의 앞부분과 일치하는지.
 * @details 잘라 쓴 MAC을 받아들이되, 빈 MAC과 기대값보다 긴 MAC은 거부한다. 빈 MAC을
 *          허용하면 아무 메시지나 통과한다. 길이 하한은 앞서 확인해 둔다.
 */
fn mac_matches(expected: &[u8], received: &[u8]) -> bool {
    !received.is_empty()
        && received.len() <= expected.len()
        && ct_eq(&expected[..received.len()], received)
}

/**
 * @brief RDATA 안의 비압축 이름을 읽는다.
 * @details 압축 포인터를 만나면 실패로 본다. RDATA는 메시지 안에서 곳을 옮길 수 있어,
 *          안에 든 포인터가 엉뚱한 곳을 가리키게 된다.
 * @return 이름과 그 다음 오프셋.
 */
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

/** @brief 길이 접두 라벨열을 이름으로 바꾼다. 라벨이 없으면 루트다. */
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

/**
 * @brief 와이어를 훑어 마지막 레코드가 TSIG인지 확인하고 그 위치와 내용을 꺼낸다.
 *
 * @details 메시지 전체를 파싱하지 않고 레코드 경계만 건너뛴다. 파싱 후 재인코딩하면
 *          이름 압축이 달라져 MAC이 어긋난다.
 * @warning 앞쪽 레코드 중 하나라도 TSIG면 실패로 본다. TSIG가 둘이면 어느 것이 서명
 *          범위를 정하는지 모호해져 서명되지 않은 부분을 끼워 넣을 수 있다. RDATA가
 *          메시지 끝에서 정확히 끝나지 않는 것도 같은 이유로 거부한다.
 * @return TSIG 시작 오프셋, 소유자 이름, 클래스, TTL, RDATA.
 */
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

/**
 * @brief 레코드 소유자 이름을 읽는다. 여기서는 압축 포인터를 따라간다.
 * @note 포인터는 뒤쪽만 가리킬 수 있고 따라가는 횟수도 제한한다. 두 조건이 함께 있어야
 *       순환과 긴 체인을 모두 막는다.
 */
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

/** @brief 이름을 건너뛰고 그 다음 오프셋을 준다. 포인터는 2바이트로 끝난다. */
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

/** @brief 레코드 하나를 건너뛴다. 이름 뒤 고정 10바이트와 RDATA 길이를 더한다. */
fn skip_record(wire: &[u8], i: usize) -> Option<usize> {
    let i = skip_name(wire, i)?;
    let rdlen = u16::from_be_bytes([*wire.get(i + 8)?, *wire.get(i + 9)?]) as usize;
    Some(i + 10 + rdlen)
}

/**
 * @brief base64 인코딩. 설정 파일과 앵커 상태 저장에 쓴다.
 * @note 패딩을 붙인다. 표준 형식이라 다른 도구가 만든 값과 오갈 수 있어야 한다.
 */
pub fn b64_encode(data: &[u8]) -> String {
    /** @brief 표준 base64 알파벳. */
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

/**
 * @brief base64 디코딩. 공백은 무시하고 패딩에서 멈춘다.
 * @return 알파벳 밖 문자가 있거나 남은 문자가 1개면 None. 1개로는 옥텟을 만들 수 없다.
 */
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
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

/** @brief 서명·검증 왕복과 조작 거부: MAC 체인, 시각 구간, 형식 malleability. */
#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::{Header, Question};

    /** @brief 테스트용 고정 키. */
    fn key() -> TsigKey {
        TsigKey::new(
            Name::from_str("transfer-key").unwrap(),
            b"super-secret-bytes-32-chars-xxxx".to_vec(),
        )
        .unwrap()
    }

    #[test]
    /** @brief 워커용 키 복제가 비밀 바이트를 복제하지 않는지. */
    fn cloned_key_shares_one_zeroizing_secret() {
        let original = key();
        let cloned = original.clone();
        assert!(Arc::ptr_eq(&original.secret, &cloned.secret));
    }

    /** @brief AXFR 질의. TSIG가 실제로 쓰이는 대표 경로다. */
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

    /** @brief 메시지 경로와 와이어 경로가 서로의 서명을 검증하는지. 두 경로가 같은 MAC을 만들어야 한다. */
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

    /** @brief 다른 키나 구간 밖 시각은 통과하지 못한다. */
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

    /** @brief 잘라 쓴 MAC의 허용 범위: 너무 짧으면 맞히기 쉽고, 빈 것은 아무나 통과한다. */
    #[test]
    fn hmac_sha256_truncation_follows_rfc_8945_bounds() {
        /** @brief 서명을 이 길이로 자른다. */
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

    /** @brief 재생 방지 구간의 끝이 서명 시각에 fudge를 더한 값인지. 호출자가 이 값으로 중복을 막는다. */
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

    /**
     * @brief 상대가 큰 fudge를 불러도 이 서버의 상한이 적용된다.
     * @details 다만 MAC 검증을 먼저 통과해야 BADTIME이 나온다. 순서가 뒤집히면 MAC도
     *          모르는 상대에게 이 서버의 시각 상태를 알려 주게 된다.
     */
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

    /** @brief 클래스·TTL·위치·RDATA 뒷부분 등 MAC 밖 필드를 흔들어도 통과하지 못한다. */
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

    /** @brief 응답 MAC이 요청 MAC에 묶여 있는지. 응답만 떼어 재생하지 못하게 하는 성질이다. */
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

    /** @brief 중계로 ID가 바뀌어도 응답이 요청의 original_id를 쓰는지. 그래야 상대가 검증한다. */
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

    /** @brief base64 왕복. 키를 잘못 읽으면 서명이 전부 어긋난다. */
    #[test]
    fn b64_roundtrip() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("aGVsbG8h").unwrap(), b"hello!");
        assert!(b64_decode("!!!").is_none());
    }

    /** @brief 다중 엔벨로프 체인: 엔벨로프 순서와 연속성이 MAC으로 고정되는지. */
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
