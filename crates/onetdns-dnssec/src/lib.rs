/*!
 * @brief DNSSEC 검증과 온라인 서명.
 *
 * @details 신뢰 체인은 루트 앵커에서 시작해 DS→DNSKEY→RRSIG 순으로 내려간다. 각 단계에서
 *          위조를 막는 검사가 있으며, 하나라도 건너뛰면 체인 전체가 무의미해진다.
 * @warning 검증 비용은 공격 표면이다. 악의적인 zone이 질의 하나에 막대한 공개키 연산을
 *          강제할 수 있으므로(KeyTrap 계열), 연산 횟수와 반복 횟수에 상한이 걸려 있다.
 */

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use onetdns_proto::{Name, RData, Reader, Record, RecordType};

/** @brief P-256 서명 검증 전용 고속 경로. 검증 횟수가 곧 CPU 예산이라 따로 둔다. */
mod p256fast;
/** @brief TSIG: 대칭키로 트랜잭션 자체를 인증한다. DNSSEC 체인과는 별개 축이다. */
pub mod tsig;

/** @brief 온라인 zone 서명. */
pub mod sign;

/** @brief 신뢰 앵커 관리(RFC 5011 롤오버 포함). */
pub mod anchor;

/** @brief DNSSEC 검증 실패 사유. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecError {
    /** @brief 이 서버가 다루지 않는 알고리즘·다이제스트. bogus가 아니라 "판단 불가"다. */
    Unsupported(u8),

    /** @brief 공개키 바이트가 그 알고리즘의 형식에 맞지 않는다. */
    BadKey,

    /** @brief 서명이 검증되지 않았거나, 검증 예산을 다 썼다. 둘 다 fail-closed다. */
    BadSignature,

    /** @brief DS 다이제스트가 DNSKEY에서 계산한 값과 다르다. */
    BadDigest,

    /** @brief 입력 자체가 비정상: 빈 RRset, 소유자 불일치 등. */
    Invalid,
}

impl std::fmt::Display for DnssecError {
    /** @brief 사람이 읽을 실패 사유. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnssecError::Unsupported(a) => write!(f, "Unsupported algorithm or digest: {a}"),
            DnssecError::BadKey => write!(f, "Malformed public key"),
            DnssecError::BadSignature => write!(f, "Signature verification failed"),
            DnssecError::BadDigest => write!(f, "DS digest does not match"),
            DnssecError::Invalid => write!(f, "Invalid verification input"),
        }
    }
}

impl std::error::Error for DnssecError {}

/** @brief DNSKEY 레코드. zone의 공개키다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnskey {
    /** @brief 비트 7이 zone key, 비트 15가 SEP, 비트 8이 revoke다. */
    pub flags: u16,
    /** @brief 3이 아니면 DNSSEC 키가 아니다. 다른 값은 쓰지 않는다. */
    pub protocol: u8,
    /** @brief 서명 알고리즘 번호. RRSIG의 것과 일치해야 후보가 된다. */
    pub algorithm: u8,
    /** @brief 알고리즘별 공개키 바이트. 형식 검사는 검증 시점에 한다. */
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /** @brief DNSKEY RDATA를 해석한다. */
    pub fn parse(raw: &[u8]) -> Option<Dnskey> {
        let mut r = Reader::new(raw);
        let flags = r.u16().ok()?;
        let protocol = r.u8().ok()?;
        let algorithm = r.u8().ok()?;
        Some(Dnskey {
            flags,
            protocol,
            algorithm,
            public_key: raw.get(r.pos..)?.to_vec(),
        })
    }

    /** @brief 레코드에서 DNSKEY를 꺼낸다. 타입이 다르면 None. */
    pub fn from_record(rec: &Record) -> Option<Dnskey> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Dnskey::parse(raw),
            _ => None,
        }
    }

    /** @brief DNSKEY를 다시 RDATA 바이트로 만든다. DS 다이제스트 계산에 쓴다. */
    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.public_key.len());
        v.extend_from_slice(&self.flags.to_be_bytes());
        v.push(self.protocol);
        v.push(self.algorithm);
        v.extend_from_slice(&self.public_key);
        v
    }

    /**
     * @brief RFC 4034 부록 B의 key tag.
     * @warning 식별자가 아니라 힌트다. 서로 다른 키가 같은 tag를 가질 수 있고, 악의적인
     *          zone은 일부러 전부 같게 만들 수 있다(KeyTrap). tag가 맞아도 서명은 반드시
     *          실제로 검증해야 하며, 시도 횟수에는 상한이 필요하다.
     * @note 할당하지 않는다. RDATA를 만들어 쓰면 N×M 후보 루프에서 그만큼 할당이 붙는다.
     */
    pub fn key_tag(&self) -> u16 {
        let flags = self.flags.to_be_bytes();
        let mut ac: u32 = (u32::from(flags[0]) << 8) + u32::from(flags[1]);
        ac += (u32::from(self.protocol) << 8) + u32::from(self.algorithm);

        for (i, b) in self.public_key.iter().enumerate() {
            ac += if i & 1 == 0 {
                u32::from(*b) << 8
            } else {
                u32::from(*b)
            };
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /** @brief zone 키 비트(0x0100)가 서 있는지. 이 비트가 없는 키로는 RRset을 검증하지 않는다. */
    pub fn is_zone_key(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /** @brief SEP 비트. 관례상 KSK를 표시하지만 검증 규칙은 아니다. */
    pub fn is_sep(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /**
     * @brief 폐기 비트(RFC 5011)가 서 있는지.
     * @warning 폐기된 키로는 어떤 것도 검증하지 않는다. 운영자가 명시적으로 무효화한 키다.
     */
    pub fn is_revoked(&self) -> bool {
        self.flags & 0x0080 != 0
    }
}

/** @brief DS 레코드. 부모 zone이 자식 zone의 키를 가리키는 다이제스트다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ds {
    /** @brief 어느 DNSKEY를 가리키는지 알려 주는 힌트. 식별자가 아니다. */
    pub key_tag: u16,
    /** @brief 지목한 키의 서명 알고리즘. */
    pub algorithm: u8,
    /** @brief 다이제스트 알고리즘. SHA-256(2)·SHA-384(4)만 받는다. */
    pub digest_type: u8,
    /** @brief 정규 소유자 이름 ‖ DNSKEY RDATA의 다이제스트. */
    pub digest: Vec<u8>,
}

impl Ds {
    /** @brief DS RDATA를 해석한다. */
    pub fn parse(raw: &[u8]) -> Option<Ds> {
        let mut r = Reader::new(raw);
        let key_tag = r.u16().ok()?;
        let algorithm = r.u8().ok()?;
        let digest_type = r.u8().ok()?;
        Some(Ds {
            key_tag,
            algorithm,
            digest_type,
            digest: raw.get(r.pos..)?.to_vec(),
        })
    }

    /** @brief 레코드에서 DS를 꺼낸다. CDS도 같은 형식이다. */
    pub fn from_record(rec: &Record) -> Option<Ds> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Ds::parse(raw),
            _ => None,
        }
    }

    /**
     * @brief 키에서 DS를 계산한다.
     * @details 다이제스트 입력은 정규 소유자 이름과 DNSKEY RDATA를 이은 것이다. 이름이
     *          들어가야 같은 키를 다른 zone에 옮겨 붙일 수 없다.
     */
    pub fn from_dnskey(key: &Dnskey, owner: &Name, digest_type: u8) -> Option<Ds> {
        let mut input = Vec::new();
        canonical_name_into(owner, &mut input);
        input.extend_from_slice(&key.rdata_bytes());
        Some(Ds {
            key_tag: key.key_tag(),
            algorithm: key.algorithm,
            digest_type,
            digest: digest(digest_type, &input).ok()?,
        })
    }

    /** @brief DS를 RDATA 바이트로 만든다. */
    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.digest.len());
        v.extend_from_slice(&self.key_tag.to_be_bytes());
        v.push(self.algorithm);
        v.push(self.digest_type);
        v.extend_from_slice(&self.digest);
        v
    }
}

/**
 * @brief 내장된 루트 신뢰 앵커.
 * @details 모든 검증의 출발점이다. 이 값이 틀리면 정상 응답이 전부 bogus가 되거나,
 *          더 나쁘게는 위조 응답이 통과한다.
 */
pub fn root_trust_anchors() -> Vec<Ds> {
    /** @brief 2017년 루트 키의 지문. */
    const KSK_2017_DIGEST: [u8; 32] = [
        0xe0, 0x6d, 0x44, 0xb8, 0x0b, 0x8f, 0x1d, 0x39, 0xa9, 0x5c, 0x0b, 0x0d, 0x7c, 0x65, 0xd0,
        0x84, 0x58, 0xe8, 0x80, 0x40, 0x9b, 0xbc, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xc7, 0xf8,
        0xec, 0x8d,
    ];
    /** @brief 2024년 루트 키의 지문. */
    const KSK_2024_DIGEST: [u8; 32] = [
        0x68, 0x3d, 0x2d, 0x0a, 0xcb, 0x8c, 0x9b, 0x71, 0x2a, 0x19, 0x48, 0xb2, 0x7f, 0x74, 0x12,
        0x19, 0x29, 0x8d, 0x0a, 0x45, 0x0d, 0x61, 0x2c, 0x48, 0x3a, 0xf4, 0x44, 0xa4, 0xc0, 0xfb,
        0x2b, 0x16,
    ];
    vec![
        Ds {
            key_tag: 20326,
            algorithm: 8,
            digest_type: 2,
            digest: KSK_2017_DIGEST.to_vec(),
        },
        Ds {
            key_tag: 38696,
            algorithm: 8,
            digest_type: 2,
            digest: KSK_2024_DIGEST.to_vec(),
        },
    ]
}

/** @brief RRSIG 레코드. RRset 하나에 대한 서명이다. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    /** @brief 이 서명이 덮는 RR 타입. 서명 대상 구성에도 이 값이 쓰인다. */
    pub type_covered: u16,
    /** @brief 서명 알고리즘. 키의 것과 같아야 한다. */
    pub algorithm: u8,
    /** @brief 서명 당시 소유자 이름의 라벨 수. 실제 이름보다 짧으면 와일드카드 확장이다. */
    pub labels: u8,
    /** @brief 서명 대상에 넣을 TTL. 캐시를 거쳐 줄어든 수신 TTL을 쓰면 검증이 깨진다. */
    pub original_ttl: u32,
    /** @brief 서명 만료 시각(Unix 초, RFC 1982 순환 비교). */
    pub expiration: u32,
    /** @brief 서명 유효 개시 시각(Unix 초). */
    pub inception: u32,
    /** @brief 서명 키의 tag 힌트. */
    pub key_tag: u16,
    /** @brief 서명자 zone apex. 이 이름을 강제해야 다른 zone 키의 서명을 배제한다. */
    pub signer: Name,
    /** @brief 알고리즘별 서명 바이트. */
    pub signature: Vec<u8>,
}

impl Rrsig {
    /** @brief RRSIG RDATA를 해석한다. 서명자 이름은 압축될 수 없다. */
    pub fn parse(raw: &[u8]) -> Option<Rrsig> {
        let mut r = Reader::new(raw);
        let type_covered = r.u16().ok()?;
        let algorithm = r.u8().ok()?;
        let labels = r.u8().ok()?;
        let original_ttl = r.u32().ok()?;
        let expiration = r.u32().ok()?;
        let inception = r.u32().ok()?;
        let key_tag = r.u16().ok()?;
        let signer = Name::parse(&mut r).ok()?;
        Some(Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature: raw.get(r.pos..)?.to_vec(),
        })
    }

    /** @brief 레코드에서 RRSIG를 꺼낸다. */
    pub fn from_record(rec: &Record) -> Option<Rrsig> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Rrsig::parse(raw),
            _ => None,
        }
    }

    /**
     * @brief RRSIG를 RDATA 바이트로 만든다.
     * @note 서명 대상 데이터를 조립할 때 서명 값을 뺀 앞부분만 쓴다. 서명이 자기
     *       자신을 포함할 수는 없기 때문이다.
     */
    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.type_covered.to_be_bytes());
        v.push(self.algorithm);
        v.push(self.labels);
        v.extend_from_slice(&self.original_ttl.to_be_bytes());
        v.extend_from_slice(&self.expiration.to_be_bytes());
        v.extend_from_slice(&self.inception.to_be_bytes());
        v.extend_from_slice(&self.key_tag.to_be_bytes());
        canonical_name_into(&self.signer, &mut v);
        v.extend_from_slice(&self.signature);
        v
    }
}

/**
 * @brief RRset 하나에 대한 서명을 검증한다.
 *
 * @details 서명 대상은 RRSIG 앞부분 + 정규화된 RRset이다. 정규화는 소유자 이름 소문자화,
 *          원본 TTL 사용, RDATA 기준 정렬을 포함한다. 이 셋 중 하나라도 어긋나면 정상
 *          서명이 실패한다.
 * @warning 여기서 실제 공개키 연산이 일어난다. 호출자가 시도 횟수를 제한해야 한다.
 */
pub fn verify_rrsig(rrset: &[Record], rrsig: &Rrsig, key: &Dnskey) -> Result<(), DnssecError> {
    let first = validate_rrset_shape(rrset)?;
    if rrsig.algorithm != key.algorithm || !rrsig_applies_to_rrset(rrsig, first) {
        return Err(DnssecError::Invalid);
    }
    verify_rrsig_crypto(rrset, rrsig, key)
}

/** @brief RRset이 한 소유자·클래스·타입으로만 구성됐는지 한 번 검사한다. */
fn validate_rrset_shape(rrset: &[Record]) -> Result<&Record, DnssecError> {
    let Some(first) = rrset.first() else {
        return Err(DnssecError::Invalid);
    };
    if rrset.iter().any(|record| {
        record.rtype != first.rtype
            || record.class != first.class
            || !record.name.eq_ignore_case(&first.name)
    }) {
        return Err(DnssecError::Invalid);
    }
    Ok(first)
}

/** @brief 공개키 연산 전에 RRSIG가 이 RRset을 덮을 수 있는지 값싸게 거른다. */
fn rrsig_applies_to_rrset(rrsig: &Rrsig, first: &Record) -> bool {
    rrsig.type_covered == first.rtype.0
        && usize::from(rrsig.labels) <= first.name.num_labels()
        && name_is_within(&first.name, &rrsig.signer)
}

/** @brief 현재 구현이 실제 공개키 검증을 수행하는 DNSSEC 알고리즘인지. */
fn signature_algorithm_supported(algorithm: u8) -> bool {
    matches!(algorithm, 8 | 10 | 13 | 14 | 15)
}

/** @brief 구조 검사를 마친 후보 하나의 공개키 연산만 수행한다. */
fn verify_rrsig_crypto(rrset: &[Record], rrsig: &Rrsig, key: &Dnskey) -> Result<(), DnssecError> {
    let data = signed_data(rrsig, rrset);
    match key.algorithm {
        8 => verify_rsa(&key.public_key, &data, &rrsig.signature, false),
        10 => verify_rsa(&key.public_key, &data, &rrsig.signature, true),
        13 => verify_ecdsa_p256(&key.public_key, &data, &rrsig.signature),
        14 => verify_ecdsa_p384(&key.public_key, &data, &rrsig.signature),
        15 => verify_ed25519(&key.public_key, &data, &rrsig.signature),
        other => Err(DnssecError::Unsupported(other)),
    }
}

/** @brief DS 다이제스트가 이 키와 소유자 이름에서 나온 것인지 확인한다. */
pub fn verify_ds(ds: &Ds, key: &Dnskey, owner: &Name) -> Result<(), DnssecError> {
    if ds.key_tag != key.key_tag() || ds.algorithm != key.algorithm {
        return Err(DnssecError::Invalid);
    }
    let input = ds_digest_input(key, owner);
    let digest = digest(ds.digest_type, &input)?;
    if digest == ds.digest {
        Ok(())
    } else {
        Err(DnssecError::BadDigest)
    }
}

/** @brief DS 다이제스트 입력을 중간 DNSKEY RDATA 할당 없이 한 번 만든다. */
fn ds_digest_input(key: &Dnskey, owner: &Name) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + key.public_key.len() + 32);
    canonical_name_into(owner, &mut input);
    input.extend_from_slice(&key.flags.to_be_bytes());
    input.push(key.protocol);
    input.push(key.algorithm);
    input.extend_from_slice(&key.public_key);
    input
}

#[cfg(test)]
thread_local! {
    /** @brief 한 스레드에서 실제 DS digest를 계산한 횟수. */
    static DS_DIGEST_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/** @brief DS 다이제스트를 계산한다. SHA-1은 지원하지 않는다. */
fn digest(digest_type: u8, input: &[u8]) -> Result<Vec<u8>, DnssecError> {
    #[cfg(test)]
    DS_DIGEST_CALLS.with(|calls| calls.set(calls.get() + 1));
    use sha2::Digest as _;
    Ok(match digest_type {
        2 => sha2::Sha256::digest(input).to_vec(),
        4 => sha2::Sha384::digest(input).to_vec(),
        t => return Err(DnssecError::Unsupported(t)),
    })
}

/** @brief Ed25519(알고리즘 15) 서명 검증. */
fn verify_ed25519(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), DnssecError> {
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| DnssecError::BadKey)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| DnssecError::BadKey)?;
    let sigb: [u8; 64] = sig.try_into().map_err(|_| DnssecError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sigb);
    vk.verify_strict(msg, &signature)
        .map_err(|_| DnssecError::BadSignature)
}

/** @brief ECDSA P-256(알고리즘 13) 서명 검증. 가장 널리 쓰이는 알고리즘이다. */
fn verify_ecdsa_p256(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), DnssecError> {
    if pubkey.len() != 64 {
        return Err(DnssecError::BadKey);
    }
    let digest: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(msg).into()
    };

    p256fast::verify(pubkey, &digest, sig).map_err(|()| DnssecError::BadSignature)
}

/**
 * @brief RSA(알고리즘 8/10) 서명 검증. onetdns-core의 rsa 모듈을 쓴다.
 *
 * @warning 모듈러스 하한은 TLS의 것보다 낮다. org, nl을 비롯한 여러 영역이 지금도
 *          1024비트 ZSK로 서명하므로, TLS 하한을 그대로 쓰면 그 영역들이 전부 Bogus가 된다.
 */
fn verify_rsa(pubkey: &[u8], msg: &[u8], sig: &[u8], sha512: bool) -> Result<(), DnssecError> {
    use onetdns_core::rsa::{verify_pkcs1_min_bits, RsaError, RsaHash, MIN_MODULUS_BITS_DNSSEC};
    let (e, n) = parse_rfc3110(pubkey).ok_or(DnssecError::BadKey)?;
    let hash = if sha512 {
        RsaHash::Sha512
    } else {
        RsaHash::Sha256
    };
    verify_pkcs1_min_bits(hash, n, e, msg, sig, MIN_MODULUS_BITS_DNSSEC).map_err(|err| match err {
        RsaError::BadKey => DnssecError::BadKey,
        RsaError::BadSignature => DnssecError::BadSignature,
    })
}

/**
 * @brief 받아들일 RSA 모듈러스 최소 바이트 수.
 *
 * @details 1024비트다. org, nl을 비롯한 여러 영역이 지금도 1024비트 ZSK로 서명하므로,
 *          TLS와 같은 2048비트 하한을 두면 그 영역들이 전부 Bogus가 된다. 검증기가
 *          받아들이지 못하는 것과 서명이 위조된 것은 다른 일이다.
 * @warning 이 값을 올리면 그 크기로 서명하는 모든 영역이 해석되지 않는다.
 */
const MIN_RSA_MODULUS_BYTES: usize = 128;

/**
 * @brief RFC 3110 형식의 RSA 공개키에서 지수와 모듈러스를 추출한다.
 * @details 지수 길이가 1바이트로 안 담기면 0 다음에 2바이트로 온다. 길이가 0이거나
 *          남은 바이트를 넘으면 거부한다.
 */
fn parse_rfc3110(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if raw.is_empty() {
        return None;
    }
    let (explen, rest) = if raw[0] == 0 {
        if raw.len() < 3 {
            return None;
        }
        let len = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        if len < 256 {
            return None;
        }
        (len, &raw[3..])
    } else {
        (raw[0] as usize, &raw[1..])
    };
    if explen == 0 || rest.len() <= explen || rest[0] == 0 || rest[explen] == 0 {
        return None;
    }
    let e = &rest[..explen];
    let n = &rest[explen..];
    if e.len() > 5
        || n.len() < MIN_RSA_MODULUS_BYTES
        || n.len() > 1024
        || n[0] == 0
        || n.last().is_none_or(|byte| byte & 1 == 0)
    {
        return None;
    }
    let exponent = e
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    if !(3..=(1u64 << 33) - 1).contains(&exponent) || exponent & 1 == 0 {
        return None;
    }
    Some((e, n))
}

/** @brief ECDSA P-384(알고리즘 14) 서명 검증. */
fn verify_ecdsa_p384(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), DnssecError> {
    use p384::ecdsa::signature::Verifier;
    if pubkey.len() != 96 {
        return Err(DnssecError::BadKey);
    }
    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(pubkey);
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| DnssecError::BadKey)?;
    let signature =
        p384::ecdsa::Signature::from_slice(sig).map_err(|_| DnssecError::BadSignature)?;
    vk.verify(msg, &signature)
        .map_err(|_| DnssecError::BadSignature)
}

/**
 * @brief RFC 1982 순환 산술 비교(a <= b).
 * @warning 단순 크기 비교를 쓰면 안 된다. 2^32 주기로 되감기는 값이라, 되감긴 시각이
 *          영원히 과거로 판정되어 정상 서명이 만료로 보인다.
 */
fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

/** @brief 서명 유효 기간 안인지. 전역 만료 허용 설정을 함께 본다. */
pub fn rrsig_time_valid(rrsig: &Rrsig, now: u32) -> bool {
    rrsig_time_valid_accepting(rrsig, now, false)
}

/**
 * @brief 만료 허용 여부를 인자로 받아 유효 기간을 본다.
 * @param accept_expired true면 만료된 서명도 통과시킨다. 시계가 어긋난 환경의 임시 조치이며
 *                       재생 공격을 막지 못한다.
 */
pub fn rrsig_time_valid_accepting(rrsig: &Rrsig, now: u32, accept_expired: bool) -> bool {
    serial_le(rrsig.inception, now) && (accept_expired || serial_le(now, rrsig.expiration))
}

/** @brief 만료된 서명도 받아들일지. 시각이 크게 틀어진 기계에서 쓰려는 것이며, 켜면 방어가 약해진다. */
static ACCEPT_EXPIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/**
 * @brief 만료 서명 허용을 전역으로 켠다.
 * @warning 시계 동기화가 없는 환경을 위한 탈출구다. 켜면 오래전에 폐기된 서명도 통과하므로
 *          운영 환경에서는 쓰지 않는다.
 */
pub fn set_accept_expired(v: bool) {
    ACCEPT_EXPIRED.store(v, std::sync::atomic::Ordering::Relaxed);
}

/** @brief 현재 만료 허용 설정. */
fn accept_expired_now() -> bool {
    ACCEPT_EXPIRED.load(std::sync::atomic::Ordering::Relaxed)
}

/**
 * @brief 신뢰 체인의 한 단계: zone 하나의 DNSKEY와 그 위임 증거.
 * @details 루트부터 리프까지 순서대로 늘어놓으면 검증기가 앵커에서 시작해 내려간다.
 */
pub struct ChainLink {
    /** @brief 이 단계가 대표하는 zone apex. */
    pub zone: Name,

    /** @brief zone의 DNSKEY RRset 원본 레코드. 서명 검증에 정규형 그대로 필요하다. */
    pub dnskeys: Vec<Record>,

    /** @brief 위 DNSKEY RRset을 덮는 서명들. KSK로 서명돼 있어야 한다. */
    pub dnskey_rrsigs: Vec<Rrsig>,

    /** @brief 이 zone이 자식에게 준 DS RRset. 비어 있으면 위임이 서명되지 않았다는 뜻이다. */
    pub ds_records: Vec<Record>,
    /** @brief 위 DS RRset을 덮는 서명들. 부모 zone 키로 검증한다. */
    pub ds_rrsigs: Vec<Rrsig>,

    /** @brief DS 부재를 NSEC으로 증명하는 레코드들. 안전한 위임 종료 판정에 쓴다. */
    pub ds_nsec_records: Vec<Record>,
    /** @brief 위 NSEC들을 덮는 서명들. */
    pub ds_nsec_rrsigs: Vec<Rrsig>,
    /** @brief DS 부재를 NSEC3으로 증명하는 레코드들. */
    pub ds_nsec3_records: Vec<Record>,
    /** @brief 위 NSEC3들을 덮는 서명들. */
    pub ds_nsec3_rrsigs: Vec<Rrsig>,

    /** @brief ds_records를 파싱한 형태. 다음 단계의 신뢰 기준이 된다. */
    pub ds: Vec<Ds>,
}

/**
 * @brief 한 RRset을 검증하며 시도할 수 있는 공개키 연산 횟수 상한.
 *
 * @details RFC 4035는 서명이 검증될 때까지 모든 후보 키를 시도하라고 한다. 그대로 두면
 *          key tag가 전부 겹치는 DNSKEY N개와 RRSIG M개를 돌려주는 zone이 질의 한 건에
 *          N×M회 공개키 연산을 강제할 수 있다(KeyTrap, CVE-2023-50387 계열).
 * @note    정상 zone은 활성 ZSK 하나, 롤오버 중이라도 둘로 서명하므로 한 자릿수면 족하다.
 * @warning 초과 시 fail-closed로 Bogus 처리한다. 늘리면 위 소진 경로가 그만큼 열린다.
 */
const MAX_SIGNATURE_VERIFICATIONS: usize = 8;

/**
 * @brief 한 DNSKEY RRset에서 허용하는 실제 DS 다이제스트 계산 횟수.
 * @note 정상 롤오버는 KSK 1~2개와 다이제스트 종류 1~2개만 필요하다. 키 tag를 충돌시킨
 *       DNSKEY·DS 팬아웃이 해시 계산을 무한히 늘리지 못하도록 넉넉한 32회에서 닫는다.
 */
const MAX_DS_DIGEST_COMPUTATIONS: usize = 32;

#[derive(Default)]
/** @brief DNSKEY RRset 하나가 공유하는 DS 다이제스트 계산 예산. */
struct DsDigestBudget {
    computations: usize,
}

impl DsDigestBudget {
    /** @brief 실제 해시 한 번을 예약한다. 상한이면 fail-closed한다. */
    fn charge(&mut self) -> Result<(), DnssecError> {
        if self.computations >= MAX_DS_DIGEST_COMPUTATIONS {
            return Err(DnssecError::BadSignature);
        }
        self.computations += 1;
        Ok(())
    }
}

#[derive(Debug)]
/** @brief 한 DNS 응답 안에서 공유하는 공개키 검증 시도 예산. */
pub struct VerificationBudget {
    /** @brief 지금까지 실제 공개키 연산으로 넘긴 후보 수. */
    attempts: usize,
}

impl VerificationBudget {
    /** @brief 비어 있는 응답 단위 예산을 만든다. */
    pub fn new() -> Self {
        Self { attempts: 0 }
    }

    /** @brief 공개키 연산 한 번을 예약한다. 상한이면 fail-closed한다. */
    fn charge(&mut self) -> Result<(), DnssecError> {
        if self.attempts >= MAX_SIGNATURE_VERIFICATIONS {
            return Err(DnssecError::BadSignature);
        }
        self.attempts += 1;
        Ok(())
    }
}

impl Default for VerificationBudget {
    fn default() -> Self {
        Self::new()
    }
}

/**
 * @brief signer를 강제하지 않고 RRset 서명을 검증한다.
 * @note signer apex를 이미 아는 호출자는 validate_rrset_in_zone을 써야 한다. 이 형태는
 *       서명자가 어느 zone이든 상관없이 통과시키므로, 다른 zone의 키로 서명된 데이터를
 *       배제하지 못한다.
 */
pub fn validate_rrset(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    now: u32,
) -> Result<(), DnssecError> {
    let mut budget = VerificationBudget::new();
    validate_rrset_for_signer(rrset, rrsigs, keys, now, None, &mut budget, |_, _| true)
}

/**
 * @brief 서명자가 zone apex인 서명만 인정하며 RRset을 검증한다.
 * @details 이것이 기본형이다. signer를 묶어 두지 않으면 공격자가 자기 zone 키로 서명한
 *          RRset을 남의 zone 응답에 끼워 넣을 수 있다.
 */
pub fn validate_rrset_in_zone(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &Name,
    now: u32,
) -> Result<(), DnssecError> {
    let mut budget = VerificationBudget::new();
    validate_rrset_in_zone_with_budget(rrset, rrsigs, keys, zone, now, &mut budget)
}

/**
 * @brief zone 서명 중 호출자의 추가 조건까지 만족하는 첫 서명에서 검증을 끝낸다.
 * @details 와일드카드처럼 암호학적 검증 뒤 문맥 검사가 필요한 경로가 서명마다 검증 예산을
 *          새로 만들지 않도록 한다. predicate는 공개키 검증에 성공한 서명에만 호출된다.
 * @warning false를 돌려준 정상 서명도 공개키 연산 1회를 썼으므로 같은 8회 예산에 포함된다.
 */
pub fn validate_rrset_in_zone_with(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &Name,
    now: u32,
    mut predicate: impl FnMut(&Rrsig) -> bool,
) -> Result<(), DnssecError> {
    let mut budget = VerificationBudget::new();
    validate_rrset_in_zone_with_budget_and(
        rrset,
        rrsigs,
        keys,
        zone,
        now,
        &mut budget,
        |signature, _| predicate(signature),
    )
}

/** @brief 호출자가 제공한 응답 단위 예산으로 zone RRset을 검증한다. */
pub fn validate_rrset_in_zone_with_budget(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &Name,
    now: u32,
    budget: &mut VerificationBudget,
) -> Result<(), DnssecError> {
    validate_rrset_for_signer(rrset, rrsigs, keys, now, Some(zone), budget, |_, _| true)
}

/**
 * @brief 공유 예산으로 검증하고, 성공한 서명에 응답 문맥 조건을 적용한다.
 * @warning predicate가 다른 RRset을 검증할 때도 전달받은 같은 예산을 써야 한다.
 */
pub fn validate_rrset_in_zone_with_budget_and(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &Name,
    now: u32,
    budget: &mut VerificationBudget,
    predicate: impl FnMut(&Rrsig, &mut VerificationBudget) -> bool,
) -> Result<(), DnssecError> {
    validate_rrset_for_signer(rrset, rrsigs, keys, now, Some(zone), budget, predicate)
}

/**
 * @brief RRset이 주어진 키 집합 중 하나로 유효하게 서명됐는지 확인한다.
 *
 * @details 서명 하나라도 검증되면 즉시 성공이다. 값싼 걸러내기(key tag·알고리즘·프로토콜·
 *          zone key·revoke)를 먼저 통과한 조합만 실제 공개키 연산으로 넘긴다.
 * @param rrset           검증 대상 레코드 집합.
 * @param rrsigs          이 RRset을 덮는다고 주장하는 서명들.
 * @param keys            신뢰 체인이 확정한 zone 키들.
 * @param now             만료·유효개시 판정에 쓸 현재 시각(Unix 초).
 * @param expected_signer 요구할 signer apex. None이면 signer를 강제하지 않는다.
 * @return 유효한 서명을 찾으면 Ok.
 * @retval DnssecError::BadSignature 유효한 서명이 없거나 검증 예산을 넘겼을 때.
 * @invariant 공개키 연산 횟수는 MAX_SIGNATURE_VERIFICATIONS를 넘지 않는다.
 */
fn validate_rrset_for_signer(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    now: u32,
    expected_signer: Option<&Name>,
    budget: &mut VerificationBudget,
    mut predicate: impl FnMut(&Rrsig, &mut VerificationBudget) -> bool,
) -> Result<(), DnssecError> {
    let first = validate_rrset_shape(rrset)?;
    for sig in rrsigs {
        if expected_signer.is_some_and(|zone| !sig.signer.eq_ignore_case(zone))
            || !rrsig_applies_to_rrset(sig, first)
            || !signature_algorithm_supported(sig.algorithm)
            || !rrsig_time_valid_accepting(sig, now, accept_expired_now())
        {
            continue;
        }
        for k in keys {
            if sig.key_tag != k.key_tag()
                || sig.algorithm != k.algorithm
                || k.protocol != 3
                || !k.is_zone_key()
                || k.is_revoked()
            {
                continue;
            }

            budget.charge()?;
            if verify_rrsig_crypto(rrset, sig, k).is_ok() && predicate(sig, budget) {
                return Ok(());
            }
        }
    }
    Err(DnssecError::BadSignature)
}

/**
 * @brief DS로 신뢰가 확정된 KSK를 찾아 zone의 DNSKEY RRset 전체를 확정한다.
 *
 * @details 순서가 중요하다. 먼저 DNSKEY 레코드가 정말 이 zone apex 것인지 확인하고,
 *          trusted_ds 중 하나와 다이제스트가 맞는 키만 KSK 후보로 남긴다. 그 후보가
 *          DNSKEY RRset 자체의 서명을 검증해야 비로소 RRset 전체를 신뢰한다.
 *          DS는 KSK 하나만 지목하지만, 그 KSK의 서명이 나머지 ZSK까지 보증하는 구조다.
 * @param dnskeys    zone apex의 DNSKEY 레코드들. 소유자 이름과 타입이 모두 맞아야 한다.
 * @param rrsigs     DNSKEY RRset을 덮는 서명들.
 * @param trusted_ds 상위 단계에서 확정된 DS 집합.
 * @param zone       이 DNSKEY들이 속해야 할 zone apex.
 * @param now        시각 판정에 쓸 Unix 초.
 * @return 확정된 키 집합. 이것으로 zone 내 다른 RRset을 검증한다.
 * @retval DnssecError::Invalid      레코드 구성이 틀렸거나 DS에 맞는 KSK 후보가 없을 때.
 * @retval DnssecError::BadSignature KSK 후보는 있으나 DNSKEY 서명이 검증되지 않을 때.
 */
pub fn validate_dnskey_set(
    dnskeys: &[Record],
    rrsigs: &[Rrsig],
    trusted_ds: &[Ds],
    zone: &Name,
    now: u32,
) -> Result<Vec<Dnskey>, DnssecError> {
    if dnskeys.is_empty()
        || dnskeys
            .iter()
            .any(|record| record.rtype != RecordType::DNSKEY || !record.name.eq_ignore_case(zone))
    {
        return Err(DnssecError::Invalid);
    }
    let keys: Vec<Dnskey> = dnskeys.iter().filter_map(Dnskey::from_record).collect();
    if keys.is_empty() {
        return Err(DnssecError::Invalid);
    }

    let mut trusted_digests = HashMap::<(u16, u8, u8), HashSet<&[u8]>>::new();
    for ds in trusted_ds {
        let expected_len = match ds.digest_type {
            2 => 32,
            4 => 48,
            _ => continue,
        };
        if ds.digest.len() != expected_len {
            continue;
        }
        trusted_digests
            .entry((ds.key_tag, ds.algorithm, ds.digest_type))
            .or_default()
            .insert(&ds.digest);
    }

    let mut digest_budget = DsDigestBudget::default();
    let mut candidate_ksks = Vec::new();
    for key in &keys {
        if key.protocol != 3 || !key.is_zone_key() || key.is_revoked() {
            continue;
        }
        let key_tag = key.key_tag();
        if trusted_ds_matches_key(key, key_tag, zone, &trusted_digests, &mut digest_budget)? {
            candidate_ksks.push(key);
        }
    }
    if candidate_ksks.is_empty() {
        return Err(DnssecError::Invalid);
    }

    let first = &dnskeys[0];
    let mut budget = VerificationBudget::new();
    for sig in rrsigs {
        if !rrsig_time_valid_accepting(sig, now, accept_expired_now())
            || !sig.signer.eq_ignore_case(zone)
            || !rrsig_applies_to_rrset(sig, first)
            || !signature_algorithm_supported(sig.algorithm)
        {
            continue;
        }
        for ksk in &candidate_ksks {
            if sig.key_tag != ksk.key_tag() || sig.algorithm != ksk.algorithm {
                continue;
            }
            budget.charge()?;
            if verify_rrsig_crypto(dnskeys, sig, ksk).is_ok() {
                return Ok(keys);
            }
        }
    }
    Err(DnssecError::BadSignature)
}

/**
 * @brief tag·알고리즘이 같은 DS 후보를 키·다이제스트 종류별 한 번의 해시로 대조한다.
 * @details 동일한 DS가 반복되어도 SHA-256·SHA-384를 각각 최대 한 번만 계산하고, 결과는
 *          앞서 만든 digest 집합에서 O(1)에 찾는다.
 */
fn trusted_ds_matches_key(
    key: &Dnskey,
    key_tag: u16,
    zone: &Name,
    trusted_digests: &HashMap<(u16, u8, u8), HashSet<&[u8]>>,
    budget: &mut DsDigestBudget,
) -> Result<bool, DnssecError> {
    let mut input = None;
    for digest_type in [2, 4] {
        let Some(candidates) = trusted_digests.get(&(key_tag, key.algorithm, digest_type)) else {
            continue;
        };
        budget.charge()?;
        let input = input.get_or_insert_with(|| ds_digest_input(key, zone));
        let actual = digest(digest_type, input)?;
        if candidates.contains(actual.as_slice()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/**
 * @brief 루트 앵커에서 시작해 체인을 내려간 뒤 최종 응답 RRset까지 검증한다.
 * @details 리프 zone(links의 마지막)을 signer로 강제하므로, 체인 중간 zone의 키로 서명된
 *          응답은 통과하지 못한다.
 */
pub fn validate_chain(
    root_anchors: &[Ds],
    links: &[ChainLink],
    answer: &[Record],
    answer_rrsigs: &[Rrsig],
    now: u32,
) -> Result<(), DnssecError> {
    let keys = validate_chain_keys(root_anchors, links, now)?;
    let zone = &links.last().ok_or(DnssecError::Invalid)?.zone;
    validate_rrset_in_zone(answer, answer_rrsigs, &keys, zone, now)
}

/**
 * @brief 체인을 루트→리프 순으로 걸어 리프 zone의 신뢰된 키를 얻는다.
 *
 * @details trusted_ds를 갱신하며 내려간다. 각 단계에서 그 zone의 DNSKEY를 확정하고,
 *          그 키로 자식 DS RRset을 검증한 뒤에야 trusted_ds를 자식용으로 교체한다.
 *          DS 검증을 건너뛰고 교체하면 서명되지 않은 DS를 그대로 믿게 된다.
 * @note 위임이 안전하지 않은 경우(DS 부재)는 여기서 구분하지 않는다. Secure/Insecure/Bogus
 *       삼분이 필요하면 validate_chain_status를 쓴다.
 * @return 리프 zone의 확정된 키 집합.
 */
pub fn validate_chain_keys(
    root_anchors: &[Ds],
    links: &[ChainLink],
    now: u32,
) -> Result<Vec<Dnskey>, DnssecError> {
    let mut trusted_ds = root_anchors.to_vec();
    let mut trusted_keys: Vec<Dnskey> = Vec::new();
    for link in links {
        trusted_keys = validate_dnskey_set(
            &link.dnskeys,
            &link.dnskey_rrsigs,
            &trusted_ds,
            &link.zone,
            now,
        )?;

        if !link.ds_records.is_empty() {
            validate_rrset_in_zone(
                &link.ds_records,
                &link.ds_rrsigs,
                &trusted_keys,
                &link.zone,
                now,
            )?;
            trusted_ds = link.ds.clone();
        }
    }
    Ok(trusted_keys)
}

/**
 * @brief 구문상 먼저 고른 최소 부재 증명의 모든 RRset 서명이 유효한지 확인한다.
 * @details 선택은 신뢰 전 자료로 해도 안전하다. 선택된 레코드를 신뢰하는 시점은 여기서
 *          서명이 전부 검증된 뒤다. 이 순서가 무관한 NSEC/RRSIG의 공개키 연산을 없앤다.
 */
fn denial_proof_valid(
    proof: &[Record],
    sigs: &[Rrsig],
    keys: &[Dnskey],
    expected_signer: &Name,
    rtype: RecordType,
    now: u32,
    budget: &mut VerificationBudget,
) -> bool {
    !proof.is_empty()
        && proof.iter().all(|record| {
            record.rtype == rtype
                && validate_rrset_in_zone_with_budget(
                    std::slice::from_ref(record),
                    sigs,
                    keys,
                    expected_signer,
                    now,
                    budget,
                )
                .is_ok()
        })
}

/**
 * @brief 부모가 자식 zone의 DS 부재를 서명된 증거로 증명했는지.
 * @details 서명되지 않은 위임이라는 증명만 인정한다. 이름이 있다는 증명이나 위임이 아니라는
 *          증명은 DS 부재가 아니다.
 * @return 증명되면 참. 거짓이면 위임 종료를 믿을 수 없으므로 Insecure가 아니라 Bogus다.
 */
fn ds_absence_proven(
    link: &ChainLink,
    child_zone: &Name,
    parent_keys: &[Dnskey],
    now: u32,
) -> bool {
    classify_ds_absence(
        &link.zone,
        parent_keys,
        &DenialEvidence {
            nsec: &link.ds_nsec_records,
            nsec_rrsigs: &link.ds_nsec_rrsigs,
            nsec3: &link.ds_nsec3_records,
            nsec3_rrsigs: &link.ds_nsec3_rrsigs,
        },
        child_zone,
        now,
    ) == DsAbsence::InsecureDelegation
}

/** @brief DS 질의에 딸려 온 부재 증거. 서명은 아직 확인하지 않은 상태다. */
pub struct DenialEvidence<'a> {
    /** @brief 권한 구간의 NSEC 레코드. */
    pub nsec: &'a [Record],
    /** @brief NSEC을 덮는 서명. */
    pub nsec_rrsigs: &'a [Rrsig],
    /** @brief 권한 구간의 NSEC3 레코드. */
    pub nsec3: &'a [Record],
    /** @brief NSEC3을 덮는 서명. */
    pub nsec3_rrsigs: &'a [Rrsig],
}

/** @brief DS가 없는 이름이 무엇인지에 대한 판정. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsAbsence {
    /** @brief 서명되지 않은 위임이다. 이 아래는 검증할 것이 없다. */
    InsecureDelegation,
    /** @brief 위임이 아니다. 이 이름은 부모 zone 안에 있고 부모 키로 서명돼야 한다. */
    NotACut,
    /** @brief 서명된 증명이 없다. 무엇인지 알 수 없다. */
    Unproven,
}

/**
 * @brief DS가 없는 이름이 서명되지 않은 위임인지, 위임이 아닌지 부모 키로 가린다.
 *
 * @details RFC 4035 와 RFC 5155 가 정한 대로 이름과 일치하는 NSEC 또는 NSEC3 의 타입
 *          비트맵을 본다. NS 가 있고 DS 와 SOA 가 없어야 서명되지 않은 위임이다. NS 가 없으면
 *          그 이름은 부모 zone 안의 보통 이름이다. 일치하는 레코드 없이 구간에 덮이면 그
 *          이름에는 RRset 이 없으므로 위임일 수 없다. NSEC3 opt-out 구간에 덮이면 그 안에
 *          서명되지 않은 위임이 있을 수 있으므로 위임으로 본다.
 * @warning DS 비트만 보고 위임이라 판정하면 서명된 zone 의 보통 이름에서 서명을 떼어 낸
 *          답이 서명되지 않은 위임의 답으로 통과한다.
 * @param parent_zone 증명에 서명한 부모 zone apex.
 * @param parent_keys 부모 zone 의 확정된 키.
 * @param child DS 를 물은 이름.
 */
pub fn classify_ds_absence(
    parent_zone: &Name,
    parent_keys: &[Dnskey],
    evidence: &DenialEvidence<'_>,
    child: &Name,
    now: u32,
) -> DsAbsence {
    let mut budget = VerificationBudget::new();
    let bitmap = |ns: bool, ds: bool, soa: bool| {
        if ds || soa {
            DsAbsence::Unproven
        } else if ns {
            DsAbsence::InsecureDelegation
        } else {
            DsAbsence::NotACut
        }
    };

    let exact = evidence
        .nsec
        .iter()
        .find(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(child));
    if let Some(record) = exact {
        if let Some(nsec) = Nsec::from_record(record) {
            if denial_proof_valid(
                std::slice::from_ref(record),
                evidence.nsec_rrsigs,
                parent_keys,
                parent_zone,
                RecordType::NSEC,
                now,
                &mut budget,
            ) {
                return bitmap(
                    nsec.has_type(RecordType::NS.0),
                    nsec.has_type(RecordType::DS.0),
                    nsec.has_type(RecordType::SOA.0),
                );
            }
        }
    } else if let Some(record) = nsec_covering_record(evidence.nsec, child) {
        if denial_proof_valid(
            std::slice::from_ref(record),
            evidence.nsec_rrsigs,
            parent_keys,
            parent_zone,
            RecordType::NSEC,
            now,
            &mut budget,
        ) {
            return DsAbsence::NotACut;
        }
    }

    let Some(prepared) = ValidatedNsec3Set::new(evidence.nsec3, child) else {
        return DsAbsence::Unproven;
    };
    let mut hashes = Nsec3HashBudget::default();
    if let Some(record) = prepared.matching_record(child, &mut hashes) {
        let Some(parsed) = Nsec3Ref::from_record(record) else {
            return DsAbsence::Unproven;
        };
        if denial_proof_valid(
            std::slice::from_ref(record),
            evidence.nsec3_rrsigs,
            parent_keys,
            parent_zone,
            RecordType::NSEC3,
            now,
            &mut budget,
        ) {
            return bitmap(
                parsed.has_type(RecordType::NS.0),
                parsed.has_type(RecordType::DS.0),
                parsed.has_type(RecordType::SOA.0),
            );
        }
        return DsAbsence::Unproven;
    }
    let Some((encloser, encloser_record)) = prepared.closest_encloser_record(child, &mut hashes)
    else {
        return DsAbsence::Unproven;
    };
    let next_closer = child.suffix(encloser.num_labels() + 1);
    let Some((covering, opt_out)) =
        prepared.covering_record_with_opt_out_status(&next_closer, &mut hashes)
    else {
        return DsAbsence::Unproven;
    };
    if !denial_proof_valid(
        &unique_records([encloser_record, covering]),
        evidence.nsec3_rrsigs,
        parent_keys,
        parent_zone,
        RecordType::NSEC3,
        now,
        &mut budget,
    ) {
        return DsAbsence::Unproven;
    }
    if opt_out {
        DsAbsence::InsecureDelegation
    } else {
        DsAbsence::NotACut
    }
}

/**
 * @brief 체인 판정 결과 삼분.
 * @note Insecure와 Bogus를 합치면 안 된다. Insecure는 서명 없는 정상 zone이라 응답을 주고,
 *       Bogus는 서명이 깨진 것이라 SERVFAIL로 막아야 한다.
 */
pub enum ChainStatus {
    /** @brief 루트까지 이어지는 서명이 전부 검증됐다. 리프 zone의 신뢰된 키를 함께 준다. */
    Secure(Vec<Dnskey>),
    /** @brief 어느 지점에서 위임이 서명 없이 끝났다. 검증 대상이 아니다. */
    Insecure,
    /** @brief 서명이 있으나 검증에 실패했다. 응답을 내보내면 안 된다. */
    Bogus,
}

/**
 * @brief DS 부재 증명을 요구하지 않고 체인을 판정한다.
 * @note DS가 없기만 하면 Insecure로 내려간다. 공격자가 DS를 지워 검증을 무력화하는
 *       다운그레이드를 막으려면 validate_chain_status_with_options로 증명을 요구한다.
 */
pub fn validate_chain_status(root_anchors: &[Ds], links: &[ChainLink], now: u32) -> ChainStatus {
    validate_chain_status_with_options(root_anchors, links, now, false)
}

/**
 * @brief 체인을 Secure/Insecure/Bogus로 판정한다.
 *
 * @details 각 단계에서 DNSKEY를 확정한 뒤 자식 DS의 유무로 갈린다. DS가 없고 아래 단계가
 *          남아 있으면 그 지점이 위임 종료다. DS는 있으나 이 서버가 지원하는 알고리즘·
 *          다이제스트가 하나도 없어도 마찬가지로 Insecure다. 검증할 수단이 없는 것이지
 *          위조된 것은 아니기 때문이다.
 * @param require_ds_absence_proof 참이면 DS 부재를 서명된 NSEC/NSEC3으로 증명해야만
 *                                 Insecure로 내려간다. 증명이 없으면 Bogus다.
 * @return 삼분 판정. Secure일 때만 리프 zone 키가 함께 온다.
 */
pub fn validate_chain_status_with_options(
    root_anchors: &[Ds],
    links: &[ChainLink],
    now: u32,
    require_ds_absence_proof: bool,
) -> ChainStatus {
    let mut trusted_ds = root_anchors.to_vec();
    let mut keys: Vec<Dnskey> = Vec::new();
    for (i, link) in links.iter().enumerate() {
        keys = match validate_dnskey_set(
            &link.dnskeys,
            &link.dnskey_rrsigs,
            &trusted_ds,
            &link.zone,
            now,
        ) {
            Ok(k) => k,
            Err(_) => return ChainStatus::Bogus,
        };
        if link.ds_records.is_empty() {
            if i + 1 < links.len() {
                if require_ds_absence_proof {
                    let child_zone = &links[i + 1].zone;
                    if !ds_absence_proven(link, child_zone, &keys, now) {
                        return ChainStatus::Bogus;
                    }
                }
                return ChainStatus::Insecure;
            }
        } else {
            if validate_rrset_in_zone(&link.ds_records, &link.ds_rrsigs, &keys, &link.zone, now)
                .is_err()
            {
                return ChainStatus::Bogus;
            }
            let supported_ds: Vec<Ds> = link
                .ds
                .iter()
                .filter(|ds| ds_is_supported(ds))
                .cloned()
                .collect();
            if supported_ds.is_empty() && i + 1 < links.len() {
                return ChainStatus::Insecure;
            }
            trusted_ds = supported_ds;
        }
    }
    ChainStatus::Secure(keys)
}

/** @brief RFC 8509 루트 키 센티널 질의. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKeySentinel {
    /** @brief 이 key tag의 키를 신뢰하는지 묻는다. */
    IsTa(u16),
    /** @brief 이 key tag의 키를 신뢰하지 않는지 묻는다. */
    NotTa(u16),
}

impl RootKeySentinel {
    /**
     * @brief 질의 이름의 첫 라벨이 센티널 형식이면 종류와 key tag를 추출한다.
     * @details RFC 8509 가 정한 라벨은 root-key-sentinel-is-ta- 또는 root-key-sentinel-not-ta-
     *          뒤에 key tag 를 앞자리 0 을 채운 다섯 자리 십진수로 붙인 것이다.
     */
    pub fn parse(label: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(label).ok()?.to_ascii_lowercase();
        let (tag, is_ta) = if let Some(rest) = text.strip_prefix("root-key-sentinel-is-ta-") {
            (rest, true)
        } else {
            (text.strip_prefix("root-key-sentinel-not-ta-")?, false)
        };
        if tag.len() != 5 || !tag.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let tag = tag.parse::<u16>().ok()?;
        Some(if is_ta {
            RootKeySentinel::IsTa(tag)
        } else {
            RootKeySentinel::NotTa(tag)
        })
    }

    /**
     * @brief 이 센티널 질의에 SERVFAIL 로 답해야 하는지.
     * @param anchors 지금 신뢰하는 루트 앵커.
     */
    pub fn fails(self, anchors: &[Ds]) -> bool {
        match self {
            RootKeySentinel::IsTa(tag) => !anchors.iter().any(|ds| ds.key_tag == tag),
            RootKeySentinel::NotTa(tag) => anchors.iter().any(|ds| ds.key_tag == tag),
        }
    }
}

/**
 * @brief 이 DS를 이 서버가 실제로 검증할 수 있는지.
 * @details 알고리즘은 RSA/SHA-256·512(8/10), ECDSA P-256·P-384(13/14), Ed25519(15)만,
 *          다이제스트는 SHA-256(2)·SHA-384(4)만 인정한다. SHA-1(1)은 충돌 공격 때문에 뺐다.
 * @note 지원 밖 DS만 있는 위임은 Bogus가 아니라 Insecure다. 검증 수단이 없을 뿐이다.
 */
pub fn ds_is_supported(ds: &Ds) -> bool {
    matches!(ds.algorithm, 8 | 10 | 13 | 14 | 15) && matches!(ds.digest_type, 2 | 4)
}

/**
 * @brief NSEC 레코드: 정규 순서상 다음 이름과, 이 이름에 존재하는 타입 목록.
 * @details 두 이름 사이에 아무것도 없음을 주장해 부재를 증명한다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    /** @brief 정규 순서상 이 소유자 다음에 존재하는 이름. */
    pub next: Name,
    /** @brief 이 소유자 이름에 실제로 존재하는 RR 타입들. */
    pub types: Vec<u16>,
}

impl Nsec {
    /**
     * @brief NSEC RDATA를 파싱한다.
     * @note next는 압축될 수 없으므로 오프셋 계산이 안전하다. 남은 바이트 전체가
     *       타입 비트맵이며, 잘못된 비트맵은 None으로 떨군다.
     */
    pub fn parse(raw: &[u8]) -> Option<Nsec> {
        let mut r = Reader::new(raw);
        let next = Name::parse(&mut r).ok()?;
        let types = parse_type_bitmaps(raw.get(r.pos..)?)?;
        Some(Nsec { next, types })
    }

    /** @brief 레코드에서 NSEC을 꺼낸다. 미해석 RDATA로 보관돼 있어야 한다. */
    pub fn from_record(rec: &Record) -> Option<Nsec> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Nsec::parse(raw),
            _ => None,
        }
    }

    /** @brief 이 소유자 이름에 해당 타입이 존재한다고 비트맵이 말하는지. */
    pub fn has_type(&self, t: u16) -> bool {
        self.types.contains(&t)
    }
}

/**
 * @brief RFC 4034 정규 이름 순서 비교.
 * @details 라벨을 뒤에서부터(TLD 쪽부터) 비교한다. DNS 트리 구조상 이 방향이라야
 *          같은 부모 아래 형제들이 인접해, NSEC의 "사이에 아무것도 없다"가 성립한다.
 * @note 라벨이 먼저 떨어지는 쪽이 작다. a.example이 b.a.example보다 앞이다.
 */
pub fn canonical_name_cmp(a: &Name, b: &Name) -> Ordering {
    let (mut al, mut bl) = (a.labels().rev(), b.labels().rev());
    loop {
        let (left, right) = match (al.next(), bl.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => (left, right),
        };
        match canonical_label_cmp(left, right) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
}

/**
 * @brief 라벨 하나를 정규 순서로 비교한다.
 * @details 대소문자를 낮춰 옥텟 단위로 보고, 공통 접두사가 같으면 짧은 쪽이 앞이다.
 *          비교에서 대소문자를 구분하면 같은 이름이 두 위치를 갖게 돼 부재 증명이 깨진다.
 */
fn canonical_label_cmp(a: &[u8], b: &[u8]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let (lx, ly) = (x.to_ascii_lowercase(), y.to_ascii_lowercase());
        if lx != ly {
            return lx.cmp(&ly);
        }
    }
    a.len().cmp(&b.len())
}

/**
 * @brief NSEC 구간 (owner, next)가 qname을 덮는지. 양 끝은 포함하지 않는다.
 * @details zone의 마지막 NSEC은 apex로 되돌아가 next <= owner가 된다. 이 되감김 구간은
 *          두 조건 중 하나만 맞아도 덮는 것으로 봐야 한다. 그냥 범위 비교로 두면 zone 끝부분
 *          이름들의 부재가 전부 증명되지 않는다.
 */
pub fn nsec_covers(owner: &Name, next: &Name, qname: &Name) -> bool {
    let owner_lt_q = canonical_name_cmp(owner, qname) == Ordering::Less;
    let q_lt_next = canonical_name_cmp(qname, next) == Ordering::Less;
    if canonical_name_cmp(owner, next) == Ordering::Less {
        owner_lt_q && q_lt_next
    } else {
        owner_lt_q || q_lt_next
    }
}

/**
 * @brief 이름은 있으나 그 타입이 없음(NODATA)을 NSEC으로 증명한다.
 *
 * @details 두 경로가 있다. 이름과 정확히 일치하는 NSEC이 그 타입을 갖고 있지 않으면 끝이다.
 *          그렇지 않으면 이름 자체가 없는 것이므로, closest encloser를 찾아 next closer가
 *          덮이고 와일드카드도 그 타입을 갖지 않음까지 보여야 한다. 와일드카드를 빼면
 *          *.example이 답을 줄 수 있는데도 NODATA라고 속일 수 있다.
 */
pub fn prove_nodata(nsec_records: &[Record], qname: &Name, qtype: u16) -> bool {
    if nsec_record_lacking_type(nsec_records, qname, qtype).is_some() {
        return true;
    }
    let Some((ce, _)) = nsec_closest_encloser_record(nsec_records, qname) else {
        return false;
    };
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let Some(wildcard) = wildcard_name(&ce) else {
        return false;
    };
    nsec_covering_record(nsec_records, &next_closer).is_some()
        && nsec_record_lacking_type(nsec_records, &wildcard, qtype).is_some()
}

/**
 * @brief prove_nodata와 같은 판정을 하되, 증명에 실제로 쓰인 레코드를 돌려준다.
 * @details 이 서버가 직접 부재 응답을 만들 때 필요하다. 판정만 하고 원본 NSEC을 전부
 *          붙이면 증명과 무관한 레코드까지 노출된다.
 * @return 증명이 서면 최소 레코드 집합, 아니면 None.
 */
pub fn nsec_nodata_proof(nsec_records: &[Record], qname: &Name, qtype: u16) -> Option<Vec<Record>> {
    if let Some(exact) = nsec_record_lacking_type(nsec_records, qname, qtype) {
        return Some(vec![exact.clone()]);
    }

    let (ce, ce_record) = nsec_closest_encloser_record(nsec_records, qname)?;
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let next_record = nsec_covering_record(nsec_records, &next_closer)?;
    let wildcard = wildcard_name(&ce)?;
    let wildcard_record = nsec_record_lacking_type(nsec_records, &wildcard, qtype)?;
    Some(unique_records([ce_record, next_record, wildcard_record]))
}

/**
 * @brief 이름 자체가 존재하지 않음(NXDOMAIN)을 NSEC으로 증명한다.
 * @details closest encloser를 찾고, next closer와 그 아래 와일드카드가 둘 다 덮여야
 *          한다. 와일드카드 증명이 없으면 실제로는 와일드카드가 답을 주는 이름을
 *          NXDOMAIN으로 위조할 수 있다.
 */
pub fn prove_name_nonexistent(nsec_records: &[Record], qname: &Name) -> bool {
    let Some((ce, _)) = nsec_closest_encloser_record(nsec_records, qname) else {
        return false;
    };
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let Some(wildcard) = wildcard_name(&ce) else {
        return false;
    };
    nsec_covering_record(nsec_records, &next_closer).is_some()
        && nsec_covering_record(nsec_records, &wildcard).is_some()
}

/**
 * @brief prove_name_nonexistent와 같은 판정을 하되 쓰인 레코드를 돌려준다.
 * @return 증명이 서면 중복을 제거한 최소 레코드 집합, 아니면 None.
 */
pub fn nsec_name_nonexistent_proof(nsec_records: &[Record], qname: &Name) -> Option<Vec<Record>> {
    let (ce, ce_record) = nsec_closest_encloser_record(nsec_records, qname)?;
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let next_record = nsec_covering_record(nsec_records, &next_closer)?;
    let wildcard = wildcard_name(&ce)?;
    let wildcard_record = nsec_covering_record(nsec_records, &wildcard)?;
    Some(unique_records([ce_record, next_record, wildcard_record]))
}

/**
 * @brief 이 응답이 정말 와일드카드 확장으로 나왔음을 증명한다.
 *
 * @details 와일드카드로 만들어진 답에는 next closer가 존재하지 않는다는 NSEC이 따라와야
 *          한다. 그게 없으면 실제로 존재하는 더 구체적인 이름을 숨기고 와일드카드 답으로
 *          교체할 수 있다.
 * @param closest_encloser_labels RRSIG의 labels 필드에서 얻은 closest encloser 라벨 수.
 * @return 증명되면 참. 라벨 수가 qname보다 짧지 않으면 확장 자체가 성립하지 않아 거짓이다.
 */
pub fn prove_wildcard_expansion(
    nsec_records: &[Record],
    qname: &Name,
    closest_encloser_labels: usize,
) -> bool {
    nsec_wildcard_expansion_proof(nsec_records, qname, closest_encloser_labels).is_some()
}

/**
 * @brief 와일드카드 확장 판정에 실제로 필요한 NSEC 하나만 고른다.
 * @details 서명 검증 전에 이 선택을 하면 응답의 무관한 NSEC/RRSIG가 공개키 연산을
 *          강제하지 못한다. 선택 결과는 아직 신뢰되지 않았으므로 호출자가 서명을 검증해야 한다.
 */
pub fn nsec_wildcard_expansion_proof(
    nsec_records: &[Record],
    qname: &Name,
    closest_encloser_labels: usize,
) -> Option<Vec<Record>> {
    if closest_encloser_labels >= qname.num_labels() {
        return None;
    }
    let next_closer = qname.suffix(closest_encloser_labels + 1);
    nsec_covering_record(nsec_records, &next_closer).map(|record| vec![record.clone()])
}

/**
 * @brief qname의 조상 중 NSEC이 존재하는 가장 긴 것(closest encloser)을 찾는다.
 * @details 긴 접미사부터 훑어 첫 일치를 쓴다. 더 짧은 조상을 골라도 NSEC은 존재하지만,
 *          그러면 next closer가 달라져 증명이 헐거워진다.
 */
fn nsec_closest_encloser_record<'a>(
    nsec_records: &'a [Record],
    qname: &Name,
) -> Option<(Name, &'a Record)> {
    (0..qname.num_labels()).rev().find_map(|labels| {
        let candidate = qname.suffix(labels);
        nsec_records
            .iter()
            .find(|record| {
                record.rtype == RecordType::NSEC
                    && record.name.eq_ignore_case(&candidate)
                    && Nsec::from_record(record).is_some()
            })
            .map(|record| (candidate, record))
    })
}

/** @brief 이 이름을 구간으로 덮는 첫 NSEC 레코드. */
fn nsec_covering_record<'a>(nsec_records: &'a [Record], name: &Name) -> Option<&'a Record> {
    nsec_records.iter().find(|record| {
        record.rtype == RecordType::NSEC
            && Nsec::from_record(record)
                .is_some_and(|nsec| nsec_covers(&record.name, &nsec.next, name))
    })
}

/**
 * @brief 이 이름과 정확히 일치하면서 해당 타입도 CNAME도 갖지 않는 NSEC.
 * @details CNAME까지 함께 보는 이유는, CNAME이 있으면 그 타입 질의도 CNAME을 따라가
 *          답이 나오기 때문이다. CNAME을 빠뜨리면 NODATA가 아닌 것을 NODATA라 하게 된다.
 */
fn nsec_record_lacking_type<'a>(
    nsec_records: &'a [Record],
    name: &Name,
    qtype: u16,
) -> Option<&'a Record> {
    nsec_records.iter().find(|record| {
        record.rtype == RecordType::NSEC
            && record.name.eq_ignore_case(name)
            && Nsec::from_record(record)
                .is_some_and(|nsec| !nsec.has_type(qtype) && !nsec.has_type(RecordType::CNAME.0))
    })
}

/**
 * @brief 증명 레코드들을 중복 없이 모은다.
 * @details 한 NSEC이 closest encloser·next closer·와일드카드 역할을 겸할 수 있어, 그대로
 *          모으면 같은 레코드가 응답에 두세 번 담긴다. TTL은 비교에서 제외한다.
 */
fn unique_records<const N: usize>(records: [&Record; N]) -> Vec<Record> {
    let mut unique = Vec::with_capacity(N);
    for record in records {
        if !unique.iter().any(|candidate: &Record| {
            candidate.class == record.class
                && candidate.rtype == record.rtype
                && candidate.name.eq_ignore_case(&record.name)
                && candidate.rdata == record.rdata
        }) {
            unique.push(record.clone());
        }
    }
    unique
}

/**
 * @brief encloser 앞에 * 라벨을 붙인 와일드카드 이름.
 * @note 라벨 옥텟을 그대로 옮긴다. 문자열로 만들었다 되돌리면 비ASCII 라벨이 손상돼
 *       증명 대상과 다른 이름이 된다.
 * @return 255옥텟 상한을 넘기면 None.
 */
fn wildcard_name(encloser: &Name) -> Option<Name> {
    let mut labels = Vec::with_capacity(encloser.labels().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend(encloser.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).ok()
}

/** @brief base32hex 알파벳(RFC 4648). NSEC3 소유자 라벨은 소문자로 쓴다. */
const BASE32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/** @brief 외부 zone의 NSEC3에서 절대로 넘길 수 없는 반복 횟수 하드 상한. */
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

/**
 * @brief 부재 증명 하나가 쓸 수 있는 SHA-1 호출 총량.
 * @details 이름 해시 하나는 iterations+1회 SHA-1을 쓴다. 반복 상한만 두면 깊은 QNAME의
 *          closest-encloser 탐색과 곱해지므로, 둘의 곱도 8,192회에서 fail-closed한다.
 */
const MAX_NSEC3_HASH_ROUNDS: usize = 8_192;

#[derive(Default)]
/** @brief 한 NSEC3 증명·캐시 후보 탐색 전체가 공유하는 실제 SHA-1 라운드 예산. */
pub struct Nsec3HashBudget {
    used: usize,
}

impl Nsec3HashBudget {
    /** @brief 이름 해시 비용을 예약하고 남으면 실제 해시를 수행한다. */
    pub fn hash(&mut self, name: &Name, salt: &[u8], iterations: u16) -> Option<Vec<u8>> {
        let rounds = usize::from(iterations) + 1;
        let next = self.used.checked_add(rounds)?;
        if next > MAX_NSEC3_HASH_ROUNDS {
            return None;
        }
        self.used = next;
        Some(nsec3_hash(name, salt, iterations))
    }
}

#[cfg(test)]
thread_local! {
    /** @brief 한 스레드에서 실제 NSEC3 이름 해시를 계산한 횟수. */
    static NSEC3_HASH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /** @brief 한 스레드에서 NSEC3 RDATA를 완전히 파싱한 횟수. */
    static NSEC3_PARSE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/**
 * @brief NSEC3 소유자 해시(RFC 5155).
 *
 * @details SHA1(정규형 이름 ‖ salt)을 구한 뒤, SHA1(직전 해시 ‖ salt)를 iterations회
 *          더 돌린다. 반복 0회도 최초 1회는 반드시 수행한다.
 * @warning 반복 횟수는 질의자가 아니라 zone이 정한다. 이 저수준 함수를 직접 부르는 코드는
 *          상한을 책임져야 한다. 부재 증명 공개 API는 반복 150·총 8,192 SHA 라운드를 강제한다.
 * @note SHA-1은 RFC 5155가 정한 유일한 알고리즘이라 선택지가 없다. 여기서는 충돌 내성이
 *       아니라 이름 은닉이 목적이다.
 */
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
    #[cfg(test)]
    NSEC3_HASH_CALLS.with(|calls| calls.set(calls.get() + 1));
    use sha1::{Digest, Sha1};
    let mut wire = Vec::new();
    canonical_name_into(name, &mut wire);
    let mut hash = {
        let mut h = Sha1::new();
        h.update(&wire);
        h.update(salt);
        h.finalize().to_vec()
    };
    for _ in 0..iterations {
        let mut h = Sha1::new();
        h.update(&hash);
        h.update(salt);
        hash = h.finalize().to_vec();
    }
    hash
}

/**
 * @brief base32hex 인코딩. 패딩(=)은 붙이지 않는다.
 * @note NSEC3 소유자 라벨은 20바이트 고정이라 패딩이 필요 없고, DNS 이름에 =를 넣을
 *       수도 없다.
 */
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc = 0u64;
    let mut nbits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u64;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(BASE32HEX[((acc >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(BASE32HEX[((acc << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/**
 * @brief base32hex 디코딩. 대소문자를 모두 받는다.
 * @details 남은 비트가 5 이상이면 옥텟 하나를 더 낼 수 있었다는 뜻이라 길이가 틀린 것이고,
 *          남은 비트가 0이 아니면 패딩 곳에 값이 들어간 것이다. 둘 다 거부한다. 같은
 *          해시를 여러 문자열로 표현할 수 있으면 소유자 비교가 뚫린다.
 * @return 알파벳 밖 문자나 위 두 조건에 걸리면 None.
 */
fn base32hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc = 0u64;
    let mut nbits = 0u32;
    for &c in s {
        let v = u64::from(base32hex_value(c)?);
        acc = (acc << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xff) as u8);
        }
    }
    if nbits >= 5 || nbits > 0 && acc & ((1u64 << nbits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/** @brief base32hex 문자 하나의 5비트 값. */
fn base32hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'v' => Some(c - b'a' + 10),
        b'A'..=b'V' => Some(c - b'A' + 10),
        _ => None,
    }
}

/**
 * @brief NSEC/NSEC3의 타입 비트맵을 타입 번호 목록으로 푼다.
 *
 * @details 윈도우 블록의 연속이다. 정규형을 강제한다. 윈도우 번호는 엄격히 증가해야
 *          하고, 블록 길이는 1..=32이며, 마지막 옥텟이 0이면 안 된다. 같은 타입 집합을
 *          여러 바이트열로 표현할 수 있으면 서명 검증을 통과한 비트맵과 이 서버가 읽은
 *          비트맵이 달라질 수 있다.
 * @return 형식이 어긋나면 None. 부재 증명에 쓰이므로 애매한 입력은 통과시키지 않는다.
 */
fn parse_type_bitmaps(bitmap: &[u8]) -> Option<Vec<u16>> {
    let mut types = Vec::new();
    let mut i = 0usize;
    let mut previous_window: Option<u8> = None;
    while i < bitmap.len() {
        let window = *bitmap.get(i)?;
        let len = *bitmap.get(i + 1)? as usize;
        if !(1..=32).contains(&len) || previous_window.is_some_and(|previous| window <= previous) {
            return None;
        }
        i += 2;
        let block = bitmap.get(i..i + len)?;
        if block.last() == Some(&0) {
            return None;
        }
        for (j, &byte) in block.iter().enumerate() {
            for bit in 0..8u16 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(u16::from(window) * 256 + (j as u16) * 8 + bit);
                }
            }
        }
        previous_window = Some(window);
        i += len;
    }
    Some(types)
}

/** @brief 타입 비트맵의 정규형만 무할당으로 검사한다. */
fn type_bitmaps_valid(bitmap: &[u8]) -> bool {
    let mut i = 0usize;
    let mut previous_window = None;
    while i < bitmap.len() {
        let Some((&window, rest)) = bitmap.get(i..).and_then(|bytes| bytes.split_first()) else {
            return false;
        };
        let Some((&len, _)) = rest.split_first() else {
            return false;
        };
        let len = usize::from(len);
        if !(1..=32).contains(&len) || previous_window.is_some_and(|previous| window <= previous) {
            return false;
        }
        i += 2;
        let Some(block) = bitmap.get(i..i + len) else {
            return false;
        };
        if block.last() == Some(&0) {
            return false;
        }
        previous_window = Some(window);
        i += len;
    }
    true
}

/** @brief 검증된 타입 비트맵에 특정 RR 타입이 있는지 무할당으로 찾는다. */
fn type_bitmap_has(bitmap: &[u8], rtype: u16) -> bool {
    let wanted_window = (rtype >> 8) as u8;
    let wanted_bit = usize::from(rtype & 0xff);
    let mut i = 0usize;
    while i < bitmap.len() {
        let window = bitmap[i];
        let len = usize::from(bitmap[i + 1]);
        i += 2;
        if window == wanted_window {
            return bitmap
                .get(i + wanted_bit / 8)
                .is_some_and(|byte| byte & (0x80 >> (wanted_bit % 8)) != 0);
        }
        if window > wanted_window {
            return false;
        }
        i += len;
    }
    false
}

/**
 * @brief NSEC3 레코드: 이름을 해시한 공간에서의 부재 증명.
 * @details NSEC이 zone의 실제 이름을 그대로 드러내는(zone walking) 문제를 해시로 가린다.
 *          대신 매개변수(알고리즘·salt·반복)가 증명 전체에서 일치해야 한다.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    /** @brief 해시 알고리즘. RFC 5155는 SHA-1(1)만 정의한다. */
    pub hash_alg: u8,
    /** @brief 최하위 비트가 opt-out 플래그다. 나머지는 예약. */
    pub flags: u8,
    /** @brief 추가 해시 반복 횟수. 검증기가 그대로 따라 계산해야 한다. */
    pub iterations: u16,
    /** @brief 사전 계산 공격을 늦추는 salt. */
    pub salt: Vec<u8>,
    /** @brief 해시 순서상 다음 소유자 해시. 이 구간이 비어 있음을 주장한다. */
    pub next_hashed: Vec<u8>,
    /** @brief 이 소유자 이름에 존재하는 RR 타입들. */
    pub types: Vec<u16>,
}

impl Nsec3 {
    /**
     * @brief NSEC3 RDATA를 파싱한다.
     * @note salt와 해시는 길이 접두사를 갖는다. 남은 바이트 전체가 타입 비트맵이다.
     */
    pub fn parse(raw: &[u8]) -> Option<Nsec3> {
        #[cfg(test)]
        NSEC3_PARSE_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut r = Reader::new(raw);
        let hash_alg = r.u8().ok()?;
        let flags = r.u8().ok()?;
        let iterations = r.u16().ok()?;
        let salt_len = r.u8().ok()? as usize;
        let salt = r.bytes(salt_len).ok()?.to_vec();
        let hash_len = r.u8().ok()? as usize;
        let next_hashed = r.bytes(hash_len).ok()?.to_vec();
        let types = parse_type_bitmaps(raw.get(r.pos..)?)?;
        Some(Nsec3 {
            hash_alg,
            flags,
            iterations,
            salt,
            next_hashed,
            types,
        })
    }

    /** @brief 레코드에서 NSEC3을 꺼낸다. 미해석 RDATA로 보관돼 있어야 한다. */
    pub fn from_record(rec: &Record) -> Option<Nsec3> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Nsec3::parse(raw),
            _ => None,
        }
    }

    /** @brief 이 소유자 이름에 해당 타입이 존재한다고 비트맵이 말하는지. */
    pub fn has_type(&self, t: u16) -> bool {
        self.types.contains(&t)
    }
}

/** @brief 증명 hot path가 원본 RDATA에서 빌려 쓰는 무할당 NSEC3 view. */
#[derive(Clone, Copy)]
struct Nsec3Ref<'a> {
    hash_alg: u8,
    flags: u8,
    iterations: u16,
    salt: &'a [u8],
    next_hashed: &'a [u8],
    type_bitmap: &'a [u8],
}

impl<'a> Nsec3Ref<'a> {
    /** @brief 전체 형식을 검사하되 가변 필드는 원본 RDATA에서 빌린다. */
    fn from_record(record: &'a Record) -> Option<Self> {
        let RData::Unknown(_, raw) = &record.rdata else {
            return None;
        };
        #[cfg(test)]
        NSEC3_PARSE_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut reader = Reader::new(raw);
        let hash_alg = reader.u8().ok()?;
        let flags = reader.u8().ok()?;
        let iterations = reader.u16().ok()?;
        let salt_len = usize::from(reader.u8().ok()?);
        let salt = reader.bytes(salt_len).ok()?;
        let hash_len = usize::from(reader.u8().ok()?);
        let next_hashed = reader.bytes(hash_len).ok()?;
        let type_bitmap = raw.get(reader.pos..)?;
        if !type_bitmaps_valid(type_bitmap) {
            return None;
        }
        Some(Self {
            hash_alg,
            flags,
            iterations,
            salt,
            next_hashed,
            type_bitmap,
        })
    }

    /** @brief 타입 비트맵에 RR 타입이 있는지. */
    fn has_type(self, rtype: u16) -> bool {
        type_bitmap_has(self.type_bitmap, rtype)
    }
}

/** @brief base32hex_decode의 크레이트 외부 노출용 얇은 껍데기. */
pub fn base32hex_decode_pub(s: &[u8]) -> Option<Vec<u8>> {
    base32hex_decode(s)
}

/** @brief hash_covers의 크레이트 외부 노출용 얇은 껍데기. */
pub fn hash_covers_pub(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    hash_covers(owner, next, q)
}

/**
 * @brief NSEC3 레코드의 소유자 해시. 첫 라벨을 base32hex로 푼 값이다.
 * @note 첫 라벨만 본다. 나머지는 zone 이름이라 해시가 아니다.
 */
fn nsec3_owner_hash_fixed(rec: &Record) -> Option<[u8; 20]> {
    let label = rec.name.labels().first()?;
    if label.len() != 32 {
        return None;
    }
    let mut owner = [0u8; 20];
    let mut acc = 0u32;
    let mut nbits = 0u32;
    let mut out = 0usize;
    for &c in label {
        acc = (acc << 5) | u32::from(base32hex_value(c)?);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            owner[out] = ((acc >> nbits) & 0xff) as u8;
            out += 1;
        }
    }
    (out == owner.len() && nbits == 0).then_some(owner)
}

/** @brief 소유자 해시를 소유 벡터로 돌려주는 서명·테스트 호환 경로. */
#[cfg(test)]
fn nsec3_owner_hash(rec: &Record) -> Option<Vec<u8>> {
    Some(nsec3_owner_hash_fixed(rec)?.to_vec())
}

/**
 * @brief 해시 구간 (owner, next)가 q를 덮는지. 양 끝은 포함하지 않는다.
 * @details NSEC과 같은 이유로 zone 마지막 NSEC3은 되감긴다(next <= owner). 그때는 두
 *          조건 중 하나만 맞아도 덮는 것으로 본다.
 */
fn hash_covers(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    if owner < next {
        owner < q && q < next
    } else {
        owner < q || q < next
    }
}

/**
 * @brief 이 증명 집합이 요구하는 최대 해시 반복 횟수.
 * @details 호출자가 검증을 시작하기 전에 상한과 견주라고 있는 함수다. 반복 횟수는
 *          질의 하나당 이 서버의 CPU 비용을 그대로 정하므로, 확인 없이 계산에 들어가면
 *          zone 하나가 자원 소진 공격을 성립시킨다.
 */
pub fn nsec3_max_iterations(nsec3_records: &[Record]) -> u16 {
    nsec3_records
        .iter()
        .filter(|r| r.rtype == RecordType::NSEC3)
        .filter_map(|record| match &record.rdata {
            RData::Unknown(_, raw) => {
                let bytes = raw.get(2..4)?;
                Some(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/** @brief 한 번 파싱·검증한 NSEC3과 원본 레코드·소유자 해시. */
struct ValidatedNsec3Record<'a> {
    source: &'a Record,
    parsed: Nsec3Ref<'a>,
    owner: [u8; 20],
}

/** @brief 한 부재 증명에서 공통 매개변수를 검증하고 재사용하는 NSEC3 집합. */
struct ValidatedNsec3Set<'a> {
    records: Vec<ValidatedNsec3Record<'a>>,
}

/** @brief exact 한 레코드 또는 closest·next·wildcard 세 레코드의 NODATA 선택. */
enum Nsec3NodataSelection<'a> {
    Exact(&'a Record),
    Expanded([&'a Record; 3]),
}

/** @brief NXDOMAIN 최소 증명과 next-closer가 opt-out에만 기대는지. */
struct Nsec3NameSelection<'a> {
    records: [&'a Record; 3],
    relies_on_opt_out: bool,
}

impl Nsec3NodataSelection<'_> {
    /** @brief 외부 API가 소유할 최소 중복 제거 증명으로 바꾼다. */
    fn into_records(self) -> Vec<Record> {
        match self {
            Self::Exact(record) => vec![record.clone()],
            Self::Expanded(records) => unique_records(records),
        }
    }
}

impl<'a> ValidatedNsec3Set<'a> {
    /** @brief 각 RDATA를 정확히 한 번 파싱하며 하나의 온전한 해시 공간인지 확인한다. */
    fn new(records: &'a [Record], qname: &Name) -> Option<Self> {
        let mut prepared = Vec::with_capacity(records.len());
        let mut expected: Option<(u16, &'a [u8], Name)> = None;
        for record in records
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
        {
            let parsed = Nsec3Ref::from_record(record)?;
            let owner = nsec3_owner_hash_fixed(record)?;
            if parsed.hash_alg != 1
                || parsed.flags & !1 != 0
                || parsed.iterations > MAX_NSEC3_ITERATIONS
                || parsed.next_hashed.len() != 20
                || record.name.num_labels() == 0
            {
                return None;
            }
            match &expected {
                Some((iterations, salt, expected_zone)) => {
                    if *iterations != parsed.iterations
                        || *salt != parsed.salt
                        || record.name.num_labels() != expected_zone.num_labels() + 1
                        || !name_is_within(&record.name, expected_zone)
                    {
                        return None;
                    }
                }
                None => {
                    let zone = record.name.suffix(record.name.num_labels() - 1);
                    if !name_is_within(qname, &zone) {
                        return None;
                    }
                    expected = Some((parsed.iterations, parsed.salt, zone));
                }
            }
            prepared.push(ValidatedNsec3Record {
                source: record,
                parsed,
                owner,
            });
        }
        (!prepared.is_empty()).then_some(Self { records: prepared })
    }

    /** @brief 검증된 공통 salt·반복 횟수로 이름을 한 번 해시한다. */
    fn query_hash(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<Vec<u8>> {
        let params = &self.records[0].parsed;
        budget.hash(name, params.salt, params.iterations)
    }

    /** @brief 이름은 존재하지만 qtype과 CNAME은 없다고 말하는 레코드. */
    fn record_lacking_type(
        &self,
        name: &Name,
        qtype: u16,
        budget: &mut Nsec3HashBudget,
    ) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| {
                record.owner == query_hash.as_slice()
                    && !record.parsed.has_type(qtype)
                    && !record.parsed.has_type(RecordType::CNAME.0)
            })
            .map(|record| record.source)
    }

    /** @brief 이름 해시와 owner가 같은 첫 레코드. */
    fn matching_record(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| record.owner == query_hash.as_slice())
            .map(|record| record.source)
    }

    /** @brief 이름 해시를 열린 구간으로 덮는 첫 레코드. */
    fn covering_record(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| hash_covers(&record.owner, record.parsed.next_hashed, &query_hash))
            .map(|record| record.source)
    }

    /** @brief 첫 covering 레코드와 모든 covering 구간이 opt-out인지 함께 구한다. */
    fn covering_record_with_opt_out_status(
        &self,
        name: &Name,
        budget: &mut Nsec3HashBudget,
    ) -> Option<(&'a Record, bool)> {
        let query_hash = self.query_hash(name, budget)?;
        let mut first = None;
        let mut only_opt_out = true;
        for record in &self.records {
            if !hash_covers(&record.owner, record.parsed.next_hashed, &query_hash) {
                continue;
            }
            first.get_or_insert(record.source);
            only_opt_out &= record.parsed.flags & 1 != 0;
        }
        Some((first?, only_opt_out))
    }

    /** @brief qname의 조상 중 owner가 일치하는 가장 긴 이름과 레코드. */
    fn closest_encloser_record(
        &self,
        qname: &Name,
        budget: &mut Nsec3HashBudget,
    ) -> Option<(Name, &'a Record)> {
        for labels in (0..qname.num_labels()).rev() {
            let candidate = qname.suffix(labels);
            if let Some(record) = self.matching_record(&candidate, budget) {
                return Some((candidate, record));
            }
        }
        None
    }

    /** @brief exact match가 없을 때만 wildcard 해시를 덮는 레코드를 돌려준다. */
    fn covering_record_unless_matched(
        &self,
        name: &Name,
        budget: &mut Nsec3HashBudget,
    ) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        let mut covering = None;
        for record in &self.records {
            if record.owner == query_hash.as_slice() {
                return None;
            }
            if covering.is_none()
                && hash_covers(&record.owner, record.parsed.next_hashed, &query_hash)
            {
                covering = Some(record.source);
            }
        }
        covering
    }

    /** @brief opt-out 비트가 켜진 구간으로 이름을 덮는 첫 레코드. */
    fn covering_record_with_opt_out(
        &self,
        name: &Name,
        budget: &mut Nsec3HashBudget,
    ) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| {
                record.parsed.flags & 1 != 0
                    && hash_covers(&record.owner, record.parsed.next_hashed, &query_hash)
            })
            .map(|record| record.source)
    }

    /** @brief 이름이 opt-out 구간으로만 덮이는지 한 번의 해시·스캔으로 판정한다. */
    fn denial_relies_on_opt_out(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<bool> {
        let query_hash = self.query_hash(name, budget)?;
        let mut covered = false;
        for record in &self.records {
            if !hash_covers(&record.owner, record.parsed.next_hashed, &query_hash) {
                continue;
            }
            covered = true;
            if record.parsed.flags & 1 == 0 {
                return Some(false);
            }
        }
        Some(covered)
    }
}

/**
 * @brief NSEC3으로 NODATA를 증명한다.
 * @details 구조는 NSEC 버전과 같되, 먼저 ValidatedNsec3Set으로 매개변수 일관성과 반복 하드
 *          상한을 확인한다. 해시 매개변수가 섞인 집합은 서로 다른 해시 공간의 주장을 한데
 *          모은 것이라 증명이 성립하지 않는다.
 */
pub fn prove_nodata_nsec3(nsec3_records: &[Record], qname: &Name, qtype: u16) -> bool {
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    nsec3_nodata_selection(&prepared, qname, qtype, &mut budget).is_some()
}

/**
 * @brief prove_nodata_nsec3와 같은 판정을 하되 쓰인 레코드를 돌려준다.
 * @return 증명이 서면 중복을 제거한 최소 레코드 집합, 아니면 None.
 */
pub fn nsec3_nodata_proof(
    nsec3_records: &[Record],
    qname: &Name,
    qtype: u16,
) -> Option<Vec<Record>> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    Some(nsec3_nodata_selection(&prepared, qname, qtype, &mut budget)?.into_records())
}

/** @brief 준비된 한 NSEC3 집합에서 NODATA 최소 증명을 고른다. */
fn nsec3_nodata_selection<'a>(
    prepared: &ValidatedNsec3Set<'a>,
    qname: &Name,
    qtype: u16,
    budget: &mut Nsec3HashBudget,
) -> Option<Nsec3NodataSelection<'a>> {
    if let Some(exact) = prepared.record_lacking_type(qname, qtype, budget) {
        return Some(Nsec3NodataSelection::Exact(exact));
    }

    let (ce, ce_record) = prepared.closest_encloser_record(qname, budget)?;
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let next_record = prepared.covering_record(&next_closer, budget)?;
    let wildcard = wildcard_name(&ce)?;
    let wildcard_record = prepared.record_lacking_type(&wildcard, qtype, budget)?;
    Some(Nsec3NodataSelection::Expanded([
        ce_record,
        next_record,
        wildcard_record,
    ]))
}

/**
 * @brief 자식 zone에 DS가 없음을 NSEC3으로 증명한다.
 * @details 보통의 NODATA 증명을 먼저 시도하고, 실패하면 opt-out 경로를 본다. opt-out
 *          구간에 덮이면 서명되지 않은 위임이 그 안에 있을 수 있다는 뜻이라, 개별 NSEC3
 *          없이도 DS 부재가 성립한다. DS에만 허용되는 완화이며 다른 부재 증명에
 *          끌어다 쓰면 안 된다.
 */
pub fn prove_ds_absence_nsec3(nsec3_records: &[Record], child_zone: &Name) -> bool {
    nsec3_ds_absence_proof(nsec3_records, child_zone).is_some()
}

/**
 * @brief DS 부재에 필요한 NSEC3만 고른다. opt-out 경로도 포함한다.
 * @warning 반환된 레코드는 구문상 증명일 뿐이다. 신뢰하기 전에 각 RRset 서명을 검증한다.
 */
pub fn nsec3_ds_absence_proof(nsec3_records: &[Record], child_zone: &Name) -> Option<Vec<Record>> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, child_zone)?;
    let mut budget = Nsec3HashBudget::default();
    if let Some(proof) =
        nsec3_nodata_selection(&prepared, child_zone, RecordType::DS.0, &mut budget)
    {
        return Some(proof.into_records());
    }
    let (ce, ce_record) = prepared.closest_encloser_record(child_zone, &mut budget)?;
    let next_closer = child_zone.suffix(ce.num_labels() + 1);
    let next_record = prepared.covering_record_with_opt_out(&next_closer, &mut budget)?;
    Some(unique_records([ce_record, next_record]))
}

/**
 * @brief 이름이 존재하지 않음을 NSEC3으로 증명한다.
 * @details 와일드카드에 대해 "덮임"뿐 아니라 "일치하는 NSEC3이 없음"까지 요구한다.
 *          일치가 있으면 와일드카드가 실재한다는 뜻이라 NXDOMAIN이 성립하지 않는다.
 */
pub fn prove_name_nonexistent_nsec3(nsec3_records: &[Record], qname: &Name) -> bool {
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    nsec3_name_nonexistent_selection(&prepared, qname, &mut budget).is_some()
}

/**
 * @brief prove_name_nonexistent_nsec3와 같은 판정을 하되 쓰인 레코드를 돌려준다.
 * @return 증명이 서면 중복을 제거한 최소 레코드 집합, 아니면 None.
 */
pub fn nsec3_name_nonexistent_proof(nsec3_records: &[Record], qname: &Name) -> Option<Vec<Record>> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    let selection = nsec3_name_nonexistent_selection(&prepared, qname, &mut budget)?;
    Some(unique_records(selection.records))
}

/** @brief NXDOMAIN 최소 증명과 opt-out 의존 여부를 같은 해시 예산·스캔으로 구한다. */
pub fn nsec3_name_nonexistent_proof_status(
    nsec3_records: &[Record],
    qname: &Name,
) -> Option<(Vec<Record>, bool)> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    let selection = nsec3_name_nonexistent_selection(&prepared, qname, &mut budget)?;
    Some((
        unique_records(selection.records),
        selection.relies_on_opt_out,
    ))
}

/** @brief 준비된 집합에서 NXDOMAIN의 closest·next·wildcard 레코드를 고른다. */
fn nsec3_name_nonexistent_selection<'a>(
    prepared: &ValidatedNsec3Set<'a>,
    qname: &Name,
    budget: &mut Nsec3HashBudget,
) -> Option<Nsec3NameSelection<'a>> {
    let (ce, ce_record) = prepared.closest_encloser_record(qname, budget)?;
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let (next_record, relies_on_opt_out) =
        prepared.covering_record_with_opt_out_status(&next_closer, budget)?;
    let wildcard = wildcard_name(&ce)?;
    let wildcard_record = prepared.covering_record_unless_matched(&wildcard, budget)?;
    Some(Nsec3NameSelection {
        records: [ce_record, next_record, wildcard_record],
        relies_on_opt_out,
    })
}

/**
 * @brief 응답이 와일드카드 확장으로 나왔음을 NSEC3으로 증명한다.
 * @details closest encloser에 일치하는 NSEC3이 있고 next closer가 덮여야 한다.
 *          NSEC 버전과 달리 일치까지 요구하는 이유는, 해시 공간에서는 조상 존재 여부를
 *          덮임만으로 확인할 수 없기 때문이다.
 * @param closest_encloser_labels RRSIG의 labels 필드에서 얻은 closest encloser 라벨 수.
 */
pub fn prove_wildcard_expansion_nsec3(
    nsec3_records: &[Record],
    qname: &Name,
    closest_encloser_labels: usize,
) -> bool {
    if closest_encloser_labels >= qname.num_labels() {
        return false;
    }
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    nsec3_wildcard_expansion_selection(&prepared, qname, closest_encloser_labels, &mut budget)
        .is_some()
}

/**
 * @brief 와일드카드 확장에 실제로 필요한 NSEC3 RRset만 고른다.
 * @return closest-encloser 일치와 next-closer 덮임 레코드의 중복 없는 최소 집합.
 * @note 반복 150·증명당 8,192 SHA 라운드 하드 상한은 내부에서 해시 전에 적용한다.
 */
pub fn nsec3_wildcard_expansion_proof(
    nsec3_records: &[Record],
    qname: &Name,
    closest_encloser_labels: usize,
) -> Option<Vec<Record>> {
    if closest_encloser_labels >= qname.num_labels() {
        return None;
    }
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    Some(unique_records(nsec3_wildcard_expansion_selection(
        &prepared,
        qname,
        closest_encloser_labels,
        &mut budget,
    )?))
}

/** @brief 준비된 집합에서 wildcard closest·next 레코드를 고른다. */
fn nsec3_wildcard_expansion_selection<'a>(
    prepared: &ValidatedNsec3Set<'a>,
    qname: &Name,
    closest_encloser_labels: usize,
    budget: &mut Nsec3HashBudget,
) -> Option<[&'a Record; 2]> {
    let closest_encloser = qname.suffix(closest_encloser_labels);
    let next_closer = qname.suffix(closest_encloser_labels + 1);
    let closest_record = prepared.matching_record(&closest_encloser, budget)?;
    let next_record = prepared.covering_record(&next_closer, budget)?;
    Some([closest_record, next_record])
}

/** @brief 이름이 zone 안에 있는지(자기 자신 포함). */
fn name_is_within(name: &Name, zone: &Name) -> bool {
    name.ends_with_ignore_case(zone)
}

/**
 * @brief 이 부재 판정이 opt-out에 기대고 있는지.
 * @details opt-out 구간에 기댄 증명은 "이 이름이 없다"가 아니라 "있더라도 서명되지
 *          않았다"까지만 말한다. 호출자가 그 결과를 Secure가 아닌 Insecure로 낮춰야 하므로,
 *          증명 성립 여부와 별개로 이 사실을 알려 준다.
 */
pub fn nsec3_denial_relies_on_opt_out(nsec3_records: &[Record], qname: &Name) -> bool {
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    let Some((ce, _)) = prepared.closest_encloser_record(qname, &mut budget) else {
        return false;
    };
    let next_closer = qname.suffix(ce.num_labels() + 1);
    prepared
        .denial_relies_on_opt_out(&next_closer, &mut budget)
        .unwrap_or(false)
}

/**
 * @brief RFC 4034에 따라 서명 대상 옥텟열을 만든다.
 *
 * @details 서명자와 검증자가 바이트 단위로 같은 것을 만들어야 한다. 그래서 정규형이
 *          네 가지를 강제한다. 소유자 이름은 소문자, RDATA는 정규 순서로 정렬,
 *          TTL은 수신 TTL이 아니라 RRSIG의 original_ttl, 레코드 타입은 각 레코드의
 *          것이 아니라 type_covered. 수신 TTL을 쓰면 캐시를 거친 순간 검증이 깨진다.
 * @param rrsig 서명 매개변수. 헤더가 그대로 앞에 붙고, 본문 구성도 여기서 정해진다.
 * @param rrset 서명 대상 레코드들.
 * @return 서명·검증에 그대로 넣을 옥텟열.
 */
pub fn signed_data(rrsig: &Rrsig, rrset: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    out.push(rrsig.algorithm);
    out.push(rrsig.labels);
    out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    out.extend_from_slice(&rrsig.expiration.to_be_bytes());
    out.extend_from_slice(&rrsig.inception.to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    canonical_name_into(&rrsig.signer, &mut out);

    let mut items: Vec<(Vec<u8>, &Record)> = rrset
        .iter()
        .map(|r| (canonical_rdata(&r.rdata), r))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));

    for (crdata, rec) in &items {
        let owner = owner_for_signing(&rec.name, rrsig.labels);
        canonical_name_into(&owner, &mut out);
        out.extend_from_slice(&rrsig.type_covered.to_be_bytes());
        out.extend_from_slice(&rec.class.0.to_be_bytes());
        out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        out.extend_from_slice(&(crdata.len() as u16).to_be_bytes());
        out.extend_from_slice(crdata);
    }
    out
}

/**
 * @brief 서명 대상에 쓸 소유자 이름: 와일드카드 확장이면 원래 * 형태로 되돌린다.
 * @details RRSIG의 labels가 실제 이름보다 짧으면 그 답은 와일드카드에서 확장된 것이다.
 *          서명은 확장된 이름이 아니라 *.<encloser> 위에 만들어졌으므로, 검증도 같은
 *          이름으로 되돌려야 한다.
 * @return 이름 구성에 실패하면 원래 이름을 그대로 돌려준다. 어차피 서명 검증이 실패해
 *         fail-closed로 끝난다.
 */
fn owner_for_signing(name: &Name, labels: u8) -> Name {
    let labels = labels as usize;
    if name.num_labels() > labels {
        let suffix = name.suffix(labels);
        let mut owner_labels = Vec::with_capacity(suffix.labels().len() + 1);
        owner_labels.push(b"*".to_vec());
        owner_labels.extend(suffix.labels().map(<[u8]>::to_vec));
        Name::from_labels(owner_labels).unwrap_or_else(|_| name.clone())
    } else {
        name.clone()
    }
}

/**
 * @brief 이름을 정규형(비압축·소문자)으로 이어 붙인다.
 * @note 압축 포인터를 쓰지 않는다. 서명 대상은 메시지 위치에 의존하면 안 되기 때문이다.
 */
fn canonical_name_into(name: &Name, out: &mut Vec<u8>) {
    for label in name.labels() {
        out.push(label.len() as u8);
        for &b in label {
            out.push(b.to_ascii_lowercase());
        }
    }
    out.push(0);
}

/**
 * @brief RDATA를 정규형 옥텟열로 만든다.
 * @details RFC 4034가 지정한 타입(NS/CNAME/SOA/MX/PTR/SRV 등)만 이름을 소문자로
 *          내린다. 목록 밖 타입의 이름을 임의로 소문자화하면 서명자와 결과가 달라진다.
 * @note 미해석 RDATA는 받은 바이트를 그대로 쓴다. 이 서버가 해석하지 못하는 타입도 서명
 *       검증은 되어야 한다.
 */
pub fn canonical_rdata(rd: &RData) -> Vec<u8> {
    let mut out = Vec::new();
    match rd {
        RData::A(ip) => out.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        RData::Ns(n) | RData::Cname(n) | RData::Dname(n) | RData::Ptr(n) => {
            canonical_name_into(n, &mut out)
        }
        RData::Mx {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            canonical_name_into(exchange, &mut out);
        }
        RData::Txt(chunks) => {
            for c in chunks {
                out.push(c.len() as u8);
                out.extend_from_slice(c);
            }
        }
        RData::Soa(s) => {
            canonical_name_into(&s.mname, &mut out);
            canonical_name_into(&s.rname, &mut out);
            out.extend_from_slice(&s.serial.to_be_bytes());
            out.extend_from_slice(&s.refresh.to_be_bytes());
            out.extend_from_slice(&s.retry.to_be_bytes());
            out.extend_from_slice(&s.expire.to_be_bytes());
            out.extend_from_slice(&s.minimum.to_be_bytes());
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            canonical_name_into(target, &mut out);
        }
        RData::Caa { flags, tag, value } => {
            out.push(*flags);
            out.push(tag.len() as u8);
            out.extend_from_slice(tag);
            out.extend_from_slice(value);
        }
        RData::Tlsa {
            usage,
            selector,
            matching,
            data,
        } => {
            out.push(*usage);
            out.push(*selector);
            out.push(*matching);
            out.extend_from_slice(data);
        }
        RData::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        } => {
            out.push(*algorithm);
            out.push(*fp_type);
            out.extend_from_slice(fingerprint);
        }
        RData::Naptr(naptr) => {
            out.extend_from_slice(&naptr.order.to_be_bytes());
            out.extend_from_slice(&naptr.preference.to_be_bytes());
            for s in [&naptr.flags, &naptr.services, &naptr.regexp] {
                out.push(s.len() as u8);
                out.extend_from_slice(s);
            }
            canonical_name_into(&naptr.replacement, &mut out);
        }
        RData::Uri {
            priority,
            weight,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(target);
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
            out.extend_from_slice(&priority.to_be_bytes());

            for label in target.labels() {
                out.push(label.len() as u8);
                out.extend_from_slice(label);
            }
            out.push(0);
            for (key, val) in params {
                out.extend_from_slice(&key.to_be_bytes());
                out.extend_from_slice(&(val.len() as u16).to_be_bytes());
                out.extend_from_slice(val);
            }
        }
        RData::Unknown(_, raw) => out.extend_from_slice(raw),
    }
    out
}

/** @brief ZONEMD RR 타입 번호(RFC 8976). */
pub const ZONEMD_TYPE: u16 = 63;

/**
 * @brief ZONEMD 레코드: zone 전체의 다이제스트.
 * @details 전송(AXFR/파일)받은 zone이 온전한지 검사한다. RRSIG가 RRset 단위 진위를
 *          보증하는 것과 달리, 이쪽은 zone에서 레코드가 전부 빠졌는지를 잡는다.
 */
pub struct Zonemd {
    /** @brief 이 다이제스트가 대상으로 삼은 SOA serial. 다르면 계산해 볼 필요도 없다. */
    pub serial: u32,
    /** @brief 다이제스트 구성 방식. RFC 8976은 SIMPLE(1)만 정의한다. */
    pub scheme: u8,
    /** @brief 해시 알고리즘. SHA-384(1) 또는 SHA-512(2). */
    pub hash_alg: u8,
    /** @brief 다이제스트 값. 길이는 알고리즘이 정한 것과 정확히 같아야 한다. */
    pub digest: Vec<u8>,
}

impl Zonemd {
    /**
     * @brief 레코드에서 ZONEMD를 꺼낸다.
     * @return 타입이 다르거나 고정 헤더 6바이트도 못 채우면 None.
     */
    pub fn from_record(rec: &Record) -> Option<Zonemd> {
        if rec.rtype.0 != ZONEMD_TYPE {
            return None;
        }
        let RData::Unknown(_, raw) = &rec.rdata else {
            return None;
        };
        if raw.len() < 6 {
            return None;
        }
        Some(Zonemd {
            serial: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            scheme: raw[4],
            hash_alg: raw[5],
            digest: raw[6..].to_vec(),
        })
    }
}

/** @brief ZONEMD 검사 결과. */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZonemdResult {
    /** @brief 다이제스트가 일치한다. zone이 온전하다. */
    Verified,

    /** @brief apex에 ZONEMD가 없다. 검사 대상이 아니다. */
    Absent,

    /** @brief 지원하는 ZONEMD가 있는데 어느 것도 맞지 않는다. zone을 받아들이면 안 된다. */
    Mismatch,

    /** @brief ZONEMD는 있으나 scheme·알고리즘·길이가 전부 이 서버가 모르는 것이다. */
    Unsupported,
}

/**
 * @brief zone의 ZONEMD를 검사한다.
 *
 * @details apex의 ZONEMD를 모두 훑어 하나라도 맞으면 Verified다. RFC 8976은 여러 개를
 *          둘 수 있게 하므로, 아는 것 하나만 맞으면 충분하다.
 * @note Unsupported와 Mismatch를 나누는 이유는 처분이 다르기 때문이다. 전자는 이 서버가
 *       검사할 수단이 없는 것이고, 후자는 zone이 실제로 어긋난 것이다.
 * @param soa_serial zone의 현재 SOA serial. ZONEMD의 serial과 다르면 그 레코드는 건너뛴다.
 */
pub fn verify_zonemd(records: &[Record], apex: &Name, soa_serial: u32) -> ZonemdResult {
    let zonemds: Vec<&Record> = records
        .iter()
        .filter(|r| r.rtype.0 == ZONEMD_TYPE && r.name.eq_ignore_case(apex))
        .collect();
    if zonemds.is_empty() {
        return ZonemdResult::Absent;
    }
    let mut any_supported = false;
    for z in &zonemds {
        let Some(zmd) = Zonemd::from_record(z) else {
            continue;
        };
        if zmd.scheme != 1 {
            continue;
        }
        let dlen = match zmd.hash_alg {
            1 => 48,
            2 => 64,
            _ => continue,
        };
        if zmd.digest.len() != dlen {
            continue;
        }
        any_supported = true;
        if zmd.serial != soa_serial {
            continue;
        }
        if let Some(c) = compute_zonemd_simple(records, apex, zmd.hash_alg) {
            if c == zmd.digest {
                return ZonemdResult::Verified;
            }
        }
    }
    if any_supported {
        ZonemdResult::Mismatch
    } else {
        ZonemdResult::Unsupported
    }
}

/**
 * @brief SIMPLE scheme(RFC 8976)으로 zone 다이제스트를 계산한다.
 *
 * @details apex의 ZONEMD와 그것을 덮는 RRSIG를 빼고, 나머지를 정규 순서(이름 → 타입 →
 *          RDATA)로 정렬해 이어 붙인 뒤 해시한다. 자기 자신을 넣으면 계산이 순환하므로
 *          제외가 정의의 일부다. 완전히 같은 레코드는 한 번만 넣는다.
 * @param hash_alg SHA-384(1) 또는 SHA-512(2).
 * @return 다이제스트. 지원하지 않는 알고리즘이면 None.
 */
pub fn compute_zonemd_simple(records: &[Record], apex: &Name, hash_alg: u8) -> Option<Vec<u8>> {
    use sha2::Digest;
    let mut incl: Vec<&Record> = records
        .iter()
        .filter(|r| {
            if r.name.eq_ignore_case(apex) && r.rtype.0 == ZONEMD_TYPE {
                return false;
            }
            if r.name.eq_ignore_case(apex) && r.rtype.0 == 46 {
                if let Some(sig) = Rrsig::from_record(r) {
                    if sig.type_covered == ZONEMD_TYPE {
                        return false;
                    }
                }
            }
            true
        })
        .collect();
    incl.sort_by(|a, b| {
        canonical_name_cmp(&a.name, &b.name)
            .then(a.rtype.0.cmp(&b.rtype.0))
            .then_with(|| canonical_rdata(&a.rdata).cmp(&canonical_rdata(&b.rdata)))
    });

    let mut buf = Vec::new();
    let mut last: Option<(Vec<u8>, u16, u16, Vec<u8>)> = None;
    for r in &incl {
        let crd = canonical_rdata(&r.rdata);
        let mut owner = Vec::new();
        canonical_name_into(&r.name, &mut owner);

        let key = (owner.clone(), r.rtype.0, r.class.0, crd.clone());
        if last.as_ref() == Some(&key) {
            continue;
        }
        buf.extend_from_slice(&owner);
        buf.extend_from_slice(&r.rtype.0.to_be_bytes());
        buf.extend_from_slice(&r.class.0.to_be_bytes());
        buf.extend_from_slice(&r.ttl.to_be_bytes());
        buf.extend_from_slice(&(crd.len() as u16).to_be_bytes());
        buf.extend_from_slice(&crd);
        last = Some(key);
    }
    match hash_alg {
        1 => Some(sha2::Sha384::digest(&buf).to_vec()),
        2 => Some(sha2::Sha512::digest(&buf).to_vec()),
        _ => None,
    }
}

/** @brief ZONEMD 계산·검사를 RFC 8976 부록 A 벡터에 맞춰 고정한다. */
#[cfg(test)]
mod zonemd_tests {
    use super::*;
    use onetdns_proto::{Record, Soa};

    /** @brief 다이제스트를 RFC 벡터와 눈으로 비교할 수 있게 16진 문자열로. */
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    /** @brief 영역 요약 확인에서 이름의 원래 바이트가 바뀌지 않는지. */
    fn zonemd_apex_match_preserves_raw_name_octets() {
        let apex = Name::from_str("�").unwrap();
        let raw_owner = Name::from_labels(vec![vec![0xff]]).unwrap();
        let mut rdata = 1u32.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 1]);
        rdata.extend_from_slice(&[0; 48]);
        let record = Record::new(raw_owner, 60, RData::Unknown(ZONEMD_TYPE, rdata));

        assert_eq!(verify_zonemd(&[record], &apex, 1), ZonemdResult::Absent);
    }

    /** @brief RFC 8976 부록 A.1의 예제 zone. 공표된 다이제스트와 대조할 기준이다. */
    fn rfc_zone() -> (Vec<Record>, Name) {
        let apex = Name::from_str("example").unwrap();
        let zone = vec![
            Record::new(
                apex.clone(),
                86400,
                RData::soa(Soa {
                    mname: Name::from_str("ns1.example").unwrap(),
                    rname: Name::from_str("admin.example").unwrap(),
                    serial: 2018031900,
                    refresh: 1800,
                    retry: 900,
                    expire: 604800,
                    minimum: 86400,
                }),
            ),
            Record::new(
                apex.clone(),
                86400,
                RData::Ns(Name::from_str("ns1.example").unwrap()),
            ),
            Record::new(
                apex.clone(),
                86400,
                RData::Ns(Name::from_str("ns2.example").unwrap()),
            ),
            Record::new(
                Name::from_str("ns1.example").unwrap(),
                3600,
                RData::A("203.0.113.63".parse().unwrap()),
            ),
            Record::new(
                Name::from_str("ns2.example").unwrap(),
                3600,
                RData::Aaaa("2001:db8::63".parse().unwrap()),
            ),
        ];
        (zone, apex)
    }

    #[test]
    /** @brief 영역 요약이 규격 예제와 맞는지. */
    fn rfc8976_a1_simple_vector() {
        let (zone, apex) = rfc_zone();
        let digest = compute_zonemd_simple(&zone, &apex, 1).unwrap();
        assert_eq!(
            hex(&digest),
            "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c"
        );
    }

    #[test]
    /** @brief 서명한 것을 검증하고, 손대면 걸리는지. */
    fn verify_roundtrip_and_tamper() {
        let (mut zone, apex) = rfc_zone();
        let digest = compute_zonemd_simple(&zone, &apex, 1).unwrap();
        let mut rd = 2018031900u32.to_be_bytes().to_vec();
        rd.push(1);
        rd.push(1);
        rd.extend_from_slice(&digest);
        zone.push(Record::new(
            apex.clone(),
            86400,
            RData::Unknown(ZONEMD_TYPE, rd),
        ));

        assert_eq!(
            verify_zonemd(&zone, &apex, 2018031900),
            ZonemdResult::Verified
        );

        assert_eq!(verify_zonemd(&zone, &apex, 1), ZonemdResult::Mismatch);

        let mut tampered = zone.clone();
        tampered.push(Record::new(
            Name::from_str("evil.example").unwrap(),
            3600,
            RData::A("203.0.113.66".parse().unwrap()),
        ));
        assert_eq!(
            verify_zonemd(&tampered, &apex, 2018031900),
            ZonemdResult::Mismatch
        );

        let (bare, apex2) = rfc_zone();
        assert_eq!(
            verify_zonemd(&bare, &apex2, 2018031900),
            ZonemdResult::Absent
        );
    }
}

/** @brief 검증기 전반: 서명 대상 구성, 알고리즘별 검증, 체인 판정, 부재 증명. */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /** @brief 와일드카드 이름을 만들 때 원래 바이트가 바뀌지 않는지. */
    fn wildcard_construction_preserves_raw_name_octets() {
        let parent = Name::from_labels(vec![vec![0xff], b"test".to_vec()]).unwrap();
        let wildcard = wildcard_name(&parent).unwrap();
        let wildcard_labels: Vec<&[u8]> = wildcard.labels().collect();
        assert_eq!(wildcard_labels[0], b"*");
        assert_eq!(wildcard_labels[1], [0xff]);

        let source =
            Name::from_labels(vec![b"host".to_vec(), vec![0xff], b"test".to_vec()]).unwrap();
        let owner = owner_for_signing(&source, 2);
        let owner_labels: Vec<&[u8]> = owner.labels().collect();
        assert_eq!(owner_labels[0], b"*");
        assert_eq!(owner_labels[1], [0xff]);
    }
    use ed25519_dalek::{Signer, SigningKey};
    use onetdns_proto::RData;
    use std::net::Ipv4Addr;

    #[test]
    /** @brief 내장한 루트 지문이 공표된 값과 같은지. 다르면 이 서버만 다른 루트를 믿는다. */
    fn root_trust_anchors_match_iana_ksk_2017_and_2024() {
        let anchors = root_trust_anchors();
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].key_tag, 20326, "IANA 루트 KSK-2017 key tag");
        assert_eq!(anchors[1].key_tag, 38696, "IANA 루트 KSK-2024 key tag");
        assert_eq!(anchors[0].digest.len(), 32);
        assert_eq!(anchors[1].digest.len(), 32);
        assert_eq!(anchors[0].digest[0], 0xe0);
        assert_eq!(anchors[0].digest[31], 0x8d);
        assert_eq!(anchors[1].digest[0], 0x68);
        assert_eq!(anchors[1].digest[31], 0x16);
    }

    /** @brief 정렬·TTL 정규화를 확인할 때 쓰는 A 레코드 한 건. */
    fn a_record(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(Ipv4Addr::from(ip)),
        )
    }

    #[test]
    /** @brief 서명 대상 바이트 배치가 규격과 같은지. */
    fn signed_data_matches_rfc4034_layout() {
        let rrset = vec![a_record("example.com", 7200, [192, 0, 2, 1])];
        let rrsig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 2,
            original_ttl: 3600,
            expiration: 0x5A00_0000,
            inception: 0x5900_0000,
            key_tag: 0x1234,
            signer: Name::from_str("example.com").unwrap(),
            signature: vec![],
        };

        let name = [&[7u8][..], b"example", &[3][..], b"com", &[0][..]].concat();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 1]);
        expected.push(15);
        expected.push(2);
        expected.extend_from_slice(&3600u32.to_be_bytes());
        expected.extend_from_slice(&0x5A00_0000u32.to_be_bytes());
        expected.extend_from_slice(&0x5900_0000u32.to_be_bytes());
        expected.extend_from_slice(&[0x12, 0x34]);
        expected.extend_from_slice(&name);
        expected.extend_from_slice(&name);
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&[0, 1]);
        expected.extend_from_slice(&3600u32.to_be_bytes());
        expected.extend_from_slice(&[0, 4]);
        expected.extend_from_slice(&[192, 0, 2, 1]);

        assert_eq!(signed_data(&rrsig, &rrset), expected);
    }

    #[test]
    /** @brief 서명 전 정렬이 언제나 같은지. 다르면 같은 자료의 서명이 갈린다. */
    fn rrset_canonical_ordering_is_stable() {
        let rrsig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 2,
            original_ttl: 300,
            expiration: 1,
            inception: 0,
            key_tag: 0,
            signer: Name::from_str("e.com").unwrap(),
            signature: vec![],
        };
        let a = a_record("e.com", 300, [1, 1, 1, 1]);
        let b = a_record("e.com", 300, [2, 2, 2, 2]);
        let asc = signed_data(&rrsig, &[a.clone(), b.clone()]);
        let desc = signed_data(&rrsig, &[b, a]);
        assert_eq!(asc, desc, "정렬로 순서 독립적");
    }

    /**
     * @brief key tag가 전부 같아지도록 만든 DNSKEY 집합.
     * @details tag는 RDATA 16비트 워드의 합이라, 앞 두 워드를 합이 일정하게 잡으면 서로 다른
     *          키가 같은 tag를 갖는다. KeyTrap식 소진을 흉내 내는 재료다.
     */
    fn colliding_keys(count: usize, algorithm: u8) -> Vec<Dnskey> {
        (0..count)
            .map(|i| {
                let mut public_key = vec![0u8; 32];
                let first = i as u16 + 1;
                let second = 0x8000u16 - first;
                public_key[0..2].copy_from_slice(&first.to_be_bytes());
                public_key[2..4].copy_from_slice(&second.to_be_bytes());
                Dnskey {
                    flags: 256,
                    protocol: 3,
                    algorithm,
                    public_key,
                }
            })
            .collect()
    }

    #[test]
    /** @brief 표식이 겹치는 키를 잔뜩 보내 검증을 무한히 시키지 못하는지. */
    fn colliding_key_tags_cannot_force_unbounded_verifications() {
        let keys = colliding_keys(64, 15);
        let tag = keys[0].key_tag();
        assert!(
            keys.iter().all(|k| k.key_tag() == tag),
            "픽스처가 tag를 겹치게 만들지 못했다"
        );

        let rrset = vec![a_record("victim.test.", 3600, [10, 0, 0, 1])];
        let sigs: Vec<Rrsig> = (0..64)
            .map(|i| Rrsig {
                type_covered: 1,
                algorithm: 15,
                labels: 2,
                original_ttl: 3600,
                expiration: 0x7FFF_FFFF,
                inception: 0,
                key_tag: tag,
                signer: Name::from_str("victim.test.").unwrap(),
                signature: vec![i as u8; 64],
            })
            .collect();

        let started = std::time::Instant::now();
        let verdict = validate_rrset_in_zone(
            &rrset,
            &sigs,
            &keys,
            &Name::from_str("victim.test.").unwrap(),
            1_000,
        );
        let elapsed = started.elapsed();
        assert!(verdict.is_err(), "위조 서명이 통과하면 안 된다");

        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "검증 예산이 걸리지 않았다: {elapsed:?}"
        );
    }

    #[test]
    /** @brief 다른 RRset의 정상 서명들이 실제 답변 서명의 공개키 예산을 먹지 않는지. */
    fn unrelated_rrsigs_do_not_consume_the_verification_budget() {
        let (sk, key) = p256_key(91);
        let owner = "host.example.";
        let answer = vec![a_record(owner, 3600, [192, 0, 2, 91])];
        let unrelated = vec![Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Aaaa("2001:db8::91".parse().unwrap()),
        )];
        let unrelated_sig = sign(&sk, &key, "example.", RecordType::AAAA.0, &unrelated);
        assert_eq!(
            verify_rrsig(&unrelated, &unrelated_sig, &key),
            Ok(()),
            "공격 픽스처의 무관 서명 자체는 정상이어야 한다"
        );

        let mut signatures = vec![unrelated_sig; MAX_SIGNATURE_VERIFICATIONS + 1];
        signatures.push(sign(&sk, &key, "example.", RecordType::A.0, &answer));
        assert!(
            validate_rrset_in_zone(
                &answer,
                &signatures,
                &[key],
                &Name::from_str("example.").unwrap(),
                1,
            )
            .is_ok(),
            "다른 타입을 덮는 RRSIG는 이 RRset의 공개키 예산과 무관하다"
        );
    }

    #[test]
    /** @brief 키 교체 중처럼 키가 여럿일 때도 검증되는지. */
    fn rollover_sized_key_set_still_validates() {
        let (sk, key) = test_key();
        let rrset = vec![a_record("host.example.", 3600, [10, 0, 0, 1])];
        let mut rrsig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 2,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str("example.").unwrap(),
            signature: vec![],
        };
        let data = signed_data(&rrsig, &rrset);
        rrsig.signature = sk.sign(&data).to_bytes().to_vec();

        let mut keys = colliding_keys(3, 15);
        for k in &mut keys {
            let mut bytes = k.public_key.clone();
            bytes.resize(key.public_key.len(), 0);
            k.public_key = bytes;
        }
        keys.push(key);
        assert!(
            validate_rrset(&rrset, &[rrsig], &keys, 1_000).is_ok(),
            "정상 롤오버 규모의 키 집합이 예산에 걸리면 안 된다"
        );
    }

    /** @brief 고정 시드에서 만든 Ed25519 키쌍과 그에 대응하는 DNSKEY. */
    fn test_key() -> (SigningKey, Dnskey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let dnskey = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 15,
            public_key: sk.verifying_key().to_bytes().to_vec(),
        };
        (sk, dnskey)
    }

    #[test]
    /** @brief 이 알고리즘의 검증과 위조 탐지. */
    fn ed25519_roundtrip_verifies_and_tamper_fails() {
        let (sk, key) = test_key();
        let rrset = vec![a_record("host.example.", 3600, [10, 0, 0, 1])];
        let mut rrsig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 2,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str("example.").unwrap(),
            signature: vec![],
        };

        let sig = sk.sign(&signed_data(&rrsig, &rrset));
        rrsig.signature = sig.to_bytes().to_vec();

        assert_eq!(verify_rrsig(&rrset, &rrsig, &key), Ok(()));

        let tampered = vec![a_record("host.example.", 3600, [10, 0, 0, 2])];
        assert_eq!(
            verify_rrsig(&tampered, &rrsig, &key),
            Err(DnssecError::BadSignature)
        );

        let (_, other) = {
            let sk2 = SigningKey::from_bytes(&[9u8; 32]);
            (
                sk2.clone(),
                Dnskey {
                    flags: 257,
                    protocol: 3,
                    algorithm: 15,
                    public_key: sk2.verifying_key().to_bytes().to_vec(),
                },
            )
        };
        assert_eq!(
            verify_rrsig(&rrset, &rrsig, &other),
            Err(DnssecError::BadSignature)
        );
    }

    #[test]
    /** @brief 이 알고리즘의 검증과 위조 탐지. */
    fn ecdsa_p256_roundtrip_verifies_and_tamper_fails() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let key = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        let rrset = vec![a_record("host.example.", 3600, [10, 0, 0, 1])];
        let mut rrsig = Rrsig {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str("example.").unwrap(),
            signature: vec![],
        };
        let sig: Signature = sk.sign(&signed_data(&rrsig, &rrset));
        rrsig.signature = sig.to_bytes().to_vec();

        assert_eq!(verify_rrsig(&rrset, &rrsig, &key), Ok(()));
        let tampered = vec![a_record("host.example.", 3600, [10, 0, 0, 2])];
        assert_eq!(
            verify_rrsig(&tampered, &rrsig, &key),
            Err(DnssecError::BadSignature)
        );
    }

    #[test]
    /** @brief 이 알고리즘의 검증과 위조 탐지. */
    fn ecdsa_p384_roundtrip_verifies_and_tamper_fails() {
        use p384::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x42u8; 48]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let key = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 14,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        let rrset = vec![a_record("h.test.", 600, [203, 0, 113, 9])];
        let mut rrsig = Rrsig {
            type_covered: 1,
            algorithm: 14,
            labels: 2,
            original_ttl: 600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str("test.").unwrap(),
            signature: vec![],
        };
        let sig: Signature = sk.sign(&signed_data(&rrsig, &rrset));
        rrsig.signature = sig.to_bytes().to_vec();

        assert_eq!(verify_rrsig(&rrset, &rrsig, &key), Ok(()));
        let tampered = vec![a_record("h.test.", 600, [203, 0, 113, 10])];
        assert_eq!(
            verify_rrsig(&tampered, &rrsig, &key),
            Err(DnssecError::BadSignature)
        );
    }

    /**
     * @brief 테스트용 RSA-2048 키. 테스트 데이터의 PKCS#8을 읽어 온다.
     * @warning 서명은 rsa::testsign: 상수 시간이 아니며 테스트 전용이다.
     */
    fn rsa_test_key_pair() -> onetdns_core::rsa::testsign::TestRsaKey {
        let private_der = crate::tsig::b64_decode(include_str!(
            "../../../testdata/rsa_test_private_key_2048.pk8.b64"
        ))
        .unwrap();
        onetdns_core::rsa::testsign::TestRsaKey::from_pkcs8(&private_der).unwrap()
    }

    /**
     * @brief RSA 키를 RFC 3110 공개키 형식으로 인코딩한다.
     * @details 지수 길이가 255를 넘으면 1바이트 0에 이어 16비트 길이를 쓰는 이중 형식이다.
     */
    fn rsa_dnskey_public(key: &onetdns_core::rsa::testsign::TestRsaKey) -> Vec<u8> {
        let mut public = Vec::with_capacity(key.e.len() + key.n.len() + 3);
        if key.e.len() < 256 {
            public.push(key.e.len() as u8);
        } else {
            public.push(0);
            public.extend_from_slice(&(key.e.len() as u16).to_be_bytes());
        }
        public.extend_from_slice(&key.e);
        public.extend_from_slice(&key.n);
        public
    }

    #[test]
    /** @brief 규격을 벗어난 키 표기를 거부하는지. */
    fn rfc3110_public_key_parser_rejects_noncanonical_encodings() {
        let public = rsa_dnskey_public(&rsa_test_key_pair());
        let (e, n) = parse_rfc3110(&public).unwrap();
        assert_eq!(e, &[1, 0, 1]);
        assert_eq!(n.len(), 256);

        let mut extended_short_exponent = vec![0, 0, 3, 1, 0, 1];
        extended_short_exponent.extend_from_slice(n);
        assert!(parse_rfc3110(&extended_short_exponent).is_none());

        let mut zero_prefixed_exponent = vec![4, 0, 1, 0, 1];
        zero_prefixed_exponent.extend_from_slice(n);
        assert!(parse_rfc3110(&zero_prefixed_exponent).is_none());

        let mut zero_prefixed_modulus = vec![3, 1, 0, 1, 0];
        zero_prefixed_modulus.extend_from_slice(n);
        assert!(parse_rfc3110(&zero_prefixed_modulus).is_none());

        /* 하한은 1024비트다. 실제로 쓰이는 크기를 막지 않으면서 그보다 작은 것은 물린다. */
        let mut short_modulus = vec![3, 1, 0, 1];
        short_modulus.extend_from_slice(&[0x81; MIN_RSA_MODULUS_BYTES - 1]);
        assert!(parse_rfc3110(&short_modulus).is_none());

        let mut even_exponent = vec![1, 2];
        even_exponent.extend_from_slice(n);
        assert!(parse_rfc3110(&even_exponent).is_none());

        let mut oversized_exponent = vec![5, 2, 0, 0, 0, 1];
        oversized_exponent.extend_from_slice(n);
        assert!(parse_rfc3110(&oversized_exponent).is_none());

        let mut even_modulus = public.clone();
        *even_modulus.last_mut().unwrap() &= !1;
        assert!(parse_rfc3110(&even_modulus).is_none());
        assert!(parse_rfc3110(&[]).is_none());
        assert!(parse_rfc3110(&[0, 1]).is_none());
    }

    #[test]
    /** @brief RSA 계열의 검증. */
    fn rsa_sha256_and_sha512_roundtrip() {
        let private_key = rsa_test_key_pair();
        let pk = rsa_dnskey_public(&private_key);

        let rrset = vec![a_record("rsa.example.", 3600, [192, 0, 2, 7])];

        let key8 = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: pk.clone(),
        };
        let mut sig8 = Rrsig {
            type_covered: 1,
            algorithm: 8,
            labels: 2,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key8.key_tag(),
            signer: Name::from_str("example.").unwrap(),
            signature: vec![],
        };
        sig8.signature = private_key.sign_pkcs1(
            onetdns_core::rsa::RsaHash::Sha256,
            &signed_data(&sig8, &rrset),
        );
        assert_eq!(verify_rrsig(&rrset, &sig8, &key8), Ok(()));
        let tampered = vec![a_record("rsa.example.", 3600, [192, 0, 2, 8])];
        assert_eq!(
            verify_rrsig(&tampered, &sig8, &key8),
            Err(DnssecError::BadSignature)
        );

        let key10 = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 10,
            public_key: pk,
        };
        let mut sig10 = Rrsig {
            algorithm: 10,
            key_tag: key10.key_tag(),
            ..sig8.clone()
        };
        sig10.signature = vec![];
        sig10.signature = private_key.sign_pkcs1(
            onetdns_core::rsa::RsaHash::Sha512,
            &signed_data(&sig10, &rrset),
        );
        assert_eq!(verify_rrsig(&rrset, &sig10, &key10), Ok(()));
    }

    #[test]
    /** @brief 다루지 않는 알고리즘을 그렇다고 알리는지. */
    fn unsupported_algorithm_reported() {
        let key = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 3,
            public_key: vec![0; 64],
        };
        let rrsig = Rrsig {
            type_covered: 1,
            algorithm: 3,
            labels: 1,
            original_ttl: 60,
            expiration: 1,
            inception: 0,
            key_tag: 0,
            signer: Name::from_str("x.").unwrap(),
            signature: vec![0; 128],
        };
        let rrset = vec![a_record("x.", 60, [1, 2, 3, 4])];
        assert_eq!(
            verify_rrsig(&rrset, &rrsig, &key),
            Err(DnssecError::Unsupported(3))
        );
    }

    #[test]
    /** @brief 깨진 이전 알고리즘을 받아들이지 않는지. 받아들이면 서명을 지어낼 수 있다. */
    fn legacy_rsa_sha1_algorithms_are_unsupported() {
        let pk = rsa_dnskey_public(&rsa_test_key_pair());
        let rrset = vec![a_record("rsa-sha1.example.", 3600, [192, 0, 2, 9])];
        for alg in [5, 7] {
            let key = Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: alg,
                public_key: pk.clone(),
            };
            let sig = Rrsig {
                type_covered: 1,
                algorithm: alg,
                labels: 2,
                original_ttl: 3600,
                expiration: 0x7FFF_FFFF,
                inception: 0,
                key_tag: key.key_tag(),
                signer: Name::from_str("example.").unwrap(),
                signature: vec![0; 256],
            };
            assert_eq!(
                verify_rrsig(&rrset, &sig, &key),
                Err(DnssecError::Unsupported(alg)),
                "legacy algorithm {alg}"
            );
        }
    }

    #[test]
    /** @brief 지문이 가리키는 알고리즘과 이 서버가 검증하는 것이 맞는지. */
    fn ds_supported_matches_verifier_algorithms() {
        let ds = |alg: u8| Ds {
            key_tag: 0,
            algorithm: alg,
            digest_type: 2,
            digest: vec![0; 32],
        };
        for alg in [5u8, 7] {
            assert!(
                !ds_is_supported(&ds(alg)),
                "algo {alg}는 verifier 미구현이라 미지원(→Insecure)이어야 한다"
            );
        }
        for alg in [8u8, 10, 13, 14, 15] {
            assert!(ds_is_supported(&ds(alg)), "algo {alg}는 지원되어야 한다");
        }
    }

    #[test]
    /** @brief 키 지문이 맞고, 손대면 걸리는지. */
    fn ds_digest_matches_and_tamper_fails() {
        let (_, key) = test_key();
        let owner = Name::from_str("example.com").unwrap();

        let mut input = Vec::new();
        canonical_name_into(&owner, &mut input);
        input.extend_from_slice(&key.rdata_bytes());
        let good_digest = digest(2, &input).unwrap();
        let ds = Ds {
            key_tag: key.key_tag(),
            algorithm: 15,
            digest_type: 2,
            digest: good_digest.clone(),
        };
        assert_eq!(verify_ds(&ds, &key, &owner), Ok(()));

        let mut bad = ds.clone();
        bad.digest[0] ^= 0xFF;
        assert_eq!(verify_ds(&bad, &key, &owner), Err(DnssecError::BadDigest));

        let mut wrong_tag = ds.clone();
        wrong_tag.key_tag ^= 0x1;
        assert_eq!(
            verify_ds(&wrong_tag, &key, &owner),
            Err(DnssecError::Invalid)
        );
    }

    /** @brief 시드로 고정한 P-256 키쌍. DNSKEY 공개키는 비압축 점에서 0x04 접두사를 뗀다. */
    fn p256_key(seed: u8) -> (p256::ecdsa::SigningKey, Dnskey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let dnskey = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        (sk, dnskey)
    }

    /** @brief DNSKEY를 미해석 RDATA 레코드로 감싼다. 검증기가 실제로 보는 형태다. */
    fn dnskey_rec(zone: &str, key: &Dnskey) -> Record {
        Record::new(
            Name::from_str(zone).unwrap(),
            3600,
            RData::Unknown(48, key.rdata_bytes()),
        )
    }

    /**
     * @brief 알고리즘 13으로 RRset을 서명해 RRSIG를 만든다.
     * @details 서명 대상은 signed_data로 만든다. 검증기와 같은 함수를 써야 정규형 불일치가
     *          아니라 실제 서명 논리를 테스트하게 된다.
     */
    fn sign(
        sk: &p256::ecdsa::SigningKey,
        key: &Dnskey,
        signer: &str,
        type_covered: u16,
        rrset: &[Record],
    ) -> Rrsig {
        use p256::ecdsa::{signature::Signer, Signature};
        let mut rrsig = Rrsig {
            type_covered,
            algorithm: 13,
            labels: rrset[0].name.num_labels() as u8,
            original_ttl: 3600,
            expiration: 0x7FFF_FFFF,
            inception: 0,
            key_tag: key.key_tag(),
            signer: Name::from_str(signer).unwrap(),
            signature: vec![],
        };
        let sig: Signature = sk.sign(&signed_data(&rrsig, rrset));
        rrsig.signature = sig.to_bytes().to_vec();
        rrsig
    }

    #[test]
    /** @brief 지문이 맞아도 쓸 수 없는 키는 거부하는지. */
    fn dnskey_set_rejects_unusable_ksk_even_when_the_ds_matches() {
        let (sk, key) = p256_key(77);
        let zone = Name::from_str("example").unwrap();

        let good = dnskey_rec("example", &key);
        let good_sig = sign(&sk, &key, "example", RecordType::DNSKEY.0, &[good.clone()]);
        let good_ds = Ds::from_dnskey(&key, &zone, 2).unwrap();
        assert!(
            validate_dnskey_set(&[good], &[good_sig], &[good_ds], &zone, 1).is_ok(),
            "온전한 KSK는 받아들여야 한다"
        );

        let mut wrong_protocol = key.clone();
        wrong_protocol.protocol = 2;
        let mut not_zone_key = key.clone();
        not_zone_key.flags &= !0x0100;
        let mut revoked = key.clone();
        revoked.flags |= 0x0080;
        for unusable in [wrong_protocol, not_zone_key, revoked] {
            let record = dnskey_rec("example", &unusable);
            let sig = sign(
                &sk,
                &unusable,
                "example",
                RecordType::DNSKEY.0,
                &[record.clone()],
            );
            let ds = Ds::from_dnskey(&unusable, &zone, 2).unwrap();
            assert_eq!(
                validate_dnskey_set(&[record], &[sig], &[ds], &zone, 1),
                Err(DnssecError::Invalid),
                "flags={:#06x} protocol={}",
                unusable.flags,
                unusable.protocol
            );
        }
    }

    #[test]
    /** @brief 같은 키를 가리키는 DS 팬아웃이 같은 다이제스트를 반복 계산하지 않는지. */
    fn dnskey_set_coalesces_repeated_ds_digest_work() {
        let (sk, key) = p256_key(78);
        let zone = Name::from_str("digest.example.").unwrap();
        let record = dnskey_rec("digest.example.", &key);
        let signature = sign(
            &sk,
            &key,
            "digest.example.",
            RecordType::DNSKEY.0,
            &[record.clone()],
        );
        let good_ds = Ds::from_dnskey(&key, &zone, 2).unwrap();
        let mut bad_ds = good_ds.clone();
        bad_ds.digest[0] ^= 0xFF;
        let mut trusted_ds = vec![bad_ds; 64];
        trusted_ds.push(good_ds);

        DS_DIGEST_CALLS.with(|calls| calls.set(0));
        assert!(
            validate_dnskey_set(&[record], &[signature], &trusted_ds, &zone, 1).is_ok(),
            "마지막의 정상 DS를 찾되 중복 다이제스트는 합쳐야 한다"
        );
        DS_DIGEST_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    }

    #[test]
    /** @brief 서로 다른 충돌 후보도 DS 해시 예산을 넘어 CPU를 소진하지 못하는지. */
    fn dnskey_set_has_a_ds_digest_computation_budget() {
        let zone = Name::from_str("digest-budget.example.").unwrap();
        let mut signing_key = None;
        let mut keys = Vec::with_capacity(MAX_DS_DIGEST_COMPUTATIONS + 1);
        let mut records = Vec::with_capacity(MAX_DS_DIGEST_COMPUTATIONS + 1);
        let mut trusted_ds = Vec::with_capacity(MAX_DS_DIGEST_COMPUTATIONS + 1);

        for seed in 1..=(MAX_DS_DIGEST_COMPUTATIONS as u8 + 1) {
            let (sk, key) = p256_key(seed);
            if signing_key.is_none() {
                signing_key = Some(sk);
            }
            records.push(dnskey_rec("digest-budget.example.", &key));
            trusted_ds.push(Ds::from_dnskey(&key, &zone, 2).unwrap());
            keys.push(key);
        }
        let signature = sign(
            signing_key.as_ref().unwrap(),
            &keys[0],
            "digest-budget.example.",
            RecordType::DNSKEY.0,
            &records,
        );

        DS_DIGEST_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            validate_dnskey_set(&records, &[signature], &trusted_ds, &zone, 1),
            Err(DnssecError::BadSignature),
            "33번째 DS 해시 전에 fail-closed해야 한다"
        );
        DS_DIGEST_CALLS.with(|calls| assert_eq!(calls.get(), MAX_DS_DIGEST_COMPUTATIONS));
    }

    #[test]
    /** @brief DNSKEY 자기서명 검증도 충돌 키에 공개키 연산을 무한히 쓰지 않는지. */
    fn dnskey_set_validation_has_a_public_key_operation_budget() {
        let (sk, trusted_key) = p256_key(92);
        let zone = Name::from_str("budget.example.").unwrap();
        let target_tag = trusted_key.key_tag();
        let mut keys = Vec::with_capacity(MAX_SIGNATURE_VERIFICATIONS + 1);

        for marker in 1..=MAX_SIGNATURE_VERIFICATIONS as u16 {
            let mut fake = Dnskey {
                flags: trusted_key.flags,
                protocol: trusted_key.protocol,
                algorithm: trusted_key.algorithm,
                public_key: vec![0; trusted_key.public_key.len()],
            };
            fake.public_key[0..2].copy_from_slice(&marker.to_be_bytes());
            let matching_word = (0..=u16::MAX)
                .find(|word| {
                    fake.public_key[2..4].copy_from_slice(&word.to_be_bytes());
                    fake.key_tag() == target_tag
                })
                .expect("16비트 key tag에 맞는 공개키 워드");
            fake.public_key[2..4].copy_from_slice(&matching_word.to_be_bytes());
            assert_eq!(fake.key_tag(), target_tag);
            keys.push(fake);
        }
        keys.push(trusted_key.clone());

        let records: Vec<Record> = keys
            .iter()
            .map(|key| dnskey_rec("budget.example.", key))
            .collect();
        let signature = sign(
            &sk,
            &trusted_key,
            "budget.example.",
            RecordType::DNSKEY.0,
            &records,
        );
        let trusted_ds: Vec<Ds> = keys
            .iter()
            .map(|key| Ds::from_dnskey(key, &zone, 2).unwrap())
            .collect();

        assert_eq!(
            validate_dnskey_set(&records, &[signature], &trusted_ds, &zone, 1),
            Err(DnssecError::BadSignature),
            "아홉 번째 충돌 키가 진짜여도 8회에서 fail-closed 해야 한다"
        );
    }

    #[test]
    /** @brief 형태가 어긋난 자료와 키를 거부하는지. */
    fn validation_rejects_structurally_invalid_rrsets_and_keys() {
        let (sk, key) = p256_key(42);
        let valid = a_record("host.example", 3600, [192, 0, 2, 1]);

        let mixed_owner = vec![
            valid.clone(),
            a_record("other.example", 3600, [192, 0, 2, 2]),
        ];
        let mixed_sig = sign(&sk, &key, "example", RecordType::A.0, &mixed_owner);
        assert_eq!(
            verify_rrsig(&mixed_owner, &mixed_sig, &key),
            Err(DnssecError::Invalid)
        );

        let wrong_type_sig = sign(&sk, &key, "example", RecordType::AAAA.0, &[valid.clone()]);
        assert_eq!(
            verify_rrsig(&[valid.clone()], &wrong_type_sig, &key),
            Err(DnssecError::Invalid)
        );

        let outside_sig = sign(&sk, &key, "outside", RecordType::A.0, &[valid.clone()]);
        assert_eq!(
            verify_rrsig(&[valid.clone()], &outside_sig, &key),
            Err(DnssecError::Invalid)
        );

        let mut excessive_labels = sign(&sk, &key, "example", RecordType::A.0, &[valid.clone()]);
        excessive_labels.labels = 3;
        assert_eq!(
            verify_rrsig(&[valid.clone()], &excessive_labels, &key),
            Err(DnssecError::Invalid)
        );

        let mut wrong_protocol = key.clone();
        wrong_protocol.protocol = 2;
        let mut not_zone_key = key.clone();
        not_zone_key.flags &= !0x0100;
        let mut revoked = key.clone();
        revoked.flags |= 0x0080;
        for unusable in [wrong_protocol, not_zone_key, revoked] {
            let sig = sign(&sk, &unusable, "example", RecordType::A.0, &[valid.clone()]);
            assert!(validate_rrset(&[valid.clone()], &[sig], &[unusable], 1).is_err());
        }

        let zone = Name::from_str("example").unwrap();
        let misplaced = dnskey_rec("other.example", &key);
        let misplaced_sig = sign(
            &sk,
            &key,
            "other.example",
            RecordType::DNSKEY.0,
            &[misplaced.clone()],
        );
        let ds = Ds::from_dnskey(&key, &zone, 2).unwrap();
        assert_eq!(
            validate_dnskey_set(&[misplaced], &[misplaced_sig], &[ds], &zone, 1),
            Err(DnssecError::Invalid)
        );
    }

    /** @brief 자식 키에 대한 DS를 레코드와 파싱 형태로 함께 만든다. */
    fn ds_for(child_zone: &str, child_key: &Dnskey) -> (Record, Ds) {
        let owner = Name::from_str(child_zone).unwrap();
        let mut input = Vec::new();
        canonical_name_into(&owner, &mut input);
        input.extend_from_slice(&child_key.rdata_bytes());
        let ds = Ds {
            key_tag: child_key.key_tag(),
            algorithm: 13,
            digest_type: 2,
            digest: digest(2, &input).unwrap(),
        };
        let rec = Record::new(owner, 3600, RData::Unknown(43, ds.rdata_bytes()));
        (rec, ds)
    }

    #[test]
    /** @brief 루트부터 리프까지 이어지는지, 그리고 손대면 걸리는지. */
    fn chain_validates_root_to_leaf_and_tamper_is_bogus() {
        let (sk_root, k_root) = p256_key(1);
        let (sk_test, k_test) = p256_key(2);

        let (_, ds_root) = ds_for(".", &k_root);

        let root_dnskey = dnskey_rec(".", &k_root);
        let root_dnskey_rrsig = sign(&sk_root, &k_root, ".", 48, &[root_dnskey.clone()]);
        let (test_ds_rec, test_ds) = ds_for("test", &k_test);
        let test_ds_rrsig = sign(&sk_root, &k_root, ".", 43, &[test_ds_rec.clone()]);
        let root_link = ChainLink {
            zone: Name::from_str(".").unwrap(),
            dnskeys: vec![root_dnskey],
            dnskey_rrsigs: vec![root_dnskey_rrsig],
            ds_records: vec![test_ds_rec],
            ds_rrsigs: vec![test_ds_rrsig],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![test_ds],
        };

        let test_dnskey = dnskey_rec("test", &k_test);
        let test_dnskey_rrsig = sign(&sk_test, &k_test, "test", 48, &[test_dnskey.clone()]);
        let test_link = ChainLink {
            zone: Name::from_str("test").unwrap(),
            dnskeys: vec![test_dnskey],
            dnskey_rrsigs: vec![test_dnskey_rrsig],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        };

        let answer = vec![a_record("host.test", 3600, [10, 0, 0, 5])];
        let answer_rrsig = sign(&sk_test, &k_test, "test", 1, &answer);

        let links = [root_link, test_link];

        let now = 1000u32;

        assert_eq!(
            validate_chain(
                &[ds_root.clone()],
                &links,
                &answer,
                &[answer_rrsig.clone()],
                now
            ),
            Ok(())
        );

        let wrong_signer_answer_rrsig = sign(&sk_test, &k_test, ".", 1, &answer);
        assert!(
            validate_chain(
                &[ds_root.clone()],
                &links,
                &answer,
                &[wrong_signer_answer_rrsig],
                now
            )
            .is_err(),
            "암호학적으로 유효해도 signer가 leaf apex와 다르면 bogus여야"
        );

        let tampered = vec![a_record("host.test", 3600, [10, 0, 0, 6])];
        assert!(
            validate_chain(
                &[ds_root.clone()],
                &links,
                &tampered,
                &[answer_rrsig.clone()],
                now
            )
            .is_err(),
            "변조된 답은 bogus여야"
        );

        assert!(
            validate_chain(
                &[ds_root.clone()],
                &links,
                &answer,
                &[answer_rrsig.clone()],
                0xFFFF_FFF0
            )
            .is_err(),
            "만료 서명은 bogus여야"
        );

        let (_, ds_wrong) = ds_for(".", &k_test);
        assert!(
            validate_chain(&[ds_wrong], &links, &answer, &[answer_rrsig], now).is_err(),
            "틀린 앵커는 bogus여야"
        );
    }

    #[test]
    /** @brief 체인 상태가 셋으로 제대로 갈리는지. */
    fn chain_status_secure_insecure_bogus() {
        let (sk_root, k_root) = p256_key(21);
        let (sk_test, k_test) = p256_key(22);
        let (_, ds_root) = ds_for(".", &k_root);
        let now = 1000u32;

        let root_dnskey = dnskey_rec(".", &k_root);
        let root_dnskey_rrsig = sign(&sk_root, &k_root, ".", 48, &[root_dnskey.clone()]);
        let test_dnskey = dnskey_rec("test", &k_test);
        let test_dnskey_rrsig = sign(&sk_test, &k_test, "test", 48, &[test_dnskey.clone()]);
        let (test_ds_rec, test_ds) = ds_for("test", &k_test);
        let test_ds_rrsig = sign(&sk_root, &k_root, ".", 43, &[test_ds_rec.clone()]);

        let mk_test_link = || ChainLink {
            zone: Name::from_str("test").unwrap(),
            dnskeys: vec![test_dnskey.clone()],
            dnskey_rrsigs: vec![test_dnskey_rrsig.clone()],
            ds_records: vec![],
            ds_rrsigs: vec![],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![],
        };

        let mk_root_link = |with_ds: bool| ChainLink {
            zone: Name::from_str(".").unwrap(),
            dnskeys: vec![root_dnskey.clone()],
            dnskey_rrsigs: vec![root_dnskey_rrsig.clone()],
            ds_records: if with_ds {
                vec![test_ds_rec.clone()]
            } else {
                vec![]
            },
            ds_rrsigs: if with_ds {
                vec![test_ds_rrsig.clone()]
            } else {
                vec![]
            },
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: if with_ds {
                vec![test_ds.clone()]
            } else {
                vec![]
            },
        };

        let secure = validate_chain_status(
            &[ds_root.clone()],
            &[mk_root_link(true), mk_test_link()],
            now,
        );
        assert!(
            matches!(secure, ChainStatus::Secure(_)),
            "정상 체인 → Secure"
        );

        let insec = validate_chain_status(
            &[ds_root.clone()],
            &[mk_root_link(false), mk_test_link()],
            now,
        );
        assert!(
            matches!(insec, ChainStatus::Insecure),
            "DS 없는 위임 → Insecure"
        );

        let parent_nsec = nsec_record("test", "zzz", &[2, 46, 47]);
        let parent_nsec_sig = sign(
            &sk_root,
            &k_root,
            ".",
            RecordType::NSEC.0,
            std::slice::from_ref(&parent_nsec),
        );
        let mut proven_insecure_root = mk_root_link(false);
        proven_insecure_root.ds_nsec_records = vec![parent_nsec.clone()];
        proven_insecure_root.ds_nsec_rrsigs = vec![parent_nsec_sig];
        assert!(matches!(
            validate_chain_status_with_options(
                &[ds_root.clone()],
                &[proven_insecure_root, mk_test_link()],
                now,
                true,
            ),
            ChainStatus::Insecure
        ));

        let leaf_nsec = nsec_record("test", "zzz", &[1, 46, 47]);
        let leaf_nsec_sig = sign(
            &sk_root,
            &k_root,
            ".",
            RecordType::NSEC.0,
            std::slice::from_ref(&leaf_nsec),
        );
        let mut leaf_root = mk_root_link(false);
        leaf_root.ds_nsec_records = vec![leaf_nsec.clone()];
        leaf_root.ds_nsec_rrsigs = vec![leaf_nsec_sig.clone()];
        assert!(
            matches!(
                validate_chain_status_with_options(
                    &[ds_root.clone()],
                    &[leaf_root, mk_test_link()],
                    now,
                    true,
                ),
                ChainStatus::Bogus
            ),
            "NS 없는 이름의 DS 부재는 서명되지 않은 위임의 증명이 아니다"
        );
        let root = Name::from_str(".").unwrap();
        let child = Name::from_str("test").unwrap();
        let classify = |records: &[Record], sigs: &[Rrsig], name: &Name| {
            classify_ds_absence(
                &root,
                std::slice::from_ref(&k_root),
                &DenialEvidence {
                    nsec: records,
                    nsec_rrsigs: sigs,
                    nsec3: &[],
                    nsec3_rrsigs: &[],
                },
                name,
                now,
            )
        };
        assert_eq!(
            classify(
                std::slice::from_ref(&leaf_nsec),
                std::slice::from_ref(&leaf_nsec_sig),
                &child
            ),
            DsAbsence::NotACut
        );
        assert_eq!(
            classify(
                std::slice::from_ref(&leaf_nsec),
                std::slice::from_ref(&leaf_nsec_sig),
                &Name::from_str("tp").unwrap()
            ),
            DsAbsence::NotACut,
            "구간에 덮인 이름은 RRset이 없으므로 위임일 수 없다"
        );
        let apex_nsec = nsec_record("test", "zzz", &[2, 6, 46, 47]);
        let apex_nsec_sig = sign(
            &sk_root,
            &k_root,
            ".",
            RecordType::NSEC.0,
            std::slice::from_ref(&apex_nsec),
        );
        assert_eq!(
            classify(
                std::slice::from_ref(&apex_nsec),
                std::slice::from_ref(&apex_nsec_sig),
                &child
            ),
            DsAbsence::Unproven,
            "SOA가 있는 NSEC은 자식 쪽 apex의 것이라 위임 증명이 아니다"
        );
        assert_eq!(
            classify(std::slice::from_ref(&leaf_nsec), &[], &child),
            DsAbsence::Unproven
        );

        let wrong_parent_signer = sign(
            &sk_root,
            &k_root,
            "test",
            RecordType::NSEC.0,
            std::slice::from_ref(&parent_nsec),
        );
        let mut forged_insecure_root = mk_root_link(false);
        forged_insecure_root.ds_nsec_records = vec![parent_nsec];
        forged_insecure_root.ds_nsec_rrsigs = vec![wrong_parent_signer];
        assert!(matches!(
            validate_chain_status_with_options(
                &[ds_root.clone()],
                &[forged_insecure_root, mk_test_link()],
                now,
                true,
            ),
            ChainStatus::Bogus
        ));

        let unsupported_ds = Ds {
            key_tag: k_test.key_tag(),
            algorithm: 253,
            digest_type: 253,
            digest: vec![1, 2, 3],
        };
        let unsupported_rec = Record::new(
            Name::from_str("test").unwrap(),
            3600,
            RData::Unknown(43, unsupported_ds.rdata_bytes()),
        );
        let unsupported_sig = sign(
            &sk_root,
            &k_root,
            ".",
            RecordType::DS.0,
            &[unsupported_rec.clone()],
        );
        let unsupported_root = ChainLink {
            zone: Name::from_str(".").unwrap(),
            dnskeys: vec![root_dnskey.clone()],
            dnskey_rrsigs: vec![root_dnskey_rrsig.clone()],
            ds_records: vec![unsupported_rec],
            ds_rrsigs: vec![unsupported_sig],
            ds_nsec_records: vec![],
            ds_nsec_rrsigs: vec![],
            ds_nsec3_records: vec![],
            ds_nsec3_rrsigs: vec![],
            ds: vec![unsupported_ds],
        };
        assert!(matches!(
            validate_chain_status(&[ds_root.clone()], &[unsupported_root, mk_test_link()], now),
            ChainStatus::Insecure
        ));

        let (_, ds_wrong) = ds_for(".", &k_test);
        let bogus = validate_chain_status(&[ds_wrong], &[mk_root_link(true), mk_test_link()], now);
        assert!(matches!(bogus, ChainStatus::Bogus), "틀린 앵커 → Bogus");
    }

    #[test]
    /** @brief 서명 유효 기간을 지키는지. */
    fn rrsig_time_window() {
        let sig = Rrsig {
            type_covered: 1,
            algorithm: 13,
            labels: 1,
            original_ttl: 60,
            expiration: 2000,
            inception: 1000,
            key_tag: 0,
            signer: Name::from_str("x.").unwrap(),
            signature: vec![],
        };
        assert!(rrsig_time_valid(&sig, 1500));
        assert!(rrsig_time_valid(&sig, 1000));
        assert!(rrsig_time_valid(&sig, 2000));
        assert!(!rrsig_time_valid(&sig, 999));
        assert!(!rrsig_time_valid(&sig, 2001));

        assert!(
            rrsig_time_valid_accepting(&sig, 2001, true),
            "accept_expired: 만료 서명 허용"
        );
        assert!(
            !rrsig_time_valid_accepting(&sig, 2001, false),
            "기본: 만료 거부"
        );
        assert!(
            !rrsig_time_valid_accepting(&sig, 999, true),
            "accept_expired여도 미도래는 거부"
        );
    }

    /** @brief NSEC 레코드를 RDATA 바이트부터 손으로 만든다. 비트맵 인코딩까지 테스트 대상이다. */
    fn nsec_record(owner: &str, next: &str, types: &[u16]) -> Record {
        let mut rdata = Vec::new();
        for label in next.trim_end_matches('.').split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let max = types.iter().copied().max().unwrap_or(0);
        let nbytes = (max / 8 + 1) as usize;
        let mut bm = vec![0u8; nbytes];
        for &t in types {
            bm[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        rdata.push(0);
        rdata.push(nbytes as u8);
        rdata.extend_from_slice(&bm);
        Record::new(
            Name::from_str(owner).unwrap(),
            3600,
            RData::Unknown(47, rdata),
        )
    }

    #[test]
    /** @brief 부재 증명의 타입 비트맵와 정렬. */
    fn nsec_bitmap_and_canonical_order() {
        let rec = nsec_record("a.test", "c.test", &[1, 28, 46, 47]);
        let nsec = Nsec::from_record(&rec).unwrap();
        assert_eq!(nsec.next.to_ascii_lower(), "c.test");
        assert!(nsec.has_type(1) && nsec.has_type(28) && nsec.has_type(47));
        assert!(!nsec.has_type(15));

        let cmp = |a: &str, b: &str| {
            canonical_name_cmp(&Name::from_str(a).unwrap(), &Name::from_str(b).unwrap())
        };
        assert_eq!(cmp("example.com", "a.example.com"), Ordering::Less);
        assert_eq!(cmp("a.example.com", "b.example.com"), Ordering::Less);
        assert_eq!(cmp("a.com", "a.net"), Ordering::Less);
        assert_eq!(cmp("example.com", "example.com"), Ordering::Equal);
    }

    #[test]
    /** @brief 어긋나거나 잘린 타입 비트맵을 거부하는지. */
    fn denial_type_bitmaps_reject_noncanonical_and_truncated_encodings() {
        assert_eq!(
            parse_type_bitmaps(&[0, 1, 0x40, 1, 1, 0x80]),
            Some(vec![1, 256])
        );

        for invalid in [
            vec![0],
            vec![0, 0],
            vec![0, 33],
            vec![0, 2, 0x80],
            vec![0, 2, 0x80, 0],
            vec![1, 1, 0x80, 0, 1, 0x80],
            vec![0, 1, 0x80, 0, 1, 0x40],
        ] {
            assert_eq!(parse_type_bitmaps(&invalid), None, "{invalid:02x?}");
        }

        let mut malformed_nsec = nsec_record("host.test", "next.test", &[1, 46]);
        if let RData::Unknown(_, raw) = &mut malformed_nsec.rdata {
            raw.push(0);
        }
        assert!(Nsec::from_record(&malformed_nsec).is_none());

        let mut malformed_nsec3 = nsec3_record(&[0x11; 20], "test", &[], 0, &[0x22; 20], &[1, 46]);
        if let RData::Unknown(_, raw) = &mut malformed_nsec3.rdata {
            raw.push(0);
        }
        assert!(Nsec3::from_record(&malformed_nsec3).is_none());
    }

    #[test]
    /** @brief 비었다는 것과 없다는 것을 증명하는지. */
    fn nsec_proves_nodata_and_nonexistence() {
        let nd = nsec_record("host.test", "next.test", &[28, 46]);
        let host = Name::from_str("host.test").unwrap();
        assert!(prove_nodata(&[nd.clone()], &host, 1));
        assert_eq!(nsec_nodata_proof(&[nd.clone()], &host, 1).unwrap().len(), 1);
        assert!(!prove_nodata(&[nd.clone()], &host, 28));

        let nd_cname = nsec_record("host.test", "next.test", &[5, 46]);
        assert!(!prove_nodata(&[nd_cname], &host, 1));

        let cover_name = nsec_record("a.test", "c.test", &[1, 46]);
        let cover_wild = nsec_record("test", "a.test", &[6, 46, 47]);
        let proof = [cover_wild.clone(), cover_name.clone()];
        let missing = Name::from_str("b.test").unwrap();
        assert!(prove_name_nonexistent(&proof, &missing));
        let selected = nsec_name_nonexistent_proof(&proof, &missing).unwrap();
        assert!(selected.len() <= 3);
        assert!(prove_name_nonexistent(&selected, &missing));

        assert!(!prove_name_nonexistent(
            &[cover_name.clone()],
            &Name::from_str("b.test").unwrap()
        ));

        assert!(!prove_name_nonexistent(
            &proof,
            &Name::from_str("z.test").unwrap()
        ));

        let wild_exists = nsec_record("*.test", "a.test", &[1, 46]);
        assert!(!prove_name_nonexistent(
            &[wild_exists, cover_name],
            &Name::from_str("b.test").unwrap()
        ));

        let inferred_only = [
            nsec_record("!.test", "a.test", &[1, 46]),
            nsec_record("a.test", "c.test", &[1, 46]),
        ];
        assert!(!prove_name_nonexistent(
            &inferred_only,
            &Name::from_str("b.test").unwrap()
        ));

        let wildcard_nodata = [
            nsec_record("test", "a.test", &[6, 46, 47]),
            nsec_record("a.test", "c.test", &[1, 46]),
            nsec_record("*.test", "a.test", &[28, 46]),
        ];
        assert!(prove_nodata(
            &wildcard_nodata,
            &Name::from_str("b.test").unwrap(),
            RecordType::A.0
        ));
        let selected = nsec_nodata_proof(
            &wildcard_nodata,
            &Name::from_str("b.test").unwrap(),
            RecordType::A.0,
        )
        .unwrap();
        assert!(selected.len() <= 3);
    }

    /** @brief 이름을 감춘 형태의 테스트용 증명 기록. */
    fn nsec3_record(
        owner_hash: &[u8],
        zone: &str,
        salt: &[u8],
        iter: u16,
        next_hashed: &[u8],
        types: &[u16],
    ) -> Record {
        let mut rdata = Vec::new();
        rdata.push(1);
        rdata.push(0);
        rdata.extend_from_slice(&iter.to_be_bytes());
        rdata.push(salt.len() as u8);
        rdata.extend_from_slice(salt);
        rdata.push(next_hashed.len() as u8);
        rdata.extend_from_slice(next_hashed);
        let max = types.iter().copied().max().unwrap_or(0);
        let nbytes = (max / 8 + 1) as usize;
        let mut bm = vec![0u8; nbytes];
        for &t in types {
            bm[(t / 8) as usize] |= 0x80 >> (t % 8);
        }
        rdata.push(0);
        rdata.push(nbytes as u8);
        rdata.extend_from_slice(&bm);
        let owner = format!("{}.{}", base32hex_encode(owner_hash), zone);
        Record::new(
            Name::from_str(&owner).unwrap(),
            3600,
            RData::Unknown(50, rdata),
        )
    }

    #[test]
    /** @brief 반복 횟수 상한이 걸리는지. 없으면 질의 하나로 CPU를 태운다. */
    fn nsec3_max_iterations_returns_max() {
        let a = nsec3_record(&[0x11; 20], "example", &[0xaa], 5, &[0xff; 20], &[1]);
        let b = nsec3_record(&[0x22; 20], "example", &[0xaa], 200, &[0xff; 20], &[1]);
        let malformed_high = Record::new(
            Name::from_str("broken.example").unwrap(),
            60,
            RData::Unknown(RecordType::NSEC3.0, vec![1, 0, 0xff, 0xff]),
        );
        NSEC3_PARSE_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            nsec3_max_iterations(&[a.clone(), b.clone(), malformed_high]),
            u16::MAX,
            "잘린 RDATA도 반복 횟수 헤더가 높으면 해시 전에 보수적으로 차단한다"
        );
        assert_eq!(nsec3_max_iterations(&[a]), 5);

        assert_eq!(nsec3_max_iterations(&[]), 0);
        NSEC3_PARSE_CALLS.with(|calls| {
            assert_eq!(
                calls.get(),
                0,
                "반복 상한 판정은 전체 RDATA를 할당 파싱하지 않는다"
            )
        });
    }

    #[test]
    /** @brief 같은 매개변수의 NSEC3가 많아도 질의 이름은 한 번만 해시하는지. */
    fn nsec3_exact_match_hash_cost_is_independent_of_record_count() {
        let salt = [0xde, 0xad];
        let iterations = 150;
        let qname = Name::from_str("host.example").unwrap();
        let query_hash = nsec3_hash(&qname, &salt, iterations);
        let mut records = Vec::new();
        for marker in 0..96u8 {
            let mut owner = [marker; 20];
            if owner.as_slice() == query_hash.as_slice() {
                owner[0] ^= 0xff;
            }
            records.push(nsec3_record(
                &owner,
                "example",
                &salt,
                iterations,
                &[0xff; 20],
                &[RecordType::AAAA.0, RecordType::RRSIG.0, RecordType::NSEC3.0],
            ));
        }
        records.push(nsec3_record(
            &query_hash,
            "example",
            &salt,
            iterations,
            &[0xff; 20],
            &[RecordType::AAAA.0, RecordType::RRSIG.0, RecordType::NSEC3.0],
        ));

        NSEC3_HASH_CALLS.with(|calls| calls.set(0));
        NSEC3_PARSE_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            nsec3_nodata_proof(&records, &qname, RecordType::A.0)
                .expect("마지막 NSEC3 exact match")
                .len(),
            1
        );
        let calls = NSEC3_HASH_CALLS.with(std::cell::Cell::get);
        assert_eq!(
            calls, 1,
            "공통 salt/iteration의 같은 이름을 레코드마다 다시 해시하면 안 된다"
        );
        let parses = NSEC3_PARSE_CALLS.with(std::cell::Cell::get);
        assert_eq!(
            parses,
            records.len(),
            "증명 입력은 레코드마다 한 번만 완전히 파싱해야 한다"
        );
    }

    #[test]
    /** @brief 깊은 이름과 반복 횟수의 곱도 증명 단위 SHA 예산을 넘지 않는지. */
    fn nsec3_total_hash_round_budget_is_fail_closed() {
        let qname = Name::from_labels((0..127).map(|_| vec![b'a']).collect()).unwrap();
        let root = Name::from_labels(Vec::new()).unwrap();
        let records = |iterations| {
            let root_hash = nsec3_hash(&root, &[], iterations);
            [
                nsec3_record(&root_hash, "", &[], iterations, &[0xff; 20], &[2, 6]),
                nsec3_record(&[0; 20], "", &[], iterations, &[0xff; 20], &[46]),
            ]
        };

        let within_budget = records(62);
        NSEC3_HASH_CALLS.with(|calls| calls.set(0));
        assert!(nsec3_name_nonexistent_proof(&within_budget, &qname).is_some());
        NSEC3_HASH_CALLS.with(|calls| {
            assert_eq!(
                calls.get(),
                129,
                "127개 closest 후보와 next·wildcard를 각각 한 번 해시한다"
            )
        });

        let over_budget = records(63);
        NSEC3_HASH_CALLS.with(|calls| calls.set(0));
        assert!(
            nsec3_name_nonexistent_proof(&over_budget, &qname).is_none(),
            "129×64 SHA-1은 8,192회 예산 다음 연산에서 닫혀야 한다"
        );
        NSEC3_HASH_CALLS.with(|calls| assert_eq!(calls.get(), 128));

        let shallow = Name::from_str("host.example").unwrap();
        let too_many_iterations = nsec3_record(
            &nsec3_hash(&shallow, &[], MAX_NSEC3_ITERATIONS + 1),
            "example",
            &[],
            MAX_NSEC3_ITERATIONS + 1,
            &[0xff; 20],
            &[46],
        );
        NSEC3_HASH_CALLS.with(|calls| calls.set(0));
        assert!(!prove_nodata_nsec3(
            &[too_many_iterations],
            &shallow,
            RecordType::A.0
        ));
        NSEC3_HASH_CALLS.with(|calls| {
            assert_eq!(
                calls.get(),
                0,
                "반복 하드 상한은 해시를 시작하기 전에 적용한다"
            )
        });
    }

    #[test]
    /** @brief 감추기 요약이 규격 예제와 맞는지. */
    fn nsec3_hash_rfc5155_vector() {
        let h = nsec3_hash(
            &Name::from_str("example").unwrap(),
            &[0xaa, 0xbb, 0xcc, 0xdd],
            12,
        );
        assert_eq!(base32hex_encode(&h), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
    }

    #[test]
    /** @brief 이름에 쓰는 표기의 왕복. */
    fn base32hex_roundtrip() {
        let data = [0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf];
        let enc = base32hex_encode(&data);
        assert_eq!(base32hex_decode(enc.as_bytes()).unwrap(), data);
        assert_eq!(base32hex_decode(b"00"), Some(vec![0]));
        assert_eq!(base32hex_decode(b"0"), None, "불가능한 5-bit 잔여 길이");
        assert_eq!(base32hex_decode(b"01"), None, "0이 아닌 padding bit");
        assert_eq!(
            base32hex_decode(&[b'0'; 33]),
            None,
            "비정규 SHA-1 hash label 길이"
        );
    }

    #[test]
    /** @brief 감춘 형태로도 비었음과 없음을 증명하는지. */
    fn nsec3_proves_nodata_and_nonexistence() {
        let salt: &[u8] = &[0xde, 0xad];
        let iter = 5u16;
        let qname = Name::from_str("host.example").unwrap();
        let qh = nsec3_hash(&qname, salt, iter);

        let nd = nsec3_record(&qh, "example", salt, iter, &[0xff; 20], &[28, 46]);
        assert!(prove_nodata_nsec3(&[nd.clone()], &qname, 1));
        assert_eq!(
            nsec3_nodata_proof(&[nd.clone()], &qname, 1).unwrap().len(),
            1
        );
        assert!(!prove_nodata_nsec3(&[nd], &qname, 28));

        let ce = Name::from_str("example").unwrap();
        let ce_hash = nsec3_hash(&ce, salt, iter);
        let ce_rec = nsec3_record(&ce_hash, "example", salt, iter, &[0xff; 20], &[6, 2]);
        let wide = nsec3_record(&[0x00; 20], "example", salt, iter, &[0xff; 20], &[46]);
        NSEC3_HASH_CALLS.with(|calls| calls.set(0));
        NSEC3_PARSE_CALLS.with(|calls| calls.set(0));
        assert!(prove_name_nonexistent_nsec3(
            &[ce_rec.clone(), wide.clone()],
            &qname
        ));
        NSEC3_PARSE_CALLS.with(|calls| assert_eq!(calls.get(), 2));
        NSEC3_HASH_CALLS.with(|calls| {
            assert_eq!(
                calls.get(),
                3,
                "closest·next·wildcard 이름은 각각 한 번만 해시해야 한다"
            )
        });
        let selected =
            nsec3_name_nonexistent_proof(&[ce_rec.clone(), wide.clone()], &qname).unwrap();
        assert!(selected.len() <= 3);
        assert!(prove_name_nonexistent_nsec3(&selected, &qname));

        assert!(!prove_name_nonexistent_nsec3(&[wide.clone()], &qname));

        let wild_hash = nsec3_hash(&Name::from_str("*.example").unwrap(), salt, iter);
        let wild_match = nsec3_record(&wild_hash, "example", salt, iter, &[0xff; 20], &[1, 46]);
        assert!(!prove_name_nonexistent_nsec3(
            &[ce_rec.clone(), wide.clone(), wild_match],
            &qname
        ));

        let wildcard_nodata =
            nsec3_record(&wild_hash, "example", salt, iter, &[0xff; 20], &[28, 46]);
        assert!(prove_nodata_nsec3(
            &[ce_rec.clone(), wide.clone(), wildcard_nodata],
            &qname,
            RecordType::A.0
        ));

        let child = Name::from_str("unsigned.example").unwrap();
        let mut opt_out = wide.clone();
        if let RData::Unknown(_, raw) = &mut opt_out.rdata {
            raw[1] = 1;
        }
        assert!(!prove_nodata_nsec3(
            &[ce_rec.clone(), opt_out.clone()],
            &child,
            RecordType::DS.0
        ));
        assert!(prove_ds_absence_nsec3(
            &[ce_rec.clone(), opt_out.clone()],
            &child
        ));
        assert!(!prove_ds_absence_nsec3(&[ce_rec, wide], &child));
    }

    #[test]
    /** @brief 일부를 비워 두는 방식으로는 없다고 단정하지 않는지. */
    fn nsec3_nxdomain_covered_only_by_opt_out_is_not_authenticated_denial() {
        let salt: &[u8] = &[0xde, 0xad];
        let iter = 5u16;
        let qname = Name::from_str("host.example").unwrap();
        let ce = Name::from_str("example").unwrap();
        let ce_hash = nsec3_hash(&ce, salt, iter);

        let mut ce_next = ce_hash.clone();
        for byte in ce_next.iter_mut().rev() {
            if *byte == 0xff {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
        let ce_rec = nsec3_record(&ce_hash, "example", salt, iter, &ce_next, &[6, 2]);
        let wide = nsec3_record(&[0x00; 20], "example", salt, iter, &[0xff; 20], &[46]);

        assert!(prove_name_nonexistent_nsec3(
            &[ce_rec.clone(), wide.clone()],
            &qname
        ));
        assert!(!nsec3_denial_relies_on_opt_out(
            &[ce_rec.clone(), wide.clone()],
            &qname
        ));
        assert_eq!(
            nsec3_name_nonexistent_proof_status(&[ce_rec.clone(), wide.clone()], &qname)
                .map(|(_, relies)| relies),
            Some(false)
        );

        let mut opt_out = wide.clone();
        if let RData::Unknown(_, raw) = &mut opt_out.rdata {
            raw[1] = 1;
        }
        assert!(nsec3_denial_relies_on_opt_out(
            &[ce_rec.clone(), opt_out.clone()],
            &qname
        ));
        assert_eq!(
            nsec3_name_nonexistent_proof_status(&[ce_rec.clone(), opt_out.clone()], &qname)
                .map(|(_, relies)| relies),
            Some(true)
        );

        assert!(!nsec3_denial_relies_on_opt_out(
            &[ce_rec.clone(), opt_out.clone(), wide.clone()],
            &qname
        ));
        assert_eq!(
            nsec3_name_nonexistent_proof_status(&[ce_rec.clone(), opt_out, wide], &qname)
                .map(|(_, relies)| relies),
            Some(false)
        );

        assert!(!nsec3_denial_relies_on_opt_out(&[ce_rec], &qname));
    }

    #[test]
    /** @brief 모르는 설정이나 섞인 매개변수를 거부하는지. 섞이면 있는 것을 없다고 한다. */
    fn nsec3_proof_rejects_unknown_algorithm_flags_and_mixed_parameters() {
        let qname = Name::from_str("host.example").unwrap();
        let salt_a = [0x11];
        let salt_b = [0x22];
        let iter = 1;
        let qh = nsec3_hash(&qname, &salt_a, iter);
        let valid = nsec3_record(&qh, "example", &salt_a, iter, &[0xff; 20], &[28, 46]);

        let mut unknown_algorithm = valid.clone();
        if let RData::Unknown(_, raw) = &mut unknown_algorithm.rdata {
            raw[0] = 2;
        }
        assert!(!prove_nodata_nsec3(&[unknown_algorithm], &qname, 1));

        let mut unknown_flags = valid;
        if let RData::Unknown(_, raw) = &mut unknown_flags.rdata {
            raw[1] = 2;
        }
        assert!(!prove_nodata_nsec3(&[unknown_flags], &qname, 1));

        let ce = Name::from_str("example").unwrap();
        let ce_hash = nsec3_hash(&ce, &salt_a, iter);
        let ce_record = nsec3_record(&ce_hash, "example", &salt_a, iter, &[0xff; 20], &[6, 2]);
        let mixed_cover = nsec3_record(&[0x00; 20], "example", &salt_b, iter, &[0xff; 20], &[46]);
        assert!(
            !prove_name_nonexistent_nsec3(&[ce_record, mixed_cover], &qname),
            "서로 다른 salt의 NSEC3 레코드를 한 증명으로 결합하면 안 됨"
        );

        let outside = Name::from_str("host.outside").unwrap();
        let outside_hash = nsec3_hash(&outside, &salt_a, iter);
        let wrong_zone = nsec3_record(
            &outside_hash,
            "example",
            &salt_a,
            iter,
            &[0xff; 20],
            &[28, 46],
        );
        assert!(!prove_nodata_nsec3(&[wrong_zone], &outside, 1));
    }

    #[test]
    /**
     * @brief 1024비트 ZSK로 서명한 영역을 받아들이는지.
     *
     * @details org, nl을 비롯한 여러 영역이 지금도 1024비트 ZSK로 서명한다. 하한이 2048이면
     *          그 영역들의 서명 후보가 아예 만들어지지 않아, 정상 영역이 전부 Bogus가 된다.
     *          실제로 iana.org, nlnetlabs.nl, internetsociety.org가 전부 SERVFAIL이었다.
     * @warning 하한을 올리면 그 크기로 서명하는 모든 영역이 해석되지 않는다.
     */
    fn rfc3110_accepts_the_1024_bit_keys_real_zones_still_use() {
        /* exponent 65537 + 홀수 모듈러스. 앞바이트가 0이 아니고 끝바이트가 홀수여야 한다. */
        let key_with_modulus_bytes = |bytes: usize| {
            let mut raw = vec![3u8, 1, 0, 1];
            raw.extend(std::iter::repeat_n(0xabu8, bytes - 1));
            raw.push(0x8d);
            raw
        };

        for bytes in [128usize, 192, 256, 384, 512] {
            let raw = key_with_modulus_bytes(bytes);
            let (e, n) = parse_rfc3110(&raw)
                .unwrap_or_else(|| panic!("{}비트 키를 읽지 못했습니다", bytes * 8));
            assert_eq!(e, [1, 0, 1]);
            assert_eq!(n.len(), bytes);
        }

        /*
         * 대조군. 1024비트 아래는 그대로 물린다. 받아들일 이유가 없고, 위 단정이
         * 길이 검사를 전부 지워도 통과하지 않게 한다.
         */
        for bytes in [64usize, 96, 127] {
            assert!(
                parse_rfc3110(&key_with_modulus_bytes(bytes)).is_none(),
                "{}비트 키를 받아들였습니다",
                bytes * 8
            );
        }
    }

    #[test]
    /** @brief 여러 기록의 읽기와 적기 왕복. */
    fn parse_roundtrips() {
        let (_, key) = test_key();
        let raw = key.rdata_bytes();
        assert_eq!(Dnskey::parse(&raw), Some(key.clone()));

        assert_ne!(key.key_tag(), 0);

        let mut raw = Vec::new();
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.push(15);
        raw.push(2);
        raw.extend_from_slice(&3600u32.to_be_bytes());
        raw.extend_from_slice(&100u32.to_be_bytes());
        raw.extend_from_slice(&50u32.to_be_bytes());
        raw.extend_from_slice(&0xABCDu16.to_be_bytes());
        canonical_name_into(&Name::from_str("example.com").unwrap(), &mut raw);
        raw.extend_from_slice(&[0xDE, 0xAD]);
        let sig = Rrsig::parse(&raw).unwrap();
        assert_eq!(sig.type_covered, 1);
        assert_eq!(sig.key_tag, 0xABCD);
        assert_eq!(sig.signer.to_ascii_lower(), "example.com");
        assert_eq!(sig.signature, vec![0xDE, 0xAD]);

        let mut dsraw = Vec::new();
        dsraw.extend_from_slice(&0x1234u16.to_be_bytes());
        dsraw.push(15);
        dsraw.push(2);
        dsraw.extend_from_slice(&[1, 2, 3, 4]);
        let ds = Ds::parse(&dsraw).unwrap();
        assert_eq!(ds.key_tag, 0x1234);
        assert_eq!(ds.digest, vec![1, 2, 3, 4]);
    }
}
