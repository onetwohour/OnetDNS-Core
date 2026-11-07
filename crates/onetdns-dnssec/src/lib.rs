//! DNSSEC validation and online signing. The chain of trust runs from the root anchor through
//! DS, DNSKEY and RRSIG; skipping any check breaks the whole chain. Validation cost is attack
//! surface: a hostile zone can force many public-key operations per query (KeyTrap), so operations
//! and hash iterations are capped.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

use onetdns_proto::{Name, RData, Reader, Record, RecordType};

mod p256fast;
pub mod tsig;

pub mod sign;

pub mod anchor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecError {
    /// An algorithm or digest this server does not implement: undecidable, not bogus.
    Unsupported(u8),

    BadKey,

    /// The signature did not verify, or the verification budget ran out; both fail closed.
    BadSignature,

    BadDigest,

    /// Malformed input, such as an empty RRset or mismatched owners.
    Invalid,
}

impl std::fmt::Display for DnssecError {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnskey {
    /// Bit 7 zone key, bit 8 revoked, bit 15 SEP.
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
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

    pub fn from_record(rec: &Record) -> Option<Dnskey> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Dnskey::parse(raw),
            _ => None,
        }
    }

    /// Input to the DS digest.
    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.public_key.len());
        v.extend_from_slice(&self.flags.to_be_bytes());
        v.push(self.protocol);
        v.push(self.algorithm);
        v.extend_from_slice(&self.public_key);
        v
    }

    /// The RFC 4034 key tag, a hint and not an identifier: different keys can share it, and a
    /// hostile zone can make them all equal (KeyTrap). A matching tag still needs a real
    /// verification, and attempts need a cap. Allocation-free, since it runs in the N x M candidate
    /// loop.
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

    /// Keys without this bit never validate an RRset.
    pub fn is_zone_key(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Marks a KSK by convention; validation does not depend on it.
    pub fn is_sep(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// RFC 5011. A revoked key validates nothing.
    pub fn is_revoked(&self) -> bool {
        self.flags & 0x0080 != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ds {
    /// A hint, not an identifier.
    pub key_tag: u16,
    pub algorithm: u8,
    /// Only SHA-256 (2) and SHA-384 (4) are accepted.
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl Ds {
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

    /// CDS has the same format.
    pub fn from_record(rec: &Record) -> Option<Ds> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Ds::parse(raw),
            _ => None,
        }
    }

    /// The digest covers the canonical owner name too, so a key cannot be moved to another zone.
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

    pub fn rdata_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.digest.len());
        v.extend_from_slice(&self.key_tag.to_be_bytes());
        v.push(self.algorithm);
        v.push(self.digest_type);
        v.extend_from_slice(&self.digest);
        v
    }
}

/// The start of all validation: a wrong value makes every answer bogus or, worse, lets forgeries
/// through.
pub fn root_trust_anchors() -> Vec<Ds> {
    const KSK_2017_DIGEST: [u8; 32] = [
        0xe0, 0x6d, 0x44, 0xb8, 0x0b, 0x8f, 0x1d, 0x39, 0xa9, 0x5c, 0x0b, 0x0d, 0x7c, 0x65, 0xd0,
        0x84, 0x58, 0xe8, 0x80, 0x40, 0x9b, 0xbc, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xc7, 0xf8,
        0xec, 0x8d,
    ];
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    /// Fewer labels than the owner name means wildcard expansion.
    pub labels: u8,
    /// The TTL in the signed data; the received TTL shrinks in caches and would break validation.
    pub original_ttl: u32,
    /// Compared in RFC 1982 serial arithmetic.
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    /// Must be the zone apex; enforcing it excludes signatures by other zones' keys.
    pub signer: Name,
    pub signature: Vec<u8>,
}

impl Rrsig {
    /// The signer name is never compressed.
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

    pub fn from_record(rec: &Record) -> Option<Rrsig> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Rrsig::parse(raw),
            _ => None,
        }
    }

    /// The signed data uses the RDATA without the signature.
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

/// The signed data is the RRSIG header and the canonical RRset: lowercase owner, original TTL,
/// RDATA order. This runs the public-key operation, so callers must cap the attempts.
pub fn verify_rrsig(rrset: &[Record], rrsig: &Rrsig, key: &Dnskey) -> Result<(), DnssecError> {
    let first = validate_rrset_shape(rrset)?;
    if rrsig.algorithm != key.algorithm || !rrsig_applies_to_rrset(rrsig, first) {
        return Err(DnssecError::Invalid);
    }
    verify_rrsig_crypto(rrset, rrsig, key)
}

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

/// Cheap checks before any public-key operation.
fn rrsig_applies_to_rrset(rrsig: &Rrsig, first: &Record) -> bool {
    rrsig.type_covered == first.rtype.0
        && usize::from(rrsig.labels) <= first.name.num_labels()
        && name_is_within(&first.name, &rrsig.signer)
}

fn signature_algorithm_supported(algorithm: u8) -> bool {
    matches!(algorithm, 8 | 10 | 13 | 14 | 15)
}

/// The public-key operation for one candidate that passed the structural checks.
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

/// Built once, without an intermediate DNSKEY RDATA allocation.
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
    static DS_DIGEST_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// SHA-1 is not supported.
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

fn verify_ed25519(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), DnssecError> {
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| DnssecError::BadKey)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| DnssecError::BadKey)?;
    let sigb: [u8; 64] = sig.try_into().map_err(|_| DnssecError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sigb);
    vk.verify_strict(msg, &signature)
        .map_err(|_| DnssecError::BadSignature)
}

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

/// The modulus floor is below TLS's, since org, nl and other zones still sign with 1024-bit ZSKs.
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

/// 1024 bits. org, nl and other zones still sign with 1024-bit ZSKs; a 2048-bit floor as in TLS
/// would make them all bogus. Raising this breaks every zone that signs at that size.
const MIN_RSA_MODULUS_BYTES: usize = 128;

/// RFC 3110: an exponent length that does not fit one byte comes as 0 and two bytes. A zero length
/// or one past the end is rejected.
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

/// RFC 1982 serial comparison. A plain comparison would treat a wrapped time as forever past and
/// every signature as expired.
fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

/// Also honours the global accept-expired setting.
pub fn rrsig_time_valid(rrsig: &Rrsig, now: u32) -> bool {
    rrsig_time_valid_accepting(rrsig, now, false)
}

/// `accept_expired` passes expired signatures; it is a stopgap for bad clocks and does not stop
/// replay.
pub fn rrsig_time_valid_accepting(rrsig: &Rrsig, now: u32, accept_expired: bool) -> bool {
    serial_le(rrsig.inception, now) && (accept_expired || serial_le(now, rrsig.expiration))
}

/// For machines with badly wrong clocks; it weakens the defense.
static ACCEPT_EXPIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// An escape hatch for hosts without clock sync: expired, long-revoked signatures pass. Not for
/// production.
pub fn set_accept_expired(v: bool) {
    ACCEPT_EXPIRED.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn accept_expired_now() -> bool {
    ACCEPT_EXPIRED.load(std::sync::atomic::Ordering::Relaxed)
}

/// One step of the chain of trust: a zone's DNSKEYs and its delegation evidence. Ordered from the
/// root to the leaf.
pub struct ChainLink {
    pub zone: Name,

    /// The raw records, as signature validation needs their canonical form.
    pub dnskeys: Vec<Record>,

    /// Must be signed by a KSK.
    pub dnskey_rrsigs: Vec<Rrsig>,

    /// The DS RRset for the child; empty means the delegation is unsigned.
    pub ds_records: Vec<Record>,
    /// Validated with the parent zone's keys.
    pub ds_rrsigs: Vec<Rrsig>,

    /// NSEC records proving the DS absent, for a secure end of delegation.
    pub ds_nsec_records: Vec<Record>,
    pub ds_nsec_rrsigs: Vec<Rrsig>,
    pub ds_nsec3_records: Vec<Record>,
    pub ds_nsec3_rrsigs: Vec<Rrsig>,

    /// Parsed `ds_records`, the trust basis for the next step.
    pub ds: Vec<Ds>,
}

/// Public-key operations allowed while validating one RRset. RFC 4035 says to try every
/// candidate until one verifies; a zone returning N DNSKEYs with colliding tags and M RRSIGs
/// would then force N x M operations per query (KeyTrap, CVE-2023-50387). A normal zone signs
/// with one ZSK, two during a rollover. Exceeding this fails closed as bogus.
const MAX_SIGNATURE_VERIFICATIONS: usize = 8;

/// DS digest computations allowed per DNSKEY RRset. A normal rollover needs one or two KSKs and
/// digest types; this stops colliding DNSKEY and DS fan-out from hashing without bound.
const MAX_DS_DIGEST_COMPUTATIONS: usize = 32;

#[derive(Default)]
struct DsDigestBudget {
    computations: usize,
}

impl DsDigestBudget {
    /// Fails closed at the cap.
    fn charge(&mut self) -> Result<(), DnssecError> {
        if self.computations >= MAX_DS_DIGEST_COMPUTATIONS {
            return Err(DnssecError::BadSignature);
        }
        self.computations += 1;
        Ok(())
    }
}

#[derive(Debug)]
/// Shared across one DNS response.
pub struct VerificationBudget {
    attempts: usize,
}

impl VerificationBudget {
    pub fn new() -> Self {
        Self { attempts: 0 }
    }

    /// Fails closed at the cap.
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

/// Does not enforce the signer. Callers that know the apex must use `validate_rrset_in_zone`;
/// this form accepts data signed with any zone's key.
pub fn validate_rrset(
    rrset: &[Record],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    now: u32,
) -> Result<(), DnssecError> {
    let mut budget = VerificationBudget::new();
    validate_rrset_for_signer(rrset, rrsigs, keys, now, None, &mut budget, |_, _| true)
}

/// The default form. Without binding the signer, an attacker could sign an RRset with their own
/// zone's key and splice it into another zone's answer.
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

/// Stops at the first zone signature that also satisfies `predicate`, so checks that follow the
/// cryptography, such as wildcard context, share one budget. `predicate` runs only on signatures
/// that verified, and a valid signature it rejects still counts against the budget.
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

/// `predicate` must use the same budget when it validates other RRsets.
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

/// Succeeds on the first signature that verifies. Only combinations that pass the cheap filters
/// (key tag, algorithm, protocol, zone key, revoke) reach a public-key operation, and those never
/// exceed `MAX_SIGNATURE_VERIFICATIONS`. `expected_signer` of `None` does not enforce the signer.
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

/// Checks that the DNSKEY records belong to the apex, keeps only keys whose digest matches a
/// trusted DS as KSK candidates, and trusts the RRset once a candidate validates its signature:
/// the DS names one KSK, and its signature vouches for the ZSKs. `Invalid` when the records are
/// malformed or no key matches a DS, `BadSignature` when no candidate validates the RRset.
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

/// Hashes once per key and digest type even when DS records repeat, and looks the result up in the
/// digest set.
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

/// Enforces the leaf zone as the signer, so an answer signed by an intermediate zone's key fails.
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

/// Replaces `trusted_ds` with the child's only after the child DS RRset validates with this zone's
/// keys; replacing it first would trust an unsigned DS. Does not tell insecure delegations apart;
/// use `validate_chain_status` for Secure, Insecure and Bogus.
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

/// Selecting from untrusted data is safe, since the selection is trusted only after every
/// signature here verifies; this keeps unrelated NSEC and RRSIG records from costing public-key
/// operations.
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

/// Only a proof of an unsigned delegation counts; a proof that the name exists, or that it is not
/// a cut, is not DS absence. False means the end of delegation cannot be trusted: Bogus, not
/// Insecure.
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

/// Signatures not yet checked.
pub struct DenialEvidence<'a> {
    pub nsec: &'a [Record],
    pub nsec_rrsigs: &'a [Rrsig],
    pub nsec3: &'a [Record],
    pub nsec3_rrsigs: &'a [Rrsig],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsAbsence {
    /// Nothing below needs validation.
    InsecureDelegation,
    /// The name is inside the parent zone and must be signed with the parent's keys.
    NotACut,
    Unproven,
}

/// Reads the type bitmap of the NSEC or NSEC3 matching the name (RFC 4035, RFC 5155). NS without
/// DS or SOA is an unsigned delegation; no NS is an ordinary name in the parent zone. A name only
/// covered by an interval has no RRsets, so it cannot be a cut; an NSEC3 opt-out interval may hide
/// an unsigned delegation, so it counts as one. Deciding from the DS bit alone would let an answer
/// stripped of its signatures pass as an unsigned delegation.
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

/// Insecure and Bogus must stay apart: an insecure zone is answered, a bogus one gets SERVFAIL.
pub enum ChainStatus {
    /// With the leaf zone's trusted keys.
    Secure(Vec<Dnskey>),
    Insecure,
    Bogus,
}

pub fn validate_chain_status(root_anchors: &[Ds], links: &[ChainLink], now: u32) -> ChainStatus {
    validate_chain_status_with_options(root_anchors, links, now, false)
}

/// Without a DS absence proof, a missing DS drops to Insecure; an attacker who strips the DS can
/// then disable validation. `validate_chain_status_with_options` can require the proof.
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

/// A missing DS with steps left below is the end of delegation; so is a DS set with no algorithm
/// or digest this server supports, since that is a lack of means, not a forgery. With
/// `require_ds_absence_proof` the absence must be proven by signed NSEC or NSEC3, or it is Bogus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKeySentinel {
    IsTa(u16),
    NotTa(u16),
}

impl RootKeySentinel {
    /// RFC 8509: root-key-sentinel-is-ta- or root-key-sentinel-not-ta- followed by a five-digit
    /// zero-padded key tag.
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

    /// Whether to answer SERVFAIL, given the root anchors trusted now.
    pub fn fails(self, anchors: &[Ds]) -> bool {
        match self {
            RootKeySentinel::IsTa(tag) => !anchors.iter().any(|ds| ds.key_tag == tag),
            RootKeySentinel::NotTa(tag) => anchors.iter().any(|ds| ds.key_tag == tag),
        }
    }
}

/// Algorithms 8, 10, 13, 14 and 15, digests 2 and 4. SHA-1 is excluded for its collisions. A
/// delegation with only unsupported DS records is Insecure, not Bogus.
pub fn ds_is_supported(ds: &Ds) -> bool {
    matches!(ds.algorithm, 8 | 10 | 13 | 14 | 15) && matches!(ds.digest_type, 2 | 4)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    pub next: Name,
    pub types: Vec<u16>,
}

impl Nsec {
    /// `next` is never compressed, so the offset is safe. The rest is the type bitmap; a malformed
    /// one yields `None`.
    pub fn parse(raw: &[u8]) -> Option<Nsec> {
        let mut r = Reader::new(raw);
        let next = Name::parse(&mut r).ok()?;
        let types = parse_type_bitmaps(raw.get(r.pos..)?)?;
        Some(Nsec { next, types })
    }

    pub fn from_record(rec: &Record) -> Option<Nsec> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Nsec::parse(raw),
            _ => None,
        }
    }

    pub fn has_type(&self, t: u16) -> bool {
        self.types.contains(&t)
    }
}

/// RFC 4034 canonical order: labels compared from the TLD end, so siblings sit next to each other
/// and an NSEC interval holds. A shorter name sorts first. The labels are collected once and read
/// backwards, since reversing the iterator rescans the name per step and a sort comparator would
/// turn quadratic.
pub fn canonical_name_cmp(a: &Name, b: &Name) -> Ordering {
    // A wire name is at most 255 octets and each non-root label has a length octet, so there are at
    // most 127 labels and this array needs no heap. `take` only guards a broken invariant.
    const MAX_LABELS: usize = 128;
    let empty: &[u8] = &[];
    let mut abuf = [empty; MAX_LABELS];
    let mut bbuf = [empty; MAX_LABELS];
    let mut an = 0usize;
    for label in a.labels().take(MAX_LABELS) {
        abuf[an] = label;
        an += 1;
    }
    let mut bn = 0usize;
    for label in b.labels().take(MAX_LABELS) {
        bbuf[bn] = label;
        bn += 1;
    }
    loop {
        match (an, bn) {
            (0, 0) => return Ordering::Equal,
            (0, _) => return Ordering::Less,
            (_, 0) => return Ordering::Greater,
            _ => {
                an -= 1;
                bn -= 1;
                match canonical_label_cmp(abuf[an], bbuf[bn]) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
        }
    }
}

/// Case-insensitive by octet; a shorter common prefix sorts first. A case-sensitive compare would
/// give one name two positions and break denial proofs.
fn canonical_label_cmp(a: &[u8], b: &[u8]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let (lx, ly) = (x.to_ascii_lowercase(), y.to_ascii_lowercase());
        if lx != ly {
            return lx.cmp(&ly);
        }
    }
    a.len().cmp(&b.len())
}

/// Exclusive at both ends. The last NSEC wraps to the apex (next <= owner), and then either bound
/// alone covers; a plain range check would leave names past the end unproven.
pub fn nsec_covers(owner: &Name, next: &Name, qname: &Name) -> bool {
    let owner_lt_q = canonical_name_cmp(owner, qname) == Ordering::Less;
    let q_lt_next = canonical_name_cmp(qname, next) == Ordering::Less;
    if canonical_name_cmp(owner, next) == Ordering::Less {
        owner_lt_q && q_lt_next
    } else {
        owner_lt_q || q_lt_next
    }
}

/// Either the NSEC matching the name lacks the type, or the name does not exist and the closest
/// encloser, the covered next closer and a wildcard lacking the type are all shown. Without the
/// wildcard, an answer `*.example` gives could be denied as NODATA.
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

/// Returns only the records the proof used, so a response built from it exposes nothing else.
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

/// Both the next closer and its wildcard must be covered; without the wildcard proof a name the
/// wildcard answers could be forged into NXDOMAIN.
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

/// Returns the deduplicated records the proof used.
pub fn nsec_name_nonexistent_proof(nsec_records: &[Record], qname: &Name) -> Option<Vec<Record>> {
    let (ce, ce_record) = nsec_closest_encloser_record(nsec_records, qname)?;
    let next_closer = qname.suffix(ce.num_labels() + 1);
    let next_record = nsec_covering_record(nsec_records, &next_closer)?;
    let wildcard = wildcard_name(&ce)?;
    let wildcard_record = nsec_covering_record(nsec_records, &wildcard)?;
    Some(unique_records([ce_record, next_record, wildcard_record]))
}

/// A wildcard answer must come with an NSEC showing the next closer absent; otherwise a more
/// specific name could be hidden behind the wildcard. `closest_encloser_labels` comes from the
/// RRSIG labels field; false when it is not shorter than `qname`.
pub fn prove_wildcard_expansion(
    nsec_records: &[Record],
    qname: &Name,
    closest_encloser_labels: usize,
) -> bool {
    nsec_wildcard_expansion_proof(nsec_records, qname, closest_encloser_labels).is_some()
}

/// Selecting before signature validation keeps unrelated NSEC and RRSIG records from forcing
/// public-key operations. The selection is untrusted until the caller validates it.
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

/// Takes the longest suffix: a shorter ancestor also has an NSEC, but its next closer would make
/// the proof weaker.
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

fn nsec_covering_record<'a>(nsec_records: &'a [Record], name: &Name) -> Option<&'a Record> {
    nsec_records.iter().find(|record| {
        record.rtype == RecordType::NSEC
            && Nsec::from_record(record)
                .is_some_and(|nsec| nsec_covers(&record.name, &nsec.next, name))
    })
}

/// CNAME counts as well, since a query for any type follows a CNAME; ignoring it would call an
/// answerable query NODATA.
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

/// One NSEC can serve as closest encloser, next closer and wildcard, so duplicates go. TTL is not
/// compared.
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

/// Copies label octets as is; a string round trip would damage non-ASCII labels. `None` past 255
/// octets.
fn wildcard_name(encloser: &Name) -> Option<Name> {
    let mut labels = Vec::with_capacity(encloser.labels().len() + 1);
    labels.push(b"*".to_vec());
    labels.extend(encloser.labels().map(<[u8]>::to_vec));
    Name::from_labels(labels).ok()
}

const BASE32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Hard cap on an external zone's NSEC3 iterations.
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

/// SHA-1 calls one denial proof may spend. A name hash costs iterations + 1 calls, and the
/// closest-encloser search over a deep QNAME multiplies that, so the product is capped too.
const MAX_NSEC3_HASH_ROUNDS: usize = 8_192;

#[derive(Default)]
/// SHA-1 rounds shared by one NSEC3 proof or cache candidate search.
pub struct Nsec3HashBudget {
    used: usize,
}

impl Nsec3HashBudget {
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
    static NSEC3_HASH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static NSEC3_PARSE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// RFC 5155: SHA1(canonical name || salt), then SHA1(previous || salt) `iterations` more times.
/// The zone, not the querier, picks the count, so code calling this directly owns the cap; the
/// public denial API enforces 150 iterations and 8192 rounds per proof. SHA-1 is the only
/// algorithm RFC 5155 defines, and the goal is hiding names, not collision resistance.
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

/// Unpadded: owner labels are a fixed 20 bytes, and `=` is not allowed in a DNS name.
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

/// Case-insensitive. Rejects five or more leftover bits (a wrong length) and nonzero leftover
/// bits; otherwise one hash would have several spellings and owner comparison could be fooled.
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

fn base32hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'v' => Some(c - b'a' + 10),
        b'A'..=b'V' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Enforces canonical form: strictly increasing windows, block lengths 1..=32, no trailing zero
/// octet. Otherwise one type set would have several encodings, and the bitmap the signature
/// covered could differ from the one read here.
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

/// Checks canonical form without allocating.
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

/// Hides names behind hashes against zone walking; the parameters must match across the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    /// RFC 5155 defines only SHA-1 (1).
    pub hash_alg: u8,
    /// The low bit is opt-out; the rest are reserved.
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed: Vec<u8>,
    pub types: Vec<u16>,
}

impl Nsec3 {
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

    pub fn from_record(rec: &Record) -> Option<Nsec3> {
        match &rec.rdata {
            RData::Unknown(_, raw) => Nsec3::parse(raw),
            _ => None,
        }
    }

    pub fn has_type(&self, t: u16) -> bool {
        self.types.contains(&t)
    }
}

/// Borrows the variable fields from the RDATA, for the allocation-free proof path.
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

    fn has_type(self, rtype: u16) -> bool {
        type_bitmap_has(self.type_bitmap, rtype)
    }
}

pub fn base32hex_decode_pub(s: &[u8]) -> Option<Vec<u8>> {
    base32hex_decode(s)
}

pub fn hash_covers_pub(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    hash_covers(owner, next, q)
}

/// The first label decoded from base32hex; the rest is the zone name.
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

#[cfg(test)]
fn nsec3_owner_hash(rec: &Record) -> Option<Vec<u8>> {
    Some(nsec3_owner_hash_fixed(rec)?.to_vec())
}

/// Exclusive at both ends; the last NSEC3 wraps (next <= owner), and then either bound alone
/// covers.
fn hash_covers(owner: &[u8], next: &[u8], q: &[u8]) -> bool {
    if owner < next {
        owner < q && q < next
    } else {
        owner < q || q < next
    }
}

/// Callers compare this against the cap before validating: the zone picks the count, and it sets
/// this server's CPU cost per query.
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

struct ValidatedNsec3Record<'a> {
    source: &'a Record,
    parsed: Nsec3Ref<'a>,
    owner: [u8; 20],
}

/// NSEC3 records of one proof with validated, shared parameters.
struct ValidatedNsec3Set<'a> {
    records: Vec<ValidatedNsec3Record<'a>>,
}

enum Nsec3NodataSelection<'a> {
    Exact(&'a Record),
    Expanded([&'a Record; 3]),
}

struct Nsec3NameSelection<'a> {
    records: [&'a Record; 3],
    relies_on_opt_out: bool,
}

impl Nsec3NodataSelection<'_> {
    fn into_records(self) -> Vec<Record> {
        match self {
            Self::Exact(record) => vec![record.clone()],
            Self::Expanded(records) => unique_records(records),
        }
    }
}

impl<'a> ValidatedNsec3Set<'a> {
    /// Parses each RDATA exactly once and checks that the records form one hash space.
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

    fn query_hash(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<Vec<u8>> {
        let params = &self.records[0].parsed;
        budget.hash(name, params.salt, params.iterations)
    }

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

    fn matching_record(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| record.owner == query_hash.as_slice())
            .map(|record| record.source)
    }

    fn covering_record(&self, name: &Name, budget: &mut Nsec3HashBudget) -> Option<&'a Record> {
        let query_hash = self.query_hash(name, budget)?;
        self.records
            .iter()
            .find(|record| hash_covers(&record.owner, record.parsed.next_hashed, &query_hash))
            .map(|record| record.source)
    }

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

/// Checks parameter consistency and the hard iteration cap first: records with mixed parameters
/// come from different hash spaces and prove nothing.
pub fn prove_nodata_nsec3(nsec3_records: &[Record], qname: &Name, qtype: u16) -> bool {
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    nsec3_nodata_selection(&prepared, qname, qtype, &mut budget).is_some()
}

/// Returns the deduplicated records the proof used.
pub fn nsec3_nodata_proof(
    nsec3_records: &[Record],
    qname: &Name,
    qtype: u16,
) -> Option<Vec<Record>> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    Some(nsec3_nodata_selection(&prepared, qname, qtype, &mut budget)?.into_records())
}

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

/// Tries a plain NODATA proof, then opt-out: an opt-out interval may hold unsigned delegations, so
/// it proves the DS absent without a matching NSEC3. This relaxation is for DS only.
pub fn prove_ds_absence_nsec3(nsec3_records: &[Record], child_zone: &Name) -> bool {
    nsec3_ds_absence_proof(nsec3_records, child_zone).is_some()
}

/// The records are only a syntactic proof; validate each RRset's signatures before trusting them.
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

/// For the wildcard, requires no matching NSEC3 besides coverage: a match means the wildcard
/// exists.
pub fn prove_name_nonexistent_nsec3(nsec3_records: &[Record], qname: &Name) -> bool {
    let Some(prepared) = ValidatedNsec3Set::new(nsec3_records, qname) else {
        return false;
    };
    let mut budget = Nsec3HashBudget::default();
    nsec3_name_nonexistent_selection(&prepared, qname, &mut budget).is_some()
}

/// Returns the deduplicated records the proof used.
pub fn nsec3_name_nonexistent_proof(nsec3_records: &[Record], qname: &Name) -> Option<Vec<Record>> {
    let prepared = ValidatedNsec3Set::new(nsec3_records, qname)?;
    let mut budget = Nsec3HashBudget::default();
    let selection = nsec3_name_nonexistent_selection(&prepared, qname, &mut budget)?;
    Some(unique_records(selection.records))
}

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

/// Requires an NSEC3 matching the closest encloser, unlike NSEC, since coverage alone cannot show
/// an ancestor exists in hash space.
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

/// The iteration and per-proof round caps apply before hashing.
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

fn name_is_within(name: &Name, zone: &Name) -> bool {
    name.ends_with_ignore_case(zone)
}

/// An opt-out proof says only that the name, if present, is unsigned; callers must downgrade the
/// result to Insecure.
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

/// RFC 4034 signed data, byte-identical for signer and validator: lowercase owner, RDATA in
/// canonical order, the RRSIG's original TTL rather than the received one, and type_covered as
/// the type.
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

/// Fewer RRSIG labels than the name means wildcard expansion, and the signature covers
/// `*.<encloser>`. On failure the name is returned unchanged and validation fails closed.
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

/// Never compressed, since the signed data must not depend on message position.
fn canonical_name_into(name: &Name, out: &mut Vec<u8>) {
    for label in name.labels() {
        out.push(label.len() as u8);
        for &b in label {
            out.push(b.to_ascii_lowercase());
        }
    }
    out.push(0);
}

/// Lowercases names only in the types RFC 4034 lists; lowercasing others would diverge from the
/// signer. Unparsed RDATA is used as received, so unknown types still validate.
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

pub const ZONEMD_TYPE: u16 = 63;

/// Checks that a transferred zone is complete; RRSIG covers single RRsets, while this catches
/// dropped records.
pub struct Zonemd {
    /// When it differs from the zone's serial there is nothing to compute.
    pub serial: u32,
    /// RFC 8976 defines only SIMPLE (1).
    pub scheme: u8,
    /// SHA-384 (1) or SHA-512 (2).
    pub hash_alg: u8,
    /// Its length must match the algorithm.
    pub digest: Vec<u8>,
}

impl Zonemd {
    /// `None` when the type differs or the 6-byte header is short.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZonemdResult {
    Verified,

    Absent,

    /// A supported ZONEMD exists and none matches; the zone must not be accepted.
    Mismatch,

    /// Every ZONEMD has an unknown scheme, algorithm or length.
    Unsupported,
}

/// Verified when any apex ZONEMD matches; RFC 8976 allows several. Unsupported and Mismatch are
/// kept apart because the first is a lack of means and the second a broken zone. Records whose
/// serial differs from `soa_serial` are skipped.
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

/// Excludes the apex ZONEMD and its RRSIG, which would make the digest circular, sorts the rest by
/// name, type and RDATA, and hashes each distinct record once. `None` for an unsupported
/// algorithm.
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

#[cfg(test)]
mod zonemd_tests {
    use super::*;
    use onetdns_proto::{Record, Soa};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn zonemd_apex_match_preserves_raw_name_octets() {
        let apex = Name::from_str("�").unwrap();
        let raw_owner = Name::from_labels(vec![vec![0xff]]).unwrap();
        let mut rdata = 1u32.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[1, 1]);
        rdata.extend_from_slice(&[0; 48]);
        let record = Record::new(raw_owner, 60, RData::Unknown(ZONEMD_TYPE, rdata));

        assert_eq!(verify_zonemd(&[record], &apex, 1), ZonemdResult::Absent);
    }

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
    fn rfc8976_a1_simple_vector() {
        let (zone, apex) = rfc_zone();
        let digest = compute_zonemd_simple(&zone, &apex, 1).unwrap();
        assert_eq!(
            hex(&digest),
            "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c"
        );
    }

    #[test]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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

    fn a_record(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::new(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(Ipv4Addr::from(ip)),
        )
    }

    #[test]
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

    /// The tag sums the RDATA's 16-bit words, so fixing the sum of the first two words gives
    /// distinct keys one tag, as a KeyTrap attack would.
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
    fn ecdsa_p256_roundtrip_verifies_and_tamper_fails() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
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
    fn ecdsa_p384_roundtrip_verifies_and_tamper_fails() {
        use p384::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[0x42u8; 48]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
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

    /// Signs with `rsa::testsign`, which is not constant time and is for tests only.
    fn rsa_test_key_pair() -> onetdns_core::rsa::testsign::TestRsaKey {
        let private_der = crate::tsig::b64_decode(include_str!(
            "../../../testdata/rsa_test_private_key_2048.pk8.b64"
        ))
        .unwrap();
        onetdns_core::rsa::testsign::TestRsaKey::from_pkcs8(&private_der).unwrap()
    }

    /// An exponent longer than 255 bytes uses 0 and a 16-bit length.
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

        // The floor is 1024 bits: sizes in real use pass, smaller ones fail.
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

    fn p256_key(seed: u8) -> (p256::ecdsa::SigningKey, Dnskey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        let dnskey = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: point.as_bytes()[1..].to_vec(),
        };
        (sk, dnskey)
    }

    fn dnskey_rec(zone: &str, key: &Dnskey) -> Record {
        Record::new(
            Name::from_str(zone).unwrap(),
            3600,
            RData::Unknown(48, key.rdata_bytes()),
        )
    }

    /// Builds the signed data with `signed_data`, so the test exercises signing rather than a
    /// canonical-form mismatch.
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
    fn canonical_name_cmp_orders_deep_names() {
        let deep = |first: &str| {
            let mut s = String::from(first);
            for _ in 0..60 {
                s.push_str(".a");
            }
            s.push_str(".test");
            Name::from_str(&s).unwrap()
        };
        let a = deep("a");
        let b = deep("b");
        assert_eq!(canonical_name_cmp(&a, &b), Ordering::Less);
        assert_eq!(canonical_name_cmp(&b, &a), Ordering::Greater);
        assert_eq!(canonical_name_cmp(&a, &a), Ordering::Equal);

        let parent = Name::from_str("test").unwrap();
        assert_eq!(canonical_name_cmp(&parent, &a), Ordering::Less);
        assert_eq!(canonical_name_cmp(&a, &parent), Ordering::Greater);
    }

    #[test]
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
    fn nsec3_hash_rfc5155_vector() {
        let h = nsec3_hash(
            &Name::from_str("example").unwrap(),
            &[0xaa, 0xbb, 0xcc, 0xdd],
            12,
        );
        assert_eq!(base32hex_encode(&h), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
    }

    #[test]
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
    /// org, nl and other zones still sign with 1024-bit ZSKs; a 2048-bit floor would make them all
    /// bogus.
    fn rfc3110_accepts_the_1024_bit_keys_real_zones_still_use() {
        // Exponent 65537 and an odd modulus with a nonzero first byte.
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

        // Below 1024 bits is still rejected, so this test fails if the length check is removed.
        for bytes in [64usize, 96, 127] {
            assert!(
                parse_rfc3110(&key_with_modulus_bytes(bytes)).is_none(),
                "{}비트 키를 받아들였습니다",
                bytes * 8
            );
        }
    }

    #[test]
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
