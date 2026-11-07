//! Online signing of authoritative zones. Signing builds its input with the same `signed_data`
//! the validator uses, so the two cannot drift apart.

use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use onetdns_proto::{DnsClass, Name, RData, Record, RecordType};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{signed_data, Dnskey, Ds, Rrsig};

/// Tolerates clock skew between validators and this server.
const INCEPTION_SKEW: u64 = 3_600;
/// Shorter means more re-signing; longer means a revoked key stays usable longer.
const VALIDITY: u64 = 14 * 86_400;

/// Algorithm 15 signs more cheaply, but validators that lack it treat the zone as insecure, so the
/// default stays 13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignAlgorithm {
    #[default]
    EcdsaP256,
    Ed25519,
}

impl SignAlgorithm {
    pub fn number(self) -> u8 {
        match self {
            SignAlgorithm::EcdsaP256 => 13,
            SignAlgorithm::Ed25519 => 15,
        }
    }

    /// `None` for an unknown name.
    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "ecdsap256" => Some(SignAlgorithm::EcdsaP256),
            "ed25519" => Some(SignAlgorithm::Ed25519),
            _ => None,
        }
    }
}

/// The single source of the algorithm number: signatures, DNSKEYs and PEM all branch here.
enum SignKey {
    EcdsaP256(SigningKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl SignKey {
    fn algorithm(&self) -> SignAlgorithm {
        match self {
            SignKey::EcdsaP256(_) => SignAlgorithm::EcdsaP256,
            SignKey::Ed25519(_) => SignAlgorithm::Ed25519,
        }
    }

    /// Rehashes a seed that is not a valid key.
    fn from_seed(algorithm: SignAlgorithm, seed: [u8; 32]) -> Self {
        match algorithm {
            SignAlgorithm::EcdsaP256 => SignKey::EcdsaP256(key_from_seed(seed)),
            SignAlgorithm::Ed25519 => {
                let mut seed = Zeroizing::new(seed);
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                seed.zeroize();
                SignKey::Ed25519(Box::new(key))
            }
        }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            SignKey::EcdsaP256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(data);
                signature.to_bytes().to_vec()
            }
            SignKey::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
        }
    }

    /// x||y for P-256, the 32-byte key for Ed25519.
    fn public_key(&self) -> Vec<u8> {
        match self {
            SignKey::EcdsaP256(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                let mut pk = Vec::with_capacity(64);
                pk.extend_from_slice(
                    point
                        .x()
                        .expect("P-256 public key must have an x coordinate"),
                );
                pk.extend_from_slice(
                    point
                        .y()
                        .expect("P-256 public key must have a y coordinate"),
                );
                pk
            }
            SignKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
        }
    }

    fn to_pkcs8_pem(&self) -> Option<Zeroizing<String>> {
        match self {
            SignKey::EcdsaP256(key) => key.to_pkcs8_pem(Default::default()).ok(),
            SignKey::Ed25519(key) => key.to_pkcs8_pem(Default::default()).ok(),
        }
    }

    /// The PEM says which algorithm it holds: P-256 is tried first, then Ed25519.
    fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            return Some(SignKey::EcdsaP256(key));
        }
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .ok()
            .map(|key| SignKey::Ed25519(Box::new(key)))
    }
}

/// Without a KSK the one key also serves as the SEP. With one, the KSK signs the DNSKEY RRset
/// and the ZSK signs the rest.
pub struct ZoneSigner {
    /// Signs everything when there is no KSK.
    key: SignKey,
    /// Signs only the DNSKEY RRset.
    ksk: Option<SignKey>,

    /// The zone apex: signer name and DNSKEY owner.
    pub owner: Name,

    /// Published in the DNSKEY RRset for a rollover but not used to sign.
    published_extra: Vec<Dnskey>,
}

impl ZoneSigner {
    /// One ZSK that also serves as the SEP.
    pub fn generate(owner: Name, seed: [u8; 32]) -> ZoneSigner {
        Self::generate_with(owner, seed, SignAlgorithm::default())
    }

    pub fn generate_with(owner: Name, seed: [u8; 32], algorithm: SignAlgorithm) -> ZoneSigner {
        ZoneSigner {
            key: SignKey::from_seed(algorithm, seed),
            ksk: None,
            owner,
            published_extra: Vec::new(),
        }
    }

    pub fn algorithm(&self) -> SignAlgorithm {
        self.key.algorithm()
    }

    /// Only the KSK goes to the parent as a DS, so the ZSK can roll freely.
    pub fn generate_split(owner: Name, zsk_seed: [u8; 32], ksk_seed: [u8; 32]) -> ZoneSigner {
        Self::generate_split_with(owner, zsk_seed, ksk_seed, SignAlgorithm::default())
    }

    pub fn generate_split_with(
        owner: Name,
        zsk_seed: [u8; 32],
        ksk_seed: [u8; 32],
        algorithm: SignAlgorithm,
    ) -> ZoneSigner {
        ZoneSigner {
            key: SignKey::from_seed(algorithm, zsk_seed),
            ksk: Some(SignKey::from_seed(algorithm, ksk_seed)),
            owner,
            published_extra: Vec::new(),
        }
    }

    /// Restarting with the same key keeps cached signatures valid.
    pub fn from_pkcs8_pem(pem: &str, owner: Name) -> Option<ZoneSigner> {
        let key = SignKey::from_pkcs8_pem(pem)?;
        Some(ZoneSigner {
            key,
            ksk: None,
            owner,
            published_extra: Vec::new(),
        })
    }

    /// `None` when either fails to parse: reading one and generating the other would publish a
    /// DNSKEY that does not match the signing key.
    pub fn from_pkcs8_pems(
        zsk_pem: &str,
        ksk_pem: Option<&str>,
        owner: Name,
    ) -> Option<ZoneSigner> {
        let key = SignKey::from_pkcs8_pem(zsk_pem)?;
        let ksk = match ksk_pem {
            Some(p) => Some(SignKey::from_pkcs8_pem(p)?),
            None => None,
        };
        Some(ZoneSigner {
            key,
            ksk,
            owner,
            published_extra: Vec::new(),
        })
    }

    /// A rollover publishes the new key first and moves signing only after validators have seen it;
    /// switching at once fails validation in between.
    pub fn with_published_keys(mut self, extra: Vec<Dnskey>) -> Self {
        self.published_extra = extra;
        self
    }

    /// Keeps the key across restarts.
    pub fn to_pkcs8_pem(&self) -> Option<Zeroizing<String>> {
        self.key.to_pkcs8_pem()
    }

    /// `None` when the keys are not split.
    pub fn ksk_pem(&self) -> Option<Zeroizing<String>> {
        self.ksk.as_ref()?.to_pkcs8_pem()
    }

    pub fn is_split(&self) -> bool {
        self.ksk.is_some()
    }

    /// The ZSK, the KSK if any, and the prepublished keys.
    pub fn dnskeys(&self) -> Vec<Dnskey> {
        let mut v = vec![self.dnskey()];
        if let Some(k) = self.ksk_dnskey() {
            v.push(k);
        }
        v.extend(self.published_extra.iter().cloned());
        v
    }

    /// Flags 257 (SEP) when there is no KSK, 256 otherwise.
    pub fn dnskey(&self) -> Dnskey {
        let flags = if self.ksk.is_some() { 256 } else { 257 };
        dnskey_of(&self.key, flags)
    }

    /// Always flagged SEP.
    pub fn ksk_dnskey(&self) -> Option<Dnskey> {
        self.ksk.as_ref().map(|k| dnskey_of(k, 257))
    }

    pub fn dnskey_records(&self, ttl: u32) -> Vec<Record> {
        let mut v = vec![Record {
            name: self.owner.clone(),
            rtype: RecordType(48),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(48, self.dnskey().rdata_bytes()),
        }];
        if let Some(ksk) = self.ksk_dnskey() {
            v.push(Record {
                name: self.owner.clone(),
                rtype: RecordType(48),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(48, ksk.rdata_bytes()),
            });
        }

        for k in &self.published_extra {
            v.push(Record {
                name: self.owner.clone(),
                rtype: RecordType(48),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(48, k.rdata_bytes()),
            });
        }
        v
    }

    /// From the KSK if any, else the ZSK. The parent points at this key, so it must not change when
    /// the ZSK rolls.
    pub fn ds(&self) -> Option<Ds> {
        let key = self.ksk_dnskey().unwrap_or_else(|| self.dnskey());
        Ds::from_dnskey(&key, &self.owner, 2)
    }

    /// The child's request for the parent's DS. The parent applies it as is, so it must match the
    /// real SEP key or the delegation breaks.
    pub fn cds_cdnskey_records(&self, ttl: u32) -> Vec<Record> {
        let key = self.ksk_dnskey().unwrap_or_else(|| self.dnskey());
        let Some(ds) = self.ds() else {
            return Vec::new();
        };
        vec![
            Record {
                name: self.owner.clone(),
                rtype: RecordType(59),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(59, ds.rdata_bytes()),
            },
            Record {
                name: self.owner.clone(),
                rtype: RecordType(60),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(60, key.rdata_bytes()),
            },
        ]
    }

    /// Microseconds per Ed25519 signature, for comparison with algorithm 13.
    pub fn bench_ed25519_sign_us(iterations: usize) -> f64 {
        if iterations == 0 {
            return 0.0;
        }
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let message = [0x5au8; 32];
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            let signature = key.sign(std::hint::black_box(&message));
            std::hint::black_box(&signature);
        }
        started.elapsed().as_secs_f64() * 1e6 / iterations as f64
    }

    /// Microseconds per signature over a fixed digest, measuring the curve operation alone.
    pub fn bench_raw_sign_us(&self, iterations: usize) -> f64 {
        if iterations == 0 {
            return 0.0;
        }
        let digest = [0x5au8; 32];
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(self.key.sign(std::hint::black_box(&digest)));
        }
        started.elapsed().as_secs_f64() * 1e6 / iterations as f64
    }

    /// The KSK signs the DNSKEY RRset and the ZSK the rest. The labels field leaves out a leading
    /// `*`, since validators use it to undo wildcard expansion. `None` for an empty RRset.
    pub fn sign_rrset(&self, rrset: &[Record], now: u64) -> Option<Record> {
        let first = rrset.first()?;
        let (signing_key, key_tag) = if first.rtype.0 == 48 {
            match (self.ksk.as_ref(), self.ksk_dnskey()) {
                (Some(key), Some(dnskey)) => (key, dnskey.key_tag()),
                _ => (&self.key, self.dnskey().key_tag()),
            }
        } else {
            (&self.key, self.dnskey().key_tag())
        };

        let labels = first
            .name
            .labels()
            .iter()
            .filter(|l| !l.is_empty() && *l != b"*")
            .count() as u8;
        let mut meta = Rrsig {
            type_covered: first.rtype.0,
            algorithm: signing_key.algorithm().number(),
            labels,
            original_ttl: first.ttl,
            expiration: (now + VALIDITY) as u32,
            inception: now.saturating_sub(INCEPTION_SKEW) as u32,
            key_tag,
            signer: self.owner.clone(),
            signature: Vec::new(),
        };
        let data = signed_data(&meta, rrset);
        meta.signature = signing_key.sign(&data);
        Some(Record {
            name: first.name.clone(),
            rtype: RecordType(46),
            class: DnsClass::IN,
            ttl: first.ttl,
            rdata: RData::Unknown(46, meta.rdata_bytes()),
        })
    }
}

/// Rehashes a seed outside the group order: the chance is negligible, but key generation must not
/// panic.
fn key_from_seed(seed: [u8; 32]) -> SigningKey {
    let mut seed = Zeroizing::new(seed);
    loop {
        if let Ok(k) = SigningKey::from_bytes((&*seed).into()) {
            return k;
        }
        use sha2::Digest as _;
        let next = sha2::Sha256::digest(seed.as_slice()).into();
        seed.zeroize();
        *seed = next;
    }
}

/// The public part of a stored ZSK, for the prepublication list.
pub fn zsk_dnskey_from_pkcs8_pem(pem: &str) -> Option<Dnskey> {
    let key = SignKey::from_pkcs8_pem(pem)?;
    Some(dnskey_of(&key, 256))
}

fn dnskey_of(key: &SignKey, flags: u16) -> Dnskey {
    Dnskey {
        flags,
        protocol: 3,
        algorithm: key.algorithm().number(),
        public_key: key.public_key(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct Nsec3Params {
    /// Each iteration adds validator CPU, so keep it small.
    pub iterations: u16,
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub enum DenialMode {
    /// Simple, but exposes every name in the zone.
    #[default]
    Nsec,
    /// Hides names behind hashes at a higher validation cost.
    Nsec3(Nsec3Params),
}

pub fn sign_zone(records: &[Record], signer: &ZoneSigner, now: u64) -> Vec<Record> {
    sign_zone_with(records, signer, now, &DenialMode::Nsec)
}

/// Removes existing DNSSEC records first, so old and new signatures do not mix. Data below a
/// delegation belongs to the child zone and stays unsigned; at a delegation this server signs only
/// the DS and the denial records.
pub fn sign_zone_with(
    records: &[Record],
    signer: &ZoneSigner,
    now: u64,
    mode: &DenialMode,
) -> Vec<Record> {
    sign_zone_reusing(records, signer, now, mode, &[])
}

/// Re-signing a whole zone for each edit costs time proportional to its size, so an unchanged
/// RRset with enough lifetime left keeps its signature. `previous` must hold only records this
/// server signed and stored itself: an RRSIG from elsewhere would be served unverified. An empty
/// `previous` signs everything.
pub fn sign_zone_reusing(
    records: &[Record],
    signer: &ZoneSigner,
    now: u64,
    mode: &DenialMode,
    previous: &[Record],
) -> Vec<Record> {
    use std::collections::{BTreeMap, HashSet};
    let soa_min = records
        .iter()
        .find_map(|r| match &r.rdata {
            RData::Soa(s) => Some(s.minimum),
            _ => None,
        })
        .unwrap_or(300);

    let mut out: Vec<Record> = records
        .iter()
        .filter(|r| !matches!(r.rtype.0, 46 | 47 | 48 | 50 | 51 | 59 | 60))
        .cloned()
        .collect();
    out.extend(signer.dnskey_records(3_600));
    out.extend(signer.cds_cdnskey_records(3_600));

    let origin_labels = signer.owner.num_labels();
    let mut delegation_names: Vec<Name> = out
        .iter()
        .filter(|record| {
            record.rtype == RecordType::NS && !record.name.eq_ignore_case(&signer.owner)
        })
        .map(|record| record.name.clone())
        .collect();
    delegation_names.sort_by_key(Name::num_labels);
    let mut delegation_keys = HashSet::<Vec<Vec<u8>>>::new();
    for name in delegation_names {
        let below_existing_cut = ((origin_labels + 1)..name.num_labels())
            .any(|labels| delegation_keys.contains(&canonical_key(&name.suffix(labels))));
        if !below_existing_cut {
            delegation_keys.insert(canonical_key(&name));
        }
    }
    let delegation_scope = |name: &Name| -> u8 {
        if delegation_keys.contains(&canonical_key(name)) {
            return 1;
        }
        for labels in (origin_labels + 1)..name.num_labels() {
            if delegation_keys.contains(&canonical_key(&name.suffix(labels))) {
                return 2;
            }
        }
        0
    };

    let mut owners: BTreeMap<Vec<Vec<u8>>, (Name, Vec<u16>)> = BTreeMap::new();
    for r in &out {
        let scope = delegation_scope(&r.name);
        if scope == 2 || scope == 1 && !matches!(r.rtype, RecordType::NS | RecordType::DS) {
            continue;
        }
        let key = canonical_key(&r.name);
        let e = owners
            .entry(key)
            .or_insert_with(|| (r.name.clone(), Vec::new()));
        if !e.1.contains(&r.rtype.0) {
            e.1.push(r.rtype.0);
        }
    }
    let owner_names: Vec<Name> = owners.values().map(|(name, _)| name.clone()).collect();
    for name in owner_names {
        if name.num_labels() < origin_labels
            || !name.suffix(origin_labels).eq_ignore_case(&signer.owner)
        {
            continue;
        }
        for labels in origin_labels..name.num_labels() {
            let ancestor = name.suffix(labels);
            owners
                .entry(canonical_key(&ancestor))
                .or_insert_with(|| (ancestor, Vec::new()));
        }
    }
    let ordered: Vec<(Name, Vec<u16>)> = owners.into_values().collect();

    match mode {
        DenialMode::Nsec => out.extend(build_nsec_chain(&ordered, soa_min)),
        DenialMode::Nsec3(params) => {
            out.push(nsec3param_record(&signer.owner, params, soa_min));
            out.extend(build_nsec3_chain(&signer.owner, &ordered, params, soa_min));
        }
    }

    let mut sets: BTreeMap<(Vec<Vec<u8>>, u16), Vec<Record>> = BTreeMap::new();
    for r in &out {
        sets.entry((canonical_key(&r.name), r.rtype.0))
            .or_default()
            .push(r.clone());
    }
    let mut signable: Vec<&Vec<Record>> = Vec::new();
    let reusable = ReusableSignatures::new(previous, signer, now);
    for rrset in sets.values() {
        let first = &rrset[0];
        let scope = delegation_scope(&first.name);
        if scope == 2 || scope == 1 && !matches!(first.rtype, RecordType::DS | RecordType::NSEC) {
            continue;
        }
        match reusable.take(rrset) {
            Some(sig) => out.push(sig),
            None => signable.push(rrset),
        }
    }
    sign_rrsets_into(&mut out, &signable, signer, now);
    out
}

/// A signature is reused only when the signer, algorithm, key tag, remaining lifetime, original
/// TTL and RRset contents all match.
struct ReusableSignatures<'a> {
    /// Keyed by flat `Name::canonical_key` bytes: per-label vectors would make building this table
    /// cost more than the signing.
    entries: std::collections::HashMap<(Vec<u8>, u16), (&'a Record, Vec<&'a Record>)>,
}

/// Never hands on a signature close to expiry.
const REUSE_MIN_REMAINING: u64 = VALIDITY / 4;

/// Reads only what the reuse check needs, without copying the signature or signer name. Returns
/// (covered type, algorithm, inception, expiration, key tag), or `None` when malformed or signed by
/// a name other than `apex_wire`.
fn rrsig_reuse_header(record: &Record, apex_wire: &[u8]) -> Option<(u16, u8, u32, u32, u16)> {
    let RData::Unknown(46, raw) = &record.rdata else {
        return None;
    };
    if raw.len() < 18 {
        return None;
    }
    let type_covered = u16::from_be_bytes([raw[0], raw[1]]);
    let algorithm = raw[2];
    let expiration = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let inception = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let key_tag = u16::from_be_bytes([raw[16], raw[17]]);
    let signer = raw.get(18..)?;
    if signer.len() < apex_wire.len()
        || !signer[..apex_wire.len()]
            .iter()
            .zip(apex_wire)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return None;
    }
    Some((type_covered, algorithm, inception, expiration, key_tag))
}

impl<'a> ReusableSignatures<'a> {
    fn new(previous: &'a [Record], signer: &ZoneSigner, now: u64) -> Self {
        let mut entries = std::collections::HashMap::new();
        if previous.is_empty() {
            return Self { entries };
        }
        let zsk_tag = signer.dnskey().key_tag();
        let ksk_tag = signer.ksk_dnskey().map(|key| key.key_tag());
        let expected_algorithm = signer.algorithm().number();
        let apex_wire = signer.owner.canonical_key();

        // Reuse needs the old RRset, so collect those first.
        let mut rrsets: std::collections::HashMap<(Vec<u8>, u16), Vec<&'a Record>> =
            std::collections::HashMap::new();
        for record in previous.iter().filter(|record| record.rtype.0 != 46) {
            rrsets
                .entry((record.name.canonical_key(), record.rtype.0))
                .or_default()
                .push(record);
        }

        for record in previous.iter().filter(|record| record.rtype.0 == 46) {
            let Some((type_covered, algorithm, inception, expiration, key_tag)) =
                rrsig_reuse_header(record, &apex_wire)
            else {
                continue;
            };
            let expected_tag = if type_covered == 48 {
                ksk_tag.unwrap_or(zsk_tag)
            } else {
                zsk_tag
            };
            let alive = u64::from(expiration) > now.saturating_add(REUSE_MIN_REMAINING)
                && u64::from(inception) <= now;
            if algorithm != expected_algorithm || key_tag != expected_tag || !alive {
                continue;
            }
            let key = (record.name.canonical_key(), type_covered);
            let Some(rrset) = rrsets.remove(&key) else {
                continue;
            };
            entries.insert(key, (record, rrset));
        }
        Self { entries }
    }

    fn take(&self, rrset: &[Record]) -> Option<Record> {
        let first = rrset.first()?;
        let mut buffer = [0u8; 255];
        let key = first.name.canonical_key_into(&mut buffer)?;
        let (sig, previous) = self.entries.get(&(key.to_vec(), first.rtype.0))?;
        rrsets_identical(rrset, previous).then(|| (*sig).clone())
    }
}

/// TTL is part of the signed data, so it is compared; order is not, since canonical form sorts.
fn rrsets_identical(left: &[Record], right: &[&Record]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // Order-insensitive; the small side makes a quadratic scan enough.
    let same = |a: &Record, b: &Record| {
        a.ttl == b.ttl && a.class == b.class && a.rtype == b.rtype && a.rdata == b.rdata
    };
    let mut used = [false; 8];
    if left.len() > used.len() {
        // Large RRsets are rare; only then compare sorted keys.
        let key = |record: &Record| {
            (
                record.ttl,
                record.class.0,
                crate::canonical_rdata(&record.rdata),
            )
        };
        let mut a: Vec<_> = left.iter().map(key).collect();
        let mut b: Vec<_> = right.iter().map(|record| key(record)).collect();
        a.sort();
        b.sort();
        return a == b;
    }
    for candidate in left {
        let mut matched = false;
        for (index, other) in right.iter().enumerate() {
            if !used[index] && same(candidate, other) {
                used[index] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

/// Below this, starting threads costs more than signing in parallel.
const PARALLEL_SIGN_MIN_RRSETS: usize = 256;

/// RRsets sign independently and the signer is not mutated, so a large zone spreads the work over
/// cores. Chunks are appended in order, so the output does not depend on the core count. A panic in
/// a chunk is re-raised: a half-signed zone would be bogus to validators.
fn sign_rrsets_into(out: &mut Vec<Record>, rrsets: &[&Vec<Record>], signer: &ZoneSigner, now: u64) {
    let sign_part = |part: &[&Vec<Record>]| -> Vec<Record> {
        part.iter()
            .filter_map(|rrset| signer.sign_rrset(rrset, now))
            .collect()
    };

    let threads = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(rrsets.len().max(1));
    if threads < 2 || rrsets.len() < PARALLEL_SIGN_MIN_RRSETS {
        out.extend(sign_part(rrsets));
        return;
    }

    out.reserve(rrsets.len());
    let chunk = rrsets.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let handles: Vec<_> = rrsets
            .chunks(chunk)
            .map(|part| scope.spawn(move || sign_part(part)))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(part) => out.extend(part),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
}

/// The last name's next wraps to the first, which covers names past the end. Each NSEC lists NSEC
/// and RRSIG, which exist at its owner; omitting them would prove NODATA for those types.
fn build_nsec_chain(ordered: &[(Name, Vec<u16>)], ttl: u32) -> Vec<Record> {
    let n = ordered.len();
    let mut nsecs = Vec::with_capacity(n);
    for i in 0..n {
        let (owner, types) = &ordered[i];
        let (next, _) = &ordered[(i + 1) % n];
        let mut all_types: Vec<u16> = types.clone();
        all_types.push(46);
        all_types.push(47);
        let mut rdata = Vec::new();
        crate::canonical_name_into(next, &mut rdata);
        rdata.extend_from_slice(&type_bitmap(&all_types));
        nsecs.push(Record {
            name: owner.clone(),
            rtype: RecordType(47),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(47, rdata),
        });
    }
    nsecs
}

fn nsec3param_record(apex: &Name, p: &Nsec3Params, ttl: u32) -> Record {
    let mut rdata = vec![1u8, 0u8];
    rdata.extend_from_slice(&p.iterations.to_be_bytes());
    rdata.push(p.salt.len() as u8);
    rdata.extend_from_slice(&p.salt);
    Record {
        name: apex.clone(),
        rtype: RecordType(51),
        class: DnsClass::IN,
        ttl,
        rdata: RData::Unknown(51, rdata),
    }
}

/// Sorted by hash; colliding hashes merge, since two NSEC3s at one owner are ambiguous. The apex
/// lists NSEC3PARAM.
fn build_nsec3_chain(
    apex: &Name,
    ordered: &[(Name, Vec<u16>)],
    p: &Nsec3Params,
    ttl: u32,
) -> Vec<Record> {
    let mut nodes: Vec<(Vec<u8>, Vec<u16>)> = ordered
        .iter()
        .map(|(name, types)| {
            let mut t = types.clone();
            t.push(46);
            if name.eq_ignore_case(apex) {
                t.push(51);
            }
            (crate::nsec3_hash(name, &p.salt, p.iterations), t)
        })
        .collect();
    nodes.sort_by(|a, b| a.0.cmp(&b.0));
    nodes.dedup_by(|a, b| a.0 == b.0);

    let n = nodes.len();
    let mut out = Vec::with_capacity(n);
    let mut skipped = 0usize;
    for i in 0..n {
        let (hash, types) = &nodes[i];
        let (next_hash, _) = &nodes[(i + 1) % n];
        let owner_label = crate::base32hex_encode(hash).to_ascii_lowercase();
        let mut owner_labels = Vec::with_capacity(apex.labels().len() + 1);
        owner_labels.push(owner_label.into_bytes());
        owner_labels.extend(apex.labels().map(<[u8]>::to_vec));

        let owner = match Name::from_labels(owner_labels) {
            Ok(owner) => owner,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let mut rdata = vec![1u8, 0u8];
        rdata.extend_from_slice(&p.iterations.to_be_bytes());
        rdata.push(p.salt.len() as u8);
        rdata.extend_from_slice(&p.salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(next_hash);
        rdata.extend_from_slice(&type_bitmap(types));
        out.push(Record {
            name: owner,
            rtype: RecordType(50),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(50, rdata),
        });
    }
    if skipped > 0 {
        onetdns_core::error!(event = "dnssec.nsec3_owner_invalid", zone = %apex.to_ascii_lower(), skipped = skipped, nodes = n, "Could not build an NSEC3 owner name, leaving a gap in the chain; denial proofs for this zone will fail validation");
    }
    out
}

/// Labels reversed and lowercased.
fn canonical_key(name: &Name) -> Vec<Vec<u8>> {
    name.labels()
        .iter()
        .rev()
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/// Canonical form: windows in order, trailing zero octets trimmed, empty windows omitted. The
/// parser accepts only this form.
fn type_bitmap(types: &[u16]) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for &t in types {
        let w = (t >> 8) as u8;
        let lo = (t & 0xff) as usize;
        let bm = windows.entry(w).or_insert([0u8; 32]);
        bm[lo / 8] |= 0x80 >> (lo % 8);
    }
    let mut out = Vec::new();
    for (w, bm) in windows {
        let len = bm.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        if len == 0 {
            continue;
        }
        out.push(w);
        out.push(len as u8);
        out.extend_from_slice(&bm[..len]);
    }
    out
}

/// NODATA needs the one NSEC matching the name; NXDOMAIN also needs NSECs covering the possible
/// wildcards, or validators reject the proof. Returns the minimal set, deduplicated by owner, so
/// the response does not expose the whole chain.
pub fn pick_denial_nsecs(nsecs: &[Record], qname: &Name, nxdomain: bool) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut push = |r: &Record| {
        if !out.iter().any(|x| x.name.eq_ignore_case(&r.name)) {
            out.push(r.clone());
        }
    };
    if !nxdomain {
        for r in nsecs {
            if r.name.eq_ignore_case(qname) {
                push(r);
            }
        }
        return out;
    }

    let mut targets = vec![qname.clone()];
    let labels = qname.labels();
    for i in 1..labels.len() {
        let mut wildcard_labels = vec![b"*".to_vec()];
        wildcard_labels.extend(qname.labels().skip(i).map(<[u8]>::to_vec));
        if let Ok(w) = Name::from_labels(wildcard_labels) {
            targets.push(w);
        }
    }
    for t in &targets {
        for r in nsecs {
            if r.rtype != RecordType(47) {
                continue;
            }
            if let Some(n) = crate::Nsec::from_record(r) {
                if crate::nsec_covers(&r.name, &n.next, t) {
                    push(r);
                }
            }
        }
    }
    out
}

/// NXDOMAIN needs three NSEC3s: one matching the closest encloser, one covering the next closer
/// name and one covering the wildcard. The hash parameters come from the first NSEC3 in the chain.
pub fn pick_denial_nsec3(nsec3s: &[Record], qname: &Name, nxdomain: bool) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut push = |r: &Record| {
        if !out.iter().any(|x| x.name.eq_ignore_case(&r.name)) {
            out.push(r.clone());
        }
    };

    let Some(first) = nsec3s.iter().find_map(crate::Nsec3::from_record) else {
        return out;
    };
    let (salt, iters) = (first.salt.clone(), first.iterations);
    let hash_owner = |r: &Record| -> Option<Vec<u8>> {
        r.name
            .labels()
            .first()
            .and_then(crate::base32hex_decode_pub)
    };
    let covers = |name: &Name| -> Option<Record> {
        let q = crate::nsec3_hash(name, &salt, iters);
        for r in nsec3s {
            if r.rtype != RecordType(50) {
                continue;
            }
            let (Some(owner), Some(n3)) = (hash_owner(r), crate::Nsec3::from_record(r)) else {
                continue;
            };
            if crate::hash_covers_pub(&owner, &n3.next_hashed, &q) {
                return Some(r.clone());
            }
        }
        None
    };
    let matches = |name: &Name| -> Option<Record> {
        let q = crate::nsec3_hash(name, &salt, iters);
        nsec3s
            .iter()
            .find(|r| hash_owner(r).as_deref() == Some(q.as_slice()))
            .cloned()
    };

    if !nxdomain {
        if let Some(r) = matches(qname) {
            push(&r);
        }
        return out;
    }

    let labels = qname.labels();
    let mut ce: Option<Name> = None;
    for count in (0..=labels.len()).rev() {
        let cand = qname.suffix(count);
        if matches(&cand).is_some() {
            ce = Some(cand);
            break;
        }
    }

    if let Some(ce) = &ce {
        if let Some(r) = matches(ce) {
            push(&r);
        }

        let ce_n = ce.num_labels();
        if qname.num_labels() > ce_n {
            let nc = qname.suffix(ce_n + 1);
            if let Some(r) = covers(&nc) {
                push(&r);
            }
        }

        let mut wildcard_labels = vec![b"*".to_vec()];
        wildcard_labels.extend(ce.labels().map(<[u8]>::to_vec));
        if let Ok(w) = Name::from_labels(wildcard_labels) {
            if let Some(r) = covers(&w) {
                push(&r);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::Soa;
    use std::net::Ipv4Addr;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn zone_records() -> Vec<Record> {
        vec![
            Record {
                name: n("example.com"),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: n("ns1.example.com"),
                    rname: n("admin.example.com"),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    minimum: 60,
                }),
            },
            Record::new(n("example.com"), 300, RData::Ns(n("ns1.example.com"))),
            Record::new(
                n("ns1.example.com"),
                300,
                RData::A(Ipv4Addr::new(10, 0, 0, 1)),
            ),
            Record::new(
                n("www.example.com"),
                300,
                RData::A(Ipv4Addr::new(10, 0, 0, 2)),
            ),
        ]
    }

    #[test]
    fn cds_cdnskey_published_and_signed() {
        let signer = ZoneSigner::generate_split(n("example.com"), [3u8; 32], [9u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let apex = n("example.com");

        let cds: Vec<&Record> = signed
            .iter()
            .filter(|r| r.rtype.0 == 59 && r.name.eq_ignore_case(&apex))
            .collect();
        let cdnskey: Vec<&Record> = signed
            .iter()
            .filter(|r| r.rtype.0 == 60 && r.name.eq_ignore_case(&apex))
            .collect();
        assert_eq!(cds.len(), 1, "CDS 1건");
        assert_eq!(cdnskey.len(), 1, "CDNSKEY 1건");

        let ds = signer.ds().unwrap();
        let ksk = signer.ksk_dnskey().unwrap();
        assert_eq!(cds[0].rdata, RData::Unknown(59, ds.rdata_bytes()));
        assert_eq!(cdnskey[0].rdata, RData::Unknown(60, ksk.rdata_bytes()));

        let covers = |tc: u16| {
            signed.iter().any(|r| {
                r.rtype.0 == 46
                    && r.name.eq_ignore_case(&apex)
                    && Rrsig::from_record(r)
                        .map(|s| s.type_covered == tc)
                        .unwrap_or(false)
            })
        };
        assert!(covers(59), "CDS RRSIG");
        assert!(covers(60), "CDNSKEY RRSIG");

        let resigned = sign_zone(&signed, &signer, now);
        assert_eq!(
            resigned.iter().filter(|r| r.rtype.0 == 59).count(),
            1,
            "재서명 CDS 1건"
        );
        assert_eq!(
            resigned.iter().filter(|r| r.rtype.0 == 60).count(),
            1,
            "재서명 CDNSKEY 1건"
        );
    }

    #[test]
    fn pre_published_zsk_in_signed_dnskey_rrset() {
        let next_key = ZoneSigner::generate(n("example.com"), [88u8; 32]).dnskey();
        let signer = ZoneSigner::generate_split(n("example.com"), [3u8; 32], [9u8; 32])
            .with_published_keys(vec![next_key.clone()]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let apex = n("example.com");

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&apex) && r.rtype.0 == 48)
            .cloned()
            .collect();
        assert_eq!(keyset.len(), 3, "ZSK+KSK+차기ZSK");
        assert!(
            keyset
                .iter()
                .any(|r| r.rdata == RData::Unknown(48, next_key.rdata_bytes())),
            "차기 ZSK 게시"
        );

        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&apex) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        let ksk = signer.ksk_dnskey().unwrap();
        crate::validate_rrset(&keyset, &keysigs, &[ksk], now as u32)
            .expect("DNSKEY 검증(차기 키 포함)");

        let next_tag = next_key.key_tag();
        assert!(
            !signed
                .iter()
                .filter(|r| r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .any(|s| s.key_tag == next_tag),
            "차기 ZSK는 서명에 미사용"
        );
    }

    #[test]
    fn ed25519_signed_zone_validates_and_persists() {
        let signer =
            ZoneSigner::generate_with(n("example.com"), [31u8; 32], SignAlgorithm::Ed25519);
        let now = 1_700_000_000u64;
        assert_eq!(signer.algorithm(), SignAlgorithm::Ed25519);
        assert_eq!(signer.dnskey().algorithm, 15);
        assert_eq!(
            signer.dnskey().public_key.len(),
            32,
            "Ed25519 공개 키는 32옥텟입니다"
        );

        let signed = sign_zone(&zone_records(), &signer, now);
        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(sigs.iter().all(|s| s.algorithm == 15));
        crate::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("알고리즘 15 서명이 이 서버의 검증기를 통과해야 합니다");

        // The DNSKEY RRset must validate too, or the chain of trust breaks.
        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &[signer.dnskey()], now as u32)
            .expect("DNSKEY RRset 자기 서명도 검증되어야 합니다");
        assert!(signer.ds().is_some(), "부모에 올릴 DS가 나와야 합니다");

        // The key must survive a restart through PEM.
        let pem = signer.to_pkcs8_pem().expect("Ed25519 PEM 내보내기");
        let restored =
            ZoneSigner::from_pkcs8_pem(&pem, n("example.com")).expect("Ed25519 PEM 읽기");
        assert_eq!(restored.algorithm(), SignAlgorithm::Ed25519);
        assert_eq!(restored.dnskey().public_key, signer.dnskey().public_key);
        assert_eq!(restored.dnskey().key_tag(), signer.dnskey().key_tag());

        // A stored key says which algorithm it is.
        let p256_pem = ZoneSigner::generate(n("example.com"), [7u8; 32])
            .to_pkcs8_pem()
            .expect("P-256 PEM");
        let back = ZoneSigner::from_pkcs8_pem(&p256_pem, n("example.com")).expect("P-256 PEM 읽기");
        assert_eq!(back.algorithm(), SignAlgorithm::EcdsaP256);
        assert_eq!(back.dnskey().algorithm, 13);
    }

    #[test]
    fn resigning_reuses_only_what_is_still_valid_and_unchanged() {
        use std::net::Ipv4Addr;

        let signer = ZoneSigner::generate(n("example.com"), [11u8; 32]);
        let now = 1_700_000_000u64;
        let mut records = zone_records();
        for index in 0..64 {
            records.push(Record::new(
                n(&format!("h{index:03}.example.com")),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8)),
            ));
        }
        let first = sign_zone(&records, &signer, now);

        // With no change every signature is reused, byte for byte.
        let again = sign_zone_reusing(&records, &signer, now + 60, &DenialMode::Nsec, &first);
        let sigs = |zone: &[Record]| -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = zone
                .iter()
                .filter(|r| r.rtype.0 == 46)
                .filter_map(|r| Rrsig::from_record(r).map(|s| s.signature))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            sigs(&first),
            sigs(&again),
            "내용이 그대로면 지난 서명을 그대로 써야 합니다"
        );

        // Changing one address re-signs only that RRset.
        let mut changed = records.clone();
        for record in &mut changed {
            if record.name.eq_ignore_case(&n("h007.example.com")) {
                record.rdata = RData::A(Ipv4Addr::new(203, 0, 113, 9));
            }
        }
        let after = sign_zone_reusing(&changed, &signer, now + 60, &DenialMode::Nsec, &first);
        let target_sig = |zone: &[Record]| -> Option<Vec<u8>> {
            zone.iter()
                .filter(|r| r.name.eq_ignore_case(&n("h007.example.com")) && r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .find(|s| s.type_covered == RecordType::A.0)
                .map(|s| s.signature)
        };
        assert_ne!(
            target_sig(&first),
            target_sig(&after),
            "바뀐 RRset은 새로 서명해야 합니다"
        );
        let untouched = |zone: &[Record]| -> Option<Vec<u8>> {
            zone.iter()
                .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .find(|s| s.type_covered == RecordType::A.0)
                .map(|s| s.signature)
        };
        assert_eq!(
            untouched(&first),
            untouched(&after),
            "안 바뀐 이웃은 지난 서명을 유지해야 합니다"
        );
        // Reused signatures must still validate.
        let rrset: Vec<Record> = after
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let rrsigs: Vec<Rrsig> = after
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(&rrset, &rrsigs, &[signer.dnskey()], (now + 60) as u32)
            .expect("물려받은 서명도 검증되어야 합니다");

        // No reuse close to expiry.
        let late = now + VALIDITY - REUSE_MIN_REMAINING / 2;
        let refreshed = sign_zone_reusing(&records, &signer, late, &DenialMode::Nsec, &first);
        assert_ne!(
            sigs(&first),
            sigs(&refreshed),
            "만료가 가까운 서명은 새로 만들어야 합니다"
        );

        // No reuse across keys.
        let other = ZoneSigner::generate(n("example.com"), [22u8; 32]);
        let foreign = sign_zone_reusing(&records, &other, now + 60, &DenialMode::Nsec, &first);
        assert_ne!(
            sigs(&first),
            sigs(&foreign),
            "다른 키가 만든 서명을 물려받으면 안 됩니다"
        );
        let foreign_rrset: Vec<Record> = foreign
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let foreign_sigs: Vec<Rrsig> = foreign
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(
            &foreign_rrset,
            &foreign_sigs,
            &[other.dnskey()],
            (now + 60) as u32,
        )
        .expect("새 키로 다시 서명한 결과가 그 키로 검증되어야 합니다");
    }

    #[test]
    fn parallel_signing_matches_the_sequential_order_and_signs_everything() {
        use std::net::Ipv4Addr;

        // Large enough to cross the parallel threshold.
        let owners = PARALLEL_SIGN_MIN_RRSETS * 4;
        let signer = ZoneSigner::generate(n("example.com"), [9u8; 32]);
        let now = 1_700_000_000u64;
        let mut records = zone_records();
        for index in 0..owners {
            records.push(Record::new(
                n(&format!("h{index:05}.example.com")),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8)),
            ));
        }

        let signed = sign_zone(&records, &signer, now);
        assert!(
            signed.iter().filter(|r| r.rtype.0 == 46).count() > PARALLEL_SIGN_MIN_RRSETS,
            "병렬 경로를 실제로 태우는 크기여야 합니다"
        );

        // Signatures follow the sorted RRset order whatever the core count.
        let sig_keys: Vec<(Vec<Vec<u8>>, u16)> = signed
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(|r| Rrsig::from_record(r).map(|s| (canonical_key(&r.name), s.type_covered)))
            .collect();
        let mut sorted = sig_keys.clone();
        sorted.sort();
        assert_eq!(sig_keys, sorted, "서명이 정규 순서를 벗어났습니다");

        // No RRset may be left unsigned.
        let mut unsigned: Vec<String> = Vec::new();
        let signed_set: std::collections::HashSet<(Vec<Vec<u8>>, u16)> =
            sig_keys.into_iter().collect();
        for record in signed.iter().filter(|r| r.rtype.0 != 46) {
            if !signed_set.contains(&(canonical_key(&record.name), record.rtype.0)) {
                unsigned.push(format!("{} {}", record.name, record.rtype.0));
            }
        }
        assert!(unsigned.is_empty(), "서명이 빠진 RRset: {unsigned:?}");

        // The signatures must also validate.
        let target = n("h00000.example.com");
        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&target) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&target) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("병렬로 만든 서명도 검증되어야 합니다");
    }

    #[test]
    fn signed_zone_validates_with_own_verifier() {
        let signer = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);

        let dnskey = signer.dnskey();

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(!sigs.is_empty(), "www A RRSIG 존재");
        crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], now as u32).expect("양성 검증");

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &[dnskey.clone()], now as u32)
            .expect("DNSKEY 검증");
        let ds = signer.ds().expect("DS");
        crate::verify_ds(&ds, &dnskey, &n("example.com")).expect("DS 일치");

        let nsecs: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 47).cloned().collect();
        assert!(!nsecs.is_empty(), "NSEC 체인 존재");
        assert!(
            crate::prove_name_nonexistent(&nsecs, &n("nope.example.com")),
            "NXDOMAIN 부재증명"
        );

        assert!(!crate::prove_name_nonexistent(
            &nsecs,
            &n("www.example.com")
        ));

        assert!(
            crate::prove_nodata(&nsecs, &n("www.example.com"), 28),
            "NODATA 증명"
        );
        assert!(
            !crate::prove_nodata(&nsecs, &n("www.example.com"), 1),
            "A는 있음"
        );
    }

    #[test]
    fn nsec3_signed_zone_validates() {
        let signer = ZoneSigner::generate(n("example.com"), [21u8; 32]);
        let now = 1_700_000_000u64;
        let salt = vec![0xab, 0xcd];
        let mode = DenialMode::Nsec3(Nsec3Params {
            iterations: 0,
            salt: salt.clone(),
        });
        let mut source = zone_records();
        source.push(Record::new(
            n("deep.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 3)),
        ));
        let signed = sign_zone_with(&source, &signer, now, &mode);

        let nsec3s: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 50).cloned().collect();
        assert!(nsec3s.len() >= 3, "owner마다 NSEC3");
        assert!(signed.iter().any(|r| r.rtype.0 == 51), "NSEC3PARAM 부착");

        let denial = pick_denial_nsec3(&nsec3s, &n("nope.example.com"), true);
        assert!(!denial.is_empty(), "부재증명 NSEC3 선택");
        assert!(
            crate::prove_name_nonexistent_nsec3(&denial, &n("nope.example.com")),
            "NSEC3 NXDOMAIN 증명"
        );

        let nd = pick_denial_nsec3(&nsec3s, &n("www.example.com"), false);
        assert!(
            crate::prove_nodata_nsec3(&nd, &n("www.example.com"), 28),
            "NSEC3 NODATA"
        );
        assert!(
            !crate::prove_nodata_nsec3(&nd, &n("www.example.com"), 1),
            "A는 있음"
        );

        let deep_query = n("missing.deep.example.com");
        let deep_denial = pick_denial_nsec3(&nsec3s, &deep_query, true);
        let deep_hash = crate::nsec3_hash(&n("deep.example.com"), &salt, 0);
        assert!(deep_denial.iter().any(|record| {
            record
                .name
                .labels()
                .first()
                .and_then(crate::base32hex_decode_pub)
                .is_some_and(|hash| hash == deep_hash)
        }));

        let owner = &nsec3s[0].name;
        let set: Vec<Record> = nsec3s
            .iter()
            .filter(|r| r.name.eq_ignore_case(owner))
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(owner) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 50)
            .collect();
        assert!(!sigs.is_empty(), "RRSIG(NSEC3)");
        crate::validate_rrset(&set, &sigs, &[signer.dnskey()], now as u32)
            .expect("NSEC3 RRSIG 검증");
    }

    /// An empty non-terminal has no records but exists in the tree; leaving it out would prove it
    /// absent.
    #[test]
    fn denial_chains_include_empty_nonterminals() {
        let signer = ZoneSigner::generate(n("example.com"), [31u8; 32]);
        let now = 1_700_000_000u64;
        let mut source = zone_records();
        source.push(Record::new(
            n("leaf.empty.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 4)),
        ));
        let empty = n("empty.example.com");

        let nsec_signed = sign_zone_with(&source, &signer, now, &DenialMode::Nsec);
        let nsecs: Vec<Record> = nsec_signed
            .into_iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .collect();
        assert!(nsecs
            .iter()
            .any(|record| record.name.eq_ignore_case(&empty)));
        assert!(crate::prove_nodata(&nsecs, &empty, RecordType::AAAA.0));

        let params = Nsec3Params {
            iterations: 0,
            salt: vec![0xab, 0xcd],
        };
        let nsec3_signed =
            sign_zone_with(&source, &signer, now, &DenialMode::Nsec3(params.clone()));
        let nsec3s: Vec<Record> = nsec3_signed
            .into_iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .collect();
        let empty_hash = crate::nsec3_hash(&empty, &params.salt, params.iterations);
        assert!(
            nsec3s
                .iter()
                .any(|record| crate::nsec3_owner_hash(record)
                    .is_some_and(|owner| owner == empty_hash))
        );
        assert!(crate::prove_nodata_nsec3(
            &nsec3s,
            &empty,
            RecordType::AAAA.0
        ));
    }

    #[test]
    fn delegation_ns_and_glue_are_not_zone_signed() {
        let signer = ZoneSigner::generate(n("example.com"), [32u8; 32]);
        let now = 1_700_000_000u64;
        let child = n("child.example.com");
        let glue = n("ns.child.example.com");
        let nested = n("deep.child.example.com");
        let mut source = zone_records();
        source.push(Record::new(child.clone(), 300, RData::Ns(glue.clone())));
        source.push(Record::new(
            child.clone(),
            300,
            RData::Unknown(43, vec![0, 1, 13, 2]),
        ));
        source.push(Record::new(
            glue.clone(),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 53)),
        ));
        source.push(Record::new(
            n("host.child.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 54)),
        ));
        source.push(Record::new(
            nested.clone(),
            300,
            RData::Ns(n("ns.deep.child.example.com")),
        ));
        source.push(Record::new(
            nested.clone(),
            300,
            RData::Unknown(43, vec![0, 2, 13, 2]),
        ));

        let signed = sign_zone_with(&source, &signer, now, &DenialMode::Nsec);
        let signatures = |owner: &Name, covered: RecordType| {
            signed
                .iter()
                .filter(|record| record.name.eq_ignore_case(owner))
                .filter_map(Rrsig::from_record)
                .filter(|signature| signature.type_covered == covered.0)
                .count()
        };
        assert_eq!(signatures(&child, RecordType::NS), 0);
        assert_eq!(signatures(&child, RecordType::DS), 1);
        assert_eq!(signatures(&glue, RecordType::A), 0);
        assert_eq!(signatures(&nested, RecordType::DS), 0);
        let child_nsec = signed
            .iter()
            .find(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&child))
            .and_then(crate::Nsec::from_record)
            .expect("delegation NSEC");
        assert!(child_nsec.has_type(RecordType::NS.0));
        assert!(child_nsec.has_type(RecordType::DS.0));
        assert!(!child_nsec.has_type(RecordType::A.0));
        assert!(!signed
            .iter()
            .any(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&glue)));
        assert!(!signed
            .iter()
            .any(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&nested)));

        let params = Nsec3Params {
            iterations: 0,
            salt: vec![0xab, 0xcd],
        };
        let nsec3_signed =
            sign_zone_with(&source, &signer, now, &DenialMode::Nsec3(params.clone()));
        let child_hash = crate::nsec3_hash(&child, &params.salt, params.iterations);
        let glue_hash = crate::nsec3_hash(&glue, &params.salt, params.iterations);
        let nested_hash = crate::nsec3_hash(&nested, &params.salt, params.iterations);
        let hashes: Vec<Vec<u8>> = nsec3_signed
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .filter_map(crate::nsec3_owner_hash)
            .collect();
        assert!(hashes.contains(&child_hash));
        assert!(!hashes.contains(&glue_hash));
        assert!(!hashes.contains(&nested_hash));
    }

    #[test]
    fn dnssec_negative_proof_corpus() {
        let signer = ZoneSigner::generate(n("example.com"), [42u8; 32]);
        let now = 1_700_000_000u64;
        let nowu = now as u32;
        let signed = sign_zone_with(&zone_records(), &signer, now, &DenialMode::Nsec);
        let dnskey = signer.dnskey();

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(!rrset.is_empty() && !sigs.is_empty());

        crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], nowu).expect("기준 양성");

        let expired_at = (now + VALIDITY + 100) as u32;
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], expired_at).is_err(),
            "만료 서명 거부"
        );

        let before = (now - INCEPTION_SKEW - 100) as u32;
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], before).is_err(),
            "미도래 서명 거부"
        );

        let mut tampered = rrset.clone();
        if let RData::A(ip) = &mut tampered[0].rdata {
            *ip = Ipv4Addr::new(6, 6, 6, 6);
        }
        assert!(
            crate::validate_rrset(&tampered, &sigs, &[dnskey.clone()], nowu).is_err(),
            "변조 rrset 거부"
        );

        let mut badsig = sigs.clone();
        badsig[0].signature[0] ^= 0xff;
        assert!(
            crate::validate_rrset(&rrset, &badsig, &[dnskey.clone()], nowu).is_err(),
            "변조 서명 거부"
        );

        let other = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[other.dnskey()], nowu).is_err(),
            "타 키 거부"
        );

        let mut ds = signer.ds().expect("DS");
        ds.digest[0] ^= 0xff;
        assert!(
            crate::verify_ds(&ds, &dnskey, &n("example.com")).is_err(),
            "변조 DS 거부"
        );

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        assert!(
            crate::validate_dnskey_set(
                &keyset,
                &keysigs,
                &[other.ds().unwrap()],
                &n("example.com"),
                nowu
            )
            .is_err(),
            "비매칭 DS → 매칭 KSK 없음으로 거부"
        );
        crate::validate_dnskey_set(
            &keyset,
            &keysigs,
            &[signer.ds().unwrap()],
            &n("example.com"),
            nowu,
        )
        .expect("정상 DNSKEY 검증");

        let nsecs: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 47).cloned().collect();
        assert!(
            crate::prove_name_nonexistent(&nsecs, &n("nope.example.com")),
            "NXDOMAIN 부재증명"
        );
        let owner = nsecs[0].name.clone();
        let nset: Vec<Record> = nsecs
            .iter()
            .filter(|r| r.name.eq_ignore_case(&owner))
            .cloned()
            .collect();
        let nsigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&owner) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 47)
            .collect();
        crate::validate_rrset(&nset, &nsigs, &[dnskey.clone()], nowu).expect("NSEC RRSIG 검증");
        assert!(
            crate::validate_rrset(&nset, &nsigs, &[dnskey.clone()], expired_at).is_err(),
            "만료 NSEC 거부(denial도 시간유효 필요)"
        );
    }

    #[test]
    fn signer_key_persists_via_pem() {
        let s1 = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        let pem = s1.to_pkcs8_pem().expect("pem");
        let s2 = ZoneSigner::from_pkcs8_pem(&pem, n("example.com")).expect("load");
        assert_eq!(
            s1.dnskey().key_tag(),
            s2.dnskey().key_tag(),
            "키 영속화 → 같은 key_tag/DS"
        );
        assert_eq!(s1.ds().unwrap().digest, s2.ds().unwrap().digest);
    }

    #[test]
    fn ksk_zsk_split_signs_and_validates() {
        let signer = ZoneSigner::generate_split(n("example.com"), [31u8; 32], [32u8; 32]);
        assert!(signer.is_split());
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let keys = signer.dnskeys();
        assert_eq!(keys.len(), 2, "ZSK+KSK 게시");
        assert_eq!(signer.dnskey().flags, 256, "ZSK flags 256");
        assert_eq!(signer.ksk_dnskey().unwrap().flags, 257, "KSK flags 257 SEP");

        let ds = signer.ds().unwrap();
        assert_eq!(
            ds.key_tag,
            signer.ksk_dnskey().unwrap().key_tag(),
            "DS는 KSK"
        );

        let keyset: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 48).cloned().collect();
        assert_eq!(keyset.len(), 2);
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &keys, now as u32).expect("DNSKEY(KSK) 검증");

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 1)
            .cloned()
            .collect();
        let asigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 1)
            .collect();
        assert_eq!(asigs[0].key_tag, signer.dnskey().key_tag(), "A는 ZSK 서명");
        crate::validate_rrset(&rrset, &asigs, &keys, now as u32).expect("A(ZSK) 검증");
    }
}
