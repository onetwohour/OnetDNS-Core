//! Validates forwarded responses itself. Recursion collects DNSKEY and DS on its way down the
//! delegations; forwarding has no such path, so this layer asks the upstream for DNSKEY and DS to
//! build the chain of trust. The upstream's AD bit is not trusted, since this server cannot check
//! what the upstream did.
//!
//! Upstream queries always set CD: otherwise the upstream answers SERVFAIL first for a name with a
//! broken signature, and this server cannot see what went wrong.

use crate::native::{ResolveFailure, ResolveOutcome, Resolver};
use onetdns_core::MutexExt;
use onetdns_proto::{Edns, Message, Name, Record, RecordType, ResponseCode};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

/// Upstream queries one chain may spend, so one name cannot cause unbounded upstream queries. One
/// DS and one DNSKEY per label from the root down is enough, so common depths use less than half.
/// Going over counts as a validation failure.
const MAX_CHAIN_QUERIES: u32 = 24;

const MAX_CHAIN_DEPTH: usize = 16;

const CHAIN_CACHE_ENTRIES: usize = 4096;

const CHAIN_CACHE_MAX_TTL: u32 = 3600;

/// Floor, so a short TTL does not make every query rebuild the chain.
const CHAIN_CACHE_MIN_TTL: u32 = 60;

/// An unsigned delegation leaves nothing to validate below it. Telling that apart from a validation
/// failure keeps unsigned zones from being answered SERVFAIL.
#[derive(Clone)]
enum ChainVerdict {
    Secure {
        keys: Arc<[onetdns_dnssec::Dnskey]>,
        /// The deepest zone apex containing the name.
        apex: Name,
    },
    /// The delegation is unsigned; nothing to validate.
    Insecure,
}

struct CachedChain {
    verdict: ChainVerdict,
    /// Unix seconds.
    expires: u32,
    /// Fingerprint of the anchors this verdict used; the entry is discarded when they change.
    anchor_tag: u64,
}

/// Layers above it, the caches, see only validated responses; everything below it, fallback
/// upstreams included, goes through it.
pub struct ForwardValidateLayer {
    inner: Arc<dyn Resolver>,
    /// Root trust anchors; replaced by hot reload.
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    chains: Mutex<onetdns_core::LruMap<Vec<u8>, CachedChain>>,
    next_id: AtomicU16,
    policy: ForwardValidationPolicy,
}

/// Uses the recursive resolver's config keys. Forwarding is the default, so keys that reached only
/// the recursive resolver would do nothing on most installations.
pub struct ForwardValidationPolicy {
    /// Require a signed proof for a missing DS.
    pub strict: bool,
    /// Send a failed answer without AD instead of SERVFAIL.
    pub permissive: bool,
    /// Validate even when the client sets CD.
    pub ignore_cd: bool,
    /// Not validated, subdomains included.
    pub insecure_domains: Vec<Name>,
    /// Answer RFC 8509 root key sentinel queries by the anchor state.
    pub root_key_sentinel: bool,
}

impl ForwardValidateLayer {
    /// `inner` must include the fallback upstreams.
    pub fn new(
        inner: Arc<dyn Resolver>,
        anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
        policy: ForwardValidationPolicy,
    ) -> Self {
        ForwardValidateLayer {
            inner,
            anchors,
            chains: Mutex::new(onetdns_core::LruMap::new(CHAIN_CACHE_ENTRIES)),
            next_id: AtomicU16::new(1),
            policy,
        }
    }

    /// Whether a validated answer to a sentinel query must become SERVFAIL. Queriers learn which
    /// root key this server trusts from the difference between the is-ta and not-ta answers.
    /// Applies only to validated A and AAAA answers.
    fn sentinel_fails(&self, request: &Message) -> bool {
        let Some(question) = request.questions.first() else {
            return false;
        };
        if question.qtype != RecordType::A && question.qtype != RecordType::AAAA {
            return false;
        }
        question
            .name
            .labels()
            .first()
            .and_then(onetdns_dnssec::RootKeySentinel::parse)
            .is_some_and(|sentinel| sentinel.fails(&self.anchors.load()))
    }

    fn query_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed) | 1
    }

    /// DO to get signatures, CD to keep the upstream from judging. None when unreachable.
    fn ask(&self, name: &Name, qtype: RecordType, budget: &mut u32) -> Option<Message> {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let mut query = Message::query(self.query_id(), name.clone(), qtype);
        query.header.checking_disabled = true;
        let edns = Edns {
            dnssec_ok: true,
            ..Edns::default()
        };
        query.additionals.push(edns.try_to_record().ok()?);
        let response = self.inner.resolve(&query)?;
        if response.header.rcode != ResponseCode::NoError.0
            && response.header.rcode != ResponseCode::NXDomain.0
        {
            return None;
        }
        Some(response)
    }

    /// So cached verdicts stop counting once the anchors change.
    fn anchor_tag(anchors: &[onetdns_dnssec::Ds]) -> u64 {
        let mut tag: u64 = 0xcbf2_9ce4_8422_2325;
        for ds in anchors {
            for byte in ds
                .key_tag
                .to_be_bytes()
                .iter()
                .chain(std::slice::from_ref(&ds.algorithm))
                .chain(std::slice::from_ref(&ds.digest_type))
                .chain(ds.digest.iter())
            {
                tag ^= u64::from(*byte);
                tag = tag.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        tag
    }

    /// None when the anchors changed or the entry expired.
    fn cached(&self, zone: &Name, now: u32, anchor_tag: u64) -> Option<ChainVerdict> {
        let key = zone.canonical_key();
        let mut chains = self.chains.lock_recover();
        let entry = chains.get(&key)?;
        if entry.anchor_tag != anchor_tag || entry.expires <= now {
            chains.pop(&key);
            return None;
        }
        Some(entry.verdict.clone())
    }

    fn remember(&self, zone: &Name, verdict: &ChainVerdict, now: u32, ttl: u32, anchor_tag: u64) {
        let ttl = ttl.clamp(CHAIN_CACHE_MIN_TTL, CHAIN_CACHE_MAX_TTL);
        self.chains.lock_recover().put(
            zone.canonical_key(),
            CachedChain {
                verdict: verdict.clone(),
                expires: now.saturating_add(ttl),
                anchor_tag,
            },
        );
    }

    /// Builds the chain of trust from the root to the zone containing `name`. After confirming the
    /// root DNSKEY against the anchors, it walks down one label at a time asking for DS. A DS means
    /// a signed delegation: its DNSKEY is confirmed and the walk continues. Without a DS, the
    /// parent-signed proof tells an unsigned delegation from an ordinary name, and an ordinary name
    /// continues with the same zone keys.
    ///
    /// Assuming every label is a delegation would read the DS denial for an ordinary name in a
    /// signed zone as proof of an unsigned delegation: a stripped answer would then go out
    /// unvalidated, and a forged signature naming the name itself as signer would pass.
    ///
    /// `name` is the signer of the response signature, or the query name when unsigned. None when
    /// the chain cannot be built, which counts as a validation failure.
    fn chain_to(&self, name: &Name, now: u32, budget: &mut u32) -> Option<ChainVerdict> {
        let anchors = self.anchors.load();
        if anchors.is_empty() {
            return None;
        }
        let anchor_tag = Self::anchor_tag(&anchors);
        if let Some(verdict) = self.cached(name, now, anchor_tag) {
            return Some(verdict);
        }

        let labels = name.num_labels();
        if labels > MAX_CHAIN_DEPTH {
            return None;
        }

        let mut trusted_ds: Vec<onetdns_dnssec::Ds> = anchors.to_vec();
        let mut apex = Name::root();
        let mut examined = 0usize;
        let mut ttl = u32::MAX;
        let verdict = 'zones: loop {
            let Some((dnskeys, dnskey_rrsigs)) = self.dnskey_rrset(&apex, budget) else {
                onetdns_core::debug!(
                    event = "dnssec.forward_no_dnskey",
                    zone = %apex.to_ascii_lower(),
                    "Could not get this zone's DNSKEY and its signatures; cannot build the chain"
                );
                return None;
            };
            ttl = dnskeys.iter().map(|record| record.ttl).fold(ttl, u32::min);
            let keys = match onetdns_dnssec::validate_dnskey_set(
                &dnskeys,
                &dnskey_rrsigs,
                &trusted_ds,
                &apex,
                now,
            ) {
                Ok(keys) => keys,
                Err(error) => {
                    onetdns_core::debug!(
                        event = "dnssec.forward_chain_bogus",
                        zone = %apex.to_ascii_lower(),
                        error = ?error,
                        "Zone key does not match the DS established above"
                    );
                    return None;
                }
            };
            while examined < labels {
                examined += 1;
                let child = name.suffix(examined);
                let Some((ds_records, ds_rrsigs, nsec, nsec_rrsigs, nsec3, nsec3_rrsigs)) =
                    self.delegation_evidence(&child, budget)
                else {
                    onetdns_core::debug!(
                        event = "dnssec.forward_no_ds",
                        zone = %child.to_ascii_lower(),
                        "Could not get a DS response; cannot build the chain"
                    );
                    return None;
                };
                if !ds_records.is_empty() {
                    if onetdns_dnssec::validate_rrset_in_zone(
                        &ds_records,
                        &ds_rrsigs,
                        &keys,
                        &apex,
                        now,
                    )
                    .is_err()
                    {
                        onetdns_core::debug!(
                            event = "dnssec.forward_ds_bogus",
                            zone = %child.to_ascii_lower(),
                            "Delegation's DS signature does not verify with the parent key"
                        );
                        return None;
                    }
                    let supported: Vec<onetdns_dnssec::Ds> = ds_records
                        .iter()
                        .filter_map(onetdns_dnssec::Ds::from_record)
                        .filter(onetdns_dnssec::ds_is_supported)
                        .collect();
                    if supported.is_empty() {
                        break 'zones ChainVerdict::Insecure;
                    }
                    trusted_ds = supported;
                    apex = child;
                    continue 'zones;
                }
                let evidence = onetdns_dnssec::DenialEvidence {
                    nsec: &nsec,
                    nsec_rrsigs: &nsec_rrsigs,
                    nsec3: &nsec3,
                    nsec3_rrsigs: &nsec3_rrsigs,
                };
                match onetdns_dnssec::classify_ds_absence(&apex, &keys, &evidence, &child, now) {
                    onetdns_dnssec::DsAbsence::InsecureDelegation => {
                        break 'zones ChainVerdict::Insecure;
                    }
                    onetdns_dnssec::DsAbsence::NotACut => {}
                    onetdns_dnssec::DsAbsence::Unproven if self.policy.strict => {
                        onetdns_core::debug!(
                            event = "dnssec.forward_ds_unproven",
                            zone = %child.to_ascii_lower(),
                            "No signed proof that the DS is absent"
                        );
                        return None;
                    }
                    onetdns_dnssec::DsAbsence::Unproven => break 'zones ChainVerdict::Insecure,
                }
            }
            break ChainVerdict::Secure {
                keys: keys.into(),
                apex,
            };
        };
        let ttl = if ttl == u32::MAX {
            CHAIN_CACHE_MIN_TTL
        } else {
            ttl
        };
        self.remember(name, &verdict, now, ttl, anchor_tag);
        Some(verdict)
    }

    /// None unless both the DNSKEY set and its signatures are present.
    fn dnskey_rrset(
        &self,
        zone: &Name,
        budget: &mut u32,
    ) -> Option<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>)> {
        let response = self.ask(zone, RecordType::DNSKEY, budget)?;
        let (dnskeys, dnskey_rrsigs) =
            onetdns_dnssec::anchor::extract_dnskey_rrset(&response.answers, zone);
        if dnskeys.is_empty() || dnskey_rrsigs.is_empty() {
            return None;
        }
        Some((dnskeys, dnskey_rrsigs))
    }

    /// The DS for this name, or the proof that it has none. Returns (DS, DS signatures, NSEC, NSEC
    /// signatures, NSEC3, NSEC3 signatures).
    #[allow(clippy::type_complexity)]
    fn delegation_evidence(
        &self,
        child: &Name,
        budget: &mut u32,
    ) -> Option<(
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
    )> {
        let response = self.ask(child, RecordType::DS, budget)?;
        let ds_records = section_records(&response.answers, child, RecordType::DS);
        let ds_rrsigs = covering_rrsigs(&response.answers, child, RecordType::DS);
        if !ds_records.is_empty() {
            return Some((
                ds_records,
                ds_rrsigs,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
        }
        onetdns_core::debug!(
            event = "dnssec.forward_ds_empty",
            zone = %child.to_ascii_lower(),
            rcode = response.header.rcode,
            answers = response.answers.len(),
            authorities = response.authorities.len(),
            "Delegation has no DS; treating it as proven absent"
        );
        let nsec = records_of_type(&response.authorities, RecordType::NSEC);
        let nsec3 = records_of_type(&response.authorities, RecordType::NSEC3);
        let nsec_rrsigs = rrsigs_covering_type(&response.authorities, RecordType::NSEC);
        let nsec3_rrsigs = rrsigs_covering_type(&response.authorities, RecordType::NSEC3);
        Some((
            Vec::new(),
            Vec::new(),
            nsec,
            nsec_rrsigs,
            nsec3,
            nsec3_rrsigs,
        ))
    }

    /// True when the signatures check out and AD is set; false when there is nothing to validate
    /// and the response passes as is. None on failure, which the caller turns into SERVFAIL.
    fn verdict_for(&self, response: &Message, now: u32, budget: &mut u32) -> Option<bool> {
        let question = response.questions.first()?;
        if response.answers.is_empty() {
            // No answer records. The proof is in the authority section, and this layer does not
            // check denial proofs, so the response passes without AD. Treating a missing answer
            // signature as stripped would SERVFAIL every NODATA in signed zones.
            //
            // A signed zone with no signature even in the authority section was stripped, though,
            // and is blocked; otherwise deleting the answers to fake a negative response would
            // work.
            let stripped = matches!(
                self.chain_to(&question.name, now, budget),
                Some(ChainVerdict::Secure { .. })
            ) && !response
                .authorities
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG);
            if stripped {
                onetdns_core::debug!(
                    event = "dnssec.forward_denial_unsigned",
                    qname = %question.name.to_ascii_lower(),
                    "Negative answer from a signed zone carries no signatures"
                );
                return None;
            }
            return Some(false);
        }
        let signer = match answer_signer(response) {
            Some(signer) => signer,
            None => {
                // No signatures at all, so the chain tells whether there should be some: an
                // unsigned zone passes as is, and a signed zone was stripped.
                return match self.chain_to(&question.name, now, budget) {
                    Some(ChainVerdict::Insecure) => Some(false),
                    Some(ChainVerdict::Secure { .. }) => None,
                    None => None,
                };
            }
        };
        let keys = match self.chain_to(&signer, now, budget)? {
            ChainVerdict::Secure { keys, apex } if apex.eq_ignore_case(&signer) => keys,
            ChainVerdict::Secure { apex, .. } => {
                onetdns_core::debug!(
                    event = "dnssec.forward_signer_not_apex",
                    signer = %signer.to_ascii_lower(),
                    apex = %apex.to_ascii_lower(),
                    "Signer name is not the zone apex"
                );
                return None;
            }
            ChainVerdict::Insecure => return Some(false),
        };
        let rrset = section_records(&response.answers, &question.name, question.qtype);
        if rrset.is_empty() {
            // No records of the question's name and type, as with an alias only. That is not
            // checked further here, so AD is not claimed; a missing AD is better than a wrong one.
            return Some(false);
        }
        let rrsigs = covering_rrsigs(&response.answers, &question.name, question.qtype);
        if rrsigs.is_empty() {
            onetdns_core::debug!(
                event = "dnssec.forward_answer_unsigned",
                qname = %question.name.to_ascii_lower(),
                "Answer from a signed zone has no covering signature"
            );
            return None;
        }
        match onetdns_dnssec::validate_rrset_in_zone(&rrset, &rrsigs, &keys, &signer, now) {
            Ok(()) => Some(true),
            Err(error) => {
                onetdns_core::debug!(
                    event = "dnssec.forward_answer_bogus",
                    signer = %signer.to_ascii_lower(),
                    records = rrset.len(),
                    signatures = rrsigs.len(),
                    keys = keys.len(),
                    error = ?error,
                    "Covering signature on the answer did not verify"
                );
                None
            }
        }
    }
}

impl Resolver for ForwardValidateLayer {
    fn resolve(&self, request: &Message) -> Option<Message> {
        crate::layers::outcome_to_option(self.resolve_outcome(request))
    }

    /// Validates the upstream answer and sets AD. A client CD skips validation, as CD means. A
    /// failed answer is not sent, and its reason is reported as a non-retryable failure, since
    /// another upstream would send the same signatures.
    ///
    /// DNSSEC-only records are stripped per the original query before sending. Inner layers see the
    /// query with DO set by this server and do not strip them, so a querier without DO or without
    /// EDNS would otherwise get RRSIGs.
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        let honor_cd = request.header.checking_disabled && !self.policy.ignore_cd;
        if honor_cd || request.questions.len() != 1 {
            return self.inner.resolve_outcome(request);
        }
        let mut upstream = request.clone();
        upstream.header.checking_disabled = true;
        set_dnssec_ok(&mut upstream);

        let mut response = match self.inner.resolve_outcome(&upstream) {
            ResolveOutcome::Response(response) => response,
            failure => return failure,
        };
        if response.header.rcode != ResponseCode::NoError.0
            && response.header.rcode != ResponseCode::NXDomain.0
        {
            response.header.authentic_data = false;
            crate::native::strip_dnssec_unless_requested(request, &mut response);
            return ResolveOutcome::Response(response);
        }

        let insecure = request.questions[0].name.clone();
        if self
            .policy
            .insecure_domains
            .iter()
            .any(|domain| insecure.ends_with_ignore_case(domain))
        {
            response.header.authentic_data = false;
            crate::native::strip_dnssec_unless_requested(request, &mut response);
            return ResolveOutcome::Response(response);
        }

        let now = now_secs();
        let mut budget = MAX_CHAIN_QUERIES;
        match self.verdict_for(&response, now, &mut budget) {
            Some(true) if self.policy.root_key_sentinel && self.sentinel_fails(request) => {
                response.answers.clear();
                response.authorities.clear();
                response
                    .additionals
                    .retain(|record| record.rtype == RecordType::OPT);
                response.header.rcode = ResponseCode::ServFail.0;
                response.header.authentic_data = false;
                ResolveOutcome::Response(response)
            }
            Some(authentic) => {
                response.header.authentic_data = authentic && asks_for_ad(request);
                crate::native::strip_dnssec_unless_requested(request, &mut response);
                ResolveOutcome::Response(response)
            }
            None if self.policy.permissive => {
                onetdns_core::warn!(
                    event = "dnssec.forward_bogus_permissive",
                    qname = %insecure.to_ascii_lower(),
                    "Could not verify signatures; answering without AD because permissive mode is on"
                );
                response.header.authentic_data = false;
                crate::native::strip_dnssec_unless_requested(request, &mut response);
                ResolveOutcome::Response(response)
            }
            None => {
                let question = response
                    .questions
                    .first()
                    .map(|q| q.name.to_ascii_lower())
                    .unwrap_or_default();
                onetdns_core::warn!(
                    event = "dnssec.forward_bogus",
                    qname = %question,
                    "Could not verify signatures on the forwarded answer; not answering"
                );
                ResolveOutcome::Failure(ResolveFailure::Permanent(Some(
                    onetdns_proto::ede_code::DNSSEC_BOGUS,
                )))
            }
        }
    }
}

/// RFC 6840: set AD only for a querier that set DO or AD; one that set neither may not understand
/// it.
fn asks_for_ad(request: &Message) -> bool {
    request.header.authentic_data
        || request
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .filter_map(Edns::from_record)
            .any(|edns| edns.dnssec_ok)
}

/// Creates the OPT when missing.
pub(crate) fn set_dnssec_ok(request: &mut Message) {
    if let Some(existing) = request
        .additionals
        .iter()
        .position(|record| record.rtype == RecordType::OPT)
    {
        if let Some(mut edns) = Edns::from_record(&request.additionals[existing]) {
            if edns.dnssec_ok {
                return;
            }
            edns.dnssec_ok = true;
            if let Ok(record) = edns.try_to_record() {
                request.additionals[existing] = record;
            }
            return;
        }
        request.additionals.remove(existing);
    }
    let edns = Edns {
        dnssec_ok: true,
        ..Edns::default()
    };
    if let Ok(record) = edns.try_to_record() {
        request.additionals.push(record);
    }
}

fn section_records(section: &[Record], name: &Name, qtype: RecordType) -> Vec<Record> {
    section
        .iter()
        .filter(|record| record.rtype == qtype && record.name.eq_ignore_case(name))
        .cloned()
        .collect()
}

/// The name is ignored.
fn records_of_type(section: &[Record], qtype: RecordType) -> Vec<Record> {
    section
        .iter()
        .filter(|record| record.rtype == qtype)
        .cloned()
        .collect()
}

fn covering_rrsigs(
    section: &[Record],
    name: &Name,
    qtype: RecordType,
) -> Vec<onetdns_dnssec::Rrsig> {
    section
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG && record.name.eq_ignore_case(name))
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|rrsig| rrsig.type_covered == qtype.0)
        .collect()
}

/// The name is ignored.
fn rrsigs_covering_type(section: &[Record], qtype: RecordType) -> Vec<onetdns_dnssec::Rrsig> {
    section
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|rrsig| rrsig.type_covered == qtype.0)
        .collect()
}

/// Forwarding keeps no record of the delegations, so only the signature itself says which zone's
/// keys check it. The signer of the answer signature covering the question type.
fn answer_signer(response: &Message) -> Option<Name> {
    let qtype = response.questions.first()?.qtype;
    response
        .answers
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .find(|rrsig| rrsig.type_covered == qtype.0 || rrsig.type_covered == RecordType::CNAME.0)
        .map(|rrsig| rrsig.signer)
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::ResolveOutcome;
    use onetdns_proto::{DnsClass, Question, RData};

    /// Answers only from preset responses, so tests never reach a real upstream.
    struct Canned {
        /// Keyed by lowercase name and type.
        answers: std::collections::HashMap<(String, u16), Message>,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl Resolver for Canned {
        fn resolve(&self, request: &Message) -> Option<Message> {
            self.asked.fetch_add(1, Ordering::Relaxed);
            let question = request.questions.first()?;
            let key = (question.name.to_ascii_lower(), question.qtype.0);
            let mut response = self.answers.get(&key)?.clone();
            response.header.id = request.header.id;
            response.questions = request.questions.clone();
            Some(response)
        }
    }

    fn unsigned_answer(name: &str) -> Message {
        let owner = Name::from_str(name).unwrap();
        let mut message = Message::query(1, owner.clone(), RecordType::A);
        message.header.response = true;
        message.header.recursion_available = true;
        message.answers.push(Record {
            name: owner,
            rtype: RecordType::A,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::A([192, 0, 2, 1].into()),
        });
        message
    }

    /// With no root anchors, no chain can be built.
    fn layer_without_anchors(inner: Arc<dyn Resolver>) -> ForwardValidateLayer {
        ForwardValidateLayer::new(
            inner,
            Arc::new(onetdns_core::ArcSwap::new(Arc::new(Vec::new()))),
            ForwardValidationPolicy {
                strict: true,
                permissive: false,
                ignore_cd: false,
                insecure_domains: Vec::new(),
                root_key_sentinel: true,
            },
        )
    }

    #[test]
    /// Otherwise a diagnosis that turns validation off to see the original answer would be blocked
    /// by this server's verdict.
    fn checking_disabled_passes_through_untouched() {
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            ("unsigned.test".to_string(), 1),
            unsigned_answer("unsigned.test"),
        );
        let canned = Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        });
        let layer = layer_without_anchors(canned.clone());

        let mut request =
            Message::query(7, Name::from_str("unsigned.test").unwrap(), RecordType::A);
        request.header.checking_disabled = true;
        let outcome = layer.resolve_outcome(&request);
        assert!(
            matches!(outcome, ResolveOutcome::Response(ref r) if r.answers.len() == 1),
            "CD=1인데 답을 막았습니다"
        );
        assert_eq!(
            canned.asked.load(Ordering::Relaxed),
            1,
            "CD=1인데 체인을 세우려 했습니다"
        );
    }

    #[test]
    /// Upstream queries set DO, so signed answers come back. The branch that passes an error
    /// response through and the validated branch go through the same stripping.
    fn dnssec_records_do_not_reach_a_client_that_did_not_ask() {
        let owner = Name::from_str("refused.test").unwrap();
        let mut refused = Message::query(1, owner.clone(), RecordType::A);
        refused.header.response = true;
        refused.header.rcode = ResponseCode::Refused.0;
        refused.authorities.push(Record {
            name: owner.clone(),
            rtype: RecordType::RRSIG,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::Unknown(RecordType::RRSIG.0, vec![0; 18]),
        });
        let mut answers = std::collections::HashMap::new();
        answers.insert(("refused.test".to_string(), 1), refused);
        let layer = layer_without_anchors(Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        }));

        let plain = Message::query(7, owner.clone(), RecordType::A);
        let ResolveOutcome::Response(response) = layer.resolve_outcome(&plain) else {
            panic!("오류 응답을 그대로 넘기지 않았습니다");
        };
        assert!(
            response.authorities.is_empty(),
            "DO 없이 물었는데 RRSIG 가 나갔습니다"
        );

        let mut asked = Message::query(8, owner, RecordType::A);
        set_dnssec_ok(&mut asked);
        let ResolveOutcome::Response(response) = layer.resolve_outcome(&asked) else {
            panic!("오류 응답을 그대로 넘기지 않았습니다");
        };
        assert_eq!(
            response.authorities.len(),
            1,
            "DO=1로 물었는데 RRSIG 를 걷어냈습니다"
        );
    }

    #[test]
    /// Without root anchors, whether signatures exist cannot even be decided; passing the answer
    /// would claim validation that never happened.
    fn an_unbuildable_chain_is_not_answered() {
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            ("unsigned.test".to_string(), 1),
            unsigned_answer("unsigned.test"),
        );
        let canned = Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        });
        let layer = layer_without_anchors(canned);

        let request = Message::query(7, Name::from_str("unsigned.test").unwrap(), RecordType::A);
        assert!(
            matches!(
                layer.resolve_outcome(&request),
                ResolveOutcome::Failure(ResolveFailure::Permanent(Some(code)))
                    if code == onetdns_proto::ede_code::DNSSEC_BOGUS
            ),
            "체인을 구성하지 못했는데 답했습니다"
        );
    }

    /// `signed_denial` puts a signed denial in the authority section.
    fn nodata_answer(name: &str, signed_denial: bool) -> Message {
        let owner = Name::from_str(name).unwrap();
        let mut message = Message::query(1, owner.clone(), RecordType::A);
        message.header.response = true;
        message.header.recursion_available = true;
        message.authorities.push(Record {
            name: owner.clone(),
            rtype: RecordType::SOA,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::Unknown(RecordType::SOA.0, vec![0u8; 4]),
        });
        if signed_denial {
            message.authorities.push(Record {
                name: owner,
                rtype: RecordType::RRSIG,
                class: DnsClass::IN,
                ttl: 60,
                rdata: RData::Unknown(RecordType::RRSIG.0, vec![0u8; 20]),
            });
        }
        message
    }

    #[test]
    /// A negative answer's proof is in the authority section, so a missing answer signature is
    /// normal. Judging by the answer section alone would SERVFAIL every NODATA in signed zones,
    /// such as names without AAAA or HTTPS records.
    ///
    /// A signed zone with no signature in the authority section either is still blocked, so
    /// stripping answers to fake a negative response does not pass.
    fn a_negative_answer_is_not_treated_as_a_stripped_signature() {
        let build = |signed_denial: bool| {
            let mut answers = std::collections::HashMap::new();
            answers.insert(
                ("nodata.test".to_string(), 1),
                nodata_answer("nodata.test", signed_denial),
            );
            Arc::new(Canned {
                answers,
                asked: std::sync::atomic::AtomicUsize::new(0),
            })
        };
        let request = Message::query(9, Name::from_str("nodata.test").unwrap(), RecordType::A);

        // No root anchors, so the chain is not Secure and the negative answer passes.
        let layer = layer_without_anchors(build(true));
        let outcome = layer.resolve_outcome(&request);
        let ResolveOutcome::Response(response) = outcome else {
            panic!("부정 응답을 막았습니다");
        };
        assert_eq!(
            response.header.rcode,
            onetdns_proto::ResponseCode::NoError.0
        );
        assert!(response.answers.is_empty());
        assert!(
            !response.header.authentic_data,
            "부재 증명을 확인하지 않았으므로 AD를 설정하면 안 됩니다"
        );

        // Unsigned authority, but without a Secure chain there is no ground to block.
        let layer = layer_without_anchors(build(false));
        assert!(
            matches!(layer.resolve_outcome(&request), ResolveOutcome::Response(_)),
            "서명 여부를 판정할 수 없으면 그대로 내보내야 합니다"
        );
    }

    #[test]
    fn upstream_queries_carry_do_and_cd() {
        struct Spy(Mutex<Vec<(bool, bool)>>);
        impl Resolver for Spy {
            fn resolve(&self, request: &Message) -> Option<Message> {
                let dnssec_ok = request
                    .additionals
                    .iter()
                    .filter(|record| record.rtype == RecordType::OPT)
                    .filter_map(Edns::from_record)
                    .any(|edns| edns.dnssec_ok);
                self.0
                    .lock_recover()
                    .push((dnssec_ok, request.header.checking_disabled));
                None
            }
        }
        let spy = Arc::new(Spy(Mutex::new(Vec::new())));
        let layer = layer_without_anchors(spy.clone());
        let request = Message::query(7, Name::from_str("a.test").unwrap(), RecordType::A);
        let _ = layer.resolve_outcome(&request);
        let seen = spy.0.lock_recover().clone();
        assert_eq!(
            seen,
            vec![(true, true)],
            "업스트림 질의에 DO 또는 CD가 없습니다"
        );
    }

    #[test]
    fn existing_opt_keeps_its_payload_size() {
        let mut request = Message::query(7, Name::from_str("a.test").unwrap(), RecordType::A);
        let edns = Edns {
            udp_payload: 4096,
            ..Edns::default()
        };
        request.additionals.push(edns.try_to_record().unwrap());
        set_dnssec_ok(&mut request);

        let found: Vec<Edns> = request
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .filter_map(Edns::from_record)
            .collect();
        assert_eq!(found.len(), 1, "OPT가 하나여야 합니다");
        assert!(found[0].dnssec_ok, "DO를 설정하지 않았습니다");
        assert_eq!(found[0].udp_payload, 4096, "요청이 알린 크기를 바꿨습니다");
    }

    #[test]
    fn the_signer_comes_from_the_signature() {
        let owner = Name::from_str("deep.sub.example.test").unwrap();
        let mut response = unsigned_answer("deep.sub.example.test");
        response.questions = vec![Question {
            name: owner.clone(),
            qtype: RecordType::A,
            qclass: DnsClass::IN,
        }];
        assert!(
            answer_signer(&response).is_none(),
            "서명이 없는데 서명자를 찾았습니다"
        );
    }
}
