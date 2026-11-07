//! Authoritative requests: AXFR, IXFR, NOTIFY and UPDATE, with TSIG checks and the zone change
//! journal.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use onetdns_control::Action;
use onetdns_core::log::sampled;
use onetdns_core::{AclDecision, ArcSwap, ClientInfo, MutexExt, RateDecision};
use onetdns_proto::{
    DnsClass, Message, Name as ApName, RData as ApRData, Record as ApRecord, RecordType as ApRt,
    ResponseCode,
};
use onetdns_runtime::{RequestCtx, Transport as RtTransport};

use crate::native::query::{advertised_udp_payload, base_edns};
use crate::native::response::{base_response, edns_error_resp, error_resp, finalize, now_unix};
use crate::native::{NativeServer, DDR_OWNER_WIRE, EMPTY_OPT_WIRE_LEN, SERVER_UDP_MAX};

/// The key a request was verified with; the response must be signed with the same key.
type TsigContext = (
    onetdns_dnssec::tsig::TsigKey,
    onetdns_dnssec::tsig::VerifiedTsig,
);

#[derive(Default)]
/// Zones a primary reported changed, waiting for a refresh.
pub struct NotifyKick {
    pending: std::sync::Mutex<HashSet<String>>,
    wake: std::sync::Condvar,
}

impl NotifyKick {
    pub fn push(&self, origin: String) {
        let inserted = self.pending.lock_recover().insert(origin);
        if inserted {
            self.wake.notify_one();
        }
    }

    /// Waits up to `timeout` for a push, then takes every pending zone.
    pub fn wait_take(&self, timeout: std::time::Duration) -> HashSet<String> {
        let mut pending = self.pending.lock_recover();
        if pending.is_empty() {
            pending = match self.wake.wait_timeout(pending, timeout) {
                Ok((pending, _)) => pending,
                Err(error) => error.into_inner().0,
            };
        }
        std::mem::take(&mut *pending)
    }
}

#[derive(Clone)]
/// One rule on who may change what.
pub struct UpdateRule {
    grant: bool,
    /// Only requests signed with this key; `None` matches all.
    identity: Option<ApName>,
    name: UpdateRuleName,
    /// Empty matches every type.
    types: Vec<u16>,
}

#[derive(Clone)]
enum UpdateRuleName {
    Any,
    Exact(ApName),
    /// The name and everything below it.
    Subtree(ApName),
}

impl UpdateRule {
    /// `None` when the name is malformed.
    pub fn new(grant: bool, identity: &str, name: &str, types: Vec<u16>) -> Option<Self> {
        let raw_identity = identity.trim();
        if raw_identity != "*" && raw_identity.contains('*') {
            return None;
        }
        let identity = raw_identity.trim_end_matches('.');
        let identity = if identity == "*" {
            None
        } else {
            Some(ApName::from_str(identity).ok()?)
        };
        let raw_name = name.trim();
        let rule_name = raw_name.trim_end_matches('.');
        let name = if rule_name == "*" {
            if raw_name != "*" {
                return None;
            }
            UpdateRuleName::Any
        } else if let Some(suffix) = rule_name.strip_prefix("*.") {
            if suffix.is_empty() || suffix.starts_with('.') || suffix.contains('*') {
                return None;
            }
            UpdateRuleName::Subtree(ApName::from_str(suffix).ok()?)
        } else {
            if rule_name.starts_with('.') || rule_name.contains('*') {
                return None;
            }
            UpdateRuleName::Exact(ApName::from_str(rule_name).ok()?)
        };
        Some(Self {
            grant,
            identity,
            name,
            types,
        })
    }
}

pub(crate) fn name_ends_with(name: &ApName, suffix: &ApName) -> bool {
    name.ends_with_ignore_case(suffix)
}

fn update_name_matches(rule_name: &UpdateRuleName, qname: &ApName) -> bool {
    match rule_name {
        UpdateRuleName::Any => true,
        UpdateRuleName::Exact(name) => name.eq_ignore_case(qname),
        UpdateRuleName::Subtree(suffix) => {
            qname.num_labels() > suffix.num_labels() && name_ends_with(qname, suffix)
        }
    }
}

/// The first matching rule decides. With none the update is denied: a default grant would open
/// every zone that has no rules.
fn update_granted(
    rules: &[UpdateRule],
    identity: Option<&ApName>,
    qname: &ApName,
    rtype: u16,
) -> bool {
    for r in rules {
        let id_ok = match (&r.identity, identity) {
            (None, _) => true,
            (Some(rule), Some(actual)) => rule.eq_ignore_case(actual),
            (Some(_), None) => false,
        };
        let ty_ok = r.types.is_empty() || r.types.contains(&rtype);
        if id_ok && ty_ok && update_name_matches(&r.name, qname) {
            return r.grant;
        }
    }
    false
}

/// An empty RDATA means delete.
fn update_rdata_is_empty(record: &ApRecord) -> bool {
    matches!(&record.rdata, ApRData::Unknown(rtype, bytes) if *rtype == record.rtype.0 && bytes.is_empty())
}

fn update_rdata_key(record: &ApRecord) -> Vec<u8> {
    onetdns_dnssec::canonical_rdata(&record.rdata)
}

/// Signatures and denial proofs: letting an update insert them would break validation.
fn prohibited_update_type(rtype: ApRt) -> bool {
    matches!(rtype.0, 0 | 41 | 249..=254)
}

/// The 4-byte address and 1-byte protocol at the start of WKS RDATA, or what there is of them.
fn wks_endpoint(record: &ApRecord) -> &[u8] {
    match &record.rdata {
        ApRData::Unknown(11, bytes) => &bytes[..bytes.len().min(5)],
        _ => &[],
    }
}

/// RFC 2136 allows one CNAME and one SOA per name, and treats WKS with the same address and
/// protocol as the same record. Other types replace only an identical record; a different one
/// joins the RRset.
fn update_replaces(incoming: &ApRecord, existing: &ApRecord) -> bool {
    if incoming.rtype == ApRt::CNAME || incoming.rtype == ApRt::SOA {
        return true;
    }
    if incoming.rtype == ApRt(11) {
        return wks_endpoint(incoming) == wks_endpoint(existing);
    }
    incoming.rdata == existing.rdata
}

/// RFC 2136 ignores an SOA replacement that moves the serial back, compared with RFC 1982
/// arithmetic. An equal serial passes; nothing changed, so the server bumps it later. False
/// without a current SOA or when `incoming` is not an SOA.
fn soa_update_moves_forward(current: &[ApRecord], incoming: &ApRecord) -> bool {
    let Some(now) = current.iter().find_map(|r| match &r.rdata {
        ApRData::Soa(soa) if r.rtype == ApRt::SOA => Some(soa.serial),
        _ => None,
    }) else {
        return false;
    };
    match &incoming.rdata {
        ApRData::Soa(soa) => !crate::zones::serial_gt(now, soa.serial),
        _ => false,
    }
}

fn soa_serial_of(records: &[ApRecord]) -> Option<u32> {
    records.iter().find_map(|r| match &r.rdata {
        ApRData::Soa(soa) if r.rtype == ApRt::SOA => Some(soa.serial),
        _ => None,
    })
}

/// What the fast path for plain authoritative queries needs.
pub(crate) struct AuthorityWirePath {
    pub(crate) store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    pub(crate) recursion_available: bool,
}

#[derive(Clone)]
/// What changed from one zone serial to the next.
pub struct ZoneDelta {
    pub from: u32,
    pub to: u32,

    pub deleted: Vec<ApRecord>,

    pub added: Vec<ApRecord>,

    /// Encoded size; a delta larger than the full zone is dropped.
    wire_bytes: usize,
}

#[derive(Default)]
/// Recent zone changes, so secondaries can fetch only what changed. Once the changes add up to
/// more than the full zone they are dropped, since a full transfer is then cheaper.
pub struct ZoneJournal {
    /// Oldest first.
    pub deltas: std::collections::VecDeque<ZoneDelta>,
}

impl ZoneJournal {
    const MAX: usize = 64;

    pub fn record(&mut self, from: u32, to: u32, old: &[ApRecord], new: &[ApRecord]) {
        let deleted: Vec<ApRecord> = old
            .iter()
            .filter(|r| r.rtype != ApRt::SOA && !new.contains(r))
            .cloned()
            .collect();
        let added: Vec<ApRecord> = new
            .iter()
            .filter(|r| r.rtype != ApRt::SOA && !old.contains(r))
            .cloned()
            .collect();
        if deleted.is_empty() && added.is_empty() {
            if from != to {
                self.deltas.clear();
            }
            return;
        }
        let Some(soa) = new.iter().find(|record| record.rtype == ApRt::SOA) else {
            self.deltas.clear();
            return;
        };
        let soa_bytes = journal_records_wire_bytes(std::slice::from_ref(soa));
        let wire_bytes = journal_records_wire_bytes(&deleted)
            .saturating_add(journal_records_wire_bytes(&added))
            .saturating_add(soa_bytes.saturating_mul(2));
        let axfr_bytes = journal_records_wire_bytes(new).saturating_add(soa_bytes);
        if wire_bytes.saturating_add(soa_bytes.saturating_mul(2)) >= axfr_bytes {
            self.deltas.clear();
            return;
        }
        self.deltas.push_back(ZoneDelta {
            from,
            to,
            deleted,
            added,
            wire_bytes,
        });
        let mut retained_bytes = self
            .deltas
            .iter()
            .fold(0usize, |sum, delta| sum.saturating_add(delta.wire_bytes));
        while self.deltas.len() > Self::MAX
            || retained_bytes.saturating_add(soa_bytes.saturating_mul(2)) >= axfr_bytes
        {
            let Some(removed) = self.deltas.pop_front() else {
                break;
            };
            retained_bytes = retained_bytes.saturating_sub(removed.wire_bytes);
        }
    }

    /// `None` when the chain from `client_serial` is broken.
    pub fn path_from(&self, client_serial: u32, current: u32) -> Option<Vec<&ZoneDelta>> {
        if client_serial == current {
            return Some(vec![]);
        }
        let mut path = Vec::new();
        let mut cur = client_serial;
        while cur != current {
            let d = self.deltas.iter().find(|d| d.from == cur)?;
            path.push(d);
            cur = d.to;
            if path.len() > Self::MAX {
                return None;
            }
        }
        Some(path)
    }
}

fn journal_records_wire_bytes(records: &[ApRecord]) -> usize {
    let mut writer = onetdns_proto::Writer::new();
    records.iter().fold(0usize, |sum, record| {
        writer.clear();
        record.encode(&mut writer);
        sum.saturating_add(writer.buf.len())
    })
}

impl NativeServer {
    /// Sends the pre-encoded zone transfer as is, instead of encoding the zone each time.
    pub(crate) fn handle_cached_axfr_wire(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
        emit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Option<bool> {
        let authority = self.authority.load();
        if request.header.opcode != 0
            || request.questions.len() != 1
            || !request.authorities.is_empty()
            || request.questions[0].qtype != ApRt(252)
            || request.questions[0].qclass != DnsClass::IN
            || !ctx.transport.supports_xfr()
            || self.rate_limiters.iter().any(|limiter| limiter.is_active())
        {
            return None;
        }
        let features = self.features.load();
        // dnstap needs one entry per envelope, which pre-built bytes cannot provide. Stats record
        // no successful transfer on either path, so they give no reason to fall back here.
        if features.dnstap.is_some() {
            return None;
        }
        let client = self.identify(ctx);
        if self.acl.check(&client) != AclDecision::Allow
            || !authority
                .xfr_allow
                .iter()
                .any(|network| network.contains(&ctx.src.ip()))
        {
            return None;
        }

        let tsig_ctx = if onetdns_dnssec::tsig::contains_tsig(request) {
            match self.check_tsig(request, ctx.raw, authority.xfr_tsig_required, false) {
                Ok(Some(context)) => Some(context),
                Ok(None) | Err(_) => return None,
            }
        } else if authority.xfr_tsig_required {
            return None;
        } else {
            None
        };

        let store = self.xfr_store.as_ref()?.load();
        let question = &request.questions[0];
        let zone = store
            .zones()
            .iter()
            .find(|zone| zone.origin().eq_ignore_case(&question.name))?;
        let templates = zone.axfr_wire_templates().ok()?;
        let question_wire = question.name.as_uncompressed_wire();
        let now = now_unix();
        let mut previous_mac = None;
        for (index, template) in templates.iter().enumerate() {
            out.clear();
            out.push_bytes(template);
            out.buf[0..2].copy_from_slice(&request.header.id.to_be_bytes());
            if request.header.recursion_desired {
                out.buf[2] |= 0x01;
            } else {
                out.buf[2] &= !0x01;
            }
            if index == 0 {
                let name_end = 12 + question_wire.len();
                let target = out.buf.get_mut(12..name_end)?;
                if target.len() != question_wire.len() {
                    return None;
                }
                target.copy_from_slice(question_wire);
            }
            if let Some((key, request_tsig)) = &tsig_ctx {
                let mac = if index == 0 {
                    onetdns_dnssec::tsig::sign_response_wire(out, key, now, request_tsig)
                } else {
                    onetdns_dnssec::tsig::sign_response_wire_subsequent(
                        out,
                        key,
                        now,
                        previous_mac.as_deref().unwrap_or(&[]),
                        request_tsig,
                    )
                }
                .expect("A 60 KiB AXFR wire template leaves room for TSIG");
                previous_mac = Some(mac);
            }
            if !emit(&out.buf) {
                return Some(false);
            }
        }
        Some(true)
    }

    /// The client must be in `xfr_allow` and pass TSIG: a full transfer hands out every name in
    /// the zone at once.
    pub(crate) fn handle_axfr(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        qname: &ApName,
        client: &ClientInfo,
        emit: &mut dyn FnMut(Message) -> bool,
    ) -> Option<()> {
        let authority = self.authority.load();
        let qtype = request
            .questions
            .first()
            .map(|q| q.qtype)
            .unwrap_or(ApRt(252));
        let axfr = qtype;
        let is_ixfr = qtype == ApRt(251);

        let store = self.xfr_store.as_ref()?.load();
        if !authority
            .xfr_allow
            .iter()
            .any(|net| net.contains(&ctx.src.ip()))
        {
            static NOT_ALLOWED: AtomicU64 = AtomicU64::new(0);
            if let Some(count) = sampled(&NOT_ALLOWED) {
                onetdns_core::warn!(event = "xfr.refused", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), reason = "not_in_xfr_allow", count = count, "Refused zone transfer from an address that is not allowed");
            }
            self.rec(client, Action::Refused, Some(qname), Some(axfr));
            return emit(error_resp(request, ResponseCode::Refused)).then_some(());
        }

        let tsig_ctx = match self.check_tsig(request, ctx.raw, authority.xfr_tsig_required, false) {
            Ok(t) => t,
            Err(response) => {
                static TSIG_FAILED: AtomicU64 = AtomicU64::new(0);
                if let Some(count) = sampled(&TSIG_FAILED) {
                    onetdns_core::warn!(event = "xfr.refused", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), reason = "tsig", count = count, "Refused zone transfer because TSIG verification failed");
                }
                self.rec(client, Action::Refused, Some(qname), Some(axfr));
                return emit(response).then_some(());
            }
        };
        let zone = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(qname));
        let Some(zone) = zone else {
            static UNKNOWN_ZONE: AtomicU64 = AtomicU64::new(0);
            if let Some(count) = sampled(&UNKNOWN_ZONE) {
                onetdns_core::warn!(event = "xfr.unknown_zone", peer = %ctx.src.ip(), zone = %qname.to_ascii_lower(), count = count, "Refused transfer of a zone this server is not authoritative for");
            }
            return emit(xfr_single_response(
                request,
                ResponseCode(9),
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        };

        let client_serial = if is_ixfr {
            match request.authorities.as_slice() {
                [record]
                    if record.name.eq_ignore_case(qname)
                        && record.rtype == ApRt::SOA
                        && record.class == DnsClass::IN =>
                {
                    match &record.rdata {
                        ApRData::Soa(soa) => Some(soa.serial),
                        _ => None,
                    }
                }
                _ => None,
            }
        } else {
            Some(0)
        };
        if client_serial.is_none() {
            return emit(xfr_single_response(
                request,
                ResponseCode::FormErr,
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        }

        if !ctx.transport.supports_xfr() {
            if is_ixfr && ctx.transport == RtTransport::Do53Udp {
                let soa = zone.axfr_records_iter().next()?;
                let stale = client_serial != Some(zone.soa().serial);
                let m = xfr_single_response(
                    request,
                    ResponseCode::NoError,
                    Some(soa),
                    stale,
                    tsig_ctx.as_ref(),
                );
                self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                return emit(m).then_some(());
            }
            self.rec(client, Action::Refused, Some(qname), Some(axfr));
            return emit(xfr_single_response(
                request,
                ResponseCode::Refused,
                None,
                false,
                tsig_ctx.as_ref(),
            ))
            .then_some(());
        }

        if is_ixfr {
            let client_serial = client_serial.expect("The IXFR serial was checked above");
            let cur_serial = zone.soa().serial;
            if client_serial == cur_serial {
                let soa = zone.axfr_records_iter().next()?;
                self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                return xfr_envelopes_stream(request, std::iter::once(soa), tsig_ctx, emit)
                    .then_some(());
            }
            {
                let jr = self.journal.lock_recover();
                if let Some(path) = jr
                    .get(&apex_key(qname))
                    .and_then(|j| j.path_from(client_serial, cur_serial))
                {
                    let soa_rec = zone.axfr_records_iter().next()?;
                    let mut recs = Vec::new();
                    recs.push(soa_rec.clone());
                    for d in &path {
                        recs.push(soa_with_serial(&soa_rec, d.from));
                        recs.extend(d.deleted.iter().cloned());
                        recs.push(soa_with_serial(&soa_rec, d.to));
                        recs.extend(d.added.iter().cloned());
                    }
                    recs.push(soa_rec);
                    drop(jr);
                    self.rec(client, Action::Resolved, Some(qname), Some(axfr));
                    return xfr_envelopes_stream(request, recs, tsig_ctx, emit).then_some(());
                }
            }
        }

        self.rec(client, Action::Resolved, Some(qname), Some(axfr));
        xfr_envelopes_stream(request, zone.axfr_records_iter(), tsig_ctx, emit).then_some(())
    }

    /// Remembers each signature so a captured request cannot be replayed.
    pub(crate) fn check_tsig(
        &self,
        request: &Message,
        raw: Option<&[u8]>,
        required: bool,
        replay_protected: bool,
    ) -> Result<Option<TsigContext>, Message> {
        let authority = self.authority.load();
        // TSIG error responses echo the request's OPT too, placed before the signature so the MAC
        // covers it.
        let edns_buffer = self.features.load().edns_buffer;
        if onetdns_dnssec::tsig::contains_tsig(request) {
            let Some(key_name) = onetdns_dnssec::tsig::peek_key_name(request) else {
                return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer));
            };
            let key = authority
                .tsig_keys
                .iter()
                .find(|key| key.name.eq_ignore_case(&key_name))
                .cloned();
            let Some(key) = key else {
                let request_tsig = match onetdns_dnssec::tsig::request_data(request) {
                    Ok(data) => data,
                    Err(_) => {
                        return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer))
                    }
                };
                return Err(unsigned_tsig_error_response(
                    request,
                    &request_tsig,
                    onetdns_dnssec::tsig::UnsignedTsigError::BadKey,
                    edns_buffer,
                ));
            };
            let now = now_unix();
            let verified = match raw {
                Some(wire) => onetdns_dnssec::tsig::verify_wire_detailed(wire, &key, now, None),
                None => return Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer)),
            };
            match verified {
                Ok(onetdns_dnssec::tsig::WireVerification::Valid { tsig, .. }) => {
                    if replay_protected {
                        let mut replay_key = key.name.to_ascii_lower().into_bytes();
                        replay_key.push(0);
                        replay_key.extend_from_slice(tsig.mac());
                        let mut replay = self.tsig_replay.lock_recover();
                        if replay
                            .peek(&replay_key)
                            .is_some_and(|expires| *expires >= now)
                        {
                            static REPLAYED: AtomicU64 = AtomicU64::new(0);
                            if let Some(count) = sampled(&REPLAYED) {
                                onetdns_core::warn!(event = "authority.tsig_replay_blocked", key = %key.name.to_ascii_lower(), count = count, "Blocked a replayed TSIG request");
                            }
                            return Err(signed_tsig_error_response(
                                request,
                                &key,
                                &tsig,
                                ResponseCode(9),
                                edns_buffer,
                            ));
                        }
                        replay.put(replay_key, tsig.valid_until());
                    }
                    Ok(Some((key, tsig)))
                }
                Ok(onetdns_dnssec::tsig::WireVerification::BadTime { tsig, .. }) => Err(
                    signed_badtime_response(request, &key, &tsig, now, edns_buffer),
                ),
                Err(
                    onetdns_dnssec::tsig::TsigError::Missing
                    | onetdns_dnssec::tsig::TsigError::InvalidMessage,
                ) => Err(edns_error_resp(request, ResponseCode::FormErr, edns_buffer)),
                Err(
                    error @ (onetdns_dnssec::tsig::TsigError::BadKey
                    | onetdns_dnssec::tsig::TsigError::BadAlg
                    | onetdns_dnssec::tsig::TsigError::BadSig),
                ) => {
                    let request_tsig = match onetdns_dnssec::tsig::request_data(request) {
                        Ok(data) => data,
                        Err(_) => {
                            return Err(edns_error_resp(
                                request,
                                ResponseCode::FormErr,
                                edns_buffer,
                            ))
                        }
                    };
                    let response_error = if matches!(
                        error,
                        onetdns_dnssec::tsig::TsigError::BadKey
                            | onetdns_dnssec::tsig::TsigError::BadAlg
                    ) {
                        onetdns_dnssec::tsig::UnsignedTsigError::BadKey
                    } else {
                        onetdns_dnssec::tsig::UnsignedTsigError::BadSig
                    };
                    Err(unsigned_tsig_error_response(
                        request,
                        &request_tsig,
                        response_error,
                        edns_buffer,
                    ))
                }
                Err(onetdns_dnssec::tsig::TsigError::BadTime) => {
                    unreachable!("Detailed TSIG verification keeps the BADTIME context")
                }
            }
        } else if required {
            Err(error_resp(request, ResponseCode::Refused))
        } else {
            Ok(None)
        }
    }

    /// Whether a loaded zone covers `qname`, so the standard lookup can tell whether it exists.
    pub(crate) fn serves_zone_for(&self, qname: &ApName) -> bool {
        self.authority_wire_path
            .as_ref()
            .is_some_and(|path| path.store.load().zone_for(qname).is_some())
    }

    /// Accepts NOTIFY only from a configured primary.
    pub(crate) fn handle_notify(&self, request: &Message, ctx: &RequestCtx) -> Option<Message> {
        let authority = self.authority.load();
        if request.header.response {
            return None;
        }
        let mut m = base_response(request);
        m.header.opcode = 4;
        m.header.authoritative = true;
        m.header.recursion_available = false;
        m.additionals.clear();
        // RFC 6891 applies here too; the OPT goes before the TSIG so the signature covers it.
        if request.opt().is_some() {
            m = finalize(
                m,
                Some(base_edns(request, self.features.load().edns_buffer)),
            );
        }
        let Some(q) = request.questions.first().filter(|q| {
            request.questions.len() == 1 && q.qtype == ApRt::SOA && q.qclass == DnsClass::IN
        }) else {
            m.header.rcode = ResponseCode::FormErr.0;
            return Some(m);
        };
        let known = authority
            .notify_secondaries
            .iter()
            .find(|(o, p, _)| o.eq_ignore_case(&q.name) && *p == ctx.src.ip())
            .map(|(origin, _, key)| (origin, key))
            .or_else(|| {
                authority
                    .notify_catalog_primaries
                    .iter()
                    .find(|(primary, _)| *primary == ctx.src.ip())
                    .map(|(_, key)| (&q.name, key))
            });
        match known {
            Some((origin, expected_key)) => {
                let tsig_ctx =
                    match self.check_tsig(request, ctx.raw, expected_key.is_some(), false) {
                        Ok(context) => context,
                        Err(response) => return Some(response),
                    };
                if let (Some(expected), Some((actual, verified))) =
                    (expected_key.as_ref(), tsig_ctx.as_ref())
                {
                    if !actual.name.eq_ignore_case(expected) {
                        return Some(signed_tsig_error_response(
                            request,
                            actual,
                            verified,
                            ResponseCode(9),
                            self.features.load().edns_buffer,
                        ));
                    }
                }
                self.notify_kick.push(origin.to_ascii_lower());
                onetdns_core::info!(event = "authority.notify_received", zone = %origin.to_ascii_lower(), src = %ctx.src, "Received DNS NOTIFY; scheduled a secondary zone refresh");
                if let Some((key, verified)) = tsig_ctx.as_ref() {
                    if onetdns_dnssec::tsig::sign_response_message(
                        &mut m,
                        key,
                        now_unix(),
                        verified,
                    )
                    .is_err()
                    {
                        return Some(edns_error_resp(
                            request,
                            ResponseCode::ServFail,
                            self.features.load().edns_buffer,
                        ));
                    }
                }
            }
            None => {
                static UNKNOWN_PRIMARY: AtomicU64 = AtomicU64::new(0);
                if let Some(count) = sampled(&UNKNOWN_PRIMARY) {
                    onetdns_core::warn!(event = "authority.notify_unknown_master", zone = %q.name.to_ascii_lower(), src = %ctx.src, count = count, "Ignored DNS NOTIFY from an unknown primary");
                }
                return None;
            }
        }
        Some(m)
    }

    /// The client must pass the address range, the key and the rules. Prerequisites are checked
    /// first, and if any fails nothing changes.
    pub(crate) fn handle_update(
        &self,
        request: &Message,
        ctx: &RequestCtx,
        client: &ClientInfo,
    ) -> Option<Message> {
        let authority = self.authority.load();
        let reply = |rcode: u16| {
            let mut m = base_response(request);
            m.header.opcode = 5;
            m.header.rcode = rcode;
            m.additionals.clear();
            Some(m)
        };

        // RFC 2136 treats only the zone count and ZTYPE as format errors. A wrong ZCLASS names a
        // zone this server does not hold, which gets NOTAUTH below.
        if request.questions.len() != 1 || request.questions[0].qtype != ApRt::SOA {
            return reply(ResponseCode::FormErr.0);
        }

        if !authority
            .update_allow
            .iter()
            .any(|net| net.contains(&ctx.src.ip()))
        {
            self.rec(client, Action::Refused, None, None);
            return reply(ResponseCode::Refused.0);
        }

        let tsig_ctx = match self.check_tsig(request, ctx.raw, authority.update_tsig_required, true)
        {
            Ok(t) => t,
            Err(response) => {
                self.rec(client, Action::Refused, None, None);
                return Some(response);
            }
        };
        let reply = |rcode: u16| {
            let mut m = base_response(request);
            m.header.opcode = 5;
            m.header.rcode = rcode;
            m.additionals.clear();
            if let Some((key, request_tsig)) = &tsig_ctx {
                onetdns_dnssec::tsig::sign_response_message(&mut m, key, now_unix(), request_tsig)
                    .expect("A minimal UPDATE response can always be encoded before TSIG signing");
            }
            Some(m)
        };

        let zq = request.questions.first();
        let Some(zq) = zq.filter(|q| q.qtype == ApRt::SOA) else {
            return reply(ResponseCode::FormErr.0);
        };
        let Some(store_swap) = self.xfr_store.as_ref() else {
            return reply(9);
        };
        if zq.qclass != DnsClass::IN {
            return reply(9);
        }
        let Some(target) = authority
            .update_targets
            .iter()
            .find(|target| target.origin.eq_ignore_case(&zq.name))
        else {
            return reply(9);
        };

        let mut journals = self.journal.lock_recover();
        let store = store_swap.load();
        let Some(zone) = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(&zq.name))
        else {
            return reply(9);
        };

        let mut recs = zone.axfr_records();
        recs.pop();
        let old_recs = recs.clone();
        let old_serial = zone.soa().serial;

        let mut present_names = std::collections::HashSet::new();
        let mut present_sets: std::collections::HashMap<(Vec<u8>, u16), Vec<Vec<u8>>> =
            std::collections::HashMap::new();
        for record in &recs {
            let name = record.name.canonical_key();
            present_names.insert(name.clone());
            present_sets
                .entry((name, record.rtype.0))
                .or_default()
                .push(update_rdata_key(record));
        }
        for values in present_sets.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        let mut prerequisite_classes = std::collections::HashMap::new();
        let mut required_sets: std::collections::HashMap<(Vec<u8>, u16), Vec<Vec<u8>>> =
            std::collections::HashMap::new();

        for p in &request.answers {
            // RFC 2136's pseudocode checks TTL before the zone range, which decides the error for a
            // request wrong on both.
            if p.ttl != 0 {
                return reply(ResponseCode::FormErr.0);
            }
            if !zone.contains(&p.name) {
                return reply(10);
            }
            if prohibited_update_type(p.rtype) {
                return reply(ResponseCode::FormErr.0);
            }
            if matches!(p.class.0, 254 | 255) && !update_rdata_is_empty(p) {
                return reply(ResponseCode::FormErr.0);
            }
            if p.class == DnsClass::IN && (p.rtype == ApRt(255) || p.rdata.record_type() != p.rtype)
            {
                return reply(ResponseCode::FormErr.0);
            }
            let name = p.name.canonical_key();
            let key = (name.clone(), p.rtype.0);
            if prerequisite_classes
                .insert(key.clone(), p.class.0)
                .is_some_and(|class| class != p.class.0)
            {
                return reply(ResponseCode::FormErr.0);
            }
            let exists_name = present_names.contains(&name);
            let exists_type = present_sets.contains_key(&key);
            match p.class.0 {
                255 if p.rtype == ApRt(255) => {
                    if !exists_name {
                        return reply(ResponseCode::NXDomain.0);
                    }
                }
                255 => {
                    if !exists_type {
                        return reply(8);
                    }
                }
                254 if p.rtype == ApRt(255) => {
                    if exists_name {
                        return reply(6);
                    }
                }
                254 => {
                    if exists_type {
                        return reply(7);
                    }
                }
                1 => {
                    required_sets
                        .entry(key)
                        .or_default()
                        .push(update_rdata_key(p));
                }
                _ => return reply(ResponseCode::FormErr.0),
            }
        }
        for (key, required) in &mut required_sets {
            required.sort_unstable();
            required.dedup();
            if present_sets.get(key) != Some(required) {
                return reply(8);
            }
        }

        let apex = zone.origin().clone();

        for u in &request.authorities {
            if !zone.contains(&u.name) {
                return reply(10);
            }
            if prohibited_update_type(u.rtype) {
                return reply(ResponseCode::FormErr.0);
            }
            match u.class.0 {
                1 if u.rtype != ApRt(255)
                    && !update_rdata_is_empty(u)
                    && u.rdata.record_type() == u.rtype => {}
                255 if u.ttl == 0 && update_rdata_is_empty(u) => {}
                254 if u.ttl == 0
                    && u.rtype != ApRt(255)
                    && !update_rdata_is_empty(u)
                    && u.rdata.record_type() == u.rtype => {}
                _ => return reply(ResponseCode::FormErr.0),
            }
        }

        if !authority.update_policy.is_empty() {
            let identity = tsig_ctx.as_ref().map(|(k, _)| &k.name);
            for u in &request.authorities {
                if u.rtype == ApRt::SOA {
                    continue;
                }
                if !update_granted(&authority.update_policy, identity, &u.name, u.rtype.0) {
                    self.rec(client, Action::Refused, Some(&u.name), Some(u.rtype));
                    return reply(ResponseCode::Refused.0);
                }
            }
        }

        for u in &request.authorities {
            match u.class.0 {
                1 => {
                    // CNAME cannot coexist with other data, either way round: skip only this RR.
                    // Failing the whole message would lose the valid updates with it; RFC 2136
                    // processes the rest and answers NOERROR.
                    let conflicting_cname = if u.rtype == ApRt::CNAME {
                        recs.iter()
                            .any(|r| r.name.eq_ignore_case(&u.name) && r.rtype != ApRt::CNAME)
                    } else {
                        recs.iter()
                            .any(|r| r.name.eq_ignore_case(&u.name) && r.rtype == ApRt::CNAME)
                    };
                    if conflicting_cname {
                        continue;
                    }
                    if u.rtype == ApRt::SOA && !soa_update_moves_forward(&recs, u) {
                        continue;
                    }
                    if let Some(ex) = recs.iter_mut().find(|r| {
                        r.name.eq_ignore_case(&u.name)
                            && r.rtype == u.rtype
                            && update_replaces(u, r)
                    }) {
                        *ex = u.clone();
                    } else {
                        recs.push(u.clone());
                    }
                }
                255 if u.rtype == ApRt(255) => {
                    recs.retain(|r| {
                        !r.name.eq_ignore_case(&u.name)
                            || (r.name.eq_ignore_case(&apex)
                                && (r.rtype == ApRt::SOA || r.rtype == ApRt::NS))
                    });
                }
                255 => {
                    if u.name.eq_ignore_case(&apex) && (u.rtype == ApRt::SOA || u.rtype == ApRt::NS)
                    {
                        continue;
                    }
                    recs.retain(|r| !(r.name.eq_ignore_case(&u.name) && r.rtype == u.rtype));
                }
                254 => {
                    if u.rtype == ApRt::SOA {
                        continue;
                    }
                    // Deleting the apex's last NS would leave the zone without an authoritative
                    // server, so RFC 2136 skips this RR. Below the apex an NS is a delegation, and
                    // removing the last one is normal.
                    if u.rtype == ApRt::NS
                        && u.name.eq_ignore_case(&apex)
                        && !recs.iter().any(|r| {
                            r.name.eq_ignore_case(&apex)
                                && r.rtype == ApRt::NS
                                && r.rdata != u.rdata
                        })
                    {
                        continue;
                    }
                    recs.retain(|r| {
                        !(r.name.eq_ignore_case(&u.name)
                            && r.rtype == u.rtype
                            && r.rdata == u.rdata)
                    });
                }
                _ => return reply(ResponseCode::FormErr.0),
            }
        }

        if recs == old_recs {
            self.rec(client, Action::Resolved, Some(&zq.name), Some(ApRt::SOA));
            return reply(ResponseCode::NoError.0);
        }

        // RFC 2136 has the server bump the serial only when the update did not set it; bumping on
        // top would lose the value the requester wrote.
        if soa_serial_of(&recs) == Some(old_serial) {
            if let Some(soa_rec) = recs.iter_mut().find(|r| r.rtype == ApRt::SOA) {
                if let ApRData::Soa(s) = &mut soa_rec.rdata {
                    s.serial = s.serial.wrapping_add(1);
                }
            }
        }

        if let Some((_, ctx)) = authority
            .zone_signers
            .iter()
            .find(|(o, _)| o.eq_ignore_case(&apex))
        {
            recs = ctx.sign(&recs);
        }
        let new_zone = match onetdns_authority::Zone::from_records(recs) {
            Ok(z) => z,
            Err(error) => {
                onetdns_core::error!(event = "authority.ddns_zone_invalid", zone = %apex.to_ascii_lower(), %error, "Discarded a dynamic DNS update that would leave the zone inconsistent");
                return reply(ResponseCode::ServFail.0);
            }
        };

        let path = &target.file;
        let new_zone = match crate::zones::persist_zone(path, Some(zone), new_zone) {
            Ok(saved) => saved,
            Err(error) => {
                onetdns_core::error!(event = "authority.ddns_save_failed", zone = %apex.to_ascii_lower(), path = %path.display(), %error,
                    "Could not save a dynamic DNS update; reverted the change");
                return reply(ResponseCode::ServFail.0);
            }
        };

        let mut new_recs = new_zone.axfr_records();
        new_recs.pop();
        let new_serial = new_zone.soa().serial;
        crate::zones::swap_zone(store_swap, &mut journals, new_zone);
        journals
            .entry(apex.canonical_key())
            .or_default()
            .record(old_serial, new_serial, &old_recs, &new_recs);
        drop(journals);
        if let Some(notify) = &self.update_notify {
            notify(&apex, new_serial);
        }
        onetdns_core::info!(event = "authority.ddns_applied", zone = %apex.to_ascii_lower(), src = %ctx.src, "Applied a dynamic DNS update and bumped the serial");

        self.rec(client, Action::Resolved, Some(&zq.name), Some(ApRt::SOA));
        reply(ResponseCode::NoError.0)
    }

    /// Answers plain authoritative queries without building a message. Anything that could change
    /// the response goes the normal way: delegations, signing requests, extra options, and features
    /// that must record the query.
    pub(crate) fn authority_wire_dispatch(
        &self,
        packet: &[u8],
        ctx: &RequestCtx,
        out: &mut onetdns_proto::Writer,
    ) -> onetdns_runtime::WireDisposition {
        use onetdns_runtime::WireDisposition as Wire;

        let Some(path) = &self.authority_wire_path else {
            return Wire::Fallback;
        };
        let Some(scanned) = crate::wirecache::scan_query(packet) else {
            return Wire::Fallback;
        };
        if !matches!(scanned.qtype, 1 | 28) {
            return Wire::Fallback;
        }
        // Takes only a bare query or one with an empty OPT. Options or DO need content in the
        // response, and an advertised size below this server's limit needs the truncation ladder,
        // so those go the structured way. Queries taken here are always below the large-query
        // limit, so that check is skipped.
        let bare_len = 12 + scanned.qname.len() + 4;
        let has_opt = match &scanned.edns {
            None => {
                if packet.len() != bare_len {
                    return Wire::Fallback;
                }
                false
            }
            Some(edns) => {
                if edns.dnssec_ok
                    || edns.has_options
                    || edns.udp_payload < SERVER_UDP_MAX
                    || packet.len() != bare_len + EMPTY_OPT_WIRE_LEN
                {
                    return Wire::Fallback;
                }
                true
            }
        };
        if self.filter.wire_blocked() {
            return Wire::Fallback;
        }
        // Load the feature set once, after every content-based filter, so declined queries pay no
        // lock and the path conditions, DDR check and EDNS size all see the same set.
        let features = self.features.load();
        if !features.lanes.authority
            || self.safe_search.load(Ordering::Acquire)
            || (features.ddr_enabled && scanned.canonical_qname() == DDR_OWNER_WIRE)
        {
            return Wire::Fallback;
        }
        let edns = has_opt.then(|| advertised_udp_payload(features.edns_buffer));
        let acl_trivially_allows = self.acl.is_trivially_allow();
        let rate_limiters_active = self.rate_limiters.iter().any(|limiter| limiter.is_active());
        let client = (!acl_trivially_allows || rate_limiters_active).then(|| self.identify(ctx));
        if !acl_trivially_allows
            && self
                .acl
                .check(client.as_ref().expect("non-trivial ACL needs client"))
                != AclDecision::Allow
        {
            return Wire::Fallback;
        }
        let id = u16::from_be_bytes(scanned.id);
        let recursion_desired = packet[2] & 0x01 != 0;
        let request_flags = (u16::from(recursion_desired) << 8)
            | (u16::from(path.recursion_available) << 7)
            | u16::from(packet[3] & 0x10);
        out.clear();
        let simple = onetdns_authority::SimpleRequest {
            original_qname: scanned.qname,
            qtype: ApRt(scanned.qtype),
            id,
            request_flags,
            edns,
        };
        if !path
            .store
            .load()
            .write_simple_response(scanned.canonical_qname(), &simple, out)
        {
            return Wire::Fallback;
        }
        // Without EDNS, UDP is capped at 512 bytes (RFC 1035). This path has no truncation ladder,
        // so a larger answer goes the structured way. TCP has no such cap.
        if edns.is_none()
            && ctx.transport == RtTransport::Do53Udp
            && out.buf.len() > onetdns_runtime::NON_EDNS_UDP_MAX
        {
            out.clear();
            return Wire::Fallback;
        }
        for limiter in self
            .rate_limiters
            .iter()
            .filter(|limiter| limiter.is_active())
        {
            // The limiter came on after the check above, so no client was built. Go the normal way
            // rather than skip the limit; handing a fast-path query to the general path is always
            // correct.
            let Some(client) = client.as_ref() else {
                out.clear();
                return Wire::Fallback;
            };
            if limiter.check(client) == RateDecision::Throttle {
                out.clear();
                return Wire::Fallback;
            }
        }
        self.record_authority_wire(ctx, &scanned, client, out);
        Wire::Respond
    }

    /// Records a fast-path answer in the metrics, reading the rcode from the wire just written so
    /// it matches the structured path. `client` is reused when access control or a limiter already
    /// built it.
    fn record_authority_wire(
        &self,
        ctx: &RequestCtx,
        scanned: &crate::wirecache::ScannedQuery<'_>,
        client: Option<ClientInfo>,
        out: &onetdns_proto::Writer,
    ) {
        let Some(recorder) = self.events() else {
            return;
        };
        let Some(flags) = out.buf.get(3) else {
            return;
        };
        let rcode = ResponseCode(u16::from(flags & 0x0f));
        let client = match client {
            Some(client) => client,
            None => self.identify(ctx),
        };
        let qname = ApName::from_uncompressed_wire(scanned.qname);
        let (log, stat) = self.filter.load().client_log_stat(&client);
        self.rec_rc_diag_with(
            recorder,
            &client,
            Action::Resolved,
            qname.as_ref(),
            Some(ApRt(scanned.qtype)),
            rcode,
            "",
            "",
            "",
            log,
            stat,
            None,
        );
    }
}

fn apex_key(name: &ApName) -> Vec<u8> {
    name.canonical_key()
}

fn soa_with_serial(soa: &ApRecord, serial: u32) -> ApRecord {
    let mut r = soa.clone();
    if let ApRData::Soa(s) = &mut r.rdata {
        s.serial = serial;
    }
    r
}

/// A peer whose key is unknown cannot be signed for.
fn unsigned_tsig_error_response(
    request: &Message,
    request_tsig: &onetdns_dnssec::tsig::TsigRecordData,
    error: onetdns_dnssec::tsig::UnsignedTsigError,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, ResponseCode(9), udp_payload);
    onetdns_dnssec::tsig::append_unsigned_error(&mut response, request_tsig, error);
    if response.try_encode().is_err() {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::append_unsigned_error(&mut response, request_tsig, error);
    }
    response
}

/// Carries this server's time so the peer can correct its clock.
fn signed_badtime_response(
    request: &Message,
    key: &onetdns_dnssec::tsig::TsigKey,
    request_tsig: &onetdns_dnssec::tsig::VerifiedTsig,
    server_now: u64,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, ResponseCode(9), udp_payload);
    if onetdns_dnssec::tsig::sign_badtime_response(&mut response, key, request_tsig, server_now)
        .is_err()
    {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::sign_badtime_response(&mut response, key, request_tsig, server_now)
            .expect("A minimal BADTIME response can always be encoded before TSIG signing");
    }
    response
}

fn signed_tsig_error_response(
    request: &Message,
    key: &onetdns_dnssec::tsig::TsigKey,
    request_tsig: &onetdns_dnssec::tsig::VerifiedTsig,
    code: ResponseCode,
    udp_payload: u16,
) -> Message {
    let mut response = edns_error_resp(request, code, udp_payload);
    if onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
        .is_err()
    {
        response.questions.clear();
        response.additionals.clear();
        onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
            .expect("A minimal TSIG error response can always be encoded before signing");
    }
    response
}

const XFR_CHUNK_BUDGET: usize = onetdns_authority::XFR_CHUNK_BUDGET;

fn xfr_single_response(
    request: &Message,
    rcode: ResponseCode,
    answer: Option<ApRecord>,
    truncated: bool,
    tsig_ctx: Option<&TsigContext>,
) -> Message {
    let mut response = base_response(request);
    response.additionals.clear();
    response.header.authoritative = true;
    response.header.rcode = rcode.0;
    response.header.truncated = truncated;
    response.answers.extend(answer);
    if let Some((key, request_tsig)) = tsig_ctx {
        onetdns_dnssec::tsig::sign_response_message(&mut response, key, now_unix(), request_tsig)
            .expect("A size-limited single XFR response can be encoded before TSIG signing");
    }
    response
}

fn xfr_envelopes_stream<I>(
    request: &Message,
    records: I,
    tsig_ctx: Option<TsigContext>,
    emit: &mut dyn FnMut(Message) -> bool,
) -> bool
where
    I: IntoIterator<Item = ApRecord>,
{
    let mut chunk = Vec::new();
    let mut size = 0usize;
    let mut index = 0usize;
    let mut prev_mac = None;

    let mut estimate_writer = onetdns_proto::Writer::new();
    for r in records {
        estimate_writer.clear();
        r.encode(&mut estimate_writer);
        let est = estimate_writer.buf.len();
        if size + est > XFR_CHUNK_BUDGET && !chunk.is_empty() {
            let message = xfr_envelope(
                request,
                std::mem::take(&mut chunk),
                index,
                &tsig_ctx,
                &mut prev_mac,
            );
            if !emit(message) {
                return false;
            }
            index += 1;
            size = 0;
        }
        size += est;
        chunk.push(r);
    }
    emit(xfr_envelope(
        request,
        chunk,
        index,
        &tsig_ctx,
        &mut prev_mac,
    ))
}

fn xfr_envelope(
    request: &Message,
    answers: Vec<ApRecord>,
    index: usize,
    tsig_ctx: &Option<TsigContext>,
    prev_mac: &mut Option<Vec<u8>>,
) -> Message {
    let mut message = base_response(request);
    message.additionals.clear();
    message.header.authoritative = true;
    if index > 0 {
        message.questions.clear();
    }
    message.answers = answers;
    if let Some((key, request_tsig)) = tsig_ctx {
        let mac = if index == 0 {
            onetdns_dnssec::tsig::sign_response_message(&mut message, key, now_unix(), request_tsig)
        } else {
            onetdns_dnssec::tsig::sign_response_subsequent(
                &mut message,
                key,
                now_unix(),
                prev_mac.as_deref().unwrap_or(&[]),
                request_tsig,
            )
        }
        .expect("An XFR message capped at 16 KiB always encodes before TSIG signing");
        *prev_mac = Some(mac);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::tests::{ctx, q, server, shaped_server};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use onetdns_proto::{
        DnsClass, Edns, Message, Name as ApName, RData as ApRData, Record as ApRecord,
        RecordType as ApRt, ResponseCode,
    };
    use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

    #[test]
    /// RFC 6891: with an OPT in the request the response carries one too. Dropping it makes the
    /// peer assume no EDNS and fall back to 512 bytes for every later query.
    fn protocol_error_responses_echo_the_request_opt() {
        let server = shaped_server(true);

        let with_edns = |mut request: Message| {
            let mut edns = Edns::default();
            edns.udp_payload = 1232;
            request.additionals.push(edns.try_to_record().unwrap());
            request
        };

        let mut not_implemented = with_edns(q("opcode.example"));
        not_implemented.header.opcode = 2;
        let mut zero_questions = with_edns(q("qdcount.example"));
        zero_questions.questions.clear();
        let mut bad_update = with_edns(q("update.example"));
        bad_update.header.opcode = 5;
        let mut bad_notify = with_edns(q("notify.example"));
        bad_notify.header.opcode = 4;

        for (label, request, rcode) in [
            ("opcode 2", not_implemented, ResponseCode::NotImp.0),
            ("QDCOUNT 0", zero_questions, ResponseCode::FormErr.0),
            ("UPDATE zone question", bad_update, ResponseCode::FormErr.0),
            ("NOTIFY zone question", bad_notify, ResponseCode::FormErr.0),
        ] {
            let response = server.handle(&request, &ctx()).expect("오류 응답");
            assert_eq!(response.header.rcode, rcode, "{label}");
            assert!(
                response.opt().is_some(),
                "{label}: 요청 OPT를 그대로 돌려줘야 합니다"
            );
        }

        let mut plain = q("opcode.example");
        plain.header.opcode = 2;
        let response = server.handle(&plain, &ctx()).expect("EDNS 없는 오류 응답");
        assert!(
            response.opt().is_none(),
            "요청에 OPT가 없으면 응답에도 넣지 않습니다"
        );

        // TSIG errors follow the same rule, and the OPT must precede the TSIG for the signature to
        // cover it.
        let key = onetdns_dnssec::tsig::TsigKey::new(
            ApName::from_str("probe-key").unwrap(),
            vec![7u8; 32],
        )
        .expect("테스트용 TSIG 키");
        let mut signed = with_edns(q("tsig.example"));
        onetdns_dnssec::tsig::sign_message(&mut signed, &key, 1_700_000_000, None)
            .expect("요청 서명");
        let request_tsig = onetdns_dnssec::tsig::request_data(&signed).expect("요청 TSIG");
        let unsigned_error = unsigned_tsig_error_response(
            &signed,
            &request_tsig,
            onetdns_dnssec::tsig::UnsignedTsigError::BadKey,
            1232,
        );
        assert!(
            unsigned_error.opt().is_some(),
            "TSIG BADKEY 응답도 요청 OPT를 그대로 돌려줘야 합니다"
        );
        let types: Vec<u16> = unsigned_error
            .additionals
            .iter()
            .map(|record| record.rtype.0)
            .collect();
        assert_eq!(types, vec![41, 250], "OPT가 TSIG보다 앞이어야 합니다");
    }

    #[test]
    /// Member zones are learned from the catalog, so the configuration does not name them. NOTIFY
    /// from other addresses is still ignored.
    fn notify_from_catalog_primary_wakes_member_refresh() {
        let kick = Arc::new(NotifyKick::default());
        let srv = server("").with_notify_secondaries(Vec::new(), kick.clone());
        srv.edit_authority(|authority| {
            authority.notify_catalog_primaries = vec![("192.0.2.53".parse().unwrap(), None)];
        });
        let mut request = Message::default();
        request.header.opcode = 4;
        request.header.authoritative = true;
        request.questions.push(onetdns_proto::Question {
            name: ApName::from_str("member.test").unwrap(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        let context = |src: &str| RequestCtx {
            src: src.parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        assert!(srv
            .handle(&request, &context("198.51.100.9:53000"))
            .is_none());
        assert!(kick.wait_take(Duration::ZERO).is_empty());

        let response = srv
            .handle(&request, &context("192.0.2.53:53000"))
            .expect("NOTIFY ACK");
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(kick.wait_take(Duration::ZERO).contains("member.test"));
    }

    #[test]
    fn notify_only_acknowledges_known_master_requests_and_wakes_refresh() {
        let origin = ApName::from_str("secondary.test").unwrap();
        let kick = Arc::new(NotifyKick::default());
        let srv = server("").with_notify_secondaries(
            vec![(origin.clone(), "127.0.0.1".parse().unwrap(), None)],
            kick.clone(),
        );
        let mut request = Message::default();
        request.header.id = 0x4e4f;
        request.header.opcode = 4;
        request.header.authoritative = true;
        request.questions.push(onetdns_proto::Question {
            name: origin,
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        let context = RequestCtx {
            src: "127.0.0.1:53000".parse().unwrap(),
            transport: RtTransport::Do53Udp,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };

        let response = srv.handle(&request, &context).expect("NOTIFY ACK");
        assert!(response.header.response);
        assert!(
            response.header.authoritative,
            "RFC 1996 NOTIFY ACK에는 AA가 필요"
        );
        assert!(!response.header.recursion_available);
        assert_eq!(response.header.id, request.header.id);
        assert_eq!(response.header.opcode, 4);
        assert_eq!(response.header.rcode, ResponseCode::NoError.0);
        assert!(
            kick.wait_take(Duration::ZERO).contains("secondary.test"),
            "수신 즉시 갱신 작업을 깨워야 함"
        );

        request.header.response = true;
        assert!(
            srv.handle(&request, &context).is_none(),
            "NOTIFY 응답에 다시 응답하면 패킷 루프가 생김"
        );

        request.header.response = false;
        let unknown = RequestCtx {
            src: "127.0.0.2:53000".parse().unwrap(),
            ..context
        };
        assert!(
            srv.handle(&request, &unknown).is_none(),
            "RFC 1996은 알 수 없는 master의 NOTIFY를 무시하도록 요구"
        );
    }

    #[test]
    fn ixfr_journal_does_not_retain_deltas_larger_than_axfr() {
        let old = onetdns_authority::parse_zone(
            "$ORIGIN budget.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\na IN A 192.0.2.10\nb IN A 192.0.2.11\nc IN A 192.0.2.12\nd IN A 192.0.2.13\n",
            "budget.test",
        )
        .unwrap();
        let new = onetdns_authority::parse_zone(
            "$ORIGIN budget.test.\n@ IN SOA ns admin 2 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nw IN A 198.51.100.10\nx IN A 198.51.100.11\ny IN A 198.51.100.12\nz IN A 198.51.100.13\n",
            "budget.test",
        )
        .unwrap();
        let mut old_records = old.axfr_records();
        let mut new_records = new.axfr_records();
        old_records.pop();
        new_records.pop();

        let mut journal = ZoneJournal::default();
        journal.record(1, 2, &old_records, &new_records);
        assert!(
            journal.deltas.is_empty(),
            "AXFR보다 큰 증분은 메모리에 보존하지 않습니다"
        );
    }

    #[test]
    fn ixfr_journal_retention_is_bounded_by_current_zone_size() {
        let zone = onetdns_authority::parse_zone(
            "$ORIGIN bounded.test.\n@ IN SOA ns admin 1 300 60 86400 60\n@ IN NS ns\nns IN A 192.0.2.1\nseed IN A 192.0.2.2\n",
            "bounded.test",
        )
        .unwrap();
        let mut current = zone.axfr_records();
        current.pop();
        let mut journal = ZoneJournal::default();
        for serial in 2..=65 {
            let old = current.clone();
            current[0] = soa_with_serial(&current[0], serial);
            current.push(ApRecord::new(
                ApName::from_str(&format!("added-{serial}.bounded.test")).unwrap(),
                60,
                ApRData::A(Ipv4Addr::new(198, 51, 100, serial as u8)),
            ));
            journal.record(serial - 1, serial, &old, &current);
        }
        assert!(
            journal.deltas.len() < ZoneJournal::MAX,
            "작은 zone의 저널이 고정 개수 상한까지 비대해지지 않습니다"
        );
        let oldest = journal.deltas.front().unwrap().from;
        assert!(journal.path_from(oldest, 65).is_some());
    }

    #[test]
    fn update_policy_grant_deny_matching() {
        let rules = vec![
            UpdateRule::new(false, "*", "locked.example", vec![]).unwrap(),
            UpdateRule::new(true, "dhcp-key", "*.dyn.example", vec![1, 28]).unwrap(),
        ];

        let identity = ApName::from_str("dhcp-key").unwrap();
        let upper_identity = ApName::from_str("DHCP-KEY").unwrap();
        let other_identity = ApName::from_str("other").unwrap();
        let locked = ApName::from_str("locked.example").unwrap();
        let dynamic = ApName::from_str("host.dyn.example").unwrap();
        let dynamic_apex = ApName::from_str("dyn.example").unwrap();
        let elsewhere = ApName::from_str("elsewhere.example").unwrap();

        assert!(!update_granted(&rules, Some(&identity), &locked, 1));

        assert!(update_granted(&rules, Some(&identity), &dynamic, 1));
        assert!(update_granted(&rules, Some(&upper_identity), &dynamic, 28));
        assert!(
            !update_granted(&rules, Some(&identity), &dynamic_apex, 1),
            "*.dyn.example은 영역 정점 자체에 권한을 주면 안 됨"
        );

        assert!(!update_granted(&rules, Some(&identity), &dynamic, 16));

        assert!(!update_granted(&rules, Some(&other_identity), &dynamic, 1));

        assert!(!update_granted(&rules, Some(&identity), &elsewhere, 1));
    }

    #[test]
    /// A removed alias left accepted would pass a rule with a different meaning.
    fn update_policy_rejects_removed_subtree_alias() {
        assert!(UpdateRule::new(true, "*", ".dyn.example", vec![1]).is_none());
    }

    #[test]
    fn update_policy_preserves_raw_name_octets() {
        let rules = vec![UpdateRule::new(true, "*", "�", vec![1]).unwrap()];
        let configured = ApName::from_str("�").unwrap();
        let raw = ApName::from_labels(vec![vec![0xff]]).unwrap();

        assert!(update_granted(&rules, None, &configured, 1));
        assert!(!update_granted(&rules, None, &raw, 1));
    }

    #[test]
    fn rebind_allow_suffix_preserves_raw_name_octets() {
        let configured = ApName::from_str("�").unwrap();
        let child = ApName::from_str("host.�").unwrap();
        let raw = ApName::from_labels(vec![b"host".to_vec(), vec![0xff]]).unwrap();

        assert!(name_ends_with(&child, &configured));
        assert!(!name_ends_with(&raw, &configured));
    }
}
