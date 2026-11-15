//! Synthesizes local A and AAAA answers in split mode, and the table behind them.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};

use onetdns_proto::{Message, Name, RData, Record, RecordType};

use super::{answer_message, configured_name_key, outcome_to_option};
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};

/// The TTL is an atomic so a reload applies from the next query.
pub struct LocalAddressTable {
    addresses: HashMap<Vec<u8>, LocalAddresses>,
    local_ttl: Arc<std::sync::atomic::AtomicU32>,
}

#[derive(Default)]
struct LocalAddresses {
    a: Option<Ipv4Addr>,
    aaaa: Option<Ipv6Addr>,
}

impl LocalAddressTable {
    /// Fails on an invalid or duplicate name.
    pub fn new(
        local_a: &[(String, Ipv4Addr)],
        local_aaaa: &[(String, Ipv6Addr)],
        local_ttl: Arc<std::sync::atomic::AtomicU32>,
    ) -> Result<Self, String> {
        let mut addresses = HashMap::<Vec<u8>, LocalAddresses>::with_capacity(
            local_a.len().saturating_add(local_aaaa.len()),
        );
        for (name, ip) in local_a {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("Invalid local A record name: {name}"))?;
            if addresses.entry(key).or_default().a.replace(*ip).is_some() {
                return Err(format!("Duplicate local A record name: {name}"));
            }
        }
        for (name, ip) in local_aaaa {
            let key = configured_name_key(name)
                .ok_or_else(|| format!("Invalid local AAAA record name: {name}"))?;
            if addresses
                .entry(key)
                .or_default()
                .aaaa
                .replace(*ip)
                .is_some()
            {
                return Err(format!("Duplicate local AAAA record name: {name}"));
            }
        }
        Ok(Self {
            addresses,
            local_ttl,
        })
    }

    fn local_answer(&self, name: &Name, qtype: RecordType) -> Option<(Vec<Record>, u32)> {
        let mut key = [0u8; 255];
        let key = name.canonical_key_into(&mut key)?;
        let addresses = self.addresses.get(key)?;
        let ttl = self.local_ttl.load(std::sync::atomic::Ordering::Acquire);
        let answers = match qtype {
            RecordType::A => addresses
                .a
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::A(ip))])
                .unwrap_or_default(),
            RecordType::AAAA => addresses
                .aaaa
                .map(|ip| vec![Record::new(name.clone(), ttl, RData::Aaaa(ip))])
                .unwrap_or_default(),
            _ => vec![],
        };
        Some((answers, ttl))
    }
}

/// Marks its answers in the cache; otherwise an outer layer's answer could later be taken for this
/// layer's and promoted to a fixed-TTL entry.
pub struct LocalAddressLayer {
    inner: Arc<dyn Resolver>,
    addresses: Arc<LocalAddressTable>,
    wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
}

impl LocalAddressLayer {
    pub fn new(
        inner: Arc<dyn Resolver>,
        addresses: Arc<LocalAddressTable>,
        wire_cache: Option<Arc<OnceLock<crate::cache::CacheHandle>>>,
    ) -> Self {
        Self {
            inner,
            addresses,
            wire_cache,
        }
    }
}

impl Resolver for LocalAddressLayer {
    fn resolve(&self, req: &Message) -> Option<Message> {
        outcome_to_option(self.resolve_outcome(req))
    }

    fn resolve_outcome(&self, req: &Message) -> ResolveOutcome {
        let Some(q) = req.questions.first() else {
            return ResolveOutcome::Failure(ResolveFailure::Permanent(None));
        };
        if let Some((answers, ttl)) = self.addresses.local_answer(&q.name, q.qtype) {
            if let Some(cache) = self.wire_cache.as_ref().and_then(|slot| slot.get()) {
                cache.ensure_local_wire_candidate(req);
            }
            let mut response = answer_message(req.header.id, q.name.clone(), q.qtype, answers);
            if response.answers.is_empty() {
                response.authorities.push(Record::new(
                    q.name.clone(),
                    ttl,
                    RData::Soa(Box::new(onetdns_proto::Soa {
                        mname: Name::root(),
                        rname: Name::root(),
                        serial: 1,
                        refresh: 3_600,
                        retry: 600,
                        expire: 86_400,
                        minimum: ttl,
                    })),
                ));
            }
            return ResolveOutcome::Response(response);
        }
        self.inner.resolve_outcome(req)
    }
}
