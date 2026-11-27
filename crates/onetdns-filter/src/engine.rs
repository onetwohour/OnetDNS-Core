//! Block verdict engine. Each query walks several sets in a fixed priority order, from client
//! policy to per-type rules.
//!
//! The order is the meaning: important rules beat plain allow rules, and allow rules beat plain
//! block rules. Reordering changes what the operator's rules mean.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::compact::{CompactDomainMap, CompactMatch};
use crate::regex::{Regex, RegexSet};
use crate::table::DomainTable;
use onetdns_core::{
    ArcSwap, BlockResponse, ClientInfo, FilterEngine, FilterExplanation, FilterVerdict, IpNet,
    MatchStage, NetIndex, RewriteTarget,
};
use onetdns_proto::{Name, RecordType};

pub const NO_SOURCE: u32 = u32::MAX;

#[derive(Debug, Default)]
/// Per-rule hit counts; allocated only when enabled.
struct HitCounters {
    dense: Box<[AtomicU64]>,
    /// Rebuilt only when tracking is on.
    dense_names: DenseHitNames,
    /// For names not compacted.
    sparse: HashMap<Box<str>, AtomicU64>,
}

#[derive(Debug, Default)]
struct DenseHitNames {
    text: Box<str>,
    /// Each name's start, plus the end of the last.
    offsets: Box<[u32]>,
}

impl DenseHitNames {
    /// Walks the automaton once to build the names for reports.
    fn from_compact(compact: &CompactDomainMap) -> Self {
        if compact.is_empty() {
            return Self::default();
        }
        let mut text = String::new();
        let mut offsets = Vec::with_capacity(compact.len() + 1);
        let rebuilt = compact.for_each_entry(|index, key, _| {
            debug_assert_eq!(index, offsets.len());
            offsets.push(text.len() as u32);
            text.push_str(key);
        });
        if rebuilt.is_err() || offsets.len() != compact.len() {
            return Self::default();
        }
        offsets.push(text.len() as u32);
        Self {
            text: text.into_boxed_str(),
            offsets: offsets.into_boxed_slice(),
        }
    }

    fn get(&self, index: usize) -> Option<&str> {
        let start = *self.offsets.get(index)? as usize;
        let end = *self.offsets.get(index + 1)? as usize;
        self.text.get(start..end)
    }

    fn storage_bytes(&self) -> usize {
        self.text.len() + self.offsets.len() * size_of::<u32>()
    }
}

impl HitCounters {
    fn new(compact: &CompactDomainMap, fallback: &DomainTable) -> Self {
        let dense = std::iter::repeat_with(|| AtomicU64::new(0))
            .take(compact.len())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let sparse = fallback
            .keys()
            .map(|key| (key.into(), AtomicU64::new(0)))
            .collect();
        Self {
            dense,
            dense_names: DenseHitNames::from_compact(compact),
            sparse,
        }
    }

    fn increment(&self, index: Option<usize>, key: &str) {
        let counter = index
            .and_then(|index| self.dense.get(index))
            .or_else(|| self.sparse.get(key));
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn value(&self, index: Option<usize>, key: &str) -> u64 {
        index
            .and_then(|index| self.dense.get(index))
            .or_else(|| self.sparse.get(key))
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn dense_value(&self, index: usize) -> u64 {
        self.dense
            .get(index)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn entries(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        let dense = self
            .dense
            .iter()
            .enumerate()
            .filter_map(|(index, counter)| {
                self.dense_names
                    .get(index)
                    .map(|key| (key, counter.load(Ordering::Relaxed)))
            });
        let sparse = self
            .sparse
            .iter()
            .map(|(key, counter)| (&**key, counter.load(Ordering::Relaxed)));
        dense.chain(sparse)
    }

    fn storage_bytes(&self) -> usize {
        self.dense.len() * size_of::<AtomicU64>()
            + self.dense_names.storage_bytes()
            + self.sparse.capacity()
                * (size_of::<Box<str>>() + size_of::<AtomicU64>() + size_of::<usize>())
            + self.sparse.keys().map(|key| key.len()).sum::<usize>()
    }
}

#[derive(Clone, Copy)]
struct DomainMatch<'a> {
    key: &'a str,
    source: u32,
    is_exact: bool,
    /// Position in the compact data, for hit counting.
    compact_index: Option<usize>,
}

#[derive(Debug, Default)]
/// One domain set: a table while loading, the minimal automaton once frozen. An edit thaws it back
/// into a table until the next freeze.
pub struct DomainSet {
    exact: DomainTable,
    suffixes: DomainTable,
    exact_compact: CompactDomainMap,
    suffix_compact: CompactDomainMap,

    exact_hits: Option<HitCounters>,
    suffix_hits: Option<HitCounters>,
    entry_count: usize,
}

impl DomainSet {
    pub fn encode_compact(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
        self.encode_compact_chunks(&mut |bytes| output.extend_from_slice(bytes))
    }

    pub(crate) fn encode_compact_chunks(
        &self,
        output: &mut impl FnMut(&[u8]),
    ) -> Result<(), &'static str> {
        if !self.exact.is_empty() || !self.suffixes.is_empty() {
            return Err("Domain set is not compacted yet and cannot be cached");
        }
        self.exact_compact.encode_chunks(output)?;
        self.suffix_compact.encode_chunks(output)
    }

    pub fn decode_compact(input: &mut &[u8]) -> Result<Self, &'static str> {
        let exact_compact = CompactDomainMap::decode_from(input)?;
        let suffix_compact = CompactDomainMap::decode_from(input)?;
        let entry_count = exact_compact
            .len()
            .checked_add(suffix_compact.len())
            .ok_or("DomainSet entry count overflowed")?;
        Ok(Self {
            exact_compact,
            suffix_compact,
            entry_count,
            ..Self::default()
        })
    }

    pub fn add_exact(&mut self, domain: &str) {
        self.add_exact_src(domain, NO_SOURCE);
    }

    /// Also matches subdomains.
    pub fn add_suffix(&mut self, domain: &str) {
        self.add_suffix_src(domain, NO_SOURCE);
    }

    pub fn add_exact_src(&mut self, domain: &str, source: u32) {
        Self::thaw(
            &mut self.exact,
            &mut self.exact_compact,
            &mut self.exact_hits,
        );
        if self.exact.insert_if_absent(&normalize_str(domain), source) {
            self.entry_count += 1;
        }
    }

    pub fn add_suffix_src(&mut self, domain: &str, source: u32) {
        let normalized = normalize_str(domain);

        if normalized.is_empty() {
            return;
        }
        Self::thaw(
            &mut self.suffixes,
            &mut self.suffix_compact,
            &mut self.suffix_hits,
        );
        if self.suffixes.insert_if_absent(&normalized, source) {
            self.entry_count += 1;
        }
    }

    /// Thaws first if frozen.
    pub fn remove_exact(&mut self, domain: &str) {
        Self::thaw(
            &mut self.exact,
            &mut self.exact_compact,
            &mut self.exact_hits,
        );
        self.entry_count -= usize::from(self.exact.remove(normalize_str(domain).as_str()));
        self.exact_hits = None;
    }

    /// Thaws first if frozen.
    pub fn remove_suffix(&mut self, domain: &str) {
        Self::thaw(
            &mut self.suffixes,
            &mut self.suffix_compact,
            &mut self.suffix_hits,
        );
        self.entry_count -= usize::from(self.suffixes.remove(normalize_str(domain).as_str()));
        self.suffix_hits = None;
    }

    /// Each half is the built automaton, or the table kept when building was abandoned.
    pub(crate) fn from_built(
        exact: Result<CompactDomainMap, DomainTable>,
        suffix: Result<CompactDomainMap, DomainTable>,
    ) -> Self {
        let mut set = Self::default();
        match exact {
            Ok(built) => set.exact_compact = built,
            Err(table) => set.exact = table,
        }
        match suffix {
            Ok(built) => set.suffix_compact = built,
            Err(table) => set.suffixes = table,
        }
        set.entry_count = set.exact.len()
            + set.exact_compact.len()
            + set.suffixes.len()
            + set.suffix_compact.len();
        set
    }

    /// Exact and suffix entries as tables, leaving the set empty.
    pub(crate) fn take_tables(&mut self) -> (DomainTable, DomainTable) {
        Self::thaw(
            &mut self.exact,
            &mut self.exact_compact,
            &mut self.exact_hits,
        );
        Self::thaw(
            &mut self.suffixes,
            &mut self.suffix_compact,
            &mut self.suffix_hits,
        );
        let tables = (
            std::mem::take(&mut self.exact),
            std::mem::take(&mut self.suffixes),
        );
        *self = Self::default();
        tables
    }

    /// `(exact, name, source)`, sorted.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> Vec<(bool, String, u32)> {
        let mut entries = Vec::new();
        for (exact, table, compact) in [
            (true, &self.exact, &self.exact_compact),
            (false, &self.suffixes, &self.suffix_compact),
        ] {
            entries.extend(
                table
                    .iter()
                    .map(|(key, source)| (exact, key.to_string(), source)),
            );
            compact
                .for_each_entry(|_, key, source| entries.push((exact, key.to_string(), source)))
                .expect("a built set lists its entries");
        }
        entries.sort();
        entries
    }

    /// Once, after loading.
    fn finalize(&mut self) {
        Self::compact(&mut self.exact, &mut self.exact_compact);
        Self::compact(&mut self.suffixes, &mut self.suffix_compact);
    }

    fn enable_hits(&mut self) {
        self.finalize();
        self.exact_hits = Some(HitCounters::new(&self.exact_compact, &self.exact));
        self.suffix_hits = Some(HitCounters::new(&self.suffix_compact, &self.suffixes));
    }

    /// On failure the table stays.
    fn compact(map: &mut DomainTable, compact: &mut CompactDomainMap) {
        if map.is_empty() {
            return;
        }
        let owned = std::mem::take(map);
        match CompactDomainMap::try_from_table(owned) {
            Ok(built) => *compact = built,
            Err(fallback) => *map = fallback,
        }
    }

    /// Needed before edits.
    fn thaw(map: &mut DomainTable, compact: &mut CompactDomainMap, hits: &mut Option<HitCounters>) {
        if compact.is_empty() {
            return;
        }
        let frozen = std::mem::take(compact);
        let mut rebuilt = DomainTable::default();
        rebuilt.reserve(frozen.len());
        if frozen
            .for_each_entry(|_, key, source| {
                rebuilt.insert_if_absent(key, source);
            })
            .is_err()
        {
            *compact = frozen;
            return;
        }
        *map = rebuilt;
        *hits = None;
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    pub fn len(&self) -> usize {
        self.entry_count
    }

    pub fn storage_bytes(&self) -> usize {
        self.exact_compact.storage_bytes()
            + self.suffix_compact.storage_bytes()
            + self.exact.storage_bytes()
            + self.suffixes.storage_bytes()
            + self
                .exact_hits
                .as_ref()
                .map(HitCounters::storage_bytes)
                .unwrap_or(0)
            + self
                .suffix_hits
                .as_ref()
                .map(HitCounters::storage_bytes)
                .unwrap_or(0)
    }

    pub fn matches(&self, normalized: &str) -> bool {
        self.matched(normalized).is_some()
    }

    pub fn matched<'a>(&self, normalized: &'a str) -> Option<&'a str> {
        self.matched_kv(normalized).map(|found| found.key)
    }

    pub fn source_of(&self, normalized: &str) -> Option<u32> {
        let found = self.matched_kv(normalized)?;
        if let Some(index) = found.compact_index {
            if found.is_exact {
                self.exact_compact.source(index)
            } else {
                self.suffix_compact.source(index)
            }
        } else {
            Some(found.source)
        }
    }

    /// Also counts the hit.
    pub fn hit<'a>(&self, normalized: &'a str) -> Option<&'a str> {
        let found = self.matched_kv(normalized)?;
        let counters = if found.is_exact {
            self.exact_hits.as_ref()
        } else {
            self.suffix_hits.as_ref()
        };
        if let Some(counters) = counters {
            counters.increment(found.compact_index, found.key);
        }
        Some(found.key)
    }

    /// Exact match first, then the longest suffix. Suffixes match only at label boundaries;
    /// otherwise evil-example.com would match an example.com rule.
    fn matched_kv<'a>(&self, normalized: &'a str) -> Option<DomainMatch<'a>> {
        if self.is_empty() {
            return None;
        }
        if !self.exact.is_empty() {
            if let Some((_, source)) = self.exact.get_key_value(normalized) {
                return Some(DomainMatch {
                    key: normalized,
                    source,
                    is_exact: true,
                    compact_index: None,
                });
            }
        }
        if !self.exact_compact.is_empty() {
            if let Some(found) = self.exact_compact.lookup_exact(normalized) {
                return Some(Self::compact_match(found, true));
            }
        }

        if !self.suffixes.is_empty() {
            let mut rest = normalized;
            loop {
                if let Some((_, source)) = self.suffixes.get_key_value(rest) {
                    return Some(DomainMatch {
                        key: rest,
                        source,
                        is_exact: false,
                        compact_index: None,
                    });
                }
                match rest.find('.') {
                    Some(idx) => rest = &rest[idx + 1..],
                    None => break,
                }
            }
        }
        self.suffix_compact
            .lookup_suffix(normalized)
            .map(|found| Self::compact_match(found, false))
    }

    fn compact_match<'a>(found: CompactMatch<'a>, is_exact: bool) -> DomainMatch<'a> {
        DomainMatch {
            key: found.key,

            source: NO_SOURCE,
            is_exact,
            compact_index: Some(found.index),
        }
    }

    fn hit_entries(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.exact_hits
            .iter()
            .flat_map(HitCounters::entries)
            .chain(self.suffix_hits.iter().flat_map(HitCounters::entries))
    }

    fn source_entries(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        let exact = self.exact.iter().map(move |(k, src)| {
            let hits = self
                .exact_hits
                .as_ref()
                .map(|counters| counters.value(None, k))
                .unwrap_or(0);
            (src, hits)
        });
        let exact_compact = self
            .exact_compact
            .indexed_sources()
            .map(move |(index, source)| {
                let hits = self
                    .exact_hits
                    .as_ref()
                    .map(|counters| counters.dense_value(index))
                    .unwrap_or(0);
                (source, hits)
            });
        let suffix = self.suffixes.iter().map(move |(k, src)| {
            let hits = self
                .suffix_hits
                .as_ref()
                .map(|counters| counters.value(None, k))
                .unwrap_or(0);
            (src, hits)
        });
        let suffix_compact = self
            .suffix_compact
            .indexed_sources()
            .map(move |(index, source)| {
                let hits = self
                    .suffix_hits
                    .as_ref()
                    .map(|counters| counters.dense_value(index))
                    .unwrap_or(0);
                (source, hits)
            });
        exact
            .chain(exact_compact)
            .chain(suffix)
            .chain(suffix_compact)
    }
}

#[derive(Debug, Default)]
pub struct RewriteSet {
    pub(crate) exact: HashMap<Box<str>, RewriteTarget>,

    pub(crate) suffix: HashMap<Box<str>, RewriteTarget>,

    /// `$dnsrewrite` rules, in rule order. Each covers the name and every name under it.
    pub(crate) rules: HashMap<Box<str>, Vec<RewriteTarget>>,
}

impl RewriteSet {
    pub fn add_exact(&mut self, domain: &str, target: RewriteTarget) {
        self.exact
            .insert(normalize_str(domain).into_boxed_str(), target);
    }

    pub fn add_suffix(&mut self, domain: &str, target: RewriteTarget) {
        self.suffix
            .insert(normalize_str(domain).into_boxed_str(), target);
    }

    pub fn add_rule(&mut self, domain: &str, target: RewriteTarget) {
        self.rules
            .entry(normalize_str(domain).into_boxed_str())
            .or_default()
            .push(target);
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty() && self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len() + self.rules.values().map(Vec::len).sum::<usize>()
    }

    /// Removes an exact entry only when it still holds `target`, and every `$dnsrewrite` rule
    /// with `target`.
    pub(crate) fn remove(&mut self, domain: &str, exact: bool, target: &RewriteTarget) {
        let key = normalize_str(domain);
        if exact {
            if self.exact.get(key.as_str()) == Some(target) {
                self.exact.remove(key.as_str());
            }
        } else if let Some(targets) = self.rules.get_mut(key.as_str()) {
            targets.retain(|t| t != target);
            if targets.is_empty() {
                self.rules.remove(key.as_str());
            }
        }
    }

    /// An exact match wins, then the longest suffix. On the same name a configured rewrite wins
    /// over `$dnsrewrite` rules, and of those the last one not `lifted` wins.
    fn get(
        &self,
        normalized: &str,
        lifted: impl Fn(&RewriteTarget) -> bool,
    ) -> Option<&RewriteTarget> {
        if let Some(t) = self.exact.get(normalized) {
            return Some(t);
        }
        let mut rest = normalized;
        loop {
            if let Some(target) = self.suffix.get(rest) {
                return Some(target);
            }
            if let Some(target) = self
                .rules
                .get(rest)
                .and_then(|targets| targets.iter().rev().find(|t| !lifted(t)))
            {
                return Some(target);
            }
            rest = match rest.find('.') {
                Some(index) => &rest[index + 1..],
                None => return None,
            };
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
/// What a `$dnsrewrite` rule answers.
pub enum RewriteValue {
    NxDomain,
    Refused,
    NoData,
    NoResponse,
    Answer(RewriteTarget),
}

#[derive(Debug, Clone, PartialEq)]
/// An `@@` rule with `$dnsrewrite`. The `$dnsrewrite` rules with `value`, or all of them when it is
/// None, do not apply to the names it covers. Other rules still do.
pub struct RewriteException {
    /// A normalized name, covering it and every name under it, or a regex.
    pub pattern: String,
    pub regex: bool,
    pub value: Option<RewriteValue>,
}

#[derive(Debug, Clone)]
/// What a configured local zone does to names under it.
pub enum LocalZoneAction {
    /// Block response; a plain allow rule wins over it.
    Deny,
    Refuse,
    /// Answers the zone and every name under it with the given records or the zero address.
    Rewrite(RewriteTarget),
    /// Only the listed names have answers; other names in the zone do not exist.
    Static(StaticZone),
    /// Lifts the enclosing local zone's action below here and resolves normally.
    Transparent,
}

#[derive(Debug, Clone, Default)]
/// Answers listed per name in a static zone. Names between a listed name and the zone exist without
/// data and get NODATA; with NXDOMAIN some resolvers would cache everything below as nonexistent,
/// and the listed names under them would vanish.
pub struct StaticZone {
    /// Normalized; the root zone is the empty string.
    zone: Box<str>,
    names: HashMap<Box<str>, RewriteTarget>,
    /// Names between the listed names and the zone name.
    interior: HashSet<Box<str>>,
}

pub enum StaticAnswer<'a> {
    Data(&'a RewriteTarget),
    NoData,
    NxDomain,
}

impl StaticZone {
    pub fn new(zone: &str) -> Self {
        Self {
            zone: normalize_str(zone).into_boxed_str(),
            ..Self::default()
        }
    }

    /// Fails when the name is outside the zone or already has an answer.
    pub fn insert(&mut self, name: &str, target: RewriteTarget) -> Result<(), String> {
        let name = normalize_str(name);
        let zone: &str = &self.zone;
        let inside = zone.is_empty()
            || name == zone
            || name
                .strip_suffix(zone)
                .is_some_and(|head| head.ends_with('.'));
        if !inside {
            return Err(format!("'{name}' is outside zone '{zone}'"));
        }
        if self.names.contains_key(name.as_str()) {
            return Err(format!("'{name}' has two answers"));
        }
        let mut rest = name.as_str();
        while rest != zone {
            rest = match rest.find('.') {
                Some(index) => &rest[index + 1..],
                None => "",
            };
            if rest == zone {
                break;
            }
            self.interior.insert(rest.into());
        }
        self.names.insert(name.into_boxed_str(), target);
        Ok(())
    }

    /// The zone name itself exists even without an answer.
    pub fn answer(&self, normalized: &str) -> StaticAnswer<'_> {
        if let Some(target) = self.names.get(normalized) {
            StaticAnswer::Data(target)
        } else if normalized == &*self.zone || self.interior.contains(normalized) {
            StaticAnswer::NoData
        } else {
            StaticAnswer::NxDomain
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &RewriteTarget)> {
        self.names
            .iter()
            .map(|(name, target)| (name.as_ref(), target))
    }
}

#[derive(Debug)]
struct LocalZoneEntry {
    action: LocalZoneAction,
    /// Counted only with hit tracking on.
    hits: AtomicU64,
}

#[derive(Debug, Default)]
/// Every configured local zone, kept apart from block, refuse, and rewrite rules. When zones
/// overlap on a name only the most specific applies; mixed in with the rest, a transparent zone
/// could not lift just the enclosing zone and would also open subscribed blocklists.
pub struct LocalZoneSet {
    zones: HashMap<Box<str>, LocalZoneEntry>,
}

impl LocalZoneSet {
    /// Rejects a zone that already exists.
    pub fn insert(&mut self, zone: &str, action: LocalZoneAction) -> Result<(), String> {
        let key = normalize_str(zone).into_boxed_str();
        if self.zones.contains_key(&key) {
            return Err(format!("Duplicate local zone: {key}"));
        }
        self.zones.insert(
            key,
            LocalZoneEntry {
                action,
                hits: AtomicU64::new(0),
            },
        );
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn len(&self) -> usize {
        self.zones.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &LocalZoneAction)> {
        self.zones
            .iter()
            .map(|(zone, entry)| (zone.as_ref(), &entry.action))
    }

    /// Strips one label at a time starting from the name itself, so the first zone found is the
    /// most specific. The root zone is stored under the empty key and checked last.
    fn lookup(&self, normalized: &str) -> Option<(&str, &LocalZoneAction)> {
        let mut rest = normalized;
        loop {
            if let Some((zone, entry)) = self.zones.get_key_value(rest) {
                return Some((zone, &entry.action));
            }
            rest = match rest.find('.') {
                Some(index) => &rest[index + 1..],
                None if !rest.is_empty() => "",
                None => return None,
            };
        }
    }

    /// Only for the zone whose action was applied.
    fn record_hit(&self, zone: &str) {
        if let Some(entry) = self.zones.get(zone) {
            entry.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn hit_entries(&self) -> impl Iterator<Item = (&str, u64)> {
        self.zones
            .iter()
            .map(|(zone, entry)| (zone.as_ref(), entry.hits.load(Ordering::Relaxed)))
    }
}

/// Only at label boundaries.
fn name_matches_suffix(name: &str, suf: &str) -> bool {
    if name == suf {
        return true;
    }
    name.len() > suf.len()
        && name.ends_with(suf)
        && name.as_bytes()[name.len() - suf.len() - 1] == b'.'
}

#[derive(Debug, Default, Clone)]
/// Shown on the dashboard.
pub struct FilterLoadReport {
    pub rules_total: u64,
    pub rules_skipped: u64,

    /// Count per unsupported modifier.
    pub unsupported_modifier: BTreeMap<String, u64>,

    pub invalid_regex: u64,

    pub invalid_pattern: u64,

    /// Rules that mean nothing for DNS blocking.
    pub not_applicable: u64,
}

impl FilterLoadReport {
    pub(crate) fn absorb(&mut self, other: Self) {
        self.rules_total += other.rules_total;
        self.rules_skipped += other.rules_skipped;
        self.invalid_regex += other.invalid_regex;
        self.invalid_pattern += other.invalid_pattern;
        self.not_applicable += other.not_applicable;
        for (modifier, count) in other.unsupported_modifier {
            *self.unsupported_modifier.entry(modifier).or_default() += count;
        }
    }

    pub fn rules_applied(&self) -> u64 {
        self.rules_total.saturating_sub(self.rules_skipped)
    }

    pub fn to_json(&self) -> String {
        let mods: Vec<String> = self
            .unsupported_modifier
            .iter()
            .map(|(k, v)| format!("{}:{}", onetdns_core::json::escape(k), v))
            .collect();
        format!(
            "{{\"rules_total\":{},\"rules_applied\":{},\"rules_skipped\":{},\
             \"skip_reasons\":{{\"unsupported_modifier\":{{{}}},\"invalid_regex\":{},\"invalid_pattern\":{},\"not_applicable\":{}}}}}",
            self.rules_total,
            self.rules_applied(),
            self.rules_skipped,
            mods.join(","),
            self.invalid_regex,
            self.invalid_pattern,
            self.not_applicable
        )
    }
}

#[derive(Debug, Clone)]
pub struct RpzIpRule {
    pub net: IpNet,
    pub verdict: FilterVerdict,
    /// Shown to identify the rule.
    pub display: Box<str>,
}

impl RpzIpRule {
    pub fn new(net: IpNet, verdict: FilterVerdict) -> Self {
        let display = net.to_string().into_boxed_str();
        Self {
            net,
            verdict,
            display,
        }
    }
}

#[derive(Debug, Clone)]
/// Nameserver-based RPZ rule.
pub struct RpzNameRule {
    pub(crate) suffix: Name,
    pub verdict: FilterVerdict,
}

impl RpzNameRule {
    pub fn new(domain: &str, verdict: FilterVerdict) -> Option<Self> {
        let suffix = Name::from_str(domain.trim_end_matches('.')).ok()?;
        Some(Self { suffix, verdict })
    }

    pub fn matches(&self, ns: &Name) -> bool {
        ns.ends_with_ignore_case(&self.suffix)
    }

    /// When several match, the more specific wins.
    fn specificity(&self) -> usize {
        self.suffix.labels().len()
    }
}

impl EngineParts {
    fn domain_sets(&self) -> Vec<&DomainSet> {
        let mut sets = vec![
            &self.block,
            &self.allow,
            &self.block_important,
            &self.allow_important,
            &self.refuse,
            &self.nodata,
            &self.no_response,
            &self.rewrite_refuse,
            &self.rewrite_nodata,
            &self.rewrite_nxdomain,
        ];
        sets.extend(self.typed_block.iter().map(|(_, set)| set));
        sets.extend(self.typed_block_except.iter().map(|(_, set)| set));
        sets.extend(self.typed_allow.iter().map(|(_, set)| set));
        sets.extend(self.typed_allow_except.iter().map(|(_, set)| set));
        sets
    }

    fn domain_sets_mut(&mut self) -> Vec<&mut DomainSet> {
        let mut sets: Vec<&mut DomainSet> = vec![
            &mut self.block,
            &mut self.allow,
            &mut self.block_important,
            &mut self.allow_important,
            &mut self.refuse,
            &mut self.nodata,
            &mut self.no_response,
            &mut self.rewrite_refuse,
            &mut self.rewrite_nodata,
            &mut self.rewrite_nxdomain,
        ];
        sets.extend(self.typed_block.iter_mut().map(|(_, s)| s));
        sets.extend(self.typed_block_except.iter_mut().map(|(_, s)| s));
        sets.extend(self.typed_allow.iter_mut().map(|(_, s)| s));
        sets.extend(self.typed_allow_except.iter_mut().map(|(_, s)| s));
        sets
    }

    pub(crate) fn finalize_domain_sets(&mut self) {
        for set in self.domain_sets_mut() {
            set.finalize();
        }
    }
}

#[derive(Default)]
/// Every set and rule that makes up an engine: the result of loading, and what the cache stores.
pub struct EngineParts {
    pub block: DomainSet,
    pub allow: DomainSet,

    pub block_important: DomainSet,
    pub allow_important: DomainSet,

    /// Refused names and RPZ rules.
    pub refuse: DomainSet,

    /// RPZ rules.
    pub nodata: DomainSet,

    /// `$dnsrewrite` rules that answer with a response code. They have sets of their own so
    /// `rewrite_exceptions` lifts them and nothing else.
    pub no_response: DomainSet,
    pub rewrite_refuse: DomainSet,
    pub rewrite_nodata: DomainSet,
    pub rewrite_nxdomain: DomainSet,

    pub typed_block: Vec<(RecordType, DomainSet)>,

    pub typed_block_except: Vec<(Vec<RecordType>, DomainSet)>,

    pub typed_allow: Vec<(RecordType, DomainSet)>,

    pub typed_allow_except: Vec<(Vec<RecordType>, DomainSet)>,

    pub regex_block: Vec<String>,
    pub regex_allow: Vec<String>,

    pub regex_block_important: Vec<String>,
    pub regex_allow_important: Vec<String>,

    /// `$dnsrewrite` rules, like the code sets above.
    pub regex_refuse: Vec<String>,
    pub regex_nodata: Vec<String>,
    pub regex_no_response: Vec<String>,
    pub regex_nxdomain: Vec<String>,

    pub regex_rewrites: Vec<(String, RewriteTarget)>,

    pub regex_typed_block: Vec<(RecordType, String)>,
    pub regex_typed_block_except: Vec<(Vec<RecordType>, String)>,

    pub regex_typed_allow: Vec<(RecordType, String)>,
    pub regex_typed_allow_except: Vec<(Vec<RecordType>, String)>,

    pub rewrites: RewriteSet,

    pub rewrite_exceptions: Vec<RewriteException>,

    pub local_zones: LocalZoneSet,

    pub client_rules: Vec<ClientRule>,

    /// Matched on the client's address.
    pub rpz_client_ip: Vec<RpzIpRule>,

    /// Matched on addresses in the answer.
    pub rpz_ip: Vec<RpzIpRule>,

    /// Matched on nameserver names in the answer.
    pub rpz_nsdname: Vec<RpzNameRule>,

    /// Matched on those nameservers' addresses.
    pub rpz_nsip: Vec<RpzIpRule>,

    pub report: FilterLoadReport,

    /// The lists this engine was built from.
    pub sources: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SourceStat {
    pub source: String,
    pub rules: u64,
    pub hits: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientCond {
    Net { negated: bool, net: IpNet },
    Id { negated: bool, id: String },
}

#[derive(Debug, Clone, Default, PartialEq)]
/// A rule that applies only to certain clients.
pub struct ClientRule {
    pub domain: String,

    /// Used instead of the name.
    pub regex: Option<String>,

    pub allow: bool,

    pub clients: Vec<ClientCond>,

    pub ctags: Vec<(bool, String)>,

    /// Names excluded from this rule.
    pub denyallow: Vec<String>,
}

/// Client rule positions by domain, so a query checks only the rules for its name and its parents
/// and the rules without a domain.
#[derive(Debug, Default)]
struct ClientRuleIndex {
    by_domain: HashMap<Box<str>, Vec<u32>>,
    any_domain: Vec<u32>,
}

impl ClientRuleIndex {
    fn new(rules: &[ClientRule]) -> Self {
        let mut index = Self::default();
        for (position, rule) in rules.iter().enumerate() {
            let position = u32::try_from(position).expect("client rules stay under 2^32");
            if rule.domain.is_empty() {
                index.any_domain.push(position);
            } else {
                index
                    .by_domain
                    .entry(rule.domain.as_str().into())
                    .or_default()
                    .push(position);
            }
        }
        index
    }

    /// In no particular order. A rule's domain matches `key` exactly when it is `key` or what
    /// follows one of its dots, which is what `name_matches_suffix` tests.
    fn candidates<'a>(&'a self, key: &'a str) -> impl Iterator<Item = usize> + 'a {
        let mut rest = Some(key);
        std::iter::from_fn(move || {
            let current = rest?;
            rest = current.find('.').map(|dot| &current[dot + 1..]);
            Some(current)
        })
        .filter_map(|suffix| self.by_domain.get(suffix))
        .flatten()
        .chain(&self.any_domain)
        .map(|&position| position as usize)
    }
}

impl ClientRule {
    fn applies(&self, key: &str, client: &ClientInfo, tags: &[String]) -> bool {
        if !self.domain.is_empty() && !name_matches_suffix(key, &self.domain) {
            return false;
        }

        if self.denyallow.iter().any(|d| name_matches_suffix(key, d)) {
            return false;
        }

        if !self.clients.is_empty() {
            let mut has_pos = false;
            let mut pos_hit = false;
            for c in &self.clients {
                let (neg, hit) = match c {
                    ClientCond::Net { negated, net } => (*negated, net.contains(&client.source_ip)),
                    ClientCond::Id { negated, id } => (
                        *negated,
                        client
                            .client_id
                            .as_deref()
                            .is_some_and(|x| x.eq_ignore_ascii_case(id)),
                    ),
                };
                if neg {
                    if hit {
                        return false;
                    }
                } else {
                    has_pos = true;
                    if hit {
                        pos_hit = true;
                    }
                }
            }
            if has_pos && !pos_hit {
                return false;
            }
        }

        if !self.ctags.is_empty() {
            let mut has_pos = false;
            let mut pos_hit = false;
            for (neg, tag) in &self.ctags {
                let hit = tags.iter().any(|t| t.eq_ignore_ascii_case(tag));
                if *neg {
                    if hit {
                        return false;
                    }
                } else {
                    has_pos = true;
                    if hit {
                        pos_hit = true;
                    }
                }
            }
            if has_pos && !pos_hit {
                return false;
            }
        }
        true
    }
}

#[derive(Debug)]
/// Policy for one client group.
pub struct ClientPolicy {
    nets: Vec<IpNet>,

    ids: Vec<String>,

    tags: Vec<String>,
    block: DomainSet,
    allow: DomainSet,

    disable_filtering: bool,

    /// None follows the global setting.
    safe_search: Option<bool>,

    ignore_querylog: bool,
    ignore_stats: bool,
}

impl ClientPolicy {
    pub fn new(
        nets: Vec<IpNet>,
        block: &[String],
        allow: &[String],
        disable_filtering: bool,
    ) -> Self {
        Self::with_options(nets, vec![], vec![], block, allow, disable_filtering, None)
    }

    #[allow(clippy::too_many_arguments)]
    /// Otherwise the fast path can skip it.
    pub(crate) fn affects_verdict(&self) -> bool {
        !self.block.is_empty() || !self.allow.is_empty() || self.disable_filtering
    }

    pub fn with_options(
        nets: Vec<IpNet>,
        ids: Vec<String>,
        tags: Vec<String>,
        block: &[String],
        allow: &[String],
        disable_filtering: bool,
        safe_search: Option<bool>,
    ) -> Self {
        let mut b = DomainSet::default();
        for d in block {
            b.add_suffix(d);
        }
        b.finalize();
        let mut a = DomainSet::default();
        for d in allow {
            a.add_suffix(d);
        }
        a.finalize();
        Self {
            nets,
            ids,
            tags,
            block: b,
            allow: a,
            disable_filtering,
            safe_search,
            ignore_querylog: false,
            ignore_stats: false,
        }
    }

    pub fn with_log_flags(mut self, ignore_querylog: bool, ignore_stats: bool) -> Self {
        self.ignore_querylog = ignore_querylog;
        self.ignore_stats = ignore_stats;
        self
    }

    fn enable_hits(&mut self) {
        self.block.enable_hits();
        self.allow.enable_hits();
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    fn matches(&self, client: &ClientInfo) -> bool {
        if self.nets.iter().any(|n| n.contains(&client.source_ip)) {
            return true;
        }
        if let Some(id) = &client.client_id {
            if self.ids.iter().any(|x| x.eq_ignore_ascii_case(id)) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
/// Immutable once built. Replacing lists builds a new engine and swaps it whole, which is why the
/// query path takes no locks.
pub struct BlockEngine {
    parts: EngineParts,

    has_verdict_rules: bool,

    regex_block: RegexMatcher,
    regex_allow: RegexMatcher,
    regex_block_important: RegexMatcher,
    regex_allow_important: RegexMatcher,
    regex_refuse: RegexMatcher,
    regex_nodata: RegexMatcher,
    regex_no_response: RegexMatcher,
    regex_nxdomain: RegexMatcher,

    regex_rewrites: Vec<(String, Regex, RewriteTarget)>,
    regex_typed: Vec<(RecordType, String, Regex)>,
    regex_typed_except: Vec<(Vec<RecordType>, String, Regex)>,
    regex_typed_allow: Vec<(RecordType, String, Regex)>,
    regex_typed_allow_except: Vec<(Vec<RecordType>, String, Regex)>,

    /// `rewrite_exceptions` with their regexes compiled; None for a name.
    rewrite_exceptions: Vec<(Option<Regex>, RewriteException)>,

    /// Precompiled per client rule.
    client_rule_regex: Vec<Option<Regex>>,
    client_rule_index: ClientRuleIndex,

    rpz_client_ip_nets: NetIndex,
    rpz_ip_nets: NetIndex,
    rpz_nsip_nets: NetIndex,

    default_block: BlockResponse,
    clients: Vec<ClientPolicy>,

    track_hits: bool,
}

#[derive(Debug, Default)]
/// Regex bundles; patterns are split across several so no one bundle grows too large.
struct RegexMatcher {
    chunks: Vec<(RegexSet, Vec<(String, Regex)>)>,
    /// Patterns from bundles that exceeded the size limit, checked one by one.
    individual: Vec<(String, Regex)>,
}

impl RegexMatcher {
    fn find(&self, text: &str) -> Option<&str> {
        for (set, members) in &self.chunks {
            if set.is_match(text) {
                if let Some((pattern, _)) = members.iter().find(|(_, re)| re.is_match(text)) {
                    return Some(pattern);
                }
            }
        }
        self.individual
            .iter()
            .find(|(_, re)| re.is_match(text))
            .map(|(pattern, _)| pattern.as_str())
    }
}

/// A failure does not affect the others.
fn compile_isolated(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(re) => Some(re),
        Err(error) => {
            onetdns_core::warn!(event = "filter.regex_rule_skipped", pattern, error = %error, "Excluded one problematic regex rule");
            None
        }
    }
}

fn build_regexes(patterns: &[String]) -> RegexMatcher {
    const SET_CHUNK: usize = 32;
    let mut compiled: Vec<(String, Regex)> = patterns
        .iter()
        .filter_map(|p| compile_isolated(p).map(|re| (p.clone(), re)))
        .collect();

    let mut matcher = RegexMatcher::default();
    while !compiled.is_empty() {
        let rest = compiled.split_off(SET_CHUNK.min(compiled.len()));
        let chunk = std::mem::replace(&mut compiled, rest);
        match RegexSet::new(chunk.iter().map(|(p, _)| p.as_str())) {
            Ok(set) => matcher.chunks.push((set, chunk)),
            Err(error) => {
                onetdns_core::warn!(event = "filter.regex_bundle_split", error = %error, "Combined regex exceeds its size limit; checking this rule bundle rule by rule");
                matcher.individual.extend(chunk);
            }
        }
    }
    matcher
}

impl std::fmt::Debug for EngineParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineParts")
            .field("block", &self.block.len())
            .field("allow", &self.allow.len())
            .field("block_important", &self.block_important.len())
            .field("allow_important", &self.allow_important.len())
            .field("refuse", &self.refuse.len())
            .field("nodata", &self.nodata.len())
            .field("no_response", &self.no_response.len())
            .field("typed_block", &self.typed_block.len())
            .field("regex_block", &self.regex_block.len())
            .field("regex_allow", &self.regex_allow.len())
            .field("rewrites", &self.rewrites.len())
            .field("rewrite_exceptions", &self.rewrite_exceptions.len())
            .field("local_zones", &self.local_zones.len())
            .field("rules_total", &self.report.rules_total)
            .field("rules_skipped", &self.report.rules_skipped)
            .finish()
    }
}

impl BlockEngine {
    /// Freezes the sets and compiles the regexes.
    pub fn new(mut parts: EngineParts, default_block: BlockResponse) -> Self {
        parts.finalize_domain_sets();
        let has_verdict_rules = parts.domain_sets().iter().any(|set| !set.is_empty())
            || !parts.regex_block.is_empty()
            || !parts.regex_allow.is_empty()
            || !parts.regex_block_important.is_empty()
            || !parts.regex_allow_important.is_empty()
            || !parts.regex_refuse.is_empty()
            || !parts.regex_nodata.is_empty()
            || !parts.regex_no_response.is_empty()
            || !parts.regex_nxdomain.is_empty()
            || !parts.regex_rewrites.is_empty()
            || !parts.regex_typed_block.is_empty()
            || !parts.regex_typed_block_except.is_empty()
            || !parts.rewrites.is_empty()
            || !parts.local_zones.is_empty()
            || !parts.client_rules.is_empty()
            || !parts.rpz_client_ip.is_empty();
        let regex_block = build_regexes(&parts.regex_block);
        let regex_allow = build_regexes(&parts.regex_allow);
        let regex_block_important = build_regexes(&parts.regex_block_important);
        let regex_allow_important = build_regexes(&parts.regex_allow_important);
        let regex_refuse = build_regexes(&parts.regex_refuse);
        let regex_nodata = build_regexes(&parts.regex_nodata);
        let regex_no_response = build_regexes(&parts.regex_no_response);
        let regex_nxdomain = build_regexes(&parts.regex_nxdomain);
        let regex_rewrites = parts
            .regex_rewrites
            .iter()
            .filter_map(|(p, t)| compile_isolated(p).map(|re| (p.clone(), re, t.clone())))
            .collect();
        let regex_typed = parts
            .regex_typed_block
            .iter()
            .filter_map(|(t, p)| compile_isolated(p).map(|re| (*t, p.clone(), re)))
            .collect();
        let regex_typed_except = parts
            .regex_typed_block_except
            .iter()
            .filter_map(|(ex, p)| compile_isolated(p).map(|re| (ex.clone(), p.clone(), re)))
            .collect();
        let regex_typed_allow = parts
            .regex_typed_allow
            .iter()
            .filter_map(|(t, p)| compile_isolated(p).map(|re| (*t, p.clone(), re)))
            .collect();
        let regex_typed_allow_except = parts
            .regex_typed_allow_except
            .iter()
            .filter_map(|(ex, p)| compile_isolated(p).map(|re| (ex.clone(), p.clone(), re)))
            .collect();
        let rewrite_exceptions = parts
            .rewrite_exceptions
            .iter()
            .filter_map(|exception| {
                let regex = if exception.regex {
                    Some(compile_isolated(&exception.pattern)?)
                } else {
                    None
                };
                Some((regex, exception.clone()))
            })
            .collect();
        let client_rule_regex = parts
            .client_rules
            .iter()
            .map(|r| r.regex.as_deref().and_then(compile_isolated))
            .collect();
        let client_rule_index = ClientRuleIndex::new(&parts.client_rules);
        let nets = |rules: &[RpzIpRule]| NetIndex::new(rules.iter().map(|rule| &rule.net));
        let rpz_client_ip_nets = nets(&parts.rpz_client_ip);
        let rpz_ip_nets = nets(&parts.rpz_ip);
        let rpz_nsip_nets = nets(&parts.rpz_nsip);
        Self {
            parts,
            has_verdict_rules,
            regex_block,
            regex_allow,
            regex_block_important,
            regex_allow_important,
            regex_refuse,
            regex_nodata,
            regex_no_response,
            regex_nxdomain,
            regex_rewrites,
            regex_typed,
            regex_typed_except,
            regex_typed_allow,
            regex_typed_allow_except,
            rewrite_exceptions,
            client_rule_regex,
            client_rule_index,
            rpz_client_ip_nets,
            rpz_ip_nets,
            rpz_nsip_nets,
            default_block,
            clients: Vec::new(),
            track_hits: false,
        }
    }

    pub fn with_clients(mut self, clients: Vec<ClientPolicy>) -> Self {
        self.has_verdict_rules |= clients
            .iter()
            .any(|client| !client.block.is_empty() || !client.allow.is_empty());
        self.clients = clients;
        self
    }

    pub fn with_hit_tracking(mut self, on: bool) -> Self {
        self.track_hits = on;
        if on {
            for set in self.parts.domain_sets_mut() {
                set.enable_hits();
            }
            for client in &mut self.clients {
                client.enable_hits();
            }
        }
        self
    }

    pub fn hits_enabled(&self) -> bool {
        self.track_hits
    }

    pub fn top_rule_hits(&self, n: usize) -> Vec<(String, u64)> {
        let p = &self.parts;
        let mut out: Vec<(String, u64)> = Vec::new();
        for set in p.domain_sets() {
            for (k, c) in set.hit_entries() {
                if c > 0 {
                    out.push((k.to_string(), c));
                }
            }
        }
        for (zone, c) in p.local_zones.hit_entries() {
            if c > 0 {
                out.push((zone.to_string(), c));
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out.truncate(n);
        out
    }

    pub fn source_stats(&self) -> Vec<SourceStat> {
        let p = &self.parts;
        let mut agg: HashMap<u32, (u64, u64)> = HashMap::new();
        for set in p.domain_sets() {
            for (src, hits) in set.source_entries() {
                let e = agg.entry(src).or_default();
                e.0 += 1;
                e.1 += hits;
            }
        }
        for entry in p.local_zones.zones.values() {
            if matches!(entry.action, LocalZoneAction::Transparent) {
                continue;
            }
            let e = agg.entry(NO_SOURCE).or_default();
            e.0 += 1;
            e.1 += entry.hits.load(Ordering::Relaxed);
        }

        let mut out: Vec<SourceStat> = agg
            .into_iter()
            .map(|(id, (rules, hits))| {
                let source = if id == NO_SOURCE {
                    "inline".to_string()
                } else {
                    p.sources
                        .get(id as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("source#{id}"))
                };
                SourceStat {
                    source,
                    rules,
                    hits,
                }
            })
            .collect();
        out.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.source.cmp(&b.source)));
        out
    }

    pub fn empty(default_block: BlockResponse) -> Self {
        Self::new(EngineParts::default(), default_block)
    }

    pub fn block_count(&self) -> usize {
        self.parts.block.len()
            + self.parts.block_important.len()
            + self.parts.refuse.len()
            + self.parts.nodata.len()
            + self.parts.no_response.len()
            + self.parts.rewrite_refuse.len()
            + self.parts.rewrite_nodata.len()
            + self.parts.rewrite_nxdomain.len()
            + self.parts.regex_block.len()
            + self.parts.regex_block_important.len()
            + self.parts.regex_refuse.len()
            + self.parts.regex_nodata.len()
            + self.parts.regex_no_response.len()
            + self.parts.regex_nxdomain.len()
            + self.parts.regex_typed_block.len()
            + self.parts.regex_typed_block_except.len()
            + self
                .parts
                .typed_block
                .iter()
                .map(|(_, s)| s.len())
                .sum::<usize>()
    }

    pub fn domain_storage_bytes(&self) -> usize {
        self.parts
            .domain_sets()
            .into_iter()
            .map(DomainSet::storage_bytes)
            .sum::<usize>()
            + self
                .clients
                .iter()
                .map(|client| client.block.storage_bytes() + client.allow.storage_bytes())
                .sum::<usize>()
    }

    pub fn allow_count(&self) -> usize {
        let p = &self.parts;
        p.allow.len()
            + p.allow_important.len()
            + p.regex_allow.len()
            + p.regex_allow_important.len()
            + p.typed_allow.iter().map(|(_, s)| s.len()).sum::<usize>()
            + p.typed_allow_except
                .iter()
                .map(|(_, s)| s.len())
                .sum::<usize>()
            + p.regex_typed_allow.len()
            + p.regex_typed_allow_except.len()
    }

    pub fn load_report(&self) -> &FilterLoadReport {
        &self.parts.report
    }

    pub fn has_rpz_ip(&self) -> bool {
        !self.parts.rpz_ip.is_empty()
    }

    pub fn rpz_ip_verdict(&self, ip: std::net::IpAddr) -> Option<&FilterVerdict> {
        self.rpz_ip_nets
            .longest(&ip)
            .map(|(_, at)| &self.parts.rpz_ip[at].verdict)
    }

    /// Without any, the fast path opens.
    pub fn has_client_specific_rules(&self) -> bool {
        !self.parts.client_rules.is_empty()
            || !self.parts.rpz_client_ip.is_empty()
            || self.clients.iter().any(|policy| policy.affects_verdict())
    }

    pub fn has_rpz_ns(&self) -> bool {
        !self.parts.rpz_nsdname.is_empty() || !self.parts.rpz_nsip.is_empty()
    }

    /// The most specific rule wins.
    pub fn rpz_ns_verdict(
        &self,
        ns_names: &[Name],
        ns_ips: &[std::net::IpAddr],
    ) -> Option<FilterVerdict> {
        if !self.has_rpz_ns() {
            return None;
        }
        if let Some((_, at)) = ns_ips
            .iter()
            .filter_map(|ip| self.rpz_nsip_nets.longest(ip))
            .max_by_key(|(prefix, _)| *prefix)
        {
            return Some(self.parts.rpz_nsip[at].verdict.clone());
        }
        ns_names
            .iter()
            .flat_map(|name| {
                self.parts
                    .rpz_nsdname
                    .iter()
                    .filter(move |rule| rule.matches(name))
            })
            .max_by_key(|rule| rule.specificity())
            .map(|rule| rule.verdict.clone())
    }

    pub fn client_safe_search(&self, client: &ClientInfo) -> Option<bool> {
        self.clients
            .iter()
            .find(|p| p.matches(client))
            .and_then(|p| p.safe_search)
    }

    /// Whether to leave this client out of the query log and stats.
    pub fn client_log_stat(&self, client: &ClientInfo) -> (bool, bool) {
        self.clients
            .iter()
            .find(|p| p.matches(client))
            .map(|p| (!p.ignore_querylog, !p.ignore_stats))
            .unwrap_or((true, true))
    }

    /// The wire fast path trusts this and skips the filter; a wrong true bypasses every block.
    pub fn is_trivially_allow(&self) -> bool {
        !self.has_verdict_rules && self.clients.is_empty()
    }
}

impl FilterEngine for BlockEngine {
    fn verdict(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterVerdict {
        self.verdict_counting(name, qtype, client, self.track_hits)
    }

    /// Also tells which stage matched and on what.
    fn explain(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterExplanation {
        let mut buf = [0u8; MAX_NAME];
        let key = match normalize_into(name, &mut buf) {
            Some(k) => k,
            None => {
                return FilterExplanation {
                    verdict: FilterVerdict::Allow,
                    stage: MatchStage::DefaultAllow,
                    matched: None,
                    source: None,
                }
            }
        };

        let (verdict, stage, matched) = self.classify(&key, qtype, client, false);
        let source = matched.and_then(|_| self.source_name(stage, &key));
        FilterExplanation {
            verdict,
            stage,
            matched: matched.map(String::from),
            source,
        }
    }
}

impl BlockEngine {
    /// `verdict` without counting a rule hit, for a check after which the query may still go to
    /// the path that applies the verdict and counts it.
    pub fn verdict_uncounted(
        &self,
        name: &Name,
        qtype: RecordType,
        client: &ClientInfo,
    ) -> FilterVerdict {
        self.verdict_counting(name, qtype, client, false)
    }

    fn verdict_counting(
        &self,
        name: &Name,
        qtype: RecordType,
        client: &ClientInfo,
        count: bool,
    ) -> FilterVerdict {
        if !self.has_verdict_rules {
            return FilterVerdict::Allow;
        }
        let mut buf = [0u8; MAX_NAME];
        let Some(key) = normalize_into(name, &mut buf) else {
            return FilterVerdict::Allow;
        };
        self.classify(&key, qtype, client, count).0
    }

    /// `verdict` with the stage, rule, and list behind it from the same lookup. The rule and list
    /// are filled in only for a verdict other than Allow, so allowed queries still do not allocate.
    pub fn verdict_with_rule(
        &self,
        name: &Name,
        qtype: RecordType,
        client: &ClientInfo,
    ) -> FilterExplanation {
        self.explain_counting(name, qtype, client, self.track_hits)
    }

    /// `verdict_with_rule` without counting the hit, like `verdict_uncounted`.
    pub fn verdict_with_rule_uncounted(
        &self,
        name: &Name,
        qtype: RecordType,
        client: &ClientInfo,
    ) -> FilterExplanation {
        self.explain_counting(name, qtype, client, false)
    }

    fn explain_counting(
        &self,
        name: &Name,
        qtype: RecordType,
        client: &ClientInfo,
        count: bool,
    ) -> FilterExplanation {
        let allow = FilterExplanation {
            verdict: FilterVerdict::Allow,
            stage: MatchStage::DefaultAllow,
            matched: None,
            source: None,
        };
        if !self.has_verdict_rules {
            return allow;
        }
        let mut buf = [0u8; MAX_NAME];
        let Some(key) = normalize_into(name, &mut buf) else {
            return allow;
        };
        let (verdict, stage, matched) = self.classify(&key, qtype, client, count);
        if matches!(verdict, FilterVerdict::Allow) {
            return FilterExplanation { stage, ..allow };
        }
        FilterExplanation {
            verdict,
            stage,
            matched: matched.map(String::from),
            source: matched.and_then(|_| self.source_name(stage, &key)),
        }
    }

    /// The list that held the rule behind the verdict, looked up in the set that stage checks.
    /// Stages without list sources, such as regexes, local zones, and client rules, answer None.
    /// Diagnostic path only.
    fn source_name(&self, stage: MatchStage, key: &str) -> Option<String> {
        let p = &self.parts;
        let (set, rewrite_set) = match stage {
            MatchStage::Block => (&p.block, Some(&p.rewrite_nxdomain)),
            MatchStage::ImportantBlock => (&p.block_important, None),
            MatchStage::Allow => (&p.allow, None),
            MatchStage::ImportantAllow => (&p.allow_important, None),
            MatchStage::NoResponse => (&p.no_response, None),
            MatchStage::Refuse => (&p.refuse, Some(&p.rewrite_refuse)),
            MatchStage::NoData => (&p.nodata, Some(&p.rewrite_nodata)),
            _ => return None,
        };
        let id = set
            .source_of(key)
            .or_else(|| rewrite_set.and_then(|set| set.source_of(key)))?;
        if id == NO_SOURCE {
            return None;
        }
        p.sources.get(id as usize).cloned()
    }
    /// Walks the priority ladder; the core of the engine. The order is client policy, RPZ, client
    /// rules, important allow, no response, important block, refuse, nodata, rewrite, allow, regex,
    /// block, and per-type rules.
    ///
    /// No response comes before every block: if a block won, one rule in another list would make
    /// the server answer a name it was meant to hide, and the block rule's intent is kept without
    /// answering.
    ///
    /// Only the most specific local zone is looked up, and its action is used at the refuse,
    /// rewrite, or block stage that fits. A transparent zone leaves no local zone action.
    ///
    /// This order is what the rules mean; changing it changes what the operator expects.
    fn classify<'a>(
        &'a self,
        key: &'a str,
        qtype: RecordType,
        client: &ClientInfo,
        count: bool,
    ) -> (FilterVerdict, MatchStage, Option<&'a str>) {
        let p = &self.parts;
        // Only the most specific local zone applies to a name, so it is looked up once whichever
        // stage uses it.
        let mut local_zone = None;
        let mut local_zone_looked = false;
        let mut local_zone_of = |key: &'a str| {
            if !local_zone_looked {
                local_zone_looked = true;
                if !p.local_zones.is_empty() {
                    local_zone = p.local_zones.lookup(key);
                }
            }
            local_zone
        };
        let local_zone_hit = |zone: &str| {
            if count {
                p.local_zones.record_hit(zone);
            }
        };

        let cpol = self.clients.iter().find(|pol| pol.matches(client));
        if let Some(pol) = cpol {
            if pol.disable_filtering {
                return (FilterVerdict::Allow, MatchStage::ClientPolicyDisable, None);
            }
            if let Some(m) = self.lookup(&pol.allow, key, count) {
                return (FilterVerdict::Allow, MatchStage::ClientPolicyAllow, Some(m));
            }
            if let Some(m) = self.lookup(&pol.block, key, count) {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::ClientPolicyBlock,
                    Some(m),
                );
            }
        }

        if let Some((_, at)) = self.rpz_client_ip_nets.longest(&client.source_ip) {
            let rule = &p.rpz_client_ip[at];
            return (
                rule.verdict.clone(),
                MatchStage::RpzClientIp,
                Some(&rule.display),
            );
        }

        if !p.client_rules.is_empty() {
            let tags: &[String] = cpol.map(|pol| pol.tags()).unwrap_or(&[]);

            let applies = |i: usize, r: &ClientRule| {
                if r.regex.is_some() {
                    match self.client_rule_regex.get(i).and_then(|o| o.as_ref()) {
                        Some(re) if re.is_match(key) => {}
                        _ => return false,
                    }
                }
                r.applies(key, client, tags)
            };
            // The first allowing rule in list order wins, then the first blocking one.
            let (mut allow, mut block) = (None, None);
            for i in self.client_rule_index.candidates(key) {
                let r = &p.client_rules[i];
                let first = if r.allow { &mut allow } else { &mut block };
                if first.is_none_or(|first| i < first) && applies(i, r) {
                    *first = Some(i);
                }
            }
            if let Some(i) = allow {
                return (
                    FilterVerdict::Allow,
                    MatchStage::ClientRuleAllow,
                    rule_key(&p.client_rules[i]),
                );
            }
            if let Some(i) = block {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::ClientRuleBlock,
                    rule_key(&p.client_rules[i]),
                );
            }
        }

        if let Some(m) = self.lookup(&p.allow_important, key, count) {
            return (FilterVerdict::Allow, MatchStage::ImportantAllow, Some(m));
        }
        if let Some(m) = self.regex_allow_important.find(key) {
            return (FilterVerdict::Allow, MatchStage::ImportantAllow, Some(m));
        }

        if !self.rewrite_lifted(key, |v| *v == RewriteValue::NoResponse) {
            if let Some(m) = self.lookup(&p.no_response, key, count) {
                return (FilterVerdict::Drop, MatchStage::NoResponse, Some(m));
            }
            if let Some(m) = self.regex_no_response.find(key) {
                return (FilterVerdict::Drop, MatchStage::NoResponse, Some(m));
            }
        }

        if let Some(m) = self.lookup(&p.block_important, key, count) {
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::ImportantBlock,
                Some(m),
            );
        }
        if let Some(m) = self.regex_block_important.find(key) {
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::ImportantBlock,
                Some(m),
            );
        }

        if let Some(m) = self.lookup(&p.refuse, key, count) {
            return (
                FilterVerdict::Block(BlockResponse::Refused),
                MatchStage::Refuse,
                Some(m),
            );
        }
        if !self.rewrite_lifted(key, |v| *v == RewriteValue::Refused) {
            if let Some(m) = self.lookup(&p.rewrite_refuse, key, count) {
                return (
                    FilterVerdict::Block(BlockResponse::Refused),
                    MatchStage::Refuse,
                    Some(m),
                );
            }
            if let Some(m) = self.regex_refuse.find(key) {
                return (
                    FilterVerdict::Block(BlockResponse::Refused),
                    MatchStage::Refuse,
                    Some(m),
                );
            }
        }
        if let Some((zone, LocalZoneAction::Refuse)) = local_zone_of(key) {
            local_zone_hit(zone);
            return (
                FilterVerdict::Block(BlockResponse::Refused),
                MatchStage::Refuse,
                Some(zone),
            );
        }

        if let Some(m) = self.lookup(&p.nodata, key, count) {
            return (
                FilterVerdict::Block(BlockResponse::NoData),
                MatchStage::NoData,
                Some(m),
            );
        }
        if !self.rewrite_lifted(key, |v| *v == RewriteValue::NoData) {
            if let Some(m) = self.lookup(&p.rewrite_nodata, key, count) {
                return (
                    FilterVerdict::Block(BlockResponse::NoData),
                    MatchStage::NoData,
                    Some(m),
                );
            }
            if let Some(m) = self.regex_nodata.find(key) {
                return (
                    FilterVerdict::Block(BlockResponse::NoData),
                    MatchStage::NoData,
                    Some(m),
                );
            }
        }

        let answer_lifted = |t: &RewriteTarget| {
            self.rewrite_lifted(key, |v| matches!(v, RewriteValue::Answer(a) if a == t))
        };
        if let Some(t) = p.rewrites.get(key, answer_lifted) {
            return (FilterVerdict::Rewrite(t.clone()), MatchStage::Rewrite, None);
        }
        if let Some((zone, LocalZoneAction::Rewrite(t))) = local_zone_of(key) {
            local_zone_hit(zone);
            return (
                FilterVerdict::Rewrite(t.clone()),
                MatchStage::Rewrite,
                Some(zone),
            );
        }
        if let Some((zone, LocalZoneAction::Static(data))) = local_zone_of(key) {
            local_zone_hit(zone);
            let verdict = match data.answer(key) {
                StaticAnswer::Data(t) => FilterVerdict::Rewrite(t.clone()),
                StaticAnswer::NoData => FilterVerdict::Block(BlockResponse::NoData),
                StaticAnswer::NxDomain => FilterVerdict::Block(BlockResponse::NxDomain),
            };
            return (verdict, MatchStage::Rewrite, Some(zone));
        }
        if let Some((pattern, _, t)) = self
            .regex_rewrites
            .iter()
            .find(|(_, re, t)| re.is_match(key) && !answer_lifted(t))
        {
            return (
                FilterVerdict::Rewrite(t.clone()),
                MatchStage::Rewrite,
                Some(pattern),
            );
        }

        if let Some(m) = self.lookup(&p.allow, key, count) {
            return (FilterVerdict::Allow, MatchStage::Allow, Some(m));
        }
        if let Some(m) = self.regex_allow.find(key) {
            return (FilterVerdict::Allow, MatchStage::RegexAllow, Some(m));
        }
        for (excluded, set) in &p.typed_allow_except {
            if !excluded.contains(&qtype) {
                if let Some(m) = self.lookup(set, key, count) {
                    return (FilterVerdict::Allow, MatchStage::Allow, Some(m));
                }
            }
        }
        for (t, set) in &p.typed_allow {
            if *t == qtype {
                if let Some(m) = self.lookup(set, key, count) {
                    return (FilterVerdict::Allow, MatchStage::Allow, Some(m));
                }
            }
        }
        for (excluded, pattern, re) in &self.regex_typed_allow_except {
            if !excluded.contains(&qtype) && re.is_match(key) {
                return (FilterVerdict::Allow, MatchStage::RegexAllow, Some(pattern));
            }
        }
        for (t, pattern, re) in &self.regex_typed_allow {
            if *t == qtype && re.is_match(key) {
                return (FilterVerdict::Allow, MatchStage::RegexAllow, Some(pattern));
            }
        }

        let nxdomain_lifted = self.rewrite_lifted(key, |v| *v == RewriteValue::NxDomain);
        if let Some(m) = self.lookup(&p.block, key, count) {
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::Block,
                Some(m),
            );
        }
        if !nxdomain_lifted {
            if let Some(m) = self.lookup(&p.rewrite_nxdomain, key, count) {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::Block,
                    Some(m),
                );
            }
        }
        if let Some((zone, LocalZoneAction::Deny)) = local_zone_of(key) {
            local_zone_hit(zone);
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::Block,
                Some(zone),
            );
        }
        if let Some(m) = self.regex_block.find(key) {
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::RegexBlock,
                Some(m),
            );
        }
        if !nxdomain_lifted {
            if let Some(m) = self.regex_nxdomain.find(key) {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::RegexBlock,
                    Some(m),
                );
            }
        }
        for (excluded, set) in &p.typed_block_except {
            if !excluded.contains(&qtype) {
                if let Some(m) = self.lookup(set, key, count) {
                    return (
                        FilterVerdict::Block(self.default_block),
                        MatchStage::TypedBlock,
                        Some(m),
                    );
                }
            }
        }
        for (t, set) in &p.typed_block {
            if *t == qtype {
                if let Some(m) = self.lookup(set, key, count) {
                    return (
                        FilterVerdict::Block(self.default_block),
                        MatchStage::TypedBlock,
                        Some(m),
                    );
                }
            }
        }
        for (excluded, pattern, re) in &self.regex_typed_except {
            if !excluded.contains(&qtype) && re.is_match(key) {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::TypedBlock,
                    Some(pattern),
                );
            }
        }
        for (t, pattern, re) in &self.regex_typed {
            if *t == qtype && re.is_match(key) {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::TypedBlock,
                    Some(pattern),
                );
            }
        }
        (FilterVerdict::Allow, MatchStage::DefaultAllow, None)
    }

    /// Whether an `@@` rule with `$dnsrewrite` covering `key` lifts the `$dnsrewrite` rules whose
    /// value passes `is_value`.
    fn rewrite_lifted(&self, key: &str, is_value: impl Fn(&RewriteValue) -> bool) -> bool {
        self.rewrite_exceptions.iter().any(|(regex, exception)| {
            exception.value.as_ref().is_none_or(&is_value)
                && match regex {
                    Some(re) => re.is_match(key),
                    None => covers(&exception.pattern, key),
                }
        })
    }

    #[inline]
    /// Counts the hit when `count` is set.
    fn lookup<'a>(&'a self, set: &'a DomainSet, key: &'a str, count: bool) -> Option<&'a str> {
        if count {
            set.hit(key)
        } else {
            set.matched(key)
        }
    }
}

/// Whether the normalized `name` is `key` or a parent of it.
fn covers(name: &str, key: &str) -> bool {
    key.strip_suffix(name)
        .is_some_and(|head| head.is_empty() || head.ends_with('.'))
}

fn rule_key(r: &ClientRule) -> Option<&str> {
    if !r.domain.is_empty() {
        Some(&r.domain)
    } else {
        r.regex.as_deref()
    }
}

/// Atomically swapped engine handle that holds the fast-path gate with it.
pub struct SharedFilter {
    swap: ArcSwap<BlockEngine>,
    /// Kept apart so it can be read without loading the engine.
    wire_blocked: AtomicBool,
}

impl SharedFilter {
    pub fn from_pointee(engine: BlockEngine) -> Self {
        let wire_blocked = Self::blocks_wire(&engine);
        Self {
            swap: ArcSwap::from_pointee(engine),
            wire_blocked: AtomicBool::new(wire_blocked),
        }
    }

    pub fn new(engine: Arc<BlockEngine>) -> Self {
        let wire_blocked = Self::blocks_wire(&engine);
        Self {
            swap: ArcSwap::new(engine),
            wire_blocked: AtomicBool::new(wire_blocked),
        }
    }

    /// Whether this engine closes the wire fast path.
    fn blocks_wire(engine: &BlockEngine) -> bool {
        !engine.is_trivially_allow() || engine.has_rpz_ns() || engine.has_rpz_ip()
    }

    pub fn load(&self) -> Arc<BlockEngine> {
        self.swap.load()
    }

    /// Updates the fast-path gate in the same step; updated apart, there would be a window where
    /// the new engine blocks while the gate is still open.
    pub fn store(&self, engine: Arc<BlockEngine>) {
        let wire_blocked = Self::blocks_wire(&engine);
        if wire_blocked {
            self.wire_blocked.store(true, Ordering::Release);
        }
        self.swap.store(engine);
        if !wire_blocked {
            self.wire_blocked.store(false, Ordering::Release);
        }
    }

    pub fn wire_blocked(&self) -> bool {
        self.wire_blocked.load(Ordering::Acquire)
    }
}

const MAX_NAME: usize = 256;

/// Into a stack buffer, so queries do not allocate; only names that do not fit allocate.
fn normalize_into<'a>(name: &Name, buf: &'a mut [u8; MAX_NAME]) -> Option<Cow<'a, str>> {
    let mut len = 0usize;
    for label in name.labels() {
        if len != 0 {
            if len >= buf.len() {
                return None;
            }
            buf[len] = b'.';
            len += 1;
        }
        for &b in label {
            if len >= buf.len() {
                return None;
            }
            buf[len] = b.to_ascii_lowercase();
            len += 1;
        }
    }
    Some(String::from_utf8_lossy(&buf[..len]))
}

pub fn normalize_name(name: &Name) -> String {
    name.to_ascii_lower()
}

/// Lowercases and drops the trailing dot.
pub fn normalize_str(domain: &str) -> String {
    let mut s = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.starts_with("*.") {
        s = s[2..].to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_core::Transport;

    fn client() -> ClientInfo {
        ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    /// If transparent also opened blocklists, the operator's subscribed lists would be silently
    /// disabled.
    fn most_specific_local_zone_wins_and_transparent_only_lifts_local_zones() {
        let a =
            |ip: &str| RewriteTarget::Records(vec![onetdns_proto::RData::A(ip.parse().unwrap())]);
        let mut parts = EngineParts::default();
        parts.block.add_suffix("listed.corp.example");
        parts.allow.add_suffix("allowed.corp.example");
        for (zone, action) in [
            ("corp.example", LocalZoneAction::Deny),
            ("api.corp.example", LocalZoneAction::Transparent),
            ("listed.corp.example", LocalZoneAction::Transparent),
            (
                "static.corp.example",
                LocalZoneAction::Rewrite(a("192.0.2.1")),
            ),
            ("deny.static.corp.example", LocalZoneAction::Deny),
            ("lan", LocalZoneAction::Refuse),
            ("open.lan", LocalZoneAction::Transparent),
            (".", LocalZoneAction::Transparent),
        ] {
            parts.local_zones.insert(zone, action).unwrap();
        }
        assert!(parts
            .local_zones
            .insert("CORP.example.", LocalZoneAction::Refuse)
            .is_err());
        let engine = BlockEngine::new(parts, BlockResponse::NxDomain).with_hit_tracking(true);
        let verdict = |q: &str| engine.verdict(&name(q), RecordType::A, &client());

        assert!(matches!(
            verdict("www.corp.example"),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(verdict("corp.example"), FilterVerdict::Block(_)));
        assert!(matches!(verdict("api.corp.example"), FilterVerdict::Allow));
        assert!(matches!(
            verdict("v1.api.corp.example"),
            FilterVerdict::Allow
        ));
        assert!(
            matches!(verdict("x.listed.corp.example"), FilterVerdict::Block(_)),
            "transparent가 차단 목록 규칙을 풀면 안 된다"
        );
        assert!(
            matches!(verdict("allowed.corp.example"), FilterVerdict::Allow),
            "일반 허용 규칙은 로컬 deny 영역을 이긴다"
        );
        assert!(matches!(
            verdict("host.static.corp.example"),
            FilterVerdict::Rewrite(_)
        ));
        assert!(matches!(
            verdict("x.deny.static.corp.example"),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            verdict("printer.lan"),
            FilterVerdict::Block(BlockResponse::Refused)
        ));
        assert!(matches!(verdict("nas.open.lan"), FilterVerdict::Allow));
        assert!(matches!(verdict("elsewhere.example"), FilterVerdict::Allow));

        let hits = engine.top_rule_hits(20);
        assert!(hits
            .iter()
            .any(|(rule, count)| rule == "corp.example" && *count == 2));
    }

    #[test]
    /// With NXDOMAIN for an intermediate name, some resolvers would cache everything below as
    /// nonexistent and the listed names would vanish. Taking a name outside the zone would hijack
    /// another zone's answers.
    fn static_local_zone_answers_only_listed_names() {
        let a =
            |ip: &str| RewriteTarget::Records(vec![onetdns_proto::RData::A(ip.parse().unwrap())]);
        let mut data = StaticZone::new("corp.example.");
        data.insert("www.corp.example", a("192.0.2.2")).unwrap();
        data.insert("host.dept.corp.example", a("192.0.2.3"))
            .unwrap();
        assert!(data.insert("www.corp.example", a("192.0.2.9")).is_err());
        assert!(data.insert("xcorp.example", a("192.0.2.9")).is_err());
        let mut parts = EngineParts::default();
        parts
            .local_zones
            .insert("corp.example", LocalZoneAction::Static(data))
            .unwrap();
        parts
            .local_zones
            .insert("deny.corp.example", LocalZoneAction::Deny)
            .unwrap();
        let engine = BlockEngine::new(parts, BlockResponse::ZeroIp);
        let verdict = |q: &str| engine.verdict(&name(q), RecordType::A, &client());

        assert!(matches!(
            verdict("www.corp.example"),
            FilterVerdict::Rewrite(RewriteTarget::Records(_))
        ));
        assert!(matches!(
            verdict("host.dept.corp.example"),
            FilterVerdict::Rewrite(_)
        ));
        for existing in ["corp.example", "dept.corp.example"] {
            assert!(
                matches!(
                    verdict(existing),
                    FilterVerdict::Block(BlockResponse::NoData)
                ),
                "{existing}"
            );
        }
        for missing in ["other.corp.example", "a.www.corp.example"] {
            assert!(
                matches!(
                    verdict(missing),
                    FilterVerdict::Block(BlockResponse::NxDomain)
                ),
                "{missing}"
            );
        }
        assert!(
            matches!(
                verdict("x.deny.corp.example"),
                FilterVerdict::Block(BlockResponse::ZeroIp)
            ),
            "더 구체적인 영역이 static 영역을 이긴다"
        );
        assert!(matches!(verdict("corp.example.net"), FilterVerdict::Allow));
    }

    #[test]
    /// If wrong, the wire fast path skips the filter.
    fn is_trivially_allow_is_sound_and_conservative() {
        use crate::build_from_str;

        let empty = build_from_str("", "", BlockResponse::NxDomain);
        assert!(empty.is_trivially_allow());
        assert!(matches!(
            empty.verdict(&name("anything.test"), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
        assert_eq!(empty.client_safe_search(&client()), None);

        assert!(
            !build_from_str("||blocked.test^", "", BlockResponse::NxDomain).is_trivially_allow()
        );

        let net = "10.0.0.0/8".parse().unwrap();
        let with_block = build_from_str("", "", BlockResponse::NxDomain).with_clients(vec![
            ClientPolicy::with_options(
                vec![net],
                vec![],
                vec![],
                &["ads.test".to_string()],
                &[],
                false,
                None,
            ),
        ]);
        assert!(!with_block.is_trivially_allow());

        let net = "10.0.0.0/8".parse().unwrap();
        let ss = build_from_str("", "", BlockResponse::NxDomain).with_clients(vec![
            ClientPolicy::with_options(vec![net], vec![], vec![], &[], &[], false, Some(true)),
        ]);
        assert!(
            !ss.is_trivially_allow(),
            "safe_search 클라가 있으면 자명-허용 금지(safe_search 우회 방지)"
        );
        let ss_client = ClientInfo {
            source_ip: "10.0.0.5".parse().unwrap(),
            ..client()
        };
        assert_eq!(
            ss.client_safe_search(&ss_client),
            Some(true),
            "그 클라는 실제로 safe_search 대상"
        );
    }

    #[test]
    fn shared_filter_gate_tracks_hot_replacement() {
        use crate::build_from_str;

        let shared = SharedFilter::from_pointee(build_from_str("", "", BlockResponse::NxDomain));
        assert!(!shared.wire_blocked());

        shared.store(Arc::new(build_from_str(
            "||blocked.test^",
            "",
            BlockResponse::NxDomain,
        )));
        assert!(shared.wire_blocked());

        shared.store(Arc::new(build_from_str("", "", BlockResponse::NxDomain)));
        assert!(!shared.wire_blocked());
    }

    #[test]
    fn compact_finalize_preserves_all_matches_and_releases_hashmaps() {
        let mut set = DomainSet::default();
        set.add_suffix("blocked.example");
        assert!(set.matches("deep.blocked.example"));

        for count in [0usize, 1, 10, 256, 257, 5000] {
            let mut set = DomainSet::default();
            let domains: Vec<String> = (0..count)
                .map(|i| format!("d{i}.blocked.example"))
                .collect();
            for d in &domains {
                set.add_suffix(d);
            }
            set.finalize();

            assert!(set.suffixes.is_empty());
            assert_eq!(set.suffix_compact.len(), count);

            for d in &domains {
                assert!(set.matches(d), "정확 매칭 실패 count={count} d={d}");
                assert!(
                    set.matches(&format!("sub.{d}")),
                    "접미사 매칭 실패 count={count} d={d}"
                );
            }
            assert!(!set.matches("totally.unrelated.test"));
        }
    }

    #[test]
    fn compact_binary_roundtrip_preserves_exact_suffix_and_sources() {
        let mut set = DomainSet::default();
        set.add_exact_src("only.example", 7);
        set.add_exact_src("another.example", 8);
        set.add_suffix_src("blocked.example", 9);
        set.add_suffix_src("deep.blocked.example", 10);
        set.finalize();

        let mut bytes = Vec::new();
        set.encode_compact(&mut bytes).unwrap();
        let mut input = bytes.as_slice();
        let restored = DomainSet::decode_compact(&mut input).unwrap();

        assert!(input.is_empty());
        assert_eq!(restored.len(), set.len());
        assert_eq!(restored.source_of("only.example"), Some(7));
        assert_eq!(restored.source_of("another.example"), Some(8));
        assert_eq!(restored.source_of("x.blocked.example"), Some(9));
        assert_eq!(restored.source_of("x.deep.blocked.example"), Some(10));
        assert_eq!(restored.source_of("unrelated.test"), None);
    }

    #[test]
    fn compact_binary_rejects_unfinalized_set() {
        let mut set = DomainSet::default();
        set.add_suffix("blocked.example");
        assert!(set.encode_compact(&mut Vec::new()).is_err());
    }

    #[test]
    fn mutation_after_finalize_thaws_without_losing_rules() {
        let mut set = DomainSet::default();
        set.add_exact_src("only.example", 7);
        set.add_suffix_src("blocked.example", 8);
        set.finalize();

        set.add_suffix_src("new.example", 9);
        assert_eq!(set.source_of("only.example"), Some(7));
        assert_eq!(set.source_of("x.blocked.example"), Some(8));
        assert_eq!(set.source_of("x.new.example"), Some(9));

        set.remove_suffix("blocked.example");
        assert!(!set.matches("x.blocked.example"));
        assert!(set.matches("x.new.example"));
    }

    #[test]
    /// Accepting one would match every name, and the two paths would disagree.
    fn empty_suffix_rule_is_rejected_so_both_paths_agree() {
        for rule in [".", "", ".."] {
            let mut set = DomainSet::default();
            set.add_suffix(rule);
            set.add_suffix("blocked.example");
            assert_eq!(set.len(), 1, "rule={rule:?}");
            for finalized in [false, true] {
                if finalized {
                    set.finalize();
                }
                assert!(!set.matches(""), "rule={rule:?} finalized={finalized}");
                assert!(
                    !set.matches("example.com"),
                    "rule={rule:?} finalized={finalized}"
                );
                assert!(
                    set.matches("sub.blocked.example"),
                    "rule={rule:?} finalized={finalized}"
                );
            }
        }

        let mut set = DomainSet::default();
        set.add_suffix("*.");
        set.add_suffix("blocked.example");
        assert_eq!(set.len(), 2);
        for finalized in [false, true] {
            if finalized {
                set.finalize();
            }
            assert!(!set.matches(""), "finalized={finalized}");
            assert!(!set.matches("example.com"), "finalized={finalized}");
            assert!(set.matches("sub.blocked.example"), "finalized={finalized}");
        }

        let mut parts = EngineParts::default();
        parts.block.add_suffix(".");
        parts.block.add_suffix("blocked.example");
        let eng = BlockEngine::new(parts, BlockResponse::NxDomain);
        assert!(matches!(
            eng.verdict(&Name::root(), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            eng.verdict(&name("example.com"), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            eng.verdict(&name("sub.blocked.example"), RecordType::A, &client()),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    fn hit_tracking_off_stores_no_counter_maps() {
        let mut set = DomainSet::default();
        set.add_suffix("blocked.example");
        set.finalize();
        assert!(set.exact_hits.is_none());
        assert!(set.suffix_hits.is_none());

        assert_eq!(set.hit("x.blocked.example"), Some("blocked.example"));
    }

    fn client_ip(ip: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    fn engine_with(parts: EngineParts) -> BlockEngine {
        BlockEngine::new(parts, BlockResponse::NxDomain)
    }

    #[test]
    fn rpz_client_ip_triggers_verdict() {
        let mut parts = EngineParts::default();
        parts.rpz_client_ip.push(RpzIpRule::new(
            "10.0.0.0/8".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::NxDomain),
        ));
        let eng = engine_with(parts);

        let e = eng.explain(
            &name("anything.test."),
            RecordType::A,
            &client_ip("10.1.2.3"),
        );
        assert_eq!(e.stage, MatchStage::RpzClientIp);
        assert!(matches!(e.verdict, FilterVerdict::Block(_)));
        assert_eq!(e.matched.as_deref(), Some("10.0.0.0/8"));

        let e2 = eng.explain(
            &name("anything.test."),
            RecordType::A,
            &client_ip("192.168.1.1"),
        );
        assert_eq!(e2.stage, MatchStage::DefaultAllow);
    }

    #[test]
    fn client_rules_keep_list_order_across_domains() {
        let rule = |domain: &str, allow: bool, net: &str| ClientRule {
            domain: domain.into(),
            allow,
            clients: vec![ClientCond::Net {
                negated: false,
                net: net.parse().unwrap(),
            }],
            ..ClientRule::default()
        };
        let mut parts = EngineParts::default();
        parts.client_rules = vec![
            rule("ads.example", false, "10.0.0.0/8"),
            rule("example", false, "10.0.0.0/8"),
            rule("example", true, "10.9.0.0/16"),
            rule("", false, "10.7.0.0/16"),
            rule("cdn.ads.example", true, "10.0.0.0/8"),
        ];
        let eng = engine_with(parts);
        let explain = |qname: &str, ip: &str| {
            let e = eng.explain(&name(qname), RecordType::A, &client_ip(ip));
            (e.stage, e.matched)
        };
        assert_eq!(
            explain("x.ads.example.", "10.1.1.1"),
            (MatchStage::ClientRuleBlock, Some("ads.example".into()))
        );
        assert_eq!(
            explain("www.example.", "10.1.1.1"),
            (MatchStage::ClientRuleBlock, Some("example".into()))
        );
        assert_eq!(
            explain("x.ads.example.", "10.9.1.1"),
            (MatchStage::ClientRuleAllow, Some("example".into()))
        );
        assert_eq!(
            explain("cdn.ads.example.", "10.1.1.1"),
            (MatchStage::ClientRuleAllow, Some("cdn.ads.example".into()))
        );
        assert_eq!(
            explain("other.test.", "10.7.1.1").0,
            MatchStage::ClientRuleBlock
        );
        assert_eq!(
            explain("other.test.", "10.1.1.1").0,
            MatchStage::DefaultAllow
        );
        assert_eq!(
            explain("notexample.", "10.1.1.1").0,
            MatchStage::DefaultAllow
        );
    }

    #[test]
    fn rpz_ip_verdict_matches_answer_ip() {
        let mut parts = EngineParts::default();
        parts.rpz_ip.push(RpzIpRule::new(
            "203.0.113.0/24".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::NxDomain),
        ));
        let eng = engine_with(parts);
        assert!(eng.has_rpz_ip());
        assert!(eng.rpz_ip_verdict("203.0.113.5".parse().unwrap()).is_some());
        assert!(eng.rpz_ip_verdict("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn rpz_ns_verdict_matches_name_and_ip() {
        let mut parts = EngineParts::default();
        parts.rpz_nsdname.push(
            RpzNameRule::new(
                "evil-ns.example",
                FilterVerdict::Block(BlockResponse::NxDomain),
            )
            .unwrap(),
        );
        parts.rpz_nsip.push(RpzIpRule::new(
            "192.0.2.0/24".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::NxDomain),
        ));
        let eng = engine_with(parts);
        assert!(eng.has_rpz_ns());

        let ns = vec![name("a.evil-ns.example.")];
        assert!(eng.rpz_ns_verdict(&ns, &[]).is_some());

        assert!(eng
            .rpz_ns_verdict(&[], &["192.0.2.50".parse().unwrap()])
            .is_some());

        assert!(eng
            .rpz_ns_verdict(&[name("good.example.")], &["8.8.8.8".parse().unwrap()])
            .is_none());
    }

    #[test]
    fn rpz_nsdname_preserves_raw_name_octets() {
        let mut parts = EngineParts::default();
        parts
            .rpz_nsdname
            .push(RpzNameRule::new("�", FilterVerdict::Block(BlockResponse::NxDomain)).unwrap());
        let eng = engine_with(parts);
        let configured = Name::from_str("�").unwrap();
        let raw = Name::from_labels(vec![vec![0xff]]).unwrap();

        assert!(eng.rpz_ns_verdict(&[configured], &[]).is_some());
        assert!(eng.rpz_ns_verdict(&[raw], &[]).is_none());
    }

    #[test]
    fn rpz_ns_verdict_uses_global_most_specific_rule() {
        let mut parts = EngineParts::default();
        parts.rpz_nsip.push(RpzIpRule::new(
            "192.0.0.0/8".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::NxDomain),
        ));
        parts.rpz_nsip.push(RpzIpRule::new(
            "192.0.2.0/24".parse().unwrap(),
            FilterVerdict::Block(BlockResponse::Refused),
        ));
        parts.rpz_nsdname.push(
            RpzNameRule::new("example", FilterVerdict::Block(BlockResponse::NxDomain)).unwrap(),
        );
        parts.rpz_nsdname.push(
            RpzNameRule::new("evil.example", FilterVerdict::Block(BlockResponse::Refused)).unwrap(),
        );
        let eng = engine_with(parts);

        assert!(matches!(
            eng.rpz_ns_verdict(
                &[],
                &["192.1.1.1".parse().unwrap(), "192.0.2.9".parse().unwrap()]
            ),
            Some(FilterVerdict::Block(BlockResponse::Refused))
        ));
        assert!(matches!(
            eng.rpz_ns_verdict(&[name("ns.example."), name("a.evil.example.")], &[]),
            Some(FilterVerdict::Block(BlockResponse::Refused))
        ));
    }

    #[test]
    fn per_rule_hit_counting() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("ads.example.com");
        parts.block.add_suffix("tracker.net");
        let eng = engine_with(parts).with_hit_tracking(true);
        assert!(eng.hits_enabled());

        for _ in 0..3 {
            eng.verdict(&name("x.ads.example.com."), RecordType::A, &client());
        }
        eng.verdict(&name("tracker.net."), RecordType::A, &client());

        eng.verdict(&name("clean.test."), RecordType::A, &client());
        assert_eq!(
            eng.top_rule_hits(10),
            vec![
                ("ads.example.com".to_string(), 3),
                ("tracker.net".to_string(), 1)
            ]
        );

        eng.explain(&name("x.ads.example.com."), RecordType::A, &client());
        eng.verdict_uncounted(&name("x.ads.example.com."), RecordType::A, &client());
        assert_eq!(eng.top_rule_hits(10)[0], ("ads.example.com".to_string(), 3));

        eng.verdict_with_rule(&name("x.ads.example.com."), RecordType::A, &client());
        assert_eq!(eng.top_rule_hits(10)[0], ("ads.example.com".to_string(), 4));
    }

    #[test]
    /// Turning it on costs memory and time.
    fn hit_tracking_off_by_default() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("ads.example.com");
        let eng = engine_with(parts);
        assert!(!eng.hits_enabled());
        eng.verdict(&name("ads.example.com."), RecordType::A, &client());
        assert!(eng.top_rule_hits(10).is_empty(), "추적 꺼지면 카운트 0");
    }

    #[test]
    fn exact_block() {
        let mut parts = EngineParts::default();
        parts.block.add_exact("ads.example.com");
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("ads.example.com."), RecordType::A, &client()),
            FilterVerdict::Block(_)
        ));

        assert!(matches!(
            eng.verdict(&name("x.ads.example.com."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn suffix_blocks_subdomains() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("tracker.net");
        let eng = engine_with(parts);
        for q in ["tracker.net.", "a.tracker.net.", "a.b.tracker.net."] {
            assert!(
                matches!(
                    eng.verdict(&name(q), RecordType::A, &client()),
                    FilterVerdict::Block(_)
                ),
                "{q} should be blocked"
            );
        }
        assert!(matches!(
            eng.verdict(&name("nottracker.net."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn explain_reports_stage_and_matched() {
        let mut parts = EngineParts::default();
        parts.block_important.add_suffix("ads.example.com");
        parts.refuse.add_exact("refused.test");
        parts.nodata.add_suffix("nd.test");
        parts.allow.add_exact("ok.test");
        let eng = engine_with(parts);

        let imp = eng.explain(&name("x.ads.example.com."), RecordType::A, &client());
        assert_eq!(imp.stage, MatchStage::ImportantBlock);
        assert_eq!(imp.matched.as_deref(), Some("ads.example.com"));
        assert!(matches!(imp.verdict, FilterVerdict::Block(_)));

        let r = eng.explain(&name("refused.test."), RecordType::A, &client());
        assert_eq!(r.stage, MatchStage::Refuse);
        assert!(matches!(
            r.verdict,
            FilterVerdict::Block(BlockResponse::Refused)
        ));

        let nd = eng.explain(&name("a.nd.test."), RecordType::A, &client());
        assert_eq!(nd.stage, MatchStage::NoData);
        assert_eq!(nd.matched.as_deref(), Some("nd.test"));
        assert!(matches!(
            nd.verdict,
            FilterVerdict::Block(BlockResponse::NoData)
        ));

        let ok = eng.explain(&name("ok.test."), RecordType::A, &client());
        assert_eq!(ok.stage, MatchStage::Allow);
        assert_eq!(ok.matched.as_deref(), Some("ok.test"));

        let def = eng.explain(&name("unknown.test."), RecordType::A, &client());
        assert_eq!(def.stage, MatchStage::DefaultAllow);
        assert!(def.matched.is_none());
        assert!(matches!(def.verdict, FilterVerdict::Allow));
    }

    #[test]
    /// Building the engine freezes lists into automata, so sources must survive freezing. Rules
    /// entered by hand are not a list and have no source.
    fn explain_reports_source_list_after_freezing() {
        let lines = vec![
            "||listed.example^".to_string(),
            "@@||ok.listed.example^".to_string(),
            "||hidden.example^$dnsrewrite=NORESPONSE".to_string(),
        ];
        let parts = crate::loader::load_parts_with_subscriptions(
            &[] as &[std::path::PathBuf],
            &[] as &[std::path::PathBuf],
            &[crate::loader::SubscriptionSource {
                name: "https://lists.example/malware.txt",
                rules: crate::loader::SubscriptionRules::Lines(&lines),
            }],
            &["||typed.example^"],
            &[],
        )
        .unwrap();
        let eng = engine_with(parts);

        let listed = eng.explain(&name("a.listed.example."), RecordType::A, &client());
        assert_eq!(listed.stage, MatchStage::Block);
        assert_eq!(
            listed.source.as_deref(),
            Some("https://lists.example/malware.txt")
        );

        let allowed = eng.explain(&name("ok.listed.example."), RecordType::A, &client());
        assert_eq!(allowed.stage, MatchStage::Allow);
        assert_eq!(
            allowed.source.as_deref(),
            Some("https://lists.example/malware.txt")
        );

        let hidden = eng.explain(&name("a.hidden.example."), RecordType::A, &client());
        assert_eq!(hidden.stage, MatchStage::NoResponse);
        assert_eq!(
            hidden.source.as_deref(),
            Some("https://lists.example/malware.txt")
        );

        let typed = eng.explain(&name("typed.example."), RecordType::A, &client());
        assert_eq!(typed.stage, MatchStage::Block);
        assert!(typed.source.is_none());

        let unmatched = eng.explain(&name("other.example."), RecordType::A, &client());
        assert!(unmatched.source.is_none());
    }

    #[test]
    /// If they disagree, the explanation is false.
    fn explain_verdict_agrees_with_verdict() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("block.test");
        parts.allow.add_exact("allow.test");
        parts.refuse.add_exact("refuse.test");
        parts.nodata.add_suffix("nodata.test");
        parts.no_response.add_suffix("quiet.test");
        let eng = engine_with(parts);
        for q in [
            "block.test.",
            "a.block.test.",
            "allow.test.",
            "refuse.test.",
            "x.nodata.test.",
            "x.quiet.test.",
            "free.test.",
        ] {
            let v = eng.verdict(&name(q), RecordType::A, &client());
            let e = eng.explain(&name(q), RecordType::A, &client());
            assert_eq!(
                std::mem::discriminant(&v),
                std::mem::discriminant(&e.verdict),
                "{q}: verdict/explain 일치하지 않습니다"
            );
            // The query path logs this instead of asking explain a second time.
            let r = eng.verdict_with_rule(&name(q), RecordType::A, &client());
            assert_eq!(
                std::mem::discriminant(&v),
                std::mem::discriminant(&r.verdict),
                "{q}"
            );
            if !matches!(v, FilterVerdict::Allow) {
                assert_eq!(
                    (r.stage, &r.matched, &r.source),
                    (e.stage, &e.matched, &e.source),
                    "{q}"
                );
            }
        }
    }

    #[test]
    /// If a block won, one block or refuse rule in another list would make the server answer a name
    /// it was meant to hide. A plain allow does not lift no response; only an important allow does.
    fn noresponse_sits_between_important_allow_and_important_block() {
        let mut parts = EngineParts::default();
        parts.no_response.add_suffix("quiet.test");
        parts.block_important.add_suffix("quiet.test");
        parts.refuse.add_suffix("quiet.test");
        parts.allow.add_exact("ok.quiet.test");
        parts.allow_important.add_exact("vip.quiet.test");
        parts.regex_no_response.push("^scan[0-9]+\\.test$".into());
        parts.regex_block_important.push("[0-9]+\\.test$".into());
        parts.block_important.add_exact("loud.test");
        parts.refuse.add_exact("refused.test");
        let eng = engine_with(parts);
        let ask = |q: &str| eng.explain(&name(q), RecordType::A, &client());

        let quiet = ask("a.quiet.test.");
        assert!(
            matches!(quiet.verdict, FilterVerdict::Drop),
            "같은 이름의 중요 차단이나 거부 규칙이 무응답을 이겼습니다: {quiet:?}"
        );
        assert_eq!(quiet.stage, MatchStage::NoResponse);
        assert_eq!(quiet.matched.as_deref(), Some("quiet.test"));
        assert!(
            matches!(ask("ok.quiet.test.").verdict, FilterVerdict::Drop),
            "일반 허용이 무응답을 풀었습니다"
        );
        assert_eq!(ask("vip.quiet.test.").stage, MatchStage::ImportantAllow);

        let scan = ask("scan7.test.");
        assert!(
            matches!(scan.verdict, FilterVerdict::Drop),
            "같은 이름의 정규식 중요 차단이 무응답을 이겼습니다: {scan:?}"
        );
        assert_eq!(scan.stage, MatchStage::NoResponse);
        assert_eq!(scan.matched.as_deref(), Some("^scan[0-9]+\\.test$"));

        for loud in ["loud.test.", "loud7.test."] {
            assert_eq!(
                ask(loud).stage,
                MatchStage::ImportantBlock,
                "대조군이 무효입니다: 무응답 규칙이 없는 {loud} 에 중요 차단이 걸리지 않았습니다"
            );
        }
        assert!(
            matches!(
                ask("refused.test.").verdict,
                FilterVerdict::Block(BlockResponse::Refused)
            ),
            "대조군이 무효입니다: 무응답 규칙이 없는 이름의 거부 규칙이 동작하지 않습니다"
        );
    }

    #[test]
    fn allow_wins() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("example.com");
        parts.allow.add_exact("good.example.com");
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("good.example.com."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
        assert!(matches!(
            eng.verdict(&name("bad.example.com."), RecordType::A, &client()),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    fn important_block_beats_allow() {
        let mut parts = EngineParts::default();
        parts.allow.add_suffix("example.com");
        parts.block_important.add_suffix("ads.example.com");
        let eng = engine_with(parts);

        assert!(matches!(
            eng.verdict(&name("ads.example.com."), RecordType::A, &client()),
            FilterVerdict::Block(_)
        ));
    }

    #[test]
    /// The top of the ladder.
    fn important_allow_beats_important_block() {
        let mut parts = EngineParts::default();
        parts.block_important.add_suffix("example.com");
        parts.allow_important.add_exact("vip.example.com");
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("vip.example.com."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn dnstype_block_only_matching_type() {
        let mut parts = EngineParts::default();
        let mut set = DomainSet::default();
        set.add_suffix("noaaaa.example.com");
        parts.typed_block.push((RecordType::AAAA, set));
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("noaaaa.example.com."), RecordType::AAAA, &client()),
            FilterVerdict::Block(_)
        ));

        assert!(matches!(
            eng.verdict(&name("noaaaa.example.com."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn regex_block_matches() {
        let mut parts = EngineParts::default();
        parts.regex_block.push(r"^ads?\d*\.".to_string());
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("ad3.example.com."), RecordType::A, &client()),
            FilterVerdict::Block(_)
        ));
        assert!(matches!(
            eng.verdict(&name("safe.example.com."), RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn non_utf8_label_does_not_bypass_suffix_block() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("blocked.example");
        let eng = engine_with(parts);

        let evil =
            Name::from_labels(vec![vec![0xff], b"blocked".to_vec(), b"example".to_vec()]).unwrap();
        assert!(
            matches!(
                eng.verdict(&evil, RecordType::A, &client()),
                FilterVerdict::Block(_)
            ),
            "비-UTF8 라벨 접두 질의가 차단돼야 함"
        );

        let ok =
            Name::from_labels(vec![vec![0xff], b"safe".to_vec(), b"example".to_vec()]).unwrap();
        assert!(matches!(
            eng.verdict(&ok, RecordType::A, &client()),
            FilterVerdict::Allow
        ));
    }

    #[test]
    fn rewrite_exact_and_wildcard() {
        use onetdns_proto::RData;
        let mut parts = EngineParts::default();
        parts.rewrites.add_exact(
            "router.lan",
            RewriteTarget::ip("192.168.1.1".parse().unwrap()),
        );
        parts.rewrites.add_suffix(
            "internal.test",
            RewriteTarget::Records(vec![RData::A(
                "10.0.0.9".parse::<std::net::Ipv4Addr>().unwrap(),
            )]),
        );
        parts.rewrites.add_suffix(
            "b.internal.test",
            RewriteTarget::Records(vec![RData::A(
                "10.0.0.10".parse::<std::net::Ipv4Addr>().unwrap(),
            )]),
        );
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("router.lan."), RecordType::A, &client()),
            FilterVerdict::Rewrite(RewriteTarget::Records(_))
        ));

        let FilterVerdict::Rewrite(RewriteTarget::Records(records)) =
            eng.verdict(&name("a.b.internal.test."), RecordType::A, &client())
        else {
            panic!("가장 구체적인 suffix rewrite 기대");
        };
        assert!(
            matches!(records.as_slice(), [RData::A(ip)] if *ip == "10.0.0.10".parse::<std::net::Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn refuse_set_returns_refused() {
        let mut parts = EngineParts::default();
        parts.refuse.add_suffix("blocked.test");
        let eng = engine_with(parts);
        assert!(matches!(
            eng.verdict(&name("x.blocked.test."), RecordType::A, &client()),
            FilterVerdict::Block(BlockResponse::Refused)
        ));
    }
}
