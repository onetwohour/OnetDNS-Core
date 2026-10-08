/*!
 * @brief 차단 판정 엔진.
 *
 * @details 질의마다 정해진 우선순위로 여러 집합을 훑는다. 클라이언트 정책부터 타입별
 *          규칙까지 열여덟 단계가 순서대로 걸린다.
 * @warning 이 순서가 곧 의미다. 중요 표시가 일반 허용을 이기고, 허용이 일반 차단을
 *          이긴다. 순서를 바꾸면 운영자가 쓴 규칙의 뜻이 달라진다.
 * @note 엔진은 전부 원자 교체된다. 질의 경로는 잠금을 잡지 않고 스냅숏을 본다.
 */

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
    MatchStage, RewriteTarget,
};
use onetdns_proto::{Name, RecordType};

/** @brief 출처가 기록되지 않았음을 뜻하는 값. */
pub const NO_SOURCE: u32 = u32::MAX;

#[derive(Debug, Default)]
/** @brief 규칙별 적중 수. 켰을 때만 슬롯을 잡는다. */
struct HitCounters {
    /** @brief 고정한 이름마다의 적중 수. */
    dense: Box<[AtomicU64]>,
    /** @brief 적중 보고에 쓸 고정한 이름. 추적을 켰을 때만 재구성한다. */
    dense_names: DenseHitNames,
    /** @brief 굳히지 않은 이름의 적중 수. */
    sparse: HashMap<Box<str>, AtomicU64>,
}

#[derive(Debug, Default)]
/** @brief hit-tracking을 켠 경우에만 보존하는 연속 이름 아레나. */
struct DenseHitNames {
    /** @brief 이름을 순위 순서로 이어 붙인 글. */
    text: Box<str>,
    /** @brief 각 이름의 시작점과 마지막 끝점. */
    offsets: Box<[u32]>,
}

impl DenseHitNames {
    /** @brief 오토마톤 언어를 한 번 순회해 보고용 이름을 만든다. */
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

    /** @brief 순위로 이름을 얻는다. */
    fn get(&self, index: usize) -> Option<&str> {
        let start = *self.offsets.get(index)? as usize;
        let end = *self.offsets.get(index + 1)? as usize;
        self.text.get(start..end)
    }

    /** @brief 이름 아레나가 쓰는 바이트. */
    fn storage_bytes(&self) -> usize {
        self.text.len() + self.offsets.len() * size_of::<u32>()
    }
}

impl HitCounters {
    /** @brief 집합 크기에 맞춰 카운터를 만든다. */
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

    /** @brief 적중을 하나 올린다. */
    fn increment(&self, index: Option<usize>, key: &str) {
        let counter = index
            .and_then(|index| self.dense.get(index))
            .or_else(|| self.sparse.get(key));
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /** @brief 이 규칙의 적중 수. */
    fn value(&self, index: Option<usize>, key: &str) -> u64 {
        index
            .and_then(|index| self.dense.get(index))
            .or_else(|| self.sparse.get(key))
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /** @brief 고정한 항목의 적중 수. */
    fn dense_value(&self, index: usize) -> u64 {
        self.dense
            .get(index)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /** @brief 이름과 함께 모든 적중 카운터를 훑는다. */
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

    /** @brief 카운터가 쓰는 바이트. */
    fn storage_bytes(&self) -> usize {
        self.dense.len() * size_of::<AtomicU64>()
            + self.dense_names.storage_bytes()
            + self.sparse.capacity()
                * (size_of::<Box<str>>() + size_of::<AtomicU64>() + size_of::<usize>())
            + self.sparse.keys().map(|key| key.len()).sum::<usize>()
    }
}

#[derive(Clone, Copy)]
/** @brief 집합에서 찾은 결과. */
struct DomainMatch<'a> {
    /** @brief 찾아낸 이름. */
    key: &'a str,
    /** @brief 어느 목록에서 온 규칙인지. */
    source: u32,
    /** @brief 이름 전체가 맞았는지, 접미사로 맞았는지. */
    is_exact: bool,
    /** @brief 고정한 자료에서의 곳. 적중 수를 셀 때 쓴다. */
    compact_index: Option<usize>,
}

#[derive(Debug, Default)]
/**
 * @brief 도메인 집합 하나. 로드 중에는 테이블, 고정한 뒤에는 최소 오토마톤이다.
 * @details 고치면 다시 테이블로 풀렸다가, 다음 고정에서 오토마톤으로 돌아간다.
 */
pub struct DomainSet {
    /** @brief 로드 중의 이름 전체 일치 테이블. */
    exact: DomainTable,
    /** @brief 로드 중의 접미사 일치 테이블. */
    suffixes: DomainTable,
    /** @brief 고정한 이름 전체 일치 자료. */
    exact_compact: CompactDomainMap,
    /** @brief 고정한 접미사 일치 자료. */
    suffix_compact: CompactDomainMap,

    /** @brief 이름 전체 일치의 적중 수. 켰을 때만 있다. */
    exact_hits: Option<HitCounters>,
    /** @brief 접미사 일치의 적중 수. 켰을 때만 있다. */
    suffix_hits: Option<HitCounters>,
    /** @brief 담긴 이름 수. */
    entry_count: usize,
}

impl DomainSet {
    /** @brief 고정한 집합을 인코딩한다. */
    pub fn encode_compact(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
        self.encode_compact_chunks(&mut |bytes| output.extend_from_slice(bytes))
    }

    /** @brief 고정한 집합을 청크 단위로 스트리밍한다. */
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

    /** @brief 인코딩된 집합을 되읽는다. */
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

    /** @brief 정확 일치 규칙을 넣는다. */
    pub fn add_exact(&mut self, domain: &str) {
        self.add_exact_src(domain, NO_SOURCE);
    }

    /** @brief 접미사 규칙을 넣는다. 하위 도메인까지 걸린다. */
    pub fn add_suffix(&mut self, domain: &str) {
        self.add_suffix_src(domain, NO_SOURCE);
    }

    /** @brief 출처를 함께 기록해 정확 일치 규칙을 넣는다. */
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

    /** @brief 출처를 함께 기록해 접미사 규칙을 넣는다. */
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

    /** @brief 규칙을 지운다. 고정해 있었으면 먼저 푼다. */
    pub fn remove(&mut self, domain: &str) {
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
        let n = normalize_str(domain);
        self.entry_count -= usize::from(self.exact.remove(n.as_str()));
        self.entry_count -= usize::from(self.suffixes.remove(n.as_str()));
        self.exact_hits = None;
        self.suffix_hits = None;
    }

    /** @brief 최소 오토마톤으로 고정한다. 로드가 끝난 뒤 한 번 한다. */
    fn finalize(&mut self) {
        Self::compact(&mut self.exact, &mut self.exact_compact);
        Self::compact(&mut self.suffixes, &mut self.suffix_compact);
    }

    /** @brief 적중 카운터를 켠다. */
    fn enable_hits(&mut self) {
        self.finalize();
        self.exact_hits = Some(HitCounters::new(&self.exact_compact, &self.exact));
        self.suffix_hits = Some(HitCounters::new(&self.suffix_compact, &self.suffixes));
    }

    /** @brief 테이블을 오토마톤으로 고정한다. 실패하면 테이블을 그대로 둔다. */
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

    /** @brief 오토마톤을 테이블로 되돌린다. 고치려면 필요하다. */
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

    /** @brief 비었는지. */
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /** @brief 규칙 수. */
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /** @brief 이 집합이 쓰는 바이트. */
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

    /** @brief 이 이름이 걸리는지. */
    pub fn matches(&self, normalized: &str) -> bool {
        self.matched(normalized).is_some()
    }

    /** @brief 걸린 규칙 문자열. */
    pub fn matched<'a>(&self, normalized: &'a str) -> Option<&'a str> {
        self.matched_kv(normalized).map(|found| found.key)
    }

    /** @brief 걸린 규칙의 출처. */
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

    /** @brief 걸린 규칙을 찾고 적중을 센다. */
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

    /**
     * @brief 정확 일치를 먼저 보고, 없으면 가장 긴 접미사를 본다.
     * @note 접미사는 라벨 경계에서만 맞는다. 그러지 않으면 evil-example.com이
     *       example.com 규칙에 걸린다.
     */
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

    /** @brief 고정한 형태의 결과를 공통 형태로 옮긴다. */
    fn compact_match<'a>(found: CompactMatch<'a>, is_exact: bool) -> DomainMatch<'a> {
        DomainMatch {
            key: found.key,

            source: NO_SOURCE,
            is_exact,
            compact_index: Some(found.index),
        }
    }

    /** @brief 규칙별 적중 수를 훑는다. */
    fn hit_entries(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.exact_hits
            .iter()
            .flat_map(HitCounters::entries)
            .chain(self.suffix_hits.iter().flat_map(HitCounters::entries))
    }

    /** @brief 출처별 적중 수를 훑는다. */
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
/** @brief 재작성 규칙 집합. */
pub struct RewriteSet {
    /** @brief 이름 전체가 맞을 때의 재작성. */
    pub(crate) exact: HashMap<Box<str>, RewriteTarget>,

    /** @brief 접미사가 맞을 때의 재작성. */
    pub(crate) suffix: HashMap<Box<str>, RewriteTarget>,
}

impl RewriteSet {
    /** @brief 정확 일치 재작성을 넣는다. */
    pub fn add_exact(&mut self, domain: &str, target: RewriteTarget) {
        self.exact
            .insert(normalize_str(domain).into_boxed_str(), target);
    }

    /** @brief 접미사 재작성을 넣는다. */
    pub fn add_suffix(&mut self, domain: &str, target: RewriteTarget) {
        self.suffix
            .insert(normalize_str(domain).into_boxed_str(), target);
    }

    /** @brief 비었는지. */
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty()
    }

    /** @brief 규칙 수. */
    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len()
    }

    /** @brief 이 이름에 걸리는 재작성 대상. 정확 일치가 우선이다. */
    fn get(&self, normalized: &str) -> Option<&RewriteTarget> {
        if let Some(t) = self.exact.get(normalized) {
            return Some(t);
        }
        let mut rest = normalized;
        loop {
            if let Some(target) = self.suffix.get(rest) {
                return Some(target);
            }
            rest = match rest.find('.') {
                Some(index) => &rest[index + 1..],
                None => return None,
            };
        }
    }
}

#[derive(Debug, Clone)]
/** @brief 설정의 로컬 영역 하나가 그 아래 이름에 내리는 처분. */
pub enum LocalZoneAction {
    /** @brief 차단 응답. 일반 허용 규칙이 이긴다. */
    Deny,
    /** @brief REFUSED 응답. */
    Refuse,
    /** @brief 영역과 그 아래 모든 이름에 적은 레코드나 0 주소로 답한다. */
    Rewrite(RewriteTarget),
    /** @brief 이름별로 적은 답만 있고 영역 안의 나머지 이름은 없는 이름이다. */
    Static(StaticZone),
    /** @brief 둘러싼 로컬 영역의 처분을 이 아래에서 거두고 평소대로 해석한다. */
    Transparent,
}

#[derive(Debug, Clone, Default)]
/**
 * @brief static 영역에 이름별로 적어 둔 답.
 * @details 적은 이름과 영역 이름 사이에 있는 중간 이름은 존재하되 답이 없는 이름이라
 *          NODATA로 답한다. NXDOMAIN으로 답하면 그 아래 이름까지 없다고 캐시하는 리졸버가
 *          있어, 적어 둔 아래 이름이 사라진다.
 */
pub struct StaticZone {
    /** @brief 영역 이름. 정규화했고 루트 영역은 빈 문자열이다. */
    zone: Box<str>,
    /** @brief 정규화한 이름에서 그 이름의 답으로. */
    names: HashMap<Box<str>, RewriteTarget>,
    /** @brief 적은 이름과 영역 이름 사이의 중간 이름. */
    interior: HashSet<Box<str>>,
}

/** @brief static 영역이 한 이름에 내리는 답. */
pub enum StaticAnswer<'a> {
    /** @brief 적어 둔 답. */
    Data(&'a RewriteTarget),
    /** @brief 이름은 있으나 답이 없다. */
    NoData,
    /** @brief 영역 안에 없는 이름이다. */
    NxDomain,
}

impl StaticZone {
    /** @brief 빈 static 영역. */
    pub fn new(zone: &str) -> Self {
        Self {
            zone: normalize_str(zone).into_boxed_str(),
            ..Self::default()
        }
    }

    /**
     * @brief 영역 안의 이름 하나에 답을 넣는다.
     * @retval Err 이름이 영역 밖에 있거나 이미 답이 있다.
     */
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

    /** @brief 이 영역 안의 이름에 줄 답. 영역 이름 자체는 답이 없어도 있는 이름이다. */
    pub fn answer(&self, normalized: &str) -> StaticAnswer<'_> {
        if let Some(target) = self.names.get(normalized) {
            StaticAnswer::Data(target)
        } else if normalized == &*self.zone || self.interior.contains(normalized) {
            StaticAnswer::NoData
        } else {
            StaticAnswer::NxDomain
        }
    }

    /** @brief 이름과 답 전부. 순서는 정해져 있지 않다. */
    pub fn iter(&self) -> impl Iterator<Item = (&str, &RewriteTarget)> {
        self.names
            .iter()
            .map(|(name, target)| (name.as_ref(), target))
    }
}

#[derive(Debug)]
/** @brief 로컬 영역 하나와 적중 수. */
struct LocalZoneEntry {
    /** @brief 이 영역의 처분. */
    action: LocalZoneAction,
    /** @brief 이 영역에 걸린 질의 수. 적중 추적을 켰을 때만 센다. */
    hits: AtomicU64,
}

#[derive(Debug, Default)]
/**
 * @brief 설정의 로컬 영역 전부.
 * @details 차단 목록, 거절 목록, 재작성 규칙과 섞지 않고 따로 둔다. 한 이름에 여러 영역이
 *          겹치면 가장 구체적인 영역 하나만 적용해야 하는데, 섞어 두면 transparent 영역이
 *          둘러싼 영역만 골라 거둘 수 없고 구독한 차단 목록까지 풀게 된다.
 */
pub struct LocalZoneSet {
    /** @brief 정규화한 영역 이름에서 처분으로. */
    zones: HashMap<Box<str>, LocalZoneEntry>,
}

impl LocalZoneSet {
    /** @brief 영역을 넣는다. 같은 이름이 이미 있으면 거절한다. */
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

    /** @brief 비었는지. */
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /** @brief 영역 수. */
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /** @brief 영역 이름과 처분 전부. 순서는 정해져 있지 않다. */
    pub fn iter(&self) -> impl Iterator<Item = (&str, &LocalZoneAction)> {
        self.zones
            .iter()
            .map(|(zone, entry)| (zone.as_ref(), &entry.action))
    }

    /**
     * @brief 이 이름을 품는 가장 구체적인 영역을 찾는다.
     * @details 이름 자신부터 라벨을 하나씩 떼며 찾으므로 먼저 찾은 영역이 가장 구체적이다.
     *          루트 영역은 빈 키로 들어 있어 마지막에 본다.
     */
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

    /** @brief 처분을 실제로 적용한 영역의 적중을 센다. */
    fn record_hit(&self, zone: &str) {
        if let Some(entry) = self.zones.get(zone) {
            entry.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    /** @brief 영역마다의 적중 수. */
    fn hit_entries(&self) -> impl Iterator<Item = (&str, u64)> {
        self.zones
            .iter()
            .map(|(zone, entry)| (zone.as_ref(), entry.hits.load(Ordering::Relaxed)))
    }
}

/** @brief 이름이 접미사에 걸리는지. 라벨 경계에서만 맞는 것으로 본다. */
fn name_matches_suffix(name: &str, suf: &str) -> bool {
    if name == suf {
        return true;
    }
    name.len() > suf.len()
        && name.ends_with(suf)
        && name.as_bytes()[name.len() - suf.len() - 1] == b'.'
}

#[derive(Debug, Default, Clone)]
/** @brief 목록 로드 결과 보고. 대시보드가 보여 준다. */
pub struct FilterLoadReport {
    /** @brief 읽어 본 규칙 수. */
    pub rules_total: u64,
    /** @brief 건너뛴 규칙 수. */
    pub rules_skipped: u64,

    /** @brief 다루지 않는 수식어와 그 수. */
    pub unsupported_modifier: BTreeMap<String, u64>,

    /** @brief 형식이 깨진 정규식 수. */
    pub invalid_regex: u64,

    /** @brief 형식이 깨진 규칙 수. */
    pub invalid_pattern: u64,

    /** @brief DNS 차단에는 뜻이 없는 규칙 수. */
    pub not_applicable: u64,
}

impl FilterLoadReport {
    /** @brief 실제로 적용된 규칙 수. */
    pub fn rules_applied(&self) -> u64 {
        self.rules_total.saturating_sub(self.rules_skipped)
    }

    /** @brief 보고를 JSON으로. */
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
/** @brief 주소 대역 기반 RPZ 규칙. */
pub struct RpzIpRule {
    /** @brief 이 대역에 걸린다. */
    pub net: IpNet,
    /** @brief 걸렸을 때의 판정. */
    pub verdict: FilterVerdict,
    /** @brief 어느 규칙인지 보일 문구. */
    pub display: Box<str>,
}

impl RpzIpRule {
    /** @brief 대역과 처분으로 만든다. */
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
/** @brief 네임서버 기반 RPZ 규칙. */
pub struct RpzNameRule {
    /** @brief 이 접미사에 걸린다. */
    pub(crate) suffix: Name,
    /** @brief 걸렸을 때의 판정. */
    pub verdict: FilterVerdict,
}

impl RpzNameRule {
    /** @brief 도메인과 처분으로 만든다. */
    pub fn new(domain: &str, verdict: FilterVerdict) -> Option<Self> {
        let suffix = Name::from_str(domain.trim_end_matches('.')).ok()?;
        Some(Self { suffix, verdict })
    }

    /** @brief 이 네임서버에 걸리는지. */
    pub fn matches(&self, ns: &Name) -> bool {
        ns.ends_with_ignore_case(&self.suffix)
    }

    /** @brief 규칙의 구체성. 여럿 걸리면 더 구체적인 것이 이긴다. */
    fn specificity(&self) -> usize {
        self.suffix.labels().len()
    }
}

impl EngineParts {
    /** @brief 이 구성의 모든 도메인 집합. */
    fn domain_sets(&self) -> Vec<&DomainSet> {
        let mut sets = vec![
            &self.block,
            &self.allow,
            &self.block_important,
            &self.allow_important,
            &self.refuse,
            &self.nodata,
            &self.no_response,
        ];
        sets.extend(self.typed_block.iter().map(|(_, set)| set));
        sets.extend(self.typed_block_except.iter().map(|(_, set)| set));
        sets
    }

    /** @brief 이 구성의 모든 도메인 집합을 바꿀 수 있게. */
    fn domain_sets_mut(&mut self) -> Vec<&mut DomainSet> {
        let mut sets: Vec<&mut DomainSet> = vec![
            &mut self.block,
            &mut self.allow,
            &mut self.block_important,
            &mut self.allow_important,
            &mut self.refuse,
            &mut self.nodata,
            &mut self.no_response,
        ];
        sets.extend(self.typed_block.iter_mut().map(|(_, s)| s));
        sets.extend(self.typed_block_except.iter_mut().map(|(_, s)| s));
        sets
    }

    /** @brief 모든 집합을 고정한다. */
    pub(crate) fn finalize_domain_sets(&mut self) {
        for set in self.domain_sets_mut() {
            set.finalize();
        }
    }
}

#[derive(Default)]
/** @brief 엔진을 이루는 집합과 규칙 전부. 로드 결과이자 캐시 대상이다. */
pub struct EngineParts {
    /** @brief 차단할 이름들. */
    pub block: DomainSet,
    /** @brief 허용할 이름들. */
    pub allow: DomainSet,

    /** @brief 무엇보다 먼저 보는 차단. */
    pub block_important: DomainSet,
    /** @brief 무엇보다 먼저 보는 허용. */
    pub allow_important: DomainSet,

    /** @brief 거절로 답할 이름들. */
    pub refuse: DomainSet,

    /** @brief 비어 있다고 답할 이름들. */
    pub nodata: DomainSet,

    /** @brief 아무것도 답하지 않을 이름들. */
    pub no_response: DomainSet,

    /** @brief 이 종류만 막을 이름들. */
    pub typed_block: Vec<(RecordType, DomainSet)>,

    /** @brief 이 종류만 빼고 막을 이름들. */
    pub typed_block_except: Vec<(Vec<RecordType>, DomainSet)>,

    /** @brief 정규식 차단. */
    pub regex_block: Vec<String>,
    /** @brief 정규식 허용. */
    pub regex_allow: Vec<String>,

    /** @brief 먼저 보는 정규식 차단. */
    pub regex_block_important: Vec<String>,
    /** @brief 먼저 보는 정규식 허용. */
    pub regex_allow_important: Vec<String>,

    /** @brief 정규식 거절. */
    pub regex_refuse: Vec<String>,
    /** @brief 정규식 빈 응답. */
    pub regex_nodata: Vec<String>,
    /** @brief 정규식 무응답. */
    pub regex_no_response: Vec<String>,

    /** @brief 정규식 재작성. */
    pub regex_rewrites: Vec<(String, RewriteTarget)>,

    /** @brief 종류를 지정한 정규식 차단. */
    pub regex_typed_block: Vec<(RecordType, String)>,
    /** @brief 종류를 빼고 막는 정규식 차단. */
    pub regex_typed_block_except: Vec<(Vec<RecordType>, String)>,

    /** @brief 재작성 규칙. */
    pub rewrites: RewriteSet,

    /** @brief 설정의 로컬 영역. */
    pub local_zones: LocalZoneSet,

    /** @brief 클라이언트 조건이 붙은 규칙. */
    pub client_rules: Vec<ClientRule>,

    /** @brief 클라이언트 주소로 거는 영역 규칙. */
    pub rpz_client_ip: Vec<RpzIpRule>,

    /** @brief 답에 담긴 주소로 거는 영역 규칙. */
    pub rpz_ip: Vec<RpzIpRule>,

    /** @brief 답에 담긴 이름 서버로 거는 영역 규칙. */
    pub rpz_nsdname: Vec<RpzNameRule>,

    /** @brief 그 이름 서버의 주소로 거는 영역 규칙. */
    pub rpz_nsip: Vec<RpzIpRule>,

    /** @brief 로드 결과 요약. */
    pub report: FilterLoadReport,

    /** @brief 이 엔진을 만든 목록들. */
    pub sources: Vec<String>,
}

#[derive(Debug, Clone)]
/** @brief 목록 하나의 통계. */
pub struct SourceStat {
    /** @brief 목록 이름. */
    pub source: String,
    /** @brief 그 목록의 규칙 수. */
    pub rules: u64,
    /** @brief 그 목록이 걸린 횟수. */
    pub hits: u64,
}

#[derive(Debug, Clone)]
/** @brief 클라이언트 규칙이 걸리는 조건. */
pub enum ClientCond {
    /** @brief 이 대역에 든 클라이언트. */
    Net { negated: bool, net: IpNet },
    /** @brief 이 식별자를 가진 클라이언트. */
    Id { negated: bool, id: String },
}

#[derive(Debug, Clone, Default)]
/** @brief 특정 클라이언트에만 걸리는 규칙. */
pub struct ClientRule {
    /** @brief 이 규칙이 걸릴 이름. */
    pub domain: String,

    /** @brief 이름 대신 쓸 정규식. */
    pub regex: Option<String>,

    /** @brief 차단이 아니라 허용인지. */
    pub allow: bool,

    /** @brief 이 클라이언트들에만 건다. */
    pub clients: Vec<ClientCond>,

    /** @brief 이 태그가 붙은 클라이언트에만 건다. */
    pub ctags: Vec<(bool, String)>,

    /** @brief 여기 적힌 이름은 이 규칙에서 뺀다. */
    pub denyallow: Vec<String>,
}

impl ClientRule {
    /** @brief 이 규칙이 이 클라이언트와 이름에 걸리는지. */
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
/** @brief 클라이언트 그룹 하나에 대한 정책. */
pub struct ClientPolicy {
    /** @brief 이 그룹에 드는 대역. */
    nets: Vec<IpNet>,

    /** @brief 이 그룹에 드는 식별자. */
    ids: Vec<String>,

    /** @brief 이 그룹에 붙은 태그. */
    tags: Vec<String>,
    /** @brief 이 그룹에만 적용할 차단. */
    block: DomainSet,
    /** @brief 이 그룹에만 적용할 허용. */
    allow: DomainSet,

    /** @brief 이 그룹은 차단을 하지 않는다. */
    disable_filtering: bool,

    /** @brief 안전 검색 여부. 없으면 전체 설정을 따른다. */
    safe_search: Option<bool>,

    /** @brief 이 그룹의 질의는 기록하지 않는다. */
    ignore_querylog: bool,
    /** @brief 이 그룹의 질의는 통계에 넣지 않는다. */
    ignore_stats: bool,
}

impl ClientPolicy {
    /** @brief 이름과 대상으로 정책을 만든다. */
    pub fn new(
        nets: Vec<IpNet>,
        block: &[String],
        allow: &[String],
        disable_filtering: bool,
    ) -> Self {
        Self::with_options(nets, vec![], vec![], block, allow, disable_filtering, None)
    }

    #[allow(clippy::too_many_arguments)]
    /** @brief 이 정책이 판정을 바꾸는지. 아니면 고속 경로가 건너뛸 수 있다. */
    pub(crate) fn affects_verdict(&self) -> bool {
        !self.block.is_empty() || !self.allow.is_empty() || self.disable_filtering
    }

    /** @brief 세부 설정을 붙인다. */
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

    /** @brief 기록과 통계 제외 설정을 붙인다. */
    pub fn with_log_flags(mut self, ignore_querylog: bool, ignore_stats: bool) -> Self {
        self.ignore_querylog = ignore_querylog;
        self.ignore_stats = ignore_stats;
        self
    }

    /** @brief 이 정책의 집합에도 적중 추적을 켠다. */
    fn enable_hits(&mut self) {
        self.block.enable_hits();
        self.allow.enable_hits();
    }

    /** @brief 이 정책이 붙는 태그들. */
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /** @brief 이 클라이언트가 이 정책 대상인지. */
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
/**
 * @brief 완성된 판정 엔진. 만들어진 뒤에는 바뀌지 않는다.
 * @note 목록을 교체할 때는 새 엔진을 만들어 전부 바꾼다. 질의 경로가 잠금을 잡지
 *       않는 이유다.
 */
pub struct BlockEngine {
    /** @brief 고정한 규칙 자료. */
    parts: EngineParts,

    /** @brief 판정을 바꿀 규칙이 하나라도 있는지. */
    has_verdict_rules: bool,

    /** @brief 정규식 차단. */
    regex_block: RegexMatcher,
    /** @brief 정규식 허용. */
    regex_allow: RegexMatcher,
    /** @brief 먼저 보는 정규식 차단. */
    regex_block_important: RegexMatcher,
    /** @brief 먼저 보는 정규식 허용. */
    regex_allow_important: RegexMatcher,
    /** @brief 정규식 거절. */
    regex_refuse: RegexMatcher,
    /** @brief 정규식 빈 응답. */
    regex_nodata: RegexMatcher,
    /** @brief 정규식 무응답. */
    regex_no_response: RegexMatcher,

    /** @brief 정규식 재작성. */
    regex_rewrites: Vec<(String, Regex, RewriteTarget)>,
    /** @brief 종류를 지정한 정규식 차단. */
    regex_typed: Vec<(RecordType, String, Regex)>,
    /** @brief 종류를 빼고 막는 정규식 차단. */
    regex_typed_except: Vec<(Vec<RecordType>, String, Regex)>,

    /** @brief 클라이언트 규칙마다 미리 엮어 둔 정규식. */
    client_rule_regex: Vec<Option<Regex>>,

    /** @brief 차단할 때의 기본 답 방식. */
    default_block: BlockResponse,
    /** @brief 클라이언트별 정책. */
    clients: Vec<ClientPolicy>,

    /** @brief 적중 수를 셀지. */
    track_hits: bool,
}

#[derive(Debug, Default)]
/** @brief 정규식 번들. 여럿을 나눠 담아 하나가 커지는 것을 막는다. */
struct RegexMatcher {
    /** @brief 여러 정규식을 한 번에 훑는 번들들. */
    chunks: Vec<(RegexSet, Vec<(String, Regex)>)>,
    /** @brief 번들이 맞았을 때 하나씩 확인할 정규식들. */
    individual: Vec<(String, Regex)>,
}

impl RegexMatcher {
    /** @brief 맞는 첫 패턴. */
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

/** @brief 패턴 하나를 따로 컴파일한다. 실패해도 나머지에 영향을 주지 않는다. */
fn compile_isolated(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(re) => Some(re),
        Err(error) => {
            onetdns_core::warn!(event = "filter.regex_rule_skipped", pattern, error = %error, "Excluded one problematic regex rule");
            None
        }
    }
}

/** @brief 패턴들을 번들로 컴파일한다. */
fn build_regexes(patterns: &[String]) -> RegexMatcher {
    /** @brief 번들 하나에 담을 패턴 수. */
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
    /** @brief 사람이 읽을 설명. */
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
            .field("local_zones", &self.local_zones.len())
            .field("rules_total", &self.report.rules_total)
            .field("rules_skipped", &self.report.rules_skipped)
            .finish()
    }
}

impl BlockEngine {
    /** @brief 구성에서 엔진을 만든다. 집합을 굳히고 정규식을 컴파일한다. */
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
        let client_rule_regex = parts
            .client_rules
            .iter()
            .map(|r| r.regex.as_deref().and_then(compile_isolated))
            .collect();
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
            regex_rewrites,
            regex_typed,
            regex_typed_except,
            client_rule_regex,
            default_block,
            clients: Vec::new(),
            track_hits: false,
        }
    }

    /** @brief 클라이언트 정책을 붙인다. */
    pub fn with_clients(mut self, clients: Vec<ClientPolicy>) -> Self {
        self.has_verdict_rules |= clients
            .iter()
            .any(|client| !client.block.is_empty() || !client.allow.is_empty());
        self.clients = clients;
        self
    }

    /** @brief 적중 추적을 켜고 끈다. */
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

    /** @brief 적중 추적이 켜져 있는지. */
    pub fn hits_enabled(&self) -> bool {
        self.track_hits
    }

    /** @brief 가장 많이 걸린 규칙들. */
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

    /** @brief 목록별 통계. */
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

    /** @brief 아무것도 막지 않는 엔진. */
    pub fn empty(default_block: BlockResponse) -> Self {
        Self::new(EngineParts::default(), default_block)
    }

    /** @brief 차단 규칙 수. */
    pub fn block_count(&self) -> usize {
        self.parts.block.len()
            + self.parts.block_important.len()
            + self.parts.refuse.len()
            + self.parts.nodata.len()
            + self.parts.no_response.len()
            + self.parts.regex_block.len()
            + self.parts.regex_block_important.len()
            + self.parts.regex_refuse.len()
            + self.parts.regex_nodata.len()
            + self.parts.regex_no_response.len()
            + self.parts.regex_typed_block.len()
            + self.parts.regex_typed_block_except.len()
            + self
                .parts
                .typed_block
                .iter()
                .map(|(_, s)| s.len())
                .sum::<usize>()
    }

    /** @brief 도메인 집합들이 쓰는 바이트. */
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

    /** @brief 허용 규칙 수. */
    pub fn allow_count(&self) -> usize {
        self.parts.allow.len()
            + self.parts.allow_important.len()
            + self.parts.regex_allow.len()
            + self.parts.regex_allow_important.len()
    }

    /** @brief 로드 보고. */
    pub fn load_report(&self) -> &FilterLoadReport {
        &self.parts.report
    }

    /** @brief 주소 기반 RPZ 규칙이 있는지. */
    pub fn has_rpz_ip(&self) -> bool {
        !self.parts.rpz_ip.is_empty()
    }

    /** @brief 이 주소에 걸리는 RPZ 처분. */
    pub fn rpz_ip_verdict(&self, ip: std::net::IpAddr) -> Option<&FilterVerdict> {
        self.parts
            .rpz_ip
            .iter()
            .filter(|rule| rule.net.contains(&ip))
            .max_by_key(|rule| rule.net.prefix_len())
            .map(|rule| &rule.verdict)
    }

    /** @brief 클라이언트별 규칙이 있는지. 없으면 고속 경로가 열린다. */
    pub fn has_client_specific_rules(&self) -> bool {
        !self.parts.client_rules.is_empty()
            || !self.parts.rpz_client_ip.is_empty()
            || self.clients.iter().any(|policy| policy.affects_verdict())
    }

    /** @brief 네임서버 기반 RPZ 규칙이 있는지. */
    pub fn has_rpz_ns(&self) -> bool {
        !self.parts.rpz_nsdname.is_empty() || !self.parts.rpz_nsip.is_empty()
    }

    /** @brief 네임서버에 걸리는 RPZ 처분. 가장 구체적인 규칙이 이긴다. */
    pub fn rpz_ns_verdict(
        &self,
        ns_names: &[Name],
        ns_ips: &[std::net::IpAddr],
    ) -> Option<FilterVerdict> {
        if !self.has_rpz_ns() {
            return None;
        }
        if let Some(rule) = ns_ips
            .iter()
            .flat_map(|ip| {
                self.parts
                    .rpz_nsip
                    .iter()
                    .filter(move |rule| rule.net.contains(ip))
            })
            .max_by_key(|rule| rule.net.prefix_len())
        {
            return Some(rule.verdict.clone());
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

    /** @brief 이 클라이언트의 안전 검색 설정. */
    pub fn client_safe_search(&self, client: &ClientInfo) -> Option<bool> {
        self.clients
            .iter()
            .find(|p| p.matches(client))
            .and_then(|p| p.safe_search)
    }

    /** @brief 이 클라이언트를 기록과 통계에서 뺄지. */
    pub fn client_log_stat(&self, client: &ClientInfo) -> (bool, bool) {
        self.clients
            .iter()
            .find(|p| p.matches(client))
            .map(|p| (!p.ignore_querylog, !p.ignore_stats))
            .unwrap_or((true, true))
    }

    /**
     * @brief 이 엔진이 아무것도 막지 않는지.
     * @warning wire 고속 경로가 이 판정을 믿고 필터를 건너뛴다. 잘못 참을 돌려주면
     *          차단이 전부 우회된다.
     */
    pub fn is_trivially_allow(&self) -> bool {
        !self.has_verdict_rules && self.clients.is_empty()
    }
}

impl FilterEngine for BlockEngine {
    /** @brief 이 질의의 처분. */
    fn verdict(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterVerdict {
        if !self.has_verdict_rules {
            return FilterVerdict::Allow;
        }
        let mut buf = [0u8; MAX_NAME];
        let key = match normalize_into(name, &mut buf) {
            Some(k) => k,
            None => return FilterVerdict::Allow,
        };

        self.classify(&key, qtype, client, self.track_hits).0
    }

    /** @brief 처분과 함께 어느 단계에서 무엇에 걸렸는지 알려 준다. */
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
    /**
     * @brief 판정을 낸 규칙이 들어 있던 목록의 이름.
     * @details 단계마다 그 단계가 보는 집합에서 출처를 찾는다. 정규식, 로컬 영역, 클라이언트
     *          규칙처럼 목록 출처를 두지 않는 단계는 없다고 답한다. 진단 경로에서만 부른다.
     */
    fn source_name(&self, stage: MatchStage, key: &str) -> Option<String> {
        let p = &self.parts;
        let set = match stage {
            MatchStage::Block => &p.block,
            MatchStage::ImportantBlock => &p.block_important,
            MatchStage::Allow => &p.allow,
            MatchStage::ImportantAllow => &p.allow_important,
            MatchStage::NoResponse => &p.no_response,
            MatchStage::Refuse => &p.refuse,
            MatchStage::NoData => &p.nodata,
            _ => return None,
        };
        let id = set.source_of(key)?;
        if id == NO_SOURCE {
            return None;
        }
        p.sources.get(id as usize).cloned()
    }
    /**
     * @brief 우선순위 사다리를 따라 처분을 정한다. 엔진의 본체다.
     *
     * @details 클라이언트 정책, RPZ, 클라이언트 규칙, 중요 허용, 무응답, 중요 차단, 거부,
     *          데이터 없음, 재작성, 허용, 정규식, 차단, 타입별 순서다. 무응답은 모든 차단보다
     *          앞선다. 차단이 이기면 다른 목록의 규칙 하나 때문에 숨기려던 이름에 서버가 답한다.
     *          차단 규칙의 뜻은 답하지 않아도 지켜진다.
     * @note 로컬 영역은 가장 구체적인 영역 하나만 찾고, 그 처분을 거부, 재작성, 차단 단계
     *       가운데 맞는 곳에서 쓴다. transparent 영역이 걸리면 로컬 영역 처분은 없다.
     * @warning 이 순서가 규칙의 뜻이다. 바꾸면 운영자가 기대한 동작이 달라진다.
     */
    fn classify<'a>(
        &'a self,
        key: &'a str,
        qtype: RecordType,
        client: &ClientInfo,
        count: bool,
    ) -> (FilterVerdict, MatchStage, Option<&'a str>) {
        let p = &self.parts;
        /* 한 이름에는 가장 구체적인 로컬 영역 하나만 걸린다. 처분이 어느 단계에서 쓰이든 한 번만 찾는다. */
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

        if !p.rpz_client_ip.is_empty() {
            if let Some(rule) = p
                .rpz_client_ip
                .iter()
                .filter(|rule| rule.net.contains(&client.source_ip))
                .max_by_key(|rule| rule.net.prefix_len())
            {
                return (
                    rule.verdict.clone(),
                    MatchStage::RpzClientIp,
                    Some(&rule.display),
                );
            }
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
            if let Some((_, r)) = p
                .client_rules
                .iter()
                .enumerate()
                .find(|(i, r)| r.allow && applies(*i, r))
            {
                return (
                    FilterVerdict::Allow,
                    MatchStage::ClientRuleAllow,
                    rule_key(r),
                );
            }
            if let Some((_, r)) = p
                .client_rules
                .iter()
                .enumerate()
                .find(|(i, r)| !r.allow && applies(*i, r))
            {
                return (
                    FilterVerdict::Block(self.default_block),
                    MatchStage::ClientRuleBlock,
                    rule_key(r),
                );
            }
        }

        if let Some(m) = self.lookup(&p.allow_important, key, count) {
            return (FilterVerdict::Allow, MatchStage::ImportantAllow, Some(m));
        }
        if let Some(m) = self.regex_allow_important.find(key) {
            return (FilterVerdict::Allow, MatchStage::ImportantAllow, Some(m));
        }

        if let Some(m) = self.lookup(&p.no_response, key, count) {
            return (FilterVerdict::Drop, MatchStage::NoResponse, Some(m));
        }
        if let Some(m) = self.regex_no_response.find(key) {
            return (FilterVerdict::Drop, MatchStage::NoResponse, Some(m));
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
        if let Some(m) = self.regex_refuse.find(key) {
            return (
                FilterVerdict::Block(BlockResponse::Refused),
                MatchStage::Refuse,
                Some(m),
            );
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
        if let Some(m) = self.regex_nodata.find(key) {
            return (
                FilterVerdict::Block(BlockResponse::NoData),
                MatchStage::NoData,
                Some(m),
            );
        }

        if let Some(t) = p.rewrites.get(key) {
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
            .find(|(_, re, _)| re.is_match(key))
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

        if let Some(m) = self.lookup(&p.block, key, count) {
            return (
                FilterVerdict::Block(self.default_block),
                MatchStage::Block,
                Some(m),
            );
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

    #[inline]
    /** @brief 집합에서 찾고, 필요하면 적중을 센다. */
    fn lookup<'a>(&'a self, set: &'a DomainSet, key: &'a str, count: bool) -> Option<&'a str> {
        if count {
            set.hit(key)
        } else {
            set.matched(key)
        }
    }
}

/** @brief 클라이언트 규칙의 키. */
fn rule_key(r: &ClientRule) -> Option<&str> {
    if !r.domain.is_empty() {
        Some(&r.domain)
    } else {
        r.regex.as_deref()
    }
}

/** @brief 원자 교체되는 엔진 핸들. 고속 경로 게이트를 함께 가지고 있다. */
pub struct SharedFilter {
    /** @brief 지금 엔진. 한꺼번에 교체한다. */
    swap: ArcSwap<BlockEngine>,
    /** @brief 이 엔진이 무언가 막는지. 복제 없이 답하려고 따로 둔다. */
    wire_blocked: AtomicBool,
}

impl SharedFilter {
    /** @brief 엔진 하나로 만든다. */
    pub fn from_pointee(engine: BlockEngine) -> Self {
        let wire_blocked = Self::blocks_wire(&engine);
        Self {
            swap: ArcSwap::from_pointee(engine),
            wire_blocked: AtomicBool::new(wire_blocked),
        }
    }

    /** @brief 공유 엔진으로 만든다. */
    pub fn new(engine: Arc<BlockEngine>) -> Self {
        let wire_blocked = Self::blocks_wire(&engine);
        Self {
            swap: ArcSwap::new(engine),
            wire_blocked: AtomicBool::new(wire_blocked),
        }
    }

    /** @brief 이 엔진이 고속 경로를 막는지. */
    fn blocks_wire(engine: &BlockEngine) -> bool {
        !engine.is_trivially_allow() || engine.has_rpz_ns() || engine.has_rpz_ip()
    }

    /** @brief 지금 엔진 스냅숏. 질의 경로가 이것을 쓴다. */
    pub fn load(&self) -> Arc<BlockEngine> {
        self.swap.load()
    }

    /**
     * @brief 엔진을 교체한다.
     * @note 고속 경로 게이트도 함께 갱신한다. 따로 두면 새 엔진이 막는데도 게이트가
     *       열려 있는 구간이 생긴다.
     */
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

    /** @brief 지금 엔진이 고속 경로를 막는지. 잠금 없이 읽는다. */
    pub fn wire_blocked(&self) -> bool {
        self.wire_blocked.load(Ordering::Acquire)
    }
}

/** @brief 정규화한 이름을 담을 버퍼 크기. */
const MAX_NAME: usize = 256;

/**
 * @brief 이름을 정규화해 스택 버퍼에 담는다.
 * @note 질의마다 할당하지 않으려는 것이다. 버퍼에 담기지 않는 이름만 따로 할당한다.
 */
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

/** @brief 이름을 정규화한 문자열로. */
pub fn normalize_name(name: &Name) -> String {
    name.to_ascii_lower()
}

/** @brief 문자열을 정규화한다. 소문자로 내리고 끝점을 뗀다. */
pub fn normalize_str(domain: &str) -> String {
    let mut s = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if s.starts_with("*.") {
        s = s[2..].to_string();
    }
    s
}

#[cfg(test)]
/** @brief 우선순위 사다리, 고정 왕복, 그리고 고속 경로 게이트 판정. */
mod tests {
    use super::*;
    use onetdns_core::Transport;

    /** @brief 테스트용 클라이언트 정보. */
    fn client() -> ClientInfo {
        ClientInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    /** @brief 이름 문자열을 Name으로. */
    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    /**
     * @brief 한 이름에는 가장 구체적인 로컬 영역만 걸리고, transparent는 로컬 영역만 거두는지.
     * @details transparent가 차단 목록까지 풀면 운영자가 구독한 목록이 조용히 무력화된다.
     */
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
    /**
     * @brief static 영역이 적은 이름에만 답하고 나머지를 없는 이름으로 답하는지.
     * @details 중간 이름을 NXDOMAIN으로 답하면 그 아래 이름까지 없다고 캐시하는 리졸버가
     *          있어, 적어 둔 아래 이름이 사라진다. 영역 밖 이름을 받으면 다른 영역의 답을
     *          가로챈다.
     */
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
    /** @brief 아무것도 막지 않는다는 판정이 정확한지. 틀리면 wire 고속 경로가 필터를 건너뛴다. */
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
    /** @brief 엔진을 교체하면 고속 경로 게이트도 따라 바뀌는지. */
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
    /** @brief 고정한 뒤에도 모든 판정이 같고 임시 구조가 풀려나는지. */
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
    /** @brief 인코딩 왕복에서 정확 일치, 접미사, 출처가 보존되는지. */
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
    /** @brief 굳히지 않은 집합의 인코딩을 거부하는지. */
    fn compact_binary_rejects_unfinalized_set() {
        let mut set = DomainSet::default();
        set.add_suffix("blocked.example");
        assert!(set.encode_compact(&mut Vec::new()).is_err());
    }

    #[test]
    /** @brief 고정한 뒤 고치면 다시 풀리면서 규칙이 하나도 새지 않는지. */
    fn mutation_after_finalize_thaws_without_losing_rules() {
        let mut set = DomainSet::default();
        set.add_exact_src("only.example", 7);
        set.add_suffix_src("blocked.example", 8);
        set.finalize();

        set.add_suffix_src("new.example", 9);
        assert_eq!(set.source_of("only.example"), Some(7));
        assert_eq!(set.source_of("x.blocked.example"), Some(8));
        assert_eq!(set.source_of("x.new.example"), Some(9));

        set.remove("blocked.example");
        assert!(!set.matches("x.blocked.example"));
        assert!(set.matches("x.new.example"));
    }

    #[test]
    /** @brief 빈 접미사 규칙을 거부하는지. 받으면 모든 이름이 걸려 두 경로의 답이 갈린다. */
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
    /** @brief 적중 추적을 끄면 카운터 메모리를 아예 잡지 않는지. */
    fn hit_tracking_off_stores_no_counter_maps() {
        let mut set = DomainSet::default();
        set.add_suffix("blocked.example");
        set.finalize();
        assert!(set.exact_hits.is_none());
        assert!(set.suffix_hits.is_none());

        assert_eq!(set.hit("x.blocked.example"), Some("blocked.example"));
    }

    /** @brief 주소만 지정한 테스트용 클라이언트. */
    fn client_ip(ip: &str) -> ClientInfo {
        ClientInfo {
            source_ip: ip.parse().unwrap(),
            client_id: None,
            transport: Transport::Do53Udp,
            authenticated: false,
        }
    }

    /** @brief 구성으로 엔진을 만든다. */
    fn engine_with(parts: EngineParts) -> BlockEngine {
        BlockEngine::new(parts, BlockResponse::NxDomain)
    }

    #[test]
    /** @brief 클라이언트 주소 기반 RPZ가 걸리는지. */
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
    /** @brief 응답 주소 기반 RPZ가 걸리는지. */
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
    /** @brief 네임서버 기반 RPZ가 이름과 주소 모두로 걸리는지. */
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
    /** @brief 네임서버 규칙이 원본 옥텟을 보존하는지. */
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
    /** @brief 네임서버 규칙 중 가장 구체적인 것이 이기는지. */
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
    /** @brief 규칙별 적중이 따로 세어지는지. */
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
        assert_eq!(eng.top_rule_hits(10)[0], ("ads.example.com".to_string(), 3));
    }

    #[test]
    /** @brief 적중 추적이 기본으로 꺼져 있는지. 켜면 메모리와 시간이 는다. */
    fn hit_tracking_off_by_default() {
        let mut parts = EngineParts::default();
        parts.block.add_suffix("ads.example.com");
        let eng = engine_with(parts);
        assert!(!eng.hits_enabled());
        eng.verdict(&name("ads.example.com."), RecordType::A, &client());
        assert!(eng.top_rule_hits(10).is_empty(), "추적 꺼지면 카운트 0");
    }

    #[test]
    /** @brief 정확 일치 차단. */
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
    /** @brief 접미사 차단이 하위 도메인까지 막는지. */
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
    /** @brief 설명이 어느 단계에서 무엇에 걸렸는지 알려 주는지. */
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
    /**
     * @brief 설명이 규칙이 들어 있던 목록을 목록 단위로 알려 주는지.
     * @details 엔진을 만들면 목록이 오토마톤으로 고정되므로, 고정한 뒤에도 출처가 남아야
     *          한다. 직접 입력한 규칙은 목록이 아니므로 출처가 없어야 한다.
     */
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
    /** @brief 설명 경로와 판정 경로의 답이 같은지. 갈리면 설명이 거짓이 된다. */
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
        }
    }

    #[test]
    /**
     * @brief 무응답 규칙이 중요 허용 다음, 중요 차단 앞에서 판정되는지.
     * @details 차단이 이기면 다른 목록의 차단이나 거부 규칙 하나 때문에 숨기려던 이름에 서버가
     *          답한다. 일반 허용은 무응답을 풀지 못하고, 중요 허용만 푼다.
     */
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
    /** @brief 허용이 일반 차단을 이기는지. */
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
    /** @brief 중요 차단이 허용을 이기는지. */
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
    /** @brief 중요 허용이 중요 차단을 이기는지. 사다리의 가장 위다. */
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
    /** @brief 타입 제한 차단이 그 타입에만 걸리는지. */
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
    /** @brief 정규식 차단이 걸리는지. */
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
    /** @brief UTF-8이 아닌 라벨로 접미사 차단을 우회하지 못하는지. */
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
    /** @brief 재작성이 정확 일치와 별표 모두에서 걸리는지. */
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
    /** @brief 거부 집합이 거부 응답을 내는지. */
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
