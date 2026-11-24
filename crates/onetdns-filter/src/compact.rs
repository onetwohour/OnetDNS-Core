//! Compact form of a domain set: domains are reversed, sorted, and frozen into a minimal acyclic
//! automaton. Domains sharing a suffix share states, so millions of entries shrink to a fraction.
//!
//! The rank summed during a walk is the entry's position in sorted order and indexes the source
//! array directly. The matched text is a slice of the query itself, so it is not stored.
//!
//! Decoding validates the whole structure: a cycle or out-of-range index left in would send the
//! verdict path into an infinite loop or a wrong read.

use std::cmp::Ordering;
use std::mem::size_of;

use crate::table::{DomainTable, SortedDomains};

const NONE: u32 = u32::MAX;
const TERMINAL_BIT: u32 = 1 << 31;
const EDGE_COUNT_MASK: u32 = !TERMINAL_BIT;
const MAP_HEADER_BYTES: usize = 13;

/// A little-endian `u16`: the edge count in the low bits, the terminal flag in the top bit.
const STATE_HEADER_BYTES: usize = 2;
const HEADER_COUNT_MASK: u16 = 0x1ff;
const HEADER_TERMINAL: u16 = 1 << 15;
/// Little-endian `u32`s: the target block, the output added to the rank, and the tail position.
const EDGE_RECORD_BYTES: usize = 12;

/// About 0.4% of names outside the set pass a [`Prefilter`] this size.
const PREFILTER_BITS_PER_NAME: usize = 12;
const PREFILTER_BLOCK_BITS: usize = 512;
/// In smaller sets a walk that finds nothing ends about as fast as hashing every suffix.
const PREFILTER_MIN_NAMES: usize = 256;
/// One odd multiplier per word, so a name's bits in the eight words are independent.
const PREFILTER_SALTS: [u32; 8] = [
    0x47b6_137b,
    0x4497_4d91,
    0x8824_ad5b,
    0xa2b7_289d,
    0x7054_95c7,
    0x2df1_424b,
    0x9efc_4947,
    0x5c6b_fb31,
];

/// The length fits in one byte.
const MAX_EDGE_TAIL: usize = 255;

const MAX_ENCODED_MAP_BYTES: usize = 512 * 1024 * 1024;
const SOURCE_EMPTY: u8 = 0;
const SOURCE_UNIFORM: u8 = 1;
const SOURCE_U8: u8 = 2;
const SOURCE_U16: u8 = 3;
const SOURCE_U32: u8 = 4;

#[cfg(test)]
type DomainMap = std::collections::HashMap<Box<str>, u32>;

#[derive(Debug, Clone, Copy)]
/// Edge start, edge count, and terminal flag in one word.
struct PackedState {
    first_edge: u32,
    edge_count_and_terminal: u32,
}

impl PackedState {
    fn new(first_edge: u32, edge_count: usize, terminal: bool) -> Self {
        let terminal = if terminal { TERMINAL_BIT } else { 0 };
        Self {
            first_edge,
            edge_count_and_terminal: edge_count as u32 | terminal,
        }
    }

    #[inline]
    fn edge_count(self) -> usize {
        (self.edge_count_and_terminal & EDGE_COUNT_MASK) as usize
    }

    #[inline]
    fn terminal(self) -> bool {
        self.edge_count_and_terminal & TERMINAL_BIT != 0
    }
}

#[derive(Debug, Default)]
/// Immutable once built.
pub(crate) struct CompactDomainMap {
    /// Every state as one block, the root at 0: a header with the edge count and the terminal
    /// flag, the edge labels in order, then one record per edge. A step reads one block, so a walk
    /// waits on one load per state instead of one per array.
    states: Box<[u8]>,
    /// An edge's tail position points at a length byte followed by the bytes the edge consumes
    /// after its label. Position 0 means none, so the first byte is left empty.
    tail_bytes: Box<[u8]>,
    prefilter: Prefilter,
    sources: SourceTable,
}

/// One state's block.
#[derive(Clone, Copy)]
struct Block<'a> {
    labels: &'a [u8],
    edges: &'a [u8],
    terminal: bool,
}

impl Block<'_> {
    /// Target block, rank output, and tail position.
    #[inline]
    fn edge(self, position: usize) -> Option<(u32, u32, u32)> {
        let at = position * EDGE_RECORD_BYTES;
        let record: &[u8; EDGE_RECORD_BYTES] = self
            .edges
            .get(at..at + EDGE_RECORD_BYTES)?
            .try_into()
            .ok()?;
        let word = |offset: usize| {
            u32::from_le_bytes([
                record[offset],
                record[offset + 1],
                record[offset + 2],
                record[offset + 3],
            ])
        };
        Some((word(0), word(4), word(8)))
    }

    fn len(self) -> usize {
        STATE_HEADER_BYTES + self.labels.len() + self.edges.len()
    }
}

#[derive(Debug, Default)]
/// A blocked Bloom filter over a map's names. A name sets one bit in each word of one 64-byte
/// block, so a check reads one cache line. A name it rejects is not in the map; one it passes is
/// still walked, so it never decides a match.
struct Prefilter {
    /// Empty means every name may be in the map.
    blocks: Box<[[u64; 8]]>,
}

impl Prefilter {
    /// Empty, sized for `names`. None for a set too small to gain from one, or when it cannot be
    /// allocated; every lookup then walks, which is still correct.
    fn for_names(names: usize) -> Option<Self> {
        if names < PREFILTER_MIN_NAMES {
            return None;
        }
        let blocks = names
            .checked_mul(PREFILTER_BITS_PER_NAME)?
            .div_ceil(PREFILTER_BLOCK_BITS);
        let blocks = filled_vec(
            blocks,
            [0u64; 8],
            "Out of memory storing the compact filter prefilter",
        )
        .ok()?;
        Some(Self {
            blocks: blocks.into_boxed_slice(),
        })
    }

    fn insert(&mut self, name: &[u8]) {
        let hash = name_hash(name);
        let index = self.block_index(hash);
        for (word, bits) in self.blocks[index].iter_mut().enumerate() {
            *bits |= prefilter_bit(hash, word);
        }
    }

    #[inline]
    fn block_index(&self, hash: u64) -> usize {
        (((hash >> 32) * self.blocks.len() as u64) >> 32) as usize
    }

    /// Checks all eight words without stopping early, so no branch waits on the block's load.
    #[inline]
    fn passes(&self, hash: u64) -> bool {
        let block = &self.blocks[self.block_index(hash)];
        block.iter().enumerate().fold(true, |all, (word, bits)| {
            all & (bits & prefilter_bit(hash, word) != 0)
        })
    }

    #[inline]
    fn may_contain(&self, name: &[u8]) -> bool {
        self.blocks.is_empty() || self.passes(name_hash(name))
    }

    /// Whether any suffix starting at a label boundary may be in the map. The hash is built from
    /// the end, so each suffix's hash is on hand when its boundary is reached. Every boundary is
    /// checked before deciding, so the blocks load in parallel.
    #[inline]
    fn may_contain_suffix(&self, name: &[u8]) -> bool {
        if self.blocks.is_empty() {
            return true;
        }
        let mut state = NAME_HASH_SEED;
        let mut any = false;
        for at in (0..name.len()).rev() {
            state = absorb(state, name[at]);
            if at == 0 || name[at - 1] == b'.' {
                any |= self.passes(finish(state));
            }
        }
        any
    }

    fn storage_bytes(&self) -> usize {
        self.blocks.len() * size_of::<[u64; 8]>()
    }
}

const NAME_HASH_SEED: u64 = 0xcbf2_9ce4_8422_2325;

/// Hashes from the last byte to the first, as [`Prefilter::may_contain_suffix`] reads suffixes.
#[inline]
fn name_hash(name: &[u8]) -> u64 {
    finish(
        name.iter()
            .rev()
            .fold(NAME_HASH_SEED, |state, byte| absorb(state, *byte)),
    )
}

#[inline]
fn absorb(state: u64, byte: u8) -> u64 {
    (state ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
}

/// Spreads every input bit over the whole word; the byte step alone leaves the high bits weak.
#[inline]
fn finish(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ hash >> 33
}

#[inline]
fn prefilter_bit(hash: u64, word: usize) -> u64 {
    1 << ((hash as u32).wrapping_mul(PREFILTER_SALTS[word]) >> 26)
}

#[derive(Debug, Default)]
/// The representation is chosen to fit the value range. Most sets have only a few sources or just
/// one; always using 4 bytes would waste memory in proportion to the entry count.
pub(crate) enum SourceTable {
    #[default]
    Empty,
    Uniform {
        value: u32,
        len: u32,
    },
    U8(Box<[u8]>),
    U16(Box<[u16]>),
    Dense(Box<[u32]>),
}

impl SourceTable {
    /// `len` is below `u32::MAX`, as every name count is.
    pub(crate) fn uniform(value: u32, len: usize) -> Self {
        if len == 0 {
            return Self::Empty;
        }
        Self::Uniform {
            value,
            len: len as u32,
        }
    }

    /// Picks the smallest representation for the value range.
    pub(crate) fn from_vec(values: Vec<u32>) -> Self {
        let Some(&value) = values.first() else {
            return Self::Empty;
        };
        if values.iter().all(|candidate| *candidate == value) {
            Self::Uniform {
                value,
                len: values.len() as u32,
            }
        } else if values
            .iter()
            .all(|candidate| *candidate == u32::MAX || *candidate < u8::MAX as u32)
        {
            Self::U8(
                values
                    .into_iter()
                    .map(|candidate| {
                        if candidate == u32::MAX {
                            u8::MAX
                        } else {
                            candidate as u8
                        }
                    })
                    .collect(),
            )
        } else if values
            .iter()
            .all(|candidate| *candidate == u32::MAX || *candidate < u16::MAX as u32)
        {
            Self::U16(
                values
                    .into_iter()
                    .map(|candidate| {
                        if candidate == u32::MAX {
                            u16::MAX
                        } else {
                            candidate as u16
                        }
                    })
                    .collect(),
            )
        } else {
            Self::Dense(values.into_boxed_slice())
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Uniform { len, .. } => *len as usize,
            Self::U8(values) => values.len(),
            Self::U16(values) => values.len(),
            Self::Dense(values) => values.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    fn get(&self, index: usize) -> Option<u32> {
        match self {
            Self::Empty => None,
            Self::Uniform { value, len } if index < *len as usize => Some(*value),
            Self::Uniform { .. } => None,
            Self::U8(values) => values.get(index).map(|value| {
                if *value == u8::MAX {
                    u32::MAX
                } else {
                    u32::from(*value)
                }
            }),
            Self::U16(values) => values.get(index).map(|value| {
                if *value == u16::MAX {
                    u32::MAX
                } else {
                    u32::from(*value)
                }
            }),
            Self::Dense(values) => values.get(index).copied(),
        }
    }

    fn storage_bytes(&self) -> usize {
        match self {
            Self::U8(values) => std::mem::size_of_val(&**values),
            Self::U16(values) => std::mem::size_of_val(&**values),
            Self::Dense(values) => std::mem::size_of_val(&**values),
            Self::Empty | Self::Uniform { .. } => 0,
        }
    }

    fn wire_kind(&self) -> u8 {
        match self {
            Self::Empty => SOURCE_EMPTY,
            Self::Uniform { .. } => SOURCE_UNIFORM,
            Self::U8(_) => SOURCE_U8,
            Self::U16(_) => SOURCE_U16,
            Self::Dense(_) => SOURCE_U32,
        }
    }

    fn wire_len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Uniform { .. } => Some(size_of::<u32>()),
            Self::U8(values) => Some(values.len()),
            Self::U16(values) => values.len().checked_mul(size_of::<u16>()),
            Self::Dense(values) => values.len().checked_mul(size_of::<u32>()),
        }
    }

    fn encode_payload_chunks(&self, output: &mut impl FnMut(&[u8])) {
        match self {
            Self::Empty => {}
            Self::Uniform { value, .. } => output(&value.to_le_bytes()),
            Self::U8(values) => output(values),
            Self::U16(values) => {
                for value in values {
                    output(&value.to_le_bytes());
                }
            }
            Self::Dense(values) => {
                for value in values {
                    output(&value.to_le_bytes());
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompactMatch<'a> {
    pub(crate) key: &'a str,
    pub(crate) index: usize,
}

#[cfg(test)]
fn rebuild_table(map: &CompactDomainMap) -> Option<DomainTable> {
    let mut table = DomainTable::default();
    table.reserve(map.len());
    map.for_each_entry(|_, key, source| {
        table.insert_if_absent(key, source);
    })
    .ok()?;
    Some(table)
}

fn rebuild_input_table(domains: &str, offsets: &[u32], sources: &SourceTable) -> DomainTable {
    let mut table = DomainTable::default();
    table.reserve(offsets.len().saturating_sub(1));
    for (index, window) in offsets.windows(2).enumerate() {
        let (start, end) = (window[0] as usize, window[1] as usize);
        let Some(key) = domains.get(start..end) else {
            continue;
        };
        if let Some(source) = sources.get(index) {
            table.insert_if_absent(key, source);
        }
    }
    table
}

fn collect_sources(sorted: &SortedDomains) -> SourceTable {
    let mut sources = SourceTableBuilder::with_capacity(sorted.len());
    for (_, source) in sorted.iter() {
        sources.push(source);
    }
    sources.finish()
}

/// Collects one source per name in order, keeping a single value until a second one appears.
pub(crate) struct SourceTableBuilder {
    capacity: usize,
    uniform: Option<(u32, usize)>,
    dense: Vec<u32>,
}

impl SourceTableBuilder {
    /// `capacity` is the most names that will be pushed.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            uniform: None,
            dense: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, source: u32) {
        match self.uniform {
            None => self.uniform = Some((source, 1)),
            Some((value, count)) if self.dense.is_empty() && value == source => {
                self.uniform = Some((value, count + 1));
            }
            Some((value, count)) if self.dense.is_empty() => {
                self.dense.reserve_exact(self.capacity);
                self.dense.resize(count, value);
                self.dense.push(source);
            }
            Some(_) => self.dense.push(source),
        }
    }

    pub(crate) fn finish(self) -> SourceTable {
        match self.uniform {
            None => SourceTable::Empty,
            Some((value, len)) if self.dense.is_empty() => SourceTable::uniform(value, len),
            Some(_) => SourceTable::from_vec(self.dense),
        }
    }
}

/// Picks from a sample whether going through a small contiguous input beats overlapping the large
/// builder with the sorted table. Random or DGA lists build large automata, so dropping the 16-byte
/// sorted entries first is better; lists whose suffixes overlap well build small automata, so
/// building straight from the source has a lower peak.
fn staging_reduces_peak(sorted: &SortedDomains, total_bytes: usize) -> bool {
    const SAMPLE_ENTRIES: usize = 32 * 1024;
    if sorted.len() <= SAMPLE_ENTRIES {
        return false;
    }

    let mut sample = DawgBuilder::new();
    for (domain, _) in sorted.iter().take(SAMPLE_ENTRIES) {
        sample.insert_reversed(domain.as_bytes());
    }
    sample.complete();
    let (states, labels, targets, outputs, _) = sample.finish_completed();
    let sample_bytes = states.len() * size_of::<PackedState>()
        + labels.len()
        + targets.len() * size_of::<u32>()
        + outputs.len() * size_of::<u32>();
    staging_beats_direct(
        sample_bytes as u64,
        SAMPLE_ENTRIES as u64,
        sorted.len() as u64,
        total_bytes as u64,
    )
}

/// Whether the builder estimate scaled up from the sample exceeds the contiguous input. Counted in
/// u64, not usize: sample bytes times entries easily passes 4 GiB, and on 32-bit platforms a
/// saturated value becomes smaller after dividing by the sample count. That flips the decision, so
/// the platform with the least memory would pick the higher peak. `sample_entries` must not be 0.
fn staging_beats_direct(
    sample_bytes: u64,
    sample_entries: u64,
    entries: u64,
    total_bytes: u64,
) -> bool {
    let estimated_builder = sample_bytes
        .saturating_mul(entries)
        .div_ceil(sample_entries.max(1));
    let staged_input = total_bytes.saturating_add(
        entries
            .saturating_add(1)
            .saturating_mul(size_of::<u32>() as u64),
    );
    estimated_builder > staged_input
}

impl CompactDomainMap {
    #[inline]
    fn header(&self, at: usize) -> Option<u16> {
        let bytes = self.states.get(at..at.checked_add(STATE_HEADER_BYTES)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    #[inline]
    fn block(&self, at: usize) -> Option<Block<'_>> {
        let header = self.header(at)?;
        let labels_at = at + STATE_HEADER_BYTES;
        let count = usize::from(header & HEADER_COUNT_MASK);
        let edges_at = labels_at + count;
        Some(Block {
            labels: self.states.get(labels_at..edges_at)?,
            edges: self
                .states
                .get(edges_at..edges_at + count * EDGE_RECORD_BYTES)?,
            terminal: header & HEADER_TERMINAL != 0,
        })
    }

    /// Every block with its position, in layout order, up to the first one that does not fit.
    fn blocks(&self) -> impl Iterator<Item = (usize, Block<'_>)> + '_ {
        let mut at = 0usize;
        std::iter::from_fn(move || {
            let block = self.block(at)?;
            let here = at;
            at += block.len();
            Some((here, block))
        })
    }

    #[inline]
    /// Empty when there are none.
    fn edge_tail(&self, at: u32) -> Option<&[u8]> {
        let at = at as usize;
        if at == 0 {
            return Some(&[]);
        }
        let length = *self.tail_bytes.get(at)? as usize;
        self.tail_bytes.get(at + 1..at + 1 + length)
    }

    #[inline]
    fn terminal(&self, at: usize) -> bool {
        self.header(at)
            .is_some_and(|header| header & HEADER_TERMINAL != 0)
    }

    /// Folds branchless intermediate states so one edge consumes several bytes, then writes every
    /// remaining state as one block. A state with one outgoing edge, not terminal, and no rank to
    /// add is only a pass-through, yet it would cost a header and an edge record for one byte of
    /// information. Each such run is stored once after the leading edge's label, and several edges
    /// can point at the same run.
    fn lay_out(
        states: &[PackedState],
        edge_labels: &[u8],
        edge_targets: &[u32],
        edge_outputs: &[u32],
    ) -> (Box<[u8]>, Box<[u8]>) {
        // The root is never folded; folding it would lose the start.
        let passthrough = |index: usize| -> bool {
            if index == 0 {
                return false;
            }
            let state = states[index];
            state.edge_count() == 1
                && !state.terminal()
                && edge_outputs[state.first_edge as usize] == 0
        };

        // A state where folding stopped at the length limit must stay: removing it as a
        // pass-through would leave that edge with no target. So where folding stops is settled
        // first, and positions come after.
        let mut keep: Vec<bool> = (0..states.len()).map(|index| !passthrough(index)).collect();
        let mut pending: Vec<usize> = (0..states.len()).filter(|index| keep[*index]).collect();
        while let Some(index) = pending.pop() {
            let state = states[index];
            let first = state.first_edge as usize;
            for edge in first..first + state.edge_count() {
                let mut walk = edge_targets[edge] as usize;
                let mut length = 0usize;
                while !keep[walk] && length < MAX_EDGE_TAIL {
                    length += 1;
                    walk = edge_targets[states[walk].first_edge as usize] as usize;
                }
                if !keep[walk] {
                    keep[walk] = true;
                    pending.push(walk);
                }
            }
        }

        // Blocks follow in state order, so every position is known before any block is written.
        let mut block_at = vec![NONE; states.len()];
        let mut size = 0usize;
        for index in 0..states.len() {
            if keep[index] {
                block_at[index] = size as u32;
                size += STATE_HEADER_BYTES + states[index].edge_count() * (1 + EDGE_RECORD_BYTES);
            }
        }
        debug_assert!(size <= u32::MAX as usize, "callers check blocks_fit");

        let mut blocks = Vec::with_capacity(size);
        // Position 0 is left empty so it cannot collide with the none marker.
        let mut tail_bytes = vec![0u8];
        let mut tail_at = vec![NONE; states.len()];
        for index in 0..states.len() {
            if !keep[index] {
                continue;
            }
            let state = states[index];
            let first = state.first_edge as usize;
            let end = first + state.edge_count();
            let terminal = if state.terminal() { HEADER_TERMINAL } else { 0 };
            blocks.extend_from_slice(&(state.edge_count() as u16 | terminal).to_le_bytes());
            blocks.extend_from_slice(&edge_labels[first..end]);
            for edge in first..end {
                let entry = edge_targets[edge] as usize;
                let mut walk = entry;
                let mut length = 0usize;
                while !keep[walk] && length < MAX_EDGE_TAIL {
                    length += 1;
                    walk = edge_targets[states[walk].first_edge as usize] as usize;
                }
                let tail = if length == 0 {
                    0
                } else if tail_at[entry] != NONE {
                    tail_at[entry]
                } else {
                    let at = tail_bytes.len() as u32;
                    tail_at[entry] = at;
                    tail_bytes.push(length as u8);
                    let mut cursor = entry;
                    for _ in 0..length {
                        let only = states[cursor].first_edge as usize;
                        tail_bytes.push(edge_labels[only]);
                        cursor = edge_targets[only] as usize;
                    }
                    at
                };
                blocks.extend_from_slice(&block_at[walk].to_le_bytes());
                blocks.extend_from_slice(&edge_outputs[edge].to_le_bytes());
                blocks.extend_from_slice(&tail.to_le_bytes());
            }
        }
        debug_assert_eq!(blocks.len(), size);
        (blocks.into_boxed_slice(), tail_bytes.into_boxed_slice())
    }

    /// After building, checks that every entry is found again at its own rank. If any is not,
    /// compaction is abandoned and the table is returned as is: using more memory beats silently
    /// using a wrong set.
    pub(crate) fn try_from_table(table: DomainTable) -> Result<Self, DomainTable> {
        if table.is_empty() {
            return Ok(Self::default());
        }
        if table.len() > u32::MAX as usize {
            return Err(table);
        }
        Self::try_from_sorted(table.into_sorted(reverse_cmp))
    }

    /// Takes names sorted with [`reverse_cmp`], each once.
    pub(crate) fn try_from_sorted(sorted: SortedDomains) -> Result<Self, DomainTable> {
        let entry_count = sorted.len();
        let fallback = |sorted: &SortedDomains| {
            let mut table = DomainTable::default();
            table.reserve(entry_count);
            for (domain, source) in sorted.iter() {
                table.insert_if_absent(domain, source);
            }
            table
        };
        if entry_count == 0 {
            return Ok(Self::default());
        }
        let total_bytes = sorted
            .iter()
            .try_fold(0usize, |total, (key, _)| total.checked_add(key.len()))
            .filter(|total| blocks_fit(*total));
        let Some(total_bytes) = total_bytes else {
            return Err(fallback(&sorted));
        };

        let sources = collect_sources(&sorted);
        if staging_reduces_peak(&sorted, total_bytes) {
            let (domains, offsets) = sorted.into_staged(total_bytes);
            return Self::try_from_staged(domains, offsets, sources);
        }
        let mut builder = DawgBuilder::new();
        for (domain, _) in sorted.iter() {
            builder.insert_reversed(domain.as_bytes());
        }
        builder.complete();
        if !sorted
            .iter()
            .all(|(domain, _)| builder.contains_reversed(domain.as_bytes()))
        {
            return Err(fallback(&sorted));
        }
        drop(sorted);
        Ok(Self::from_builder(builder, sources))
    }

    /// Takes names back to back, sorted with [`reverse_cmp`] and each once, with `offsets` holding
    /// where each starts followed by the total length, and one source per name.
    pub(crate) fn try_from_staged(
        domains: String,
        offsets: Vec<u32>,
        sources: SourceTable,
    ) -> Result<Self, DomainTable> {
        if offsets.len() < 2 {
            return Ok(Self::default());
        }
        if !offsets
            .last()
            .is_some_and(|total| blocks_fit(*total as usize))
        {
            return Err(rebuild_input_table(&domains, &offsets, &sources));
        }
        let mut builder = DawgBuilder::new();
        for window in offsets.windows(2) {
            let (start, end) = (window[0] as usize, window[1] as usize);
            builder.insert_reversed(&domains.as_bytes()[start..end]);
        }
        builder.complete();
        if !offsets.windows(2).all(|window| {
            let (start, end) = (window[0] as usize, window[1] as usize);
            builder.contains_reversed(&domains.as_bytes()[start..end])
        }) {
            return Err(rebuild_input_table(&domains, &offsets, &sources));
        }
        drop(domains);
        drop(offsets);
        Ok(Self::from_builder(builder, sources))
    }

    fn from_builder(builder: DawgBuilder, sources: SourceTable) -> Self {
        let (states, edge_labels, edge_targets, edge_outputs, root_terms) =
            builder.finish_completed();
        assert_eq!(
            root_terms,
            sources.len() as u32,
            "Validated compact filter item count changed while packing"
        );
        let (blocks, tail_bytes) =
            Self::lay_out(&states, &edge_labels, &edge_targets, &edge_outputs);
        drop(states);
        drop(edge_labels);
        drop(edge_targets);
        drop(edge_outputs);
        Self {
            states: blocks,
            tail_bytes,
            prefilter: Prefilter::default(),
            sources,
        }
        .with_prefilter()
    }

    fn with_prefilter(mut self) -> Self {
        if let Some(mut prefilter) = Prefilter::for_names(self.len()) {
            if self
                .for_each_entry(|_, key, _| prefilter.insert(key.as_bytes()))
                .is_ok()
            {
                self.prefilter = prefilter;
            }
        }
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.sources.len()
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.states.len()
            + self.tail_bytes.len()
            + self.prefilter.storage_bytes()
            + self.sources.storage_bytes()
    }

    pub(crate) fn source(&self, index: usize) -> Option<u32> {
        self.sources.get(index)
    }

    /// For statistics without keeping the strings.
    pub(crate) fn indexed_sources(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        (0..self.len()).filter_map(|index| self.source(index).map(|source| (index, source)))
    }

    /// Rebuilds every name the automaton accepts, in rank order. This is a cold path, used only to
    /// turn the set back into a table for edits or to name hits in reports; the query path uses
    /// slices of its input and never walks this.
    ///
    /// Not recursive: a corrupt cache or a long test key must not exhaust the call stack.
    pub(crate) fn for_each_entry(
        &self,
        mut visitor: impl FnMut(usize, &str, u32),
    ) -> Result<(), &'static str> {
        if self.states.is_empty() {
            return if self.sources.is_empty() {
                Ok(())
            } else {
                Err("Empty automaton still has source entries")
            };
        }

        let mut reversed = Vec::new();
        let mut forward = Vec::new();
        // The fifth value is how many bytes were pushed on entering this slot. One edge carries
        // several bytes, so popping a single byte on the way out would corrupt the name.
        let mut stack = vec![(0usize, 0usize, 0u32, false, 0usize)];
        while !stack.is_empty() {
            let frame_index = stack.len() - 1;
            let (at, next_edge, rank, terminal_emitted, _) = stack[frame_index];
            let block = self
                .block(at)
                .ok_or("Automaton traversal state is out of range")?;
            if !terminal_emitted {
                stack[frame_index].3 = true;
                if block.terminal {
                    let index = rank as usize;
                    let source = self.source(index).ok_or("Automaton rank has no source")?;
                    forward.clear();
                    forward.extend(reversed.iter().rev().copied());
                    let key = std::str::from_utf8(&forward)
                        .map_err(|_| "Domain rebuilt from the automaton is not UTF-8")?;
                    visitor(index, key, source);
                }
                continue;
            }

            if next_edge < block.labels.len() {
                stack[frame_index].1 += 1;
                let (target, output, tail) = block
                    .edge(next_edge)
                    .ok_or("Automaton edge has no record")?;
                let child_rank = rank
                    .checked_add(output)
                    .ok_or("Automaton traversal rank overflowed")?;
                reversed.push(block.labels[next_edge]);
                let tail = self
                    .edge_tail(tail)
                    .ok_or("Could not read automaton edge tail bytes")?;
                reversed.extend_from_slice(tail);
                stack.push((target as usize, 0, child_rank, false, 1 + tail.len()));
                continue;
            }

            let (_, _, _, _, pushed) = stack.pop().unwrap_or((0, 0, 0, false, 0));
            if !stack.is_empty() {
                reversed.truncate(reversed.len().saturating_sub(pushed));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), &'static str> {
        let encoded_len = self
            .encoded_len()
            .ok_or("Compact map size computation overflowed")?;
        if encoded_len > MAX_ENCODED_MAP_BYTES {
            return Err("Compact filter map is too large");
        }
        output
            .try_reserve(encoded_len)
            .map_err(|_| "Out of memory storing the compact filter map")?;
        self.encode_chunks(&mut |bytes| output.extend_from_slice(bytes))
    }

    pub(crate) fn encode_chunks(&self, output: &mut impl FnMut(&[u8])) -> Result<(), &'static str> {
        let encoded_len = self
            .encoded_len()
            .ok_or("Compact map size computation overflowed")?;
        if encoded_len > MAX_ENCODED_MAP_BYTES {
            return Err("Compact filter map is too large");
        }
        for value in [self.states.len(), self.sources.len(), self.tail_bytes.len()] {
            let value =
                u32::try_from(value).map_err(|_| "Compact filter map length exceeds 32 bits")?;
            output(&value.to_le_bytes());
        }
        output(&[self.sources.wire_kind()]);
        output(&self.states);
        output(&self.tail_bytes);
        self.sources.encode_payload_chunks(output);
        Ok(())
    }

    /// Validates the whole structure after reading: block bounds, edge targets, cycles,
    /// reachability, and partial ranks. Using it with any of these wrong would send the verdict
    /// path into an infinite loop or a wrong read.
    pub(crate) fn decode_from(input: &mut &[u8]) -> Result<Self, &'static str> {
        let states_len = read_u32(input)? as usize;
        let entries_len = read_u32(input)? as usize;
        let tail_len = read_u32(input)? as usize;
        let source_kind = read_u8(input)?;
        if states_len == 0 && entries_len == 0 && tail_len == 0 {
            return if source_kind == SOURCE_EMPTY {
                Ok(Self::default())
            } else {
                Err("Invalid source format for an empty compact map")
            };
        }
        if states_len == 0 || entries_len == 0 {
            return Err("Compact domain map state is incomplete");
        }
        let source_bytes = source_wire_len(source_kind, entries_len)?;
        let body_len = states_len
            .checked_add(tail_len)
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .ok_or("Could not compute compact domain map size")?;
        let encoded_len = MAP_HEADER_BYTES
            .checked_add(body_len)
            .ok_or("Could not compute compact domain map size")?;
        if encoded_len > MAX_ENCODED_MAP_BYTES || body_len > input.len() {
            return Err("Invalid compact map serialized length");
        }

        let states = copy_bytes(
            input,
            states_len,
            "Out of memory storing compact filter states",
        )?;
        let tail_bytes = copy_bytes(
            input,
            tail_len,
            "Out of memory storing compact filter tail bytes",
        )?;
        let sources = decode_source_table(
            input,
            entries_len,
            source_kind,
            "Out of memory storing compact filter sources",
        )?;
        let mut map = Self {
            states: states.into_boxed_slice(),
            tail_bytes: tail_bytes.into_boxed_slice(),
            prefilter: Prefilter::default(),
            sources,
        };
        // Validation visits every name anyway, so the prefilter is filled on the way.
        let mut prefilter = Prefilter::for_names(map.len());
        map.validate_decoded(|name| {
            if let Some(prefilter) = prefilter.as_mut() {
                prefilter.insert(name.as_bytes());
            }
        })?;
        map.prefilter = prefilter.unwrap_or_default();
        Ok(map)
    }

    pub(crate) fn lookup_exact<'a>(&self, domain: &'a str) -> Option<CompactMatch<'a>> {
        if self.states.is_empty() || !self.prefilter.may_contain(domain.as_bytes()) {
            return None;
        }
        let bytes = domain.as_bytes();
        let mut state = 0usize;
        let mut rank = 0u32;
        let mut eaten = 0usize;
        while eaten < bytes.len() {
            (state, rank, eaten) = self.step(state, rank, bytes, eaten)?;
        }
        if !self.terminal(state) {
            return None;
        }
        self.matched_entry(rank, domain)
    }

    /// Matches only at label boundaries; otherwise evil-example.com would match an example.com
    /// rule.
    pub(crate) fn lookup_suffix<'a>(&self, domain: &'a str) -> Option<CompactMatch<'a>> {
        if self.states.is_empty() || !self.prefilter.may_contain_suffix(domain.as_bytes()) {
            return None;
        }
        let bytes = domain.as_bytes();
        let mut state = 0usize;
        let mut rank = 0u32;
        let mut matched = None;

        let mut consumed = 0usize;
        while consumed < bytes.len() {
            let Some(next) = self.step(state, rank, bytes, consumed) else {
                break;
            };
            (state, rank, consumed) = next;

            let remaining = bytes.len() - consumed;
            let label_boundary = remaining == 0 || bytes[remaining - 1] == b'.';
            if label_boundary && self.terminal(state) {
                matched = Some((rank, remaining));
            }
        }

        let (rank, start) = matched?;
        self.matched_entry(rank, domain.get(start..)?)
    }

    fn matched_entry<'a>(&self, rank: u32, key: &'a str) -> Option<CompactMatch<'a>> {
        let index = rank as usize;
        self.sources.get(index)?;
        Some(CompactMatch { key, index })
    }

    fn encoded_len(&self) -> Option<usize> {
        MAP_HEADER_BYTES
            .checked_add(self.states.len())?
            .checked_add(self.tail_bytes.len())?
            .checked_add(self.sources.wire_len()?)
    }

    fn validate_decoded(&self, mut each_name: impl FnMut(&str)) -> Result<(), &'static str> {
        // The blocks must parse one after another up to the end, and an edge may point only where
        // one starts; any other position would read labels out of record bytes.
        let len = self.states.len();
        let mut starts = filled_vec(
            len.div_ceil(64),
            0u64,
            "Out of memory storing compact filter state positions",
        )?;
        let mut state_count = 0usize;
        let mut end = 0usize;
        for (at, block) in self.blocks() {
            let header = self.header(at).unwrap_or(u16::MAX);
            if header & !(HEADER_COUNT_MASK | HEADER_TERMINAL) != 0 {
                return Err("Compact filter state header has unused bits set");
            }
            if block.labels.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err("Compact filter edge labels are not sorted");
            }
            starts[at / 64] |= 1 << (at % 64);
            state_count += 1;
            end = at + block.len();
        }
        if end != len {
            return Err("Compact filter state blocks do not fill the state data");
        }
        let mut before = reserved_vec(
            starts.len(),
            "Out of memory storing compact filter state positions",
        )?;
        let mut seen = 0usize;
        for word in &starts {
            before.push(seen);
            seen += word.count_ones() as usize;
        }
        let index_of = |at: u32| -> Option<usize> {
            let at = at as usize;
            let word = *starts.get(at / 64)?;
            let bit = at % 64;
            (word >> bit & 1 == 1)
                .then(|| before[at / 64] + (word & ((1u64 << bit) - 1)).count_ones() as usize)
        };

        for (_, block) in self.blocks() {
            for position in 0..block.labels.len() {
                let (target, _, tail) = block
                    .edge(position)
                    .ok_or("Compact filter edge record is missing")?;
                if index_of(target).is_none() {
                    return Err("Invalid compact filter edge target");
                }
                // Position 0 is the none marker and must not be read as bytes.
                if tail != 0 {
                    let tail = tail as usize;
                    let Some(length) = self.tail_bytes.get(tail).map(|value| *value as usize)
                    else {
                        return Err("Compact filter edge points to a missing tail");
                    };
                    if length == 0 || tail + 1 + length > self.tail_bytes.len() {
                        return Err("Invalid compact filter tail length");
                    }
                }
            }
        }

        const VISITING: u32 = NONE - 1;
        let mut calculated = filled_vec(
            state_count,
            NONE,
            "Out of memory storing compact filter graph counts",
        )?;
        let mut stack = reserved_vec(
            state_count.min(256),
            "Out of memory storing the compact filter traversal stack",
        )?;
        let target_index = |block: Block<'_>, position: usize| -> Result<usize, &'static str> {
            let (target, _, _) = block
                .edge(position)
                .ok_or("Compact filter edge record is missing")?;
            index_of(target).ok_or("Invalid compact filter edge target")
        };
        calculated[0] = VISITING;
        stack.push((0usize, 0usize));
        while let Some((at, next_edge)) = stack.last_mut() {
            let at = *at;
            let block = self
                .block(at)
                .ok_or("Compact filter state is out of range")?;
            if *next_edge < block.labels.len() {
                let (target_at, _, _) = block
                    .edge(*next_edge)
                    .ok_or("Compact filter edge record is missing")?;
                *next_edge += 1;
                let target = index_of(target_at).ok_or("Invalid compact filter edge target")?;
                match calculated[target] {
                    NONE => {
                        calculated[target] = VISITING;
                        if stack.len() == stack.capacity() {
                            stack.try_reserve(1).map_err(|_| {
                                "Out of memory storing the compact filter traversal stack"
                            })?;
                        }
                        stack.push((target_at as usize, 0));
                    }
                    VISITING => return Err("Compact automaton has a cycle"),
                    _ => {}
                }
                continue;
            }
            let mut terms = u64::from(block.terminal);
            for position in 0..block.labels.len() {
                terms = terms
                    .checked_add(u64::from(calculated[target_index(block, position)?]))
                    .ok_or("Compact subtree term count overflowed")?;
            }
            let terms = u32::try_from(terms)
                .map_err(|_| "Compact filter subtree has too many terminal entries")?;
            let index = index_of(at as u32).ok_or("Compact filter state is out of range")?;
            calculated[index] = terms;
            stack.pop();
        }
        if calculated.iter().any(|count| *count >= VISITING)
            || calculated.first().map(|count| *count as usize) != Some(self.sources.len())
        {
            return Err("Compact automaton reachable and final state counts do not match");
        }

        for (_, block) in self.blocks() {
            let mut expected = u32::from(block.terminal);
            for position in 0..block.labels.len() {
                let (_, output, _) = block
                    .edge(position)
                    .ok_or("Compact filter edge record is missing")?;
                if output != expected {
                    return Err("Compact edge output rank does not match");
                }
                expected = expected
                    .checked_add(calculated[target_index(block, position)?])
                    .ok_or("Compact edge output computation overflowed")?;
            }
        }
        let mut expected_index = 0usize;
        let mut ranks_match = true;
        self.for_each_entry(|index, key, _| {
            each_name(key);
            if index != expected_index
                || self.lookup_exact(key).map(|found| found.index) != Some(index)
            {
                ranks_match = false;
            }
            expected_index += 1;
        })?;
        if !ranks_match || expected_index != self.len() {
            return Err("Compact domain and automaton ranks do not match");
        }
        Ok(())
    }

    /// Reads the name from the end and advances one edge. Returns the next state, the summed rank,
    /// and the new consumed count; one edge can consume several bytes.
    #[inline]
    fn step(
        &self,
        at: usize,
        rank: u32,
        bytes: &[u8],
        eaten: usize,
    ) -> Option<(usize, u32, usize)> {
        let block = self.block(at)?;
        let labels = block.labels;
        let label = *bytes.get(bytes.len().checked_sub(eaten + 1)?)?;
        let position = match labels.len() {
            0 => return None,
            1 if labels[0] == label => 0,
            1 => return None,
            2..=8 => labels.iter().position(|candidate| *candidate == label)?,
            _ => labels.binary_search(&label).ok()?,
        };

        let (target, output, tail) = block.edge(position)?;
        let mut eaten = eaten + 1;
        for expected in self.edge_tail(tail)? {
            if *bytes.get(bytes.len().checked_sub(eaten + 1)?)? != *expected {
                return None;
            }
            eaten += 1;
        }
        Some((target as usize, rank + output, eaten))
    }

    #[cfg(test)]
    fn state_count(&self) -> usize {
        self.blocks().count()
    }
}

/// Block positions are `u32`. Every edge consumes at least one name byte and every state but the
/// root is entered by an edge, so the blocks take at most one header and one labelled edge record
/// per name byte, plus the root header.
fn blocks_fit(name_bytes: usize) -> bool {
    name_bytes
        .checked_mul(STATE_HEADER_BYTES + 1 + EDGE_RECORD_BYTES)
        .and_then(|bytes| bytes.checked_add(STATE_HEADER_BYTES))
        .is_some_and(|bytes| bytes <= u32::MAX as usize)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, &'static str> {
    let bytes = take_bytes(input, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u8(input: &mut &[u8]) -> Result<u8, &'static str> {
    Ok(take_bytes(input, 1)?[0])
}

fn take_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], &'static str> {
    let bytes = input.get(..len).ok_or("Compact map data is truncated")?;
    *input = &input[len..];
    Ok(bytes)
}

/// Fails past the limit.
fn reserved_vec<T>(len: usize, error: &'static str) -> Result<Vec<T>, &'static str> {
    let mut values = Vec::new();
    values.try_reserve_exact(len).map_err(|_| error)?;
    Ok(values)
}

fn filled_vec<T: Clone>(len: usize, value: T, error: &'static str) -> Result<Vec<T>, &'static str> {
    let mut values = reserved_vec(len, error)?;
    values.resize(len, value);
    Ok(values)
}

fn copy_bytes(input: &mut &[u8], len: usize, error: &'static str) -> Result<Vec<u8>, &'static str> {
    let source = take_bytes(input, len)?;
    let mut bytes = reserved_vec(len, error)?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

fn read_u32_vec(
    input: &mut &[u8],
    len: usize,
    error: &'static str,
) -> Result<Vec<u32>, &'static str> {
    let mut values = reserved_vec(len, error)?;
    for _ in 0..len {
        values.push(read_u32(input)?);
    }
    Ok(values)
}

/// Rejects unknown or nonminimal representations.
fn decode_source_table(
    input: &mut &[u8],
    len: usize,
    kind: u8,
    error: &'static str,
) -> Result<SourceTable, &'static str> {
    match kind {
        SOURCE_UNIFORM => Ok(SourceTable::Uniform {
            value: read_u32(input)?,
            len: len as u32,
        }),
        SOURCE_U8 => {
            let values = copy_bytes(input, len, error)?;
            if values.windows(2).all(|pair| pair[0] == pair[1]) {
                return Err("Source array is not in minimal-width uniform form");
            }
            Ok(SourceTable::U8(values.into_boxed_slice()))
        }
        SOURCE_U16 => {
            let mut values = reserved_vec(len, error)?;
            let mut first = None;
            let mut uniform = true;
            let mut needs_u16 = false;
            for _ in 0..len {
                let bytes = take_bytes(input, 2)?;
                let value = u16::from_le_bytes([bytes[0], bytes[1]]);
                uniform &= first.is_none_or(|candidate| candidate == value);
                first.get_or_insert(value);
                needs_u16 |= value != u16::MAX && value >= u8::MAX as u16;
                values.push(value);
            }
            if uniform || !needs_u16 {
                return Err("Source array is not in minimal-width u16 form");
            }
            Ok(SourceTable::U16(values.into_boxed_slice()))
        }
        SOURCE_U32 => {
            let values = read_u32_vec(input, len, error)?;
            let first = values[0];
            let uniform = values.iter().all(|value| *value == first);
            let needs_u32 = values
                .iter()
                .any(|value| *value != u32::MAX && *value >= u16::MAX as u32);
            if uniform || !needs_u32 {
                return Err("Source array is not in minimal-width u32 form");
            }
            Ok(SourceTable::Dense(values.into_boxed_slice()))
        }
        _ => Err("Invalid compact map source format tag"),
    }
}

fn source_wire_len(kind: u8, len: usize) -> Result<usize, &'static str> {
    if len == 0 {
        return if kind == SOURCE_EMPTY {
            Ok(0)
        } else {
            Err("Invalid format tag for an empty source array")
        };
    }
    match kind {
        SOURCE_UNIFORM => Ok(size_of::<u32>()),
        SOURCE_U8 => Ok(len),
        SOURCE_U16 => len
            .checked_mul(size_of::<u16>())
            .ok_or("Could not compute compact filter u16 source length"),
        SOURCE_U32 => len
            .checked_mul(size_of::<u32>())
            .ok_or("Could not compute compact filter u32 source length"),
        _ => Err("Invalid compact map source format tag"),
    }
}

/// Compares strings by their reversed bytes. Read from the end, domains under the same parent sit
/// together, which is what lets states sharing a suffix merge.
pub(crate) fn reverse_cmp(left: &str, right: &str) -> Ordering {
    left.as_bytes()
        .iter()
        .rev()
        .cmp(right.as_bytes().iter().rev())
}

#[derive(Debug)]
/// Reuses slots through a free list.
struct EdgeArena {
    label: Vec<u8>,
    target: Vec<u32>,
    next: Vec<u32>,
    free: u32,
    live: usize,
}

impl EdgeArena {
    fn new() -> Self {
        Self {
            label: Vec::new(),
            target: Vec::new(),
            next: Vec::new(),
            free: NONE,
            live: 0,
        }
    }

    fn alloc(&mut self, label: u8, target: u32, next: u32) -> u32 {
        self.live += 1;
        if self.free != NONE {
            let cell = self.free as usize;
            self.free = self.next[cell];
            self.label[cell] = label;
            self.target[cell] = target;
            self.next[cell] = next;
            return cell as u32;
        }
        let cell = self.label.len() as u32;
        self.label.push(label);
        self.target.push(target);
        self.next.push(next);
        cell
    }

    fn release(&mut self, head: u32) {
        let mut cursor = head;
        while cursor != NONE {
            debug_assert!(self.live > 0);
            self.live -= 1;
            let following = self.next[cursor as usize];
            self.next[cursor as usize] = self.free;
            self.free = cursor;
            cursor = following;
        }
    }
}

#[derive(Debug)]
struct BuildState {
    terminal: bool,

    edge_head: u32,
    /// Next state of the same shape in the register.
    register_next: u32,
}

/// Pins the build state size; it scales load memory.
const _: () = assert!(size_of::<Option<BuildState>>() == 12);

impl BuildState {
    fn new() -> Self {
        Self {
            terminal: false,
            edge_head: NONE,
            register_next: NONE,
        }
    }
}

/// Builds a minimal acyclic automaton. Sorted input is inserted in order and the settled tail is
/// minimized right away; minimizing after inserting everything would need far more memory in
/// between.
struct DawgBuilder {
    states: Vec<Option<BuildState>>,
    free: Vec<u32>,
    edges: EdgeArena,

    buckets: Vec<u32>,
    registered: usize,
    path: Vec<u32>,
    /// The shared prefix with it is reused.
    previous: Vec<u8>,
}

impl DawgBuilder {
    fn new() -> Self {
        Self {
            states: vec![Some(BuildState::new())],
            free: Vec::new(),
            edges: EdgeArena::new(),
            buckets: vec![NONE; 1024],
            registered: 0,
            path: vec![0],
            previous: Vec::new(),
        }
    }

    /// The input must be sorted.
    fn insert_reversed(&mut self, domain: &[u8]) {
        let common = self
            .previous
            .iter()
            .zip(domain.iter().rev())
            .take_while(|(left, right)| left == right)
            .count();
        self.minimize(common);

        for &label in domain.iter().rev().skip(common) {
            let child = self.new_state();
            let parent = self.path[self.path.len() - 1];
            let head = self.state(parent).edge_head;
            let cell = self.edges.alloc(label, child, head);
            self.state_mut(parent).edge_head = cell;
            self.path.push(child);
        }
        let terminal = self.path[self.path.len() - 1];
        self.state_mut(terminal).terminal = true;

        self.previous.clear();
        self.previous.extend(domain.iter().rev().copied());
    }

    /// Minimizes what is left and makes the read-only graph used to check the input.
    fn complete(&mut self) {
        self.minimize(0);
        self.buckets = Vec::new();
        self.path.clear();
        self.previous.clear();
    }

    fn contains_reversed(&self, domain: &[u8]) -> bool {
        let mut state_id = 0u32;
        for label in domain.iter().rev() {
            let mut cursor = self.state(state_id).edge_head;
            let mut found = None;
            while cursor != NONE {
                let cell = cursor as usize;
                if self.edges.label[cell] == *label {
                    found = Some(self.edges.target[cell]);
                    break;
                }
                cursor = self.edges.next[cell];
            }
            let Some(next) = found else {
                return false;
            };
            state_id = next;
        }
        self.state(state_id).terminal
    }

    fn finish_completed(self) -> (Box<[PackedState]>, Box<[u8]>, Box<[u32]>, Box<[u32]>, u32) {
        self.pack(0)
    }

    /// Settles the states past the common prefix and merges equal ones.
    fn minimize(&mut self, prefix_len: usize) {
        while self.path.len() > prefix_len + 1 {
            let child = self.path.pop().unwrap_or(0);
            let canonical = self.register_state(child);
            let parent = self.path[self.path.len() - 1];

            let head = self.state(parent).edge_head;
            if head != NONE {
                debug_assert_eq!(self.edges.target[head as usize], child);
                self.edges.target[head as usize] = canonical;
            }
        }
    }

    /// Reuses an equal state if one exists; otherwise registers this one.
    fn register_state(&mut self, state_id: u32) -> u32 {
        let hash = self.state_hash(state_id);
        let mut candidate = self.buckets[(hash & self.bucket_mask()) as usize];
        while candidate != NONE {
            if self.states_equal(state_id, candidate) {
                let head = self.state(state_id).edge_head;
                self.edges.release(head);
                self.states[state_id as usize] = None;
                self.free.push(state_id);
                return candidate;
            }
            candidate = self.state(candidate).register_next;
        }

        if self.registered >= self.buckets.len() {
            self.grow_register();
        }
        let slot = (hash & self.bucket_mask()) as usize;
        self.state_mut(state_id).register_next = self.buckets[slot];
        self.buckets[slot] = state_id;
        self.registered += 1;
        state_id
    }

    #[inline]
    fn bucket_mask(&self) -> u64 {
        self.buckets.len() as u64 - 1
    }

    fn grow_register(&mut self) {
        let old = std::mem::take(&mut self.buckets);
        self.buckets = vec![NONE; old.len() * 2];
        let mask = self.bucket_mask();
        for head in old {
            let mut cursor = head;
            while cursor != NONE {
                let following = self.state(cursor).register_next;
                let slot = (self.state_hash(cursor) & mask) as usize;
                let previous_head = self.buckets[slot];
                self.state_mut(cursor).register_next = previous_head;
                self.buckets[slot] = cursor;
                cursor = following;
            }
        }
    }

    fn new_state(&mut self) -> u32 {
        let state = BuildState::new();
        if let Some(id) = self.free.pop() {
            self.states[id as usize] = Some(state);
            id
        } else {
            let id = self.states.len() as u32;
            self.states.push(Some(state));
            id
        }
    }

    fn state(&self, id: u32) -> &BuildState {
        self.states[id as usize]
            .as_ref()
            .expect("Active compact filter state must exist")
    }

    fn state_mut(&mut self, id: u32) -> &mut BuildState {
        self.states[id as usize]
            .as_mut()
            .expect("Active compact filter state must exist")
    }

    /// Same language: compares edges and the terminal flag.
    fn states_equal(&self, left: u32, right: u32) -> bool {
        if self.state(left).terminal != self.state(right).terminal {
            return false;
        }
        let mut left = self.state(left).edge_head;
        let mut right = self.state(right).edge_head;
        while left != NONE && right != NONE {
            let (left_cell, right_cell) = (left as usize, right as usize);
            if self.edges.label[left_cell] != self.edges.label[right_cell]
                || self.edges.target[left_cell] != self.edges.target[right_cell]
            {
                return false;
            }
            left = self.edges.next[left_cell];
            right = self.edges.next[right_cell];
        }
        left == right
    }

    fn state_hash(&self, id: u32) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        hash ^= u64::from(self.state(id).terminal);
        hash = hash.wrapping_mul(0x100000001b3);
        let mut cursor = self.state(id).edge_head;
        while cursor != NONE {
            let cell = cursor as usize;
            hash ^= self.edges.label[cell] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            for byte in self.edges.target[cell].to_le_bytes() {
                hash ^= byte as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            cursor = self.edges.next[cell];
        }
        hash
    }

    fn collect_edges(&self, state_id: u32, out: &mut Vec<u32>) {
        out.clear();
        let mut cursor = self.state(state_id).edge_head;
        while cursor != NONE {
            out.push(cursor);
            cursor = self.edges.next[cursor as usize];
        }
        out.reverse();
    }

    #[cold]
    #[inline(never)]
    fn pack(self, root: u32) -> (Box<[PackedState]>, Box<[u8]>, Box<[u32]>, Box<[u32]>, u32) {
        let live_states = self.states.len().saturating_sub(self.free.len());
        let mut remap = vec![NONE; self.states.len()];
        let mut chain = Vec::new();
        let mut states = vec![PackedState::new(0, 0, false); live_states];
        let mut edge_labels = Vec::with_capacity(self.edges.live);
        let mut edge_targets = Vec::with_capacity(self.edges.live);

        states[0].first_edge = root;
        remap[root as usize] = 0;
        let mut next_state = 1u32;
        let mut cursor = 0usize;
        while cursor < next_state as usize {
            let state_id = states[cursor].first_edge;
            self.collect_edges(state_id, &mut chain);
            states[cursor] = PackedState::new(
                edge_labels.len() as u32,
                chain.len(),
                self.state(state_id).terminal,
            );
            for &cell in &chain {
                let target = self.edges.target[cell as usize];
                if remap[target as usize] == NONE {
                    remap[target as usize] = next_state;
                    states[next_state as usize].first_edge = target;
                    next_state += 1;
                }
                edge_labels.push(self.edges.label[cell as usize]);
                edge_targets.push(remap[target as usize]);
            }
            cursor += 1;
        }
        states.truncate(next_state as usize);
        debug_assert_eq!(states.len(), live_states);
        debug_assert_eq!(edge_labels.len(), self.edges.live);
        drop(chain);
        drop(self);

        let counts = if states.is_empty() {
            Vec::new()
        } else {
            term_counts(remap, &states, &edge_targets)
        };
        let mut edge_outputs = Vec::with_capacity(edge_targets.len());
        for state in &states {
            let first = state.first_edge as usize;
            let end = first + state.edge_count();
            let mut output = u32::from(state.terminal());
            for &target in &edge_targets[first..end] {
                edge_outputs.push(output);
                output += counts[target as usize];
            }
        }
        let root_terms = counts.first().copied().unwrap_or(0);
        (
            states.into_boxed_slice(),
            edge_labels.into_boxed_slice(),
            edge_targets.into_boxed_slice(),
            edge_outputs.into_boxed_slice(),
            root_terms,
        )
    }
}

/// Counts the words reachable from each state. Summing the counts of the branches passed over
/// during a walk gives the position in sorted order.
fn term_counts(mut counts: Vec<u32>, states: &[PackedState], edge_targets: &[u32]) -> Vec<u32> {
    counts.truncate(states.len());
    counts.fill(NONE);
    let mut stack = vec![(0usize, false)];
    while let Some((state_index, expanded)) = stack.pop() {
        if counts[state_index] != NONE {
            continue;
        }
        let state = states[state_index];
        let first = state.first_edge as usize;
        let end = first + state.edge_count();
        if !expanded {
            stack.push((state_index, true));
            for &target in &edge_targets[first..end] {
                if counts[target as usize] == NONE {
                    stack.push((target as usize, false));
                }
            }
            continue;
        }

        let mut count = u64::from(state.terminal());
        for &target in &edge_targets[first..end] {
            count += u64::from(counts[target as usize]);
        }
        counts[state_index] = count as u32;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "빌더 계량 프로브: cargo test -p onetdns-filter --release -- --ignored --nocapture"]
    /// Growth here grows load memory.
    fn probe_dawg_builder_shape() {
        const N: u32 = 200_000;

        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let tlds = ["com", "net", "org", "io", "ru", "cn", "info"];
        let mut entries: Vec<(Box<str>, u32)> = (0..N)
            .map(|_| {
                let r = next();
                let len = 5 + (r % 9) as usize;
                let mut label = String::with_capacity(len);
                let mut bits = next();
                for _ in 0..len {
                    label.push((b'a' + (bits % 26) as u8) as char);
                    bits /= 26;
                    if bits == 0 {
                        bits = next();
                    }
                }
                let tld = tlds[(r >> 32) as usize % tlds.len()];
                (format!("{label}.{tld}").into_boxed_str(), 0u32)
            })
            .collect();
        entries.sort_unstable_by(|left, right| reverse_cmp(&left.0, &right.0));
        entries.dedup_by(|left, right| left.0 == right.0);
        entries.sort_unstable_by(|left, right| reverse_cmp(&left.0, &right.0));

        let mut builder = DawgBuilder::new();
        for (domain, _) in &entries {
            builder.insert_reversed(domain.as_bytes());
        }

        let slots = builder.states.len();
        let live = builder
            .states
            .iter()
            .filter(|state| state.is_some())
            .count();
        let mut edges_total = 0usize;
        let mut hist = [0usize; 6];
        let mut chain = Vec::new();
        for id in 0..slots as u32 {
            if builder.states[id as usize].is_none() {
                continue;
            }
            builder.collect_edges(id, &mut chain);
            edges_total += chain.len();
            let bucket = match chain.len() {
                0 => 0,
                1 => 1,
                2 => 2,
                3..=4 => 3,
                5..=8 => 4,
                _ => 5,
            };
            hist[bucket] += 1;
        }

        let arena_cells = builder.edges.label.len();
        println!("PROBE domains={N} slots={slots} live_states={live} edges={edges_total}");
        println!(
            "PROBE edge_hist 0={} 1={} 2={} 3-4={} 5-8={} 9+={}",
            hist[0], hist[1], hist[2], hist[3], hist[4], hist[5]
        );
        println!(
            "PROBE arena_cells={arena_cells} arena_bytes={} state_struct_bytes={} register_buckets={}",
            arena_cells * 9,
            slots * std::mem::size_of::<Option<BuildState>>(),
            builder.buckets.len(),
        );
    }

    fn compact(entries: &[(&str, u32)]) -> CompactDomainMap {
        CompactDomainMap::try_from_table(table_of(entries)).expect("작은 map은 압축 가능")
    }

    #[test]
    fn abandoning_compaction_restores_every_entry_with_its_source() {
        let entries = [
            ("ads.example.com", 7u32),
            ("a.example.com", 1),
            ("example.com", 2),
            ("com", 3),
            ("tracker.evil.test", 9),
            ("evil.test", 9),
        ];
        let map = CompactDomainMap::try_from_table(table_of(&entries)).expect("압축 가능");

        let restored = rebuild_table(&map).expect("오토마톤 언어 복원");
        assert_eq!(restored.len(), entries.len(), "항목 수가 보존돼야 한다");
        for (domain, source) in entries {
            assert_eq!(
                restored.get_key_value(domain),
                Some((domain, source)),
                "{domain}이(가) source와 함께 복원돼야 한다"
            );
        }
    }

    fn table_of(entries: &[(&str, u32)]) -> DomainTable {
        let mut table = DomainTable::default();
        for (domain, source) in entries {
            table.insert_if_absent(domain, *source);
        }
        table
    }

    fn table_from_reference(reference: &DomainMap) -> DomainTable {
        let mut table = DomainTable::default();
        for (domain, source) in reference {
            table.insert_if_absent(domain, *source);
        }
        table
    }

    fn source_payload_start(map: &CompactDomainMap) -> usize {
        MAP_HEADER_BYTES + map.states.len() + map.tail_bytes.len()
    }

    fn owned_entries(map: &CompactDomainMap) -> Vec<(String, u32)> {
        let mut entries = Vec::with_capacity(map.len());
        map.for_each_entry(|_, key, source| entries.push((key.to_string(), source)))
            .expect("정상 오토마톤 순회");
        entries
    }

    #[test]
    fn exact_and_longest_suffix_return_the_original_value() {
        let map = compact(&[
            ("example.com", 1),
            ("ads.example.com", 2),
            ("ample.com", 3),
            ("한글.example", 4),
        ]);

        let exact = map.lookup_exact("ads.example.com").expect("exact");
        assert_eq!(
            (exact.key, map.source(exact.index)),
            ("ads.example.com", Some(2))
        );
        assert!(map.lookup_exact("deep.ads.example.com").is_none());

        let suffix = map
            .lookup_suffix("deep.ads.example.com")
            .expect("longest suffix");
        assert_eq!(
            (suffix.key, map.source(suffix.index)),
            ("ads.example.com", Some(2))
        );
        assert_eq!(
            map.lookup_suffix("한글.example")
                .and_then(|item| map.source(item.index)),
            Some(4)
        );
    }

    #[test]
    fn matches_borrow_the_query_instead_of_retaining_domain_text() {
        let map = compact(&[("ads.example.com", 2)]);
        let query = String::from("deep.ads.example.com");
        let found = map.lookup_suffix(&query).expect("suffix");
        assert_eq!(found.key, "ads.example.com");
        let query_start = query.as_ptr() as usize;
        let query_end = query_start + query.len();
        let found_start = found.key.as_ptr() as usize;
        assert!(found_start >= query_start && found_start < query_end);
        assert_eq!(
            map.storage_bytes(),
            map.states.len()
                + map.tail_bytes.len()
                + map.prefilter.storage_bytes()
                + map.sources.storage_bytes(),
            "compact map에는 도메인 문자열이나 offset 배열을 상주시키지 않는다"
        );
    }

    #[test]
    fn uniform_sources_use_constant_storage_and_one_wire_value() {
        let map = compact(&[
            ("one.example", 17),
            ("two.example", 17),
            ("three.example", 17),
        ]);
        assert!(matches!(
            &map.sources,
            SourceTable::Uniform { value: 17, len: 3 }
        ));
        assert_eq!(map.sources.storage_bytes(), 0);

        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).unwrap();
        let source_start = source_payload_start(&map);
        assert_eq!(encoded[MAP_HEADER_BYTES - 1], 1, "uniform source tag");
        assert_eq!(&encoded[source_start..source_start + 4], &[17, 0, 0, 0]);
        assert_eq!(encoded.len(), source_start + 4);
        let mut input = encoded.as_slice();
        let decoded = CompactDomainMap::decode_from(&mut input).unwrap();
        assert!(input.is_empty());
        assert!(matches!(
            &decoded.sources,
            SourceTable::Uniform { value: 17, len: 3 }
        ));
        for domain in ["one.example", "two.example", "three.example"] {
            assert_eq!(
                decoded
                    .lookup_exact(domain)
                    .and_then(|found| decoded.source(found.index)),
                Some(17)
            );
        }
    }

    #[test]
    fn small_mixed_sources_use_one_byte_entries_and_preserve_no_source() {
        let map = compact(&[
            ("one.example", 1),
            ("two.example", 2),
            ("none.example", u32::MAX),
        ]);
        assert!(matches!(map.sources, SourceTable::U8(_)));
        assert_eq!(map.sources.storage_bytes(), 3);
        assert_eq!(
            map.lookup_exact("none.example")
                .and_then(|found| map.source(found.index)),
            Some(u32::MAX)
        );
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).unwrap();
        let expected = match &map.sources {
            SourceTable::U8(values) => values.as_ref(),
            _ => unreachable!(),
        };
        let source_start = source_payload_start(&map);
        assert_eq!(encoded[MAP_HEADER_BYTES - 1], 2, "u8 source tag");
        assert_eq!(
            &encoded[source_start..source_start + expected.len()],
            expected
        );
        assert_eq!(encoded.len(), source_start + expected.len());
        let decoded = CompactDomainMap::decode_from(&mut encoded.as_slice()).unwrap();
        assert!(matches!(decoded.sources, SourceTable::U8(_)));
        assert_eq!(
            decoded
                .lookup_exact("none.example")
                .and_then(|found| decoded.source(found.index)),
            Some(u32::MAX)
        );
    }

    #[test]
    fn medium_sources_use_two_byte_entries() {
        let map = compact(&[("one.example", 255), ("two.example", 65_534)]);
        assert!(matches!(map.sources, SourceTable::U16(_)));
        assert_eq!(map.sources.storage_bytes(), 2 * size_of::<u16>());
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).unwrap();
        let expected = match &map.sources {
            SourceTable::U16(values) => values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>(),
            _ => unreachable!(),
        };
        let source_start = source_payload_start(&map);
        assert_eq!(encoded[MAP_HEADER_BYTES - 1], 3, "u16 source tag");
        assert_eq!(
            &encoded[source_start..source_start + expected.len()],
            &expected
        );
        assert_eq!(encoded.len(), source_start + expected.len());
        let decoded = CompactDomainMap::decode_from(&mut encoded.as_slice()).unwrap();
        assert!(matches!(decoded.sources, SourceTable::U16(_)));
        assert_eq!(
            decoded
                .lookup_exact("two.example")
                .and_then(|found| decoded.source(found.index)),
            Some(65_534)
        );
    }

    #[test]
    /// Narrowing would turn the value into the none marker.
    fn source_value_that_conflicts_with_the_u16_sentinel_remains_dense() {
        let map = compact(&[("one.example", 65_535), ("two.example", u32::MAX)]);
        assert!(matches!(map.sources, SourceTable::Dense(_)));
        assert_eq!(map.sources.storage_bytes(), 2 * size_of::<u32>());
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).unwrap();
        let source_start = source_payload_start(&map);
        assert_eq!(encoded[MAP_HEADER_BYTES - 1], 4, "u32 source tag");
        assert_eq!(encoded.len(), source_start + 2 * size_of::<u32>());
        let decoded = CompactDomainMap::decode_from(&mut encoded.as_slice()).unwrap();
        assert!(matches!(decoded.sources, SourceTable::Dense(_)));
    }

    #[test]
    fn source_decoder_rejects_unknown_and_nonminimal_encodings() {
        let mut unknown = &[][..];
        assert!(decode_source_table(&mut unknown, 2, 0xff, "allocation").is_err());

        let mut uniform_u8 = &[7, 7][..];
        assert!(decode_source_table(&mut uniform_u8, 2, SOURCE_U8, "allocation").is_err());

        let mut narrow_u16 = &[1, 0, 2, 0][..];
        assert!(decode_source_table(&mut narrow_u16, 2, SOURCE_U16, "allocation").is_err());

        let mut narrow_u32 = &[1, 0, 0, 0, 2, 0, 0, 0][..];
        assert!(decode_source_table(&mut narrow_u32, 2, SOURCE_U32, "allocation").is_err());
    }

    #[test]
    /// Otherwise another party's domain would match this server's rule.
    fn suffix_match_requires_a_dns_label_boundary() {
        let map = compact(&[("example.com", 1), ("ample.net", 2)]);
        assert!(map.lookup_suffix("notexample.com").is_none());
        assert!(map.lookup_suffix("sample.net").is_none());
        assert!(map.lookup_suffix("x.example.com").is_some());
    }

    #[test]
    fn output_rank_indexes_every_sorted_entry() {
        let entries: Vec<(String, u32)> = (0..10_000)
            .map(|index| (format!("ad{index}.tenant{}.example", index % 97), index))
            .collect();
        let map = compact(
            &entries
                .iter()
                .map(|(domain, source)| (domain.as_str(), *source))
                .collect::<Vec<_>>(),
        );
        for (domain, source) in &entries {
            let found = map.lookup_exact(domain).expect("모든 key 검색");
            assert_eq!(map.source(found.index), Some(*source));
            assert_eq!(found.key, domain);
        }
    }

    #[test]
    fn build_peak_estimate_survives_narrow_usize_width() {
        // A sample from a 40,000-entry wide list. With a 32-bit usize this product saturates, and
        // dividing the saturated value by the sample count gives 131,072, which picks direct.
        const SAMPLE_BYTES: u64 = 5_372_650;
        const ENTRIES: u64 = 40_000;
        const SAMPLE_ENTRIES: u64 = 32 * 1024;
        assert!(
            SAMPLE_BYTES.saturating_mul(ENTRIES) > u64::from(u32::MAX),
            "이 곱이 32비트를 넘어야 회귀가 성립합니다"
        );
        assert!(
            staging_beats_direct(SAMPLE_BYTES, SAMPLE_ENTRIES, ENTRIES, 960_004),
            "넘치는 곱이 포화해 direct로 뒤집히면 안 됩니다"
        );
        // A list whose suffixes overlap well builds a small automaton and must stay direct.
        assert!(!staging_beats_direct(
            79_768,
            SAMPLE_ENTRIES,
            ENTRIES,
            1_331_734
        ));
    }

    #[test]
    fn build_peak_strategy_adapts_to_automaton_density() {
        const COUNT: usize = 40_000;

        let mut structured = DomainTable::default();
        for index in 0..COUNT {
            structured.insert_if_absent(
                &format!("ad{index}.tenant{}.tracking.example", index % 257),
                0,
            );
        }
        let structured = structured.into_sorted(reverse_cmp);
        let structured_bytes = structured.iter().map(|(key, _)| key.len()).sum();
        assert!(!staging_reduces_peak(&structured, structured_bytes));

        let mut wide = DomainTable::default();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..COUNT {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let value = seed;
            // Truncating by width would make 32-bit and 64-bit builds measure different fixtures.
            wide.insert_if_absent(
                &format!(
                    "{:016x}.{}",
                    value,
                    ["com", "net", "org"][(value % 3) as usize]
                ),
                0,
            );
        }
        let wide = wide.into_sorted(reverse_cmp);
        let wide_bytes = wide.iter().map(|(key, _)| key.len()).sum();
        assert!(staging_reduces_peak(&wide, wide_bytes));
    }

    #[test]
    fn randomized_suffix_queries_match_naive_longest_suffix() {
        let mut seed = 0x4f4e_4554_444e_5355u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let tlds = ["com", "net", "test", "example", "한국", "co.kr"];
        let label = |next: &mut dyn FnMut() -> u64| {
            let value = next();
            match value % 8 {
                0 => "한글".to_string(),
                1 => format!("x{}-{}", value % 97, (value >> 8) % 13),
                2 => format!("{}", value % 3),
                _ => {
                    let len = 1 + (value % 9) as usize;
                    let mut bits = next();
                    let mut out = String::with_capacity(len);
                    for _ in 0..len {
                        out.push((b'a' + (bits % 26) as u8) as char);
                        bits /= 26;
                        if bits == 0 {
                            bits = next();
                        }
                    }
                    out
                }
            }
        };

        let mut reference = DomainMap::new();
        let mut domains = Vec::new();
        let mut source = 0u32;
        while source < 1200 {
            let depth = 1 + (next() % 5) as usize;
            let mut parts = Vec::with_capacity(depth + 1);
            for _ in 0..depth {
                parts.push(label(&mut next));
            }
            parts.push(tlds[(next() % tlds.len() as u64) as usize].to_string());

            let cuts = if next() % 3 == 0 { 3 } else { 1 };
            for cut in 0..cuts.min(parts.len()) {
                let domain = parts[cut..].join(".");
                if reference.contains_key(domain.as_str()) {
                    continue;
                }
                reference.insert(domain.clone().into(), source);
                domains.push(domain);
                source += 1;
            }
        }
        let built =
            CompactDomainMap::try_from_table(table_from_reference(&reference)).expect("compact");
        assert!(
            !built.prefilter.blocks.is_empty(),
            "이 크기에는 사전 필터가 붙어야 합니다"
        );
        let mut encoded = Vec::new();
        built.encode_into(&mut encoded).expect("encode");
        let compact = CompactDomainMap::decode_from(&mut encoded.as_slice()).expect("decode");
        assert!(
            !compact.prefilter.blocks.is_empty(),
            "디코딩한 맵에도 사전 필터가 붙어야 합니다"
        );

        for (domain, expected) in &reference {
            let found = compact
                .lookup_exact(domain)
                .expect("등록한 이름은 정확 일치");
            assert_eq!(found.key, domain.as_ref());
            assert_eq!(compact.source(found.index), Some(*expected));
        }

        for index in 0..8000usize {
            let selected = domains[next() as usize % domains.len()].clone();
            let query = match index % 8 {
                0 => selected,
                1 => format!("deep.sub.{selected}"),
                2 => format!("not{selected}"),
                3 => format!("random{}.unrelated.example", next()),
                4 => format!("{}.{selected}", label(&mut next)),

                5 => selected
                    .split_once('.')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or(selected),
                6 => format!("{selected}.{}", label(&mut next)),
                _ => format!(".{selected}"),
            };
            let expected = reference
                .iter()
                .filter(|(domain, _)| {
                    let domain: &str = domain;
                    query == domain
                        || query
                            .strip_suffix(domain)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
                .max_by_key(|(domain, _)| domain.len())
                .map(|(domain, source)| (&**domain, *source));
            let actual = compact
                .lookup_suffix(&query)
                .map(|found| (found.key, compact.source(found.index).unwrap()));
            assert_eq!(actual, expected, "suffix query={query}");

            let expected_exact = reference
                .get_key_value(query.as_str())
                .map(|(domain, source)| (&**domain, *source));
            let actual_exact = compact
                .lookup_exact(&query)
                .map(|found| (found.key, compact.source(found.index).unwrap()));
            assert_eq!(actual_exact, expected_exact, "exact query={query}");
        }
    }

    #[test]
    /// The core of minimization. Read from the end, ab and ac are ba and ca. The slots that read
    /// the remaining a are the same for both branches, so they merge, and having no branch that
    /// slot folds into the edge before it. Only the root and the end remain, and both edges point
    /// at the same end and the same byte run.
    fn equivalent_suffix_languages_share_states() {
        let map = compact(&[("ab", 1), ("ac", 2)]);
        assert_eq!(map.state_count(), 2);
        let root = map.block(0).expect("root");
        assert_eq!(root.labels.len(), 2);
        let (first_target, _, first_tail) = root.edge(0).expect("first edge");
        let (second_target, _, second_tail) = root.edge(1).expect("second edge");
        assert_eq!(first_target, second_target);
        assert_eq!(first_tail, second_tail);
        assert_eq!(map.edge_tail(first_tail), Some(b"a".as_slice()));
    }

    #[test]
    /// The bytes one edge can carry are limited because the length fits in one byte. Removing the
    /// state where folding stopped as a pass-through would leave that edge with no target; a length
    /// several times the limit exercises that.
    fn keys_longer_than_one_edge_can_carry_are_still_found() {
        let key = "z".repeat(MAX_EDGE_TAIL * 3 + 7);
        let map = compact(&[(key.as_str(), 4), ("other.example", 5)]);
        assert_eq!(
            map.lookup_exact(&key)
                .and_then(|found| map.source(found.index)),
            Some(4),
            "상한을 넘겨 접은 이름을 찾지 못했습니다"
        );
        assert_eq!(
            map.lookup_exact("other.example")
                .and_then(|found| map.source(found.index)),
            Some(5)
        );
        assert!(map.tail_bytes.len() > 1, "접힌 엣지가 없습니다");
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).expect("encode");
        let decoded = CompactDomainMap::decode_from(&mut encoded.as_slice()).expect("decode");
        assert_eq!(decoded.lookup_exact(&key).map(|found| found.index), Some(1));
    }

    #[test]
    /// The prefilter may let an absent name through but must never stop a present one, at any
    /// label boundary.
    fn prefilter_passes_every_entry_and_its_subdomains() {
        let fillers: Vec<String> = (0..PREFILTER_MIN_NAMES)
            .map(|n| format!("filler{n}.test"))
            .collect();
        let mut entries = vec![
            ("ads.example.com", 1),
            ("tracker.test", 2),
            ("한글.example", 3),
            ("x", 4),
        ];
        entries.extend(fillers.iter().map(|name| (name.as_str(), 5)));
        let map = compact(&entries);
        assert!(
            !map.prefilter.blocks.is_empty(),
            "사전 필터가 붙지 않았습니다"
        );
        for (query, expected) in [
            ("ads.example.com", Some("ads.example.com")),
            ("deep.ads.example.com", Some("ads.example.com")),
            ("a.b.tracker.test", Some("tracker.test")),
            ("사이트.한글.example", Some("한글.example")),
            ("y.x", Some("x")),
            ("example.com", None),
            ("bads.example.com", None),
        ] {
            assert_eq!(
                map.lookup_suffix(query).map(|found| found.key),
                expected,
                "{query}"
            );
        }
        assert!(map.lookup_exact("tracker.test").is_some());
        assert!(map.lookup_exact("deep.tracker.test").is_none());

        let rejected = (0..1000)
            .filter(|n| {
                !map.prefilter
                    .may_contain(format!("absent{n}.test").as_bytes())
            })
            .count();
        assert!(
            rejected > 900,
            "rejected only {rejected} of 1000 absent names"
        );
    }

    #[test]
    fn empty_map_is_queryable_without_special_allocation() {
        let map = CompactDomainMap::try_from_table(DomainTable::default()).expect("empty");
        assert!(map.is_empty());
        assert_eq!(map.storage_bytes(), 0);
        assert!(map.lookup_exact("example.com").is_none());
        assert!(map.lookup_suffix("example.com").is_none());
    }

    #[test]
    fn binary_roundtrip_preserves_rank_sources_and_suffixes() {
        let map = compact(&[
            ("example.com", 11),
            ("ads.example.com", 12),
            ("한글.example", 13),
            ("", 14),
        ]);
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).expect("encode");
        encoded.extend_from_slice(b"next-section");

        let mut input = encoded.as_slice();
        let decoded = CompactDomainMap::decode_from(&mut input).expect("decode");
        assert_eq!(input, b"next-section");
        assert_eq!(owned_entries(&decoded), owned_entries(&map));
        assert_eq!(
            decoded
                .lookup_suffix("deep.ads.example.com")
                .map(|found| (found.key, decoded.source(found.index).unwrap())),
            Some(("ads.example.com", 12))
        );

        let mut empty = Vec::new();
        CompactDomainMap::default()
            .encode_into(&mut empty)
            .expect("empty encode");
        assert!(CompactDomainMap::decode_from(&mut empty.as_slice())
            .expect("empty decode")
            .is_empty());
    }

    #[test]
    /// A cycle left in would send verdicts into an infinite loop.
    fn binary_decoder_rejects_cycles_and_never_panics_on_corruption() {
        let map = compact(&[("a.example", 1), ("b.example", 2), ("deep.a.example", 3)]);
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).expect("encode");

        let root_edges = usize::from(encoded[MAP_HEADER_BYTES]);
        let first_target = MAP_HEADER_BYTES + STATE_HEADER_BYTES + root_edges;
        let mut cyclic = encoded.clone();
        cyclic[first_target..first_target + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(CompactDomainMap::decode_from(&mut cyclic.as_slice()).is_err());

        for index in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[index] ^= 0x5a;
            let result = std::panic::catch_unwind(|| {
                let _ = CompactDomainMap::decode_from(&mut corrupted.as_slice());
            });
            assert!(result.is_ok(), "손상 위치 {index}에서 panic");
        }
        for len in 0..encoded.len() {
            let result = std::panic::catch_unwind(|| {
                let _ = CompactDomainMap::decode_from(&mut &encoded[..len]);
            });
            assert!(result.is_ok(), "절단 길이 {len}에서 panic");
        }
    }

    #[test]
    /// A recursive walk would overflow the stack.
    fn pathological_key_length_does_not_use_the_call_stack() {
        let key = "a".repeat(100_000);
        let map = compact(&[(&key, 7)]);
        assert_eq!(
            map.lookup_exact(&key)
                .and_then(|found| map.source(found.index)),
            Some(7)
        );
        let rebuilt = rebuild_table(&map).expect("긴 키도 힙 순회로 복원");
        assert_eq!(rebuilt.get_key_value(&key), Some((key.as_str(), 7)));
    }
}
