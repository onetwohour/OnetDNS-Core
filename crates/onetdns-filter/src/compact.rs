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
const MAP_HEADER_BYTES: usize = 17;

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
    /// The first edge of each state. Its length is the state count plus one, and the last value is
    /// the total edge count.
    ///
    /// Edges are laid out contiguously in state order, so a state's edge count is the next state's
    /// start minus its own. Storing a count per state would hold the same information twice.
    state_edges: Box<[u32]>,
    state_terminal: Box<[u64]>,
    edge_labels: Box<[u8]>,
    edge_targets: Box<[u32]>,
    /// Added when the edge is taken; the sum along a path is the name's rank.
    edge_outputs: Box<[u32]>,
    /// Where the bytes an edge consumes after its first label sit; 0 means none. The first byte
    /// there is the length and the bytes follow. Edges with the same bytes point at the same place,
    /// so each run is stored once.
    edge_tails: Box<[u32]>,
    /// Index 0 is left empty to mean none.
    tail_bytes: Box<[u8]>,
    sources: SourceTable,
}

struct CollapsedArrays {
    state_edges: Box<[u32]>,
    state_terminal: Box<[u64]>,
    edge_labels: Box<[u8]>,
    edge_targets: Box<[u32]>,
    edge_outputs: Box<[u32]>,
    edge_tails: Box<[u32]>,
    tail_bytes: Box<[u8]>,
}

#[derive(Debug, Default)]
/// The representation is chosen to fit the value range. Most sets have only a few sources or just
/// one; always using 4 bytes would waste memory in proportion to the entry count.
enum SourceTable {
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
    /// Picks the smallest representation for the value range.
    fn from_vec(values: Vec<u32>) -> Self {
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
    let entry_count = sorted.len();
    let mut uniform_source = None::<(u32, usize)>;
    let mut dense_sources = Vec::new();
    for (_, source) in sorted.iter() {
        match uniform_source {
            None => uniform_source = Some((source, 1)),
            Some((value, count)) if dense_sources.is_empty() && value == source => {
                uniform_source = Some((value, count + 1));
            }
            Some((value, count)) if dense_sources.is_empty() => {
                dense_sources.reserve_exact(entry_count);
                dense_sources.resize(count, value);
                dense_sources.push(source);
            }
            Some(_) => dense_sources.push(source),
        }
    }
    if dense_sources.is_empty() {
        let (value, len) = uniform_source.expect("A non-empty map has a source");
        SourceTable::Uniform {
            value,
            len: len as u32,
        }
    } else {
        SourceTable::from_vec(dense_sources)
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
    fn state_count(&self) -> usize {
        self.state_edges.len().saturating_sub(1)
    }

    #[inline]
    fn state(&self, index: usize) -> Option<PackedState> {
        let first = *self.state_edges.get(index)?;
        let end = *self.state_edges.get(index + 1)?;
        Some(PackedState::new(
            first,
            end.checked_sub(first)? as usize,
            self.terminal(index),
        ))
    }

    fn iter_states(&self) -> impl Iterator<Item = PackedState> + '_ {
        (0..self.state_count()).filter_map(|index| self.state(index))
    }

    #[inline]
    /// Out of range reads as an empty state.
    fn state_at(&self, index: usize) -> PackedState {
        self.state(index)
            .unwrap_or_else(|| PackedState::new(0, 0, false))
    }

    #[inline]
    /// Empty when there are none.
    fn edge_tail(&self, edge: usize) -> Option<&[u8]> {
        let at = *self.edge_tails.get(edge)? as usize;
        if at == 0 {
            return Some(&[]);
        }
        let length = *self.tail_bytes.get(at)? as usize;
        self.tail_bytes.get(at + 1..at + 1 + length)
    }

    #[inline]
    fn terminal(&self, index: usize) -> bool {
        let Some(word) = self.state_terminal.get(index / 64) else {
            return false;
        };
        word >> (index % 64) & 1 == 1
    }

    /// Folds branchless intermediate states so one edge consumes several bytes. A state with one
    /// outgoing edge, not terminal, and no rank to add is only a pass-through, yet it costs 8 bytes
    /// of state and 12 of edge for one byte of information. Each such run is appended after the
    /// leading edge's label and the intermediate states are removed. Several edges can point at the
    /// same run, so each run is stored once.
    fn collapse_chains(
        states: &[PackedState],
        edge_labels: &[u8],
        edge_targets: &[u32],
        edge_outputs: &[u32],
    ) -> CollapsedArrays {
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
        // first, and numbering comes after.
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

        let mut new_id = vec![NONE; states.len()];
        let mut kept = 0u32;
        let mut edge_total = 0usize;
        for index in 0..states.len() {
            if !keep[index] {
                continue;
            }
            new_id[index] = kept;
            kept += 1;
            edge_total += states[index].edge_count();
        }

        let mut state_edges = Vec::with_capacity(kept as usize + 1);
        let mut terminal_bits = vec![0u64; (kept as usize).div_ceil(64)];
        let mut labels = Vec::with_capacity(edge_total);
        let mut targets = Vec::with_capacity(edge_total);
        let mut outputs = Vec::with_capacity(edge_total);
        let mut tails = Vec::with_capacity(edge_total);
        // Index 0 is left empty so it cannot collide with the none marker.
        let mut tail_bytes = vec![0u8];
        let mut tail_at = vec![NONE; states.len()];

        for index in 0..states.len() {
            if !keep[index] {
                continue;
            }
            let id = new_id[index] as usize;
            if states[index].terminal() {
                terminal_bits[id / 64] |= 1 << (id % 64);
            }
            let state = states[index];
            let first = state.first_edge as usize;
            state_edges.push(labels.len() as u32);
            for edge in first..first + state.edge_count() {
                labels.push(edge_labels[edge]);
                outputs.push(edge_outputs[edge]);

                let entry = edge_targets[edge] as usize;
                let mut walk = entry;
                let mut length = 0usize;
                while !keep[walk] && length < MAX_EDGE_TAIL {
                    length += 1;
                    walk = edge_targets[states[walk].first_edge as usize] as usize;
                }
                if length == 0 {
                    tails.push(0);
                } else if tail_at[entry] != NONE {
                    tails.push(tail_at[entry]);
                } else {
                    let at = tail_bytes.len() as u32;
                    tail_at[entry] = at;
                    tails.push(at);
                    tail_bytes.push(length as u8);
                    let mut cursor = entry;
                    for _ in 0..length {
                        let only = states[cursor].first_edge as usize;
                        tail_bytes.push(edge_labels[only]);
                        cursor = edge_targets[only] as usize;
                    }
                }
                targets.push(new_id[walk]);
            }
        }
        state_edges.push(labels.len() as u32);

        CollapsedArrays {
            state_edges: state_edges.into_boxed_slice(),
            state_terminal: terminal_bits.into_boxed_slice(),
            edge_labels: labels.into_boxed_slice(),
            edge_targets: targets.into_boxed_slice(),
            edge_outputs: outputs.into_boxed_slice(),
            edge_tails: tails.into_boxed_slice(),
            tail_bytes: tail_bytes.into_boxed_slice(),
        }
    }

    /// After building, checks that every entry is found again at its own rank. If any is not,
    /// compaction is abandoned and the table is returned as is: using more memory beats silently
    /// using a wrong set.
    pub(crate) fn try_from_table(table: DomainTable) -> Result<Self, DomainTable> {
        if table.is_empty() {
            return Ok(Self::default());
        }

        let Some(total_bytes) = table
            .keys()
            .try_fold(0usize, |total, key| total.checked_add(key.len()))
        else {
            return Err(table);
        };
        if table.len() > u32::MAX as usize || total_bytes >= u32::MAX as usize {
            return Err(table);
        }

        let sorted = table.into_sorted(reverse_cmp);

        let entry_count = sorted.len();
        let sources = collect_sources(&sorted);
        let stage_input = staging_reduces_peak(&sorted, total_bytes);
        let mut builder = DawgBuilder::new();
        if stage_input {
            let mut domains = String::new();
            domains.reserve_exact(total_bytes);
            let mut offsets = Vec::with_capacity(entry_count + 1);
            for (domain, _) in sorted.iter() {
                offsets.push(domains.len() as u32);
                domains.push_str(domain);
            }
            offsets.push(domains.len() as u32);
            drop(sorted);

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
        } else {
            for (domain, _) in sorted.iter() {
                builder.insert_reversed(domain.as_bytes());
            }
            builder.complete();
            if !sorted
                .iter()
                .all(|(domain, _)| builder.contains_reversed(domain.as_bytes()))
            {
                let mut fallback = DomainTable::default();
                fallback.reserve(entry_count);
                for (domain, source) in sorted.iter() {
                    fallback.insert_if_absent(domain, source);
                }
                return Err(fallback);
            }
            drop(sorted);
        }

        let (states, edge_labels, edge_targets, edge_outputs, root_terms) =
            builder.finish_completed();
        assert_eq!(
            root_terms,
            sources.len() as u32,
            "Validated compact filter item count changed while packing"
        );
        let collapsed = Self::collapse_chains(&states, &edge_labels, &edge_targets, &edge_outputs);
        drop(states);
        drop(edge_labels);
        drop(edge_targets);
        drop(edge_outputs);
        let built = Self {
            state_edges: collapsed.state_edges,
            state_terminal: collapsed.state_terminal,
            edge_labels: collapsed.edge_labels,
            edge_targets: collapsed.edge_targets,
            edge_outputs: collapsed.edge_outputs,
            edge_tails: collapsed.edge_tails,
            tail_bytes: collapsed.tail_bytes,
            sources,
        };

        Ok(built)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.sources.len()
    }

    pub(crate) fn storage_bytes(&self) -> usize {
        self.state_edges.len() * size_of::<u32>()
            + self.state_terminal.len() * size_of::<u64>()
            + self.edge_labels.len()
            + self.edge_targets.len() * size_of::<u32>()
            + self.edge_outputs.len() * size_of::<u32>()
            + self.edge_tails.len() * size_of::<u32>()
            + self.tail_bytes.len()
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
        if self.state_count() == 0 {
            return if self.sources.is_empty() {
                Ok(())
            } else {
                Err("Empty automaton still has source entries")
            };
        }

        let mut reversed = Vec::new();
        let mut forward = Vec::new();
        // The fourth value is how many bytes were pushed on entering this slot. One edge carries
        // several bytes, so popping a single byte on the way out would corrupt the name.
        let mut stack = vec![(0usize, 0usize, 0u32, false, 0usize)];
        while !stack.is_empty() {
            let frame_index = stack.len() - 1;
            let (state_index, next_edge, rank, terminal_emitted, pushed) = stack[frame_index];
            let _ = pushed;
            let state = self
                .state(state_index)
                .ok_or("Automaton traversal state is out of range")?;
            if !terminal_emitted {
                stack[frame_index].3 = true;
                if state.terminal() {
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

            if next_edge < state.edge_count() {
                let edge = (state.first_edge as usize)
                    .checked_add(next_edge)
                    .ok_or("Could not compute automaton edge position")?;
                stack[frame_index].1 += 1;
                let label = *self
                    .edge_labels
                    .get(edge)
                    .ok_or("Automaton edge has no label")?;
                let target = *self
                    .edge_targets
                    .get(edge)
                    .ok_or("Automaton edge has no target")? as usize;
                let child_rank = rank
                    .checked_add(
                        *self
                            .edge_outputs
                            .get(edge)
                            .ok_or("Automaton edge has no output")?,
                    )
                    .ok_or("Automaton traversal rank overflowed")?;
                reversed.push(label);
                let tail = self
                    .edge_tail(edge)
                    .ok_or("Could not read automaton edge tail bytes")?;
                reversed.extend_from_slice(tail);
                stack.push((target, 0, child_rank, false, 1 + tail.len()));
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
        for value in [
            self.state_count(),
            self.edge_labels.len(),
            self.sources.len(),
            self.tail_bytes.len(),
        ] {
            let value =
                u32::try_from(value).map_err(|_| "Compact filter map length exceeds 32 bits")?;
            output(&value.to_le_bytes());
        }
        output(&[self.sources.wire_kind()]);
        for start in self.state_edges.iter() {
            output(&start.to_le_bytes());
        }
        for word in self.state_terminal.iter() {
            output(&word.to_le_bytes());
        }
        output(&self.edge_labels);
        for values in [&self.edge_targets, &self.edge_outputs, &self.edge_tails] {
            for value in values.iter() {
                output(&value.to_le_bytes());
            }
        }
        output(&self.tail_bytes);
        self.sources.encode_payload_chunks(output);
        Ok(())
    }

    /// Validates the whole structure after reading: cycles, out-of-range indexes, edge order,
    /// reachability, and partial ranks. Using it with any of these wrong would send the verdict
    /// path into an infinite loop or a wrong read.
    pub(crate) fn decode_from(input: &mut &[u8]) -> Result<Self, &'static str> {
        let states_len = read_u32(input)? as usize;
        let edges_len = read_u32(input)? as usize;
        let entries_len = read_u32(input)? as usize;
        let tail_len = read_u32(input)? as usize;
        let source_kind = read_u8(input)?;
        if states_len == 0 && edges_len == 0 && entries_len == 0 {
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
            .checked_add(1)
            .and_then(|count| count.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(states_len.div_ceil(64).checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add(edges_len))
            .and_then(|bytes| bytes.checked_add(edges_len.checked_mul(12)?))
            .and_then(|bytes| bytes.checked_add(tail_len))
            .and_then(|bytes| bytes.checked_add(source_bytes))
            .ok_or("Could not compute compact domain map size")?;
        let encoded_len = MAP_HEADER_BYTES
            .checked_add(body_len)
            .ok_or("Could not compute compact domain map size")?;
        if encoded_len > MAX_ENCODED_MAP_BYTES || body_len > input.len() {
            return Err("Invalid compact map serialized length");
        }

        let state_edges = read_u32_vec(
            input,
            states_len + 1,
            "Out of memory storing compact filter states",
        )?
        .into_boxed_slice();
        let mut state_terminal = reserved_vec(
            states_len.div_ceil(64),
            "Out of memory storing compact filter final-state bits",
        )?;
        for _ in 0..states_len.div_ceil(64) {
            state_terminal.push(read_u64(input)?);
        }
        let state_terminal = state_terminal.into_boxed_slice();
        let edge_labels = copy_bytes(
            input,
            edges_len,
            "Out of memory storing compact filter edge labels",
        )?;
        let edge_targets = read_u32_vec(
            input,
            edges_len,
            "Out of memory storing compact filter edge targets",
        )?;
        let edge_outputs = read_u32_vec(
            input,
            edges_len,
            "Out of memory storing compact filter edge outputs",
        )?;
        let edge_tails = read_u32_vec(
            input,
            edges_len,
            "Out of memory storing compact filter edge tail offsets",
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
        let map = Self {
            state_edges,
            state_terminal,
            edge_labels: edge_labels.into_boxed_slice(),
            edge_targets: edge_targets.into_boxed_slice(),
            edge_outputs: edge_outputs.into_boxed_slice(),
            edge_tails: edge_tails.into_boxed_slice(),
            tail_bytes: tail_bytes.into_boxed_slice(),
            sources,
        };
        map.validate_decoded()?;
        Ok(map)
    }

    pub(crate) fn lookup_exact<'a>(&self, domain: &'a str) -> Option<CompactMatch<'a>> {
        if self.state_count() == 0 {
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
        if self.state_count() == 0 {
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
            .checked_add(self.state_edges.len().checked_mul(4)?)?
            .checked_add(self.state_terminal.len().checked_mul(8)?)?
            .checked_add(self.edge_labels.len())?
            .checked_add(self.edge_targets.len().checked_mul(4)?)?
            .checked_add(self.edge_outputs.len().checked_mul(4)?)?
            .checked_add(self.edge_tails.len().checked_mul(4)?)?
            .checked_add(self.tail_bytes.len())?
            .checked_add(self.sources.wire_len()?)
    }

    fn validate_decoded(&self) -> Result<(), &'static str> {
        if self.edge_labels.len() != self.edge_targets.len()
            || self.edge_labels.len() != self.edge_outputs.len()
        {
            return Err("Compact map array length invariant violated");
        }

        // Edge counts come from the difference of adjacent starts, so if this array is not
        // monotonic a state silently disappears and validation passes while reading the wrong
        // edges.
        if self.state_edges.first() != Some(&0)
            || self.state_edges.last().map(|last| *last as usize) != Some(self.edge_labels.len())
        {
            return Err("Compact filter edge start offsets do not match at the ends");
        }
        if self.state_edges.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err("Compact filter edge start offsets are not increasing");
        }
        if self.state_terminal.len() != self.state_count().div_ceil(64) {
            return Err("Compact filter final-state bit length does not match the state count");
        }
        // Unless the spare bits are pinned to 0, the same set encodes to different bytes.
        let spare = self.state_terminal.len() * 64 - self.state_count();
        if spare > 0
            && self
                .state_terminal
                .last()
                .is_some_and(|word| word >> (64 - spare) != 0)
        {
            return Err("Compact filter final-state bits have unused bits set");
        }

        if self.edge_tails.len() != self.edge_labels.len() {
            return Err("Compact filter edge tail array length does not match");
        }
        // Index 0 is the none marker and must not be read as bytes.
        if self.tail_bytes.len() == 1 && self.edge_tails.iter().any(|at| *at != 0) {
            return Err("Compact filter edge points to tail bytes that do not exist");
        }
        for at in self.edge_tails.iter() {
            let at = *at as usize;
            if at == 0 {
                continue;
            }
            let Some(length) = self.tail_bytes.get(at).map(|value| *value as usize) else {
                return Err("Compact filter edge points to a missing tail");
            };
            if length == 0 || at + 1 + length > self.tail_bytes.len() {
                return Err("Invalid compact filter tail length");
            }
        }

        let mut edge_cursor = 0usize;
        for state in self.iter_states() {
            let first = state.first_edge as usize;
            let count = state.edge_count();
            let end = first
                .checked_add(count)
                .ok_or("Compact filter edge range overflowed")?;
            if first != edge_cursor || end > self.edge_labels.len() || count > 256 {
                return Err("Invalid compact filter edge range");
            }
            let labels = &self.edge_labels[first..end];
            if labels.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err("Compact filter edge labels are not sorted");
            }
            if self.edge_targets[first..end]
                .iter()
                .any(|target| *target as usize >= self.state_count())
            {
                return Err("Invalid compact filter edge target");
            }
            edge_cursor = end;
        }
        if edge_cursor != self.edge_labels.len() {
            return Err("Compact filter has unreferenced edge data");
        }

        const VISITING: u32 = NONE - 1;
        let mut calculated = filled_vec(
            self.state_count(),
            NONE,
            "Out of memory storing compact filter graph counts",
        )?;
        let mut stack = reserved_vec(
            self.state_count().min(256),
            "Out of memory storing the compact filter traversal stack",
        )?;
        calculated[0] = VISITING;
        stack.push((0usize, 0usize));
        while let Some((state_index, next_edge)) = stack.last_mut() {
            let state = self.state_at(*state_index);
            let first = state.first_edge as usize;
            let count = state.edge_count();
            if *next_edge < count {
                let target = self.edge_targets[first + *next_edge] as usize;
                *next_edge += 1;
                match calculated[target] {
                    NONE => {
                        calculated[target] = VISITING;
                        if stack.len() == stack.capacity() {
                            stack.try_reserve(1).map_err(|_| {
                                "Out of memory storing the compact filter traversal stack"
                            })?;
                        }
                        stack.push((target, 0));
                    }
                    VISITING => return Err("Compact automaton has a cycle"),
                    _ => {}
                }
                continue;
            }
            let mut terms = u64::from(state.terminal());
            for target in &self.edge_targets[first..first + count] {
                terms = terms
                    .checked_add(u64::from(calculated[*target as usize]))
                    .ok_or("Compact subtree term count overflowed")?;
            }
            let terms = u32::try_from(terms)
                .map_err(|_| "Compact filter subtree has too many terminal entries")?;
            calculated[*state_index] = terms;
            stack.pop();
        }
        if calculated.iter().any(|count| *count >= VISITING)
            || calculated[0] as usize != self.sources.len()
        {
            return Err("Compact automaton reachable and final state counts do not match");
        }

        for state in self.iter_states() {
            let first = state.first_edge as usize;
            let end = first + state.edge_count();
            let mut expected = u32::from(state.terminal());
            for edge in first..end {
                if self.edge_outputs[edge] != expected {
                    return Err("Compact edge output rank does not match");
                }
                expected = expected
                    .checked_add(calculated[self.edge_targets[edge] as usize])
                    .ok_or("Compact edge output computation overflowed")?;
            }
        }
        let mut expected_index = 0usize;
        let mut ranks_match = true;
        self.for_each_entry(|index, key, _| {
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
        state_index: usize,
        rank: u32,
        bytes: &[u8],
        eaten: usize,
    ) -> Option<(usize, u32, usize)> {
        // Choosing an edge needs only the edge range. Reading the terminal flag too would touch
        // another array per byte for a value not used here.
        let first = *self.state_edges.get(state_index)? as usize;
        let end = *self.state_edges.get(state_index + 1)? as usize;
        let labels = self.edge_labels.get(first..end)?;
        let label = *bytes.get(bytes.len().checked_sub(eaten + 1)?)?;
        let position = match labels.len() {
            0 => return None,
            1 if labels[0] == label => 0,
            1 => return None,
            2..=8 => labels.iter().position(|candidate| *candidate == label)?,
            _ => labels.binary_search(&label).ok()?,
        };

        let edge = first + position;
        let mut eaten = eaten + 1;
        let tail = self.edge_tail(edge)?;
        for expected in tail {
            if *bytes.get(bytes.len().checked_sub(eaten + 1)?)? != *expected {
                return None;
            }
            eaten += 1;
        }

        let next_rank = rank + *self.edge_outputs.get(edge)?;
        let target = *self.edge_targets.get(edge)? as usize;
        Some((target, next_rank, eaten))
    }
}

fn read_u32(input: &mut &[u8]) -> Result<u32, &'static str> {
    let bytes = take_bytes(input, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(input: &mut &[u8]) -> Result<u64, &'static str> {
    let bytes = take_bytes(input, 8)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
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
fn reverse_cmp(left: &str, right: &str) -> Ordering {
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

    fn state_area_bytes(map: &CompactDomainMap) -> usize {
        map.state_edges.len() * size_of::<u32>() + map.state_terminal.len() * size_of::<u64>()
    }

    fn source_payload_start(map: &CompactDomainMap) -> usize {
        MAP_HEADER_BYTES
            + state_area_bytes(map)
            + map.edge_labels.len()
            + map.edge_targets.len() * size_of::<u32>()
            + map.edge_outputs.len() * size_of::<u32>()
            + map.edge_tails.len() * size_of::<u32>()
            + map.tail_bytes.len()
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
            state_area_bytes(&map)
                + map.edge_labels.len()
                + map.edge_targets.len() * size_of::<u32>()
                + map.edge_outputs.len() * size_of::<u32>()
                + map.edge_tails.len() * size_of::<u32>()
                + map.tail_bytes.len()
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
        let compact =
            CompactDomainMap::try_from_table(table_from_reference(&reference)).expect("compact");

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
        assert_eq!(map.edge_labels.len(), 2);
        assert_eq!(map.edge_targets[0], map.edge_targets[1]);
        assert_eq!(map.edge_tails[0], map.edge_tails[1]);
        assert_eq!(map.edge_tail(0), Some(b"a".as_slice()));
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
        assert!(
            map.edge_tails.iter().any(|at| *at != 0),
            "접힌 엣지가 없습니다"
        );
        let mut encoded = Vec::new();
        map.encode_into(&mut encoded).expect("encode");
        let decoded = CompactDomainMap::decode_from(&mut encoded.as_slice()).expect("decode");
        assert_eq!(decoded.lookup_exact(&key).map(|found| found.index), Some(1));
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

        let states = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        let edges = u32::from_le_bytes(encoded[4..8].try_into().unwrap()) as usize;
        let first_target = MAP_HEADER_BYTES + (states + 1) * 4 + states.div_ceil(64) * 8 + edges;
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
