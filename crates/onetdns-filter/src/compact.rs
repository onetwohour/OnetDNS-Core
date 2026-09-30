/*!
 * @brief 도메인 집합의 최소 형태.
 *
 * @details 도메인을 뒤집어 정렬한 뒤 최소 비순환 오토마톤으로 고정한다. 접미사를 공유하는
 *          도메인들이 같은 상태를 나눠 쓰므로, 수백만 항목이 몇 분의 일로 줄어든다.
 * @note 훑는 동안 순위를 누적한다. 그 순위가 곧 정렬 순서상의 번호라 출처 배열을 바로
 *       가리킨다. 일치 문자열은 질의 자체의 정확/접미사 슬라이스이므로 따로 보존하지 않는다.
 * @warning 되읽을 때 구조를 전부 검증한다. 순환이나 범위 밖 인덱스가 남으면 판정 경로가
 *          무한 루프에 빠지거나 엉뚱한 곳을 읽는다.
 */

use std::cmp::Ordering;
use std::mem::size_of;

use crate::table::{DomainTable, SortedDomains};

/** @brief 없음 표시. */
const NONE: u32 = u32::MAX;
/** @brief 이 상태에서 단어가 끝날 수 있음을 뜻하는 비트. */
const TERMINAL_BIT: u32 = 1 << 31;
/** @brief 엣지 수를 꺼내는 마스크. */
const EDGE_COUNT_MASK: u32 = !TERMINAL_BIT;
/** @brief 인코딩된 맵의 헤더 크기. 상태 수, 엣지 수, 항목 수, 꼬리 길이, 출처 형태다. */
const MAP_HEADER_BYTES: usize = 17;

/** @brief 엣지 하나가 첫 글자 뒤에 더 먹을 수 있는 글자 수 상한. 길이를 한 바이트에 담는다. */
const MAX_EDGE_TAIL: usize = 255;

/** @brief 인코딩된 맵 크기 상한. */
const MAX_ENCODED_MAP_BYTES: usize = 512 * 1024 * 1024;
/** @brief 출처가 하나도 없는 형태. */
const SOURCE_EMPTY: u8 = 0;
/** @brief 모든 출처가 같은 형태. 값 하나만 담는다. */
const SOURCE_UNIFORM: u8 = 1;
/** @brief 출처가 1바이트에 담기는 형태. */
const SOURCE_U8: u8 = 2;
/** @brief 출처가 2바이트에 담기는 형태. */
const SOURCE_U16: u8 = 3;
/** @brief 출처가 4바이트가 필요한 형태. */
const SOURCE_U32: u8 = 4;

#[cfg(test)]
/** @brief 테스트에서 기준으로 쓰는 단순 맵. */
type DomainMap = std::collections::HashMap<Box<str>, u32>;

#[derive(Debug, Clone, Copy)]
/** @brief 오토마톤 상태 하나. 엣지 시작, 개수, 종단 여부를 한 워드에 담는다. */
struct PackedState {
    /** @brief 이 상태에서 나가는 첫 엣지의 곳. */
    first_edge: u32,
    /** @brief 나가는 엣지 수와 이 상태가 끝인지를 함께 담은 값. */
    edge_count_and_terminal: u32,
}

impl PackedState {
    /** @brief 상태를 만든다. */
    fn new(first_edge: u32, edge_count: usize, terminal: bool) -> Self {
        let terminal = if terminal { TERMINAL_BIT } else { 0 };
        Self {
            first_edge,
            edge_count_and_terminal: edge_count as u32 | terminal,
        }
    }

    #[inline]
    /** @brief 이 상태의 엣지 수. */
    fn edge_count(self) -> usize {
        (self.edge_count_and_terminal & EDGE_COUNT_MASK) as usize
    }

    #[inline]
    /** @brief 이 상태에서 단어가 끝날 수 있는지. */
    fn terminal(self) -> bool {
        self.edge_count_and_terminal & TERMINAL_BIT != 0
    }
}

#[derive(Debug, Default)]
/** @brief 고정한 도메인 집합. 만들어진 뒤에는 바뀌지 않는다. */
pub(crate) struct CompactDomainMap {
    /**
     * @brief 상태마다 나가는 첫 엣지의 자리. 길이는 상태 수 더하기 하나이고 마지막 값은
     *        엣지의 총 개수다.
     * @invariant 엣지는 상태 번호 순서대로 빈틈없이 놓인다. 그래서 어떤 상태의 엣지 수는
     *            다음 상태의 시작 자리에서 자기 시작 자리를 빼면 나온다. 상태마다 엣지 수를
     *            따로 들고 있으면 이 배열과 똑같은 정보를 두 번 저장하는 셈이 된다.
     */
    state_edges: Box<[u32]>,
    /** @brief 상태가 종료 상태인지를 담은 비트들. 상태 하나에 한 비트다. */
    state_terminal: Box<[u64]>,
    /** @brief 엣지마다의 글자. */
    edge_labels: Box<[u8]>,
    /** @brief 엣지가 가리키는 상태. */
    edge_targets: Box<[u32]>,
    /** @brief 엣지를 지날 때 더할 값. 이것을 모으면 이름의 곳이 된다. */
    edge_outputs: Box<[u32]>,
    /**
     * @brief 엣지가 첫 글자 뒤에 이어서 먹는 글자들의 자리. 0 이면 이어지는 글자가 없다.
     * @details 가리키는 자리의 첫 바이트가 길이고 그 뒤로 길이만큼이 글자다. 같은 글자
     *          묶음은 여러 엣지가 같은 자리를 가리켜 한 번만 저장한다.
     */
    edge_tails: Box<[u32]>,
    /** @brief 이어지는 글자들을 모아 둔 곳. 0번 자리는 없음 표시에 쓰려고 비워 둔다. */
    tail_bytes: Box<[u8]>,
    /** @brief 이름마다 어느 목록에서 왔는지. */
    sources: SourceTable,
}

/** @brief 접은 뒤의 배열 묶음. */
struct CollapsedArrays {
    /** @brief 상태마다 나가는 첫 엣지의 자리. */
    state_edges: Box<[u32]>,
    /** @brief 상태가 종료 상태인지를 담은 비트들. */
    state_terminal: Box<[u64]>,
    /** @brief 엣지마다의 첫 글자. */
    edge_labels: Box<[u8]>,
    /** @brief 엣지가 가리키는 상태. */
    edge_targets: Box<[u32]>,
    /** @brief 엣지를 지날 때 더할 값. */
    edge_outputs: Box<[u32]>,
    /** @brief 엣지가 첫 글자 뒤에 이어서 먹는 글자들의 자리. */
    edge_tails: Box<[u32]>,
    /** @brief 이어지는 글자들을 모아 둔 곳. */
    tail_bytes: Box<[u8]>,
}

#[derive(Debug, Default)]
/**
 * @brief 출처 번호 배열. 값 범위에 맞춰 표현을 고른다.
 * @details 대부분의 집합은 출처가 몇 개뿐이거나 아예 하나다. 항상 4바이트로 담으면
 *          항목 수에 비례해 메모리가 낭비된다.
 */
enum SourceTable {
    #[default]
    /** @brief 어느 목록에서 왔는지 두지 않는다. */
    Empty,
    /** @brief 전부 같은 목록에서 왔다. */
    Uniform { value: u32, len: u32 },
    /** @brief 목록 수가 적어 1바이트로 담는다. */
    U8(Box<[u8]>),
    /** @brief 목록 수가 조금 많아 2바이트로 담는다. */
    U16(Box<[u16]>),
    /** @brief 목록 수가 많아 4바이트로 담는다. */
    Dense(Box<[u32]>),
}

impl SourceTable {
    /** @brief 값 범위를 보고 가장 작은 표현을 고른다. */
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
    /** @brief 항목 수. */
    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Uniform { len, .. } => *len as usize,
            Self::U8(values) => values.len(),
            Self::U16(values) => values.len(),
            Self::Dense(values) => values.len(),
        }
    }

    /** @brief 비었는지. */
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    /** @brief 인덱스로 출처를 얻는다. */
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

    /** @brief 이 테이블이 쓰는 바이트. */
    fn storage_bytes(&self) -> usize {
        match self {
            Self::U8(values) => std::mem::size_of_val(&**values),
            Self::U16(values) => std::mem::size_of_val(&**values),
            Self::Dense(values) => std::mem::size_of_val(&**values),
            Self::Empty | Self::Uniform { .. } => 0,
        }
    }

    /** @brief 인코딩할 때 쓸 표현 번호. */
    fn wire_kind(&self) -> u8 {
        match self {
            Self::Empty => SOURCE_EMPTY,
            Self::Uniform { .. } => SOURCE_UNIFORM,
            Self::U8(_) => SOURCE_U8,
            Self::U16(_) => SOURCE_U16,
            Self::Dense(_) => SOURCE_U32,
        }
    }

    /** @brief 인코딩된 크기. */
    fn wire_len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Uniform { .. } => Some(size_of::<u32>()),
            Self::U8(values) => Some(values.len()),
            Self::U16(values) => values.len().checked_mul(size_of::<u16>()),
            Self::Dense(values) => values.len().checked_mul(size_of::<u32>()),
        }
    }

    /** @brief 테이블 내용을 청크 단위로 스트리밍한다. */
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
/** @brief 찾은 결과. 도메인과 출처를 함께 준다. */
pub(crate) struct CompactMatch<'a> {
    /** @brief 찾아낸 이름. */
    pub(crate) key: &'a str,
    /** @brief 그 이름의 곳. */
    pub(crate) index: usize,
}

#[cfg(test)]
/** @brief 오토마톤 언어를 순회해 수정 가능한 테이블로 되돌린다. */
fn rebuild_table(map: &CompactDomainMap) -> Option<DomainTable> {
    let mut table = DomainTable::default();
    table.reserve(map.len());
    map.for_each_entry(|_, key, source| {
        table.insert_if_absent(key, source);
    })
    .ok()?;
    Some(table)
}

/** @brief 빌드용 연속 문자열을 수정 가능한 테이블로 되돌린다. */
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

/** @brief 정렬 순서에 맞춘 출처 테이블을 만든다. */
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

/**
 * @brief 큰 빌더와 정렬 테이블을 겹치기보다 작은 연속 입력을 거치는 편이 나은지 표본으로 고른다.
 * @details 무작위/DGA 목록은 오토마톤이 커서 16바이트 정렬 항목을 먼저 버리는 편이 낫고,
 *          접미사가 잘 겹치는 목록은 오토마톤이 작아 원본에서 바로 만드는 편이 피크가 낮다.
 */
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

/**
 * @brief 표본에서 늘린 빌더 추정치가 연속 입력보다 큰지.
 *
 * @details usize가 아니라 u64로 센다. 표본 바이트에 항목 수를 곱하면 4 GiB를 쉽게 넘는데,
 *          32비트에서 포화한 값은 표본 수로 나눈 뒤 오히려 작아져 판정을 뒤집는다. 그러면
 *          메모리가 가장 빠듯한 platform이 피크가 높은 쪽을 고르게 된다.
 * @param sample_bytes 표본 오토마톤이 차지한 바이트.
 * @param sample_entries 표본에 넣은 항목 수. 0이면 안 된다.
 * @param entries 전체 항목 수.
 * @param total_bytes 전체 key 바이트 합.
 */
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
    /** @brief 상태 수. */
    fn state_count(&self) -> usize {
        self.state_edges.len().saturating_sub(1)
    }

    #[inline]
    /** @brief 상태 하나를 읽는다. 범위를 벗어나면 None 이다. */
    fn state(&self, index: usize) -> Option<PackedState> {
        let first = *self.state_edges.get(index)?;
        let end = *self.state_edges.get(index + 1)?;
        Some(PackedState::new(
            first,
            end.checked_sub(first)? as usize,
            self.terminal(index),
        ))
    }

    /** @brief 모든 상태를 차례로 읽는다. */
    fn iter_states(&self) -> impl Iterator<Item = PackedState> + '_ {
        (0..self.state_count()).filter_map(|index| self.state(index))
    }

    #[inline]
    /** @brief 상태 하나를 읽는다. 범위를 벗어나면 빈 상태로 본다. */
    fn state_at(&self, index: usize) -> PackedState {
        self.state(index)
            .unwrap_or_else(|| PackedState::new(0, 0, false))
    }

    #[inline]
    /** @brief 엣지가 첫 글자 뒤에 이어서 먹는 글자들. 없으면 빈 조각이다. */
    fn edge_tail(&self, edge: usize) -> Option<&[u8]> {
        let at = *self.edge_tails.get(edge)? as usize;
        if at == 0 {
            return Some(&[]);
        }
        let length = *self.tail_bytes.get(at)? as usize;
        self.tail_bytes.get(at + 1..at + 1 + length)
    }

    #[inline]
    /** @brief 이 상태에서 단어가 끝날 수 있는지. */
    fn terminal(&self, index: usize) -> bool {
        let Some(word) = self.state_terminal.get(index / 64) else {
            return false;
        };
        word >> (index % 64) & 1 == 1
    }

    /**
     * @brief 분기 없는 중간 상태를 접어 엣지 하나가 여러 글자를 먹게 만든다.
     * @details 나가는 엣지가 하나뿐이고 종료도 아니며 순위에 더할 값도 없는 상태는 그저
     *          지나가는 자리다. 그런 상태 하나마다 상태 여덟 바이트와 엣지 열두 바이트를
     *          쓰는데 실제 정보는 글자 한 바이트뿐이다. 그래서 이어진 구간을 앞 엣지의
     *          글자 뒤에 붙이고 중간 상태를 없앤다.
     * @note 같은 글자 묶음을 여러 엣지가 가리킬 수 있으므로 묶음은 한 번만 저장한다.
     */
    fn collapse_chains(
        states: &[PackedState],
        edge_labels: &[u8],
        edge_targets: &[u32],
        edge_outputs: &[u32],
    ) -> CollapsedArrays {
        // 뿌리는 접지 않는다. 접으면 시작 자리가 사라진다.
        let passthrough = |index: usize| -> bool {
            if index == 0 {
                return false;
            }
            let state = states[index];
            state.edge_count() == 1
                && !state.terminal()
                && edge_outputs[state.first_edge as usize] == 0
        };

        // 상한에 걸려 멈춘 자리는 남겨야 한다. 지나가는 자리라고 지워 버리면 그 엣지가
        // 가리킬 상태가 사라진다. 그래서 어디서 멈추는지 먼저 확정하고 나서 번호를 준다.
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
        // 0번 자리는 "이어지는 글자 없음" 을 나타내는 값과 겹치지 않도록 비워 둔다.
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

    /**
     * @brief 테이블을 고정해 최소 오토마톤으로 만든다.
     * @warning 만든 뒤 모든 항목이 실제로 자기 순위로 되찾아지는지 확인한다. 하나라도
     *          어긋나면 고정를 포기하고 테이블을 그대로 돌려준다. 조용히 틀린 집합을
     *          쓰는 것보다 메모리를 더 쓰는 쪽이 낫다.
     */
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

    /** @brief 비었는지. */
    pub(crate) fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /** @brief 항목 수. */
    pub(crate) fn len(&self) -> usize {
        self.sources.len()
    }

    /** @brief 이 집합이 쓰는 바이트. */
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

    /** @brief 순위로 출처를 얻는다. */
    pub(crate) fn source(&self, index: usize) -> Option<u32> {
        self.sources.get(index)
    }

    /** @brief 순위 순서의 출처를 훑는다. 문자열 보존 없이 통계를 만들 때 쓴다. */
    pub(crate) fn indexed_sources(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        (0..self.len()).filter_map(|index| self.source(index).map(|source| (index, source)))
    }

    /**
     * @brief 오토마톤이 받아들이는 모든 이름을 순위 순서로 재구성한다.
     * @details 수정 때문에 테이블로 되돌리거나 hit 보고 이름을 만들 때만 쓰는 콜드 경로다.
     *          질의 경로는 입력 문자열의 슬라이스를 쓰므로 이 순회를 하지 않는다.
     * @warning 재귀 호출을 쓰지 않는다. 손상 캐시나 긴 테스트 키가 호출 스택을 소진하면 안 된다.
     */
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
        // 네 번째 값은 이 칸에 들어오며 밀어 넣은 글자 수다. 엣지 하나가 여러 글자를
        // 실으므로 돌아 나갈 때 한 글자만 빼면 이름이 어긋난다.
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
    /** @brief 맵을 버퍼에 인코딩한다. */
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

    /** @brief 맵을 청크 단위로 스트리밍한다. */
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

    /**
     * @brief 인코딩된 맵을 읽는다.
     * @warning 읽은 뒤 구조를 전부 검증한다. 순환, 범위 밖 인덱스, 엣지 순서, 도달 가능성,
     *          부분 순위를 모두 본다. 하나라도 어긋난 채 쓰면 판정 경로가 무한 루프에
     *          빠지거나 엉뚱한 곳을 읽는다.
     */
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

    /** @brief 정확히 일치하는 항목을 찾는다. */
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

    /**
     * @brief 가장 긴 접미사 일치를 찾는다.
     * @note 라벨 경계에서만 맞는 것으로 본다. 그러지 않으면 evil-example.com이
     *       example.com 규칙에 걸린다.
     */
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

    /** @brief 순위로 항목을 되찾는다. */
    fn matched_entry<'a>(&self, rank: u32, key: &'a str) -> Option<CompactMatch<'a>> {
        let index = rank as usize;
        self.sources.get(index)?;
        Some(CompactMatch { key, index })
    }

    /** @brief 인코딩했을 때의 크기. */
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

    /** @brief 읽은 구조가 온전한지 전부 확인한다. */
    fn validate_decoded(&self) -> Result<(), &'static str> {
        if self.edge_labels.len() != self.edge_targets.len()
            || self.edge_labels.len() != self.edge_outputs.len()
        {
            return Err("Compact map array length invariant violated");
        }

        // 엣지 수는 이웃한 두 시작 자리의 차이로 얻는다. 그래서 이 배열이 단조가 아니면
        // 상태 하나가 조용히 사라지고, 검증은 통과한 채로 엉뚱한 엣지를 읽게 된다.
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
        // 남는 비트를 0 으로 못 박지 않으면 같은 집합이 서로 다른 바이트로 인코딩된다.
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
        // 0번 자리는 "이어지는 글자 없음" 표시이므로 글자로 읽히면 안 된다.
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

    /**
     * @brief 이름을 뒤에서부터 읽으며 엣지 하나만큼 나아간다.
     * @param bytes 원래 순서의 이름. 뒤에서부터 읽는다.
     * @param eaten 지금까지 먹은 글자 수.
     * @return 다음 상태, 누적 순위, 그리고 새로 늘어난 먹은 글자 수.
     * @note 엣지 하나가 여러 글자를 먹을 수 있으므로 몇 글자를 먹었는지 함께 돌려준다.
     */
    #[inline]
    fn step(
        &self,
        state_index: usize,
        rank: u32,
        bytes: &[u8],
        eaten: usize,
    ) -> Option<(usize, u32, usize)> {
        // 엣지를 고를 때는 엣지 범위만 필요하다. 종료 여부까지 함께 읽으면 글자마다 다른
        // 배열을 한 번 더 건드리게 되고, 그 값은 여기서 쓰이지도 않는다.
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

/** @brief 32비트 값을 읽는다. */
fn read_u32(input: &mut &[u8]) -> Result<u32, &'static str> {
    let bytes = take_bytes(input, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/** @brief 64비트 값을 읽는다. */
fn read_u64(input: &mut &[u8]) -> Result<u64, &'static str> {
    let bytes = take_bytes(input, 8)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
}

/** @brief 8비트 값을 읽는다. */
fn read_u8(input: &mut &[u8]) -> Result<u8, &'static str> {
    Ok(take_bytes(input, 1)?[0])
}

/** @brief 정해진 길이만큼 가져온다. */
fn take_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], &'static str> {
    let bytes = input.get(..len).ok_or("Compact map data is truncated")?;
    *input = &input[len..];
    Ok(bytes)
}

/** @brief 길이를 미리 잡은 벡터. 상한을 넘으면 오류다. */
fn reserved_vec<T>(len: usize, error: &'static str) -> Result<Vec<T>, &'static str> {
    let mut values = Vec::new();
    values.try_reserve_exact(len).map_err(|_| error)?;
    Ok(values)
}

/** @brief 값으로 채운 벡터. */
fn filled_vec<T: Clone>(len: usize, value: T, error: &'static str) -> Result<Vec<T>, &'static str> {
    let mut values = reserved_vec(len, error)?;
    values.resize(len, value);
    Ok(values)
}

/** @brief 바이트를 복사해 가져온다. */
fn copy_bytes(input: &mut &[u8], len: usize, error: &'static str) -> Result<Vec<u8>, &'static str> {
    let source = take_bytes(input, len)?;
    let mut bytes = reserved_vec(len, error)?;
    bytes.extend_from_slice(source);
    Ok(bytes)
}

/** @brief 32비트 값 배열을 읽는다. */
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

/** @brief 출처 테이블을 읽는다. 표현 번호가 모르는 값이거나 비최소면 거부한다. */
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

/** @brief 이 표현의 인코딩 크기. */
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

/**
 * @brief 뒤집은 순서로 문자열을 비교한다.
 * @details 도메인을 뒤에서부터 보면 같은 상위 도메인끼리 모인다. 그 배치라야 접미사를
 *          공유하는 상태를 하나로 합칠 수 있다.
 */
fn reverse_cmp(left: &str, right: &str) -> Ordering {
    left.as_bytes()
        .iter()
        .rev()
        .cmp(right.as_bytes().iter().rev())
}

#[derive(Debug)]
/** @brief 엣지를 담는 아레나. 자유 목록으로 곳을 되쓴다. */
struct EdgeArena {
    /** @brief 엣지의 글자. */
    label: Vec<u8>,
    /** @brief 엣지가 가리키는 상태. */
    target: Vec<u32>,
    /** @brief 같은 상태에서 나가는 다음 엣지. */
    next: Vec<u32>,
    /** @brief 다시 쓸 수 있는 곳들의 머리. */
    free: u32,
    /** @brief 지금 쓰이고 있는 엣지 수. */
    live: usize,
}

impl EdgeArena {
    /** @brief 빈 아레나. */
    fn new() -> Self {
        Self {
            label: Vec::new(),
            target: Vec::new(),
            next: Vec::new(),
            free: NONE,
            live: 0,
        }
    }

    /** @brief 엣지 하나를 잡는다. */
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

    /** @brief 엣지 체인을 놓아 자유 목록에 넣는다. */
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
/** @brief 만드는 중의 상태 하나. */
struct BuildState {
    /** @brief 이 상태가 이름의 끝인지. */
    terminal: bool,

    /** @brief 이 상태에서 나가는 첫 엣지. */
    edge_head: u32,
    /** @brief 같은 모양의 상태를 잇는 다음 위치. */
    register_next: u32,
}

/** @brief 만드는 중 상태 하나의 크기를 못 고정한다. */
const _: () = assert!(size_of::<Option<BuildState>>() == 12);

impl BuildState {
    /** @brief 빈 상태. */
    fn new() -> Self {
        Self {
            terminal: false,
            edge_head: NONE,
            register_next: NONE,
        }
    }
}

/**
 * @brief 최소 비순환 오토마톤을 만드는 것.
 * @details 정렬된 입력을 순서대로 넣으며 확정된 뒷부분을 바로 최소화한다. 전부 넣은 뒤
 *          최소화하면 중간 메모리가 훨씬 커진다.
 */
struct DawgBuilder {
    /** @brief 만드는 중인 상태들. */
    states: Vec<Option<BuildState>>,
    /** @brief 다시 쓸 수 있는 상태 곳들. */
    free: Vec<u32>,
    /** @brief 엣지 저장소. */
    edges: EdgeArena,

    /** @brief 같은 모양의 상태를 찾는 곳. */
    buckets: Vec<u32>,
    /** @brief 이미 고정해 합친 상태 수. */
    registered: usize,
    /** @brief 지금 넣고 있는 이름이 지나온 상태들. */
    path: Vec<u32>,
    /** @brief 직전에 넣은 이름. 앞부분이 같으면 그만큼 다시 쓴다. */
    previous: Vec<u8>,
}

impl DawgBuilder {
    /** @brief 빈 빌더. */
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

    /** @brief 뒤집은 도메인 하나를 넣는다. 입력은 정렬돼 있어야 한다. */
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

    /** @brief 남은 상태를 최소화하고 입력 검증에 쓸 읽기 전용 그래프로 만든다. */
    fn complete(&mut self) {
        self.minimize(0);
        self.buckets = Vec::new();
        self.path.clear();
        self.previous.clear();
    }

    /** @brief 완성된 그래프가 뒤집은 이름을 받아들이는지. */
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

    /** @brief 최소화를 마친 그래프를 연속 배열로 고정한다. */
    fn finish_completed(self) -> (Box<[PackedState]>, Box<[u8]>, Box<[u32]>, Box<[u32]>, u32) {
        self.pack(0)
    }

    /** @brief 공통 접두사보다 뒤쪽 상태들을 확정하고 같은 것끼리 합친다. */
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

    /** @brief 같은 상태가 이미 있으면 그것을 쓰고, 없으면 등록한다. */
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
    /** @brief 등록부 버킷 마스크. */
    fn bucket_mask(&self) -> u64 {
        self.buckets.len() as u64 - 1
    }

    /** @brief 등록부를 키운다. */
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

    /** @brief 새 상태를 만든다. */
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

    /** @brief 상태를 빌린다. */
    fn state(&self, id: u32) -> &BuildState {
        self.states[id as usize]
            .as_ref()
            .expect("Active compact filter state must exist")
    }

    /** @brief 상태를 바꿀 수 있게 빌린다. */
    fn state_mut(&mut self, id: u32) -> &mut BuildState {
        self.states[id as usize]
            .as_mut()
            .expect("Active compact filter state must exist")
    }

    /** @brief 두 상태가 같은 언어를 나타내는지. 엣지와 종단 여부를 모두 본다. */
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

    /** @brief 상태의 해시. 같은 상태를 찾는 데 쓴다. */
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

    /** @brief 상태의 엣지들을 모은다. */
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
    /** @brief 만든 상태들을 연속 배열로 고정한다. */
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

/**
 * @brief 각 상태에서 도달할 수 있는 단어 수를 센다.
 * @details 이 값이 순위 누적의 재료다. 훑으면서 지나친 가지의 단어 수를 더하면 정렬
 *          순서상의 번호가 나온다.
 */
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
/** @brief 고정한 형태가 원본과 같은 답을 내는지, 그리고 조작된 인코딩을 거부하는지. */
mod tests {
    use super::*;

    #[test]
    #[ignore = "빌더 계량 프로브: cargo test -p onetdns-filter --release -- --ignored --nocapture"]
    /** @brief 만드는 중의 자료구조 크기를 확인한다. 커지면 로드 메모리가 함께 커진다. */
    fn probe_dawg_builder_shape() {
        /** @brief 테스트에 쓸 규칙 수. */
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

    /** @brief 항목들로 고정한 집합을 만든다. */
    fn compact(entries: &[(&str, u32)]) -> CompactDomainMap {
        CompactDomainMap::try_from_table(table_of(entries)).expect("작은 map은 압축 가능")
    }

    #[test]
    /** @brief 고정를 포기하면 모든 항목이 출처와 함께 되돌아오는지. */
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

    /** @brief 항목들로 테이블을 만든다. */
    fn table_of(entries: &[(&str, u32)]) -> DomainTable {
        let mut table = DomainTable::default();
        for (domain, source) in entries {
            table.insert_if_absent(domain, *source);
        }
        table
    }

    /** @brief 기준 맵에서 테이블을 만든다. */
    fn table_from_reference(reference: &DomainMap) -> DomainTable {
        let mut table = DomainTable::default();
        for (domain, source) in reference {
            table.insert_if_absent(domain, *source);
        }
        table
    }

    /** @brief 인코딩에서 출처 테이블이 시작하는 위치. */
    /** @brief 상태 영역이 차지하는 바이트. */
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

    /** @brief 콜드 순회 결과를 비교하기 쉬운 소유 형태로 모은다. */
    fn owned_entries(map: &CompactDomainMap) -> Vec<(String, u32)> {
        let mut entries = Vec::with_capacity(map.len());
        map.for_each_entry(|_, key, source| entries.push((key.to_string(), source)))
            .expect("정상 오토마톤 순회");
        entries
    }

    #[test]
    /** @brief 정확 일치와 최장 접미사가 원래 값을 주는지. */
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
    /** @brief 일치 문자열이 보존 복사본이 아니라 질의 버퍼를 빌리는지. */
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
    /** @brief 출처가 모두 같으면 값 하나만 담는지. */
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
    /** @brief 작은 값 범위에서 1바이트 표현을 쓰고 없음 표시도 보존되는지. */
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
    /** @brief 중간 값 범위에서 2바이트 표현을 쓰는지. */
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
    /** @brief 없음 표시와 겹치는 값이 오면 좁은 표현으로 줄이지 않는지. 줄이면 값이 없음으로 둔갑한다. */
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
    /** @brief 모르는 표현과 비최소 인코딩을 거부하는지. */
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
    /** @brief 접미사 일치가 라벨 경계에서만 걸리는지. 아니면 남의 도메인이 이 서버의 규칙에 걸린다. */
    fn suffix_match_requires_a_dns_label_boundary() {
        let map = compact(&[("example.com", 1), ("ample.net", 2)]);
        assert!(map.lookup_suffix("notexample.com").is_none());
        assert!(map.lookup_suffix("sample.net").is_none());
        assert!(map.lookup_suffix("x.example.com").is_some());
    }

    #[test]
    /** @brief 누적 순위가 정렬된 모든 항목을 정확히 가리키는지. */
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
    /** @brief 빌더 추정이 좁은 usize 폭에서 넘쳐 판정이 뒤집히지 않는지. */
    fn build_peak_estimate_survives_narrow_usize_width() {
        // 4만 항목 wide 목록에서 실제로 나온 표본값이다. usize가 32비트면 이 곱이 넘쳐
        // 포화하고, 포화값을 표본 수로 나누면 131,072이 되어 direct를 고른다.
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
        // 접미사가 잘 겹쳐 오토마톤이 작은 목록은 그대로 direct여야 한다.
        assert!(!staging_beats_direct(
            79_768,
            SAMPLE_ENTRIES,
            ENTRIES,
            1_331_734
        ));
    }

    #[test]
    /** @brief 빌드 피크 경로가 압축이 잘 되는 목록과 wide 목록을 구분하는지. */
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
            // 폭에 따라 잘리면 32비트와 64비트가 서로 다른 픽스처를 재게 된다.
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
    /** @brief 무작위 질의에서 단순 구현과 답이 같은지. */
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
    /**
     * @brief 같은 접미사 언어를 가진 상태들이 실제로 합쳐지는지. 최소화의 핵심이다.
     * @details ab 와 ac 는 뒤에서 읽으면 ba 와 ca 다. 남은 a 를 읽는 자리는 두 갈래가
     *          같으므로 하나로 합쳐지고, 그 자리는 분기가 없어 앞 엣지에 접힌다. 그래서
     *          뿌리와 끝 두 상태만 남고, 두 엣지가 같은 끝과 같은 글자 묶음을 가리킨다.
     */
    fn equivalent_suffix_languages_share_states() {
        let map = compact(&[("ab", 1), ("ac", 2)]);
        assert_eq!(map.state_count(), 2);
        assert_eq!(map.edge_labels.len(), 2);
        assert_eq!(map.edge_targets[0], map.edge_targets[1]);
        assert_eq!(map.edge_tails[0], map.edge_tails[1]);
        assert_eq!(map.edge_tail(0), Some(b"a".as_slice()));
    }

    #[test]
    /**
     * @brief 접을 글자가 상한을 넘는 이름도 제대로 찾아지는지.
     * @details 한 엣지가 실을 수 있는 글자 수는 길이를 한 바이트에 담는 탓에 한계가 있다.
     *          거기서 멈춘 자리를 지나가는 자리로 보고 지워 버리면 그 엣지가 가리킬 상태가
     *          사라진다. 상한을 여러 번 넘는 길이로 그 경우를 건드린다.
     */
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
    /** @brief 빈 집합도 특별 처리 없이 질의되는지. */
    fn empty_map_is_queryable_without_special_allocation() {
        let map = CompactDomainMap::try_from_table(DomainTable::default()).expect("empty");
        assert!(map.is_empty());
        assert_eq!(map.storage_bytes(), 0);
        assert!(map.lookup_exact("example.com").is_none());
        assert!(map.lookup_suffix("example.com").is_none());
    }

    #[test]
    /** @brief 인코딩 왕복에서 순위, 출처, 접미사가 보존되는지. */
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
    /** @brief 순환이 든 인코딩을 거부하고 어떤 변조에도 패닉하지 않는지. 순환이 남으면 판정이 무한 루프에 빠진다. */
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
    /** @brief 아주 긴 키에서도 호출 스택을 쓰지 않는지. 재귀였다면 스택이 넘친다. */
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
