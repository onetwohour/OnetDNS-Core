/*!
 * @brief 로드 중에만 쓰는 도메인 테이블.
 *
 * @details 목록을 읽는 동안 중복을 걸러 내는 용도다. 다 읽으면 정렬해 최소 오토마톤으로
 *          굳히고 이 테이블은 버린다.
 * @note 표준 해시맵 대신 쓰는 이유는 배치 때문이다. 키를 아레나 하나에 이어 붙여 두어
 *       항목마다 할당이 생기지 않는다. 목록이 수백만 줄이면 그 차이가 크다.
 */

/** @brief 빈 슬롯 표시. */
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::mem::size_of;

/** @brief 가리키는 곳이 없음을 나타내는 값. */
const NONE: u32 = u32::MAX;

/** @brief 지워진 항목 표시. 슬롯을 재사용하지 않고 건너뛴다. */
const DEAD: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
/** @brief 테이블의 항목 하나. 키는 아레나 안의 범위로 가리킨다. */
struct Entry {
    /** @brief 이 이름이 텍스트에서 시작하는 위치. */
    start: u32,

    /** @brief 이 이름의 길이. */
    len: u32,
    /** @brief 어느 목록에서 왔는지. */
    source: u32,

    /** @brief 같은 위치로 몰린 다음 항목. */
    next: u32,
}

#[derive(Debug)]
/** @brief 도메인에서 출처 번호로 가는 테이블. */
pub(crate) struct DomainTable {
    /** @brief 이름들을 이어 붙인 텍스트. */
    text: String,
    /** @brief 이름마다의 위치와 길이. */
    entries: Vec<Entry>,
    /** @brief 해시값에서 항목으로 가는 버킷. */
    buckets: Vec<u32>,
    /** @brief 해시 함수. 프로세스마다 시드가 다르다. */
    hasher: RandomState,
    /** @brief 담긴 이름 수. */
    live: usize,

    /** @brief 담을 수 있는 수를 넘겼는지. */
    overflowed: bool,
}

impl Default for DomainTable {
    /** @brief 빈 테이블. */
    fn default() -> Self {
        Self {
            text: String::new(),
            entries: Vec::new(),
            buckets: Vec::new(),
            hasher: RandomState::new(),
            live: 0,
            overflowed: false,
        }
    }
}

/**
 * @brief 아레나가 32비트 오프셋 안에 들어가는지.
 * @warning 넘치면 자르지 않고 거부한다. 자르면 오프셋이 되감겨 엉뚱한 키를 가리킨다.
 */
fn arena_fits(text_len: usize, key_len: usize, entry_count: usize) -> bool {
    text_len
        .checked_add(key_len)
        .is_some_and(|end| end <= u32::MAX as usize)
        && entry_count < NONE as usize
}

impl DomainTable {
    /** @brief 살아 있는 항목 수. */
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    /** @brief 비었는지. */
    pub(crate) fn is_empty(&self) -> bool {
        self.live == 0
    }

    /** @brief 이 키가 들어갈 버킷 번호. */
    fn slot(&self, key: &str) -> usize {
        let mut hasher = self.hasher.build_hasher();
        hasher.write(key.as_bytes());
        (hasher.finish() & (self.buckets.len() as u64 - 1)) as usize
    }

    /** @brief 항목이 가리키는 키 문자열. */
    fn key_of(&self, entry: &Entry) -> &str {
        key_in(&self.text, entry)
    }

    /**
     * @brief 없을 때만 넣는다. 이미 있으면 그대로 둔다.
     * @note 먼저 온 것이 이긴다. 목록 순서가 우선순위를 뜻하므로, 나중 것으로 덮으면
     *       앞 목록의 규칙이 밀려난다.
     */
    pub(crate) fn insert_if_absent(&mut self, key: &str, source: u32) -> bool {
        if self.buckets.is_empty() {
            self.buckets = vec![NONE; 64];
        } else if self.live >= self.buckets.len() {
            self.grow();
        }
        let slot = self.slot(key);
        let mut cursor = self.buckets[slot];
        while cursor != NONE {
            let entry = self.entries[cursor as usize];
            if entry.len != DEAD && self.key_of(&entry) == key {
                return false;
            }
            cursor = entry.next;
        }

        if !arena_fits(self.text.len(), key.len(), self.entries.len()) {
            if !self.overflowed {
                self.overflowed = true;
                onetdns_core::warn!(
                    event = "filter.rule_table_overflow",
                    "Blocklist exceeds the 32-bit index limit; later rules were not added"
                );
            }
            return false;
        }
        let start = self.text.len() as u32;
        self.text.push_str(key);
        self.entries.push(Entry {
            start,
            len: key.len() as u32,
            source,
            next: self.buckets[slot],
        });
        self.buckets[slot] = (self.entries.len() - 1) as u32;
        self.live += 1;
        true
    }

    /** @brief 항목을 지운다. 같은 버킷의 다른 항목은 건드리지 않는다. */
    pub(crate) fn remove(&mut self, key: &str) -> bool {
        if self.buckets.is_empty() {
            return false;
        }
        let slot = self.slot(key);
        let mut previous = NONE;
        let mut cursor = self.buckets[slot];
        while cursor != NONE {
            let entry = self.entries[cursor as usize];
            if entry.len != DEAD && self.key_of(&entry) == key {
                if previous == NONE {
                    self.buckets[slot] = entry.next;
                } else {
                    self.entries[previous as usize].next = entry.next;
                }
                self.entries[cursor as usize].len = DEAD;
                self.live -= 1;
                return true;
            }
            previous = cursor;
            cursor = entry.next;
        }
        false
    }

    /** @brief 저장된 키와 출처를 찾는다. */
    pub(crate) fn get_key_value(&self, key: &str) -> Option<(&str, u32)> {
        if self.buckets.is_empty() {
            return None;
        }
        let mut cursor = self.buckets[self.slot(key)];
        while cursor != NONE {
            let entry = &self.entries[cursor as usize];
            if entry.len != DEAD && self.key_of(entry) == key {
                return Some((self.key_of(entry), entry.source));
            }
            cursor = entry.next;
        }
        None
    }

    /** @brief 모든 항목. 순서는 정해져 있지 않다. */
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.len != DEAD)
            .map(|entry| (self.key_of(entry), entry.source))
    }

    /** @brief 모든 키. */
    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.iter().map(|(key, _)| key)
    }

    /** @brief 정렬된 형태로 옮긴다. 오토마톤을 만들려면 순서가 정해져 있어야 한다. */
    pub(crate) fn into_sorted(
        mut self,
        order: impl Fn(&str, &str) -> std::cmp::Ordering,
    ) -> SortedDomains {
        self.buckets = Vec::new();
        let text = std::mem::take(&mut self.text);
        let mut entries = std::mem::take(&mut self.entries);
        entries.retain(|entry| entry.len != DEAD);
        entries.sort_unstable_by(|left, right| order(key_in(&text, left), key_in(&text, right)));
        SortedDomains { text, entries }
    }

    /** @brief 이 테이블이 쓰는 바이트. 로드 중 메모리 추적에 쓴다. */
    pub(crate) fn storage_bytes(&self) -> usize {
        self.text.capacity()
            + self.entries.capacity() * size_of::<Entry>()
            + self.buckets.capacity() * size_of::<u32>()
    }

    /** @brief 미리 슬롯을 잡는다. 로드 중 재할당을 줄인다. */
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
        let wanted = (self.live + additional).next_power_of_two().max(64);
        if wanted > self.buckets.len() {
            self.rebuild_buckets(wanted);
        }
    }

    /** @brief 테이블을 키운다. */
    fn grow(&mut self) {
        let wanted = (self.buckets.len() * 2).max(64);
        self.rebuild_buckets(wanted);
    }

    /** @brief 버킷을 다시 만든다. 지워진 항목은 옮기지 않는다. */
    fn rebuild_buckets(&mut self, len: usize) {
        self.buckets = vec![NONE; len];
        let mask = len as u64 - 1;
        for index in 0..self.entries.len() {
            if self.entries[index].len == DEAD {
                continue;
            }
            let slot = {
                let key = self.key_of(&self.entries[index]);
                let mut hasher = self.hasher.build_hasher();
                hasher.write(key.as_bytes());
                (hasher.finish() & mask) as usize
            };
            self.entries[index].next = self.buckets[slot];
            self.buckets[slot] = index as u32;
        }
    }
}

/** @brief 아레나에서 항목의 키를 잘라 낸다. */
fn key_in<'a>(text: &'a str, entry: &Entry) -> &'a str {
    let start = entry.start as usize;
    &text[start..start + entry.len as usize]
}

/** @brief 정렬된 도메인 목록. 오토마톤 만들기의 입력이다. */
pub(crate) struct SortedDomains {
    /** @brief 이름들을 이어 붙인 텍스트. */
    text: String,
    /** @brief 정렬한 이름들의 곳과 길이. */
    entries: Vec<Entry>,
}

impl SortedDomains {
    /** @brief 항목 수. */
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /** @brief 정렬된 순서로 훑는다. */
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.entries
            .iter()
            .map(|entry| (key_in(&self.text, entry), entry.source))
    }
}

#[cfg(test)]
/** @brief 먼저 온 것이 이기는 규칙, 삭제 뒤 재삽입, 그리고 아레나 상한. */
mod tests {
    use super::*;

    #[test]
    /** @brief 아레나 상한에서 자르지 않고 거부하는지. 자르면 엉뚱한 키를 가리킨다. */
    fn arena_limit_refuses_instead_of_truncating_the_offset() {
        assert!(arena_fits(0, 10, 0));
        assert!(arena_fits(u32::MAX as usize - 10, 10, 5));
        assert!(!arena_fits(u32::MAX as usize - 10, 11, 5));
        assert!(!arena_fits(u32::MAX as usize, 1, 5));
        assert!(!arena_fits(usize::MAX, 1, 5));
        assert!(arena_fits(0, 1, NONE as usize - 1));
        assert!(!arena_fits(0, 1, NONE as usize));
    }

    #[test]
    /** @brief 먼저 넣은 것이 이기고, 조회가 저장된 키를 주는지. */
    fn insert_is_first_wins_and_lookup_returns_the_stored_key() {
        let mut table = DomainTable::default();
        assert!(table.insert_if_absent("ads.example", 1));
        assert!(!table.insert_if_absent("ads.example", 2));
        assert_eq!(table.get_key_value("ads.example"), Some(("ads.example", 1)));
        assert_eq!(table.get_key_value("other.example"), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
    /** @brief 삭제가 같은 버킷의 다른 항목을 건드리지 않는지. */
    fn remove_unlinks_without_disturbing_bucket_mates() {
        let mut table = DomainTable::default();
        for index in 0..2000u32 {
            assert!(table.insert_if_absent(&format!("n{index}.example"), index));
        }
        assert_eq!(table.len(), 2000);
        for index in (0..2000u32).step_by(3) {
            assert!(table.remove(&format!("n{index}.example")));
            assert!(!table.remove(&format!("n{index}.example")));
        }
        let expected = 2000 - (0..2000).step_by(3).count();
        assert_eq!(table.len(), expected);
        assert_eq!(table.iter().count(), expected);
        for index in 0..2000u32 {
            let key = format!("n{index}.example");
            let found = table.get_key_value(&key);
            if index % 3 == 0 {
                assert_eq!(found, None, "{key}");
            } else {
                assert_eq!(found, Some((key.as_str(), index)), "{key}");
            }
        }
    }

    #[test]
    /** @brief 지운 뒤 다시 넣으면 새 곳을 쓰는지. */
    fn reinsert_after_remove_takes_a_fresh_slot() {
        let mut table = DomainTable::default();
        table.insert_if_absent("a.example", 1);
        table.remove("a.example");
        assert!(table.insert_if_absent("a.example", 7));
        assert_eq!(table.get_key_value("a.example"), Some(("a.example", 7)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    /** @brief 테이블을 키워도 항목이 하나도 새지 않는지. */
    fn growth_preserves_every_entry() {
        let mut table = DomainTable::default();
        for index in 0..5000u32 {
            table.insert_if_absent(&format!("x{index}.test"), index);
        }
        assert_eq!(table.len(), 5000);
        for index in 0..5000u32 {
            let key = format!("x{index}.test");
            assert_eq!(table.get_key_value(&key), Some((key.as_str(), index)));
        }
    }

    #[test]
    /** @brief 정렬 결과가 지운 항목을 빼고 주어진 순서를 따르는지. */
    fn into_sorted_skips_removed_entries_and_follows_the_given_order() {
        let mut table = DomainTable::default();
        for (index, key) in ["c.test", "a.test", "b.test"].iter().enumerate() {
            table.insert_if_absent(key, index as u32);
        }
        table.remove("b.test");
        let sorted = table.into_sorted(|left, right| left.cmp(right));
        assert_eq!(sorted.len(), 2);
        let pairs: Vec<(&str, u32)> = sorted.iter().collect();
        assert_eq!(pairs, [("a.test", 1), ("c.test", 0)]);
    }
}
