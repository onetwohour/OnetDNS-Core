//! Domain table used only while loading, to drop duplicates as lists are read. Once loading
//! finishes it is sorted into the compact automaton and dropped.
//!
//! It replaces the std HashMap for layout: keys are appended to one arena, so no entry allocates on
//! its own. With lists of millions of lines that matters.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::mem::size_of;

/// Empty bucket or end of a chain.
const NONE: u32 = u32::MAX;

/// Marks a removed entry in its len field; it is skipped, not reused.
const DEAD: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct Entry {
    start: u32,

    len: u32,
    source: u32,

    next: u32,
}

#[derive(Debug)]
pub(crate) struct DomainTable {
    text: String,
    entries: Vec<Entry>,
    buckets: Vec<u32>,
    /// Seeded per process.
    hasher: RandomState,
    live: usize,

    overflowed: bool,
}

impl Default for DomainTable {
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

/// Past 32-bit offsets the insert is refused, not truncated: a truncated offset wraps and points at
/// the wrong key.
fn arena_fits(text_len: usize, key_len: usize, entry_count: usize) -> bool {
    text_len
        .checked_add(key_len)
        .is_some_and(|end| end <= u32::MAX as usize)
        && entry_count < NONE as usize
}

impl DomainTable {
    pub(crate) fn len(&self) -> usize {
        self.live
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn slot(&self, key: &str) -> usize {
        let mut hasher = self.hasher.build_hasher();
        hasher.write(key.as_bytes());
        (hasher.finish() & (self.buckets.len() as u64 - 1)) as usize
    }

    fn key_of(&self, entry: &Entry) -> &str {
        key_in(&self.text, entry)
    }

    /// The first wins: list order is priority, so overwriting would push out an earlier list's
    /// rule.
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.len != DEAD)
            .map(|entry| (self.key_of(entry), entry.source))
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.iter().map(|(key, _)| key)
    }

    /// The automaton builder needs sorted input.
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

    pub(crate) fn storage_bytes(&self) -> usize {
        self.text.capacity()
            + self.entries.capacity() * size_of::<Entry>()
            + self.buckets.capacity() * size_of::<u32>()
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
        let wanted = (self.live + additional).next_power_of_two().max(64);
        if wanted > self.buckets.len() {
            self.rebuild_buckets(wanted);
        }
    }

    fn grow(&mut self) {
        let wanted = (self.buckets.len() * 2).max(64);
        self.rebuild_buckets(wanted);
    }

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

fn key_in<'a>(text: &'a str, entry: &Entry) -> &'a str {
    let start = entry.start as usize;
    &text[start..start + entry.len as usize]
}

/// Input to the automaton builder.
pub(crate) struct SortedDomains {
    text: String,
    entries: Vec<Entry>,
}

impl SortedDomains {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        self.entries
            .iter()
            .map(|entry| (key_in(&self.text, entry), entry.source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    fn insert_is_first_wins_and_lookup_returns_the_stored_key() {
        let mut table = DomainTable::default();
        assert!(table.insert_if_absent("ads.example", 1));
        assert!(!table.insert_if_absent("ads.example", 2));
        assert_eq!(table.get_key_value("ads.example"), Some(("ads.example", 1)));
        assert_eq!(table.get_key_value("other.example"), None);
        assert_eq!(table.len(), 1);
    }

    #[test]
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
    fn reinsert_after_remove_takes_a_fresh_slot() {
        let mut table = DomainTable::default();
        table.insert_if_absent("a.example", 1);
        table.remove("a.example");
        assert!(table.insert_if_absent("a.example", 7));
        assert_eq!(table.get_key_value("a.example"), Some(("a.example", 7)));
        assert_eq!(table.len(), 1);
    }

    #[test]
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
