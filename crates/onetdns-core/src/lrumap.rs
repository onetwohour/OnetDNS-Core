//! Bounded LRU map, the storage behind the response cache and rate-limit counters. Nodes live in an
//! arena (Vec) linked by an intrusive doubly linked list in recency order. 32-bit indexes instead
//! of pointers halve the per-node link cost, which dominates resident memory once a cache holds
//! millions of entries.

use std::borrow::Borrow;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};

type NodeIndex = u32;

/// Empty link. new keeps the capacity below this, so it never collides with an index.
const NIL: NodeIndex = NodeIndex::MAX;

type Digest = u32;

/// Passes an already computed hash through: the seeded hasher hashes each key once, and the index
/// map uses the result as is.
///
/// write_u32 multiplies by the golden-ratio constant. A raw 32-bit digest leaves the top bits zero,
/// so the top 7 bits std's map keeps as its control byte would all be equal and collisions would
/// pile up.
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut value = 0u64;
        for (shift, byte) in bytes.iter().take(8).enumerate() {
            value |= u64::from(*byte) << (shift * 8);
        }
        self.0 = value;
    }

    fn write_u32(&mut self, value: u32) {
        self.0 = u64::from(value).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/// Digest to the head of its collision chain.
type HashIndex = HashMap<Digest, NodeIndex, BuildHasherDefault<IdentityHasher>>;

/// prev/next link the recency list; hash_next links nodes with the same digest. Both chains run
/// through the node, so collisions need no separate storage.
struct Node<K, V> {
    key: K,
    val: V,
    prev: NodeIndex,
    next: NodeIndex,

    hash_next: NodeIndex,
}

/// Digests are 32 bits, so collisions do happen; lookups walk the chain comparing full keys.
/// Trusting the digest alone would let two names share one cache entry.
///
/// head and tail are NIL or point to active nodes; every index in free is None in nodes.
pub struct LruMap<K, V> {
    cap: usize,
    map: HashIndex,
    hash_builder: RandomState,
    nodes: Vec<Option<Node<K, V>>>,
    free: Vec<NodeIndex>,
    head: NodeIndex,
    tail: NodeIndex,
    len: usize,
}

/// The configured capacity is not reserved up front, so a server with a large cache does not hold
/// all that memory before filling it.
const INITIAL_RESERVE: usize = 1024;

impl<K: Hash + Eq, V> LruMap<K, V> {
    /// `cap` 0 becomes 1. Panics unless cap < u32::MAX: silently truncating a bad setting would
    /// make link indexes collide with NIL and corrupt the list.
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        assert!(
            cap < NIL as usize,
            "LRU capacity must be less than u32::MAX"
        );
        let reserve = cap.min(INITIAL_RESERVE);
        Self {
            cap,
            map: HashMap::with_capacity_and_hasher(reserve, BuildHasherDefault::default()),
            hash_builder: RandomState::new(),
            nodes: Vec::with_capacity(reserve),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find_index(key).is_some()
    }

    /// Does not change recency, for stats and diagnostics where reading must not disturb eviction
    /// order.
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        Some(&self.node(idx).val)
    }

    /// Does not change recency. Background tasks use it to edit entries; bumping recency would keep
    /// entries nobody asks for from being evicted.
    pub fn peek_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.nodes[idx as usize].as_mut().map(|node| &mut node.val)
    }

    /// Keeps the arena allocation so a reload does not allocate again.
    pub fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
        self.len = 0;
    }

    /// Seeded, so inputs cannot be chosen to collide. Truncates the 64-bit hash to 32 bits; the
    /// chain walk and full key comparison handle collisions.
    #[inline]
    fn key_hash<Q: Hash + ?Sized>(&self, key: &Q) -> Digest {
        self.hash_builder.hash_one(key) as Digest
    }

    fn find_index<Q>(&self, key: &Q) -> Option<NodeIndex>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.key_hash(key);
        self.find_index_with_hash(hash, key)
    }

    /// Takes a digest already computed, so insert and remove do not hash twice. Compares the full
    /// key even when digests match; skipping that lets two colliding names read each other's cache
    /// entries.
    fn find_index_with_hash<Q>(&self, hash: Digest, key: &Q) -> Option<NodeIndex>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut index = *self.map.get(&hash)?;
        while index != NIL {
            let node = self.node(index);
            if <K as Borrow<Q>>::borrow(&node.key) == key {
                return Some(index);
            }
            index = node.hash_next;
        }
        None
    }

    /// Panics on an inactive index: indexes are made only internally, so an inactive one means the
    /// structure is already corrupt.
    #[inline]
    fn node(&self, idx: NodeIndex) -> &Node<K, V> {
        self.nodes[idx as usize]
            .as_ref()
            .expect("Active LRU list node must exist")
    }

    fn set_prev(&mut self, idx: NodeIndex, prev: NodeIndex) {
        self.nodes[idx as usize]
            .as_mut()
            .expect("Active LRU list node must exist")
            .prev = prev;
    }

    fn set_next(&mut self, idx: NodeIndex, next: NodeIndex) {
        self.nodes[idx as usize]
            .as_mut()
            .expect("Active LRU list node must exist")
            .next = next;
    }

    /// Also moves head or tail when the node is at an end.
    fn unlink(&mut self, idx: NodeIndex) {
        let (prev, next) = {
            let n = self.node(idx);
            (n.prev, n.next)
        };
        if prev != NIL {
            self.set_next(prev, next);
        } else {
            self.head = next;
        }
        if next != NIL {
            self.set_prev(next, prev);
        } else {
            self.tail = prev;
        }
    }

    /// The node must already be unlinked.
    fn push_front(&mut self, idx: NodeIndex) {
        let old_head = self.head;
        self.set_prev(idx, NIL);
        self.set_next(idx, old_head);
        if old_head != NIL {
            self.set_prev(old_head, idx);
        }
        self.head = idx;
        if self.tail == NIL {
            self.tail = idx;
        }
    }

    fn move_front(&mut self, idx: NodeIndex) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.push_front(idx);
    }

    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.move_front(idx);
        Some(&self.node(idx).val)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.move_front(idx);
        self.nodes[idx as usize].as_mut().map(|node| &mut node.val)
    }

    /// Inserts or overwrites and makes the entry most recent. At capacity it evicts the oldest
    /// first; if growing the arena then fails to allocate, it evicts once more to make room. With
    /// still no slot it returns without inserting: a missed cache insert is not a correctness
    /// problem, but panicking under memory pressure kills the server.
    pub fn put(&mut self, key: K, val: V) {
        let hash = self.key_hash(&key);
        if let Some(idx) = self.find_index_with_hash(hash, &key) {
            self.nodes[idx as usize]
                .as_mut()
                .expect("Active LRU list node must exist")
                .val = val;
            self.move_front(idx);
            return;
        }
        if self.len >= self.cap {
            self.evict_lru();
        }

        if self.free.is_empty() && self.try_grow_one().is_err() {
            self.evict_lru();
            if self.free.is_empty() {
                return;
            }
        }
        let hash_next = self.map.get(&hash).copied().unwrap_or(NIL);
        let node = Node {
            key,
            val,
            prev: NIL,
            next: NIL,
            hash_next,
        };
        let idx = if let Some(i) = self.free.pop() {
            self.nodes[i as usize] = Some(node);
            i
        } else {
            let index = NodeIndex::try_from(self.nodes.len())
                .expect("LRU node index must fit the u32 range checked at construction");
            self.nodes.push(Some(node));
            index
        };
        self.map.insert(hash, idx);
        self.len += 1;
        self.push_front(idx);
    }

    pub fn pop<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.key_hash(key);
        let idx = self.find_index_with_hash(hash, key)?;
        Some(self.remove_index(idx, hash).val)
    }

    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        let tail = self.tail;
        if tail == NIL {
            return None;
        }
        let hash = self.key_hash(&self.node(tail).key);
        let node = self.remove_index(tail, hash);
        Some((node.key, node.val))
    }

    /// Removes every entry for which `keep` returns false, without changing the recency order of
    /// the rest. `keep` runs once per entry, in no particular order.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        for slot in 0..self.nodes.len() {
            let kept = match self.nodes[slot].as_mut() {
                Some(node) => keep(&node.key, &mut node.val),
                None => continue,
            };
            if !kept {
                let index = NodeIndex::try_from(slot)
                    .expect("LRU node index must fit the u32 range checked at construction");
                let hash = self.key_hash(&self.node(index).key);
                self.remove_index(index, hash);
            }
        }
    }

    /// Unlinks the node from both chains, frees its slot, and returns the node. A node left in the
    /// collision chain would leave a link to a freed slot for the next lookup to read; a broken
    /// chain cannot be repaired, so this panics.
    fn remove_index(&mut self, index: NodeIndex, hash: Digest) -> Node<K, V> {
        let hash_next = self.node(index).hash_next;
        let head = *self.map.get(&hash).expect("LRU hash chain head must exist");
        if head == index {
            if hash_next == NIL {
                self.map.remove(&hash);
            } else {
                self.map.insert(hash, hash_next);
            }
        } else {
            let mut previous = head;
            loop {
                let next = self.node(previous).hash_next;
                assert!(next != NIL, "LRU hash collision chain is broken");
                if next == index {
                    self.nodes[previous as usize]
                        .as_mut()
                        .expect("Active LRU hash chain node must exist")
                        .hash_next = hash_next;
                    break;
                }
                previous = next;
            }
        }
        self.unlink(index);
        self.len -= 1;
        self.free.push(index);
        self.nodes[index as usize]
            .take()
            .expect("LRU node to remove must exist")
    }

    fn evict_lru(&mut self) {
        self.pop_lru();
    }

    /// Makes room for one more entry; a no-op while reserved space remains. Grows with try_reserve,
    /// so running out of memory is an Err, which the caller answers by evicting.
    fn try_grow_one(&mut self) -> Result<(), ()> {
        if self.nodes.len() < self.nodes.capacity() && self.map.len() < self.map.capacity() {
            return Ok(());
        }
        self.nodes.try_reserve(1).map_err(|_| ())?;
        self.map.try_reserve(1).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as ReferenceMap;

    #[derive(Debug, PartialEq, Eq)]
    struct NonCloneKey(u32);

    impl Hash for NonCloneKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CollidingKey(u32);

    impl Hash for CollidingKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            0u8.hash(state);
        }
    }

    #[test]
    fn index_hasher_spreads_into_the_control_byte() {
        let mut seen = std::collections::HashSet::new();
        for value in 0..256u32 {
            let mut hasher = IdentityHasher::default();
            value.hash(&mut hasher);
            seen.insert((hasher.finish() >> 57) as u8);
        }
        assert!(
            seen.len() >= 64,
            "상위 7비트가 {}가지뿐입니다. 인덱스 키 확산이 빠졌습니다",
            seen.len()
        );
    }

    #[test]
    fn basic_get_put() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.put(1, 10);
        m.put(2, 20);
        assert_eq!(m.get(&1), Some(&10));
        assert_eq!(m.get(&2), Some(&20));
        assert_eq!(m.len(), 2);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    /// Larger indexes would cost more memory per entry.
    fn node_links_stay_compact() {
        assert_eq!(
            std::mem::size_of::<Node<Box<[u8]>, [u8; 16]>>(),
            48,
            "LRU 링크나 불변 키 헤더가 다시 넓어졌습니다"
        );
    }

    #[test]
    #[should_panic(expected = "LRU capacity must be less than u32::MAX")]
    fn rejects_capacity_that_cannot_be_indexed() {
        let _ = LruMap::<u8, u8>::new(u32::MAX as usize);
    }

    #[test]
    fn owned_vec_keys_support_borrowed_slice_lookup() {
        let mut map: LruMap<Vec<u8>, u32> = LruMap::new(2);
        map.put(vec![1, 2, 3], 7);

        assert_eq!(map.get([1, 2, 3].as_slice()), Some(&7));
        assert!(map.contains_key([1, 2, 3].as_slice()));
        assert_eq!(map.pop([1, 2, 3].as_slice()), Some(7));
    }

    #[test]
    fn evicts_lru() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.put(1, 10);
        m.put(2, 20);

        assert_eq!(m.get(&1), Some(&10));
        m.put(3, 30);
        assert_eq!(m.get(&2), None);
        assert_eq!(m.get(&1), Some(&10));
        assert_eq!(m.get(&3), Some(&30));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn pop_returns_value() {
        let mut m: LruMap<u32, String> = LruMap::new(4);
        m.put(1, "a".into());
        assert_eq!(m.pop(&1), Some("a".into()));
        assert_eq!(m.pop(&1), None);
        assert!(m.is_empty());
    }

    #[test]
    fn pop_lru_returns_oldest_and_updates_map() {
        let mut m = LruMap::new(3);
        m.put(1, 10);
        m.put(2, 20);
        m.put(3, 30);
        assert_eq!(m.get(&1), Some(&10));

        assert_eq!(m.pop_lru(), Some((2, 20)));
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&2), None);
    }

    #[test]
    fn update_existing() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.put(1, 10);
        m.put(1, 11);
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn slot_reuse_after_evict() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        for i in 0..10 {
            m.put(i, i * 10);
        }

        assert_eq!(m.len(), 2);
        assert_eq!(m.get(&9), Some(&90));
        assert_eq!(m.get(&8), Some(&80));
        assert_eq!(m.get(&0), None);
    }

    #[test]
    fn get_mut_updates_and_refreshes_lru() {
        let mut m = LruMap::new(2);
        m.put(1, 10);
        m.put(2, 20);
        *m.get_mut(&1).unwrap() = 11;
        m.put(3, 30);
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.get(&2), None);
    }

    #[test]
    fn keys_do_not_need_clone() {
        let mut map = LruMap::new(2);
        map.put(NonCloneKey(1), 10);
        map.put(NonCloneKey(2), 20);

        assert_eq!(map.get(&NonCloneKey(1)), Some(&10));
        assert_eq!(map.pop_lru(), Some((NonCloneKey(2), 20)));
    }

    #[test]
    /// Mixing them up would serve another name's answer.
    fn hash_collisions_preserve_distinct_keys_and_lru_order() {
        let mut map = LruMap::new(3);
        map.put(CollidingKey(1), 10);
        map.put(CollidingKey(2), 20);
        map.put(CollidingKey(3), 30);
        assert_eq!(map.get(&CollidingKey(2)), Some(&20));
        assert_eq!(map.pop(&CollidingKey(1)), Some(10));
        map.put(CollidingKey(4), 40);
        map.put(CollidingKey(5), 50);

        assert_eq!(map.get(&CollidingKey(3)), None);
        assert_eq!(map.peek(&CollidingKey(2)), Some(&20));
        assert_eq!(map.peek(&CollidingKey(4)), Some(&40));
        assert_eq!(map.peek(&CollidingKey(5)), Some(&50));
        assert_eq!(map.pop_lru(), Some((CollidingKey(2), 20)));
    }

    #[test]
    fn randomized_operations_match_reference_model() {
        const CAPACITY: usize = 8;
        let mut map = LruMap::new(CAPACITY);
        let mut reference = ReferenceMap::<u16, u32>::new();
        let mut order = Vec::<u16>::new();
        let mut state = 0x6a09_e667_f3bc_c909u64;

        for step in 0..50_000u32 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = ((state >> 32) as u16) & 31;
            match state & 15 {
                0..=6 => {
                    if !reference.contains_key(&key) && reference.len() == CAPACITY {
                        let evicted = order.pop().unwrap();
                        reference.remove(&evicted);
                    }
                    reference.insert(key, step);
                    touch(&mut order, key);
                    map.put(key, step);
                }
                7..=10 => {
                    let expected = reference.get(&key).copied();
                    assert_eq!(map.get(&key).copied(), expected);
                    if expected.is_some() {
                        touch(&mut order, key);
                    }
                }
                11..=12 => {
                    let expected = reference.remove(&key);
                    if expected.is_some() {
                        order.retain(|candidate| *candidate != key);
                    }
                    assert_eq!(map.pop(&key), expected);
                }
                13 => {
                    let expected = order.pop().map(|key| {
                        let value = reference.remove(&key).unwrap();
                        (key, value)
                    });
                    assert_eq!(map.pop_lru(), expected);
                }
                14 if step % 257 == 0 => {
                    map.clear();
                    reference.clear();
                    order.clear();
                }
                14 if step % 7 == 0 => {
                    // Survivors change only in value; eviction order stays the same.
                    let keep = |key: u16| (u32::from(key) ^ step) % 4 != 0;
                    map.retain(|key, value| {
                        *value = value.wrapping_add(1);
                        keep(*key)
                    });
                    reference.retain(|key, value| {
                        *value = value.wrapping_add(1);
                        keep(*key)
                    });
                    order.retain(|key| reference.contains_key(key));
                }
                15 => {
                    // Editing must not bump recency, or the pop_lru below would return a different
                    // key.
                    if let Some(value) = map.peek_mut(&key) {
                        *value = step;
                    }
                    if let Some(value) = reference.get_mut(&key) {
                        *value = step;
                    }
                }
                _ => {}
            }

            assert_eq!(map.len(), reference.len());
            assert_eq!(map.is_empty(), reference.is_empty());
            for candidate in 0..32u16 {
                assert_eq!(
                    map.contains_key(&candidate),
                    reference.contains_key(&candidate)
                );
                assert_eq!(map.peek(&candidate), reference.get(&candidate));
            }
        }
    }

    fn touch(order: &mut Vec<u16>, key: u16) {
        order.retain(|candidate| *candidate != key);
        order.insert(0, key);
    }
}
