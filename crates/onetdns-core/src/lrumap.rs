/*!
 * @brief 용량 제한 LRU 맵. 응답 캐시와 속도 제한 카운터의 저장 구조다.
 *
 * @details 노드를 아레나(Vec)에 담고 침습적 이중 연결 리스트로 최근성 순서를 유지한다.
 *          포인터 대신 32비트 인덱스를 쓰는 이유는 노드 하나당 링크 비용이 절반이고, 캐시가
 *          수백만 항목까지 커질 때 그 차이가 상주 메모리를 좌우하기 때문이다.
 */

use std::borrow::Borrow;
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};

/** @brief 아레나 인덱스 폭. 포인터 대신 이걸 써서 노드당 링크 비용을 줄인다. */
type NodeIndex = u32;

/** @brief 빈 링크 표시. 생성 시 용량이 이 값보다 작음을 보장해 인덱스와 겹치지 않는다. */
const NIL: NodeIndex = NodeIndex::MAX;

/** @brief 인덱스에 저장하는 키 요약값 폭. */
type Digest = u32;

/**
 * @brief 이미 해시된 값을 통과시키는 해셔.
 *
 * @details 키 해싱은 무작위 시드 해셔가 한 번만 하고, 인덱스 맵은 그 결과를 재해싱 없이 쓴다.
 * @note write_u32만 황금비 상수를 곱한다. 요약값이 32비트라 그대로 넣으면 상위 비트가
 *       전부 0이 되어, 표준 맵이 슬롯 선택에 쓰는 상위 7비트가 상수가 되고 충돌이 몰린다.
 */
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    /** @brief 지금까지 섞은 값. */
    fn finish(&self) -> u64 {
        self.0
    }

    /** @brief 바이트열을 섞어 넣는다. */
    fn write(&mut self, bytes: &[u8]) {
        let mut value = 0u64;
        for (shift, byte) in bytes.iter().take(8).enumerate() {
            value |= u64::from(*byte) << (shift * 8);
        }
        self.0 = value;
    }

    /** @brief 32비트 수를 섞어 넣는다. */
    fn write_u32(&mut self, value: u32) {
        self.0 = u64::from(value).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    /** @brief 64비트 수를 섞어 넣는다. */
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/** @brief 요약값 → 충돌 체인 머리 인덱스. */
type HashIndex = HashMap<Digest, NodeIndex, BuildHasherDefault<IdentityHasher>>;

/**
 * @brief 아레나 노드 하나.
 * @details prev/next는 최근성 리스트의 링크, hash_next는 같은 요약값을 가진 다음
 *          노드다. 두 체인이 같은 노드를 공유하므로 별도 충돌 저장이 필요 없다.
 */
struct Node<K, V> {
    /** @brief 키. */
    key: K,
    /** @brief 값. */
    val: V,
    /** @brief 최근 순서에서 앞의 곳. */
    prev: NodeIndex,
    /** @brief 최근 순서에서 뒤의 곳. */
    next: NodeIndex,

    /** @brief 같은 위치로 몰린 다음 항목. */
    hash_next: NodeIndex,
}

/**
 * @brief 용량이 정해진 LRU 맵.
 *
 * @details 요약값이 32비트라 충돌이 실제로 일어난다. 그래서 체인을 훑으며 키 전체를
 *          비교한다. 요약값만 믿으면 서로 다른 이름이 같은 캐시 항목을 공유하게 된다.
 * @invariant head/tail이 NIL이거나 유효한 활성 노드를 가리킨다. free의 인덱스는
 *            nodes에서 None인 곳이다.
 */
pub struct LruMap<K, V> {
    /** @brief 담을 수 있는 개수. */
    cap: usize,
    /** @brief 키에서 곳으로 가는 인덱스. */
    map: HashIndex,
    /** @brief 해시 함수. 프로세스마다 시드가 다르다. */
    hash_builder: RandomState,
    /** @brief 실제 항목들이 놓인 위치. */
    nodes: Vec<Option<Node<K, V>>>,
    /** @brief 다시 쓸 수 있는 곳들. */
    free: Vec<NodeIndex>,
    /** @brief 가장 최근에 쓴 항목. */
    head: NodeIndex,
    /** @brief 가장 오래된 항목. 밀어낼 때 여기서 뺀다. */
    tail: NodeIndex,
    /** @brief 담긴 개수. */
    len: usize,
}

/**
 * @brief 초기 예약 항목 수.
 * @details 설정된 용량 전체를 미리 잡지 않는다. 큰 캐시를 설정한 서버가 실제로 채우기도
 *          전에 상주 메모리를 다 물고 시작하지 않게 하려는 것이다.
 */
const INITIAL_RESERVE: usize = 1024;

impl<K: Hash + Eq, V> LruMap<K, V> {
    /**
     * @brief 용량이 정해진 빈 맵을 만든다.
     * @param cap 최대 항목 수. 0은 1로 올린다.
     * @warning NIL과 겹치지 않도록 u32::MAX 미만이어야 한다. 넘으면 패닉한다.
     *          설정 오류를 조용히 잘라 받으면 링크 인덱스가 NIL과 충돌해 리스트가 깨진다.
     */
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

    /** @brief 현재 항목 수. */
    pub fn len(&self) -> usize {
        self.len
    }

    /** @brief 비어 있는지. */
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /** @brief 키가 있는지. 최근성 순서를 바꾸지 않는다. */
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find_index(key).is_some()
    }

    /**
     * @brief 값을 읽되 최근성 순서를 바꾸지 않는다.
     * @note 통계·진단처럼 조회 자체가 퇴거 순서를 흔들면 안 되는 곳에 쓴다.
     */
    pub fn peek<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        Some(&self.node(idx).val)
    }

    /**
     * @brief 값을 가변으로 빌리되 최근성 순서를 바꾸지 않는다.
     * @note 뒤에서 도는 작업이 항목을 고칠 때 쓴다. 그 작업이 순서를 올리면 아무도 찾지 않는
     *       항목이 퇴거되지 않고 남는다.
     */
    pub fn peek_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.nodes[idx as usize].as_mut().map(|node| &mut node.val)
    }

    /** @brief 모든 항목을 버린다. 아레나 할당은 유지해 재로드 시 다시 잡지 않는다. */
    pub fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
        self.len = 0;
    }

    /**
     * @brief 키의 요약값. 무작위 시드라 충돌 유도 공격에 내성이 있다.
     * @note 64비트 해시를 32비트로 자른다. 충돌은 체인 탐색과 키 전체 비교로 처리한다.
     */
    #[inline]
    fn key_hash<Q: Hash + ?Sized>(&self, key: &Q) -> Digest {
        self.hash_builder.hash_one(key) as Digest
    }

    /** @brief 키에 해당하는 노드 인덱스를 찾는다. */
    fn find_index<Q>(&self, key: &Q) -> Option<NodeIndex>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.key_hash(key);
        self.find_index_with_hash(hash, key)
    }

    /**
     * @brief 이미 구한 요약값으로 체인을 훑어 노드를 찾는다.
     * @details 삽입·제거 경로가 요약값을 재계산하지 않게 하려고 분리했다.
     * @warning 요약값이 같다고 멈추지 않고 키 전체를 비교한다. 이걸 생략하면 충돌한 두
     *          이름이 서로의 캐시 항목을 읽는다.
     */
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

    /**
     * @brief 활성 노드를 빌린다.
     * @warning 인덱스는 내부에서만 만들어지므로 활성이어야 한다. 비활성이면 자료구조가 이미
     *          깨진 것이라 계속 진행하지 않고 패닉한다.
     */
    #[inline]
    fn node(&self, idx: NodeIndex) -> &Node<K, V> {
        self.nodes[idx as usize]
            .as_ref()
            .expect("Active LRU list node must exist")
    }

    /** @brief 노드의 이전 링크를 교체한다. */
    fn set_prev(&mut self, idx: NodeIndex, prev: NodeIndex) {
        self.nodes[idx as usize]
            .as_mut()
            .expect("Active LRU list node must exist")
            .prev = prev;
    }

    /** @brief 노드의 다음 링크를 교체한다. */
    fn set_next(&mut self, idx: NodeIndex, next: NodeIndex) {
        self.nodes[idx as usize]
            .as_mut()
            .expect("Active LRU list node must exist")
            .next = next;
    }

    /** @brief 노드를 최근성 리스트에서 떼어낸다. 양끝인 경우 head/tail을 함께 옮긴다. */
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

    /** @brief 노드를 최근성 리스트의 머리로 넣는다. 이미 떼어낸 상태여야 한다. */
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

    /** @brief 노드를 가장 최근으로 올린다. 이미 머리면 링크를 건드리지 않는다. */
    fn move_front(&mut self, idx: NodeIndex) {
        if self.head == idx {
            return;
        }
        self.unlink(idx);
        self.push_front(idx);
    }

    /** @brief 값을 읽고 그 항목을 가장 최근으로 올린다. */
    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.move_front(idx);
        Some(&self.node(idx).val)
    }

    /** @brief 값을 가변으로 빌리고 그 항목을 가장 최근으로 올린다. */
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.find_index(key)?;
        self.move_front(idx);
        self.nodes[idx as usize].as_mut().map(|node| &mut node.val)
    }

    /**
     * @brief 항목을 넣거나 덮어쓴다. 넣은 항목은 가장 최근이 된다.
     *
     * @details 용량이 찼으면 먼저 가장 오래된 것을 퇴거시킨다. 그다음 아레나를 키워야 하는데
     *          할당에 실패하면 한 번 더 퇴거해 곳을 만든다.
     * @warning 그래도 슬롯이 없으면 조용히 넣지 않고 돌아간다. 캐시 삽입 실패는 정확성
     *          문제가 아니지만, 메모리 압박에서 패닉하면 서버가 죽는다.
     */
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

    /** @brief 항목을 꺼내 제거한다. */
    pub fn pop<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let hash = self.key_hash(key);
        let idx = self.find_index_with_hash(hash, key)?;
        Some(self.remove_index(idx, hash).val)
    }

    /** @brief 가장 오래된 항목을 꺼내 제거한다. 명시적 축소와 퇴거가 이걸 쓴다. */
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        let tail = self.tail;
        if tail == NIL {
            return None;
        }
        let hash = self.key_hash(&self.node(tail).key);
        let node = self.remove_index(tail, hash);
        Some((node.key, node.val))
    }

    /**
     * @brief keep 이 거짓을 돌려준 항목을 모두 제거한다.
     * @details 남은 항목의 최근성 순서는 바꾸지 않는다. keep 은 항목마다 한 번 불리며, 부르는
     *          순서는 정해져 있지 않다.
     */
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

    /**
     * @brief 노드를 두 체인(충돌·최근성)에서 모두 떼고 슬롯을 반납한다.
     * @warning 충돌 체인에서 빠뜨리면 이미 사라진 노드를 가리키는 링크가 남아 다음 조회가
     *          해제된 곳을 읽는다. 체인이 끊긴 상태는 복구할 수 없으므로 패닉한다.
     * @return 떼어낸 노드. 호출자가 키·값을 가져간다.
     */
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

    /** @brief 가장 오래된 항목을 버린다. */
    fn evict_lru(&mut self) {
        self.pop_lru();
    }

    /**
     * @brief 항목 하나를 더 넣을 수 있게 용량을 늘린다.
     * @details 예약된 여유가 남아 있으면 아무것도 하지 않는다. 그 외에는 try_reserve로
     *          늘려, 메모리 부족을 패닉이 아니라 오류로 받는다.
     * @return 슬롯이 확보되면 Ok. 할당 실패는 Err이며 호출자가 퇴거로 대응한다.
     */
    fn try_grow_one(&mut self) -> Result<(), ()> {
        if self.nodes.len() < self.nodes.capacity() && self.map.len() < self.map.capacity() {
            return Ok(());
        }
        self.nodes.try_reserve(1).map_err(|_| ())?;
        self.map.try_reserve(1).map_err(|_| ())
    }
}

#[cfg(test)]
/** @brief 상한과 밀어내기 순서, 그리고 키가 겹쳐도 서로 섞이지 않는지. */
mod tests {
    use super::*;
    use std::collections::HashMap as ReferenceMap;

    #[derive(Debug, PartialEq, Eq)]
    /** @brief 복제할 수 없는 키. 복제를 요구하지 않는지 보려는 것이다. */
    struct NonCloneKey(u32);

    impl Hash for NonCloneKey {
        /** @brief 값을 그대로 해시값으로 쓴다. */
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0.hash(state);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    /** @brief 언제나 같은 위치로 가는 키. */
    struct CollidingKey(u32);

    impl Hash for CollidingKey {
        /** @brief 언제나 같은 값을 낸다. */
        fn hash<H: Hasher>(&self, state: &mut H) {
            0u8.hash(state);
        }
    }

    #[test]
    /** @brief 해시값이 표식 바이트까지 고르게 퍼지는지. */
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
    /** @brief 넣고 꺼내기. */
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
    /** @brief 연결 인덱스가 작은 정수로 유지되는지. 커지면 항목마다 메모리가 더 든다. */
    fn node_links_stay_compact() {
        assert_eq!(
            std::mem::size_of::<Node<Box<[u8]>, [u8; 16]>>(),
            48,
            "LRU 링크나 불변 키 헤더가 다시 넓어졌습니다"
        );
    }

    #[test]
    #[should_panic(expected = "LRU capacity must be less than u32::MAX")]
    /** @brief 인덱스할 수 없는 크기를 거부하는지. */
    fn rejects_capacity_that_cannot_be_indexed() {
        let _ = LruMap::<u8, u8>::new(u32::MAX as usize);
    }

    #[test]
    /** @brief 조회할 때 키를 새로 만들지 않아도 되는지. */
    fn owned_vec_keys_support_borrowed_slice_lookup() {
        let mut map: LruMap<Vec<u8>, u32> = LruMap::new(2);
        map.put(vec![1, 2, 3], 7);

        assert_eq!(map.get([1, 2, 3].as_slice()), Some(&7));
        assert!(map.contains_key([1, 2, 3].as_slice()));
        assert_eq!(map.pop([1, 2, 3].as_slice()), Some(7));
    }

    #[test]
    /** @brief 가득 차면 가장 오래된 것부터 밀어내는지. */
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
    /** @brief 빼면서 값을 돌려주는지. */
    fn pop_returns_value() {
        let mut m: LruMap<u32, String> = LruMap::new(4);
        m.put(1, "a".into());
        assert_eq!(m.pop(&1), Some("a".into()));
        assert_eq!(m.pop(&1), None);
        assert!(m.is_empty());
    }

    #[test]
    /** @brief 가장 오래된 것을 빼고 인덱스도 함께 맞추는지. */
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
    /** @brief 이미 있는 키에 덮어쓰기. */
    fn update_existing() {
        let mut m: LruMap<u32, u32> = LruMap::new(2);
        m.put(1, 10);
        m.put(1, 11);
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.len(), 1);
    }

    #[test]
    /** @brief 밀려난 곳을 다시 쓰는지. */
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
    /** @brief 고쳐 쓰면 최근 쓴 것으로 올라오는지. */
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
    /** @brief 키에 복제를 요구하지 않는지. */
    fn keys_do_not_need_clone() {
        let mut map = LruMap::new(2);
        map.put(NonCloneKey(1), 10);
        map.put(NonCloneKey(2), 20);

        assert_eq!(map.get(&NonCloneKey(1)), Some(&10));
        assert_eq!(map.pop_lru(), Some((NonCloneKey(2), 20)));
    }

    #[test]
    /** @brief 같은 위치로 몰려도 서로 다른 키가 섞이지 않는지. 섞이면 남의 답을 준다. */
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
    /** @brief 무작위로 두드려도 단순한 모형과 같은 결과가 나오는지. */
    fn randomized_operations_match_reference_model() {
        /** @brief 테스트에 쓸 용량. */
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
                    /* 남는 항목은 값만 바뀌고 밀려나는 순서는 그대로여야 한다. */
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
                    /* 값을 고쳐도 최근성은 올리지 않는다. 올리면 뒤의 pop_lru 가 다른 키를 낸다. */
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

    /** @brief 모형 쪽에서 최근 쓴 것으로 올린다. */
    fn touch(order: &mut Vec<u16>, key: u16) {
        order.retain(|candidate| *candidate != key);
        order.insert(0, key);
    }
}
