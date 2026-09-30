use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::sync::Mutex;
use std::time::Instant;

use onetdns_core::LruMap;

/**
 * @brief 키 하나의 토큰 상태.
 * @details 시간을 미리 채우지 않고 조회 시점에 경과분을 계산한다. 주기적으로 전체를
 *          훑는 스레드가 없어야 키 수와 무관하게 비용이 일정하다.
 */
struct Bucket {
    /** @brief 남은 몫. */
    tokens: f64,
    /** @brief 마지막으로 채운 시각. */
    last: Instant,
}

/**
 * @brief 샤드 하나가 기억하는 키 수 상한.
 * @warning 이 상한이 메모리 방어다. 공격자가 매번 다른 출발지로 질의하면 키가 무한정
 *          늘어나므로, LRU로 오래된 키를 버려 유계로 만든다.
 */
const CAP_PER_SHARD: usize = 4096;

/**
 * @brief 샤딩된 토큰 버킷 속도 제한기.
 *
 * @details 잠금 경합을 줄이려고 키를 해시해 16개 샤드로 나눈다. 샤드 배치는 프로세스마다 다른
 *          무작위 시드로 정해진다. 고정 해시면 공격자가 한 샤드에 키를 몰아 그 락만
 *          경합시키거나 다른 클라이언트의 항목을 밀어낼 수 있다.
 */
pub struct TokenBucket<K> {
    /** @brief 1초에 채울 몫. */
    rate: f64,
    /** @brief 한꺼번에 쓸 수 있는 몫. */
    burst: f64,
    /** @brief 조각들. 조각마다 잠금이 따로다. */
    shards: Vec<Mutex<LruMap<K, Bucket>>>,
    /** @brief 조각 번호를 뽑는 데 쓰는 가리개. */
    mask: usize,
    /** @brief 해시 함수. 프로세스마다 시드가 다르다. */
    hash_builder: RandomState,
}

impl<K: Hash + Eq + Clone> TokenBucket<K> {
    /**
     * @brief 제한기를 만든다.
     * @param per_second 초당 허용 속도. 0이면 None을 돌려주며 이는 "제한 없음"을 뜻한다.
     * @param burst 순간 허용량. 속도보다 작으면 속도로 올린다. 그러지 않으면 정상 속도의
     *              질의도 걸린다.
     */
    pub fn new(per_second: u32, burst: u32) -> Option<Self> {
        if per_second == 0 {
            return None;
        }
        let burst = burst.max(per_second) as f64;
        /** @brief 잠금을 나눌 조각 수. */
        const NSHARDS: usize = 16;
        let shards = (0..NSHARDS)
            .map(|_| Mutex::new(LruMap::new(CAP_PER_SHARD)))
            .collect();
        Some(Self {
            rate: per_second as f64,
            burst,
            shards,
            mask: NSHARDS - 1,
            hash_builder: RandomState::new(),
        })
    }

    /** @brief 키가 속할 샤드. 프로세스별 비밀 시드로 정해진다. */
    fn shard(&self, key: &K) -> usize {
        (self.hash_builder.hash_one(key) as usize) & self.mask
    }

    /**
     * @brief 토큰 하나를 소비한다.
     * @details 경과 시간만큼 토큰을 채운 뒤 하나를 뺀다. 채우는 양은 버스트 한도에서 잘린다.
     * @note 포이즌된 락을 복구해서 잠근다. 여기서 패닉을 전파하면 요청 하나의 실패가
     *       그 샤드에 속한 모든 클라이언트의 영구 차단이 된다.
     * @return 통과시키면 true, 한도를 넘었으면 false.
     */
    pub fn check(&self, key: &K) -> bool {
        let idx = self.shard(key);
        let now = Instant::now();

        let mut map = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());

        if map.get(key).is_none() {
            map.put(
                key.clone(),
                Bucket {
                    tokens: self.burst,
                    last: now,
                },
            );
        }
        let b = map
            .get_mut(key)
            .expect("Just inserted or an existing bucket");
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.rate).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
/** @brief 몫이 떨어지면 막는지, 그리고 담는 키 수가 상한을 지키는지. */
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    /** @brief 몫이 있으면 통과하고 떨어지면 막는지. */
    fn permits_then_throttles() {
        let tb: TokenBucket<IpAddr> = TokenBucket::new(1, 2).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(tb.check(&ip));
        assert!(tb.check(&ip));
        assert!(!tb.check(&ip));

        assert!(tb.check(&"5.6.7.8".parse().unwrap()));
    }

    #[test]
    /** @brief 0으로 두면 제한이 꺼지는지. */
    fn disabled_when_zero() {
        assert!(TokenBucket::<IpAddr>::new(0, 0).is_none());
    }

    #[test]
    /** @brief 한 조각에서 패닉이 났어도 계속 도는지. */
    fn survives_poisoned_shard() {
        let tb: TokenBucket<IpAddr> = TokenBucket::new(5, 5).unwrap();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let idx = tb.shard(&ip);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = tb.shards[idx].lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(poisoned.is_err(), "패닉이 뮤텍스를 poison");

        assert!(tb.check(&ip), "poison 이후에도 정상 허용");
    }

    #[test]
    /** @brief 키를 지어내도 담는 수가 상한을 지키는지. 없으면 그것만으로 메모리가 동난다. */
    fn unique_keys_remain_bounded() {
        let tb: TokenBucket<u32> = TokenBucket::new(1, 1).unwrap();
        let shard = tb.shard(&0);
        let mut inserted = 0u32;
        while inserted < 100_000 {
            if tb.shard(&inserted) == shard {
                assert!(tb.check(&inserted));
            }
            inserted += 1;
        }
        assert!(tb.shards[shard].lock().unwrap().len() <= CAP_PER_SHARD);
    }

    #[test]
    /** @brief 조각 배정이 프로세스마다 다른지. 같으면 한 조각에 몰리게 만들 수 있다. */
    fn shard_assignment_is_process_keyed() {
        let first: TokenBucket<u32> = TokenBucket::new(1, 1).unwrap();
        let second: TokenBucket<u32> = TokenBucket::new(1, 1).unwrap();
        let changed = (0..1024)
            .filter(|key| first.shard(key) != second.shard(key))
            .count();
        assert!(
            changed > 512,
            "프로세스 비밀이 바뀌어도 rate-limit 샤드 배치가 충분히 달라지지 않았습니다: {changed}"
        );
    }
}
