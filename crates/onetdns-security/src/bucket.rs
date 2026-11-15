use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::sync::Mutex;
use std::time::Instant;

use onetdns_core::LruMap;

/// Refilled lazily on lookup: no thread sweeps all keys, so the cost does not grow with the number
/// of keys.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// This cap is the memory defence: an attacker querying from a new source each time would grow the
/// keys without bound, so the oldest are evicted.
const CAP_PER_SHARD: usize = 4096;

/// Keys hash into 16 shards to cut lock contention. Shard placement uses a random per-process seed:
/// with a fixed hash an attacker could pile keys onto one shard to contend its lock or evict other
/// clients' entries.
pub struct TokenBucket<K> {
    rate: f64,
    burst: f64,
    shards: Vec<Mutex<LruMap<K, Bucket>>>,
    mask: usize,
    hash_builder: RandomState,
}

impl<K: Hash + Eq + Clone> TokenBucket<K> {
    /// Returns `None` for `per_second` 0, meaning no limit. A `burst` below the rate is raised to
    /// it, or queries at the normal rate would be throttled.
    pub fn new(per_second: u32, burst: u32) -> Option<Self> {
        if per_second == 0 {
            return None;
        }
        let burst = burst.max(per_second) as f64;
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

    fn shard(&self, key: &K) -> usize {
        (self.hash_builder.hash_one(key) as usize) & self.mask
    }

    /// Refills for the elapsed time, capped at the burst, then takes one token. A poisoned lock is
    /// recovered: propagating the panic would turn one failed request into a permanent block for
    /// every client in that shard. Returns false over the limit.
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
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn permits_then_throttles() {
        let tb: TokenBucket<IpAddr> = TokenBucket::new(1, 2).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(tb.check(&ip));
        assert!(tb.check(&ip));
        assert!(!tb.check(&ip));

        assert!(tb.check(&"5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn disabled_when_zero() {
        assert!(TokenBucket::<IpAddr>::new(0, 0).is_none());
    }

    #[test]
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
