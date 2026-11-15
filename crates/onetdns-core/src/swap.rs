//! Shared snapshots replaced whole and atomically: the hot-reload path for state that is read
//! constantly and replaced rarely, such as blocklists, zones, and config.

use std::sync::{Arc, RwLock};

/// Not lock-free despite the name: an RwLock, where reading clones the Arc as a snapshot and
/// releases the lock, so long query handling never blocks an update. A snapshot taken stays valid
/// after replacement.
///
/// Every lock path recovers from poisoning; if one request's panic made this state unreachable for
/// good, the server would stop.
pub struct ArcSwap<T> {
    inner: RwLock<Arc<T>>,
}

impl<T> ArcSwap<T> {
    pub fn from_pointee(val: T) -> Self {
        Self {
            inner: RwLock::new(Arc::new(val)),
        }
    }

    pub fn new(arc: Arc<T>) -> Self {
        Self {
            inner: RwLock::new(arc),
        }
    }

    /// The returned Arc stays valid regardless of later stores, so one query sees consistent state
    /// throughout.
    pub fn load(&self) -> Arc<T> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&guard)
    }

    /// Snapshots already taken are untouched.
    pub fn store(&self, val: Arc<T>) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = val;
    }

    /// Builds the new value from the current one under the write lock, so concurrent updates
    /// serialize; load then store would let two updates overwrite each other. Locking the same
    /// holder inside the closure deadlocks.
    pub fn update(&self, update: impl FnOnce(&T) -> T) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Arc::new(update(guard.as_ref()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_store() {
        let s = ArcSwap::from_pointee(10u32);
        assert_eq!(*s.load(), 10);
        s.store(Arc::new(20));
        assert_eq!(*s.load(), 20);

        let a = s.load();
        s.store(Arc::new(30));
        assert_eq!(*a, 20);
        assert_eq!(*s.load(), 30);
    }

    #[test]
    /// Otherwise one writer's change would be lost.
    fn update_serializes_concurrent_writers() {
        let value = Arc::new(ArcSwap::from_pointee(0usize));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let value = value.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    value.update(|current| current + 1);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*value.load(), 8_000);
    }
}
