//! Global allocator with a thread-local free list in front. Query handling creates and drops many
//! small short-lived blocks; caching them for the freeing thread to reuse avoids the system
//! allocator's global lock. When the cache is empty or unavailable, allocation falls through to the
//! system allocator. This layer is purely an optimization and must not change behavior.
//!
//! Cached blocks are allocated and freed with their size class's layout (class_layout); a mismatch
//! between allocation and free layouts is undefined behavior.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Alignment above this is not cached.
const MAX_ALIGN: usize = crate::ALLOC_MAX_ALIGN;

const CLASSES: [usize; 12] = crate::ALLOC_SIZE_CLASSES;

/// Blocks a thread may hold per class, fewer for larger classes. A thread can pin the sum of class
/// size times this; the same count for large classes would pin several MiB per thread.
const SLOT_CAPS: [u8; 12] = [32, 32, 32, 32, 24, 24, 16, 16, 8, 8, 8, 4];

/// Must be at least the largest SLOT_CAPS entry.
const MAX_SLOTS: usize = 32;

/// Smallest class that fits; None for 0 or above the largest class.
fn class_of(size: usize) -> Option<usize> {
    if size == 0 {
        return None;
    }
    CLASSES.iter().position(|&c| size <= c)
}

/// Every cached block moves in this layout.
fn class_layout(class: usize) -> Layout {
    // SAFETY: every CLASSES entry is a nonzero multiple of MAX_ALIGN; class_boundaries pins this.
    unsafe { Layout::from_size_align_unchecked(CLASSES[class], MAX_ALIGN) }
}

/// Over-aligned and oversized layouts are not cached.
fn cacheable(layout: Layout) -> Option<usize> {
    if layout.align() > MAX_ALIGN {
        return None;
    }
    class_of(layout.size())
}

/// One thread's free lists per class. counts[c] <= SLOT_CAPS[c] <= MAX_SLOTS, and only the first
/// counts[c] entries of slots[c] are valid.
struct ThreadCache {
    slots: [[*mut u8; MAX_SLOTS]; CLASSES.len()],
    counts: [u8; CLASSES.len()],
}

impl ThreadCache {
    const fn new() -> Self {
        Self {
            slots: [[std::ptr::null_mut(); MAX_SLOTS]; CLASSES.len()],
            counts: [0; CLASSES.len()],
        }
    }

    fn pop(&mut self, class: usize) -> Option<*mut u8> {
        let n = self.counts[class];
        if n == 0 {
            return None;
        }
        self.counts[class] = n - 1;
        Some(self.slots[class][usize::from(n) - 1])
    }

    /// False when the class is full; the caller must then free to the system allocator.
    fn push(&mut self, class: usize, ptr: *mut u8) -> bool {
        let n = self.counts[class];
        if n >= SLOT_CAPS[class] {
            return false;
        }
        self.slots[class][usize::from(n)] = ptr;
        self.counts[class] = n + 1;
        true
    }

    /// Returns every held block to the system; runs at thread exit.
    fn flush(&mut self) {
        for class in 0..CLASSES.len() {
            for i in 0..usize::from(self.counts[class]) {
                // SAFETY: each cached block was allocated with class_layout(class) and is still
                // live; counts is reset below, so none is freed twice.
                unsafe { System.dealloc(self.slots[class][i], class_layout(class)) };
            }
            self.counts[class] = 0;
        }
    }
}

/// 0 uninitialized, 1 initializing, 2 ready, 3 failed for good. Without 3, an environment where key
/// creation fails would retry on every allocation.
static KEY_STATE: AtomicUsize = AtomicUsize::new(0);

/// Valid only when KEY_STATE is 2.
static KEY: AtomicUsize = AtomicUsize::new(0);

/// pthread destructor that flushes and frees the cache at thread exit.
unsafe extern "C" fn flush_cache(p: *mut libc::c_void) {
    let cache = p.cast::<ThreadCache>();
    if cache.is_null() {
        return;
    }
    // SAFETY: p is null or the ThreadCache this module stored under the key; nothing else is stored
    // there.
    unsafe {
        (*cache).flush();
        System.dealloc(cache.cast::<u8>(), Layout::new::<ThreadCache>());
    }
}

/// Creates the key once. Threads arriving during initialization get None and use the system
/// allocator; waiting here would put a lock wait in the allocation path.
fn cache_key() -> Option<libc::pthread_key_t> {
    match KEY_STATE.load(Ordering::Acquire) {
        2 => Some(KEY.load(Ordering::Relaxed) as libc::pthread_key_t),
        0 => {
            if KEY_STATE
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let mut key: libc::pthread_key_t = 0;
                if unsafe { libc::pthread_key_create(&mut key, Some(flush_cache)) } == 0 {
                    KEY.store(key as usize, Ordering::Relaxed);
                    KEY_STATE.store(2, Ordering::Release);
                    return Some(key);
                }
                KEY_STATE.store(3, Ordering::Release);
            }
            None
        }
        _ => None,
    }
}

/// Creates and registers the cache on first use. Not thread_local!, whose initialization may
/// allocate and recurse into the global allocator; a pthread key does not. Null when the key or
/// allocation fails, and the caller falls through to the system allocator.
fn cache_ptr() -> *mut ThreadCache {
    let Some(key) = cache_key() else {
        return std::ptr::null_mut();
    };
    // SAFETY: the block comes straight from the system allocator with ThreadCache's layout and is
    // initialized with write before use; if setspecific fails it is freed here.
    unsafe {
        let existing = libc::pthread_getspecific(key).cast::<ThreadCache>();
        if !existing.is_null() {
            return existing;
        }
        let block = System
            .alloc(Layout::new::<ThreadCache>())
            .cast::<ThreadCache>();
        if block.is_null() {
            return std::ptr::null_mut();
        }
        block.write(ThreadCache::new());
        if libc::pthread_setspecific(key, block.cast::<libc::c_void>()) != 0 {
            System.dealloc(block.cast::<u8>(), Layout::new::<ThreadCache>());
            return std::ptr::null_mut();
        }
        block
    }
}

fn cache_pop(class: usize) -> Option<*mut u8> {
    let cache = cache_ptr();
    if cache.is_null() {
        return None;
    }
    // SAFETY: the cache from cache_ptr belongs to this thread alone.
    unsafe { (*cache).pop(class) }
}

/// Goes to the freeing thread's cache, not the allocating one. When producer-consumer traffic flows
/// one way, blocks pile up on one side, but the per-class caps bound it.
fn cache_push(class: usize, ptr: *mut u8) -> bool {
    let cache = cache_ptr();
    if cache.is_null() {
        return false;
    }
    // SAFETY: the cache from cache_ptr belongs to this thread alone.
    unsafe { (*cache).push(class, ptr) }
}

pub struct ThreadCachedSystem;

// SAFETY: alloc returns either a system allocation for the requested layout or a cached block of a
// class that covers its size and alignment, and dealloc frees cacheable blocks with the class
// layout they were allocated with.
unsafe impl GlobalAlloc for ThreadCachedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(class) = cacheable(layout) {
            if let Some(ptr) = cache_pop(class) {
                return ptr;
            }
            return unsafe { System.alloc(class_layout(class)) };
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(class) = cacheable(layout) {
            if cache_push(class, ptr) {
                return;
            }
            // SAFETY: cacheable blocks were allocated with class_layout in alloc; the caller's
            // layout would not match their size.
            return unsafe { System.dealloc(ptr, class_layout(class)) };
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    /// Returns the same pointer within one class, since the block already has the room; growing a
    /// buffer in small steps then copies nothing. Null if the new layout is invalid.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return std::ptr::null_mut();
        };
        match (cacheable(layout), cacheable(new_layout)) {
            (Some(old), Some(new)) if old == new => ptr,

            (None, None) => unsafe { System.realloc(ptr, layout, new_size) },

            _ => {
                let new_ptr = unsafe { self.alloc(new_layout) };
                if !new_ptr.is_null() {
                    // SAFETY: new_ptr is a fresh block, so it does not overlap ptr, and both hold
                    // at least the smaller of the two sizes.
                    unsafe {
                        std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                        self.dealloc(ptr, layout);
                    }
                }
                new_ptr
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ThreadCachedSystem = ThreadCachedSystem;

    #[test]
    fn class_boundaries() {
        assert_eq!(class_of(0), None);
        assert_eq!(class_of(1), Some(0));
        assert_eq!(class_of(16), Some(0));
        assert_eq!(class_of(17), Some(1));
        assert_eq!(class_of(2048), Some(CLASSES.len() - 1));
        assert_eq!(class_of(2049), None);
        for (i, &c) in CLASSES.iter().enumerate() {
            assert_eq!(class_of(c), Some(i), "정확히 클래스 크기");
            assert_eq!(c % MAX_ALIGN, 0, "클래스는 16의 배수");
        }
    }

    #[test]
    fn roundtrip_reuses_cached_block_and_preserves_writes() {
        let layout = Layout::from_size_align(100, 8).unwrap();
        unsafe {
            let p1 = A.alloc(layout);
            assert!(!p1.is_null());
            std::ptr::write_bytes(p1, 0xA5, 100);
            A.dealloc(p1, layout);

            let p2 = A.alloc(Layout::from_size_align(128, 8).unwrap());
            assert_eq!(p1, p2, "클래스(128) 캐시 재사용");
            std::ptr::write_bytes(p2, 0x5A, 128);
            assert_eq!(*p2.add(127), 0x5A);
            A.dealloc(p2, Layout::from_size_align(128, 8).unwrap());
        }
    }

    #[test]
    fn oversized_and_overaligned_pass_through() {
        unsafe {
            let big = Layout::from_size_align(4096, 8).unwrap();
            let p = A.alloc(big);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 1, 4096);
            A.dealloc(p, big);

            let aligned = Layout::from_size_align(64, 64).unwrap();
            let p = A.alloc(aligned);
            assert!(!p.is_null());
            assert_eq!(p as usize % 64, 0);
            A.dealloc(p, aligned);
        }
    }

    #[test]
    /// Leftover contents would leak another request's data.
    fn alloc_zeroed_after_dirty_reuse_is_zero() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        unsafe {
            let p = A.alloc(layout);
            std::ptr::write_bytes(p, 0xFF, 64);
            A.dealloc(p, layout);
            let z = A.alloc_zeroed(layout);
            for i in 0..64 {
                assert_eq!(*z.add(i), 0, "재사용 블록도 0으로 초기화");
            }
            A.dealloc(z, layout);
        }
    }

    #[test]
    fn realloc_within_class_is_in_place_and_across_class_copies() {
        let layout = Layout::from_size_align(70, 8).unwrap();
        unsafe {
            let p = A.alloc(layout);
            for i in 0..70u8 {
                *p.add(usize::from(i)) = i;
            }

            let q = A.realloc(p, layout, 90);
            assert_eq!(p, q);

            let r = A.realloc(q, Layout::from_size_align(90, 8).unwrap(), 300);
            assert!(!r.is_null());
            for i in 0..70u8 {
                assert_eq!(*r.add(usize::from(i)), i);
            }
            A.dealloc(r, Layout::from_size_align(300, 8).unwrap());
        }
    }

    #[test]
    /// Sending it back to the allocating thread would be contention.
    fn cross_thread_free_lands_in_freeing_threads_cache() {
        let layout = Layout::from_size_align(256, 8).unwrap();
        let ptr = unsafe { A.alloc(layout) } as usize;
        let handle = std::thread::spawn(move || {
            unsafe { A.dealloc(ptr as *mut u8, layout) };

            let again = unsafe { A.alloc(layout) } as usize;
            assert_eq!(again, ptr);
            unsafe { A.dealloc(again as *mut u8, layout) };
        });
        handle.join().unwrap();
    }

    #[test]
    fn multithread_stress_with_pattern_integrity() {
        let mut handles = Vec::new();
        for t in 0..8u8 {
            handles.push(std::thread::spawn(move || {
                let mut state = u64::from(t) * 2654435761 + 1;
                let mut lcg = move || {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    state
                };
                let mut live: Vec<(usize, Layout, u8)> = Vec::new();
                for _ in 0..20_000 {
                    if live.len() < 32 && lcg() % 3 != 0 {
                        let size = (lcg() % 3000 + 1) as usize;
                        let layout = Layout::from_size_align(size, 8).unwrap();
                        let p = unsafe { A.alloc(layout) };
                        assert!(!p.is_null());
                        let tag = (lcg() & 0xFF) as u8;
                        unsafe { std::ptr::write_bytes(p, tag, size) };
                        live.push((p as usize, layout, tag));
                    } else if let Some((p, layout, tag)) = live.pop() {
                        unsafe {
                            for i in [0, layout.size() / 2, layout.size() - 1] {
                                assert_eq!(*(p as *mut u8).add(i), tag, "블록 내용 무결성");
                            }
                            A.dealloc(p as *mut u8, layout);
                        }
                    }
                }
                for (p, layout, tag) in live {
                    unsafe {
                        assert_eq!(*(p as *mut u8), tag);
                        A.dealloc(p as *mut u8, layout);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
