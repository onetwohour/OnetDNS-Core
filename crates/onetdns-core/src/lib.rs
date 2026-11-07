//! Policy traits and primitives shared by the upper crates.
//!
//! This is the layer right above onetdns-proto. Its traits are the boundary between the data
//! plane and the filter, ACL and rate-limit implementations, so upper crates meet only here.

pub mod client;
pub mod fs;
pub mod ipnet;
/// Confines a panic to the query that caused it.
pub mod isolation;
pub mod json;
pub mod log;
/// Bounded caches.
pub mod lrumap;
/// The HTTPS origin the dashboard is published under.
pub mod origin;
/// What ACLs, rate limits and blocking must guarantee.
pub mod policy;
pub mod rng;
/// RSA signature verification.
pub mod rsa;
/// A secret string whose clones share one buffer.
pub mod secret;
/// A value that is replaced as a whole.
pub mod swap;
#[cfg(unix)]
/// An allocator with a small per-thread cache.
pub mod talloc;
/// TCP streams that honor an absolute deadline and a shutdown flag.
pub mod tcp;
/// UDP sockets that ICMP errors cannot break.
pub mod udp;

pub use client::{ClientInfo, Transport};
pub use ipnet::IpNet;
pub use lrumap::LruMap;
pub use origin::HttpsOrigin;
pub use policy::{
    AccessControl, AclDecision, BlockResponse, DropReason, FilterEngine, FilterExplanation,
    FilterVerdict, MatchStage, RateDecision, RateLimiter, RewriteTarget,
};
pub use rng::{
    ephemeral_random_array, fill_ephemeral_random, fill_random, random_array, try_fill_random,
    try_random_array,
};
pub use secret::SecretString;
pub use swap::ArcSwap;

/// Size classes of the thread-local allocator. A request is rounded up to one of these so that
/// freed blocks of the same class can be reused.
pub const ALLOC_SIZE_CLASSES: [usize; 12] =
    [16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048];

/// Largest alignment the size classes handle; larger ones go to the system allocator.
pub const ALLOC_MAX_ALIGN: usize = 16;

/// The smallest class that fits `size`, or `size` itself when no class fits or the alignment is
/// too large.
pub fn alloc_class_size(size: usize, align: usize) -> usize {
    if size == 0 || align > ALLOC_MAX_ALIGN {
        return size;
    }
    match ALLOC_SIZE_CLASSES.iter().find(|&&class| size <= class) {
        Some(&class) => class,
        None => size,
    }
}

/// Locks a mutex even when a panicking thread poisoned it.
///
/// Unwrapping a poisoned lock would spread one request's panic to every later request that
/// takes the lock. Recovery does not make the data consistent: state behind these locks must
/// stay usable after a partial update.
pub trait MutexExt<T: ?Sized> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for std::sync::Mutex<T> {
    fn lock_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}
