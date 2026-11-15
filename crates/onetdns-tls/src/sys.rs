pub use onetdns_core::rng::fill_random;

/// Panics when the OS cannot supply randomness: a handshake without it would derive predictable
/// secrets.
pub fn random_32() -> [u8; 32] {
    onetdns_core::rng::random_array::<32>()
}
