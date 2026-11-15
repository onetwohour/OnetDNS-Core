//! Deterministic RNG and mutator for sweeping crate-private parsers. Integration tests cannot reach
//! crate internals, so private paths such as the database wire parsers are swept per module with
//! these. The same seed gives the same result, so the seed alone reproduces a panic.

/// SplitMix64.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 0 when n is 0, so an empty buffer does not divide by zero.
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    pub(crate) fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    pub(crate) fn rand_bytes(&mut self, max: usize) -> Vec<u8> {
        let count = self.below(max);
        (0..count).map(|_| self.byte()).collect()
    }
}

/// Mixes substitution, bit flips, insertion, deletion, truncation, and appending. Truncation
/// produces inputs whose length fields disagree with their real length, which actually exercises
/// the bounds checks.
pub(crate) fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for _ in 0..1 + rng.below(10) {
        if bytes.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                let index = rng.below(bytes.len());
                bytes[index] = rng.byte();
            }
            1 => {
                let index = rng.below(bytes.len());
                bytes[index] ^= 1 << rng.below(8);
            }
            2 => {
                let index = rng.below(bytes.len());
                bytes.insert(index, rng.byte());
            }
            3 => {
                let index = rng.below(bytes.len());
                bytes.remove(index);
            }
            4 => {
                let index = rng.below(bytes.len());
                bytes.truncate(index);
            }
            _ => bytes.push(rng.byte()),
        }
    }
    bytes
}
