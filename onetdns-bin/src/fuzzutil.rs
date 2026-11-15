//! Deterministic RNG and mutators for parser sweeps; a seed alone reproduces a panic.

#![allow(dead_code)]

/// SplitMix64.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    pub fn rand_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        (0..n).map(|_| self.byte()).collect()
    }
}

/// Truncation matters: it makes length fields disagree with the actual length, which exercises the
/// bounds checks.
pub fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(10) {
        if b.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                let i = rng.below(b.len());
                b[i] = rng.byte();
            }
            1 => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            2 => {
                let i = rng.below(b.len());
                b.insert(i, rng.byte());
            }
            3 => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            4 => {
                let i = rng.below(b.len());
                b.truncate(i);
            }
            _ => b.push(rng.byte()),
        }
    }
    b
}
