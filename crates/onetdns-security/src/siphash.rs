//! SipHash, used for the server part of DNS Cookies. The standard library hasher neither takes our
//! key nor promises stable output, and cookies must hash the same across restarts and nodes.
//!
//! It is a keyed PRF, not a cryptographic hash: enough for cookies, not for signatures or
//! integrity. Variants with other round counts give other values; RFC 9018 fixes 2-4 for server
//! cookies, so using 1-3 there breaks interoperability.

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// `C` rounds per block and `D` rounds at finalization. Only the low `ntail` bytes of `tail` are
/// valid; a full 8 bytes is compressed and cleared.
pub struct SipHasher<const C: usize, const D: usize> {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: u64,
    ntail: usize,
    length: usize,
}

/// Default variant for internal use.
pub type SipHasher13 = SipHasher<1, 3>;

/// The variant RFC 9018 fixes for server cookies.
pub type SipHasher24 = SipHasher<2, 4>;

impl<const C: usize, const D: usize> SipHasher<C, D> {
    pub fn new_with_keys(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            tail: 0,
            ntail: 0,
            length: 0,
        }
    }

    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..C {
            sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= m;
    }

    /// Splitting the input across calls gives the same result.
    pub fn write(&mut self, msg: &[u8]) {
        let len = msg.len();
        self.length += len;

        let mut consumed = 0;
        if self.ntail != 0 {
            let needed = 8 - self.ntail;
            let take = needed.min(len);
            let mut add = 0u64;
            for (i, &b) in msg[..take].iter().enumerate() {
                add |= (b as u64) << (8 * (self.ntail + i));
            }
            self.tail |= add;
            if take < needed {
                self.ntail += take;
                return;
            }
            let t = self.tail;
            self.compress(t);
            self.ntail = 0;
            self.tail = 0;
            consumed = take;
        }

        let rest = &msg[consumed..];
        let nchunks = rest.len() / 8;
        for chunk in rest[..nchunks * 8].chunks_exact(8) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            self.compress(u64::from_le_bytes(word));
        }
        let leftover = &rest[nchunks * 8..];
        let mut t = 0u64;
        for (i, &b) in leftover.iter().enumerate() {
            t |= (b as u64) << (8 * i);
        }
        self.tail = t;
        self.ntail = leftover.len();
    }

    /// Leaves the state usable. The last block carries the low 8 bits of the total length.
    pub fn finish(&self) -> u64 {
        let (mut v0, mut v1, mut v2, mut v3) = (self.v0, self.v1, self.v2, self.v3);
        let b = ((self.length as u64 & 0xff) << 56) | self.tail;
        v3 ^= b;
        for _ in 0..C {
            sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= b;
        v2 ^= 0xff;
        for _ in 0..D {
            sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^ v1 ^ v2 ^ v3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(k0: u64, k1: u64, data: &[u8]) -> u64 {
        let mut h = SipHasher13::new_with_keys(k0, k1);
        h.write(data);
        h.finish()
    }

    #[test]
    fn deterministic_and_keyed() {
        assert_eq!(hash(1, 2, b"hello"), hash(1, 2, b"hello"));

        assert_ne!(hash(1, 2, b"hello"), hash(3, 4, b"hello"));

        assert_ne!(hash(1, 2, b"hello"), hash(1, 2, b"hellp"));
    }

    #[test]
    /// Vectors are from appendix A of the SipHash paper: key 00..0f, input 00, 01, ... up to the
    /// length. A single different bit would stop other implementations that share the secret from
    /// accepting our cookies.
    fn siphash24_matches_reference_vectors() {
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let run = |len: usize| {
            let input: Vec<u8> = (0..len as u8).collect();
            let mut h = SipHasher24::new_with_keys(k0, k1);
            h.write(&input);
            h.finish()
        };
        assert_eq!(run(0), 0x726f_db47_dd0e_0e31, "빈 입력");
        assert_eq!(run(1), 0x74f8_39c5_93dc_67fd, "1바이트");
        assert_eq!(run(8), 0x93f5_f579_9a93_2462, "8바이트(블록 경계)");
        assert_eq!(run(15), 0xa129_ca61_49be_45e5, "15바이트");

        // Variants with different round counts must give different values; swapping them breaks
        // compatibility silently.
        let mut thirteen = SipHasher13::new_with_keys(k0, k1);
        thirteen.write(&[]);
        assert_ne!(thirteen.finish(), run(0));
    }

    #[test]
    fn streaming_equals_oneshot() {
        let mut a = SipHasher13::new_with_keys(9, 9);
        a.write(b"abcdef");
        a.write(b"ghijklmno");
        let one = {
            let mut h = SipHasher13::new_with_keys(9, 9);
            h.write(b"abcdefghijklmno");
            h.finish()
        };
        assert_eq!(a.finish(), one);
    }
}
