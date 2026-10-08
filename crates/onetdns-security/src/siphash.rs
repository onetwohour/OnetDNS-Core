/*!
 * @brief SipHash. DNS 쿠키의 서버 쪽 값을 만드는 데 쓴다.
 *
 * @details 표준 라이브러리 해셔는 키를 이 서버가 정할 수 없고 출력이 안정적이라는 보장도 없다.
 *          쿠키는 프로세스를 재시작하거나 노드가 달라져도 같은 입력에 같은 값을 내야 한다.
 * @note 암호학적 해시가 아니라 키드 유사난수 함수(PRF)다. 쿠키 용도에는 충분하며
 *       서명이나 무결성 증명에 쓰지 않는다.
 * @note 라운드 수가 다른 변형은 서로 다른 값을 낸다. RFC 9018 서버 쿠키는 2-4 를 못박으므로
 *       그곳에 1-3 을 쓰면 다른 구현과 쿠키를 주고받지 못한다.
 */

/** @brief SipHash 한 라운드의 ARX 치환. */
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

/**
 * @brief 증분 입력을 받는 SipHash 상태. C 는 블록마다, D 는 마무리에 실행하는 라운드 수다.
 * @invariant tail의 하위 ntail바이트만 유효하다. 8바이트가 차면 압축하고 비운다.
 */
pub struct SipHasher<const C: usize, const D: usize> {
    /** @brief 섞기 상태. */
    v0: u64,
    /** @brief 섞기 상태. */
    v1: u64,
    /** @brief 섞기 상태. */
    v2: u64,
    /** @brief 섞기 상태. */
    v3: u64,
    /** @brief 아직 8바이트를 못 채운 나머지. */
    tail: u64,
    /** @brief 그 나머지의 길이. */
    ntail: usize,
    /** @brief 지금까지 넣은 전체 길이. */
    length: usize,
}

/** @brief SipHash-1-3. 이 서버의 내부 용도의 기본 변형이다. */
pub type SipHasher13 = SipHasher<1, 3>;

/** @brief SipHash-2-4. RFC 9018 이 서버 쿠키에 못박은 변형이다. */
pub type SipHasher24 = SipHasher<2, 4>;

impl<const C: usize, const D: usize> SipHasher<C, D> {
    /** @brief 128비트 키로 상태를 초기화한다. 상수는 SipHash 명세 그대로다. */
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

    /** @brief 8바이트 블록 하나를 상태에 섞는다. */
    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        for _ in 0..C {
            sipround(&mut self.v0, &mut self.v1, &mut self.v2, &mut self.v3);
        }
        self.v0 ^= m;
    }

    /**
     * @brief 바이트를 입력에 덧붙인다. 여러 번 나눠 불러도 결과는 같다.
     * @details 이전 호출이 남긴 부분 블록을 먼저 채운 뒤 8바이트 단위로 압축하고, 남은
     *          자투리는 다시 tail에 보관한다.
     */
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

    /**
     * @brief 최종 해시값. 상태를 소비하지 않는다.
     * @details 마지막 블록에 전체 길이의 하위 8비트를 담아 길이 확장을 막는다.
     */
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
/** @brief 비밀값에 따라 값이 갈리고, 나눠 넣어도 같은 결과인지. */
mod tests {
    use super::*;

    /** @brief 이 비밀값으로 요약한다. */
    fn hash(k0: u64, k1: u64, data: &[u8]) -> u64 {
        let mut h = SipHasher13::new_with_keys(k0, k1);
        h.write(data);
        h.finish()
    }

    #[test]
    /** @brief 같은 입력은 같은 값, 비밀값이 다르면 다른 값인지. */
    fn deterministic_and_keyed() {
        assert_eq!(hash(1, 2, b"hello"), hash(1, 2, b"hello"));

        assert_ne!(hash(1, 2, b"hello"), hash(3, 4, b"hello"));

        assert_ne!(hash(1, 2, b"hello"), hash(1, 2, b"hellp"));
    }

    #[test]
    /**
     * @brief SipHash-2-4가 명세의 테스트 벡터와 같은 값을 내는지.
     *
     * @details RFC 9018 서버 쿠키는 이 변형을 규정한다. 값이 한 비트라도 다르면 같은 비밀을
     *          나눠 가진 다른 구현이 이 서버의 쿠키를 인정하지 못한다. 벡터는 SipHash 논문
     *          부록 A의 것으로, 키는 00..0f이고 입력은 00부터 길이만큼 이어지는 바이트다.
     */
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

        /*
         * 라운드 수가 다른 변형은 같은 입력에 다른 값을 낸다. 둘을 바꿔 쓰면 조용히
         * 호환이 깨지므로 여기서 갈라 둔다.
         */
        let mut thirteen = SipHasher13::new_with_keys(k0, k1);
        thirteen.write(&[]);
        assert_ne!(thirteen.finish(), run(0));
    }

    #[test]
    /** @brief 나눠 넣어도 한 번에 넣은 것과 같은지. */
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
