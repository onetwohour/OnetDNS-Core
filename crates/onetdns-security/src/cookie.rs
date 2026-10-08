/*!
 * @brief DNS 쿠키(RFC 7873). 출발지 주소 위조를 걸러 내는 값싼 왕복 증명이다.
 *
 * @details 서버는 상태를 저장하지 않는다. 서버 쿠키는 클라이언트 쿠키와 출발지 주소를
 *          비밀 키로 해싱한 값이라, 되돌아온 쿠키가 맞으면 그 주소가 실제로 응답을
 *          받았다는 뜻이다. 증폭 공격의 반사 대상이 되는 것을 막는다.
 */

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::siphash::SipHasher24;
use zeroize::Zeroize;

/** @brief RFC 9018이 정한 서버 쿠키 길이: Version 1, Reserved 3, Timestamp 4, Hash 8. */
pub const SERVER_COOKIE_LEN: usize = 16;

/** @brief 이 구현이 내는 서버 쿠키 버전. */
const COOKIE_VERSION: u8 = 1;

/** @brief 과거로 받아 주는 폭. RFC 9018이 한 시간을 권한다. */
const ACCEPT_PAST_SECS: i64 = 3600;

/** @brief 미래로 받아 주는 폭. 시계가 조금 앞선 상대를 위한 여유다. */
const ACCEPT_FUTURE_SECS: i64 = 300;

/** @brief 서버 비밀을 자동으로 교체하는 주기. RFC 9018은 매달 교체를 권한다. */
const SECRET_EPOCH_SECS: u32 = 30 * 24 * 60 * 60;

/** @brief epoch별 두 SipHash 키를 서로 갈라 주는 문맥 문자열. */
const EPOCH_KEY_CONTEXT: &[u8] = b"OnetDNS DNS Cookie epoch key v1";

/** @brief 서버 쿠키 생성·검증에 쓰는 비밀 키를 잡은 타입. */
pub struct CookieKeeper {
    /** @brief 쿠키를 만드는 비밀값. */
    k0: u64,
    /** @brief 그 두 번째 값. */
    k1: u64,
    /** @brief 참이면 k0·k1을 루트로 삼아 쿠키 시각의 30일 epoch 키를 파생한다. */
    rotating: bool,
}

/** @brief 쿠키 검사 결과. */
pub struct CookieCheck {
    /** @brief 클라이언트가 보낸 8바이트. 응답에 그대로 되돌려 준다. */
    pub client: [u8; 8],

    /** @brief 서버 쿠키가 이 출발지에 대해 유효한지. false면 왕복이 아직 증명되지 않은 것이다. */
    pub valid: bool,
}

impl CookieKeeper {
    /** @brief 무작위 루트 비밀로 초기화한다. 쿠키 키는 30일마다 자동으로 바뀐다. */
    pub fn random() -> Self {
        let mut secret = onetdns_core::random_array::<16>();
        let keeper = Self::from_master_secret(&secret);
        secret.zeroize();
        keeper
    }

    /**
     * @brief 주어진 비밀로 초기화한다.
     * @note 여러 인스턴스가 쿠키를 서로 인정하게 하려면 같은 비밀을 써야 한다. 다르면
     *       클라이언트가 다른 노드로 갈 때마다 왕복 증명을 다시 한다.
     */
    pub fn from_secret(secret: &[u8; 16]) -> Self {
        Self {
            k0: u64::from_le_bytes([
                secret[0], secret[1], secret[2], secret[3], secret[4], secret[5], secret[6],
                secret[7],
            ]),
            k1: u64::from_le_bytes([
                secret[8], secret[9], secret[10], secret[11], secret[12], secret[13], secret[14],
                secret[15],
            ]),
            rotating: false,
        }
    }

    /**
     * @brief 주어진 루트 비밀에서 30일 epoch별 서버 비밀을 파생한다.
     * @details 상태나 잠금 없이 쿠키에 새겨진 시각으로 해당 epoch 키를 다시 얻는다. 그래서
     *          월 경계 직전 쿠키도 수락 구간 안에서는 이전 epoch 키로 검증되고, 여러 노드가
     *          같은 루트를 쓰면 어느 노드로 이동해도 같은 쿠키를 인정한다.
     */
    pub fn from_master_secret(secret: &[u8; 16]) -> Self {
        let mut keeper = Self::from_secret(secret);
        keeper.rotating = true;
        keeper
    }

    /** @brief 고정 키 또는 쿠키 시각이 속한 epoch의 파생 키를 고른다. */
    #[inline]
    fn keys_at(&self, stamp: u32) -> (u64, u64) {
        if !self.rotating {
            return (self.k0, self.k1);
        }
        let epoch = stamp / SECRET_EPOCH_SECS;
        let derive = |domain: u8| {
            let mut h = SipHasher24::new_with_keys(self.k0, self.k1);
            h.write(EPOCH_KEY_CONTEXT);
            h.write(&epoch.to_be_bytes());
            h.write(&[domain]);
            h.finish()
        };
        (derive(0), derive(1))
    }

    /**
     * @brief 주어진 시각으로 서버 쿠키 16바이트를 만든다.
     *
     * @details RFC 9018이 정한 배치를 그대로 따른다. Version 1바이트, Reserved 3바이트,
     *          Timestamp 4바이트, 그리고 나머지를 재료로 한 SipHash-2-4 8바이트다. 주소를
     *          재료에 넣는 것이 핵심이다. 넣지 않으면 한 번 받은 쿠키를 아무 위조 주소에나
     *          붙여 쓸 수 있어 왕복 증명이 무의미해진다.
     * @param stamp 쿠키에 새길 Unix 시각. 검증할 때는 받은 쿠키의 값을 그대로 넣는다.
     */
    pub fn server_cookie_at(&self, client_cookie: &[u8], ip: IpAddr, stamp: u32) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = COOKIE_VERSION;
        out[4..8].copy_from_slice(&stamp.to_be_bytes());

        let (k0, k1) = self.keys_at(stamp);
        let mut h = SipHasher24::new_with_keys(k0, k1);
        h.write(client_cookie);
        h.write(&out[0..8]);
        match ip {
            IpAddr::V4(v4) => h.write(&v4.octets()),
            IpAddr::V6(v6) => h.write(&v6.octets()),
        }
        out[8..].copy_from_slice(&h.finish().to_le_bytes());
        out
    }

    /** @brief 지금 시각으로 만든 서버 쿠키. */
    pub fn server_cookie(&self, client_cookie: &[u8], ip: IpAddr) -> [u8; 16] {
        self.server_cookie_at(client_cookie, ip, unix_now())
    }

    /** @brief 응답에 담을 24바이트 쿠키: 클라이언트 쿠키 8바이트 + 서버 쿠키 16바이트. */
    pub fn response_cookie(&self, client_cookie: &[u8; 8], ip: IpAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + SERVER_COOKIE_LEN);
        out.extend_from_slice(client_cookie);
        out.extend_from_slice(&self.server_cookie(client_cookie, ip));
        out
    }

    /**
     * @brief 쿠키 옵션을 해석하고 서버 쪽을 검증한다.
     * @details 길이는 8(클라이언트만) 또는 16~40(서버 쿠키 포함)만 유효하다. 그 밖은 형식
     *          위반이라 None이다.
     * @return 형식이 맞으면 클라이언트 쿠키와 유효 여부. 유효하지 않아도 클라이언트 쿠키는
     *         돌려주므로, 호출자가 올바른 쿠키를 담아 재시도를 유도할 수 있다.
     */
    pub fn parse_and_validate(&self, cookie: &[u8], ip: IpAddr) -> Option<CookieCheck> {
        self.parse_and_validate_at(cookie, ip, unix_now())
    }

    /** @brief 지정한 현재 시각으로 쿠키를 해석한다. 테스트가 월·수락 구간 경계를 고정한다. */
    fn parse_and_validate_at(&self, cookie: &[u8], ip: IpAddr, now: u32) -> Option<CookieCheck> {
        if cookie.len() != 8 && !(16..=40).contains(&cookie.len()) {
            return None;
        }
        let mut client = [0u8; 8];
        client.copy_from_slice(&cookie[0..8]);

        let valid = self.server_part_is_ours_at(&cookie[8..], &client, ip, now);
        Some(CookieCheck { client, valid })
    }

    /**
     * @brief 되돌아온 서버 쿠키가 이 서버가 이 주소에 준 것인지.
     *
     * @details 시각을 쿠키에서 읽어 그 값으로 다시 계산한다. 해시가 맞아도 구간 밖이면
     *          받아 주지 않는다. RFC 9018이 한 시간 과거와 5분 미래를 권한다. 구간이
     *          없으면 한 번 새어 나간 쿠키가 영원히 유효해 왕복 증명이 시간과 무관해진다.
     * @return 이 서버의 것이고 시각 구간 안이면 참.
     */
    fn server_part_is_ours_at(
        &self,
        server: &[u8],
        client: &[u8; 8],
        ip: IpAddr,
        now: u32,
    ) -> bool {
        if server.len() != SERVER_COOKIE_LEN || server[0] != COOKIE_VERSION {
            return false;
        }
        let stamp = u32::from_be_bytes([server[4], server[5], server[6], server[7]]);
        let age = i64::from(now.wrapping_sub(stamp) as i32);
        if !(-ACCEPT_FUTURE_SECS..=ACCEPT_PAST_SECS).contains(&age) {
            return false;
        }
        ct_eq(server, &self.server_cookie_at(client, ip, stamp))
    }
}

impl Drop for CookieKeeper {
    /** @brief 정책 교체·종료 때 루트 비밀이 해제된 메모리에 남지 않게 지운다. */
    fn drop(&mut self) {
        self.k0.zeroize();
        self.k1.zeroize();
    }
}

/** @brief 지금의 Unix 시각(초). 시계를 읽지 못하면 0. */
fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/**
 * @brief 상수시간 바이트 비교.
 * @warning 짧은 비교라도 조기 종료하면 안 된다. 시간 차이로 서버 쿠키를 한 바이트씩
 *          맞춰 나갈 수 있다.
 */
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
/** @brief 쿠키가 출발지에 묶이고 어긋난 것을 거부하는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 이 서버가 준 쿠키를 이 서버가 확인할 수 있는지. */
    fn roundtrip_validates() {
        let keeper = CookieKeeper::from_secret(&[7u8; 16]);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let resp = keeper.response_cookie(&client, ip);
        let check = keeper.parse_and_validate(&resp, ip).unwrap();
        assert!(check.valid);
        assert_eq!(check.client, client);
    }

    #[test]
    /** @brief 클라이언트 쪽만 든 쿠키를 통과로 보지 않는지. */
    fn client_only_is_invalid() {
        let keeper = CookieKeeper::from_secret(&[9u8; 16]);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let check = keeper
            .parse_and_validate(&[1, 2, 3, 4, 5, 6, 7, 8], ip)
            .unwrap();
        assert!(!check.valid);
    }

    #[test]
    /** @brief 다른 주소에서 온 쿠키를 거부하는지. 안 그러면 쿠키를 훔쳐 출발지를 속인다. */
    fn wrong_ip_fails() {
        let keeper = CookieKeeper::from_secret(&[3u8; 16]);
        let client = [8u8, 7, 6, 5, 4, 3, 2, 1];
        let resp = keeper.response_cookie(&client, "10.0.0.1".parse().unwrap());

        let check = keeper
            .parse_and_validate(&resp, "10.0.0.2".parse().unwrap())
            .unwrap();
        assert!(!check.valid);
    }

    #[test]
    /** @brief 어긋난 쿠키를 거부하는지. */
    fn malformed_rejected() {
        let keeper = CookieKeeper::from_secret(&[0u8; 16]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(keeper.parse_and_validate(&[1, 2, 3], ip).is_none());
    }

    #[test]
    /**
     * @brief 서버 쿠키가 RFC 9018이 정한 배치인지.
     *
     * @details 4는 128비트를 Version 1, Reserved 3, Timestamp 4, Hash 8로 나눈다. 길이나
     *          곳이 다르면 같은 비밀을 나눠 가진 다른 구현이 이 서버의 쿠키를 인정하지 못한다.
     */
    fn server_cookie_has_the_interoperable_layout() {
        let keeper = CookieKeeper::from_secret(&[5u8; 16]);
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let client = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let cookie = keeper.server_cookie_at(&client, ip, 0x1234_5678);
        assert_eq!(cookie.len(), SERVER_COOKIE_LEN);
        assert_eq!(cookie[0], 1, "Version");
        assert_eq!(&cookie[1..4], &[0, 0, 0], "Reserved는 0입니다");
        assert_eq!(
            &cookie[4..8],
            &0x1234_5678u32.to_be_bytes(),
            "Timestamp는 네트워크 바이트 순서입니다"
        );

        let full = keeper.response_cookie(&client, ip);
        assert_eq!(full.len(), 8 + SERVER_COOKIE_LEN, "클라이언트 8 + 서버 16");
        assert_eq!(&full[..8], &client, "클라이언트 쿠키를 그대로 되돌립니다");
    }

    #[test]
    /** @brief RFC 9018 Appendix A.1의 공식 IPv4 벡터와 해시 바이트까지 같은지. */
    fn server_cookie_matches_rfc9018_appendix_a1() {
        let secret = [
            0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f, 0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37,
            0xbf, 0xcf,
        ];
        let client = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
        let expected = [
            0x01, 0x00, 0x00, 0x00, 0x5c, 0xf7, 0x9f, 0x11, 0x1f, 0x81, 0x30, 0xc3, 0xee, 0xe2,
            0x94, 0x80,
        ];

        let cookie = CookieKeeper::from_secret(&secret).server_cookie_at(
            &client,
            "198.51.100.100".parse().unwrap(),
            1_559_731_985,
        );
        assert_eq!(cookie, expected);
    }

    #[test]
    /** @brief 같은 루트는 노드가 달라도 같은 쿠키를 만들고 다른 루트는 만들지 않는지. */
    fn shared_master_secret_is_stable_across_nodes() {
        let client = [1u8, 3, 5, 7, 9, 11, 13, 15];
        let ip: IpAddr = "2001:db8::53".parse().unwrap();
        let stamp = 1_800_000_000;
        let first = CookieKeeper::from_master_secret(&[0x11; 16]);
        let second = CookieKeeper::from_master_secret(&[0x11; 16]);
        let other = CookieKeeper::from_master_secret(&[0x22; 16]);

        assert_eq!(
            first.server_cookie_at(&client, ip, stamp),
            second.server_cookie_at(&client, ip, stamp)
        );
        assert_ne!(
            first.server_cookie_at(&client, ip, stamp),
            other.server_cookie_at(&client, ip, stamp)
        );
    }

    #[test]
    /** @brief 월 경계에서 키가 바뀌되 직전 쿠키는 한 시간 수락 구간 동안 인정하는지. */
    fn rotating_secret_accepts_the_previous_epoch_at_the_boundary() {
        let keeper = CookieKeeper::from_master_secret(&[0x5a; 16]);
        let ip: IpAddr = "192.0.2.53".parse().unwrap();
        let client = [2u8, 4, 6, 8, 10, 12, 14, 16];
        let boundary = SECRET_EPOCH_SECS * 700;
        let previous_stamp = boundary - 1;
        let current_stamp = boundary;
        let full = |stamp| {
            let mut cookie = client.to_vec();
            cookie.extend_from_slice(&keeper.server_cookie_at(&client, ip, stamp));
            cookie
        };

        assert_ne!(
            keeper.server_cookie_at(&client, ip, previous_stamp)[8..],
            keeper.server_cookie_at(&client, ip, current_stamp)[8..],
            "epoch가 바뀌면 서버 비밀도 바뀝니다"
        );
        assert!(
            keeper
                .parse_and_validate_at(&full(previous_stamp), ip, boundary + 1)
                .unwrap()
                .valid,
            "직전 epoch 쿠키는 수락 구간 안에서 유효합니다"
        );
        assert!(
            keeper
                .parse_and_validate_at(&full(current_stamp), ip, boundary + 1)
                .unwrap()
                .valid
        );
    }

    #[test]
    /**
     * @brief 시각 구간 밖의 쿠키를 거부하는지.
     *
     * @details RFC 9018은 한 시간 과거와 5분 미래를 받아 주라고 한다. 구간이 없으면 한 번
     *          새어 나간 쿠키가 영원히 유효해, 왕복 증명이 시간과 무관해진다.
     */
    fn cookie_outside_the_time_window_is_rejected() {
        let keeper = CookieKeeper::from_secret(&[6u8; 16]);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let client = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let now = unix_now();

        let check = |stamp: u32| {
            let mut cookie = client.to_vec();
            cookie.extend_from_slice(&keeper.server_cookie_at(&client, ip, stamp));
            keeper
                .parse_and_validate_at(&cookie, ip, now)
                .unwrap()
                .valid
        };

        assert!(check(now), "지금 만든 것은 유효합니다");
        assert!(check(now - 3000), "한 시간 안은 유효합니다");
        assert!(!check(now - 7200), "두 시간 전은 거부합니다");
        assert!(!check(now + 3600), "한 시간 뒤는 거부합니다");
        assert!(check(now + 60), "1분 앞선 시계는 받아 줍니다");

        /* 해시가 맞아도 버전이 다르면 이 서버의 것이 아니다. */
        let mut wrong_version = client.to_vec();
        let mut server = keeper.server_cookie_at(&client, ip, now);
        server[0] = 2;
        wrong_version.extend_from_slice(&server);
        assert!(
            !keeper
                .parse_and_validate_at(&wrong_version, ip, now)
                .unwrap()
                .valid
        );
    }
}
