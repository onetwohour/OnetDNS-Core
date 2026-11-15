//! DNS Cookies (RFC 7873): a cheap round-trip proof against spoofed source addresses. The server
//! keeps no state: the server cookie is a keyed hash of the client cookie and the source address,
//! so a returned cookie that matches proves the address received our response. This keeps the
//! server from being reflected in amplification attacks.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::siphash::SipHasher24;
use zeroize::Zeroize;

/// RFC 9018 layout: version 1, reserved 3, timestamp 4, hash 8.
pub const SERVER_COOKIE_LEN: usize = 16;

const COOKIE_VERSION: u8 = 1;

/// RFC 9018 recommends one hour.
const ACCEPT_PAST_SECS: i64 = 3600;

/// Slack for peers whose clock runs slightly ahead.
const ACCEPT_FUTURE_SECS: i64 = 300;

/// RFC 9018 recommends rotating the server secret monthly.
const SECRET_EPOCH_SECS: u32 = 30 * 24 * 60 * 60;

/// Domain separation for the per-epoch SipHash keys.
const EPOCH_KEY_CONTEXT: &[u8] = b"OnetDNS DNS Cookie epoch key v1";

pub struct CookieKeeper {
    k0: u64,
    k1: u64,
    /// Derive a 30-day epoch key from `k0` and `k1` for each cookie's timestamp.
    rotating: bool,
}

pub struct CookieCheck {
    /// Echoed back in the response.
    pub client: [u8; 8],

    /// False means the round trip is not proven yet.
    pub valid: bool,
}

impl CookieKeeper {
    /// Cookie keys rotate every 30 days.
    pub fn random() -> Self {
        let mut secret = onetdns_core::random_array::<16>();
        let keeper = Self::from_master_secret(&secret);
        secret.zeroize();
        keeper
    }

    /// Instances must share the secret to accept each other's cookies; otherwise a client repeats
    /// the round trip every time it reaches another node.
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

    /// Derives the server secret for each 30-day epoch from `secret` and the timestamp in the
    /// cookie, without state or locks. A cookie from just before a boundary still validates with
    /// the previous epoch key inside the acceptance window, and nodes sharing the root accept each
    /// other's cookies.
    pub fn from_master_secret(secret: &[u8; 16]) -> Self {
        let mut keeper = Self::from_secret(secret);
        keeper.rotating = true;
        keeper
    }

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

    /// RFC 9018 layout: version (1), reserved (3), timestamp (4), then a SipHash-2-4 (8) over the
    /// rest. The source address must be part of the hash, or a cookie received once could be
    /// attached to any spoofed address. When validating, `stamp` is the timestamp read from the
    /// received cookie.
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

    pub fn server_cookie(&self, client_cookie: &[u8], ip: IpAddr) -> [u8; 16] {
        self.server_cookie_at(client_cookie, ip, unix_now())
    }

    /// Client cookie (8) followed by server cookie (16).
    pub fn response_cookie(&self, client_cookie: &[u8; 8], ip: IpAddr) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + SERVER_COOKIE_LEN);
        out.extend_from_slice(client_cookie);
        out.extend_from_slice(&self.server_cookie(client_cookie, ip));
        out
    }

    /// Only 8 bytes (client cookie only) or 16 to 40 bytes are well-formed; anything else returns
    /// `None`. An invalid server cookie still returns the client cookie, so the caller can answer
    /// with a fresh cookie and invite a retry.
    pub fn parse_and_validate(&self, cookie: &[u8], ip: IpAddr) -> Option<CookieCheck> {
        self.parse_and_validate_at(cookie, ip, unix_now())
    }

    /// Takes `now` so tests can pin the epoch and window boundaries.
    fn parse_and_validate_at(&self, cookie: &[u8], ip: IpAddr, now: u32) -> Option<CookieCheck> {
        if cookie.len() != 8 && !(16..=40).contains(&cookie.len()) {
            return None;
        }
        let mut client = [0u8; 8];
        client.copy_from_slice(&cookie[0..8]);

        let valid = self.server_part_is_ours_at(&cookie[8..], &client, ip, now);
        Some(CookieCheck { client, valid })
    }

    /// Recomputes the hash with the timestamp read from the cookie and rejects the cookie outside
    /// the window even when the hash matches: without a window a leaked cookie would stay valid
    /// forever.
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
    fn drop(&mut self) {
        self.k0.zeroize();
        self.k1.zeroize();
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Constant time, even for short inputs: an early exit would let an attacker guess the server
/// cookie byte by byte.
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
mod tests {
    use super::*;

    #[test]
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
    fn client_only_is_invalid() {
        let keeper = CookieKeeper::from_secret(&[9u8; 16]);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let check = keeper
            .parse_and_validate(&[1, 2, 3, 4, 5, 6, 7, 8], ip)
            .unwrap();
        assert!(!check.valid);
    }

    #[test]
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
    fn malformed_rejected() {
        let keeper = CookieKeeper::from_secret(&[0u8; 16]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(keeper.parse_and_validate(&[1, 2, 3], ip).is_none());
    }

    #[test]
    /// A different length or position would stop other implementations that share the secret from
    /// accepting our cookies.
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

        // A matching hash with another version is still not ours.
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
