//! DNS stamps (`sdns://`) naming a DNSCrypt server, as upstream settings take them, optionally
//! followed by `#` and the stamp of an Anonymized DNSCrypt relay to reach it through. Both carry an
//! IP address, so they need no bootstrap lookup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const DNSCRYPT: u8 = 0x01;
const DNSCRYPT_RELAY: u8 = 0x81;

/// The port a DNSCrypt or relay stamp implies when it names none.
const DEFAULT_PORT: u16 = 443;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnscryptUpstream {
    pub addr: SocketAddr,
    /// The provider's Ed25519 key, which signs its certificates.
    pub public_key: [u8; 32],
    /// Certificates are fetched as TXT records of this name.
    pub provider_name: String,
    pub relay: Option<SocketAddr>,
}

pub fn dnscrypt_upstream(text: &str) -> Option<DnscryptUpstream> {
    let (server, relay) = match text.trim().split_once('#') {
        Some((server, relay)) => (server, Some(dnscrypt_relay(relay)?)),
        None => (text, None),
    };
    let bytes = decode(server, DNSCRYPT)?;
    // Eight bytes of properties follow the type.
    let mut rest = bytes.get(9..)?;
    let addr = address(take_lp(&mut rest)?)?;
    let public_key = take_lp(&mut rest)?.try_into().ok()?;
    let provider_name = std::str::from_utf8(take_lp(&mut rest)?)
        .ok()
        .filter(|name| crate::settings::valid_dns_name(name))?
        .trim_end_matches('.')
        .to_string();
    Some(DnscryptUpstream {
        addr,
        public_key,
        provider_name,
        relay,
    })
}

fn dnscrypt_relay(text: &str) -> Option<SocketAddr> {
    let bytes = decode(text, DNSCRYPT_RELAY)?;
    address(take_lp(&mut &bytes[1..])?)
}

fn decode(text: &str, kind: u8) -> Option<Vec<u8>> {
    let bytes = base64url(text.trim().strip_prefix("sdns://")?)?;
    (bytes.first() == Some(&kind)).then_some(bytes)
}

fn take_lp<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (&len, tail) = rest.split_first()?;
    let value = tail.get(..usize::from(len))?;
    *rest = &tail[usize::from(len)..];
    Some(value)
}

/// An IP address with an optional port, IPv6 in brackets.
fn address(raw: &[u8]) -> Option<SocketAddr> {
    let text = std::str::from_utf8(raw).ok()?;
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return (addr.port() != 0).then_some(addr);
    }
    let ip = match text
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        Some(inner) => IpAddr::V6(inner.parse::<Ipv6Addr>().ok()?),
        None => IpAddr::V4(text.parse::<Ipv4Addr>().ok()?),
    };
    Some(SocketAddr::new(ip, DEFAULT_PORT))
}

/// Without padding, as stamps are written.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // One leftover character cannot hold a byte, and set leftover bits mean a different encoding.
    (bits < 6 && acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AdGuard's published DNSCrypt stamp.
    const ADGUARD: &str = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";

    #[test]
    fn a_published_dnscrypt_stamp_decodes() {
        let stamp = dnscrypt_upstream(ADGUARD).unwrap();
        assert_eq!(stamp.addr, "94.140.14.14:5443".parse().unwrap());
        assert_eq!(stamp.provider_name, "2.dnscrypt.default.ns1.adguard.com");
        assert_eq!(&stamp.public_key[..4], &[0xd1, 0x2b, 0x47, 0xf2]);
        assert_eq!(stamp.relay, None);
    }

    #[test]
    /// A relay stamp has no properties, only an address, whose port defaults to 443.
    fn a_relay_stamp_after_the_server_names_the_route() {
        let routed = |relay: &str| dnscrypt_upstream(&format!("{ADGUARD}#{relay}"));
        assert_eq!(
            routed("sdns://gQ4xOTIuMC4yLjE6NTQ0Mw").unwrap().relay,
            Some("192.0.2.1:5443".parse().unwrap())
        );
        let v6 = routed("sdns://gQ1bMjAwMTpkYjg6OjFd").unwrap();
        assert_eq!(v6.relay, Some("[2001:db8::1]:443".parse().unwrap()));
        assert_eq!(v6.addr, "94.140.14.14:5443".parse().unwrap());

        assert!(routed(ADGUARD).is_none(), "릴레이 자리에 서버 스탬프");
        assert!(
            routed("sdns://gQ4xOTIuMC4yLjE6NTQ0").is_none(),
            "잘린 릴레이"
        );
        assert!(
            routed("sdns://gQtleGFtcGxlLmNvbQ").is_none(),
            "호스트명 릴레이"
        );
        assert!(routed("").is_none(), "빈 릴레이");
    }

    /// A stamp of `kind` holding `fields` as length-prefixed values, after eight property bytes.
    fn stamp(kind: u8, fields: &[&[u8]]) -> String {
        let mut bytes = vec![kind, 0, 0, 0, 0, 0, 0, 0, 0];
        for field in fields {
            bytes.push(field.len() as u8);
            bytes.extend_from_slice(field);
        }
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut text = String::from("sdns://");
        for chunk in bytes.chunks(3) {
            let word = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                text.push(char::from(ALPHABET[(word >> (18 - 6 * i) & 63) as usize]));
            }
        }
        text
    }

    #[test]
    fn a_server_stamp_without_a_port_means_443() {
        let parsed = dnscrypt_upstream(&stamp(
            DNSCRYPT,
            &[b"[2001:db8::1]", &[7; 32], b"2.dnscrypt-cert.example."],
        ))
        .unwrap();
        assert_eq!(parsed.addr, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(parsed.provider_name, "2.dnscrypt-cert.example");
    }

    #[test]
    fn wrong_kinds_and_damaged_stamps_are_refused() {
        let doh = "sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5";
        assert!(dnscrypt_upstream(doh).is_none());
        let good = stamp(
            DNSCRYPT,
            &[b"192.0.2.1", &[7; 32], b"2.dnscrypt-cert.example"],
        );
        assert!(dnscrypt_upstream(&good).is_some());
        assert!(dnscrypt_upstream(&good.replace("sdns://", "https://")).is_none());
        assert!(dnscrypt_upstream(&format!("{good}==")).is_none());
        assert!(
            dnscrypt_upstream(&good[..good.len() - 2]).is_none(),
            "잘린 스탬프"
        );
        for (what, fields) in [
            (
                "호스트명",
                [&b"dns.example"[..], &[7; 32], b"2.dnscrypt-cert.example"],
            ),
            (
                "포트 0",
                [b"192.0.2.1:0", &[7; 32], b"2.dnscrypt-cert.example"],
            ),
            (
                "짧은 키",
                [b"192.0.2.1", &[7; 31], b"2.dnscrypt-cert.example"],
            ),
            ("이름 아님", [b"192.0.2.1", &[7; 32], b"2.dnscrypt cert"]),
        ] {
            assert!(
                dnscrypt_upstream(&stamp(DNSCRYPT, &fields)).is_none(),
                "{what}"
            );
        }
        assert!(dnscrypt_upstream("sdns://AQ").is_none(), "속성 없음");
    }
}
