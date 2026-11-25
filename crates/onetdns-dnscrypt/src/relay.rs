//! Anonymized DNSCrypt relay. A client puts a server's address in front of its packet; the relay
//! sends the packet on over UDP and passes the answer back, so the server sees the relay's address
//! instead of the client's. Anyone can name any address, so only packets that look like DNSCrypt
//! go out, only to targets the operator allows, and only a reply to that packet, no larger than it,
//! comes back.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use onetdns_core::udp::RecvWait;

use crate::{read_qname, CLIENT_MAGIC_LEN, CLIENT_NONCE_LEN, PUBKEY_LEN, RESOLVER_MAGIC};

/// Eight 0xff bytes and two zeros, which no client magic or DNS query starts with. An IPv6 or
/// IPv4-mapped address and a big-endian port follow.
pub const ANON_MAGIC: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

const NONCE_AT: usize = CLIENT_MAGIC_LEN + PUBKEY_LEN;

/// Header, MAC and one 64-byte block of padded plaintext.
const MIN_QUERY: usize = NONCE_AT + CLIENT_NONCE_LEN + 16 + 64;

/// The largest packet the protocol allows.
pub const MAX_PACKET: usize = 4096;

/// The largest packet a client sends a relay: the target's address and port, then the packet.
pub const MAX_ANONYMIZED: usize = ANON_MAGIC.len() + 16 + 2 + MAX_PACKET;

/// Resolver magic, nonce, MAC and a DNS header with one byte of padding.
const MIN_RESPONSE: usize = RESOLVER_MAGIC.len() + 24 + 16 + 12 + 1;

/// Clients give up on a server after about this long.
const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// Relayed UDP queries waiting at once, each on its own thread.
const MAX_INFLIGHT: usize = 128;

const RELAY_STACK_BYTES: usize = 128 * 1024;

pub fn is_anonymized(packet: &[u8]) -> bool {
    packet.starts_with(&ANON_MAGIC)
}

/// `packet` as a client sends it to a relay to have it passed on to `target`.
pub fn wrap(target: SocketAddr, packet: &[u8]) -> Vec<u8> {
    let ip = match target.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    let mut wrapped = Vec::with_capacity(MAX_ANONYMIZED - MAX_PACKET + packet.len());
    wrapped.extend_from_slice(&ANON_MAGIC);
    wrapped.extend_from_slice(&ip.octets());
    wrapped.extend_from_slice(&target.port().to_be_bytes());
    wrapped.extend_from_slice(packet);
    wrapped
}

pub struct Relay {
    allow_target: Box<dyn Fn(SocketAddr) -> bool + Send + Sync>,
    inflight: AtomicUsize,
}

/// A packet accepted for relaying, with where it goes.
pub struct Forward {
    target: SocketAddr,
    packet: Vec<u8>,
    kind: Kind,
}

enum Kind {
    Query,
    /// The question as `read_qname` gives it, with type and class.
    Certificate {
        question: Vec<u8>,
    },
}

impl Relay {
    pub fn new(allow_target: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        Relay {
            allow_target: Box::new(allow_target),
            inflight: AtomicUsize::new(0),
        }
    }

    /// None when `packet` must not be relayed: not anonymized, not DNSCrypt inside, or headed for a
    /// target the operator does not allow.
    pub fn accept(&self, packet: &[u8]) -> Option<Forward> {
        let rest = packet.strip_prefix(&ANON_MAGIC)?;
        let (address, rest) = rest.split_first_chunk::<16>()?;
        let (port, inner) = rest.split_first_chunk::<2>()?;
        let ip = Ipv6Addr::from(*address);
        let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
        let target = SocketAddr::new(ip, u16::from_be_bytes(*port));
        let kind = kind_of(inner)?;
        (self.allow_target)(target).then(|| Forward {
            target,
            packet: inner.to_vec(),
            kind,
        })
    }

    /// For UDP, whose listener cannot wait: the exchange runs on its own thread and `reply` gets
    /// the answer. Dropped when too many are already waiting.
    pub fn spawn(self: &Arc<Self>, forward: Forward, reply: impl FnOnce(&[u8]) + Send + 'static) {
        if self.inflight.fetch_add(1, Ordering::AcqRel) >= MAX_INFLIGHT {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            onetdns_core::debug!(event = "dnscrypt.relay_busy", target = %forward.target, "Too many relayed DNSCrypt queries are waiting; dropped this one");
            return;
        }
        let relay = self.clone();
        let spawned = std::thread::Builder::new()
            .name("dnscrypt-relay".into())
            .stack_size(RELAY_STACK_BYTES)
            .spawn(move || {
                let _ = onetdns_core::isolation::catch_request(|| {
                    if let Some(answer) = forward.exchange() {
                        reply(&answer);
                    }
                });
                relay.inflight.fetch_sub(1, Ordering::AcqRel);
            });
        if let Err(error) = spawned {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            onetdns_core::debug!(event = "dnscrypt.relay_spawn_failed", %error, "Could not start a thread for a relayed DNSCrypt query");
        }
    }
}

impl Forward {
    /// Sends the packet to its target and waits for the answer.
    pub fn exchange(&self) -> Option<Vec<u8>> {
        let any = if self.target.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = onetdns_core::udp::bind((any, 0)).ok()?;
        onetdns_core::udp::allow_fragmentation(&socket);
        socket.connect(self.target).ok()?;
        socket.send(&self.packet).ok()?;
        let deadline = Instant::now() + RELAY_TIMEOUT;
        // One byte more than the query, so a larger answer shows as such.
        let mut buf = vec![0u8; self.packet.len() + 1];
        loop {
            let wait = RecvWait::new(deadline.saturating_duration_since(Instant::now()));
            wait.install(&socket).ok()?;
            match wait.recv(&socket, &mut buf) {
                Ok(len) if len <= self.packet.len() && self.answered_by(&buf[..len]) => {
                    return Some(buf[..len].to_vec());
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return None;
                }
                // Windows fails the receive of a datagram larger than the buffer.
                _ if Instant::now() >= deadline => return None,
                _ => {}
            }
        }
    }

    fn answered_by(&self, response: &[u8]) -> bool {
        match &self.kind {
            Kind::Query => {
                let nonce = &self.packet[NONCE_AT..NONCE_AT + CLIENT_NONCE_LEN];
                response.len() >= MIN_RESPONSE
                    && response.starts_with(&RESOLVER_MAGIC)
                    && response[RESOLVER_MAGIC.len()..].starts_with(nonce)
            }
            Kind::Certificate { question } => {
                response.len() >= 12
                    && response[..2] == self.packet[..2]
                    && response[2] & 0x80 != 0
                    && response[4..6] == [0, 1]
                    && certificate_question_at(response) == Some(question.clone())
            }
        }
    }
}

/// A sealed query, or a lookup of a provider's certificates.
fn kind_of(inner: &[u8]) -> Option<Kind> {
    if let Some(question) = certificate_lookup(inner) {
        return Some(Kind::Certificate { question });
    }
    // A client magic of all 0xff would nest another anonymized packet, and seven zeros would look
    // like QUIC to a server sharing the port.
    let query = (MIN_QUERY..=MAX_PACKET).contains(&inner.len())
        && inner[..CLIENT_MAGIC_LEN] != [0xff; CLIENT_MAGIC_LEN]
        && inner[..7] != [0; 7];
    query.then_some(Kind::Query)
}

/// One TXT question and nothing else but an OPT record for padding.
fn certificate_lookup(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 12 || packet.len() > MAX_PACKET {
        return None;
    }
    let count = |at: usize| u16::from_be_bytes([packet[at], packet[at + 1]]);
    let plain_query = packet[2] & 0xf8 == 0;
    if !plain_query || count(4) != 1 || count(6) != 0 || count(8) != 0 || count(10) > 1 {
        return None;
    }
    certificate_question_at(packet)
}

/// The first question if it asks TXT IN of a name starting `2.dnscrypt`, as provider names do.
fn certificate_question_at(packet: &[u8]) -> Option<Vec<u8>> {
    let (mut name, end) = read_qname(packet, 12)?;
    let kind = packet.get(end..end + 4)?;
    let provider_like = name.starts_with(&[1, b'2']) && name.get(3..11) == Some(&b"dnscrypt"[..]);
    if !provider_like || kind != [0, 16, 0, 1] {
        return None;
    }
    name.extend_from_slice(kind);
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Certificate, Session};
    use crate::Provider;
    use std::net::UdpSocket;

    fn certificate_query(name: &str) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 16, 0, 1]);
        query
    }

    fn sealed_query(provider: &Provider) -> (Session, Vec<u8>, [u8; 12]) {
        let cert = Certificate::verify(
            &provider.cert_bytes(),
            &provider.provider_public_key(),
            crate::unix_now(),
        )
        .unwrap();
        let session = Session::new(&cert).unwrap();
        let query =
            b"\x00\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let (packet, nonce) = session.seal(query, 256);
        (session, packet, nonce)
    }

    fn open_relay() -> Relay {
        Relay::new(|_target| true)
    }

    #[test]
    /// What goes out must be DNSCrypt: a sealed query of plausible size or a certificate lookup.
    fn only_dnscrypt_packets_are_accepted() {
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let (_, sealed, _) = sealed_query(&provider);
        let relay = open_relay();

        assert!(relay.accept(&wrap(target, &sealed)).is_some());
        let lookup = certificate_query("2.dnscrypt-cert.test");
        assert!(relay.accept(&wrap(target, &lookup)).is_some());
        let adguard = certificate_query("2.dnscrypt.default.ns1.adguard.com");
        assert!(relay.accept(&wrap(target, &adguard)).is_some());

        let mut ordinary = certificate_query("www.example.com");
        assert!(
            relay.accept(&wrap(target, &ordinary)).is_none(),
            "일반 질의"
        );
        ordinary = certificate_query("2.dnscrypt-cert.test");
        let qtype = ordinary.len() - 3;
        ordinary[qtype] = 1;
        assert!(relay.accept(&wrap(target, &ordinary)).is_none(), "TXT 아님");
        let mut answer = lookup.clone();
        answer[2] |= 0x80;
        assert!(relay.accept(&wrap(target, &answer)).is_none(), "응답");
        assert!(
            relay.accept(&wrap(target, &sealed[..100])).is_none(),
            "짧음"
        );
        assert!(relay.accept(&wrap(target, &vec![7; 4097])).is_none(), "김");
        let nested = wrap(target, &sealed);
        assert!(relay.accept(&wrap(target, &nested)).is_none(), "중첩");
        let mut quic = sealed.clone();
        quic[..8].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(relay.accept(&wrap(target, &quic)).is_none(), "QUIC");
        assert!(relay.accept(&sealed).is_none(), "익명화 아님");
        assert!(
            relay.accept(&wrap(target, &sealed)[..27]).is_none(),
            "잘린 머리"
        );
    }

    #[test]
    /// The target policy sees the address as IPv4 when the client wrote it IPv4-mapped.
    fn the_target_policy_decides_and_sees_mapped_addresses_as_ipv4() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let (_, sealed, _) = sealed_query(&provider);
        let relay = Relay::new(|target| target == "192.0.2.1:443".parse().unwrap());
        assert!(relay
            .accept(&wrap("192.0.2.1:443".parse().unwrap(), &sealed))
            .is_some());
        assert!(relay
            .accept(&wrap("192.0.2.1:444".parse().unwrap(), &sealed))
            .is_none());
        assert!(relay
            .accept(&wrap("[2001:db8::1]:443".parse().unwrap(), &sealed))
            .is_none());
    }

    /// A UDP server on loopback that answers each datagram with what `answer` makes of it.
    fn fake_server(
        answer: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, UdpSocket) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let worker = server.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((len, from)) = worker.recv_from(&mut buf) {
                for reply in answer(&buf[..len]) {
                    let _ = worker.send_to(&reply, from);
                }
            }
        });
        (addr, server)
    }

    #[test]
    /// The answer to the relayed query comes back; one to another nonce or one larger than the
    /// query does not, even with the right magic and nonce.
    fn only_an_answer_to_the_relayed_query_no_larger_than_it_comes_back() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let (session, sealed, nonce) = sealed_query(&provider);
        let server_provider = provider.clone();
        let (addr, _server) = fake_server(move |packet| {
            let real = crate::server::respond(
                &server_provider,
                packet,
                "127.0.0.1:1".parse().unwrap(),
                true,
                &|query: Vec<u8>, _src, _budget| {
                    let mut answer = query;
                    answer[2] |= 0x80;
                    Some(answer)
                },
                &|_src| true,
            )
            .unwrap();
            let mut stray = real.clone();
            stray[RESOLVER_MAGIC.len()] ^= 1;
            let mut big = real.clone();
            big.resize(packet.len() + 1, 0);
            vec![stray, big, real]
        });
        let forward = open_relay().accept(&wrap(addr, &sealed)).unwrap();
        let answer = forward.exchange().expect("서버 응답");
        assert!(answer.len() <= sealed.len());
        let plain = session
            .open(&answer, &nonce)
            .expect("릴레이가 다른 응답을 넘겼습니다");
        assert_eq!(&plain[..2], &[0x00, 0x07]);
    }

    #[test]
    fn a_certificate_answer_must_echo_the_lookup() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 3_600);
        let mut lookup = certificate_query("2.dnscrypt-cert.test");
        // The relay passes nothing larger than the query, so a lookup through it is padded.
        let padding: u16 = 400;
        lookup[11] = 1;
        lookup.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
        lookup.extend_from_slice(&(padding + 4).to_be_bytes());
        lookup.extend_from_slice(&[0, 12]);
        lookup.extend_from_slice(&padding.to_be_bytes());
        lookup.resize(lookup.len() + usize::from(padding), 0);
        let server_provider = provider.clone();
        let (addr, _server) = fake_server(move |packet| {
            let real = server_provider.cert_txt_response(packet).unwrap();
            let mut other_id = real.clone();
            other_id[1] ^= 1;
            vec![other_id, real]
        });
        let forward = open_relay().accept(&wrap(addr, &lookup)).unwrap();
        let answer = forward.exchange().expect("인증서 응답");
        assert_eq!(&answer[..2], &lookup[..2]);
        assert!(answer.windows(4).any(|window| window == b"DNSC"));
    }
}
