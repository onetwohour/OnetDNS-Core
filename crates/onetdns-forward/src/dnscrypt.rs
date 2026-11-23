//! DNSCrypt upstream. The provider's certificate is fetched from the server itself, checked against
//! the key in the stamp and kept per upstream until it is due for refresh. Queries go over UDP and
//! are asked again over TCP when the answer comes back truncated. With a relay, every packet goes to
//! it with the server's address in front, certificate lookups included.

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use onetdns_core::{LruMap, MutexExt};
use onetdns_dnscrypt::client::{best_certificate, Certificate, Session, QUERY_OVERHEAD};
use onetdns_dnscrypt::relay;
use onetdns_proto::{Edns, Message, Name, RData, RecordType};

use crate::{deadline_after, io_err, validate_response, ForwardError};

/// The protocol draft suggests refreshing hourly; servers publish the next certificate well before
/// the current one ends.
const CERT_REFRESH_SECS: u32 = 3_600;

/// A failed refresh is tried again this much later rather than on every query, while the held
/// certificate stays valid.
const CERT_RETRY_SECS: u32 = 60;

/// Where the UDP query size starts. The server's answer may be no larger than the query, so this
/// leaves room for most answers; the draft allows starting here.
const UDP_QUERY_START: usize = 512;

/// Packets are multiples of 64; this is the largest within the IPv6 minimum MTU less the IPv6 and
/// UDP headers (1232). A larger query risks fragmentation.
const UDP_QUERY_MAX: usize = 1_216;

const UDP_QUERY_STEP: usize = 64;

/// Upstreams with state kept at once; one forgotten past this fetches its certificate again.
const MAX_UPSTREAMS: usize = 256;

/// The server to ask and how to trust it, as a DNSCrypt stamp gives them.
pub(crate) struct Server<'a> {
    pub(crate) addr: SocketAddr,
    pub(crate) provider_name: &'a str,
    pub(crate) public_key: &'a [u8; 32],
    pub(crate) relay: Option<SocketAddr>,
}

impl Server<'_> {
    /// Where to send `packet` for the server, and what to send.
    fn route<'p>(&self, packet: &'p [u8]) -> (SocketAddr, Cow<'p, [u8]>) {
        match self.relay {
            Some(relay) => (relay, Cow::Owned(relay::wrap(self.addr, packet))),
            None => (self.addr, Cow::Borrowed(packet)),
        }
    }
}

struct Active {
    session: Session,
    ts_end: u32,
    refresh_at: AtomicU32,
}

#[derive(Default)]
struct State {
    active: Mutex<Option<Arc<Active>>>,
    /// Set while one query refreshes a certificate the others keep using.
    refreshing: AtomicBool,
    /// 0 until a truncated answer first grows it.
    udp_query_len: AtomicUsize,
}

type Key = (SocketAddr, String, [u8; 32]);

fn state(server: &Server<'_>) -> Arc<State> {
    static STATES: OnceLock<Mutex<LruMap<Key, Arc<State>>>> = OnceLock::new();
    let key = (
        server.addr,
        server.provider_name.to_string(),
        *server.public_key,
    );
    let mut states = STATES
        .get_or_init(|| Mutex::new(LruMap::new(MAX_UPSTREAMS)))
        .lock_recover();
    if let Some(found) = states.get(&key) {
        return found.clone();
    }
    let fresh = Arc::new(State::default());
    states.put(key, fresh.clone());
    fresh
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
        })
}

impl State {
    /// The session to seal with. A certificate due for refresh is fetched again by one query while
    /// the others keep using it; a failed fetch keeps it until it expires.
    fn session(&self, server: &Server<'_>, deadline: Instant) -> Result<Arc<Active>, ForwardError> {
        let now = unix_now();
        let held = self
            .active
            .lock_recover()
            .clone()
            .filter(|active| now <= active.ts_end);
        if let Some(active) = &held {
            if now < active.refresh_at.load(Ordering::Relaxed)
                || self.refreshing.swap(true, Ordering::AcqRel)
            {
                return Ok(active.clone());
            }
        }
        let fetched = fetch_certificate(server, deadline).and_then(|cert| {
            let session = Session::new(&cert).ok_or(ForwardError::BadResponse)?;
            let fetched_at = unix_now();
            let refresh_at = fetched_at
                .saturating_add(CERT_REFRESH_SECS.min(cert.ts_end.saturating_sub(fetched_at) / 2));
            Ok(Arc::new(Active {
                session,
                ts_end: cert.ts_end,
                refresh_at: AtomicU32::new(refresh_at),
            }))
        });
        if held.is_some() {
            self.refreshing.store(false, Ordering::Release);
        }
        match fetched {
            Ok(active) => {
                *self.active.lock_recover() = Some(active.clone());
                Ok(active)
            }
            Err(error) => {
                crate::note_upstream_connect_failure(
                    "dnscrypt",
                    server.addr,
                    server.provider_name,
                    &error,
                );
                let held = held.ok_or(error)?;
                held.refresh_at.store(
                    unix_now().saturating_add(CERT_RETRY_SECS),
                    Ordering::Relaxed,
                );
                Ok(held)
            }
        }
    }

    fn udp_query_len(&self) -> usize {
        self.udp_query_len
            .load(Ordering::Relaxed)
            .max(UDP_QUERY_START)
    }

    /// A larger query would have let the answer through over UDP.
    fn grow_udp_query(&self, sent: usize) {
        let grown = (sent + UDP_QUERY_STEP).min(UDP_QUERY_MAX);
        self.udp_query_len.fetch_max(grown, Ordering::Relaxed);
    }
}

pub(crate) fn exchange(
    server: Server<'_>,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: std::time::Duration,
) -> Result<Message, ForwardError> {
    let deadline = deadline_after(timeout);
    let state = state(&server);
    let active = state.session(&server, deadline)?;
    let answer = |plain: Vec<u8>| {
        Message::parse(&plain)
            .ok()
            .filter(|response| validate_response(request, response, Some(wire_id)).is_ok())
    };

    let udp_len = state.udp_query_len();
    let (packet, nonce) = active.session.seal(wire, udp_len);
    let (dest, packet) = server.route(&packet);
    let response = udp_roundtrip(dest, &packet, deadline, |bytes| {
        active.session.open(bytes, &nonce).and_then(answer)
    })?;
    if !response.header.truncated {
        return Ok(response);
    }
    state.grow_udp_query(udp_len);

    let tcp_len = if server.relay.is_some() {
        // The relay passes it on over UDP, where the answer may be no larger than the query.
        relay::MAX_PACKET
    } else {
        // Random padding up to 256 bytes hides the query length on TCP, where the answer size
        // does not depend on it.
        let extra = usize::from(onetdns_core::ephemeral_random_array::<1>()[0] % 4) * 64;
        QUERY_OVERHEAD + wire.len() + 1 + extra
    };
    let (packet, nonce) = active.session.seal(wire, tcp_len);
    let (dest, packet) = server.route(&packet);
    let bytes = tcp_roundtrip(dest, &packet, deadline)?;
    active
        .session
        .open(&bytes, &nonce)
        .and_then(answer)
        .ok_or(ForwardError::BadResponse)
}

/// TXT records of the provider name, each holding one certificate. UDP gets part of the budget so
/// TCP, which the spec falls back to on any UDP failure, keeps the rest.
fn fetch_certificate(server: &Server<'_>, deadline: Instant) -> Result<Certificate, ForwardError> {
    let name = Name::from_str(server.provider_name).map_err(|_| ForwardError::BadResponse)?;
    let id = crate::next_id();
    let mut query = Message::query(id, name, RecordType::TXT);
    if server.relay.is_some() {
        // A relay passes back nothing larger than the lookup.
        let opt = Edns::default()
            .try_to_record()
            .map_err(|_| ForwardError::BadResponse)?;
        query.additionals.push(opt);
        query
            .pad_to(UDP_QUERY_MAX)
            .map_err(|_| ForwardError::BadResponse)?;
    }
    let wire = query.try_encode().map_err(|_| ForwardError::BadResponse)?;
    let (dest, wire) = server.route(&wire);
    let valid = |response: Message| {
        validate_response(&query, &response, Some(id))
            .is_ok()
            .then_some(response)
    };

    let over_udp = udp_roundtrip(dest, &wire, crate::bounded_first_try(deadline), |bytes| {
        Message::parse_udp_reply(bytes).and_then(valid)
    });
    let response = match over_udp {
        Ok(response) if !response.header.truncated => response,
        _ => {
            let bytes = tcp_roundtrip(dest, &wire, deadline)?;
            Message::parse(&bytes)
                .ok()
                .and_then(valid)
                .ok_or(ForwardError::BadResponse)?
        }
    };
    let certificates: Vec<Vec<u8>> = response
        .answers
        .iter()
        .filter(|record| record.name.eq_ignore_case(&query.questions[0].name))
        .filter_map(|record| match &record.rdata {
            RData::Txt(chunks) => Some(chunks.concat()),
            _ => None,
        })
        .collect();
    best_certificate(
        certificates.iter().map(Vec::as_slice),
        server.public_key,
        unix_now(),
    )
    .ok_or_else(|| {
        ForwardError::Io(format!(
            "No valid DNSCrypt certificate signed by the stamp's key among {} offered",
            certificates.len()
        ))
    })
}

/// Sends one packet and returns the first reply from `dest` that `accept` takes. The socket goes
/// back to the pool only after an accepted reply.
fn udp_roundtrip<T>(
    dest: SocketAddr,
    packet: &[u8],
    deadline: Instant,
    mut accept: impl FnMut(&[u8]) -> Option<T>,
) -> Result<T, ForwardError> {
    let bind = crate::outgoing_bind(dest);
    let (sock, uses, _) = crate::take_pooled_udp_socket(bind).map_err(io_err)?;
    let mut timeout = None;
    let result = (|| {
        sock.send_to(packet, dest).map_err(io_err)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ForwardError::Timeout);
            }
            sock.set_read_timeout(Some(remaining)).map_err(io_err)?;
            timeout = Some(remaining);
            let accepted = crate::UDP_RECV_BUFFER.with(|slot| {
                let mut buf = slot.borrow_mut();
                sock.recv_from(&mut buf)
                    .map(|(len, from)| (from == dest).then(|| accept(&buf[..len])).flatten())
            });
            if let Some(value) = accepted.map_err(io_err)? {
                return Ok(value);
            }
        }
    })();
    if result.is_ok() {
        crate::return_pooled_udp_socket(bind, sock, uses, timeout);
    } else {
        drop(sock);
        crate::discard_pooled_udp_socket(bind);
    }
    result
}

/// One transaction per connection, as DNSCrypt servers close after answering.
fn tcp_roundtrip(
    dest: SocketAddr,
    packet: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, ForwardError> {
    let len = u16::try_from(packet.len()).map_err(|_| ForwardError::BadResponse)?;
    let mut stream = crate::connect_upstream(dest, deadline).map_err(io_err)?;
    let mut framed = Vec::with_capacity(2 + packet.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(packet);
    stream.write_all(&framed).map_err(io_err)?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).map_err(io_err)?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut body).map_err(io_err)?;
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Forwarder, Upstream};
    use onetdns_dnscrypt::Provider;
    use onetdns_proto::Record;
    use std::net::{TcpListener, UdpSocket};
    use std::time::Duration;

    pub(crate) const PROVIDER: &str = "2.dnscrypt-cert.test";

    pub(crate) struct TestServer {
        pub(crate) addr: SocketAddr,
        pub(crate) public_key: [u8; 32],
        pub(crate) cert_lookups: Arc<AtomicUsize>,
        tcp_queries: Arc<AtomicUsize>,
        refuse_certificates: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
        }
    }

    /// TCP first: Windows reserves ranges of TCP ports that UDP may still be given. A port UDP
    /// cannot take stays held, so the next try gets another.
    fn bind_udp_and_tcp() -> (UdpSocket, TcpListener) {
        let mut taken = Vec::new();
        for _ in 0..512 {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            match UdpSocket::bind(tcp.local_addr().unwrap()) {
                Ok(udp) => return (udp, tcp),
                Err(_) => taken.push(tcp),
            }
        }
        panic!("UDP 와 TCP 가 함께 비어 있는 포트를 찾지 못했습니다");
    }

    /// A DNSCrypt server on one loopback port, UDP and TCP, answering A queries with `answers`
    /// addresses and truncating what does not fit the UDP budget.
    pub(crate) fn spawn_server(answers: usize) -> TestServer {
        let provider = Provider::generate(PROVIDER, 3_600);
        let (udp, tcp) = bind_udp_and_tcp();
        let addr = udp.local_addr().unwrap();
        tcp.set_nonblocking(true).unwrap();
        let server = TestServer {
            addr,
            public_key: provider.provider_public_key(),
            cert_lookups: Arc::new(AtomicUsize::new(0)),
            tcp_queries: Arc::new(AtomicUsize::new(0)),
            refuse_certificates: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let handler = move |query: Vec<u8>, _src: SocketAddr, budget: usize| {
            let mut response = Message::parse(&query).ok()?;
            response.header.response = true;
            let name = response.questions[0].name.clone();
            for index in 0..answers {
                let ip = std::net::Ipv4Addr::new(192, 0, 2, index as u8);
                response
                    .answers
                    .push(Record::new(name.clone(), 60, RData::A(ip)));
            }
            let wire = response.try_encode().ok()?;
            if wire.len() <= budget {
                return Some(wire);
            }
            response.answers.clear();
            response.header.truncated = true;
            response.try_encode().ok()
        };
        let lookups = server.cert_lookups.clone();
        let refuse = server.refuse_certificates.clone();
        let allowed = move |_src: SocketAddr| {
            lookups.fetch_add(1, Ordering::Relaxed);
            !refuse.load(Ordering::Relaxed)
        };

        let (udp_provider, udp_allowed, stop) =
            (provider.clone(), allowed.clone(), server.stop.clone());
        std::thread::spawn(move || {
            onetdns_dnscrypt::server::serve(
                udp_provider,
                udp,
                handler,
                udp_allowed,
                |_src| false,
                None,
                &stop,
            )
        });
        let (tcp_queries, stop) = (server.tcp_queries.clone(), server.stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let Ok((mut stream, peer)) = tcp.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).unwrap();
                let mut packet = vec![0u8; usize::from(u16::from_be_bytes(len))];
                stream.read_exact(&mut packet).unwrap();
                if packet[..8] == provider.client_magic {
                    tcp_queries.fetch_add(1, Ordering::Relaxed);
                }
                let reply = onetdns_dnscrypt::server::respond(
                    &provider, &packet, peer, false, &handler, &allowed,
                );
                if let Some(reply) = reply {
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    let _ = stream.write_all(&framed);
                }
            }
        });
        server
    }

    fn ask(upstream: Upstream) -> Result<Message, ForwardError> {
        let forwarder = Forwarder::with_upstreams(vec![upstream], Duration::from_secs(2));
        let name = Name::from_str("dnscrypt.example").unwrap();
        forwarder.resolve(&Message::query(0x4242, name, RecordType::A))
    }

    fn upstream(server: &TestServer) -> Upstream {
        Upstream::dnscrypt(server.addr, PROVIDER, server.public_key, None)
    }

    fn held_state(server: &TestServer) -> Arc<State> {
        state(&Server {
            addr: server.addr,
            provider_name: PROVIDER,
            public_key: &server.public_key,
            relay: None,
        })
    }

    #[test]
    fn a_dnscrypt_upstream_answers_under_a_verified_certificate() {
        let server = spawn_server(1);
        let response = ask(upstream(&server)).expect("DNSCrypt 업스트림 응답");
        assert_eq!(response.header.id, 0x4242);
        assert_eq!(response.answers.len(), 1);
        ask(upstream(&server)).expect("두 번째 질의");
        assert_eq!(
            server.cert_lookups.load(Ordering::Relaxed),
            1,
            "유효한 인증서가 있는데 다시 받았습니다"
        );
    }

    #[test]
    fn a_certificate_not_signed_by_the_stamp_key_is_refused() {
        let server = spawn_server(1);
        let stranger = Provider::generate(PROVIDER, 3_600).provider_public_key();
        let refused = ask(Upstream::dnscrypt(server.addr, PROVIDER, stranger, None));
        assert!(
            refused.is_err(),
            "스탬프 키가 서명하지 않은 인증서를 믿었습니다"
        );
    }

    #[test]
    /// The relay counts what it passes on; the certificate lookup and the query must both be there.
    fn a_relayed_upstream_reaches_its_server_only_through_the_relay() {
        let server = spawn_server(1);
        let relay_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let relayed = Arc::new(AtomicUsize::new(0));
        let (count, target, stop) = (relayed.clone(), server.addr, server.stop.clone());
        std::thread::spawn(move || {
            onetdns_dnscrypt::server::serve(
                Provider::generate("2.dnscrypt-cert.relay", 3_600),
                relay_socket,
                |_query, _src, _budget| None,
                |_src| true,
                |_src| false,
                Some(Arc::new(relay::Relay::new(move |to| {
                    count.fetch_add(1, Ordering::Relaxed);
                    to == target
                }))),
                &stop,
            )
        });
        let relayed_upstream =
            Upstream::dnscrypt(server.addr, PROVIDER, server.public_key, Some(relay_addr));
        let response = ask(relayed_upstream).expect("릴레이를 거친 응답");
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            relayed.load(Ordering::Relaxed),
            2,
            "인증서 조회와 질의가 모두 릴레이를 거쳐야 합니다"
        );
    }

    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp_and_grows_the_udp_query() {
        let server = spawn_server(40);
        let response = ask(upstream(&server)).expect("TCP 로 다시 물은 응답");
        assert_eq!(response.answers.len(), 40);
        assert!(!response.header.truncated);
        assert_eq!(server.tcp_queries.load(Ordering::Relaxed), 1);
        assert_eq!(
            held_state(&server).udp_query_len(),
            UDP_QUERY_START + UDP_QUERY_STEP
        );
    }

    #[test]
    /// A refresh that fails keeps the certificate in hand while it is valid, and is not tried
    /// again on the very next query.
    fn a_certificate_due_for_refresh_is_fetched_again_and_kept_when_that_fails() {
        let server = spawn_server(1);
        ask(upstream(&server)).unwrap();
        let state = held_state(&server);
        let due = || {
            let active = state.active.lock_recover().clone().unwrap();
            active.refresh_at.store(0, Ordering::Relaxed);
        };
        due();
        ask(upstream(&server)).unwrap();
        assert_eq!(server.cert_lookups.load(Ordering::Relaxed), 2, "갱신");

        due();
        server.refuse_certificates.store(true, Ordering::Relaxed);
        ask(upstream(&server)).expect("갱신에 실패해도 유효한 인증서로 답해야 합니다");
        let after_failure = server.cert_lookups.load(Ordering::Relaxed);
        ask(upstream(&server)).unwrap();
        assert_eq!(
            server.cert_lookups.load(Ordering::Relaxed),
            after_failure,
            "실패한 갱신을 질의마다 다시 시도했습니다"
        );
    }
}
