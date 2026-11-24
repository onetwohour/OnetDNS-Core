use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onetdns_core::udp::{shared_read_timeout, wake_readers};

use crate::relay::{self, Relay};
use crate::{
    decrypt_query, encrypt_response, Provider, CLIENT_MAGIC_LEN, CLIENT_NONCE_LEN, PUBKEY_LEN,
    RESOLVER_MAGIC,
};

const HEADER_LEN: usize = CLIENT_MAGIC_LEN + PUBKEY_LEN + CLIENT_NONCE_LEN;

const AEAD_TAG_LEN: usize = 16;

const RESPONSE_OVERHEAD: usize = RESOLVER_MAGIC.len() + 24 + AEAD_TAG_LEN;

const PAD_BLOCK: usize = 64;

/// A UDP response must not be longer than the query that asked for it, or a small spoofed query
/// becomes an amplifier. The plaintext is padded to a multiple of 64 with at least one byte of
/// padding, so the budget is what remains after that. Zero means no answer fits.
fn response_budget(query_len: usize) -> usize {
    let room = query_len.saturating_sub(RESPONSE_OVERHEAD);
    (room / PAD_BLOCK * PAD_BLOCK).saturating_sub(1)
}

/// TCP confirms the source with its handshake, so amplification does not apply; only the 16-bit
/// length prefix limits the answer.
const TCP_RESPONSE_BUDGET: usize = u16::MAX as usize - RESPONSE_OVERHEAD - PAD_BLOCK;

/// A TCP query has no reason to grow with the answer, and trusting the length prefix alone would
/// let the sender choose how much memory we allocate.
pub const MAX_TCP_QUERY: usize = 8192;

/// Shared by UDP and TCP. The first 8 bytes tell an encrypted query (client magic) from a possible
/// certificate lookup; anything else gets no answer. Over UDP the answer is cut to fit the query
/// length. The returned payload has no TCP length prefix.
pub fn respond<H, A>(
    provider: &Provider,
    packet: &[u8],
    src: SocketAddr,
    over_udp: bool,
    handler: &H,
    allowed: &A,
) -> Option<Vec<u8>>
where
    H: Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>>,
    A: Fn(SocketAddr) -> bool,
{
    if packet.len() >= CLIENT_MAGIC_LEN && packet[..CLIENT_MAGIC_LEN] == provider.client_magic {
        if packet.len() < HEADER_LEN + AEAD_TAG_LEN {
            return None;
        }
        // Before the key exchange: a packet too short to carry any answer must not cost a scalar
        // multiplication and a decryption.
        let budget = if over_udp {
            response_budget(packet.len())
        } else {
            TCP_RESPONSE_BUDGET
        };
        if budget == 0 {
            return None;
        }
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(&packet[CLIENT_MAGIC_LEN..CLIENT_MAGIC_LEN + PUBKEY_LEN]);
        let mut client_nonce = [0u8; 12];
        client_nonce.copy_from_slice(&packet[CLIENT_MAGIC_LEN + PUBKEY_LEN..HEADER_LEN]);

        let key = provider.shared_key(&client_pk);
        let dns_query = match decrypt_query(&key, &client_nonce, &packet[HEADER_LEN..]) {
            Some(query) => query,
            None => {
                onetdns_core::trace!(%src, "Could not decrypt DNSCrypt request");
                return None;
            }
        };

        let dns_response = handler(dns_query, src, budget)?;
        if dns_response.len() > budget {
            onetdns_core::debug!(event = "dnscrypt.response_over_budget", client = %src, len = dns_response.len(), budget = budget, "Response exceeds the size budget; not sent");
            return None;
        }
        let (nonce, ct) = encrypt_response(&key, &client_nonce, &dns_response);
        let mut out = Vec::with_capacity(RESOLVER_MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(&RESOLVER_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Some(out)
    } else if allowed(src) {
        provider.cert_txt_response(packet)
    } else {
        None
    }
}

/// Logs only every power-of-two failure: an unreachable client sending many queries would otherwise
/// turn logging into load.
fn record_send_error(src: SocketAddr, error: &std::io::Error) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "dnscrypt.send_failed", client = %src, count = count, %error, "Could not send DNSCrypt response");
    }
}

/// How often a reader on Unix, or the waiting thread on Windows, looks at the shutdown signal.
const SHUTDOWN_POLL: Duration = Duration::from_millis(500);

/// `allowed` guards the certificate lookup too: anyone can call it without encryption or
/// authentication, so without this check it would be an amplification path past access control and
/// rate limiting. It guards relayed packets as well, which never reach the pipeline. `drops` is
/// checked first on every packet: a source dropped by address gets no answer whatever the packet
/// holds, so it must not cost a key exchange.
///
/// `workers` threads read the socket and answer what they read, as the Do53 UDP workers do, so a
/// query waiting on its upstream holds up only its own thread. Each packet runs inside a fault
/// isolation boundary, so a panic from a crafted packet cannot kill a thread. Every thread must end
/// on shutdown, or the socket stays bound after a reload: on Unix they see the signal through the
/// socket's receive timeout, and on Windows this thread wakes them.
#[allow(clippy::too_many_arguments)]
pub fn serve<H, A, D>(
    provider: Provider,
    socket: UdpSocket,
    handler: H,
    allowed: A,
    drops: D,
    relay: Option<Arc<Relay>>,
    workers: usize,
    shutdown: &AtomicBool,
) -> std::io::Result<()>
where
    H: Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>> + Sync,
    A: Fn(SocketAddr) -> bool + Sync,
    D: Fn(SocketAddr) -> bool + Sync,
{
    let timeout = shared_read_timeout(SHUTDOWN_POLL);
    if let Err(error) = socket.set_read_timeout(timeout) {
        onetdns_core::error!(event = "dnscrypt.read_timeout_failed", %error, "Could not set a receive timeout; the DNSCrypt workers will not exit on reload and will keep the port bound");
    }
    let addr = socket.local_addr();
    // Relay threads hold it weakly, so a late answer cannot keep the port bound after shutdown.
    let socket = Arc::new(socket);
    std::thread::scope(|scope| {
        let mut readers = Vec::new();
        for index in 0..workers.max(1) {
            let spawned = std::thread::Builder::new()
                .name(format!("dnscrypt-worker-{index}"))
                .spawn_scoped(scope, || {
                    read_and_answer(
                        &socket,
                        &provider,
                        &handler,
                        &allowed,
                        &drops,
                        relay.as_ref(),
                        shutdown,
                    )
                });
            match spawned {
                Ok(reader) => readers.push(reader),
                Err(error) if readers.is_empty() => return Err(error),
                Err(error) => {
                    onetdns_core::error!(event = "dnscrypt.worker_spawn_failed", started = readers.len(), wanted = workers, %error, "Could not start every DNSCrypt worker; answering with fewer");
                    break;
                }
            }
        }
        if timeout.is_none() {
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(SHUTDOWN_POLL);
            }
            let running = || {
                readers
                    .iter()
                    .filter(|reader| !reader.is_finished())
                    .count()
            };
            if addr.and_then(|addr| wake_readers(addr, running)).is_err() {
                onetdns_core::error!(event = "dnscrypt.wake_failed", "Could not wake the DNSCrypt workers; shutdown waits until each receives its next query");
            }
        }
        Ok(())
    })
}

fn read_and_answer<H, A, D>(
    socket: &Arc<UdpSocket>,
    provider: &Provider,
    handler: &H,
    allowed: &A,
    drops: &D,
    relay: Option<&Arc<Relay>>,
    shutdown: &AtomicBool,
) where
    H: Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>>,
    A: Fn(SocketAddr) -> bool,
    D: Fn(SocketAddr) -> bool,
{
    let mut buf = vec![0u8; relay::MAX_ANONYMIZED];
    // Checked before receiving, not after: a query read during a handoff must still be answered.
    while !shutdown.load(Ordering::Relaxed) {
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                onetdns_core::debug!(event = "dnscrypt.recv_failed", error = %e, "Failed to receive DNSCrypt packet");
                continue;
            }
        };
        let packet = &buf[..n];

        let _ = onetdns_core::isolation::catch_request(|| {
            if drops(src) {
                return;
            }
            if let Some(relay) = relay.filter(|_| relay::is_anonymized(packet)) {
                if let Some(forward) = relay.accept(packet).filter(|_| allowed(src)) {
                    let socket = Arc::downgrade(socket);
                    relay.spawn(forward, move |answer| {
                        if let Some(socket) = socket.upgrade() {
                            if let Err(error) = socket.send_to(answer, src) {
                                record_send_error(src, &error);
                            }
                        }
                    });
                }
                return;
            }
            if let Some(out) = respond(provider, packet, src, true, handler, allowed) {
                if let Err(error) = socket.send_to(&out, src) {
                    record_send_error(src, &error);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// The budget is the DNS message length; magic, nonce, tag and padding to a multiple of 64 make
    /// up the rest of the packet.
    fn a_response_never_outgrows_the_query_that_asked_for_it() {
        for query_len in [132usize, 256, 324, 512, 1024, 1500, 4096] {
            let budget = response_budget(query_len);
            let padded = crate::pad(&vec![0u8; budget], PAD_BLOCK).len();
            let packet = RESPONSE_OVERHEAD + padded;
            assert!(
                packet <= query_len,
                "질의 {query_len}B 에 응답 {packet}B 는 증폭입니다 (예산 {budget})"
            );
        }
    }

    #[test]
    fn a_query_too_short_to_carry_an_answer_gets_no_budget() {
        for query_len in [0usize, 48, 100, 111] {
            assert_eq!(response_budget(query_len), 0, "{query_len}B");
        }
    }

    fn ask_for_cert(allow: bool, drop: bool) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};

        let provider = Provider::generate("2.dnscrypt-cert.test", 86_400);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            let _ = serve(
                provider,
                server,
                |_query, _src, _budget| None,
                move |_src| allow,
                move |_src| drop,
                None,
                2,
                &worker_stop,
            );
        });

        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in "2.dnscrypt-cert.test".split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 16, 0, 1]);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(700)))
            .unwrap();
        client.send_to(&query, addr).unwrap();
        let mut buf = [0u8; 4096];
        let answered = client.recv_from(&mut buf).is_ok();
        stop.store(true, Ordering::Release);
        let _ = thread.join();
        answered
    }

    fn build_query(provider: &Provider, dns: &[u8], pad_to: usize) -> Vec<u8> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut csk = [0u8; 32];
        onetdns_core::fill_random(&mut csk);
        let client_sk = StaticSecret::from(csk);
        let client_pk = PublicKey::from(&client_sk).to_bytes();
        let raw = client_sk
            .diffie_hellman(&PublicKey::from(provider.resolver_pk))
            .to_bytes();
        let shared = crate::box_beforenm(&raw);

        let mut client_nonce = [0u8; 12];
        onetdns_core::fill_random(&mut client_nonce);
        let mut nonce = [0u8; 24];
        nonce[..12].copy_from_slice(&client_nonce);

        let mut padded = dns.to_vec();
        padded.push(0x80);
        while padded.len() < pad_to {
            padded.push(0);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&provider.client_magic);
        packet.extend_from_slice(&client_pk);
        packet.extend_from_slice(&client_nonce);
        packet.extend_from_slice(&crate::secretbox_seal(&shared, &nonce, &padded));
        packet
    }

    #[test]
    /// TCP sources are confirmed by the handshake, so answers keep their full size; shrinking them
    /// would leave large answers no way through.
    fn tcp_does_not_shrink_the_answer_to_the_query() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 86_400);
        let dns: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let packet = build_query(&provider, dns, 256);

        let seen = std::sync::Mutex::new(Vec::new());
        let handler = |_q: Vec<u8>, _src: SocketAddr, budget: usize| -> Option<Vec<u8>> {
            seen.lock().unwrap().push(budget);
            None
        };
        let allow = |_src: SocketAddr| true;
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        respond(&provider, &packet, src, true, &handler, &allow);
        respond(&provider, &packet, src, false, &handler, &allow);
        let budgets = seen.lock().unwrap().clone();
        assert_eq!(budgets.len(), 2, "두 번 다 핸들러에 닿아야 합니다");
        assert!(
            budgets[0] < packet.len(),
            "UDP 예산 {}은 질의 {}보다 작아야 합니다",
            budgets[0],
            packet.len()
        );
        assert!(
            budgets[1] > 4096,
            "TCP 예산 {}이 질의 길이에 묶여 있습니다",
            budgets[1]
        );
    }

    #[test]
    /// Packets between the minimum header and the smallest answerable size can still decrypt, so
    /// UDP must refuse them by length alone; TCP keeps answering them.
    fn short_udp_queries_are_refused_before_they_reach_the_handler() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 86_400);
        let dns: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let handler = |_q: Vec<u8>, _src: SocketAddr, _budget: usize| -> Option<Vec<u8>> {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        };
        let allow = |_src: SocketAddr| true;
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let shortest = HEADER_LEN + AEAD_TAG_LEN + dns.len() + 1;
        for pad_to in dns.len() + 1..=111 - HEADER_LEN - AEAD_TAG_LEN {
            let packet = build_query(&provider, dns, pad_to);
            assert!((shortest..=111).contains(&packet.len()));
            assert!(respond(&provider, &packet, src, true, &handler, &allow).is_none());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);

        let packet = build_query(&provider, dns, dns.len() + 1);
        respond(&provider, &packet, src, false, &handler, &allow);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the same packet decrypts over TCP"
        );
    }

    /// A listener on loopback that answers queries with the query itself, flagged as a response.
    fn spawn_listener(
        provider: Provider,
        allowed: impl Fn(SocketAddr) -> bool + Send + Sync + 'static,
        relay: Option<Arc<Relay>>,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicBool>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = stop.clone();
        std::thread::spawn(move || {
            serve(
                provider,
                socket,
                |query: Vec<u8>, _src, _budget| {
                    let mut answer = query;
                    answer[2] |= 0x80;
                    Some(answer)
                },
                allowed,
                |_src| false,
                relay,
                2,
                &worker_stop,
            )
        });
        (addr, stop)
    }

    #[test]
    /// The relay passes a sealed query on to an allowed target and its answer back; another target
    /// or a client the gate refuses gets nothing.
    fn the_listener_relays_anonymized_queries_to_allowed_targets() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let server = Provider::generate("2.dnscrypt-cert.server", 3_600);
        let cert = crate::client::Certificate::verify(
            &server.cert_bytes(),
            &server.provider_public_key(),
            crate::unix_now(),
        )
        .unwrap();
        let (server_addr, server_stop) = spawn_listener(server, |_src| true, None);
        let gate_open = Arc::new(AtomicBool::new(true));
        let gate = gate_open.clone();
        let (relay_addr, relay_stop) = spawn_listener(
            Provider::generate("2.dnscrypt-cert.relay", 3_600),
            move |_src| gate.load(Ordering::Relaxed),
            Some(Arc::new(Relay::new(move |target| target == server_addr))),
        );

        let session = crate::client::Session::new(&cert).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(700)))
            .unwrap();
        let ask_padded = |target: SocketAddr, len: usize| {
            let (sealed, nonce) = session.seal(
                b"\x00\x09\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01",
                len,
            );
            client
                .send_to(&relay::wrap(target, &sealed), relay_addr)
                .unwrap();
            let mut buf = [0u8; 4096];
            let (len, _) = client.recv_from(&mut buf).ok()?;
            session.open(&buf[..len], &nonce)
        };
        let ask = |target: SocketAddr| ask_padded(target, 512);

        let answer = ask(server_addr).expect("릴레이를 거친 응답");
        assert_eq!(&answer[..3], &[0x00, 0x09, 0x81]);
        assert!(
            ask_padded(server_addr, 4096).is_some(),
            "가장 큰 질의를 릴레이 머리와 함께 받지 못했습니다"
        );
        let elsewhere = SocketAddr::new(server_addr.ip(), server_addr.port().wrapping_add(1));
        assert!(
            ask(elsewhere).is_none(),
            "허용하지 않은 대상으로 보냈습니다"
        );
        gate_open.store(false, Ordering::Relaxed);
        assert!(ask(server_addr).is_none(), "막힌 클라이언트를 중계했습니다");

        server_stop.store(true, Ordering::Release);
        relay_stop.store(true, Ordering::Release);
    }

    #[test]
    /// The certificate lookup needs no encryption or authentication, answers with four times the
    /// query size and bypasses the pipeline, so it has to be gated here.
    fn the_certificate_lookup_answers_only_allowed_clients() {
        assert!(
            ask_for_cert(true, false),
            "허용된 클라이언트는 답을 받아야 합니다"
        );
        assert!(
            !ask_for_cert(false, false),
            "막힌 클라이언트에게 인증서를 내주면 안 됩니다"
        );
        assert!(
            !ask_for_cert(true, true),
            "주소로 버리는 클라이언트에게는 아무것도 보내면 안 됩니다"
        );
    }
}
