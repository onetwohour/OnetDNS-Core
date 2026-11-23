//! DNSCrypt listener, on UDP and TCP at the same address. Clients retry over TCP after a failure or
//! a truncated response, so UDP alone would break them.

use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::tcp::DeadlineTcp;
use onetdns_dnscrypt::relay::{self, Relay};
use onetdns_dnscrypt::Provider;
use onetdns_proto::{Message, Writer};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

use crate::connection_limit::{
    spawn_bounded_connection_thread, AdmissionProtocol, AdmittedConnection, ConnectionLimiter,
    EncryptedTcpListener, PrefixedTcp,
};
use crate::native::NativeServer;
use crate::transport_observe;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn make_handler(
    handler: Arc<NativeServer>,
) -> impl Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>> {
    move |dns_query: Vec<u8>, src: SocketAddr, budget: usize| {
        let request = Message::parse(&dns_query).ok()?;
        if request.header.response {
            return None;
        }
        let ctx = RequestCtx {
            src,
            transport: RtTransport::DnsCrypt,
            raw: Some(dns_query.as_slice()),
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let response = handler.handle(&request, &ctx)?;
        let mut writer = Writer::new();
        onetdns_runtime::encode_within(&request, &response, &mut writer, budget);
        writer.finish().ok()
    }
}

/// Whether a source address may be answered.
fn make_gate(handler: Arc<NativeServer>) -> impl Fn(SocketAddr) -> bool {
    move |src: SocketAddr| {
        handler.client_allowed(&RequestCtx {
            src,
            transport: RtTransport::DnsCrypt,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        })
    }
}

/// None when relaying is off. A relayed query goes only to an allowed port, and only to a public
/// address that is not one of this server's listeners unless an allowed network names it.
pub(crate) fn relay(cfg: &Config) -> Option<Arc<Relay>> {
    if !cfg.dnscrypt_relay {
        return None;
    }
    let ports = cfg.dnscrypt_relay_ports.clone();
    let allowed = cfg.dnscrypt_relay_allow_targets.clone();
    let listeners = crate::dns_listeners(cfg);
    Some(Arc::new(Relay::new(move |target: SocketAddr| {
        ports.contains(&target.port())
            && (allowed.iter().any(|net| net.contains(&target.ip()))
                || onetdns_core::is_globally_routable(target.ip())
                    && !crate::upstream::points_at_listener(target, &listeners))
    })))
}

/// Serves DNSCrypt over UDP through the shared pipeline. A response larger than the query packet
/// allows is truncated with TC set, as Do53 does, and the client retries over TCP or with more
/// padding.
///
/// Certificate lookups and relayed queries bypass the pipeline, so access control and rate limits
/// are applied here.
pub fn serve(
    handler: Arc<NativeServer>,
    socket: UdpSocket,
    provider: Provider,
    relay: Option<Arc<Relay>>,
    workers: usize,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let gate = make_gate(handler.clone());
    let drops = {
        let handler = handler.clone();
        move |src: SocketAddr| handler.drops_source(src.ip())
    };
    let h = make_handler(handler);
    onetdns_dnscrypt::server::serve(provider, socket, h, gate, drops, relay, workers, &shutdown)
}

/// Serves DNSCrypt over TCP on `listener`, already bound, one transaction per connection as the
/// spec requires.
///
/// A length prefix over the limit closes the connection unread; allocating what it says would let
/// any peer choose this server's memory use.
pub fn serve_tcp(
    listener: TcpListener,
    handler: Arc<NativeServer>,
    provider: Provider,
    relay: Option<Arc<Relay>>,
    admission: Arc<ConnectionLimiter>,
) -> io::Result<EncryptedTcpListener> {
    let drops = handler.clone();
    EncryptedTcpListener::spawn(
        listener,
        "dnscrypt",
        AdmissionProtocol::Dnscrypt,
        admission,
        move |source| drops.drops_source(source),
        None,
        move |connection: AdmittedConnection| {
            let peer = connection.peer;
            let provider = provider.clone();
            let handler = handler.clone();
            let relay = relay.clone();
            let spawned = spawn_bounded_connection_thread("dnscrypt-tcp-connection", move || {
                let AdmittedConnection {
                    stream,
                    signals,
                    hold: _hold,
                    ..
                } = connection;
                let result = onetdns_core::isolation::catch_request(|| {
                    serve_conn(
                        signals.watch(DeadlineTcp::new(
                            stream,
                            std::time::Instant::now() + IO_TIMEOUT,
                        )),
                        peer,
                        &provider,
                        &handler,
                        relay.as_deref(),
                    )
                });
                if let Ok(Err(error)) = result {
                    transport_observe::record_error("dnscrypt", "connection", Some(peer), error);
                }
            });
            match spawned {
                Ok(thread) => drop(thread),
                Err(error) => {
                    transport_observe::record_error("dnscrypt", "spawn", Some(peer), error)
                }
            }
        },
    )
}

/// A relayed query is sent on over UDP, as relays always do, and waited for here.
fn serve_conn(
    mut stream: DeadlineTcp<PrefixedTcp>,
    peer: SocketAddr,
    provider: &Provider,
    handler: &Arc<NativeServer>,
    relay: Option<&Relay>,
) -> io::Result<()> {
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes)?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len == 0 || len > onetdns_dnscrypt::server::MAX_TCP_QUERY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt TCP query length is out of range",
        ));
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet)?;

    let gate = make_gate(handler.clone());
    if let Some(relay) = relay.filter(|_| relay::is_anonymized(&packet)) {
        return match relay.accept(&packet).filter(|_| gate(peer)) {
            Some(forward) => match forward.exchange() {
                Some(answer) => write_framed(&mut stream, &answer),
                None => Ok(()),
            },
            None => Ok(()),
        };
    }
    let respond_to = make_handler(handler.clone());
    let Some(payload) =
        onetdns_dnscrypt::server::respond(provider, &packet, peer, false, &respond_to, &gate)
    else {
        return Ok(());
    };
    write_framed(&mut stream, &payload)
}

fn write_framed(stream: &mut DeadlineTcp<PrefixedTcp>, payload: &[u8]) -> io::Result<()> {
    let Ok(prefix) = u16::try_from(payload.len()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt TCP response does not fit in the length prefix",
        ));
    };
    stream.write_all(&prefix.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Whether the relay built from `settings` passes a sealed-looking packet on to `target`.
    fn relays_to(settings: &str, target: &str) -> bool {
        let cfg = Config::from_toml_str(&format!("dnscrypt_relay = true\n{settings}")).unwrap();
        let packet = relay::wrap(target.parse().unwrap(), &[0x42; 256]);
        relay(&cfg).unwrap().accept(&packet).is_some()
    }

    #[test]
    /// A relay is an open path to whatever address a stranger names, so by default it reaches
    /// only public servers on port 443 other than this one.
    fn the_relay_reaches_only_public_servers_on_allowed_ports() {
        assert!(
            relay(&Config::default()).is_none(),
            "기본값은 꺼져 있어야 합니다"
        );
        assert!(relays_to("", "8.8.8.8:443"));
        assert!(relays_to("", "[2606:4700::1111]:443"));
        assert!(!relays_to("", "8.8.8.8:53"), "허용하지 않은 포트");
        assert!(relays_to("dnscrypt_relay_ports = [5443]", "8.8.8.8:5443"));
        for internal in [
            "127.0.0.1:443",
            "192.168.1.5:443",
            "[::1]:443",
            "[fd00::1]:443",
        ] {
            assert!(!relays_to("", internal), "{internal}");
        }
        assert!(
            !relays_to("listen_dnscrypt = [\"8.8.4.4:443\"]", "8.8.4.4:443"),
            "자기 자신"
        );
        assert!(
            !relays_to("listen = [\"8.8.4.4:443\"]", "8.8.4.4:443"),
            "자기 Do53"
        );
        let allowed = "dnscrypt_relay_allow_targets = [\"127.0.0.0/8\", \"8.8.4.4\"]";
        assert!(relays_to(allowed, "127.0.0.1:443"));
        assert!(
            !relays_to(allowed, "127.0.0.1:53"),
            "허용 대상도 포트는 지켜야 합니다"
        );
        assert!(relays_to(
            &format!("{allowed}\nlisten_dnscrypt = [\"8.8.4.4:443\"]"),
            "8.8.4.4:443"
        ));
    }

    #[test]
    /// A partial frame must not hold shutdown until the I/O deadline.
    fn stalled_tcp_read_observes_listener_stop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let signals = crate::connection_limit::ConnectionSignals::default();
        let mut server = signals.watch(DeadlineTcp::new(
            PrefixedTcp::new(server, Vec::new()),
            std::time::Instant::now() + IO_TIMEOUT,
        ));
        let worker = std::thread::spawn(move || {
            let mut length = [0u8; 2];
            server.read_exact(&mut length).unwrap_err().kind()
        });

        std::thread::sleep(Duration::from_millis(20));
        let started = std::time::Instant::now();
        signals.stop.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), io::ErrorKind::ConnectionAborted);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "리스너 종료가 DNSCrypt 30초 I/O 데드라인까지 지연됐습니다"
        );
        drop(client);
    }

    fn native_handler(acl: onetdns_security::IpAcl, upstream: SocketAddr) -> Arc<NativeServer> {
        Arc::new(NativeServer::new(
            Arc::new(onetdns_filter::SharedFilter::from_pointee(
                onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain),
            )),
            Arc::new(acl),
            vec![],
            Arc::new(crate::native::NativeBackend::Forward(
                onetdns_forward::Forwarder::new(vec![upstream], Duration::from_secs(1)),
            )),
            60,
        ))
    }

    /// A listener with this ACL, and a certificate query to send it.
    fn certificate_listener(
        acl: onetdns_security::IpAcl,
    ) -> (crate::connection_limit::EncryptedTcpListener, Vec<u8>) {
        let listener = serve_tcp(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            native_handler(acl, "127.0.0.1:1".parse().unwrap()),
            Provider::generate("2.dnscrypt-cert.onetdns", 86400),
            None,
            Arc::new(ConnectionLimiter::default()),
        )
        .expect("TCP 리스너");

        let mut question = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in "2.dnscrypt-cert.onetdns".split('.') {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.extend_from_slice(&[0, 0, 16, 0, 1]);
        (listener, question)
    }

    #[test]
    /// Clients need the certificate before they can send an encrypted query, so without this every
    /// TCP client fails.
    fn tcp_listener_answers_a_certificate_lookup_and_closes() {
        let (listener, question) = certificate_listener(onetdns_security::IpAcl::allow_all());
        let mut stream = TcpStream::connect(listener.addr()).expect("연결");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("수신 제한 시간");
        let mut framed = (question.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&question);
        stream.write_all(&framed).expect("질의 전송");

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).expect("응답 길이");
        let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).expect("응답 본문");
        assert_eq!(
            &response[..2],
            &question[..2],
            "응답이 질의 ID를 되울립니다"
        );
        assert!(
            response.windows(4).any(|window| window == b"DNSC"),
            "TXT 레코드에 인증서가 실려 있지 않습니다"
        );

        let mut extra = [0u8; 1];
        assert_eq!(
            stream.read(&mut extra).expect("연결 종료 확인"),
            0,
            "거래 하나를 마친 뒤에도 연결이 열려 있습니다"
        );
    }

    #[test]
    /// Even a certificate response shows that a DNSCrypt server is at this address.
    fn tcp_listener_sends_nothing_to_dropped_clients() {
        let (listener, question) = certificate_listener(
            onetdns_security::IpAcl::allow_all().with_drop(vec!["127.0.0.0/8".parse().unwrap()]),
        );
        let mut stream = TcpStream::connect(listener.addr()).expect("연결");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("수신 제한 시간");
        let mut framed = (question.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&question);
        // The server may already have closed; only what was received matters.
        let _ = stream.write_all(&framed);
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        assert!(received.is_empty(), "버리는 주소에 인증서를 보냈습니다");
    }

    /// A plain DNS server answering every query with `answers` A records.
    fn many_answers_upstream(answers: u8) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((len, from)) = socket.recv_from(&mut buf) {
                let Ok(mut answer) = Message::parse(&buf[..len]) else {
                    continue;
                };
                answer.header.response = true;
                answer.additionals.clear();
                let name = answer.questions[0].name.clone();
                for index in 0..answers {
                    answer.answers.push(onetdns_proto::Record::new(
                        name.clone(),
                        60,
                        onetdns_proto::RData::A(std::net::Ipv4Addr::new(192, 0, 2, index)),
                    ));
                }
                let _ = socket.send_to(&answer.try_encode().unwrap(), from);
            }
        });
        addr
    }

    #[test]
    /// The relay in front is another OnetDNS listener, so this covers both ends. The answer does
    /// not fit the first UDP query, so the client asks the relay again over TCP and the relay still
    /// passes it on over UDP.
    fn a_query_through_a_relay_is_answered_by_the_listener() {
        let stop = Arc::new(AtomicBool::new(false));
        let handler = native_handler(
            onetdns_security::IpAcl::allow_all(),
            many_answers_upstream(40),
        );
        let provider = Provider::generate("2.dnscrypt-cert.onetdns", 86_400);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let (server_provider, server_handler, server_stop) =
            (provider.clone(), handler.clone(), stop.clone());
        std::thread::spawn(move || {
            serve(
                server_handler,
                server,
                server_provider,
                None,
                2,
                server_stop,
            )
        });

        let cfg = Config::from_toml_str(&format!(
            "dnscrypt_relay = true\n\
             dnscrypt_relay_ports = [{}]\n\
             dnscrypt_relay_allow_targets = [\"127.0.0.0/8\"]\n",
            server_addr.port()
        ))
        .unwrap();
        // TCP first, as Windows reserves TCP port ranges that UDP may still be given.
        let mut taken = Vec::new();
        let (relay_tcp, relay_udp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            match UdpSocket::bind(tcp.local_addr().unwrap()) {
                Ok(udp) => break (tcp, udp),
                Err(_) => taken.push(tcp),
            }
        };
        let relay_addr = relay_udp.local_addr().unwrap();
        let relay_provider = Provider::generate("2.dnscrypt-cert.relay", 86_400);
        let _relay_tcp = serve_tcp(
            relay_tcp,
            handler.clone(),
            relay_provider.clone(),
            relay(&cfg),
            Arc::new(ConnectionLimiter::default()),
        )
        .expect("릴레이 TCP 리스너");
        let (relay_handler, relay_stop) = (handler.clone(), stop.clone());
        std::thread::spawn(move || {
            serve(
                relay_handler,
                relay_udp,
                relay_provider,
                relay(&cfg),
                2,
                relay_stop,
            )
        });

        let client = onetdns_forward::Forwarder::with_upstreams(
            vec![onetdns_forward::Upstream::dnscrypt(
                server_addr,
                "2.dnscrypt-cert.onetdns",
                provider.provider_public_key(),
                Some(relay_addr),
            )],
            Duration::from_secs(3),
        );
        let query = Message::query(
            0x5151,
            onetdns_proto::Name::from_str("many.test").unwrap(),
            onetdns_proto::RecordType::A,
        );
        let response = client.resolve(&query);
        stop.store(true, Ordering::Release);
        let response = response.expect("릴레이를 거친 응답");
        assert_eq!(response.header.id, 0x5151);
        assert!(!response.header.truncated);
        assert_eq!(response.answers.len(), 40);
    }

    /// Answers every query after `delay`, each on its own thread.
    fn slow_upstream(delay: Duration) -> SocketAddr {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((len, from)) = socket.recv_from(&mut buf) {
                let Ok(mut answer) = Message::parse(&buf[..len]) else {
                    continue;
                };
                let socket = socket.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    answer.header.response = true;
                    answer.additionals.clear();
                    let _ = socket.send_to(&answer.try_encode().unwrap(), from);
                });
            }
        });
        addr
    }

    #[test]
    fn a_slow_upstream_answer_does_not_hold_up_other_queries() {
        const DELAY: Duration = Duration::from_millis(200);
        const CLIENTS: u16 = 8;
        let stop = Arc::new(AtomicBool::new(false));
        let handler = native_handler(onetdns_security::IpAcl::allow_all(), slow_upstream(DELAY));
        let provider = Provider::generate("2.dnscrypt-cert.onetdns", 86_400);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let (server_provider, server_stop) = (provider.clone(), stop.clone());
        std::thread::spawn(move || {
            serve(
                handler,
                server,
                server_provider,
                None,
                usize::from(CLIENTS),
                server_stop,
            )
        });

        let key = provider.provider_public_key();
        let started = std::time::Instant::now();
        let clients: Vec<_> = (0..CLIENTS)
            .map(|index| {
                std::thread::spawn(move || {
                    let client = onetdns_forward::Forwarder::with_upstreams(
                        vec![onetdns_forward::Upstream::dnscrypt(
                            addr,
                            "2.dnscrypt-cert.onetdns",
                            key,
                            None,
                        )],
                        Duration::from_secs(5),
                    );
                    let query = Message::query(
                        index,
                        onetdns_proto::Name::from_str(&format!("slow{index}.test")).unwrap(),
                        onetdns_proto::RecordType::A,
                    );
                    client.resolve(&query).is_ok()
                })
            })
            .collect();
        let answered = clients
            .into_iter()
            .filter_map(|client| client.join().ok())
            .filter(|answered| *answered)
            .count();
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Release);
        assert_eq!(answered, usize::from(CLIENTS));
        assert!(
            elapsed < DELAY * 4,
            "업스트림을 기다리는 질의 {CLIENTS}개가 차례로 처리됐습니다: {elapsed:?}"
        );
    }
}
