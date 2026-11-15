//! DNSCrypt listener, on UDP and TCP at the same address. Clients retry over TCP after a failure or
//! a truncated response, so UDP alone would break them.

use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onetdns_core::tcp::DeadlineTcp;
use onetdns_dnscrypt::Provider;
use onetdns_proto::{Message, Writer};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

use crate::connection_limit::{
    poll_pending_encrypted_connections, spawn_bounded_connection_thread, wake_tcp_listener,
    AdmissionProtocol, ConnectionLimiter, ConnectionTracker, PendingEncryptedConnection,
    PrefixedTcp, ENCRYPTED_ACCEPT_BATCH,
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

/// Serves DNSCrypt over UDP through the shared pipeline. A response larger than the query packet
/// allows is truncated with TC set, as Do53 does, and the client retries over TCP or with more
/// padding.
///
/// Certificate lookups bypass the pipeline, so access control and rate limits are applied here.
pub fn serve(
    handler: Arc<NativeServer>,
    socket: UdpSocket,
    provider: Provider,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let gate = make_gate(handler.clone());
    let h = make_handler(handler);
    onetdns_dnscrypt::server::serve(provider, socket, h, gate, &shutdown)
}

/// Stops the listener and joins its threads when dropped.
pub struct DnscryptTcpListener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DnscryptTcpListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_tcp_listener(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serves DNSCrypt over TCP, one transaction per connection as the spec requires.
///
/// A length prefix over the limit closes the connection unread; allocating what it says would let
/// any peer choose this server's memory use.
pub fn serve_tcp(
    addr: SocketAddr,
    handler: Arc<NativeServer>,
    provider: Provider,
    admission: Arc<ConnectionLimiter>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<DnscryptTcpListener> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let tracker = ConnectionTracker::new();
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let listener_shutdown = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("dnscrypt-tcp-listener".into())
        .spawn(move || {
            let mut pending = Vec::new();
            let mut listener_nonblocking = false;
            while !listener_shutdown.load(Ordering::Relaxed)
                && !listener_stop.load(Ordering::Relaxed)
            {
                let mut accepted = 0usize;
                if pending.is_empty() {
                    if listener_nonblocking {
                        if let Err(error) = listener.set_nonblocking(false) {
                            transport_observe::record_error(
                                "dnscrypt",
                                "set_listener_blocking",
                                None,
                                error,
                            );
                            break;
                        }
                        listener_nonblocking = false;
                    }
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            if listener_shutdown.load(Ordering::Relaxed)
                                || listener_stop.load(Ordering::Relaxed)
                            {
                                break;
                            }
                            if handler.drops_source(peer.ip()) {
                                continue;
                            }
                            match PendingEncryptedConnection::admit(
                                stream,
                                peer,
                                &admission,
                                AdmissionProtocol::Dnscrypt,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dnscrypt",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dnscrypt",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                            accepted = 1;
                        }
                        Err(error) => {
                            transport_observe::record_error("dnscrypt", "accept", None, error);
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }

                if !listener_nonblocking {
                    if let Err(error) = listener.set_nonblocking(true) {
                        transport_observe::record_error(
                            "dnscrypt",
                            "set_listener_nonblocking",
                            None,
                            error,
                        );
                        break;
                    }
                    listener_nonblocking = true;
                }
                while accepted < ENCRYPTED_ACCEPT_BATCH {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            accepted += 1;
                            if handler.drops_source(peer.ip()) {
                                continue;
                            }
                            match PendingEncryptedConnection::admit(
                                stream,
                                peer,
                                &admission,
                                AdmissionProtocol::Dnscrypt,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dnscrypt",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dnscrypt",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            transport_observe::record_error("dnscrypt", "accept", None, error);
                            break;
                        }
                    }
                }

                poll_pending_encrypted_connections(
                    &mut pending,
                    |stream, peer, guard| {
                        let provider = provider.clone();
                        let handler = handler.clone();
                        let connection_shutdown = listener_shutdown.clone();
                        let connection_stop = listener_stop.clone();
                        let activity = tracker.track();
                        let spawned =
                            spawn_bounded_connection_thread("dnscrypt-tcp-connection", move || {
                                let _guards = (guard, activity);
                                let result = onetdns_core::isolation::catch_request(|| {
                                    serve_conn(
                                        connection_io(stream, connection_shutdown, connection_stop),
                                        peer,
                                        &provider,
                                        &handler,
                                    )
                                });
                                if let Ok(Err(error)) = result {
                                    transport_observe::record_error(
                                        "dnscrypt",
                                        "connection",
                                        Some(peer),
                                        error,
                                    );
                                }
                            });
                        match spawned {
                            Ok(thread) => drop(thread),
                            Err(error) => transport_observe::record_error(
                                "dnscrypt",
                                "spawn",
                                Some(peer),
                                error,
                            ),
                        }
                    },
                    |peer, error| {
                        transport_observe::record_error(
                            "dnscrypt",
                            "frame_admission",
                            Some(peer),
                            error,
                        )
                    },
                );
                if !pending.is_empty() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            drop(pending);
            tracker.wait_until_idle();
        })?;
    Ok(DnscryptTcpListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/// Puts a connection under the I/O deadline and both stop signals: `shutdown` for the server,
/// `stop` for this listener.
fn connection_io(
    stream: PrefixedTcp,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> DeadlineTcp<PrefixedTcp> {
    DeadlineTcp::new(stream, std::time::Instant::now() + IO_TIMEOUT)
        .stop_on(shutdown)
        .stop_on(stop)
}

fn serve_conn(
    mut stream: DeadlineTcp<PrefixedTcp>,
    peer: SocketAddr,
    provider: &Provider,
    handler: &Arc<NativeServer>,
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
    let respond_to = make_handler(handler.clone());
    let Some(payload) =
        onetdns_dnscrypt::server::respond(provider, &packet, peer, false, &respond_to, &gate)
    else {
        return Ok(());
    };
    let Ok(prefix) = u16::try_from(payload.len()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt TCP response does not fit in the length prefix",
        ));
    };
    stream.write_all(&prefix.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// A partial frame must not hold shutdown until the I/O deadline.
    fn stalled_tcp_read_observes_listener_stop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut server = connection_io(
            PrefixedTcp::new(server, Vec::new()),
            Arc::new(AtomicBool::new(false)),
            stop.clone(),
        );
        let worker = std::thread::spawn(move || {
            let mut length = [0u8; 2];
            server.read_exact(&mut length).unwrap_err().kind()
        });

        std::thread::sleep(Duration::from_millis(20));
        let started = std::time::Instant::now();
        stop.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), io::ErrorKind::ConnectionAborted);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "리스너 종료가 DNSCrypt 30초 I/O 데드라인까지 지연됐습니다"
        );
        drop(client);
    }

    /// A listener with this ACL, and a certificate query to send it.
    fn certificate_listener(acl: onetdns_security::IpAcl) -> (DnscryptTcpListener, Vec<u8>) {
        let handler = Arc::new(NativeServer::new(
            Arc::new(onetdns_filter::SharedFilter::from_pointee(
                onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain),
            )),
            Arc::new(acl),
            vec![],
            Arc::new(crate::native::NativeBackend::Forward(
                onetdns_forward::Forwarder::new(
                    vec!["127.0.0.1:1".parse().unwrap()],
                    Duration::from_secs(1),
                ),
            )),
            60,
        ));
        let listener = serve_tcp(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Provider::generate("2.dnscrypt-cert.onetdns", 86400),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
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
        let mut stream = TcpStream::connect(listener.addr).expect("연결");
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
        let mut stream = TcpStream::connect(listener.addr).expect("연결");
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
}
