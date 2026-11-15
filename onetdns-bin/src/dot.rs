//! DoT listener: length-prefixed DNS messages over TLS. After the handshake, queries go through the
//! same handler and pipeline as other transports.
//!
//! Connection count and deadlines are capped; otherwise connections that start a handshake and then
//! do nothing could take every slot.

use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_proto::{Message, Writer};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
use onetdns_tls::{server_handshake, ServerConfig, TlsConnection, TlsError};

use crate::connection_limit::{
    poll_pending_encrypted_connections, spawn_bounded_connection_thread, wake_tcp_listener,
    AdmissionProtocol, ConnectionLimiter, ConnectionTracker, PendingEncryptedConnection,
    PrefixedTcp, ENCRYPTED_ACCEPT_BATCH,
};
use crate::native::NativeServer;
use crate::transport_observe;

/// Stops the listener and joins its threads when dropped.
pub struct DotListener {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Time for one handshake, or for one query and its answer; also the idle limit between queries. A
/// connection silent this long is idle and closed.
const DOT_IO_TIMEOUT: Duration = Duration::from_secs(30);

impl DotListener {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for DotListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_tcp_listener(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn serve_dot(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    admission: Arc<ConnectionLimiter>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<DotListener> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let tracker = ConnectionTracker::new();
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let listener_shutdown = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("dot-listener".into())
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
                                "dot",
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
                                AdmissionProtocol::Tls,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dot",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dot",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                            accepted = 1;
                        }
                        Err(error) => {
                            transport_observe::record_error("dot", "accept", None, error);
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }

                if !listener_nonblocking {
                    if let Err(error) = listener.set_nonblocking(true) {
                        transport_observe::record_error(
                            "dot",
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
                                AdmissionProtocol::Tls,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dot",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dot",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            transport_observe::record_error("dot", "accept", None, error);
                            break;
                        }
                    }
                }

                poll_pending_encrypted_connections(
                    &mut pending,
                    |stream, peer, guard| {
                        let tls = tls.clone();
                        let handler = handler.clone();
                        let connection_shutdown = listener_shutdown.clone();
                        let connection_stop = listener_stop.clone();
                        let activity = tracker.track();
                        match spawn_bounded_connection_thread("dot-connection", move || {
                            let _guards = (guard, activity);
                            let result = onetdns_core::isolation::catch_request(|| {
                                serve_conn(
                                    stream,
                                    &tls.load(),
                                    &handler,
                                    connection_shutdown.clone(),
                                    connection_stop.clone(),
                                    DOT_IO_TIMEOUT,
                                )
                            });
                            if let Ok(Err(error)) = result {
                                if !connection_shutdown.load(Ordering::Relaxed)
                                    && !connection_stop.load(Ordering::Relaxed)
                                {
                                    match error {
                                        ConnError::Tls(error) => transport_observe::record_error(
                                            "dot",
                                            "connection",
                                            Some(peer),
                                            error,
                                        ),
                                        ConnError::Dns(stage, detail) => {
                                            transport_observe::record_error(
                                                "dot",
                                                stage,
                                                Some(peer),
                                                detail,
                                            )
                                        }
                                    }
                                }
                            }
                        }) {
                            Ok(connection) => drop(connection),
                            Err(error) => transport_observe::record_error(
                                "dot",
                                "thread_spawn",
                                Some(peer),
                                error,
                            ),
                        }
                    },
                    |peer, error| {
                        transport_observe::record_error(
                            "dot",
                            "handshake_admission",
                            Some(peer),
                            error,
                        )
                    },
                );
                if !pending.is_empty() {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            drop(pending);
            tracker.wait_until_idle();
        })?;
    Ok(DotListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/// On a TLS failure, the TLS layer has already sent its alert. A broken DNS exchange is still fine
/// as TLS, so close_notify goes out before closing, as on a clean close.
enum ConnError {
    Tls(TlsError),
    /// Stage name for error counts, and the reason to log.
    Dns(&'static str, &'static str),
}

impl From<TlsError> for ConnError {
    fn from(error: TlsError) -> Self {
        ConnError::Tls(error)
    }
}

/// `io_timeout` bounds the handshake and each query, and is the idle limit between queries.
fn serve_conn(
    stream: PrefixedTcp,
    tls: &ServerConfig,
    handler: &NativeServer,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    io_timeout: Duration,
) -> Result<(), ConnError> {
    let src = stream.peer_addr().map_err(|_| TlsError::Io)?;

    let mut stream = DeadlineTcp::new(stream, Instant::now() + io_timeout)
        .stop_on(shutdown)
        .stop_on(stop);
    let mut conn = server_handshake(&mut stream, tls)?;
    let served = serve_queries(&mut conn, &mut stream, handler, src, io_timeout);
    send_close_notify_without_waiting(&mut conn, &mut stream.into_inner());
    served
}

/// Writes close_notify once, without waiting, before closing. RFC 8446 requires it from a side that
/// closes its writes without an error alert; without it, the client cannot tell this from a
/// truncated response. The TLS layer skips it after an alert or when records were not fully sent.
///
/// It is also sent when an idle deadline passes and when the listener stops, so it writes to a
/// socket without the deadline and stop signals, and does not wait, so shutdown is never delayed.
/// With a full send buffer, the connection closes without it.
fn send_close_notify_without_waiting(conn: &mut TlsConnection, socket: &mut PrefixedTcp) {
    if socket.set_nonblocking(true).is_ok() {
        let _ = conn.send_close_notify(socket);
    }
}

/// Ok when no query was lost: the peer closed between messages, the deadline passed with no next
/// query, or the handler chose not to answer. With ConnError::Dns, the TLS connection is still
/// sound.
fn serve_queries(
    conn: &mut TlsConnection,
    stream: &mut DeadlineTcp<PrefixedTcp>,
    handler: &NativeServer,
    src: SocketAddr,
    io_timeout: Duration,
) -> Result<(), ConnError> {
    let tls_authenticated = conn.client_authenticated();
    let tls_auth_identity = conn.client_auth_identity().map(|s| s.to_string());

    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut writer = Writer::new();
    let mut framed = Vec::with_capacity(2050);
    loop {
        stream.set_deadline(Instant::now() + io_timeout);
        let len_bytes = match read_n(conn, stream, &mut buf, 2) {
            Ok(bytes) => bytes,
            // Closed between length-prefixed messages, so no query was lost. Many clients close
            // without close_notify after their answer, so this is not an error.
            Err(TlsError::CloseNotify | TlsError::Eof) if buf.is_empty() => return Ok(()),
            // The deadline passed before the next query's first byte: an idle connection. Unlike
            // one that stalled mid-query, it lost nothing.
            Err(TlsError::Io) if buf.is_empty() && stream.idle_expired() => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if len < 12 {
            return Err(ConnError::Dns(
                "dns_short_message",
                "DNS message shorter than its header",
            ));
        }
        let msg_bytes = read_n(conn, stream, &mut buf, len)?;
        let request = match Message::parse(&msg_bytes) {
            Ok(m) => m,
            Err(error) => {
                transport_observe::record_error("dot", "dns_parse", Some(src), error);
                // An unreadable message still gets an answer, and the connection stays open. The
                // framing is the same as Do53 over TCP, so message boundaries are already known;
                // closing on one bad message would cost a pipelining client its connection and TLS
                // handshake.
                let ctx = RequestCtx {
                    src,
                    transport: RtTransport::DoT,
                    raw: Some(msg_bytes.as_slice()),
                    client_id: None,
                    authenticated: tls_authenticated,
                    auth_identity: tls_auth_identity.clone(),
                };
                if msg_bytes[2] & 0x80 == 0 {
                    if let Some(response) = handler.handle_unparsable(&msg_bytes, &ctx) {
                        writer.clear();
                        if response.try_encode_into(&mut writer).is_ok() {
                            if let Ok(n) = u16::try_from(writer.buf.len()) {
                                framed.clear();
                                framed.extend_from_slice(&n.to_be_bytes());
                                framed.extend_from_slice(&writer.buf);
                                conn.write_app(stream, &framed)?;
                            }
                        }
                    }
                }
                continue;
            }
        };
        if request.header.response {
            return Err(ConnError::Dns(
                "dns_response_as_query",
                "unsolicited DNS response",
            ));
        }
        let ctx = RequestCtx {
            src,
            transport: RtTransport::DoT,
            raw: Some(msg_bytes.as_slice()),
            client_id: None,
            authenticated: tls_authenticated,
            auth_identity: tls_auth_identity.clone(),
        };

        let mut write_error = None;
        let completed = handler.handle_stream(&request, &ctx, &mut |resp| {
            let result = (|| -> Result<(), ConnError> {
                writer.clear();
                resp.try_encode_into(&mut writer)
                    .map_err(|_| ConnError::Dns("dns_encode", "response could not be encoded"))?;
                let n = u16::try_from(writer.buf.len()).map_err(|_| {
                    ConnError::Dns("dns_encode", "response exceeds the 65535-byte frame")
                })?;
                framed.clear();
                framed.extend_from_slice(&n.to_be_bytes());
                framed.extend_from_slice(&writer.buf);
                conn.write_app(stream, &framed)?;
                Ok(())
            })();
            if let Err(error) = result {
                write_error = Some(error);
                return false;
            }
            true
        });
        if let Some(error) = write_error {
            return Err(error);
        }
        if !completed {
            // The handler chose not to answer. That is policy, not a transport error. The
            // connection is closed so the client does not wait out its deadline for an answer that
            // will never come.
            return Ok(());
        }
    }
}

fn read_n<S: Read + Write>(
    conn: &mut TlsConnection,
    stream: &mut S,
    buf: &mut Vec<u8>,
    n: usize,
) -> Result<Vec<u8>, TlsError> {
    while buf.len() < n {
        let pt = conn.read_app(stream)?;
        if pt.is_empty() {
            return Err(TlsError::Io);
        }
        buf.extend_from_slice(&pt);
    }
    let out = buf[..n].to_vec();
    buf.drain(..n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::UdpSocket;

    #[test]
    fn dropping_dot_listener_joins_idle_handshake() {
        let listener = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_tls())),
            native_handler(),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let client = TcpStream::connect(listener.addr()).unwrap();
        thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(client);
    }

    use onetdns_core::BlockResponse;
    use onetdns_filter::{build_from_str, SharedFilter};
    use onetdns_forward::Forwarder;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_security::IpAcl;
    use onetdns_tls::{client_handshake, ClientConfig};

    use crate::native::NativeBackend;

    fn mock_upstream() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        thread::spawn(move || {
            let mut b = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut b) {
                if let Ok(req) = Message::parse(&b[..n]) {
                    let mut m = Message::default();
                    m.header.id = req.header.id;
                    m.header.response = true;
                    m.header.recursion_available = true;
                    m.questions = req.questions.clone();
                    if let Some(q) = req.questions.first() {
                        m.answers.push(onetdns_proto::Record::new(
                            q.name.clone(),
                            60,
                            ApRData::A(std::net::Ipv4Addr::new(9, 9, 9, 9)),
                        ));
                    }
                    let _ = sock.send_to(&m.try_encode().unwrap(), from);
                }
            }
        });
        addr
    }

    fn native_handler() -> Arc<NativeServer> {
        native_handler_with(IpAcl::allow_all())
    }

    fn native_handler_with(acl: IpAcl) -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            Arc::new(acl),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    fn self_signed_tls() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        Arc::new(ServerConfig::from_pkcs8(cert_der, &key_der).expect("ECDSA P-256 서명자"))
    }

    fn dot_query(addr: SocketAddr, name: &str, qtype: RecordType) -> Message {
        let mut stream = TcpStream::connect(addr).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut stream, &cfg).expect("클라 핸드셰이크");

        let q = Message::query(0x4242, ApName::from_str(name).unwrap(), qtype);
        let body = q.try_encode().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
        framed.extend_from_slice(&body);
        conn.write_app(&mut stream, &framed).unwrap();

        let mut buf = Vec::new();
        let len_b = read_n(&mut conn, &mut stream, &mut buf, 2).unwrap();
        let len = u16::from_be_bytes([len_b[0], len_b[1]]) as usize;
        let msg_b = read_n(&mut conn, &mut stream, &mut buf, len).unwrap();
        let _ = stream.flush();
        Message::parse(&msg_b).unwrap()
    }

    #[test]
    /// close_notify is a normal close. Counting it as an error would log a warning per well-behaved
    /// client and bury the real errors.
    fn dot_clean_client_close_is_not_counted_as_an_error() {
        let handler = native_handler();
        let tls = self_signed_tls();
        let listener = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();

        let before = transport_observe::count("dot", "connection");

        let mut stream = TcpStream::connect(listener.addr()).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut stream, &cfg).expect("클라 핸드셰이크");

        let query = Message::query(
            0x4242,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let body = query.try_encode().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
        framed.extend_from_slice(&body);
        conn.write_app(&mut stream, &framed).unwrap();

        let mut buf = Vec::new();
        let len_bytes = read_n(&mut conn, &mut stream, &mut buf, 2).unwrap();
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        read_n(&mut conn, &mut stream, &mut buf, len).unwrap();

        conn.send_close_notify(&mut stream).unwrap();
        let _ = stream.flush();
        drop(stream);

        for _ in 0..100 {
            if transport_observe::count("dot", "connection") != before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            transport_observe::count("dot", "connection"),
            before,
            "정상 종료한 연결을 오류로 셌습니다"
        );
    }

    #[test]
    /// Common clients such as dig close this way.
    fn dot_eof_between_messages_is_not_counted_as_an_error() {
        let listener = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_tls())),
            native_handler(),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        let before = transport_observe::count("dot", "connection");

        let mut stream = TcpStream::connect(listener.addr()).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut stream, &cfg).expect("클라 핸드셰이크");
        let body = Message::query(
            0x4343,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        )
        .try_encode()
        .unwrap();
        let mut framed = (body.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        conn.write_app(&mut stream, &framed).unwrap();
        let mut buf = Vec::new();
        let len_bytes = read_n(&mut conn, &mut stream, &mut buf, 2).unwrap();
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        read_n(&mut conn, &mut stream, &mut buf, len).unwrap();

        stream.shutdown(std::net::Shutdown::Both).unwrap();
        drop(stream);

        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            transport_observe::count("dot", "connection"),
            before,
            "메시지 사이에서 끊긴 연결을 오류로 셌습니다"
        );
    }

    #[test]
    /// The connection is still sound as TLS; without close_notify the client could not tell this
    /// from a truncated response. The error counts against the DNS stage, not TLS.
    fn dot_dns_framing_error_closes_with_close_notify() {
        let listener = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_tls())),
            native_handler(),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        let before = transport_observe::count("dot", "dns_short_message");

        let mut stream = TcpStream::connect(listener.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        };
        let mut conn = client_handshake(&mut stream, &cfg).expect("클라 핸드셰이크");
        conn.write_app(&mut stream, &[0, 5]).unwrap();
        assert_eq!(
            conn.read_app(&mut stream),
            Err(TlsError::CloseNotify),
            "close_notify 없이 연결을 닫았습니다"
        );

        for _ in 0..100 {
            if transport_observe::count("dot", "dns_short_message") > before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            transport_observe::count("dot", "dns_short_message") > before,
            "헤더보다 짧은 메시지를 DNS 단계 오류로 세지 않았습니다"
        );
    }

    /// Skips certificate verification.
    fn client_config() -> ClientConfig {
        ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![],
            ..Default::default()
        }
    }

    fn framed_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let body = Message::query(0x4545, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut framed = (body.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    fn exchange(conn: &mut TlsConnection, client: &mut TcpStream) {
        conn.write_app(client, &framed_query("allowed.test", RecordType::A))
            .unwrap();
        let mut buf = Vec::new();
        let len_bytes = read_n(conn, client, &mut buf, 2).unwrap();
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        read_n(conn, client, &mut buf, len).unwrap();
    }

    /// Returns the client socket and a thread that yields serve_conn's result.
    fn served_connection(
        io_timeout: Duration,
        shutdown: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    ) -> (TcpStream, thread::JoinHandle<Result<(), ConnError>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let tls = self_signed_tls();
        let handler = native_handler();
        let serving = thread::spawn(move || {
            serve_conn(
                PrefixedTcp::new(server, Vec::new()),
                &tls,
                &handler,
                shutdown,
                stop,
                io_timeout,
            )
        });
        (client, serving)
    }

    /// An unset stop signal.
    fn calm() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    /// Closing an idle connection is normal. Without close_notify the client sees a dropped
    /// connection, and counting it as an error would let long-lived clients fill the error metrics.
    fn dot_idle_timeout_closes_with_close_notify() {
        let (mut client, serving) = served_connection(Duration::from_secs(2), calm(), calm());
        let mut conn = client_handshake(&mut client, &client_config()).expect("클라 핸드셰이크");
        exchange(&mut conn, &mut client);
        assert_eq!(
            conn.read_app(&mut client),
            Err(TlsError::CloseNotify),
            "쉬던 연결을 close_notify 없이 닫았습니다"
        );
        assert!(
            serving.join().unwrap().is_ok(),
            "쉬던 연결을 닫은 것을 오류로 돌려주었습니다"
        );
    }

    #[test]
    /// A connection that sent part of a length prefix or a TLS record is not idle, and neither is
    /// part of a next query already buffered from the same record as the previous one. Treating
    /// those as idle would hide lost queries.
    fn dot_stalled_query_ends_with_an_error() {
        let idle = Duration::from_secs(2);
        let (mut half_prefix, prefix_served) = served_connection(idle, calm(), calm());
        let mut conn =
            client_handshake(&mut half_prefix, &client_config()).expect("클라 핸드셰이크");
        conn.write_app(&mut half_prefix, &[0]).unwrap();

        let (mut half_record, record_served) = served_connection(idle, calm(), calm());
        client_handshake(&mut half_record, &client_config()).expect("클라 핸드셰이크");
        half_record.write_all(&[23, 3, 3]).unwrap();

        let (mut leftover, leftover_served) = served_connection(idle, calm(), calm());
        let mut leftover_conn =
            client_handshake(&mut leftover, &client_config()).expect("클라 핸드셰이크");
        let mut pipelined = framed_query("allowed.test", RecordType::A);
        pipelined.push(0);
        leftover_conn.write_app(&mut leftover, &pipelined).unwrap();

        assert!(
            prefix_served.join().unwrap().is_err(),
            "길이 프리픽스 일부만 온 연결을 쉬던 연결로 보았습니다"
        );
        assert!(
            record_served.join().unwrap().is_err(),
            "TLS 레코드 일부만 온 연결을 쉬던 연결로 보았습니다"
        );
        assert!(
            leftover_served.join().unwrap().is_err(),
            "앞 질의와 함께 받은 다음 질의 일부를 버리고 쉬던 연결로 보았습니다"
        );
    }

    #[test]
    /// A stop signal ends connections regardless of the idle limit, and they still get
    /// close_notify, so clients do not see them as cut off.
    fn dot_stop_closes_open_connections_with_close_notify() {
        for listener_stops in [true, false] {
            let (shutdown, stop) = (calm(), calm());
            let (mut client, serving) =
                served_connection(DOT_IO_TIMEOUT, shutdown.clone(), stop.clone());
            let mut conn =
                client_handshake(&mut client, &client_config()).expect("클라 핸드셰이크");
            exchange(&mut conn, &mut client);

            let started = Instant::now();
            let signal = if listener_stops { stop } else { shutdown };
            signal.store(true, Ordering::Release);
            assert_eq!(
                conn.read_app(&mut client),
                Err(TlsError::CloseNotify),
                "멈추는 연결을 close_notify 없이 닫았습니다"
            );
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "종료 신호를 받은 연결이 유휴 한도까지 남았습니다"
            );
            let _ = serving.join().unwrap();
        }
    }

    #[test]
    /// A client that never reads must not delay listener shutdown, not even by the socket's
    /// remaining write timeout.
    fn close_notify_does_not_wait_for_a_full_send_buffer() {
        let tls = self_signed_tls();
        let handshake = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = handshake.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            client_handshake(&mut stream, &client_config()).expect("클라 핸드셰이크");
        });
        let (mut stream, _) = handshake.accept().unwrap();
        let mut conn = server_handshake(&mut stream, &tls).expect("서버 핸드셰이크");
        client.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _silent_reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let chunk = [0u8; 64 * 1024];
        loop {
            match (&socket).write(&chunk) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("송신 버퍼를 채우지 못했습니다: {error}"),
            }
        }
        socket.set_nonblocking(false).unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();

        let started = Instant::now();
        send_close_notify_without_waiting(&mut conn, &mut PrefixedTcp::new(socket, Vec::new()));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "송신 버퍼가 찬 연결에서 close_notify 를 기다렸습니다"
        );
    }

    #[test]
    /// Not answering is policy. Counting it as a transport error would raise the metric whenever
    /// policy drops a query; for example, a server without zone transfers configured does not
    /// answer AXFR.
    fn dot_declined_query_closes_without_an_error() {
        let (mut client, serving) = served_connection(DOT_IO_TIMEOUT, calm(), calm());
        let mut conn = client_handshake(&mut client, &client_config()).expect("클라 핸드셰이크");
        conn.write_app(&mut client, &framed_query("zone.test", RecordType(252)))
            .unwrap();
        assert_eq!(
            conn.read_app(&mut client),
            Err(TlsError::CloseNotify),
            "답하지 않은 질의 뒤에 close_notify 없이 닫았습니다"
        );
        assert!(
            serving.join().unwrap().is_ok(),
            "답하지 않기로 한 질의를 오류로 돌려주었습니다"
        );
    }

    #[test]
    fn dot_allowed_query_resolves_over_self_tls() {
        let handler = native_handler();
        let tls = self_signed_tls();
        let l = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();

        let resp = dot_query(l.addr(), "allowed.test", RecordType::A);
        assert_eq!(resp.header.id, 0x4242);
        assert_eq!(resp.answers.len(), 1, "A 레코드 1개");
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    fn dot_blocked_query_returns_nxdomain_over_self_tls() {
        let handler = native_handler();
        let tls = self_signed_tls();
        let l = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();

        let resp = dot_query(l.addr(), "blocked.test", RecordType::A);
        assert_eq!(resp.header.rcode, onetdns_proto::ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }

    /// Counts bytes from the server while passing them through.
    struct Tally(TcpStream, usize);

    impl Read for Tally {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n;
            Ok(n)
        }
    }

    impl Write for Tally {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    /// Whether the handshake finished, and how many bytes the server sent.
    fn dot_handshake_under(acl: IpAcl) -> (bool, usize) {
        let listener = serve_dot(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(self_signed_tls())),
            native_handler_with(acl),
            Arc::new(ConnectionLimiter::default()),
            calm(),
        )
        .unwrap();
        let stream = TcpStream::connect(listener.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut tally = Tally(stream, 0);
        let finished = client_handshake(&mut tally, &client_config()).is_ok();
        (finished, tally.1)
    }

    #[test]
    /// A single ServerHello or alert would reveal a server at that address.
    fn dot_drops_listed_clients_before_the_handshake() {
        let (finished, received) = dot_handshake_under(IpAcl::allow_all());
        assert!(
            finished && received > 0,
            "대조군이 무효입니다. 허용한 주소와 핸드셰이크하지 못했습니다"
        );
        let (finished, received) =
            dot_handshake_under(IpAcl::allow_all().with_drop(vec!["127.0.0.0/8".parse().unwrap()]));
        assert!(!finished, "버리는 주소와 TLS 핸드셰이크를 마쳤습니다");
        assert_eq!(received, 0, "버리는 주소에 TLS 바이트를 보냈습니다");
    }
}
