/*!
 * @brief DoT 리스너.
 *
 * @details TLS 위에 길이 접두사가 붙은 DNS 메시지가 오간다. 핸드셰이크를 마치면 같은 핸들러로
 *          넘겨 다른 전송과 파이프라인을 공유한다.
 * @warning 연결 수와 데드라인에 상한이 있다. 없으면 핸드셰이크만 걸어 두고 아무것도 하지 않는
 *          연결로 슬롯을 다 차지할 수 있다.
 */

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

/** @brief DoT 리스너. 사라질 때 연결 스레드를 정리한다. */
pub struct DotListener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 루프를 실행하는 스레드. */
    thread: Option<std::thread::JoinHandle<()>>,
}

/**
 * @brief 핸드셰이크 하나, 또는 질의 하나를 받아 답하는 데 쓸 수 있는 시간.
 * @details 다음 질의를 기다리는 유휴 한도이기도 하다. 이 시간 동안 아무것도 보내지 않은 연결은
 *          쉬던 연결로 보고 닫는다.
 */
const DOT_IO_TIMEOUT: Duration = Duration::from_secs(30);

impl DotListener {
    /** @brief 이 리스너가 묶인 주소. */
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for DotListener {
    /** @brief 종료를 알리고 연결 스레드가 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_tcp_listener(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/** @brief 리스너를 열고 연결을 받는다. */
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

/**
 * @brief DoT 연결을 오류로 끝낸 사유.
 * @details TLS 계층이 실패했으면 보낼 경고는 그 계층이 이미 보냈다. DNS 교환이 어긋난 경우는
 *          TLS 로서는 정상이므로 정상 종료처럼 close_notify 를 보내고 닫는다.
 */
enum ConnError {
    /** @brief TLS 계층의 실패. */
    Tls(TlsError),
    /** @brief DNS 교환이 어긋났다. 오류 집계에 쓸 단계 이름과 기록할 사유를 담는다. */
    Dns(&'static str, &'static str),
}

impl From<TlsError> for ConnError {
    fn from(error: TlsError) -> Self {
        ConnError::Tls(error)
    }
}

/**
 * @brief 연결 하나에서 질의를 받아 처리한다.
 * @param io_timeout 핸드셰이크와 질의 하나에 쓸 수 있는 시간이자 질의 사이의 유휴 한도.
 */
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

/**
 * @brief 연결을 닫기 전에 close_notify 를 기다리지 않고 한 번만 써 본다.
 * @details RFC 8446 은 오류 경고 없이 쓰기를 닫는 쪽에 close_notify 를 요구한다. 없으면
 *          클라이언트는 응답이 중간에 잘린 것과 구분하지 못한다. 경고를 주고받았거나 레코드를 다
 *          보내지 못한 연결이면 TLS 계층이 보내지 않는다. 쉬던 연결의 데드라인이 지났을 때와
 *          리스너가 멈출 때도 보내야 하므로 데드라인과 종료 신호가 없는 소켓에 쓰고, 종료가
 *          늦어지지 않게 기다리지 않는다. 송신 버퍼가 차 있으면 보내지 못한 채 닫힌다.
 */
fn send_close_notify_without_waiting(conn: &mut TlsConnection, socket: &mut PrefixedTcp) {
    if socket.set_nonblocking(true).is_ok() {
        let _ = conn.send_close_notify(socket);
    }
}

/**
 * @brief 핸드셰이크를 마친 연결에서 질의를 받아 답한다.
 * @return 잃은 질의 없이 끝났으면 Ok. 상대가 메시지 사이에서 닫았거나, 다음 질의 없이
 *         데드라인이 지났거나, 처리기가 질의에 답하지 않기로 한 경우다. ConnError::Dns 를
 *         돌려줄 때 TLS 연결은 아직 정상이다.
 */
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
            /*
             * 길이 프리픽스로 경계가 정해진 DNS 메시지 사이에서 닫혔으면 잃은 질의가 없다.
             * 답을 받고 종료 알림 없이 소켓을 닫는 클라이언트가 흔해서 오류로 세지 않는다.
             */
            Err(TlsError::CloseNotify | TlsError::Eof) if buf.is_empty() => return Ok(()),
            /*
             * 다음 질의의 첫 바이트도 오지 않은 채 데드라인이 지났으면 쉬던 연결이다. 질의를
             * 보내다 멈춘 연결과 달리 잃은 질의가 없다.
             */
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
                /*
                 * 읽지 못해도 답을 주고 연결은 이어 간다. Do53 TCP 와 같은 길이 프리픽스
                 * 프레이밍이라 메시지 경계는 이미 정해져 있고, 하나가 깨졌다고 끊으면
                 * 질의를 이어 보내던 클라이언트가 연결과 TLS 핸드셰이크를 함께 잃는다.
                 */
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
            /*
             * 처리기가 답하지 않기로 한 질의다. 정책이 정한 결과이므로 전송 오류로 세지 않는다.
             * 답이 오지 않을 질의를 클라이언트가 데드라인까지 기다리지 않도록 연결은 닫는다.
             */
            return Ok(());
        }
    }
}

/** @brief 정해진 길이만큼 읽는다. 모자라면 오류다. */
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
/** @brief 데드라인 처리, 종료, 그리고 실제 TLS 위 질의 왕복. */
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::UdpSocket;

    #[test]
    /** @brief 핸드셰이크 중인 연결도 종료 때 정리되는지. */
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

    /** @brief 고정 응답을 내는 테스트용 업스트림. */
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

    /** @brief 테스트용 질의 핸들러. */
    fn native_handler() -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    /** @brief 테스트용 자체 서명 인증서 설정. */
    fn self_signed_tls() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        Arc::new(ServerConfig::from_pkcs8(cert_der, &key_der).expect("ECDSA P-256 서명자"))
    }

    /** @brief DoT로 질의 하나를 보내고 답을 받는다. */
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
    /**
     * @brief 클라이언트가 얌전히 끊은 것을 오류로 세지 않는지.
     * @details close_notify는 정상 종료다. 이것을 오류로 세면 예의 바른 클라이언트마다
     *          경고가 한 줄씩 남아 진짜 오류가 묻힌다.
     */
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
    /**
     * @brief 답을 받고 종료 알림 없이 끊은 클라이언트를 오류로 세지 않는지.
     * @details dig 같은 흔한 클라이언트가 이렇게 끊는다. 길이 프리픽스 사이에서 끊겼으면
     *          잃은 질의가 없다.
     */
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
    /**
     * @brief DNS 교환이 어긋나 연결을 닫을 때 close_notify 를 먼저 보내는지.
     * @details TLS 로서는 정상인 연결이다. close_notify 없이 닫으면 클라이언트는 응답이 중간에
     *          잘린 것과 구분하지 못한다. 오류는 TLS 실패가 아니라 DNS 단계로 센다.
     */
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

    /** @brief 인증서를 검증하지 않는 시험용 클라이언트 설정. */
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

    /** @brief 길이 프리픽스를 붙인 질의. */
    fn framed_query(name: &str, qtype: RecordType) -> Vec<u8> {
        let body = Message::query(0x4545, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut framed = (body.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    /** @brief 질의 하나를 보내고 답을 끝까지 읽는다. */
    fn exchange(conn: &mut TlsConnection, client: &mut TcpStream) {
        conn.write_app(client, &framed_query("allowed.test", RecordType::A))
            .unwrap();
        let mut buf = Vec::new();
        let len_bytes = read_n(conn, client, &mut buf, 2).unwrap();
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        read_n(conn, client, &mut buf, len).unwrap();
    }

    /**
     * @brief serve_conn 이 처리하는 연결 하나를 연다.
     * @return 클라이언트 쪽 소켓과, serve_conn 의 결과를 돌려줄 스레드.
     */
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

    /** @brief 서지 않은 종료 신호. */
    fn calm() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    /**
     * @brief 다음 질의 없이 유휴 한도가 지난 연결을 close_notify 로 닫고 오류로 끝내지 않는지.
     * @details 쉬던 연결을 닫는 것은 정상 동작이다. close_notify 가 없으면 클라이언트는 연결이
     *          도중에 끊긴 것으로 보고, 오류로 세면 연결을 오래 쓰는 클라이언트가 오류 지표를
     *          채운다.
     */
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
    /**
     * @brief 질의를 보내다 멈춘 연결은 데드라인이 지나면 오류로 끝나는지.
     * @details 길이 프리픽스 일부나 TLS 레코드 일부만 보낸 연결은 쉬던 연결이 아니다. 앞 질의와
     *          한 레코드에 실려 와 이미 받아 둔 다음 질의 일부도 같다. 쉬던 연결처럼 다루면 질의를
     *          잃은 것이 기록되지 않는다.
     */
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
    /**
     * @brief 리스너나 프로세스가 멈출 때 열린 연결에 close_notify 를 보내고 곧바로 닫는지.
     * @details 종료 신호를 받은 연결은 유휴 한도와 상관없이 끝나야 한다. 그때도 close_notify 를
     *          보내야 클라이언트가 연결이 잘린 것으로 보지 않는다.
     */
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
    /**
     * @brief 송신 버퍼가 찬 연결에서는 close_notify 를 기다리지 않고 포기하는지.
     * @details 답을 읽지 않는 클라이언트 하나 때문에 리스너 종료가 늦어지면 안 된다. 소켓에
     *          남아 있는 쓰기 제한 시간만큼도 기다리지 않아야 한다.
     */
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
    /**
     * @brief 처리기가 답하지 않기로 한 질의를 오류로 세지 않고 연결을 close_notify 로 닫는지.
     * @details 답하지 않는 것은 정책이 정한 결과다. 전송 오류로 세면 정책이 질의를 버릴 때마다
     *          오류 지표가 오른다. 영역 전송을 설정하지 않은 서버는 AXFR 에 답하지 않는다.
     */
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
    /** @brief 허용된 이름이 실제 TLS 위에서 해석되는지. */
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
    /** @brief 차단된 이름이 막히는지. */
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
}
