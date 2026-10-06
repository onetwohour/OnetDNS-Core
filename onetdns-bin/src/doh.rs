/*!
 * @brief DoH 리스너.
 *
 * @details TLS 위 HTTP/2로 DNS 메시지를 주고받는다. 상대가 HTTP/2를 협상하지 못하면
 *          1.1로 전환한다.
 * @note 경로에 클라이언트 식별자를 담을 수 있다. 다만 그것은 인증된 연결에서만 신뢰한다.
 *       평문 경로에 적힌 값은 누구나 지어낼 수 있다.
 */

use std::io;
#[cfg(test)]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_proto::Message;
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
use onetdns_tls::{server_handshake, ServerConfig, TlsStream};

use crate::connection_limit::{
    poll_pending_encrypted_connections, spawn_bounded_connection_thread, wake_tcp_listener,
    AdmissionProtocol, ConnectionLimiter, ConnectionTracker, PendingEncryptedConnection,
    PrefixedTcp, ENCRYPTED_ACCEPT_BATCH,
};
use crate::native::NativeServer;
use crate::transport_observe;

/** @brief DoH 리스너. 사라질 때 연결 스레드를 정리한다. */
pub struct DohListener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 루프를 실행하는 스레드. */
    thread: Option<std::thread::JoinHandle<()>>,
}

/** @brief 연결 하나의 입출력 데드라인. */
const DOH_IO_TIMEOUT: Duration = Duration::from_secs(30);

impl DohListener {
    /** @brief 이 리스너가 묶인 주소. */
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for DohListener {
    /** @brief 종료를 알리고 연결 스레드가 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_tcp_listener(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/**
 * @brief 이 응답을 HTTP 캐시가 얼마나 신선하다고 볼지.
 *
 * @details RFC 8484는 그 시간이 답변부 최소 TTL을 넘지 못하게 하고, 답변부가 비고
 *          권한부에 SOA가 있으면 그 MINIMUM을 넘지 못하게 한다. 둘 다 없으면 0을 준다.
 *          명시하지 않으면 중간 캐시가 스스로 어림잡아 TTL보다 오래 가지고 있을 수 있다.
 * @param msg 내보낼 응답.
 * @return max-age에 담을 초.
 */
pub(crate) fn http_freshness_secs(msg: &Message) -> u32 {
    if let Some(ttl) = msg.answers.iter().map(|record| record.ttl).min() {
        return ttl;
    }
    msg.authorities
        .iter()
        .filter_map(|record| match &record.rdata {
            onetdns_proto::RData::Soa(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
        .unwrap_or(0)
}

/** @brief 리스너를 열고 연결을 받는다. */
pub fn serve_doh(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    path: String,
    admission: Arc<ConnectionLimiter>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> io::Result<DohListener> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let path = Arc::new(path);
    let tracker = ConnectionTracker::new();
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let listener_shutdown = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("doh-listener".into())
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
                                "doh",
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
                                    "doh",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "doh",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                            accepted = 1;
                        }
                        Err(error) => {
                            transport_observe::record_error("doh", "accept", None, error);
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }

                if !listener_nonblocking {
                    if let Err(error) = listener.set_nonblocking(true) {
                        transport_observe::record_error(
                            "doh",
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
                                    "doh",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "doh",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            transport_observe::record_error("doh", "accept", None, error);
                            break;
                        }
                    }
                }

                poll_pending_encrypted_connections(
                    &mut pending,
                    |stream, peer, guard| {
                        let tls = tls.clone();
                        let handler = handler.clone();
                        let path = path.clone();
                        let connection_shutdown = listener_shutdown.clone();
                        let connection_stop = listener_stop.clone();
                        let activity = tracker.track();
                        match spawn_bounded_connection_thread("doh-connection", move || {
                            let _guards = (guard, activity);
                            let result = onetdns_core::isolation::catch_request(|| {
                                serve_conn(
                                    stream,
                                    &tls.load(),
                                    &handler,
                                    &path,
                                    connection_shutdown.clone(),
                                    connection_stop.clone(),
                                )
                            });
                            if let Ok(Err(stage)) = result {
                                if !connection_shutdown.load(Ordering::Relaxed)
                                    && !connection_stop.load(Ordering::Relaxed)
                                {
                                    transport_observe::record_error(
                                        "doh",
                                        stage,
                                        Some(peer),
                                        stage,
                                    );
                                }
                            }
                        }) {
                            Ok(connection) => drop(connection),
                            Err(error) => transport_observe::record_error(
                                "doh",
                                "thread_spawn",
                                Some(peer),
                                error,
                            ),
                        }
                    },
                    |peer, error| {
                        transport_observe::record_error(
                            "doh",
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
    Ok(DohListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/**
 * @brief 경로에 담긴 클라이언트 식별자를 신뢰할지 정한다.
 * @warning 인증된 연결에서만 받아들인다. 그러지 않으면 아무나 경로에 남의 식별자를
 *          적어 그 클라이언트의 정책을 가져갈 수 있다.
 */
pub(crate) fn authenticated_path_identity(
    path_identity: Option<&str>,
    authenticated: bool,
    auth_identity: Option<&str>,
) -> Result<Option<String>, ()> {
    if !authenticated {
        return Ok(None);
    }
    let Some(auth_identity) = auth_identity else {
        return Ok(None);
    };
    if let Some(path_identity) = path_identity {
        if path_identity != auth_identity {
            return Err(());
        }
    }
    Ok(Some(auth_identity.to_string()))
}

/** @brief 연결 하나에서 HTTP 요청을 받아 처리한다. */
fn serve_conn(
    tcp: PrefixedTcp,
    tls: &ServerConfig,
    handler: &NativeServer,
    path: &str,
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), &'static str> {
    let src = tcp.peer_addr().map_err(|_| "peer_addr")?;
    let mut tcp = DeadlineTcp::new(tcp, Instant::now() + DOH_IO_TIMEOUT)
        .stop_on(shutdown)
        .stop_on(stop);
    let conn = server_handshake(&mut tcp, tls).map_err(|_| "tls_handshake")?;

    let alpn = conn.alpn().map(|a| a.to_vec());
    let tls_authenticated = conn.client_authenticated();
    let tls_auth_identity = conn.client_auth_identity().map(|s| s.to_string());
    let mut stream = TlsStream::new(conn, tcp);

    // 실패는 HTTP 상태로 알린다. 읽지 못한 본문은 요청 잘못이므로 4xx 여야 한다.
    // 5xx 는 서버 잘못이라는 뜻이라 클라이언트가 같은 서버에 다시 보낸다.
    let dns = |q: &[u8],
               path_client_id: Option<&str>|
     -> Result<onetdns_http2::DohAnswer, &'static str> {
        let request = match Message::parse(q) {
            Ok(request) => request,
            Err(error) => {
                transport_observe::record_error("doh", "dns_parse", Some(src), error);
                return Err("400");
            }
        };
        if request.header.response {
            transport_observe::record_error(
                "doh",
                "dns_response_as_query",
                Some(src),
                "unsolicited DNS response",
            );
            return Err("400");
        }
        let client_id = match authenticated_path_identity(
            path_client_id,
            tls_authenticated,
            tls_auth_identity.as_deref(),
        ) {
            Ok(identity) => identity,
            Err(()) => {
                transport_observe::record_error(
                    "doh",
                    "client_identity_mismatch",
                    Some(src),
                    "path identity does not match authenticated identity",
                );
                onetdns_core::warn!(event = "doh.client_id_mismatch",
                    peer = %src,
                    path_identity = path_client_id.unwrap_or(""),
                    auth_identity = tls_auth_identity.as_deref().unwrap_or(""),
                    "Client ID in the DoH URL does not match the client ID in the mTLS certificate"
                );
                return Err("403");
            }
        };
        let ctx = RequestCtx {
            src,
            transport: RtTransport::DoH,
            raw: Some(q),
            client_id,
            authenticated: tls_authenticated,
            auth_identity: tls_auth_identity.clone(),
        };
        let response = handler.handle(&request, &ctx).ok_or("502")?;
        let max_age = http_freshness_secs(&response);
        Ok(onetdns_http2::DohAnswer {
            body: response.try_encode().map_err(|_| "502")?,
            max_age,
        })
    };

    match alpn.as_deref() {
        Some(b"h2") => {
            onetdns_http2::serve_doh_with_deadline_reset(&mut stream, path, dns, |stream| {
                stream
                    .inner_mut()
                    .set_deadline(Instant::now() + DOH_IO_TIMEOUT)
            })
            .map_err(|_| "http2_connection")
        }

        _ => onetdns_http2::serve_doh_h1_with_deadline_reset(&mut stream, path, dns, |stream| {
            stream
                .inner_mut()
                .set_deadline(Instant::now() + DOH_IO_TIMEOUT)
        })
        .map_err(|_| "http1_connection"),
    }
}

#[cfg(test)]
/** @brief 데드라인 처리, 경로 식별자의 인증 요구, 그리고 두 HTTP 버전의 왕복. */
mod tests {
    use super::*;

    /** @brief 테스트용 SOA. */
    fn soa(minimum: u32) -> onetdns_proto::RData {
        onetdns_proto::RData::Soa(Box::new(onetdns_proto::Soa {
            mname: onetdns_proto::Name::from_str("ns.example.com").unwrap(),
            rname: onetdns_proto::Name::from_str("hostmaster.example.com").unwrap(),
            serial: 1,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum,
        }))
    }

    #[test]
    /**
     * @brief HTTP 캐시 유효 기간이 RFC 8484의 상한을 넘지 않는지.
     * @details 답변부가 있으면 그 최소 TTL, 없고 SOA가 있으면 MINIMUM, 둘 다 없으면 0이다.
     */
    fn http_freshness_never_outlives_the_dns_answer() {
        let name = onetdns_proto::Name::from_str("host.example.com").unwrap();

        let mut positive = Message::default();
        positive.answers.push(onetdns_proto::Record::new(
            name.clone(),
            900,
            onetdns_proto::RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        ));
        positive.answers.push(onetdns_proto::Record::new(
            name.clone(),
            120,
            onetdns_proto::RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2)),
        ));
        assert_eq!(http_freshness_secs(&positive), 120, "답변부 최소 TTL");

        let mut negative = Message::default();
        negative
            .authorities
            .push(onetdns_proto::Record::new(name.clone(), 3600, soa(300)));
        assert_eq!(
            http_freshness_secs(&negative),
            300,
            "SOA MINIMUM을 넘지 못한다"
        );

        let mut shorter_soa_ttl = Message::default();
        shorter_soa_ttl
            .authorities
            .push(onetdns_proto::Record::new(name, 60, soa(300)));
        assert_eq!(http_freshness_secs(&shorter_soa_ttl), 60);

        assert_eq!(
            http_freshness_secs(&Message::default()),
            0,
            "근거가 없으면 신선하다고 말하지 않는다"
        );
    }
    use std::io::{Read, Write};
    use std::net::UdpSocket;

    #[test]
    /** @brief 핸드셰이크 중인 연결도 종료 때 정리되는지. */
    fn dropping_doh_listener_joins_idle_handshake() {
        let (tls, _) = self_signed();
        let listener = serve_doh(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            native_handler(),
            "/dns-query".to_string(),
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
    use onetdns_http2::frame::{self, flags, frame_type, FrameHeader};
    use onetdns_http2::hpack;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_security::IpAcl;
    use onetdns_tls::{client_handshake, ClientConfig, TlsStream, TrustStore};

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

    /** @brief 테스트용 자체 서명 설정. */
    fn self_signed() -> (Arc<ServerConfig>, Arc<TrustStore>) {
        self_signed_alpn(vec![b"h2".to_vec()])
    }

    /** @brief 프로토콜 목록을 지정한 테스트용 설정. */
    fn self_signed_alpn(alpn: Vec<Vec<u8>>) -> (Arc<ServerConfig>, Arc<TrustStore>) {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        let trust = Arc::new(TrustStore::from_ders([cert_der.as_slice()]));
        let cfg = ServerConfig::from_pkcs8(cert_der, &key_der)
            .unwrap()
            .with_alpn(alpn);
        (Arc::new(cfg), trust)
    }

    /** @brief HTTP/2 프레임 하나를 읽는다. */
    fn read_frame<S: Read>(s: &mut S) -> Option<(FrameHeader, Vec<u8>)> {
        let mut hdr = [0u8; 9];
        s.read_exact(&mut hdr).ok()?;
        let h = FrameHeader::parse(&hdr)?;
        let mut p = vec![0u8; h.length as usize];
        s.read_exact(&mut p).ok()?;
        Some((h, p))
    }

    /** @brief HTTP/2로 질의를 보내고 답을 받는다. */
    fn doh_post(addr: SocketAddr, trust: Arc<TrustStore>, query: &[u8]) -> Vec<u8> {
        let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: true,
            roots: Some((*trust).clone()),
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        };
        let conn = client_handshake(&mut tcp, &cfg).expect("클라 핸드셰이크");
        assert_eq!(conn.alpn(), Some(b"h2".as_slice()), "h2 협상");
        let mut s = TlsStream::new(conn, tcp);

        s.write_all(frame::PREFACE).unwrap();
        let mut f = Vec::new();
        frame::write_frame(&mut f, frame_type::SETTINGS, 0, 0, &[]);
        s.write_all(&f).unwrap();

        let block = hpack::encode_response(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", "/dns-query"),
            ("content-type", "application/dns-message"),
        ]);
        let mut f = Vec::new();
        frame::write_frame(&mut f, frame_type::HEADERS, flags::END_HEADERS, 1, &block);
        frame::write_frame(&mut f, frame_type::DATA, flags::END_STREAM, 1, query);
        s.write_all(&f).unwrap();

        let mut body = Vec::new();
        let mut ok = false;
        let mut dec = hpack::Decoder::new(4096);
        while let Some((h, payload)) = read_frame(&mut s) {
            match h.frame_type {
                frame_type::HEADERS => {
                    let hs = dec.decode(&payload).unwrap();
                    if hs.iter().any(|(n, v)| n == b":status" && v == b"200") {
                        ok = true;
                    }
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::DATA => {
                    body.extend_from_slice(&payload);
                    if h.has_flag(flags::END_STREAM) {
                        break;
                    }
                }
                frame_type::SETTINGS if !h.has_flag(flags::ACK) => {
                    let mut a = Vec::new();
                    frame::write_frame(&mut a, frame_type::SETTINGS, flags::ACK, 0, &[]);
                    s.write_all(&a).unwrap();
                }
                _ => {}
            }
        }
        assert!(ok, "200 응답");
        body
    }

    #[test]
    /** @brief 인증되지 않은 연결의 경로 식별자를 무시하는지. 받으면 남의 정책을 가져갈 수 있다. */
    fn path_identity_requires_transport_authentication() {
        assert_eq!(
            authenticated_path_identity(Some("admin"), false, None),
            Ok(None),
            "비인증 URL ID는 정책 ID가 되어서는 안 됨"
        );
        assert_eq!(
            authenticated_path_identity(Some("device-a"), true, Some("device-a")),
            Ok(Some("device-a".to_string()))
        );
        assert_eq!(
            authenticated_path_identity(Some("admin"), true, Some("device-a")),
            Err(()),
            "mTLS ID와 URL ID 충돌은 거부"
        );
    }

    #[test]
    /** @brief HTTP/2 위에서 질의가 해석되는지. */
    fn doh_h2_over_self_tls_resolves() {
        let (tls, trust) = self_signed();
        let handler = native_handler();
        let l = serve_doh(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            "/dns-query".to_string(),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();

        let query = Message::query(
            0x7777,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let resp_bytes = doh_post(l.addr(), trust, &query.try_encode().unwrap());
        let resp = Message::parse(&resp_bytes).unwrap();
        assert_eq!(resp.header.id, 0x7777);
        assert_eq!(resp.answers.len(), 1, "A 레코드 1개");
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            o => panic!("A 기대, {o:?}"),
        }
        let started = Instant::now();
        drop(l);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /** @brief HTTP/1.1로 질의를 보내고 답을 받는다. */
    fn doh_post_h1(addr: SocketAddr, trust: Arc<TrustStore>, query: &[u8]) -> Vec<u8> {
        let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: true,
            roots: Some((*trust).clone()),
            alpn: vec![b"http/1.1".to_vec()],
            ..Default::default()
        };
        let conn = client_handshake(&mut tcp, &cfg).expect("클라 핸드셰이크");
        assert_eq!(conn.alpn(), Some(b"http/1.1".as_slice()), "http/1.1 협상");
        let mut s = TlsStream::new(conn, tcp);

        let mut req = format!(
            "POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            query.len()
        )
        .into_bytes();
        req.extend_from_slice(query);
        s.write_all(&req).unwrap();

        let mut resp = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(split) = resp.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&resp[..split]).to_ascii_lowercase();
                if let Some(want) = head.split("\r\n").find_map(|line| {
                    line.strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                }) {
                    if resp.len() >= split + 4 + want {
                        break;
                    }
                }
            }
            match s.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let split = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("헤더 끝");
        let head = std::str::from_utf8(&resp[..split]).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "200 응답: {head}");
        resp[split + 4..].to_vec()
    }

    #[test]
    /** @brief HTTP/1.1로 전환해도 질의가 해석되는지. */
    fn doh_h1_over_self_tls_resolves() {
        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let handler = native_handler();
        let l = serve_doh(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            "/dns-query".to_string(),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();

        let query = Message::query(
            0x4242,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let resp_bytes = doh_post_h1(l.addr(), trust, &query.try_encode().unwrap());
        let resp = Message::parse(&resp_bytes).unwrap();
        assert_eq!(resp.header.id, 0x4242);
        assert_eq!(resp.answers.len(), 1, "A 레코드 1개");
    }
}
