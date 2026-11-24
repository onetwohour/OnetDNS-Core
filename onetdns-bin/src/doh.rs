//! DoH listener: DNS over HTTP/2 over TLS, with HTTP/1.1 for clients that do not negotiate h2.

use std::io;
use std::net::TcpListener;
#[cfg(test)]
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use onetdns_core::tcp::DeadlineTcp;
use onetdns_proto::Message;
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
use onetdns_tls::{server_handshake, ServerConfig, TlsStream};

use crate::connection_limit::{
    spawn_bounded_connection_thread, AdmissionProtocol, AdmittedConnection, ConnectionLimiter,
    ConnectionSignals, EncryptedTcpListener, PrefixedTcp,
};
use crate::native::NativeServer;
use crate::odoh::{ObliviousConn, ObliviousDoh};
use crate::ohttp::OhttpConn;
use crate::transport_observe;

const DOH_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// max-age for the response. RFC 8484 caps it at the smallest answer TTL, or the SOA MINIMUM for an
/// empty answer; 0 when there is neither. Without it, intermediate caches would guess a lifetime
/// and could keep the answer past its TTL.
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

fn doh_answer(response: &Message) -> Result<onetdns_http2::DohAnswer, &'static str> {
    Ok(onetdns_http2::DohAnswer {
        body: response.try_encode().map_err(|_| "502")?,
        max_age: http_freshness_secs(response),
    })
}

/// Serves DoH on `listener`, already bound, and the oblivious services `oblivious` holds.
pub fn serve_doh(
    listener: TcpListener,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    path: String,
    oblivious: Option<Arc<ObliviousDoh>>,
    admission: Arc<ConnectionLimiter>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<EncryptedTcpListener> {
    let path = Arc::new(path);
    let drops = handler.clone();
    EncryptedTcpListener::spawn(
        listener,
        "doh",
        AdmissionProtocol::Tls,
        admission,
        move |source| drops.drops_source(source),
        Some(shutdown),
        move |connection: AdmittedConnection| {
            let peer = connection.peer;
            let tls = tls.clone();
            let handler = handler.clone();
            let path = path.clone();
            let oblivious = oblivious.clone();
            let spawned = spawn_bounded_connection_thread("doh-connection", move || {
                let AdmittedConnection {
                    stream,
                    signals,
                    hold: _hold,
                    ..
                } = connection;
                let result = onetdns_core::isolation::catch_request(|| {
                    serve_conn(
                        stream,
                        &tls.load(),
                        &handler,
                        &path,
                        oblivious.as_deref(),
                        &signals,
                    )
                });
                if let Ok(Err(stage)) = result {
                    if !signals.stopping() {
                        transport_observe::record_error("doh", stage, Some(peer), stage);
                    }
                }
            });
            match spawned {
                Ok(thread) => drop(thread),
                Err(error) => {
                    transport_observe::record_error("doh", "thread_spawn", Some(peer), error)
                }
            }
        },
    )
}

/// A client ID in the path counts only on an authenticated connection; otherwise anyone could write
/// another client's ID there and get its policy.
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

fn serve_conn(
    tcp: PrefixedTcp,
    tls: &ServerConfig,
    handler: &NativeServer,
    path: &str,
    oblivious: Option<&ObliviousDoh>,
    signals: &ConnectionSignals,
) -> Result<(), &'static str> {
    let src = tcp.peer_addr().map_err(|_| "peer_addr")?;
    let mut tcp = signals.watch(DeadlineTcp::new(tcp, Instant::now() + DOH_IO_TIMEOUT));
    let conn = server_handshake(&mut tcp, tls).map_err(|_| "tls_handshake")?;

    let alpn = conn.alpn().map(|a| a.to_vec());
    let tls_authenticated = conn.client_authenticated();
    let tls_auth_identity = conn.client_auth_identity().map(|s| s.to_string());
    let mut stream = TlsStream::new(conn, tcp);

    // Failures are HTTP statuses. An unreadable body is the request's fault, so it gets a 4xx; a
    // 5xx means a server fault, and clients would resend to the same server. A query the handler
    // chose not to answer gets no status; the connection just ends.
    let resolve = |q: &[u8], client_id: Option<String>| -> Result<Option<Message>, &'static str> {
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
        let ctx = RequestCtx {
            src,
            transport: RtTransport::DoH,
            raw: Some(q),
            client_id,
            authenticated: tls_authenticated,
            auth_identity: tls_auth_identity.clone(),
        };
        Ok(handler.handle(&request, &ctx))
    };
    let dns = |q: &[u8],
               path_client_id: Option<&str>|
     -> Result<Option<onetdns_http2::DohAnswer>, &'static str> {
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
        resolve(q, client_id)?.as_ref().map(doh_answer).transpose()
    };
    // A relayed message names no client in the path; the connection's own identity is the only
    // one.
    let connection_identity =
        authenticated_path_identity(None, tls_authenticated, tls_auth_identity.as_deref())
            .ok()
            .flatten();
    let relayed = |q: &[u8]| -> Result<Option<onetdns_http2::DohAnswer>, &'static str> {
        resolve(q, connection_identity.clone())?
            .as_ref()
            .map(doh_answer)
            .transpose()
    };
    let admit_relay = || {
        handler.admit_relay(&RequestCtx {
            src,
            transport: RtTransport::DoH,
            raw: None,
            client_id: connection_identity.clone(),
            authenticated: tls_authenticated,
            auth_identity: tls_auth_identity.clone(),
        })
    };
    let ohttp = oblivious
        .filter(|service| service.gateway.is_some() || service.ohttp_relays.is_some())
        .map(|service| OhttpConn {
            gateway: service.gateway.as_ref(),
            relays: service.ohttp_relays.as_ref(),
            peer: src,
            doh_path: path,
            resolve: relayed,
            admit_relay,
        });
    let ohttp = ohttp
        .as_ref()
        .map(|conn| conn as &dyn onetdns_http2::ObliviousHttp);
    let oblivious = oblivious
        .filter(|service| service.target.is_some() || service.proxy.is_some())
        .map(|service| ObliviousConn {
            service,
            peer: src,
            resolve: relayed,
            admit_relay,
        });
    let oblivious = oblivious
        .as_ref()
        .map(|conn| conn as &dyn onetdns_http2::Oblivious);

    match alpn.as_deref() {
        Some(b"h2") => onetdns_http2::serve_doh_with_deadline_reset(
            &mut stream,
            path,
            dns,
            |stream| {
                stream
                    .inner_mut()
                    .set_deadline(Instant::now() + DOH_IO_TIMEOUT)
            },
            &signals.drain,
            oblivious,
            ohttp,
        )
        .map_err(|_| "http2_connection"),

        _ => onetdns_http2::serve_doh_h1_with_deadline_reset(
            &mut stream,
            path,
            dns,
            |stream| {
                stream
                    .inner_mut()
                    .set_deadline(Instant::now() + DOH_IO_TIMEOUT)
            },
            oblivious,
            ohttp,
        )
        .map_err(|_| "http1_connection"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::thread;

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
    fn dropping_doh_listener_joins_idle_handshake() {
        let (tls, _) = self_signed();
        let listener = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            native_handler(),
            "/dns-query".to_string(),
            None,
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let client = TcpStream::connect(listener.addr()).unwrap();
        thread::sleep(Duration::from_millis(150));
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < onetdns_core::tcp::DRAIN_LIMIT);
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
        native_handler_with(Arc::new(IpAcl::allow_all()))
    }

    fn native_handler_with(acl: Arc<dyn onetdns_core::AccessControl>) -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            acl,
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    fn self_signed() -> (Arc<ServerConfig>, Arc<TrustStore>) {
        self_signed_alpn(vec![b"h2".to_vec()])
    }

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

    fn read_frame<S: Read>(s: &mut S) -> Option<(FrameHeader, Vec<u8>)> {
        let mut hdr = [0u8; 9];
        s.read_exact(&mut hdr).ok()?;
        let h = FrameHeader::parse(&hdr)?;
        let mut p = vec![0u8; h.length as usize];
        s.read_exact(&mut p).ok()?;
        Some((h, p))
    }

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
    fn doh_h2_over_self_tls_resolves() {
        let (tls, trust) = self_signed();
        let handler = native_handler();
        let l = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            "/dns-query".to_string(),
            None,
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

    fn doh_post_h1(addr: SocketAddr, trust: Arc<TrustStore>, query: &[u8]) -> Vec<u8> {
        let (head, body) = https_post_h1(addr, trust, "application/dns-message", query);
        assert!(head.starts_with("HTTP/1.1 200"), "200 응답: {head}");
        body
    }

    fn https_post_h1(
        addr: SocketAddr,
        trust: Arc<TrustStore>,
        content_type: &str,
        body: &[u8],
    ) -> (String, Vec<u8>) {
        https_post_path_h1(addr, trust, "/dns-query", content_type, body)
    }

    fn https_post_path_h1(
        addr: SocketAddr,
        trust: Arc<TrustStore>,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> (String, Vec<u8>) {
        let mut req = format!(
            "POST {path} HTTP/1.1\r\nHost: dns.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        https_h1(addr, trust, &req)
    }

    fn odoh_target() -> Arc<ObliviousDoh> {
        Arc::new(ObliviousDoh {
            target: Some(Arc::new(crate::odoh::OdohTarget::new(
                onetdns_tls::hpke::PrivateKey::generate(),
            ))),
            proxy: None,
            gateway: None,
            ohttp_relays: None,
        })
    }

    /// One HTTP/1.1 request over TLS; returns the status line with the header fields, and the body.
    fn https_h1(addr: SocketAddr, trust: Arc<TrustStore>, req: &[u8]) -> (String, Vec<u8>) {
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
        s.write_all(req).unwrap();

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
        let head = std::str::from_utf8(&resp[..split]).unwrap().to_string();
        (head, resp[split + 4..].to_vec())
    }

    #[test]
    /// A client fetches the config, seals a query to it, and opens the answer, which went through
    /// the same filtering as DoH.
    fn odoh_queries_resolve_through_the_doh_listener() {
        use onetdns_forward::odoh::PublicConfig;
        use onetdns_tls::hpke::PrivateKey;

        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let l = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(tls)),
            native_handler(),
            "/dns-query".to_string(),
            Some(odoh_target()),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        let get =
            b"GET /.well-known/odohconfigs HTTP/1.1\r\nHost: dns.test\r\nConnection: close\r\n\r\n";
        let (head, configs) = https_h1(l.addr(), trust.clone(), get);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let config = PublicConfig::from_configs(&configs).unwrap();

        let ask = |name: &str, id: u16| {
            let query = Message::query(id, ApName::from_str(name).unwrap(), RecordType::A);
            let (message, pending) = config.seal_query(&query.try_encode().unwrap()).unwrap();
            let (head, body) = https_post_h1(
                l.addr(),
                trust.clone(),
                onetdns_http2::ODOH_MEDIA_TYPE,
                &message,
            );
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            assert!(head.contains("cache-control: no-cache, no-store"), "{head}");
            Message::parse(&pending.open_response(&body).unwrap()).unwrap()
        };
        let allowed = ask("allowed.test", 0x6161);
        assert_eq!(allowed.header.id, 0x6161);
        assert!(matches!(
            allowed.answers[0].rdata,
            ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
        ));
        let blocked = ask("blocked.test", 0x6262);
        assert_eq!(
            blocked.header.rcode,
            onetdns_proto::ResponseCode::NXDomain.0
        );

        let other_key = onetdns_forward::odoh::TargetKey::new(PrivateKey::generate());
        let stale = PublicConfig::from_configs(&other_key.configs()).unwrap();
        let query = Message::query(1, ApName::from_str("allowed.test").unwrap(), RecordType::A);
        let (message, _) = stale.seal_query(&query.try_encode().unwrap()).unwrap();
        let (head, _) = https_post_h1(l.addr(), trust, onetdns_http2::ODOH_MEDIA_TYPE, &message);
        assert!(
            head.starts_with("HTTP/1.1 401"),
            "a query for another key tells the client to refetch: {head}"
        );
    }

    #[test]
    /// A client fetches the key configuration, encapsulates DoH requests to it, and opens the
    /// answers, which went through the same filtering as DoH. The relay's address stands for every
    /// client behind it, so UPDATE is refused.
    fn ohttp_requests_resolve_through_the_doh_listener() {
        use onetdns_forward::ohttp::{GatewayKey, KeyConfig};
        use onetdns_http2::bhttp::{Control, Message as Bhttp};
        use onetdns_tls::hpke::PrivateKey;

        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let l = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(tls)),
            native_handler(),
            "/dns-query".to_string(),
            Some(Arc::new(ObliviousDoh {
                target: None,
                proxy: None,
                gateway: Some(GatewayKey::new(PrivateKey::generate())),
                ohttp_relays: None,
            })),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        let get = b"GET /.well-known/ohttp-gateway HTTP/1.1\r\nHost: dns.test\r\nAccept: application/ohttp-keys\r\nConnection: close\r\n\r\n";
        let (head, keys) = https_h1(l.addr(), trust.clone(), get);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            head.contains("content-type: application/ohttp-keys"),
            "{head}"
        );
        let (configs, _) = https_h1(
            l.addr(),
            trust.clone(),
            b"GET /.well-known/odohconfigs HTTP/1.1\r\nHost: dns.test\r\nConnection: close\r\n\r\n",
        );
        assert!(
            configs.starts_with("HTTP/1.1 404"),
            "not an ODoH target: {configs}"
        );

        let send = |method: &str, path: String, content: Vec<u8>| {
            let fields = if method == "POST" {
                vec![(
                    b"content-type".to_vec(),
                    b"application/dns-message".to_vec(),
                )]
            } else {
                Vec::new()
            };
            let request = Bhttp {
                control: Control::Request {
                    method: method.as_bytes().to_vec(),
                    scheme: b"https".to_vec(),
                    authority: b"dns.test".to_vec(),
                    path: path.into_bytes(),
                },
                fields,
                content,
            };
            let (encapsulated, client) = KeyConfig::from_keys(&keys)
                .unwrap()
                .encapsulate(&request.encode())
                .unwrap();
            let (head, body) = https_post_path_h1(
                l.addr(),
                trust.clone(),
                onetdns_http2::OHTTP_GATEWAY_PATH,
                onetdns_http2::OHTTP_REQUEST_MEDIA_TYPE,
                &encapsulated,
            );
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            assert!(head.contains("content-type: message/ohttp-res"), "{head}");
            assert!(head.contains("cache-control: private, no-store"), "{head}");
            let plaintext = client.open_response(&body).unwrap();
            assert_eq!(plaintext.len() % 468, 0, "the answer is padded");
            Bhttp::decode(&plaintext).unwrap()
        };
        let ask = |name: &str, id: u16| {
            let query = Message::query(id, ApName::from_str(name).unwrap(), RecordType::A);
            let response = send("POST", "/dns-query".into(), query.try_encode().unwrap());
            assert_eq!(response.control, Control::Response(200));
            Message::parse(&response.content).unwrap()
        };
        let allowed = ask("allowed.test", 0x7171);
        assert_eq!(allowed.header.id, 0x7171);
        assert!(matches!(
            allowed.answers[0].rdata,
            ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
        ));
        let blocked = ask("blocked.test", 0x7272);
        assert_eq!(
            blocked.header.rcode,
            onetdns_proto::ResponseCode::NXDomain.0
        );

        let query = Message::query(
            0x7373,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let by_get = send(
            "GET",
            format!(
                "/dns-query?dns={}",
                crate::acme::b64url(&query.try_encode().unwrap())
            ),
            Vec::new(),
        );
        assert_eq!(by_get.control, Control::Response(200));
        assert_eq!(Message::parse(&by_get.content).unwrap().header.id, 0x7373);

        let mut update = query.clone();
        update.header.opcode = 5;
        let refused = send("POST", "/dns-query".into(), update.try_encode().unwrap());
        assert_eq!(refused.control, Control::Response(200));
        assert_eq!(
            Message::parse(&refused.content).unwrap().header.rcode,
            onetdns_proto::ResponseCode::Refused.0
        );
        let elsewhere = send("POST", "/other".into(), query.try_encode().unwrap());
        assert_eq!(elsewhere.control, Control::Response(404));

        let stale = GatewayKey::new(PrivateKey::generate());
        let (encapsulated, _) = KeyConfig::from_keys(stale.keys())
            .unwrap()
            .encapsulate(b"request")
            .unwrap();
        let (head, _) = https_post_path_h1(
            l.addr(),
            trust,
            onetdns_http2::OHTTP_GATEWAY_PATH,
            onetdns_http2::OHTTP_REQUEST_MEDIA_TYPE,
            &encapsulated,
        );
        assert!(
            head.starts_with("HTTP/1.1 422"),
            "a request for another key is refused unencapsulated: {head}"
        );
    }

    #[test]
    /// The client reaches the target only through the proxy, which relays to the listed target and
    /// refuses any other.
    fn odoh_proxy_relays_only_to_listed_targets() {
        use onetdns_forward::odoh::{PublicConfig, Relay};
        use onetdns_tls::hpke::PrivateKey;

        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let tls = Arc::new(onetdns_core::ArcSwap::new(tls));
        let target = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            tls.clone(),
            native_handler(),
            "/dns-query".to_string(),
            Some(odoh_target()),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let listed = format!("https://{}/dns-query#dns.test", target.addr());
        let serve_proxy = |acl: Arc<dyn onetdns_core::AccessControl>| {
            serve_doh(
                std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
                tls.clone(),
                native_handler_with(acl),
                "/dns-query".to_string(),
                Some(Arc::new(ObliviousDoh {
                    target: None,
                    proxy: Some(crate::odoh::OdohProxy::new(
                        std::slice::from_ref(&listed),
                        Arc::new(onetdns_core::ArcSwap::from_pointee(
                            onetdns_config::Config::default(),
                        )),
                        Relay::with_trust(trust.clone()),
                    )),
                    gateway: None,
                    ohttp_relays: None,
                })),
                Arc::new(ConnectionLimiter::default()),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap()
        };
        let proxy = serve_proxy(Arc::new(IpAcl::allow_all()));

        let get =
            b"GET /.well-known/odohconfigs HTTP/1.1\r\nHost: dns.test\r\nConnection: close\r\n\r\n";
        let (_, configs) = https_h1(target.addr(), trust.clone(), get);
        let config = PublicConfig::from_configs(&configs).unwrap();
        let (head, _) = https_h1(proxy.addr(), trust.clone(), get);
        assert!(
            head.starts_with("HTTP/1.1 404"),
            "a proxy alone has no key: {head}"
        );

        let query = Message::query(
            0x7171,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let relayed_path = format!(
            "/dns-query?targethost={}&targetpath=%2Fdns-query",
            target.addr()
        );
        let send = |proxy: SocketAddr, path: &str, config: &PublicConfig| {
            let (message, pending) = config.seal_query(&query.try_encode().unwrap()).unwrap();
            let (head, body) = https_post_path_h1(
                proxy,
                trust.clone(),
                path,
                onetdns_http2::ODOH_MEDIA_TYPE,
                &message,
            );
            (head, body, pending)
        };

        // Twice, so the second rides the pooled target connection.
        for _ in 0..2 {
            let (head, body, pending) = send(proxy.addr(), &relayed_path, &config);
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            let answer = Message::parse(&pending.open_response(&body).unwrap()).unwrap();
            assert_eq!(answer.header.id, 0x7171);
            assert!(matches!(
                answer.answers[0].rdata,
                ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
            ));
        }

        let elsewhere = "/dns-query?targethost=odoh.example&targetpath=/dns-query";
        let (head, _, _) = send(proxy.addr(), elsewhere, &config);
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");
        assert!(
            head.contains("proxy-status: OnetDNS; error=http_request_denied"),
            "{head}"
        );
        let other_path = format!("/dns-query?targethost={}&targetpath=/other", target.addr());
        let (head, _, _) = send(proxy.addr(), &other_path, &config);
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");

        let other_key = onetdns_forward::odoh::TargetKey::new(PrivateKey::generate());
        let stale = PublicConfig::from_configs(&other_key.configs()).unwrap();
        let (head, _, _) = send(proxy.addr(), &relayed_path, &stale);
        assert!(head.starts_with("HTTP/1.1 401"), "{head}");
        assert!(
            head.contains("proxy-status: OnetDNS; received-status=401"),
            "{head}"
        );

        // OnetDNS's own ODoH upstream, through this proxy to this target. The URL form would name
        // the target by IP, which this test certificate does not cover, so the TLS name is given
        // apart from `targethost`.
        let upstream = onetdns_forward::Upstream::odoh(
            proxy.addr(),
            "dns.test",
            onetdns_forward::odoh::proxy_request_path(
                "/dns-query",
                &target.addr().to_string(),
                "/dns-query",
            ),
            "dns.test",
            target.addr(),
        );
        let forwarder = Forwarder::with_upstreams(vec![upstream], Duration::from_secs(5))
            .with_trust(trust.clone());
        let resolved = forwarder.resolve(&query).unwrap();
        assert_eq!(resolved.header.id, 0x7171);
        assert!(matches!(
            resolved.answers[0].rdata,
            ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
        ));

        let denying = serve_proxy(Arc::new(IpAcl::new(
            vec![],
            vec!["127.0.0.0/8".parse().unwrap()],
            true,
        )));
        let (head, _, _) = send(denying.addr(), &relayed_path, &config);
        assert!(
            head.starts_with("HTTP/1.1 403"),
            "the ACL applies to relays: {head}"
        );
    }

    #[test]
    /// The client reaches the gateway only through a relay resource, which passes the request to
    /// its gateway and the gateway's answer back unchanged.
    fn ohttp_relay_passes_requests_to_its_gateway() {
        use crate::ohttp::OhttpRelays;
        use onetdns_forward::odoh::Relay;
        use onetdns_forward::ohttp::{GatewayKey, KeyConfig};
        use onetdns_http2::bhttp::{Control, Message as Bhttp};
        use onetdns_tls::hpke::PrivateKey;

        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let tls = Arc::new(onetdns_core::ArcSwap::new(tls));
        let key = GatewayKey::new(PrivateKey::generate());
        let keys = key.keys().to_vec();
        let gateway = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            tls.clone(),
            native_handler(),
            "/dns-query".to_string(),
            Some(Arc::new(ObliviousDoh {
                target: None,
                proxy: None,
                gateway: Some(key),
                ohttp_relays: None,
            })),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let resources = [onetdns_config::OhttpRelay {
            path: "/relay".to_string(),
            gateway: format!(
                "https://{}{}#dns.test",
                gateway.addr(),
                onetdns_http2::OHTTP_GATEWAY_PATH
            ),
        }];
        let serve_relay = |acl: Arc<dyn onetdns_core::AccessControl>| {
            serve_doh(
                std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
                tls.clone(),
                native_handler_with(acl),
                "/dns-query".to_string(),
                Some(Arc::new(ObliviousDoh {
                    target: None,
                    proxy: None,
                    gateway: None,
                    ohttp_relays: Some(OhttpRelays::new(
                        &resources,
                        Arc::new(onetdns_core::ArcSwap::from_pointee(
                            onetdns_config::Config::default(),
                        )),
                        Relay::with_trust(trust.clone()),
                    )),
                })),
                Arc::new(ConnectionLimiter::default()),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap()
        };
        let relay = serve_relay(Arc::new(IpAcl::allow_all()));

        let query = Message::query(
            0x7171,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        let request = Bhttp {
            control: Control::Request {
                method: b"POST".to_vec(),
                scheme: b"https".to_vec(),
                authority: b"dns.test".to_vec(),
                path: b"/dns-query".to_vec(),
            },
            fields: vec![(
                b"content-type".to_vec(),
                b"application/dns-message".to_vec(),
            )],
            content: query.try_encode().unwrap(),
        }
        .encode();
        let send = |relay: SocketAddr, path: &str, keys: &[u8]| {
            let (encapsulated, client) = KeyConfig::from_keys(keys)
                .unwrap()
                .encapsulate(&request)
                .unwrap();
            let (head, body) = https_post_path_h1(
                relay,
                trust.clone(),
                path,
                onetdns_http2::OHTTP_REQUEST_MEDIA_TYPE,
                &encapsulated,
            );
            (head, body, client)
        };

        // Twice, so the second rides the pooled gateway connection.
        for _ in 0..2 {
            let (head, body, client) = send(relay.addr(), "/relay", &keys);
            assert!(head.starts_with("HTTP/1.1 200"), "{head}");
            assert!(head.contains("content-type: message/ohttp-res"), "{head}");
            let response = Bhttp::decode(&client.open_response(&body).unwrap()).unwrap();
            assert_eq!(response.control, Control::Response(200));
            let answer = Message::parse(&response.content).unwrap();
            assert_eq!(answer.header.id, 0x7171);
            assert!(matches!(
                answer.answers[0].rdata,
                ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
            ));
        }

        // OnetDNS's own OHTTP upstream, through this relay to this gateway. The URL form would name
        // the gateway by IP, which this test certificate does not cover, so the TLS name is given
        // apart from `targethost`.
        let upstream = onetdns_forward::Upstream::ohttp(
            relay.addr(),
            "dns.test",
            "/relay",
            "dns.test",
            "/dns-query",
            "dns.test",
            gateway.addr(),
        );
        let forwarder = Forwarder::with_upstreams(vec![upstream], Duration::from_secs(5))
            .with_trust(trust.clone());
        let resolved = forwarder.resolve(&query).unwrap();
        assert_eq!(resolved.header.id, 0x7171);
        assert!(matches!(
            resolved.answers[0].rdata,
            ApRData::A(ip) if ip == std::net::Ipv4Addr::new(9, 9, 9, 9)
        ));

        let (head, _, _) = send(relay.addr(), "/other", &keys);
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");
        let (head, _, _) = send(relay.addr(), onetdns_http2::OHTTP_GATEWAY_PATH, &keys);
        assert!(
            head.starts_with("HTTP/1.1 404"),
            "a relay alone is no gateway: {head}"
        );

        let stale = GatewayKey::new(PrivateKey::generate());
        let (head, _, _) = send(relay.addr(), "/relay", stale.keys());
        assert!(head.starts_with("HTTP/1.1 422"), "{head}");
        assert!(
            head.contains("proxy-status: OnetDNS; received-status=422"),
            "{head}"
        );

        let denying = serve_relay(Arc::new(IpAcl::new(
            vec![],
            vec!["127.0.0.0/8".parse().unwrap()],
            true,
        )));
        let (head, _, _) = send(denying.addr(), "/relay", &keys);
        assert!(
            head.starts_with("HTTP/1.1 403"),
            "the ACL applies to relays: {head}"
        );
    }

    #[test]
    fn doh_h1_over_self_tls_resolves() {
        let (tls, trust) = self_signed_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let handler = native_handler();
        let l = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(tls)),
            handler,
            "/dns-query".to_string(),
            None,
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

    #[test]
    /// A dropped address cannot finish the TLS handshake. If it becomes dropped after connecting,
    /// the handler gives no answer and the connection closes without a status; a 502 instead would
    /// make the client resend.
    fn doh_drops_listed_clients_without_an_http_status() {
        let dropping = || -> Arc<dyn onetdns_core::AccessControl> {
            Arc::new(IpAcl::allow_all().with_drop(vec!["127.0.0.0/8".parse().unwrap()]))
        };
        let acl = Arc::new(crate::native_config::DynamicAccessControl::new(dropping()));
        let (tls, trust) = self_signed();
        let l = serve_doh(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(tls)),
            native_handler_with(acl.clone()),
            "/dns-query".to_string(),
            None,
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: true,
            roots: Some((*trust).clone()),
            alpn: vec![b"h2".to_vec()],
            ..Default::default()
        };
        let connect = || {
            let tcp = TcpStream::connect_timeout(&l.addr(), Duration::from_secs(5)).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp
        };

        let mut tcp = connect();
        assert!(
            client_handshake(&mut tcp, &cfg).is_err(),
            "버리는 주소와 TLS 핸드셰이크를 마쳤습니다"
        );

        acl.replace(Arc::new(IpAcl::allow_all()));
        let mut tcp = connect();
        let conn =
            client_handshake(&mut tcp, &cfg).expect("허용한 주소와 핸드셰이크하지 못했습니다");
        let mut s = TlsStream::new(conn, tcp);
        let mut f = Vec::new();
        f.extend_from_slice(frame::PREFACE);
        frame::write_frame(&mut f, frame_type::SETTINGS, 0, 0, &[]);
        s.write_all(&f).unwrap();

        acl.replace(dropping());
        let query = Message::query(
            0x5151,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        )
        .try_encode()
        .unwrap();
        let block = hpack::encode_response(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "dns.test"),
            (":path", "/dns-query"),
            ("content-type", "application/dns-message"),
        ]);
        let mut f = Vec::new();
        frame::write_frame(&mut f, frame_type::HEADERS, flags::END_HEADERS, 1, &block);
        frame::write_frame(&mut f, frame_type::DATA, flags::END_STREAM, 1, &query);
        s.write_all(&f).unwrap();
        let started = Instant::now();
        let mut frames = Vec::new();
        while let Some((h, _)) = read_frame(&mut s) {
            frames.push(h.frame_type);
        }
        assert!(
            !frames.contains(&frame_type::HEADERS),
            "버리게 된 주소의 요청에 HTTP 상태를 보냈습니다: {frames:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "버리게 된 주소의 연결을 닫지 않고 붙들고 있었습니다"
        );
    }
}
