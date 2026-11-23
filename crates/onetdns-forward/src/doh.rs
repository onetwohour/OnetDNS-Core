//! DNS over HTTPS upstream on HTTP/2 (RFC 8484).

use std::cell::RefCell;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_http2::{H2Client, H2Error};
use onetdns_proto::Message;
use onetdns_tls::{client_handshake, ClientConfig, TlsSession, TlsStream, TrustStore};

use crate::{validate_response, DeadlineTcp, Endpoint, ForwardError};

pub(crate) struct DohConn {
    pub(crate) client: H2Client<TlsStream<DeadlineTcp>>,

    /// Observed round-trip time; sets the PING wait on reuse.
    pub(crate) rtt_hint: Duration,
}

/// Where opening an HTTP/2 connection over TLS failed.
pub(crate) enum ConnectError {
    Tcp(ForwardError),
    Tls(onetdns_tls::TlsError),
    /// The revocation check refused the certificate.
    Revoked(ForwardError),
    Preface,
}

thread_local! {
    static POOL: RefCell<LruMap<(Endpoint, String, String, crate::TlsCacheScope), DohConn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
    /// Sessions for resuming dropped HTTP/2 connections quickly.
    static SESSIONS: RefCell<LruMap<(Endpoint, String, crate::TlsCacheScope), TlsSession>> =
        RefCell::new(LruMap::new(MAX_CACHED_SESSIONS));
}

const MAX_POOLED_CONNECTIONS: usize = 256;
const MAX_CACHED_SESSIONS: usize = 64;

/// Sends a PING with the query on a kept connection, giving a two-stage deadline: a dead connection
/// is given up quickly, a live one gets the upstream's resolution time. On connection failure,
/// drops the connection from the pool and retries once on a new one. An error status from the
/// server leaves the connection in place and is not retried: it is the server's answer, a new
/// connection would not change it, and 429 and 503 also ask clients not to retry at once.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange(
    endpoint: &Endpoint,
    server_name: &str,
    path: &str,
    wire: &[u8],
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    let deadline = super::deadline_after(timeout);
    with_pooled(endpoint, server_name, path, deadline, trust, |conn| {
        roundtrip(conn, server_name, path, wire, request, deadline)
    })?
}

/// Runs `roundtrip` on this thread's connection for `endpoint`, `server_name` and `path`. An error
/// from `roundtrip` means the connection is unusable: it leaves the pool, and a reused one is
/// replaced once.
pub(crate) fn with_pooled<T>(
    endpoint: &Endpoint,
    server_name: &str,
    path: &str,
    deadline: Instant,
    trust: &TrustStore,
    mut roundtrip: impl FnMut(&mut DohConn) -> Result<T, ForwardError>,
) -> Result<T, ForwardError> {
    #[cfg(test)]
    let _revocation_test_guard = crate::revocation_test_read_guard();
    POOL.with(|pool| {
        let scope = crate::tls_cache_scope(trust);
        let key = (
            endpoint.clone(),
            server_name.to_string(),
            path.to_string(),
            scope,
        );
        let session_key = (endpoint.clone(), server_name.to_string(), scope);

        for attempt in 0..2 {
            let reused = { pool.borrow().contains_key(&key) };
            if !reused {
                let session =
                    SESSIONS.with(|sessions| sessions.borrow().peek(&session_key).cloned());
                let c = connect(endpoint, server_name, deadline, trust, session)?;
                pool.borrow_mut().put(key.clone(), c);
            }
            let (res, session) = {
                let mut p = pool.borrow_mut();
                let conn = p.get_mut(&key).expect("Just inserted");
                let result = roundtrip(conn);
                let session = conn.client.stream_mut().take_sessions().pop();
                (result, session)
            };
            if let Some(session) = session {
                SESSIONS.with(|sessions| sessions.borrow_mut().put(session_key.clone(), session));
            }
            match res {
                Ok(answer) => return Ok(answer),
                Err(e) => {
                    pool.borrow_mut().pop(&key);
                    if reused && attempt == 0 {
                        onetdns_core::debug!(event = "forward.conn_retry",
                            transport = "doh",
                            addr = %endpoint,
                            path = path,
                            reason = ?e,
                            "Could not reuse the existing connection; retrying on a new one"
                        );
                    }
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        Err(ForwardError::Timeout)
    })
}

fn connect(
    endpoint: &Endpoint,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
    session: Option<TlsSession>,
) -> Result<DohConn, ForwardError> {
    connect_h2(endpoint, server_name, deadline, trust, session).map_err(|error| match error {
        ConnectError::Tcp(e) => e,
        ConnectError::Tls(e) => {
            crate::note_upstream_connect_failure("doh", endpoint, server_name, &e);
            ForwardError::Io(format!("DoH handshake: {e}"))
        }
        ConnectError::Revoked(e) => e,
        ConnectError::Preface => ForwardError::Io("DoH HTTP/2 preface".into()),
    })
}

/// Checks revocation right after the handshake, before a query. A certificate the hook rejects is
/// reported to the server with a fatal alert, as when TLS rejects it.
pub(crate) fn connect_h2(
    endpoint: &Endpoint,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
    session: Option<TlsSession>,
) -> Result<DohConn, ConnectError> {
    let started = Instant::now();
    // Through a proxy this spans the tunnel setup, which the proxy completes only after reaching
    // the server, so it still approximates the round trip to the server.
    let mut tcp = crate::connect_stream(endpoint, deadline).map_err(ConnectError::Tcp)?;
    let rtt_hint = started.elapsed();
    let cfg = ClientConfig {
        server_name: server_name.to_string(),
        verify_name: true,
        roots: Some(trust.clone()),
        alpn: vec![b"h2".to_vec()],
        session,
        ..Default::default()
    };
    let mut tls = client_handshake(&mut tcp, &cfg).map_err(ConnectError::Tls)?;
    if !tls.is_resumed() {
        crate::check_revocation(tls.verified_chain(), server_name)
            .inspect_err(|_| tls.reject_peer_certificate(&mut tcp))
            .map_err(ConnectError::Revoked)?;
    }
    let stream = TlsStream::new(tls, tcp);
    let client = H2Client::connect(stream).map_err(|_| ConnectError::Preface)?;
    Ok(DohConn { client, rtt_hint })
}

/// Sets the short deadline a probed request starts with; its `on_alive` moves it out to `deadline`.
pub(crate) fn arm_probe(conn: &mut DohConn, deadline: Instant) {
    let silence = Duration::from_millis(crate::quicdrive::silence_limit_ms(
        conn.rtt_hint.as_millis() as u64,
    ));
    let probe_deadline = Instant::now()
        .checked_add(silence)
        .map_or(deadline, |d| d.min(deadline));
    conn.client
        .stream_mut()
        .inner_mut()
        .set_deadline(probe_deadline);
}

/// An outer Err means the connection is unusable. An inner Err means the server answered this query
/// alone with an error status, and the connection is still good.
fn roundtrip(
    conn: &mut DohConn,
    server_name: &str,
    path: &str,
    wire: &[u8],
    request: &Message,
    deadline: Instant,
) -> Result<Result<Message, ForwardError>, ForwardError> {
    if wire.len() > 0xffff {
        return Err(ForwardError::BadResponse);
    }

    let mut q = wire.to_vec();
    q[0] = 0;
    q[1] = 0;

    arm_probe(conn, deadline);
    let answer = conn.client.query_probed(server_name, path, &q, |stream| {
        stream.inner_mut().set_deadline(deadline);
    });
    let body = match answer {
        Ok(body) => body,
        Err(H2Error::BadStatus(_)) => {
            return Ok(Err(ForwardError::Io("DoH non-200 status".into())))
        }
        Err(H2Error::Closed) => {
            return Err(ForwardError::Io("DoH server closed the connection".into()))
        }
        Err(H2Error::Protocol) => return Err(ForwardError::BadResponse),
        Err(H2Error::Io) => {
            return Err(ForwardError::Io(
                "I/O error on the DoH HTTP/2 connection".into(),
            ))
        }
    };
    let resp = Message::parse(&body).map_err(|_| ForwardError::BadResponse)?;

    validate_response(request, &resp, Some(0))?;
    Ok(Ok(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use onetdns_http2::serve_doh;
    use onetdns_proto::{Name, RData, Record, RecordType};
    use onetdns_tls::conn::ServerResumption;
    use onetdns_tls::{server_handshake, signer_from_pkcs8_der, ServerConfig as TlsServerConfig};

    use crate::socks5::test_proxy::{self, Mode, Request};
    use crate::{Forwarder, Socks5Proxy, Upstream};

    fn doh_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _accepts, _signatures) = doh_server_ex(ip, false);
        (addr, trust)
    }

    /// Counts connections and full-handshake signatures.
    fn doh_server_ex(
        ip: Ipv4Addr,
        one_shot: bool,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let trust = Arc::new(TrustStore::from_ders([cert_der.as_slice()]));
        let (scheme, sign) = signer_from_pkcs8_der(&key_der).unwrap();
        let signatures = Arc::new(AtomicUsize::new(0));
        let signatures_for_signer = Arc::clone(&signatures);
        let counted_sign = Arc::new(move |content: &[u8]| {
            signatures_for_signer.fetch_add(1, Ordering::Relaxed);
            sign(content)
        });

        let server_cfg = Arc::new(TlsServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: scheme,
            sign: counted_sign,
            alpn: vec![b"h2".to_vec()],
            client_ca: None,
            resumption: Some(ServerResumption::secure_default()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_ret = accepts.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                accepts.fetch_add(1, Ordering::Relaxed);
                let cfg = server_cfg.clone();
                thread::spawn(move || {
                    let Ok(tls) = server_handshake(&mut s, &cfg) else {
                        return;
                    };
                    let mut tstream = TlsStream::new(tls, s);

                    let answered = std::cell::Cell::new(false);
                    serve_doh(&mut tstream, "/dns-query", move |q, _cid| {
                        if one_shot && answered.get() {
                            loop {
                                thread::park();
                            }
                        }
                        answered.set(true);
                        let req = Message::parse(q).map_err(|_| "400")?;
                        let mut m = Message::default();
                        m.header.id = req.header.id;
                        m.header.response = true;
                        m.header.recursion_available = true;
                        m.questions = req.questions.clone();
                        if let Some(qq) = req.questions.first() {
                            m.answers
                                .push(Record::new(qq.name.clone(), 60, RData::A(ip)));
                        }
                        Ok(Some(onetdns_http2::DohAnswer {
                            body: m.try_encode().map_err(|_| "502")?,
                            max_age: 0,
                        }))
                    })
                    .ok();
                });
            }
        });
        (addr, trust, accepts_ret, signatures)
    }

    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    fn doh_forward_verified_and_reuses_connection() {
        let (addr, trust) = doh_server(Ipv4Addr::new(3, 3, 3, 3));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(trust);

        let r1 = fwd.resolve(&q(0xABCD, "secure.test")).unwrap();
        assert_eq!(r1.header.id, 0xABCD);
        assert_eq!(r1.answers.len(), 1);
        match &r1.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(3, 3, 3, 3)),
            o => panic!("A 기대, {o:?}"),
        }

        let r2 = fwd.resolve(&q(0x1111, "again.test")).unwrap();
        assert_eq!(r2.header.id, 0x1111);
        assert_eq!(r2.answers.len(), 1);
    }

    #[test]
    /// Closing TCP without an alert leaves the server unable to tell a rejection from a connection
    /// cut on the way.
    fn doh_revocation_rejection_is_reported_to_the_server() {
        let _revocation_test_guard = crate::revocation_test_write_guard();
        let (addr, trust, reads) = crate::tls_first_read_recorder(b"h2");
        crate::set_revocation_hook(Box::new(|_, host| {
            if host == "dns.test" {
                Err("폐기됨".to_string())
            } else {
                Ok(())
            }
        }));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        let res = fwd.resolve(&q(1, "x.test"));
        crate::clear_revocation_hook();
        assert!(
            res.is_err(),
            "폐기 확인이 거부한 서버의 답을 받아들였습니다"
        );
        let read = reads
            .recv_timeout(Duration::from_secs(10))
            .expect("서버가 핸드셰이크를 마치지 못했습니다");
        assert_eq!(
            read,
            Err(onetdns_tls::TlsError::PeerAlert {
                level: 2,
                description: 46
            }),
            "certificate_unknown 치명 경고가 아닙니다"
        );
    }

    #[test]
    fn doh_idle_alive_connection_is_reused() {
        let (addr, trust, accepts, _signatures) = doh_server_ex(Ipv4Addr::new(7, 7, 7, 7), false);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "a.test")).unwrap();
        std::thread::sleep(Duration::from_millis(120));
        let r = fwd.resolve(&q(0x2, "b.test")).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(accepts.load(Ordering::Relaxed), 1, "유휴 후에도 재사용");
    }

    #[test]
    fn doh_reused_zombie_fails_fast_then_reconnects() {
        let (addr, trust, accepts, signatures) = doh_server_ex(Ipv4Addr::new(8, 8, 8, 8), true);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "first.test")).unwrap();
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

        let start = Instant::now();
        let r = fwd.resolve(&q(0x2, "second.test")).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.header.id, 0x2);
        assert_eq!(accepts.load(Ordering::Relaxed), 2, "좀비 실패 후 새 연결");
        assert_eq!(
            signatures.load(Ordering::Relaxed),
            1,
            "재접속은 TLS 1.3 PSK-DHE 재개라 인증서 서명이 없어야 함"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "5초 데드라인을 소진하지 않아야 함: {elapsed:?}"
        );
    }

    #[test]
    fn doh_rejects_wrong_server_name() {
        let (addr, trust) = doh_server(Ipv4Addr::new(4, 4, 4, 4));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "evil.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    fn doh_rejects_untrusted_cert() {
        let (addr, _trust) = doh_server(Ipv4Addr::new(5, 5, 5, 5));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /// A stricter trust policy must not reuse connections or sessions from before.
    fn doh_cache_is_scoped_to_trust_policy() {
        let (addr, trust) = doh_server(Ipv4Addr::new(5, 5, 5, 6));
        let trusted = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        trusted.resolve(&q(1, "trusted.test")).unwrap();

        let untrusted = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(untrusted.resolve(&q(2, "must-reverify.test")).is_err());
    }

    #[test]
    fn doh_bad_path_is_error() {
        let (addr, trust) = doh_server(Ipv4Addr::new(6, 6, 6, 6));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(addr, "dns.test", "/wrong")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /// An error status is the server's answer to this query; dropping the connection and resending
    /// would repeat the handshake to get the same answer.
    fn doh_error_status_fails_only_that_query() {
        let (addr, trust, accepts, _signatures) = doh_server_ex(Ipv4Addr::new(6, 6, 6, 7), false);
        let results = thread::spawn(move || {
            let request = q(1, "page.test");
            let wire = request.try_encode().unwrap();
            [(); 2].map(|()| {
                exchange(
                    &Endpoint::Direct(addr),
                    "dns.test",
                    "/wrong",
                    &wire,
                    &request,
                    Duration::from_secs(5),
                    &trust,
                )
            })
        })
        .join()
        .unwrap();
        for result in results {
            assert_eq!(
                result.err(),
                Some(ForwardError::Io("DoH non-200 status".into()))
            );
        }
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            1,
            "오류 상태를 받은 연결을 버리고 새로 맺었습니다"
        );
    }

    #[test]
    /// Nothing on this machine can resolve dns.test, so an answer means the proxy did.
    fn doh_through_socks5_lets_the_proxy_resolve_the_name() {
        let (addr, trust, accepts, _signatures) = doh_server_ex(Ipv4Addr::new(9, 9, 8, 1), false);
        let proxy = test_proxy::spawn(Mode::Open, &[("dns.test", addr.ip())]);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh_via(
                Arc::new(Socks5Proxy::new(proxy.addr)),
                "dns.test",
                addr.port(),
                "dns.test",
                "/dns-query",
            )],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        for id in [1, 2] {
            let response = fwd.resolve(&q(id, "proxied.test")).unwrap();
            assert_eq!(response.header.id, id);
            assert_eq!(response.answers.len(), 1);
        }
        assert_eq!(
            proxy.requests(),
            [Request {
                atyp: 3,
                host: "dns.test".into(),
                port: addr.port()
            }],
            "the second query should reuse the pooled tunnel"
        );
        assert_eq!(accepts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn doh_through_socks5_authenticates_and_sends_an_address_as_an_address() {
        let (addr, trust, _accepts, _signatures) = doh_server_ex(Ipv4Addr::new(9, 9, 8, 2), false);
        let proxy = test_proxy::spawn(Mode::Password("user", "secret"), &[]);
        let resolve = |password: &str| {
            Forwarder::with_upstreams(
                vec![Upstream::doh_via(
                    Arc::new(
                        Socks5Proxy::new(proxy.addr).with_credentials("user", password.into()),
                    ),
                    "127.0.0.1",
                    addr.port(),
                    "dns.test",
                    "/dns-query",
                )],
                Duration::from_secs(5),
            )
            .with_trust(trust.clone())
            .resolve(&q(3, "x.test"))
        };

        let wrong = resolve("wrong").unwrap_err();
        assert!(
            wrong
                .to_string()
                .contains("rejected the user name or password"),
            "{wrong}"
        );
        assert_eq!(resolve("secret").unwrap().answers.len(), 1);
        assert_eq!(
            proxy.requests(),
            [Request {
                atyp: 1,
                host: "127.0.0.1".into(),
                port: addr.port()
            }]
        );
    }

    #[test]
    fn doh_through_socks5_reports_a_refused_connection() {
        let proxy = test_proxy::spawn(Mode::Refuse(4), &[]);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh_via(
                Arc::new(Socks5Proxy::new(proxy.addr)),
                "dns.test",
                443,
                "dns.test",
                "/dns-query",
            )],
            Duration::from_secs(5),
        );
        let error = fwd.resolve(&q(1, "x.test")).unwrap_err();
        assert!(error.to_string().contains("host unreachable"), "{error}");
    }

    #[test]
    #[ignore = "네트워크 필요(Cloudflare DoH 실서버)"]
    fn doh_live_cloudflare() {
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh(
                "1.1.1.1:443".parse().unwrap(),
                "cloudflare-dns.com",
                "/dns-query",
            )],
            Duration::from_secs(5),
        );
        let resp = fwd
            .resolve(&q(0x4242, "example.com"))
            .expect("DoH 질의 성공");
        assert!(resp.header.response);
        assert_eq!(resp.header.id, 0x4242, "업스트림이 요청 ID로 복원");
        assert!(
            resp.answers.iter().any(|r| matches!(r.rdata, RData::A(_))),
            "example.com A 레코드가 최소 1개"
        );
    }
}
