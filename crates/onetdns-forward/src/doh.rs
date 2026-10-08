/*!
 * @brief DoH 업스트림: HTTP/2 위의 DNS(RFC 8484).
 */

use std::cell::RefCell;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_http2::{H2Client, H2Error};
use onetdns_proto::Message;
use onetdns_tls::{client_handshake, ClientConfig, TlsSession, TlsStream, TrustStore};

use crate::{validate_response, DeadlineTcp, ForwardError};

/** @brief 보관 중인 DoH 연결 하나. */
struct DohConn {
    /** @brief 이 연결의 HTTP/2 클라이언트. */
    client: H2Client<TlsStream<DeadlineTcp>>,

    /** @brief 관측된 왕복 시간. 재사용 시 PING 대기 시간을 정하는 데 쓴다. */
    rtt_hint: Duration,
}

thread_local! {
    /** @brief (주소, 서버 이름, 경로)별 연결 풀. */
    static POOL: RefCell<LruMap<(SocketAddr, String, String, crate::TlsCacheScope), DohConn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
    /** @brief 끊긴 HTTP/2 연결을 TLS 재개로 빠르게 복구할 세션. */
    static SESSIONS: RefCell<LruMap<(SocketAddr, String, crate::TlsCacheScope), TlsSession>> =
        RefCell::new(LruMap::new(MAX_CACHED_SESSIONS));
}

/** @brief 스레드 하나가 보관할 DoH 연결 수 상한. */
const MAX_POOLED_CONNECTIONS: usize = 256;
/** @brief 스레드 하나가 보관할 최근 DoH 세션 수 상한. */
const MAX_CACHED_SESSIONS: usize = 64;

/**
 * @brief DoH로 질의를 교환한다.
 * @details 재사용 연결에는 PING을 함께 보내 두 단계 데드라인을 만든다. 죽은 연결이면 빨리
 *          포기하고, 살아 있으면 업스트림의 해석 시간을 기다려 준다. 연결이 실패하면 풀에서
 *          빼고 새 연결로 한 번 더 보낸다. 서버가 오류 상태로 답했으면 연결을 그대로 두고 다시
 *          보내지 않는다. 오류 상태는 서버가 내린 답이라 새 연결로 다시 물어도 달라지지 않고,
 *          429 와 503 은 곧바로 다시 묻지 말라는 뜻이기도 하다.
 */
#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange(
    addr: SocketAddr,
    server_name: &str,
    path: &str,
    wire: &[u8],
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    #[cfg(test)]
    let _revocation_test_guard = crate::revocation_test_read_guard();
    let deadline = super::deadline_after(timeout);
    POOL.with(|pool| {
        let scope = crate::tls_cache_scope(trust);
        let key = (addr, server_name.to_string(), path.to_string(), scope);
        let session_key = (addr, server_name.to_string(), scope);

        for attempt in 0..2 {
            let reused = { pool.borrow().contains_key(&key) };
            if !reused {
                let session =
                    SESSIONS.with(|sessions| sessions.borrow().peek(&session_key).cloned());
                let c = connect(addr, server_name, deadline, trust, session)?;
                pool.borrow_mut().put(key.clone(), c);
            }
            let (res, session) = {
                let mut p = pool.borrow_mut();
                let conn = p.get_mut(&key).expect("Just inserted");
                let result = roundtrip(conn, server_name, path, wire, request, deadline);
                let session = conn.client.stream_mut().take_sessions().pop();
                (result, session)
            };
            if let Some(session) = session {
                SESSIONS.with(|sessions| sessions.borrow_mut().put(session_key.clone(), session));
            }
            match res {
                Ok(answer) => return answer,
                Err(e) => {
                    pool.borrow_mut().pop(&key);
                    if reused && attempt == 0 {
                        onetdns_core::debug!(event = "forward.conn_retry",
                            transport = "doh",
                            addr = %addr,
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

/**
 * @brief 새 DoH 연결을 맺는다. 폐기 확인은 핸드셰이크 직후, 질의 전에 한다.
 * @details 훅이 거부한 인증서는 TLS 가 거부했을 때처럼 치명 경고로 서버에 알린다.
 */
fn connect(
    addr: SocketAddr,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
    session: Option<TlsSession>,
) -> Result<DohConn, ForwardError> {
    let started = Instant::now();
    let mut tcp = crate::connect_upstream(addr, deadline).map_err(crate::io_err)?;
    let rtt_hint = started.elapsed();
    let cfg = ClientConfig {
        server_name: server_name.to_string(),
        verify_name: true,
        roots: Some(trust.clone()),
        alpn: vec![b"h2".to_vec()],
        session,
        ..Default::default()
    };
    let mut tls = client_handshake(&mut tcp, &cfg).map_err(|e| {
        crate::note_upstream_connect_failure("doh", addr, server_name, &e);
        ForwardError::Io(format!("DoH handshake: {e}"))
    })?;
    if !tls.is_resumed() {
        crate::check_revocation(tls.verified_chain(), server_name)
            .inspect_err(|_| tls.reject_peer_certificate(&mut tcp))?;
    }
    let stream = TlsStream::new(tls, tcp);
    let client =
        H2Client::connect(stream).map_err(|_| ForwardError::Io("DoH HTTP/2 preface".into()))?;
    Ok(DohConn { client, rtt_hint })
}

/**
 * @brief 연결 하나로 DoH 질의를 보내고 응답을 받는다.
 * @return 바깥 Err 는 이 연결을 더 쓸 수 없다는 뜻이다. 안쪽 Err 는 서버가 이 질의에만 오류
 *         상태로 답했다는 뜻이고, 연결은 그대로 쓸 수 있다.
 */
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
    let answer = conn.client.query_probed(server_name, path, &q, |stream| {
        stream.inner_mut().set_deadline(deadline);
    });
    let body = match answer {
        Ok(body) => body,
        Err(H2Error::BadStatus) => return Ok(Err(ForwardError::Io("DoH non-200 status".into()))),
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
/** @brief 인증서 검증, 연결 재사용, 그리고 죽은 연결에서의 빠른 복구. */
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::thread;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use onetdns_http2::serve_doh;
    use onetdns_proto::{Name, RData, Record, RecordType};
    use onetdns_tls::conn::ServerResumption;
    use onetdns_tls::{server_handshake, signer_from_pkcs8_der, ServerConfig as TlsServerConfig};

    use crate::{Forwarder, Upstream};

    /** @brief 자체 서명 인증서를 쓰는 테스트용 업스트림. */
    fn doh_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _accepts, _signatures) = doh_server_ex(ip, false);
        (addr, trust)
    }

    /** @brief 접속 수와 전체 핸드셰이크 서명 수를 셀 수 있는 테스트용 업스트림. */
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
                        Ok(onetdns_http2::DohAnswer {
                            body: m.try_encode().map_err(|_| "502")?,
                            max_age: 0,
                        })
                    })
                    .ok();
                });
            }
        });
        (addr, trust, accepts_ret, signatures)
    }

    /** @brief 테스트용 질의. */
    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    /** @brief 인증서를 검증하고 연결을 다시 쓰는지. */
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
    /**
     * @brief 폐기 확인이 거부한 인증서를 certificate_unknown 치명 경고로 서버에 알리는지.
     * @details 경고 없이 TCP 만 끊으면 서버는 거부와 중간에서 잘린 연결을 구분하지 못한다.
     */
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
    /** @brief 쉬고 있어도 살아 있으면 다시 쓰는지. */
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
    /** @brief 이미 죽은 연결을 붙잡지 않고 곧바로 다시 잇는지. */
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
    /** @brief 이름이 다른 인증서를 거부하는지. */
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
    /** @brief 믿을 수 없는 인증서를 거부하는지. */
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
    /** @brief 같은 업스트림이라도 더 엄격한 신뢰 정책이 이전 연결·세션을 재사용하지 않는지. */
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
    /** @brief 잘못된 경로가 오류가 되는지. */
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
    /**
     * @brief 오류 상태를 그 질의의 실패로만 다루고 연결은 계속 쓰는지.
     * @details 오류 상태는 서버가 이 질의에 내린 답이라 새 연결로 다시 물어도 달라지지 않는다.
     *          연결을 버리고 다시 보내면 같은 답을 받으려고 핸드셰이크를 한 번 더 한다.
     */
    fn doh_error_status_fails_only_that_query() {
        let (addr, trust, accepts, _signatures) = doh_server_ex(Ipv4Addr::new(6, 6, 6, 7), false);
        let results = thread::spawn(move || {
            let request = q(1, "page.test");
            let wire = request.try_encode().unwrap();
            [(); 2].map(|()| {
                exchange(
                    addr,
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
    #[ignore = "네트워크 필요(Cloudflare DoH 실서버)"]
    /** @brief 실제 공개 업스트림과의 왕복. */
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
