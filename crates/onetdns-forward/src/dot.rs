/*!
 * @brief DoT 업스트림: TLS 위의 DNS(RFC 7858).
 *
 * @details 연결을 스레드 지역 풀에 보관해 재사용한다. 핸드셰이크는 비싸므로, 질의마다
 *          새로 맺으면 DoT가 평문 대비 크게 느려진다.
 */

use std::cell::RefCell;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_proto::Message;
use onetdns_tls::{client_handshake, ClientConfig, TlsConnection, TlsSession, TrustStore};

use crate::{validate_response, DeadlineTcp, ForwardError};

/** @brief 보관 중인 DoT 연결 하나. */
struct DotConn {
    /** @brief 이 연결의 스트림. */
    tcp: DeadlineTcp,
    /** @brief 그 위의 TLS 상태. */
    tls: TlsConnection,

    /** @brief 읽기 버퍼. 연결과 함께 살아 있어 질의마다 다시 잡지 않는다. */
    buf: Vec<u8>,

    /** @brief 마지막 사용 시각. 너무 오래된 연결은 재사용하지 않는다. */
    last_used: Instant,
}

thread_local! {
    /** @brief (주소, 서버 이름)별 연결 풀. 스레드 지역이라 잠금이 없다. */
    static POOL: RefCell<LruMap<(SocketAddr, String, crate::TlsCacheScope), DotConn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
    /** @brief 끊긴 연결을 PSK-DHE로 다시 붙일 최근 세션. */
    static SESSIONS: RefCell<LruMap<(SocketAddr, String, crate::TlsCacheScope), TlsSession>> =
        RefCell::new(LruMap::new(MAX_CACHED_SESSIONS));
}

/** @brief 스레드 하나가 보관할 DoT 연결 수 상한. */
const MAX_POOLED_CONNECTIONS: usize = 256;
/** @brief 스레드 하나가 보관할 최근 DoT 세션 수 상한. */
const MAX_CACHED_SESSIONS: usize = 64;

/**
 * @brief DoT로 질의를 교환한다.
 * @details 보관된 연결이 있으면 짧은 데드라인으로 먼저 시도한다. 죽은 연결에 예산을 다 쓰지
 *          않고 새 연결로 넘어가기 위해서다.
 */
pub(crate) fn exchange(
    addr: SocketAddr,
    server_name: &str,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    #[cfg(test)]
    let _revocation_test_guard = crate::revocation_test_read_guard();
    let deadline = super::deadline_after(timeout);
    POOL.with(|pool| {
        let key = (addr, server_name.to_string(), crate::tls_cache_scope(trust));

        let idle = { pool.borrow().peek(&key).map(|c| c.last_used.elapsed()) };
        if idle.is_some_and(|idle| idle >= super::tcp_idle_reuse_max()) {
            pool.borrow_mut().pop(&key);
            onetdns_core::debug!(event = "forward.conn_idle_closed",
                transport = "dot",
                addr = %addr,
                idle_ms = idle.unwrap_or_default().as_millis() as u64,
                "Closed an idle pooled connection"
            );
        }

        for attempt in 0..2 {
            let reused = { pool.borrow().contains_key(&key) };
            if !reused {
                let session = SESSIONS.with(|sessions| sessions.borrow().peek(&key).cloned());
                let c = connect(addr, server_name, deadline, trust, session)?;
                pool.borrow_mut().put(key.clone(), c);
            }
            let rt_deadline = if reused && attempt == 0 {
                super::bounded_first_try(deadline)
            } else {
                deadline
            };
            let (res, session) = {
                let mut p = pool.borrow_mut();
                let conn = p.get_mut(&key).expect("Just inserted");
                let r = roundtrip(conn, wire, wire_id, request, rt_deadline);
                if r.is_ok() {
                    conn.last_used = Instant::now();
                }
                (r, conn.tls.take_sessions().pop())
            };
            if let Some(session) = session {
                SESSIONS.with(|sessions| sessions.borrow_mut().put(key.clone(), session));
            }
            match res {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    pool.borrow_mut().pop(&key);
                    if reused && attempt == 0 {
                        onetdns_core::debug!(event = "forward.conn_retry",
                            transport = "dot",
                            addr = %addr,
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
 * @brief 새 DoT 연결을 맺는다.
 * @details TLS 핸드셰이크 직후, 질의를 보내기 전에 폐기 확인 훅을 부른다. 순서를
 *          바꾸면 폐기된 인증서를 쓰는 서버에 질의가 이미 나간 뒤가 된다. 훅이 거부한 인증서는
 *          TLS 가 거부했을 때처럼 치명 경고로 서버에 알린다.
 */
fn connect(
    addr: SocketAddr,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
    session: Option<TlsSession>,
) -> Result<DotConn, ForwardError> {
    let mut tcp = crate::connect_upstream(addr, deadline).map_err(crate::io_err)?;
    let cfg = ClientConfig {
        server_name: server_name.to_string(),
        verify_name: true,
        roots: Some(trust.clone()),
        alpn: vec![b"dot".to_vec()],
        session,
        ..Default::default()
    };
    let mut tls = client_handshake(&mut tcp, &cfg).map_err(|e| {
        crate::note_upstream_connect_failure("dot", addr, server_name, &e);
        ForwardError::Io(format!("DoT handshake failed: {e}"))
    })?;
    if !tls.is_resumed() {
        crate::check_revocation(tls.verified_chain(), server_name)
            .inspect_err(|_| tls.reject_peer_certificate(&mut tcp))?;
    }
    Ok(DotConn {
        tcp,
        tls,
        buf: Vec::new(),
        last_used: Instant::now(),
    })
}

/** @brief 연결 하나로 질의를 보내고 응답을 받는다. 2바이트 길이 접두사 프레이밍이다. */
fn roundtrip(
    conn: &mut DotConn,
    wire: &[u8],
    wire_id: u16,
    request: &Message,
    deadline: Instant,
) -> Result<Message, ForwardError> {
    if wire.len() > 0xffff {
        return Err(ForwardError::BadResponse);
    }
    let mut framed = Vec::with_capacity(2 + wire.len());
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    conn.tcp.set_deadline(deadline);
    conn.tls.write_app(&mut conn.tcp, &framed).map_err(tls_io)?;

    let lenb = read_n(conn, 2, deadline)?;
    let rlen = u16::from_be_bytes([lenb[0], lenb[1]]) as usize;
    let rbuf = read_n(conn, rlen, deadline)?;
    let resp = Message::parse(&rbuf).map_err(|_| ForwardError::BadResponse)?;
    validate_response(request, &resp, Some(wire_id))?;
    Ok(resp)
}

/** @brief 데드라인 안에서 n바이트를 읽는다. */
fn read_n(conn: &mut DotConn, n: usize, deadline: Instant) -> Result<Vec<u8>, ForwardError> {
    while conn.buf.len() < n {
        conn.tcp.set_deadline(deadline);
        let chunk = conn.tls.read_app(&mut conn.tcp).map_err(tls_io)?;
        if chunk.is_empty() {
            return Err(ForwardError::Io("DoT server closed the connection".into()));
        }
        conn.buf.extend_from_slice(&chunk);
    }
    let out = conn.buf[..n].to_vec();
    conn.buf.drain(..n);
    Ok(out)
}

/**
 * @brief TLS 오류를 전달 오류로 바꾼다.
 * @note 상세 사유를 밖으로 흘리지 않는다. 어떤 검증에서 걸렸는지가 응답 차이로 드러나면
 *       상대가 그것을 신탁으로 삼을 수 있다.
 */
fn tls_io(_e: onetdns_tls::TlsError) -> ForwardError {
    ForwardError::Io("I/O error on the DoT TLS connection".into())
}

#[cfg(test)]
/** @brief 인증서 검증, 연결 재사용, 그리고 죽은 연결에서의 빠른 복구. */
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use onetdns_proto::{Name, RData, Record, RecordType};
    use onetdns_tls::conn::ServerResumption;
    use onetdns_tls::{server_handshake, signer_from_pkcs8_der, ServerConfig as TlsServerConfig};

    use crate::{Forwarder, Upstream};

    /** @brief 자체 서명 인증서를 쓰는 테스트용 업스트림. */
    fn dot_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _accepts, _signatures) = dot_server_ex(ip);
        (addr, trust)
    }

    /** @brief 접속 수와 전체 핸드셰이크 서명 수를 셀 수 있는 테스트용 업스트림. */
    fn dot_server_ex(
        ip: Ipv4Addr,
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
            alpn: vec![b"dot".to_vec()],
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
                    let Ok(mut conn) = server_handshake(&mut s, &cfg) else {
                        return;
                    };
                    let mut buf: Vec<u8> = Vec::new();
                    loop {
                        if !fill(&mut conn, &mut s, &mut buf, 2) {
                            return;
                        }
                        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        buf.drain(..2);
                        if !fill(&mut conn, &mut s, &mut buf, len) {
                            return;
                        }
                        let q: Vec<u8> = buf.drain(..len).collect();
                        let Ok(req) = Message::parse(&q) else { return };
                        let mut m = Message::default();
                        m.header.id = req.header.id;
                        m.header.response = true;
                        m.header.recursion_available = true;
                        m.questions = req.questions.clone();
                        if let Some(qq) = req.questions.first() {
                            m.answers
                                .push(Record::new(qq.name.clone(), 60, RData::A(ip)));
                        }
                        let out = m.try_encode().unwrap();
                        let mut framed = (out.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&out);
                        if conn.write_app(&mut s, &framed).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, trust, accepts_ret, signatures)
    }

    /** @brief 이만큼 읽힐 때까지 채운다. */
    fn fill(conn: &mut TlsConnection, s: &mut TcpStream, buf: &mut Vec<u8>, n: usize) -> bool {
        while buf.len() < n {
            match conn.read_app(s) {
                Ok(c) if !c.is_empty() => buf.extend_from_slice(&c),
                _ => return false,
            }
        }
        true
    }

    /** @brief 테스트용 질의. */
    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    /** @brief 인증서를 검증하고 연결을 다시 쓰는지. */
    fn dot_forward_verified_and_reuses_connection() {
        let (addr, trust) = dot_server(Ipv4Addr::new(3, 3, 3, 3));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
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
    /** @brief 오래 쉰 연결을 버리는지. */
    fn dot_drops_idle_pooled_connection() {
        crate::set_reuse_caps_for_test(Duration::from_millis(1500), Duration::from_millis(30));
        let (addr, trust, accepts, signatures) = dot_server_ex(Ipv4Addr::new(7, 7, 7, 7));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "a.test")).unwrap();
        std::thread::sleep(Duration::from_millis(45));
        let r = fwd.resolve(&q(0x2, "b.test")).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            2,
            "유휴 초과 → 재사용 대신 새 TCP 연결"
        );
        assert_eq!(
            signatures.load(Ordering::Relaxed),
            1,
            "두 번째 연결은 TLS 1.3 PSK-DHE 재개라 인증서 서명이 없어야 함"
        );
        crate::clear_reuse_caps_for_test();
    }

    #[test]
    /**
     * @brief 폐기 확인이 거부한 인증서를 certificate_unknown 치명 경고로 서버에 알리는지.
     * @details 경고 없이 TCP 만 끊으면 서버는 거부와 중간에서 잘린 연결을 구분하지 못한다.
     */
    fn dot_revocation_rejection_is_reported_to_the_server() {
        let _revocation_test_guard = crate::revocation_test_write_guard();
        let (addr, trust, reads) = crate::tls_first_read_recorder(b"dot");
        crate::set_revocation_hook(Box::new(|_, host| {
            if host == "dns.test" {
                Err("폐기됨".to_string())
            } else {
                Ok(())
            }
        }));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
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
    /** @brief 이름이 다른 인증서를 거부하는지. */
    fn dot_rejects_wrong_server_name() {
        let (addr, trust) = dot_server(Ipv4Addr::new(4, 4, 4, 4));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "evil.test")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /** @brief 믿을 수 없는 인증서를 거부하는지. */
    fn dot_rejects_untrusted_cert() {
        let (addr, _trust) = dot_server(Ipv4Addr::new(5, 5, 5, 5));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /** @brief 같은 업스트림이라도 더 엄격한 신뢰 정책이 이전 연결·세션을 재사용하지 않는지. */
    fn dot_cache_is_scoped_to_trust_policy() {
        let (addr, trust) = dot_server(Ipv4Addr::new(5, 5, 5, 6));
        let trusted = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        trusted.resolve(&q(1, "trusted.test")).unwrap();

        let untrusted = Forwarder::with_upstreams(
            vec![Upstream::dot(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(untrusted.resolve(&q(2, "must-reverify.test")).is_err());
    }
}
