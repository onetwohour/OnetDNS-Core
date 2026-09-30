/*!
 * @brief DoQ 업스트림: QUIC 위의 DNS(RFC 9250).
 *
 * @details 질의마다 새 양방향 스트림을 연다. 스트림이 독립이라 하나가 막혀도 다른 질의가
 *          밀리지 않는 것이 TCP 기반 전송과 다른 점이다.
 */

use std::cell::RefCell;
#[cfg(test)]
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(test)]
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_proto::Message;
use onetdns_quic::Connection;
use onetdns_tls::TrustStore;

use crate::quicdrive::{
    check_peer_revocation, flush_out, harvest_sessions, new_client_connection, pump_handshake,
    recv_once, silence_limit_ms, QuicSocket,
};
use crate::{validate_response, ForwardError};

/** @brief 보관 중인 DoQ 연결 하나. */
struct DoqConn {
    /** @brief 이 연결의 소켓. */
    sock: QuicSocket,
    /** @brief 이 연결의 QUIC 상태 기계. */
    conn: Connection,

    /** @brief 다음에 열 클라이언트 양방향 스트림 번호. */
    next_bidi: u64,

    /** @brief 이 연결을 연 시각. 너무 오래되면 버린다. */
    created: Instant,
    /** @brief 붙은 서버 이름. */
    server_name: String,
    /** @brief 폐기 확인을 이미 했는지. 연결당 한 번만 한다. */
    revocation_checked: bool,
}

thread_local! {
    /** @brief (주소, 서버 이름)별 연결 풀. */
    static POOL: RefCell<LruMap<(SocketAddr, String, crate::TlsCacheScope), DoqConn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
}

/** @brief 스레드 하나가 보관할 DoQ 연결 수 상한. */
const MAX_POOLED_CONNECTIONS: usize = 256;

/** @brief DoQ로 질의를 교환한다. 보관된 연결이 있으면 재사용한다. */
pub(crate) fn exchange(
    addr: SocketAddr,
    server_name: &str,
    wire: &[u8],
    request: &Message,
    timeout: Duration,
    trust: &TrustStore,
) -> Result<Message, ForwardError> {
    #[cfg(test)]
    let _revocation_test_guard = crate::revocation_test_read_guard();
    let deadline = super::deadline_after(timeout);
    POOL.with(|pool| {
        let key = (addr, server_name.to_string(), crate::tls_cache_scope(trust));

        for attempt in 0..2 {
            let reused = { pool.borrow().contains_key(&key) };
            if !reused {
                let c = connect(addr, server_name, deadline, trust)?;
                pool.borrow_mut().put(key.clone(), c);
            }
            let res = {
                let mut p = pool.borrow_mut();
                let conn = p.get_mut(&key).expect("Just inserted");
                let r = roundtrip(conn, wire, request, deadline);
                if r.is_ok() {
                    harvest_sessions(&mut conn.conn, addr, server_name, b"doq", trust);
                }
                r
            };
            match res {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    pool.borrow_mut().pop(&key);
                    if reused && attempt == 0 {
                        onetdns_core::debug!(event = "forward.conn_retry",
                            transport = "doq",
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

/** @brief 새 DoQ 연결을 맺고 핸드셰이크를 끝낸다. */
fn connect(
    addr: SocketAddr,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
) -> Result<DoqConn, ForwardError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ForwardError::Timeout)?;
    let created = Instant::now();
    let (sock, mut conn) = new_client_connection(addr, server_name, b"doq", timeout, trust)?;

    if !conn.can_send_early() {
        pump_handshake(&sock, &mut conn, created, deadline).inspect_err(|error| {
            crate::note_upstream_connect_failure("doq", addr, server_name, error);
        })?;
    }
    Ok(DoqConn {
        sock,
        conn,
        next_bidi: 0,
        created,
        server_name: server_name.to_string(),
        revocation_checked: false,
    })
}

/**
 * @brief 스트림 하나를 열어 질의를 보내고 응답을 받는다.
 * @note DoQ 메시지는 트랜잭션 ID를 0으로 보낸다(RFC 9250). 스트림이 이미 질의와 응답을
 *       짝지어 주므로 ID가 필요 없고, 남겨 두면 연결 지문이 된다.
 */
fn roundtrip(
    c: &mut DoqConn,
    wire: &[u8],
    request: &Message,
    deadline: Instant,
) -> Result<Message, ForwardError> {
    if wire.len() > 0xffff {
        return Err(ForwardError::BadResponse);
    }

    let mut q = wire.to_vec();
    q[0] = 0;
    q[1] = 0;

    c.conn.set_now(c.created.elapsed().as_millis() as u64);
    c.conn.on_timeout(c.created.elapsed().as_millis() as u64);
    if c.conn.is_closed() {
        return Err(ForwardError::Io("Idle DoQ connection closed".into()));
    }

    check_peer_revocation(&c.conn, &c.server_name, &mut c.revocation_checked)?;

    let sid = c.next_bidi << 2;
    c.conn.set_now(c.created.elapsed().as_millis() as u64);
    c.conn
        .send_dns_message(sid, &q)
        .map_err(|error| ForwardError::Io(format!("Could not send DoQ request: {error}")))?;
    c.next_bidi += 1;
    flush_out(&c.sock, &mut c.conn)?;

    let silence_limit = Duration::from_millis(silence_limit_ms(c.conn.base_pto_ms()));
    let mut last_rx = Instant::now();
    let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
    while Instant::now() < deadline {
        if c.conn.is_closed() {
            return Err(ForwardError::Io("DoQ server closed the connection".into()));
        }
        c.conn.set_now(c.created.elapsed().as_millis() as u64);
        if recv_once(&c.sock, &mut c.conn, &mut buf)? {
            last_rx = Instant::now();
        } else {
            c.conn.on_timeout(c.created.elapsed().as_millis() as u64);
            if last_rx.elapsed() >= silence_limit {
                return Err(ForwardError::Io(
                    "No response on the DoQ connection; server marked unavailable".into(),
                ));
            }
        }
        flush_out(&c.sock, &mut c.conn)?;

        check_peer_revocation(&c.conn, &c.server_name, &mut c.revocation_checked)?;
        if c.conn
            .take_resets()
            .iter()
            .any(|(stream_id, _)| *stream_id == sid)
        {
            return Err(ForwardError::Io(
                "DoQ server reset the request stream".into(),
            ));
        }
        for (rid, dns) in c.conn.take_stream_requests() {
            if rid == sid {
                let resp = Message::parse(&dns).map_err(|_| ForwardError::BadResponse)?;
                validate_response(request, &resp, Some(0))?;
                return Ok(resp);
            }
        }
    }
    Err(ForwardError::Timeout)
}

#[cfg(test)]
/** @brief 인증서 검증, 연결 재사용, 그리고 죽은 연결에서의 빠른 복구. */
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::thread;

    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use onetdns_proto::{Name, RData, Record, RecordType};
    use onetdns_quic::params::TransportParams;
    use onetdns_tls::{signer_from_pkcs8_der, ServerConfig};

    use crate::quicdrive::random_cid;
    use crate::{Forwarder, Upstream};

    /** @brief 자체 서명 인증서를 쓰는 테스트용 업스트림. */
    fn doq_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _peers) = doq_server_ex(ip, false, "dns.test");
        (addr, trust)
    }

    /** @brief 접속 수를 셀 수 있는 테스트용 업스트림. */
    fn doq_server_ex(
        ip: Ipv4Addr,
        one_shot: bool,
        name: &str,
    ) -> (SocketAddr, Arc<TrustStore>, Arc<AtomicUsize>) {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let trust = Arc::new(TrustStore::from_ders([cert_der.as_slice()]));
        let (scheme, sign) = signer_from_pkcs8_der(&key_der).unwrap();
        let scfg = Arc::new(ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: scheme,
            sign,
            alpn: vec![b"doq".to_vec()],
            client_ca: None,

            resumption: Some(onetdns_tls::conn::ServerResumption::secure_default()),
        });

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let peers = Arc::new(AtomicUsize::new(0));
        let peers_ret = peers.clone();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, Connection> = HashMap::new();
            let mut spent: HashSet<SocketAddr> = HashSet::new();
            let base_tp = TransportParams::server_defaults();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                if one_shot && spent.contains(&peer) {
                    continue;
                }
                let conn = conns.entry(peer).or_insert_with(|| {
                    peers.fetch_add(1, Ordering::Relaxed);
                    Connection::new_server(scfg.clone(), random_cid(), base_tp.clone())
                });
                if conn.recv_datagram(&buf[..n]).is_err() {
                    conns.remove(&peer);
                    continue;
                }
                for (sid, q) in conn.take_stream_requests() {
                    if let Ok(req) = Message::parse(&q) {
                        let mut m = Message::default();
                        m.header.id = req.header.id;
                        m.header.response = true;
                        m.header.recursion_available = true;
                        m.questions = req.questions.clone();
                        if let Some(qq) = req.questions.first() {
                            m.answers
                                .push(Record::new(qq.name.clone(), 60, RData::A(ip)));
                        }
                        conn.send_dns_message(sid, &m.try_encode().unwrap())
                            .unwrap();
                        if one_shot {
                            spent.insert(peer);
                        }
                    }
                }
                while let Some(dg) = conn.next_datagram() {
                    let _ = sock.send_to(&dg, peer);
                }
            }
        });
        (addr, trust, peers_ret)
    }

    /** @brief 테스트용 질의. */
    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
    /** @brief 인증서를 검증하고 연결을 다시 쓰는지. */
    fn doq_forward_verified_and_reuses_connection() {
        let (addr, trust) = doq_server(Ipv4Addr::new(3, 3, 3, 3));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
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
    /** @brief 쉬고 있어도 살아 있으면 다시 쓰는지. */
    fn doq_idle_alive_connection_is_reused() {
        let (addr, trust, peers) = doq_server_ex(Ipv4Addr::new(7, 7, 7, 7), false, "dns.test");
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "a.test")).unwrap();
        assert_eq!(peers.load(Ordering::Relaxed), 1, "첫 질의는 새 연결 1개");
        std::thread::sleep(Duration::from_millis(120));
        let r = fwd.resolve(&q(0x2, "b.test")).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(peers.load(Ordering::Relaxed), 1, "유휴 후에도 재사용");
    }

    #[test]
    /** @brief 이미 죽은 연결을 붙잡지 않고 곧바로 다시 잇는지. */
    fn doq_reused_zombie_fails_fast_then_reconnects() {
        let (addr, trust, peers) = doq_server_ex(Ipv4Addr::new(8, 8, 8, 8), true, "dns.test");
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "first.test")).unwrap();
        assert_eq!(peers.load(Ordering::Relaxed), 1);

        let start = Instant::now();
        let r = fwd.resolve(&q(0x2, "second.test")).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.header.id, 0x2);
        assert_eq!(peers.load(Ordering::Relaxed), 2, "좀비 실패 후 새 연결");
        assert!(
            elapsed < Duration::from_secs(2),
            "5초 데드라인을 소진하지 않아야 함: {elapsed:?}"
        );
    }

    #[test]
    /** @brief 같은 연결로 잇달아 물어도 모두 답을 받는지. */
    fn doq_many_sequential_reuses_all_succeed() {
        let (addr, trust) = doq_server(Ipv4Addr::new(2, 2, 2, 2));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        for i in 0..8u16 {
            let r = fwd.resolve(&q(0x100 + i, "loop.test")).unwrap();
            assert_eq!(r.header.id, 0x100 + i);
            assert_eq!(r.answers.len(), 1);
        }
    }

    #[test]
    /** @brief 폐기 확인 훅이 실제로 걸리는지. */
    fn doq_enforces_revocation_hook() {
        let _revocation_test_guard = crate::revocation_test_write_guard();
        let (addr, trust, _) = doq_server_ex(Ipv4Addr::new(4, 4, 4, 4), false, "revoke.test");
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "revoke.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        fwd.resolve(&q(0x8, "before-policy-change.test")).unwrap();

        crate::set_revocation_hook(Box::new(|chain, host| {
            if host == "revoke.test" && !chain.is_empty() {
                Err("폐기됨".to_string())
            } else {
                Ok(())
            }
        }));
        let res = fwd.resolve(&q(0x9, "x.test"));
        crate::clear_revocation_hook();
        assert!(
            res.is_err(),
            "폐기 정책이 바뀌면 이전 QUIC 연결·세션을 버리고 새 훅을 적용해야"
        );
    }

    #[test]
    /** @brief 믿을 수 없는 인증서를 거부하는지. */
    fn doq_rejects_untrusted_cert() {
        let (addr, _trust) = doq_server(Ipv4Addr::new(5, 5, 5, 5));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /** @brief 같은 업스트림이라도 더 엄격한 신뢰 정책이 이전 QUIC 연결·세션을 재사용하지 않는지. */
    fn doq_cache_is_scoped_to_trust_policy() {
        let (addr, trust) = doq_server(Ipv4Addr::new(5, 5, 5, 6));
        let trusted = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        trusted.resolve(&q(1, "trusted.test")).unwrap();

        let untrusted = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(untrusted.resolve(&q(2, "must-reverify.test")).is_err());
    }

    #[test]
    #[ignore = "네트워크 필요(AdGuard DoQ 실서버 상호운용성 테스트)"]
    /** @brief 실제 공개 업스트림과의 왕복. */
    fn doq_live_adguard() {
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(
                "94.140.14.14:853".parse().unwrap(),
                "dns.adguard-dns.com",
            )],
            Duration::from_secs(8),
        );
        let resp = fwd
            .resolve(&q(0x4242, "example.com"))
            .expect("DoQ 질의 성공");
        assert!(resp.header.response);
        assert_eq!(resp.header.id, 0x4242);
        assert!(
            resp.answers.iter().any(|r| matches!(r.rdata, RData::A(_))),
            "A 레코드"
        );
    }

    #[test]
    /** @brief 담아 둔 세션으로 왕복 없이 이어 붙는지. */
    fn doq_resumes_with_cached_session_and_zero_rtt() {
        let (addr, trust) = doq_server(Ipv4Addr::new(9, 9, 9, 9));

        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust.clone());
        let r1 = fwd.resolve(&q(0x1001, "first.test")).unwrap();
        assert_eq!(r1.answers.len(), 1);
        assert!(
            crate::quicdrive::cached_session(addr, "dns.test", b"doq", trust.as_ref()).is_some(),
            "첫 연결에서 세션 티켓이 캐시되어야"
        );

        let trust2 = trust.clone();
        let handle = thread::spawn(move || {
            let fwd2 = Forwarder::with_upstreams(
                vec![Upstream::doq(addr, "dns.test")],
                Duration::from_secs(5),
            )
            .with_trust(trust2);
            fwd2.resolve(&q(0x1002, "resumed.test"))
                .expect("재개 연결 질의 성공")
        });
        let r2 = handle.join().unwrap();
        assert_eq!(r2.header.id, 0x1002);
        assert_eq!(r2.answers.len(), 1);
        match &r2.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(9, 9, 9, 9)),
            o => panic!("A 기대, {o:?}"),
        }
    }
}
