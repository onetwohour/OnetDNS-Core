/*!
 * @brief DoH3 업스트림: HTTP/3 위의 DNS.
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
use onetdns_quic::H3Client;
use onetdns_tls::TrustStore;

use crate::quicdrive::{
    check_peer_revocation, flush_out, harvest_sessions, new_client_connection, pump_handshake,
    recv_once, silence_limit_ms, QuicSocket,
};
use crate::{validate_response, ForwardError};

/** @brief 보관 중인 DoH3 연결 하나. */
struct Doh3Conn {
    /** @brief 이 연결의 소켓. */
    sock: QuicSocket,
    /** @brief 이 연결의 HTTP/3 클라이언트. */
    h3: H3Client,

    /** @brief 이 연결을 연 시각. 너무 오래되면 버린다. */
    created: Instant,
    /** @brief 붙은 서버 이름. */
    server_name: String,
    /** @brief 폐기 확인을 이미 했는지. 연결당 한 번만 한다. */
    revocation_checked: bool,
}

thread_local! {
    /** @brief (주소, 서버 이름, 경로)별 연결 풀. */
    static POOL: RefCell<LruMap<(SocketAddr, String, String, crate::TlsCacheScope), Doh3Conn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
}

/** @brief 스레드 하나가 보관할 DoH3 연결 수 상한. */
const MAX_POOLED_CONNECTIONS: usize = 256;

/** @brief DoH3로 질의를 교환한다. */
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
        let key = (
            addr,
            server_name.to_string(),
            path.to_string(),
            crate::tls_cache_scope(trust),
        );

        for attempt in 0..2 {
            let reused = { pool.borrow().contains_key(&key) };
            if !reused {
                let c = connect(addr, server_name, deadline, trust)?;
                pool.borrow_mut().put(key.clone(), c);
            }
            let res = {
                let mut p = pool.borrow_mut();
                let conn = p.get_mut(&key).expect("Just inserted");
                let r = roundtrip(conn, server_name, path, wire, request, deadline);
                if r.is_ok() {
                    harvest_sessions(conn.h3.conn_mut(), addr, server_name, b"h3", trust);
                }
                r
            };
            match res {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    pool.borrow_mut().pop(&key);
                    if reused && attempt == 0 {
                        onetdns_core::debug!(event = "forward.conn_retry",
                            transport = "doh3",
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

/** @brief 새 DoH3 연결을 맺고 HTTP/3 제어 스트림까지 준비한다. */
fn connect(
    addr: SocketAddr,
    server_name: &str,
    deadline: Instant,
    trust: &TrustStore,
) -> Result<Doh3Conn, ForwardError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ForwardError::Timeout)?;
    let created = Instant::now();
    let (sock, conn) = new_client_connection(addr, server_name, b"h3", timeout, trust)?;
    let mut h3 = H3Client::new(conn);

    if !h3.can_send_early() {
        pump_handshake(&sock, &mut h3, created, deadline).inspect_err(|error| {
            crate::note_upstream_connect_failure("doh3", addr, server_name, error);
        })?;
    }
    Ok(Doh3Conn {
        sock,
        h3,
        created,
        server_name: server_name.to_string(),
        revocation_checked: false,
    })
}

/** @brief HTTP/3 요청 하나로 질의를 보내고 응답을 받는다. */
fn roundtrip(
    c: &mut Doh3Conn,
    authority: &str,
    path: &str,
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

    c.h3.set_now(c.created.elapsed().as_millis() as u64);
    c.h3.on_timeout(c.created.elapsed().as_millis() as u64);
    if c.h3.is_closed() {
        return Err(ForwardError::Io("DoH3 connection closed after idle".into()));
    }

    check_peer_revocation(c.h3.conn_mut(), &c.server_name, &mut c.revocation_checked)?;

    c.h3.set_now(c.created.elapsed().as_millis() as u64);
    let sid =
        c.h3.send_request(authority, path, &q)
            .map_err(|error| ForwardError::Io(format!("DoH3 request send: {error}")))?;
    flush_out(&c.sock, &mut c.h3)?;

    let silence_limit = Duration::from_millis(silence_limit_ms(c.h3.conn_mut().base_pto_ms()));
    let mut last_rx = Instant::now();
    let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
    while Instant::now() < deadline {
        if c.h3.is_closed() {
            return Err(ForwardError::Io("DoH3 connection closed".into()));
        }
        c.h3.set_now(c.created.elapsed().as_millis() as u64);
        if recv_once(&c.sock, &mut c.h3, &mut buf)? {
            last_rx = Instant::now();
        } else {
            c.h3.on_timeout(c.created.elapsed().as_millis() as u64);
            if last_rx.elapsed() >= silence_limit {
                return Err(ForwardError::Io(
                    "DoH3 transport unresponsive; path considered dead".into(),
                ));
            }
        }
        flush_out(&c.sock, &mut c.h3)?;

        check_peer_revocation(c.h3.conn_mut(), &c.server_name, &mut c.revocation_checked)?;
        for (rid, status, body) in c.h3.take_responses() {
            if rid == sid {
                if status != 200 {
                    return Err(ForwardError::Io(format!("DoH3 non-200 status: {status}")));
                }
                let resp = Message::parse(&body).map_err(|_| ForwardError::BadResponse)?;
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
    use onetdns_quic::{Connection, H3Connection};
    use onetdns_tls::{signer_from_pkcs8_der, ServerConfig};

    use crate::quicdrive::random_cid;
    use crate::{Forwarder, Upstream};

    /** @brief 자체 서명 인증서를 쓰는 테스트용 업스트림. */
    fn doh3_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _peers) = doh3_server_ex(ip, false);
        (addr, trust)
    }

    /** @brief 접속 수를 셀 수 있는 테스트용 업스트림. */
    fn doh3_server_ex(
        ip: Ipv4Addr,
        one_shot: bool,
    ) -> (SocketAddr, Arc<TrustStore>, Arc<AtomicUsize>) {
        let ck = rcgen::generate_simple_self_signed(vec!["dns.test".to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.key_pair.serialize_der();
        let trust = Arc::new(TrustStore::from_ders([cert_der.as_slice()]));
        let (scheme, sign) = signer_from_pkcs8_der(&key_der).unwrap();
        let scfg = Arc::new(ServerConfig {
            cert_chain: vec![cert_der],
            sign_scheme: scheme,
            sign,
            alpn: vec![b"h3".to_vec()],
            client_ca: None,
            resumption: None,
        });

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let peers = Arc::new(AtomicUsize::new(0));
        let peers_ret = peers.clone();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, H3Connection> = HashMap::new();
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
                let h3c = conns.entry(peer).or_insert_with(|| {
                    peers.fetch_add(1, Ordering::Relaxed);
                    H3Connection::new(Connection::new_server(
                        scfg.clone(),
                        random_cid(),
                        base_tp.clone(),
                    ))
                });
                if h3c.recv_datagram(&buf[..n]).is_err() {
                    conns.remove(&peer);
                    continue;
                }
                for (sid, qbytes) in h3c.take_requests() {
                    if let Ok(req) = Message::parse(&qbytes) {
                        let mut m = Message::default();
                        m.header.id = req.header.id;
                        m.header.response = true;
                        m.header.recursion_available = true;
                        m.questions = req.questions.clone();
                        if let Some(qq) = req.questions.first() {
                            m.answers
                                .push(Record::new(qq.name.clone(), 60, RData::A(ip)));
                        }
                        h3c.send_response(sid, &m.try_encode().unwrap(), 0).unwrap();
                        if one_shot {
                            spent.insert(peer);
                        }
                    }
                }
                while let Some(dg) = h3c.next_datagram() {
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
    fn doh3_forward_verified_and_reuses_connection() {
        let (addr, trust) = doh3_server(Ipv4Addr::new(4, 4, 4, 4));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        let r1 = fwd.resolve(&q(0xABCD, "secure.test")).unwrap();
        assert_eq!(r1.header.id, 0xABCD);
        assert_eq!(r1.answers.len(), 1);
        match &r1.answers[0].rdata {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(4, 4, 4, 4)),
            o => panic!("A 기대, {o:?}"),
        }

        let r2 = fwd.resolve(&q(0x2222, "again.test")).unwrap();
        assert_eq!(r2.header.id, 0x2222);
        assert_eq!(r2.answers.len(), 1);
    }

    #[test]
    /** @brief 쉬고 있어도 살아 있으면 다시 쓰는지. */
    fn doh3_idle_alive_connection_is_reused() {
        let (addr, trust, peers) = doh3_server_ex(Ipv4Addr::new(7, 7, 7, 7), false);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);

        fwd.resolve(&q(0x1, "a.test")).unwrap();
        assert_eq!(peers.load(Ordering::Relaxed), 1);
        std::thread::sleep(Duration::from_millis(120));
        let r = fwd.resolve(&q(0x2, "b.test")).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(peers.load(Ordering::Relaxed), 1, "유휴 후에도 재사용");
    }

    #[test]
    /** @brief 이미 죽은 연결을 붙잡지 않고 곧바로 다시 잇는지. */
    fn doh3_reused_zombie_fails_fast_then_reconnects() {
        let (addr, trust, peers) = doh3_server_ex(Ipv4Addr::new(8, 8, 8, 8), true);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
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
    /** @brief 믿을 수 없는 인증서를 거부하는지. */
    fn doh3_rejects_untrusted_cert() {
        let (addr, _trust) = doh3_server(Ipv4Addr::new(6, 6, 6, 6));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
    }

    #[test]
    /** @brief 같은 업스트림이라도 더 엄격한 신뢰 정책이 이전 QUIC 연결·세션을 재사용하지 않는지. */
    fn doh3_cache_is_scoped_to_trust_policy() {
        let (addr, trust) = doh3_server(Ipv4Addr::new(6, 6, 6, 7));
        let trusted = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(trust);
        trusted.resolve(&q(1, "trusted.test")).unwrap();

        let untrusted = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(untrusted.resolve(&q(2, "must-reverify.test")).is_err());
    }

    #[test]
    #[ignore = "네트워크 필요(Cloudflare DoH3 실서버 상호운용성 테스트)"]
    /** @brief 실제 공개 업스트림과의 왕복. */
    fn doh3_live_cloudflare() {
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(
                "1.1.1.1:443".parse().unwrap(),
                "cloudflare-dns.com",
                "/dns-query",
            )],
            Duration::from_secs(8),
        );
        let resp = fwd
            .resolve(&q(0x4242, "example.com"))
            .expect("DoH3 질의 성공");
        assert!(resp.header.response);
        assert_eq!(resp.header.id, 0x4242);
        assert!(
            resp.answers.iter().any(|r| matches!(r.rdata, RData::A(_))),
            "A 레코드"
        );
    }
}
