//! DNS over QUIC upstream (RFC 9250). Each query opens a new bidirectional stream, so unlike TCP
//! transports one stalled query does not hold up the others.

use std::cell::RefCell;
#[cfg(test)]
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(test)]
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_proto::Message;
use onetdns_quic::{doq, Connection};
use onetdns_tls::TrustStore;

use crate::quicdrive::{
    check_peer_revocation, flush_out, harvest_sessions, new_client_connection, pump_handshake,
    recv_once, silence_limit_ms, QuicSocket,
};
use crate::{validate_response, ForwardError};

pub(crate) struct DoqConn {
    sock: QuicSocket,
    conn: Connection,

    next_bidi: u64,

    /// Too old connections are dropped.
    created: Instant,
    server_name: String,
    /// Checked once per connection.
    revocation_checked: bool,
}

impl Drop for DoqConn {
    /// Tells the server the connection is going away, whichever way it is dropped: error, timeout,
    /// silence, LRU eviction, or thread exit. An open connection closes with no error code; a
    /// closed one sends only its queued close frame. The socket closes too, so there is no wait for
    /// the closing period. Without the notice, the server holds the connection until its own idle
    /// deadline.
    fn drop(&mut self) {
        if !self.conn.is_closed() {
            self.conn.close(doq::NO_ERROR, "");
        }
        let _ = flush_out(&self.sock, &mut self.conn);
    }
}

thread_local! {
    static POOL: RefCell<LruMap<(SocketAddr, String, crate::TlsCacheScope), DoqConn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
}

const MAX_POOLED_CONNECTIONS: usize = 256;

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
    let (sock, conn) = new_client_connection(addr, server_name, b"doq", timeout, trust)?;
    DoqConn::establish(sock, conn, created, server_name.to_string(), deadline).inspect_err(
        |error| {
            crate::note_upstream_connect_failure("doq", addr, server_name, error);
        },
    )
}

impl DoqConn {
    /// Completes the handshake. `created` is when `conn` was made, its clock's zero.
    pub(crate) fn establish(
        sock: QuicSocket,
        conn: Connection,
        created: Instant,
        server_name: String,
        deadline: Instant,
    ) -> Result<Self, ForwardError> {
        let mut c = DoqConn {
            sock,
            conn,
            next_bidi: 0,
            created,
            server_name,
            revocation_checked: false,
        };
        if !c.conn.can_send_early() {
            pump_handshake(&c.sock, &mut c.conn, created, deadline)?;
        }
        Ok(c)
    }
}

/// Sends with transaction ID 0, as RFC 9250 requires: the stream already pairs query and response,
/// and a kept ID would fingerprint the connection.
pub(crate) fn roundtrip(
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

    check_peer_revocation(&mut c.conn, &c.server_name, &mut c.revocation_checked)?;

    let sid = c.next_bidi << 2;
    c.conn.set_now(c.created.elapsed().as_millis() as u64);
    if let Err(error) = c.conn.send_dns_message(sid, &q) {
        c.conn
            .close(doq::INTERNAL_ERROR, "Could not send the DNS query");
        return Err(ForwardError::Io(format!(
            "Could not send DoQ request: {error}"
        )));
    }
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

        check_peer_revocation(&mut c.conn, &c.server_name, &mut c.revocation_checked)?;
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
                let resp = Message::parse(&dns)
                    .map_err(|_| ForwardError::BadResponse)
                    .and_then(|resp| validate_response(request, &resp, Some(0)).map(|()| resp));
                if resp.is_err() {
                    c.conn.close(doq::PROTOCOL_ERROR, "Invalid DNS response");
                }
                return resp;
            }
        }
    }
    Err(ForwardError::Timeout)
}

#[cfg(test)]
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

    fn doq_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _peers) = doq_server_ex(ip, false, "dns.test");
        (addr, trust)
    }

    /// DoQ server config with a self-signed certificate, and a trust store that trusts only it.
    fn doq_server_config(name: &str) -> (Arc<ServerConfig>, Arc<TrustStore>) {
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
        (scfg, trust)
    }

    /// Counts connections.
    fn doq_server_ex(
        ip: Ipv4Addr,
        one_shot: bool,
        name: &str,
    ) -> (SocketAddr, Arc<TrustStore>, Arc<AtomicUsize>) {
        let (scfg, trust) = doq_server_config(name);

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

    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
    }

    #[test]
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
    /// Without the notice, the server holds the half-done connection until its own idle deadline.
    fn doq_rejected_certificate_is_reported_to_the_server() {
        let (addr, _trust, closes) = doq_close_recorder("dns.test", answer_in_kind);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(3),
        )
        .with_trust(Arc::new(TrustStore::empty()));
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 거부 사유를 서버에 보내지 않았습니다");
        assert_eq!(
            close.error_code,
            0x100 + 48,
            "unknown_ca 경고를 담은 CRYPTO_ERROR 여야 합니다"
        );
    }

    /// Echoes the question with no answer records.
    fn answer_in_kind(req: &Message) -> Message {
        let mut m = Message::default();
        m.header.id = req.header.id;
        m.header.response = true;
        m.questions = req.questions.clone();
        m
    }

    /// Answers a different name than asked.
    fn answer_other_question(req: &Message) -> Message {
        let mut m = answer_in_kind(req);
        m.questions = q(req.header.id, "other.test").questions;
        m
    }

    /// Upstream that collects the close reasons the client reports. `answer` builds the reply to
    /// each query. Returns the server address, a trust store for its certificate, and a receiver of
    /// each connection's close reasons.
    fn doq_close_recorder(
        name: &str,
        answer: fn(&Message) -> Message,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        std::sync::mpsc::Receiver<onetdns_quic::PeerClose>,
    ) {
        let (scfg, trust) = doq_server_config(name);
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (closes, reported) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, Connection> = HashMap::new();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let conn = conns.entry(peer).or_insert_with(|| {
                    Connection::new_server(
                        scfg.clone(),
                        random_cid(),
                        TransportParams::server_defaults(),
                    )
                });
                let received = conn.recv_datagram(&buf[..n]);
                if let Some(close) = conn.peer_close().cloned() {
                    conns.remove(&peer);
                    if closes.send(close).is_err() {
                        return;
                    }
                    continue;
                }
                if received.is_err() {
                    conns.remove(&peer);
                    continue;
                }
                for (sid, query) in conn.take_stream_requests() {
                    if let Ok(req) = Message::parse(&query) {
                        let _ = conn.send_dns_message(sid, &answer(&req).try_encode().unwrap());
                    }
                }
                while let Some(dg) = conn.next_datagram() {
                    let _ = sock.send_to(&dg, peer);
                }
            }
        });
        (addr, trust, reported)
    }

    #[test]
    /// Here the pool goes away as its thread ends. Without the notice, the server holds the
    /// connection until its own idle deadline.
    fn doq_discarded_connection_notifies_the_server() {
        let (addr, trust, closes) = doq_close_recorder("dns.test", answer_in_kind);
        thread::spawn(move || {
            let request = q(1, "bye.test");
            let wire = request.try_encode().unwrap();
            exchange(
                addr,
                "dns.test",
                &wire,
                &request,
                Duration::from_secs(5),
                &trust,
            )
            .expect("질의에 대한 답을 받지 못했습니다");
        })
        .join()
        .unwrap();
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("버려진 연결이 서버에 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x0, None));
    }

    #[test]
    /// Later answers from such a server on the same connection cannot be trusted either.
    fn doq_mismatched_answer_closes_with_protocol_error() {
        let (addr, trust, closes) = doq_close_recorder("dns.test", answer_other_question);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "dns.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x2, None));
    }

    #[test]
    /// The server has acknowledged nothing, so the send buffer is full. The connection is dropped
    /// and the server is told of an internal failure, distinct from a normal close.
    fn doq_unsendable_query_closes_with_internal_error() {
        let _revocation_test_guard = crate::revocation_test_read_guard();
        let (addr, trust, closes) = doq_close_recorder("dns.test", answer_in_kind);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut conn =
            connect(addr, "dns.test", deadline, &trust).expect("업스트림에 연결하지 못했습니다");
        crate::quicdrive::fill_send_buffer(&mut conn.conn);
        let request = q(1, "stuck.test");
        let wire = request.try_encode().unwrap();
        let result = roundtrip(&mut conn, &wire, &request, deadline);
        assert!(matches!(result, Err(ForwardError::Io(_))), "{result:?}");
        drop(conn);
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x1, None));
    }

    #[test]
    /// Goes out as a transport close carrying CRYPTO_ERROR, as when TLS rejects a certificate.
    fn doq_revocation_rejection_is_reported_to_the_server() {
        let _revocation_test_guard = crate::revocation_test_write_guard();
        let (addr, trust, closes) = doq_close_recorder("revoked.test", answer_in_kind);
        crate::set_revocation_hook(Box::new(|_, host| {
            if host == "revoked.test" {
                Err("폐기됨".to_string())
            } else {
                Ok(())
            }
        }));
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doq(addr, "revoked.test")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        let res = fwd.resolve(&q(1, "x.test"));
        crate::clear_revocation_hook();
        assert!(
            res.is_err(),
            "폐기 확인이 거부한 서버의 답을 받아들였습니다"
        );
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 거부 사유를 서버에 보내지 않았습니다");
        assert_eq!(
            close.error_code,
            0x100 + 46,
            "certificate_unknown 경고를 담은 CRYPTO_ERROR 여야 합니다"
        );
        assert!(close.frame_type.is_some(), "전송 계층 종료여야 합니다");
    }

    #[test]
    /// A stricter trust policy must not reuse QUIC connections or sessions from before.
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
