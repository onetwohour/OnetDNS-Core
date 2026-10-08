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
use onetdns_quic::{H3Client, H3Error};
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

impl Drop for Doh3Conn {
    /**
     * @brief 버려지는 연결의 종료를 서버에 알린다.
     * @details 오류, 시간 초과, 무응답, LRU 축출, 스레드 종료 가운데 어느 경로로 버려도 여기를
     *          지난다. 열린 연결은 알릴 오류 없이 닫고, 이미 닫힌 연결은 쌓아 둔 종료 프레임만
     *          내보낸다. 소켓도 함께 닫으므로 closing 기간은 기다리지 않는다. 알리지 않으면 서버는
     *          자기 유휴 데드라인까지 연결을 붙들고 있다.
     */
    fn drop(&mut self) {
        if !self.h3.is_closed() {
            self.h3.close(H3Error::NoError);
        }
        let _ = flush_out(&self.sock, &mut self.h3);
    }
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
    let mut c = Doh3Conn {
        sock,
        h3: H3Client::new(conn),
        created,
        server_name: server_name.to_string(),
        revocation_checked: false,
    };
    if !c.h3.can_send_early() {
        pump_handshake(&c.sock, &mut c.h3, created, deadline).inspect_err(|error| {
            crate::note_upstream_connect_failure("doh3", addr, server_name, error);
        })?;
    }
    Ok(c)
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
    /*
     * GOAWAY 를 받은 연결에는 새 요청을 열 수 없다. 여기서 돌려주면 이 연결은 풀에서 빠지며
     * H3_NO_ERROR 로 닫히고, 질의는 새 연결로 다시 간다. 보내기 실패 경로로 넘기면 서버의 정상
     * 종료를 이쪽 내부 실패로 알리게 된다.
     */
    if c.h3.is_going_away() {
        return Err(ForwardError::Io("DoH3 server sent GOAWAY".into()));
    }

    check_peer_revocation(c.h3.conn_mut(), &c.server_name, &mut c.revocation_checked)?;

    c.h3.set_now(c.created.elapsed().as_millis() as u64);
    let sid = match c.h3.send_request(authority, path, &q) {
        Ok(sid) => sid,
        Err(error) => {
            c.h3.close(H3Error::Internal);
            return Err(ForwardError::Io(format!("DoH3 request send: {error}")));
        }
    };
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
                if status == 0 {
                    return Err(ForwardError::Io(
                        "DoH3 request reset or refused by server".into(),
                    ));
                }
                if status != 200 {
                    return Err(ForwardError::Io(format!("DoH3 non-200 status: {status}")));
                }
                let resp = Message::parse(&body)
                    .map_err(|_| ForwardError::BadResponse)
                    .and_then(|resp| validate_response(request, &resp, Some(0)).map(|()| resp));
                if resp.is_err() {
                    c.h3.close(H3Error::GeneralProtocol);
                }
                return resp;
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

    /** @brief dns.test 자체 서명 인증서를 쓰는 DoH3 서버 설정과 그 인증서만 믿는 신뢰 저장소. */
    fn doh3_server_config() -> (Arc<ServerConfig>, Arc<TrustStore>) {
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
        (scfg, trust)
    }

    /** @brief 접속 수를 셀 수 있는 테스트용 업스트림. */
    fn doh3_server_ex(
        ip: Ipv4Addr,
        one_shot: bool,
    ) -> (SocketAddr, Arc<TrustStore>, Arc<AtomicUsize>) {
        let (scfg, trust) = doh3_server_config();
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

    /** @brief 질의를 그대로 되돌려 주는 응답. 답 레코드는 없다. */
    fn answer_in_kind(req: &Message) -> Message {
        let mut m = Message::default();
        m.header.id = req.header.id;
        m.header.response = true;
        m.questions = req.questions.clone();
        m
    }

    /** @brief 다른 이름을 물은 질의에 대한 응답. */
    fn answer_other_question(req: &Message) -> Message {
        let mut m = answer_in_kind(req);
        m.questions = q(req.header.id, "other.test").questions;
        m
    }

    /**
     * @brief 클라이언트가 알린 종료 사유를 모으는 테스트용 업스트림.
     * @param answer 받은 질의에 실을 응답을 만든다.
     * @return 서버 주소, 그 인증서만 믿는 신뢰 저장소, 연결마다 받은 종료 사유를 차례로 받는 곳.
     */
    fn doh3_close_recorder(
        answer: fn(&Message) -> Message,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        std::sync::mpsc::Receiver<onetdns_quic::PeerClose>,
    ) {
        let (scfg, trust) = doh3_server_config();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let (closes, reported) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, H3Connection> = HashMap::new();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let h3c = conns.entry(peer).or_insert_with(|| {
                    H3Connection::new(Connection::new_server(
                        scfg.clone(),
                        random_cid(),
                        TransportParams::server_defaults(),
                    ))
                });
                let received = h3c.recv_datagram(&buf[..n]);
                if let Some(close) = h3c.conn_mut().peer_close().cloned() {
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
                for (sid, query) in h3c.take_requests() {
                    if let Ok(req) = Message::parse(&query) {
                        let _ = h3c.send_response(sid, &answer(&req).try_encode().unwrap(), 0);
                    }
                }
                while let Some(dg) = h3c.next_datagram() {
                    let _ = sock.send_to(&dg, peer);
                }
            }
        });
        (addr, trust, reported)
    }

    /** @brief 이 서버 구현이 처음 여는 단방향 스트림. HTTP/3 제어 스트림이다. */
    const SERVER_CONTROL_STREAM: u64 = 3;
    /** @brief RFC 9114 의 GOAWAY 프레임 종류. */
    const GOAWAY_FRAME: u64 = 0x07;

    /**
     * @brief 이 스트림부터는 처리하지 않는다는 GOAWAY 를 보낸다.
     * @note 이 서버 구현은 스스로 GOAWAY 를 보내지 않아 제어 스트림에 직접 쓴다.
     */
    fn send_goaway(h3c: &mut H3Connection, first_unprocessed: u64) {
        let mut payload = Vec::new();
        onetdns_quic::varint::write(&mut payload, first_unprocessed);
        let mut frame = Vec::new();
        onetdns_quic::h3::encode_frame(&mut frame, GOAWAY_FRAME, &payload);
        h3c.conn_mut()
            .send_stream(SERVER_CONTROL_STREAM, &frame, false)
            .unwrap();
    }

    /**
     * @brief 질의에 답하면서 GOAWAY 를 보내는 테스트용 업스트림.
     * @param refuse_later 참이면 연결의 첫 질의에만 답한다. 그 뒤 질의에는 답하지 않고 그
     *                     스트림부터 처리하지 않는다는 GOAWAY 를 보내며, 소켓이 조용할 때마다 같은
     *                     GOAWAY 를 다시 보내 연결을 살려 둔다. 거짓이면 다음 스트림부터 처리하지
     *                     않는다는 GOAWAY 를 보낸 뒤 질의에 답한다.
     * @return 서버 주소, 신뢰 저장소, 맺은 연결 수, 클라이언트가 알린 종료 사유를 차례로 받는 곳.
     */
    fn doh3_goaway_server(
        refuse_later: bool,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        Arc<AtomicUsize>,
        std::sync::mpsc::Receiver<onetdns_quic::PeerClose>,
    ) {
        let (scfg, trust) = doh3_server_config();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let peers = Arc::new(AtomicUsize::new(0));
        let peers_ret = peers.clone();
        let (closes, reported) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, H3Connection> = HashMap::new();
            let mut refused: HashMap<SocketAddr, u64> = HashMap::new();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                    for (peer, first_unprocessed) in &refused {
                        let Some(h3c) = conns.get_mut(peer) else {
                            continue;
                        };
                        send_goaway(h3c, *first_unprocessed);
                        while let Some(dg) = h3c.next_datagram() {
                            let _ = sock.send_to(&dg, peer);
                        }
                    }
                    continue;
                };
                let h3c = conns.entry(peer).or_insert_with(|| {
                    peers.fetch_add(1, Ordering::Relaxed);
                    H3Connection::new(Connection::new_server(
                        scfg.clone(),
                        random_cid(),
                        TransportParams::server_defaults(),
                    ))
                });
                let received = h3c.recv_datagram(&buf[..n]);
                if let Some(close) = h3c.conn_mut().peer_close().cloned() {
                    conns.remove(&peer);
                    refused.remove(&peer);
                    if closes.send(close).is_err() {
                        return;
                    }
                    continue;
                }
                if received.is_err() {
                    conns.remove(&peer);
                    refused.remove(&peer);
                    continue;
                }
                for (sid, query) in h3c.take_requests() {
                    let Ok(req) = Message::parse(&query) else {
                        continue;
                    };
                    let answer = answer_in_kind(&req).try_encode().unwrap();
                    if !refuse_later {
                        /* 답보다 먼저 보내야 클라이언트가 답을 받기 전에 GOAWAY 를 읽는다. */
                        send_goaway(h3c, sid + 4);
                        let _ = h3c.send_response(sid, &answer, 0);
                    } else if sid == 0 {
                        let _ = h3c.send_response(sid, &answer, 0);
                    } else {
                        send_goaway(h3c, sid);
                        refused.insert(peer, sid);
                    }
                }
                while let Some(dg) = h3c.next_datagram() {
                    let _ = sock.send_to(&dg, peer);
                }
            }
        });
        (addr, trust, peers_ret, reported)
    }

    #[test]
    /**
     * @brief GOAWAY 를 받은 연결을 다시 쓰지 않고 H3_NO_ERROR 로 닫는지.
     * @details 서버가 연결 정리를 알렸으면 다음 질의는 새 연결로 가야 한다. 그 연결에 요청을 열다
     *          실패한 것으로 처리하면 서버의 정상 종료를 이쪽 내부 실패로 알리게 된다.
     */
    fn doh3_goaway_moves_the_next_query_to_a_new_connection() {
        let (addr, trust, peers, closes) = doh3_goaway_server(false);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        fwd.resolve(&q(1, "first.test")).unwrap();
        assert_eq!(fwd.resolve(&q(2, "second.test")).unwrap().header.id, 2);
        assert_eq!(
            peers.load(Ordering::Relaxed),
            2,
            "GOAWAY 를 받은 연결을 다시 썼습니다"
        );
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("버린 연결이 서버에 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x100, None));
    }

    #[test]
    /**
     * @brief GOAWAY 가 처리하지 않는다고 알린 질의를 데드라인까지 기다리지 않고 새 연결로 보내는지.
     * @details 서버는 그 요청에 답하지 않으면서 같은 GOAWAY 를 계속 다시 보내므로, 연결이 조용해서
     *          포기하는 경로는 작동하지 않는다. GOAWAY 를 읽고 바로 알아차리지 못하면 질의는
     *          데드라인을 다 쓰고 실패한다.
     */
    fn doh3_query_refused_by_goaway_is_retried_at_once() {
        let (addr, trust, peers, closes) = doh3_goaway_server(true);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        fwd.resolve(&q(1, "first.test")).unwrap();

        let start = Instant::now();
        let second = fwd.resolve(&q(2, "second.test"));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "GOAWAY 를 받고도 데드라인까지 기다렸습니다: {elapsed:?}, {second:?}"
        );
        assert_eq!(second.unwrap().header.id, 2);
        assert_eq!(peers.load(Ordering::Relaxed), 2);
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("버린 연결이 서버에 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x100, None));
    }

    #[test]
    /**
     * @brief 질의를 실어 보낼 수 없는 연결을 H3_INTERNAL_ERROR 로 닫는지.
     * @details 서버가 앞선 데이터를 확인하지 않아 보낼 버퍼가 가득 찬 경우다. 그 연결은 버리고,
     *          서버에는 정상 종료와 구분되는 내부 실패로 알린다.
     */
    fn doh3_unsendable_request_closes_with_internal_error() {
        let _revocation_test_guard = crate::revocation_test_read_guard();
        let (addr, trust, closes) = doh3_close_recorder(answer_in_kind);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut conn =
            connect(addr, "dns.test", deadline, &trust).expect("업스트림에 연결하지 못했습니다");
        crate::quicdrive::fill_send_buffer(conn.h3.conn_mut());
        let request = q(1, "stuck.test");
        let wire = request.try_encode().unwrap();
        let result = roundtrip(
            &mut conn,
            "dns.test",
            "/dns-query",
            &wire,
            &request,
            deadline,
        );
        assert!(matches!(result, Err(ForwardError::Io(_))), "{result:?}");
        drop(conn);
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x102, None));
    }

    #[test]
    /**
     * @brief 풀에서 버려지는 연결이 H3_NO_ERROR 로 닫힌다고 서버에 알리는지.
     * @details 연결을 쥔 스레드가 끝나며 풀이 사라지는 경우다. 알리지 않으면 서버는 자기 유휴
     *          데드라인까지 연결을 붙들고 있다.
     */
    fn doh3_discarded_connection_notifies_the_server() {
        let (addr, trust, closes) = doh3_close_recorder(answer_in_kind);
        thread::spawn(move || {
            let request = q(1, "bye.test");
            let wire = request.try_encode().unwrap();
            exchange(
                addr,
                "dns.test",
                "/dns-query",
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
        assert_eq!((close.error_code, close.frame_type), (0x100, None));
    }

    #[test]
    /**
     * @brief 질의에 맞지 않는 응답을 받으면 H3_GENERAL_PROTOCOL_ERROR 로 연결을 닫는지.
     * @details 그런 서버가 같은 연결로 보낼 다음 응답도 믿을 수 없다.
     */
    fn doh3_mismatched_answer_closes_with_general_protocol_error() {
        let (addr, trust, closes) = doh3_close_recorder(answer_other_question);
        let fwd = Forwarder::with_upstreams(
            vec![Upstream::doh3(addr, "dns.test", "/dns-query")],
            Duration::from_secs(5),
        )
        .with_trust(trust);
        assert!(fwd.resolve(&q(1, "x.test")).is_err());
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x101, None));
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
