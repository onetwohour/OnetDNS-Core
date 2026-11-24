//! DNS over HTTP/3 upstream.

use std::cell::RefCell;
#[cfg(test)]
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(test)]
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use onetdns_core::LruMap;
use onetdns_proto::Message;
use onetdns_quic::{H3Client, H3Error, H3Response};
use onetdns_tls::TrustStore;

use crate::quicdrive::{
    check_peer_revocation, flush_out, harvest_sessions, new_client_connection, pump_handshake,
    recv_once, silence_limit_ms, QuicSocket,
};
use crate::{validate_response, ForwardError};

struct Doh3Conn {
    sock: QuicSocket,
    h3: H3Client,

    /// Too old connections are dropped.
    created: Instant,
    server_name: String,
    /// Checked once per connection.
    revocation_checked: bool,
}

impl Drop for Doh3Conn {
    /// Tells the server the connection is going away, whichever way it is dropped: error, timeout,
    /// silence, LRU eviction, or thread exit. An open connection closes with no error code; a
    /// closed one sends only its queued close frame. The socket closes too, so there is no wait for
    /// the closing period. Without the notice, the server holds the connection until its own idle
    /// deadline.
    fn drop(&mut self) {
        if !self.h3.is_closed() {
            self.h3.close(H3Error::NoError);
        }
        let _ = flush_out(&self.sock, &mut self.h3);
    }
}

thread_local! {
    /// Keyed by address, server name, path, and security policy.
    static POOL: RefCell<LruMap<(SocketAddr, String, String, crate::TlsCacheScope), Doh3Conn>> =
        RefCell::new(LruMap::new(MAX_POOLED_CONNECTIONS));
}

/// Per thread.
const MAX_POOLED_CONNECTIONS: usize = 256;

/// On connection failure, drops the connection from the pool and retries once on a new one. An
/// error status from the server leaves the connection in place and is not retried: it is the
/// server's answer, a new connection would not change it, and 429 and 503 also ask clients not to
/// retry at once.
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
                Ok(answer) => return answer,
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

/// Includes setting up the HTTP/3 control streams.
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

/// An outer Err means the connection is unusable. An inner Err means the server answered this query
/// alone with an error status, and the connection is still good.
fn roundtrip(
    c: &mut Doh3Conn,
    authority: &str,
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

    c.h3.set_now(c.created.elapsed().as_millis() as u64);
    c.h3.on_timeout(c.created.elapsed().as_millis() as u64);
    if c.h3.is_closed() {
        return Err(ForwardError::Io("DoH3 connection closed after idle".into()));
    }
    // A connection that got GOAWAY cannot open new requests. Returning here drops it from the pool
    // with H3_NO_ERROR and retries the query on a new connection; going through the send-failure
    // path would report the server's graceful close as our internal failure.
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
        for (rid, response) in c.h3.take_responses() {
            if rid != sid {
                continue;
            }
            // Under RFC 8484 a 200 response carries a DNS message. A 200 without one is a protocol
            // violation like an unparsable DNS body and closes the connection; other statuses fail
            // only this query.
            let resp = match response {
                H3Response::Dns(body) => Message::parse(&body)
                    .map_err(|_| ForwardError::BadResponse)
                    .and_then(|resp| validate_response(request, &resp, Some(0)).map(|()| resp)),
                H3Response::NotDns(200) => Err(ForwardError::BadResponse),
                H3Response::NotDns(status) => {
                    return Ok(Err(ForwardError::Io(format!(
                        "DoH3 non-200 status: {status}"
                    ))))
                }
                H3Response::Unanswered => {
                    return Err(ForwardError::Io(
                        "DoH3 request reset or refused by server".into(),
                    ))
                }
            };
            if resp.is_err() {
                c.h3.close(H3Error::GeneralProtocol);
            }
            return resp.map(Ok);
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
    use onetdns_quic::{Connection, H3Connection};
    use onetdns_tls::{signer_from_pkcs8_der, ServerConfig};

    use crate::quicdrive::random_cid;
    use crate::{Forwarder, Upstream};

    /// Upstream with a self-signed certificate.
    fn doh3_server(ip: Ipv4Addr) -> (SocketAddr, Arc<TrustStore>) {
        let (addr, trust, _peers) = doh3_server_ex(ip, false);
        (addr, trust)
    }

    /// DoH3 server config with a self-signed dns.test certificate, and a trust store that trusts
    /// only it.
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

    /// Counts connections.
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

    fn q(id: u16, name: &str) -> Message {
        Message::query(id, Name::from_str(name).unwrap(), RecordType::A)
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
    fn doh3_close_recorder(
        answer: fn(&Message) -> Message,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        std::sync::mpsc::Receiver<onetdns_quic::PeerClose>,
    ) {
        let (addr, trust, _peers, closes) = doh3_close_recorder_with(move |h3c, sid, req| {
            let _ = h3c.send_response(sid, &answer(req).try_encode().unwrap(), 0);
        });
        (addr, trust, closes)
    }

    const DATA_FRAME: u64 = 0x00;
    const HEADERS_FRAME: u64 = 0x01;

    /// What a web server that does not know the DoH path sends instead of a DNS message.
    const HTML_PAGE: &[u8] = b"<html>no DNS here</html>";

    /// Answers with an HTML page instead of a DNS message.
    fn answer_with_html_page(h3c: &mut H3Connection, sid: u64, status: &[u8], page: &[u8]) {
        let headers: [(&[u8], &[u8]); 2] = [(b":status", status), (b"content-type", b"text/html")];
        let (section, _) = onetdns_quic::qpack::Encoder::new().encode_field_section(&headers);
        let mut payload = Vec::new();
        onetdns_quic::h3::encode_frame(&mut payload, HEADERS_FRAME, &section);
        onetdns_quic::h3::encode_frame(&mut payload, DATA_FRAME, page);
        h3c.conn_mut().send_stream(sid, &payload, true).unwrap();
    }

    /// Like doh3_close_recorder, but `respond` writes each answer itself. Also returns the number
    /// of connections made.
    fn doh3_close_recorder_with(
        respond: impl Fn(&mut H3Connection, u64, &Message) + Send + 'static,
    ) -> (
        SocketAddr,
        Arc<TrustStore>,
        Arc<AtomicUsize>,
        std::sync::mpsc::Receiver<onetdns_quic::PeerClose>,
    ) {
        let (scfg, trust) = doh3_server_config();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let peers = Arc::new(AtomicUsize::new(0));
        let peers_ret = peers.clone();
        let (closes, reported) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut conns: HashMap<SocketAddr, H3Connection> = HashMap::new();
            let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf) else {
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
                        respond(h3c, sid, &req);
                    }
                }
                while let Some(dg) = h3c.next_datagram() {
                    let _ = sock.send_to(&dg, peer);
                }
            }
        });
        (addr, trust, peers_ret, reported)
    }

    /// The first unidirectional stream this server implementation opens: the HTTP/3 control stream.
    const SERVER_CONTROL_STREAM: u64 = 3;
    const GOAWAY_FRAME: u64 = 0x07;

    /// This server implementation never sends GOAWAY itself, so it is written to the control stream
    /// directly.
    fn send_goaway(h3c: &mut H3Connection, first_unprocessed: u64) {
        let mut payload = Vec::new();
        onetdns_quic::varint::write(&mut payload, first_unprocessed);
        let mut frame = Vec::new();
        onetdns_quic::h3::encode_frame(&mut frame, GOAWAY_FRAME, &payload);
        h3c.conn_mut()
            .send_stream(SERVER_CONTROL_STREAM, &frame, false)
            .unwrap();
    }

    /// Upstream that sends GOAWAY while answering. With `refuse_later`, it answers only the first
    /// query on a connection; later queries get no answer but a GOAWAY saying processing stops at
    /// that stream, resent whenever the socket is quiet to keep the connection alive. Without it,
    /// it sends GOAWAY for the next stream and then answers. Returns the server address, trust
    /// store, connection count, and a receiver of close reasons.
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
                        // Sent before the answer, so the client reads GOAWAY before the answer
                        // arrives.
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
    /// Once the server announces cleanup, the next query must go to a new connection; treating a
    /// failed request open as an error would report the server's graceful close as our internal
    /// failure.
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
    /// The server never answers that request and keeps resending GOAWAY, so the give-up-on-silence
    /// path never fires; without noticing GOAWAY at once, the query would spend its whole deadline
    /// and fail.
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
    /// The server has acknowledged nothing, so the send buffer is full. The connection is dropped
    /// and the server is told of an internal failure, distinct from a normal close.
    fn doh3_unsendable_request_closes_with_internal_error() {
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
    /// Here the pool goes away as its thread ends. Without the notice, the server holds the
    /// connection until its own idle deadline.
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
    /// Later answers from such a server on the same connection cannot be trusted either.
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

    /// The connection goes into this thread's pool and is dropped with the thread.
    fn exchange_once(addr: SocketAddr, trust: &TrustStore) -> Result<Message, ForwardError> {
        let request = q(1, "page.test");
        let wire = request.try_encode().unwrap();
        exchange(
            addr,
            "dns.test",
            "/dns-query",
            &wire,
            &request,
            Duration::from_secs(5),
            trust,
        )
    }

    #[test]
    /// A non-200 answer is a complete HTTP message on a healthy connection. Closing with
    /// H3_MESSAGE_ERROR would tell the server its response was broken, and reconnecting would
    /// repeat the handshake to get the same answer. Pages larger than the response buffer limit
    /// behave the same.
    fn doh3_error_page_fails_only_that_query() {
        for page in [HTML_PAGE.to_vec(), vec![b'x'; 200 * 1024]] {
            let size = page.len();
            let requests = Arc::new(AtomicUsize::new(0));
            let counted = requests.clone();
            let (addr, trust, peers, closes) = doh3_close_recorder_with(move |h3c, sid, _| {
                counted.fetch_add(1, Ordering::Relaxed);
                answer_with_html_page(h3c, sid, b"404", &page);
            });
            let results =
                thread::spawn(move || [exchange_once(addr, &trust), exchange_once(addr, &trust)])
                    .join()
                    .unwrap();
            for result in results {
                assert_eq!(
                    result.err(),
                    Some(ForwardError::Io("DoH3 non-200 status: 404".into())),
                    "페이지 {size} 바이트"
                );
            }
            assert_eq!(
                requests.load(Ordering::Relaxed),
                2,
                "오류 상태를 받은 질의를 다시 보냈습니다 (페이지 {size} 바이트)"
            );
            assert_eq!(
                peers.load(Ordering::Relaxed),
                1,
                "오류 상태를 받은 연결을 버렸습니다 (페이지 {size} 바이트)"
            );
            let close = closes
                .recv_timeout(Duration::from_secs(10))
                .expect("스레드가 끝나며 버린 연결이 서버에 종료를 알리지 않았습니다");
            assert_eq!(
                (close.error_code, close.frame_type),
                (0x100, None),
                "페이지 {size} 바이트"
            );
        }
    }

    #[test]
    /// Under RFC 8484 a 200 carries a DNS message. A server breaking that is told
    /// H3_GENERAL_PROTOCOL_ERROR, and the query fails as with a mismatched answer.
    fn doh3_success_status_without_a_dns_message_is_a_bad_response() {
        let (addr, trust, _peers, closes) = doh3_close_recorder_with(|h3c, sid, _| {
            answer_with_html_page(h3c, sid, b"200", HTML_PAGE)
        });
        let result = thread::spawn(move || exchange_once(addr, &trust))
            .join()
            .unwrap();
        assert_eq!(result.err(), Some(ForwardError::BadResponse));
        let close = closes
            .recv_timeout(Duration::from_secs(10))
            .expect("클라이언트가 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x101, None));
    }

    #[test]
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
    /// A stricter trust policy must not reuse QUIC connections or sessions from before.
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
