//! DoQ listener: one query per QUIC stream. quic_listener accepts and keeps connections; this
//! checks queries, hands them to workers, and writes responses to streams.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use onetdns_proto::Message;
use onetdns_quic::{doq, Connection, QuicError};
use onetdns_runtime::Transport as RtTransport;
use onetdns_tls::ServerConfig;

use crate::native::NativeServer;
use crate::quic_listener::{self, Abandon, Intake, QuicListener, QuicService};
use crate::quic_memory::QuicMemoryBudget;
use crate::qworker::QueryJob;
use crate::transport_observe;

pub fn serve_doq(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    shutdown: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<QuicListener> {
    quic_listener::serve(Doq, addr, tls, handler, shutdown, memory_budget)
}

/// The reason to close the connection with DOQ_PROTOCOL_ERROR, or None. RFC 9250 makes a non-zero
/// message ID and the edns-tcp-keepalive option fatal: streams already pair queries with responses,
/// and keepalive belongs to TCP and conflicts with QUIC's own connection management.
fn doq_protocol_error(req: &Message) -> Option<&'static str> {
    if req.header.id != 0 {
        return Some("DNS message ID over QUIC must be zero");
    }
    let carries_keepalive = req
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .is_some_and(|edns| edns.has_option(onetdns_proto::EDNS_TCP_KEEPALIVE));
    if carries_keepalive {
        return Some("edns-tcp-keepalive is not allowed over QUIC");
    }
    None
}

pub(crate) struct Doq;

impl QuicService for Doq {
    type Conn = Connection;
    const NAME: &'static str = "doq";

    fn dispatch(&self, conn: &mut Connection, intake: &mut Intake<'_>) {
        let _ = conn.take_resets();
        for (stream_id, query) in conn.take_stream_requests() {
            let req = match Message::parse(&query) {
                Ok(req) if !req.header.response => req,
                Ok(_) => {
                    transport_observe::record_error(
                        Self::NAME,
                        "dns_response_as_query",
                        Some(intake.peer()),
                        "unsolicited DNS response",
                    );
                    conn.close(doq::PROTOCOL_ERROR, "unsolicited DNS response");
                    return;
                }
                Err(error) => {
                    transport_observe::record_error(
                        Self::NAME,
                        "dns_parse",
                        Some(intake.peer()),
                        error,
                    );
                    conn.close(doq::PROTOCOL_ERROR, "malformed DNS message");
                    return;
                }
            };
            if let Some(reason) = doq_protocol_error(&req) {
                transport_observe::record_error(
                    Self::NAME,
                    "doq_protocol_error",
                    Some(intake.peer()),
                    reason,
                );
                conn.close(doq::PROTOCOL_ERROR, reason);
                return;
            }
            let auth_identity = conn.client_auth_identity().map(str::to_string);
            let job = QueryJob {
                conn_key: intake.key().to_vec(),
                epoch: intake.epoch(),
                stream_id,
                query,
                peer: intake.peer(),
                transport: RtTransport::DoQ,
                client_id: auth_identity.clone(),
                authenticated: conn.client_authenticated(),
                auth_identity,
            };
            if !intake.submit::<Self>(conn, &req, job) {
                return;
            }
        }
    }

    fn send_answer(
        conn: &mut Connection,
        stream_id: u64,
        mut wire: Vec<u8>,
        _max_age: u32,
    ) -> Result<(), QuicError> {
        // Forced on send too, so no path can send a non-zero ID.
        if let Some(id) = wire.get_mut(..2) {
            id.fill(0);
        }
        conn.send_dns_message_owned(stream_id, wire)
    }

    fn abandon(conn: &mut Connection, why: Abandon) {
        let (code, reason) = match why {
            Abandon::Shutdown => (doq::NO_ERROR, ""),
            Abandon::Internal => (doq::INTERNAL_ERROR, "Could not send a DNS response"),
            Abandon::ExcessiveLoad => (doq::EXCESSIVE_LOAD, "Server resource limit exceeded"),
        };
        conn.close(code, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::thread;
    use std::time::{Duration, Instant};

    use onetdns_core::udp::RecvWait;
    use onetdns_core::BlockResponse;
    use onetdns_filter::{build_from_str, SharedFilter};
    use onetdns_forward::Forwarder;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_quic::params::TransportParams;
    use onetdns_security::IpAcl;
    use onetdns_tls::ClientConfig;

    use crate::native::NativeBackend;
    use crate::quic_listener::random_cid;

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
        native_handler_with(IpAcl::allow_all())
    }

    fn native_handler_with(acl: IpAcl) -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            Arc::new(acl),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    fn self_signed_doq() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        let cfg = ServerConfig::from_pkcs8(cert_der, &key_der)
            .expect("ECDSA P-256 서명자")
            .with_alpn(vec![b"doq".to_vec()]);
        Arc::new(cfg)
    }

    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    fn dropping_doq_listener_joins_event_loop() {
        let listener = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn doq_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        doq_query_with_blackout(server, name, qtype, Duration::ZERO, random_cid())
    }

    /// Loses packets for `blackout` after sending the query. `client_cid` may be zero-length.
    fn doq_query_with_blackout(
        server: SocketAddr,
        name: &str,
        qtype: RecordType,
        blackout: Duration,
        client_cid: Vec<u8>,
    ) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // The blackout test stops the client's timers, so a lost datagram is never recovered. A
        // socket receive timeout on Windows can drop a response that arrives as it fires, failing
        // the test whatever the server does.
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&sock).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            client_cid,
            TransportParams::server_defaults(),
        )
        .unwrap();

        let query = Message::query(0, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut asked = false;
        let mut blackout_started = None;
        let mut b = [0u8; 2048];
        // A deadline, not an iteration count: each pass takes one datagram or 50 ms, and on a busy
        // CI runner a server thread a few seconds late would outlast a count. It catches a response
        // that never comes; it is not a latency requirement.
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while Instant::now() < deadline {
            // The connection never reads a clock, so time is passed in and retransmission timers
            // run; otherwise one lost client datagram would never be resent. The blackout test
            // stops the timers after the query: client probes would let the server learn of the
            // loss from their ACKs, and the test would no longer show that the server retransmits
            // on its own.
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            if blackout.is_zero() || !asked {
                client.on_timeout(now_ms);
            }
            while let Some(dg) = client.next_datagram() {
                sock.send_to(&dg, server).unwrap();
            }
            if client.is_handshake_complete() && !asked {
                client.send_dns_message(0, &query).unwrap();
                asked = true;
                blackout_started = Some(Instant::now());
                while let Some(dg) = client.next_datagram() {
                    sock.send_to(&dg, server).unwrap();
                }
            }
            if asked {
                if let Some((_, resp)) = client.take_stream_requests().into_iter().next() {
                    return Message::parse(&resp).unwrap();
                }
            }
            match wait.recv_from(&sock, &mut b) {
                Ok((n, _)) => {
                    if blackout_started.is_some_and(|started| started.elapsed() < blackout) {
                        continue;
                    }
                    client.recv_datagram(&b[..n]).unwrap();
                }
                Err(_) => {}
            }
        }
        panic!("DoQ 응답 없음");
    }

    #[test]
    fn doq_allowed_query_resolves_over_self_quic() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query(l.addr(), "allowed.test", RecordType::A);
        assert_eq!(resp.header.id, 0, "RFC 9250: QUIC 위 메시지 ID는 0");
        assert_eq!(resp.answers.len(), 1, "A 레코드 1개");
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    /// Whether anything at all comes back to a first packet within `wait`.
    fn first_packet_answered(acl: IpAcl, wait: Duration) -> bool {
        let listener = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler_with(acl),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            random_cid(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(wait)).unwrap();
        let initial = client
            .next_datagram()
            .expect("클라이언트가 첫 패킷을 만들지 않았습니다");
        sock.send_to(&initial, listener.addr()).unwrap();
        let mut buf = [0u8; 2048];
        sock.recv_from(&mut buf).is_ok()
    }

    #[test]
    /// Not even a Retry. The listener asks the query handler about every datagram; without that, a
    /// dropped address would get a Retry and learn a server is there.
    fn doq_listener_sends_nothing_to_dropped_clients() {
        assert!(
            first_packet_answered(IpAcl::allow_all(), Duration::from_secs(5)),
            "대조군이 무효입니다. 허용한 주소의 첫 패킷에 답하지 않았습니다"
        );
        assert!(
            !first_packet_answered(
                IpAcl::allow_all().with_drop(vec!["127.0.0.0/8".parse().unwrap()]),
                Duration::from_secs(1),
            ),
            "버리는 주소의 첫 패킷에 답했습니다"
        );
    }

    #[test]
    /// If the listener does not send the close frame the connection queued, the client waits until
    /// its idle deadline.
    fn rejected_handshake_reaches_the_client() {
        let mut tls = (*self_signed_doq()).clone();
        tls.client_ca = Some(onetdns_tls::TrustStore::from_ders([
            tls.cert_chain[0].as_slice()
        ]));
        let listener = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(Arc::new(tls))),
            native_handler(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&sock).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            random_cid(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        let mut b = [0u8; 2048];
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while !client.is_closed() && Instant::now() < deadline {
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            client.on_timeout(now_ms);
            while let Some(dg) = client.next_datagram() {
                sock.send_to(&dg, listener.addr()).unwrap();
            }
            if let Ok((n, _)) = wait.recv_from(&sock, &mut b) {
                client.recv_datagram(&b[..n]).unwrap();
            }
        }
        let close = client
            .peer_close()
            .cloned()
            .expect("리스너가 종료 사유를 보내지 않았습니다");
        assert_eq!(
            close.error_code,
            0x100 + 116,
            "certificate_required 경고를 담은 CRYPTO_ERROR 여야 합니다"
        );
    }

    #[test]
    /// Otherwise clients hold dead connections until their idle deadline. One query first confirms
    /// the handshake finished, so the close goes out as an application close.
    fn stopping_the_listener_notifies_open_connections() {
        let listener = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let server = listener.addr();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let wait = RecvWait::new(Duration::from_millis(50));
        wait.install(&sock).unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"doq".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            random_cid(),
            TransportParams::server_defaults(),
        )
        .unwrap();
        let query = Message::query(0, ApName::from_str("allowed.test").unwrap(), RecordType::A)
            .try_encode()
            .unwrap();

        let mut listener = Some(listener);
        let mut asked = false;
        let mut b = [0u8; 2048];
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while !client.is_closed() && Instant::now() < deadline {
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            client.on_timeout(now_ms);
            if client.is_handshake_complete() && !asked {
                client.send_dns_message(0, &query).unwrap();
                asked = true;
            }
            while let Some(dg) = client.next_datagram() {
                let _ = sock.send_to(&dg, server);
            }
            if asked && listener.is_some() && !client.take_stream_requests().is_empty() {
                drop(listener.take());
            }
            if let Ok((n, _)) = wait.recv_from(&sock, &mut b) {
                let _ = client.recv_datagram(&b[..n]);
            }
        }
        assert!(listener.is_none(), "질의에 대한 답을 받지 못했습니다");
        let close = client
            .peer_close()
            .cloned()
            .expect("리스너가 멈추며 종료를 알리지 않았습니다");
        assert_eq!((close.error_code, close.frame_type), (0x0, None));
    }

    #[test]
    /// Both close the connection, so neither gets an answer.
    fn doq_protocol_errors_are_recognized() {
        let ok = Message::query(0, ApName::from_str("allowed.test").unwrap(), RecordType::A);
        assert!(doq_protocol_error(&ok).is_none(), "정상 질의는 통과한다");

        let bad_id = Message::query(
            0x4242,
            ApName::from_str("allowed.test").unwrap(),
            RecordType::A,
        );
        assert!(
            doq_protocol_error(&bad_id).is_some(),
            "QUIC 위 메시지 ID는 0이어야 한다"
        );

        let mut keepalive = ok.clone();
        keepalive.set_tcp_keepalive(100).unwrap();
        assert!(
            doq_protocol_error(&keepalive).is_some(),
            "edns-tcp-keepalive는 TCP 전용이라 QUIC에서는 오류다"
        );
    }

    #[test]
    fn doq_blocked_query_returns_nxdomain_over_self_quic() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query(l.addr(), "blocked.test", RecordType::A);
        assert_eq!(resp.header.rcode, onetdns_proto::ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }

    #[test]
    /// Otherwise a lost response is never sent.
    fn doq_server_pto_retransmits_without_new_client_packets() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query_with_blackout(
            l.addr(),
            "pto.test",
            RecordType::A,
            Duration::from_millis(400),
            random_cid(),
        );
        assert_eq!(resp.header.id, 0, "RFC 9250: QUIC 위 메시지 ID는 0");
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    /// msquic clients connect this way; rejecting their Initial times out the handshake.
    fn doq_answers_client_with_zero_length_connection_id() {
        let l = serve_doq(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_doq())),
            native_handler(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doq_query_with_blackout(
            l.addr(),
            "allowed.test",
            RecordType::A,
            Duration::ZERO,
            Vec::new(),
        );
        assert_eq!(resp.answers.len(), 1);
    }
}
