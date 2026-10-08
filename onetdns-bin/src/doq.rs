/*!
 * @brief DoQ 리스너.
 *
 * @details QUIC 스트림 하나에 질의 하나가 오간다. 연결을 받고 유지하는 일은
 *          quic_listener 가 맡고, 여기서는 받은 질의를 검사해 워커에 맡기는 일과 응답을
 *          스트림에 싣는 일만 한다.
 */

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

/** @brief 리스너를 열고 연결을 받는다. */
pub fn serve_doq(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    shutdown: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<QuicListener> {
    quic_listener::serve(Doq, addr, tls, handler, shutdown, memory_budget)
}

/**
 * @brief 이 질의가 DoQ에서 연결을 끊어야 하는 프로토콜 오류인지.
 *
 * @details RFC 9250은 QUIC 위의 DNS Message ID를 0으로 규정한다. 질의와 응답은
 *          스트림으로 짝지어지므로 ID 필드가 필요 없기 때문이다. 같은 RFC가 0이 아닌 ID와
 *          edns-tcp-keepalive 옵션을 각각 치명적 오류로 열거한다. 후자는 TCP 전용이라
 *          QUIC 연결 관리와 뜻이 겹치고 어긋난다. 치명적 오류는 DOQ_PROTOCOL_ERROR 를 담은
 *          CONNECTION_CLOSE 로 알린다.
 * @return 끊어야 하면 그 까닭, 정상이면 None.
 */
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

/** @brief DoQ 의 질의 검사와 응답. */
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
        /*
         * RFC 9250 에서 QUIC 위로 나가는 DNS 메시지의 ID 는 0 이어야 한다. 받는 쪽에서 0 이 아닌
         * 질의를 이미 끊지만, 내보내는 곳에서도 강제해 어떤 경로로도 새지 않게 한다.
         */
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
/** @brief 종료, 재전송, 프로토콜 오류 판정, 그리고 실제 QUIC 위 질의 왕복. */
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

    /** @brief 고정 응답을 내는 테스트용 업스트림. */
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

    /** @brief 테스트용 질의 핸들러. */
    fn native_handler() -> Arc<NativeServer> {
        let engine = build_from_str("||blocked.test^\n", "", BlockResponse::NxDomain);
        Arc::new(NativeServer::new(
            Arc::new(SharedFilter::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(NativeBackend::Forward(Forwarder::new(
                vec![mock_upstream()],
                Duration::from_secs(2),
            ))),
            60,
        ))
    }

    /** @brief 테스트용 자체 서명 설정. */
    fn self_signed_doq() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        let cfg = ServerConfig::from_pkcs8(cert_der, &key_der)
            .expect("ECDSA P-256 서명자")
            .with_alpn(vec![b"doq".to_vec()]);
        Arc::new(cfg)
    }

    /** @brief 테스트 하나가 쓰는 독립 QUIC 전역 예산. */
    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    /** @brief 종료 때 반복이 정리되는지. */
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

    /** @brief QUIC로 질의를 보내고 답을 받는다. */
    fn doq_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        doq_query_with_blackout(server, name, qtype, Duration::ZERO, random_cid())
    }

    /**
     * @brief 패킷이 잠시 끊기는 상황을 만들어 질의를 보낸다.
     * @param client_cid 클라이언트가 쓸 연결 식별자. 길이 0이어도 된다.
     */
    fn doq_query_with_blackout(
        server: SocketAddr,
        name: &str,
        qtype: RecordType,
        blackout: Duration,
        client_cid: Vec<u8>,
    ) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        /*
         * 블랙아웃 시험은 질의 뒤 클라이언트 타이머를 멈추므로 잃은 데이터그램을 되찾지 못한다.
         * 소켓 수신 한도에 기대면 윈도우에서 한도에 걸리는 순간 도착한 응답이 사라져 서버
         * 재전송과 무관하게 실패한다.
         */
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
        /*
         * 반복 횟수가 아니라 시각으로 끝낸다. 한 바퀴마다 데이터그램 하나를 받거나 50밀리초를
         * 기다리므로, 횟수로 세면 전체 시험을 병렬로 돌리는 CI 러너에서 서버 스레드가 몇 초
         * 밀렸을 때 응답보다 한도가 먼저 끝난다. 이 한도는 응답이 아예 오지 않는 경우를
         * 잡으려는 것이지 지연 요구가 아니다.
         */
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while Instant::now() < deadline {
            /*
             * 연결 상태 기계는 시계를 직접 읽지 않으므로 시각을 넘기고 재전송 타이머를 돌린다.
             * 돌리지 않으면 클라이언트가 보낸 데이터그램 하나가 사라졌을 때 다시 보내지 않아
             * 응답을 끝내 받지 못한다. 블랙아웃 시험은 질의를 보낸 뒤 타이머를 멈춘다.
             * 클라이언트가 프로브를 계속 보내면 서버가 그 ACK 로 응답 손실을 알아채 다시
             * 보낼 수 있어, 서버가 스스로 재전송하는지 증명하지 못한다.
             */
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
    /** @brief 허용된 이름이 해석되는지. */
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

    #[test]
    /**
     * @brief 리스너가 핸드셰이크를 거부하면 그 까닭이 클라이언트에 닿는지.
     * @details 연결이 쌓아 둔 종료 프레임을 리스너가 보내지 않으면 클라이언트는 자기 유휴
     *          데드라인까지 기다린다.
     */
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
    /**
     * @brief 리스너를 멈추면 열린 연결의 클라이언트가 종료를 통보받는지.
     * @details 알리지 않으면 클라이언트는 자기 유휴 데드라인까지 끊긴 연결을 붙들고 있다.
     *          서버가 핸드셰이크를 마친 것을 질의 하나로 확인한 뒤 멈춰야 종료가 응용 계층
     *          종료로 나간다.
     */
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
    /**
     * @brief RFC 9250이 열거한 두 프로토콜 오류를 가려내는지.
     * @details 0이 아닌 ID와 edns-tcp-keepalive다. 둘 다 연결을 끊어야 하므로 답이 없다.
     */
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
    /** @brief 차단된 이름이 막히는지. */
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
    /** @brief 클라이언트가 조용해도 서버가 스스로 재전송하는지. 안 하면 잃은 응답이 영영 안 간다. */
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
    /**
     * @brief 길이 0인 연결 식별자를 쓰는 클라이언트의 질의에 답하는지.
     * @details msquic 을 쓰는 클라이언트가 이렇게 연결한다. 리스너가 그 Initial 을 받아들이지
     *          않으면 핸드셰이크가 시간 초과로 끝난다.
     */
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
