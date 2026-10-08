/*!
 * @brief DoH3 리스너.
 *
 * @details QUIC 위 HTTP/3로 DNS 메시지를 주고받는다. 연결을 받고 유지하는 일은
 *          quic_listener 가 맡고, 여기서는 요청을 검사해 워커에 맡기는 일과 응답을
 *          스트림에 싣는 일만 한다.
 */

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use onetdns_proto::Message;
use onetdns_quic::{H3Connection, H3Error, QuicError};
use onetdns_runtime::Transport as RtTransport;
use onetdns_tls::ServerConfig;

use crate::native::NativeServer;
use crate::quic_listener::{self, Abandon, Intake, QuicListener, QuicService};
use crate::quic_memory::QuicMemoryBudget;
use crate::qworker::QueryJob;
use crate::transport_observe;

/** @brief 리스너를 열고 연결을 받는다. */
pub fn serve_doh3(
    addr: SocketAddr,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    doh_path: String,
    shutdown: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<QuicListener> {
    quic_listener::serve(
        Doh3 { doh_path },
        addr,
        tls,
        handler,
        shutdown,
        memory_budget,
    )
}

/** @brief 요청 경로가 이 서버가 서빙하는 것인지. */
fn match_doh_path(path: &[u8], expected: &str) -> bool {
    let path_only = path.split(|&b| b == b'?').next().unwrap_or(path);
    if path_only == expected.as_bytes() {
        return true;
    }
    let mut prefix = expected.as_bytes().to_vec();
    prefix.push(b'/');
    path_only
        .strip_prefix(prefix.as_slice())
        .is_some_and(|rest| !rest.is_empty() && !rest.contains(&b'/'))
}

/** @brief DoH3 의 요청 검사와 응답. */
pub(crate) struct Doh3 {
    /** @brief 이 서버가 답하는 경로. */
    doh_path: String,
}

impl QuicService for Doh3 {
    type Conn = H3Connection;
    const NAME: &'static str = "doh3";

    fn dispatch(&self, h3: &mut H3Connection, intake: &mut Intake<'_>) {
        for r in h3.take_requests_meta() {
            if !match_doh_path(&r.path, &self.doh_path) {
                if !send_status(h3, intake.peer(), r.stream_id, b"404") {
                    return;
                }
                continue;
            }
            let req = match Message::parse(&r.wire) {
                Ok(req) if !req.header.response => req,
                Ok(_) => {
                    transport_observe::record_error(
                        Self::NAME,
                        "dns_response_as_query",
                        Some(intake.peer()),
                        "unsolicited DNS response",
                    );
                    if !send_status(h3, intake.peer(), r.stream_id, b"400") {
                        return;
                    }
                    continue;
                }
                Err(error) => {
                    /*
                     * 읽지 못한 본문은 요청 잘못이다. 아무것도 보내지 않으면 스트림이 매달린
                     * 채로 클라이언트가 자기 데드라인까지 기다린다. 응답을 질의로 보낸 경우와
                     * 같은 상태로 답한다.
                     */
                    transport_observe::record_error(
                        Self::NAME,
                        "dns_parse",
                        Some(intake.peer()),
                        error,
                    );
                    if !send_status(h3, intake.peer(), r.stream_id, b"400") {
                        return;
                    }
                    continue;
                }
            };
            let authenticated = h3.client_authenticated();
            let auth_identity = h3.client_auth_identity().map(str::to_string);
            let client_id = match crate::doh::authenticated_path_identity(
                r.client_id.as_deref(),
                authenticated,
                auth_identity.as_deref(),
            ) {
                Ok(id) => id,
                Err(()) => {
                    onetdns_core::warn!(event = "doh3.client_id_mismatch",
                        peer = %intake.peer(),
                        path_identity = %r.client_id.as_deref().unwrap_or(""),
                        auth_identity = %auth_identity.as_deref().unwrap_or(""),
                        "Client ID in the DoH3 URL does not match the client ID in the mTLS certificate"
                    );
                    if !send_status(h3, intake.peer(), r.stream_id, b"403") {
                        return;
                    }
                    continue;
                }
            };
            let job = QueryJob {
                conn_key: intake.key().to_vec(),
                epoch: intake.epoch(),
                stream_id: r.stream_id,
                query: r.wire,
                peer: intake.peer(),
                transport: RtTransport::DoH3,
                client_id,
                authenticated,
                auth_identity,
            };
            if !intake.submit::<Self>(h3, &req, job) {
                return;
            }
        }
    }

    fn send_answer(
        h3: &mut H3Connection,
        stream_id: u64,
        wire: Vec<u8>,
        max_age: u32,
    ) -> Result<(), QuicError> {
        h3.send_response_owned(stream_id, wire, max_age)
    }

    fn abandon(h3: &mut H3Connection, why: Abandon) {
        h3.close(match why {
            Abandon::Shutdown => H3Error::NoError,
            Abandon::Internal => H3Error::Internal,
            Abandon::ExcessiveLoad => H3Error::ExcessiveLoad,
        });
    }
}

/**
 * @brief 본문 없이 상태 코드만 답한다.
 * @return 연결을 계속 쓸 수 있으면 true. 못 쓰면 연결은 이미 닫혔다.
 */
fn send_status(h3: &mut H3Connection, peer: SocketAddr, stream_id: u64, status: &[u8]) -> bool {
    let sent = h3.send_status(stream_id, status);
    quic_listener::connection_survives::<Doh3>(h3, peer, sent)
}

#[cfg(test)]
/** @brief 종료, 그리고 실제 HTTP/3 위 질의 왕복. */
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::thread;
    use std::time::{Duration, Instant};

    use onetdns_core::BlockResponse;
    use onetdns_filter::{build_from_str, SharedFilter};
    use onetdns_forward::Forwarder;
    use onetdns_proto::{Name as ApName, RData as ApRData, RecordType};
    use onetdns_quic::params::TransportParams;
    use onetdns_quic::{h3, qpack, Connection};
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
    fn self_signed_h3() -> Arc<ServerConfig> {
        let (certs, key) = onetdns_transport::self_signed_material("dns.test").unwrap();
        let cert_der = certs[0].clone();
        let key_der = key.clone();
        Arc::new(
            ServerConfig::from_pkcs8(cert_der, &key_der)
                .expect("ECDSA P-256")
                .with_alpn(vec![b"h3".to_vec()]),
        )
    }

    /** @brief 테스트 하나가 쓰는 독립 QUIC 전역 예산. */
    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    /** @brief 종료 때 반복이 정리되는지. */
    fn dropping_doh3_listener_joins_event_loop() {
        let listener = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".to_string(),
            Arc::new(AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let started = Instant::now();
        drop(listener);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /** @brief HTTP/3로 질의를 보내고 답을 받는다. */
    fn doh3_query(server: SocketAddr, name: &str, qtype: RecordType) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let cfg = ClientConfig {
            server_name: "dns.test".into(),
            verify_name: false,
            roots: None,
            insecure_verifier: Some(
                onetdns_tls::InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let mut client = Connection::new_client(
            cfg,
            random_cid(),
            random_cid(),
            TransportParams::server_defaults(),
        )
        .unwrap();

        let query = Message::query(0x4242, ApName::from_str(name).unwrap(), qtype)
            .try_encode()
            .unwrap();
        let mut sent = false;
        let mut stream0: Vec<u8> = Vec::new();
        let mut b = [0u8; 2048];
        /*
         * 한도는 반복 횟수가 아니라 시각으로 둔다. 연결 상태 기계는 시계를 직접 읽지 않으므로
         * 시각을 넘기고 재전송 타이머를 돌린다. 돌리지 않으면 클라이언트가 보낸 데이터그램
         * 하나가 사라졌을 때 다시 보내지 않아 응답을 끝내 받지 못한다.
         */
        let clock = Instant::now();
        let deadline = clock + Duration::from_secs(15);
        while Instant::now() < deadline {
            let now_ms = clock.elapsed().as_millis() as u64;
            client.set_now(now_ms);
            client.on_timeout(now_ms);
            while let Some(dg) = client.next_datagram() {
                sock.send_to(&dg, server).unwrap();
            }
            if client.is_handshake_complete() && !sent {
                let mut payload = Vec::new();
                h3::encode_frame(
                    &mut payload,
                    h3::FRAME_HEADERS,
                    &qpack::doh_post_request_headers("dns.test", "/dns-query", query.len()),
                );
                h3::encode_frame(&mut payload, h3::FRAME_DATA, &query);
                client.send_stream(0, &payload, true).unwrap();
                sent = true;
                while let Some(dg) = client.next_datagram() {
                    sock.send_to(&dg, server).unwrap();
                }
            }
            for (id, data, _fin) in client.take_readable() {
                if id == 0 {
                    stream0.extend_from_slice(&data);
                }
            }
            if let Some(frames) = h3::parse_frames(&stream0) {
                for (t, p) in &frames {
                    if *t == h3::FRAME_DATA && !p.is_empty() {
                        return Message::parse(p).unwrap();
                    }
                }
            }
            if let Ok((n, _)) = sock.recv_from(&mut b) {
                client.recv_datagram(&b[..n]).unwrap();
            }
        }
        panic!("DoH3 응답 없음");
    }

    #[test]
    /** @brief 허용된 이름이 해석되는지. */
    fn doh3_allowed_query_resolves_over_self_h3() {
        let l = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".into(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doh3_query(l.addr(), "allowed.test", RecordType::A);
        assert_eq!(resp.header.id, 0x4242);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].rdata {
            ApRData::A(ip) => assert_eq!(*ip, std::net::Ipv4Addr::new(9, 9, 9, 9)),
            other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
        }
    }

    #[test]
    /** @brief 차단된 이름이 막히는지. */
    fn doh3_blocked_query_returns_nxdomain_over_self_h3() {
        let l = serve_doh3(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(onetdns_core::ArcSwap::new(self_signed_h3())),
            native_handler(),
            "/dns-query".into(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            memory_budget(),
        )
        .unwrap();
        let resp = doh3_query(l.addr(), "blocked.test", RecordType::A);
        assert_eq!(resp.header.rcode, onetdns_proto::ResponseCode::NXDomain.0);
        assert!(resp.answers.is_empty());
    }
}
