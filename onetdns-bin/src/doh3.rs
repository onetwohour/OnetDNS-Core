//! DoH3 listener: DNS over HTTP/3 over QUIC. quic_listener accepts and keeps connections; this
//! checks requests, hands them to workers, and writes responses to streams.

use std::io;
use std::net::{SocketAddr, UdpSocket};
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

/// Serves DoH3 on `socket`, already bound.
pub fn serve_doh3(
    socket: UdpSocket,
    tls: Arc<onetdns_core::ArcSwap<ServerConfig>>,
    handler: Arc<NativeServer>,
    doh_path: String,
    shutdown: Arc<AtomicBool>,
    memory_budget: Arc<QuicMemoryBudget>,
) -> io::Result<QuicListener> {
    quic_listener::serve(
        Doh3 { doh_path },
        socket,
        tls,
        handler,
        shutdown,
        memory_budget,
    )
}

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

pub(crate) struct Doh3 {
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
                    // An unreadable body is the request's fault. Sending nothing would leave the
                    // stream hanging until the client's deadline, so it gets the same status as a
                    // response sent as a query.
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

    fn go_away(h3: &mut H3Connection) -> Result<(), QuicError> {
        h3.go_away()
    }

    fn abandon(h3: &mut H3Connection, why: Abandon) {
        h3.close(match why {
            Abandon::Shutdown => H3Error::NoError,
            Abandon::Internal => H3Error::Internal,
            Abandon::ExcessiveLoad => H3Error::ExcessiveLoad,
        });
    }
}

/// True when the connection is still usable; otherwise it is already closed.
fn send_status(h3: &mut H3Connection, peer: SocketAddr, stream_id: u64, status: &[u8]) -> bool {
    let sent = h3.send_status(stream_id, status);
    quic_listener::connection_survives::<Doh3>(h3, peer, sent)
}

#[cfg(test)]
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

    fn memory_budget() -> Arc<QuicMemoryBudget> {
        Arc::new(QuicMemoryBudget::default())
    }

    #[test]
    fn dropping_doh3_listener_joins_event_loop() {
        let listener = serve_doh3(
            onetdns_core::udp::bind(([127, 0, 0, 1], 0)).unwrap(),
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
        // The limit is a deadline, not an iteration count. The connection never reads a clock, so
        // time is passed in and retransmission timers run; otherwise one lost client datagram would
        // never be resent and no answer would arrive.
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
    fn doh3_allowed_query_resolves_over_self_h3() {
        let l = serve_doh3(
            onetdns_core::udp::bind(([127, 0, 0, 1], 0)).unwrap(),
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
    fn doh3_blocked_query_returns_nxdomain_over_self_h3() {
        let l = serve_doh3(
            onetdns_core::udp::bind(([127, 0, 0, 1], 0)).unwrap(),
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
