/*!
 * @brief DNSCrypt 리스너.
 *
 * @details 같은 주소를 UDP 와 TCP 둘 다로 받는다. 규격은 인증서 조회부터 UDP 로 하고
 *          실패나 절단이면 TCP 로 다시 하라고 하며, 잘린 응답을 본 클라이언트에게도 TCP
 *          재시도를 먼저 시킨다. UDP 만 열면 그 경로가 전부 막힌다.
 */

use std::io::{self, Read, Write};
#[cfg(test)]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use onetdns_dnscrypt::Provider;
use onetdns_proto::{Message, Writer};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};

use crate::connection_limit::{
    poll_pending_encrypted_connections, spawn_bounded_connection_thread, wake_tcp_listener,
    AdmissionProtocol, ConnectionLimiter, ConnectionTracker, PendingEncryptedConnection,
    PrefixedTcp, ENCRYPTED_ACCEPT_BATCH,
};
use crate::native::NativeServer;
use crate::transport_observe;

/** @brief 연결 하나의 입출력 데드라인. */
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/** @brief 종료 신호를 확인하는 주기. */
const SHUTDOWN_POLL: Duration = Duration::from_millis(250);

/** @brief 질의를 처리해 DNS 응답 와이어를 돌려주는 콜백. */
fn make_handler(
    handler: Arc<NativeServer>,
) -> impl Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>> {
    move |dns_query: Vec<u8>, src: SocketAddr, budget: usize| {
        let request = Message::parse(&dns_query).ok()?;
        if request.header.response {
            return None;
        }
        let ctx = RequestCtx {
            src,
            transport: RtTransport::DnsCrypt,
            raw: Some(dns_query.as_slice()),
            client_id: None,
            authenticated: false,
            auth_identity: None,
        };
        let response = handler.handle(&request, &ctx)?;
        let mut writer = Writer::new();
        onetdns_runtime::encode_within(&request, &response, &mut writer, budget);
        writer.finish().ok()
    }
}

/** @brief 이 주소에 답해도 되는지 묻는 콜백. */
fn make_gate(handler: Arc<NativeServer>) -> impl Fn(SocketAddr) -> bool {
    move |src: SocketAddr| {
        handler.client_allowed(&RequestCtx {
            src,
            transport: RtTransport::DnsCrypt,
            raw: None,
            client_id: None,
            authenticated: false,
            auth_identity: None,
        })
    }
}

/**
 * @brief DNSCrypt 요청을 UDP 로 받아 같은 핸들러로 넘긴다. 다른 전송과 파이프라인을 공유한다.
 *
 * @details 응답은 질의 패킷이 허락하는 크기 안으로 줄인다. 넘치면 Do53 과 같은 사다리로
 *          TC 비트를 설정한 축약을 내보내고, 클라이언트는 규격대로 TCP 로 다시 묻거나
 *          패딩을 늘려 다시 묻는다.
 * @note 인증서 조회는 파이프라인을 타지 않으므로 접근 제어와 속도 제한을 여기서 건다.
 */
pub fn serve(
    handler: Arc<NativeServer>,
    socket: UdpSocket,
    provider: Provider,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let gate = make_gate(handler.clone());
    let h = make_handler(handler);
    onetdns_dnscrypt::server::serve(provider, socket, h, gate, &shutdown)
}

/** @brief DNSCrypt TCP 리스너. 사라질 때 연결 스레드를 정리한다. */
pub struct DnscryptTcpListener {
    /** @brief 이 리스너가 묶인 주소. */
    addr: SocketAddr,
    /** @brief 반복을 끝내라는 표시. */
    stop: Arc<AtomicBool>,
    /** @brief 루프를 실행하는 스레드. */
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DnscryptTcpListener {
    /** @brief 종료를 알리고 연결 스레드가 끝나기를 기다린다. */
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_tcp_listener(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/**
 * @brief DNSCrypt 를 TCP 로 받는다.
 *
 * @details 규격은 연결 하나에 거래 하나만 허용한다. 응답을 보내고 나면 양쪽이 연결을
 *          닫으므로 여기서도 한 번 답하고 끝낸다.
 * @warning 길이 접두사를 그대로 믿고 슬롯을 잡으면 아무 숫자나 적어 보낸 쪽이 이 서버의
 *          메모리를 정하게 된다. 상한을 넘으면 읽지 않고 끊는다.
 */
pub fn serve_tcp(
    addr: SocketAddr,
    handler: Arc<NativeServer>,
    provider: Provider,
    admission: Arc<ConnectionLimiter>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<DnscryptTcpListener> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let tracker = ConnectionTracker::new();
    let stop = Arc::new(AtomicBool::new(false));
    let listener_stop = stop.clone();
    let listener_shutdown = shutdown.clone();
    let thread = std::thread::Builder::new()
        .name("dnscrypt-tcp-listener".into())
        .spawn(move || {
            let mut pending = Vec::new();
            let mut listener_nonblocking = false;
            while !listener_shutdown.load(Ordering::Relaxed)
                && !listener_stop.load(Ordering::Relaxed)
            {
                let mut accepted = 0usize;
                if pending.is_empty() {
                    if listener_nonblocking {
                        if let Err(error) = listener.set_nonblocking(false) {
                            transport_observe::record_error(
                                "dnscrypt",
                                "set_listener_blocking",
                                None,
                                error,
                            );
                            break;
                        }
                        listener_nonblocking = false;
                    }
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            if listener_shutdown.load(Ordering::Relaxed)
                                || listener_stop.load(Ordering::Relaxed)
                            {
                                break;
                            }
                            match PendingEncryptedConnection::admit(
                                stream,
                                peer,
                                &admission,
                                AdmissionProtocol::Dnscrypt,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dnscrypt",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dnscrypt",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                            accepted = 1;
                        }
                        Err(error) => {
                            transport_observe::record_error("dnscrypt", "accept", None, error);
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    }
                }

                if !listener_nonblocking {
                    if let Err(error) = listener.set_nonblocking(true) {
                        transport_observe::record_error(
                            "dnscrypt",
                            "set_listener_nonblocking",
                            None,
                            error,
                        );
                        break;
                    }
                    listener_nonblocking = true;
                }
                while accepted < ENCRYPTED_ACCEPT_BATCH {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            accepted += 1;
                            match PendingEncryptedConnection::admit(
                                stream,
                                peer,
                                &admission,
                                AdmissionProtocol::Dnscrypt,
                            ) {
                                Ok(Some(connection)) => pending.push(connection),
                                Ok(None) => transport_observe::record_error(
                                    "dnscrypt",
                                    "connection_limit",
                                    Some(peer),
                                    "maximum concurrent connections reached",
                                ),
                                Err(error) => transport_observe::record_error(
                                    "dnscrypt",
                                    "admission_start",
                                    Some(peer),
                                    error,
                                ),
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => {
                            transport_observe::record_error("dnscrypt", "accept", None, error);
                            break;
                        }
                    }
                }

                poll_pending_encrypted_connections(
                    &mut pending,
                    |stream, peer, guard| {
                        let provider = provider.clone();
                        let handler = handler.clone();
                        let connection_shutdown = listener_shutdown.clone();
                        let connection_stop = listener_stop.clone();
                        let activity = tracker.track();
                        let spawned =
                            spawn_bounded_connection_thread("dnscrypt-tcp-connection", move || {
                                let _guards = (guard, activity);
                                let result = onetdns_core::isolation::catch_request(|| {
                                    serve_conn(
                                        stream,
                                        peer,
                                        &provider,
                                        &handler,
                                        &connection_shutdown,
                                        &connection_stop,
                                    )
                                });
                                if let Ok(Err(error)) = result {
                                    transport_observe::record_error(
                                        "dnscrypt",
                                        "connection",
                                        Some(peer),
                                        error,
                                    );
                                }
                            });
                        match spawned {
                            Ok(thread) => drop(thread),
                            Err(error) => transport_observe::record_error(
                                "dnscrypt",
                                "spawn",
                                Some(peer),
                                error,
                            ),
                        }
                    },
                    |peer, error| {
                        transport_observe::record_error(
                            "dnscrypt",
                            "frame_admission",
                            Some(peer),
                            error,
                        )
                    },
                );
                if !pending.is_empty() {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            drop(pending);
            tracker.wait_until_idle();
        })?;
    Ok(DnscryptTcpListener {
        addr: bound,
        stop,
        thread: Some(thread),
    })
}

/** @brief 연결 하나에서 거래 하나를 처리한다. */
fn serve_conn(
    mut stream: PrefixedTcp,
    peer: SocketAddr,
    provider: &Provider,
    handler: &Arc<NativeServer>,
    shutdown: &AtomicBool,
    stop: &AtomicBool,
) -> io::Result<()> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;

    let mut len_bytes = [0u8; 2];
    read_exact_until(&mut stream, &mut len_bytes, shutdown, stop, deadline)?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len == 0 || len > onetdns_dnscrypt::server::MAX_TCP_QUERY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt TCP query length is out of range",
        ));
    }
    let mut packet = vec![0u8; len];
    read_exact_until(&mut stream, &mut packet, shutdown, stop, deadline)?;

    let gate = make_gate(handler.clone());
    let respond_to = make_handler(handler.clone());
    let Some(payload) =
        onetdns_dnscrypt::server::respond(provider, &packet, peer, false, &respond_to, &gate)
    else {
        return Ok(());
    };
    let Ok(prefix) = u16::try_from(payload.len()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNSCrypt TCP response does not fit in the length prefix",
        ));
    };
    write_all_until(&mut stream, &prefix.to_be_bytes(), shutdown, stop, deadline)?;
    write_all_until(&mut stream, &payload, shutdown, stop, deadline)?;
    stream.flush()
}

/** @brief 절대 데드라인과 종료 신호를 지키며 버퍼를 모두 읽는다. */
fn read_exact_until(
    stream: &mut PrefixedTcp,
    mut buffer: &mut [u8],
    shutdown: &AtomicBool,
    stop: &AtomicBool,
    deadline: std::time::Instant,
) -> io::Result<()> {
    while !buffer.is_empty() {
        if shutdown.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining.min(SHUTDOWN_POLL)))?;
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => buffer = &mut buffer[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) && std::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/** @brief 절대 데드라인과 종료 신호를 지키며 버퍼를 모두 쓴다. */
fn write_all_until(
    stream: &mut PrefixedTcp,
    mut buffer: &[u8],
    shutdown: &AtomicBool,
    stop: &AtomicBool,
    deadline: std::time::Instant,
) -> io::Result<()> {
    while !buffer.is_empty() {
        if shutdown.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_write_timeout(Some(remaining.min(SHUTDOWN_POLL)))?;
        match stream.write(buffer) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) && std::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /** @brief 부분 TCP 프레임이 30초 데드라인까지 리스너 종료를 붙잡지 않는지. */
    fn stalled_tcp_read_observes_listener_stop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut server = PrefixedTcp::new(server, Vec::new());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut length = [0u8; 2];
            read_exact_until(
                &mut server,
                &mut length,
                &AtomicBool::new(false),
                &worker_stop,
                std::time::Instant::now() + IO_TIMEOUT,
            )
            .unwrap_err()
            .kind()
        });

        std::thread::sleep(Duration::from_millis(20));
        let started = std::time::Instant::now();
        stop.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), io::ErrorKind::ConnectionAborted);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "리스너 종료가 DNSCrypt 30초 I/O 데드라인까지 지연됐습니다"
        );
        drop(client);
    }

    #[test]
    /**
     * @brief TCP 리스너가 인증서 조회에 길이 접두사를 붙여 답하고 연결을 닫는지.
     *
     * @details 규격은 연결 하나에 거래 하나다. 클라이언트는 먼저 인증서를 받아야 암호화
     *          질의를 만들 수 있으므로, 이 경로가 막히면 TCP 로 붙는 길이 전부 막힌다.
     */
    fn tcp_listener_answers_a_certificate_lookup_and_closes() {
        let handler = Arc::new(NativeServer::new(
            Arc::new(onetdns_filter::SharedFilter::from_pointee(
                onetdns_filter::build_from_str("", "", onetdns_core::BlockResponse::NxDomain),
            )),
            Arc::new(onetdns_security::IpAcl::allow_all()),
            vec![],
            Arc::new(crate::native::NativeBackend::Forward(
                onetdns_forward::Forwarder::new(
                    vec!["127.0.0.1:1".parse().unwrap()],
                    Duration::from_secs(1),
                ),
            )),
            60,
        ));
        let listener = serve_tcp(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            Provider::generate("2.dnscrypt-cert.onetdns", 86400),
            Arc::new(ConnectionLimiter::default()),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("TCP 리스너");

        let mut question = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in "2.dnscrypt-cert.onetdns".split('.') {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.extend_from_slice(&[0, 0, 16, 0, 1]);

        let mut stream = TcpStream::connect(listener.addr).expect("연결");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("수신 제한 시간");
        let mut framed = (question.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&question);
        stream.write_all(&framed).expect("질의 전송");

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).expect("응답 길이");
        let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).expect("응답 본문");
        assert_eq!(
            &response[..2],
            &question[..2],
            "응답이 질의 ID를 되울립니다"
        );
        assert!(
            response.windows(4).any(|window| window == b"DNSC"),
            "TXT 레코드에 인증서가 실려 있지 않습니다"
        );

        let mut extra = [0u8; 1];
        assert_eq!(
            stream.read(&mut extra).expect("연결 종료 확인"),
            0,
            "거래 하나를 마친 뒤에도 연결이 열려 있습니다"
        );
    }
}
