use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onetdns_core::udp::RecvWait;
use onetdns_quic::params::TransportParams;
use onetdns_quic::{Connection, QuicError};
use onetdns_tls::{ClientConfig, TlsSession, TrustStore};

use crate::{io_err, ForwardError};

/** @brief QUIC 연결을 구동할 때의 폴링 간격. */
const POLL: Duration = Duration::from_millis(200);

/** @brief 보관할 TLS 세션 티켓 수. 0-RTT 재개에 쓴다. */
const MAX_CACHED_SESSIONS: usize = 256;

/** @brief (주소, 서버 이름, ALPN, 보안 정책)별 세션 티켓. 워커 사이에서 공유된다. */
static SESSIONS: Mutex<
    Option<HashMap<(SocketAddr, String, Vec<u8>, crate::TlsCacheScope), TlsSession>>,
> = Mutex::new(None);

/** @brief 재개에 쓸 세션 티켓을 꺼낸다. */
pub(crate) fn cached_session(
    addr: SocketAddr,
    server_name: &str,
    alpn: &[u8],
    trust: &TrustStore,
) -> Option<TlsSession> {
    let mut guard = SESSIONS.lock().ok()?;
    let map = guard.as_mut()?;
    let key = (
        addr,
        server_name.to_string(),
        alpn.to_vec(),
        crate::tls_cache_scope(trust),
    );
    let now_ms = onetdns_tls::session::now_ms();
    if map.get(&key).is_some_and(|s| !s.is_fresh(now_ms)) {
        map.remove(&key);
        return None;
    }
    map.get(&key).cloned()
}

/** @brief 세션 티켓을 보관한다. 상한을 넘으면 오래된 것부터 버린다. */
fn cache_session(
    map: &mut HashMap<(SocketAddr, String, Vec<u8>, crate::TlsCacheScope), TlsSession>,
    key: (SocketAddr, String, Vec<u8>, crate::TlsCacheScope),
    session: TlsSession,
    now_ms: u64,
) {
    map.retain(|_, cached| cached.is_fresh(now_ms));
    if !map.contains_key(&key) && map.len() >= MAX_CACHED_SESSIONS {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, cached)| cached.obtained_at_ms)
            .map(|(key, _)| key.clone())
        {
            map.remove(&oldest);
        }
    }
    map.insert(key, session);
}

/** @brief 연결에서 새로 받은 세션 티켓을 거둬 보관한다. */
pub(crate) fn harvest_sessions(
    conn: &mut Connection,
    addr: SocketAddr,
    server_name: &str,
    alpn: &[u8],
    trust: &TrustStore,
) {
    let new = conn.take_new_sessions();
    if new.is_empty() {
        return;
    }
    if let Ok(mut guard) = SESSIONS.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some(last) = new.into_iter().last() {
            cache_session(
                map,
                (
                    addr,
                    server_name.to_string(),
                    alpn.to_vec(),
                    crate::tls_cache_scope(trust),
                ),
                last,
                onetdns_tls::session::now_ms(),
            );
        }
    }
}

/**
 * @brief 소켓 없이 만들어진 QUIC 상태를 구동하는 인터페이스.
 *
 * @details onetdns-quic은 sans-IO다. 소켓을 몰라서 스스로 데이터그램을 주고받지 못한다.
 *          이 트레이트가 그 상태를 실제 소켓에 연결하는 지점이며, DoQ 연결과 DoH3
 *          클라이언트가 각각 구현한다.
 */
pub(crate) trait QuicDriven {
    /** @brief 받은 데이터그램을 상태에 넣는다. */
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError>;
    /** @brief 내보낼 데이터그램을 꺼낸다. 없으면 None. */
    fn next_datagram(&mut self) -> Option<Vec<u8>>;
    /** @brief 핸드셰이크가 끝났는지. */
    fn is_handshake_complete(&self) -> bool;
    /** @brief 응용 데이터를 보낼 수 있는 상태인지. */
    fn can_send_app(&self) -> bool;
    /** @brief 연결이 닫혔는지. */
    fn is_closed(&self) -> bool;
    /** @brief 연결이 닫힌 까닭. 진단에 쓴다. */
    fn close_detail(&mut self) -> Option<String>;

    /** @brief 현재 시각을 알려 준다. sans-IO라 시계도 밖에서 넣어 준다. */
    fn set_now(&mut self, now_ms: u64);

    /** @brief 타이머 만료를 처리한다. 재전송과 유휴 종료가 여기서 일어난다. */
    fn on_timeout(&mut self, now_ms: u64);
}

impl QuicDriven for Connection {
    /** @brief 받은 데이터그램을 상태 기계에 넣는다. */
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        Connection::recv_datagram(self, dg)
    }
    /** @brief 내보낼 데이터그램. 없으면 없다. */
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        Connection::next_datagram(self)
    }
    /** @brief 핸드셰이크가 끝났는지. */
    fn is_handshake_complete(&self) -> bool {
        Connection::is_handshake_complete(self)
    }
    /** @brief 이제 질의를 보낼 수 있는지. */
    fn can_send_app(&self) -> bool {
        Connection::can_send_app(self)
    }
    /** @brief 연결이 닫혔는지. */
    fn is_closed(&self) -> bool {
        Connection::is_closed(self)
    }
    /** @brief 연결이 닫힌 까닭. */
    fn close_detail(&mut self) -> Option<String> {
        Connection::close_detail(self)
    }
    /** @brief 지금 시각을 알린다. */
    fn set_now(&mut self, now_ms: u64) {
        Connection::set_now(self, now_ms)
    }
    /** @brief 데드라인이 지났음을 알려 재전송을 돌린다. */
    fn on_timeout(&mut self, now_ms: u64) {
        Connection::on_timeout(self, now_ms);
    }
}

impl QuicDriven for onetdns_quic::H3Client {
    /** @brief 받은 데이터그램을 상태 기계에 넣는다. */
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        onetdns_quic::H3Client::recv_datagram(self, dg)
    }
    /** @brief 내보낼 데이터그램. 없으면 없다. */
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        onetdns_quic::H3Client::next_datagram(self)
    }
    /** @brief 핸드셰이크가 끝났는지. */
    fn is_handshake_complete(&self) -> bool {
        onetdns_quic::H3Client::is_handshake_complete(self)
    }
    /** @brief 이제 질의를 보낼 수 있는지. */
    fn can_send_app(&self) -> bool {
        onetdns_quic::H3Client::can_send_app(self)
    }
    /** @brief 연결이 닫혔는지. */
    fn is_closed(&self) -> bool {
        onetdns_quic::H3Client::is_closed(self)
    }
    /** @brief 연결이 닫힌 까닭. */
    fn close_detail(&mut self) -> Option<String> {
        self.conn_mut().close_detail()
    }
    /** @brief 지금 시각을 알린다. */
    fn set_now(&mut self, now_ms: u64) {
        self.conn_mut().set_now(now_ms)
    }
    /** @brief 데드라인이 지났음을 알려 재전송을 돌린다. */
    fn on_timeout(&mut self, now_ms: u64) {
        self.conn_mut().on_timeout(now_ms);
    }
}

/** @brief 응답이 전혀 없을 때 연결을 포기하기까지의 시간. PTO의 배수로 정한다. */
pub(crate) fn silence_limit_ms(base_pto_ms: u64) -> u64 {
    (3 * base_pto_ms).clamp(500, 1500)
}

/**
 * @brief 무작위 연결 ID를 만든다.
 * @warning 예측 가능한 연결 ID는 경로 밖 공격자가 연결을 흉내 내는 경로가 된다.
 */
pub(crate) fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    onetdns_tls::sys::fill_random(&mut cid);
    cid.to_vec()
}

/**
 * @brief 업스트림 QUIC 클라이언트의 TLS 설정.
 *
 * @details 세션 티켓이 있으면 재개를 시도한다. 재개는 PSK-DHE로만 하므로 전방 비밀성이
 *          유지된다.
 * @warning 0-RTT는 켜지 않는다. 켜면 DoQ·DoH3 질의가 전방 비밀성 없는 early data로 나가
 *          경로상 공격자가 기록해 두었다가 그대로 재생할 수 있고, 티켓 키가 나중에
 *          털리면 어떤 이름을 물었는지가 드러난다. DoH3는 POST를 쓰므로 RFC 8470이
 *          경고하는 형태이기도 하다. doh3·doq의 can_send_early 분기는 이 값이 거짓이라
 *          생산 경로에서 닿지 않는다. 이 값을 바꾸면 그 분기가 살아난다.
 */
pub(crate) fn client_tls_config(
    addr: SocketAddr,
    server_name: &str,
    alpn: &[u8],
    trust: &TrustStore,
) -> ClientConfig {
    ClientConfig {
        server_name: server_name.to_string(),
        verify_name: true,
        roots: Some(trust.clone()),
        alpn: vec![alpn.to_vec()],
        session: cached_session(addr, server_name, alpn, trust),
        enable_early_data: false,
        ..Default::default()
    }
}

/**
 * @brief 상대에 연결한 QUIC 소켓과 그 소켓에 건 수신 한도.
 * @details 수신은 반드시 이 한도로 기다려야 한다. 소켓 수신 한도에 기대면 윈도우에서 한도에
 *          걸리는 순간 도착한 데이터그램을 버린다.
 */
pub(crate) struct QuicSocket {
    /** @brief 상대에 연결한 UDP 소켓. */
    sock: UdpSocket,
    /** @brief 이 소켓에 건 수신 한도. */
    wait: RecvWait,
}

/** @brief 클라이언트 QUIC 연결 상태를 만든다. 세션 티켓이 있으면 재개를 시도한다. */
pub(crate) fn new_client_connection(
    addr: SocketAddr,
    server_name: &str,
    alpn: &[u8],
    read_timeout: Duration,
    trust: &TrustStore,
) -> Result<(QuicSocket, Connection), ForwardError> {
    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = onetdns_core::udp::bind(bind).map_err(io_err)?;
    sock.connect(addr).map_err(io_err)?;
    let wait = RecvWait::new(read_timeout.min(POLL));
    wait.install(&sock).map_err(io_err)?;

    let cfg = client_tls_config(addr, server_name, alpn, trust);
    let conn = Connection::new_client(
        cfg,
        random_cid(),
        random_cid(),
        TransportParams::server_defaults(),
    )
    .map_err(|_| ForwardError::Io("Could not create QUIC client".into()))?;
    Ok((QuicSocket { sock, wait }, conn))
}

/**
 * @brief QUIC 상대 인증서의 폐기 여부를 확인한다.
 * @details 연결당 한 번, 핸드셰이크가 끝난 직후에 부른다. DoQ와 DoH3가 공유한다.
 */
pub(crate) fn check_peer_revocation(
    conn: &Connection,
    server_name: &str,
    checked: &mut bool,
) -> Result<(), ForwardError> {
    if *checked || !conn.is_handshake_complete() {
        return Ok(());
    }
    let chain = conn.verified_chain();
    if !chain.is_empty() {
        crate::check_revocation(chain, server_name)?;
    }
    *checked = true;
    Ok(())
}

/** @brief 상태가 내보낼 데이터그램을 전부 소켓으로 보낸다. */
pub(crate) fn flush_out<D: QuicDriven>(sock: &QuicSocket, d: &mut D) -> Result<(), ForwardError> {
    while let Some(dg) = d.next_datagram() {
        sock.sock.send(&dg).map_err(io_err)?;
    }
    Ok(())
}

/**
 * @brief 데이터그램 하나를 받아 상태에 넣는다.
 * @details 넣다가 연결 오류가 나면 상태 기계는 그 오류를 알리는 종료 프레임을 쌓아 두고
 *          닫힌다. 부른 쪽은 이 오류를 받으면 연결을 버리므로 여기서 그 프레임을 내보낸다.
 * @return 데이터그램을 받았으면 true, 수신 한도까지 아무것도 오지 않았으면 false.
 */
pub(crate) fn recv_once<D: QuicDriven>(
    sock: &QuicSocket,
    d: &mut D,
    buf: &mut [u8],
) -> Result<bool, ForwardError> {
    use std::io::ErrorKind;
    match sock.wait.recv(&sock.sock, buf) {
        Ok(n) => {
            if let Err(error) = d.recv_datagram(&buf[..n]) {
                /*
                 * 종료 프레임을 보내지 못해도 돌려줄 것은 원래 오류다.
                 */
                let _ = flush_out(sock, d);
                return Err(ForwardError::Io(format!(
                    "Could not process QUIC datagram: {error}"
                )));
            }
            Ok(true)
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(false),
        Err(e) => Err(io_err(e)),
    }
}

/**
 * @brief 핸드셰이크가 끝날 때까지 연결을 구동한다.
 * @details 데드라인과 무응답 한도를 함께 본다. 응답이 오지만 진전이 없는 경우와 아예 침묵인
 *          경우를 모두 끊어야 한다.
 */
pub(crate) fn pump_handshake<D: QuicDriven>(
    sock: &QuicSocket,
    d: &mut D,
    created: Instant,
    deadline: Instant,
) -> Result<(), ForwardError> {
    let mut buf = [0u8; onetdns_quic::MAX_RECV_UDP_PAYLOAD as usize];
    d.set_now(created.elapsed().as_millis() as u64);
    flush_out(sock, d)?;
    while Instant::now() < deadline {
        if d.is_closed() {
            let detail = d
                .close_detail()
                .unwrap_or_else(|| "Closed without a reason".into());
            return Err(ForwardError::Io(format!("QUIC handshake failed: {detail}")));
        }
        if d.is_handshake_complete() && d.can_send_app() {
            d.set_now(created.elapsed().as_millis() as u64);
            flush_out(sock, d)?;
            return Ok(());
        }
        d.set_now(created.elapsed().as_millis() as u64);
        let got = recv_once(sock, d, &mut buf)?;
        if !got {
            d.on_timeout(created.elapsed().as_millis() as u64);
        }
        flush_out(sock, d)?;
    }
    Err(ForwardError::Timeout)
}

#[cfg(test)]
/** @brief 담아 둔 세션이 만료되고 상한을 지키는지. */
mod tests {
    use super::*;

    /** @brief 테스트용 세션. */
    fn session(obtained_at_ms: u64, lifetime_secs: u32) -> TlsSession {
        TlsSession {
            server_name: "dns.example".to_string(),
            suite: 0x1301,
            psk: vec![1; 32],
            ticket: vec![2; 32],
            lifetime_secs,
            age_add: 0,
            max_early_data: 0,
            alpn: Some(b"h3".to_vec()),
            server_transport_params: Vec::new(),
            obtained_at_ms,
        }
    }

    #[test]
    /**
     * @brief 업스트림 QUIC 클라이언트가 0-RTT를 제시하지 않는지.
     * @details 켜지면 질의가 전방 비밀성 없는 early data로 나가 재생 가능해진다.
     *          기본값에 기대지 않고 여기서 값을 못 고정한다. doh3·doq의 can_send_early
     *          분기가 이 값 하나로 생산 경로에서 죽어 있기 때문이다.
     */
    fn forward_quic_client_never_offers_early_data() {
        let trust = TrustStore::empty();
        for alpn in [b"doq".as_slice(), b"h3".as_slice()] {
            let cfg = client_tls_config(
                "127.0.0.1:853".parse().expect("고정 주소"),
                "dns.example",
                alpn,
                &trust,
            );
            assert!(
                !cfg.enable_early_data,
                "업스트림 {} 클라이언트가 0-RTT를 켰습니다",
                String::from_utf8_lossy(alpn)
            );
        }
    }

    #[test]
    /** @brief 만료된 세션이 걷히고 담는 양이 상한을 지키는지. */
    fn session_cache_prunes_expired_entries_and_stays_bounded() {
        let mut map = HashMap::new();
        let scope = crate::tls_cache_scope(&TrustStore::empty());
        map.insert(
            (
                SocketAddr::from(([127, 0, 0, 1], 1)),
                "expired".into(),
                b"h3".to_vec(),
                scope,
            ),
            session(0, 1),
        );

        for port in 2..=(MAX_CACHED_SESSIONS as u16 + 2) {
            cache_session(
                &mut map,
                (
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    port.to_string(),
                    b"h3".to_vec(),
                    scope,
                ),
                session(port as u64, 3600),
                2_000,
            );
        }

        assert_eq!(map.len(), MAX_CACHED_SESSIONS);
        assert!(!map.keys().any(|(_, name, _, _)| name == "expired"));
        assert!(!map.keys().any(|(addr, _, _, _)| addr.port() == 2));
        assert!(map.keys().any(|(addr, _, _, _)| addr.port() == 258));
    }
}
