use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use onetdns_core::udp::RecvWait;
use onetdns_quic::params::TransportParams;
use onetdns_quic::{Connection, QuicError};
use onetdns_tls::{ClientConfig, TlsSession, TrustStore};

use crate::{io_err, ForwardError};

const POLL: Duration = Duration::from_millis(200);

/// Session tickets kept for resumption.
const MAX_CACHED_SESSIONS: usize = 256;

/// Keyed by address, server name, ALPN, and security policy; shared across workers.
static SESSIONS: Mutex<
    Option<HashMap<(SocketAddr, String, Vec<u8>, crate::TlsCacheScope), TlsSession>>,
> = Mutex::new(None);

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

/// Evicts the oldest past the limit.
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

/// Drives a QUIC state machine built without sockets. onetdns-quic is sans-IO and cannot send or
/// receive datagrams itself; this trait connects it to a real socket, implemented by DoQ
/// connections and the DoH3 client.
pub(crate) trait QuicDriven {
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError>;
    fn next_datagram(&mut self) -> Option<Vec<u8>>;
    fn is_handshake_complete(&self) -> bool;
    fn can_send_app(&self) -> bool;
    fn is_closed(&self) -> bool;
    fn close_detail(&mut self) -> Option<String>;

    /// Sans-IO, so the clock comes from outside too.
    fn set_now(&mut self, now_ms: u64);

    /// Retransmission and idle close happen here.
    fn on_timeout(&mut self, now_ms: u64);
}

impl QuicDriven for Connection {
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        Connection::recv_datagram(self, dg)
    }
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        Connection::next_datagram(self)
    }
    fn is_handshake_complete(&self) -> bool {
        Connection::is_handshake_complete(self)
    }
    fn can_send_app(&self) -> bool {
        Connection::can_send_app(self)
    }
    fn is_closed(&self) -> bool {
        Connection::is_closed(self)
    }
    fn close_detail(&mut self) -> Option<String> {
        Connection::close_detail(self)
    }
    fn set_now(&mut self, now_ms: u64) {
        Connection::set_now(self, now_ms)
    }
    fn on_timeout(&mut self, now_ms: u64) {
        Connection::on_timeout(self, now_ms);
    }
}

impl QuicDriven for onetdns_quic::H3Client {
    fn recv_datagram(&mut self, dg: &[u8]) -> Result<(), QuicError> {
        onetdns_quic::H3Client::recv_datagram(self, dg)
    }
    fn next_datagram(&mut self) -> Option<Vec<u8>> {
        onetdns_quic::H3Client::next_datagram(self)
    }
    fn is_handshake_complete(&self) -> bool {
        onetdns_quic::H3Client::is_handshake_complete(self)
    }
    fn can_send_app(&self) -> bool {
        onetdns_quic::H3Client::can_send_app(self)
    }
    fn is_closed(&self) -> bool {
        onetdns_quic::H3Client::is_closed(self)
    }
    fn close_detail(&mut self) -> Option<String> {
        self.conn_mut().close_detail()
    }
    fn set_now(&mut self, now_ms: u64) {
        self.conn_mut().set_now(now_ms)
    }
    fn on_timeout(&mut self, now_ms: u64) {
        self.conn_mut().on_timeout(now_ms);
    }
}

/// How long total silence lasts before giving up, as a multiple of the PTO.
pub(crate) fn silence_limit_ms(base_pto_ms: u64) -> u64 {
    (3 * base_pto_ms).clamp(500, 1500)
}

/// A predictable connection ID lets an off-path attacker impersonate the connection.
pub(crate) fn random_cid() -> Vec<u8> {
    let mut cid = [0u8; 8];
    onetdns_tls::sys::fill_random(&mut cid);
    cid.to_vec()
}

/// Resumes when a session ticket exists, only with PSK-DHE, so forward secrecy holds.
///
/// 0-RTT stays off. With it on, DoQ and DoH3 queries would go out as early data without forward
/// secrecy: an on-path attacker could record and replay them, and a ticket key leaked later would
/// reveal which names were asked. DoH3 uses POST, the form RFC 8470 warns about. Opportunistic
/// encryption sends early data over DoQ under its own config; for configured upstreams this value
/// is what keeps it off.
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

/// A connected QUIC socket and the receive limit set on it. Receives must wait with this limit;
/// relying on the socket's own receive timeout drops datagrams arriving at the moment it fires on
/// Windows.
pub(crate) struct QuicSocket {
    sock: UdpSocket,
    wait: RecvWait,
}

/// Resumes when a session ticket exists.
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
    let cfg = client_tls_config(addr, server_name, alpn, trust);
    open_client_connection(addr, bind, cfg, read_timeout)
}

pub(crate) fn open_client_connection(
    addr: SocketAddr,
    bind: SocketAddr,
    cfg: ClientConfig,
    read_timeout: Duration,
) -> Result<(QuicSocket, Connection), ForwardError> {
    let sock = onetdns_core::udp::bind(bind).map_err(io_err)?;
    sock.connect(addr).map_err(io_err)?;
    let wait = RecvWait::new(read_timeout.min(POLL));
    wait.install(&sock).map_err(io_err)?;

    let conn = Connection::new_client(
        cfg,
        random_cid(),
        random_cid(),
        TransportParams::server_defaults(),
    )
    .map_err(|_| ForwardError::Io("Could not create QUIC client".into()))?;
    Ok((QuicSocket { sock, wait }, conn))
}

/// Once per connection, right after the handshake, shared by DoQ and DoH3. A rejection closes with
/// CRYPTO_ERROR, as when TLS rejects a certificate.
pub(crate) fn check_peer_revocation(
    conn: &mut Connection,
    server_name: &str,
    checked: &mut bool,
) -> Result<(), ForwardError> {
    if *checked || !conn.is_handshake_complete() {
        return Ok(());
    }
    let chain = conn.verified_chain();
    if !chain.is_empty() {
        if let Err(error) = crate::check_revocation(chain, server_name) {
            conn.reject_peer_certificate("Certificate revocation check failed");
            return Err(error);
        }
    }
    *checked = true;
    Ok(())
}

pub(crate) fn flush_out<D: QuicDriven>(sock: &QuicSocket, d: &mut D) -> Result<(), ForwardError> {
    while let Some(dg) = d.next_datagram() {
        sock.sock.send(&dg).map_err(io_err)?;
    }
    Ok(())
}

/// Receives one datagram into the state. A connection error there queues a close frame and closes
/// the state; the frame goes out when the owning DoqConn or Doh3Conn is dropped. True when a
/// datagram arrived, false when nothing came within the receive limit.
pub(crate) fn recv_once<D: QuicDriven>(
    sock: &QuicSocket,
    d: &mut D,
    buf: &mut [u8],
) -> Result<bool, ForwardError> {
    use std::io::ErrorKind;
    match sock.wait.recv(&sock.sock, buf) {
        Ok(n) => {
            if let Err(error) = d.recv_datagram(&buf[..n]) {
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

/// Watches both the deadline and the silence limit: a peer that answers without progress and one
/// that stays silent must both be cut off.
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
/// Fills the send buffer to the end as if the peer had acknowledged nothing, on stream numbers
/// beyond what the peer allows, so nothing actually goes out. After this, not one more byte can be
/// sent.
pub(crate) fn fill_send_buffer(conn: &mut Connection) {
    let mut id = 1u64 << 40;
    let mut size = 64 * 1024;
    while size > 0 {
        if conn.send_stream(id, &vec![0; size], false).is_ok() {
            id += 4;
        } else {
            size /= 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// Early data would carry queries without forward secrecy, open to replay. The value is pinned
    /// here instead of relying on the default, since this one value keeps configured upstreams from
    /// sending it.
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
