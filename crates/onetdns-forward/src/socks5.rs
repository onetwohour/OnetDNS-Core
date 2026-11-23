//! SOCKS5 client (RFC 1928) with user name and password authentication (RFC 1929), the way DoT and
//! DoH upstreams reach their server through a proxy such as Tor.

use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use onetdns_core::{SecretBytes, SecretString};

use crate::{DeadlineTcp, ForwardError};

const VERSION: u8 = 5;
const NO_AUTHENTICATION: u8 = 0x00;
const USERNAME_PASSWORD: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const USERNAME_PASSWORD_VERSION: u8 = 1;
const CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// Longest user name, password, or host name the protocol can carry, in bytes.
const MAX_FIELD_LEN: usize = 255;

/// A SOCKS5 proxy and the credentials it asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Proxy {
    addr: SocketAddr,
    credentials: Option<(String, SecretString)>,
}

/// Leaves the password out; values that compare equal still hash alike.
impl Hash for Socks5Proxy {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.credentials.as_ref().map(|(user, _)| user).hash(state);
    }
}

impl std::fmt::Display for Socks5Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socks5://{}", self.addr)
    }
}

impl Socks5Proxy {
    pub fn new(addr: SocketAddr) -> Self {
        Socks5Proxy {
            addr,
            credentials: None,
        }
    }

    /// Each must be 1 to `MAX_FIELD_LEN` bytes; connecting fails otherwise.
    pub fn with_credentials(mut self, username: impl Into<String>, password: SecretString) -> Self {
        self.credentials = Some((username.into(), password));
        self
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn error(&self, reason: &str) -> ForwardError {
        ForwardError::Io(format!("SOCKS5 proxy {} {reason}", self.addr))
    }
}

/// `host:port`, with an IPv6 address in brackets.
pub(crate) fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Opens a tunnel through `proxy` to `host` and `port`. An IP address goes in the request as an
/// address and anything else as a name, so the proxy resolves it and this machine never looks it
/// up.
pub(crate) fn connect(
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<DeadlineTcp, ForwardError> {
    let result = open(proxy, host, port, deadline);
    if let Err(error) = &result {
        note_failure(proxy, host, port, error);
    }
    result
}

fn open(
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<DeadlineTcp, ForwardError> {
    let request = connect_request(host, port)
        .ok_or_else(|| proxy.error("takes a host name of 1 to 255 bytes"))?;
    if proxy.credentials.as_ref().is_some_and(|(user, password)| {
        !(1..=MAX_FIELD_LEN).contains(&user.len()) || !(1..=MAX_FIELD_LEN).contains(&password.len())
    }) {
        return Err(proxy.error("takes a user name and a password of 1 to 255 bytes each"));
    }
    let mut tcp = crate::connect_upstream(proxy.addr, deadline).map_err(crate::io_err)?;
    negotiate(&mut tcp, proxy)?;
    tcp.write_all(&request).map_err(crate::io_err)?;
    read_reply(&mut tcp, proxy)?;
    Ok(tcp)
}

fn negotiate<S: Read + Write>(stream: &mut S, proxy: &Socks5Proxy) -> Result<(), ForwardError> {
    // Offering only the configured method keeps a proxy from picking no authentication when
    // credentials were set.
    let method = match proxy.credentials {
        Some(_) => USERNAME_PASSWORD,
        None => NO_AUTHENTICATION,
    };
    stream
        .write_all(&[VERSION, 1, method])
        .map_err(crate::io_err)?;
    let mut choice = [0u8; 2];
    read_exact(stream, &mut choice, proxy)?;
    if choice[0] != VERSION {
        return Err(proxy.error("answered with something other than SOCKS5"));
    }
    match choice[1] {
        chosen if chosen == method => {}
        NO_ACCEPTABLE_METHODS if method == NO_AUTHENTICATION => {
            return Err(proxy.error("requires a user name and password"));
        }
        NO_ACCEPTABLE_METHODS => {
            return Err(proxy.error("does not accept user name and password authentication"));
        }
        _ => return Err(proxy.error("chose an authentication method that was not offered")),
    }
    if let Some((user, password)) = &proxy.credentials {
        authenticate(stream, proxy, user.as_bytes(), password.as_bytes())?;
    }
    Ok(())
}

fn authenticate<S: Read + Write>(
    stream: &mut S,
    proxy: &Socks5Proxy,
    user: &[u8],
    password: &[u8],
) -> Result<(), ForwardError> {
    let mut request = SecretBytes::new(Vec::with_capacity(3 + user.len() + password.len()));
    request.push(USERNAME_PASSWORD_VERSION);
    request.push(user.len() as u8);
    request.extend_from_slice(user);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).map_err(crate::io_err)?;
    let mut status = [0u8; 2];
    read_exact(stream, &mut status, proxy)?;
    // Only the status decides; the version byte is not checked.
    if status[1] != 0 {
        return Err(proxy.error("rejected the user name or password"));
    }
    Ok(())
}

/// None when the host name is empty or longer than the protocol can carry.
fn connect_request(host: &str, port: u16) -> Option<Vec<u8>> {
    let mut request = vec![VERSION, CONNECT, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(host.len()).ok().filter(|len| *len > 0)?;
            request.push(ATYP_DOMAIN);
            request.push(len);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Some(request)
}

/// Reads the whole reply, bound address included, so TLS starts on the tunnel's first byte.
fn read_reply<S: Read>(stream: &mut S, proxy: &Socks5Proxy) -> Result<(), ForwardError> {
    let mut head = [0u8; 4];
    read_exact(stream, &mut head, proxy)?;
    if head[0] != VERSION {
        return Err(proxy.error("answered with something other than SOCKS5"));
    }
    if head[1] != 0 {
        return Err(proxy.error(&format!(
            "refused the connection: {}",
            reply_reason(head[1])
        )));
    }
    let address_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len, proxy)?;
            usize::from(len[0])
        }
        _ => return Err(proxy.error("answered with an unknown address type")),
    };
    let mut bound = [0u8; MAX_FIELD_LEN + 2];
    read_exact(stream, &mut bound[..address_len + 2], proxy)
}

fn reply_reason(code: u8) -> String {
    match code {
        1 => "general failure".into(),
        2 => "not allowed by its rules".into(),
        3 => "network unreachable".into(),
        4 => "host unreachable".into(),
        5 => "the destination refused the connection".into(),
        6 => "TTL expired".into(),
        7 => "command not supported".into(),
        8 => "address type not supported".into(),
        code => format!("reply code {code}"),
    }
}

fn read_exact<S: Read>(
    stream: &mut S,
    buf: &mut [u8],
    proxy: &Socks5Proxy,
) -> Result<(), ForwardError> {
    stream.read_exact(buf).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            proxy.error("closed the connection")
        } else {
            crate::io_err(error)
        }
    })
}

/// Logs power-of-two occurrences, since a dead proxy fails every query.
fn note_failure(proxy: &Socks5Proxy, host: &str, port: u16, error: &ForwardError) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "forward.proxy_failed", proxy = %proxy, target = %host_port(host, port), count = count, %error, "Could not reach the upstream DNS server through the SOCKS5 proxy");
    }
}

/// SOCKS5 proxy for tests: relays to a loopback address and resolves the names it is given.
#[cfg(test)]
pub(crate) mod test_proxy {
    use std::collections::HashMap;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Clone, Copy)]
    pub(crate) enum Mode {
        Open,
        Password(&'static str, &'static str),
        /// Answers every CONNECT with this reply code.
        Refuse(u8),
    }

    /// A CONNECT as the client sent it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Request {
        pub(crate) atyp: u8,
        pub(crate) host: String,
        pub(crate) port: u16,
    }

    pub(crate) struct TestProxy {
        pub(crate) addr: SocketAddr,
        pub(crate) requests: Arc<Mutex<Vec<Request>>>,
    }

    impl TestProxy {
        pub(crate) fn requests(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    pub(crate) fn spawn(mode: Mode, names: &[(&str, IpAddr)]) -> TestProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let names: Arc<HashMap<String, IpAddr>> = Arc::new(
            names
                .iter()
                .map(|(name, ip)| (name.to_string(), *ip))
                .collect(),
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(client) = stream else { continue };
                let (names, seen) = (Arc::clone(&names), Arc::clone(&seen));
                thread::spawn(move || {
                    let _ = serve(client, mode, &names, &seen);
                });
            }
        });
        TestProxy { addr, requests }
    }

    fn serve(
        mut client: TcpStream,
        mode: Mode,
        names: &HashMap<String, IpAddr>,
        seen: &Mutex<Vec<Request>>,
    ) -> io::Result<()> {
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting)?;
        let mut methods = vec![0u8; usize::from(greeting[1])];
        client.read_exact(&mut methods)?;
        let wanted = match mode {
            Mode::Password(..) => 0x02,
            _ => 0x00,
        };
        if greeting[0] != 5 || !methods.contains(&wanted) {
            return client.write_all(&[5, 0xff]);
        }
        client.write_all(&[5, wanted])?;
        if let Mode::Password(user, password) = mode {
            let mut head = [0u8; 2];
            client.read_exact(&mut head)?;
            let mut sent_user = vec![0u8; usize::from(head[1])];
            client.read_exact(&mut sent_user)?;
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut sent_password = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut sent_password)?;
            if head[0] != 1 || sent_user != user.as_bytes() || sent_password != password.as_bytes()
            {
                return client.write_all(&[1, 1]);
            }
            client.write_all(&[1, 0])?;
        }

        let mut head = [0u8; 4];
        client.read_exact(&mut head)?;
        let reply = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
        let host = match head[3] {
            1 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip)?;
                Ipv4Addr::from(ip).to_string()
            }
            4 => {
                let mut ip = [0u8; 16];
                client.read_exact(&mut ip)?;
                Ipv6Addr::from(ip).to_string()
            }
            3 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len)?;
                let mut name = vec![0u8; usize::from(len[0])];
                client.read_exact(&mut name)?;
                String::from_utf8_lossy(&name).into_owned()
            }
            _ => return client.write_all(&reply(8)),
        };
        let mut port = [0u8; 2];
        client.read_exact(&mut port)?;
        let port = u16::from_be_bytes(port);
        seen.lock().unwrap().push(Request {
            atyp: head[3],
            host: host.clone(),
            port,
        });
        if let Mode::Refuse(code) = mode {
            return client.write_all(&reply(code));
        }
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => match names.get(&host) {
                Some(ip) => *ip,
                None => return client.write_all(&reply(4)),
            },
        };
        let Ok(upstream) = TcpStream::connect((ip, port)) else {
            return client.write_all(&reply(5));
        };
        client.write_all(&reply(0))?;
        relay(client, upstream)
    }

    fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
        let mut client_read = client.try_clone()?;
        let mut upstream_write = upstream.try_clone()?;
        let forward = thread::spawn(move || {
            let _ = io::copy(&mut client_read, &mut upstream_write);
            let _ = upstream_write.shutdown(Shutdown::Both);
        });
        let (mut upstream_read, mut client_write) = (upstream, client);
        let _ = io::copy(&mut upstream_read, &mut client_write);
        let _ = client_write.shutdown(Shutdown::Both);
        let _ = forward.join();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn connect_request_sends_addresses_as_addresses_and_names_as_names() {
        assert_eq!(
            connect_request("192.0.2.1", 853).unwrap(),
            [5, 1, 0, ATYP_IPV4, 192, 0, 2, 1, 0x03, 0x55]
        );
        let v6 = connect_request("2001:db8::1", 443).unwrap();
        assert_eq!(v6[3], ATYP_IPV6);
        assert_eq!(v6.len(), 4 + 16 + 2);
        assert_eq!(
            connect_request("dns.test", 443).unwrap(),
            [
                &[5, 1, 0, ATYP_DOMAIN, 8][..],
                b"dns.test",
                &443u16.to_be_bytes()
            ]
            .concat()
        );
        assert!(connect_request(&"a".repeat(MAX_FIELD_LEN), 443).is_some());
        assert!(connect_request(&"a".repeat(MAX_FIELD_LEN + 1), 443).is_none());
        assert!(connect_request("", 443).is_none());
    }

    #[test]
    /// The TLS handshake starts right after the reply, so a bound address left unread would be
    /// taken for the server's first TLS record.
    fn the_whole_reply_is_consumed_for_every_address_type() {
        let proxy = Socks5Proxy::new("127.0.0.1:1080".parse().unwrap());
        for reply in [
            [&[5, 0, 0, ATYP_IPV4][..], &[0; 4 + 2]].concat(),
            [&[5, 0, 0, ATYP_IPV6][..], &[0; 16 + 2]].concat(),
            [&[5, 0, 0, ATYP_DOMAIN, 5][..], b"proxy", &[0; 2]].concat(),
        ] {
            let mut stream = [&reply[..], b"next"].concat();
            let mut reader = &stream[..];
            read_reply(&mut reader, &proxy).unwrap();
            assert_eq!(reader, b"next");
            stream.truncate(reply.len() - 1);
            assert!(read_reply(&mut &stream[..], &proxy).is_err());
        }
    }

    #[test]
    fn a_refusal_names_the_reason_without_the_password() {
        let proxy = Socks5Proxy::new("127.0.0.1:1080".parse().unwrap())
            .with_credentials("user", SecretString::from("hunter2"));
        let error = read_reply(&mut &[5, 4, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0][..], &proxy)
            .unwrap_err()
            .to_string();
        assert!(error.contains("host unreachable"), "{error}");
        assert!(!format!("{proxy:?}").contains("hunter2"));
        assert!(!proxy.to_string().contains("user"));
    }

    #[test]
    fn credentials_the_protocol_cannot_carry_fail_before_connecting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Socks5Proxy::new(listener.local_addr().unwrap())
            .with_credentials("u".repeat(MAX_FIELD_LEN + 1), SecretString::from("p"));
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(connect(&proxy, "dns.test", 853, deadline).is_err());
        listener.set_nonblocking(true).unwrap();
        assert!(
            listener.accept().is_err(),
            "connected to the proxy with credentials it could not send"
        );
    }

    #[test]
    fn a_silent_proxy_times_out_at_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = Socks5Proxy::new(listener.local_addr().unwrap());
        let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
        let started = Instant::now();
        let result = connect(
            &proxy,
            "dns.test",
            853,
            started + Duration::from_millis(300),
        );
        assert_eq!(result.err(), Some(ForwardError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(held.join());
    }
}
