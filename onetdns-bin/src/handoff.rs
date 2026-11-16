//! Listening sockets carried from one set of listeners to the next without closing them, so the
//! queries queued on a socket are answered by whoever serves it next.

use std::net::{SocketAddr, TcpListener, UdpSocket};

/// What a listening socket serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketRole {
    Do53,
    Dot,
    Doh,
    Doq,
    Doh3,
    Dnscrypt,
}

#[derive(Debug)]
pub(crate) enum ListeningSocket {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

/// Sockets that are open but not served, keyed by role and bound address. A listener opening an
/// address takes its sockets from here before it binds.
///
/// Port 0 never matches: the configured address then differs from the bound one, and the listener
/// binds a new socket.
#[derive(Debug, Default)]
pub(crate) struct SocketPool {
    entries: Vec<(SocketRole, SocketAddr, ListeningSocket)>,
}

impl SocketPool {
    pub(crate) fn put(&mut self, role: SocketRole, addr: SocketAddr, socket: ListeningSocket) {
        self.entries.push((role, addr, socket));
    }

    /// Every UDP socket for `role` at `addr`; several when they form a reuseport group.
    pub(crate) fn take_udp(&mut self, role: SocketRole, addr: SocketAddr) -> Vec<UdpSocket> {
        self.take(role, addr, |socket| match socket {
            ListeningSocket::Udp(socket) => Ok(socket),
            other => Err(other),
        })
    }

    /// Every TCP socket for `role` at `addr`; several when they form a reuseport group.
    pub(crate) fn take_tcp(&mut self, role: SocketRole, addr: SocketAddr) -> Vec<TcpListener> {
        self.take(role, addr, |socket| match socket {
            ListeningSocket::Tcp(socket) => Ok(socket),
            other => Err(other),
        })
    }

    fn take<T>(
        &mut self,
        role: SocketRole,
        addr: SocketAddr,
        mut kind: impl FnMut(ListeningSocket) -> Result<T, ListeningSocket>,
    ) -> Vec<T> {
        let mut taken = Vec::new();
        let mut kept = Vec::with_capacity(self.entries.len());
        for (entry_role, entry_addr, socket) in self.entries.drain(..) {
            if entry_role != role || entry_addr != addr {
                kept.push((entry_role, entry_addr, socket));
                continue;
            }
            match kind(socket) {
                Ok(socket) => taken.push(socket),
                Err(socket) => kept.push((entry_role, entry_addr, socket)),
            }
        }
        self.entries = kept;
        taken
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Role and address of each socket, for logs.
    pub(crate) fn describe(&self) -> String {
        let mut names: Vec<String> = self
            .entries
            .iter()
            .map(|(role, addr, socket)| {
                let kind = match socket {
                    ListeningSocket::Udp(_) => "udp",
                    ListeningSocket::Tcp(_) => "tcp",
                };
                format!("{role:?}/{kind}/{addr}")
            })
            .collect();
        names.dedup();
        names.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_only_the_matching_role_address_and_kind() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let mut pool = SocketPool::default();
        pool.put(SocketRole::Do53, udp_addr, ListeningSocket::Udp(udp));
        pool.put(SocketRole::Dot, tcp_addr, ListeningSocket::Tcp(tcp));

        assert!(pool.take_tcp(SocketRole::Do53, udp_addr).is_empty());
        assert!(pool.take_udp(SocketRole::Doq, udp_addr).is_empty());
        assert_eq!(pool.take_udp(SocketRole::Do53, udp_addr).len(), 1);
        assert!(pool.take_udp(SocketRole::Do53, udp_addr).is_empty());
        assert!(!pool.is_empty());
        assert_eq!(pool.take_tcp(SocketRole::Dot, tcp_addr).len(), 1);
        assert!(pool.is_empty());
    }
}
