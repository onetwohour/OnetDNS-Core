//! Requester identity for policy decisions. Each transport parses its own protocol and passes only
//! what policy needs into the shared pipeline.

use std::net::IpAddr;

/// Not onetdns_runtime::Transport: same name, different variants, and neither re-exports the other.
/// Do not swap them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The only transport the wire fast path serves.
    Do53Udp,
    Do53Tcp,
    DoT,
    DoH,
    DoH3,
    DoQ,
    DnsCrypt,
}

impl Transport {
    /// Length of per-transport stats arrays.
    pub const COUNT: usize = 7;

    /// Decides whether padding applies.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, Transport::Do53Udp | Transport::Do53Tcp)
    }

    /// In 0..COUNT and equal to the position in ALL; a mismatch mixes one transport's stats into
    /// another's.
    pub fn index(self) -> usize {
        match self {
            Transport::Do53Udp => 0,
            Transport::Do53Tcp => 1,
            Transport::DoT => 2,
            Transport::DoH => 3,
            Transport::DoH3 => 4,
            Transport::DoQ => 5,
            Transport::DnsCrypt => 6,
        }
    }

    /// Log and metric label. It is part of metric names, so changing it breaks dashboards.
    pub fn name(self) -> &'static str {
        match self {
            Transport::Do53Udp => "do53-udp",
            Transport::Do53Tcp => "do53-tcp",
            Transport::DoT => "dot",
            Transport::DoH => "doh",
            Transport::DoH3 => "doh3",
            Transport::DoQ => "doq",
            Transport::DnsCrypt => "dnscrypt",
        }
    }

    /// In index() order.
    pub const ALL: [Transport; Self::COUNT] = [
        Transport::Do53Udp,
        Transport::Do53Tcp,
        Transport::DoT,
        Transport::DoH,
        Transport::DoH3,
        Transport::DoQ,
        Transport::DnsCrypt,
    ];
}

/// Inputs to ACL, rate limiting, filtering, and policy decisions. A feature whose response depends
/// on a value here must register with the wire fast path's eligibility gate: the fast path caches
/// only responses that do not vary by client.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// The original client when the PROXY protocol was used.
    pub source_ip: IpAddr,

    pub client_id: Option<String>,

    pub transport: Transport,

    /// Verified at the transport by a client certificate or pre-shared credential.
    pub authenticated: bool,
}
