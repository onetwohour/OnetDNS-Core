//! What a client needs to reach this server, encoded as DNS stamps and as an Apple configuration
//! profile. Both encoders read one `Endpoints` value built from the running listeners.

use std::net::{IpAddr, SocketAddr};

use onetdns_config::Config;
use onetdns_tls::{TrustStore, X509};
use sha2::{Digest, Sha256};

use crate::listeners::DnscryptIdentity;

/// Apple platforms reject a TLS server certificate valid for longer, even one the user trusts.
const APPLE_MAX_VALIDITY_SECS: i64 = 825 * 86400;

/// Apple devices have no port setting for DNS over TLS.
const DOT_PORT: u16 = 853;

const STAMP_PROP_DNSSEC: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Transport {
    Plain,
    Dnscrypt,
    Doh,
    Dot,
    Doq,
}

impl Transport {
    /// DoH3 has no stamp type; clients reach it through the DoH listener.
    fn from_listener_kind(kind: &str) -> Option<Self> {
        match kind {
            "do53-udp" | "do53-tcp" => Some(Transport::Plain),
            "dnscrypt" => Some(Transport::Dnscrypt),
            "doh" => Some(Transport::Doh),
            "dot" => Some(Transport::Dot),
            "doq" => Some(Transport::Doq),
            _ => None,
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Self> {
        match name {
            "dns" => Some(Transport::Plain),
            "dnscrypt" => Some(Transport::Dnscrypt),
            "doh" => Some(Transport::Doh),
            "dot" => Some(Transport::Dot),
            "doq" => Some(Transport::Doq),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Transport::Plain => "dns",
            Transport::Dnscrypt => "dnscrypt",
            Transport::Doh => "doh",
            Transport::Dot => "dot",
            Transport::Doq => "doq",
        }
    }

    fn stamp_type(self) -> u8 {
        match self {
            Transport::Plain => 0x00,
            Transport::Dnscrypt => 0x01,
            Transport::Doh => 0x02,
            Transport::Dot => 0x03,
            Transport::Doq => 0x04,
        }
    }

    /// The port a stamp implies when it names none.
    fn stamp_default_port(self) -> u16 {
        match self {
            Transport::Plain => 53,
            _ => 443,
        }
    }
}

/// Read from the running server.
pub(crate) struct Served {
    /// Listener registry entries: kind, configured address, bound address.
    pub(crate) listeners: Vec<(&'static str, String, String)>,
    /// What the encrypted listeners present, leaf first; empty without one.
    pub(crate) chain: Vec<Vec<u8>>,
    /// A `tls_self_signed_host` certificate that is not kept in a file, so the next start replaces
    /// it.
    pub(crate) chain_changes_on_restart: bool,
    pub(crate) dnscrypt: Option<DnscryptIdentity>,
}

struct ServedCertificate {
    der: Vec<Vec<u8>>,
    parsed: Vec<X509>,
    /// Whether this machine's trust store accepts the chain for the chosen hostname.
    trusted: bool,
    /// Replaced at the next start; see `Served::chain_changes_on_restart`.
    ephemeral: bool,
}

pub(crate) struct Endpoints {
    /// Where clients reach the listeners; see `client_address`. Plain DNS and DNSCrypt stamps need
    /// an address, and a listener bound to every address has none of its own. Without one, TLS
    /// stamps leave the client to resolve the hostname.
    address: Option<IpAddr>,
    /// A name the certificate covers; TLS transports need one.
    hostname: Option<String>,
    /// One per transport, port, and bound address, sorted. The address is `None` for a listener
    /// bound to every address.
    listeners: Vec<(Transport, u16, Option<IpAddr>)>,
    doh_path: String,
    dnssec: bool,
    dnscrypt: Option<DnscryptIdentity>,
    certificate: Option<ServedCertificate>,
}

impl Endpoints {
    /// The `requested` hostname must be covered by the certificate; without it, `ddr_name` is used
    /// when the certificate covers it, and otherwise the first non-wildcard name in the
    /// certificate. Without a certificate there is no hostname.
    pub(crate) fn new(
        cfg: &Config,
        served: Served,
        address: Option<IpAddr>,
        requested: Option<&str>,
        store: &TrustStore,
        now: i64,
    ) -> Result<Self, String> {
        let mut listeners: Vec<(Transport, u16, Option<IpAddr>)> = served
            .listeners
            .iter()
            .filter_map(|(kind, _, bound)| {
                let transport = Transport::from_listener_kind(kind)?;
                let bound = bound.parse::<SocketAddr>().ok()?;
                let ip = Some(bound.ip()).filter(|ip| !ip.is_unspecified());
                Some((transport, bound.port(), ip))
            })
            .collect();
        listeners.sort_unstable();
        listeners.dedup();

        let mut hostname = None;
        let mut certificate = None;
        if !served.chain.is_empty() {
            hostname = requested.map(|name| name.trim_end_matches('.').to_ascii_lowercase());
            let parsed = served
                .chain
                .iter()
                .map(|der| X509::parse(der))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("Could not parse the served certificate: {error:?}"))?;
            let leaf = &parsed[0];
            match &hostname {
                Some(name) if !leaf.matches_hostname(name) => {
                    return Err(format!(
                        "The served certificate does not cover this name: {name}"
                    ));
                }
                Some(_) => {}
                None => {
                    let ddr_name = cfg.ddr_name.trim_end_matches('.').to_ascii_lowercase();
                    if !ddr_name.is_empty() && leaf.matches_hostname(&ddr_name) {
                        hostname = Some(ddr_name);
                    }
                }
            }
            if hostname.is_none() {
                hostname = leaf
                    .san_dns
                    .iter()
                    .find(|name| !name.starts_with('*'))
                    .map(|name| name.to_ascii_lowercase());
            }
            let trusted = hostname
                .as_deref()
                .is_some_and(|name| onetdns_tls::verify_chain(&parsed, store, name, now).is_ok());
            certificate = Some(ServedCertificate {
                der: served.chain,
                parsed,
                trusted,
                ephemeral: served.chain_changes_on_restart,
            });
        }

        Ok(Endpoints {
            address,
            hostname,
            listeners,
            doh_path: cfg.doh_path.clone(),
            dnssec: cfg.dnssec,
            dnscrypt: served.dnscrypt,
            certificate,
        })
    }

    pub(crate) fn address(&self) -> Option<IpAddr> {
        self.address
    }

    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Whether the certificate is trusted here, and whether it changes at every start.
    pub(crate) fn certificate_status(&self) -> Option<(bool, bool)> {
        self.certificate
            .as_ref()
            .map(|cert| (cert.trusted, cert.ephemeral))
    }

    /// The address clients use for a listener bound to `bound`, which is `None` for every address.
    /// A listener on a loopback address is reached only there. Any other takes the requested
    /// address, which may be a NAT front for it.
    fn client_address(&self, bound: Option<IpAddr>) -> Option<IpAddr> {
        match bound {
            Some(ip) if ip.is_loopback() => Some(ip),
            bound => self.address.or(bound),
        }
    }

    /// One stamp per open listener, port, and client address. A listener is left out when the
    /// stamp would lack a required part: an address for plain DNS and DNSCrypt, a hostname for the
    /// TLS transports.
    pub(crate) fn stamps(&self) -> Result<Vec<(Transport, u16, Option<IpAddr>, String)>, String> {
        let mut targets: Vec<(Transport, u16, Option<IpAddr>)> = self
            .listeners
            .iter()
            .map(|&(transport, port, bound)| (transport, port, self.client_address(bound)))
            .collect();
        targets.sort();
        targets.dedup();
        let mut out = Vec::new();
        for (transport, port, address) in targets {
            if let Some(stamp) = self.stamp(transport, port, address)? {
                out.push((transport, port, address, stamp));
            }
        }
        Ok(out)
    }

    fn stamp(
        &self,
        transport: Transport,
        port: u16,
        address: Option<IpAddr>,
    ) -> Result<Option<String>, String> {
        let default_port = transport.stamp_default_port();
        let address = address.map(|ip| with_port(&ip_literal(ip), port, default_port));
        let mut props = 0u64;
        if self.dnssec {
            props |= STAMP_PROP_DNSSEC;
        }
        let mut out = vec![transport.stamp_type()];
        out.extend_from_slice(&props.to_le_bytes());
        match transport {
            Transport::Plain => {
                let Some(address) = address else {
                    return Ok(None);
                };
                push_lp(&mut out, address.as_bytes(), "address")?;
            }
            Transport::Dnscrypt => {
                let (Some(address), Some(identity)) = (address, &self.dnscrypt) else {
                    return Ok(None);
                };
                push_lp(&mut out, address.as_bytes(), "address")?;
                push_lp(&mut out, &identity.public_key, "public key")?;
                push_lp(&mut out, identity.provider_name.as_bytes(), "provider name")?;
            }
            Transport::Doh | Transport::Dot | Transport::Doq => {
                let Some(hostname) = &self.hostname else {
                    return Ok(None);
                };
                push_lp(&mut out, address.unwrap_or_default().as_bytes(), "address")?;
                push_vlp(&mut out, &self.pinned_hashes());
                let host = with_port(hostname, port, default_port);
                push_lp(&mut out, host.as_bytes(), "hostname")?;
                if transport == Transport::Doh {
                    push_lp(&mut out, self.doh_path.as_bytes(), "doh_path")?;
                }
            }
        }
        Ok(Some(format!("sdns://{}", crate::acme::b64url(&out))))
    }

    /// A client that cannot validate the chain can pin the topmost certificate, which is the
    /// self-signed one when the chain carries its root.
    fn pinned_hashes(&self) -> Vec<[u8; 32]> {
        match &self.certificate {
            Some(cert) if !cert.trusted => cert
                .parsed
                .last()
                .map(|top| Sha256::digest(&top.tbs_raw).into())
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    /// A `.mobileconfig` that sets the system DNS on Apple devices to DoH or DoT. It carries the
    /// root certificate when this machine does not trust the chain. With `ssids`, the setting
    /// applies only on those Wi-Fi networks.
    pub(crate) fn apple_profile(
        &self,
        transport: Transport,
        ssids: &[String],
    ) -> Result<String, String> {
        let cert = self
            .certificate
            .as_ref()
            .ok_or("No DoH or DoT listener is open")?;
        let hostname = self
            .hostname
            .as_deref()
            .ok_or("The served certificate names no host to connect to")?;
        if cert.ephemeral {
            return Err("The tls_self_signed_host certificate could not be kept in a file, so it changes at every start and a profile made from it would stop working after a restart. Run with a config file, or create a certificate with `OnetDNS --cli cert --host <name>` and set tls_cert and tls_key".to_string());
        }
        let leaf = &cert.parsed[0];
        if leaf.eku_server_auth != Some(true)
            || leaf.not_after - leaf.not_before >= APPLE_MAX_VALIDITY_SECS
        {
            return Err("Apple devices reject the served certificate: it needs the serverAuth extended key usage and a validity of 825 days or less. Create one with `OnetDNS --cli cert --host <name>`".to_string());
        }
        for ssid in ssids {
            if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
                return Err(format!(
                    "A Wi-Fi network name must be 1 to 32 bytes without control characters: {ssid:?}"
                ));
            }
        }
        let ports: Vec<u16> = self
            .listeners
            .iter()
            .filter(|(listener, _, _)| *listener == transport)
            .map(|(_, port, _)| *port)
            .collect();
        let (port, dns_settings) = match transport {
            Transport::Doh => {
                let port = if ports.contains(&443) {
                    443
                } else {
                    *ports.first().ok_or("No DoH listener is open")?
                };
                let url = format!(
                    "https://{}{}",
                    with_port(hostname, port, 443),
                    self.doh_path
                );
                (
                    port,
                    plist_entries(&[("DNSProtocol", "HTTPS"), ("ServerURL", &url)]),
                )
            }
            Transport::Dot => {
                if !ports.contains(&DOT_PORT) {
                    return Err(format!(
                        "Apple devices use DNS over TLS on port {DOT_PORT} only, and no DoT listener is open on it"
                    ));
                }
                (
                    DOT_PORT,
                    plist_entries(&[("DNSProtocol", "TLS"), ("ServerName", hostname)]),
                )
            }
            _ => return Err("Apple devices take DoH or DoT only".to_string()),
        };

        let identifier = format!("onetdns.{hostname}");
        let display_name = format!("OnetDNS ({hostname})");
        let mut payloads = String::new();
        if !cert.trusted {
            let top = cert.parsed.last().unwrap_or(leaf);
            if top.verify_self_signed().is_err() {
                return Err("The served chain does not include its root certificate, so the profile cannot carry it. Append the root to the tls_cert file".to_string());
            }
            let der = cert.der.last().map(Vec::as_slice).unwrap_or_default();
            let name = top.subject_label().unwrap_or_else(|| hostname.to_string());
            payloads.push_str("<dict>\n");
            payloads.push_str(&plist_entries(&[(
                "PayloadCertificateFileName",
                &format!("{hostname}.cer"),
            )]));
            payloads.push_str(&format!(
                "<key>PayloadContent</key>\n<data>{}</data>\n",
                &*crate::acme::b64_std(der)
            ));
            payloads.push_str(&payload_header(
                &name,
                &format!("{identifier}.root"),
                "com.apple.security.root",
            ));
            payloads.push_str("</dict>\n");
        }

        payloads.push_str("<dict>\n<key>DNSSettings</key>\n<dict>\n");
        payloads.push_str(&dns_settings);
        let address = self
            .listeners
            .iter()
            .filter(|&&(listener, at, _)| listener == transport && at == port)
            .find_map(|&(_, _, bound)| self.client_address(bound));
        if let Some(address) = address {
            payloads.push_str(&format!(
                "<key>ServerAddresses</key>\n<array>\n<string>{address}</string>\n</array>\n"
            ));
        }
        payloads.push_str("</dict>\n");
        if !ssids.is_empty() {
            let names: String = ssids
                .iter()
                .map(|ssid| format!("<string>{}</string>\n", plist_escape(ssid)))
                .collect();
            payloads.push_str(&format!(
                "<key>OnDemandRules</key>\n<array>\n<dict>\n<key>Action</key>\n<string>Connect</string>\n<key>SSIDMatch</key>\n<array>\n{names}</array>\n</dict>\n<dict>\n<key>Action</key>\n<string>Disconnect</string>\n</dict>\n</array>\n"
            ));
        }
        payloads.push_str(&payload_header(
            &display_name,
            &format!("{identifier}.dns"),
            "com.apple.dnsSettings.managed",
        ));
        payloads.push_str("</dict>\n");

        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n<key>PayloadContent</key>\n<array>\n{payloads}</array>\n{}</dict>\n</plist>\n",
            payload_header(&display_name, &identifier, "Configuration")
        ))
    }
}

/// The address clients connect to. A port is refused: each stamp takes its listener's port.
pub(crate) fn parse_address(text: &str) -> Result<IpAddr, String> {
    if text.parse::<SocketAddr>().is_ok() {
        return Err(format!("Enter the IP address without a port: {text}"));
    }
    let ip: IpAddr = text
        .parse()
        .map_err(|_| format!("Invalid IP address: {text}"))?;
    if ip.is_unspecified() {
        return Err(format!("0.0.0.0 and :: mean every address on this machine, so clients cannot connect to them. Enter the address clients reach this server at, such as its public IP, instead of {text}"));
    }
    Ok(ip)
}

/// IPv6 goes in brackets even without a port.
fn ip_literal(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

fn with_port(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn push_lp(out: &mut Vec<u8>, value: &[u8], what: &str) -> Result<(), String> {
    let len = u8::try_from(value.len()).map_err(|_| format!("Too long for a DNS stamp: {what}"))?;
    out.push(len);
    out.extend_from_slice(value);
    Ok(())
}

/// Every length but the last has its top bit set; an empty set is a single zero.
fn push_vlp(out: &mut Vec<u8>, hashes: &[[u8; 32]]) {
    if hashes.is_empty() {
        out.push(0);
        return;
    }
    for (index, hash) in hashes.iter().enumerate() {
        let more = if index + 1 < hashes.len() { 0x80 } else { 0 };
        out.push(more | hash.len() as u8);
        out.extend_from_slice(hash);
    }
}

fn plist_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist_entries(entries: &[(&str, &str)]) -> String {
    entries
        .iter()
        .map(|(key, value)| {
            format!(
                "<key>{key}</key>\n<string>{}</string>\n",
                plist_escape(value)
            )
        })
        .collect()
}

/// A reinstalled profile replaces the one with the same identifier; the UUID is new each time.
fn payload_header(display_name: &str, identifier: &str, payload_type: &str) -> String {
    format!(
        "{}<key>PayloadVersion</key>\n<integer>1</integer>\n",
        plist_entries(&[
            ("PayloadDisplayName", display_name),
            ("PayloadIdentifier", identifier),
            ("PayloadType", payload_type),
            ("PayloadUUID", &random_uuid()),
        ])
    )
}

fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    onetdns_core::fill_random(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        crate::unix_now() as i64
    }

    fn decode(stamp: &str) -> Vec<u8> {
        let body = stamp
            .strip_prefix("sdns://")
            .expect("sdns:// 접두사가 없습니다");
        crate::acme::b64_decode(body)
            .expect("base64url 해독")
            .to_vec()
    }

    fn endpoints(dnssec: bool, address: Option<&str>) -> Endpoints {
        Endpoints {
            address: address.map(|text| text.parse().unwrap()),
            hostname: None,
            listeners: Vec::new(),
            doh_path: "/dns-query".to_string(),
            dnssec,
            dnscrypt: None,
            certificate: None,
        }
    }

    #[test]
    fn doh_stamp_matches_a_published_one() {
        // Cloudflare's published stamp sets the no-log and no-filter bits too; the layout after
        // the props is what this checks.
        let mut e = endpoints(true, Some("1.0.0.1"));
        e.hostname = Some("dns.cloudflare.com".to_string());
        let stamp = e.stamp(Transport::Doh, 443, e.address).unwrap().unwrap();
        let mut published =
            decode("sdns://AgcAAAAAAAAABzEuMC4wLjEAEmRucy5jbG91ZGZsYXJlLmNvbQovZG5zLXF1ZXJ5");
        published[1] = STAMP_PROP_DNSSEC as u8;
        assert_eq!(decode(&stamp), published);
    }

    #[test]
    fn pinned_hash_is_encoded_like_a_published_stamp() {
        let published = decode("sdns://AgMAAAAAAAAADDk0LjE0MC4xNC4xNCCbNPrD425-Kx_uSEenN2Yi1M4shzeMLqLUYEcj3T_2KQw5NC4xNDAuMTQuMTQKL2Rucy1xdWVyeQ");
        let hash: [u8; 32] = published[23..55].try_into().unwrap();
        let mut out = vec![0x02];
        out.extend_from_slice(&3u64.to_le_bytes());
        push_lp(&mut out, b"94.140.14.14", "address").unwrap();
        push_vlp(&mut out, &[hash]);
        push_lp(&mut out, b"94.140.14.14", "hostname").unwrap();
        push_lp(&mut out, b"/dns-query", "doh_path").unwrap();
        assert_eq!(out, published);

        let mut two = Vec::new();
        push_vlp(&mut two, &[hash, hash]);
        assert_eq!(
            two[0],
            0x80 | 32,
            "마지막이 아닌 해시에 연속 비트가 없습니다"
        );
        assert_eq!(two[33], 32);
    }

    #[test]
    fn ports_are_written_only_when_not_the_stamp_default() {
        let e = endpoints(false, Some("2001:db8::1"));
        let plain = decode(&e.stamp(Transport::Plain, 53, e.address).unwrap().unwrap());
        assert_eq!(&plain[9..], b"\x0d[2001:db8::1]");
        let plain = decode(&e.stamp(Transport::Plain, 5353, e.address).unwrap().unwrap());
        assert_eq!(&plain[9..], b"\x12[2001:db8::1]:5353");

        let mut e = endpoints(false, None);
        e.hostname = Some("dns.example".to_string());
        let dot = decode(&e.stamp(Transport::Dot, 853, None).unwrap().unwrap());
        assert_eq!(&dot[9..], b"\x00\x00\x0fdns.example:853");
    }

    #[test]
    fn an_address_with_a_port_is_refused_with_its_own_reason() {
        assert_eq!(parse_address("192.0.2.1"), Ok("192.0.2.1".parse().unwrap()));
        assert_eq!(
            parse_address("2001:db8::1"),
            Ok("2001:db8::1".parse().unwrap())
        );
        for text in ["127.0.0.1:5443", "[2001:db8::1]:853"] {
            assert_eq!(
                parse_address(text),
                Err(format!("Enter the IP address without a port: {text}"))
            );
        }
        assert_eq!(
            parse_address("dns.example"),
            Err("Invalid IP address: dns.example".to_string())
        );
        for text in ["0.0.0.0", "::"] {
            let refused = parse_address(text).unwrap_err();
            assert!(
                refused.ends_with(&format!("instead of {text}")),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_stamp_missing_a_required_part_is_left_out() {
        let e = endpoints(false, None);
        assert_eq!(e.stamp(Transport::Plain, 53, None).unwrap(), None);
        assert_eq!(e.stamp(Transport::Doh, 443, None).unwrap(), None);
        let e = endpoints(false, Some("192.0.2.1"));
        assert_eq!(e.stamp(Transport::Dnscrypt, 443, e.address).unwrap(), None);
    }

    #[test]
    fn dnscrypt_stamp_matches_a_published_one() {
        // AdGuard's published stamp also sets the no-log bit.
        let mut published = decode("sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20");
        let mut e = endpoints(true, Some("94.140.14.14"));
        e.dnscrypt = Some(DnscryptIdentity {
            provider_name: "2.dnscrypt.default.ns1.adguard.com".to_string(),
            public_key: published[28..60].try_into().unwrap(),
        });
        let stamp = e
            .stamp(Transport::Dnscrypt, 5443, e.address)
            .unwrap()
            .unwrap();
        published[1] = STAMP_PROP_DNSSEC as u8;
        assert_eq!(decode(&stamp), published);
    }

    fn serving(host: &str, kinds: &[(&'static str, &str)]) -> (Served, Vec<u8>) {
        let (chain, _key) = onetdns_transport::self_signed_material(host).unwrap();
        let leaf = chain[0].clone();
        let served = Served {
            listeners: kinds
                .iter()
                .map(|(kind, bound)| (*kind, bound.to_string(), bound.to_string()))
                .collect(),
            chain,
            chain_changes_on_restart: false,
            dnscrypt: None,
        };
        (served, leaf)
    }

    #[test]
    fn listeners_collapse_to_one_entry_per_transport_and_port() {
        let (served, _) = serving(
            "dns.example",
            &[
                ("do53-udp", "0.0.0.0:53"),
                ("do53-tcp", "0.0.0.0:53"),
                ("do53-udp", "[::]:53"),
                ("doh3", "0.0.0.0:443"),
                ("doh", "0.0.0.0:443"),
                ("dot", "0.0.0.0:853"),
            ],
        );
        let e = Endpoints::new(
            &Config::default(),
            served,
            None,
            None,
            &TrustStore::empty(),
            now(),
        )
        .unwrap();
        assert_eq!(
            e.listeners,
            vec![
                (Transport::Plain, 53, None),
                (Transport::Doh, 443, None),
                (Transport::Dot, 853, None)
            ]
        );
    }

    #[test]
    fn a_listener_on_one_address_needs_no_address_from_the_request() {
        let listeners = vec![
            ("do53-udp", String::new(), "127.0.0.1:53".to_string()),
            ("do53-udp", String::new(), "0.0.0.0:5353".to_string()),
            ("dnscrypt", String::new(), "127.0.0.1:5443".to_string()),
        ];
        let stamps = |requested: Option<&str>| {
            let served = Served {
                listeners: listeners.clone(),
                chain: Vec::new(),
                chain_changes_on_restart: false,
                dnscrypt: Some(DnscryptIdentity {
                    provider_name: "2.dnscrypt-cert.onetdns".to_string(),
                    public_key: [7; 32],
                }),
            };
            let requested = requested.map(|ip| ip.parse().unwrap());
            let e = Endpoints::new(
                &Config::default(),
                served,
                requested,
                None,
                &TrustStore::empty(),
                now(),
            )
            .unwrap();
            e.stamps()
                .unwrap()
                .into_iter()
                .map(|(transport, port, address, _)| (transport, port, address))
                .collect::<Vec<_>>()
        };
        let local = Some("127.0.0.1".parse().unwrap());
        assert_eq!(
            stamps(None),
            vec![
                (Transport::Plain, 53, local),
                (Transport::Dnscrypt, 5443, local)
            ],
            "모든 주소에 묶인 리스너는 요청 주소 없이 스탬프를 만들 수 없습니다"
        );
        let lan = Some("192.168.0.10".parse().unwrap());
        assert_eq!(
            stamps(Some("192.168.0.10")),
            vec![
                (Transport::Plain, 53, local),
                (Transport::Plain, 5353, lan),
                (Transport::Dnscrypt, 5443, local)
            ],
            "루프백에 묶인 리스너에 다른 주소로 스탬프를 만들었습니다"
        );
    }

    #[test]
    fn hostname_comes_from_the_certificate() {
        let cfg = Config {
            ddr_name: "DNS.example.".to_string(),
            ..Config::default()
        };
        let (s, _) = serving("dns.example", &[]);
        let e = Endpoints::new(&cfg, s, None, None, &TrustStore::empty(), now()).unwrap();
        assert_eq!(e.hostname(), Some("dns.example"));

        let other = Config {
            ddr_name: "other.example".to_string(),
            ..Config::default()
        };
        let (s, _) = serving("dns.example", &[]);
        let e = Endpoints::new(&other, s, None, None, &TrustStore::empty(), now()).unwrap();
        assert_eq!(
            e.hostname(),
            Some("dns.example"),
            "인증서에 없는 ddr_name을 썼습니다"
        );

        let (s, _) = serving("dns.example", &[]);
        let refused = Endpoints::new(
            &cfg,
            s,
            None,
            Some("other.example"),
            &TrustStore::empty(),
            now(),
        );
        assert!(refused.is_err(), "인증서가 덮지 않는 호스트명을 받았습니다");
    }

    #[test]
    fn only_an_untrusted_chain_is_pinned_in_tls_stamps() {
        let (s, leaf) = serving("dns.example", &[("doh", "0.0.0.0:443")]);
        let tbs = X509::parse(&leaf).unwrap().tbs_raw;
        let e = Endpoints::new(
            &Config::default(),
            s,
            None,
            None,
            &TrustStore::empty(),
            now(),
        )
        .unwrap();
        assert_eq!(e.certificate_status(), Some((false, false)));
        let bytes = decode(&e.stamps().unwrap()[0].3);
        assert_eq!(&bytes[9..11], &[0, 32]);
        assert_eq!(&bytes[11..43], &Sha256::digest(&tbs)[..]);

        let (s, leaf) = serving("dns.example", &[("doh", "0.0.0.0:443")]);
        let store = TrustStore::from_ders([leaf.as_slice()]);
        let e = Endpoints::new(&Config::default(), s, None, None, &store, now()).unwrap();
        assert_eq!(e.certificate_status(), Some((true, false)));
        let bytes = decode(&e.stamps().unwrap()[0].3);
        assert_eq!(&bytes[9..11], &[0, 0], "신뢰하는 체인에 해시를 넣었습니다");
    }

    fn profile_endpoints(kinds: &[(&'static str, &str)]) -> (Endpoints, Vec<u8>) {
        let (s, leaf) = serving("dns.example", kinds);
        let e = Endpoints::new(
            &Config::default(),
            s,
            Some("192.0.2.1".parse().unwrap()),
            None,
            &TrustStore::empty(),
            now(),
        )
        .unwrap();
        (e, leaf)
    }

    #[test]
    fn profile_for_a_self_signed_certificate_carries_its_root() {
        let (e, leaf) = profile_endpoints(&[("doh", "0.0.0.0:8443")]);
        let profile = e
            .apple_profile(Transport::Doh, &["Home & Co".to_string()])
            .unwrap();
        assert!(profile.contains("<string>https://dns.example:8443/dns-query</string>"));
        assert!(profile.contains("<string>com.apple.security.root</string>"));
        assert!(profile.contains(&format!("<data>{}</data>", &*crate::acme::b64_std(&leaf))));
        assert!(profile.contains("<string>192.0.2.1</string>"));
        assert!(profile.contains("<string>Home &amp; Co</string>"));
        assert!(profile.contains("<string>onetdns.dns.example.dns</string>"));
    }

    #[test]
    fn profile_is_refused_where_apple_devices_would_fail() {
        let (e, _) = profile_endpoints(&[("dot", "0.0.0.0:8853")]);
        assert!(
            e.apple_profile(Transport::Dot, &[]).is_err(),
            "853이 아닌 DoT를 받았습니다"
        );
        let (e, _) = profile_endpoints(&[("dot", "0.0.0.0:853")]);
        assert!(e.apple_profile(Transport::Dot, &[]).is_ok());
        assert!(e.apple_profile(Transport::Doq, &[]).is_err());

        let (mut e, _) = profile_endpoints(&[("doh", "0.0.0.0:443")]);
        assert!(e.apple_profile(Transport::Doh, &["x".repeat(33)]).is_err());
        if let Some(cert) = &mut e.certificate {
            cert.parsed[0].eku_server_auth = None;
        }
        assert!(
            e.apple_profile(Transport::Doh, &[]).is_err(),
            "EKU 없는 인증서를 받았습니다"
        );
        if let Some(cert) = &mut e.certificate {
            cert.parsed[0].eku_server_auth = Some(true);
            cert.ephemeral = true;
        }
        assert!(
            e.apple_profile(Transport::Doh, &[]).is_err(),
            "매번 바뀌는 인증서를 받았습니다"
        );
    }
}
