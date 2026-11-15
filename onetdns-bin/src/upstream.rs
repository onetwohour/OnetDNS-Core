//! Turns configured upstream URLs into connect targets. An upstream that points back at this server
//! is rejected, since queries would loop.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use onetdns_forward::Upstream;

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);

/// Hostname upstreams are checked after resolving; the URL alone would miss this server hidden
/// behind a name.
pub fn ensure_not_listener(
    upstreams: &[Upstream],
    listeners: &[SocketAddr],
    label: &str,
) -> Result<(), String> {
    if let Some(upstream) = upstreams.iter().find(|upstream| {
        listeners.iter().any(|listener| {
            onetdns_config::dns_endpoint_conflicts(*listener, upstream.addr)
                || listener.port() == upstream.addr.port()
                    && listener.ip().is_unspecified()
                    && (listener.is_ipv6() || listener.is_ipv4() == upstream.addr.is_ipv4())
                    && is_local_ip(upstream.addr.ip())
        })
    }) {
        return Err(format!(
            "{label}={} points to this server's own DNS listening address after the initial lookup, which would create a query loop",
            upstream.addr
        ));
    }
    Ok(())
}

/// Loopback, unspecified, or assigned to this machine.
pub(crate) fn is_local_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    UdpSocket::bind(bind)
        .and_then(|socket| {
            socket.connect(SocketAddr::new(ip, 9))?;
            socket.local_addr()
        })
        .is_ok_and(|local| local.ip() == ip)
}

pub fn native_upstreams(plain: &[IpAddr], urls: &[String], bootstrap: &[IpAddr]) -> Vec<Upstream> {
    let mut out: Vec<Upstream> = plain
        .iter()
        .map(|ip| Upstream::udp(SocketAddr::new(*ip, 53)))
        .collect();
    for u in urls {
        match parse_native_upstream(u, bootstrap) {
            Some(up) => out.push(up),
            None => {
                onetdns_core::warn!(event = "upstream.parse_failed", url = %u, "Could not resolve an upstream DNS server's address; skipping that server")
            }
        }
    }
    out
}

pub fn servers_to_upstreams(servers: &[String], bootstrap: &[IpAddr]) -> Vec<Upstream> {
    let mut out = Vec::new();
    for s in servers {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            out.push(Upstream::udp(SocketAddr::new(ip, 53)));
        } else if let Some(up) = parse_native_upstream(s, bootstrap) {
            out.push(up);
        } else {
            onetdns_core::warn!(event = "upstream.fallback_parse_failed", server = %s, "Could not resolve a stub or fallback upstream DNS server's address; skipping that server");
        }
    }
    out
}

/// Hostnames need bootstrap servers.
pub fn url_uses_hostname(url: &str) -> bool {
    let rest = url.trim().split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split_once('#').map(|(r, _)| r).unwrap_or(rest);
    let hostport = rest.split_once('/').map(|(hp, _)| hp).unwrap_or(rest);
    let host = if let Some(bracketed) = hostport.strip_prefix('[') {
        bracketed
            .split_once(']')
            .map(|(h, _)| h)
            .unwrap_or(bracketed)
    } else if hostport.matches(':').count() == 1 {
        hostport
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
    } else {
        hostport
    };
    !host.is_empty() && host.parse::<IpAddr>().is_err()
}

/// None for an unknown scheme, a malformed URL, or a hostname without bootstrap servers.
fn parse_native_upstream(url: &str, bootstrap: &[IpAddr]) -> Option<Upstream> {
    let url = url.trim();
    if url.is_empty() || url.chars().any(char::is_control) {
        return None;
    }
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("udp".to_string(), url),
    };

    let (rest, sni) = match rest.split_once('#') {
        Some((r, s)) if !s.trim().is_empty() => (r, Some(s.trim().to_string())),
        Some(_) => return None,
        None => (rest, None),
    };
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, Some(format!("/{p}"))),
        None => (rest, None),
    };
    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        let end = bracketed.find(']')?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            suffix
                .strip_prefix(':')?
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
        };
        if !suffix.is_empty() && port.is_none() {
            return None;
        }
        (host, port)
    } else if hostport.matches(':').count() == 1 {
        let (host, raw_port) = hostport.rsplit_once(':')?;
        match raw_port.parse::<u16>() {
            Ok(port) if port != 0 => (host, Some(port)),
            _ => return None,
        }
    } else {
        (hostport, None)
    };
    if host.trim().is_empty() {
        return None;
    }
    let ip = resolve_host(host, bootstrap)?;
    let sni = || sni.clone().unwrap_or_else(|| host.to_string());
    let doh_path = || path.clone().unwrap_or_else(|| "/dns-query".to_string());
    match scheme.as_str() {
        "udp" => Some(Upstream::udp(SocketAddr::new(ip, port.unwrap_or(53)))),
        "tcp" => Some(Upstream::tcp(SocketAddr::new(ip, port.unwrap_or(53)))),
        "tls" => Some(Upstream::dot(
            SocketAddr::new(ip, port.unwrap_or(853)),
            sni(),
        )),
        "https" => Some(Upstream::doh(
            SocketAddr::new(ip, port.unwrap_or(443)),
            sni(),
            doh_path(),
        )),
        "quic" => Some(Upstream::doq(
            SocketAddr::new(ip, port.unwrap_or(853)),
            sni(),
        )),
        "h3" => Some(Upstream::doh3(
            SocketAddr::new(ip, port.unwrap_or(443)),
            sni(),
            doh_path(),
        )),
        _ => None,
    }
}

fn resolve_host(host: &str, bootstrap: &[IpAddr]) -> Option<IpAddr> {
    let resolved = resolve_host_via_bootstrap(host, bootstrap);
    if resolved.is_none() && host.parse::<IpAddr>().is_err() {
        if bootstrap.is_empty() {
            onetdns_core::warn!(event = "forward.bootstrap_required", %host, "Upstream DNS servers given by hostname need a bootstrap setting");
        } else {
            onetdns_core::warn!(event = "forward.bootstrap_lookup_failed", %host, servers = bootstrap.len(), "Could not resolve the upstream DNS server name through the bootstrap servers");
        }
    }
    resolved
}

/// Never asks this server: it cannot answer during startup, and resolving its own upstreams through
/// itself is circular.
pub fn resolve_host_via_bootstrap(host: &str, bootstrap: &[IpAddr]) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok().or_else(|| {
        (!bootstrap.is_empty())
            .then(|| onetdns_forward::resolve_via_bootstrap(host, bootstrap, BOOTSTRAP_TIMEOUT))
            .flatten()
            .map(|(address, _ttl)| address)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_forward::Transport;

    #[test]
    fn resolved_upstream_cannot_point_back_to_listener() {
        let upstreams = vec![Upstream::doh(
            "127.0.0.1:443".parse().unwrap(),
            "dns.example",
            "/dns-query",
        )];
        assert!(ensure_not_listener(
            &upstreams,
            &["127.0.0.1:443".parse().unwrap()],
            "upstream_urls"
        )
        .is_err());
        assert!(ensure_not_listener(
            &upstreams,
            &["127.0.0.1:53".parse().unwrap()],
            "upstream_urls"
        )
        .is_ok());
        assert!(ensure_not_listener(
            &upstreams,
            &["0.0.0.0:443".parse().unwrap()],
            "upstream_urls"
        )
        .is_err());
        assert!(
            ensure_not_listener(&upstreams, &["[::]:443".parse().unwrap()], "upstream_urls")
                .is_err()
        );

        let mapped = vec![Upstream::udp("[::ffff:127.0.0.1]:53".parse().unwrap())];
        assert!(
            ensure_not_listener(&mapped, &["127.0.0.1:53".parse().unwrap()], "upstreams").is_err()
        );
        assert!(is_local_ip(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn native_upstreams_mixes_all_transports() {
        let plain = vec!["9.9.9.9".parse().unwrap()];
        let urls = vec![
            "tls://1.1.1.1#cloudflare-dns.com".to_string(),
            "tcp://8.8.8.8".to_string(),
            "https://8.8.4.4/dns-query#dns.google".to_string(),
            "quic://1.0.0.1#cloudflare-dns.com".to_string(),
            "h3://8.8.8.8/dns-query#dns.google".to_string(),
        ];
        let ups = native_upstreams(&plain, &urls, &[]);
        assert_eq!(ups.len(), 6, "평문1 + tls + tcp + doh + doq + doh3");
        assert_eq!(ups[0].transport, Transport::Udp);
        assert_eq!(
            ups[1].transport,
            Transport::Dot {
                server_name: "cloudflare-dns.com".into()
            }
        );
        assert_eq!(ups[2].transport, Transport::Tcp);
        assert_eq!(
            ups[3].transport,
            Transport::Doh {
                server_name: "dns.google".into(),
                path: "/dns-query".into()
            }
        );
        assert_eq!(
            ups[4].transport,
            Transport::Doq {
                server_name: "cloudflare-dns.com".into()
            }
        );
        assert_eq!(ups[4].addr, "1.0.0.1:853".parse().unwrap());
        assert_eq!(
            ups[5].transport,
            Transport::Doh3 {
                server_name: "dns.google".into(),
                path: "/dns-query".into()
            }
        );
        assert_eq!(ups[5].addr, "8.8.8.8:443".parse().unwrap());
    }

    #[test]
    fn hostname_upstream_needs_bootstrap_but_ip_literal_does_not() {
        assert!(parse_native_upstream("h3://cloudflare-dns.com/dns-query", &[]).is_none());
        assert!(url_uses_hostname("h3://cloudflare-dns.com/dns-query"));

        let up = parse_native_upstream("h3://1.1.1.1/dns-query#cloudflare-dns.com", &[]).unwrap();
        assert_eq!(up.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(
            up.transport,
            Transport::Doh3 {
                server_name: "cloudflare-dns.com".into(),
                path: "/dns-query".into()
            }
        );
        assert!(!url_uses_hostname(
            "h3://1.1.1.1/dns-query#cloudflare-dns.com"
        ));
        assert!(!url_uses_hostname("tls://9.9.9.9:853"));
        assert!(!url_uses_hostname("udp://[2606:4700:4700::1111]:53"));
    }

    #[test]
    fn parses_doh_defaults_and_overrides() {
        let up = parse_native_upstream("https://1.1.1.1", &[]).unwrap();
        assert_eq!(up.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(
            up.transport,
            Transport::Doh {
                server_name: "1.1.1.1".into(),
                path: "/dns-query".into()
            }
        );

        let up = parse_native_upstream("https://9.9.9.9:8443/resolve#dns.quad9.net", &[]).unwrap();
        assert_eq!(up.addr, "9.9.9.9:8443".parse().unwrap());
        assert_eq!(
            up.transport,
            Transport::Doh {
                server_name: "dns.quad9.net".into(),
                path: "/resolve".into()
            }
        );
    }

    #[test]
    fn parses_doq_and_doh3() {
        let up = parse_native_upstream("quic://1.1.1.1", &[]).unwrap();
        assert_eq!(up.addr, "1.1.1.1:853".parse().unwrap());
        assert_eq!(
            up.transport,
            Transport::Doq {
                server_name: "1.1.1.1".into()
            }
        );

        let up = parse_native_upstream("h3://1.1.1.1#cloudflare-dns.com", &[]).unwrap();
        assert_eq!(up.addr, "1.1.1.1:443".parse().unwrap());
        assert_eq!(
            up.transport,
            Transport::Doh3 {
                server_name: "cloudflare-dns.com".into(),
                path: "/dns-query".into()
            }
        );
    }

    #[test]
    fn servers_to_upstreams_ip_and_tls() {
        let ups = servers_to_upstreams(
            &[
                "1.0.0.1".to_string(),
                "tls://9.9.9.9#dns.quad9.net".to_string(),
            ],
            &[],
        );
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].transport, Transport::Udp);
        assert_eq!(ups[1].addr, "9.9.9.9:853".parse().unwrap());
    }

    #[test]
    fn unknown_scheme_skipped() {
        assert!(parse_native_upstream("ftp://1.2.3.4", &[]).is_none());
        assert!(parse_native_upstream("gopher://8.8.8.8", &[]).is_none());
    }

    #[test]
    fn removed_scheme_aliases_are_rejected() {
        for scheme in ["dot", "doh", "h2", "doq", "doh3"] {
            assert!(
                parse_native_upstream(&format!("{scheme}://192.0.2.1"), &[]).is_none(),
                "{scheme}"
            );
        }
    }
    #[test]
    fn bracketed_ipv6_with_port_is_parsed() {
        let up =
            parse_native_upstream("tls://[2001:4860:4860::8888]:8853#dns.google", &[]).unwrap();
        assert_eq!(up.addr, "[2001:4860:4860::8888]:8853".parse().unwrap());
    }

    #[test]
    fn hostname_without_bootstrap_is_rejected() {
        assert!(parse_native_upstream("https://dns.example/dns-query", &[]).is_none());
        assert!(resolve_host_via_bootstrap("dns.example", &[]).is_none());
        assert_eq!(
            resolve_host_via_bootstrap("192.0.2.53", &[]),
            Some("192.0.2.53".parse().unwrap())
        );
    }

    #[test]
    fn malformed_authority_is_rejected() {
        assert!(parse_native_upstream("udp://1.1.1.1:not-a-port", &[]).is_none());
        assert!(parse_native_upstream("udp://1.1.1.1:0", &[]).is_none());
        assert!(parse_native_upstream("https:///dns-query", &[]).is_none());
        assert!(parse_native_upstream("tls://1.1.1.1#", &[]).is_none());
    }
}
