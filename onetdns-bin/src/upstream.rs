//! Turns configured upstream URLs into connect targets. An upstream that points back at this server
//! is rejected, since queries would loop.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;
use onetdns_forward::{Endpoint, Socks5Proxy, Upstream};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(5);

/// How a forwarder reaches its upstreams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamRoute {
    /// Host names are resolved through `bootstrap` when the URL is read.
    Direct { bootstrap: Vec<IpAddr> },
    /// The proxy is given host names as written, so this server never looks them up. Only DoT and
    /// DoH can use it.
    Socks5(Arc<Socks5Proxy>),
}

impl UpstreamRoute {
    /// The route of the default, fallback, and client forwarders.
    pub fn forwarding(cfg: &Config) -> Self {
        let Some(addr) = cfg.upstream_proxy else {
            return UpstreamRoute::Direct {
                bootstrap: cfg.bootstrap.clone(),
            };
        };
        let mut proxy = Socks5Proxy::new(addr);
        if let (Some(username), Some(password)) =
            (&cfg.upstream_proxy_username, &cfg.upstream_proxy_password)
        {
            proxy = proxy.with_credentials(username.clone(), password.clone());
        }
        UpstreamRoute::Socks5(Arc::new(proxy))
    }
}

/// Hostname upstreams are checked after resolving; the URL alone would miss this server hidden
/// behind a name.
pub fn ensure_not_listener(
    upstreams: &[Upstream],
    listeners: &[SocketAddr],
    label: &str,
) -> Result<(), String> {
    let direct = upstreams
        .iter()
        .filter_map(|upstream| match upstream.endpoint {
            Endpoint::Direct(addr) => Some(addr),
            Endpoint::Socks5 { .. } => None,
        });
    for addr in direct {
        if points_at_listener(addr, listeners) {
            return Err(format!(
                "{label}={addr} points to this server's own DNS listening address after the initial lookup, which would create a query loop"
            ));
        }
    }
    Ok(())
}

/// A listener on the unspecified address also answers at every address of this machine.
pub(crate) fn points_at_listener(target: SocketAddr, listeners: &[SocketAddr]) -> bool {
    listeners.iter().any(|listener| {
        onetdns_config::dns_endpoint_conflicts(*listener, target)
            || listener.port() == target.port()
                && listener.ip().is_unspecified()
                && (listener.is_ipv6() || listener.is_ipv4() == target.is_ipv4())
                && is_local_ip(target.ip())
    })
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

/// Plain servers cannot use a proxy route; validation refuses them with one.
pub fn native_upstreams(plain: &[IpAddr], urls: &[String], route: &UpstreamRoute) -> Vec<Upstream> {
    let mut out: Vec<Upstream> = match route {
        UpstreamRoute::Direct { .. } => plain
            .iter()
            .map(|ip| Upstream::udp(SocketAddr::new(*ip, 53)))
            .collect(),
        UpstreamRoute::Socks5(_) => Vec::new(),
    };
    for u in urls {
        match parse_native_upstream(u, route) {
            Some(up) => out.push(up),
            None => {
                onetdns_core::warn!(event = "upstream.parse_failed", url = %u, "Could not resolve an upstream DNS server's address; skipping that server")
            }
        }
    }
    out
}

pub fn servers_to_upstreams(servers: &[String], route: &UpstreamRoute) -> Vec<Upstream> {
    let mut out = Vec::new();
    for s in servers {
        let s = s.trim();
        if let (Ok(ip), UpstreamRoute::Direct { .. }) = (s.parse::<IpAddr>(), route) {
            out.push(Upstream::udp(SocketAddr::new(ip, 53)));
        } else if let Some(up) = parse_native_upstream(s, route) {
            out.push(up);
        } else {
            onetdns_core::warn!(event = "upstream.fallback_parse_failed", server = %s, "Could not resolve a stub or fallback upstream DNS server's address; skipping that server");
        }
    }
    out
}

/// Hostnames need bootstrap servers.
pub fn url_uses_hostname(url: &str) -> bool {
    if url.trim().starts_with("sdns://") {
        return false;
    }
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

/// None for an unknown scheme, a malformed URL, a hostname without bootstrap servers, or a scheme
/// the route cannot carry.
fn parse_native_upstream(url: &str, route: &UpstreamRoute) -> Option<Upstream> {
    let url = url.trim();
    if url.is_empty() || url.chars().any(char::is_control) {
        return None;
    }
    if url.starts_with("sdns://") {
        if matches!(route, UpstreamRoute::Socks5(_)) {
            return None;
        }
        let stamp = onetdns_config::stamp::dnscrypt_server(url)?;
        return Some(Upstream::dnscrypt(
            stamp.addr,
            stamp.provider_name,
            stamp.public_key,
        ));
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
    let sni = || sni.clone().unwrap_or_else(|| host.to_string());
    let doh_path = || path.clone().unwrap_or_else(|| "/dns-query".to_string());
    let bootstrap = match route {
        UpstreamRoute::Direct { bootstrap } => bootstrap,
        UpstreamRoute::Socks5(proxy) => {
            return match scheme.as_str() {
                "tls" => Some(Upstream::dot_via(
                    Arc::clone(proxy),
                    host,
                    port.unwrap_or(853),
                    sni(),
                )),
                "https" => Some(Upstream::doh_via(
                    Arc::clone(proxy),
                    host,
                    port.unwrap_or(443),
                    sni(),
                    doh_path(),
                )),
                _ => None,
            };
        }
    };
    let ip = resolve_host(host, bootstrap)?;
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

    const DIRECT: UpstreamRoute = UpstreamRoute::Direct {
        bootstrap: Vec::new(),
    };

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
        let ups = native_upstreams(&plain, &urls, &DIRECT);
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
        assert_eq!(
            ups[4].endpoint,
            Endpoint::Direct("1.0.0.1:853".parse().unwrap())
        );
        assert_eq!(
            ups[5].transport,
            Transport::Doh3 {
                server_name: "dns.google".into(),
                path: "/dns-query".into()
            }
        );
        assert_eq!(
            ups[5].endpoint,
            Endpoint::Direct("8.8.8.8:443".parse().unwrap())
        );
    }

    #[test]
    fn hostname_upstream_needs_bootstrap_but_ip_literal_does_not() {
        assert!(parse_native_upstream("h3://cloudflare-dns.com/dns-query", &DIRECT).is_none());
        assert!(url_uses_hostname("h3://cloudflare-dns.com/dns-query"));

        let up =
            parse_native_upstream("h3://1.1.1.1/dns-query#cloudflare-dns.com", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("1.1.1.1:443".parse().unwrap())
        );
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
        let up = parse_native_upstream("https://1.1.1.1", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("1.1.1.1:443".parse().unwrap())
        );
        assert_eq!(
            up.transport,
            Transport::Doh {
                server_name: "1.1.1.1".into(),
                path: "/dns-query".into()
            }
        );

        let up =
            parse_native_upstream("https://9.9.9.9:8443/resolve#dns.quad9.net", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("9.9.9.9:8443".parse().unwrap())
        );
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
        let up = parse_native_upstream("quic://1.1.1.1", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("1.1.1.1:853".parse().unwrap())
        );
        assert_eq!(
            up.transport,
            Transport::Doq {
                server_name: "1.1.1.1".into()
            }
        );

        let up = parse_native_upstream("h3://1.1.1.1#cloudflare-dns.com", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("1.1.1.1:443".parse().unwrap())
        );
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
            &DIRECT,
        );
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].transport, Transport::Udp);
        assert_eq!(
            ups[1].endpoint,
            Endpoint::Direct("9.9.9.9:853".parse().unwrap())
        );
    }

    #[test]
    /// A stamp carries its own address, so it needs no bootstrap servers.
    fn a_dnscrypt_stamp_is_an_upstream_without_bootstrap() {
        let stamp = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
        assert!(!url_uses_hostname(stamp));
        let up = parse_native_upstream(stamp, &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("94.140.14.14:5443".parse().unwrap())
        );
        assert!(matches!(
            &up.transport,
            Transport::Dnscrypt { provider_name, .. }
                if provider_name == "2.dnscrypt.default.ns1.adguard.com"
        ));
        assert_eq!(
            servers_to_upstreams(&[stamp.to_string()], &DIRECT),
            vec![up]
        );
        assert!(parse_native_upstream(&stamp[..stamp.len() - 2], &DIRECT).is_none());
        let proxy = UpstreamRoute::Socks5(Arc::new(Socks5Proxy::new(
            "127.0.0.1:9050".parse().unwrap(),
        )));
        assert!(
            parse_native_upstream(stamp, &proxy).is_none(),
            "DNSCrypt 는 UDP 라 프록시를 거치지 못합니다"
        );
    }

    #[test]
    fn unknown_scheme_skipped() {
        assert!(parse_native_upstream("ftp://1.2.3.4", &DIRECT).is_none());
        assert!(parse_native_upstream("gopher://8.8.8.8", &DIRECT).is_none());
    }

    #[test]
    fn removed_scheme_aliases_are_rejected() {
        for scheme in ["dot", "doh", "h2", "doq", "doh3"] {
            assert!(
                parse_native_upstream(&format!("{scheme}://192.0.2.1"), &DIRECT).is_none(),
                "{scheme}"
            );
        }
    }
    #[test]
    fn bracketed_ipv6_with_port_is_parsed() {
        let up =
            parse_native_upstream("tls://[2001:4860:4860::8888]:8853#dns.google", &DIRECT).unwrap();
        assert_eq!(
            up.endpoint,
            Endpoint::Direct("[2001:4860:4860::8888]:8853".parse().unwrap())
        );
    }

    #[test]
    fn hostname_without_bootstrap_is_rejected() {
        assert!(parse_native_upstream("https://dns.example/dns-query", &DIRECT).is_none());
        assert!(resolve_host_via_bootstrap("dns.example", &[]).is_none());
        assert_eq!(
            resolve_host_via_bootstrap("192.0.2.53", &[]),
            Some("192.0.2.53".parse().unwrap())
        );
    }

    #[test]
    fn malformed_authority_is_rejected() {
        assert!(parse_native_upstream("udp://1.1.1.1:not-a-port", &DIRECT).is_none());
        assert!(parse_native_upstream("udp://1.1.1.1:0", &DIRECT).is_none());
        assert!(parse_native_upstream("https:///dns-query", &DIRECT).is_none());
        assert!(parse_native_upstream("tls://1.1.1.1#", &DIRECT).is_none());
    }

    #[test]
    /// The proxy gets the host as written: nothing is looked up here, even with bootstrap set.
    fn proxy_route_passes_host_names_to_the_proxy() {
        let cfg = Config {
            bootstrap: vec!["192.0.2.53".parse().unwrap()],
            upstream_proxy: Some("127.0.0.1:9050".parse().unwrap()),
            upstream_proxy_username: Some("onet".into()),
            upstream_proxy_password: Some("secret".into()),
            ..Config::default()
        };
        let route = UpstreamRoute::forwarding(&cfg);
        let UpstreamRoute::Socks5(proxy) = &route else {
            panic!("{route:?}");
        };
        assert_eq!(
            **proxy,
            Socks5Proxy::new("127.0.0.1:9050".parse().unwrap())
                .with_credentials("onet", "secret".into())
        );

        let up = parse_native_upstream("tls://dns.example#dns.example", &route).unwrap();
        assert_eq!(
            up,
            Upstream::dot_via(Arc::clone(proxy), "dns.example", 853, "dns.example")
        );
        let up = parse_native_upstream("https://[2001:db8::1]:8443/q#dns.example", &route).unwrap();
        assert_eq!(
            up,
            Upstream::doh_via(Arc::clone(proxy), "2001:db8::1", 8443, "dns.example", "/q")
        );
        for url in ["quic://dns.example", "h3://dns.example", "udp://192.0.2.1"] {
            assert!(parse_native_upstream(url, &route).is_none(), "{url}");
        }
        assert!(native_upstreams(&["192.0.2.1".parse().unwrap()], &[], &route).is_empty());
        assert!(servers_to_upstreams(&["192.0.2.1".to_string()], &route).is_empty());
    }
}
