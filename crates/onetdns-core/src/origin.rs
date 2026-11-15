/// One HTTPS web origin, the address the management UI is served under behind a reverse proxy.
/// Normalized to the form browsers send in Origin: lowercase scheme and host, default port 443
/// dropped. Browsers drop the default port too, so keeping it would compare one origin as two
/// values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsOrigin {
    /// Host and port to compare with the Host header, such as admin.example.com or
    /// admin.example.com:8443.
    authority: String,
}

impl HttpsOrigin {
    /// Reads https://host[:port]; rejects any path, query, or user info.
    pub fn parse(value: &str) -> Option<Self> {
        let scheme = value.get(..8)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return None;
        }
        let authority = parse_authority(&value[8..])?;
        Some(Self { authority })
    }

    /// Ignores case and an explicit default port.
    pub fn matches_host(&self, host: &str) -> bool {
        parse_authority(host).is_some_and(|authority| authority == self.authority)
    }

    pub fn matches_origin(&self, origin: &str) -> bool {
        Self::parse(origin).is_some_and(|other| other == *self)
    }
}

impl std::fmt::Display for HttpsOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}", self.authority)
    }
}

/// Names become lowercase DNS names; addresses are IPv4 or bracketed IPv6. Drops port 443 and
/// rejects 0 or out-of-range ports.
fn parse_authority(value: &str) -> Option<String> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (format!("[{}]", inner.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        };
        let valid = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            })
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.');
        if !valid {
            return None;
        }
        (host.to_ascii_lowercase(), port)
    };
    match port {
        None => Some(host),
        Some(port) => {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            match port.parse::<u16>().ok()? {
                0 => None,
                443 => Some(host),
                port => Some(format!("{host}:{port}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HttpsOrigin;

    #[test]
    fn origins_are_normalized_the_way_browsers_send_them() {
        let origin = HttpsOrigin::parse("HTTPS://Admin.Example.com:443").unwrap();
        assert_eq!(origin.to_string(), "https://admin.example.com");
        assert!(origin.matches_origin("https://admin.example.com"));
        assert!(origin.matches_host("admin.example.com"));
        assert!(origin.matches_host("ADMIN.example.com:443"));
        assert!(!origin.matches_host("admin.example.com:8443"));
        assert!(!origin.matches_origin("http://admin.example.com"));

        let ported = HttpsOrigin::parse("https://[::1]:8443").unwrap();
        assert!(ported.matches_host("[::1]:8443"));
        assert!(!ported.matches_host("[::1]"));
    }

    #[test]
    fn anything_but_a_bare_https_origin_is_rejected() {
        for value in [
            "http://admin.example.com",
            "https://admin.example.com/",
            "https://admin.example.com/dashboard",
            "https://user@admin.example.com",
            "https://admin.example.com?x=1",
            "https://admin.example.com:0",
            "https://admin.example.com:70000",
            "https://",
            "https://-bad.example.com",
            "admin.example.com",
        ] {
            assert!(HttpsOrigin::parse(value).is_none(), "{value}");
        }
    }
}
