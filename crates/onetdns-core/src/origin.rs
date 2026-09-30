/**
 * @brief HTTPS 웹 출처 하나. 관리 화면을 리버스 프록시 뒤에서 내보일 주소다.
 * @details 브라우저가 Origin 헤더에 싣는 형태로 정규화해 둔다. 스킴과 호스트는 소문자이고
 *          기본 포트 443은 뺀다. 브라우저도 기본 포트를 빼고 보내므로, 빼지 않으면 같은 출처를
 *          다른 값으로 비교하게 된다.
 */
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsOrigin {
    /** @brief Host 헤더와 비교할 호스트와 포트. 예: admin.example.com, admin.example.com:8443 */
    authority: String,
}

impl HttpsOrigin {
    /**
     * @brief https://host[:port] 형태를 읽는다. 경로, 질의, 사용자 정보가 붙으면 거부한다.
     * @return 형식이 맞지 않으면 None.
     */
    pub fn parse(value: &str) -> Option<Self> {
        let scheme = value.get(..8)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return None;
        }
        let authority = parse_authority(&value[8..])?;
        Some(Self { authority })
    }

    /** @brief Host 헤더 값이 이 출처를 가리키는지. 대소문자와 기본 포트 표기를 무시한다. */
    pub fn matches_host(&self, host: &str) -> bool {
        parse_authority(host).is_some_and(|authority| authority == self.authority)
    }

    /** @brief Origin 헤더 값이 이 출처와 같은지. */
    pub fn matches_origin(&self, origin: &str) -> bool {
        Self::parse(origin).is_some_and(|other| other == *self)
    }
}

impl std::fmt::Display for HttpsOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}", self.authority)
    }
}

/**
 * @brief 호스트와 포트를 정규화한다. 이름은 소문자 DNS 이름, 주소는 IPv4나 괄호로 감싼 IPv6다.
 * @note 포트 443은 떼어 낸다. 0이나 범위 밖 포트는 거부한다.
 */
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
    /** @brief 브라우저가 보내는 형태와 같은 값으로 정규화하는지. */
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
    /** @brief 경로나 사용자 정보가 붙은 값, HTTPS가 아닌 값을 거부하는지. */
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
