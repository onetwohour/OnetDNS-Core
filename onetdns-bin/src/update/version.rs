/*!
 * @brief 릴리스 버전의 우선순위.
 *
 * @details semver 의 우선순위 규칙을 따른다. 빌드 메타데이터(+ 뒤)는 받지 않는다. 우선순위에
 *          들어가지 않아 같은 순위의 서로 다른 버전을 만들 수 있기 때문이고, 릴리스 태그에는
 *          붙지 않는다.
 */

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 시험판 식별자 하나. */
enum Identifier {
    /** @brief 숫자로만 된 식별자. 수로 비교한다. */
    Numeric(u64),
    /** @brief 문자가 섞인 식별자. ASCII 순서로 비교한다. */
    Text(String),
}

impl Ord for Identifier {
    /** @brief 숫자 식별자는 늘 문자 식별자보다 낮다. */
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Identifier::Numeric(left), Identifier::Numeric(right)) => left.cmp(right),
            (Identifier::Numeric(_), Identifier::Text(_)) => Ordering::Less,
            (Identifier::Text(_), Identifier::Numeric(_)) => Ordering::Greater,
            (Identifier::Text(left), Identifier::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 버전 하나. 같은 문자열에서 읽은 것끼리만 같다. */
pub(crate) struct Version {
    /** @brief 주 번호. */
    major: u64,
    /** @brief 부 번호. */
    minor: u64,
    /** @brief 수 번호. */
    patch: u64,
    /** @brief 시험판 식별자. 비어 있으면 정식판이다. */
    pre: Vec<Identifier>,
}

/** @brief 앞에 0 이 붙지 않은 10진수. 0 자체는 받는다. */
fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

impl Version {
    /** @brief MAJOR.MINOR.PATCH 와 선택적인 -시험판 식별자를 읽는다. 그 밖의 형태는 받지 않는다. */
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let major = number(parts.next()?)?;
        let minor = number(parts.next()?)?;
        let patch = number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|identifier| {
                    if identifier.is_empty()
                        || !identifier
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    {
                        return None;
                    }
                    if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                        number(identifier).map(Identifier::Numeric)
                    } else {
                        Some(Identifier::Text(identifier.to_string()))
                    }
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /** @brief v 로 시작하는 릴리스 태그에서 버전을 읽는다. */
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }

    /** @brief 시험판인지. */
    pub(crate) fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /**
     * @brief 이 버전에서 그 버전으로 올라가도 되는지.
     * @details 우선순위가 엄격히 높아야 한다. 정식판은 정식판으로만 가고, 시험판은 시험판과
     *          정식판으로 모두 간다. 정식판을 쓰는 운영자가 시험판을 받지 않게 하려는 것이다.
     */
    pub(crate) fn accepts(&self, candidate: &Version) -> bool {
        candidate > self && (self.is_prerelease() || !candidate.is_prerelease())
    }
}

impl Ord for Version {
    /** @brief semver 우선순위. 시험판은 같은 번호의 정식판보다 낮다. */
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    /** @brief 읽은 문자열과 같은 모양으로 쓴다. 읽을 때 다른 표기를 받지 않으므로 하나뿐이다. */
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (index, identifier) in self.pre.iter().enumerate() {
            f.write_str(if index == 0 { "-" } else { "." })?;
            match identifier {
                Identifier::Numeric(value) => write!(f, "{value}")?,
                Identifier::Text(value) => f.write_str(value)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
/** @brief 우선순위와 후보 규칙. */
mod tests {
    use super::*;

    /** @brief 테스트용으로 반드시 읽히는 버전. */
    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} 를 읽지 못했습니다"))
    }

    #[test]
    /** @brief semver 문서가 예로 드는 순서를 그대로 따르는지. */
    fn precedence_follows_semver() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
            "10.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert!(v("0.1.0-alpha.10") > v("0.1.0-alpha.9"));
    }

    #[test]
    /** @brief 표기가 틀린 버전과 빌드 메타데이터를 받지 않는지. */
    fn malformed_versions_are_rejected() {
        for text in [
            "",
            "1",
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.00.0",
            "1.0.0-",
            "1.0.0-alpha..1",
            "1.0.0-alpha.01",
            "1.0.0+build",
            "1.0.0-alpha+build",
            "v1.0.0",
            " 1.0.0",
            "1.0.0-al_pha",
            "1.0.0-é",
            "18446744073709551616.0.0",
        ] {
            assert!(Version::parse(text).is_none(), "{text:?}");
        }
        assert!(Version::parse("1.0.0-x-y.0").is_some());
    }

    #[test]
    /** @brief 읽은 버전을 다시 쓰면 같은 문자열인지. 매니페스트와 태그를 문자열로 맞대는 근거다. */
    fn display_round_trips() {
        for text in ["0.1.0-alpha.5", "1.2.3", "1.0.0-rc.1.x-y", "0.0.0"] {
            assert_eq!(v(text).to_string(), text);
        }
        assert_eq!(
            Version::from_tag("v0.1.0-alpha.6"),
            Some(v("0.1.0-alpha.6"))
        );
        assert_eq!(Version::from_tag("0.1.0"), None);
        assert_eq!(Version::from_tag("release-1"), None);
    }

    #[test]
    /** @brief 같거나 낮은 버전으로는 가지 않고, 정식판은 시험판을 받지 않는지. */
    fn candidates_must_be_newer_and_match_the_channel() {
        let stable = v("1.0.0");
        assert!(stable.accepts(&v("1.0.1")));
        assert!(!stable.accepts(&v("1.0.0")));
        assert!(!stable.accepts(&v("0.9.9")));
        assert!(!stable.accepts(&v("1.1.0-alpha.1")));

        let alpha = v("0.1.0-alpha.5");
        assert!(alpha.accepts(&v("0.1.0-alpha.6")));
        assert!(alpha.accepts(&v("0.1.0")));
        assert!(alpha.accepts(&v("0.2.0-beta.1")));
        assert!(!alpha.accepts(&v("0.1.0-alpha.5")));
        assert!(!alpha.accepts(&v("0.1.0-alpha.4")));
        assert!(!alpha.accepts(&v("0.0.9")));
    }
}
