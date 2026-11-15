//! Release version precedence, by semver rules. Build metadata is rejected: it takes no part in
//! precedence, so it would allow different versions of equal rank, and release tags never carry it.

use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Identifier {
    Numeric(u64),
    Text(String),
}

impl Ord for Identifier {
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
/// Two versions are equal only when parsed from the same string.
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    /// Empty for a release.
    pre: Vec<Identifier>,
}

/// Decimal without leading zeros; 0 itself is allowed.
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
    /// MAJOR.MINOR.PATCH with an optional -prerelease; nothing else.
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

    /// Tags are `v` followed by the version.
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        Self::parse(tag.strip_prefix('v')?)
    }

    pub(crate) fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }

    /// It must be strictly newer, and a release only moves to another release, so release users
    /// never get a prerelease.
    pub(crate) fn accepts(&self, candidate: &Version) -> bool {
        candidate > self && (self.is_prerelease() || !candidate.is_prerelease())
    }
}

impl Ord for Version {
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
    /// Writes the string it was parsed from; parsing accepts one spelling only.
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
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} 를 읽지 못했습니다"))
    }

    #[test]
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
    /// Manifests and tags are compared as strings, which relies on this.
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
