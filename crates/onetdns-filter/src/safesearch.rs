//! Safe search rewriting: a search service's name is answered with the safe-search name that
//! service provides. Filtering happens at the service, not here.

pub const SAFE_SEARCH: &[(&str, &str)] = &[
    ("google.com", "forcesafesearch.google.com"),
    ("www.google.com", "forcesafesearch.google.com"),
    ("google.co.kr", "forcesafesearch.google.com"),
    ("www.google.co.kr", "forcesafesearch.google.com"),
    ("bing.com", "strict.bing.com"),
    ("www.bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"),
    ("www.duckduckgo.com", "safe.duckduckgo.com"),
    ("youtube.com", "restrict.youtube.com"),
    ("www.youtube.com", "restrict.youtube.com"),
    ("m.youtube.com", "restrict.youtube.com"),
];

pub fn safe_target(normalized_qname: &str) -> Option<&'static str> {
    SAFE_SEARCH
        .iter()
        .find(|(host, _)| *host == normalized_qname)
        .map(|(_, target)| *target)
}
