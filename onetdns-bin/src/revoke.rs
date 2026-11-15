//! Revocation checks for upstream certificates: fetches OCSP or CRLs from the URLs in the
//! certificate. The tls crate verifies them; this fetches and decides.
//!
//! What happens when the check fails is policy. Passing lets anyone who can block the check use a
//! revoked certificate; blocking stops this server whenever the responder is down.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use onetdns_tls::revoke::{build_ocsp_request, check_ocsp_response, Crl, RevocationStatus};
use onetdns_tls::X509;

use crate::http;

const MAX_OCSP_RESPONSE: u64 = 1024 * 1024;
const MAX_CRL_RESPONSE: u64 = 16 * 1024 * 1024;

/// Warned at powers of two.
static SOFT_PASSES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationMode {
    Off,
    Ocsp,
    Crl,

    /// Chooses by what the certificate lists.
    Auto,
}

impl RevocationMode {
    pub fn parse(s: &str) -> RevocationMode {
        match s.trim().to_ascii_lowercase().as_str() {
            "ocsp" => RevocationMode::Ocsp,
            "crl" => RevocationMode::Crl,
            "auto" | "both" | "prefer_ocsp" => RevocationMode::Auto,
            _ => RevocationMode::Off,
        }
    }
}

pub struct RevocationChecker {
    pub mode: RevocationMode,
    /// Pass when the check cannot be made.
    pub soft_fail: bool,
    /// For OCSP and for CRLs each, shared across their URLs. Auto checks OCSP and then CRLs, so it
    /// can take twice this.
    pub timeout: Duration,
    /// Resolves responder names without asking this server.
    resolver: Option<http::HostResolver>,
}

impl RevocationChecker {
    pub fn new(mode: RevocationMode, soft_fail: bool, timeout: Duration) -> Self {
        RevocationChecker {
            mode,
            soft_fail,
            timeout,
            resolver: None,
        }
    }

    pub fn with_resolver(mut self, resolver: http::HostResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// `chain` must be the path TLS verification built; the certificate after the leaf is taken as
    /// its issuer. The chain the peer sent will not do: when a root issued the leaf directly, its
    /// second certificate is unverified, and a forged response signed with that key would pass.
    pub fn check_chain(&self, chain: &[X509], now: i64) -> Result<RevocationStatus, String> {
        if self.mode == RevocationMode::Off {
            return Ok(RevocationStatus::Good);
        }
        let leaf = chain
            .first()
            .ok_or("No verified certificate to check for revocation")?;
        let Some(issuer) = chain.get(1) else {
            return self.soft("No verified issuer certificate, so revocation cannot be checked");
        };

        let status = match self.mode {
            RevocationMode::Ocsp => self.via_ocsp(leaf, issuer, now),
            RevocationMode::Crl => self.via_crl(leaf, issuer, now),
            RevocationMode::Auto => {
                let o = self.via_ocsp(leaf, issuer, now);
                match o {
                    Some(RevocationStatus::Good) | Some(RevocationStatus::Revoked) => o,
                    _ => self.via_crl(leaf, issuer, now).or(o),
                }
            }
            RevocationMode::Off => unreachable!(),
        };

        match status {
            Some(RevocationStatus::Revoked) => Err("The certificate has been revoked".to_string()),
            Some(RevocationStatus::Good) => Ok(RevocationStatus::Good),
            Some(RevocationStatus::Unknown) | None => {
                self.soft("Could not check whether the certificate has been revoked")
            }
        }
    }

    /// Follows the operator's choice, and always logs why.
    fn soft(&self, why: &str) -> Result<RevocationStatus, String> {
        if self.soft_fail {
            let count = SOFT_PASSES.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_power_of_two() {
                onetdns_core::warn!(event = "tls.revocation_soft_pass", reason = %why, count = count, "Accepted an upstream certificate whose revocation could not be checked, as configured; blocking the checking server alone is enough to let a revoked certificate through");
            }
            Ok(RevocationStatus::Unknown)
        } else {
            Err(format!(
                "Rejected the connection because certificate revocation could not be checked: {why}"
            ))
        }
    }

    fn via_ocsp(&self, leaf: &X509, issuer: &X509, now: i64) -> Option<RevocationStatus> {
        first_definitive(&leaf.ocsp_urls, self.timeout, |url, remaining| {
            self.ocsp_once(url, remaining, leaf, issuer, now)
        })
    }

    fn ocsp_once(
        &self,
        url: &str,
        timeout: Duration,
        leaf: &X509,
        issuer: &X509,
        now: i64,
    ) -> Option<RevocationStatus> {
        let mut request = http::post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .timeout(timeout)
            .max_response(MAX_OCSP_RESPONSE)
            .deny_private_targets()
            .body_bytes(build_ocsp_request(leaf, issuer));
        if let Some(resolver) = &self.resolver {
            request = request.resolver(resolver.clone());
        }
        let resp = match request.call() {
            Ok(resp) => resp,
            Err(e) => {
                onetdns_core::debug!(event = "tls.ocsp_fetch_failed", url = %url, error = %e, "Could not reach the OCSP responder");
                return None;
            }
        };
        if resp.status != 200 {
            onetdns_core::debug!(event = "tls.ocsp_status_unexpected", url = %url, status = resp.status, "OCSP responder returned a non-200 status");
            return None;
        }
        match check_ocsp_response(&resp.body, issuer, &leaf.serial, now) {
            Ok(status) => Some(status),
            Err(e) => {
                onetdns_core::debug!(event = "tls.ocsp_response_invalid", url = %url, error = %e, "Could not verify the OCSP response");
                None
            }
        }
    }

    fn via_crl(&self, leaf: &X509, issuer: &X509, now: i64) -> Option<RevocationStatus> {
        first_definitive(&leaf.crl_urls, self.timeout, |url, remaining| {
            self.crl_once(url, remaining, leaf, issuer, now)
        })
    }

    fn crl_once(
        &self,
        url: &str,
        timeout: Duration,
        leaf: &X509,
        issuer: &X509,
        now: i64,
    ) -> Option<RevocationStatus> {
        let mut request = http::get(url)
            .timeout(timeout)
            .max_response(MAX_CRL_RESPONSE)
            .deny_private_targets();
        if let Some(resolver) = &self.resolver {
            request = request.resolver(resolver.clone());
        }
        let resp = match request.call() {
            Ok(resp) => resp,
            Err(e) => {
                onetdns_core::debug!(event = "tls.crl_fetch_failed", url = %url, error = %e, "Could not fetch the revocation list");
                return None;
            }
        };
        if resp.status != 200 {
            onetdns_core::debug!(event = "tls.crl_status_unexpected", url = %url, status = resp.status, "Revocation list server returned a non-200 status");
            return None;
        }
        let crl = match Crl::parse(&resp.body, issuer) {
            Ok(crl) => crl,
            Err(e) => {
                onetdns_core::debug!(event = "tls.crl_invalid", url = %url, error = %e, "Could not verify the revocation list");
                return None;
            }
        };
        if !crl.covers(leaf) {
            onetdns_core::debug!(event = "tls.crl_out_of_scope", url = %url, "The revocation list at this address does not cover the certificate");
        }
        Some(crl.status(leaf, now))
    }
}

/// Tries the URLs in order and stops at the first revoked or good answer; an unknown answer or a
/// failed fetch moves on. Each try gets only the time left, so the total stays within the budget.
///
/// Without a definitive answer: Unknown if any server answered unknown, None otherwise.
fn first_definitive(
    urls: &[String],
    budget: Duration,
    mut fetch: impl FnMut(&str, Duration) -> Option<RevocationStatus>,
) -> Option<RevocationStatus> {
    let deadline = Instant::now() + budget;
    let mut unknown = None;
    for url in urls {
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            break;
        };
        match fetch(url, remaining) {
            Some(RevocationStatus::Unknown) => unknown = Some(RevocationStatus::Unknown),
            Some(definitive) => return Some(definitive),
            None => {}
        }
    }
    unknown
}

pub fn pem_chain_to_ders(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = pem;
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    while let Some(b) = rest.find(begin) {
        let after = &rest[b + begin.len()..];
        let Some(e) = after.find(end) else { break };
        if let Some(der) = b64_decode(&after[..e]) {
            out.push(der);
        }
        rest = &after[e + end.len()..];
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// For the dashboard.
pub fn check_pem_chain_json(
    pem: &str,
    now: i64,
    timeout: Duration,
    resolver: http::HostResolver,
) -> Result<String, String> {
    let ders = pem_chain_to_ders(pem);
    if ders.len() < 2 {
        return Err(
            "At least two PEM certificates are needed: the server certificate and its issuer"
                .to_string(),
        );
    }
    let leaf =
        X509::parse(&ders[0]).map_err(|_| "Could not parse the leaf certificate".to_string())?;
    let issuer =
        X509::parse(&ders[1]).map_err(|_| "Could not parse the issuer certificate".to_string())?;

    let ocsp_checker =
        RevocationChecker::new(RevocationMode::Ocsp, true, timeout).with_resolver(resolver.clone());
    let crl_checker =
        RevocationChecker::new(RevocationMode::Crl, true, timeout).with_resolver(resolver);
    let ocsp = ocsp_checker.via_ocsp(&leaf, &issuer, now);
    let crl = crl_checker.via_crl(&leaf, &issuer, now);

    let revoked = ocsp == Some(RevocationStatus::Revoked) || crl == Some(RevocationStatus::Revoked);
    Ok(format!(
        "{{\"ocsp\":{},\"crl\":{},\"ocsp_urls\":{},\"crl_urls\":{},\"revoked\":{}}}",
        status_json(ocsp),
        status_json(crl),
        leaf.ocsp_urls.len(),
        leaf.crl_urls.len(),
        revoked
    ))
}

fn status_json(s: Option<RevocationStatus>) -> &'static str {
    match s {
        Some(RevocationStatus::Good) => "\"good\"",
        Some(RevocationStatus::Revoked) => "\"revoked\"",
        Some(RevocationStatus::Unknown) => "\"unknown\"",
        None => "\"unavailable\"",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parse() {
        assert_eq!(RevocationMode::parse("ocsp"), RevocationMode::Ocsp);
        assert_eq!(RevocationMode::parse("CRL"), RevocationMode::Crl);
        assert_eq!(RevocationMode::parse("auto"), RevocationMode::Auto);
        assert_eq!(RevocationMode::parse("off"), RevocationMode::Off);
        assert_eq!(RevocationMode::parse("garbage"), RevocationMode::Off);
    }

    #[test]
    fn off_mode_passes() {
        let c = RevocationChecker::new(RevocationMode::Off, false, Duration::from_secs(1));
        assert_eq!(c.check_chain(&[], 0).unwrap(), RevocationStatus::Good);
    }

    #[test]
    /// A leaf trusted through a certificate pin has no issuer in the path.
    fn missing_issuer_softfails_or_hardfails() {
        let (certs, _key) = onetdns_transport::self_signed_material("leaf.test").unwrap();
        let leaf = X509::parse(&certs[0]).unwrap();
        let soft = RevocationChecker::new(RevocationMode::Ocsp, true, Duration::from_secs(1));
        assert_eq!(
            soft.check_chain(std::slice::from_ref(&leaf), 0).unwrap(),
            RevocationStatus::Unknown
        );
        let hard = RevocationChecker::new(RevocationMode::Ocsp, false, Duration::from_secs(1));
        assert!(hard.check_chain(std::slice::from_ref(&leaf), 0).is_err());
    }

    fn urls(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn later_urls_are_tried_until_a_definitive_answer() {
        let answers = |url: &str| match url {
            "down" => None,
            "unsure" => Some(RevocationStatus::Unknown),
            "revoked" => Some(RevocationStatus::Revoked),
            _ => Some(RevocationStatus::Good),
        };
        let mut asked = Vec::new();
        let status = first_definitive(
            &urls(&["down", "unsure", "revoked", "good"]),
            Duration::from_secs(5),
            |url, _| {
                asked.push(url.to_string());
                answers(url)
            },
        );
        assert_eq!(status, Some(RevocationStatus::Revoked));
        assert_eq!(
            asked,
            ["down", "unsure", "revoked"],
            "확정 답 뒤로는 묻지 않아야 한다"
        );

        let mut asked = Vec::new();
        let status = first_definitive(
            &urls(&["good", "revoked"]),
            Duration::from_secs(5),
            |url, _| {
                asked.push(url.to_string());
                answers(url)
            },
        );
        assert_eq!(status, Some(RevocationStatus::Good));
        assert_eq!(asked, ["good"]);
    }

    #[test]
    fn no_definitive_answer_reports_unknown_only_if_a_server_answered() {
        let none = first_definitive(&urls(&["a", "b"]), Duration::from_secs(5), |_, _| None);
        assert_eq!(none, None);

        let unknown = first_definitive(&urls(&["a", "b"]), Duration::from_secs(5), |url, _| {
            (url == "a").then_some(RevocationStatus::Unknown)
        });
        assert_eq!(unknown, Some(RevocationStatus::Unknown));

        assert_eq!(
            first_definitive(&[], Duration::from_secs(5), |_, _| None),
            None
        );
    }

    #[test]
    fn urls_share_one_budget() {
        let budget = Duration::from_millis(400);
        let mut given = Vec::new();
        first_definitive(&urls(&["slow", "next"]), budget, |url, remaining| {
            given.push(remaining);
            if url == "slow" {
                std::thread::sleep(Duration::from_millis(100));
            }
            None
        });
        assert_eq!(given.len(), 2);
        assert!(given[0] <= budget);
        assert!(
            given[1] <= budget - Duration::from_millis(100),
            "앞 주소가 쓴 시간을 빼고 넘겨야 한다: {given:?}"
        );

        let mut asked = Vec::new();
        first_definitive(
            &urls(&["hang", "never"]),
            Duration::from_millis(30),
            |url, _| {
                asked.push(url.to_string());
                std::thread::sleep(Duration::from_millis(60));
                None
            },
        );
        assert_eq!(
            asked,
            ["hang"],
            "예산을 다 쓰면 다음 주소를 시도하지 않아야 한다"
        );
    }

    #[test]
    fn pem_chain_decodes_multiple() {
        let (cert_pem, _key_pem) = onetdns_transport::generate_self_signed_pem("a.test").unwrap();
        let two = format!("{cert_pem}\n{cert_pem}");
        assert_eq!(pem_chain_to_ders(&two).len(), 2);
    }
}
