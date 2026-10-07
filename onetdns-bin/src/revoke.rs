/*!
 * @brief 업스트림 인증서의 폐기 확인.
 *
 * @details 인증서에 적힌 주소로 OCSP나 폐기 목록을 받아 온다. 검증 자체는 tls 크레이트가
 *          하고, 여기서는 받아 오는 일과 처분을 맡는다.
 * @warning 확인에 실패했을 때 통과시킬지 막을지가 정책이다. 통과시키면 확인을 막는 것만으로
 *          폐기된 인증서를 쓸 수 있고, 막으면 확인 서버가 죽었을 때 이 서버도 멈춘다.
 */

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use onetdns_tls::revoke::{build_ocsp_request, check_ocsp_response, Crl, RevocationStatus};
use onetdns_tls::X509;

use crate::http;

/** @brief 받아들일 OCSP 응답 크기 상한. */
const MAX_OCSP_RESPONSE: u64 = 1024 * 1024;
/** @brief 받아들일 폐기 목록 크기 상한. */
const MAX_CRL_RESPONSE: u64 = 16 * 1024 * 1024;

/** @brief 확인 없이 통과시킨 누적 횟수. 2의 거듭제곱 번째만 경고해 로그 폭주를 막는다. */
static SOFT_PASSES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 폐기 확인 방식. */
pub enum RevocationMode {
    /** @brief 확인하지 않는다. */
    Off,
    /** @brief OCSP로 확인한다. */
    Ocsp,
    /** @brief 폐기 목록으로 확인한다. */
    Crl,

    /** @brief 인증서에 적힌 것을 보고 고른다. */
    Auto,
}

impl RevocationMode {
    /** @brief 설정 문자열을 방식으로. */
    pub fn parse(s: &str) -> RevocationMode {
        match s.trim().to_ascii_lowercase().as_str() {
            "ocsp" => RevocationMode::Ocsp,
            "crl" => RevocationMode::Crl,
            "auto" | "both" | "prefer_ocsp" => RevocationMode::Auto,
            _ => RevocationMode::Off,
        }
    }
}

/** @brief 폐기를 확인하는 것. */
pub struct RevocationChecker {
    /** @brief 확인 방식. */
    pub mode: RevocationMode,
    /** @brief 확인하지 못했을 때 통과시킬지. */
    pub soft_fail: bool,
    /**
     * @brief OCSP와 폐기 목록에 각각 쓸 수 있는 시간. 주소가 여럿이면 이 시간을 나눠 쓴다.
     * @note 자동 방식은 OCSP 다음에 폐기 목록을 확인하므로 최대 두 배까지 걸린다.
     */
    pub timeout: Duration,
    /** @brief 확인 서버 이름을 풀 방법. 자기 자신에게 묻지 않으려는 것이다. */
    resolver: Option<http::HostResolver>,
}

impl RevocationChecker {
    /** @brief 방식과 실패 처분, 데드라인으로 만든다. */
    pub fn new(mode: RevocationMode, soft_fail: bool, timeout: Duration) -> Self {
        RevocationChecker {
            mode,
            soft_fail,
            timeout,
            resolver: None,
        }
    }

    /** @brief 확인 서버 이름을 풀 방법을 지정한다. 자기 자신에게 묻지 않으려는 것이다. */
    pub fn with_resolver(mut self, resolver: http::HostResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /**
     * @brief 검증한 인증 경로에서 리프가 폐기됐는지 확인한다.
     * @param chain TLS 검증이 돌려준 인증 경로. 리프 바로 다음 인증서를 발급자로 쓴다.
     * @warning 상대가 보낸 체인을 그대로 넘기면 안 된다. 리프를 루트가 바로 발급했으면 그
     *          체인의 두 번째 인증서는 아무도 검증하지 않은 값이고, 그 키로 서명한 가짜 폐기
     *          응답이 통과한다.
     */
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

    /**
     * @brief 확인하지 못했을 때의 처분.
     * @warning 통과시키면 확인을 막는 것만으로 폐기된 인증서를 쓸 수 있다. 운영자가
     *          정한 대로 따르되 사유는 반드시 남긴다.
     */
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

    /** @brief 인증서에 적힌 OCSP 주소를 차례로 물어 확인한다. */
    fn via_ocsp(&self, leaf: &X509, issuer: &X509, now: i64) -> Option<RevocationStatus> {
        first_definitive(&leaf.ocsp_urls, self.timeout, |url, remaining| {
            self.ocsp_once(url, remaining, leaf, issuer, now)
        })
    }

    /** @brief OCSP 응답 서버 하나에 묻는다. */
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

    /** @brief 인증서에 적힌 폐기 목록 주소를 차례로 받아 확인한다. */
    fn via_crl(&self, leaf: &X509, issuer: &X509, now: i64) -> Option<RevocationStatus> {
        first_definitive(&leaf.crl_urls, self.timeout, |url, remaining| {
            self.crl_once(url, remaining, leaf, issuer, now)
        })
    }

    /** @brief 폐기 목록 하나를 받아 확인한다. */
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

/**
 * @brief 주소를 차례로 시도해 처음 나온 확정 답을 돌려준다.
 * @details 폐기됨이나 정상을 받으면 멈춘다. 알 수 없음을 받았거나 받아 오지 못했으면 다음
 *          주소로 넘어간다. 시도마다 남은 시간만 넘기므로 주소가 많아도 전체가 예산을 넘지
 *          않는다.
 * @return 확정 답이 없을 때 알 수 없음을 한 번이라도 받았으면 알 수 없음, 아니면 없음.
 */
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

/** @brief PEM 체인을 DER 목록으로. */
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

/** @brief base64 디코딩. */
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    /** @brief 문자 하나를 6비트 값으로. */
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

/** @brief 체인을 확인하고 결과를 JSON으로. 대시보드가 쓴다. */
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

/** @brief 상태를 JSON 값으로. */
fn status_json(s: Option<RevocationStatus>) -> &'static str {
    match s {
        Some(RevocationStatus::Good) => "\"good\"",
        Some(RevocationStatus::Revoked) => "\"revoked\"",
        Some(RevocationStatus::Unknown) => "\"unknown\"",
        None => "\"unavailable\"",
    }
}

#[cfg(test)]
/** @brief 방식 해석과 실패 처분. */
mod tests {
    use super::*;

    #[test]
    /** @brief 방식 이름이 읽히는지. */
    fn mode_parse() {
        assert_eq!(RevocationMode::parse("ocsp"), RevocationMode::Ocsp);
        assert_eq!(RevocationMode::parse("CRL"), RevocationMode::Crl);
        assert_eq!(RevocationMode::parse("auto"), RevocationMode::Auto);
        assert_eq!(RevocationMode::parse("off"), RevocationMode::Off);
        assert_eq!(RevocationMode::parse("garbage"), RevocationMode::Off);
    }

    #[test]
    /** @brief 확인을 끄면 그냥 통과하는지. */
    fn off_mode_passes() {
        let c = RevocationChecker::new(RevocationMode::Off, false, Duration::from_secs(1));
        assert_eq!(c.check_chain(&[], 0).unwrap(), RevocationStatus::Good);
    }

    #[test]
    /** @brief 경로에 발급자가 없을 때 정책대로 갈리는지. 인증서 핀으로 믿은 리프가 이렇다. */
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

    /** @brief 주소 목록을 만든다. */
    fn urls(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    /** @brief 첫 주소가 실패하거나 모르면 다음 주소로 넘어가고, 확정 답에서 멈추는지. */
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
    /** @brief 확정 답이 없을 때, 알 수 없음을 받은 적이 있는지에 따라 결과가 갈리는지. */
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
    /** @brief 주소들이 예산 하나를 나눠 쓰는지. 앞 주소가 쓴 시간만큼 뒤 주소의 몫이 준다. */
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
    /** @brief 여러 인증서가 든 PEM이 풀리는지. */
    fn pem_chain_decodes_multiple() {
        let (cert_pem, _key_pem) = onetdns_transport::generate_self_signed_pem("a.test").unwrap();
        let two = format!("{cert_pem}\n{cert_pem}");
        assert_eq!(pem_chain_to_ders(&two).len(), 2);
    }
}
