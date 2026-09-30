/*!
 * @brief 실행 중인 서버의 관리 API를 부르는 ctl 명령.
 */

use std::net::{IpAddr, SocketAddr};

use onetdns_config::Config;

use crate::cli::CtlArgs;
use crate::error::BoxResult;
use crate::filters::blocklist_host_resolver;
use crate::http;

/** @brief 컨트롤 플레인 주소와 토큰을 정한다. */
fn resolve_ctl(ctl: &CtlArgs) -> BoxResult<(String, String)> {
    if let Some(p) = &ctl.config {
        let cfg = Config::load_or_default(Some(p))?;
        let addr = cfg.control_listen.ok_or_else(|| {
            crate::anyhow!("The configuration file has no control_listen setting")
        })?;
        Ok((base_url(addr), cfg.control_token.as_str().to_owned()))
    } else {
        let url = ctl
            .url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8553".to_string());
        Ok((url, ctl.token.clone().unwrap_or_default()))
    }
}

/** @brief 컨트롤 플레인 기본 주소. */
fn base_url(addr: SocketAddr) -> String {
    let ip = addr.ip();
    if ip.is_unspecified() {
        match ip {
            IpAddr::V4(_) => format!("http://127.0.0.1:{}", addr.port()),
            IpAddr::V6(_) => format!("http://[::1]:{}", addr.port()),
        }
    } else if addr.is_ipv6() {
        format!("http://[{}]:{}", ip, addr.port())
    } else {
        format!("http://{addr}")
    }
}

/**
 * @brief 관리 API 응답이 성공일 때만 본문을 돌려준다.
 *
 * @details 요청이 거절되어도 HTTP 응답 자체는 도착하므로, 상태 코드를 보지 않으면 인증
 *          실패나 리더가 아닌 노드의 거절을 성공으로 출력하게 된다. 서버가 보낸 error
 *          문구가 있으면 그 문구를 오류로 쓴다.
 */
fn ctl_body(resp: http::Resp) -> BoxResult<String> {
    let status = resp.status;
    let body = resp.into_string()?;
    if (200..300).contains(&status) {
        return Ok(body);
    }
    let message = onetdns_core::json::parse(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_else(|| body.trim().to_owned());
    if message.is_empty() {
        crate::bail!("The management API rejected the request (HTTP {status})");
    }
    crate::bail!("The management API rejected the request (HTTP {status}): {message}")
}

/** @brief 토큰을 인증 헤더 값으로. */
fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/** @brief 지표를 보여 준다. */
pub(crate) fn ctl_stats(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::get(&format!("{base}/v1/stats"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("Management API request failed: {e}"))?;
    let body = ctl_body(resp)?;

    println!("{body}");
    Ok(())
}

/** @brief 많이 물은 이름들을 보여 준다. */
pub(crate) fn ctl_top(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::get(&format!("{base}/v1/top"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("Management API request failed: {e}"))?;
    let body = ctl_body(resp)?;
    let v = onetdns_core::json::parse(&body)
        .map_err(|e| crate::anyhow!("Could not parse the management API response: {e}"))?;
    let show = |label: &str, key: &str| {
        println!("[{label}]");
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            for item in arr.iter().take(10) {
                if let Some(pair) = item.as_array() {
                    let count = pair.get(1).and_then(|c| c.as_u64()).unwrap_or(0);
                    let name = pair.first().and_then(|n| n.as_str()).unwrap_or("");
                    println!("  {count:>6}  {name}");
                }
            }
        }
    };
    show("Top domains", "domains");
    show("Top blocked domains", "blocked");
    show("Top clients", "clients");
    Ok(())
}

/** @brief 설정을 다시 읽게 한다. */
pub(crate) fn ctl_reload(ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let resp = http::post(&format!("{base}/v1/reload"))
        .header("Authorization", &bearer(&token))
        .resolver(resolver)
        .call()
        .map_err(|e| crate::anyhow!("Management API request failed: {e}"))?;
    let body = ctl_body(resp)?;
    println!("Configuration reloaded: {body}");
    Ok(())
}

/** @brief 차단 또는 허용 목록에 이름을 넣는다. */
pub(crate) fn ctl_add(kind: &str, domain: &str, ctl: &CtlArgs) -> BoxResult<()> {
    let (base, token) = resolve_ctl(ctl)?;
    let resolver = blocklist_host_resolver(&Config::default());
    let json = format!("{{\"domain\":{}}}", onetdns_core::json::escape(domain));
    let resp = http::post(&format!("{base}/v1/{kind}"))
        .header("Authorization", &bearer(&token))
        .header("Content-Type", "application/json")
        .resolver(resolver)
        .body_string(&json)
        .call()
        .map_err(|e| crate::anyhow!("Management API request failed: {e}"))?;
    let body = ctl_body(resp)?;
    println!("Added {domain} to the {kind} rules: {body}");
    Ok(())
}

/** @brief 목록 개수. */
pub(crate) fn counts((block, allow): (usize, usize)) -> onetdns_control::ListCounts {
    onetdns_control::ListCounts { block, allow }
}
