//! The ctl command, which calls a running server's management API.

use std::net::{IpAddr, SocketAddr};

use onetdns_config::Config;

use crate::cli::CtlArgs;
use crate::error::BoxResult;
use crate::filters::blocklist_host_resolver;
use crate::http;

/// Without `--config` or `--url`, reads the config a server started without `--config` uses.
fn resolve_ctl(ctl: &CtlArgs) -> BoxResult<(String, String)> {
    let config = match (&ctl.config, &ctl.url) {
        (Some(path), _) => Some(path.clone()),
        // The token in this machine's config must not go to an address the user typed.
        (None, Some(_)) => None,
        (None, None) => crate::existing_auto_config(),
    };
    let Some(path) = config else {
        let url = ctl
            .url
            .clone()
            .unwrap_or_else(|| base_url(crate::DEFAULT_CONTROL_LISTEN));
        return Ok((url, ctl.token.clone().unwrap_or_default()));
    };
    let cfg = Config::load_or_default(Some(&path))?;
    let addr = cfg.control_listen.unwrap_or(crate::DEFAULT_CONTROL_LISTEN);
    let token = ctl
        .token
        .clone()
        .unwrap_or_else(|| cfg.control_token.as_str().to_owned());
    Ok((base_url(addr), token))
}

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

/// A rejected request still gets an HTTP response, so without checking the status an auth failure
/// or a non-leader's refusal would print as success. The server's error text, when present, becomes
/// the error.
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

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

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

pub(crate) fn counts((block, allow): (usize, usize)) -> onetdns_control::ListCounts {
    onetdns_control::ListCounts { block, allow }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_file(body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-ctl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("OnetDNS.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn a_config_without_control_listen_reaches_the_default_dashboard() {
        let path = config_file("control_token = \"config-token\"\n");
        let ctl = CtlArgs {
            config: Some(path.clone()),
            ..CtlArgs::default()
        };
        let (url, token) = resolve_ctl(&ctl).unwrap();
        assert_eq!(url, "http://127.0.0.1:8553");
        assert_eq!(token, "config-token");

        let typed = CtlArgs {
            config: Some(path.clone()),
            token: Some("typed-token".into()),
            ..CtlArgs::default()
        };
        assert_eq!(resolve_ctl(&typed).unwrap().1, "typed-token");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_typed_address_gets_only_a_typed_token() {
        let ctl = CtlArgs {
            url: Some("https://dns.example:8554".into()),
            ..CtlArgs::default()
        };
        assert_eq!(
            resolve_ctl(&ctl).unwrap(),
            ("https://dns.example:8554".to_string(), String::new())
        );
    }
}
