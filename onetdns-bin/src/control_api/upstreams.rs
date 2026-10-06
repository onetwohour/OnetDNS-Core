/*!
 * @brief 관리 API: 업스트림 서버.
 */

use super::*;
use crate::config_edit::{rewrite_config_string_array, upstream_key, upstream_values};
use crate::native_config::stable_resource_id;

impl ControlDeps {
    /** @brief 업스트림 하나에 시험 질의를 보내 닿는지 본다. */
    pub(super) fn upstream_test(&self, body: &str) -> Result<String, String> {
        let bootstrap = self.runtime_cfg.load().bootstrap.clone();
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let addr_s = j
            .get("addr")
            .and_then(|v| v.as_str())
            .ok_or("`addr` is required".to_string())?
            .trim()
            .to_string();
        let mut candidates = if addr_s.contains("://") {
            upstream::native_upstreams(&[], &[addr_s.clone()], &bootstrap)
        } else {
            let ip: std::net::IpAddr = addr_s
                .parse()
                .map_err(|_| format!("Invalid IP address: {addr_s}"))?;
            vec![onetdns_forward::Upstream::udp(std::net::SocketAddr::new(
                ip, 53,
            ))]
        };
        let Some(up) = candidates.pop() else {
            return Err(format!("Invalid upstream DNS server address: {addr_s}"));
        };
        let fwd = onetdns_forward::Forwarder::with_upstreams(vec![up], Duration::from_secs(3));
        let probe = onetdns_proto::Message::query(
            0x4f54,
            onetdns_proto::Name::from_str("example.com")
                .map_err(|_| "Could not parse the built-in probe domain name".to_string())?,
            onetdns_proto::RecordType::A,
        );
        let start = std::time::Instant::now();
        match fwd.resolve(&probe) {
            Ok(ans) if !matches!(ans.header.rcode, 0 | 3) => Ok(format!(
                "{{\"ok\":false,\"error\":{},\"rcode\":{},\"addr\":{}}}",
                onetdns_core::json::escape(&format!(
                    "Upstream DNS server answered {}",
                    native::rcode_str(onetdns_proto::ResponseCode(ans.header.rcode))
                )),
                ans.header.rcode,
                onetdns_core::json::escape(&addr_s)
            )),
            Ok(ans) => Ok(format!(
                "{{\"ok\":true,\"latency_ms\":{},\"rcode\":{},\"answers\":{},\"addr\":{}}}",
                start.elapsed().as_millis(),
                ans.header.rcode,
                ans.answers.len(),
                onetdns_core::json::escape(&addr_s)
            )),
            Err(error) => Ok(format!(
                "{{\"ok\":false,\"error\":{},\"addr\":{}}}",
                onetdns_core::json::escape(&error.to_string()),
                onetdns_core::json::escape(&addr_s)
            )),
        }
    }

    /** @brief 업스트림 목록과 서버마다의 성적. */
    pub(super) fn upstreams_list(&self) -> String {
        let snapshot = self.runtime_cfg.load();
        let mut ups: Vec<String> = snapshot.upstreams.iter().map(|u| u.to_string()).collect();
        ups.extend(snapshot.upstream_urls.clone());

        let stats = self
            .forward_stats
            .lock_recover()
            .as_ref()
            .map(|handle| handle.snapshot())
            .filter(|s| s.len() == ups.len());
        let items: Vec<String> = ups
            .iter()
            .enumerate()
            .map(|(i, addr)| match stats.as_ref().map(|s| &s[i]) {
                Some(s) => format!(
                    "{{\"id\":{},\"addr\":{},\"queries\":{},\"ok\":{},\"fail\":{},\"ewma_ms\":{:.1}}}",
                    onetdns_core::json::escape(&stable_resource_id("upstream", addr)),
                    onetdns_core::json::escape(addr),
                    s.queries,
                    s.ok,
                    s.fail,
                    s.ewma_ms
                ),
                None => format!(
                    "{{\"id\":{},\"addr\":{}}}",
                    onetdns_core::json::escape(&stable_resource_id("upstream", addr)),
                    onetdns_core::json::escape(addr)
                ),
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /** @brief 업스트림을 넣는다. */
    pub(super) fn upstream_add(&self, entry: &str) -> Result<String, String> {
        let entry = entry.trim().to_string();
        if entry.is_empty() {
            return Err("Upstream DNS server address to add is empty".to_string());
        }
        let key = upstream_key(&entry);
        let result = self.edit_config(|text| {
            let cfg = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            let mut vals = upstream_values(&cfg, key);
            if vals.iter().any(|value| value == &entry) {
                return Err(format!("Upstream DNS server already registered: {entry}"));
            }
            vals.push(entry.clone());
            /*
             * 한쪽 목록만 파일에 적히면 적히지 않은 다른 쪽 기본값이 물러난다. 지금 쓰던 다른 쪽
             * 목록을 텍스트로 남기지 않으면 화면 목록에서 조용히 사라진다.
             */
            let other = if key == "upstream_urls" {
                "upstreams"
            } else {
                "upstream_urls"
            };
            let others = upstream_values(&cfg, other);
            let text = if others.is_empty() {
                text.to_string()
            } else {
                rewrite_config_string_array(text, other, &others)?
            };
            rewrite_config_string_array(&text, key, &vals)
        })?;
        onetdns_core::info!(
            event = "upstream.added",
            address = %entry,
            config_key = key,
            apply_mode = result.mode.as_str(),
            "Added an upstream DNS server"
        );
        Ok(format!(
            "{{\"added\":{},\"id\":{},\"key\":{},{} }}",
            onetdns_core::json::escape(&entry),
            onetdns_core::json::escape(&stable_resource_id("upstream", &entry)),
            onetdns_core::json::escape(key),
            result.json_fields()
        ))
    }

    /** @brief 업스트림을 뺀다. */
    pub(super) fn upstream_remove(&self, entry: &str) -> Result<String, String> {
        let entry = entry.trim().to_string();
        let key = upstream_key(&entry);
        let result = self.edit_config(|text| {
            let cfg = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            let mut vals = upstream_values(&cfg, key);
            let before = vals.len();
            vals.retain(|value| value != &entry);
            if vals.len() == before {
                return Err(format!("Upstream DNS server not found: {entry}"));
            }
            rewrite_config_string_array(text, key, &vals)
        })?;
        onetdns_core::info!(
            event = "upstream.removed",
            address = %entry,
            config_key = key,
            apply_mode = result.mode.as_str(),
            "Removed an upstream DNS server"
        );
        Ok(format!(
            "{{\"removed\":{},\"id\":{},\"key\":{},{} }}",
            onetdns_core::json::escape(&entry),
            onetdns_core::json::escape(&stable_resource_id("upstream", &entry)),
            onetdns_core::json::escape(key),
            result.json_fields()
        ))
    }
}
