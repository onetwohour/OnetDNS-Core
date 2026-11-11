//! Management API: client groups.

use super::*;
use crate::config_edit::{client_block_from_json, remove_client_block, update_client_disable};
use onetdns_control::FilterApply;

impl ControlDeps {
    pub(super) fn clients_list(&self) -> String {
        let snapshot = self.runtime_cfg.load();
        let items: Vec<String> = snapshot
            .clients
            .iter()
            .map(|c| {
                let ids: Vec<String> = c.ids.iter().map(|n| n.to_string()).collect();
                format!(
                    "{{\"name\":{},\"nets\":{},\"client_ids\":{},\"tags\":{},\"block_rules\":{},\"disable_filtering\":{}}}",
                    onetdns_core::json::escape(&c.name),
                    json_str_array(&ids),
                    json_str_array(&c.client_ids),
                    json_str_array(&c.tags),
                    c.block.len(),
                    c.disable_filtering
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    pub(super) fn client_add(&self, body: &str, apply: FilterApply) -> Result<String, String> {
        let (block, name) = client_block_from_json(body)?;
        let result = self.edit_config_with(apply, |text| {
            let cfg = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            if cfg.clients.iter().any(|c| c.name == name) {
                return Err(format!("Client already exists: {name}"));
            }
            let mut t = text.to_string();
            if !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&block);
            Ok(t)
        })?;
        Ok(format!(
            "{{\"added\":true,\"name\":{},{} }}",
            onetdns_core::json::escape(&name),
            result.json_fields()
        ))
    }

    pub(super) fn client_remove(&self, name: &str, apply: FilterApply) -> Result<String, String> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("`name` is required".to_string());
        }
        let result = self.edit_config_with(apply, |text| {
            remove_client_block(text, &name).ok_or_else(|| format!("Client not found: {name}"))
        })?;
        Ok(format!(
            "{{\"removed\":true,\"name\":{},{} }}",
            onetdns_core::json::escape(&name),
            result.json_fields()
        ))
    }

    pub(super) fn client_update(&self, body: &str, apply: FilterApply) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let name = j
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let disable = j
            .get("disable_filtering")
            .and_then(|v| v.as_bool())
            .ok_or("`disable_filtering` is required".to_string())?;
        if name.is_empty() {
            return Err("`name` is required".to_string());
        }
        let result =
            self.edit_config_with(apply, |text| update_client_disable(text, &name, disable))?;
        Ok(format!(
            "{{\"updated\":true,\"name\":{},\"disable_filtering\":{disable},{} }}",
            onetdns_core::json::escape(&name),
            result.json_fields()
        ))
    }
}
