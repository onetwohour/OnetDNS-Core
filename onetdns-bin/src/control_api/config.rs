//! Management API: reads, edits, and applies the config file.

use super::*;
use crate::config_apply::{
    conditional_hot_reload_keys, config_changed_keys, config_status_json, desired_config_json,
    normalize_config_for_comparison, service_restart_keys,
};
use onetdns_control::FilterApply;

use crate::config_edit::{
    json_to_toml_literal, materialize_mode_acl_patch, merge_config_snippet, remove_config_key,
    rewrite_config_kv, validate_config_patch_values,
};

impl ControlDeps {
    /// Checks a snippet merged into the current text without applying it.
    pub(super) fn config_validate(&self, toml: &str) -> Result<(), String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let merged = merge_config_snippet(&current, toml)?;
        let cfg = onetdns_config::Config::from_toml_str(&merged).map_err(|e| e.to_string())?;
        runtime_preflight(&cfg)
    }

    pub(super) fn config_diff(&self, proposed: &str) -> Result<String, String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let proposed = merge_config_snippet(&current, proposed)?;
        change_report(&self.runtime_cfg.load(), &current, &proposed)
    }

    pub(super) fn config_set_diff(&self, body: &str) -> Result<String, String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let pairs = config_patch(body)?;
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let proposed = apply_config_patch(&current, &pairs)?;
        change_report(&self.runtime_cfg.load(), &current, &proposed)
    }

    pub(super) fn config_apply(&self, toml: &str) -> Result<String, String> {
        let result = self.edit_config(|text| merge_config_snippet(text, toml))?;
        onetdns_core::info!(
            event = "config.patch_applied",
            mode = result.mode.as_str(),
            changed = result.changed.len(),
            keys = ?result.changed,
            "Applied configuration changes"
        );
        Ok(format!("{{\"applied\":true,{}}}", result.json_fields()))
    }

    pub(super) fn config_set(&self, body: &str, apply: FilterApply) -> Result<String, String> {
        let pairs = config_patch(body)?;
        let result = self.edit_config_with(apply, |text| apply_config_patch(text, &pairs))?;
        let keys: Vec<String> = pairs
            .iter()
            .map(|(k, _)| onetdns_core::json::escape(k))
            .collect();
        let changed_keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        onetdns_core::info!(
            event = "config.keys_applied",
            count = pairs.len(),
            mode = result.mode.as_str(),
            keys = ?changed_keys,
            "Applied configuration setting"
        );
        Ok(format!(
            "{{\"applied\":true,{},\"keys\":[{}]}}",
            result.json_fields(),
            keys.join(",")
        ))
    }

    pub(super) fn config_schema(&self) -> String {
        let keys = onetdns_config::known_keys();
        let list: Vec<String> = keys.iter().map(|k| onetdns_core::json::escape(k)).collect();
        // Uses the rule applying uses, or the dashboard would call a restarting key hot.
        let conditional_keys = conditional_hot_reload_keys(&self.runtime_cfg.load());
        let hot: Vec<String> = keys
            .iter()
            .copied()
            .filter(|key| config_keys::is_hot(key) && !conditional_keys.contains(key))
            .map(onetdns_core::json::escape)
            .collect();
        let conditional: Vec<String> = conditional_keys
            .iter()
            .map(|key| onetdns_core::json::escape(key))
            .collect();
        format!(
            "{{\"count\":{},\"keys\":[{}],\"hot_reload_keys\":[{}],\"conditional_hot_reload_keys\":[{}],\"fields\":{},\"note\":\"Settings in hot_reload_keys apply without restarting the DNS service. Settings in conditional_hot_reload_keys can restart it under the current configuration; for example, while a client has dedicated upstream DNS servers, a change that rebuilds the resolver chain restarts the service. /v1/config/diff and /v1/config/set/diff report what a specific change does.\"}}",
            keys.len(),
            list.join(","),
            hot.join(","),
            conditional.join(","),
            onetdns_config::schema::schema_json()
        )
    }

    pub(super) fn config_rollback(&self) -> Result<String, String> {
        let snapshot = self.config_prev.lock_recover().clone();
        let Some(text) = snapshot else {
            return Err("There is no previous configuration to restore".to_string());
        };
        let result = self.edit_config(|_| Ok(text.as_str().to_owned()))?;
        onetdns_core::info!(
            event = "config.rollback_applied",
            mode = result.mode.as_str(),
            keys = ?result.changed,
            "Restored the previous configuration"
        );
        Ok(format!("{{\"rolled_back\":true,{}}}", result.json_fields()))
    }

    pub(super) fn config_desired(&self) -> String {
        desired_config_json(self.config_path.as_deref(), &self.runtime_cfg.load())
    }

    pub(super) fn config_effective(&self) -> String {
        self.runtime_cfg.load().effective_json()
    }

    pub(super) fn config_status(&self) -> String {
        config_status_json(self.config_path.as_deref(), &self.runtime_cfg.load())
    }

    /// Applies the saved file. With no key changed, only re-reads certificate files.
    pub(super) fn config_reload(&self) -> Result<String, String> {
        let path = self.config_path.as_deref().ok_or_else(|| {
            "There is no configuration file path, so the on-disk configuration cannot be applied".to_string()
        })?;
        let text = onetdns_core::SecretString::from(
            Config::read_text(path).map_err(|error| error.to_string())?,
        );
        let desired = Config::from_toml_str(&text).map_err(|error| error.to_string())?;
        let current = self.runtime_cfg.load();
        let previous_text = self.applied_config_text.lock_recover().clone();
        let changed = config_changed_keys(&current, &desired);
        if changed.is_empty() {
            if previous_text.as_deref() != Some(text.as_str()) {
                *self.config_prev.lock_recover() = previous_text;
                *self.applied_config_text.lock_recover() = Some(text);
            }
            // A renewed certificate leaves the keys unchanged but must still be picked up.
            if let Some(slots) = self.tls_slot_handle.lock_recover().clone() {
                let swapped = slots.refresh_certificate_files(&current)?;
                if !swapped.is_empty() {
                    onetdns_core::info!(
                        event = "tls.certificate_reloaded",
                        changed = %swapped.join(","),
                        "Replaced the TLS certificate without closing listening addresses"
                    );
                    let names: Vec<String> = swapped
                        .iter()
                        .map(|key| onetdns_core::json::escape(key))
                        .collect();
                    return Ok(format!(
                        "{{\"accepted\":true,\"mode\":\"hot_reload\",\"restart_required\":false,\"changed\":[{}]}}",
                        names.join(",")
                    ));
                }
            }
            return Ok("{\"accepted\":false,\"mode\":\"no_change\",\"restart_required\":false,\"changed\":[]}".to_string());
        }

        let (hot_applied, effective_changed) = (self.hot_config_apply)(&desired, &changed)?;
        let changed_json: Vec<String> = effective_changed
            .iter()
            .map(|key| onetdns_core::json::escape(key))
            .collect();
        if hot_applied {
            *self.config_prev.lock_recover() = previous_text;
            *self.applied_config_text.lock_recover() = Some(text);
            onetdns_core::info!(
                event = "config.disk_hot_applied",
                path = %path.display(),
                changed = effective_changed.len(),
                "Applied the saved configuration file to the running service"
            );
            return Ok(format!(
                "{{\"accepted\":true,\"mode\":\"hot_reload\",\"restart_required\":false,\"changed\":[{}]}}",
                changed_json.join(",")
            ));
        }
        *self.config_prev.lock_recover() = previous_text;
        self.reload
            .store(true, std::sync::atomic::Ordering::Release);
        onetdns_core::info!(
            event = "config.disk_restart_requested",
            path = %path.display(),
            changed = effective_changed.len(),
            "Restarting the DNS service to apply the saved configuration file"
        );
        Ok(format!(
            "{{\"accepted\":true,\"mode\":\"service_restart\",\"restart_required\":true,\"changed\":[{}]}}",
            changed_json.join(",")
        ))
    }
}

/// Without a config file, the text read at startup.
fn current_config_text(
    path: Option<&std::path::Path>,
    startup: &onetdns_core::SecretString,
) -> Result<onetdns_core::SecretString, String> {
    match path {
        Some(p) => Config::read_text(p)
            .map(onetdns_core::SecretString::from)
            .map_err(|e| {
                format!(
                    "Could not read the current configuration file ({}): {e}",
                    p.display()
                )
            }),
        None => Ok(startup.clone()),
    }
}

/// Shared by apply and preview, so a preview judges the same keys.
fn config_patch(body: &str) -> Result<Vec<(String, onetdns_core::json::Json)>, String> {
    let onetdns_core::json::Json::Obj(mut pairs) = onetdns_core::json::parse(body)
        .map_err(|_| "Could not parse the JSON request body".to_string())?
    else {
        return Err("The request body must be a top-level object of keys and values".to_string());
    };
    materialize_mode_acl_patch(&mut pairs)?;
    validate_config_patch_values(&pairs)?;
    if pairs.is_empty() {
        return Err("No settings to change".to_string());
    }
    Ok(pairs)
}

/// A null value removes the key, returning it to its default.
fn apply_config_patch(
    text: &str,
    pairs: &[(String, onetdns_core::json::Json)],
) -> Result<String, String> {
    let mut out = text.to_string();
    for (key, value) in pairs {
        out = match value {
            onetdns_core::json::Json::Null => remove_config_key(&out, key)?,
            value => rewrite_config_kv(&out, key, &json_to_toml_literal(value)?)?,
        };
    }
    Ok(out)
}

/// Judges a change as applying does: unchanged text applies nothing, and changed text compares
/// the whole new config with the running one.
fn change_report(active: &Config, current: &str, proposed: &str) -> Result<String, String> {
    let (added, removed, changed) =
        onetdns_config::Config::diff_toml(current, proposed).map_err(|e| e.to_string())?;
    let proposed_cfg = onetdns_config::Config::from_toml_str(proposed)
        .map_err(|e| format!("Could not parse the settings to change: {e}"))?;
    let (effective, restart) = if added.is_empty() && removed.is_empty() && changed.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let proposed_cfg = normalize_config_for_comparison(active, &proposed_cfg);
        let effective = config_changed_keys(active, &proposed_cfg);
        let restart = service_restart_keys(active, &proposed_cfg, &effective);
        (effective, restart)
    };
    let hot: Vec<String> = effective
        .iter()
        .filter(|key| !restart.contains(key))
        .cloned()
        .collect();
    let arr = |v: &[String]| {
        v.iter()
            .map(|k| onetdns_core::json::escape(k))
            .collect::<Vec<_>>()
            .join(",")
    };
    Ok(format!(
        "{{\"added\":[{}],\"removed\":[{}],\"changed\":[{}],\"effective_changed\":[{}],\"hot_reload\":[{}],\"service_restart\":[{}],\"restart_required\":{}}}",
        arr(&added),
        arr(&removed),
        arr(&changed),
        arr(&effective),
        arr(&hot),
        arr(&restart),
        !restart.is_empty()
    ))
}
