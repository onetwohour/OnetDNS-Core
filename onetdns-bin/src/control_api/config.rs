/*!
 * @brief 관리 API: 설정 파일을 읽고 고치고 반영한다.
 */

use super::*;
use crate::config_apply::{
    conditional_hot_reload_keys, config_changed_keys, config_status_json, desired_config_json,
    normalize_config_for_comparison, service_restart_keys,
};
use crate::config_edit::{
    json_to_toml_literal, materialize_mode_acl_patch, merge_config_snippet, remove_config_key,
    rewrite_config_kv, validate_config_patch_values,
};

impl ControlDeps {
    /** @brief 설정 조각을 지금 원문에 합쳐 검사한다. 적용하지는 않는다. */
    pub(super) fn config_validate(&self, toml: &str) -> Result<(), String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let merged = merge_config_snippet(&current, toml)?;
        let cfg = onetdns_config::Config::from_toml_str(&merged).map_err(|e| e.to_string())?;
        runtime_preflight(&cfg)
    }

    /** @brief 설정 조각을 합치면 무엇이 바뀌고 어떻게 반영되는지. */
    pub(super) fn config_diff(&self, proposed: &str) -> Result<String, String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let proposed = merge_config_snippet(&current, proposed)?;
        change_report(&self.runtime_cfg.load(), &current, &proposed)
    }

    /** @brief 항목들을 고치면 무엇이 바뀌고 어떻게 반영되는지. */
    pub(super) fn config_set_diff(&self, body: &str) -> Result<String, String> {
        let startup = self.cfg_text.clone().unwrap_or_default();
        let pairs = config_patch(body)?;
        let current = current_config_text(self.config_path.as_deref(), &startup)?;
        let proposed = apply_config_patch(&current, &pairs)?;
        change_report(&self.runtime_cfg.load(), &current, &proposed)
    }

    /** @brief 설정 조각을 합쳐 반영한다. */
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

    /** @brief 항목 몇 개를 고쳐 반영한다. */
    pub(super) fn config_set(&self, body: &str) -> Result<String, String> {
        let pairs = config_patch(body)?;
        let result = self.edit_config(|text| apply_config_patch(text, &pairs))?;
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

    /** @brief 설정 명세와 재시작 없이 바뀌는 항목들. */
    pub(super) fn config_schema(&self) -> String {
        let keys = onetdns_config::known_keys();
        let list: Vec<String> = keys.iter().map(|k| onetdns_core::json::escape(k)).collect();
        /*
         * 재시작 여부는 적용할 때와 같은 규칙에서 낸다. 따로 정하면 화면이 실제로
         * 재시작하는 항목을 무중단이라고 적는다.
         */
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

    /** @brief 직전 설정으로 되돌린다. */
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

    /** @brief 파일에 적힌 설정. */
    pub(super) fn config_desired(&self) -> String {
        desired_config_json(self.config_path.as_deref(), &self.runtime_cfg.load())
    }

    /** @brief 지금 적용 중인 설정. */
    pub(super) fn config_effective(&self) -> String {
        self.runtime_cfg.load().effective_json()
    }

    /** @brief 파일과 적용 중인 설정이 어긋나는지. */
    pub(super) fn config_status(&self) -> String {
        config_status_json(self.config_path.as_deref(), &self.runtime_cfg.load())
    }

    /** @brief 파일에 저장된 설정을 반영한다. 항목이 그대로면 인증서 파일만 다시 읽는다. */
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
            /*
             * 설정 항목이 그대로여도 그 항목이 가리키는 인증서 파일은 갱신되었을 수 있다. 여기서
             * 보지 않으면 갱신 뒤 다시 시작할 때까지 만료된 인증서를 계속 내민다.
             */
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

/** @brief 지금 설정 파일의 원문. 파일 없이 돌면 시작할 때 읽은 원문이다. */
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

/**
 * @brief /v1/config/set 본문을 바꿀 항목 목록으로 읽는다.
 * @details 적용과 미리보기가 이 함수 하나로 읽어야 미리보기가 적용과 같은 항목을 판정한다.
 */
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

/**
 * @brief 설정 원문에 항목들을 적는다.
 * @details null 은 항목을 지우라는 뜻이다. 값을 비우는 것과 달리 기본값으로 돌아가고, 선택 항목은
 *          꺼진다.
 */
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

/**
 * @brief 설정 원문을 current 에서 proposed 로 바꾸면 무엇이 바뀌고 어떻게 반영되는지 JSON으로.
 * @details 반영하는 경로와 같은 입력으로 같은 판정을 내야 미리보기가 반영 결과와 맞는다. 반영
 *          경로는 파일 원문이 그대로면 아무것도 반영하지 않고, 원문이 바뀌면 실행 중 설정과
 *          비교용으로 맞춘 새 설정 전체를 비교해 service_restart_keys 로 판정한다. 그래서 파일에만
 *          적혀 있고 아직 반영하지 않은 항목은 원문이 함께 바뀔 때만 이번 변경에 들어간다.
 */
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
