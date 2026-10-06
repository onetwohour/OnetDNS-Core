/*!
 * @brief 관리 API: 관리 토큰과 대시보드 계정.
 */

use super::*;
use crate::config_edit::{
    append_user_block, remove_token_by_id, rewrite_config_string_array, rewrite_user_password_hash,
    token_id, token_mask,
};

impl ControlDeps {
    /** @brief 관리 토큰 목록. 토큰 값은 가린다. */
    pub(super) fn tokens_list(&self) -> String {
        let c = self.runtime_cfg.load();
        let mut items: Vec<String> = Vec::new();
        let mut push = |tok: &str, role: &str| {
            items.push(format!(
                "{{\"id\":{},\"role\":{},\"masked\":{}}}",
                onetdns_core::json::escape(&token_id(tok)),
                onetdns_core::json::escape(role),
                onetdns_core::json::escape(&token_mask(tok))
            ));
        };
        for t in &c.control_admin_tokens {
            push(t, "admin");
        }
        for t in &c.control_readonly_tokens {
            push(t, "readonly");
        }
        format!("{{\"tokens\":[{}]}}", items.join(","))
    }

    /** @brief 관리 토큰을 만들어 설정에 적는다. */
    pub(super) fn token_add(&self, body: &str) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let readonly = j.get("role").and_then(|v| v.as_str()) != Some("admin");
        let bytes = onetdns_core::rng::try_random_array::<24>().map_err(|error| {
            format!("Could not get random bytes for the security token: {error}")
        })?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let key = if readonly {
            "control_readonly_tokens"
        } else {
            "control_admin_tokens"
        };
        let tok = token.clone();
        let result = self.edit_config(|text| {
            let cur = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            let mut v = if readonly {
                cur.control_readonly_tokens
            } else {
                cur.control_admin_tokens
            };
            v.push(tok.clone().into());
            rewrite_config_string_array(text, key, &v)
        })?;
        onetdns_core::info!(
            event = "control.temp_token_issued",
            role = key,
            "Issued a temporary management token"
        );
        Ok(format!(
            "{{\"created\":true,\"role\":{},\"token\":{},\"id\":{},{}}}",
            onetdns_core::json::escape(if readonly { "readonly" } else { "admin" }),
            onetdns_core::json::escape(&token),
            onetdns_core::json::escape(&token_id(&token)),
            result.json_fields()
        ))
    }

    /** @brief 관리 토큰을 지운다. */
    pub(super) fn token_delete(&self, body: &str) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let id = j
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("`id` is required".to_string())?
            .to_string();
        let mut removed = 0usize;
        let result = self.edit_config(|text| {
            let (out, count) = remove_token_by_id(text, &id)?;
            removed = count;
            Ok(out)
        })?;
        Ok(format!(
            "{{\"removed\":{removed},{}}}",
            result.json_fields()
        ))
    }

    /**
     * @brief 대시보드 계정의 암호 해시를 바꾼다.
     * @details 계정 변경은 DNS 처리와 무관하다. 무조건 재시작하는 경로를 쓰면 비밀번호를 한 번
     *          바꿀 때마다 이름 풀이가 끊긴다.
     */
    pub(super) fn password_change(&self, name: &str, hash: &str) -> Result<String, String> {
        let result = self.edit_config(|text| rewrite_user_password_hash(text, name, hash))?;
        Ok(format!(
            "{{\"changed\":true,\"mode\":\"{}\",\"restart_required\":{}}}",
            result.mode.as_str(),
            result.mode.restart_required()
        ))
    }

    /** @brief 첫 관리자 계정을 설정에 적고 설정 코드 파일을 지운다. */
    pub(super) fn user_create(&self, name: &str, hash: &str) -> Result<String, String> {
        let result = self.edit_config(|text| append_user_block(text, name, hash))?;
        if let Some(code_file) = crate::setup_code_path(self.config_path.as_deref()) {
            crate::remove_setup_code_file(&code_file);
        }
        Ok(format!(
            "{{\"created\":true,\"mode\":\"{}\",\"restart_required\":{}}}",
            result.mode.as_str(),
            result.mode.restart_required()
        ))
    }
}
