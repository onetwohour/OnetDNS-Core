/*!
 * @brief 관리 API: TLS 인증서.
 */

use super::*;
use crate::tls_material::{acme_issue_run, inspect_tls_material, tls_configure};

impl ControlDeps {
    /** @brief 지금 설정에 적힌 인증서와 암호화 수신 주소. */
    pub(super) fn tls_status(&self) -> String {
        let current = self.runtime_cfg.load();
        let (cert, key) = (&current.tls_cert, &current.tls_key);
        let listen_doh = current.listen_doh.len();
        let listen_dot = current.listen_dot.len();
        let configured = cert.is_some() && key.is_some();
        format!(
            "{{\"configured\":{},\"cert\":{},\"key\":{},\"doh_listeners\":{},\"dot_listeners\":{}}}",
            configured,
            cert.as_ref().map(|p| onetdns_core::json::escape(&p.display().to_string())).unwrap_or_else(|| "null".into()),
            key.as_ref().map(|p| onetdns_core::json::escape(&p.display().to_string())).unwrap_or_else(|| "null".into()),
            listen_doh, listen_dot
        )
    }

    /**
     * @brief 지금 인증서와 키가 맞물리고 기간과 체인이 유효한지 본다.
     * @details 신뢰와 이름은 보지 않는다.
     */
    pub(super) fn tls_validate(&self) -> Result<String, String> {
        let current = self.runtime_cfg.load();
        let (Some(cp), Some(kp)) = (&current.tls_cert, &current.tls_key) else {
            return Err("tls_cert and tls_key are not set".to_string());
        };
        let (certs, keyder) = onetdns_transport::load_pem(cp, kp)
            .map_err(|e| format!("Could not load the PEM data: {e}"))?;
        let chain_len = certs.len();
        let material = inspect_tls_material(&certs, &keyder)?;
        let leaf = material
            .parsed
            .first()
            .ok_or("Certificate chain is empty".to_string())?;
        let now = unix_now() as i64;
        let self_signed = material.self_signed;
        let all_times_valid = material.all_times_valid;
        let chain_links_valid = material.chain_links_valid;
        let chain_constraints_valid = material.chain_constraints_valid;
        let material_valid = all_times_valid && chain_links_valid && chain_constraints_valid;

        let trusted = false;
        let hostname_checked = false;
        let valid = false;
        let days_left = (leaf.not_after - now).div_euclid(86_400);
        let subject = leaf
            .subject_label()
            .or_else(|| leaf.san_dns.first().cloned())
            .unwrap_or_default();
        let issuer = leaf.issuer_label().unwrap_or_default();
        Ok(format!(
            "{{\"valid\":{valid},\"material_valid\":{material_valid},\"key_matches\":true,\"chain_links_valid\":{chain_links_valid},\"chain_constraints_valid\":{chain_constraints_valid},\"all_times_valid\":{all_times_valid},\"self_signed\":{self_signed},\"trusted\":{trusted},\"hostname_checked\":{hostname_checked},\"validation_scope\":\"material_only\",\"chain_len\":{chain_len},\"subject\":{},\"issuer\":{},\"sans\":{},\"not_before\":{},\"not_after\":{},\"days_left\":{days_left}}}",
            onetdns_core::json::escape(&subject),
            onetdns_core::json::escape(&issuer),
            json_str_array(&leaf.san_dns),
            leaf.not_before,
            leaf.not_after,
        ))
    }

    /** @brief 인증서와 키를 바꾼다. */
    pub(super) fn tls_configure(&self, body: &str) -> Result<String, String> {
        let current = self.runtime_cfg.load();
        tls_configure(
            body,
            &current.tls_cert,
            &current.tls_key,
            &self.config_path,
            &self.config_prev,
            &self.reload,
        )
    }

    /** @brief 보낸 인증서 체인이 폐기됐는지 확인한다. */
    pub(super) fn tls_revocation_check(&self, body: &str) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Could not parse the JSON request body: {e}"))?;
        let pem = j
            .get("certificate_chain")
            .and_then(|v| v.as_str())
            .ok_or("`certificate_chain` is required")?;
        revoke::check_pem_chain_json(
            pem,
            unix_now() as i64,
            Duration::from_secs(10),
            self.blocklist_resolver.clone(),
        )
    }

    /** @brief ACME 로 인증서를 발급받는다. */
    pub(super) fn acme_issue(&self, body: &str) -> Result<String, String> {
        /*
         * 실행 중 설정을 본다. 시작할 때 값을 가지고 있으면 ACME 설정을 바꿔도 이전 디렉터리
         * 주소와 이전 도메인으로 발급을 시도한다.
         */
        acme_issue_run(
            &self.runtime_cfg.load(),
            body,
            self.blocklist_resolver.clone(),
            self.tls_slot_handle.lock_recover().clone(),
        )
    }
}
