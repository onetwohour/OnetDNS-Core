//! Management API: TLS certificates.

use super::*;
use crate::tls_material::{
    acme_issue, inspect_tls_material, tls_configure, AcmeFiles, AcmeRequest,
};

impl ControlDeps {
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

    /// Checks that the certificate and key match and that validity and the chain hold; trust and
    /// names are not checked.
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

    /// Reads the live config: values captured at startup would keep issuing with the old
    /// directory URL and domains after an ACME config change.
    pub(super) fn acme_issue(&self, body: &str) -> Result<String, String> {
        let request = AcmeRequest::parse(body, &self.runtime_cfg.load())?;
        if !request.recorded_in(&self.runtime_cfg.load()) {
            self.edit_config(|text| request.record(text))?;
        }
        let cfg = self.runtime_cfg.load();
        let files = AcmeFiles::of(&cfg, self.config_path.as_deref()).ok_or(
            "There is no configuration file to keep the certificate next to; set acme_cert_file and acme_key_file",
        )?;
        let (account, issued) = acme_issue(
            &request,
            &files,
            &cfg,
            self.blocklist_resolver.clone(),
            self.tls_slot_handle.lock_recover().clone(),
            self.shutdown.clone(),
        )?;
        if issued && files.needs_serving(&cfg) {
            self.edit_config(|text| files.serve(text)).map_err(|error| {
                format!(
                    "Saved the issued certificate to {}, but could not switch the listeners to it: {error}",
                    files.cert.display()
                )
            })?;
        }
        let file = |path: &std::path::Path| {
            if issued {
                onetdns_core::json::escape(&path.display().to_string())
            } else {
                "null".to_string()
            }
        };
        Ok(format!(
            "{{\"account\":{},\"issued\":{issued},\"cert_file\":{},\"key_file\":{}}}",
            onetdns_core::json::escape(&account),
            file(&files.cert),
            file(&files.key),
        ))
    }
}
