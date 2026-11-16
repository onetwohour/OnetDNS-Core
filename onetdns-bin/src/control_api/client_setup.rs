//! Management API: DNS stamps and Apple configuration profiles for clients.

use super::*;
use crate::client_setup::{parse_address, Endpoints, Served, Transport};

impl ControlDeps {
    fn endpoints(&self, request: &onetdns_core::json::Json) -> Result<Endpoints, String> {
        let text = |key: &str| {
            request
                .get(key)
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let address = text("address").map(parse_address).transpose()?;
        let cfg = self.runtime_cfg.load();
        let chain = self
            .tls_slot_handle
            .lock_recover()
            .as_ref()
            .map(|slots| slots.served_chain())
            .unwrap_or_default();
        let kept = || {
            let file = crate::tls_material::self_signed_file(self.config_path.as_deref());
            chain
                .first()
                .is_some_and(|leaf| crate::tls_material::self_signed_is_kept(file.as_deref(), leaf))
        };
        let served = Served {
            listeners: self.listener_reg.lock_recover().clone(),
            chain_changes_on_restart: cfg.tls_self_signed_host.is_some() && !kept(),
            chain,
            dnscrypt: self.dnscrypt_identity.lock_recover().clone(),
        };
        Endpoints::new(
            &cfg,
            served,
            address,
            text("hostname"),
            &onetdns_tls::TrustStore::system(),
            unix_now() as i64,
        )
    }

    pub(super) fn client_stamps(&self, body: &str) -> Result<String, String> {
        let request = parse_body(body)?;
        let endpoints = self.endpoints(&request)?;
        let esc = onetdns_core::json::escape;
        let stamps: Vec<String> = endpoints
            .stamps()?
            .into_iter()
            .map(|(transport, port, address, stamp)| {
                format!(
                    "{{\"protocol\":\"{}\",\"port\":{port},\"address\":{},\"stamp\":{}}}",
                    transport.name(),
                    address.map_or("null".to_string(), |ip| esc(&ip.to_string())),
                    esc(&stamp)
                )
            })
            .collect();
        let certificate = match endpoints.certificate_status() {
            Some((trusted, changes_on_restart)) => {
                format!("{{\"trusted\":{trusted},\"changes_on_restart\":{changes_on_restart}}}")
            }
            None => "null".to_string(),
        };
        Ok(format!(
            "{{\"address\":{},\"hostname\":{},\"certificate\":{certificate},\"stamps\":[{}]}}",
            endpoints
                .address()
                .map_or("null".to_string(), |ip| esc(&ip.to_string())),
            endpoints.hostname().map_or("null".to_string(), esc),
            stamps.join(",")
        ))
    }

    pub(super) fn client_apple_profile(&self, body: &str) -> Result<String, String> {
        let request = parse_body(body)?;
        let protocol = request
            .get("protocol")
            .and_then(|value| value.as_str())
            .ok_or("`protocol` is required")?;
        let transport = Transport::parse(protocol)
            .filter(|transport| matches!(transport, Transport::Doh | Transport::Dot))
            .ok_or_else(|| format!("`protocol` must be doh or dot: {protocol}"))?;
        let ssids = match request.get("ssids") {
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .ok_or("`ssids` must be an array of strings")?
                .iter()
                .map(|ssid| ssid.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or("`ssids` must be an array of strings")?,
        };
        self.endpoints(&request)?.apple_profile(transport, &ssids)
    }
}

fn parse_body(body: &str) -> Result<onetdns_core::json::Json, String> {
    if body.trim().is_empty() {
        return Ok(onetdns_core::json::Json::Obj(Vec::new()));
    }
    onetdns_core::json::parse(body)
        .map_err(|error| format!("Could not parse the JSON request body: {error}"))
}
