/*!
 * @brief 관리 API: 권한 영역과 그 기록.
 */

use super::*;
use crate::native_config::qtype_numbers;
use crate::zones::{
    apply_zone_mutation, apply_zone_mutation_locked, ensure_zone_file_unchanged, remove_zone,
    resolve_zone_name, zone_api_target, zone_record_json, zone_record_value,
    zone_records_without_closing_soa,
};

impl ControlDeps {
    /** @brief 권한 영역 목록과 영역마다의 기록. */
    pub(super) fn zones_list(&self) -> String {
        let store = self.zones.store.load();
        let items: Vec<String> = store
            .zones()
            .iter()
            .map(|z| {
                let records: Vec<String> = zone_records_without_closing_soa(z)
                    .iter()
                    .map(zone_record_json)
                    .collect();
                format!(
                    "{{\"origin\":{},\"serial\":{},\"records\":{},\"record_items\":[{}]}}",
                    onetdns_core::json::escape(&z.origin().to_ascii_lower()),
                    z.soa().serial,
                    z.axfr_records().len().saturating_sub(2),
                    records.join(",")
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /** @brief 이 영역의 기록들. */
    pub(super) fn zone_get(&self, origin: &str) -> Result<String, String> {
        let name = onetdns_proto::Name::from_str(origin)
            .map_err(|_| format!("Invalid DNS zone name: {origin}"))?;
        let store = self.zones.store.load();
        let zone = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(&name))
            .ok_or_else(|| format!("DNS zone not found: {origin}"))?;
        let records: Vec<String> = zone_records_without_closing_soa(zone)
            .iter()
            .map(zone_record_json)
            .collect();
        Ok(format!(
            "{{\"origin\":{},\"serial\":{},\"record_count\":{},\"records\":[{}]}}",
            onetdns_core::json::escape(&zone.origin().to_ascii_lower()),
            zone.soa().serial,
            records.len(),
            records.join(",")
        ))
    }

    /** @brief 이 영역을 보낸 내용으로 통째로 바꾼다. */
    pub(super) fn zone_put(&self, origin: &str, text: &str) -> Result<String, String> {
        let current_cfg = self.runtime_cfg.load();
        let target = zone_api_target(&current_cfg, &self.zones.store.load(), origin, "modify")?;
        let key = target.key.clone();
        let zone = onetdns_authority::parse_zone(text, origin)
            .map_err(|e| format!("Invalid DNS zone data: {e}"))?;

        let path = target.path.clone();
        let applied = apply_zone_mutation(
            &self.zones.store,
            zone,
            &self.zones.signers.load(),
            &self.zones.journal,
            path.as_deref(),
            &self.zones.notify,
            "zone save",
        )?;
        onetdns_core::info!(event = "authority.zone_saved", origin = %key, serial = applied.serial, persisted = applied.persisted, "Saved DNS zone");
        Ok(format!(
            "{{\"origin\":\"{}\",\"serial\":{},\"records\":{},\"persisted\":{},\"signed\":{},\"served\":{}}}",
            applied.origin,
            applied.serial,
            applied.records,
            applied.persisted,
            applied.signed,
            authority_sources_configured(&current_cfg)
        ))
    }

    /** @brief 이 영역을 지운다. 영역 파일도 지운다. */
    pub(super) fn zone_delete(&self, origin: &str) -> Result<String, String> {
        let current_cfg = self.runtime_cfg.load();
        let target = zone_api_target(&current_cfg, &self.zones.store.load(), origin, "delete")?;
        let key = target.key.clone();
        let name = onetdns_proto::Name::from_str(origin)
            .map_err(|_| format!("Invalid DNS zone name: {origin}"))?;
        let mut journals = self.zones.journal.lock().unwrap_or_else(|e| e.into_inner());
        let store = self.zones.store.load();
        let Some(zone) = store
            .zones()
            .iter()
            .find(|z| z.origin().eq_ignore_case(&name))
        else {
            return Err(format!("DNS zone not found: {origin}"));
        };
        let path = target.path.clone();
        let mut file_removed = false;
        if let Some(p) = path {
            ensure_zone_file_unchanged(&p, Some(zone))?;
            if p.exists() {
                std::fs::remove_file(&p).map_err(|e| {
                    format!("Could not delete the DNS zone file ({}): {e}", p.display())
                })?;
                file_removed = true;
            }
        }
        remove_zone(&self.zones.store, &mut journals, &name);
        onetdns_core::info!(event = "authority.zone_deleted", origin = %key, file_removed, "Deleted DNS zone");
        Ok(format!(
            "{{\"deleted\":true,\"file_removed\":{file_removed}}}"
        ))
    }

    /** @brief 이 영역에 기록 한 줄을 넣는다. */
    pub(super) fn zone_record_add(&self, origin: &str, body: &str) -> Result<String, String> {
        let current_cfg = self.runtime_cfg.load();
        let target = zone_api_target(&current_cfg, &self.zones.store.load(), origin, "modify")?;
        let name = onetdns_proto::Name::from_str(origin)
            .map_err(|_| format!("Invalid DNS zone name: {origin}"))?;
        let line = body.trim();
        if line.is_empty() {
            return Err("DNS record text is empty".to_string());
        }
        let mut journals = self.zones.journal.lock().unwrap_or_else(|e| e.into_inner());
        let current = {
            let store = self.zones.store.load();
            let zone = store
                .zones()
                .iter()
                .find(|z| z.origin().eq_ignore_case(&name))
                .ok_or_else(|| format!("DNS zone not found: {origin}"))?;
            zone.to_master_file()
        };
        let zone = onetdns_authority::parse_zone(&format!("{current}\n{line}\n"), origin)
            .map_err(|e| format!("Invalid DNS record: {e}"))?;
        let path = target.path.clone();
        let applied = apply_zone_mutation_locked(
            &self.zones.store,
            zone,
            &self.zones.signers.load(),
            &mut journals,
            path.as_deref(),
            &self.zones.notify,
            "record add",
        )?;
        onetdns_core::info!(event = "authority.record_added", origin = %applied.origin, serial = applied.serial, "Added DNS record");
        Ok(format!(
            "{{\"origin\":\"{}\",\"serial\":{},\"records\":{},\"persisted\":{},\"signed\":{}}}",
            applied.origin, applied.serial, applied.records, applied.persisted, applied.signed
        ))
    }

    /** @brief 이 영역에서 이름과 유형이 맞는 기록을 지운다. */
    pub(super) fn zone_record_delete(&self, origin: &str, body: &str) -> Result<String, String> {
        let current_cfg = self.runtime_cfg.load();
        let target = zone_api_target(&current_cfg, &self.zones.store.load(), origin, "modify")?;
        let name = onetdns_proto::Name::from_str(origin)
            .map_err(|_| format!("Invalid DNS zone name: {origin}"))?;
        let j = onetdns_core::json::parse(body).unwrap_or(onetdns_core::json::Json::Null);
        let rname_s = j
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("`name` is required".to_string())?;
        let rtype_s = j
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or("`type` is required".to_string())?;

        let rvalue = j
            .get("value")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let rtype_num = *qtype_numbers(&[rtype_s.to_string()])
            .first()
            .ok_or_else(|| format!("Unsupported DNS record type: {rtype_s}"))?;
        if rtype_num == 6 {
            return Err("The SOA record cannot be deleted".to_string());
        }
        let rtype = onetdns_proto::RecordType(rtype_num);
        let rname = resolve_zone_name(rname_s, origin)
            .ok_or_else(|| format!("Invalid DNS name: {rname_s}"))?;
        let mut journals = self.zones.journal.lock().unwrap_or_else(|e| e.into_inner());
        let mut recs = {
            let store = self.zones.store.load();
            let zone = store
                .zones()
                .iter()
                .find(|z| z.origin().eq_ignore_case(&name))
                .ok_or_else(|| format!("DNS zone not found: {origin}"))?;
            zone.axfr_records()
        };
        recs.pop();
        let before = recs.len();
        recs.retain(|record| {
            let same_owner = record.name.eq_ignore_case(&rname);
            let same_type = record.rtype == rtype;
            let same_value = rvalue
                .map(|expected| zone_record_value(record) == expected)
                .unwrap_or(true);
            !(same_owner && same_type && same_value)
        });
        let removed = before - recs.len();
        if removed == 0 {
            return Err(format!("No matching DNS record: {rname_s} {rtype_s}"));
        }
        let zone = onetdns_authority::Zone::from_records(recs)
            .map_err(|e| format!("Could not rebuild the DNS zone: {e}"))?;
        let path = target.path.clone();
        let applied = apply_zone_mutation_locked(
            &self.zones.store,
            zone,
            &self.zones.signers.load(),
            &mut journals,
            path.as_deref(),
            &self.zones.notify,
            "record delete",
        )?;
        onetdns_core::info!(event = "authority.record_deleted", origin = %applied.origin, removed, serial = applied.serial, "Deleted DNS record");
        Ok(format!(
            "{{\"deleted\":{removed},\"origin\":{},\"serial\":{},\"persisted\":{}}}",
            onetdns_core::json::escape(&applied.origin.to_string()),
            applied.serial,
            applied.persisted
        ))
    }

    /** @brief 이 영역의 서명 키와 DS. */
    pub(super) fn zone_dnssec(&self, origin: &str) -> Result<String, String> {
        let name = onetdns_proto::Name::from_str(origin)
            .map_err(|_| format!("Invalid DNS zone name: {origin}"))?;
        let signers = self.zones.signers.load();
        let Some((_, ctx)) = signers.iter().find(|(o, _)| o.eq_ignore_case(&name)) else {
            return Ok(format!(
                "{{\"origin\":{},\"signed\":false,\"dnskeys\":[],\"ds\":null}}",
                onetdns_core::json::escape(&name.to_ascii_lower())
            ));
        };
        let signer = &ctx.signer;
        let mut keys: Vec<String> = Vec::new();
        let zsk = signer.dnskey();
        let has_ksk = signer.ksk_dnskey().is_some();
        keys.push(format!(
            "{{\"key_tag\":{},\"flags\":{},\"algorithm\":{},\"role\":\"{}\"}}",
            zsk.key_tag(),
            zsk.flags,
            zsk.algorithm,
            if has_ksk { "ZSK" } else { "CSK" }
        ));
        if let Some(ksk) = signer.ksk_dnskey() {
            keys.push(format!(
                "{{\"key_tag\":{},\"flags\":{},\"algorithm\":{},\"role\":\"KSK\"}}",
                ksk.key_tag(),
                ksk.flags,
                ksk.algorithm
            ));
        }
        let ds_json = match signer.ds() {
            Some(ds) => {
                let hex: String = ds.digest.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "{{\"key_tag\":{},\"algorithm\":{},\"digest_type\":{},\"digest\":\"{}\"}}",
                    ds.key_tag, ds.algorithm, ds.digest_type, hex
                )
            }
            None => "null".to_string(),
        };
        Ok(format!(
            "{{\"origin\":{},\"signed\":true,\"dnskeys\":[{}],\"ds\":{}}}",
            onetdns_core::json::escape(&name.to_ascii_lower()),
            keys.join(","),
            ds_json
        ))
    }
}
