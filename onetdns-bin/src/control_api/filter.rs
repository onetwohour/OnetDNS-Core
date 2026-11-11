//! Management API: filter rules, blocked services, safe search, rewrites, backup.

use super::*;
use crate::atomic_file::{atomic_write, with_rollback_result};
use crate::config_apply::{config_write_lock, update_runtime_config};
use crate::config_edit::{
    persist_config_string_array, rewrite_config_kv, rewrite_config_string_array, rewrites_to_toml,
};
use crate::ctl::counts;
use crate::filters::mutate_user_rule;
use onetdns_control::{FilterApply, ListCounts};

impl ControlDeps {
    pub(super) fn rebuild_filter(&self) -> Result<ListCounts, String> {
        (self.filters.rebuild)().map(counts)
    }

    pub(super) fn block_add(&self, rule: &str) -> Result<ListCounts, String> {
        let result = mutate_user_rule(
            &self.filters.overlay,
            self.config_path.as_deref(),
            &*self.filters.rebuild,
            rule,
            false,
            true,
        )?;
        let rules = self.filters.overlay.lock_recover().clone();
        update_runtime_config(&self.runtime_cfg, |config| {
            config.block_rules = rules.0;
            config.allow_rules = rules.1;
        });
        Ok(counts(result))
    }

    pub(super) fn allow_add(&self, rule: &str) -> Result<ListCounts, String> {
        let result = mutate_user_rule(
            &self.filters.overlay,
            self.config_path.as_deref(),
            &*self.filters.rebuild,
            rule,
            true,
            true,
        )?;
        let rules = self.filters.overlay.lock_recover().clone();
        update_runtime_config(&self.runtime_cfg, |config| {
            config.block_rules = rules.0;
            config.allow_rules = rules.1;
        });
        Ok(counts(result))
    }

    /// Rolls back the file and the list when the filter cannot be rebuilt.
    pub(super) fn service_set(
        &self,
        svc: &str,
        enable: bool,
        apply: FilterApply,
    ) -> Result<ListCounts, String> {
        let service_set = &self.filters.service_set;
        if enable && onetdns_filter::services::service_rules(svc).is_none() {
            return Err(format!("Unknown blocked service: {svc}"));
        }
        let previous = service_set.lock_recover().clone();
        let mut next = previous.clone();
        if enable {
            if !next.iter().any(|item| item == svc) {
                next.push(svc.to_string());
            }
        } else {
            next.retain(|item| item != svc);
        }
        if let Some(path) = self.config_path.as_deref() {
            persist_config_string_array(path, "blocked_services", &next)
                .map_err(|e| e.to_string())?;
        }
        *service_set.lock_recover() = next;
        match self.apply_filter(apply) {
            Ok(value) => {
                let applied = service_set.lock_recover().clone();
                update_runtime_config(&self.runtime_cfg, |config| {
                    config.blocked_services = applied;
                });
                Ok(counts(value))
            }
            Err(error) => {
                *service_set.lock_recover() = previous.clone();
                let error = if let Some(path) = self.config_path.as_deref() {
                    with_rollback_result(
                        error,
                        "Could not restore the previous blocked-service settings",
                        persist_config_string_array(path, "blocked_services", &previous)
                            .map_err(|rollback_error| rollback_error.to_string()),
                    )
                } else {
                    error
                };
                Err(error)
            }
        }
    }

    pub(super) fn safesearch_set(&self, enable: bool) -> Result<(), String> {
        if let Some(path) = self.config_path.as_deref() {
            let _write_guard = config_write_lock().lock_recover();
            let text = onetdns_core::SecretString::from(
                Config::read_text(path).map_err(|e| e.to_string())?,
            );
            let updated = onetdns_core::SecretString::from(rewrite_config_kv(
                &text,
                "safe_search",
                &enable.to_string(),
            )?);
            atomic_write(path, updated.as_bytes()).map_err(|e| e.to_string())?;
        }
        self.filters
            .safe_search
            .store(enable, std::sync::atomic::Ordering::Relaxed);
        update_runtime_config(&self.runtime_cfg, |config| config.safe_search = enable);
        Ok(())
    }

    pub(super) fn export(&self) -> String {
        let (b, a) = {
            let o = self.filters.overlay.lock_recover();
            (o.0.clone(), o.1.clone())
        };
        let svcs = self.filters.service_set.lock_recover().clone();
        let refused = self.filters.refused_domains.lock_recover().clone();
        let arr = |v: &[String]| {
            v.iter()
                .map(|s| onetdns_core::json::escape(s))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{{\"version\":1,\"block\":[{}],\"allow\":[{}],\"services\":[{}],\"refused_domains\":[{}],\"safe_search\":{}}}",
            arr(&b),
            arr(&a),
            arr(&svcs),
            arr(&refused),
            self.filters.safe_search.load(std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Rolls back the file and the running state when the filter cannot be rebuilt.
    pub(super) fn import(&self, body: &str) -> Result<ListCounts, String> {
        let overlay = &self.filters.overlay;
        let service_set = &self.filters.service_set;
        let refused_domains = &self.filters.refused_domains;
        let safe_search_flag = &self.filters.safe_search;
        let (block, allow, services, refused, safe_search) = parse_control_backup(body)?;
        let previous_overlay = overlay.lock_recover().clone();
        let previous_services = service_set.lock_recover().clone();
        let previous_refused = refused_domains.lock_recover().clone();
        let previous_safe_search = safe_search_flag.load(std::sync::atomic::Ordering::Relaxed);
        let _write_guard = config_write_lock().lock_recover();
        let previous_text = if let Some(path) = self.config_path.as_deref() {
            Some(onetdns_core::SecretString::from(
                Config::read_text(path).map_err(|e| e.to_string())?,
            ))
        } else {
            None
        };
        if let (Some(path), Some(text)) = (self.config_path.as_deref(), previous_text.as_deref()) {
            let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                text,
                "block_rules",
                &block,
            )?);
            let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                &text,
                "allow_rules",
                &allow,
            )?);
            let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                &text,
                "blocked_services",
                &services,
            )?);
            let text = onetdns_core::SecretString::from(rewrite_config_string_array(
                &text,
                "refused_domains",
                &refused,
            )?);
            let text = onetdns_core::SecretString::from(rewrite_config_kv(
                &text,
                "safe_search",
                &safe_search.to_string(),
            )?);
            atomic_write(path, text.as_bytes()).map_err(|e| e.to_string())?;
        }
        *overlay.lock_recover() = (block, allow);
        *service_set.lock_recover() = services;
        *refused_domains.lock_recover() = refused;
        safe_search_flag.store(safe_search, std::sync::atomic::Ordering::Relaxed);
        match (self.filters.rebuild)() {
            Ok(value) => {
                let rules = overlay.lock_recover().clone();
                let services = service_set.lock_recover().clone();
                let refused = refused_domains.lock_recover().clone();
                let safe_search = safe_search_flag.load(std::sync::atomic::Ordering::Relaxed);
                update_runtime_config(&self.runtime_cfg, |config| {
                    config.block_rules = rules.0;
                    config.allow_rules = rules.1;
                    config.blocked_services = services;
                    config.refused_domains = refused;
                    config.safe_search = safe_search;
                });
                Ok(counts(value))
            }
            Err(error) => {
                *overlay.lock_recover() = previous_overlay;
                *service_set.lock_recover() = previous_services;
                *refused_domains.lock_recover() = previous_refused;
                safe_search_flag.store(previous_safe_search, std::sync::atomic::Ordering::Relaxed);
                let error = if let (Some(path), Some(text)) =
                    (self.config_path.as_deref(), previous_text.as_deref())
                {
                    with_rollback_result(
                        error,
                        "Could not restore the previous filter download settings",
                        atomic_write(path, text.as_bytes())
                            .map_err(|rollback_error| rollback_error.to_string()),
                    )
                } else {
                    error
                };
                Err(error)
            }
        }
    }

    pub(super) fn rewrites_list(&self) -> String {
        let current = self.runtime_cfg.load();
        let items: Vec<String> = current
            .rewrites
            .iter()
            .map(|r| {
                format!(
                    "{{\"domain\":{},\"answer\":{}}}",
                    onetdns_core::json::escape(&r.domain),
                    onetdns_core::json::escape(&r.answer)
                )
            })
            .collect();
        format!("{{\"rewrites\":[{}]}}", items.join(","))
    }

    /// Replaces any rule for the same domain.
    pub(super) fn rewrite_add(&self, body: &str, apply: FilterApply) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let domain = j
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("`domain` is required".to_string())?
            .to_string();
        let answer = j
            .get("answer")
            .and_then(|v| v.as_str())
            .ok_or("`answer` is required".to_string())?
            .to_string();
        let result = self.edit_config_with(apply, |text| {
            let cur = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            let mut rw = cur.rewrites;
            rw.retain(|r| r.domain != domain);
            rw.push(onetdns_config::Rewrite {
                domain: domain.clone(),
                answer: answer.clone(),
            });
            rewrite_config_kv(text, "rewrites", &rewrites_to_toml(&rw))
        })?;
        Ok(format!(
            "{{\"added\":true,\"domain\":{},{} }}",
            onetdns_core::json::escape(&domain),
            result.json_fields()
        ))
    }

    pub(super) fn rewrite_delete(&self, body: &str, apply: FilterApply) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let domain = j
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or("`domain` is required".to_string())?
            .to_string();
        let mut removed = 0usize;
        let result = self.edit_config_with(apply, |text| {
            let cur = onetdns_config::Config::from_toml_str(text).map_err(|e| e.to_string())?;
            let before = cur.rewrites.len();
            let rw: Vec<_> = cur
                .rewrites
                .into_iter()
                .filter(|r| r.domain != domain)
                .collect();
            removed = before - rw.len();
            if removed == 0 {
                return Err(format!("No matching rewrite rule: {domain}"));
            }
            rewrite_config_kv(text, "rewrites", &rewrites_to_toml(&rw))
        })?;
        Ok(format!(
            "{{\"removed\":{removed},\"domain\":{},{} }}",
            onetdns_core::json::escape(&domain),
            result.json_fields()
        ))
    }

    pub(super) fn services_catalog(&self) -> String {
        let blocked = self.filters.service_set.lock_recover().clone();
        let all: Vec<String> = onetdns_filter::services::catalog()
            .iter()
            .map(|service| {
                let b = blocked.iter().any(|id| id.as_str() == service.id);
                format!(
                    "{{\"id\":{},\"name\":{},\"group\":{},\"rule_count\":{},\"blocked\":{}}}",
                    onetdns_core::json::escape(service.id),
                    onetdns_core::json::escape(service.name),
                    onetdns_core::json::escape(service.group),
                    service.rules.len(),
                    b
                )
            })
            .collect();
        format!(
            "{{\"count\":{},\"services\":[{}]}}",
            all.len(),
            all.join(",")
        )
    }

    pub(super) fn access_list(&self) -> String {
        let c = self.runtime_cfg.load();
        let arr = |v: &[onetdns_core::IpNet]| {
            v.iter()
                .map(|n| onetdns_core::json::escape(&n.to_string()))
                .collect::<Vec<_>>()
                .join(",")
        };
        let refused = c
            .refused_domains
            .iter()
            .map(|h| onetdns_core::json::escape(h))
            .collect::<Vec<_>>()
            .join(",");
        let unlisted = match c.acl_unlisted_effect() {
            None => "allow",
            Some(onetdns_config::AclUnlisted::Deny) => "deny",
            Some(onetdns_config::AclUnlisted::Drop) => "drop",
        };
        format!(
            "{{\"allowed\":[{}],\"blocked\":[{}],\"dropped\":[{}],\"unlisted\":\"{unlisted}\",\"refused_domains\":[{}]}}",
            arr(&c.acl_allow),
            arr(&c.acl_deny),
            arr(&c.acl_drop),
            refused
        )
    }

    pub(super) fn filter_report(&self) -> String {
        self.filters.filter.load().load_report().to_json()
    }

    pub(super) fn filter_top_rules(&self) -> String {
        let eng = self.filters.filter.load();
        let items: Vec<String> = eng
            .top_rule_hits(50)
            .into_iter()
            .map(|(rule, hits)| {
                let rule = onetdns_core::json::escape(&rule);
                format!("{{\"rule\":{rule},\"hits\":{hits}}}")
            })
            .collect();
        format!(
            "{{\"enabled\":{},\"top\":[{}]}}",
            eng.hits_enabled(),
            items.join(",")
        )
    }

    pub(super) fn filter_sources(&self) -> String {
        let eng = self.filters.filter.load();
        let items: Vec<String> = eng
            .source_stats()
            .into_iter()
            .map(|s| {
                let source = onetdns_core::json::escape(&s.source);
                format!(
                    "{{\"source\":{source},\"rules\":{},\"hits\":{}}}",
                    s.rules, s.hits
                )
            })
            .collect();
        format!(
            "{{\"hits_enabled\":{},\"sources\":[{}]}}",
            eng.hits_enabled(),
            items.join(",")
        )
    }

    pub(super) fn filter_rules_list(&self) -> String {
        let g = self.filters.overlay.lock_recover();
        format!(
            "{{\"block\":{},\"allow\":{},\"refused_domains\":{}}}",
            json_str_array(&g.0),
            json_str_array(&g.1),
            json_str_array(&self.filters.refused_domains.lock_recover())
        )
    }

    pub(super) fn filter_rule_mutate(
        &self,
        body: &str,
        add: bool,
        apply: FilterApply,
    ) -> Result<String, String> {
        let refused = &self.filters.refused_domains;
        let j = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let kind = j.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let rule = j.get("rule").and_then(|v| v.as_str()).unwrap_or("").trim();
        if rule.is_empty() {
            return Err("`rule` is required".to_string());
        }
        match kind {
            "block" | "allow" => {
                mutate_user_rule(
                    &self.filters.overlay,
                    self.config_path.as_deref(),
                    &|| self.apply_filter(apply),
                    rule,
                    kind == "allow",
                    add,
                )?;
                let rules = self.filters.overlay.lock_recover().clone();
                update_runtime_config(&self.runtime_cfg, |config| {
                    config.block_rules = rules.0;
                    config.allow_rules = rules.1;
                });
            }
            "refused_domain" => {
                let previous = refused.lock_recover().clone();
                let mut next = previous.clone();
                if add {
                    if !next.iter().any(|item| item == rule) {
                        next.push(rule.to_string());
                    }
                } else {
                    next.retain(|item| item != rule);
                }
                if let Some(path) = self.config_path.as_deref() {
                    persist_config_string_array(path, "refused_domains", &next)
                        .map_err(|e| e.to_string())?;
                }
                *refused.lock_recover() = next;
                if let Err(error) = self.apply_filter(apply) {
                    *refused.lock_recover() = previous.clone();
                    let error = if let Some(path) = self.config_path.as_deref() {
                        with_rollback_result(
                            error,
                            "Could not restore the previous refused-domain settings",
                            persist_config_string_array(path, "refused_domains", &previous)
                                .map_err(|rollback_error| rollback_error.to_string()),
                        )
                    } else {
                        error
                    };
                    return Err(error);
                }
                let applied = refused.lock_recover().clone();
                update_runtime_config(&self.runtime_cfg, |config| {
                    config.refused_domains = applied;
                });
            }
            _ => return Err("kind must be block, allow, or refused_domain".to_string()),
        }
        Ok("{\"updated\":true}".to_string())
    }
}
