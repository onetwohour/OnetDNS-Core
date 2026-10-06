/*!
 * @brief 관리 API: 차단 목록 구독.
 */

use super::*;
use crate::atomic_file::with_rollback_result;
use crate::config_apply::update_runtime_config;
use crate::filters::{
    active_subscription_urls, fetch_blocklist, fetch_blocklists_meta, persist_subscription_state,
    preset_list_kind, try_list_refresh_lock, SubMeta,
};

impl ControlDeps {
    /** @brief 구독한 목록과 내장 목록, 목록마다 규칙 수. */
    pub(super) fn subscriptions_list(&self) -> String {
        let list = self.filters.sub_urls.lock_recover().clone();
        let preset_list = self.filters.preset_urls.lock_recover().clone();
        let names = self.filters.sub_titles.lock_recover().clone();
        let off = self.filters.sub_disabled.lock_recover().clone();
        let m = self.filters.sub_meta.lock_recover();
        let by_url: std::collections::HashMap<&str, &SubMeta> =
            m.iter().map(|x| (x.url.as_str(), x)).collect();
        let mut lists: Vec<String> = list.iter().enumerate().map(|(i,u)| {
            let title = names.get(i).cloned().unwrap_or_default();
            let enabled = !off.iter().any(|x| x == u);
            match by_url.get(u.as_str()) {
                Some(sm) => format!("{{\"url\":{},\"title\":{},\"enabled\":{},\"rules\":{},\"updated_unix\":{}}}", onetdns_core::json::escape(u), onetdns_core::json::escape(if title.is_empty(){&sm.title}else{&title}), enabled, sm.rules, sm.updated_unix),
                None => format!("{{\"url\":{},\"title\":{},\"enabled\":{},\"rules\":0,\"updated_unix\":0}}", onetdns_core::json::escape(u), onetdns_core::json::escape(&title), enabled),
            }
        }).collect();
        /* 내장 목록도 외부에서 내려받는 목록이다. 숨기면 어디서 받는지, 받아졌는지 볼 수 없다. */
        let builtin: Vec<&String> = preset_list
            .iter()
            .filter(|url| !list.contains(url))
            .collect();
        for url in &builtin {
            let (rules, updated) = by_url
                .get(url.as_str())
                .map_or((0, 0), |meta| (meta.rules, meta.updated_unix));
            lists.push(format!(
                "{{\"url\":{},\"title\":\"\",\"enabled\":true,\"rules\":{rules},\"updated_unix\":{updated},\"preset\":{}}}",
                onetdns_core::json::escape(url),
                onetdns_core::json::escape(preset_list_kind(url)),
            ));
        }
        let block_domains: usize = list
            .iter()
            .chain(builtin.iter().copied())
            .filter_map(|url| by_url.get(url.as_str()))
            .map(|meta| meta.rules)
            .sum();
        format!(
            "{{\"count\":{},\"block_domains\":{},\"lists\":[{}]}}",
            lists.len(),
            block_domains,
            lists.join(",")
        )
    }

    /** @brief 목록을 한 번 받아 본 뒤 구독에 넣는다. 다시 만들지 못하면 되돌린다. */
    pub(super) fn subscription_add(&self, body: &str) -> Result<String, String> {
        let urls = &self.filters.sub_urls;
        let titles = &self.filters.sub_titles;
        let disabled = &self.filters.sub_disabled;
        let request = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let url = request
            .get("url")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let title = request
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("List URL must start with http:// or https://".to_string());
        }

        let _guard = try_list_refresh_lock(&self.filters.list_refresh_lock)?;
        let previous_urls = urls.lock_recover().clone();
        if previous_urls.iter().any(|item| item == &url) {
            return Err("This filter list is already registered".to_string());
        }
        let previous_titles = titles.lock_recover().clone();
        let previous_disabled = disabled.lock_recover().clone();
        let previous_meta = self.filters.sub_meta.lock_recover().clone();
        let fresh = fetch_blocklist(&url, &self.blocklist_resolver, None)?;

        let mut next_urls = previous_urls.clone();
        let mut next_titles = previous_titles.clone();
        next_titles.resize(next_urls.len(), String::new());
        next_urls.push(url.clone());
        next_titles.push(title);
        let mut next_disabled = previous_disabled.clone();
        next_disabled.retain(|item| item != &url);
        persist_subscription_state(
            self.config_path.as_deref(),
            &next_urls,
            &next_titles,
            &next_disabled,
        )?;

        *urls.lock_recover() = next_urls.clone();
        *titles.lock_recover() = next_titles;
        *disabled.lock_recover() = next_disabled.clone();
        let active = active_subscription_urls(
            &next_urls,
            &next_disabled,
            &self.filters.preset_urls.lock_recover(),
        );
        let mut next_meta = previous_meta.clone();
        next_meta.retain(|item| active.iter().any(|active_url| active_url == &item.url));
        next_meta.retain(|item| item.url != url);
        next_meta.push(fresh);
        *self.filters.sub_meta.lock_recover() = next_meta;
        if let Err(error) = (self.filters.rebuild)() {
            *urls.lock_recover() = previous_urls.clone();
            *titles.lock_recover() = previous_titles.clone();
            *disabled.lock_recover() = previous_disabled.clone();
            *self.filters.sub_meta.lock_recover() = previous_meta;
            let error = with_rollback_result(
                error,
                "Could not restore the previous subscription settings",
                persist_subscription_state(
                    self.config_path.as_deref(),
                    &previous_urls,
                    &previous_titles,
                    &previous_disabled,
                ),
            );
            let error = with_rollback_result(
                error,
                "Could not restore the previous runtime state of subscription filters",
                (self.filters.rebuild)().map(|_| ()),
            );
            return Err(error);
        }
        let applied_urls = urls.lock_recover().clone();
        let applied_titles = titles.lock_recover().clone();
        let applied_disabled = disabled.lock_recover().clone();
        update_runtime_config(&self.runtime_cfg, |config| {
            config.blocklist_urls = applied_urls;
            config.blocklist_titles = applied_titles;
            config.disabled_blocklist_urls = applied_disabled;
        });
        Ok("{\"added\":true}".to_string())
    }

    /** @brief 구독을 뺀다. 다시 만들지 못하면 되돌린다. */
    pub(super) fn subscription_remove(&self, url: &str) -> Result<String, String> {
        let urls = &self.filters.sub_urls;
        let titles = &self.filters.sub_titles;
        let disabled = &self.filters.sub_disabled;
        let target = url.trim();
        let _guard = try_list_refresh_lock(&self.filters.list_refresh_lock)?;
        let previous_urls = urls.lock_recover().clone();
        let position = previous_urls
            .iter()
            .position(|item| item == target)
            .ok_or_else(|| format!("Subscription not found: {target}"))?;
        let previous_titles = titles.lock_recover().clone();
        let previous_disabled = disabled.lock_recover().clone();
        let previous_meta = self.filters.sub_meta.lock_recover().clone();

        let mut next_urls = previous_urls.clone();
        next_urls.remove(position);
        let mut next_titles = previous_titles.clone();
        next_titles.resize(previous_urls.len(), String::new());
        next_titles.remove(position);
        next_titles.truncate(next_urls.len());
        let mut next_disabled = previous_disabled.clone();
        next_disabled.retain(|item| item != target);
        persist_subscription_state(
            self.config_path.as_deref(),
            &next_urls,
            &next_titles,
            &next_disabled,
        )?;

        *urls.lock_recover() = next_urls.clone();
        *titles.lock_recover() = next_titles;
        *disabled.lock_recover() = next_disabled.clone();
        let active = active_subscription_urls(
            &next_urls,
            &next_disabled,
            &self.filters.preset_urls.lock_recover(),
        );
        let next_meta =
            fetch_blocklists_meta(&active, &self.blocklist_resolver, &previous_meta, None);
        *self.filters.sub_meta.lock_recover() = next_meta;
        if let Err(error) = (self.filters.rebuild)() {
            *urls.lock_recover() = previous_urls.clone();
            *titles.lock_recover() = previous_titles.clone();
            *disabled.lock_recover() = previous_disabled.clone();
            *self.filters.sub_meta.lock_recover() = previous_meta;
            let error = with_rollback_result(
                error,
                "Could not restore the previous subscription settings",
                persist_subscription_state(
                    self.config_path.as_deref(),
                    &previous_urls,
                    &previous_titles,
                    &previous_disabled,
                ),
            );
            let error = with_rollback_result(
                error,
                "Could not restore the previous runtime state of subscription filters",
                (self.filters.rebuild)().map(|_| ()),
            );
            return Err(error);
        }
        let applied_urls = urls.lock_recover().clone();
        let applied_titles = titles.lock_recover().clone();
        let applied_disabled = disabled.lock_recover().clone();
        update_runtime_config(&self.runtime_cfg, |config| {
            config.blocklist_urls = applied_urls;
            config.blocklist_titles = applied_titles;
            config.disabled_blocklist_urls = applied_disabled;
        });
        Ok("{\"removed\":true}".to_string())
    }

    /** @brief 구독을 켜거나 끈다. 다시 만들지 못하면 되돌린다. */
    pub(super) fn subscription_update(&self, body: &str) -> Result<String, String> {
        let disabled = &self.filters.sub_disabled;
        let request = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let url = request
            .get("url")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim();
        let enabled = request
            .get("enabled")
            .and_then(|value| value.as_bool())
            .ok_or_else(|| "`enabled` is required".to_string())?;

        let _guard = try_list_refresh_lock(&self.filters.list_refresh_lock)?;
        let current_urls = self.filters.sub_urls.lock_recover().clone();
        if !current_urls.iter().any(|item| item == url) {
            return Err(format!("Subscription not found: {url}"));
        }
        let current_titles = self.filters.sub_titles.lock_recover().clone();
        let previous_disabled = disabled.lock_recover().clone();
        let previous_meta = self.filters.sub_meta.lock_recover().clone();
        let mut next_disabled = previous_disabled.clone();
        if enabled {
            next_disabled.retain(|item| item != url);
        } else if !next_disabled.iter().any(|item| item == url) {
            next_disabled.push(url.to_string());
        }
        persist_subscription_state(
            self.config_path.as_deref(),
            &current_urls,
            &current_titles,
            &next_disabled,
        )?;
        *disabled.lock_recover() = next_disabled.clone();
        let active = active_subscription_urls(
            &current_urls,
            &next_disabled,
            &self.filters.preset_urls.lock_recover(),
        );
        let next_meta =
            fetch_blocklists_meta(&active, &self.blocklist_resolver, &previous_meta, None);
        *self.filters.sub_meta.lock_recover() = next_meta;
        if let Err(error) = (self.filters.rebuild)() {
            *disabled.lock_recover() = previous_disabled.clone();
            *self.filters.sub_meta.lock_recover() = previous_meta;
            let error = with_rollback_result(
                error,
                "Could not restore the previous subscription enabled state",
                persist_subscription_state(
                    self.config_path.as_deref(),
                    &current_urls,
                    &current_titles,
                    &previous_disabled,
                ),
            );
            let error = with_rollback_result(
                error,
                "Could not restore the previous runtime state of subscription filters",
                (self.filters.rebuild)().map(|_| ()),
            );
            return Err(error);
        }
        let applied_urls = self.filters.sub_urls.lock_recover().clone();
        let applied_titles = self.filters.sub_titles.lock_recover().clone();
        let applied_disabled = disabled.lock_recover().clone();
        update_runtime_config(&self.runtime_cfg, |config| {
            config.blocklist_urls = applied_urls;
            config.blocklist_titles = applied_titles;
            config.disabled_blocklist_urls = applied_disabled;
        });
        Ok(format!("{{\"updated\":true,\"enabled\":{enabled}}}"))
    }

    /** @brief 구독한 목록 하나를 지금 다시 받는다. */
    pub(super) fn subscription_refresh(&self, body: &str) -> Result<String, String> {
        let presets = &self.filters.preset_urls;
        let disabled = &self.filters.sub_disabled;
        let request = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let target = request
            .get("url")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .trim();
        let _guard = try_list_refresh_lock(&self.filters.list_refresh_lock)?;
        let current_urls = self.filters.sub_urls.lock_recover().clone();
        let builtin = presets.lock_recover().iter().any(|item| item == target);
        if !builtin && !current_urls.iter().any(|item| item == target) {
            return Err(format!("Subscription not found: {target}"));
        }
        if !builtin && disabled.lock_recover().iter().any(|item| item == target) {
            return Err("A disabled subscription cannot be refreshed".to_string());
        }
        let fresh = fetch_blocklist(target, &self.blocklist_resolver, None)?;
        let previous_meta = self.filters.sub_meta.lock_recover().clone();
        let mut next_meta = previous_meta.clone();
        match next_meta.iter_mut().find(|item| item.url == target) {
            Some(item) => *item = fresh,
            None => next_meta.push(fresh),
        }
        *self.filters.sub_meta.lock_recover() = next_meta;
        if let Err(error) = (self.filters.rebuild)() {
            *self.filters.sub_meta.lock_recover() = previous_meta;
            let error = with_rollback_result(
                error,
                "Could not restore the previous runtime state of subscription filters",
                (self.filters.rebuild)().map(|_| ()),
            );
            return Err(error);
        }
        Ok("{\"refreshed\":true}".to_string())
    }
}
