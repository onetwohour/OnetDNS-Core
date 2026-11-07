use super::*;
use crate::atomic_file::with_rollback_result;
use crate::config_apply::update_runtime_config;
use crate::filters::{
    active_subscription_urls, fetch_blocklist, fetch_blocklists_meta, persist_subscription_state,
    preset_list_kind, try_list_refresh_lock, SubMeta,
};
use onetdns_control::ApiResponse;

const SUBSCRIPTIONS_PATH: &str = "/v1/filter/subscriptions";

struct NewSubscription {
    url: String,
    title: String,
    background: bool,
}

impl NewSubscription {
    fn parse(body: &str) -> Result<Self, String> {
        let request = onetdns_core::json::parse(body)
            .map_err(|_| "Could not parse the JSON request body".to_string())?;
        let text = |key: &str| {
            request
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let url = text("url");
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("List URL must start with http:// or https://".to_string());
        }
        let background = match request.get("background") {
            None => false,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "`background` must be true or false".to_string())?,
        };
        Ok(Self {
            url,
            title: text("title"),
            background,
        })
    }
}

fn ensure_not_subscribed(urls: &[String], url: &str) -> Result<(), String> {
    if urls.iter().any(|item| item == url) {
        return Err("This filter list is already registered".to_string());
    }
    Ok(())
}

fn json_response(body: &str) -> ApiResponse {
    ("200 OK", "application/json", body.to_string())
}

fn error_response(status: &'static str, message: &str) -> ApiResponse {
    (
        status,
        "application/json",
        format!("{{\"error\":{}}}", onetdns_core::json::escape(message)),
    )
}

/// The `error` field of a failed response, or the whole body when it has none.
fn response_error(response: &ApiResponse) -> String {
    onetdns_core::json::parse(&response.2)
        .ok()
        .and_then(|body| {
            body.get("error")
                .and_then(|error| error.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| response.2.clone())
}

impl ControlDeps {
    /// Subscribed and built-in lists, with the rule count of each.
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
        // Built-in lists are downloaded too; hiding them would hide where they come from and
        // whether they arrived.
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

    /// Downloads the list before subscribing to it, so a list that cannot be downloaded is not
    /// saved. With `background`, the download and save run as a job and the response carries
    /// its id.
    pub(super) fn subscription_add(self: &Arc<Self>, body: &str) -> ApiResponse {
        let request = match NewSubscription::parse(body) {
            Ok(request) => request,
            Err(error) => return error_response("400 Bad Request", &error),
        };
        // Lets a cluster follower refuse before the download instead of after it.
        let check = {
            let _mutation = onetdns_control::api::control_mutation_lock().lock_recover();
            cluster_routed_write("POST", SUBSCRIPTIONS_PATH, body, &mut || {
                match ensure_not_subscribed(&self.filters.sub_urls.lock_recover(), &request.url) {
                    Ok(()) => json_response("{}"),
                    Err(error) => error_response("400 Bad Request", &error),
                }
            })
        };
        if !check.0.starts_with('2') {
            return check;
        }
        if request.background {
            self.start_add_job(request, body)
        } else {
            self.download_and_save(&request, body)
        }
    }

    fn start_add_job(self: &Arc<Self>, request: NewSubscription, body: &str) -> ApiResponse {
        let Some(id) = self.jobs.create("add-list") else {
            return error_response("503 Service Unavailable", "Too many jobs are running");
        };
        let deps = Arc::clone(self);
        let body = body.to_string();
        let spawned = std::thread::Builder::new()
            .name(format!("add-list-{id}"))
            .spawn(move || {
                let response = deps.download_and_save(&request, &body);
                let url = &request.url;
                if response.0.starts_with('2') {
                    onetdns_core::info!(event = "filter.subscription_added", %url, "Added a blocklist");
                    deps.jobs.finish(id, true, String::new());
                } else {
                    let error = response_error(&response);
                    onetdns_core::warn!(event = "filter.subscription_add_failed", %url, %error, "Could not add a blocklist");
                    deps.jobs.finish(id, false, error);
                }
            });
        match spawned {
            Ok(thread) => {
                track_service_thread(&self.service_threads, thread);
                json_response(&format!("{{\"id\":{id},\"status\":\"running\"}}"))
            }
            Err(error) => {
                let message = format!("Could not start the job thread: {error}");
                self.jobs.finish(id, false, message.clone());
                error_response("503 Service Unavailable", &message)
            }
        }
    }

    fn download_and_save(&self, request: &NewSubscription, body: &str) -> ApiResponse {
        let fresh = match fetch_blocklist(&request.url, &self.blocklist_resolver, None) {
            Ok(fresh) => fresh,
            Err(error) => return error_response("400 Bad Request", &error),
        };
        // Waits instead of failing as busy: a refresh in progress writes back the list metadata
        // it started from, which would drop this list.
        let _refresh = self.filters.list_refresh_lock.lock_recover();
        let _mutation = onetdns_control::api::control_mutation_lock().lock_recover();
        cluster_routed_write("POST", SUBSCRIPTIONS_PATH, body, &mut || match self
            .save_subscription(request, fresh.clone())
        {
            Ok(()) => json_response("{\"added\":true}"),
            Err(error) => error_response("400 Bad Request", &error),
        })
    }

    /// Rolls back when the filter cannot be rebuilt with the new list.
    fn save_subscription(&self, request: &NewSubscription, fresh: SubMeta) -> Result<(), String> {
        let url = &request.url;
        let urls = &self.filters.sub_urls;
        let titles = &self.filters.sub_titles;
        let disabled = &self.filters.sub_disabled;
        let previous_urls = urls.lock_recover().clone();
        ensure_not_subscribed(&previous_urls, url)?;
        let previous_titles = titles.lock_recover().clone();
        let previous_disabled = disabled.lock_recover().clone();
        let previous_meta = self.filters.sub_meta.lock_recover().clone();

        let mut next_urls = previous_urls.clone();
        let mut next_titles = previous_titles.clone();
        next_titles.resize(next_urls.len(), String::new());
        next_urls.push(url.clone());
        next_titles.push(request.title.clone());
        let mut next_disabled = previous_disabled.clone();
        next_disabled.retain(|item| item != url);
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
        next_meta.retain(|item| &item.url != url);
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
        Ok(())
    }

    /// Rolls back when the filter cannot be rebuilt without the list.
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

    /// Enables or disables a subscription; rolls back when the filter cannot be rebuilt.
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
