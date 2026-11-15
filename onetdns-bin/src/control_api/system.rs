//! Management API: this machine's network settings, boot service, and self-update.

use super::*;

impl ControlDeps {
    /// Next to the config file; the original values go here before system DNS settings change.
    fn osnet_backup_dir(&self) -> PathBuf {
        self.config_path
            .as_ref()
            .and_then(|p| p.parent())
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// Backs up the original values.
    pub(super) fn dns_client_set(&self, body: &str) -> Result<String, String> {
        let backup = self.osnet_backup_dir();
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Invalid JSON request body: {e}"))?;
        let adapter = j
            .get("adapter")
            .and_then(|v| v.as_str())
            .ok_or("`adapter` is required")?;
        let servers: Vec<String> = match j.get("servers") {
            Some(onetdns_core::json::Json::Arr(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => return Err("`servers` array is required".to_string()),
        };
        if servers.is_empty() {
            return Err("servers must list at least one server".to_string());
        }
        osnet::set_dns(adapter, &servers, &backup)?;
        onetdns_core::info!(event = "osnet.client_dns_set", adapter = %adapter, servers = %servers.join(","), "Changed this machine's DNS server setting at the dashboard's request; the original value is backed up");
        Ok(format!(
            "{{\"ok\":true,\"adapter\":{}}}",
            onetdns_core::json::escape(adapter)
        ))
    }

    #[cfg(windows)]
    pub(super) fn boot_service_set(&self, body: &str) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Invalid JSON request body: {e}"))?;
        let action = j
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or("`action` must be install or uninstall")?;
        // The service must read the same config file; otherwise it boots with the default config
        // and runs differently from what the dashboard shows.
        let outcome = match action {
            "install" => service::install(self.config_path.clone()),
            "uninstall" => service::uninstall(),
            other => return Err(format!("`action` must be install or uninstall: {other}")),
        }
        .map_err(|error| error.to_string())?;
        onetdns_core::info!(
            event = "service.boot_registration_changed",
            action = %action,
            "Changed the boot-time service registration at the dashboard's request"
        );
        Ok(format!(
            "{{\"ok\":true,\"message\":{}}}",
            onetdns_core::json::escape(&outcome)
        ))
    }

    pub(super) fn dns_client_restore(&self, body: &str) -> Result<String, String> {
        let backup = self.osnet_backup_dir();
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Invalid JSON request body: {e}"))?;
        let adapter = j
            .get("adapter")
            .and_then(|v| v.as_str())
            .ok_or("`adapter` is required")?;
        osnet::restore_dns(adapter, &backup)?;
        onetdns_core::info!(event = "osnet.client_dns_restored", adapter = %adapter, "Restored this machine's DNS server setting from the backup at the dashboard's request");
        Ok(format!(
            "{{\"ok\":true,\"adapter\":{}}}",
            onetdns_core::json::escape(adapter)
        ))
    }

    pub(super) fn update_status(&self) -> String {
        crate::update::task::status_json(self.runtime_cfg.load().release_check)
    }

    pub(super) fn update_check(&self) -> Result<String, String> {
        crate::update::task::participation()?;
        let running = crate::update::task::begin(crate::update::task::Task::Check)?;
        let resolver = self.blocklist_resolver.clone();
        start_update_job(&self.jobs, running, move |running| {
            crate::update::task::check(running, &resolver)
                .map(|finding| crate::update::task::describe(&finding))
        })
    }

    pub(super) fn update_apply(&self, version: &str) -> Result<String, String> {
        let running = crate::update::task::begin(crate::update::task::Task::Apply)?;
        let release = crate::update::task::confirmed(version)?;
        let resolver = self.blocklist_resolver.clone();
        let config = self.config_path.clone();
        start_update_job(&self.jobs, running, move |running| {
            crate::update::task::install_release(running, &release, &resolver, config.as_deref())
                .map(|swapped| crate::update::task::activate(&swapped))
        })
    }

    pub(super) fn update_rollback(&self) -> Result<String, String> {
        crate::update::apply::rollback_ready()?;
        let running = crate::update::task::begin(crate::update::task::Task::Rollback)?;
        let config = self.config_path.clone();
        start_update_job(&self.jobs, running, move |running| {
            crate::update::task::rollback(running, config.as_deref())
                .map(|swapped| crate::update::task::activate(&swapped))
        })
    }
}

pub(super) fn net_adapters() -> Result<String, String> {
    let adapters = osnet::list_adapters()?;
    let esc = onetdns_core::json::escape;
    let items: Vec<String> = adapters
        .iter()
        .map(|a| {
            let dns: Vec<String> = a.dns.iter().map(|d| esc(d)).collect();
            format!("{{\"name\":{},\"dns\":[{}]}}", esc(&a.name), dns.join(","))
        })
        .collect();
    Ok(format!(
        "{{\"platform\":{},\"adapters\":[{}]}}",
        esc(osnet::platform()),
        items.join(",")
    ))
}

pub(super) fn firewall_set(body: &str) -> Result<String, String> {
    let j =
        onetdns_core::json::parse(body).map_err(|e| format!("Invalid JSON request body: {e}"))?;
    let port = j
        .get("port")
        .and_then(|v| v.as_u64())
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or("`port` must be between 1 and 65535")?;
    let udp = j.get("udp").and_then(|v| v.as_bool()).unwrap_or(true);
    let tcp = j.get("tcp").and_then(|v| v.as_bool()).unwrap_or(true);
    let action = j.get("action").and_then(|v| v.as_str()).unwrap_or("allow");
    match action {
        "allow" => {
            osnet::firewall_allow(udp, tcp, port)?;
            onetdns_core::info!(
                event = "osnet.firewall_opened",
                port = port,
                udp = udp,
                tcp = tcp,
                "Opened a port in this machine's firewall at the dashboard's request"
            );
        }
        "remove" => {
            osnet::firewall_remove(port)?;
            onetdns_core::info!(
                event = "osnet.firewall_closed",
                port = port,
                "Removed a firewall rule on this machine at the dashboard's request"
            );
        }
        other => return Err(format!("Unknown firewall action: {other}")),
    }
    Ok(format!(
        "{{\"ok\":true,\"port\":{port},\"action\":{},\"platform\":{}}}",
        onetdns_core::json::escape(action),
        onetdns_core::json::escape(osnet::platform())
    ))
}

#[cfg(windows)]
pub(super) fn boot_service_status() -> String {
    match service::status() {
        Ok((installed, running)) => {
            format!("{{\"supported\":true,\"installed\":{installed},\"running\":{running}}}")
        }
        Err(error) => format!(
            "{{\"supported\":true,\"installed\":false,\"running\":false,\"error\":{}}}",
            onetdns_core::json::escape(&error.to_string())
        ),
    }
}

/// Unsupported outside Windows.
#[cfg(not(windows))]
pub(super) fn boot_service_status() -> String {
    "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
}

#[cfg(not(windows))]
pub(super) fn boot_service_set(_body: &str) -> Result<String, String> {
    Err("Boot-time service registration is available only on Windows".to_string())
}

/// Runs on its own thread, which generation shutdown does not wait for: DNS is paused during a
/// generation switch, and downloading a binary can take minutes. The thread holds the update task
/// slot and releases it before writing the result to the job list, so the dashboard can request the
/// next job as soon as it sees this one finished.
///
/// Returns the started job; if the job cannot be listed, the slot is released at once and this
/// fails.
fn start_update_job(
    jobs: &Arc<JobRegistry>,
    running: crate::update::task::Running,
    work: impl FnOnce(&crate::update::task::Running) -> Result<String, String> + Send + 'static,
) -> Result<String, String> {
    let kind = format!("update-{}", running.task().name());
    let id = jobs
        .create(&kind)
        .ok_or_else(|| "Too many jobs are running".to_string())?;
    let task_jobs = jobs.clone();
    std::thread::Builder::new()
        .name(kind)
        .spawn(move || {
            let outcome = work(&running);
            drop(running);
            let (ok, result) = match outcome {
                Ok(message) => (true, message),
                Err(error) => (false, error),
            };
            task_jobs.finish(id, ok, result);
        })
        .map_err(|error| {
            let message = format!("Could not start the update job: {error}");
            jobs.finish(id, false, message.clone());
            message
        })?;
    Ok(format!("{{\"id\":{id},\"status\":\"running\"}}"))
}
