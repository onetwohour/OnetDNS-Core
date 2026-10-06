/*!
 * @brief 관리 API: 이 기계의 네트워크 설정, 부팅 서비스, 자체 업데이트.
 */

use super::*;

impl ControlDeps {
    /** @brief 시스템 DNS 설정을 바꾸기 전에 원래 값을 적어 둘 디렉터리. 설정 파일 옆이다. */
    fn osnet_backup_dir(&self) -> PathBuf {
        self.config_path
            .as_ref()
            .and_then(|p| p.parent())
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /** @brief 이 기계의 DNS 서버 설정을 바꾼다. 원래 값은 백업해 둔다. */
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

    /** @brief 부팅 서비스를 등록하거나 제거한다. */
    #[cfg(windows)]
    pub(super) fn boot_service_set(&self, body: &str) -> Result<String, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Invalid JSON request body: {e}"))?;
        let action = j
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or("`action` must be install or uninstall")?;
        /*
         * 서비스로 뜰 때도 지금 쓰는 설정 파일을 그대로 읽어야 한다. 넘기지 않으면 부팅 뒤에 기본
         * 설정으로 떠서 지금 화면에 보이는 것과 다르게 돈다.
         */
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

    /** @brief 이 기계의 DNS 서버 설정을 백업에서 되돌린다. */
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

    /** @brief 자체 업데이트 상태. */
    pub(super) fn update_status(&self) -> String {
        crate::update::task::status_json(self.runtime_cfg.load().release_check)
    }

    /** @brief 새 릴리스를 확인하는 작업을 시작한다. */
    pub(super) fn update_check(&self) -> Result<String, String> {
        crate::update::task::participation()?;
        let running = crate::update::task::begin(crate::update::task::Task::Check)?;
        let resolver = self.blocklist_resolver.clone();
        start_update_job(&self.jobs, running, move |running| {
            crate::update::task::check(running, &resolver)
                .map(|finding| crate::update::task::describe(&finding))
        })
    }

    /** @brief 마지막 확인에서 찾은 버전을 설치하는 작업을 시작한다. */
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

    /** @brief 확정된 업데이트를 되돌리는 작업을 시작한다. */
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

/** @brief 이 기계의 네트워크 어댑터와 어댑터마다의 DNS 서버. */
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

/** @brief 이 기계의 방화벽에 포트를 열거나 그 규칙을 지운다. */
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

/** @brief 부팅 서비스 등록 상태. */
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

/** @brief 부팅 서비스 등록 상태. Windows 가 아니면 지원하지 않는다고 답한다. */
#[cfg(not(windows))]
pub(super) fn boot_service_status() -> String {
    "{\"supported\":false,\"installed\":false,\"running\":false}".to_string()
}

/** @brief 부팅 서비스 등록은 Windows 에서만 할 수 있어 거절한다. */
#[cfg(not(windows))]
pub(super) fn boot_service_set(_body: &str) -> Result<String, String> {
    Err("Boot-time service registration is available only on Windows".to_string())
}

/**
 * @brief 업데이트 작업을 작업 목록에 올리고 따로 띄운 스레드에서 돌린다.
 * @details 이 스레드는 세대가 끝날 때 기다리는 목록에 넣지 않는다. 세대를 바꾸는 동안에는 DNS 가
 *          멈춰 있는데, 실행 파일을 받느라 몇 분 걸릴 수 있는 작업을 그동안 기다리지 않으려는
 *          것이다. 업데이트 작업 표는 스레드가 쥐고 있다가 작업 목록에 결과를 적기 전에 놓는다.
 *          관리 화면은 작업이 끝난 것을 보자마자 다음 작업을 요청할 수 있어야 한다.
 * @return 시작한 작업. 작업을 올리지 못하면 표를 바로 놓고 실패한다.
 */
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
