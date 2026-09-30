/*!
 * @brief 운영체제의 DNS 설정과 방화벽 조작.
 *
 * @details 대시보드에서 이 기계의 DNS를 이 서버로 돌리고 되돌리는 기능이다. 플랫폼마다
 *          방법이 달라 각각 구현한다.
 * @warning 바꾸기 전에 원래 값을 백업하고, 백업에는 어느 어댑터의 것인지 함께 적는다.
 *          적지 않으면 다른 어댑터의 백업으로 복원해 망을 끊는다.
 * @note 외부 명령을 부를 때 경로와 환경을 고정한다. 고정하지 않으면 경로에 심어 둔 가짜
 *       실행 파일이 이 서버의 권한으로 돌아간다.
 */

use std::path::Path;

/* 이 모듈의 실제 구현은 windows 와 linux 뿐이고, 나머지 플랫폼은 지원하지 않는다는
 * 오류만 돌려준다. 그래서 구현에서만 쓰는 이름은 같은 조건으로 들여와야 한다. 백업
 * 관련 이름은 시험이 직접 부르므로 test 도 함께 연다. */
#[cfg(any(test, windows, target_os = "linux"))]
use sha2::{Digest, Sha256};
#[cfg(any(test, windows, target_os = "linux"))]
use std::path::PathBuf;
#[cfg(any(windows, target_os = "linux"))]
use std::process::Command;

#[cfg(any(test, windows, target_os = "linux"))]
/** @brief 읽어들일 시스템 파일 크기 상한. */
const MAX_OS_NETWORK_FILE: u64 = 1024 * 1024;

#[cfg(any(test, windows, target_os = "linux"))]
/** @brief 크기 상한을 걸어 파일을 읽는다. */
fn read_text_limited(path: &Path) -> std::io::Result<String> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_OS_NETWORK_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OS_NETWORK_FILE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    String::from_utf8(bytes).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

/** @brief 네트워크 어댑터 하나와 거기 설정된 DNS. */
pub struct Adapter {
    /** @brief 어댑터 이름. */
    pub name: String,
    /** @brief 이 어댑터에 설정된 DNS 서버. */
    pub dns: Vec<String>,
}

/** @brief 지금 플랫폼 이름. */
pub fn platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

#[cfg(any(windows, target_os = "linux"))]
/**
 * @brief 시스템 도구의 전체 경로를 찾는다.
 * @warning 정해진 시스템 디렉터리에서만 찾는다. 경로 환경 변수를 따르면 앞자리에 놓인
 *          가짜 실행 파일이 이 서버의 권한으로 돌아간다.
 */
pub(crate) fn resolve_tool(name: &str) -> Option<std::ffi::OsString> {
    #[cfg(target_os = "linux")]
    {
        for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
            let cand = Path::new(dir).join(name);
            if cand.is_file() {
                return Some(cand.into_os_string());
            }
        }
    }
    #[cfg(windows)]
    {
        let system = windows_system_directory()?;
        for dir in [system.clone(), system.join(r"WindowsPowerShell\v1.0")] {
            let cand = dir.join(format!("{name}.exe"));
            if cand.is_file() {
                return Some(cand.into_os_string());
            }
        }
    }
    let _ = name;
    None
}

#[cfg(any(windows, target_os = "linux"))]
/**
 * @brief 자식 프로세스의 환경을 고정한다.
 * @warning 미리 로드 변수와 라이브러리 경로를 지운다. 남겨 두면 이 서버가 부른 시스템
 *          도구에 남의 코드가 담긴다.
 */
pub(crate) fn harden_child_env(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        command.env_remove("LD_PRELOAD");
        command.env_remove("LD_LIBRARY_PATH");
        command.env_remove("IFS");
    }
    #[cfg(windows)]
    {
        let Some(sys32) = windows_system_directory() else {
            command.env_clear();
            return;
        };
        let windows_dir = sys32.parent().unwrap_or(&sys32);
        command.env_clear();
        command.env("SystemRoot", windows_dir);
        command.env("WINDIR", windows_dir);
        command.env("PATHEXT", ".COM;.EXE;.BAT;.CMD");
        command.env(
            "PATH",
            format!(
                "{};{}",
                sys32.display(),
                sys32.join(r"WindowsPowerShell\v1.0").display()
            ),
        );
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = command;
    }
}

#[cfg(windows)]
/** @brief 시스템 디렉터리 경로. */
fn windows_system_directory() -> Option<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
        /** @brief 시스템 디렉터리 경로를 가져온다. */
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16(&buffer[..length]).ok()?))
}

#[cfg(any(windows, target_os = "linux"))]
/** @brief 시스템 도구를 부르고 출력을 받는다. 실패하면 사유를 담아 돌려준다. */
fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let Some(exe) = resolve_tool(cmd) else {
        return Err(format!(
            "Could not find the `{cmd}` executable in a trusted system path"
        ));
    };
    let mut command = Command::new(exe);
    command.args(args);
    harden_child_env(&mut command);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        /** @brief 창 없이 실행한다. 서비스로 돌 때 창이 뜨면 안 된다. */
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let out = command
        .output()
        .map_err(|e| format!("Could not run {cmd}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let so = String::from_utf8_lossy(&out.stdout);
        let msg = if err.trim().is_empty() {
            so.trim()
        } else {
            err.trim()
        };
        return Err(format!("{cmd} failed: {msg}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "linux")]
/** @brief 이 도구가 쓸 수 있는지. */
fn have(cmd: &str) -> bool {
    let Some(exe) = resolve_tool(cmd) else {
        return false;
    };
    let mut command = Command::new(exe);
    command.arg("--version");
    harden_child_env(&mut command);
    command
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(any(test, windows, target_os = "linux"))]
/**
 * @brief 이 어댑터의 백업 파일 경로.
 * @warning 이름에서 못 쓰는 문자를 바꾸면 서로 다른 어댑터가 같은 이름이 된다. 그래서
 *          원래 이름의 요약값을 뒤에 붙인다.
 */
fn backup_file(dir: &Path, adapter: &str) -> PathBuf {
    let mut safe: String = adapter
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    if safe.is_empty() {
        safe.push_str("adapter");
    }
    let digest = Sha256::digest(adapter.as_bytes());
    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    dir.join(format!("dns-backup-{safe}-{suffix}.txt"))
}

#[cfg(any(test, windows, target_os = "linux"))]
/** @brief 백업 안에 적을 어댑터 식별자. */
fn backup_adapter_id(adapter: &str) -> String {
    adapter
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(any(test, windows, target_os = "linux"))]
/** @brief 어댑터 식별자를 앞에 붙인 백업 내용. */
fn backup_blob(adapter: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("ONETDNS-DNS-BACKUP\n{}\n", backup_adapter_id(adapter)).into_bytes();
    out.extend_from_slice(data);
    out
}

#[cfg(any(test, windows, target_os = "linux"))]
/**
 * @brief 백업을 읽는다.
 * @warning 안에 적힌 어댑터가 요청한 것과 같아야 한다. 다르면 남의 설정으로 복원해
 *          망을 끊는다.
 */
fn read_backup(path: &Path, adapter: &str) -> Result<String, String> {
    let text = read_text_limited(path)
        .map_err(|error| format!("Could not read the DNS backup file to restore: {error}"))?;
    let Some(rest) = text.strip_prefix("ONETDNS-DNS-BACKUP\n") else {
        return Err("DNS backup file is malformed".to_string());
    };
    let Some((stored_adapter, data)) = rest.split_once('\n') else {
        return Err("DNS backup file has no adapter identifier".to_string());
    };
    if stored_adapter != backup_adapter_id(adapter) {
        return Err("DNS backup file is not for the requested network adapter".to_string());
    }
    Ok(data.to_string())
}

#[cfg(any(windows, target_os = "linux"))]
/** @brief 백업을 원자적으로 교체해 기록한다. 중간에 끊겨도 반쪽 파일이 남지 않는다. */
fn write_backup_atomic(path: &Path, adapter: &str, data: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Could not create the backup directory: {e}"))?;
    }
    crate::atomic_file::atomic_write(path, &backup_blob(adapter, data))
        .map_err(|e| format!("Could not write the DNS backup: {e}"))
}

#[cfg(any(windows, target_os = "linux"))]
/** @brief 백업이 없을 때만 만든다. 이미 있으면 원래 값을 덮지 않는다. */
fn ensure_backup(path: &Path, adapter: &str, data: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    write_backup_atomic(path, adapter, data)
}

#[cfg(any(windows, target_os = "linux"))]
/** @brief 올바른 IP 주소 표기인지. */
fn valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(windows)]
/** @brief 어댑터와 각각의 DNS 설정 목록. */
pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    let nonce = u64::from_le_bytes(onetdns_core::try_random_array::<8>().map_err(|error| {
        format!("Could not get random bytes for the adapter temporary file: {error}")
    })?);
    let tmp = std::env::temp_dir().join(format!(
        "onetdns-adapters-{}-{nonce:016x}.json",
        std::process::id()
    ));
    let tmp_lit = tmp.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$j = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress; [System.IO.File]::WriteAllText('{tmp_lit}', $j, (New-Object System.Text.UTF8Encoding $false))"
    );
    run(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )?;
    let out = read_text_limited(&tmp)
        .map_err(|e| format!("Could not read the adapter temporary file: {e}"));
    let _ = std::fs::remove_file(&tmp);
    parse_windows_adapters(&out?)
}

#[cfg(windows)]
/** @brief 깨진 글자를 되살린다. 도구 출력의 인코딩이 어긋날 때가 있다. */
fn fix_mojibake(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| (c as u32) > 0xFF) {
        return s.to_string();
    }
    let bytes: Vec<u8> = s.chars().map(|c| c as u8).collect();
    match std::str::from_utf8(&bytes) {
        Ok(d) if d.chars().any(|c| (c as u32) > 0x7F) => d.to_string(),
        _ => s.to_string(),
    }
}

#[cfg(windows)]
/** @brief 도구가 내놓은 JSON에서 어댑터 목록을 읽는다. */
fn parse_windows_adapters(json: &str) -> Result<Vec<Adapter>, String> {
    use onetdns_core::json::Json;
    let parsed = onetdns_core::json::parse(json.trim_start_matches('\u{feff}').trim())
        .map_err(|e| format!("Could not parse the adapter JSON: {e}"))?;
    let items: Vec<&Json> = match &parsed {
        Json::Arr(a) => a.iter().collect(),
        other => vec![other],
    };
    let mut out = Vec::new();
    for it in items {
        let name = fix_mojibake(
            it.get("InterfaceAlias")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        if name.is_empty() {
            continue;
        }
        let dns = match it.get("ServerAddresses") {
            Some(Json::Arr(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(Json::Str(s)) => vec![s.clone()],
            _ => vec![],
        };
        out.push(Adapter { name, dns });
    }
    Ok(out)
}

#[cfg(windows)]
/** @brief 이 어댑터에 지금 설정된 DNS. */
fn windows_current_dns(adapter: &str) -> Vec<String> {
    list_adapters()
        .ok()
        .and_then(|a| a.into_iter().find(|x| x.name == adapter).map(|x| x.dns))
        .unwrap_or_default()
}

#[cfg(windows)]
/**
 * @brief 이 어댑터 이름을 그대로 명령에 넘겨도 되는지.
 * @warning 실제로 있는 어댑터만 받아들인다. 확인 없이 넘기면 이름 인자에 끼워 넣은
 *          문자열이 명령 인자가 된다.
 */
fn validate_windows_adapter(adapter: &str) -> Result<(), String> {
    if adapter.is_empty() || adapter.chars().count() > 256 || adapter.chars().any(char::is_control)
    {
        return Err("Invalid network adapter name".to_string());
    }
    if !list_adapters()?.iter().any(|item| item.name == adapter) {
        return Err(format!("Network adapter does not exist: {adapter}"));
    }
    Ok(())
}

#[cfg(windows)]
/** @brief 이 어댑터의 DNS를 지정한 목록으로 바꾼다. */
fn windows_apply_dns(adapter: &str, servers: &[String]) -> Result<(), String> {
    if servers.is_empty() || servers.iter().any(|server| !valid_ip(server)) {
        return Err("Enter at least one DNS server address as a valid IP address".to_string());
    }
    run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={adapter}"),
            "static",
            servers.first().map(String::as_str).unwrap_or("127.0.0.1"),
            "primary",
        ],
    )?;
    for (i, s) in servers.iter().enumerate().skip(1) {
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "dnsservers",
                &format!("name={adapter}"),
                s,
                &format!("index={}", i + 1),
            ],
        )?;
    }
    Ok(())
}

#[cfg(windows)]
/**
 * @brief 시스템 DNS를 이 서버로 돌린다.
 * @details 바꾸기 전에 원래 값을 백업한다. 되돌릴 수 없으면 바꾸지 않는다.
 */
pub fn set_dns(adapter: &str, servers: &[String], backup_dir: &Path) -> Result<(), String> {
    validate_windows_adapter(adapter)?;
    if servers.is_empty() || servers.iter().any(|server| !valid_ip(server)) {
        return Err("Enter at least one DNS server address as a valid IP address".to_string());
    }

    let original: Vec<String> = windows_current_dns(adapter)
        .into_iter()
        .filter(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| !ip.is_loopback())
                .unwrap_or(false)
        })
        .collect();

    ensure_backup(
        &backup_file(backup_dir, adapter),
        adapter,
        original.join("\n").as_bytes(),
    )?;
    windows_apply_dns(adapter, servers)
}

#[cfg(windows)]
/** @brief 백업해 둔 원래 DNS로 되돌린다. */
pub fn restore_dns(adapter: &str, backup_dir: &Path) -> Result<(), String> {
    validate_windows_adapter(adapter)?;
    let path = backup_file(backup_dir, adapter);
    let backup = read_backup(&path, adapter)?;
    let servers: Vec<String> = backup
        .lines()
        .map(str::trim)
        .filter(|s| valid_ip(s))
        .map(str::to_string)
        .collect();
    if servers.is_empty() {
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                &format!("name={adapter}"),
                "dhcp",
            ],
        )?;
    } else {
        windows_apply_dns(adapter, &servers)?;
    }
    if let Err(e) = std::fs::remove_file(&path) {
        onetdns_core::warn!(event = "osnet.backup_cleanup_failed", path = %path.display(), error = %e, "Could not delete the restored DNS backup file; the next restore will write this stale value again");
    }
    Ok(())
}

#[cfg(windows)]
/** @brief 이 포트를 방화벽에서 연다. */
pub fn firewall_allow(udp: bool, tcp: bool, port: u16) -> Result<(), String> {
    let _ = firewall_remove(port);
    if udp {
        run(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=OnetDNS-{port}-UDP"),
                "dir=in",
                "action=allow",
                "protocol=UDP",
                &format!("localport={port}"),
            ],
        )?;
    }
    if tcp {
        run(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name=OnetDNS-{port}-TCP"),
                "dir=in",
                "action=allow",
                "protocol=TCP",
                &format!("localport={port}"),
            ],
        )?;
    }
    Ok(())
}

#[cfg(windows)]
/** @brief 이 서버가 넣은 방화벽 규칙을 지운다. */
pub fn firewall_remove(port: u16) -> Result<(), String> {
    let _ = run(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name=OnetDNS-{port}-UDP"),
        ],
    );
    let _ = run(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name=OnetDNS-{port}-TCP"),
        ],
    );
    Ok(())
}

#[cfg(target_os = "linux")]
/** @brief 시스템 해석 설정에 적힌 DNS. */
fn resolv_conf_dns() -> Vec<String> {
    read_text_limited(Path::new("/etc/resolv.conf"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| valid_ip(s))
        .collect()
}

#[cfg(target_os = "linux")]
/** @brief 어댑터와 각각의 DNS 설정 목록. */
pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    let dns = resolv_conf_dns();
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == "lo" {
                continue;
            }
            out.push(Adapter {
                name,
                dns: dns.clone(),
            });
        }
    }

    out.push(Adapter {
        name: "system".to_string(),
        dns,
    });
    Ok(out)
}

#[cfg(target_os = "linux")]
/**
 * @brief 시스템 DNS를 이 서버로 돌린다.
 * @details 관리 도구가 있으면 그것을 쓰고, 없으면 해석 설정 파일을 직접 고친다. 어느
 *          쪽을 썼는지 백업에 남겨야 되돌릴 때 같은 방법을 쓴다.
 */
pub fn set_dns(adapter: &str, servers: &[String], backup_dir: &Path) -> Result<(), String> {
    if servers.iter().any(|s| !valid_ip(s)) {
        return Err("Invalid DNS server address".to_string());
    }

    if adapter != "system" && have("resolvectl") {
        let marker = backup_file(backup_dir, adapter);
        write_backup_atomic(&marker, adapter, b"resolvectl")?;
        let mut args = vec!["dns", adapter];
        let refs: Vec<&str> = servers.iter().map(String::as_str).collect();
        args.extend(refs);
        if let Err(e) = run("resolvectl", &args) {
            if let Err(cleanup) = std::fs::remove_file(&marker) {
                onetdns_core::warn!(event = "osnet.backup_cleanup_failed", path = %marker.display(), error = %cleanup, "Could not delete the failed-apply marker file; the next restore will try to revert settings that were never changed");
            }
            return Err(e);
        }
        return Ok(());
    }

    let path = "/etc/resolv.conf";
    let cur = read_text_limited(Path::new(path)).map_err(|error| {
        format!("Could not read the current /etc/resolv.conf, so the DNS settings were not changed: {error}")
    })?;

    ensure_backup(&backup_file(backup_dir, "system"), "system", cur.as_bytes())?;
    let body: String = servers
        .iter()
        .map(|s| format!("nameserver {s}\n"))
        .collect();
    std::fs::write(path, body).map_err(|e| format!("Could not write /etc/resolv.conf: {e}"))
}

#[cfg(target_os = "linux")]
/** @brief 백업해 둔 원래 DNS로 되돌린다. */
pub fn restore_dns(adapter: &str, backup_dir: &Path) -> Result<(), String> {
    let marker = backup_file(backup_dir, adapter);
    if adapter != "system" && read_backup(&marker, adapter).ok().as_deref() == Some("resolvectl") {
        run("resolvectl", &["revert", adapter])?;
        if let Err(e) = std::fs::remove_file(&marker) {
            onetdns_core::warn!(event = "osnet.backup_cleanup_failed", path = %marker.display(), error = %e, "Could not delete the restored marker file; the next restore will write this stale value again");
        }
        return Ok(());
    }
    let sys = backup_file(backup_dir, "system");
    let saved = read_backup(&sys, "system")?;
    std::fs::write("/etc/resolv.conf", saved)
        .map_err(|e| format!("Could not restore /etc/resolv.conf: {e}"))?;
    if let Err(e) = std::fs::remove_file(&sys) {
        onetdns_core::warn!(event = "osnet.backup_cleanup_failed", path = %sys.display(), error = %e, "Could not delete the restored DNS backup file; the next restore will write this stale value again");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/** @brief 이 포트를 방화벽에서 연다. */
pub fn firewall_allow(udp: bool, tcp: bool, port: u16) -> Result<(), String> {
    let p = port.to_string();
    if have("ufw") {
        if udp {
            run("ufw", &["allow", &format!("{port}/udp")])?;
        }
        if tcp {
            run("ufw", &["allow", &format!("{port}/tcp")])?;
        }
        return Ok(());
    }
    if have("iptables") {
        let _ = firewall_remove(port);
        if udp {
            run(
                "iptables",
                &["-I", "INPUT", "-p", "udp", "--dport", &p, "-j", "ACCEPT"],
            )?;
        }
        if tcp {
            run(
                "iptables",
                &["-I", "INPUT", "-p", "tcp", "--dport", &p, "-j", "ACCEPT"],
            )?;
        }
        return Ok(());
    }
    Err("Could not find a supported firewall tool (ufw or iptables)".to_string())
}

#[cfg(target_os = "linux")]
/** @brief 이 서버가 넣은 방화벽 규칙을 지운다. */
pub fn firewall_remove(port: u16) -> Result<(), String> {
    let p = port.to_string();
    if have("ufw") {
        let _ = run("ufw", &["delete", "allow", &format!("{port}/udp")]);
        let _ = run("ufw", &["delete", "allow", &format!("{port}/tcp")]);
        return Ok(());
    }
    if have("iptables") {
        let _ = run(
            "iptables",
            &["-D", "INPUT", "-p", "udp", "--dport", &p, "-j", "ACCEPT"],
        );
        let _ = run(
            "iptables",
            &["-D", "INPUT", "-p", "tcp", "--dport", &p, "-j", "ACCEPT"],
        );
        return Ok(());
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
/** @brief 이 플랫폼에서는 지원하지 않는다. */
pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    Err("Listing network adapters is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
/** @brief 이 플랫폼에서는 지원하지 않는다. */
pub fn set_dns(_adapter: &str, _servers: &[String], _backup_dir: &Path) -> Result<(), String> {
    Err("Changing the system DNS settings is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
/** @brief 이 플랫폼에서는 지원하지 않는다. */
pub fn restore_dns(_adapter: &str, _backup_dir: &Path) -> Result<(), String> {
    Err("Restoring the system DNS settings is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
/** @brief 이 플랫폼에서는 지원하지 않는다. */
pub fn firewall_allow(_udp: bool, _tcp: bool, _port: u16) -> Result<(), String> {
    Err("Firewall settings are not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
/** @brief 이 플랫폼에서는 할 일이 없다. */
pub fn firewall_remove(_port: u16) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
/** @brief 백업 이름이 겹치지 않고, 백업이 원래 어댑터에 묶이는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 못 쓰는 문자를 바꾼 뒤에도 이름이 겹치지 않는지. 겹치면 남의 설정으로 복원한다. */
    fn backup_names_do_not_collide_after_sanitizing_adapter_names() {
        let dir = Path::new("backup");
        assert_ne!(
            backup_file(dir, "Ethernet-2"),
            backup_file(dir, "Ethernet_2")
        );
    }

    #[test]
    /** @brief 다른 어댑터의 백업으로 복원되지 않는지. */
    fn backup_payload_is_bound_to_the_original_adapter() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-osnet-backup-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(onetdns_core::random_array::<8>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = backup_file(&dir, "Ethernet-2");
        crate::atomic_file::atomic_write(&path, &backup_blob("Ethernet-2", b"1.1.1.1")).unwrap();

        assert_eq!(read_backup(&path, "Ethernet-2").unwrap(), "1.1.1.1");
        assert!(read_backup(&path, "Ethernet_2").is_err());

        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
