//! OS DNS settings and firewall rules, so the dashboard can point this machine's DNS at this server
//! and back. Each platform has its own implementation.
//!
//! The original values are backed up first, together with the adapter they belong to; restoring
//! another adapter's backup would cut the network. External commands run with a fixed path and
//! environment, or a fake executable planted in PATH would run with this server's privileges.

use std::path::Path;

// Only Windows and Linux are implemented; elsewhere every call returns an unsupported error.
// Imports used only by the implementations share their cfg, plus test, since tests call the backup
// helpers.
#[cfg(any(test, windows, target_os = "linux"))]
use sha2::{Digest, Sha256};
#[cfg(any(test, windows, target_os = "linux"))]
use std::path::PathBuf;
#[cfg(any(windows, target_os = "linux"))]
use std::process::Command;

#[cfg(any(test, windows, target_os = "linux"))]
const MAX_OS_NETWORK_FILE: u64 = 1024 * 1024;

#[cfg(any(test, windows, target_os = "linux"))]
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

pub struct Adapter {
    pub name: String,
    pub dns: Vec<String>,
}

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
/// Searches fixed system directories only; following PATH would let a fake executable placed
/// earlier run with this server's privileges.
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
/// Clears preload variables and library paths, which would otherwise load foreign code into the
/// system tools this server runs.
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
fn windows_system_directory() -> Option<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
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
        /// No console window when running as a service.
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
/// Replacing unusable characters can map different adapters to one name, so a hash of the original
/// name is appended.
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
fn backup_adapter_id(adapter: &str) -> String {
    adapter
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(any(test, windows, target_os = "linux"))]
fn backup_blob(adapter: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("ONETDNS-DNS-BACKUP\n{}\n", backup_adapter_id(adapter)).into_bytes();
    out.extend_from_slice(data);
    out
}

#[cfg(any(test, windows, target_os = "linux"))]
/// The adapter recorded inside must match the requested one; restoring another adapter's settings
/// would cut the network.
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
/// Replaced atomically, so an interruption leaves no partial file.
fn write_backup_atomic(path: &Path, adapter: &str, data: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Could not create the backup directory: {e}"))?;
    }
    crate::atomic_file::atomic_write(path, &backup_blob(adapter, data))
        .map_err(|e| format!("Could not write the DNS backup: {e}"))
}

#[cfg(any(windows, target_os = "linux"))]
/// Only when none exists, so the original values are never overwritten.
fn ensure_backup(path: &Path, adapter: &str, data: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    write_backup_atomic(path, adapter, data)
}

#[cfg(any(windows, target_os = "linux"))]
fn valid_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(windows)]
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
/// Re-decodes text that arrived as Latin-1 but was UTF-8; tool output sometimes comes in the wrong
/// encoding.
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
fn windows_current_dns(adapter: &str) -> Vec<String> {
    list_adapters()
        .ok()
        .and_then(|a| a.into_iter().find(|x| x.name == adapter).map(|x| x.dns))
        .unwrap_or_default()
}

#[cfg(windows)]
/// Only existing adapters are accepted; an unchecked name could smuggle extra command arguments.
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
/// Backs up the original first; nothing changes without a backup to restore from.
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
/// Uses the system's DNS management tool when present, and edits the resolver config file
/// otherwise. The backup records which, so the restore uses the same method.
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
pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    Err("Listing network adapters is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn set_dns(_adapter: &str, _servers: &[String], _backup_dir: &Path) -> Result<(), String> {
    Err("Changing the system DNS settings is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn restore_dns(_adapter: &str, _backup_dir: &Path) -> Result<(), String> {
    Err("Restoring the system DNS settings is not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn firewall_allow(_udp: bool, _tcp: bool, _port: u16) -> Result<(), String> {
    Err("Firewall settings are not supported on this platform".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn firewall_remove(_port: u16) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// A collision would restore another adapter's settings.
    fn backup_names_do_not_collide_after_sanitizing_adapter_names() {
        let dir = Path::new("backup");
        assert_ne!(
            backup_file(dir, "Ethernet-2"),
            backup_file(dir, "Ethernet_2")
        );
    }

    #[test]
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
