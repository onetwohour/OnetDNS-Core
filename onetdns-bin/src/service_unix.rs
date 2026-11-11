//! Registers OnetDNS with systemd or launchd so it starts at boot.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::atomic_file::with_rollback_result;
use crate::error::BoxResult;

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "onetdns";
#[cfg(target_os = "linux")]
const DEFINITION_PATH: &str = "/etc/systemd/system/onetdns.service";
#[cfg(target_os = "linux")]
const START_COMMAND: &str = "sudo systemctl start onetdns";

#[cfg(any(target_os = "macos", test))]
const LAUNCHD_LABEL: &str = "com.onetdns.server";
#[cfg(target_os = "macos")]
const SERVICE_NAME: &str = LAUNCHD_LABEL;
#[cfg(target_os = "macos")]
const DEFINITION_PATH: &str = "/Library/LaunchDaemons/com.onetdns.server.plist";
#[cfg(target_os = "macos")]
const START_COMMAND: &str =
    "sudo launchctl bootstrap system /Library/LaunchDaemons/com.onetdns.server.plist";

pub(crate) fn install(config: Option<PathBuf>) -> BoxResult<String> {
    require_root("Installing")?;
    // A system service has no user home, so the default config path would not be this user's.
    let config =
        config.ok_or("Pass --config with the configuration file the service should use")?;
    let config = std::fs::canonicalize(&config)
        .map_err(|error| format!("Could not open {}: {error}", config.display()))?;
    let executable = std::env::current_exe()?;
    let text = definition(utf8(&executable)?, utf8(&config)?)?;

    let path = Path::new(DEFINITION_PATH);
    write_new(path, &text)?;
    if let Err(error) = register() {
        let removed = std::fs::remove_file(path).map_err(|error| error.to_string());
        return Err(with_rollback_result(
            error,
            "Could not remove the service definition",
            removed,
        )
        .into());
    }
    Ok(format!(
        "Installed service '{SERVICE_NAME}'; it starts automatically from the next boot. To start it now, run: {START_COMMAND}"
    ))
}

pub(crate) fn uninstall() -> BoxResult<String> {
    require_root("Removing")?;
    let path = Path::new(DEFINITION_PATH);
    if !path.exists() {
        return Err("The service is not installed".into());
    }
    unregister()?;
    std::fs::remove_file(path)
        .map_err(|error| format!("Could not remove {}: {error}", path.display()))?;
    forget()?;
    Ok(format!("Removed service '{SERVICE_NAME}'"))
}

fn require_root(action: &str) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(format!(
            "{action} the service needs root; run it again with sudo"
        ))
    }
}

fn utf8(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("The path is not valid UTF-8: {}", path.display()))
}

fn write_new(path: &Path, text: &str) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => {
                "A service with the same name is already installed".to_string()
            }
            _ => format!("Could not write {}: {error}", path.display()),
        })?;
    if let Err(error) = file.write_all(text.as_bytes()) {
        let removed = std::fs::remove_file(path).map_err(|error| error.to_string());
        return Err(with_rollback_result(
            format!("Could not write {}: {error}", path.display()),
            "Could not remove the partial file",
            removed,
        ));
    }
    Ok(())
}

fn run(tool: &str, mut command: Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("Could not run {tool}: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{tool} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(target_os = "linux")]
use self::systemd_unit as definition;

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<(), String> {
    let program = crate::osnet::resolve_tool("systemctl")
        .ok_or("systemctl was not found; OnetDNS registers a Linux service only with systemd")?;
    let mut command = Command::new(program);
    command.args(args);
    crate::osnet::harden_child_env(&mut command);
    run("systemctl", command)
}

#[cfg(target_os = "linux")]
fn register() -> Result<(), String> {
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", SERVICE_NAME])
}

#[cfg(target_os = "linux")]
fn unregister() -> Result<(), String> {
    systemctl(&["disable", "--now", SERVICE_NAME])
}

#[cfg(target_os = "linux")]
fn forget() -> Result<(), String> {
    systemctl(&["daemon-reload"])
}

#[cfg(target_os = "macos")]
use self::launchd_plist as definition;

#[cfg(target_os = "macos")]
fn launchctl(args: &[&str]) -> Result<(), String> {
    let mut command = Command::new("/bin/launchctl");
    command.args(args).env_clear();
    run("launchctl", command)
}

/// launchd reads the folder at boot.
#[cfg(target_os = "macos")]
fn register() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn unregister() -> Result<(), String> {
    let target = format!("system/{LAUNCHD_LABEL}");
    if launchctl(&["print", &target]).is_err() {
        // Not loaded: installed but never started.
        return Ok(());
    }
    launchctl(&["bootout", &target])
}

#[cfg(target_os = "macos")]
fn forget() -> Result<(), String> {
    Ok(())
}

fn reject_control_characters(value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!(
            "A path with control characters cannot go in a service definition: {value:?}"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn systemd_quote(value: &str) -> Result<String, String> {
    reject_control_characters(value)?;
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    Ok(format!("\"{escaped}\""))
}

/// The supervisor stays the main process across updates, so the default service type fits.
#[cfg(any(target_os = "linux", test))]
fn systemd_unit(executable: &str, config: &str) -> Result<String, String> {
    let executable = systemd_quote(executable)?;
    // systemd expands `$` in arguments but not in the program path.
    let config = systemd_quote(config)?.replace('$', "$$");
    Ok(format!(
        "[Unit]\n\
         Description=OnetDNS ad-blocking DNS\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={executable} run --config {config}\n\
         Restart=on-failure\n\
         RestartSec=1\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    ))
}

#[cfg(any(target_os = "macos", test))]
fn xml_escape(value: &str) -> Result<String, String> {
    reject_control_characters(value)?;
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;"))
}

#[cfg(any(target_os = "macos", test))]
fn launchd_plist(executable: &str, config: &str) -> Result<String, String> {
    let executable = xml_escape(executable)?;
    let config = xml_escape(config)?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LAUNCHD_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{executable}</string>\n\
         \t\t<string>run</string>\n\
         \t\t<string>--config</string>\n\
         \t\t<string>{config}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<dict>\n\
         \t\t<key>SuccessfulExit</key>\n\
         \t\t<false/>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_starts_the_server_with_the_pinned_config() {
        let unit = systemd_unit("/opt/onetdns/OnetDNS", "/etc/onetdns/OnetDNS.toml").unwrap();
        assert!(
            unit.contains(
                "ExecStart=\"/opt/onetdns/OnetDNS\" run --config \"/etc/onetdns/OnetDNS.toml\"\n"
            ),
            "{unit}"
        );
        assert!(unit.contains("\n[Install]\nWantedBy=multi-user.target\n"));
    }

    #[test]
    fn systemd_specifiers_and_quotes_stay_literal() {
        assert_eq!(
            systemd_quote(r#"/a b/100%/"q"\z"#).unwrap(),
            r#""/a b/100%%/\"q\"\\z""#
        );
    }

    #[test]
    fn dollar_is_escaped_only_in_arguments() {
        let unit = systemd_unit("/opt/$x/OnetDNS", "/etc/$y.toml").unwrap();
        assert!(
            unit.contains("ExecStart=\"/opt/$x/OnetDNS\" run --config \"/etc/$$y.toml\"\n"),
            "{unit}"
        );
    }

    #[test]
    fn the_plist_escapes_xml_in_paths() {
        let plist = launchd_plist("/opt/a&b/OnetDNS", "/etc/<c>.toml").unwrap();
        assert!(plist.contains("<string>/opt/a&amp;b/OnetDNS</string>"));
        assert!(plist.contains("<string>/etc/&lt;c&gt;.toml</string>"));
    }

    #[test]
    fn a_newline_cannot_inject_a_directive() {
        assert!(systemd_unit("/a\nExecStartPre=/evil", "/c").is_err());
        assert!(launchd_plist("/a", "/c\n</string>").is_err());
    }

    #[test]
    fn an_existing_definition_is_left_alone() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-service-{}-{:x}",
            std::process::id(),
            u64::from_ne_bytes(onetdns_core::random_array())
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("onetdns.service");

        write_new(&path, "first").unwrap();
        let error = write_new(&path, "second").unwrap_err();

        assert!(error.contains("already installed"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
