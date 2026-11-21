# Installation and service management

Install the binary, choose a configuration path, and register a service with the operating system. First-run account setup is covered in [Getting started](getting-started.md).

## Download and verify your platform

Download an archive from [Releases](https://github.com/onetwohour/OnetDNS-Core/releases). Binaries are available for Linux, macOS, and Windows; select the archive for the host architecture. Extract the executable to a stable path readable by its service account.

| Platform | Executable | Service manager |
| --- | --- | --- |
| Linux | `OnetDNS` | systemd |
| macOS | `OnetDNS` | launchd |
| Windows | `OnetDNS.exe` | Windows Service Control Manager |

Check available commands with `OnetDNS --help`. Use the exact executable path from your release; examples assume it is in `PATH` or the working directory.

## Configuration discovery

Without `--config`, OnetDNS uses its user configuration directory and creates `OnetDNS.toml` if needed. The common paths are:

| Platform | Typical path |
| --- | --- |
| Windows | `%APPDATA%\OnetDNS\OnetDNS.toml` |
| Linux/macOS | `$XDG_CONFIG_HOME/OnetDNS/OnetDNS.toml`, or `~/.config/OnetDNS/OnetDNS.toml` |

For services, specify an absolute configuration path. Service accounts often use a different home directory from an interactive shell. For example, a Linux deployment may place its own file at `/etc/OnetDNS/OnetDNS.toml`; this is an operator choice, not the automatic user config location.

Check the file before starting a service:

```sh
OnetDNS --cli check --config /etc/OnetDNS/OnetDNS.toml
```

The checker validates the configuration file. Binding, permissions, and upstream connectivity are verified at runtime.

## Ports, capabilities and conflicts

The built-in plain DNS listener is `127.0.0.1:53`, so a default run usually needs to bind both TCP and UDP port 53. On Linux, binding a port below 1024 ordinarily requires root or the appropriate capability. The dashboard's default loopback HTTP port is 8553. Encrypted listeners are off until configured and require their own ports and certificates.

Before launch on Linux:

```sh
sudo ss -lntup | grep -E '(:53|:8553)'
```

On macOS use `sudo lsof -nP -i :53`; on Windows use `netstat -ano` and correlate the PID with Task Manager or PowerShell. When another local DNS service owns port 53, decide whether to change the existing service or bind OnetDNS to another address/port. Do not disable a system resolver blindly: first check whether the host depends on it for DNS.

## Run in the foreground

```sh
OnetDNS run --config /absolute/path/OnetDNS.toml
```

The foreground mode is useful for the initial setup, diagnostics and testing changes. `OnetDNS --no-web` starts headless when no explicit `control_listen` overrides that choice. For routine operation under systemd or another service manager, use the service registration command below.

## Install a system service

### Linux (systemd)

```sh
sudo /path/to/OnetDNS service install --config /etc/OnetDNS/OnetDNS.toml
sudo systemctl status onetdns
sudo journalctl -u onetdns -n 100 --no-pager
```

The registration command sets up a systemd unit for startup at boot. To remove the registration, use `sudo /path/to/OnetDNS service uninstall`; this does not mean you should delete configuration and list files. Before modifying permissions or service ownership, confirm which account the unit actually uses.

### macOS (launchd)

```sh
sudo /path/to/OnetDNS service install --config /absolute/path/OnetDNS.toml
```

Use an absolute path to both binary and configuration. Check launchd service logs and port ownership if it fails to start.

### Windows

From an elevated PowerShell or Command Prompt:

```powershell
C:\OnetDNS\OnetDNS.exe service install --config C:\OnetDNS\OnetDNS.toml
```

Service registration needs administrative rights. Installing a service and binding port 53 are distinct privilege questions on Windows.

## Why two OnetDNS processes may be visible

Normal `run` mode starts a supervisor which launches the DNS worker with `--no-supervisor`. A typical Linux status output can therefore show **one supervisor PID and one worker PID in the same service**. That does not mean two independent servers are binding every DNS socket. Check `ps -o pid,ppid,args -C OnetDNS` to confirm parent/child relationships.

Do not pass the internal `--no-supervisor` argument as a generic tuning option; it changes lifecycle and update handling. It may be appropriate when an external supervisor deliberately takes responsibility for restarting the process.

## Build from source

The workspace specifies Rust 1.88 or newer:

```sh
cargo build --release
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

The resulting executable is `target/release/OnetDNS`. The dashboard can be excluded from a build using `cargo build --release --no-default-features`. A local source build may differ from a signed release in update behavior; do not assume self-update is supported for arbitrary builds.

## After installation

Continue to [Getting started](getting-started.md) for the setup account and first query, then [Operations](operations.md) for logging, updates, backups and resource monitoring.
