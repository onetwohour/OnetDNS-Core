# Command-line reference

The executable starts a DNS server with `run` and provides administration commands through `--cli`. `--cli query` sends a direct upstream query; it does not query the running local listener.

## Starting the server

| Command | Behavior |
| --- | --- |
| `OnetDNS` | Start DNS and the local dashboard with default config discovery. |
| `OnetDNS run --config PATH` | Start using an explicit TOML file. |
| `OnetDNS --no-web` | Headless mode when no explicit control listener overrides it. |
| `OnetDNS --help` | Show command syntax and switches. |
| `OnetDNS service install --config PATH` | Register a service at boot, appropriate privileges required. |
| `OnetDNS service uninstall` | Remove the service registration. |

OnetDNS normally starts a supervisor and DNS worker. `--no-supervisor` is a lifecycle switch for environments that supply their own supervision, not a DNS performance setting.

## Configuration and diagnostics

```sh
OnetDNS --cli check --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli services
OnetDNS --cli query example.com --type AAAA
```

`--cli query` bypasses the running server’s filters, ACLs, client policy, and cache. Use `dig @SERVER NAME TYPE` to exercise its DNS listener.

## Commands that contact the running control server

```sh
OnetDNS --cli stats  --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli top    --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli reload --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli block  ads.example --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli allow  needed.example --config /etc/OnetDNS/OnetDNS.toml
```

For applicable commands, `--url URL` and `--token TOKEN` specify the control endpoint and credential. Treat tokens like passwords, especially in shell history, logs and shared process listings. The running control endpoint is separate from the DNS listening addresses.

## Certificates and users

```sh
OnetDNS --cli cert --host dns.example.com --cert-out cert.pem --key-out key.pem
OnetDNS --cli passwd --name operator
```

The first command creates certificate material for the named host; the second prompts for a password and constructs a user-entry representation for configuration. Verify resulting file permissions and follow the CLI output. User/account provisioning is separate from enabling the public DNS resolver.

## Updates

```sh
OnetDNS --cli update --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli update apply --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli update rollback --config /etc/OnetDNS/OnetDNS.toml
```

`update` checks, `apply` installs an available signed release and `rollback` reinstalls the prior version replaced by the last update. The CLI may require restarting the running service after an update. Self-built executables are not guaranteed to participate in the signed-release update channel.

## Which command to use

| Goal | Use |
| --- | --- |
| Validate a TOML file | `--cli check` |
| Test an external upstream in isolation | `--cli query` |
| Test the running filter and DNS listener | `dig @SERVER NAME TYPE` |
| Inspect statistics / high-volume names | `--cli stats`, `--cli top` |
| Apply configuration changes through control API | `--cli reload` |
| Inspect service startup errors | Platform service logs |

The management API endpoints are documented in [API.md](API.md).
