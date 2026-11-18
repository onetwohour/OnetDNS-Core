<div align="center">

# OnetDNS

An ad-blocking DNS server with a web dashboard, in one executable for Linux, Windows, and macOS.

<br>

[![Release](https://img.shields.io/github/v/release/onetwohour/OnetDNS-Core?style=for-the-badge&label=release&color=2563EB)](https://github.com/onetwohour/OnetDNS-Core/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/onetwohour/OnetDNS-Core/ci.yml?branch=main&style=for-the-badge&label=build)](https://github.com/onetwohour/OnetDNS-Core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-4C1?style=for-the-badge)](LICENSE)

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0wIDBoMTF2MTFIMHpNMTMgMGgxMXYxMUgxM3pNMCAxM2gxMXYxMUgwek0xMyAxM2gxMXYxMUgxM3oiLz48L3N2Zz4%3D)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-1.88%2B-B7410E?style=for-the-badge&logo=rust&logoColor=white)

</div>

<br>

Devices look up a name before they connect to it. When your network uses OnetDNS as its DNS server, OnetDNS answers those lookups and blocks the names on your blocklists. This works for apps, TVs, and consoles as well as browsers, with nothing installed on the devices.

## Features

- **Filtering**: blocklists in hosts or AdGuard format, RPZ, and your own block and allow rules. A name is also blocked when its CNAME chain passes through a blocked name.
- **Per-device rules**: blocked services such as TikTok or YouTube, SafeSearch and YouTube Restricted Mode, other upstreams, or no filtering. Devices are matched by IP address or subnet, MAC address, or the client ID of an encrypted connection.
- **Encrypted DNS**: DNS-over-TLS, DNS-over-HTTPS (HTTP/2 and HTTP/3), DNS-over-QUIC, and DNSCrypt. Certificates come from files, from an ACME CA such as Let's Encrypt, or are self-signed. The dashboard makes DNS stamps and Apple configuration profiles for clients.
- **Resolution**: forwarding to upstream servers, recursion from the root servers, or a split between the two by domain. DNSSEC validation.
- **Authoritative zones**: zone files, or zones stored in etcd, MySQL, PostgreSQL, SQLite, or LMDB, with DNSSEC signing, zone transfers, and dynamic updates.
- **DHCP**: DHCPv4, DHCPv6, router advertisements, and PXE boot over TFTP. Devices that get a lease can be reached by name.
- **Clustering**: several servers keep the same settings through Raft.

## Getting started

### Download

Get the archive for your system from the [releases page](https://github.com/onetwohour/OnetDNS-Core/releases) and extract it. There are builds for Linux (x86-64, x86, ARM64, ARMv7), Windows (x64, x86), and macOS (Apple silicon, Intel).

### Run

```sh
./OnetDNS
```

Without `--config`, OnetDNS uses `OnetDNS.toml` in your config folder and creates it on the first run:

| System | Path |
|---|---|
| Windows | `%APPDATA%\OnetDNS\OnetDNS.toml` |
| Linux, macOS | `$XDG_CONFIG_HOME/OnetDNS/OnetDNS.toml`, or `~/.config/OnetDNS/OnetDNS.toml` |

The new file holds only an access token, so OnetDNS starts with the defaults: it answers only this machine on `127.0.0.1:53`, forwards lookups to Cloudflare over DNS-over-HTTP/3, and blocks nothing.

On Linux, port 53 needs root or `CAP_NET_BIND_SERVICE`. On Windows it needs no administrator rights.

### Create the admin account

Open <http://127.0.0.1:8553> on the same machine. The page asks for a setup code, which OnetDNS writes to `setup-code.txt` next to the config file; the page shows the path. The first account can only be created on this machine.

### Serve your network

In the dashboard:

- **Settings**: add this machine's LAN address to the plain DNS listening addresses, for example `192.168.1.10:53`.
- **Filter lists**: add blocklists and choose how often to download them again.

Then set this machine's address as the DNS server in your router's DHCP settings. Devices switch when they reconnect or renew their lease. To try it on one device first, change the DNS server on that device only.

### Start at boot

```sh
OnetDNS service install --config PATH
```

This registers a Windows service, a systemd unit, or a launchd daemon that starts from the next boot. Windows asks for administrator rights. On Linux and macOS, run it with `sudo`.

## Configuration

All settings are in the TOML config file. The dashboard's Settings page lists every key with a description and saves changes to the file, and most changes apply without a restart. When the file is edited by hand, the dashboard shows the changed keys and applies them on request. To check a file first:

```sh
OnetDNS --cli check --config PATH
```

### Rules for some devices

```toml
[[clients]]
name = "Kids"
ids = ["192.168.1.50", "192.168.1.51"]
safe_search = true
blocked_services = ["tiktok", "youtube"]
```

`OnetDNS --cli services` lists the service names.

### Encrypted DNS

```toml
listen_dot = ["0.0.0.0:853"]   # Android Private DNS
listen_doh = ["0.0.0.0:443"]   # browsers, Apple devices

tls_cert = "/etc/OnetDNS/fullchain.pem"
tls_key  = "/etc/OnetDNS/privkey.pem"
```

Devices accept only a certificate that is valid for the name they connect to, so you need a domain name that points at this machine and a certificate for it.

To get one from Let's Encrypt, request it on the Encrypted transport page, then add `listen_dot` and `listen_doh`; they do not start without a certificate. HTTP-01 needs requests to port 80 for `/.well-known/acme-challenge/` forwarded to the dashboard address. DNS-01 needs OnetDNS to be the authoritative server for the domain.

The certificate goes to the files in `tls_cert` and `tls_key`; without them, it is saved next to the config file and set as `tls_cert` and `tls_key`. OnetDNS renews it when a third of its lifetime is left. `acme_directory_url` selects another ACME CA.

`tls_self_signed_host` makes a self-signed certificate instead. Devices trust it only if you install it on them.

### Recursion

```toml
backend = "recurse"
dnssec  = true
```

OnetDNS then asks the root servers and each domain's own servers instead of an upstream provider.

### DHCP

Turn off DHCP on your router first. Two DHCP servers on one network will conflict.

```toml
dhcp_enable      = true
dhcp_server_ip   = "192.168.1.10"   # this machine
dhcp_range_start = "192.168.1.100"
dhcp_range_end   = "192.168.1.199"
dhcp_subnet_mask = "255.255.255.0"
dhcp_router      = "192.168.1.1"
```

A device named `laptop` can then be reached as `laptop.lan`. `dhcp_local_domain` changes the suffix.

## Dashboard from another computer

Give the dashboard an HTTPS address and the URL you will type in the browser:

```toml
control_listen_https   = "0.0.0.0:8554"
control_public_origins = ["https://dns.example.com:8554"]
```

It uses the same certificate as DoT and DoH, so set `tls_cert` and `tls_key`, or `tls_self_signed_host` for a self-signed one that the browser warns about. It answers only at the addresses in `control_public_origins`.

An SSH tunnel also works, and so does an HTTPS reverse proxy such as Caddy or nginx on the same machine:

```toml
control_trusted_proxies = ["127.0.0.1/32"]
control_public_origins  = ["https://dns.example.com"]
```

The proxy must forward to `127.0.0.1:8553`, keep the original `Host` header, and set `X-Forwarded-For`.

The plain HTTP dashboard (`control_listen`) accepts only loopback addresses.

## Updates

OnetDNS checks GitHub for new releases. When one is available, the dashboard shows a banner, and Maintenance → Software updates installs it. From the command line:

```sh
OnetDNS --cli update                  # check
OnetDNS --cli update apply            # install the newest release
OnetDNS --cli update rollback         # reinstall the version the last update replaced
```

Restart OnetDNS after a command-line update.

A release is installed only if it is signed by the OnetDNS release key. A stable version is offered only stable releases; a pre-release is offered both. Builds from source do not update themselves. `release_check = false` turns off the periodic check.

## Serving the internet

In the default personal mode, OnetDNS answers only loopback and private addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, fc00::/7, and fe80::/10. To answer everyone, set public mode and a per-client rate limit:

```toml
mode               = "public"
rate_limit_per_sec = 20
rate_limit_burst   = 40
```

A DNS server that answers everyone without a rate limit can be used to flood other people's servers. OnetDNS logs a warning at every start when it is in that state. Keep the dashboard off the internet: if you set `control_listen_https`, bind it to a LAN address.

## Troubleshooting

<details>
<summary>A site or app stopped working.</summary>
<br>

Find the blocked lookup in the Query log and allow the domain there, or add an allow rule on the Filter lists page.

</details>

<details>
<summary>Port 53 is already in use.</summary>
<br>

Another DNS server is running on the machine. On Windows it is often Internet Connection Sharing or the DNS Server role; on Linux, `systemd-resolved` or `dnsmasq`. `netstat -ano` (Windows) or `ss -lunp` (Linux) shows which program holds the port.

</details>

<details>
<summary>Some sites fail to load, or lookups are slow.</summary>
<br>

Some ISPs, routers, and security programs intercept plain DNS on port 53 and answer it themselves, whichever server it was sent to. Filters on your own computer, such as AdGuard for Windows, do this too.

To check, ask a root server directly. A root server never returns an address for `example.com`; it returns the servers for `com`:

```sh
nslookup -norecurse example.com 198.41.0.4
```

If the output lists `gtld-servers.net` servers, the lookup was not intercepted. If it shows an address for `example.com`, something answered in the root server's place. Add `-vc` to check TCP the same way.

With plain IP upstreams, intercepted lookups never reach the servers you chose.

With `backend = "recurse"`, OnetDNS checks for interception at startup, logs a warning, and sends its queries over TCP if TCP is not intercepted. This does not reach every site: some authoritative servers do not answer over TCP, and lookups for those sites fail. After repeated failures, OnetDNS stops asking those servers for a while, so the lookups fail at once instead of timing out.

To fix it, best first:

- Stop the interception. For a filter on your computer, exclude OnetDNS from its DNS filtering or turn that filtering off. For a router, turn off its DNS redirect or DNS proxy option.
- With `backend = "recurse"`, add a fallback server. OnetDNS uses it only when the authoritative servers do not answer:

  ```toml
  fallback_upstreams = ["https://1.1.1.1/dns-query#cloudflare-dns.com"]
  ```

- Forward to encrypted upstreams in `upstream_urls` instead of recursing. The default settings do this.

</details>

## Command line

```sh
OnetDNS --cli check --config PATH            # check a config file
OnetDNS --cli query example.com --type AAAA  # look up a name at the default upstreams
OnetDNS --cli services                       # names for blocked_services
OnetDNS --cli stats                          # query counts from the running server
OnetDNS --cli block example.com              # add a block rule to the running server
OnetDNS --cli allow example.com              # add an allow rule to the running server
OnetDNS --cli passwd --name NAME             # print a dashboard account entry for the config file
OnetDNS --cli cert --host dns.example.com    # write a self-signed certificate
OnetDNS --help                               # everything else
```

## Building from source

Requires Rust 1.88 or newer.

```sh
cargo build --release                         # target/release/OnetDNS
cargo build --release --no-default-features   # without the dashboard
```

## License

[Apache-2.0](LICENSE)
