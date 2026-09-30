<div align="center">

# OnetDNS

**Block ads and trackers on every device in your home.**

One small program on one machine. Nothing to install on your phones, TVs, or consoles.

<br>

[![Release](https://img.shields.io/github/v/release/onetwohour/OnetDNS-Core?include_prereleases&style=flat&label=release&color=gray)](https://github.com/onetwohour/OnetDNS-Core/releases)
![Platforms](https://img.shields.io/badge/Linux_|_Windows_|_macOS-gray?style=flat)
[![License](https://img.shields.io/badge/Apache--2.0-gray?style=flat&label=license)](LICENSE)

</div>

<br>

You can't install an ad blocker on a smart TV, and the one in your browser does nothing for the apps on your phone. What they all have in common is that they look up names before they connect. OnetDNS answers those lookups for your whole network and refuses the ones that lead to ads and trackers, so the connection never happens.

Run it on a PC, a Raspberry Pi, or a small server, point your router at it, and every device on your Wi-Fi is covered.

> [!WARNING]
> OnetDNS is in alpha. The config file and the management API can change between releases, and old settings are not carried over.

<br>

## What you get

### Blocking that covers everything

Phones, laptops, TVs, consoles, and every app on them. OnetDNS reads the blocklists people already use, both hosts files and AdGuard-style rules, and re-downloads them on a schedule you choose. Trackers that hide behind a site's own domain are caught too.

### A dashboard

See what each device is looking up, what got blocked, and whether your upstream servers are healthy. Filter lists and most settings can be changed there and take effect right away. It comes in English, Korean, Japanese, and Simplified Chinese.

### Different rules for different devices

Give the kids' tablet SafeSearch, YouTube Restricted Mode, and no TikTok, and leave your work laptop unfiltered. Devices are recognized by address or hardware address.

### Private DNS for your phone

Android's Private DNS, iOS profiles, and browsers can all talk to OnetDNS over an encrypted connection (DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, DNSCrypt). It can also encrypt the lookups it sends onward.

### No middleman, if you want

Instead of passing your lookups to Cloudflare or Google, OnetDNS can find the answers itself, starting from the root servers, and check DNSSEC signatures along the way. No single company sees everything your network looks up.

### Names for your own devices

The built-in DHCP server hands out addresses, and every device that gets one is reachable by name. You can also host your own domains on it.

### Two servers, no outage

Run two copies and list both as your DNS servers. Settings stay in sync between them, and if one goes down, the other keeps answering.

<br>

## Compared to AdGuard Home and Pi-hole

All three block ads for your whole network. Where they differ:

| | OnetDNS | AdGuard Home | Pi-hole |
|---|:---:|:---:|:---:|
| Single program, no install script | ✓ | ✓ | |
| Runs on Windows | ✓ | ✓ | |
| Encrypted DNS for your devices | ✓ | ✓ | |
| Resolves without a third-party DNS | ✓ | | with Unbound |
| Hosts your own domains, with DNSSEC signing | ✓ | | |
| Two servers kept in sync | ✓ | third-party tool | third-party tool |
| DHCP server | ✓ | ✓ (not on Windows) | ✓ |

AdGuard Home and Pi-hole have years of releases and large communities behind them. OnetDNS is new; see the warning above.

<br>

## Getting started

**1. Download.** Grab the file for your system from the [releases page](https://github.com/onetwohour/OnetDNS-Core/releases) and extract it. There are builds for Linux (x86_64, i686, aarch64, armv7), Windows (x86_64, i686), and macOS (Apple Silicon, Intel). The Linux builds run on any distribution, and the Windows builds need no extra runtime.

**2. Write a config.** Out of the box OnetDNS answers only the machine it runs on, forwards lookups to Cloudflare over encrypted DNS (DNS over HTTP/3), and has no blocklists. Create `OnetDNS.toml` with this machine's LAN address and a list to start with:

```toml
listen = ["192.168.1.10:53"]

blocklist_urls    = ["https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"]
list_refresh_secs = 86400   # re-download once a day
```

You can add more lists from the dashboard later.

**3. Start it.**

```sh
OnetDNS --config OnetDNS.toml
```

On Linux, port 53 needs root or `CAP_NET_BIND_SERVICE`. On Windows it works without admin rights; to start it with Windows, run `OnetDNS service install --config OnetDNS.toml`.

**4. Open the dashboard** at <http://127.0.0.1:8553> on the same machine and create your admin account. It asks for a setup code: OnetDNS writes one to `setup-code.txt` next to its configuration file, and the page shows the exact path. The code works once.

**5. Point your devices at it.** In your router's settings, set the DNS server to this machine's address. Every device picks it up the next time it reconnects. To try it on one device first, change the DNS setting on that device only.

<br>

## Common setups

All of these go in the same `OnetDNS.toml`. Before restarting, `OnetDNS --cli check --config OnetDNS.toml` tells you if something is wrong.

### Rules for the kids' devices

```toml
[[clients]]
name = "Kids"
ids = ["192.168.1.50/32", "192.168.1.51/32"]
safe_search = true
blocked_services = ["tiktok"]
```

### Encrypted DNS for phones

```toml
listen_dot = ["0.0.0.0:853"]    # Android Private DNS
listen_doh = ["0.0.0.0:443"]    # browsers, iOS

tls_cert = "/etc/OnetDNS/fullchain.pem"
tls_key  = "/etc/OnetDNS/privkey.pem"
```

Phones only connect if the certificate is valid for the name they are given, so use a real certificate for a domain you own, such as one from Let's Encrypt.

### Skip the upstream provider

```toml
backend = "recurse"
dnssec  = true
```

### Hand out addresses

Turn off DHCP on your router first. Two DHCP servers on one network will fight.

```toml
dhcp_enable       = true
dhcp_server_ip    = "192.168.1.10"   # this machine
dhcp_range_start  = "192.168.1.100"
dhcp_range_end    = "192.168.1.199"
dhcp_subnet_mask  = "255.255.255.0"
dhcp_router       = "192.168.1.1"
```

A device named `laptop` becomes reachable as `laptop.lan`. Change the suffix with `dhcp_local_domain`.

There are many more settings. The settings page in the dashboard lists every one with a description.

<br>

## Running a resolver on the internet

OnetDNS is meant for your own network. If you do open it to the internet, set `mode = "public"` and a rate limit:

```toml
mode               = "public"
rate_limit_per_sec = 20
rate_limit_burst   = 40
```

An open DNS server without a rate limit gets used to flood other people's servers. OnetDNS starts without one but warns you every time it does. Never expose the dashboard; keep `control_listen` on localhost or your LAN.

<br>

## FAQ

<details>
<summary>A site or app stopped working. How do I unblock it?</summary>
<br>

Find the blocked name in the dashboard's live query view and add it under block and allow rules, or from the command line:

```sh
OnetDNS --cli allow example.com
```

</details>

<details>
<summary>OnetDNS says port 53 is already in use.</summary>
<br>

Something else is already a DNS server on that machine. On Windows it is often Internet Connection Sharing or the DNS Server role; on Linux, `systemd-resolved` or `dnsmasq`. `netstat -ano` (Windows) or `ss -lunp` (Linux) shows which program holds it.

</details>

<details>
<summary>Some sites fail to load, or lookups are slow.</summary>
<br>

Some ISPs, routers, and security programs quietly take over every ordinary DNS lookup, whichever server it was meant for, and answer it themselves. Filters that run on your own computer, such as AdGuard for Windows, can do this too, so it can happen even when your router is fine.

To check, run these two commands. Each prints the address of whoever answered. If the two addresses differ, something between you and Google is answering in its place.

```sh
nslookup -type=txt o-o.myaddr.l.google.com 8.8.8.8
nslookup -vc -type=txt o-o.myaddr.l.google.com 8.8.8.8
```

If you forward to plain IP upstreams, your lookups never reach the servers you picked, and some answers arrive slowly.

If you use `backend = "recurse"`, OnetDNS notices the interception at startup, warns about it in its log, and works around it. The workaround does not reach every site: a few, often ones served through large CDNs, keep failing, and the dashboard shows them as failed queries. Once a site has failed, it fails right away for a while instead of making you wait each time.

To fix it, best first:

- Stop the interception. For a filter on your computer, exclude OnetDNS from its DNS filtering or turn that filtering off; OnetDNS already blocks ads. For a router, turn off its DNS redirect or "DNS proxy" option.
- With `backend = "recurse"`, add a fallback server. OnetDNS uses it only for sites it cannot reach on its own:

  ```toml
  fallback_upstreams = ["https://1.1.1.1/dns-query#cloudflare-dns.com"]
  ```

- Or forward instead of recursing, using encrypted upstreams in `upstream_urls`. Nothing on the way can take those over. The default settings already do this.

</details>

<details>
<summary>Does it replace my router?</summary>
<br>

No. Your router still connects you to the internet. OnetDNS only takes over name lookups, and addresses too if you turn on its DHCP server.

</details>

<details>
<summary>Can I open the dashboard from another computer?</summary>
<br>

The dashboard only answers on the machine running OnetDNS, because it has no HTTPS of its own. To reach it from elsewhere, either use an SSH tunnel, or put an HTTPS reverse proxy such as Caddy or nginx on the same machine and tell OnetDNS about it:

```toml
control_trusted_proxies = ["127.0.0.1/32"]
control_public_origins = ["https://dns.example.com"]
```

The proxy has to forward to `127.0.0.1:8553`, keep the original `Host` header, and set `X-Forwarded-For`. Create your admin account on the machine itself first; the first-time setup page does not open through the proxy.

</details>

<details>
<summary>What else can I do from the command line?</summary>
<br>

```sh
OnetDNS --cli block example.com         # block a name
OnetDNS --cli allow example.com         # unblock a name
OnetDNS --cli stats                     # query stats
OnetDNS --cli top                       # most looked-up names
OnetDNS --cli reload                    # apply edits to the config file
OnetDNS --cli passwd --name admin       # add a dashboard account
OnetDNS --help                          # everything else
```

</details>

<br>

## Building from source

Requires Rust 1.88 or newer.

```sh
cargo build --release                         # target/release/OnetDNS
cargo build --release --no-default-features   # without the dashboard
```

<br>

## License

[Apache-2.0](LICENSE)
