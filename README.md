<div align="center">

# OnetDNS

[![Release](https://img.shields.io/github/v/release/onetwohour/OnetDNS-Core?style=for-the-badge&label=release&color=2563EB)](https://github.com/onetwohour/OnetDNS-Core/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/onetwohour/OnetDNS-Core/ci.yml?branch=main&style=for-the-badge&label=build)](https://github.com/onetwohour/OnetDNS-Core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-4C1?style=for-the-badge)](LICENSE)

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0wIDBoMTF2MTFIMHpNMTMgMGgxMXYxMUgxM3pNMCAxM2gxMXYxMUgwek0xMyAxM2gxMXYxMUgxM3oiLz48L3N2Zz4%3D)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-1.88%2B-B7410E?style=for-the-badge&logo=rust&logoColor=white)

[Get started](docs/getting-started.md) · [Features](#features) · [Documentation](docs/README.md) · [Configuration reference](docs/reference/README.md) · [API](docs/API.md)

</div>

OnetDNS receives queries over UDP/TCP, DoT, DoH, DoH3, DoQ, and DNSCrypt. It applies domain and client rules, then answers from local data, cache, upstream forwarding, or recursive resolution. The web interface, API, and CLI expose configuration and query statistics.

## Features

| Area | Supported functions |
| --- | --- |
| **Filtering** | Hosts/AdGuard-style lists, RPZ, allow and block rules, CNAME inspection, client-specific policies and rule explanations |
| **Transports** | Classic DNS (UDP/TCP), DoT, DoH over HTTP/2, DoH over HTTP/3, DoQ and DNSCrypt |
| **Resolution** | Encrypted upstream forwarding, recursion, split resolution, stub zones, response caching and DNSSEC validation |
| **Device policies** | IP/subnet, available MAC or encrypted-client identity, SafeSearch, blocked services, per-client upstream selection |
| **Administration** | Embedded dashboard, query log, statistics, configuration editor, API and CLI |
| **Additional services** | Authoritative DNS, zone transfers/signing, DHCPv4/v6, router advertisements, PXE/TFTP and Raft configuration clustering |

## System requirements

| Tier | CPU | RAM | Storage |
| --- | --- | --- | --- |
| Minimum | 1 vCPU | 512 MB | 1 GB |
| Recommended | 1–2 vCPU | 1 GB | 2–5 GB |
| High load | 2+ vCPU | 2 GB+ | 10 GB+ |

With 2M rules, OnetDNS uses approximately **50–80 MiB RSS** at rest, peaking around **300 MiB** during filter reloads.

Regex-heavy lists and high-concurrency encrypted DNS traffic may require additional CPU resources.

## Quick start

### Download and run

Download the appropriate archive from [Releases](https://github.com/onetwohour/OnetDNS-Core/releases), extract it and run the executable on Linux, macOS or Windows:

```sh
./OnetDNS
```

On Windows run `OnetDNS.exe`. Binding port 53 on Linux requires appropriate privileges. If no configuration exists, the program creates one in the user configuration directory.

### Open the web interface

Open **http://127.0.0.1:8553** on the same machine. The first-run screen uses the code in `setup-code.txt` beside the configuration file to create an administrator account. Filtering subscriptions can be added from **Filter lists**.

### Query the DNS listener

```sh
dig @127.0.0.1 example.com A
```

This tests the running DNS listener. To serve another device, add the machine's LAN address to `listen` and configure that device to use the address. See [Getting started](docs/getting-started.md) for client configuration and filtering.

## Example configuration: LAN filtering

```toml
backend = "forward"
listen = ["127.0.0.1:53", "192.168.1.10:53"]

# Temporary rule for verification; remove after testing.
block_rules = ["||example.com^"]
```

Replace the example LAN address, then validate the file. `example.com` is used as a temporary block test:

```sh
OnetDNS --cli check --config /path/to/OnetDNS.toml
OnetDNS run --config /path/to/OnetDNS.toml
```

## Documentation

| Start here | What you will learn |
| --- | --- |
| [Getting started](docs/getting-started.md) | Install, enroll the first administrator, connect one device and verify that filtering works |
| [Configuration guide](docs/configuration.md) | TOML, validation, changes and the relationship between settings |
| [Deployment examples](docs/examples.md) | Independent, commented configurations for common setups |
| [Feature guides](docs/README.md#guides) | Filtering, clients, resolution, encrypted transports and advanced services |
| [Configuration reference](docs/reference/README.md) | All 263 top-level keys with TOML examples; nested fields and table syntax |
| [Operations and diagnostics](docs/operations.md) | Services, monitoring, updates, troubleshooting and performance measurement |
| [Management API](docs/API.md) | HTTP API endpoints and authentication |

## Build from source

The repository specifies Rust 1.88 or newer. From the workspace root:

```sh
cargo build --release
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

The output binary is `target/release/OnetDNS`. For a headless build without the embedded dashboard, use `cargo build --release --no-default-features`.

## License and issues

Licensed under [Apache-2.0](LICENSE). Report issues in [GitHub Issues](https://github.com/onetwohour/OnetDNS-Core/issues).
