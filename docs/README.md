# OnetDNS documentation

## Find the relevant guide

| I want to… | Start here | Then read |
| --- | --- | --- |
| Try it on one computer | [First run](getting-started.md) | [Install and services](installation.md) |
| Use it for a home network | [First run](getting-started.md#serve-one-device-before-the-whole-network) | [Filtering](filtering.md), [Clients](clients.md) |
| Run encrypted DNS for devices | [Encrypted DNS](encrypted-dns.md) | [Configuration](configuration.md), [Troubleshooting](troubleshooting.md) |
| Forward or resolve recursively | [Resolution](resolution.md) | [Configuration reference](reference/README.md) |
| Manage clients or exception rules | [Clients](clients.md) | [Filtering](filtering.md) |
| Configure authoritative DNS, DHCP or clustering | [Advanced services](advanced-services.md) | [Reference](reference/README.md) |
| Operate a Linux system service | [Operations](operations.md) | [CLI](cli.md), [Troubleshooting](troubleshooting.md) |
| Find an exact TOML key and default | [Configuration reference](reference/README.md) | [Nested structures](reference/structures.md) |
| Benchmark or size a deployment | [Performance and sizing](performance.md) | [Operations](operations.md) |

## Guides

- [Installation](installation.md): platforms, filesystem layout, privileged ports, service registration and update behavior.
- [Configuration](configuration.md): file discovery, syntax, validation, dashboard edits and changes during a running service.
- [Configuration examples](examples.md): local forwarder, filtered LAN, split DNS, recursion with DNSSEC, secure listeners, public service and client profiles.
- [Filtering](filtering.md): rule formats, priority, block responses, `NORESPONSE`, rule provenance and large-list operation.
- [Client policies](clients.md): identity matching, per-client rules and verification from the correct client.
- [Resolution](resolution.md): forwarding, recursion, split mode, stub zones, caching and DNSSEC.
- [Encrypted DNS](encrypted-dns.md): DoT, DoH, DoH3, DoQ, DNSCrypt and certificate setup.
- [Advanced services](advanced-services.md): authoritative zones, DHCP, ACME and clustering with prerequisites.

## Operations and API

- [Command-line reference](cli.md)
- [Operations](operations.md)
- [Troubleshooting](troubleshooting.md)
- [Performance and sizing](performance.md)
- [REST API](API.md) — endpoints, authentication, request and response formats
- [Source build](installation.md#build-from-source)

## Conventions

Example domains use the reserved `.example` suffix; example addresses and list URLs must be replaced before deployment. Commands assume `OnetDNS` is available in `PATH`. Use `./OnetDNS` or an absolute path if needed.
