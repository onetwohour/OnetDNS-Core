# Configuration model

OnetDNS reads settings from `OnetDNS.toml`. For every key's exact TOML form, type and default, use the [configuration reference](reference/README.md). For arrays of tables and their nested fields, use [structured configuration entries](reference/structures.md). For independent configurations, see [deployment examples](examples.md).

## File location and lifecycle

Without `--config`, the executable uses `OnetDNS.toml` under the user's config directory. A normal first run creates a minimal file that preserves startup defaults and credentials; it does not write every supported key. Pass `--config /absolute/path/OnetDNS.toml` when the server runs as a service or when multiple installations must remain independent.

The common lifecycle is:

1. Start from the current working configuration; make a backup before a large change.
2. Edit the TOML or use the dashboard settings editor.
3. Run `OnetDNS --cli check --config /path/to/OnetDNS.toml`.
4. Apply the change through the dashboard's configuration workflow, or restart the service when required. Some changes can be hot-applied, but not every type of change has identical lifecycle behavior.
5. Verify the result with a DNS query sent to the actual listener and, when relevant, the Query log or server metrics.

A syntax check is only the first test. Port binding, certificate usability, network reachability and permission errors are runtime concerns.

## Quick reference: what to type

```toml
backend = "forward"                    # enum: quoted string
cache_enabled = true                    # boolean: no quotes
query_timeout_secs = 5                  # integer: no quotes
listen = ["127.0.0.1:53"]              # array of strings
block_rules = ["||ads.example.com^"]  # rule string array
local_a = [["router.lan", "192.168.1.1"]]  # array of name/address pairs

[[clients]]                             # array of tables
name = "Laptop"
ids = ["192.168.1.50/32"]
```

These are examples of syntax. A full configuration can omit any option whose default is sufficient. Keep all top-level settings above the first `[[clients]]`, `[[zones]]`, or other table array. For all accepted option values, see the [reference](reference/README.md).

## TOML basics

```toml
# Unquoted keys, quoted string values.
backend = "forward"
cache_enabled = true
cache_size = 4096
listen = ["127.0.0.1:53", "192.168.1.10:53"]

# Each [[clients]] starts a separate client profile.
[[clients]]
name = "Laptop"
ids = ["192.168.1.50/32"]
disable_filtering = false
```

TOML comments start with `#`. Arrays of strings use `["one", "two"]`; Boolean values are `true` or `false` without quotes. Duplicating a key in the same table is invalid TOML. When you add a `[[clients]]` table, subsequent keys remain inside that table until another table starts; place top-level keys before your table arrays to avoid accidental nesting.

## Configuration areas

### Listening addresses

`listen` defines plain DNS listener addresses. `listen_dot`, `listen_doh`, `listen_doh3`, `listen_doq` and `listen_dnscrypt` configure distinct inbound encrypted transports. Each is independent of upstream configuration. By default the ordinary listener is local-only; to serve your LAN you need to bind an actual LAN address and make that port reachable from devices.

### Resolution backend

`backend` selects `forward`, `recurse` or `split`. With `forward`, an upstream is consulted. With `recurse`, OnetDNS contacts the DNS hierarchy directly. With `split`, selected domains use different approaches. `[[stub_zones]]` can designate special authoritative DNS servers for a suffix. See [Resolution](resolution.md).

### Filtering and policy

`blocklist_urls`, `blocklists`, `allowlists`, `block_rules`, `allow_rules`, `rpz_*`, `[[clients]]` and several specialized policy options affect DNS filtering. Filtering rules are configured independently of `listen` and the resolution backend. Rule priority does not follow TOML file order; see [Filtering](filtering.md) and [Clients](clients.md).

### Dashboard and API

`control_listen` and `control_listen_https` configure the dashboard/API plane. This is different from the DNS request plane. Authentication, accepted HTTPS origins and reverse-proxy forwarding rules must be configured and verified independently. See [Operations](operations.md#dashboard-access).

## LAN filtering example

```toml
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:53", "192.168.1.10:53"]

# Temporary rule for testing; remove after verifying.
block_rules = ["||example.com^"]

cache_enabled = true
cache_size = 4096
```

Replace the LAN address. Confirm `example.com` resolves without the temporary rule, then enable the rule and compare `dig @192.168.1.10 example.com A` from a LAN client.

## Defaults and option interactions

An omitted option uses its implementation default or a value derived at startup. Those are not always equivalent to explicitly writing an empty array. For example, default encrypted upstreams can differ from an explicitly defined empty or alternative upstream configuration. Numeric zero has option-specific meaning: `workers = 0` uses automatic sizing, while zero in a retention or rate setting may disable that behavior. Always read the option's reference entry.

Related settings:

| Common confusion | Correct interpretation |
| --- | --- |
| `listen_doh` versus `upstream_urls` | The first serves DoH to clients; the second chooses an upstream to forward queries to. |
| `backend = "recurse"` versus `dnssec = true` | Recursive lookup and DNSSEC validation are separate capabilities. |
| `mode = "public"` versus management API origins | DNS client admission does not authorize dashboard users. |
| `[[clients]]` versus `acl_allow` | Client profiles select DNS policy; access controls determine admission behavior. |
| `block_response` versus `block_rules` | `block_response` selects a response for global block matches; `block_rules` contains matching rules. `$dnsrewrite=NORESPONSE` is a rule action, not a `block_response` value; see [NORESPONSE](filtering.md#noresponse-deliberately-leave-a-query-unanswered). |
| `[[zones]]` versus `[[stub_zones]]` | An authoritative zone is served locally; a stub zone delegates lookup for a suffix to named DNS servers. |

## Validation, application and rollback

```sh
OnetDNS --cli check --config /etc/OnetDNS/OnetDNS.toml
```

After a successful check, use the dashboard to inspect changes and apply them, or restart the service when needed. When editing directly on a service host, preserve the last known-working file before applying major changes. If the server no longer starts, restore that file and inspect `journalctl -u onetdns` (Linux) or equivalent service logs.

Validate configuration changes using the installed binary; option availability can differ between releases.

## Next pages

- [Examples](examples.md) — complete scenarios, verification and expected behavior.
- [Reference index](reference/README.md) — grouped options, types and defaults.
- [Structured tables](reference/structures.md) — nested arrays of tables and their fields.
- [Troubleshooting](troubleshooting.md) — distinguish parser errors from network and protocol failures.
