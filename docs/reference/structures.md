# Structured configuration entries

[Configuration reference](README.md) · [Configuration guide](../configuration.md)

Top-level scalar options use `name = value`. Some settings have a different TOML shape:

- `local_a` and `local_aaaa` are **arrays of two-element arrays**, not TOML tables.
- `clients`, `zones`, `policy`, `rewrites` and other structured settings use **arrays of tables** (`[[name]]`). Every `[[name]]` begins another entry.
- `wasm_plugins` accepts strings and inline tables in a normal array; it does not use `[[wasm_plugins]]` in the current schema.

Put ordinary top-level keys before your first `[[table]]`. TOML assigns keys after a table header to that table until another header begins.

All names, addresses, paths, keys and credentials below are **examples**. Replace them with deployment values. Code blocks show individual setting forms, not a single configuration to concatenate unchanged. The Rust parser additionally validates relationships between settings; check the completed file with `OnetDNS --cli check --config /path/to/OnetDNS.toml`.


## `rewrites`

```toml
[[rewrites]]
domain = "printer.lan"
answer = "192.168.1.20"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `domain` | `"printer.lan"` | DNS name, required |
| `answer` | `"192.168.1.20"` | rewrite answer, required |

## `dynamic_records`

```toml
[[dynamic_records]]
name = "service.example.com"
qtype = "A"
mode = "round_robin"
values = ["192.0.2.10", "192.0.2.11"]
ttl = 60
probe_port = 0
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"service.example.com"` | record name, required |
| `qtype` | `"A"` | A or AAAA |
| `mode` | `"round_robin"` | random, weighted, round_robin or failover |
| `values` | `["192.0.2.10", "192.0.2.11"]` | matching-IP-family addresses; weighted mode supports weight suffix |
| `ttl` | `60` | seconds |
| `probe_port` | `0` | 0 disables probing |

## `local_zones`

```toml
[[local_zones]]
name = "corp.example"
kind = "static"
records = ["printer.corp.example 192.0.2.20"]
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"corp.example"` | zone name, required |
| `kind` | `"static"` | deny/refuse/static/redirect/always_null/transparent |
| `records` | `["printer.corp.example 192.0.2.20"]` | static entries use name + answer; redirect entries use answer alone |

## `service_schedule`

```toml
[[service_schedule]]
days = ["mon", "tue", "wed", "thu", "fri"]
start = "09:00"
end = "17:00"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `days` | `["mon", "tue", "wed"]` | days of week or all; at least one |
| `start` | `"09:00"` | HH:MM, required |
| `end` | `"17:00"` | HH:MM, required, differs from start |

Times are 24-hour `HH:MM`; start and end cannot be equal.

## `local_a`

```toml
local_a = [["router.lan", "192.168.1.1"]]
```

Each entry must have exactly two strings: a DNS name and an address of the correct IP family. This is not an array of tables.

## `local_aaaa`

```toml
local_aaaa = [["router.lan", "2001:db8::1"]]
```

Each entry must have exactly two strings: a DNS name and an address of the correct IP family. This is not an array of tables.

## `stub_zones`

```toml
[[stub_zones]]
suffix = "corp.example"
servers = ["192.168.1.53"]
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `suffix` | `"corp.example"` | suffix, required |
| `servers` | `["192.168.1.53"]` | upstream resolvers for suffix, required |

## `views`

```toml
[[views]]
name = "office"
clients = ["192.168.1.0/24"]
local_a = [["intranet.corp.example", "192.168.1.20"]]
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"office"` | view name, required |
| `clients` | `["192.168.1.0/24"]` | client identifiers, required |
| `local_a` | `[["host.corp.example", "192.168.1.20"]]` | name/IPv4 pairs |
| `local_aaaa` | `[["host.corp.example", "2001:db8::20"]]` | name/IPv6 pairs |

## `zones`

```toml
[[zones]]
origin = "corp.example."
file = "/etc/OnetDNS/zones/corp.example.zone"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `origin` | `"corp.example."` | zone origin, required |
| `file` | `"/etc/OnetDNS/zones/corp.example.zone"` | zone file path |
| `dnssec_sign` | `false` | sign zone |
| `dnssec_algorithm` | `"ed25519"` | signing algorithm, if configured |
| `dnssec_key` | `"/etc/OnetDNS/zsk.pem"` | zone signing key |
| `dnssec_ksk` | `"/etc/OnetDNS/ksk.pem"` | separate key signing key |
| `dnssec_key_next` | `"/etc/OnetDNS/next.pem"` | rollover candidate |
| `dnssec_nsec3` | `false` | enable NSEC3 denial proofs |
| `dnssec_nsec3_iterations` | `0` | NSEC3 iterations |

`dnssec_sign`, signing key files and NSEC3 values are optional. The example at the top is an unsigned, file-backed zone.

## `secondary`

```toml
[[secondary]]
origin = "secondary.example."
primary = "192.0.2.53"
file = "/var/lib/OnetDNS/zones/secondary.example.zone"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `origin` | `"secondary.example."` | zone origin, required |
| `primary` | `"192.0.2.53"` | primary server IP, required |
| `primary_port` | `53` | port |
| `file` | `"/var/lib/OnetDNS/zones/secondary.zone"` | local zone file |
| `tsig_key` | `"transfer-key.example."` | TSIG key reference |

`primary` is a numeric IP address. `primary_port` and `tsig_key` are optional.

## `catalog`

```toml
[[catalog]]
origin = "catalog.example."
primary = "192.0.2.53"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `origin` | `"catalog.example."` | zone origin, required |
| `primary` | `"192.0.2.53"` | primary server IP, required |
| `primary_port` | `53` | port |
| `file` | `"/var/lib/OnetDNS/zones/catalog.zone"` | catalog file |
| `tsig_key` | `"transfer-key.example."` | TSIG key reference |

`primary` is a numeric IP address. `primary_port` and `tsig_key` are optional.

## `notify`

```toml
[[notify]]
address = "192.0.2.54:53"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `address` | `"192.0.2.54:53"` | target address:port, required |
| `tsig_key` | `"transfer-key.example."` | optional TSIG key reference |

## `tsig_keys`

```toml
[[tsig_keys]]
name = "transfer-key.example."
secret = "REPLACE_WITH_BASE64_TSIG_SECRET"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"transfer-key.example."` | key name, required |
| `secret` | `"REPLACE_WITH_BASE64_TSIG_SECRET"` | secret value, required |

## `update_policy`

```toml
[[update_policy]]
action = "deny"
identity = "transfer-key.example."
name = "corp.example."
types = ["A", "AAAA"]
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `action` | `"deny"` | grant or deny, required |
| `identity` | `"transfer-key.example."` | TSIG key identity, required |
| `name` | `"corp.example."` | target name, required |
| `types` | `["A", "AAAA"]` | DNS record types; empty means all types |

## `policy`

```toml
[[policy]]
action = "block"
clients = ["192.168.1.0/24"]
suffixes = ["ads.example.com"]
qtypes = ["A", "AAAA"]
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `action` | `"block"` | block/allow/refuse/rewrite, required |
| `clients` | `["192.168.1.0/24"]` | CIDR selectors |
| `suffixes` | `["ads.example.com"]` | domain suffix selectors |
| `qtypes` | `["A", "AAAA"]` | DNS record types |
| `rewrite` | `"192.0.2.10"` | required when action is rewrite |
| `days` | `["mon", "tue"]` | day filters |
| `start` | `"09:00"` | HH:MM time window |
| `end` | `"17:00"` | HH:MM time window |

A `rewrite` action requires a valid IPv4 `rewrite` field. Do not specify unrelated selectors just to fill a template.

## `users`

```toml
[[users]]
name = "viewer"
password_hash = "REPLACE_WITH_HASH_FROM_CLI"
role = "readonly"
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"viewer"` | username, required |
| `password_hash` | `"REPLACE_WITH_HASH_FROM_CLI"` | generate with OnetDNS --cli passwd; never plaintext |
| `role` | `"readonly"` | admin or readonly, required |

Use `OnetDNS --cli passwd` to generate a password hash. A literal sample placeholder does not create a valid login.

## `clients`

```toml
[[clients]]
name = "Workstation"
ids = ["192.168.1.50/32"]
disable_filtering = false
```

| Field | TOML value | Meaning |
| --- | --- | --- |
| `name` | `"Laptop"` | profile name, required |
| `ids` | `["192.168.1.50/32"]` | client source addresses |
| `client_ids` | `["laptop"]` | encrypted DNS identities |
| `mac` | `["aa:bb:cc:dd:ee:ff"]` | MAC identifiers where available |
| `tags` | `["home"]` | labels |
| `block` | `["||ads.example.com^"]` | client-specific blocking rules |
| `allow` | `["@@||allowed.example.com^"]` | client-specific allow rules |
| `disable_filtering` | `false` | skip filtering for this client |
| `safe_search` | `true` | optional override |
| `blocked_services` | `["youtube"]` | service identifiers |
| `upstreams` | `["1.1.1.1"]` | client-specific upstreams |
| `ignore_querylog` | `false` | omit query logs |
| `ignore_stats` | `false` | omit statistics |

## `wasm_plugins` (special array form)

```toml
wasm_plugins = [{ path = "/etc/OnetDNS/policy.wasm", name = "policy", fail_mode = "open" }]
```

Each entry can be a file path string or an inline table with `path` (required), `name` (optional) and `fail_mode` (optional).

## Example file with multiple structured settings

```toml
backend = "forward"
listen = ["127.0.0.1:53"]
local_a = [["router.lan", "192.168.1.1"]]
block_rules = ["||ads.example.com^"]

[[clients]]
name = "Laptop"
ids = ["192.168.1.50/32"]
disable_filtering = false

[[rewrites]]
domain = "printer.lan"
answer = "192.168.1.20"
```
