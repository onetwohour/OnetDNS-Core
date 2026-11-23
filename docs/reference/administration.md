# Dashboard, logging and administration — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Control-plane boundaries

The dashboard/API is not the same as the DNS listener. `control_listen` governs HTTP control access, `control_listen_https` enables HTTPS control access, and `control_public_origins` names externally accepted HTTPS origins. A reverse proxy needs correct Host and forwarded-origin handling. When no dashboard is desired, consult the `--no-web` CLI option; an explicit `control_listen` setting can take precedence. Query logging and statistics have separate retention and inclusion settings.

## Options in this chapter

- [Dashboard, API, logging, and updates](#dashboard-api-logging-and-updates)
- [Discovery and other settings](#discovery-and-other-settings)

## Dashboard, API, logging, and updates

### `control_listen`

**Type:** string  
**Default:** not set (the application provides the local dashboard endpoint at `127.0.0.1:8553`)

**TOML:**

```toml
control_listen = "127.0.0.1:8553"
```

Address that serves the dashboard and REST API over plain HTTP; only loopback addresses are allowed. For remote administration, use the HTTPS listening address, an SSH tunnel, or a trusted reverse proxy.

**Note:** This field has no explicit `Config::default()` value, but normal startup exposes the local dashboard unless changed elsewhere.

### `control_listen_https`

**Type:** string  
**Default:** not set

**TOML:**

```toml
control_listen_https = "0.0.0.0:8443"
```

Address that serves the dashboard and REST API over HTTPS to other machines. It uses the same certificate as DoT and DoH. It answers only requests addressed to a public dashboard address, so set the public dashboard address too.

### `control_public_origins`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
control_public_origins = ["https://dns.example.com"]
```

HTTPS addresses other machines reach the dashboard at. The HTTPS listening address and the reverse proxy accept only requests whose Host header is one of these. The proxy must pass this address through unchanged in the Host header.

### `control_trusted_proxies`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
control_trusted_proxies = ["127.0.0.1/32"]
```

Local address ranges your reverse proxy connects from. Only requests from these addresses may use the public dashboard address, and only their X-Forwarded-For client address is trusted.

### `control_token`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
control_token = "REPLACE_WITH_RANDOM_CONTROL_TOKEN"
# Replace with a generated secret before starting the service.
```

Token that authenticates administrator API requests.

### `control_admin_tokens`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
control_admin_tokens = ["REPLACE_WITH_RANDOM_ADMIN_TOKEN"]
# Replace with a generated secret before starting the service.
```

Additional API tokens with full administrative access.

### `control_readonly_tokens`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
control_readonly_tokens = ["REPLACE_WITH_RANDOM_READONLY_TOKEN"]
# Replace with a generated secret before starting the service.
```

API tokens limited to read-only endpoints.

### `users`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[users]]
name = "viewer"
password_hash = "REPLACE_WITH_HASH_FROM_CLI"
role = "readonly"
# Generate password_hash with OnetDNS --cli passwd. Do not use plaintext passwords.
```

See [structured table fields](structures.md#users) for the nested field definitions.

Dashboard users, password hashes, and roles.

### `clients`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[clients]]
name = "Workstation"
ids = ["192.168.1.50/32"]
disable_filtering = false
```

See [structured table fields](structures.md#clients) for the nested field definitions.

Named clients with addresses, tags, filter exceptions, and optional dedicated upstreams.

### `log_level`

**Type:** enum (`error` / `warn` / `info` / `debug` / `trace`)  
**Default:** not set

**TOML:**

```toml
log_level = "info"
```

Minimum detail level written to the system log. Debug and trace produce substantially more output.

### `querylog`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
querylog = false
```

Records query name, client, transport, and result in the recent query log.

### `querylog_size`

**Type:** integer  
**Default:** `200`

**TOML:**

```toml
querylog_size = 200
```

Maximum recent query-log entries kept in memory and exposed to the dashboard.

**Unit:** entries.

### `querylog_retention_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
querylog_retention_secs = 0
```

Removes query-log entries older than this age from memory.

**Unit:** seconds.

### `anonymize_client_ip`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
anonymize_client_ip = false
```

Masks part of each client address before writing it to the query log.

### `querylog_ignored`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
querylog_ignored = ["192.168.1.50/32"]
```

Queries for these domains and descendants are omitted from the query log.

### `querylog_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
querylog_file = "/var/log/OnetDNS/querylog.jsonl"
```

File used to save the recent query log and restore it on the next start.

### `stats_retention_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
stats_retention_secs = 0
```

Time span retained for dashboard time-series charts.

**Unit:** seconds.

### `stats_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
stats_file = "/var/lib/OnetDNS/stats.json"
```

File used to save cumulative counters and top domain and client statistics.

### `persist_flush_secs`

**Type:** integer  
**Default:** `30`

**TOML:**

```toml
persist_flush_secs = 30
```

Interval used to write in-memory query logs and statistics to disk.

**Unit:** seconds.

### `dnstap_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dnstap_file = "/var/log/OnetDNS/queries.dnstap"
```

File that receives dnstap frames.

### `dnstap_identity`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
dnstap_identity = "dns1"
```

Name of this server recorded in dnstap output.

### `release_check`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
release_check = false
```

Periodically checks GitHub for a new release.

## Discovery and other settings

### `ddr_name`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
ddr_name = "dns.example.com"
```

Server name announced so that devices can discover and switch to this server's encrypted DNS (DoH, DoT, DoQ) on their own. The TLS certificate must contain this name. Leave empty to announce nothing.

Devices find it in two ways. They can ask this server over plain DNS (DDR, RFC 9462). When DHCPv4, DHCPv6 or router advertisements are on, those services also send it as encrypted DNS options (DNR, RFC 9463): DHCP to devices that ask for option 162 (DHCPv4) or 144 (DHCPv6), router advertisements to every device. DNR names each encrypted listener at the DNS server addresses that service already hands out (`dhcp_dns`, or `dhcp_server_ip` when that is empty; `dhcp6_dns`; `ra_dns`), but only where the listener is bound to that address or to `0.0.0.0` or `[::]`. A listener on loopback alone is not announced. Announcements go in priority order (DoH, DoH3, DoT, DoQ), and any that do not fit the client's DHCPv4 message size or the 1280-byte limit of a router advertisement are left out.
