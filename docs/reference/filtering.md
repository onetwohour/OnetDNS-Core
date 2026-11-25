# Filtering and policy — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Policy model

Filtering combines subscription lists, inline rules, and per-client policies. Rule priority determines which action applies when multiple rules match. See [Filtering](../filtering.md) for the classification order and diagnostic procedure. `block_response` changes how an already-blocked lookup is answered; it does not change the rule match itself. `track_rule_hits` increases the retained per-rule state and should be measured on large lists.

## Options in this chapter

- [Filtering, rewriting, and local policy](#filtering-rewriting-and-local-policy)
- [Policy rules and WASM](#policy-rules-and-wasm)

## Filtering, rewriting, and local policy

### `blocklists`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
blocklists = ["/etc/OnetDNS/lists/blocked.txt"]
```

Local files containing block rules.

### `allowlists`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
allowlists = ["/etc/OnetDNS/lists/allowed.txt"]
```

Local files containing allow rules.

### `blocklist_urls`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
blocklist_urls = ["https://lists.example.net/block.txt"]
```

URLs downloaded periodically for block rules.

### `blocklist_titles`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
blocklist_titles = ["Example blocklist"]
```

Display names matched by position to blocklist URLs.

### `disabled_blocklist_urls`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
disabled_blocklist_urls = ["https://lists.example.net/old.txt"]
```

Blocklist URLs retained in configuration but not downloaded or applied.

### `block_rules`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
block_rules = ["||ads.example.com^", "||tracker.example.com^$dnsrewrite=NORESPONSE"]
# The NORESPONSE rule action is explained in the filtering guide.
```

Block rules written directly in the configuration file.

### `allow_rules`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
allow_rules = ["@@||allowed.example.com^"]
```

Allow rules that take precedence over block rules.

### `list_refresh_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
list_refresh_secs = 0
```

Interval used to download remote blocklists and RPZ data again.

**Unit:** seconds.

### `blocked_services`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
blocked_services = ["youtube"]
```

Selects the services to block.

### `refused_domains`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
refused_domains = ["refused.example.com"]
```

Answers queries for these domains and their subdomains with REFUSED.

### `safe_search`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
safe_search = false
```

Rewrites supported search services to their safe-search endpoints.

### `safe_browsing`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
safe_browsing = false
```

Adds the built-in malicious and phishing site list to filtering.

### `parental_control`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
parental_control = false
```

Adds the built-in adult-content list to filtering.

### `rpz_files`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
rpz_files = ["/etc/OnetDNS/lists/policy.rpz"]
```

Local Response Policy Zone files.

### `rpz_urls`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
rpz_urls = ["https://lists.example.net/policy.rpz"]
```

URLs downloaded periodically for RPZ rules.

### `block_response`

**Type:** enum (`nxdomain` / `zero_ip` / `refused` / `custom`)  
**Default:** `nxdomain`

**TOML:**

```toml
block_response = "nxdomain"
# Alternatives: "zero_ip", "refused", "custom".
# For "custom", also set block_ipv4 and/or block_ipv6.
```

Selects NXDOMAIN, zero address, REFUSED, or custom-address responses for blocked queries.


**Custom-address response:**

```toml
block_response = "custom"
block_ipv4 = "0.0.0.0"
block_ipv6 = "::"
```

`NORESPONSE` is a separate per-rule action, not a `block_response` enum value. See [NORESPONSE: deliberately leave a query unanswered](../filtering.md#noresponse-deliberately-leave-a-query-unanswered) for syntax, rule precedence, transport behavior, and testing.

### `block_ipv4`

**Type:** string  
**Default:** not set

**TOML:**

```toml
block_ipv4 = "0.0.0.0"
# Only used with block_response = "custom".
```

IPv4 address returned when the block response mode is custom.

### `block_ipv6`

**Type:** string  
**Default:** not set

**TOML:**

```toml
block_ipv6 = "::"
# Only used with block_response = "custom".
```

IPv6 address returned when the block response mode is custom.

### `blocked_response_ttl`

**Type:** integer  
**Default:** `10`

**TOML:**

```toml
blocked_response_ttl = 10
```

TTL placed on synthesized block responses.

**Unit:** seconds.

### `block_aaaa`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
block_aaaa = false
```

Blocks AAAA queries so clients do not receive IPv6 addresses.

### `bogus_nxdomain`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
bogus_nxdomain = ["198.51.100.10"]
```

Converts responses containing configured IP addresses to NXDOMAIN.

### `domain_needed`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
domain_needed = false
```

Keeps short names without a dot (such as nas) from being sent to outside DNS servers. Names from this server's zones and DHCP-registered devices are still answered.

### `bogus_priv`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
bogus_priv = false
```

Keeps reverse lookups of private IP addresses from being sent to outside DNS servers. DHCP-registered devices and reverse zones you created are still answered.

### `empty_zones`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
empty_zones = false
```

Keeps queries for special zones that do not exist on the internet, such as private reverse zones and home.arpa, from being sent to outside DNS servers. A zone you created with the same name still answers.

### `local_ttl`

**Type:** integer  
**Default:** `300`

**TOML:**

```toml
local_ttl = 300
```

Default TTL for local records and rewrite responses.

**Unit:** seconds.

### `track_rule_hits`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
track_rule_hits = false
```

Counts how many times each filter rule is applied.

### `rewrites`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[rewrites]]
domain = "printer.lan"
answer = "192.168.1.20"
```

See [structured table fields](structures.md#rewrites) for the nested field definitions.

Rules that synthesize fixed A, AAAA, or CNAME answers by domain name.

### `dynamic_records`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[dynamic_records]]
name = "service.example.com"
qtype = "A"
mode = "round_robin"
values = ["192.0.2.10", "192.0.2.11"]
ttl = 60
probe_port = 0
```

See [structured table fields](structures.md#dynamic_records) for the nested field definitions.

Local DNS records whose values may change while the server is running.

### `local_zones`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[local_zones]]
name = "corp.example"
kind = "static"
records = ["printer.corp.example 192.0.2.20"]
```

See [structured table fields](structures.md#local_zones) for the nested field definitions.

Makes this server answer a domain and the names under it directly. Each zone has a kind. Deny blocks, refuse refuses, and always_null answers with the zero address. Redirect gives every name in the zone the same answer. Static answers only the names listed in records and reports every other name as nonexistent. Transparent lifts an enclosing zone's handling inside this zone. When zones overlap, the more specific zone applies.

### `service_schedule`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[service_schedule]]
days = ["mon", "tue", "wed", "thu", "fri"]
start = "09:00"
end = "17:00"
```

See [structured table fields](structures.md#service_schedule) for the nested field definitions.

Pauses service blocking during the listed days and times. Blocklists and custom rules stay in effect.

## Policy rules and WASM

### `policy`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[policy]]
action = "block"
clients = ["192.168.1.0/24"]
suffixes = ["ads.example.com"]
qtypes = ["A", "AAAA"]
```

See [structured table fields](structures.md#policy) for the nested field definitions.

Declarative rules that allow, block, refuse, or rewrite queries by client, name, type, and time.

### `wasm_policy`

**Type:** string  
**Default:** not set

**TOML:**

```toml
wasm_policy = "/etc/OnetDNS/policy.wasm"
```

Path to one WASM module used for pre-query policy decisions.

### `wasm_plugins`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
wasm_plugins = [{ path = "/etc/OnetDNS/policy.wasm", name = "policy", fail_mode = "open" }]
# Provide an existing WASM file; valid fail_mode options are defined by the parser.
```

Ordered WASM policy modules and their individual failure modes.

### `wasm_fail_mode`

**Type:** enum (`closed-refuse` / `closed-block` / `open`)  
**Default:** `"closed-refuse"`

**TOML:**

```toml
wasm_fail_mode = "closed-refuse"
```

Controls whether a WASM failure refuses, blocks, or allows the query to continue.
