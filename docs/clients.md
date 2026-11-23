# Client identification and per-client policies

Client profiles select filtering and upstream behavior according to a source address, MAC address where available, or a transport-specific client identifier.

## Identify the actual client

Depending on transport and network topology, OnetDNS may see:

- the source IP address or subnet of the DNS connection;
- an available MAC address on directly observable networks;
- an authenticated or configured client identifier on an encrypted DNS transport.

A NAT router, VPN gateway or proxy may hide the individual device address. Oblivious DoH hides it by design: a query relayed by an ODoH proxy shows only the proxy's address, so profiles, ACLs, rate limits and the query log apply to the proxy (see [Oblivious DoH](encrypted-dns.md#oblivious-doh)). An Ethernet MAC address is generally not preserved across routed networks. Do not assume a DHCP lease name, hostname or friendly dashboard label provides authenticated client identity.

Send a query from the device, inspect its identity in Query log, and match that identity with `ids`, `client_ids`, or `mac`.

## Client profile syntax

```toml
[[clients]]
name = "Kids"
ids = ["192.168.1.50/32", "192.168.1.51/32"]
tags = ["family"]
safe_search = true
blocked_services = ["tiktok", "youtube"]

[[clients]]
name = "Lab"
ids = ["192.168.1.60/32"]
disable_filtering = true
ignore_querylog = true
```

Each `[[clients]]` starts a new profile. Put unrelated top-level settings before any table arrays so they are not accidentally interpreted as fields of the final profile. See [Structured tables](reference/structures.md).

## Policy fields

| Field | Purpose | Important distinction |
| --- | --- | --- |
| `ids` | Match IP addresses/CIDR ranges | Match the source the server observes. |
| `client_ids` | Match supported client identity strings | Relevant only when the transport provides that identity. |
| `mac` | Match hardware addresses when observable | Usually not available across routers. |
| `block`, `allow` | Client-specific domain rules | These are policy rules, not port-level admission rules. |
| `disable_filtering` | Bypass filter rules for the client | Does not switch off DNS resolution. |
| `safe_search` | Override global SafeSearch | Optional Boolean; omission follows global behavior. |
| `blocked_services` | Restrict named services | Confirm names with the CLI. |
| `upstreams` | Select client-specific forwarders | Applies to resolution, not inbound DNS transport. |
| `ignore_querylog`, `ignore_stats` | Exclude the client from corresponding telemetry | These are separate settings. |
| `tags` | Label for rule/policy matching | A descriptive name alone does not select a profile. |

Use `OnetDNS --cli services` to list the service identifiers recognized by the build. A service may require multiple hostnames; its DNS behavior can change as the service changes its infrastructure.

## How precedence affects profiles

Client policy is evaluated before general filter rules. `disable_filtering` allows requests past the filter, and client allow rules take precedence over client block rules. If no client rule matches, evaluation continues through the global stages. Profile selection follows the configured match criteria.

For a surprising result, inspect the matched profile and the winning rule stage rather than reordering entries experimentally. Also distinguish client *policy* from DNS client *admission*: `acl_allow`, `acl_deny` and related settings govern whether queries are permitted; a `[[clients]]` profile changes how an admitted query is treated.

## Use a client-specific upstream

```toml
[[clients]]
name = "Workstation"
ids = ["192.168.1.60/32"]
upstreams = ["https://1.1.1.1/dns-query#cloudflare-dns.com"]
```

The URL is illustrative of a supported upstream format. Verify it is reachable from the server. Upstream selection does not enable an encrypted listening socket; the client may still talk to OnetDNS over classic UDP or TCP DNS.

## How to test a policy

1. Send a query to OnetDNS from a client known to match the profile.
2. Send the same name/type from another client that should not match.
3. Inspect Query log or another available diagnostic to confirm both the source identity and applied rule.
4. Check a blocked and an allowed name, and consider A and AAAA separately if the rule is record-type-specific.
5. If both appear as the same client, inspect VPN, NAT, router forwarding or upstream proxying before changing rules.

Related: [Filtering](filtering.md) · [Encrypted DNS](encrypted-dns.md) · [Reference: structured tables](reference/structures.md).
