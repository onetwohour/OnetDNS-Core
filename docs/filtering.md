# Filtering and rule evaluation

Filtering evaluates domain names and record types against lists, local rules, and client policies. The resulting decision determines whether the DNS response is allowed, modified, or blocked.

## Rule sources

Configure filtering through a subscription URL, a local list, or inline rules. DNSCrypt, DoH, DoT, DoQ, and plain DNS use the same policy engine after their respective transport decoders.

| Source | Relevant keys | Notes |
| --- | --- | --- |
| Downloaded blocklists | `blocklist_urls`, `disabled_blocklist_urls`, `list_refresh_secs` | Only loaded lists contribute rules. A URL is an input to a refresh workflow, not a guaranteed live data source. |
| Local files | `blocklists`, `allowlists` | The service account must be able to read the files. |
| Inline rules | `block_rules`, `allow_rules` | Useful for minimal, reproducible tests and exceptions. |
| Response Policy Zones | `rpz_files`, `rpz_urls` | RPZ can express actions beyond a simple blocked hostname. |
| Per-client policy | `[[clients]]` | Client allow/block settings may override global behavior. |
| Specialized controls | `refused_domains`, `blocked_services`, `safe_search`, related settings | Each has its own semantics; not all are ordinary domain-list entries. |

### Start with an explicit rule

```toml
block_rules = ["||example.com^", "||tracker.example^"]
allow_rules = ["@@||needed.example^"]
```

`example.com` is a normally resolvable public test domain; temporarily block it **after confirming a baseline answer**. This verifies the policy path without relying on a third-party list. Query the actual server listener (`dig @SERVER example.com A`) and inspect the Query log rather than using `OnetDNS --cli query`, which bypasses the running filter pipeline.

## Accepted syntax and limitations

Hosts-style rules and supported AdGuard/ABP-style DNS rules can be loaded. Rule support is **DNS-specific**: the engine sees the DNS question name and type, not the HTTP path, page layout, script context or cookies. A browser extension's cosmetic filters or URL-path conditions cannot be interpreted as DNS blocking rules.

A suffix-style rule such as `||ads.example^` is intended to apply to the named host and appropriate subdomains, not merely any string containing those bytes. A leading exception (`@@`) denotes allowed behavior where supported. The precise behavior of modifiers and exceptional rule kinds must be checked against the running build rather than inferred from a browser ad blocker.

OnetDNS also inspects CNAME chains for blocked names, so a query for an apparently harmless alias can be blocked because its target matches an active rule. This is useful but can explain unexpected false positives: the Query log and rule explanation matter more than the original QNAME alone.

## Rule priority is part of the product behavior

The filter evaluates matching rules in the following priority order:

1. Matched client profile: disable filtering, then its explicit allow and block lists.
2. RPZ client-address rule.
3. Client rules (applicable allow rules before client block rules).
4. Important allow rules.
5. No-response rules, then important block rules.
6. Refuse, NODATA and rewrite/local-zone stages.
7. General allow rules, regex and general block rules.
8. Record-type-specific rules and the default allow result.

Rules are resolved by these stages rather than by their order in the TOML file. To diagnose a conflict, inspect the matched stage and rule in Query log.

## Blocking response versus rule match

`block_response` controls the response produced **after** a domain has been classified as blocked. Accepted modes in the configuration schema include `nxdomain`, `zero_ip`, `refused` and `custom`; NXDOMAIN is the built-in default. The `custom` mode uses `block_ipv4`/`block_ipv6`; `blocked_response_ttl` sets the response TTL. Distinguish the following:

| Result | Client-visible meaning |
| --- | --- |
| NXDOMAIN | The requested name does not exist from the client's perspective. |
| Zero IP | An address response pointing to an all-zero address for supported address types. |
| REFUSED | The server declines to answer the query. |
| No response / Drop rule | No DNS response is sent for the matched rule. |

These choices can affect application retries and timeout behavior; none is universally best. Test the intended class of clients after changing the response mode.

## `NORESPONSE`: deliberately leave a query unanswered

Some unwanted clients repeatedly query a particular domain, even after receiving NXDOMAIN or REFUSED. OnetDNS provides `NORESPONSE` for cases where the operator wants to give those queries **no DNS answer at all**. This can make the querying software wait for a timeout or retry instead of immediately receiving a negative response. It is an intentional choice to withhold a reply, not a claim that the domain does not exist.

`NORESPONSE` is an **OnetDNS-specific action for a filtering rule**, written using the `dnsrewrite` modifier. It is not a DNS response code and is not accepted by the global `block_response` option.

```toml
block_rules = [
    "||unwanted.example^$dnsrewrite=NORESPONSE",
]
```

The example applies to `unwanted.example` and its subdomains. The same rule can be placed in a loaded blocklist. A regular-expression rule is also supported:

```toml
block_rules = [
    "/^scan[0-9]+\\.example$/$dnsrewrite=NORESPONSE",
]
```

The action name is case-insensitive, so `noresponse` and `NORESPONSE` have the same meaning. Rule matching still follows the normal priority system: for example, a matching *important allow* rule takes precedence over `NORESPONSE`.

### Behavior by transport

On a matching query, the filter returns `Drop`. OnetDNS records the event as blocked with the result `DROPPED`; it does not send NXDOMAIN, REFUSED, SERVFAIL, or an empty NOERROR answer.

- **UDP:** No DNS response datagram is sent. A client normally waits for its configured timeout, and some clients retry or use another resolver.
- **Plain DNS over TCP:** The TCP connection is accepted before the DNS rule is evaluated. If the rule matches, OnetDNS sends no DNS response frame and closes that connection. The TCP handshake is **not** suppressed.
- **DNSCrypt over TCP:** The connection is likewise established before the DNS question can be decrypted and checked. A dropped query receives no encrypted DNS response, and the connection closes without a DNS answer.
- **Other encrypted transports:** The DNS decision is still `Drop`; the HTTP, TLS, or QUIC layer controls how its connection or stream ends. Do not assume that withholding a DNS answer is equivalent to rejecting a transport connection.

### Choosing this action

Use `NORESPONSE` selectively when silence is more useful than a prompt negative reply, such as with a specific name that is being queried repeatedly without authorization. It does not block connection establishment, authenticate a client, or prevent the incoming packets from consuming server resources. Clients may retry more often or fall back to another resolver, so silence does **not** guarantee that the requester will spend more resources than the server.

For ordinary ad and tracking domains, `nxdomain` or `refused` usually provides a more predictable result because applications receive an immediate answer. `NORESPONSE` can increase the delay before an application reports a DNS failure.

To verify the action, first query a normally resolvable name **before** adding a temporary rule for it. After enabling `||example.com^$dnsrewrite=NORESPONSE` and applying the configuration, run:

```sh
dig @127.0.0.1 example.com A +tries=1 +time=2
dig +tcp @127.0.0.1 example.com A +tries=1 +time=2
```

Replace `127.0.0.1` with the actual DNS listener. UDP should receive no DNS answer; TCP may report a closed connection rather than a timeout. The Query log should record `DROPPED`. Remove the temporary rule after testing. If an important allow rule or client policy takes precedence, the query may still be answered.

## Per-client interaction

When a client matches a `[[clients]]` profile, `disable_filtering`, `allow`, `block` and other fields can change its result independently of the global lists. The observed source identity matters: clients behind a router, proxy or VPN may share one address from the server's viewpoint. Use [Client policies](clients.md) to verify which identity and profile matched.

## Managing large lists

Domain rules are compiled into a compact read-only index. During a refresh, the previous index and the new build may coexist, raising peak memory usage. For small VMs, monitor both steady memory and peak consumption during list updates.

`track_rule_hits = true` retains additional per-rule metadata and counters. Account for the extra memory when sizing large lists.

## Diagnose an unexpected block

1. Reproduce the exact QNAME and QTYPE from the affected client, not from an unrelated host.
2. Inspect Query log: source client, transport, result, rule and list attribution where available.
3. Check whether a global rule, client rule, RPZ action or CNAME alias was responsible.
4. Create a narrow exception, then reload/apply and retest the same QNAME and QTYPE.
5. If the response seems unchanged, eliminate browser/OS caches or query the server directly with `dig @SERVER NAME TYPE`.

A missing query-log row is not proof that the request was never processed: logging may be disabled or events dropped under load. Use server counters and a packet-level diagnostic where appropriate.

## Filtering scope

DNS filtering cannot remove ads hosted under the same hostname as wanted content, cannot read encrypted URL paths, and cannot enforce a policy on a client that consistently bypasses the configured resolver. It should be evaluated for its real scope, not as a full HTTP/content blocker.

Related: [Clients](clients.md) · [Configuration reference](reference/filtering.md) · [Troubleshooting](troubleshooting.md)

