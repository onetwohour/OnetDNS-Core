# Resolution, upstreams, caching and DNSSEC

Set `backend` to `forward`, `recurse`, or `split`. The selected backend is used after client and local DNS policies have been evaluated.

## Choosing a resolution backend

| Mode | Setting | Behavior | Operational trade-off |
| --- | --- | --- | --- |
| Forwarding | `backend = "forward"` | Uses a configured recursive upstream | Simpler external resolution, reliant on chosen upstream availability and policy |
| Recursion | `backend = "recurse"` | Walks the hierarchy from root to authoritative servers | More direct control, requires network access to many servers and careful cache/validation behavior |
| Split | `backend = "split"` | Selects forward/recurse using suffix rules | Useful for mixed policies but requires explicit fallback behavior |

The initial installation uses forwarding to the built-in Cloudflare DoH3 endpoints. The backend is independent of whether the *client* talks to OnetDNS using UDP, DoH, DoQ or DNSCrypt.

## Forwarding

```toml
backend = "forward"
upstream_urls = [
  "h3://1.1.1.1/dns-query#cloudflare-dns.com",
  "h3://1.0.0.1/dns-query#cloudflare-dns.com",
]
```

`upstream_urls` accepts supported URL-based upstream endpoints, including encrypted transports. `upstreams` accepts IP-based DNS upstreams. The `#cloudflare-dns.com` part in these examples gives the TLS verification name when addressing a server by IP; changing it can break certificate validation. `bootstrap` is separate from the DNS server you query: it is relevant to resolving names needed to contact upstreams.

Upstream selection is controlled by `upstream_strategy` (such as query statistics, order, round-robin or parallel) and related concurrency/timeout options. These choices can affect both tail latency and total outbound traffic. Test them with repeated queries and a mix of cache hits/misses; do not assume sending more upstream requests always improves latency.

### Forwarding through a SOCKS5 proxy

To reach upstreams through a SOCKS5 proxy such as Tor, set `upstream_proxy` and list the upstreams as `tls://` or `https://`:

```toml
backend = "forward"
upstream_proxy = "socks5://127.0.0.1:9050"
upstream_urls = ["https://dns.quad9.net/dns-query"]
```

The host name is passed to the proxy as written, so the proxy resolves it and this server never looks it up; `bootstrap` is not needed. The certificate is still checked against the upstream's name, connections are still pooled, and a dropped connection is reopened through the proxy. If the proxy asks for a user name and password, set `upstream_proxy_username` and `upstream_proxy_password`. SOCKS5 sends them in plain text, so keep the proxy on this machine or a network you trust.

SOCKS5 carries only TCP. A configuration with a proxy is refused if any forwarding upstream would have to bypass it: entries in `upstreams`, and `udp://`, `tcp://`, `quic://` or `h3://` entries in `upstream_urls`, `fallback_upstreams` or a client's `upstreams`. QUIC upstreams would need CONNECT-UDP over HTTP/3, which OnetDNS does not support. `backend = "recurse"` is refused with a proxy for the same reason.

Some traffic still leaves directly even with a proxy set: stub zones, recursion (including the recursive part of `backend = "split"`), `bootstrap` lookups for stub zones, certificate revocation checks when `tls_revocation` is on, and blocklist and update downloads. A resumed TLS session lets the upstream link connections that use it, as it would without a proxy.

## Recursive resolution

```toml
backend = "recurse"
dnssec = true
```

Recursive resolution requests referrals through the DNS hierarchy instead of sending the question to a preselected recursive provider. The server needs to contact authoritative DNS servers directly; a network that blocks or redirects external UDP/TCP DNS can break this path even if forwarding to a DoH service works. Root hints and recursion limits can be configured separately.

Queries to authoritative servers are plain DNS by default. With `recurse_opportunistic_encryption = true`, servers that also answer over DoT or DoQ are asked that way (RFC 9539). The certificate is not checked, so this hides queries from passive observers but not from an attacker on the path, and a server whose encryption fails is still asked in plaintext. See the [reference](reference/upstreams.md#recurse_opportunistic_encryption).

When recursion fails, check: can the host contact authoritative nameservers, is the root-hints configuration valid, is the system time correct, and is DNSSEC rejection involved? Do not diagnose every `SERVFAIL` as a filter block.

## Split and stub resolution

Use `backend = "split"` when one group of suffixes should recurse and another should forward:

```toml
backend = "split"
split_default = "forward"
split_recurse = ["independent.example"]
```

Use `[[stub_zones]]` when a suffix should be sent to a specific DNS server you select:

```toml
[[stub_zones]]
suffix = "corp.example"
servers = ["192.168.1.53"]
```

These are different mechanisms. A split rule selects a *backend*. A stub zone selects an upstream authority for a *suffix*. A local rewrite changes the answer, while a locally hosted `[[zones]]` publishes authoritative data. Treat them as four different concepts when investigating unexpected private-name responses.

## DNSSEC validation and signing are different

`dnssec = true` configures **validation of received responses** when relevant. DNSSEC helps authenticate DNS data under a valid chain of trust; it does **not** encrypt DNS traffic. It requires accurate server time and correct trust anchors. `dnssec_strict`, anchor management and RFC 5011 behavior have their own settings in the [reference](reference/upstreams.md).

Authoritative zone DNSSEC signing is a separate capability configured under a zone's nested fields. Enabling recursive DNSSEC validation does not sign domains served by OnetDNS.

### Minimal validation tests

```sh
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com DNSKEY +dnssec
```

The returned flags and DNSSEC records depend on both the queried zone and the client's flags. A `+dnssec` response alone does not establish successful DNSSEC validation. To diagnose failures, compare a known-good signed name, a deliberately invalid test name from a trusted DNSSEC test provider, and the server logs; do not infer correctness solely from the presence of RRSIG records.

## Cache behavior

`cache_enabled`, `cache_size`, `min_ttl`, `max_ttl`, `neg_min_ttl` and `neg_max_ttl` govern cached responses and their lifetimes. Other settings manage stale answers, prefetch and sharding. The role of the cache is to avoid repeated upstream or recursive work; it does not remove the need for valid policy handling.

| Condition | What to check |
| --- | --- |
| First query slow, subsequent queries fast | Was the first query a cache miss? Was the second served from cache? |
| An allow rule seems not to take effect | Is the client or OS still using an earlier cached response? |
| SERVFAIL under recursion | Is there a DNSSEC failure or unreachable authority? |
| Stale response appears | Are stale-answer settings enabled and within their limits? |
| Memory rises after increasing cache size | Inspect total RSS/PSS and live entry counts, not only configured entry capacity. |

## Troubleshooting in order

1. Query the **running listener** with `dig @IP NAME TYPE`.
2. Check whether the name matched a local rule, client policy, rewrite or zone.
3. Determine whether the selected backend was forward, recurse, split or stub.
4. Inspect upstream connectivity, timeout and DNSSEC validation independently.
5. Repeat the exact query and compare cache-hit behavior; be explicit about client-side caches.

`OnetDNS --cli query` contacts an upstream without passing through the running server's filter/cache policy. It is a useful upstream diagnostic, but not a full integration test of your DNS listener.

Related: [Filtering](filtering.md) · [Examples](examples.md) · [Reference](reference/upstreams.md).
