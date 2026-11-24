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

A DNSCrypt server is given by its `sdns://` stamp, in `upstream_urls`, `fallback_upstreams`, a client's `upstreams` or a stub zone's `servers`:

```toml
upstream_urls = ["sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"]
```

The stamp carries the server's IP address, its provider name and the key that signs its certificates, so it needs no `bootstrap`. OnetDNS fetches the certificate from the server itself and uses it only if the stamp's key signed it and it is within its validity period; it fetches it again about once an hour. A UDP answer that comes back truncated is asked again over TCP, so the server must accept DNSCrypt over TCP on the same port. Only DNSCrypt server stamps are accepted; write DoH, DoT and DoQ servers as URLs.

To hide your address from the DNSCrypt server, send the queries through an Anonymized DNSCrypt relay: put `#` and the relay's stamp after the server's stamp.

```toml
upstream_urls = ["sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20#sdns://gQ4xOTIuMC4yLjE6NTQ0Mw"]
```

Everything for that server then goes through the relay, the certificate lookup included. The server sees the relay's address, and the relay sees only encrypted queries. A relay run by the server's operator sees both your address and your queries, so pick one run by someone else. The relay stamp must carry an IP address. `sdns://gQ4xOTIuMC4yLjE6NTQ0Mw` above stands for a relay at `192.0.2.1:5443`; replace it with a real relay's stamp.

Upstream selection is controlled by `upstream_strategy` (such as query statistics, order, round-robin or parallel) and related concurrency/timeout options. These choices can affect both tail latency and total outbound traffic. Test them with repeated queries and a mix of cache hits/misses; do not assume sending more upstream requests always improves latency.

### Forwarding through a SOCKS5 proxy

To reach upstreams through a SOCKS5 proxy such as Tor, set `upstream_proxy` and list the upstreams as `tls://` or `https://`:

```toml
backend = "forward"
upstream_proxy = "socks5://127.0.0.1:9050"
upstream_urls = ["https://dns.quad9.net/dns-query"]
```

The host name is passed to the proxy as written, so the proxy resolves it and this server never looks it up; `bootstrap` is not needed. The certificate is still checked against the upstream's name, connections are still pooled, and a dropped connection is reopened through the proxy. If the proxy asks for a user name and password, set `upstream_proxy_username` and `upstream_proxy_password`. SOCKS5 sends them in plain text, so keep the proxy on this machine or a network you trust.

SOCKS5 carries only TCP. A configuration with a proxy is refused if any forwarding upstream would have to bypass it: entries in `upstreams`, and `udp://`, `tcp://`, `quic://`, `h3://`, `odoh://`, `ohttp://` or `sdns://` entries in `upstream_urls`, `fallback_upstreams` or a client's `upstreams`. QUIC upstreams would need CONNECT-UDP over HTTP/3, which OnetDNS does not support. `backend = "recurse"` is refused with a proxy for the same reason.

Some traffic still leaves directly even with a proxy set: stub zones, recursion (including the recursive part of `backend = "split"`), `bootstrap` lookups for stub zones, certificate revocation checks when `tls_revocation` is on, and blocklist and update downloads. A resumed TLS session lets the upstream link connections that use it, as it would without a proxy.

### Oblivious DoH upstreams

An `odoh://` upstream sends each query encrypted to an Oblivious DoH target (RFC 9230) through a separate proxy:

```toml
upstream_urls = [
  "odoh://odoh-proxy.example/proxy?targethost=odoh-target.example&targetpath=/dns-query",
]
```

The proxy learns this server's address but not the queries; the target answers the queries but sees only the proxy's address. The split protects you only if the proxy and the target are run by different operators who do not share logs.

OnetDNS fetches the target's key configuration directly from `https://odoh-target.example/.well-known/odohconfigs` before the first query to that target, then again in the background every 12 to 22 hours. That fetch reaches the target from this server's own address, so the target can see that this server uses it, though not what it asks; only the first query, which waits for the fetch, can be matched to this server by its timing. When the target changes its key, queries through it fail until the new configuration arrives 30 seconds to 5 minutes later. Fetching it at once would let the target match the fetch to the query that triggered it. Host names in the URL, the proxy's and the target's, are resolved through `bootstrap` like other upstream names; an upstream whose proxy or target points at one of this server's own listeners is rejected.

### Oblivious HTTP upstreams

An `ohttp://` upstream sends each query as a DoH request encrypted to an Oblivious HTTP gateway (RFC 9458) through a relay:

```toml
upstream_urls = [
  "ohttp://ohttp-relay.example/relay?targethost=dns.example&targetpath=/dns-query",
]
```

The URL before `?` is the relay resource, and `targethost` and `targetpath` name the DoH server behind the gateway. Only the relay's path is sent to the relay. Each relay resource forwards to one gateway chosen by whoever runs the relay, so it must be one that forwards to `dns.example`'s gateway. The relay learns this server's address but not the queries; the gateway answers the queries but sees only the relay's address. As with ODoH, the split protects you only if different operators run the two.

OnetDNS fetches the gateway's keys from `https://dns.example/.well-known/ohttp-gateway` (RFC 9540) on the same schedule as an ODoH target's configuration. When the relay answers with a 4xx status, such as a gateway that no longer has the cached key, the query fails and the keys are fetched again 30 seconds to 5 minutes later. Requests are padded to multiples of 128 bytes so their size says less about the name. Host names and loops are handled as for `odoh://` upstreams. To be the relay or the gateway for other clients instead, see [Oblivious HTTP](encrypted-dns.md#oblivious-http).

## Recursive resolution

```toml
backend = "recurse"
dnssec = true
```

Recursive resolution requests referrals through the DNS hierarchy instead of sending the question to a preselected recursive provider. The server needs to contact authoritative DNS servers directly; a network that blocks or redirects external UDP/TCP DNS can break this path even if forwarding to a DoH service works. Root hints and recursion limits can be configured separately.

Queries to authoritative servers are plain DNS by default. With `recurse_opportunistic_encryption = true`, servers that also answer over DoT or DoQ are asked that way (RFC 9539). The certificate is not checked, so this hides queries from passive observers but not from an attacker on the path, and a server whose encryption fails is still asked in plaintext. The dashboard's Upstreams page has the switch and lists each authoritative server tried, with whether it answered over DoT or DoQ. See the [reference](reference/upstreams.md#recurse_opportunistic_encryption).

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
