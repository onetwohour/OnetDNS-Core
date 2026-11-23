# Core server — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## How the core settings fit together

- `listen` selects *where* clients connect; `do_udp` and `do_tcp` select which classic DNS transports are enabled. A loopback listener cannot serve other machines, even if the host firewall permits port 53.
- `listen_dot`, `listen_doh`, `listen_doh3`, `listen_doq` and `listen_dnscrypt` enable independent inbound transports. They do not select the protocol used to contact an upstream resolver.
- `workers = 0` requests automatic sizing; it does not mean that DNS processing is disabled.
- Caching affects repeated lookups. A fast response does not establish that a filter rule was evaluated; confirm whether a cached or special fast path was used.
- Bounds and timeouts are distinct: a limit of zero can mean automatic, disabled or no retention depending on the option. Consult the individual description rather than applying one interpretation to all numeric settings.

## Options in this chapter

- [General and operating mode](#general-and-operating-mode)
- [Listening interfaces and incoming transports](#listening-interfaces-and-incoming-transports)
- [Query processing and EDNS](#query-processing-and-edns)
- [Caching and TTL](#caching-and-ttl)

## General and operating mode

### `mode`

**Type:** enum (`personal` / `public`)  
**Default:** `personal`

**TOML:**

```toml
mode = "personal"
```

Selects personal or public operating mode. Personal mode uses private/loopback ACL presets unless overridden; public mode accepts public clients by default. Additional access and rate-limit policies are configurable separately.

### `backend`

**Type:** enum (`forward` / `recurse` / `split`)  
**Default:** `forward`

**TOML:**

```toml
backend = "forward"
```

Forward to upstream DNS hands queries to the servers you list. Resolve recursively looks names up from the root servers without any upstream. Split by domain picks one of the two for each domain.

### `workers`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
workers = 0
```

Number of threads that receive and handle plain DNS queries. Zero sizes it automatically from the CPU count. Raise it only when the server is busy but the CPU still has headroom.

**Unit:** threads.

## Listening interfaces and incoming transports

### `do_udp`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
do_udp = true
```

Accepts plain DNS queries over UDP.

### `do_tcp`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
do_tcp = true
```

Accepts plain DNS queries over TCP.

### `listen`

**Type:** array  
**Default:** `["127.0.0.1:53"]`

**TOML:**

```toml
listen = ["127.0.0.1:53", "192.168.1.10:53"]
```

IP addresses and ports that accept standard DNS requests.

### `listen_dot`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
listen_dot = ["0.0.0.0:853"]
# Requires appropriate TLS certificate/key configuration.
```

IP addresses and ports that accept DoT requests.

### `listen_doh`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
listen_doh = ["0.0.0.0:443"]
# Requires appropriate TLS certificate/key configuration.
```

IP addresses and ports that accept DoH requests.

### `listen_doq`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
listen_doq = ["0.0.0.0:853"]
# Requires appropriate TLS certificate/key configuration.
```

IP addresses and ports that accept DoQ requests.

### `listen_doh3`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
listen_doh3 = ["0.0.0.0:443"]
# Requires appropriate TLS certificate/key configuration.
```

IP addresses and ports that accept DoH3 requests.

### `listen_dnscrypt`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
listen_dnscrypt = ["0.0.0.0:5443"]
# Binds locally; generate stamps with the publicly reachable address.
```

Local IP addresses and ports on which DNSCrypt accepts both UDP and TCP requests. `0.0.0.0:5443` binds all local IPv4 interfaces; the public client address is supplied separately when generating a DNS stamp. A query that came through an Anonymized DNSCrypt relay shows the relay's address, so client policies, the ACL, rate limits and the query log all go by that address. See [DNSCrypt setup](../encrypted-dns.md#dnscrypt-setup).

### `dnscrypt_provider_name`

**Type:** string  
**Default:** `"2.dnscrypt-cert.onetdns"`

**TOML:**

```toml
dnscrypt_provider_name = "2.dnscrypt-cert.dns.example.com"
```

Provider name written into DNSCrypt certificates.

### `dnscrypt_relay`

**Type:** bool  
**Default:** `false`

**TOML:**

```toml
dnscrypt_relay = true
```

Passes Anonymized DNSCrypt queries arriving at `listen_dnscrypt` on to their server and returns the answer. The server sees only this server's address. The ACL and rate limits apply to the sender's address before anything is passed on. See [Running a relay](../encrypted-dns.md#running-a-relay).

### `dnscrypt_relay_ports`

**Type:** array  
**Default:** `[443]`

**TOML:**

```toml
dnscrypt_relay_ports = [443, 5443]
```

Server ports relayed queries may go to. Queries for any other port are not passed on.

### `dnscrypt_relay_allow_targets`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
dnscrypt_relay_allow_targets = ["192.168.1.0/24"]
```

Networks (CIDR) relayed queries may go to even though they are not public addresses or are this server. Left empty, queries go only to public addresses of other servers.

### `doh_path`

**Type:** string  
**Default:** `"/dns-query"`

**TOML:**

```toml
doh_path = "/dns-query"
```

HTTP path used for DoH requests, normally /dns-query.

### `proxy_protocol_ports`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
proxy_protocol_ports = [53]
```

Local listener ports that parse PROXY protocol headers.

### `proxy_protocol_trusted`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
proxy_protocol_trusted = ["127.0.0.1/32"]
```

Proxy address ranges allowed to send PROXY protocol headers.

## Query processing and EDNS

### `query_timeout_secs`

**Type:** integer  
**Default:** `5`

**TOML:**

```toml
query_timeout_secs = 5
```

Maximum time to wait for one upstream DNS response.

**Unit:** seconds.

### `max_inflight`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
max_inflight = 0
```

Limits the number of DNS queries processed at the same time.

### `edns_buffer_size`

**Type:** integer  
**Default:** `1232`

**TOML:**

```toml
edns_buffer_size = 1232
```

UDP answer size this server advertises that it can receive. UDP answers sent by this server never exceed 1232 bytes regardless of this value.

**Unit:** bytes.

### `edns_padding_block`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
edns_padding_block = 0
```

Padding block size for encrypted DNS messages. Zero disables padding.

**Unit:** bytes.

### `edns_tcp_keepalive_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
edns_tcp_keepalive_secs = 0
```

TCP connection lifetime advertised through the EDNS TCP Keepalive option.

**Unit:** seconds.

### `deny_any`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
deny_any = true
```

Returns only a short answer to ANY queries, which ask for every record type at once. ANY queries are commonly used in amplification attacks.

### `minimal_responses`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
minimal_responses = false
```

Keeps answers small by including only what was asked and leaving out supplementary records.

### `ecs_mode`

**Type:** enum (`off` / `strip` / `send`)  
**Default:** `off`

**TOML:**

```toml
ecs_mode = "off"
```

Controls whether EDNS Client Subnet is removed, preserved, or sent with a configured value.

### `ecs_custom_ip`

**Type:** string  
**Default:** not set

**TOML:**

```toml
ecs_custom_ip = "203.0.113.1"
# Requires ecs_mode = "send" for client-subnet injection.
```

Fixed client address or subnet used when sending ECS.

### `dns64_prefix`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dns64_prefix = "64:ff9b::/96"
```

NAT64 prefix used to synthesize IPv6 addresses from IPv4 answers.

### `dns64_synthall`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dns64_synthall = false
```

Synthesizes DNS64 addresses from A records even when AAAA records already exist.

## Caching and TTL

### `cache_size`

**Type:** integer  
**Default:** `4096`

**TOML:**

```toml
cache_size = 4096
```

Maximum number of DNS responses kept in memory. Zero disables the response cache.

**Unit:** entries.

### `min_ttl`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
min_ttl = 0
```

Raises shorter authoritative TTLs to this value before caching.

**Unit:** seconds.

### `max_ttl`

**Type:** integer  
**Default:** `86400`

**TOML:**

```toml
max_ttl = 86400
```

Longest time an answer stays in the cache. Longer TTLs are shortened to this value, including in the answer sent to the client.

**Unit:** seconds.

### `neg_min_ttl`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
neg_min_ttl = 0
```

Keeps "name does not exist" and "no such record type" answers in the cache for at least this long. Signed DNSSEC answers are never kept longer than their signatures allow.

**Unit:** seconds.

### `neg_max_ttl`

**Type:** integer  
**Default:** `86400`

**TOML:**

```toml
neg_max_ttl = 86400
```

Longest time "name does not exist" and "no such record type" answers stay in the cache. Longer TTLs are shortened to this value, including in the answer sent to the client.

**Unit:** seconds.

### `cache_enabled`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
cache_enabled = true
```

Stores DNS responses in memory for repeated queries.

### `sharded_cache`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
sharded_cache = false
```

Splits the answer cache into parts so that many simultaneous queries do not wait on each other. Increases throughput on servers with many CPU cores.

### `cache_shards`

**Type:** integer  
**Default:** `16`

**TOML:**

```toml
cache_shards = 16
```

Number of parts the cache is split into when the split cache is on.

### `serve_stale_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
serve_stale_secs = 0
```

How long an expired cached response may be served when upstream resolution fails. Requires an enabled response cache with a nonzero TTL.

**Unit:** seconds.

### `serve_expired_reply_ttl`

**Type:** integer  
**Default:** `30`

**TOML:**

```toml
serve_expired_reply_ttl = 30
```

TTL placed on expired responses sent to clients.

**Unit:** seconds.

### `serve_expired_ttl_reset`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
serve_expired_ttl_reset = false
```

Each time an expired answer is served, the period during which it may still be served starts over.

### `serve_expired_client_timeout_ms`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
serve_expired_client_timeout_ms = 0
```

Switches to an expired cached response if no fresh answer arrives within this time.

**Unit:** ms.

### `serve_stale_refresh`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
serve_stale_refresh = false
```

Returns the expired response first and refreshes it in the background.

### `prefetch`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
prefetch = false
```

Refreshes frequently used cache entries before they expire. Requires an enabled response cache with a nonzero TTL.

### `prefetch_min_hits`

**Type:** integer  
**Default:** `1`

**TOML:**

```toml
prefetch_min_hits = 1
```

Only cache entries used at least this many times are prefetched.

**Unit:** hits.

### `prefetch_ttl_pct`

**Type:** integer  
**Default:** `90`

**TOML:**

```toml
prefetch_ttl_pct = 90
```

Prefetches an entry once this percentage of its original TTL has elapsed; 90 refreshes it when 10% of the TTL remains. Values from 10 to 99 are accepted.

**Unit:** %.

### `prefetch_interval_secs`

**Type:** integer  
**Default:** `10`

**TOML:**

```toml
prefetch_interval_secs = 10
```

Interval used to scan for entries that need prefetching.

**Unit:** seconds.

### `rrset_roundrobin`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
rrset_roundrobin = false
```

When a name has several addresses, rotates their order in each answer so that connections do not all go to one address.
