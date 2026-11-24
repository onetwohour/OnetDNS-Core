# Upstreams, recursion and DNSSEC — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Resolution decisions

1. Choose `backend`: `forward`, `recurse`, or `split`.
2. For forwarding, configure `upstream_urls` (encrypted or URL-based upstreams) or `upstreams` (IP-based upstreams). For recursion, ensure the host can reach authoritative servers directly.
3. `split_*` selects a resolution strategy by name; a `[[stub_zones]]` entry instead names specific servers for one suffix.
4. `dnssec` enables validation; it does not encrypt transport. Strictness, anchors, and validator options are separate decisions.
5. Test a normal positive response, an NXDOMAIN, a deliberately unreachable upstream, and a DNSSEC failure after making resolver changes.

## Options in this chapter

- [Upstream servers and forwarding](#upstream-servers-and-forwarding)
- [Recursive and split resolution](#recursive-and-split-resolution)
- [DNSSEC validation](#dnssec-validation)

## Upstream servers and forwarding

### `upstreams`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
upstreams = ["1.1.1.1", "1.0.0.1"]
```

Plain DNS server addresses used for UDP or TCP forwarding.

### `upstream_urls`

**Type:** array  
**Default:** `["h3://1.1.1.1/dns-query#cloudflare-dns.com", "h3://1.0.0.1/dns-query#cloudflare-dns.com"]`

**TOML:**

```toml
upstream_urls = ["h3://1.1.1.1/dns-query#cloudflare-dns.com"]
```

Upstream DNS servers reached over an encrypted connection. DoT addresses start with tls://, DoH with https://, DoQ with quic://, DoH3 with h3://, Oblivious DoH with odoh://, and Oblivious HTTP with ohttp://; a DNSCrypt server is given by its sdns:// stamp. Append # and a relay stamp to a DNSCrypt stamp to query through an Anonymized DNSCrypt relay.

An Oblivious DoH upstream names the proxy and, in its query string, the target: `odoh://proxy.example/proxy-path?targethost=odoh.example&targetpath=/dns-query`. `#name` after it sets the proxy's TLS server name. Both `targethost` and `targetpath` are required, written without percent-encoding; `targethost` may carry a port. See [Oblivious DoH upstreams](../resolution.md#oblivious-doh-upstreams).

An Oblivious HTTP upstream is written the same way, with the relay in place of the proxy: `ohttp://relay.example/relay-path?targethost=dns.example&targetpath=/dns-query`. The query string names the DoH server behind the gateway and is not sent to the relay. See [Oblivious HTTP upstreams](../resolution.md#oblivious-http-upstreams).

Server certificates are checked against the operating system's root certificates. As in OpenSSL, a PEM file named by the `SSL_CERT_FILE` environment variable is used in their place.

**Note:** If `upstreams` is specified and `upstream_urls` is omitted, the implicit encrypted defaults are cleared.

### `bootstrap`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
bootstrap = ["1.1.1.1"]
```

DNS servers used to resolve upstream hostnames without the operating system resolver.

### `root_hints`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
root_hints = ["198.41.0.4"]
```

Root DNS server addresses used to start iterative resolution. An empty list uses the built-in roots.

### `fallback_upstreams`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
fallback_upstreams = ["1.1.1.1"]
```

Fallback DNS servers used only when the primary upstream transport is unavailable.

### `upstream_strategy`

**Type:** enum (`query_statistics` / `user_order` / `round_robin` / `parallel`)  
**Default:** `query_statistics`

**TOML:**

```toml
upstream_strategy = "query_statistics"
```

Controls the order and concurrency used when querying multiple upstream DNS servers.

### `upstream_concurrency`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
upstream_concurrency = 0
```

Number of upstream servers queried concurrently for one request in parallel modes.

### `query_source`

**Type:** string  
**Default:** not set

**TOML:**

```toml
query_source = "192.0.2.10"
```

Local IPv4 address used for outgoing upstream DNS queries.

### `query_source_v6`

**Type:** string  
**Default:** not set

**TOML:**

```toml
query_source_v6 = "2001:db8::10"
```

Local IPv6 address used for outgoing upstream DNS queries.

### `upstream_proxy`

**Type:** string  
**Default:** not set

**TOML:**

```toml
upstream_proxy = "socks5://127.0.0.1:9050"
```

Connects tls:// and https:// upstreams through this SOCKS5 proxy, such as Tor at socks5://127.0.0.1:9050. The proxy resolves upstream names. Once set, upstreams of any other kind are refused.

**Note:** Give the proxy as `socks5://IP[:port]` with an IP address, not a host name; the port defaults to 1080. Credentials go in the two keys below, not in the URL. The setting covers `upstream_urls`, `fallback_upstreams`, and clients' `upstreams`; `upstreams` must be empty. QUIC upstreams (`quic://`, `h3://`) cannot use it, and neither can `backend = "recurse"`. Stub zones, recursion, and certificate revocation checks still connect directly. See [Forwarding through a SOCKS5 proxy](../resolution.md#forwarding-through-a-socks5-proxy).

### `upstream_proxy_username`

**Type:** string  
**Default:** not set

**TOML:**

```toml
upstream_proxy_username = "REPLACE_WITH_PROXY_USERNAME"
```

User name sent to the SOCKS5 proxy. Set it together with the password.

### `upstream_proxy_password`

**Type:** string  
**Default:** not set

**TOML:**

```toml
upstream_proxy_password = "REPLACE_WITH_PROXY_PASSWORD"
```

Password sent to the SOCKS5 proxy. SOCKS5 sends it in plain text, so keep the proxy on this machine or a trusted network.

**Note:** The user name and the password are each 1 to 255 bytes. The password is never shown in the dashboard or returned by the management API, and it is not replicated to other cluster nodes.

## Recursive and split resolution

### `recursion_limit`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
recursion_limit = 0
```

Maximum number of delegation steps followed during iterative resolution.

**Unit:** hops.

### `cname_limit`

**Type:** integer  
**Default:** `8`

**TOML:**

```toml
cname_limit = 8
```

Maximum CNAME chain length followed for one query.

**Unit:** hops.

### `dname_limit`

**Type:** integer  
**Default:** `8`

**TOML:**

```toml
dname_limit = 8
```

Maximum number of DNAME substitutions applied to one query.

**Unit:** hops.

### `do_ip4`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
do_ip4 = false
```

Uses IPv4 for iterative nameserver queries.

### `do_ip6`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
do_ip6 = false
```

Uses IPv6 for iterative nameserver queries.

### `prefer_ip4`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
prefer_ip4 = false
```

Prefers IPv4 when both IPv4 and IPv6 nameserver addresses are available.

### `prefer_ip6`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
prefer_ip6 = false
```

Prefers IPv6 when both IPv4 and IPv6 nameserver addresses are available.

### `qname_minimisation_strict`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
qname_minimisation_strict = false
```

Sends only the part of the name each upper-level name server needs, so the full name is not revealed. Servers that cannot handle this are not retried, so some domains may fail to resolve.

### `harden_referral_path`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
harden_referral_path = false
```

Checks that a referral really points to a lower zone, so that bad referrals are not followed.

### `use_caps_for_id`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
use_caps_for_id = false
```

Randomizes the letter case of outgoing query names and checks that answers come back with the same case, which filters out forged answers. Cannot be used together with lowercasing outgoing names.

### `lowercase_outgoing`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
lowercase_outgoing = false
```

Always sends recursive query names in lowercase. Can be turned on only when query name case randomization is off.

### `harden_large_queries`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
harden_large_queries = false
```

Drops queries larger than 1024 bytes without answering.

### `harden_below_nxdomain`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
harden_below_nxdomain = false
```

Answers names below a name already confirmed not to exist as nonexistent, without asking again.

**Requirement:** This option is meaningful only with DNSSEC validation and recursive resolution.

### `recurse_deny_server`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
recurse_deny_server = ["198.51.100.0/24"]
```

Nameserver address ranges excluded from iterative queries.

### `recurse_allow_server`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
recurse_allow_server = ["192.0.2.0/24"]
```

Name server address ranges that recursive lookups may query. Private addresses that are blocked by default, and addresses on the exclusion list, are queried if listed here. Public addresses not listed here are still queried.

### `recurse_opportunistic_encryption`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
recurse_opportunistic_encryption = true
```

Queries authoritative servers over DoT or DoQ when they support it, as RFC 9539 describes. Certificates are not checked, so this stops eavesdropping but not an attacker on the path.

After a zone's server answers a query in plaintext, the same query is asked again in the background over DoT on port 853, or over DoQ on port 853 if DoT has failed, to that server and to the zone's other servers. A server that answers this way is asked over encryption for up to three days after its last encrypted answer. A server whose encryption fails is not tried again for one day.

When some of a zone's servers are known to answer over encryption, the zone is asked through them before any server is asked in plaintext, even if a plaintext server is closer. The zone is asked in plaintext when none is known yet, or when they fail or are slow, within the same query time limit. What is known is kept in memory, so after a restart the first queries to each zone go in plaintext again.

On the dashboard this is the switch under DNSSEC on the Upstreams page, and root servers asked over encryption are marked DoT or DoQ in the root server list.

**Requirement:** This option is meaningful only with `backend = "recurse"` or `"split"`. It turns off the fast path for recursive queries not in the cache, which sends only plain UDP.

### `recurse_deny_answers`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
recurse_deny_answers = ["198.51.100.0/24"]
```

Address ranges rejected in recursive answers.

### `recurse_allow_answers`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
recurse_allow_answers = ["192.168.1.0/24"]
```

Exceptions to the rejected recursive answer addresses. Has no effect when the reject list is empty.

### `ns_recursion_limit`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
ns_recursion_limit = 0
```

Maximum depth used when resolving nameserver addresses required by referrals.

### `ns_cache_size`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
ns_cache_size = 0
```

How many name server records and DNSSEC keys recursive lookups remember, for each kind. Zero sizes it automatically.

**Unit:** entries.

### `split_default`

**Type:** enum (`forward` / `recurse`)  
**Default:** `forward`

**TOML:**

```toml
split_default = "forward"
```

Selects forwarding or direct recursion for domains not matched by split rules.

### `split_recurse`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
split_recurse = ["internal.example"]
```

Domains resolved directly from the root in split mode.

### `split_forward`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
split_forward = ["public.example"]
```

Domains forwarded to upstream DNS servers in split mode.

### `local_a`

**Type:** array of `[name, IPv4 address]` pairs  
**Default:** `[]`

**TOML:**

```toml
local_a = [["router.lan", "192.168.1.1"]]
```

Local records that answer a domain name with a fixed IPv4 address. Works only when the query handling mode is Split by domain.

### `local_aaaa`

**Type:** array of `[name, IPv6 address]` pairs  
**Default:** `[]`

**TOML:**

```toml
local_aaaa = [["router.lan", "2001:db8::1"]]
```

Local records that answer a domain name with a fixed IPv6 address. Works only when the query handling mode is Split by domain.

### `stub_zones`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[stub_zones]]
suffix = "corp.example"
servers = ["192.168.1.53"]
```

See [structured table fields](structures.md#stub_zones) for the nested field definitions.

Stub zones that query only the configured authoritative servers.

### `views`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[views]]
name = "office"
clients = ["192.168.1.0/24"]
local_a = [["intranet.corp.example", "192.168.1.20"]]
```

See [structured table fields](structures.md#views) for the nested field definitions.

Applies different DNS settings according to client address or ID.

## DNSSEC validation

### `dnssec`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dnssec = false
```

Checks DNSSEC signatures to make sure answers were not forged and does not pass on answers that fail the check.

Signatures are checked for algorithms 8 and 10 (RSA), 13 and 14 (ECDSA), 15 (Ed25519), and 18 (ML-DSA-44). A zone whose DS records use only other algorithms is treated as unsigned.

If a zone's DS records include an ML-DSA-44 key, the zone must validate through ML-DSA-44; a valid signature in another algorithm alone fails. Otherwise a forged classical signature could stand in for a broken ML-DSA-44 one. This is stricter than RFC 6840, which accepts any one valid algorithm.

### `dnssec_strict`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
dnssec_strict = false
```

Treats an answer as failed when it cannot be confirmed that its zone is allowed to be unsigned.

### `val_permissive_mode`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
val_permissive_mode = false
```

Passes on answers even when DNSSEC validation fails, without marking them as validated.

### `dnssec_accept_expired`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dnssec_accept_expired = false
```

Accepts expired DNSSEC signatures. This weakens signature-expiry enforcement; incorrect system time should be corrected at the clock.

### `ignore_cd_flag`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
ignore_cd_flag = false
```

Performs DNSSEC validation even when the client asks to skip it.

### `dnssec_rfc5011`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dnssec_rfc5011 = false
```

Follows the standard key-rollover procedure to update the trust anchor automatically when the root zone's DNSSEC key changes.

### `dnssec_anchor_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dnssec_anchor_file = "/etc/OnetDNS/root.key"
```

File the DNSSEC root trust anchor is read from at startup. With automatic root trust anchor updates on, updated anchors are saved to this file too.

### `dnssec_roll_interval_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
dnssec_roll_interval_secs = 0
```

Interval used to advance authoritative-zone ZSK rollover state.

**Unit:** seconds.

### `root_key_sentinel`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
root_key_sentinel = false
```

Answers root key sentinel queries so that others can check which root key this server trusts.

### `trust_anchor_signaling`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
trust_anchor_signaling = false
```

Reports the root trust anchors this server uses to the root servers. Root server operators use these reports to count which root keys resolvers trust.

### `aggressive_nsec`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
aggressive_nsec = false
```

Reuses already validated proofs of nonexistence to answer other names in the same range as nonexistent without asking again.

**Requirement:** This option is meaningful only with DNSSEC validation and recursive resolution.

### `val_nsec3_max_iterations`

**Type:** integer  
**Default:** `150`

**TOML:**

```toml
val_nsec3_max_iterations = 150
```

Maximum hash iterations allowed when validating NSEC3 records. Can be set up to 150.

### `domain_insecure`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
domain_insecure = ["corp.example"]
```

Domains and descendants excluded from DNSSEC validation.
