# Deployment configurations

Use one example as a starting configuration. Replace illustrative names, addresses and file paths, then validate the result:

```sh
OnetDNS --cli check --config /path/to/OnetDNS.toml
```

Omitted options use their built-in defaults.

Download the [minimal filter configuration](examples/minimal-filtering.toml) or use any complete example below.

## Local-only forwarder

Listens only on loopback and forwards to the configured DoH3 upstreams.

```toml
backend = "forward"
listen = ["127.0.0.1:53"]
cache_enabled = true

upstream_urls = [
  "h3://1.1.1.1/dns-query#cloudflare-dns.com",
  "h3://1.0.0.1/dns-query#cloudflare-dns.com",
]
```

**Test:** Run `dig @127.0.0.1 example.com A` and check `status: NOERROR` with an answer. If it fails, check upstream connectivity.

## Filtered home network

Listens on loopback and one LAN address. Uses a subscription and an inline block rule.

```toml
mode = "personal"
backend = "forward"
listen = ["127.0.0.1:53", "192.168.1.10:53"]
# Temporary verification rule.
block_rules = ["||example.com^"]
```

Replace the server address. First query `example.com` with the rule commented out; then enable it and repeat `dig @192.168.1.10 example.com A` from a LAN device. Compare the DNS response status, then remove the temporary rule. Add `blocklist_urls` only after selecting a reachable subscription URL.

## Separate policy for selected devices

```toml
listen = ["127.0.0.1:53", "192.168.1.10:53"]
block_rules = ["||example.com^"]

[[clients]]
name = "Family devices"
ids = ["192.168.1.50/32", "192.168.1.51/32"]
safe_search = true
blocked_services = ["tiktok", "youtube"]

[[clients]]
name = "Lab workstation"
ids = ["192.168.1.60/32"]
disable_filtering = true
```

**Test:** send an identical blocked-name query from two different client addresses and compare their Query log entries. The `Lab workstation` profile bypasses global filtering, but other resolution behavior still applies. For service identifiers, run `OnetDNS --cli services`.

## Recursive resolver with DNSSEC

```toml
backend = "recurse"
listen = ["127.0.0.1:53"]
dnssec = true
dnssec_strict = true
cache_enabled = true
```

**Test:** query a known normal domain and inspect errors. Recursion must be able to reach authoritative servers, typically over UDP/TCP port 53 outbound. DNSSEC validation depends on trust anchors and accurate system time. Failures should be diagnosed separately from filtering.

## Split resolution

```toml
backend = "split"
split_default = "forward"
split_recurse = ["independent.example"]
upstream_urls = ["h3://1.1.1.1/dns-query#cloudflare-dns.com"]
```

The selected suffix uses recursion while other names use forwarding. Use a domain you control or a known public test zone for a meaningful split test; `.example` in the snippet is illustrative. Check both a selected and a nonselected name and verify the backend path through available metrics/logs.

## Internal name server through a stub zone

```toml
backend = "forward"

[[stub_zones]]
suffix = "corp.example"
servers = ["192.168.1.53"]
```

Here, `192.168.1.53` stands for a DNS server authoritative for the internal suffix. The stub is not a locally hosted authoritative zone. Check the intended hostname against both OnetDNS and the stub server directly to distinguish stub routing from the stub server's own response.

## Encrypted client listeners

```toml
listen_dot = ["0.0.0.0:853"]
listen_doh = ["0.0.0.0:443"]
listen_doh3 = ["0.0.0.0:443"]
listen_doq = ["0.0.0.0:853"]

tls_cert = "/etc/OnetDNS/fullchain.pem"
tls_key = "/etc/OnetDNS/privkey.pem"
doh_path = "/dns-query"
```

Use a certificate whose subject names cover the DNS hostname. Classic DoH and DoH3 use separate TCP/UDP sockets even when the port number matches. Use a client that supports the chosen protocol and inspect the connection and certificate failure separately from DNS content.

## DNSCrypt listener and public stamp

```toml
listen_dnscrypt = ["0.0.0.0:5443"]
dnscrypt_provider_name = "2.dnscrypt-cert.dns.example.com"
```

This binds DNSCrypt UDP/TCP to local IPv4 interfaces. It does **not** publish `0.0.0.0` as the client endpoint. In the dashboard's **Encryption → Client setup** section, enter the server's public IP as the client connection address before generating the stamp. The same address can be passed as `{"address":"203.0.113.10"}` to `POST /v1/client-setup/stamps`. Replace the documentation IP and provider name with deployment values; the stamp includes the actual listener port and active DNSCrypt public key. See [DNSCrypt setup](encrypted-dns.md#dnscrypt-setup).

## Public DNS service

```toml
mode = "public"
listen = ["[::]:53"]
```

This binds plain DNS to all interfaces. The `[::]` socket accepts IPv4 as well, so `0.0.0.0:53` is not listed with it; the config check rejects the pair as a conflict. `mode`, `acl_*`, and rate controls select DNS admission and traffic policy; dashboard access is configured with `control_*` settings.

## Dashboard through an HTTPS reverse proxy

```toml
control_trusted_proxies = ["127.0.0.1/32"]
control_public_origins = ["https://dns.example.com"]
```

The reverse proxy should connect to the local dashboard address, preserve the original Host information and supply the expected forwarded-client headers. A trusted-proxy setting is not a substitute for the dashboard's authentication. Confirm login, session persistence, authorization for a read-only account and change requests from the configured origin.

## Test the configuration

1. Run the config checker and resolve **all** reported errors.
2. Verify the process binds the intended TCP/UDP ports (`ss -lntup` on Linux).
3. Test from the intended client, not only on the server.
4. Compare an allowed name and a blocked or special-case name.
5. Observe service logs and memory use through one filter update.

See [Configuration reference](reference/README.md) for exact defaults and [Troubleshooting](troubleshooting.md) for a failure-by-symptom approach.
