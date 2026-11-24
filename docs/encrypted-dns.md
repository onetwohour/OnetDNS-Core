# Encrypted DNS transports

Incoming encrypted DNS uses `listen_dot`, `listen_doh`, `listen_doh3`, `listen_doq`, or `listen_dnscrypt`. Outgoing encrypted upstreams are configured with `upstream_urls`.

## Transport matrix

| Client protocol | Listener | Typical endpoint | Certificate or client information |
| --- | --- | --- | --- |
| DNS over TLS (DoT) | `listen_dot` | TCP 853 | TLS certificate for client-configured hostname |
| DNS over HTTPS (DoH, HTTP/2) | `listen_doh` | TCP 443, path `/dns-query` | HTTPS URL and matching TLS certificate |
| DNS over HTTPS/3 | `listen_doh3` | UDP 443, path `/dns-query` | HTTP/3-capable client and matching certificate |
| DNS over QUIC (DoQ) | `listen_doq` | UDP 853 | DoQ-capable client and matching certificate |
| DNSCrypt | `listen_dnscrypt` | Configured UDP/TCP port | DNSCrypt provider information/stamp |
| Oblivious DoH target | `listen_doh` with `odoh_target` | Same as DoH | Reached through an ODoH proxy; see [Oblivious DoH](#oblivious-doh) |
| Oblivious DoH proxy | `listen_doh` with `odoh_proxy_targets` | Same as DoH | ODoH client; relays only to the listed targets |
| Oblivious HTTP gateway | `listen_doh` with `ohttp_gateway` | Same as DoH, path `/.well-known/ohttp-gateway` | Reached through an OHTTP relay; see [Oblivious HTTP](#oblivious-http) |
| Oblivious HTTP relay | `listen_doh` with `ohttp_relays` | Same as DoH, each relay's `path` | Passes encrypted requests to one gateway; see [Oblivious HTTP](#oblivious-http) |

The ports shown are conventional; each transport is enabled by setting its listener. The host firewall and any cloud network rule must permit the corresponding TCP or UDP traffic.

## TLS certificates and hostnames

DoT, DoH, DoH3 and DoQ use the TLS material configured by `tls_cert` and `tls_key`, or an appropriately configured built-in certificate mechanism. Clients must connect using a hostname covered by the certificate. A certificate with the wrong Subject Alternative Name, expired validity or incomplete trust chain can cause connection failure **before any DNS query reaches the filter**.

```toml
listen_dot = ["0.0.0.0:853"]
listen_doh = ["0.0.0.0:443"]
listen_doh3 = ["0.0.0.0:443"]
listen_doq = ["0.0.0.0:853"]

tls_cert = "/etc/OnetDNS/fullchain.pem"
tls_key = "/etc/OnetDNS/privkey.pem"
doh_path = "/dns-query"
```

Use only addresses assigned to the machine. The process must be able to read the certificate/key files. Binding TCP 443 and UDP 443 simultaneously is possible; they are different sockets. The same is true of TCP/UDP 853 for DoT and DoQ.

### ACME or a self-signed certificate

The dashboard supports ACME issuance/renewal and a self-signed option. ACME challenge types have distinct prerequisites: HTTP-01 needs the relevant HTTP challenge route reachable on port 80; DNS-01 needs the necessary DNS challenge records or delegation. Self-signed certificates require explicit trust on devices. ACME configuration controls certificate issuance, not what DNS names the server blocks.

Before enabling encrypted DNS, decide which hostname clients will type, which IP/port receives the connection, and how certificate renewal will continue after restart.

## DoH and DoH3 endpoint construction

With `doh_path = "/dns-query"` and a certificate for `dns.example.com`, clients normally use:

```text
https://dns.example.com/dns-query
```

DoH uses HTTP over TLS/TCP; DoH3 uses HTTP/3 over QUIC/UDP. A browser may support classic DoH but not manually selecting DoH3. Test UDP 443 separately. HTTP errors must be diagnosed at the HTTP layer before investigating DNS policy.

## Oblivious DoH

Oblivious DoH (ODoH, RFC 9230) splits what one DoH server learns between two parties. The client encrypts its query to a **target** and sends it through a **proxy**. The proxy sees the client's address but not the query; the target decrypts and answers the query but sees only the proxy's address. OnetDNS can be the target or the proxy for other clients, as below, and can itself be a client: see [Oblivious DoH upstreams](resolution.md#oblivious-doh-upstreams).

To act as a target, turn it on for the DoH listeners:

```toml
listen_doh = ["0.0.0.0:443"]
odoh_target = true
```

The listener then also accepts `application/oblivious-dns-message` POSTs on `doh_path` and publishes its key configuration at `https://dns.example.com/.well-known/odohconfigs`. Ordinary DoH keeps working on the same listener. DoH3 listeners do not serve ODoH.

The target key is created on first use as `odoh-target.key` next to the configuration file and kept across restarts and upgrades. OnetDNS never replaces it on its own: a damaged file stops the DoH listener with an error. To change the key, delete the file and restart OnetDNS; clients holding the old configuration get HTTP 401 and fetch the new one. Anyone who can read the file can decrypt previously captured queries to this target, so protect it like the TLS private key.

**Every ODoH query appears to come from the proxy.** Client policy, ACLs, rate limits, client-specific rules and the query log key on the proxy's address (or the proxy's mTLS client identity), never on the client behind it. All clients of one proxy share its policy and its per-client rate limit; if you rate-limit clients, list the proxy in `rate_limit_allow` or the proxy's users will be throttled together. For the same reason, dynamic updates, NOTIFY and zone transfers that arrive through ODoH are refused, even when the proxy's address is in `update_allow` or `xfr_allow`.

To act as a proxy, list the targets it may relay to:

```toml
listen_doh = ["0.0.0.0:443"]
odoh_proxy_targets = ["https://odoh.example.net/dns-query"]
```

A client then POSTs its encrypted query to `https://dns.example.com/dns-query?targethost=odoh.example.net&targetpath=/dns-query`. The proxy forwards it without any header that identifies the client, over connections it shares between all clients, and returns the target's answer. It relays only to the listed targets: any other host, port or path gets HTTP 403 with a `Proxy-Status` header, so the listener never becomes an open proxy. Failures to reach a target also come back with `Proxy-Status`, and a target's error status is passed on without its body. A listener can be a proxy and a target at once.

As a proxy, OnetDNS sees each client's address but not its queries. Relayed messages do not appear in the query log or statistics. The ACL and rate limits apply to each relay as to a query from that client, but the targets see every relayed query as coming from this server.

## Oblivious HTTP

Oblivious HTTP (OHTTP, RFC 9458) splits the same knowledge for whole HTTP requests. The client encrypts a DoH request to a **gateway** and sends it through a **relay**. The relay sees the client's address but not the request; the gateway reads the request but sees only the relay's address. OnetDNS can be the gateway for its own DoH service:

```toml
listen_doh = ["0.0.0.0:443"]
ohttp_gateway = true
```

The DoH listeners then publish the key configuration (`application/ohttp-keys`) by GET at `https://dns.example.com/.well-known/ohttp-gateway`, and take encrypted requests (`message/ohttp-req`) POSTed to the same URL, as RFC 9540 describes. Each request must be a DoH request for `doh_path`, by POST or GET, and is answered like DoH from the relay. Answers are padded to a multiple of 468 bytes before encryption, so the relay cannot tell them apart by size. With `ddr_name` set, the DoH entries in DDR answers carry the `ohttp` parameter, which tells clients the gateway exists. DoH3 listeners do not serve OHTTP.

The gateway key is created on first use as `ohttp-gateway.key` next to the configuration file and kept across restarts and upgrades. It is separate from the ODoH target key, so either can be replaced without the other. OnetDNS never replaces it on its own: a damaged file stops the DoH listener with an error. To change the key, delete the file and restart OnetDNS. Requests made with the old key configuration then get HTTP 422 until the client fetches the new one. Protect the file like the TLS private key.

As with ODoH, **every OHTTP request appears to come from the relay.** Client policy, ACLs, rate limits, client-specific rules and the query log key on the relay's address, and dynamic updates, NOTIFY and zone transfers are refused.

OnetDNS can also be the relay. Each `ohttp_relays` entry names a path on the DoH listeners and the one gateway it forwards to:

```toml
listen_doh = ["0.0.0.0:443"]

[[ohttp_relays]]
path = "/relay/example"
gateway = "https://gateway.example.net/.well-known/ohttp-gateway"
```

A client POSTs `message/ohttp-req` to `https://dns.example.com/relay/example`. The relay sends the same content to the gateway and returns the gateway's answer; it can read neither. It passes on none of the client's header fields, so the gateway sees only this server's address. A path not listed gets HTTP 404. An error status from the gateway reaches the client with a `Proxy-Status` field; if the gateway cannot be reached, the client gets 502 or 504. A request the gateway may already have received is not sent again. The ACL and rate limits apply to the client, and relayed requests are not in the query log. DDR does not announce relays, so clients need the relay URL and the gateway's key configuration from their operator.

OnetDNS can also be an OHTTP client and send its own upstream queries through a relay: see [Oblivious HTTP upstreams](resolution.md#oblivious-http-upstreams).

## DNSCrypt setup

The listener address and the address published in a DNS stamp serve different purposes. `listen_dnscrypt` binds a local socket. The stamp contains an address that remote clients can reach.

```toml
listen_dnscrypt = ["0.0.0.0:5443"]
dnscrypt_provider_name = "2.dnscrypt-cert.dns.example.com"
```

`0.0.0.0:5443` accepts DNSCrypt on all local IPv4 interfaces, over **UDP and TCP**. To serve IPv6 as well, and the host has IPv6 connectivity, use `"[::]:5443"` instead. It accepts IPv4 as well; listing it together with `0.0.0.0:5443` is rejected as a conflict. Do not replace `0.0.0.0` with a cloud VM's NAT public IP unless that IP is actually assigned to a local interface.

For clients connecting over the public internet, generate the stamp with the server's **publicly reachable IP address**, not `0.0.0.0`, `127.0.0.1`, or the VM's internal-only IP. For example, when the public address is `203.0.113.10` (documentation placeholder):

1. Open **Encryption → Client setup** in the dashboard.
2. Enter `203.0.113.10` as the **client connection address** (without a port).
3. Select **Generate stamps** and copy the DNSCrypt `sdns://` value.

The admin API exposes the same operation at `POST /v1/client-setup/stamps`:

```json
{"address":"203.0.113.10"}
```

The resulting DNSCrypt stamp includes the supplied client address, the configured DNSCrypt listener port (`5443`), the provider name, and OnetDNS's active DNSCrypt provider public key. Its address is **not** the listener bind address. When a listener is bound to an unspecified address and no client address is provided, OnetDNS omits the DNSCrypt stamp because it cannot determine a reachable endpoint. The API rejects `0.0.0.0` and `::` as client addresses.

`dnscrypt_provider_name` identifies the DNSCrypt certificate provider; it is not the public IP address. Replace `dns.example.com` with your provider name. DNSCrypt uses its own certificate exchange rather than the `tls_cert`/`tls_key` identity used for DoT and DoH. Permit **both UDP and TCP 5443** through the applicable network path, then test the stamp from a remote DNSCrypt client.

### Queries that arrive through a relay

A client using Anonymized DNSCrypt sends its queries through a relay, so OnetDNS sees the relay's address, not the client's. Client policies, `[[clients]]` matching, the ACL, rate limits, statistics and the query log all go by that address. Every client behind one relay shares its rate limit, and blocking the relay's address blocks all of them.

### Running a relay

With `dnscrypt_relay = true`, the DNSCrypt listeners also pass Anonymized DNSCrypt queries on to the server the client names and return its answer. The server sees the relay's address instead of the client's, and the relay sees only encrypted queries.

```toml
listen_dnscrypt = ["0.0.0.0:443"]
dnscrypt_relay = true
dnscrypt_relay_ports = [443]
```

A relay sends packets wherever a stranger asks, so it is limited:

- The ACL and rate limits apply to the client's address before anything is passed on.
- Only packets that look like DNSCrypt are passed on: an encrypted query, or a certificate lookup for a name starting with `2.dnscrypt`.
- The target port must be in `dnscrypt_relay_ports` (default `[443]`).
- The target must be a public address and not one of this server's own listeners. Loopback, private, link-local and documentation addresses are refused, including IPv4 ones written inside IPv6. To relay to such an address anyway, for a DNSCrypt server on your LAN for example, list its network in `dnscrypt_relay_allow_targets`.
- An answer is returned only if it comes from the target, answers the query that was passed on, and is no larger than it. Anything refused gets no answer.

The relay always talks to the server over UDP, also for queries that arrived over TCP. With relaying on, **Client setup** shows a relay stamp (`sdns://` of type `0x81`) next to the DNSCrypt stamp; clients put it in their anonymized route.

## Client setup

| Client | Select |
| --- | --- |
| Android Private DNS | The hostname of your DoT endpoint, not a bare `https://` URL |
| iPhone, iPad, Mac | A configuration profile from the dashboard's client setup (`POST /v1/client-setup/apple-profile`). With a certificate this machine trusts, such as one from ACME, the profile is signed and shows as verified on the device |
| Browser encrypted DNS | Full DoH URL and a certificate the browser trusts |
| DoQ-capable app | Matching host, UDP port and protocol support |
| DNSCrypt client | Configured provider identity, resolver stamp and port |

Clients can bypass an OS-provided DNS server if they use an independent encrypted resolver. When filtering seems inactive for one device, first verify that it is actually talking to your OnetDNS listener.

## Diagnose by layer

1. **Listener:** verify the configured TCP/UDP socket is bound.
2. **Network:** test reachability from the client network, including cloud/firewall rules.
3. **Handshake:** verify hostname, certificate chain, system clock, protocol support or DNSCrypt stamp.
4. **HTTP framing where applicable:** verify path and HTTP/2 vs HTTP/3 support.
5. **DNS processing:** check QNAME/QTYPE and filter result only after transport succeeds.

The Query log's `latency_us` starts when the transport hands over the decrypted DNS message and stops when the answer is ready to send. Decryption, encryption of the answer, TLS, QUIC and HTTP processing, and network RTT are outside it, so it is **not the latency a client sees**. See [Performance](performance.md#latency-metrics).

Related: [Examples](examples.md) · [Operations](operations.md) · [Troubleshooting](troubleshooting.md) · [Reference: access and TLS](reference/access-and-tls.md).
