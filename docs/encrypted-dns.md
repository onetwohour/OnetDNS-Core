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

## Client setup

| Client | Select |
| --- | --- |
| Android Private DNS | The hostname of your DoT endpoint, not a bare `https://` URL |
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

A dashboard log entry marked with an internal microsecond latency measures a server-side span. It is **not necessarily total client-visible latency**: decryption, encryption, QUIC/TLS processing and network RTT can fall outside the timer.

Related: [Examples](examples.md) · [Operations](operations.md) · [Troubleshooting](troubleshooting.md) · [Reference: access and TLS](reference/access-and-tls.md).
