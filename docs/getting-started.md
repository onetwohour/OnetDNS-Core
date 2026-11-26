# Getting started

Start the server on loopback, test an ordinary DNS response, then add a local filter rule. LAN setup follows after the local test.

## Prerequisites

- A released binary for your operating system from the project [releases](https://github.com/onetwohour/OnetDNS-Core/releases), or a binary built from source.
- Ability to open TCP and UDP port 53 on the host, or privileges to bind it. Linux often requires root or `CAP_NET_BIND_SERVICE` for port 53.
- A browser on the same computer for initial administrator enrollment.
- A command-line DNS test tool such as `dig` or `nslookup` (these are external tools).

## 1. Start locally

Extract the archive and run:

```sh
./OnetDNS
```

If no configuration file exists, OnetDNS creates one in the user configuration directory. The initial DNS listener binds `127.0.0.1:53`; the dashboard binds `127.0.0.1:8553`. Resolution uses the configured forwarding backend.

If the program cannot bind port 53, check whether another resolver already occupies it; see [Troubleshooting](troubleshooting.md#cannot-bind-a-listening-port). If your host cannot bind privileged ports, configure a non-privileged test port in the TOML instead and pass the matching port with `dig -p`.

## 2. Create an administrator

Browse to **http://127.0.0.1:8553** on the same computer. The first-use screen points to `setup-code.txt`, stored beside `OnetDNS.toml`. Enter the code and create an account. If the dashboard is also served at an HTTPS address, the first account can be created there with the same code.

If the page does not load, verify the process is running, check the configured dashboard address, and ensure `--no-web` was not used. See [Operations](operations.md#dashboard-access).

## 3. Confirm unfiltered resolution

```sh
dig @127.0.0.1 example.com A
```

Check for `status: NOERROR` and an `ANSWER SECTION`. If you changed the listener port, use `dig -p PORT @127.0.0.1 example.com A`.

## 4. Enable filtering and test it

Open **Filter lists** and add a list from a source you trust. Alternatively, add a temporary explicit rule:

```toml
block_rules = ["||example.com^"]
```

Apply the change through the dashboard or validated config workflow. From the same client:

```sh
dig @127.0.0.1 example.com A
```

With the rule active, the same query should return the configured block response (`NXDOMAIN` for the default `block_response`). Confirm the matching rule in Query log and query `example.org` to verify that unrelated names still resolve. Remove the test rule afterward.

## Serve one device before the whole network

1. Determine the server's actual LAN address (for example, `192.168.1.10`). Make sure it is stable across restarts.
2. Add that address to the DNS listener. Keep loopback for local testing:

   ```toml
   listen = ["127.0.0.1:53", "192.168.1.10:53"]
   ```

3. Validate and apply the config, and ensure the host firewall permits the chosen TCP/UDP destination port from the test device.
4. On **one** device, select `192.168.1.10` as its DNS server. Avoid changing your router's DHCP options until that device works.
5. From that device, query the server (`dig @192.168.1.10 example.com A`) with the test rule active. Confirm the blocked response and the source address in Query log.

Once this works, you can set the router's DHCP-advertised DNS address or configure other devices. Device DNS caches and lease renewal can delay an apparent change. A browser's own secure-DNS setting may bypass the OS DNS server.

## Next steps

| Deployment | Next step |
| --- | --- |
| LAN filtering | [Filtering](filtering.md), [Client policy](clients.md) |
| Android Private DNS / browser DoH | [Encrypted DNS](encrypted-dns.md) |
| Independent recursive DNS | [Resolution](resolution.md#recursive-resolution) |
| Public DNS service | [Deployment examples](examples.md#public-dns-service) |
| Boot-time service on Linux/Windows/macOS | [Installation](installation.md#install-a-system-service) |

## Troubleshooting

For a failed query, check the bound socket, network path, client identity, filtering decision, then upstream resolution. See [Troubleshooting](troubleshooting.md).
