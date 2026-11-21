# Troubleshooting by symptom

Identify the failed stage: listener binding, network reachability, handshake, DNS parsing, policy, resolution, or response transmission. Reproduce the same query name and type from the same client after each change.

## Cannot bind a listening port

**Symptoms:** startup fails; logs mention `address already in use` or permission denial; no socket appears in `ss`.

```sh
sudo ss -lntup | grep -E '(:53|:443|:853|:8553)'
sudo journalctl -u onetdns -n 100 --no-pager
OnetDNS --cli check --config /etc/OnetDNS/OnetDNS.toml
```

Check that the configured IP belongs to a local interface and that another service is not already using the same IP/port/protocol combination. On Linux, privileged ports generally require root or capabilities. A clean config check does not prove the port is available. Avoid disabling system DNS services before understanding what relies on them.

## Local DNS works; LAN DNS fails

The initial listener is `127.0.0.1:53`. It cannot receive packets sent to the host's LAN IP. Add a LAN-bound listener and confirm TCP and UDP separately:

```sh
dig @192.168.1.10 example.com A
dig +tcp @192.168.1.10 example.com A
```

Check the host firewall, cloud rules (when relevant), router path and device DNS setting. A device may use a browser-integrated encrypted DNS provider or VPN that bypasses the OS resolver. Verify Query log sees the request before diagnosing filtering.

## A supposedly blocked name still resolves

Work through these questions in order:

1. Is the expected subscription, local list, or inline rule loaded?
2. Did the exact name match? Distinguish `ads.example` from `cdn.example` and A from AAAA where rules are type-specific.
3. Which client profile was selected? `disable_filtering` may intentionally bypass the global filter.
4. Is an allow/important allow stage winning over the block?
5. Does an application or OS cache still contain the old answer?
6. Is the device actually asking the OnetDNS listener?

Use `dig @SERVER example.com A` when testing a temporary `block_rules = ["||example.com^"]` rule. First confirm it resolves normally without the test rule, then apply the rule and compare responses. **Do not use `OnetDNS --cli query` for this test**; it bypasses the running filter pipeline.

## A site stops working after enabling lists

Compare request times and clients in Query log, then inspect rule attribution. An application may query many domains; not every blocked analytics hostname is responsible for its failure. Disable the suspect list or add a narrow exception, apply, and repeat the same action from the same device. If nothing changes, check another filter, CNAME-chain matching or local application caching before adding broad exceptions.

## DoH or DoT fails before DNS processing

| Symptom | Likely layer | First check |
| --- | --- | --- |
| Certificate error | TLS trust/name/expiry | Certificate SAN, chain, system clock, client hostname |
| Connection refused | Listener/binding | Configured IP, port, transport and process privileges |
| DoH HTTP error | HTTP path/method/content | `doh_path`, client endpoint URL, proxy configuration |
| DoH works, DoH3 fails | QUIC/UDP reachability | UDP 443 and HTTP/3 client support |
| DoT works, DoQ fails | QUIC/UDP reachability | UDP 853 and DoQ support |
| DNSCrypt fails | Provider discovery/crypto | Stamp, provider name and port |

The TLS certificate used for DoT/DoH/DoQ is different from DNSCrypt's protocol-specific provider information. If the handshake fails, changing a blocklist will not fix it.

## Forwarding fails but recursion works, or vice versa

Forwarding relies on the configured upstream; recursion relies on reaching authoritative DNS servers. On networks that intercept or block external port 53, recursion can fail while DoH forwarding succeeds. For diagnostics, a non-recursive query to a known root server can reveal unexpected interception:

```sh
dig @198.41.0.4 example.com A +norecurse
```

The expected behavior is a referral rather than a completed address answer; interpret results in network context. If DNSSEC validation causes SERVFAIL, verify time and chain correctness before relaxing validation.

## New configuration is ignored

Confirm the **exact file path** in the running service invocation, the service account that reads it, and whether the dashboard indicated a pending change or restart requirement. A shell invocation without `--config` can use a different user's config directory. Validate the same file that systemd or the service manager uses, not an unrelated copy.

## High memory use or slow DNS

Track service-wide memory, not just one PID. On Linux with systemd cgroup v2:

```sh
systemctl show onetdns -p MemoryCurrent -p MemoryPeak
cat /sys/fs/cgroup/system.slice/onetdns.service/memory.events
cat /sys/fs/cgroup/system.slice/onetdns.service/cpu.stat
```

Compare idle, loaded, and filter-refresh periods. Distinguish cache-hit, cache-miss and blocked-query workload, and separate logged internal microseconds from client RTT. Large blocklists may temporarily require extra memory during compilation or snapshot replacement even when steady usage is low.

## Two OnetDNS PIDs under one service

Normal operation uses a supervisor plus a worker with `--no-supervisor`. Check the parent-child relationship:

```sh
ps -C OnetDNS -o pid,ppid,etime,args
```

Do not count two PIDs as two independently listening DNS instances without checking process roles and sockets.

## Issue reports

Provide the OnetDNS build/version, OS, exact transport, query name/type, expected and actual response/status, a minimal redacted config and the relevant logs. For a performance issue include rule count, concurrent clients, QPS and p50/p95/p99 when available, CPU and memory limits, and whether a filter refresh was running. Avoid sharing secrets or private client activity in raw logs.

See [CLI](cli.md) for command semantics and [Operations](operations.md) for normal observability.
