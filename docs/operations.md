# Operations, monitoring and maintenance

Use the process and socket checks below to confirm the running worker, collect resource metrics, and diagnose configuration or update failures.

## Service checks

Before treating a deployment as working, confirm the actual running configuration, expected network listeners, an allowed DNS answer, a filtered answer (if filtering is enabled), and the ability to read service logs. After adding a large filter list, confirm memory during the refresh, not only several minutes later.

## Process layout on Linux

```sh
sudo systemctl status onetdns
sudo journalctl -u onetdns -n 100 --no-pager
ps -C OnetDNS -o pid,ppid,nlwp,%cpu,rss,etime,args
sudo ss -lntup | grep -E '(:53|:443|:853|:8553)'
```

The normal service runs a supervisor and a worker (`--no-supervisor`). Two processes inside `onetdns.service` can therefore be intentional. Check the parent PID and which sockets are bound before calling it a duplicate launch.

## DNS readiness versus dashboard readiness

The embedded dashboard uses local HTTP at `127.0.0.1:8553` by default. It exposes health/readiness routes if enabled:

```sh
curl -i http://127.0.0.1:8553/healthz
curl -i http://127.0.0.1:8553/readyz
```

A successful HTTP health response proves the control endpoint responds, not necessarily that every DNS protocol or upstream works. Test at least one DNS query against each listener you rely on. Control API details are in [API.md](API.md).

## Dashboard access

The default dashboard binds locally. For an externally reachable HTTPS control listener, configure an appropriate address and accepted HTTPS origin:

```toml
control_listen_https = "0.0.0.0:8554"
control_public_origins = ["https://dns.example.com:8554"]
```

Provide a certificate for the hostname and verify login/session behavior. If using a reverse proxy on the same host, set the trusted proxy subnet and accepted origin deliberately. DNS admission controls (`mode`, `acl_*`, rate settings) are separate from control-plane authentication. Allowing DNS from all clients does not imply authorizing all dashboard users.

## Metrics and query logs

The dashboard provides statistics and query history. The corresponding settings include:

```toml
querylog = true
querylog_size = 200
anonymize_client_ip = false
```

Logs can be dropped when their asynchronous queue is backpressured, preserving DNS response handling. A log row is therefore not a guaranteed one-to-one accounting entry for all processed queries. Separate detailed Query log retention from aggregated statistics, and use relevant per-client `ignore_querylog`/`ignore_stats` fields where desired.

Query log `latency_us` records an internal processing span and can exclude DNSCrypt cryptography, QUIC processing, and network RTT. See [Performance](performance.md) for measurement boundaries.

## Measuring CPU and memory

For a Linux systemd service on cgroup v2:

```sh
systemctl show onetdns -p MemoryCurrent -p MemoryPeak
cat /sys/fs/cgroup/system.slice/onetdns.service/memory.events
cat /sys/fs/cgroup/system.slice/onetdns.service/cpu.stat
ps -C OnetDNS -o pid,ppid,nlwp,%cpu,rss,etime,args
```

`MemoryCurrent` includes memory charged to the service cgroup, not only the filter map. Supervisor, worker, cache, runtime and charged file pages can contribute. `MemoryPeak` is particularly useful while replacing a large list. `memory.events` helps identify OOM behavior; `cpu.stat` includes cgroup usage and potentially throttling, but guest-level CPU throttling does not describe every form of cloud shared-CPU scheduling.

Measure **steady state**, **cold start**, **cache restore** and **full filter rebuild** as distinct workloads on small instances. The peak can be much higher than the steady filtered-query footprint.

## Applying and reviewing changes

1. Back up the working TOML and any external list files.
2. Validate with `OnetDNS --cli check --config PATH`.
3. Apply through the dashboard or restart when required.
4. Confirm listeners, allow/block outcomes and client policy.
5. Watch logs, response latency and memory during refresh or reconfiguration.

Some settings can be hot-applied; others require listener/service reconstruction. Confirm the effect on the running service instead of assuming every file edit is immediate.

## Software updates and rollback

The dashboard can check for new signed releases. CLI equivalents:

```sh
OnetDNS --cli update --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli update apply --config /etc/OnetDNS/OnetDNS.toml
OnetDNS --cli update rollback --config /etc/OnetDNS/OnetDNS.toml
```

After a command-line update, restart as instructed and inspect the process version and startup logs. Retain a known-working configuration and backups of external state. A source-built binary need not have the same updater behavior as an official release.

## Backups and restoration

Decide which objects you manage: TOML, local lists, zone files, DHCP lease state, certificates, API/session credentials and cluster state. Back up the items actually used by the deployment. Files containing credentials, query logs or key material require appropriate access restrictions. When restoring on another host, adjust interface-bound addresses, port availability, filesystem paths and service account privileges.

## Operating a public resolver

`mode = "public"` accepts public clients. Configure `acl_allow`, `acl_deny`, `acl_drop`, and rate settings according to the intended admission policy. Check DNS listener reachability independently from management API access.

Related: [Installation](installation.md) · [CLI](cli.md) · [Performance](performance.md) · [Troubleshooting](troubleshooting.md).
