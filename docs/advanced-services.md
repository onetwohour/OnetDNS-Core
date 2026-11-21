# Authoritative DNS, DHCP and clustering

Authoritative DNS, DHCP, PXE/TFTP, and Raft clustering have separate configuration sections and listener requirements.

## Authoritative DNS

Authoritative service answers for zones the operator configures. A local authoritative zone differs from:

- a **rewrite**, which maps a particular requested name to a configured answer;
- a **stub zone**, which forwards name resolution for a suffix to a specified nameserver;
- a **recursive resolver**, which discovers authoritative servers in the wider DNS hierarchy.

The project supports zone-file inputs, configured storage sources, dynamic updates, zone transfer/secondary roles and DNSSEC signing. Those capabilities have different operational preconditions. A zone file should contain an SOA and appropriate NS records; a publicly delegated zone needs delegation at its parent. Internal zones may be used without public delegation but still require correct internal client routing.

### Example zone source

```toml
[[zones]]
origin = "lab.example."
file = "/etc/OnetDNS/zones/lab.example.zone"
```

The service account needs read access to the zone file. Test SOA and NS queries with `dig` after startup; externally delegated zones also require a parent delegation.

### DNSSEC for zones

`dnssec_sign` and signing-key settings inside a zone control **publishing signatures for your authoritative data**. This is not the same as setting global `dnssec = true` to validate external responses. For a publicly signed zone, signing and parent DS publication must be coordinated; signature generation without the appropriate chain of trust does not achieve authenticated delegation.

## DHCPv4 and device names

```toml
dhcp_enable = true
dhcp_server_ip = "192.168.1.10"
dhcp_range_start = "192.168.1.100"
dhcp_range_end = "192.168.1.199"
dhcp_subnet_mask = "255.255.255.0"
dhcp_router = "192.168.1.1"
dhcp_local_domain = "lan"
```

The example assumes OnetDNS is at `192.168.1.10` and serves a single IPv4 subnet. Adapt all addresses to your network. If a router currently serves DHCP, determine whether it should remain the sole DHCP server or whether its service must be disabled when enabling OnetDNS. Unintended competing DHCP servers can return conflicting lease and gateway information. DHCP broadcast behavior and interface permissions can depend on platform and topology.

Lease-based names depend on `dhcp_local_domain` and the hostname supplied by each device. Check the DHCP lease and resulting DNS record together.

## DHCPv6 and router advertisements

DHCPv6 and IPv6 router advertisements are separately configurable. IPv6 clients may obtain default gateways from Router Advertisements rather than DHCPv6. Decide which system advertises the IPv6 prefix, route and DNS information before turning on extra RA functionality. Observe actual packets on the LAN and confirm clients receive the intended addressing and resolver settings.

## PXE/TFTP

Network boot adds a TFTP/PXE role. Validate boot file paths, access permissions, firmware expectations (UEFI versus legacy BIOS) and network reachability. An active DHCP server does not mean PXE options and TFTP files are correctly configured; each stage needs its own test.

## Raft configuration clustering

The source includes Raft-based coordination for multiple OnetDNS nodes. A multi-node deployment needs stable peer addresses, unique node IDs, persistent state and a plan for lost quorum. Config replication is not a substitute for checking that each node can bind its own DNS listeners and reach its upstream resolvers. Before deploying, test how one node behaves when a peer or network link disappears and then returns.

Do not copy an entire production node's identity or persistent cluster state onto a second node without understanding the cluster's join and recovery process.

## Verifying a new service

1. Record the intended new role and which ports/interfaces it needs.
2. Add only its related fields to a backup copy of the current config.
3. Validate TOML and field combinations with `--cli check`.
4. Apply or restart as required and verify the service actually bound the intended sockets.
5. Test the role from an independent client (zone query, DHCP lease, TFTP download or cluster status).
6. Check that ordinary DNS resolution and filtering still behave correctly.

See [Structured table reference](reference/structures.md) and the [Authoritative](reference/authority.md), [Network](reference/network.md) and [Cluster](reference/cluster.md) option chapters for field names and defaults.
