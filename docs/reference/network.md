# DHCP and network integration — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Network services are independent

DHCPv4, DHCPv6, router advertisements, TFTP/PXE, OS network integration and Redis cache integration are not enabled merely because DNS is running. Before enabling DHCP on a LAN, determine which device currently offers addresses; two unintended DHCP servers on one subnet can make clients unstable. Listen addresses, interface selection and packet forwarding permissions are platform dependent.

## Options in this chapter

- [DHCP, IPv6 RA, TFTP and PXE](#dhcp-ipv6-ra-tftp-and-pxe)
- [Networking, kernel integration and Redis](#networking-kernel-integration-and-redis)

## DHCP, IPv6 RA, TFTP and PXE

### `dhcp_enable`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dhcp_enable = false
```

Runs the DHCPv4 server and leases IPv4 addresses.

### `dhcp_server_ip`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_server_ip = "192.168.1.10"
```

Server identifier and default local address used in DHCPv4 replies.

### `dhcp_range_start`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_range_start = "192.168.1.100"
```

First IPv4 address available for dynamic DHCPv4 allocation.

### `dhcp_range_end`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_range_end = "192.168.1.200"
```

Last IPv4 address available for dynamic DHCPv4 allocation.

### `dhcp_subnet_mask`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_subnet_mask = "255.255.255.0"
```

Subnet mask sent in DHCPv4 options.

### `dhcp_router`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_router = "192.168.1.1"
```

Default gateway sent in DHCPv4 options.

### `dhcp_dns`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
dhcp_dns = ["192.168.1.1"]
```

DNS server addresses sent to DHCPv4 clients.

### `dhcp_lease_secs`

**Type:** integer  
**Default:** `86400`

**TOML:**

```toml
dhcp_lease_secs = 3600
```

Duration of one DHCPv4 address lease.

**Unit:** seconds.

### `dhcp_local_domain`

**Type:** string  
**Default:** `"lan"`

**TOML:**

```toml
dhcp_local_domain = "lan"
```

Domain appended to DHCP hostnames when creating local DNS records, and sent to clients in DHCP option 15.

### `dhcp_tftp_server`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_tftp_server = "192.168.1.10"
```

TFTP server sent to PXE clients in DHCP option 66.

### `dhcp_boot_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_boot_file = "pxelinux.0"
```

Boot file sent to PXE clients in DHCP option 67.

### `dhcp_lease_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_lease_file = "/var/lib/OnetDNS/dhcp.leases"
```

File used to save and restore DHCPv4 lease state.

### `dhcp_static_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp_static_file = "/etc/OnetDNS/static-leases.txt"
```

File containing fixed IPv4 assignments by MAC address.

### `dhcp6_enable`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
dhcp6_enable = false
```

Runs the DHCPv6 server and leases IPv6 addresses.

### `dhcp6_range_start`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp6_range_start = "2001:db8:1::100"
```

First IPv6 address available for dynamic DHCPv6 allocation.

### `dhcp6_range_end`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp6_range_end = "2001:db8:1::200"
```

Last IPv6 address available for dynamic DHCPv6 allocation.

### `dhcp6_dns`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
dhcp6_dns = ["2001:db8::53"]
```

DNS server addresses sent to DHCPv6 clients.

### `dhcp6_interface_index`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
dhcp6_interface_index = 0
```

Number of the network interface that receives DHCPv6 requests. Zero uses the operating system's default interface.

### `dhcp6_lease_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
dhcp6_lease_file = "/var/lib/OnetDNS/dhcp6.leases"
```

File used to save and restore DHCPv6 lease state.

### `mac_vendor_db`

**Type:** string  
**Default:** not set

**TOML:**

```toml
mac_vendor_db = "/etc/OnetDNS/oui.txt"
```

OUI data file used to identify vendors from MAC addresses.

### `tftp_enable`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
tftp_enable = false
```

Runs the TFTP server used for PXE file transfer.

### `tftp_root`

**Type:** string  
**Default:** not set

**TOML:**

```toml
tftp_root = "/srv/tftp"
```

Top-level directory available to TFTP clients.

### `tftp_listen`

**Type:** string  
**Default:** `"127.0.0.1:69"`

**TOML:**

```toml
tftp_listen = "0.0.0.0:69"
```

IP address and UDP port that accept TFTP requests.

### `tftp_read_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
tftp_read_allow = ["192.168.1.0/24"]
```

Client address ranges allowed to download boot files. Required when TFTP listens on a non-loopback address.

### `tftp_writable`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
tftp_writable = false
```

Allows new files to be uploaded over TFTP.

### `tftp_write_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
tftp_write_allow = ["192.168.1.0/24"]
```

Client address ranges allowed to upload files through TFTP. When empty, only this machine can upload.

### `tftp_allow_overwrite`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
tftp_allow_overwrite = false
```

Allows TFTP uploads to replace existing files.

### `ra_enable`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
ra_enable = false
# Router advertisement requires a valid prefix and interface configuration.
```

Sends IPv6 Router Advertisements on the local link.

### `ra_prefix`

**Type:** string  
**Default:** not set

**TOML:**

```toml
ra_prefix = "2001:db8:1::/64"
```

IPv6 network prefix advertised in Router Advertisements.

### `ra_managed`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
ra_managed = false
```

M flag indicating that clients should obtain addresses through DHCPv6.

### `ra_other`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
ra_other = false
```

O flag indicating that clients should obtain non-address settings through DHCPv6.

### `ra_router_lifetime`

**Type:** integer  
**Default:** `1800`

**TOML:**

```toml
ra_router_lifetime = 1800
```

Time clients may use this server as their default IPv6 router.

**Unit:** seconds.

### `ra_interval`

**Type:** integer  
**Default:** `600`

**TOML:**

```toml
ra_interval = 600
```

Interval between periodic Router Advertisements.

**Unit:** seconds.

### `ra_mtu`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
ra_mtu = 1500
```

Link MTU advertised to IPv6 clients.

### `ra_interface_index`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
ra_interface_index = 0
```

Network interface index used to send Router Advertisements.

### `ra_dns`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
ra_dns = ["2001:db8::53"]
```

IPv6 DNS server addresses sent in the Router Advertisement RDNSS option (RFC 8106). Devices that do not use DHCPv6, such as Android, learn their DNS server only this way. Each address must be IPv6, and at most 64 are accepted. The option lifetime is three times `ra_interval`, so one lost advertisement does not expire it. An empty list leaves the option out.

## Networking, kernel integration and Redis

### `ipset_name_v4`

**Type:** string  
**Default:** not set

**TOML:**

```toml
ipset_name_v4 = "onetdns-v4"
```

Linux ipset that receives filtered IPv4 addresses.

### `ipset_name_v6`

**Type:** string  
**Default:** not set

**TOML:**

```toml
ipset_name_v6 = "onetdns-v6"
```

Linux ipset that receives filtered IPv6 addresses.

### `ipset_domains`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
ipset_domains = ["example.com"]
```

Domains whose answer addresses are inserted into ipset.

### `cachedb_redis_host`

**Type:** string  
**Default:** not set

**TOML:**

```toml
cachedb_redis_host = "127.0.0.1"
```

Redis server used as a shared external response cache.

### `cachedb_redis_port`

**Type:** integer  
**Default:** `6379`

**TOML:**

```toml
cachedb_redis_port = 6379
```

TCP port of the external Redis response cache.

### `cachedb_redis_expire_secs`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
cachedb_redis_expire_secs = 0
```

Maximum lifetime of DNS responses stored in Redis.

**Unit:** seconds.

### `cachedb_redis_secret`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
cachedb_redis_secret = "REPLACE_WITH_REDIS_SECRET"
```

HMAC-SHA256 key that signs Redis cache entries. It must be at least 32 bytes, and every server using the same Redis must use the same value.

### `cachedb_redis_username`

**Type:** string  
**Default:** not set

**TOML:**

```toml
cachedb_redis_username = "REPLACE_WITH_REDIS_USERNAME"
```

Redis ACL user name. Leave it empty and set only the password to authenticate as the default user.

### `cachedb_redis_password`

**Type:** string  
**Default:** not set

**TOML:**

```toml
cachedb_redis_password = "REPLACE_WITH_REDIS_PASSWORD"
```

Password sent with the AUTH command after connecting to Redis. Without TLS it travels in plain text.

### `cachedb_redis_tls`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
cachedb_redis_tls = false
```

Connects to Redis over TLS and checks that the server certificate was issued for the name in the Redis server address.

### `cachedb_redis_tls_ca`

**Type:** string  
**Default:** not set

**TOML:**

```toml
cachedb_redis_tls_ca = "/etc/OnetDNS/redis-ca.pem"
```

CA file used to verify the Redis TLS certificate. When empty, the system trust store is used. Certificates issued by a private CA need this file.
