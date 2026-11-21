# Authoritative DNS — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Authoritative service versus recursive service

Authoritative zones answer for names the server owns. They are not automatically created by enabling recursive or forwarding resolution. Zone-file sources, dynamic updates, TSIG keys, secondary transfer inputs and DNSSEC signing have distinct roles. Treat DNSSEC validation of responses (`dnssec`) and signing your own authoritative zone (`dnssec_sign` inside a zone) as independent features.

## Options in this chapter

- [Authoritative DNS and zone transfers](#authoritative-dns-and-zone-transfers)

## Authoritative DNS and zone transfers

### `zones`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[zones]]
origin = "corp.example."
file = "/etc/OnetDNS/zones/corp.example.zone"
```

See [structured table fields](structures.md#zones) for the nested field definitions.

Authoritative DNS zones defined directly in the configuration file.

### `zones_dir`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_dir = "/etc/OnetDNS/zones"
```

Directory containing zone files; changes are watched and reloaded.

### `zones_db`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_db = "/var/lib/OnetDNS/zones.sqlite"
```

SQLite database file containing authoritative zones.

### `zones_db_table`

**Type:** string  
**Default:** `"zones"`

**TOML:**

```toml
zones_db_table = "zones"
```

SQLite table containing zone records.

### `zones_postgres`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_postgres = "postgresql://USER:PASSWORD@127.0.0.1:5432/dns"
```

PostgreSQL connection string used to load authoritative zones.

### `zones_mysql`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_mysql = "mysql://USER:PASSWORD@127.0.0.1:3306/dns"
```

MySQL connection string used to load authoritative zones.

### `zones_lmdb`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_lmdb = "/var/lib/OnetDNS/zones.lmdb"
```

LMDB environment path used to load authoritative zones.

### `zones_sql_table`

**Type:** string  
**Default:** `"zones"`

**TOML:**

```toml
zones_sql_table = "zones"
```

Table containing zones in PostgreSQL or MySQL.

### `zones_etcd`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_etcd = "http://127.0.0.1:2379"
```

etcd endpoint used to load authoritative zones.

### `zones_etcd_prefix`

**Type:** string  
**Default:** `"/onetdns/zones/"`

**TOML:**

```toml
zones_etcd_prefix = "/onetdns/zones/"
```

Key prefix used to find zone data in etcd.

### `zones_etcd_ca`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_etcd_ca = "/etc/OnetDNS/etcd-ca.pem"
```

CA file used to verify the etcd TLS certificate. Required for an https etcd endpoint; the system trust store is not used.

### `zones_etcd_user`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_etcd_user = "REPLACE_WITH_ETCD_USERNAME"
```

User name used to authenticate to etcd.

### `zones_etcd_password`

**Type:** string  
**Default:** not set

**TOML:**

```toml
zones_etcd_password = "REPLACE_WITH_ETCD_PASSWORD"
```

Password used to authenticate to etcd.

### `secondary`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[secondary]]
origin = "secondary.example."
primary = "192.0.2.53"
file = "/var/lib/OnetDNS/zones/secondary.example.zone"
```

See [structured table fields](structures.md#secondary) for the nested field definitions.

Secondary zones replicated from primary servers with AXFR or IXFR.

### `catalog`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[catalog]]
origin = "catalog.example."
primary = "192.0.2.53"
```

See [structured table fields](structures.md#catalog) for the nested field definitions.

Consumes a remote catalog zone to discover secondary zones.

### `catalog_serve`

**Type:** string  
**Default:** not set

**TOML:**

```toml
catalog_serve = "catalog.example.com"
```

Name of the catalog zone served by this server.

### `xfr_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
xfr_allow = ["192.0.2.0/24"]
```

Client address ranges allowed to request AXFR or IXFR.

### `xfr_tsig_required`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
xfr_tsig_required = false
```

Requires a valid TSIG signature on zone-transfer requests.

### `notify`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[notify]]
address = "192.0.2.54:53"
```

See [structured table fields](structures.md#notify) for the nested field definitions.

Address:port targets and optional TSIG keys for DNS NOTIFY after zone serial changes.

### `tsig_keys`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[tsig_keys]]
name = "transfer-key.example."
secret = "REPLACE_WITH_BASE64_TSIG_SECRET"
```

See [structured table fields](structures.md#tsig_keys) for the nested field definitions.

TSIG names and shared secrets used for zone transfer and dynamic update.

### `zonemd_check`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
zonemd_check = false
```

Verifies the ZONEMD digest when loading a zone.

### `zonemd_reject_absence`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
zonemd_reject_absence = false
```

Rejects zones that do not contain a ZONEMD record. Can be enabled only while zonemd_check is on.

### `update_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
update_allow = ["192.0.2.0/24"]
```

Client address ranges allowed to send dynamic DNS UPDATE requests.

### `update_policy`

**Type:** nested table / table array  
**Default:** `[]`

**TOML:**

```toml
[[update_policy]]
action = "deny"
identity = "transfer-key.example."
name = "corp.example."
types = ["A", "AAAA"]
```

See [structured table fields](structures.md#update_policy) for the nested field definitions.

Rules for who may change which names and record types through dynamic updates. Each rule gives an action (grant or deny), a TSIG key name, a target name, and optionally record types. Without types, the rule covers every type.

### `update_tsig_required`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
update_tsig_required = false
```

Requires a valid TSIG signature on dynamic DNS UPDATE requests.
