# Clustering — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Configuration propagation

Cluster settings control coordination between OnetDNS instances; they do not themselves replace DNS listeners or forwarders. When enabling clustering, document the identity, peer addresses, persistent state and expected failure behavior of every member. Verify changes from one node and observe consistency on peers; do not assume an untested multi-node configuration behaves like a standalone server.

## Options in this chapter

- [Clustering and Raft](#clustering-and-raft)

## Clustering and Raft

### `cluster_peers`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
cluster_peers = ["https://node2.example.com:8553"]
```

Management addresses of other nodes whose status is shown and with which DHCP leases are shared when running several nodes without Raft. The management token is sent, so use an https:// address unless the node is on the same machine.

### `cluster_raft`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
cluster_raft = false
```

Nodes agree on changes and apply the same settings. Settings can be changed only on the leader node, while settings that differ per node, such as listen addresses and certificates, are changed on each node.

### `cluster_node_id`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
cluster_node_id = 1
```

Numeric ID that identifies this node in the Raft cluster.

### `cluster_raft_listen`

**Type:** string  
**Default:** not set

**TOML:**

```toml
cluster_raft_listen = "0.0.0.0:7001"
```

Address that accepts connections from other Raft nodes.

### `cluster_raft_peers`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
cluster_raft_peers = ["2@192.0.2.20:7002#0000000000000000000000000000000000000000000000000000000000000000"]
# Replace the 64-zero hexadecimal sample with the peer's real Ed25519 public key.
```

Other nodes taking part in Raft, written as node-number@address:port#public-key. Each node's Cluster screen shows its entry ready to copy.

### `cluster_raft_secret`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
cluster_raft_secret = "REPLACE_WITH_CLUSTER_SHARED_SECRET"
```

Shared secret that authenticates and encrypts traffic between Raft nodes. Use the same value on every node.

### `cluster_raft_node_key`

**Type:** string  
**Default:** `""` (empty)

**TOML:**

```toml
cluster_raft_node_key = "REPLACE_WITH_NODE_PRIVATE_KEY"
# Must be valid private key material; the placeholder will not work.
```

Ed25519 private key this node uses to prove its identity, written as 64 hexadecimal digits. Must differ on every node.
