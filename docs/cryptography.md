# Cryptography

This page lists the algorithms OnetDNS uses for each protocol and for the secrets it stores.

## TLS

DoT, DoH, DoH3, DoQ, the HTTPS dashboard ([`control_listen_https`](reference/administration.md#control_listen_https)) and connections to encrypted upstream servers share one TLS implementation. Lists are in order of preference.

| Item | Supported |
| --- | --- |
| Versions | TLS 1.3 and 1.2. DoQ and DoH3 run over QUIC, which uses TLS 1.3 only. |
| TLS 1.3 cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384` |
| TLS 1.3 key exchange | `X25519MLKEM768`, `x25519`, `secp256r1` |
| TLS 1.2 cipher suites | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
| TLS 1.2 key exchange | `x25519`, `secp256r1` |
| Server signatures | `ed25519`, `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `mldsa44`, `rsa_pss_rsae_sha256`, `rsa_pss_rsae_sha384`, `rsa_pkcs1_sha256` |
| Certificate key ([`tls_key`](reference/access-and-tls.md#tls_key)) | ECDSA P-256 or ML-DSA-44, in PKCS#8 |

- `X25519MLKEM768` is a post-quantum hybrid. OnetDNS sends key shares for it and for `x25519` in its first hello, so a server without the hybrid needs no extra round trip.
- `rsa_pkcs1_sha256` is accepted only in certificate chains; TLS 1.3 forbids it for the handshake signature.
- TLS 1.2 has only suites with forward secrecy. The RSA suites are for upstream servers with RSA certificates, since OnetDNS's own key is never RSA.
- Clients that connect over TLS 1.2 must support the extended master secret (RFC 7627) and secure renegotiation (RFC 5746).
- The server accepts only TLS 1.3 when its key is ML-DSA-44 or when it verifies client certificates ([`tls_client_ca`](reference/access-and-tls.md#tls_client_ca)).
- Self-signed certificates ([`tls_self_signed_host`](reference/access-and-tls.md#tls_self_signed_host)) and certificates obtained through ACME use ECDSA P-256 keys.

## DNSCrypt

The DNSCrypt listener and DNSCrypt upstreams use X25519 key exchange and XChaCha20-Poly1305 (es-version 2). Certificates are signed with Ed25519. XSalsa20-Poly1305 (es-version 1) is not supported.

## Oblivious DoH and Oblivious HTTP

Both use HPKE (RFC 9180) with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM.

## DNSSEC

Validation:

| Item | Supported |
| --- | --- |
| Signature algorithms | 8 RSA/SHA-256, 10 RSA/SHA-512, 13 ECDSA P-256/SHA-256, 14 ECDSA P-384/SHA-384, 15 Ed25519, 18 ML-DSA-44 |
| DS digests | 2 SHA-256, 4 SHA-384 |

A zone whose DS records all use other algorithms or digests, SHA-1 included, is treated as unsigned.

If a zone's DS records include an ML-DSA-44 key, the zone must validate through ML-DSA-44; a valid signature in another algorithm alone fails. Otherwise a forged classical signature could stand in for a broken ML-DSA-44 one. This is stricter than RFC 6840, which accepts any one valid algorithm.

Authoritative zones are signed with ECDSA P-256/SHA-256 (13) by default, or Ed25519 (15). The zone's `dnssec_algorithm` field selects it ([zones](reference/structures.md#zones)).

## TSIG

TSIG accepts only `hmac-sha256`. A message signed with any other algorithm is rejected with BADKEY.

## DNS cookies

Server cookies follow RFC 9018: SipHash-2-4 over the client cookie, a timestamp and the client address, keyed with a server secret.

## Clustering

Raft traffic between nodes is encrypted and authenticated with XChaCha20-Poly1305. The key is the SHA-256 of [`cluster_raft_secret`](reference/cluster.md#cluster_raft_secret). Each node proves its identity with an Ed25519 key ([`cluster_raft_node_key`](reference/cluster.md#cluster_raft_node_key)), whose public half the other nodes list in [`cluster_raft_peers`](reference/cluster.md#cluster_raft_peers).

## Stored secrets and updates

| Use | Algorithm |
| --- | --- |
| Dashboard passwords | PBKDF2-HMAC-SHA256, 600,000 iterations for new hashes |
| Redis cache entries ([`cachedb_redis_secret`](reference/network.md#cachedb_redis_secret)) | HMAC-SHA256 |
| Update manifest (`OnetDNS-release.toml`) | Ed25519 signature; each executable must match the SHA-256 the manifest lists |
