# Access, TLS and certificates — configuration reference

[All configuration topics](README.md) · [Configuration guide](../configuration.md) · [Examples](../examples.md)

## Three independent concerns

- **DNS clients:** the `acl_*` settings and rate-limit options determine how DNS queries are handled. ACLs and rate limits are configured independently.
- **Encrypted DNS:** TLS listener settings and certificate material control incoming secure transports.
- **Control plane:** dashboard origins, sessions, tokens and trusted proxies are configured separately under the administration reference. DNS ACLs do not authenticate dashboard requests.

A certificate hostname must match what the client connects to. DoH/DoH3 may share a numeric port on different IP transports; so may DoT/DoQ.

## Options in this chapter

- [DNS client access and response controls](#dns-client-access-and-response-controls)
- [TLS certificates and transport security](#tls-certificates-and-transport-security)
- [ACME certificate automation](#acme-certificate-automation)

## DNS client access and response controls

### `acl_allow`

**Type:** array  
**Default:** personal-mode private/loopback CIDR presets; empty in public mode unless set explicitly

**TOML:**

```toml
acl_allow = ["192.168.1.0/24", "127.0.0.1/32"]
```

Client address ranges allowed to query the DNS server.

**Note:** An explicitly supplied `acl_allow` overrides the mode preset. Empty ACL lists and client-specific controls retain their documented behavior.

### `acl_deny`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
acl_deny = ["198.51.100.0/24"]
```

Client address ranges denied access. Deny rules take precedence over allow rules.

### `acl_drop`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
acl_drop = ["203.0.113.0/24"]
```

Client address ranges whose DNS queries are dropped without any response, not even a refusal. Takes precedence over deny and allow rules.

### `acl_unlisted`

**Type:** enum (`deny` / `drop`)  
**Default:** `deny`

**TOML:**

```toml
acl_unlisted = "deny"
```

When an allow list is set, whether clients that match no access rule get a refusal or no response at all.

### `acl_allow_ids`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
acl_allow_ids = ["trusted-client"]
```

Authenticated client IDs allowed on encrypted transports.

### `acl_deny_ids`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
acl_deny_ids = ["blocked-client"]
```

Authenticated client IDs denied on encrypted transports.

### `rate_limit_per_sec`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
rate_limit_per_sec = 0
```

Average number of queries one client address may send per second.

**Unit:** qps.

### `rate_limit_burst`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
rate_limit_burst = 0
```

Additional queries allowed for one client during a short burst.

### `run_as_user`

**Type:** string  
**Default:** not set

**TOML:**

```toml
run_as_user = "onetdns"
```

Linux user the DNS process switches to as soon as it starts. This user must be able to write to the configuration folder and read the files the configuration points to. It cannot change while the server runs; edit the configuration file and restart the service.

### `run_as_group`

**Type:** string  
**Default:** not set

**TOML:**

```toml
run_as_group = "onetdns"
```

Linux group applied when process privileges are dropped.

### `rate_limit_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
rate_limit_allow = ["192.168.1.0/24"]
```

Address ranges exempt from per-client rate limiting.

### `subnet_rrl_per_sec`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
subnet_rrl_per_sec = 0
```

Average responses per second allowed for one client subnet.

**Unit:** qps.

### `subnet_rrl_burst`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
subnet_rrl_burst = 0
```

Additional responses allowed for one client subnet in a short burst.

### `name_ratelimit_per_sec`

**Type:** integer  
**Default:** `0`

**TOML:**

```toml
name_ratelimit_per_sec = 0
```

Average queries per second allowed for the same query-name bucket.

**Unit:** qps.

### `name_ratelimit_labels`

**Type:** integer  
**Default:** `2`

**TOML:**

```toml
name_ratelimit_labels = 2
```

How many labels from the end of a name count as the same name for the per-name limit. With 2, a.example.com and b.example.com both count as example.com.

### `cookies`

**Type:** enum (`off` / `lenient` / `strict`)  
**Default:** `lenient`

**TOML:**

```toml
cookies = "lenient"
```

Whether to use DNS cookies to filter out queries with a forged source address.

### `rebind_protection`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
rebind_protection = false
```

Blocks public domain answers that contain private or loopback addresses.

### `rebind_allow`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
rebind_allow = ["*.corp.example"]
```

Domains exempt from DNS rebinding protection.

### `hide_identity`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
hide_identity = true
```

Suppresses the server identity in CHAOS id.server responses.

### `hide_version`

**Type:** boolean  
**Default:** `false`

**TOML:**

```toml
hide_version = true
```

Suppresses the version string in CHAOS version.bind responses.

### `nsid`

**Type:** string  
**Default:** not set

**TOML:**

```toml
nsid = "ns1"
```

Server identifier returned to queries that request an NSID. Used to tell which of several servers answered.

### `identity`

**Type:** string  
**Default:** not set

**TOML:**

```toml
identity = "dns1"
```

String returned for CHAOS id.server when identity hiding is disabled.

### `version`

**Type:** string  
**Default:** not set

**TOML:**

```toml
version = "OnetDNS"
```

String returned for CHAOS version.bind when version hiding is disabled.

## TLS certificates and transport security

### `tls_cert`

**Type:** string  
**Default:** not set

**TOML:**

```toml
tls_cert = "/etc/OnetDNS/fullchain.pem"
```

PEM certificate presented by DoT, DoH, DoQ, and DoH3 listeners.

### `tls_key`

**Type:** string  
**Default:** not set

**TOML:**

```toml
tls_key = "/etc/OnetDNS/privkey.pem"
```

PEM private key matching the configured TLS certificate, in PKCS#8: ECDSA P-256, or ML-DSA-44 (RFC 9881) with its seed. An ML-DSA-44 certificate serves only TLS 1.3 clients, and an Apple configuration profile is then left unsigned.

### `tls_self_signed_host`

**Type:** string  
**Default:** not set

**TOML:**

```toml
tls_self_signed_host = "dns.example.com"
```

Hostname used in the self-signed certificate when no certificate file is configured. The certificate is kept in tls-self-signed.pem next to the config file.

### `tls_client_ca`

**Type:** string  
**Default:** not set

**TOML:**

```toml
tls_client_ca = "/etc/OnetDNS/client-ca.pem"
```

CA certificate file used to verify mTLS client certificates.

### `tls_revocation`

**Type:** string  
**Default:** `"off"`

**TOML:**

```toml
tls_revocation = "off"
```

Controls OCSP and CRL checking for upstream TLS certificates.

### `tls_revocation_softfail`

**Type:** boolean  
**Default:** `true`

**TOML:**

```toml
tls_revocation_softfail = false
```

Allows certificate validation to continue when revocation services are unreachable.

## ACME certificate automation

### `acme_directory_url`

**Type:** string  
**Default:** not set

**TOML:**

```toml
acme_directory_url = "https://acme-v02.api.letsencrypt.org/directory"
```

ACME directory URL used for account registration and certificate issuance. Let's Encrypt when empty.

### `acme_contact_email`

**Type:** string  
**Default:** not set

**TOML:**

```toml
acme_contact_email = "dns-admin@example.com"
```

Operational contact email registered with the ACME account.

### `acme_domains`

**Type:** array  
**Default:** `[]`

**TOML:**

```toml
acme_domains = ["dns.example.com"]
# ACME also requires challenge, contact and output path settings.
```

DNS names included in the issued certificate.

### `acme_challenge`

**Type:** enum (`http01` / `dns01`)  
**Default:** `"http01"`

**TOML:**

```toml
acme_challenge = "http01"
```

How domain ownership is proven. HTTP-01 requires forwarding requests for /.well-known/acme-challenge/ on port 80 to the management address. DNS-01 is for when this server is the authoritative DNS server for the domain.

### `acme_account_key_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
acme_account_key_file = "/etc/OnetDNS/acme/account.pem"
```

File used to store the ACME account private key. Defaults to acme-account-key.pem next to the configuration file.

### `acme_cert_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
acme_cert_file = "/etc/OnetDNS/acme/fullchain.pem"
# The related ACME key-file path must also be configured.
```

File used to store the issued certificate chain. Defaults to tls_cert, or acme-cert.pem next to the configuration file.

### `acme_key_file`

**Type:** string  
**Default:** not set

**TOML:**

```toml
acme_key_file = "/etc/OnetDNS/acme/privkey.pem"
```

File used to store the private key for the issued certificate. Defaults to tls_key, or acme-key.pem next to the configuration file.
