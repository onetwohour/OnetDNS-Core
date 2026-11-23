# Configuration reference

Every top-level setting has a TOML code example immediately below its type and default. Values such as `example.com`, `192.0.2.0/24`, and `REPLACE_WITH_...` are illustrative and must be replaced when used. The samples are **independent option examples**, not a single config that can be pasted together unchanged.

Read [Structured configuration entries](structures.md) for arrays of tables (`[[clients]]`, `[[zones]]`, and others), plus `local_a` / `local_aaaa` and the special `wasm_plugins` array.

## Using the reference

- [Configuration](../configuration.md): file locations, validation, and applying changes.
- [Examples](../examples.md): deployable TOML patterns.
- [Structured configuration entries](structures.md): exact TOML layout and nested fields, including the non-table formats.

## Option chapters

| Reference | What it covers |
| --- | --- |
| [Core server](core.md) | General and operating mode; Listening interfaces and incoming transports; Query processing and EDNS; Caching and TTL |
| [Upstreams, recursion and DNSSEC](upstreams.md) | Upstream servers and forwarding; Recursive and split resolution; DNSSEC validation |
| [Filtering and policy](filtering.md) | Filtering, rewriting, and local policy; Policy rules and WASM |
| [Access, TLS and certificates](access-and-tls.md) | DNS client access and response controls; TLS certificates and transport security; ACME certificate automation |
| [Dashboard, logging and administration](administration.md) | Dashboard, API, logging, and updates; Discovery and other settings |
| [Authoritative DNS](authority.md) | Authoritative DNS and zone transfers |
| [DHCP and network integration](network.md) | DHCP, IPv6 RA, TFTP and PXE; Networking, kernel integration and Redis |
| [Clustering](cluster.md) | Clustering and Raft |

## Find a setting by name

Top-level keys are indexed alphabetically below.

### A

[`acl_allow`](access-and-tls.md#acl_allow)
[`acl_allow_ids`](access-and-tls.md#acl_allow_ids)
[`acl_deny`](access-and-tls.md#acl_deny)
[`acl_deny_ids`](access-and-tls.md#acl_deny_ids)
[`acl_drop`](access-and-tls.md#acl_drop)
[`acl_unlisted`](access-and-tls.md#acl_unlisted)
[`acme_account_key_file`](access-and-tls.md#acme_account_key_file)
[`acme_cert_file`](access-and-tls.md#acme_cert_file)
[`acme_challenge`](access-and-tls.md#acme_challenge)
[`acme_contact_email`](access-and-tls.md#acme_contact_email)
[`acme_directory_url`](access-and-tls.md#acme_directory_url)
[`acme_domains`](access-and-tls.md#acme_domains)
[`acme_key_file`](access-and-tls.md#acme_key_file)
[`aggressive_nsec`](upstreams.md#aggressive_nsec)
[`allow_rules`](filtering.md#allow_rules)
[`allowlists`](filtering.md#allowlists)
[`anonymize_client_ip`](administration.md#anonymize_client_ip)

### B

[`backend`](core.md#backend)
[`block_aaaa`](filtering.md#block_aaaa)
[`block_ipv4`](filtering.md#block_ipv4)
[`block_ipv6`](filtering.md#block_ipv6)
[`block_response`](filtering.md#block_response)
[`block_rules`](filtering.md#block_rules)
[`blocked_response_ttl`](filtering.md#blocked_response_ttl)
[`blocked_services`](filtering.md#blocked_services)
[`blocklist_titles`](filtering.md#blocklist_titles)
[`blocklist_urls`](filtering.md#blocklist_urls)
[`blocklists`](filtering.md#blocklists)
[`bogus_nxdomain`](filtering.md#bogus_nxdomain)
[`bogus_priv`](filtering.md#bogus_priv)
[`bootstrap`](upstreams.md#bootstrap)

### C

[`cache_enabled`](core.md#cache_enabled)
[`cache_shards`](core.md#cache_shards)
[`cache_size`](core.md#cache_size)
[`cachedb_redis_expire_secs`](network.md#cachedb_redis_expire_secs)
[`cachedb_redis_host`](network.md#cachedb_redis_host)
[`cachedb_redis_password`](network.md#cachedb_redis_password)
[`cachedb_redis_port`](network.md#cachedb_redis_port)
[`cachedb_redis_secret`](network.md#cachedb_redis_secret)
[`cachedb_redis_tls`](network.md#cachedb_redis_tls)
[`cachedb_redis_tls_ca`](network.md#cachedb_redis_tls_ca)
[`cachedb_redis_username`](network.md#cachedb_redis_username)
[`catalog`](authority.md#catalog)
[`catalog_serve`](authority.md#catalog_serve)
[`clients`](administration.md#clients)
[`cluster_node_id`](cluster.md#cluster_node_id)
[`cluster_peers`](cluster.md#cluster_peers)
[`cluster_raft`](cluster.md#cluster_raft)
[`cluster_raft_listen`](cluster.md#cluster_raft_listen)
[`cluster_raft_node_key`](cluster.md#cluster_raft_node_key)
[`cluster_raft_peers`](cluster.md#cluster_raft_peers)
[`cluster_raft_secret`](cluster.md#cluster_raft_secret)
[`cname_limit`](upstreams.md#cname_limit)
[`control_admin_tokens`](administration.md#control_admin_tokens)
[`control_listen`](administration.md#control_listen)
[`control_listen_https`](administration.md#control_listen_https)
[`control_public_origins`](administration.md#control_public_origins)
[`control_readonly_tokens`](administration.md#control_readonly_tokens)
[`control_token`](administration.md#control_token)
[`control_trusted_proxies`](administration.md#control_trusted_proxies)
[`cookies`](access-and-tls.md#cookies)

### D

[`ddr_name`](administration.md#ddr_name)
[`deny_any`](core.md#deny_any)
[`dhcp6_dns`](network.md#dhcp6_dns)
[`dhcp6_enable`](network.md#dhcp6_enable)
[`dhcp6_interface_index`](network.md#dhcp6_interface_index)
[`dhcp6_lease_file`](network.md#dhcp6_lease_file)
[`dhcp6_range_end`](network.md#dhcp6_range_end)
[`dhcp6_range_start`](network.md#dhcp6_range_start)
[`dhcp_boot_file`](network.md#dhcp_boot_file)
[`dhcp_dns`](network.md#dhcp_dns)
[`dhcp_enable`](network.md#dhcp_enable)
[`dhcp_lease_file`](network.md#dhcp_lease_file)
[`dhcp_lease_secs`](network.md#dhcp_lease_secs)
[`dhcp_local_domain`](network.md#dhcp_local_domain)
[`dhcp_range_end`](network.md#dhcp_range_end)
[`dhcp_range_start`](network.md#dhcp_range_start)
[`dhcp_router`](network.md#dhcp_router)
[`dhcp_server_ip`](network.md#dhcp_server_ip)
[`dhcp_static_file`](network.md#dhcp_static_file)
[`dhcp_subnet_mask`](network.md#dhcp_subnet_mask)
[`dhcp_tftp_server`](network.md#dhcp_tftp_server)
[`disabled_blocklist_urls`](filtering.md#disabled_blocklist_urls)
[`dname_limit`](upstreams.md#dname_limit)
[`dns64_prefix`](core.md#dns64_prefix)
[`dns64_synthall`](core.md#dns64_synthall)
[`dnscrypt_provider_name`](core.md#dnscrypt_provider_name)
[`dnssec`](upstreams.md#dnssec)
[`dnssec_accept_expired`](upstreams.md#dnssec_accept_expired)
[`dnssec_anchor_file`](upstreams.md#dnssec_anchor_file)
[`dnssec_rfc5011`](upstreams.md#dnssec_rfc5011)
[`dnssec_roll_interval_secs`](upstreams.md#dnssec_roll_interval_secs)
[`dnssec_strict`](upstreams.md#dnssec_strict)
[`dnstap_file`](administration.md#dnstap_file)
[`dnstap_identity`](administration.md#dnstap_identity)
[`do_ip4`](upstreams.md#do_ip4)
[`do_ip6`](upstreams.md#do_ip6)
[`do_tcp`](core.md#do_tcp)
[`do_udp`](core.md#do_udp)
[`doh_path`](core.md#doh_path)
[`domain_insecure`](upstreams.md#domain_insecure)
[`domain_needed`](filtering.md#domain_needed)
[`dynamic_records`](filtering.md#dynamic_records)

### E

[`ecs_custom_ip`](core.md#ecs_custom_ip)
[`ecs_mode`](core.md#ecs_mode)
[`edns_buffer_size`](core.md#edns_buffer_size)
[`edns_padding_block`](core.md#edns_padding_block)
[`edns_tcp_keepalive_secs`](core.md#edns_tcp_keepalive_secs)
[`empty_zones`](filtering.md#empty_zones)

### F

[`fallback_upstreams`](upstreams.md#fallback_upstreams)

### H

[`harden_below_nxdomain`](upstreams.md#harden_below_nxdomain)
[`harden_large_queries`](upstreams.md#harden_large_queries)
[`harden_referral_path`](upstreams.md#harden_referral_path)
[`hide_identity`](access-and-tls.md#hide_identity)
[`hide_version`](access-and-tls.md#hide_version)

### I

[`identity`](access-and-tls.md#identity)
[`ignore_cd_flag`](upstreams.md#ignore_cd_flag)
[`ipset_domains`](network.md#ipset_domains)
[`ipset_name_v4`](network.md#ipset_name_v4)
[`ipset_name_v6`](network.md#ipset_name_v6)

### L

[`list_refresh_secs`](filtering.md#list_refresh_secs)
[`listen`](core.md#listen)
[`listen_dnscrypt`](core.md#listen_dnscrypt)
[`listen_doh`](core.md#listen_doh)
[`listen_doh3`](core.md#listen_doh3)
[`listen_doq`](core.md#listen_doq)
[`listen_dot`](core.md#listen_dot)
[`local_a`](upstreams.md#local_a)
[`local_aaaa`](upstreams.md#local_aaaa)
[`local_ttl`](filtering.md#local_ttl)
[`local_zones`](filtering.md#local_zones)
[`log_level`](administration.md#log_level)
[`lowercase_outgoing`](upstreams.md#lowercase_outgoing)

### M

[`mac_vendor_db`](network.md#mac_vendor_db)
[`max_inflight`](core.md#max_inflight)
[`max_ttl`](core.md#max_ttl)
[`min_ttl`](core.md#min_ttl)
[`minimal_responses`](core.md#minimal_responses)
[`mode`](core.md#mode)

### N

[`name_ratelimit_labels`](access-and-tls.md#name_ratelimit_labels)
[`name_ratelimit_per_sec`](access-and-tls.md#name_ratelimit_per_sec)
[`neg_max_ttl`](core.md#neg_max_ttl)
[`neg_min_ttl`](core.md#neg_min_ttl)
[`notify`](authority.md#notify)
[`ns_cache_size`](upstreams.md#ns_cache_size)
[`ns_recursion_limit`](upstreams.md#ns_recursion_limit)
[`nsid`](access-and-tls.md#nsid)

### P

[`parental_control`](filtering.md#parental_control)
[`persist_flush_secs`](administration.md#persist_flush_secs)
[`policy`](filtering.md#policy)
[`prefer_ip4`](upstreams.md#prefer_ip4)
[`prefer_ip6`](upstreams.md#prefer_ip6)
[`prefetch`](core.md#prefetch)
[`prefetch_interval_secs`](core.md#prefetch_interval_secs)
[`prefetch_min_hits`](core.md#prefetch_min_hits)
[`prefetch_ttl_pct`](core.md#prefetch_ttl_pct)
[`proxy_protocol_ports`](core.md#proxy_protocol_ports)
[`proxy_protocol_trusted`](core.md#proxy_protocol_trusted)

### Q

[`qname_minimisation_strict`](upstreams.md#qname_minimisation_strict)
[`query_source`](upstreams.md#query_source)
[`query_source_v6`](upstreams.md#query_source_v6)
[`query_timeout_secs`](core.md#query_timeout_secs)
[`querylog`](administration.md#querylog)
[`querylog_file`](administration.md#querylog_file)
[`querylog_ignored`](administration.md#querylog_ignored)
[`querylog_retention_secs`](administration.md#querylog_retention_secs)
[`querylog_size`](administration.md#querylog_size)

### R

[`ra_dns`](network.md#ra_dns)
[`ra_enable`](network.md#ra_enable)
[`ra_interface_index`](network.md#ra_interface_index)
[`ra_interval`](network.md#ra_interval)
[`ra_managed`](network.md#ra_managed)
[`ra_mtu`](network.md#ra_mtu)
[`ra_other`](network.md#ra_other)
[`ra_prefix`](network.md#ra_prefix)
[`ra_router_lifetime`](network.md#ra_router_lifetime)
[`rate_limit_allow`](access-and-tls.md#rate_limit_allow)
[`rate_limit_burst`](access-and-tls.md#rate_limit_burst)
[`rate_limit_per_sec`](access-and-tls.md#rate_limit_per_sec)
[`rebind_allow`](access-and-tls.md#rebind_allow)
[`rebind_protection`](access-and-tls.md#rebind_protection)
[`recurse_allow_answers`](upstreams.md#recurse_allow_answers)
[`recurse_allow_server`](upstreams.md#recurse_allow_server)
[`recurse_deny_answers`](upstreams.md#recurse_deny_answers)
[`recurse_deny_server`](upstreams.md#recurse_deny_server)
[`recursion_limit`](upstreams.md#recursion_limit)
[`refused_domains`](filtering.md#refused_domains)
[`release_check`](administration.md#release_check)
[`rewrites`](filtering.md#rewrites)
[`root_hints`](upstreams.md#root_hints)
[`root_key_sentinel`](upstreams.md#root_key_sentinel)
[`rpz_files`](filtering.md#rpz_files)
[`rpz_urls`](filtering.md#rpz_urls)
[`rrset_roundrobin`](core.md#rrset_roundrobin)
[`run_as_group`](access-and-tls.md#run_as_group)
[`run_as_user`](access-and-tls.md#run_as_user)

### S

[`safe_browsing`](filtering.md#safe_browsing)
[`safe_search`](filtering.md#safe_search)
[`secondary`](authority.md#secondary)
[`serve_expired_client_timeout_ms`](core.md#serve_expired_client_timeout_ms)
[`serve_expired_reply_ttl`](core.md#serve_expired_reply_ttl)
[`serve_expired_ttl_reset`](core.md#serve_expired_ttl_reset)
[`serve_stale_refresh`](core.md#serve_stale_refresh)
[`serve_stale_secs`](core.md#serve_stale_secs)
[`service_schedule`](filtering.md#service_schedule)
[`sharded_cache`](core.md#sharded_cache)
[`split_default`](upstreams.md#split_default)
[`split_forward`](upstreams.md#split_forward)
[`split_recurse`](upstreams.md#split_recurse)
[`stats_file`](administration.md#stats_file)
[`stats_retention_secs`](administration.md#stats_retention_secs)
[`stub_zones`](upstreams.md#stub_zones)
[`subnet_rrl_burst`](access-and-tls.md#subnet_rrl_burst)
[`subnet_rrl_per_sec`](access-and-tls.md#subnet_rrl_per_sec)

### T

[`tftp_allow_overwrite`](network.md#tftp_allow_overwrite)
[`tftp_enable`](network.md#tftp_enable)
[`tftp_listen`](network.md#tftp_listen)
[`tftp_read_allow`](network.md#tftp_read_allow)
[`tftp_root`](network.md#tftp_root)
[`tftp_writable`](network.md#tftp_writable)
[`tftp_write_allow`](network.md#tftp_write_allow)
[`tls_cert`](access-and-tls.md#tls_cert)
[`tls_client_ca`](access-and-tls.md#tls_client_ca)
[`tls_key`](access-and-tls.md#tls_key)
[`tls_revocation`](access-and-tls.md#tls_revocation)
[`tls_revocation_softfail`](access-and-tls.md#tls_revocation_softfail)
[`tls_self_signed_host`](access-and-tls.md#tls_self_signed_host)
[`track_rule_hits`](filtering.md#track_rule_hits)
[`trust_anchor_signaling`](upstreams.md#trust_anchor_signaling)
[`tsig_keys`](authority.md#tsig_keys)

### U

[`update_allow`](authority.md#update_allow)
[`update_policy`](authority.md#update_policy)
[`update_tsig_required`](authority.md#update_tsig_required)
[`upstream_concurrency`](upstreams.md#upstream_concurrency)
[`upstream_proxy`](upstreams.md#upstream_proxy)
[`upstream_proxy_password`](upstreams.md#upstream_proxy_password)
[`upstream_proxy_username`](upstreams.md#upstream_proxy_username)
[`upstream_strategy`](upstreams.md#upstream_strategy)
[`upstream_urls`](upstreams.md#upstream_urls)
[`upstreams`](upstreams.md#upstreams)
[`use_caps_for_id`](upstreams.md#use_caps_for_id)
[`users`](administration.md#users)

### V

[`val_nsec3_max_iterations`](upstreams.md#val_nsec3_max_iterations)
[`val_permissive_mode`](upstreams.md#val_permissive_mode)
[`version`](access-and-tls.md#version)
[`views`](upstreams.md#views)

### W

[`wasm_fail_mode`](filtering.md#wasm_fail_mode)
[`wasm_plugins`](filtering.md#wasm_plugins)
[`wasm_policy`](filtering.md#wasm_policy)
[`workers`](core.md#workers)

### X

[`xfr_allow`](authority.md#xfr_allow)
[`xfr_tsig_required`](authority.md#xfr_tsig_required)

### Z

[`zonemd_check`](authority.md#zonemd_check)
[`zonemd_reject_absence`](authority.md#zonemd_reject_absence)
[`zones`](authority.md#zones)
[`zones_db`](authority.md#zones_db)
[`zones_db_table`](authority.md#zones_db_table)
[`zones_dir`](authority.md#zones_dir)
[`zones_etcd`](authority.md#zones_etcd)
[`zones_etcd_ca`](authority.md#zones_etcd_ca)
[`zones_etcd_password`](authority.md#zones_etcd_password)
[`zones_etcd_prefix`](authority.md#zones_etcd_prefix)
[`zones_etcd_user`](authority.md#zones_etcd_user)
[`zones_lmdb`](authority.md#zones_lmdb)
[`zones_mysql`](authority.md#zones_mysql)
[`zones_postgres`](authority.md#zones_postgres)
[`zones_sql_table`](authority.md#zones_sql_table)

## Interpretation notes

- **Default** is the `Config::default()` value. Listener availability also depends on the host and configured transport.
- `not set` and `[]` are different. For a few options, an unpopulated value triggers a default computed later in startup.
- Numeric zero can be a sentinel. The description of each key is authoritative; do not apply one meaning globally.
- Structured tables have nested fields not counted among the 263 top-level options; consult [Structured tables](structures.md).
- Validation checks accepted syntax; a successful check is not proof that the specified network port, certificate or upstream is reachable.
