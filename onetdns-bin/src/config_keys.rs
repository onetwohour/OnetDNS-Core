//! One row per config key: what a change swaps in, whether the cluster shares the value, and
//! which fast paths it closes. The `key!` macro takes all three, so a new key without them does
//! not compile, and it builds the field comparison that tells which keys changed. Keeping these
//! in separate lists would let a new key go missing from one without any failure.

use crate::native_config::LaneFacts;
use onetdns_config::{BackendKind, Config, EcsMode};
use onetdns_core::IpNet;

/// Parts swapped without a new generation. Sorted by name; changed groups are handled in sorted
/// order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApplyGroup {
    Acl,
    /// Nothing to swap: ACME issuance runs only when asked through the control API and reads the
    /// running config then.
    Acme,
    Authority,
    BlockTtl,
    /// Rebuilds the resolver chain into its slot; sockets and threads stay.
    Chain,
    /// Reopens only the cluster listener and the consensus runtime.
    Cluster,
    ConsoleAccounts,
    ControlTokens,
    /// Clock policy for DNSSEC validation.
    DnssecClock,
    /// Restarts only DHCP, DHCPv6, router advertisements and TFTP; they use their own sockets, so
    /// name resolution continues.
    EdgeServices,
    Filter,
    Forward,
    /// Opens every new address before closing removed ones.
    Listeners,
    LocalTtl,
    Log,
    MacVendor,
    /// Only what is shown on screen changes.
    Metadata,
    /// The response feature set read per query.
    Native,
    Persistence,
    Policy,
    QueryLog,
    /// Source address for upstream queries.
    QuerySource,
    RateLimit,
    /// Nothing to swap: the periodic check reads the running config each time.
    ReleaseCheck,
    Revocation,
    SafeSearch,
    Subscriptions,
    /// Swaps only the certificate slot: open connections keep the old certificate, new ones get
    /// the new one.
    Tls,
    Views,
}

impl ApplyGroup {
    /// Restarting edge services creates a new DHCP lease pool, and the chain's DHCP DNS layer holds
    /// the pool it was built with.
    pub(crate) fn also_rebuilds(self) -> Option<ApplyGroup> {
        match self {
            ApplyGroup::EdgeServices => Some(ApplyGroup::Chain),
            _ => None,
        }
    }
}

/// Whether the change from the first config to the second can be applied without a new
/// generation.
pub(crate) type Swappable = fn(&Config, &Config) -> bool;

#[derive(Clone, Copy)]
pub(crate) enum Reload {
    Hot(ApplyGroup),
    /// Swaps the group when the condition holds, otherwise starts a new generation. The condition
    /// reads only other keys, so changing this key alone can be judged from the current config.
    HotWhile(ApplyGroup, Swappable),
    /// Swaps the group when the condition holds, otherwise starts a new generation. The condition
    /// reads this key's new value, so it cannot be judged before the value is known.
    HotIf(ApplyGroup, Swappable),
    /// Dropping privileges cannot be undone within a process and works only before threads start,
    /// so a new generation only checks that the value matches the current user and otherwise fails
    /// back to the last config.
    NewGeneration,
}

impl Reload {
    /// `None` when a new generation is needed.
    fn group(self) -> Option<ApplyGroup> {
        match self {
            Reload::Hot(group) | Reload::HotWhile(group, _) | Reload::HotIf(group, _) => {
                Some(group)
            }
            Reload::NewGeneration => None,
        }
    }
}

pub(crate) fn has_client_routes(cfg: &Config) -> bool {
    cfg.clients
        .iter()
        .any(|client| !client.upstreams.is_empty())
}

/// Client route forwarders and chains are built at generation start and never swapped, so a
/// change to a route's match or upstreams needs a new generation, as does the first client
/// matched by MAC: MAC lookup is enabled only at generation start.
fn clients_swappable(previous: &Config, next: &Config) -> bool {
    fn routes(cfg: &Config) -> Vec<(&[IpNet], &[String], &[String], &[String])> {
        cfg.clients
            .iter()
            .filter(|client| !client.upstreams.is_empty())
            .map(|client| {
                (
                    &client.ids[..],
                    &client.client_ids[..],
                    &client.mac[..],
                    &client.upstreams[..],
                )
            })
            .collect()
    }
    let uses_mac = |cfg: &Config| cfg.clients.iter().any(|client| !client.mac.is_empty());
    routes(previous) == routes(next) && (uses_mac(previous) || !uses_mac(next))
}

/// Client route forwarders copy the query timeout and upstream strategy at generation start and
/// are not swapped; the default forwarder, the recursive resolver, stubs and fallback upstreams
/// are rebuilt with the new values.
fn without_client_routes(previous: &Config, next: &Config) -> bool {
    !has_client_routes(previous) && !has_client_routes(next)
}

/// Whether the Raft cluster replicates the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Replicated to every node when the leader changes it.
    Shared,
    /// Kept per node. Secrets, since replicating them makes one leaked node leak all. Node-specific
    /// values such as listen addresses, node ID, certificates and DHCP, which would collide or fail
    /// to bind elsewhere. Local file paths and authority stores, which need not exist on other
    /// nodes; zones sync by zone transfer instead.
    Node,
}

/// Whether the key closes a fast path under this config; facts not in the config come in
/// `LaneFacts`.
pub(crate) type Blocks = fn(&Config, &LaneFacts) -> bool;

/// The condition under which a key closes each fast path; `None` means its value does not
/// change that path's responses. The wire path reevaluates ACL, rate limits and filters with the
/// current generation on a hit, so their keys leave it open.
#[derive(Clone, Copy)]
pub(crate) struct Lanes {
    /// UDP fast path for cache hits.
    pub(crate) wire: Option<Blocks>,
    /// Lane for recursive queries not in the cache.
    pub(crate) reactor: Option<Blocks>,
    /// Wire fast path for authoritative answers.
    pub(crate) authority: Option<Blocks>,
}

impl Lanes {
    const OPEN: Self = Self {
        wire: None,
        reactor: None,
        authority: None,
    };
}

/// The reactor lane needs the wire path open, so it closes too.
const fn wire(blocks: Blocks) -> Lanes {
    Lanes {
        wire: Some(blocks),
        ..Lanes::OPEN
    }
}

/// For resolution features the reactor lane does not implement, even when the answer depends
/// only on the request.
const fn reactor(blocks: Blocks) -> Lanes {
    Lanes {
        reactor: Some(blocks),
        ..Lanes::OPEN
    }
}

const fn wire_and_authority(blocks: Blocks) -> Lanes {
    Lanes {
        wire: Some(blocks),
        reactor: None,
        authority: Some(blocks),
    }
}

/// For features that filter addresses in resolved answers; both paths would send answers
/// unfiltered. The wire path stays open: it holds only answers the normal path filtered, and a
/// change bumps the generation so old entries are not served.
const fn reactor_and_authority(blocks: Blocks) -> Lanes {
    Lanes {
        wire: None,
        reactor: Some(blocks),
        authority: Some(blocks),
    }
}

pub(crate) struct KeySpec {
    pub(crate) key: &'static str,
    pub(crate) reload: Reload,
    pub(crate) scope: Scope,
    pub(crate) lanes: Lanes,
    changed: fn(&Config, &Config) -> bool,
}

/// Takes the key name as a `Config` field and builds the comparison of that field.
macro_rules! key {
    ($field:ident, $reload:expr, $scope:expr, $lanes:expr $(,)?) => {
        KeySpec {
            key: stringify!($field),
            reload: $reload,
            scope: $scope,
            lanes: $lanes,
            changed: |previous: &Config, next: &Config| previous.$field != next.$field,
        }
    };
}

/// `None` for an unknown key.
pub(crate) fn spec(name: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|spec| spec.key == name)
}

/// `None` when a new generation is needed or the key is unknown.
pub(crate) fn hot_group(name: &str) -> Option<ApplyGroup> {
    spec(name)?.reload.group()
}

pub(crate) fn is_hot(name: &str) -> bool {
    hot_group(name).is_some()
}

/// In table order.
pub(crate) fn hot_keys() -> impl Iterator<Item = &'static str> {
    KEYS.iter()
        .filter(|spec| spec.reload.group().is_some())
        .map(|spec| spec.key)
}

/// In table order.
pub(crate) fn changed_keys<'a>(
    previous: &'a Config,
    next: &'a Config,
) -> impl Iterator<Item = &'static str> + 'a {
    KEYS.iter()
        .filter(move |spec| (spec.changed)(previous, next))
        .map(|spec| spec.key)
}

/// False for an unknown key. Ignores whether other changed keys rebuild the chain.
pub(crate) fn swappable(name: &str, previous: &Config, next: &Config) -> bool {
    spec(name).is_some_and(|spec| match spec.reload {
        Reload::Hot(_) => true,
        Reload::HotWhile(_, swappable) | Reload::HotIf(_, swappable) => swappable(previous, next),
        Reload::NewGeneration => false,
    })
}

/// Whether changing only this key could need a new generation under the current config.
/// `HotWhile` conditions do not read the key, so judging with the current config on both sides
/// matches changing it alone; `HotIf` conditions read the new value, so this is always true.
pub(crate) fn may_need_new_generation(name: &str, now: &Config) -> bool {
    spec(name).is_some_and(|spec| match spec.reload {
        Reload::Hot(_) => false,
        Reload::HotWhile(_, swappable) => !swappable(now, now),
        Reload::HotIf(..) | Reload::NewGeneration => true,
    })
}

/// Keys come from control API input, so lookup is lowercased; a key differing only in case must
/// not pass as shared config. Unknown keys count as shared and are rejected when the config is
/// parsed.
pub(crate) fn node_local(name: &str) -> bool {
    spec(&name.to_ascii_lowercase()).is_some_and(|spec| spec.scope == Scope::Node)
}

#[derive(Clone, Copy)]
pub(crate) enum Lane {
    /// UDP fast path for cache hits.
    Wire,
    Reactor,
    /// Wire fast path for authoritative answers.
    Authority,
}

impl Lanes {
    fn get(&self, lane: Lane) -> Option<Blocks> {
        match lane {
            Lane::Wire => self.wire,
            Lane::Reactor => self.reactor,
            Lane::Authority => self.authority,
        }
    }
}

pub(crate) fn lane_unblocked(lane: Lane, cfg: &Config, facts: &LaneFacts) -> bool {
    KEYS.iter()
        .filter_map(|spec| spec.lanes.get(lane))
        .all(|blocks| !blocks(cfg, facts))
}

use ApplyGroup::*;
use Reload::{Hot, HotIf, HotWhile, NewGeneration};
use Scope::{Node, Shared};

/// In `onetdns_config::known_keys` order.
static KEYS: &[KeySpec] = &[
    key!(mode, Hot(Metadata), Shared, Lanes::OPEN),
    key!(
        backend,
        Hot(Chain),
        Shared,
        reactor(|c, _| !matches!(c.backend, BackendKind::Recurse)),
    ),
    key!(listen, Hot(Listeners), Node, Lanes::OPEN),
    key!(upstreams, Hot(Forward), Shared, Lanes::OPEN),
    key!(blocklists, Hot(Filter), Node, Lanes::OPEN),
    key!(allowlists, Hot(Filter), Node, Lanes::OPEN),
    key!(blocklist_urls, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(blocklist_titles, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(
        disabled_blocklist_urls,
        Hot(Subscriptions),
        Shared,
        Lanes::OPEN,
    ),
    key!(block_rules, Hot(Filter), Shared, Lanes::OPEN),
    key!(allow_rules, Hot(Filter), Shared, Lanes::OPEN),
    key!(list_refresh_secs, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(blocked_services, Hot(Filter), Shared, Lanes::OPEN),
    key!(safe_search, Hot(SafeSearch), Shared, Lanes::OPEN),
    key!(
        clients,
        HotIf(Filter, clients_swappable),
        Shared,
        wire(|c, _| has_client_routes(c)),
    ),
    key!(users, Hot(ConsoleAccounts), Node, Lanes::OPEN),
    key!(
        views,
        Hot(Views),
        Shared,
        wire_and_authority(|_, f| f.views_present),
    ),
    key!(
        policy,
        Hot(Policy),
        Shared,
        wire_and_authority(|_, f| f.policy_present),
    ),
    key!(
        wasm_policy,
        Hot(Policy),
        Node,
        wire_and_authority(|_, f| f.policy_present),
    ),
    key!(
        wasm_plugins,
        Hot(Policy),
        Node,
        wire_and_authority(|_, f| f.policy_present),
    ),
    key!(wasm_fail_mode, Hot(Policy), Shared, Lanes::OPEN),
    key!(block_response, Hot(Filter), Shared, Lanes::OPEN),
    key!(
        cache_size,
        Hot(Chain),
        Shared,
        wire(|c, _| c.cache_size == 0),
    ),
    key!(min_ttl, Hot(Chain), Shared, wire(|c, _| c.min_ttl != 0)),
    key!(max_ttl, Hot(Chain), Shared, Lanes::OPEN),
    key!(
        query_timeout_secs,
        HotWhile(Forward, without_client_routes),
        Shared,
        Lanes::OPEN,
    ),
    key!(max_inflight, Hot(Native), Shared, Lanes::OPEN),
    key!(workers, Hot(Listeners), Node, Lanes::OPEN),
    key!(do_udp, Hot(Listeners), Shared, Lanes::OPEN),
    key!(do_tcp, Hot(Listeners), Shared, Lanes::OPEN),
    key!(
        serve_stale_secs,
        Hot(Chain),
        Shared,
        reactor(|c, _| c.serve_stale_secs != 0),
    ),
    key!(serve_expired_reply_ttl, Hot(Chain), Shared, Lanes::OPEN),
    key!(serve_expired_ttl_reset, Hot(Chain), Shared, Lanes::OPEN),
    key!(
        serve_expired_client_timeout_ms,
        Hot(Chain),
        Shared,
        Lanes::OPEN,
    ),
    key!(serve_stale_refresh, Hot(Chain), Shared, Lanes::OPEN),
    key!(proxy_protocol_ports, Hot(Listeners), Node, Lanes::OPEN),
    key!(proxy_protocol_trusted, Hot(Listeners), Shared, Lanes::OPEN,),
    key!(
        dns64_prefix,
        Hot(Native),
        Shared,
        wire_and_authority(|c, _| c.dns64_prefix.is_some()),
    ),
    key!(
        rebind_protection,
        Hot(Native),
        Shared,
        reactor_and_authority(|c, _| c.rebind_protection),
    ),
    key!(prefetch, Hot(Chain), Shared, wire(|c, _| c.prefetch)),
    key!(prefetch_min_hits, Hot(Chain), Shared, Lanes::OPEN),
    key!(prefetch_ttl_pct, Hot(Chain), Shared, Lanes::OPEN),
    key!(dnssec, Hot(Chain), Shared, Lanes::OPEN),
    key!(dnssec_strict, Hot(Chain), Shared, Lanes::OPEN),
    key!(val_permissive_mode, Hot(Chain), Shared, Lanes::OPEN),
    key!(dnssec_accept_expired, Hot(DnssecClock), Shared, Lanes::OPEN,),
    key!(ignore_cd_flag, Hot(Chain), Shared, Lanes::OPEN),
    key!(dnssec_rfc5011, Hot(Chain), Shared, Lanes::OPEN),
    key!(dnssec_anchor_file, Hot(Chain), Node, Lanes::OPEN),
    key!(
        dnssec_roll_interval_secs,
        Hot(Authority),
        Shared,
        Lanes::OPEN,
    ),
    key!(root_key_sentinel, Hot(Chain), Shared, Lanes::OPEN),
    key!(trust_anchor_signaling, Hot(Chain), Shared, Lanes::OPEN),
    key!(recursion_limit, Hot(Chain), Shared, Lanes::OPEN),
    key!(cname_limit, Hot(Chain), Shared, Lanes::OPEN),
    key!(dname_limit, Hot(Chain), Shared, Lanes::OPEN),
    key!(do_ip4, Hot(Chain), Shared, Lanes::OPEN),
    key!(do_ip6, Hot(Chain), Shared, Lanes::OPEN),
    key!(prefer_ip4, Hot(Chain), Shared, Lanes::OPEN),
    key!(prefer_ip6, Hot(Chain), Shared, Lanes::OPEN),
    key!(qname_minimisation_strict, Hot(Chain), Shared, Lanes::OPEN),
    key!(harden_referral_path, Hot(Chain), Shared, Lanes::OPEN),
    key!(use_caps_for_id, Hot(Chain), Shared, Lanes::OPEN),
    key!(lowercase_outgoing, Hot(Chain), Shared, Lanes::OPEN),
    key!(harden_large_queries, Hot(Native), Shared, Lanes::OPEN),
    key!(domain_insecure, Hot(Chain), Shared, Lanes::OPEN),
    key!(split_default, Hot(Chain), Shared, Lanes::OPEN),
    key!(split_recurse, Hot(Chain), Shared, Lanes::OPEN),
    key!(split_forward, Hot(Chain), Shared, Lanes::OPEN),
    key!(local_a, Hot(Chain), Shared, Lanes::OPEN),
    key!(local_aaaa, Hot(Chain), Shared, Lanes::OPEN),
    key!(acl_allow, Hot(Acl), Shared, Lanes::OPEN),
    key!(acl_deny, Hot(Acl), Shared, Lanes::OPEN),
    key!(acl_drop, Hot(Acl), Shared, Lanes::OPEN),
    key!(acl_unlisted, Hot(Acl), Shared, Lanes::OPEN),
    key!(rate_limit_per_sec, Hot(RateLimit), Shared, Lanes::OPEN),
    key!(rate_limit_burst, Hot(RateLimit), Shared, Lanes::OPEN),
    key!(run_as_user, NewGeneration, Node, Lanes::OPEN),
    key!(run_as_group, NewGeneration, Node, Lanes::OPEN),
    key!(
        cookies,
        Hot(Native),
        Shared,
        wire_and_authority(|c, _| c.cookies.is_strict()),
    ),
    key!(subnet_rrl_per_sec, Hot(RateLimit), Shared, Lanes::OPEN),
    key!(subnet_rrl_burst, Hot(RateLimit), Shared, Lanes::OPEN),
    key!(listen_dot, Hot(Listeners), Node, Lanes::OPEN),
    key!(listen_doh, Hot(Listeners), Node, Lanes::OPEN),
    key!(listen_doq, Hot(Listeners), Node, Lanes::OPEN),
    key!(listen_doh3, Hot(Listeners), Node, Lanes::OPEN),
    key!(listen_dnscrypt, Hot(Listeners), Node, Lanes::OPEN),
    key!(dnscrypt_provider_name, Hot(Listeners), Node, Lanes::OPEN),
    key!(doh_path, Hot(Listeners), Node, Lanes::OPEN),
    key!(ddr_name, Hot(Chain), Node, Lanes::OPEN),
    key!(tls_cert, Hot(Tls), Node, Lanes::OPEN),
    key!(tls_key, Hot(Tls), Node, Lanes::OPEN),
    key!(tls_self_signed_host, Hot(Tls), Node, Lanes::OPEN),
    key!(tls_client_ca, Hot(Tls), Node, Lanes::OPEN),
    key!(tls_revocation, Hot(Revocation), Node, Lanes::OPEN),
    key!(tls_revocation_softfail, Hot(Revocation), Node, Lanes::OPEN,),
    key!(
        acme_directory_url,
        Hot(Chain),
        Node,
        wire(|c, _| c.acme_directory_url.is_some()),
    ),
    key!(acme_contact_email, Hot(Acme), Node, Lanes::OPEN),
    key!(acme_domains, Hot(Acme), Node, Lanes::OPEN),
    key!(acme_challenge, Hot(Acme), Node, Lanes::OPEN),
    key!(acme_account_key_file, Hot(Acme), Node, Lanes::OPEN),
    key!(acme_cert_file, Hot(Acme), Node, Lanes::OPEN),
    key!(acme_key_file, Hot(Acme), Node, Lanes::OPEN),
    key!(control_listen, Hot(ControlTokens), Node, Lanes::OPEN),
    key!(control_token, Hot(ControlTokens), Node, Lanes::OPEN),
    key!(control_admin_tokens, Hot(ControlTokens), Node, Lanes::OPEN,),
    key!(
        control_readonly_tokens,
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key!(
        control_trusted_proxies,
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key!(
        control_public_origins,
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key!(block_ipv4, Hot(Filter), Shared, Lanes::OPEN),
    key!(block_ipv6, Hot(Filter), Shared, Lanes::OPEN),
    key!(blocked_response_ttl, Hot(BlockTtl), Shared, Lanes::OPEN),
    key!(
        block_aaaa,
        Hot(Native),
        Shared,
        wire_and_authority(|c, _| c.block_aaaa),
    ),
    key!(
        bogus_nxdomain,
        Hot(Native),
        Shared,
        reactor_and_authority(|c, _| !c.bogus_nxdomain.is_empty()),
    ),
    key!(
        domain_needed,
        Hot(Native),
        Shared,
        wire(|c, _| c.domain_needed),
    ),
    key!(bogus_priv, Hot(Native), Shared, wire(|c, _| c.bogus_priv)),
    key!(empty_zones, Hot(Native), Shared, wire(|c, _| c.empty_zones)),
    key!(local_ttl, Hot(LocalTtl), Shared, Lanes::OPEN),
    key!(rewrites, Hot(Filter), Shared, Lanes::OPEN),
    key!(
        dynamic_records,
        Hot(Chain),
        Shared,
        wire_and_authority(|c, _| !c.dynamic_records.is_empty()),
    ),
    key!(local_zones, Hot(Filter), Shared, Lanes::OPEN),
    key!(refused_domains, Hot(Filter), Shared, Lanes::OPEN),
    key!(rpz_files, Hot(Filter), Node, Lanes::OPEN),
    key!(rpz_urls, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(safe_browsing, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(parental_control, Hot(Subscriptions), Shared, Lanes::OPEN),
    key!(service_schedule, Hot(Filter), Shared, Lanes::OPEN),
    key!(upstream_urls, Hot(Forward), Shared, Lanes::OPEN),
    key!(bootstrap, Hot(Chain), Shared, Lanes::OPEN),
    key!(root_hints, Hot(Chain), Shared, Lanes::OPEN),
    key!(fallback_upstreams, Hot(Chain), Shared, Lanes::OPEN),
    key!(
        upstream_strategy,
        HotWhile(Forward, without_client_routes),
        Shared,
        Lanes::OPEN,
    ),
    key!(
        upstream_concurrency,
        HotWhile(Forward, without_client_routes),
        Shared,
        Lanes::OPEN,
    ),
    key!(query_source, Hot(QuerySource), Node, Lanes::OPEN),
    key!(query_source_v6, Hot(QuerySource), Node, Lanes::OPEN),
    key!(
        stub_zones,
        Hot(Chain),
        Shared,
        reactor(|c, _| !c.stub_zones.is_empty()),
    ),
    key!(
        zones,
        Hot(Authority),
        Node,
        wire(|c, _| !c.zones.is_empty()),
    ),
    key!(
        zones_dir,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_dir.is_some()),
    ),
    key!(
        zones_db,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_db.is_some()),
    ),
    key!(zones_db_table, Hot(Authority), Node, Lanes::OPEN),
    key!(
        zones_postgres,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_postgres.is_some()),
    ),
    key!(
        zones_mysql,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_mysql.is_some()),
    ),
    key!(
        zones_lmdb,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_lmdb.is_some()),
    ),
    key!(zones_sql_table, Hot(Authority), Node, Lanes::OPEN),
    key!(
        zones_etcd,
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_etcd.is_some()),
    ),
    key!(zones_etcd_prefix, Hot(Authority), Node, Lanes::OPEN),
    key!(zones_etcd_ca, Hot(Authority), Node, Lanes::OPEN),
    key!(zones_etcd_user, Hot(Authority), Node, Lanes::OPEN),
    key!(zones_etcd_password, Hot(Authority), Node, Lanes::OPEN),
    key!(
        secondary,
        Hot(Authority),
        Node,
        wire(|c, _| !c.secondary.is_empty()),
    ),
    key!(
        catalog,
        Hot(Authority),
        Node,
        wire(|c, _| !c.catalog.is_empty()),
    ),
    key!(catalog_serve, Hot(Authority), Node, Lanes::OPEN),
    key!(xfr_allow, Hot(Authority), Node, Lanes::OPEN),
    key!(notify, Hot(Authority), Node, Lanes::OPEN),
    key!(tsig_keys, Hot(Authority), Node, Lanes::OPEN),
    key!(xfr_tsig_required, Hot(Authority), Node, Lanes::OPEN),
    key!(zonemd_check, Hot(Authority), Node, Lanes::OPEN),
    key!(zonemd_reject_absence, Hot(Authority), Node, Lanes::OPEN),
    key!(update_allow, Hot(Authority), Node, Lanes::OPEN),
    key!(update_policy, Hot(Authority), Node, Lanes::OPEN),
    key!(update_tsig_required, Hot(Authority), Node, Lanes::OPEN),
    key!(
        ecs_mode,
        Hot(Chain),
        Shared,
        wire(|c, _| !matches!(c.ecs_mode, EcsMode::Off)),
    ),
    key!(ecs_custom_ip, Hot(Chain), Shared, Lanes::OPEN),
    key!(neg_min_ttl, Hot(Chain), Shared, Lanes::OPEN),
    key!(neg_max_ttl, Hot(Chain), Shared, Lanes::OPEN),
    key!(edns_buffer_size, Hot(Native), Shared, Lanes::OPEN),
    key!(deny_any, Hot(Native), Shared, Lanes::OPEN),
    key!(minimal_responses, Hot(Native), Shared, Lanes::OPEN),
    key!(
        edns_padding_block,
        Hot(Native),
        Shared,
        wire(|c, _| c.edns_padding_block != 0),
    ),
    key!(edns_tcp_keepalive_secs, Hot(Native), Shared, Lanes::OPEN),
    key!(
        cache_enabled,
        Hot(Chain),
        Shared,
        wire(|c, _| !c.cache_enabled),
    ),
    key!(sharded_cache, Hot(Chain), Shared, Lanes::OPEN),
    key!(cache_shards, Hot(Chain), Shared, Lanes::OPEN),
    key!(prefetch_interval_secs, Hot(Chain), Shared, Lanes::OPEN),
    key!(dns64_synthall, Hot(Native), Shared, Lanes::OPEN),
    key!(
        rrset_roundrobin,
        Hot(Native),
        Shared,
        wire_and_authority(|c, _| c.rrset_roundrobin),
    ),
    key!(track_rule_hits, Hot(Filter), Shared, Lanes::OPEN),
    key!(
        aggressive_nsec,
        Hot(Chain),
        Shared,
        reactor(|c, _| c.aggressive_nsec),
    ),
    key!(
        name_ratelimit_per_sec,
        Hot(Chain),
        Shared,
        Lanes {
            wire: Some(|c, _| c.name_ratelimit_per_sec != 0),
            reactor: Some(|c, _| c.name_ratelimit_per_sec != 0),
            authority: None,
        },
    ),
    key!(name_ratelimit_labels, Hot(Chain), Shared, Lanes::OPEN),
    key!(
        harden_below_nxdomain,
        Hot(Chain),
        Shared,
        reactor(|c, _| c.harden_below_nxdomain),
    ),
    key!(dhcp_enable, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_server_ip, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_range_start, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_range_end, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_subnet_mask, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_router, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_dns, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_lease_secs, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(
        dhcp_local_domain,
        Hot(EdgeServices),
        Node,
        wire(|c, f| f.dhcp_pool && !c.dhcp_local_domain.is_empty()),
    ),
    key!(dhcp_tftp_server, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_boot_file, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_enable, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_root, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_listen, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_read_allow, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_writable, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_write_allow, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(tftp_allow_overwrite, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_enable, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_prefix, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_managed, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_other, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_router_lifetime, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_interval, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_mtu, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(ra_interface_index, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_enable, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_range_start, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_range_end, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_dns, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_interface_index, Hot(EdgeServices), Node, Lanes::OPEN,),
    key!(dhcp_lease_file, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp_static_file, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(dhcp6_lease_file, Hot(EdgeServices), Node, Lanes::OPEN),
    key!(mac_vendor_db, Hot(MacVendor), Node, Lanes::OPEN),
    key!(
        ipset_name_v4,
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key!(
        ipset_name_v6,
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key!(
        ipset_domains,
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key!(
        cachedb_redis_host,
        Hot(Chain),
        Node,
        reactor(|c, _| c.cachedb_redis_host.is_some()),
    ),
    key!(cachedb_redis_port, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_expire_secs, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_secret, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_username, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_password, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_tls, Hot(Chain), Node, Lanes::OPEN),
    key!(cachedb_redis_tls_ca, Hot(Chain), Node, Lanes::OPEN),
    key!(cluster_peers, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_raft, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_node_id, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_raft_listen, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_raft_peers, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_raft_secret, Hot(Cluster), Node, Lanes::OPEN),
    key!(cluster_raft_node_key, Hot(Cluster), Node, Lanes::OPEN),
    key!(rebind_allow, Hot(Native), Shared, Lanes::OPEN),
    key!(recurse_deny_server, Hot(Chain), Shared, Lanes::OPEN),
    key!(recurse_allow_server, Hot(Chain), Shared, Lanes::OPEN),
    key!(ns_recursion_limit, Hot(Chain), Shared, Lanes::OPEN),
    key!(ns_cache_size, Hot(Chain), Shared, Lanes::OPEN),
    key!(
        recurse_deny_answers,
        Hot(Native),
        Shared,
        reactor_and_authority(|c, _| !c.recurse_deny_answers.is_empty()),
    ),
    key!(recurse_allow_answers, Hot(Native), Shared, Lanes::OPEN),
    key!(val_nsec3_max_iterations, Hot(Chain), Shared, Lanes::OPEN),
    key!(rate_limit_allow, Hot(RateLimit), Shared, Lanes::OPEN),
    key!(acl_allow_ids, Hot(Acl), Shared, Lanes::OPEN),
    key!(acl_deny_ids, Hot(Acl), Shared, Lanes::OPEN),
    key!(hide_identity, Hot(Native), Shared, Lanes::OPEN),
    key!(hide_version, Hot(Native), Shared, Lanes::OPEN),
    key!(nsid, Hot(Native), Node, Lanes::OPEN),
    key!(identity, Hot(Native), Node, Lanes::OPEN),
    key!(version, Hot(Native), Shared, Lanes::OPEN),
    key!(log_level, Hot(Log), Node, Lanes::OPEN),
    key!(querylog, Hot(QueryLog), Shared, Lanes::OPEN),
    key!(querylog_size, Hot(QueryLog), Shared, Lanes::OPEN),
    key!(querylog_retention_secs, Hot(QueryLog), Shared, Lanes::OPEN,),
    key!(anonymize_client_ip, Hot(QueryLog), Shared, Lanes::OPEN),
    key!(querylog_ignored, Hot(QueryLog), Shared, Lanes::OPEN),
    key!(stats_retention_secs, Hot(QueryLog), Shared, Lanes::OPEN),
    key!(querylog_file, Hot(Persistence), Node, Lanes::OPEN),
    key!(stats_file, Hot(Persistence), Node, Lanes::OPEN),
    key!(persist_flush_secs, Hot(Persistence), Shared, Lanes::OPEN),
    key!(
        dnstap_file,
        Hot(Native),
        Node,
        wire_and_authority(|c, _| c.dnstap_file.is_some()),
    ),
    key!(dnstap_identity, Hot(Native), Node, Lanes::OPEN),
    key!(release_check, Hot(ReleaseCheck), Node, Lanes::OPEN),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// The control API lists keys in table order.
    fn table_covers_every_known_key_once() {
        let table: Vec<&str> = KEYS.iter().map(|spec| spec.key).collect();
        let mut unique = table.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), table.len(), "같은 키가 표에 두 번 있습니다");
        assert_eq!(
            table,
            onetdns_config::known_keys(),
            "표와 설정 키 목록이 다릅니다"
        );
    }

    fn blockers(lane: Lane) -> Vec<&'static str> {
        KEYS.iter()
            .filter(|spec| spec.lanes.get(lane).is_some())
            .map(|spec| spec.key)
            .collect()
    }

    #[test]
    /// A key whose condition goes missing answers as if its feature did not exist; dropping one
    /// needs proof that its value leaves responses determined by the request alone.
    fn lane_blockers_are_pinned() {
        assert_eq!(
            blockers(Lane::Wire),
            [
                "clients",
                "views",
                "policy",
                "wasm_policy",
                "wasm_plugins",
                "cache_size",
                "min_ttl",
                "dns64_prefix",
                "prefetch",
                "cookies",
                "acme_directory_url",
                "block_aaaa",
                "domain_needed",
                "bogus_priv",
                "empty_zones",
                "dynamic_records",
                "zones",
                "zones_dir",
                "zones_db",
                "zones_postgres",
                "zones_mysql",
                "zones_lmdb",
                "zones_etcd",
                "secondary",
                "catalog",
                "ecs_mode",
                "edns_padding_block",
                "cache_enabled",
                "rrset_roundrobin",
                "name_ratelimit_per_sec",
                "dhcp_local_domain",
                "ipset_name_v4",
                "ipset_name_v6",
                "ipset_domains",
                "dnstap_file",
            ]
        );
        assert_eq!(
            blockers(Lane::Reactor),
            [
                "backend",
                "serve_stale_secs",
                "rebind_protection",
                "bogus_nxdomain",
                "stub_zones",
                "aggressive_nsec",
                "name_ratelimit_per_sec",
                "harden_below_nxdomain",
                "cachedb_redis_host",
                "recurse_deny_answers",
            ]
        );
        assert_eq!(
            blockers(Lane::Authority),
            [
                "views",
                "policy",
                "wasm_policy",
                "wasm_plugins",
                "dns64_prefix",
                "rebind_protection",
                "cookies",
                "block_aaaa",
                "bogus_nxdomain",
                "dynamic_records",
                "rrset_roundrobin",
                "recurse_deny_answers",
                "dnstap_file",
            ]
        );
    }

    #[test]
    fn only_privilege_drop_needs_a_new_generation() {
        let cold: Vec<&str> = KEYS
            .iter()
            .filter(|spec| matches!(spec.reload, Reload::NewGeneration))
            .map(|spec| spec.key)
            .collect();
        assert_eq!(cold, ["run_as_user", "run_as_group"]);
    }
}
