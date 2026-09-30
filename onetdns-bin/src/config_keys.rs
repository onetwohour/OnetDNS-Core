/*!
 * @brief 설정 키마다 실행 중 서버가 그 값을 다루는 방식을 정한 표.
 *
 * @details 키 하나에 세 가지를 정한다. 값을 바꿨을 때 무엇을 교체하는지, 클러스터가 그
 *          값을 공유하는지, 그리고 어느 빠른 경로를 닫는지다. 행을 만드는 함수가 셋을 모두
 *          인자로 받으므로 키를 추가하면서 하나라도 정하지 않으면 컴파일되지 않는다.
 *
 *          이 판단이 여러 목록에 흩어져 있으면 새 키를 어느 목록에 빠뜨려도 아무것도
 *          실패하지 않는다. 빠른 경로 조건에서 빠지면 캐시가 그 기능을 거치지 않은 답을
 *          내고, 노드별 목록에서 빠지면 한 노드의 값이 클러스터 전체를 덮어쓴다.
 * @invariant 표의 키 집합은 onetdns_config::known_keys 와 정확히 같다. 테스트가 강제한다.
 */

use crate::native_config::LaneFacts;
use onetdns_config::{BackendKind, Config, EcsMode};

/**
 * @brief 값이 바뀌었을 때 세대를 새로 만들지 않고 교체하는 부분.
 * @details 순서는 이름의 알파벳 순이다. 바뀐 그룹 목록을 정렬해서 다루므로 순서를 바꾸면
 *          그 목록의 순서도 바뀐다.
 */
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApplyGroup {
    /** @brief 접근 제어 목록을 교체한다. */
    Acl,
    /**
     * @brief 교체할 것이 없다.
     * @details ACME 발급은 관리 API 로 시킬 때만 돌고, 그때 실행 중 설정을 읽는다.
     */
    Acme,
    /** @brief 권한 영역 저장소를 다시 만들고 원본 감시 작업을 설정에 맞춘다. */
    Authority,
    /** @brief 차단 응답의 TTL 을 바꾼다. */
    BlockTtl,
    /** @brief 해석 체인을 새로 만들어 슬롯에 교체한다. 소켓과 스레드는 그대로 둔다. */
    Chain,
    /** @brief 클러스터 수신 주소와 합의 런타임만 다시 연다. */
    Cluster,
    /** @brief 관리 화면 계정을 교체한다. */
    ConsoleAccounts,
    /** @brief 관리 토큰을 교체한다. */
    ControlTokens,
    /** @brief DNSSEC 검증에 쓰는 시계 정책을 바꾼다. */
    DnssecClock,
    /**
     * @brief DHCP, DHCPv6, 라우터 광고, TFTP 서비스만 재시작한다.
     * @details 이 서비스들은 DNS 와 다른 소켓을 쓰므로 이름 해석은 끊기지 않는다.
     */
    EdgeServices,
    /** @brief 차단 엔진을 교체한다. */
    Filter,
    /** @brief 전달 경로를 교체한다. */
    Forward,
    /**
     * @brief 수신 주소를 열고 닫는다.
     * @details 새 주소를 모두 연 뒤에 빠진 주소를 닫는다.
     */
    Listeners,
    /** @brief 로컬 응답의 TTL 을 바꾼다. */
    LocalTtl,
    /** @brief 로그 수준을 바꾼다. */
    Log,
    /** @brief MAC 제조사 데이터베이스를 다시 읽는다. */
    MacVendor,
    /** @brief 화면에 보이는 정보만 바뀐다. */
    Metadata,
    /** @brief 질의마다 읽는 응답 기능 세트를 교체한다. */
    Native,
    /** @brief 질의 로그와 통계를 저장하는 파일을 바꾼다. */
    Persistence,
    /** @brief 정책 엔진을 교체한다. */
    Policy,
    /** @brief 질의 로그 설정을 바꾼다. */
    QueryLog,
    /** @brief 업스트림으로 나가는 출발 주소를 바꾼다. */
    QuerySource,
    /** @brief 속도 제한기를 교체한다. */
    RateLimit,
    /** @brief 업스트림 TLS 인증서 폐기 확인 정책을 다시 설치한다. */
    Revocation,
    /** @brief 안전 검색 설정을 바꾼다. */
    SafeSearch,
    /** @brief 차단 목록 구독을 다시 받는다. */
    Subscriptions,
    /**
     * @brief 수신 소켓은 그대로 두고 인증서 슬롯만 교체한다.
     * @details 이미 맺힌 연결은 이전 인증서로 이어지고 다음 연결부터 새 인증서를 쓴다.
     */
    Tls,
    /** @brief 클라이언트별 뷰를 교체한다. */
    Views,
}

/** @brief 값이 바뀌었을 때 실행 중 서버가 반영하는 방법. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reload {
    /** @brief 이 그룹만 교체한다. */
    Hot(ApplyGroup),
    /**
     * @brief 세대를 새로 만든다.
     * @details 권한을 낮추는 동작은 한 프로세스 안에서 되돌릴 수 없다.
     */
    NewGeneration,
}

/** @brief Raft 클러스터에서 이 값을 복제하는지. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /** @brief 클러스터가 공유한다. 리더가 바꾸면 모든 노드에 복제된다. */
    Shared,
    /**
     * @brief 노드마다 따로 둔다.
     * @details 세 종류다. 비밀 값은 복제하면 한 노드가 유출될 때 전부 유출된다. 수신 주소,
     *          노드 ID, 인증서, DHCP 같은 노드 고유 값은 복제하면 ID 가 겹치거나 없는 주소에
     *          바인딩하려다 서비스가 뜨지 않는다. 로컬 파일 경로와 권한 영역 저장소는 같은
     *          경로가 다른 노드에 있다는 보장이 없고, 권한 영역은 영역 전송으로 따로
     *          동기화한다.
     */
    Node,
}

/**
 * @brief 지금 설정에서 이 키가 빠른 경로를 닫는지.
 * @details 설정만으로 알 수 없는 사실은 facts 로 받는다.
 */
pub(crate) type Blocks = fn(&Config, &LaneFacts) -> bool;

/**
 * @brief 키 하나가 세 빠른 경로 각각을 닫는 조건.
 * @details 조건이 없다는 것은 그 키의 값이 해당 경로가 내는 응답을 바꾸지 않는다는 뜻이다.
 *          wire 경로는 적중할 때 ACL, 속도 제한, 필터를 현재 세대로 다시 평가하므로 그 셋에
 *          속한 키는 wire 경로를 닫지 않는다.
 */
#[derive(Clone, Copy)]
pub(crate) struct Lanes {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    pub(crate) wire: Option<Blocks>,
    /** @brief 캐시에 없는 재귀 질의를 처리하는 reactor 레인. */
    pub(crate) reactor: Option<Blocks>,
    /** @brief 권한 응답 wire 빠른 경로. */
    pub(crate) authority: Option<Blocks>,
}

impl Lanes {
    /** @brief 어느 빠른 경로도 닫지 않는다. */
    const OPEN: Self = Self {
        wire: None,
        reactor: None,
        authority: None,
    };
}

/** @brief wire 경로만 닫는다. reactor 레인은 wire 경로가 열려 있어야 켜지므로 함께 닫힌다. */
const fn wire(blocks: Blocks) -> Lanes {
    Lanes {
        wire: Some(blocks),
        ..Lanes::OPEN
    }
}

/**
 * @brief reactor 레인만 닫는다.
 * @details 응답은 요청 내용만으로 정해지지만 reactor 레인이 구현하지 않은 해석 기능이다.
 */
const fn reactor(blocks: Blocks) -> Lanes {
    Lanes {
        reactor: Some(blocks),
        ..Lanes::OPEN
    }
}

/** @brief 설정 키 하나에 대한 결정. */
pub(crate) struct KeySpec {
    /** @brief 설정 키 이름. */
    pub(crate) key: &'static str,
    /** @brief 값이 바뀌었을 때 반영하는 방법. */
    pub(crate) reload: Reload,
    /** @brief 클러스터 공유 여부. */
    pub(crate) scope: Scope,
    /** @brief 빠른 경로를 닫는 조건. */
    pub(crate) lanes: Lanes,
}

/** @brief 행 하나를 만든다. */
const fn key(key: &'static str, reload: Reload, scope: Scope, lanes: Lanes) -> KeySpec {
    KeySpec {
        key,
        reload,
        scope,
        lanes,
    }
}

/** @brief 키에 대한 결정. 알 수 없는 키면 없다. */
pub(crate) fn spec(name: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|spec| spec.key == name)
}

/** @brief 이 키를 바꿨을 때 교체하는 그룹. 세대를 새로 만들어야 하거나 알 수 없는 키면 없다. */
pub(crate) fn hot_group(name: &str) -> Option<ApplyGroup> {
    match spec(name)?.reload {
        Reload::Hot(group) => Some(group),
        Reload::NewGeneration => None,
    }
}

/** @brief 세대를 새로 만들지 않고 바꿀 수 있는 키인지. */
pub(crate) fn is_hot(name: &str) -> bool {
    hot_group(name).is_some()
}

/**
 * @brief 노드마다 따로 두고 클러스터가 복제하지 않는 키인지.
 * @details 복제 요청의 키는 관리 API 입력이다. 대소문자만 바꾼 키가 이 검사를 지나 공유
 *          설정으로 제안되지 않도록 소문자로 맞춰 찾는다. 알 수 없는 키는 공유로 보며,
 *          설정을 해석하는 단계에서 거부된다.
 */
pub(crate) fn node_local(name: &str) -> bool {
    spec(&name.to_ascii_lowercase()).is_some_and(|spec| spec.scope == Scope::Node)
}

/** @brief 세 빠른 경로 중 하나. */
#[derive(Clone, Copy)]
pub(crate) enum Lane {
    /** @brief 캐시 적중 UDP 빠른 경로. */
    Wire,
    /** @brief reactor 레인. */
    Reactor,
    /** @brief 권한 응답 wire 빠른 경로. */
    Authority,
}

impl Lanes {
    /** @brief 그 경로를 닫는 조건. */
    fn get(&self, lane: Lane) -> Option<Blocks> {
        match lane {
            Lane::Wire => self.wire,
            Lane::Reactor => self.reactor,
            Lane::Authority => self.authority,
        }
    }
}

/** @brief 이 설정에서 그 경로를 닫는 키가 하나도 없는지. */
pub(crate) fn lane_unblocked(lane: Lane, cfg: &Config, facts: &LaneFacts) -> bool {
    KEYS.iter()
        .filter_map(|spec| spec.lanes.get(lane))
        .all(|blocks| !blocks(cfg, facts))
}

use ApplyGroup::*;
use Reload::{Hot, NewGeneration};
use Scope::{Node, Shared};

/** @brief 모든 설정 키. 순서는 onetdns_config::known_keys 를 따른다. */
static KEYS: &[KeySpec] = &[
    key("mode", Hot(Metadata), Shared, Lanes::OPEN),
    key(
        "backend",
        Hot(Chain),
        Shared,
        reactor(|c, _| !matches!(c.backend, BackendKind::Recurse)),
    ),
    key("listen", Hot(Listeners), Node, Lanes::OPEN),
    key("upstreams", Hot(Forward), Shared, Lanes::OPEN),
    key("blocklists", Hot(Filter), Node, Lanes::OPEN),
    key("allowlists", Hot(Filter), Node, Lanes::OPEN),
    key("blocklist_urls", Hot(Subscriptions), Shared, Lanes::OPEN),
    key("blocklist_titles", Hot(Subscriptions), Shared, Lanes::OPEN),
    key(
        "disabled_blocklist_urls",
        Hot(Subscriptions),
        Shared,
        Lanes::OPEN,
    ),
    key("block_rules", Hot(Filter), Shared, Lanes::OPEN),
    key("allow_rules", Hot(Filter), Shared, Lanes::OPEN),
    key("list_refresh_secs", Hot(Subscriptions), Shared, Lanes::OPEN),
    key("blocked_services", Hot(Filter), Shared, Lanes::OPEN),
    key("safe_search", Hot(SafeSearch), Shared, Lanes::OPEN),
    key(
        "clients",
        Hot(Filter),
        Shared,
        wire(|c, _| c.clients.iter().any(|client| !client.upstreams.is_empty())),
    ),
    key("users", Hot(ConsoleAccounts), Node, Lanes::OPEN),
    key("views", Hot(Views), Shared, wire(|_, f| f.views_present)),
    key("policy", Hot(Policy), Shared, wire(|_, f| f.policy_present)),
    key(
        "wasm_policy",
        Hot(Policy),
        Node,
        wire(|_, f| f.policy_present),
    ),
    key(
        "wasm_plugins",
        Hot(Policy),
        Node,
        wire(|_, f| f.policy_present),
    ),
    key("wasm_fail_mode", Hot(Policy), Shared, Lanes::OPEN),
    key("block_response", Hot(Filter), Shared, Lanes::OPEN),
    key(
        "cache_size",
        Hot(Chain),
        Shared,
        wire(|c, _| c.cache_size == 0),
    ),
    key("min_ttl", Hot(Chain), Shared, wire(|c, _| c.min_ttl != 0)),
    key("max_ttl", Hot(Chain), Shared, Lanes::OPEN),
    key("query_timeout_secs", Hot(Forward), Shared, Lanes::OPEN),
    key("max_inflight", Hot(Native), Shared, Lanes::OPEN),
    key("workers", Hot(Listeners), Node, Lanes::OPEN),
    key("do_udp", Hot(Listeners), Shared, Lanes::OPEN),
    key("do_tcp", Hot(Listeners), Shared, Lanes::OPEN),
    key(
        "serve_stale_secs",
        Hot(Chain),
        Shared,
        reactor(|c, _| c.serve_stale_secs != 0),
    ),
    key("serve_expired_reply_ttl", Hot(Chain), Shared, Lanes::OPEN),
    key("serve_expired_ttl_reset", Hot(Chain), Shared, Lanes::OPEN),
    key(
        "serve_expired_client_timeout_ms",
        Hot(Chain),
        Shared,
        Lanes::OPEN,
    ),
    key("serve_stale_refresh", Hot(Chain), Shared, Lanes::OPEN),
    key("proxy_protocol_ports", Hot(Listeners), Node, Lanes::OPEN),
    key(
        "proxy_protocol_trusted",
        Hot(Listeners),
        Shared,
        Lanes::OPEN,
    ),
    key(
        "dns64_prefix",
        Hot(Native),
        Shared,
        wire(|c, _| c.dns64_prefix.is_some()),
    ),
    key("rebind_protection", Hot(Native), Shared, Lanes::OPEN),
    key("prefetch", Hot(Chain), Shared, wire(|c, _| c.prefetch)),
    key("prefetch_min_hits", Hot(Chain), Shared, Lanes::OPEN),
    key("prefetch_ttl_pct", Hot(Chain), Shared, Lanes::OPEN),
    key("dnssec", Hot(Chain), Shared, Lanes::OPEN),
    key("dnssec_strict", Hot(Chain), Shared, Lanes::OPEN),
    key("val_permissive_mode", Hot(Chain), Shared, Lanes::OPEN),
    key(
        "dnssec_accept_expired",
        Hot(DnssecClock),
        Shared,
        Lanes::OPEN,
    ),
    key("ignore_cd_flag", Hot(Chain), Shared, Lanes::OPEN),
    key("dnssec_rfc5011", Hot(Chain), Shared, Lanes::OPEN),
    key("dnssec_anchor_file", Hot(Chain), Node, Lanes::OPEN),
    key(
        "dnssec_roll_interval_secs",
        Hot(Authority),
        Shared,
        Lanes::OPEN,
    ),
    key("root_key_sentinel", Hot(Chain), Shared, Lanes::OPEN),
    key("trust_anchor_signaling", Hot(Chain), Shared, Lanes::OPEN),
    key("recursion_limit", Hot(Chain), Shared, Lanes::OPEN),
    key("cname_limit", Hot(Chain), Shared, Lanes::OPEN),
    key("dname_limit", Hot(Chain), Shared, Lanes::OPEN),
    key("do_ip4", Hot(Chain), Shared, Lanes::OPEN),
    key("do_ip6", Hot(Chain), Shared, Lanes::OPEN),
    key("prefer_ip4", Hot(Chain), Shared, Lanes::OPEN),
    key("prefer_ip6", Hot(Chain), Shared, Lanes::OPEN),
    key("qname_minimisation_strict", Hot(Chain), Shared, Lanes::OPEN),
    key("harden_referral_path", Hot(Chain), Shared, Lanes::OPEN),
    key("use_caps_for_id", Hot(Chain), Shared, Lanes::OPEN),
    key("lowercase_outgoing", Hot(Chain), Shared, Lanes::OPEN),
    key("harden_large_queries", Hot(Native), Shared, Lanes::OPEN),
    key("domain_insecure", Hot(Chain), Shared, Lanes::OPEN),
    key("split_default", Hot(Chain), Shared, Lanes::OPEN),
    key("split_recurse", Hot(Chain), Shared, Lanes::OPEN),
    key("split_forward", Hot(Chain), Shared, Lanes::OPEN),
    key("local_a", Hot(Chain), Shared, Lanes::OPEN),
    key("local_aaaa", Hot(Chain), Shared, Lanes::OPEN),
    key("acl_allow", Hot(Acl), Shared, Lanes::OPEN),
    key("acl_deny", Hot(Acl), Shared, Lanes::OPEN),
    key("rate_limit_per_sec", Hot(RateLimit), Shared, Lanes::OPEN),
    key("rate_limit_burst", Hot(RateLimit), Shared, Lanes::OPEN),
    key("run_as_user", NewGeneration, Node, Lanes::OPEN),
    key("run_as_group", NewGeneration, Node, Lanes::OPEN),
    key(
        "cookies",
        Hot(Native),
        Shared,
        wire(|c, _| c.cookies.is_strict()),
    ),
    key("subnet_rrl_per_sec", Hot(RateLimit), Shared, Lanes::OPEN),
    key("subnet_rrl_burst", Hot(RateLimit), Shared, Lanes::OPEN),
    key("listen_dot", Hot(Listeners), Node, Lanes::OPEN),
    key("listen_doh", Hot(Listeners), Node, Lanes::OPEN),
    key("listen_doq", Hot(Listeners), Node, Lanes::OPEN),
    key("listen_doh3", Hot(Listeners), Node, Lanes::OPEN),
    key("listen_dnscrypt", Hot(Listeners), Node, Lanes::OPEN),
    key("dnscrypt_provider_name", Hot(Listeners), Node, Lanes::OPEN),
    key("doh_path", Hot(Listeners), Node, Lanes::OPEN),
    key("ddr_name", Hot(Chain), Node, Lanes::OPEN),
    key("tls_cert", Hot(Tls), Node, Lanes::OPEN),
    key("tls_key", Hot(Tls), Node, Lanes::OPEN),
    key("tls_self_signed_host", Hot(Tls), Node, Lanes::OPEN),
    key("tls_client_ca", Hot(Tls), Node, Lanes::OPEN),
    key("tls_revocation", Hot(Revocation), Node, Lanes::OPEN),
    key(
        "tls_revocation_softfail",
        Hot(Revocation),
        Node,
        Lanes::OPEN,
    ),
    key(
        "acme_directory_url",
        Hot(Chain),
        Node,
        Lanes {
            wire: Some(|c, _| c.acme_directory_url.is_some()),
            reactor: None,
            authority: Some(|c, _| c.acme_directory_url.is_some()),
        },
    ),
    key("acme_contact_email", Hot(Acme), Node, Lanes::OPEN),
    key("acme_domains", Hot(Acme), Node, Lanes::OPEN),
    key("acme_challenge", Hot(Acme), Node, Lanes::OPEN),
    key("acme_account_key_file", Hot(Acme), Node, Lanes::OPEN),
    key("acme_cert_file", Hot(Acme), Node, Lanes::OPEN),
    key("acme_key_file", Hot(Acme), Node, Lanes::OPEN),
    key("control_listen", Hot(ControlTokens), Node, Lanes::OPEN),
    key("control_token", Hot(ControlTokens), Node, Lanes::OPEN),
    key(
        "control_admin_tokens",
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key(
        "control_readonly_tokens",
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key(
        "control_trusted_proxies",
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key(
        "control_public_origins",
        Hot(ControlTokens),
        Node,
        Lanes::OPEN,
    ),
    key("block_ipv4", Hot(Filter), Shared, Lanes::OPEN),
    key("block_ipv6", Hot(Filter), Shared, Lanes::OPEN),
    key("blocked_response_ttl", Hot(BlockTtl), Shared, Lanes::OPEN),
    key("block_aaaa", Hot(Native), Shared, wire(|c, _| c.block_aaaa)),
    key("bogus_nxdomain", Hot(Native), Shared, Lanes::OPEN),
    key(
        "domain_needed",
        Hot(Native),
        Shared,
        wire(|c, _| c.domain_needed),
    ),
    key("bogus_priv", Hot(Native), Shared, wire(|c, _| c.bogus_priv)),
    key(
        "empty_zones",
        Hot(Native),
        Shared,
        wire(|c, _| c.empty_zones),
    ),
    key("local_ttl", Hot(LocalTtl), Shared, Lanes::OPEN),
    key("rewrites", Hot(Filter), Shared, Lanes::OPEN),
    key(
        "dynamic_records",
        Hot(Chain),
        Shared,
        Lanes {
            wire: Some(|c, _| !c.dynamic_records.is_empty()),
            reactor: None,
            authority: Some(|c, _| !c.dynamic_records.is_empty()),
        },
    ),
    key("local_zones", Hot(Filter), Shared, Lanes::OPEN),
    key("refused_domains", Hot(Filter), Shared, Lanes::OPEN),
    key("rpz_files", Hot(Filter), Node, Lanes::OPEN),
    key("rpz_urls", Hot(Subscriptions), Shared, Lanes::OPEN),
    key("safe_browsing", Hot(Subscriptions), Shared, Lanes::OPEN),
    key("parental_control", Hot(Subscriptions), Shared, Lanes::OPEN),
    key("service_schedule", Hot(Filter), Shared, Lanes::OPEN),
    key("upstream_urls", Hot(Forward), Shared, Lanes::OPEN),
    key("bootstrap", Hot(Chain), Shared, Lanes::OPEN),
    key("root_hints", Hot(Chain), Shared, Lanes::OPEN),
    key("fallback_upstreams", Hot(Chain), Shared, Lanes::OPEN),
    key("upstream_strategy", Hot(Forward), Shared, Lanes::OPEN),
    key("upstream_concurrency", Hot(Forward), Shared, Lanes::OPEN),
    key("query_source", Hot(QuerySource), Node, Lanes::OPEN),
    key("query_source_v6", Hot(QuerySource), Node, Lanes::OPEN),
    key(
        "stub_zones",
        Hot(Chain),
        Shared,
        reactor(|c, _| !c.stub_zones.is_empty()),
    ),
    key(
        "zones",
        Hot(Authority),
        Node,
        wire(|c, _| !c.zones.is_empty()),
    ),
    key(
        "zones_dir",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_dir.is_some()),
    ),
    key(
        "zones_db",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_db.is_some()),
    ),
    key("zones_db_table", Hot(Authority), Node, Lanes::OPEN),
    key(
        "zones_postgres",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_postgres.is_some()),
    ),
    key(
        "zones_mysql",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_mysql.is_some()),
    ),
    key(
        "zones_lmdb",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_lmdb.is_some()),
    ),
    key("zones_sql_table", Hot(Authority), Node, Lanes::OPEN),
    key(
        "zones_etcd",
        Hot(Authority),
        Node,
        wire(|c, _| c.zones_etcd.is_some()),
    ),
    key("zones_etcd_prefix", Hot(Authority), Node, Lanes::OPEN),
    key("zones_etcd_ca", Hot(Authority), Node, Lanes::OPEN),
    key("zones_etcd_user", Hot(Authority), Node, Lanes::OPEN),
    key("zones_etcd_password", Hot(Authority), Node, Lanes::OPEN),
    key(
        "secondary",
        Hot(Authority),
        Node,
        wire(|c, _| !c.secondary.is_empty()),
    ),
    key(
        "catalog",
        Hot(Authority),
        Node,
        wire(|c, _| !c.catalog.is_empty()),
    ),
    key("catalog_serve", Hot(Authority), Node, Lanes::OPEN),
    key("xfr_allow", Hot(Authority), Node, Lanes::OPEN),
    key("notify", Hot(Authority), Node, Lanes::OPEN),
    key("tsig_keys", Hot(Authority), Node, Lanes::OPEN),
    key("xfr_tsig_required", Hot(Authority), Node, Lanes::OPEN),
    key("zonemd_check", Hot(Authority), Node, Lanes::OPEN),
    key("zonemd_reject_absence", Hot(Authority), Node, Lanes::OPEN),
    key("update_allow", Hot(Authority), Node, Lanes::OPEN),
    key("update_policy", Hot(Authority), Node, Lanes::OPEN),
    key("update_tsig_required", Hot(Authority), Node, Lanes::OPEN),
    key(
        "ecs_mode",
        Hot(Chain),
        Shared,
        wire(|c, _| !matches!(c.ecs_mode, EcsMode::Off)),
    ),
    key("ecs_custom_ip", Hot(Chain), Shared, Lanes::OPEN),
    key("neg_min_ttl", Hot(Chain), Shared, Lanes::OPEN),
    key("neg_max_ttl", Hot(Chain), Shared, Lanes::OPEN),
    key("edns_buffer_size", Hot(Native), Shared, Lanes::OPEN),
    key("deny_any", Hot(Native), Shared, Lanes::OPEN),
    key("minimal_responses", Hot(Native), Shared, Lanes::OPEN),
    key(
        "edns_padding_block",
        Hot(Native),
        Shared,
        wire(|c, _| c.edns_padding_block != 0),
    ),
    key("edns_tcp_keepalive_secs", Hot(Native), Shared, Lanes::OPEN),
    key(
        "cache_enabled",
        Hot(Chain),
        Shared,
        wire(|c, _| !c.cache_enabled),
    ),
    key("sharded_cache", Hot(Chain), Shared, Lanes::OPEN),
    key("cache_shards", Hot(Chain), Shared, Lanes::OPEN),
    key("prefetch_interval_secs", Hot(Chain), Shared, Lanes::OPEN),
    key("dns64_synthall", Hot(Native), Shared, Lanes::OPEN),
    key(
        "rrset_roundrobin",
        Hot(Native),
        Shared,
        wire(|c, _| c.rrset_roundrobin),
    ),
    key("track_rule_hits", Hot(Filter), Shared, Lanes::OPEN),
    key(
        "aggressive_nsec",
        Hot(Chain),
        Shared,
        reactor(|c, _| c.aggressive_nsec),
    ),
    key(
        "name_ratelimit_per_sec",
        Hot(Chain),
        Shared,
        Lanes {
            wire: Some(|c, _| c.name_ratelimit_per_sec != 0),
            reactor: Some(|c, _| c.name_ratelimit_per_sec != 0),
            authority: None,
        },
    ),
    key("name_ratelimit_labels", Hot(Chain), Shared, Lanes::OPEN),
    key(
        "harden_below_nxdomain",
        Hot(Chain),
        Shared,
        reactor(|c, _| c.harden_below_nxdomain),
    ),
    key("dhcp_enable", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_server_ip", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_range_start", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_range_end", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_subnet_mask", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_router", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_dns", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_lease_secs", Hot(EdgeServices), Node, Lanes::OPEN),
    key(
        "dhcp_local_domain",
        Hot(Chain),
        Node,
        wire(|c, f| f.dhcp_pool && !c.dhcp_local_domain.is_empty()),
    ),
    key("dhcp_tftp_server", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_boot_file", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_enable", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_root", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_listen", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_writable", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_write_allow", Hot(EdgeServices), Node, Lanes::OPEN),
    key("tftp_allow_overwrite", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_enable", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_prefix", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_managed", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_other", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_router_lifetime", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_interval", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_mtu", Hot(EdgeServices), Node, Lanes::OPEN),
    key("ra_interface_index", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp6_enable", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp6_range_start", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp6_range_end", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp6_dns", Hot(EdgeServices), Node, Lanes::OPEN),
    key(
        "dhcp6_interface_index",
        Hot(EdgeServices),
        Node,
        Lanes::OPEN,
    ),
    key("dhcp_lease_file", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp_static_file", Hot(EdgeServices), Node, Lanes::OPEN),
    key("dhcp6_lease_file", Hot(EdgeServices), Node, Lanes::OPEN),
    key("mac_vendor_db", Hot(MacVendor), Node, Lanes::OPEN),
    key(
        "ipset_name_v4",
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key(
        "ipset_name_v6",
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key(
        "ipset_domains",
        Hot(Chain),
        Node,
        wire(|c, _| crate::native_config::ipset_layer_active(c)),
    ),
    key(
        "cachedb_redis_host",
        Hot(Chain),
        Node,
        reactor(|c, _| c.cachedb_redis_host.is_some()),
    ),
    key("cachedb_redis_port", Hot(Chain), Node, Lanes::OPEN),
    key("cachedb_redis_expire_secs", Hot(Chain), Node, Lanes::OPEN),
    key("cluster_peers", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_raft", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_node_id", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_raft_listen", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_raft_peers", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_raft_secret", Hot(Cluster), Node, Lanes::OPEN),
    key("cluster_raft_node_key", Hot(Cluster), Node, Lanes::OPEN),
    key("rebind_allow", Hot(Native), Shared, Lanes::OPEN),
    key("recurse_deny_server", Hot(Chain), Shared, Lanes::OPEN),
    key("recurse_allow_server", Hot(Chain), Shared, Lanes::OPEN),
    key("ns_recursion_limit", Hot(Chain), Shared, Lanes::OPEN),
    key("ns_cache_size", Hot(Chain), Shared, Lanes::OPEN),
    key("recurse_deny_answers", Hot(Native), Shared, Lanes::OPEN),
    key("recurse_allow_answers", Hot(Native), Shared, Lanes::OPEN),
    key("val_nsec3_max_iterations", Hot(Chain), Shared, Lanes::OPEN),
    key("rate_limit_allow", Hot(RateLimit), Shared, Lanes::OPEN),
    key("acl_allow_ids", Hot(Acl), Shared, Lanes::OPEN),
    key("acl_deny_ids", Hot(Acl), Shared, Lanes::OPEN),
    key("hide_identity", Hot(Native), Shared, Lanes::OPEN),
    key("hide_version", Hot(Native), Shared, Lanes::OPEN),
    key("nsid", Hot(Native), Node, Lanes::OPEN),
    key("identity", Hot(Native), Node, Lanes::OPEN),
    key("version", Hot(Native), Shared, Lanes::OPEN),
    key("log_level", Hot(Log), Node, Lanes::OPEN),
    key("querylog", Hot(QueryLog), Shared, Lanes::OPEN),
    key("querylog_size", Hot(QueryLog), Shared, Lanes::OPEN),
    key(
        "querylog_retention_secs",
        Hot(QueryLog),
        Shared,
        Lanes::OPEN,
    ),
    key("anonymize_client_ip", Hot(QueryLog), Shared, Lanes::OPEN),
    key("querylog_ignored", Hot(QueryLog), Shared, Lanes::OPEN),
    key("stats_retention_secs", Hot(QueryLog), Shared, Lanes::OPEN),
    key("querylog_file", Hot(Persistence), Node, Lanes::OPEN),
    key("stats_file", Hot(Persistence), Node, Lanes::OPEN),
    key("persist_flush_secs", Hot(Persistence), Shared, Lanes::OPEN),
    key(
        "dnstap_file",
        Hot(Native),
        Node,
        wire(|c, _| c.dnstap_file.is_some()),
    ),
    key("dnstap_identity", Hot(Native), Node, Lanes::OPEN),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /** @brief 표가 설정 키를 빠짐없이 한 번씩 담는지. */
    fn table_covers_every_known_key_once() {
        let mut table: Vec<&str> = KEYS.iter().map(|spec| spec.key).collect();
        let mut known = onetdns_config::known_keys().to_vec();
        table.sort_unstable();
        known.sort_unstable();
        let mut unique = table.clone();
        unique.dedup();
        assert_eq!(unique.len(), table.len(), "같은 키가 표에 두 번 있습니다");
        assert_eq!(table, known, "표와 설정 키 목록이 다릅니다");
    }

    /** @brief 그 경로를 닫을 수 있는 키들. 표 순서를 따른다. */
    fn blockers(lane: Lane) -> Vec<&'static str> {
        KEYS.iter()
            .filter(|spec| spec.lanes.get(lane).is_some())
            .map(|spec| spec.key)
            .collect()
    }

    #[test]
    /**
     * @brief 빠른 경로를 닫는 키가 말없이 줄지 않는지.
     * @details 조건이 빠진 키는 그 기능이 없는 것처럼 답이 나간다. 목록에서 빼려면 그 키의
     *          값이 응답을 요청 내용만으로 정한다는 것을 먼저 보여야 한다.
     */
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
                "stub_zones",
                "aggressive_nsec",
                "name_ratelimit_per_sec",
                "harden_below_nxdomain",
                "cachedb_redis_host",
            ]
        );
        assert_eq!(
            blockers(Lane::Authority),
            ["acme_directory_url", "dynamic_records"]
        );
    }

    #[test]
    /** @brief 세대를 새로 만들어야 하는 키가 권한 강등 두 키뿐인지. */
    fn only_privilege_drop_needs_a_new_generation() {
        let cold: Vec<&str> = KEYS
            .iter()
            .filter(|spec| spec.reload == Reload::NewGeneration)
            .map(|spec| spec.key)
            .collect();
        assert_eq!(cold, ["run_as_user", "run_as_group"]);
    }
}
