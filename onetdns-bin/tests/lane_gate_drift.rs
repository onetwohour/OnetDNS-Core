//! Keeps the layer order and the hot-apply step order from changing silently. The source between
//! markers is sliced to compare the layer order, and the hot-apply path is checked for checks
//! before changes.
//!
//! The layer list is pinned on purpose, not computed.

const CHAIN_RS: &str = include_str!("../src/resolver_chain.rs");
const HOT_APPLY_RS: &str = include_str!("../src/hot_apply.rs");

fn gate_body(begin: &str, end: &str) -> String {
    let start = CHAIN_RS
        .find(begin)
        .unwrap_or_else(|| panic!("{begin} 표시를 찾지 못했습니다"));
    let stop = CHAIN_RS
        .find(end)
        .unwrap_or_else(|| panic!("{end} 표시를 찾지 못했습니다"));
    assert!(start < stop, "{begin}이 {end}보다 앞이어야 합니다");
    CHAIN_RS[start..stop].to_string()
}

#[test]
/// The order is the priority.
fn layer_stack_order_is_pinned() {
    let body = gate_body("// layer-order:begin", "// layer-order:end");
    let mut seen = Vec::new();
    let mut rest = body.as_str();
    while let Some(at) = rest.find("Layer::") {
        let head = &rest[..at + "Layer".len()];
        let start = head
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|index| index + 1)
            .unwrap_or(0);
        let name = &head[start..];
        let tail = &rest[at + "Layer::".len()..];

        if tail.starts_with("new(") || tail.starts_with("with_policy(") {
            seen.push(name.to_string());
        }
        rest = &rest[at + "Layer::".len()..];
    }

    let expected = [
        "LocalOnlyLayer",
        "FallbackLayer",
        "ForwardValidateLayer",
        "CacheDbLayer",
        "EcsLayer",
        "CacheLayer",
        "ServeStaleLayer",
        "PrefetchLayer",
        "LocalAddressLayer",
        "NameRateLimitLayer",
        "StubLayer",
        "DhcpDnsLayer",
        "IpsetLayer",
        "AuthorityLayer",
        "AcmeChallengeLayer",
        "DdrLayer",
        "DynamicRecordLayer",
    ];
    assert_eq!(
        seen, expected,
        "계층 조립 순서가 바뀌었습니다. 상대 순서가 동작을 결정합니다. 캐시가 ECS보다          안쪽으로 가면 클라이언트 서브넷이 키에서 빠지고, 권한 계층이 캐시 안쪽으로          가면 로컬 존이 가려지며, LocalOnlyLayer가 권한·DHCP 계층 바깥으로 가면          자기 home.arpa 영역을 자기가 NXDOMAIN으로 덮습니다. 의도한 변경이면          docs/architecture/layer-order.md의 계층 표와 이 목록을 함께 갱신하십시오."
    );
}

#[test]
/// Changing anything before the check that every changed key can be hot-applied would, when a
/// restart-only key is mixed in, leave changes applied and then answer that a restart is needed,
/// for example after swapping a certificate and restarting DHCP.
///
/// New group apply code goes below this check.
fn hot_apply_checks_before_it_changes_anything() {
    let guard = HOT_APPLY_RS
        .find("if !service_restart_keys(&previous_cfg, next, &changed).is_empty() {")
        .expect("교체 가능 여부 검사를 찾지 못했습니다");
    let first_apply = HOT_APPLY_RS
        .find("// hot-apply:begin")
        .expect("그룹 적용 구간 표시를 찾지 못했습니다");
    assert!(
        guard < first_apply,
        "재시작 없이 교체할 수 있는지 보기 전에 무언가를 바꾸고 있습니다. 적용 코드를 검사 \
         아래로 옮기십시오. 그러지 않으면 반쯤 바꿔 놓고 재시작하게 됩니다."
    );
}

#[test]
/// Startup defaults are not in the file, so comparing against the file alone shows them as removed:
/// turning off one query log switch would drop an untouched control address and close the
/// dashboard.
///
/// Removing this normalization brings that back.
fn hot_apply_fills_startup_defaults_before_comparing() {
    let apply = HOT_APPLY_RS
        .find("let changed = config_changed_keys(&previous_cfg, next);")
        .expect("교체 비교 지점을 찾지 못했습니다");
    let normalize = HOT_APPLY_RS
        .find("let next = &normalize_config_for_comparison(&previous_cfg, next);")
        .expect(
            "교체 경로가 시작 기본값을 채우지 않습니다. 파일에 없는 기본값이 \
             지워진 것으로 보여 손대지 않은 항목을 끕니다.",
        );
    assert!(
        normalize < apply,
        "기본값을 채우기 전에 비교하고 있습니다. 정규화를 비교 위로 옮기십시오."
    );
}

#[test]
/// The control listener can be hot-applied without rebuilding the generation. Keeping the startup
/// decision would show an empty dashboard to someone who opens the address later, and keep
/// collecting stats nobody reads for someone who closes it.
///
/// Removing this call brings both back silently; neither surfaces as an error.
fn hot_apply_redecides_whether_to_collect() {
    let end = HOT_APPLY_RS
        .find("// hot-apply:end")
        .expect("그룹 적용 구간 끝 표시를 찾지 못했습니다");
    let done = HOT_APPLY_RS[end..]
        .find("event = \"config.runtime_hot_applied\"")
        .expect("교체 성공 지점을 찾지 못했습니다");
    assert!(
        HOT_APPLY_RS[end..end + done].contains("set_collecting(telemetry_consumed(next))"),
        "교체 성공 경로가 통계 수집 여부를 다시 정하지 않습니다. 시작할 때의 \
         판정이 그대로 남아 관리 주소를 열어도 대시보드가 비어 있게 됩니다."
    );
}

#[test]
/// The feature set holds the path conditions and the chain and wire generations. Visible before the
/// chain, a request tagged with the new generation would build an answer with the old chain and
/// store it in the new cache, and a lane would resolve a newly added stub zone's name by plain
/// recursion and serve it for that TTL. Clearing the cache before publishing would let answers
/// taken under the old conditions meanwhile be stored under the post-clear generation.
///
/// New response-changing state is changed before the publish and added to the list below.
fn hot_apply_publishes_the_fast_path_snapshot_last() {
    let start = HOT_APPLY_RS
        .find("fn commit(")
        .expect("commit 함수를 찾지 못했습니다");
    let end = start
        + HOT_APPLY_RS[start..]
            .find("#[cfg(test)]")
            .expect("commit 함수의 끝을 찾지 못했습니다");
    let commit = &HOT_APPLY_RS[start..end];
    assert_eq!(
        commit.matches("features.store(").count(),
        1,
        "commit이 기능 세트를 여러 번 게시합니다. 빠른 경로가 중간 상태를 보게 됩니다."
    );
    let publish = commit.find("features.store(").unwrap();
    for write in [
        "chain.slot.replace(",
        "forward_slot.replace(",
        "state.local_ttl.store(",
        "state.policy.store(",
        "state.views.store(",
        ".local_only_names",
    ] {
        let at = commit
            .find(write)
            .unwrap_or_else(|| panic!("{write} 지점을 찾지 못했습니다"));
        assert!(
            at < publish,
            "{write} 지점이 기능 세트 게시보다 뒤에 있습니다. 새 세대의 태그를 단 요청이 \
             이전 상태로 답을 만들어 담습니다."
        );
    }
    let flush = commit
        .find(".clear()")
        .expect("캐시를 비우는 지점을 찾지 못했습니다");
    assert!(
        publish < flush,
        "기능 세트를 게시하기 전에 캐시를 비웁니다. 이전 조건으로 맡은 답이 비운 뒤의 \
         세대로 담깁니다."
    );
}
