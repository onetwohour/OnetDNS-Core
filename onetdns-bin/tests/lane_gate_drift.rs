/*!
 * @brief 계층 순서와 hot-apply 의 단계 순서가 말없이 바뀌지 않게 붙든다.
 *
 * @details 소스에서 표시 사이 구간을 그대로 잘라 계층 순서를 비교하고, hot-apply 경로에서
 *          검사와 적용의 앞뒤 관계를 확인한다.
 * @warning 계층 목록은 계산해서 나온 값이 아니라 일부러 고정해 둔 것이다.
 */

/** @brief 계층 순서를 검사할 소스. */
const CHAIN_RS: &str = include_str!("../src/resolver_chain.rs");
/** @brief 재시작 없는 설정 교체를 검사할 소스. */
const HOT_APPLY_RS: &str = include_str!("../src/hot_apply.rs");

/** @brief 표시 사이의 소스 구간. */
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
/** @brief 계층을 쌓는 순서가 그대로인지. 순서가 곧 우선순위다. */
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
/**
 * @brief 교체가 전부 아니면 전무인지.
 *
 * @details 바뀐 키가 모두 재시작 없이 교체할 수 있는지 보는 검사보다 먼저 무엇을 바꾸면,
 *          재시작해야 하는 키가 섞여 있을 때 이미 바꿔 놓고 "재시작해야 한다"고 답하게 된다.
 *          인증서를 교체하고 DHCP를 재시작한 뒤에 그렇게 답한 적이 실제로 있었다.
 * @warning 새 그룹 적용 코드는 반드시 이 검사 아래에 넣어야 한다.
 */
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
/**
 * @brief 교체가 파일만 보고 판단하지 않는지.
 *
 * @details 시작할 때 채워 넣은 기본값은 파일에 적히지 않는다. 파일만 다시 읽어 비교하면
 *          그 항목이 사라진 것으로 보인다. 실제로 질의 로그 스위치 하나를 껐을 뿐인데
 *          손대지 않은 관리 주소를 지운 것으로 처리해 웹 화면을 닫은 적이 있다.
 * @warning 이 정규화를 빼면 그 사고가 그대로 돌아온다.
 */
fn hot_apply_fills_startup_defaults_before_comparing() {
    let apply = HOT_APPLY_RS
        .find("let changed = config_changed_keys(&previous_cfg, next)?;")
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
/**
 * @brief 교체가 통계를 모을지 여부를 다시 정하는지.
 *
 * @details 관리 수신 주소는 세대를 다시 만들지 않고 교체할 수 있다. 시작할 때 한 번
 *          정한 판정을 그대로 두면, 주소를 나중에 연 사람은 대시보드에 아무것도 보이지
 *          않고 주소를 닫은 사람은 아무도 읽지 않는 통계 비용을 계속 낸다.
 * @warning 이 호출을 지우면 두 증상이 조용히 돌아온다. 어느 쪽도 오류로 드러나지 않는다.
 */
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
