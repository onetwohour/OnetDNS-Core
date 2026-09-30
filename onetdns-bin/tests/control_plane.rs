/*!
 * @brief 관리 평면의 안전장치가 소스에 남아 있는지 검사한다.
 *
 * @details 이미 적용된 설정과 사용자가 편집 중인 설정은 서로 다르다. 이 둘이 섞이면
 *          화면에는 값이 바뀐 것으로 보이지만 서버는 예전 값으로 계속 동작하고,
 *          되돌릴 방법도 남지 않는다. 그래서 두 설정의 경계, 되돌리기 순서,
 *          그리고 통계와 감사 기록이 재시작 뒤에도 남는 경로를 확인한다.
 * @note 테스트 함수 이름을 직접 확인하는 항목이 있다. 그 테스트를 지우면 여기서 실패한다.
 */

mod common;

use common::{production_files, read, root};

/** @brief onetdns-bin 의 관리 평면이 갖춰야 할 안전장치. */
const BIN_REQUIRED: &[&str] = &[
    "metrics: Arc<Mutex<Option<(onetdns_control::Recorder, onetdns_control::Stats)>>>",
    "audit: Arc<Mutex<Option<onetdns_control::AuditLog>>>",
    "event = \"stats.channel_reused\"",
    "desired_config_json(path.as_deref(), &c.load())",
    "Box::new(move || c.load().effective_json())",
    "config_status_json(path.as_deref(), &c.load())",
    r#"\"effective_changed\":[{}]"#,
    "let changed = config_changed_keys(&previous_cfg, next)?;",
    "pending_non_hot_file_change_cannot_be_hidden_by_a_hot_edit",
    "fn stable_resource_id(namespace: &str, value: &str) -> String",
    "desired_config_reports_invalid_disk_file_instead_of_runtime_fallback",
    "stable_resource_ids_do_not_depend_on_array_position",
    "fn update_runtime_config(",
    "config.block_rules = rules.0;",
    "config.blocked_services = applied;",
    "config.safe_search = enable",
    "config.blocklist_urls = applied_urls;",
    "config.refused_domains = applied;",
    "applied_config_text: ConfigTextSlot",
    "previous_config_text: ConfigTextSlot",
    "type ConfigTextSlot = Arc<Mutex<Option<onetdns_core::SecretString>>>;",
    "fn restore_last_applied_config(",
    "let ready_callback = Arc::new(Mutex::new(supervisor::take_ready_callback()?));",
    "shared.sessions.restore(session_checkpoint);",
    "fn validate_config_patch_values(",
    "config_patch_rejects_redacted_or_destructive_secret_placeholders",
    "fn normalize_config_for_comparison(",
    "fn config_changed_keys_for_status(",
    "web_dashboard_default_listener_does_not_create_false_config_drift",
    "runtime_change_comparison_does_not_hide_control_listener_removal",
    "record_items",
    r#"{{\"added\":{},\"id\":{},\"key\":{},{} }}"#,
    r#"{{\"removed\":{},\"id\":{},\"key\":{},{} }}"#,
];

/** @brief 통계를 유지하는 데 필요한 안전장치. */
const METRICS_REQUIRED: &[&str] = &[
    "pub fn reconfigure_persist(&self, persist: PersistOpts)",
    "disabling_persistence_flushes_the_previous_files",
    "persistence_paths_can_change_without_resetting_stats",
    "clear_recent_keeps_memory_when_persistent_clear_fails",
    "crate::persist::save_querylog(path, &VecDeque::<QueryEvent>::new())?;",
    "event = \"metrics.minute_summary\"",
    "event = \"stats.slot_full\"",
    "dropped_log_events",
    "dropped_stat_events",
    "dropped_stream_events",
    "pub fn flush_persisted(&self) -> std::io::Result<()>",
    "reconfigure_trims_recent_log_immediately",
];

/** @brief 관리 API 가 갖춰야 할 안전장치. */
const API_REQUIRED: &[&str] = &[
    "st.stats.recent(2_000)",
    "dropped_log_events",
    "dropped_stat_events",
    "dropped_stream_events",
    "pub audit: AuditLog",
    "fn audit_request_detail(",
    "changed_keys=",
    "record_request_actor(",
    "CONTROL_MUTATION_LOCK",
    "fn is_state_changing_request(method: &str, path: &str) -> bool",
    "diagnostic_post_requests_do_not_take_the_mutation_lock",
    "json::escape(&e.actor)",
    "json::escape(&e.detail)",
    "pub struct SessionCheckpoint",
    "pub fn checkpoint(&self) -> SessionCheckpoint",
    "DNS service settings are being applied. Try again when they are ready",
    "mutations_are_rejected_until_service_is_ready",
    "fn control_security_headers()",
    "Content-Security-Policy:",
    "X-Content-Type-Options: nosniff",
    "Cache-Control: no-store",
];

/** @brief 저장된 통계를 복구할 때 필요한 안전장치. */
const PERSIST_REQUIRED: &[&str] = &[
    "event = \"querylog.restore_invalid\"",
    "event = \"stats.restore_invalid_value\"",
    "fn parse_stats_snapshot(",
    "invalid_stats_file_is_not_partially_applied",
    "querylog_accepts_only_the_complete_current_shape",
];

/** @brief Windows 서비스가 설정을 되돌릴 때 필요한 안전장치. */
const SERVICE_REQUIRED: &[&str] = &[
    "let session_checkpoint = shared.sessions.checkpoint();",
    "shared.sessions.restore(session_checkpoint);",
    "restore_last_applied_config(config.as_deref(), &shared)",
];

/** @brief 대시보드가 서버 상태를 따라가는 데 필요한 안전장치. */
const DASHBOARD_REQUIRED: &[&str] = &[
    "desiredBody._valid!==false",
    "await this.loadConfigState();",
    "pendingLabel:this.t('파일에서 변경됨')",
    "this.resyncRecent()",
    "_upstreamProbeRun",
    "return {id:u.id,addr,proto:",
    "qlWindow:(st.qlWindow||100)+200",
    "dropped_log_events",
    "dropped_stat_events",
    "dropped_stream_events",
    "enum_labels_i18n",
    "detail:this.auditDetailText(e.detail)",
    "actor:String(e.actor||'system')",
    "actionLabel:this.t(",
    "confirmConfigImpact(keys)",
    "effective_changed",
    "sessionResetPatch(connectionState,notice)",
    "abortRequests()",
    "loadDashboardFallback()",
    "configDraftDirty",
    "fd.write_only===true",
    "nav.inert=hidden",
];

/** @brief 소스에서 찾지 못한 항목을 모은다. */
fn missing(source: &str, required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|snippet| !source.contains(**snippet))
        .map(|snippet| (*snippet).to_string())
        .collect()
}

/** @brief 찾지 못한 항목이 있으면 그 목록을 남기고 중단한다. */
fn require(source: &str, required: &[&str], subject: &str) {
    let gone = missing(source, required);
    assert!(
        gone.is_empty(),
        "{subject} 안전장치가 빠졌습니다:\n  - {}",
        gone.join("\n  - ")
    );
}

/**
 * @brief 바이너리 소스 전체를 이어 붙인 것.
 * @details 파일을 고르지 않는다. 코드가 다른 파일로 옮겨 가도 검사가 대상을 놓치지 않게
 *          하려는 것이다.
 */
fn bin_source() -> String {
    production_files(&["onetdns-bin/src"])
        .iter()
        .map(|path| read(path))
        .collect::<Vec<_>>()
        .join(
            "
",
        )
}

/** @brief 관리 평면의 각 부분이 안전장치를 갖추고 있는지 확인한다. */
#[test]
fn every_control_plane_safeguard_is_present() {
    let repo = root();
    require(&bin_source(), BIN_REQUIRED, "onetdns-bin 관리 평면");
    require(
        &read(&repo.join("crates/onetdns-control/src/metrics.rs")),
        METRICS_REQUIRED,
        "통계 수명 주기",
    );
    require(
        &read(&repo.join("crates/onetdns-control/src/api.rs")),
        API_REQUIRED,
        "관리 API",
    );
    require(
        &read(&repo.join("crates/onetdns-control/src/persist.rs")),
        PERSIST_REQUIRED,
        "통계 복구",
    );
    require(
        &read(&repo.join("onetdns-bin/src/service.rs")),
        SERVICE_REQUIRED,
        "Windows 서비스 되돌리기",
    );
    require(
        &read(&repo.join("crates/onetdns-control/dashboard/index.html")),
        DASHBOARD_REQUIRED,
        "대시보드 상태 동기화",
    );
}

/** @brief 형식이 잘못된 TOML 을 적용 중인 설정으로 조용히 대체하면 실패한다. */
#[test]
fn an_invalid_desired_file_is_reported_rather_than_replaced() {
    let source = bin_source();
    let start = source
        .find("fn desired_config_json(")
        .expect("desired_config_json 을 찾지 못했습니다");
    let end = source[start..]
        .find("fn config_status_json(")
        .map(|offset| start + offset)
        .expect("config_status_json 을 찾지 못했습니다");
    let body = &source[start..end];
    assert!(
        body.contains(r#"\"_valid\":false"#) && body.contains("Config::from_toml_str"),
        "형식이 잘못된 TOML 이 아직도 적용 중인 설정으로 조용히 대체됩니다"
    );
}

/** @brief 세션 되돌리기가 체크포인트보다 먼저 나오면 실패한다. */
#[test]
fn session_rollback_comes_after_its_checkpoint() {
    let repo = root();
    for (subject, name) in [
        ("main.rs 서비스 루프", "onetdns-bin/src/main.rs"),
        ("Windows 서비스 루프", "onetdns-bin/src/service.rs"),
    ] {
        let source = read(&repo.join(name));
        let checkpoint = source
            .find("let session_checkpoint = shared.sessions.checkpoint();")
            .unwrap_or_else(|| panic!("{subject}: 체크포인트를 찾지 못했습니다"));
        let restore = source
            .find("shared.sessions.restore(session_checkpoint);")
            .unwrap_or_else(|| panic!("{subject}: 되돌리기를 찾지 못했습니다"));
        assert!(
            restore > checkpoint,
            "{subject}: 되돌리기가 체크포인트보다 먼저 나옵니다"
        );
    }
}

/** @brief 업스트림 목록이 배열 순번을 식별자로 다시 쓰면 실패한다. */
#[test]
fn upstream_rows_keep_stable_identifiers() {
    let dashboard = read(&root().join("crates/onetdns-control/dashboard/index.html"));

    let mut from = 0usize;
    while let Some(at) = dashboard[from..].find("upstreams") {
        let start = from + at;
        from = start + "upstreams".len();
        let window = &dashboard[start..];
        let line_end = window.find('\n').unwrap_or(window.len());
        let limit = window[..line_end]
            .char_indices()
            .nth(160 + "upstreams".len())
            .map_or(line_end, |(offset, _)| offset);
        let bounded = &window[..limit];
        assert!(
            !bounded.contains("id:i+1"),
            "업스트림 목록이 배열 순번을 식별자로 씁니다: {bounded:?}"
        );
    }

    if let Some(at) = dashboard.find("map((u,i)") {
        assert!(
            !dashboard[at..].contains("id:i+1"),
            "업스트림 목록이 배열 순번을 식별자로 씁니다"
        );
    }

    assert!(
        !dashboard.contains("stableId(prefix,value)") && !dashboard.contains("u.addr||u.url"),
        "지워진 업스트림 식별자 형식을 위한 호환 경로가 남아 있습니다"
    );
}

/** @brief 열거형 원본 값에 화면 표시용 설명이 섞이면 실패한다. */
#[test]
fn enum_raw_values_carry_no_display_annotation() {
    let schema = read(&root().join("crates/onetdns-config/src/schema.rs"));
    let head = schema
        .split_once("static FIELD_COPY")
        .map(|(head, _)| head)
        .unwrap_or(schema.as_str());
    assert!(
        !head.contains("closed-refuse(기본)"),
        "열거형 원본 값에 화면 표시용 설명이 섞여 있습니다"
    );
}

/** @brief 업스트림 변경 응답이 이름 붙은 인자와 위치 인자를 섞으면 실패한다. */
#[test]
fn the_upstream_mutation_response_does_not_mix_argument_styles() {
    let source = bin_source();
    for malformed in [
        r#"{{\"added\":{},\"id\":{},\"key\":\"{key}\",{} }}"#,
        r#"{{\"removed\":{},\"id\":{},\"key\":\"{key}\",{} }}"#,
    ] {
        assert!(
            !source.contains(malformed),
            "업스트림 변경 응답이 이름 붙은 인자와 위치 인자를 섞습니다"
        );
    }
}

/** @brief 누락 판정이 실제로 동작하는지 확인한다. */
#[test]
fn the_missing_check_behaves() {
    assert_eq!(missing("가 나 다", &["가", "라"]), vec!["라".to_string()]);
    assert!(missing("가 나 다", &["가", "나"]).is_empty());
}
