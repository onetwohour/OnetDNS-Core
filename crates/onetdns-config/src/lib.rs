/*!
 * @brief 설정 파일 파싱과 검증.
 *
 * @details TOML 파서까지 직접 만든다. 모르는 키는 조용히 무시하지 않고 거부한다.
 *          오타 하나가 의도한 설정을 전부 비활성화하는 것을 막는다.
 * @warning 검증은 실패 시 막는 쪽이다. 위험한 조합은 시작 자체를 거부하고, 운영자가
 *          명시적으로 감수하겠다고 밝힌 경우에만 열어 준다.
 */

/** @brief 동작 모드와 그에 따른 기본값. */
pub mod mode;
/** @brief 설정 항목의 UI 메타데이터. 대시보드가 이것으로 편집 화면을 만든다. */
pub mod schema;
/** @brief 설정 구조와 검증. */
pub mod settings;
/** @brief TOML 파서. */
pub mod toml;

pub use mode::Mode;
pub use onetdns_core::SecretString;
pub use settings::validate_acme_request;
pub use settings::{
    dns_endpoint_conflicts, known_keys, parse_update_rtype, redact_url_credentials, AclUnlisted,
    BackendKind, BlockResponseKind, ClientConfig, Config, ConfigError, CookieMode, DynamicRecord,
    EcsMode, LocalAnswer, LocalZone, LocalZoneKind, NotifyTarget, PolicyRule, Rewrite,
    ScheduleWindow, SecondaryZone, SplitTarget, StubZone, TsigKeyConfig, UpdatePolicyRule,
    UpstreamStrategy, UserConfig, ViewConfig, WasmPluginConfig, ZoneConfig,
};
