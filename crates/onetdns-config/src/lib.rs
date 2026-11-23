//! Config file parsing and validation, with our own TOML parser. Unknown keys are rejected rather
//! than ignored, so one typo cannot silently disable what was intended. Validation fails closed: a
//! dangerous combination refuses to start unless the operator explicitly accepts it.

pub mod mode;
/// Per-key UI metadata the dashboard builds its settings screens from.
pub mod schema;
pub mod settings;
pub mod stamp;
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
