//! Control plane: REST API, dashboard, and metrics. Never blocks the data path.

pub mod api;
pub mod dnstap;
pub mod metrics;
pub mod password;
mod persist;

pub use api::{
    clear_acme_http01, serve, serve_listener, set_acme_http01, ApiResponse, AppState, AuditLog,
    Auth, ClusterWrite, Controls, FilterApply, ListCounts, ProxyPolicy, Role, SessionStore,
    UserCred,
};
pub use dnstap::{DnstapProtocol, DnstapWriter};
pub use metrics::{
    channel, Action, EventDiag, Metrics, MetricsSnapshot, PersistOpts, QueryEvent, Recorder,
    RecorderOpts, RequestTimer, Stats, TopLists,
};
pub use password::{hash_password, verify_password, PasswordError};
