//! Control plane: REST API, dashboard, and metrics. Never blocks the data path.

pub mod api;
pub mod dnstap;
pub mod metrics;
pub mod password;
mod persist;

pub use api::{
    adopt_credential_key, clear_acme_http01, credential_key, serve, serve_https_listener,
    serve_listener, set_acme_http01, ApiResponse, AppState, AuditLog, Auth, CertificateSource,
    ClusterWrite, Controls, FilterApply, ListCounts, ProxyPolicy, Role, SessionStore, UserCred,
};
pub use dnstap::{DnstapProtocol, DnstapWriter};
pub use metrics::{
    channel, Action, EventDiag, Metrics, MetricsSnapshot, PersistOpts, QueryEvent, Recorder,
    RecorderOpts, RequestTimer, Stats, TopLists,
};
pub use password::{hash_password, verify_password, PasswordError};
