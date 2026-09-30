/*!
 * @brief 컨트롤 플레인: REST API, 대시보드, 지표 수집.
 *
 * @details 데이터 경로를 절대 막지 않는 것이 이 크레이트의 제1 원칙이다. 지표는 유계
 *          채널에 넣기만 하고 넘치면 버리며, HTTP 서버는 별도 스레드에서 돈다.
 */

/** @brief REST API와 대시보드를 서빙하는 HTTP/1.1 서버. */
pub mod api;
/** @brief dnstap 형식 질의 로그. */
pub mod dnstap;
/** @brief 지표 수집과 실시간 전달. */
pub mod metrics;
/** @brief 대시보드 로그인용 비밀번호 해시. */
pub mod password;
/** @brief 지표와 설정의 디스크 보존. */
mod persist;

pub use api::{
    clear_acme_http01, serve, serve_listener, set_acme_http01, ApiResponse, AppState, AuditLog,
    Auth, ClusterWrite, Controls, ListCounts, Role, SessionStore, UserCred,
};
pub use dnstap::{DnstapProtocol, DnstapWriter};
pub use metrics::{
    channel, Action, EventDiag, Metrics, MetricsSnapshot, PersistOpts, QueryEvent, Recorder,
    RecorderOpts, RequestTimer, Stats, TopLists,
};
pub use password::{hash_password, verify_password, PasswordError};
