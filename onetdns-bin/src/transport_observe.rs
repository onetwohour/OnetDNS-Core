/*!
 * @brief 전송별 오류 관찰.
 *
 * @details 어느 전송의 어느 단계에서 얼마나 실패했는지 센다. 지표로 내보내 어디가
 *          문제인지 좁힌다.
 * @note 단계 이름은 고정 문자열이다. 상대가 준 값을 키로 쓰면 종류가 무한히 늘어난다.
 */

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

/** @brief 전송과 단계별 오류 수. */
static ERROR_COUNTS: OnceLock<Mutex<HashMap<(&'static str, &'static str), u64>>> = OnceLock::new();

/** @brief 오류를 하나 센다. */
pub fn record_error(
    transport: &'static str,
    stage: &'static str,
    peer: Option<SocketAddr>,
    detail: impl fmt::Display,
) {
    let count = {
        let counters = ERROR_COUNTS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut counters = counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let value = counters.entry((transport, stage)).or_insert(0);
        *value = value.saturating_add(1);
        *value
    };
    if count == 1 || count.is_power_of_two() {
        let peer = peer
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        onetdns_core::warn!(event = "transport.error",
            transport = transport,
            stage = stage,
            peer = %peer,
            count = count,
            error = %detail,
            "Error during DNS transport"
        );
    }
}

/** @brief QUIC 진단을 단계 카운터로 옮긴다. */
pub fn record_quic_diagnostic(
    transport: &'static str,
    peer: Option<SocketAddr>,
    diagnostic: onetdns_quic::QuicDiagnostic,
) {
    record_error(transport, diagnostic.stage(), peer, diagnostic);
}

/** @brief 지금 카운터 전부. */
pub fn snapshot() -> Vec<(&'static str, &'static str, u64)> {
    let counters = ERROR_COUNTS.get_or_init(|| Mutex::new(HashMap::new()));
    let counters = counters
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut items: Vec<_> = counters
        .iter()
        .map(|((transport, stage), count)| (*transport, *stage, *count))
        .collect();
    items.sort_unstable();
    items
}

#[cfg(test)]
/** @brief 이 전송과 단계의 오류 수. */
pub fn count(transport: &'static str, stage: &'static str) -> u64 {
    ERROR_COUNTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&(transport, stage))
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 카운터가 쌓이고 지표로 나오는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 오류가 단계별로 세어지는지. */
    fn records_stage_counter() {
        let before = count("test", "parse");
        record_error("test", "parse", None, "synthetic failure");
        assert_eq!(count("test", "parse"), before.saturating_add(1));
    }

    #[test]
    /** @brief 센 것이 그대로 나오는지. */
    fn snapshot_reports_recorded_counters() {
        record_error("test_snapshot", "stage", None, "synthetic failure");
        assert!(snapshot()
            .iter()
            .any(|(t, s, c)| *t == "test_snapshot" && *s == "stage" && *c >= 1));
    }

    #[test]
    /** @brief QUIC 진단이 고정된 단계 이름만 쓰는지. 상대가 정하는 값을 키로 쓰면 종류가 무한히 는다. */
    fn quic_diagnostics_use_bounded_stage_counters() {
        let stage = onetdns_quic::QuicDiagnostic::LongPacketProtection.stage();
        let before = count("test_quic", stage);
        record_quic_diagnostic(
            "test_quic",
            None,
            onetdns_quic::QuicDiagnostic::LongPacketProtection,
        );
        assert_eq!(count("test_quic", stage), before.saturating_add(1));
    }
}
