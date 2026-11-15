//! Error counts per transport and stage, exported as metrics. Stage names are fixed strings; keys
//! taken from the peer would grow without bound.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

static ERROR_COUNTS: OnceLock<Mutex<HashMap<(&'static str, &'static str), u64>>> = OnceLock::new();

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

pub fn record_quic_diagnostic(
    transport: &'static str,
    peer: Option<SocketAddr>,
    diagnostic: onetdns_quic::QuicDiagnostic,
) {
    record_error(transport, diagnostic.stage(), peer, diagnostic);
}

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
mod tests {
    use super::*;

    #[test]
    fn records_stage_counter() {
        let before = count("test", "parse");
        record_error("test", "parse", None, "synthetic failure");
        assert_eq!(count("test", "parse"), before.saturating_add(1));
    }

    #[test]
    fn snapshot_reports_recorded_counters() {
        record_error("test_snapshot", "stage", None, "synthetic failure");
        assert!(snapshot()
            .iter()
            .any(|(t, s, c)| *t == "test_snapshot" && *s == "stage" && *c >= 1));
    }

    #[test]
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
