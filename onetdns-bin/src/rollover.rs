//! ZSK rollover phases: publish the new key so validators see it, sign with it, then drop the old
//! key, waiting between each step. Skipping a wait fails validation in between: a validator with
//! only the old key cached cannot check the new signatures.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Stable,
    /// The new key is published; waiting for it to reach validators.
    Publish,
    /// Signing with the new key; the old one stays published.
    Activate,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Stable => "stable",
            Phase::Publish => "publish",
            Phase::Activate => "activate",
        }
    }
    fn from_str(s: &str) -> Option<Phase> {
        match s {
            "stable" => Some(Phase::Stable),
            "publish" => Some(Phase::Publish),
            "activate" => Some(Phase::Activate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RollTiming {
    /// How often a roll starts.
    pub interval: u64,

    /// Too short breaks validation.
    pub publish_wait: u64,

    /// Wait after the switch before the old key is removed.
    pub activate_wait: u64,
}

impl RollTiming {
    /// 0 disables rollover. The waits have a floor, so even a short period leaves validators time
    /// to see the new key.
    pub fn from_interval(interval: u64) -> Self {
        RollTiming {
            interval,
            publish_wait: (interval / 24).max(1),
            activate_wait: (interval / 12).max(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollState {
    pub phase: Phase,
    pub since: u64,
}

impl RollState {
    pub fn stable(now: u64) -> Self {
        RollState {
            phase: Phase::Stable,
            since: now,
        }
    }

    pub fn serialize(&self) -> String {
        format!("phase {}\nsince {}\n", self.phase.as_str(), self.since)
    }

    /// None when malformed.
    pub fn parse(s: &str) -> Option<RollState> {
        let mut lines = s.lines();
        let phase = Phase::from_str(lines.next()?.strip_prefix("phase ")?)?;
        let since_text = lines.next()?.strip_prefix("since ")?;
        if since_text.is_empty() || !since_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let since = since_text.parse::<u64>().ok()?;
        if lines.next().is_some() {
            return None;
        }
        Some(RollState { phase, since })
    }
}

/// None while the current phase is still waiting; the caller asks again next cycle.
pub fn advance(state: RollState, now: u64, t: RollTiming) -> Option<RollState> {
    if t.interval == 0 {
        return None;
    }
    let elapsed = now.saturating_sub(state.since);
    let due = match state.phase {
        Phase::Stable => t.interval,
        Phase::Publish => t.publish_wait,
        Phase::Activate => t.activate_wait,
    };
    if elapsed < due {
        return None;
    }
    let next = match state.phase {
        Phase::Stable => Phase::Publish,
        Phase::Publish => Phase::Activate,
        Phase::Activate => Phase::Stable,
    };
    Some(RollState {
        phase: next,
        since: now,
    })
}

pub fn next_path(active: &Path) -> PathBuf {
    with_ext(active, "next")
}
/// Holds the old key while it must stay published.
pub fn prev_path(active: &Path) -> PathBuf {
    with_ext(active, "prev")
}
pub fn state_path(active: &Path) -> PathBuf {
    with_ext(active, "roll")
}

fn with_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips() {
        let s = RollState {
            phase: Phase::Activate,
            since: 1_700_000_000,
        };
        let parsed = RollState::parse(&s.serialize()).unwrap();
        assert_eq!(parsed, s);
        assert!(RollState::parse("garbage").is_none());
        assert!(RollState::parse("phase stable\nsince 1\nextra value\n").is_none());
        assert!(RollState::parse("phase stable\n").is_none());
    }

    #[test]
    fn disabled_when_interval_zero() {
        let t = RollTiming::from_interval(0);
        assert!(advance(RollState::stable(0), 1_000_000, t).is_none());
    }

    #[test]
    fn full_cycle_advances_in_order() {
        let t = RollTiming {
            interval: 1000,
            publish_wait: 100,
            activate_wait: 200,
        };
        let mut st = RollState::stable(0);

        assert!(advance(st, 999, t).is_none());

        st = advance(st, 1000, t).unwrap();
        assert_eq!(st.phase, Phase::Publish);
        assert_eq!(st.since, 1000);

        assert!(advance(st, 1099, t).is_none());

        st = advance(st, 1100, t).unwrap();
        assert_eq!(st.phase, Phase::Activate);

        assert!(advance(st, 1299, t).is_none());
        st = advance(st, 1300, t).unwrap();
        assert_eq!(st.phase, Phase::Stable);
    }

    #[test]
    /// Key file paths are distinct.
    fn path_slots() {
        let p = Path::new("/etc/onetdns/example.com.zone.key");
        assert_eq!(
            next_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.next")
        );
        assert_eq!(
            prev_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.prev")
        );
        assert_eq!(
            state_path(p),
            Path::new("/etc/onetdns/example.com.zone.key.roll")
        );
    }

    #[test]
    fn from_interval_waits_are_bounded() {
        let t = RollTiming::from_interval(30 * 86_400);
        assert!(t.publish_wait >= 1 && t.publish_wait < t.interval);
        assert!(t.activate_wait >= 1 && t.activate_wait < t.interval);
        assert!(t.activate_wait > t.publish_wait);
    }
}
