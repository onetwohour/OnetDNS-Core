//! Local time for policy schedules and the console. Conversion differs per platform.
//!
//! Falls back to UTC when conversion fails: a schedule slightly off beats one that never runs.

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(unix, target_env = "musl"))]
/// The libc crate marks musl's time_t deprecated, so this uses c_long, its current definition on
/// 32- and 64-bit. If libc changes time_t, the mismatch with localtime_r's argument type fails the
/// build.
type LocalTimeT = libc::c_long;
#[cfg(all(unix, not(target_env = "musl")))]
type LocalTimeT = libc::time_t;
#[cfg(not(unix))]
type LocalTimeT = i64;

#[cfg(unix)]
type LocalTm = libc::tm;

#[cfg(not(unix))]
#[repr(C)]
/// C `struct tm`, for localtime64_s.
struct LocalTm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
}

#[cfg(all(windows, not(target_feature = "crt-static")))]
#[link(name = "msvcrt")]
unsafe extern "C" {}

#[cfg(all(windows, target_feature = "crt-static"))]
#[link(name = "libcmt")]
unsafe extern "C" {}

#[cfg(windows)]
unsafe extern "C" {
    #[link_name = "_localtime64_s"]
    fn localtime64_s(output: *mut LocalTm, time: *const LocalTimeT) -> i32;
}

/// 0 before the epoch.
pub fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn local_weekday_minute(now: SystemTime) -> (u8, u16) {
    let seconds = unix_seconds(now);
    local_weekday_minute_from_unix(seconds).unwrap_or_else(|| {
        /// Per-query path; warn once.
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            onetdns_core::warn!(event = "policy.localtime_fallback", "Could not convert to local time; using UTC, so time-of-day policy rules may fire at the wrong time");
        });
        utc_parts(seconds)
    })
}

/// Minutes since Sunday 00:00, local time.
pub fn local_minute_of_week(now: SystemTime) -> u32 {
    let (weekday, minute) = local_weekday_minute(now);
    u32::from(weekday) * 1_440 + u32::from(minute)
}

fn utc_parts(seconds: u64) -> (u8, u16) {
    let weekday = ((seconds / 86_400 + 4) % 7) as u8;
    let minute = ((seconds % 86_400) / 60) as u16;
    (weekday, minute)
}

/// Hour, minute and second, falling back to UTC.
pub fn local_clock(now: SystemTime) -> (u8, u8, u8) {
    let seconds = unix_seconds(now);
    match local_tm(seconds) {
        Some(local) if (0..=60).contains(&local.tm_sec) => (
            local.tm_hour as u8,
            local.tm_min as u8,
            local.tm_sec.min(59) as u8,
        ),
        _ => {
            let of_day = seconds % 86_400;
            (
                (of_day / 3600) as u8,
                (of_day % 3600 / 60) as u8,
                (of_day % 60) as u8,
            )
        }
    }
}

fn local_weekday_minute_from_unix(seconds: u64) -> Option<(u8, u16)> {
    let local = local_tm(seconds)?;
    if !(0..=6).contains(&local.tm_wday) {
        return None;
    }
    Some((
        local.tm_wday as u8,
        (local.tm_hour as u16) * 60 + local.tm_min as u16,
    ))
}

/// `None` when conversion fails or the hour or minute is out of range.
fn local_tm(seconds: u64) -> Option<LocalTm> {
    let time: LocalTimeT = seconds.try_into().ok()?;
    let mut local: LocalTm = unsafe { std::mem::zeroed() };
    #[cfg(unix)]
    let ok = unsafe { !libc::localtime_r(&time, &mut local).is_null() };
    #[cfg(windows)]
    let ok = unsafe { localtime64_s(&mut local, &time) == 0 };
    #[cfg(not(any(unix, windows)))]
    let ok = false;
    (ok && (0..=23).contains(&local.tm_hour) && (0..=59).contains(&local.tm_min)).then_some(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_time_is_in_range() {
        for when in [UNIX_EPOCH, SystemTime::now()] {
            let (hour, minute, second) = local_clock(when);
            assert!(hour < 24 && minute < 60 && second < 60);
        }
    }

    #[test]
    fn policy_time_stays_in_one_week() {
        let value = local_minute_of_week(UNIX_EPOCH);
        assert!(value < 7 * 1_440);
    }

    #[test]
    fn minute_of_week_round_trips_weekday_and_minute() {
        let now = SystemTime::now();
        let (weekday, minute) = local_weekday_minute(now);
        let folded = local_minute_of_week(now);
        assert_eq!(folded / 1_440, u32::from(weekday));
        assert_eq!(folded % 1_440, u32::from(minute));
    }
}
