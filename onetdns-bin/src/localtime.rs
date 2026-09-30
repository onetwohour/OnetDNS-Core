/*!
 * @brief 지역 시각 변환.
 *
 * @details 정책 규칙의 시간 구간이 지역 시각 기준이다. 플랫폼마다 변환 함수가 달라 여기서
 *          가린다.
 * @note 변환에 실패하면 UTC로 전환한다. 시간 구간 판정이 조금 어긋나는 것이 아예 못 실행되는
 *       것보다 낫다.
 */

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(unix, target_env = "musl"))]
/**
 * @brief 이 플랫폼의 시각 형.
 * @details libc 크레이트가 musl 의 time_t 를 폐기 예정으로 표시해 두어, 32비트와 64비트
 *          모두 지금 정의와 같은 c_long 을 직접 쓴다. libc 가 time_t 를 바꾸면
 *          localtime_r 의 인자 형과 어긋나 컴파일 오류로 드러난다.
 */
type LocalTimeT = libc::c_long;
#[cfg(all(unix, not(target_env = "musl")))]
/** @brief 이 플랫폼의 시각 표현. */
type LocalTimeT = libc::time_t;
#[cfg(not(unix))]
/** @brief 시각 표현. 플랫폼 정의가 없으면 64비트로 둔다. */
type LocalTimeT = i64;

#[cfg(unix)]
/** @brief 이 플랫폼의 분해된 시각 구조. */
type LocalTm = libc::tm;

#[cfg(not(unix))]
#[repr(C)]
/** @brief 분해된 시각. 플랫폼이 주지 않으면 직접 정의한다. */
struct LocalTm {
    /** @brief 초. */
    tm_sec: i32,
    /** @brief 분. */
    tm_min: i32,
    /** @brief 시. */
    tm_hour: i32,
    /** @brief 일. */
    tm_mday: i32,
    /** @brief 월. 0부터 센다. */
    tm_mon: i32,
    /** @brief 1900년부터 흐른 해. */
    tm_year: i32,
    /** @brief 요일. 일요일이 0이다. */
    tm_wday: i32,
    /** @brief 그 해의 며칠째인지. */
    tm_yday: i32,
    /** @brief 여름 시간이 걸려 있는지. */
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
    /** @brief 플랫폼의 지역 시각 변환. */
    fn localtime64_s(output: *mut LocalTm, time: *const LocalTimeT) -> i32;
}

/** @brief 유닉스 기원부터 흐른 초. 기원보다 앞선 시각은 0으로 본다. */
pub fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/** @brief 지금의 지역 요일과 하루 중 분. 시간 구간 판정에 쓴다. */
pub fn local_weekday_minute(now: SystemTime) -> (u8, u16) {
    let seconds = unix_seconds(now);
    local_weekday_minute_from_unix(seconds).unwrap_or_else(|| {
        /** @brief UTC로 전환했음을 한 번만 알린다. 질의마다 호출되는 경로라 되풀이하면 안 된다. */
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            onetdns_core::warn!(event = "policy.localtime_fallback", "Could not convert to local time; using UTC, so time-of-day policy rules may fire at the wrong time");
        });
        utc_parts(seconds)
    })
}

/** @brief 지역 시각으로 일요일 0시부터 흐른 분. 시간대 규칙이 쓰는 값이다. */
pub fn local_minute_of_week(now: SystemTime) -> u32 {
    let (weekday, minute) = local_weekday_minute(now);
    u32::from(weekday) * 1_440 + u32::from(minute)
}

/** @brief UTC 기준 요일과 분. 지역 변환이 실패했을 때 쓴다. */
fn utc_parts(seconds: u64) -> (u8, u16) {
    let weekday = ((seconds / 86_400 + 4) % 7) as u8;
    let minute = ((seconds % 86_400) / 60) as u16;
    (weekday, minute)
}

/** @brief Unix 초에서 지역 요일과 분. 변환이 실패하면 없다. */
fn local_weekday_minute_from_unix(seconds: u64) -> Option<(u8, u16)> {
    let time: LocalTimeT = seconds.try_into().ok()?;
    let mut local: LocalTm = unsafe { std::mem::zeroed() };
    #[cfg(unix)]
    let ok = unsafe { !libc::localtime_r(&time, &mut local).is_null() };
    #[cfg(windows)]
    let ok = unsafe { localtime64_s(&mut local, &time) == 0 };
    #[cfg(not(any(unix, windows)))]
    let ok = false;
    if !ok
        || !(0..=6).contains(&local.tm_wday)
        || !(0..=23).contains(&local.tm_hour)
        || !(0..=59).contains(&local.tm_min)
    {
        return None;
    }
    Some((
        local.tm_wday as u8,
        (local.tm_hour as u16) * 60 + local.tm_min as u16,
    ))
}

#[cfg(test)]
/** @brief 정책 시각이 주 범위 안에 머무는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 합친 값이 한 주 범위를 벗어나지 않는지. */
    fn policy_time_stays_in_one_week() {
        let value = local_minute_of_week(UNIX_EPOCH);
        assert!(value < 7 * 1_440);
    }

    #[test]
    /** @brief 합친 값에서 요일과 하루 중 분을 그대로 되찾는지. */
    fn minute_of_week_round_trips_weekday_and_minute() {
        let now = SystemTime::now();
        let (weekday, minute) = local_weekday_minute(now);
        let folded = local_minute_of_week(now);
        assert_eq!(folded / 1_440, u32::from(weekday));
        assert_eq!(folded % 1_440, u32::from(minute));
    }
}
