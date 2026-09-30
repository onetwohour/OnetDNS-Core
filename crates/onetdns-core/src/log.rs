/*!
 * @brief 구조화 로깅.
 *
 * @details 모든 기록은 event= 코드를 갖는다. 사람이 읽는 문구는 바뀌지만 이벤트 코드는
 *          안정된 계약이라, 경보와 로그 수집이 문구 변경에 깨지지 않는다. 코드가 없는
 *          기록에는 모듈 경로에서 만든 대체 코드를 붙인다.
 */

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/** @brief 로그 심각도. 값이 작을수록 심각하며 임계값 비교가 이 순서에 기댄다. */
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /** @brief 그대로 두면 서비스가 어긋난다. */
    Error = 0,
    /** @brief 눈여겨봐야 한다. */
    Warn = 1,
    /** @brief 평소에 남길 것. */
    Info = 2,
    /** @brief 문제를 좇을 때만 남길 것. */
    Debug = 3,
    /** @brief 아주 자세한 것. */
    Trace = 4,
}

impl Level {
    /** @brief 출력에 쓰는 대문자 표기. */
    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

/**
 * @brief 필드와 사람이 읽을 문구를 구분하는 표식.
 * @details 값에 공백이 든 필드(경로 따위)가 있어도 문구가 잘리지 않게 매크로가 여기에
 *          넣는다. 출력에는 나가지 않는다.
 */
pub const MESSAGE_SEPARATOR: char = '\u{1}';

/** @brief 현재 로그 임계값. 이 값 이하 심각도만 출력한다. 무잠금으로 읽어야 핫패스가 안 눌린다. */
static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);

/** @brief 출력 형식. 0이면 사람이 읽는 한 줄, 1이면 JSON Lines다. */
static FORMAT: AtomicU8 = AtomicU8::new(0);

/**
 * @brief 환경 변수에서 로그 수준과 형식을 읽는다.
 * @details ONETDNS_LOG가 수준, ONETDNS_LOG_FORMAT이 json/jsonl이면 JSON 출력이다.
 *          알 수 없는 값은 기본값으로 바꾼다. 오타 하나로 시작이 막히지 않게 한다.
 */
pub fn init_from_env() {
    let v = std::env::var("ONETDNS_LOG")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lvl = match v.as_str() {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => Level::Info,
    };
    THRESHOLD.store(lvl as u8, Ordering::Relaxed);
    let format = std::env::var("ONETDNS_LOG_FORMAT")
        .map(|value| {
            let value = value.trim();
            value.eq_ignore_ascii_case("json") || value.eq_ignore_ascii_case("jsonl")
        })
        .unwrap_or(false);
    FORMAT.store(u8::from(format), Ordering::Relaxed);
}

/**
 * @brief 실행 중에 로그 수준을 바꾼다. 컨트롤 플레인이 호출한다.
 * @note 알 수 없는 문자열은 조용히 무시한다. 잘못된 입력으로 수준이 초기화되면 진단 중에
 *       보고 있던 로그가 갑자기 사라진다.
 */
pub fn set_level_str(s: &str) {
    let lvl = match s.trim().to_ascii_lowercase().as_str() {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "info" => Level::Info,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => return,
    };
    THRESHOLD.store(lvl as u8, Ordering::Relaxed);
}

/**
 * @brief 이 수준이 출력 대상인지.
 * @details 로그 매크로가 인자를 포맷하기 전에 이걸 본다. 꺼진 수준의 기록은 문자열
 *          조립 비용조차 들지 않는다.
 */
#[inline]
pub fn enabled(level: Level) -> bool {
    (level as u8) <= THRESHOLD.load(Ordering::Relaxed)
}

/**
 * @brief 완성된 기록 한 줄을 표준 오류로 내보낸다.
 *
 * @param target 모듈 경로. 본문에 event=가 없을 때 대체 코드의 재료가 된다.
 * @note 표준 오류를 잠근 채 한 번의 writeln!으로 쓴다. 여러 번 쪼개 쓰면 스레드끼리
 *       줄이 섞인다.
 */
pub fn emit_with_context(level: Level, target: &str, file: &str, line: u32, body: &str) {
    let timestamp = utc_timestamp();
    let body = body.trim_end();
    let fallback_event = fallback_event_code(target, level);
    let matched_event = event_code(body);
    let event = matched_event.unwrap_or(&fallback_event);
    let pid = std::process::id();
    let json = FORMAT.load(Ordering::Relaxed) == 1;

    let (raw_fields, message) = split_body(body);
    let fields = strip_event(raw_fields, matched_event);
    let fields = fields.as_ref();

    let mut out = std::io::stderr().lock();
    if json {
        let current = std::thread::current();
        let thread = current.name().unwrap_or("unnamed");
        let _ = writeln!(
            out,
            "{{\"ts\":\"{}\",\"level\":\"{}\",\"event\":\"{}\",\"target\":\"{}\",\"pid\":{},\"thread\":\"{}\",\"source\":\"{}:{}\",\"message\":\"{}\"}}",
            json_escape(&timestamp),
            level.label(),
            json_escape(event),
            json_escape(target),
            pid,
            json_escape(thread),
            json_escape(file),
            line,
            json_escape(&body.replace(MESSAGE_SEPARATOR, ""))
        );
    } else {
        let _ = writeln!(
            out,
            "{}",
            human_line(&timestamp, level, event, message, fields)
        );
    }
}

/**
 * @brief 본문을 필드와 사람이 읽을 문구로 구분한다.
 *
 * @details 매크로가 넣은 표식으로 나눈다. 공백으로 나누면 값에 공백이 든 필드(경로 따위)의
 *          뒷부분이 문구로 넘어간다.
 * @return (필드, 문구). 표식이 없으면 전부 문구로 본다. 매크로를 거치지 않고 부른 경우다.
 */
fn split_body(body: &str) -> (&str, &str) {
    match body.find(MESSAGE_SEPARATOR) {
        Some(at) => (
            &body[..at],
            body[at + MESSAGE_SEPARATOR.len_utf8()..].trim(),
        ),
        None => ("", body.trim()),
    }
}

/**
 * @brief 필드에서 event= 하나를 걷어낸다.
 * @details event는 줄 앞자리에 따로 찍으므로, 남겨 두면 같은 값이 한 줄에 두 번 나온다.
 * @param code 본문에서 실제로 뽑힌 코드. 없으면 그대로 둔다.
 */
fn strip_event<'a>(fields: &'a str, code: Option<&str>) -> std::borrow::Cow<'a, str> {
    match code {
        Some(code) => std::borrow::Cow::Owned(
            fields
                .replacen(&format!("event={code}"), "", 1)
                .trim()
                .to_string(),
        ),
        None => std::borrow::Cow::Borrowed(fields.trim()),
    }
}

/**
 * @brief 사람이 읽을 한 줄을 만든다.
 *
 * @details 순서는 「언제·얼마나 심각한지·무슨 일인지·무슨 뜻인지·자세한 값」이다. 문구를
 *          필드 뒤에 두면 화면 오른쪽 끝에서 잘려 정작 읽어야 할 것이 안 보인다.
 * @note target, pid, 소스 위치, 스레드 이름은 넣지 않는다. 운영자가 읽는 줄에는 쓸모가 없고
 *       읽는 것을 방해하기만 한다. 수집기가 볼 JSON 쪽에는 그대로 있다.
 * @return 줄바꿈 없는 한 줄. 호출자가 한 번의 writeln으로 내보내야 스레드끼리 섞이지 않는다.
 */
fn human_line(timestamp: &str, level: Level, event: &str, message: &str, fields: &str) -> String {
    use std::fmt::Write as _;
    let mut out =
        String::with_capacity(timestamp.len() + event.len() + message.len() + fields.len() + 32);
    let _ = write!(out, "{} {:<5} {}", timestamp, level.label(), event);
    if !message.is_empty() {
        let _ = write!(out, "  {message}");
    }
    if !fields.is_empty() {
        let _ = write!(out, "  {fields}");
    }
    out
}

/** @brief 본문에서 event= 필드 값을 추출한다. 빈 값은 없는 것으로 본다. */
fn event_code(body: &str) -> Option<&str> {
    body.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("event="))
        .filter(|value| !value.is_empty())
}

/**
 * @brief event=가 없는 기록에 붙일 대체 코드를 만든다.
 * @details 모듈 경로의 구분자를 점으로 접고 수준을 덧붙인다. 결과가 안정적이어야 수집기가
 *          이 코드로 규칙을 걸 수 있다.
 */
fn fallback_event_code(target: &str, level: Level) -> String {
    let mut event = String::with_capacity(target.len() + 8);
    for ch in target.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            event.push(ch.to_ascii_lowercase());
        } else if (ch == ':' || ch == '-' || ch == '.') && !event.ends_with('.') {
            event.push('.');
        }
    }
    while event.ends_with('.') {
        event.pop();
    }
    if event.is_empty() {
        event.push_str("onetdns");
    }
    event.push('.');
    event.push_str(level.label().to_ascii_lowercase().as_str());
    event
}

/**
 * @brief JSON 문자열 값으로 이스케이프한다.
 * @warning 로그 본문에는 질의 이름 같은 외부 입력이 섞인다. 이스케이프를 빠뜨리면 그 입력이
 *          JSON 구조를 깨뜨려 로그 위조가 가능해진다. 제어문자까지 \uXXXX로 바꾼다.
 */
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch <= '\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out
}

/** @brief 밀리초까지 담은 ISO 8601 UTC 시각. */
fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/**
 * @brief 유닉스 epoch 이후 일수를 (년, 월, 일)로 바꾼다.
 * @details 3월을 해의 시작으로 잡는 시대(era) 기반 변환이라, 윤년 보정이 2월을 마지막 달로
 *          밀어내 분기 없이 처리된다.
 */
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

/**
 * @brief 수준을 지정해 기록한다. 다른 로그 매크로가 전부 이걸 거친다.
 * @details 임계값 확인이 본문 조립보다 먼저다. 꺼진 수준에서는 인자 평가조차 일어나지 않는다.
 */
#[macro_export]
macro_rules! log_at {
    ($lvl:expr, $($rest:tt)+) => {{
        if $crate::log::enabled($lvl) {
            let mut __body = ::std::string::String::new();
            $crate::log_fields!(__body, $($rest)+);
            $crate::log::emit_with_context(
                $lvl,
                module_path!(),
                file!(),
                line!(),
                &__body,
            );
        }
    }};
}

/**
 * @brief 키=값 필드를 본문에 이어 붙인다. 마지막 인자는 사람이 읽을 문구다.
 * @details %는 Display, ?는 Debug로 쓴다. 이름만 준 경우 변수명이 그대로 키가 된다.
 */
#[macro_export]
macro_rules! log_fields {
    ($m:ident, $k:ident = %$v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($m, concat!(stringify!($k), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $k:ident = ?$v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($m, concat!(stringify!($k), "={:?} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $k:ident = $v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($m, concat!(stringify!($k), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, %$v:ident, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($m, concat!(stringify!($v), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $v:ident, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($m, concat!(stringify!($v), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $($msg:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = $m.write_char($crate::log::MESSAGE_SEPARATOR);
        let _ = write!($m, $($msg)+);
    }};
}

/** @brief 오류 기록. 운영자 개입이 필요한 이벤트에만 쓴다. */
#[macro_export]
macro_rules! error { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Error, $($a)+) }; }
/** @brief 경고 기록. 동작은 계속되지만 주의가 필요한 상태다. */
#[macro_export]
macro_rules! warn  { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Warn,  $($a)+) }; }
/** @brief 정보 기록. 기본 수준이므로 질의마다 남기면 안 된다. */
#[macro_export]
macro_rules! info  { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Info,  $($a)+) }; }
/** @brief 디버그 기록. */
#[macro_export]
macro_rules! debug { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Debug, $($a)+) }; }
/** @brief 추적 기록. 질의 단위 상세 진단용이다. */
#[macro_export]
macro_rules! trace { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Trace, $($a)+) }; }

#[cfg(test)]
/** @brief 날짜 계산, 문자 감싸기, 그리고 이벤트 코드가 기계로 읽히는지. */
mod tests {
    use super::{
        civil_from_days, event_code, fallback_event_code, human_line, json_escape, split_body,
        strip_event, Level, MESSAGE_SEPARATOR,
    };

    #[test]
    /** @brief 사람이 읽는 줄에 event가 두 번 나오지 않고 문구가 앞에 오는지. */
    fn human_line_shows_the_message_before_the_fields_and_never_repeats_the_event() {
        let body = format!(
            "event=do53.started addr=127.0.0.1:53 udp=true{MESSAGE_SEPARATOR}Listening for plain DNS"
        );
        let (fields, message) = split_body(&body);
        let code = event_code(&body);
        let fields = strip_event(fields, code);
        assert_eq!(message, "Listening for plain DNS");
        assert_eq!(fields.as_ref(), "addr=127.0.0.1:53 udp=true");

        let line = human_line(
            "2026-08-02T00:00:00.000Z",
            Level::Info,
            code.unwrap(),
            message,
            fields.as_ref(),
        );
        assert_eq!(
            line,
            "2026-08-02T00:00:00.000Z INFO  do53.started  Listening for plain DNS  addr=127.0.0.1:53 udp=true"
        );
        assert_eq!(line.matches("do53.started").count(), 1, "event는 한 번만");
        assert!(!line.contains("event="), "event= 필드는 앞자리로 올라간다");
    }

    #[test]
    /** @brief 값에 공백이 있어도 문구가 잘리지 않는지. */
    fn a_field_value_with_spaces_does_not_leak_into_the_message() {
        let body = format!(
            "event=cert.loaded path=C:\\Program Files\\onetdns\\a.pem{MESSAGE_SEPARATOR}인증서를 읽었습니다"
        );
        let (fields, message) = split_body(&body);
        assert_eq!(message, "인증서를 읽었습니다");
        assert_eq!(
            strip_event(fields, event_code(&body)).as_ref(),
            "path=C:\\Program Files\\onetdns\\a.pem"
        );
    }

    #[test]
    /** @brief 경고 줄도 문구와 값에서 끝나고 소스 위치나 스레드 이름을 붙이지 않는지. */
    fn warnings_end_with_the_fields() {
        let line = human_line(
            "2026-08-02T00:00:00.000Z",
            Level::Warn,
            "cert.reload_failed",
            "인증서를 다시 읽지 못했습니다",
            "path=/x",
        );
        assert_eq!(
            line,
            "2026-08-02T00:00:00.000Z WARN  cert.reload_failed  인증서를 다시 읽지 못했습니다  path=/x"
        );
    }

    #[test]
    /** @brief 날짜 계산이 알려진 날과 맞는지. */
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(10_957 + 59), (2000, 2, 29), "윤년 2/29");
        assert_eq!(civil_from_days(20_652), (2026, 7, 18));
        assert_eq!(civil_from_days(20_653), (2026, 7, 19));
    }

    #[test]
    /** @brief 로그 값이 감싸져 형식을 깨지 않는지. */
    fn json_log_values_are_escaped() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    /** @brief 로그에서 이벤트 코드가 뽑히는지. */
    fn structured_event_code_is_extracted() {
        assert_eq!(
            event_code("event=config.applied count=2 설정 적용"),
            Some("config.applied")
        );
        assert_eq!(event_code("count=2 설정 적용"), None);
    }

    #[test]
    /** @brief 코드를 안 적은 로그도 기계로 가를 수 있는 값을 갖는지. */
    fn fallback_event_code_is_stable_and_machine_readable() {
        assert_eq!(
            fallback_event_code("onetdns_control::metrics", Level::Warn),
            "onetdns_control.metrics.warn"
        );
    }
}
