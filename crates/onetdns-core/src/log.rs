//! Structured logging. Every line carries an `event=` code: messages change, but the code is a
//! stable contract that alerts and collectors match on. A line without one gets a code built
//! from the module path.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

/// Lower is more severe; threshold checks rely on this order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
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

/// Separates fields from the message, so a field value with spaces (a path, say) does not run
/// into it. Never printed.
pub const MESSAGE_SEPARATOR: char = '\u{1}';

/// Writes text with control characters escaped. Field values and messages carry outside input
/// such as query names: a raw newline would forge a log line, a raw separator would move fields
/// into the message, and an escape sequence would reach the operator's terminal.
#[doc(hidden)]
pub struct Escaped<'a>(pub &'a mut String);

impl std::fmt::Write for Escaped<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        for ch in text.chars() {
            if ch.is_control() {
                write!(self.0, "\\x{:02x}", u32::from(ch))?;
            } else {
                self.0.push(ch);
            }
        }
        Ok(())
    }
}

/// Highest level printed. Read lock-free on the hot path.
static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// 0 for one human-readable line, 1 for JSON Lines.
static FORMAT: AtomicU8 = AtomicU8::new(0);

/// `ONETDNS_LOG` sets the level and `ONETDNS_LOG_FORMAT=json` (or `jsonl`) the format. Unknown
/// values fall back to the defaults so a typo does not stop startup.
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

/// Ignores an unknown level: resetting it would drop the logs someone is reading while
/// diagnosing.
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

/// Checked before any argument is formatted, so a disabled level costs nothing.
#[inline]
pub fn enabled(level: Level) -> bool {
    (level as u8) <= THRESHOLD.load(Ordering::Relaxed)
}

/// Writes the line with one `writeln!` under the stderr lock; split writes interleave across
/// threads. `target` builds the fallback event code.
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

/// Splits at the separator the macro wrote; without one the whole body is the message.
fn split_body(body: &str) -> (&str, &str) {
    match body.find(MESSAGE_SEPARATOR) {
        Some(at) => (
            &body[..at],
            body[at + MESSAGE_SEPARATOR.len_utf8()..].trim(),
        ),
        None => ("", body.trim()),
    }
}

/// The event is printed at the front of the line, so the field would repeat it.
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

/// Time, level, event, message, then fields: a message after the fields is cut off at the
/// right edge of the screen. Target, pid, source and thread go to JSON only.
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

/// An empty value counts as none.
fn event_code(body: &str) -> Option<&str> {
    body.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("event="))
        .filter(|value| !value.is_empty())
}

/// Collectors match on this code, so it must stay stable for a module.
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

/// Escapes quotes, backslashes and C0 controls so outside input in the body cannot break the JSON.
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

/// ISO 8601 UTC with milliseconds.
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

/// Days since the Unix epoch to (year, month, day). Starting the year in March puts the leap
/// day last, so no branch is needed.
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

/// Every log macro goes through this. The threshold check comes first, so a disabled level
/// does not even evaluate its arguments.
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

/// `key = %value` uses Display, `key = ?value` Debug, and a bare name becomes its own key. The
/// last argument is the message.
#[macro_export]
macro_rules! log_fields {
    ($m:ident, $k:ident = %$v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($crate::log::Escaped(&mut $m), concat!(stringify!($k), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $k:ident = ?$v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($crate::log::Escaped(&mut $m), concat!(stringify!($k), "={:?} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $k:ident = $v:expr, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($crate::log::Escaped(&mut $m), concat!(stringify!($k), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, %$v:ident, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($crate::log::Escaped(&mut $m), concat!(stringify!($v), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $v:ident, $($rest:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = write!($crate::log::Escaped(&mut $m), concat!(stringify!($v), "={} "), $v);
        $crate::log_fields!($m, $($rest)+);
    }};
    ($m:ident, $($msg:tt)+) => {{
        use ::std::fmt::Write as _;
        let _ = $m.write_char($crate::log::MESSAGE_SEPARATOR);
        let _ = write!($crate::log::Escaped(&mut $m), $($msg)+);
    }};
}

/// For events that need an operator.
#[macro_export]
macro_rules! error { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Error, $($a)+) }; }
#[macro_export]
macro_rules! warn  { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Warn,  $($a)+) }; }
/// The default level: never once per query.
#[macro_export]
macro_rules! info  { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Info,  $($a)+) }; }
#[macro_export]
macro_rules! debug { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Debug, $($a)+) }; }
/// Per-query diagnostics.
#[macro_export]
macro_rules! trace { ($($a:tt)+) => { $crate::log_at!($crate::log::Level::Trace, $($a)+) }; }

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, event_code, fallback_event_code, human_line, json_escape, split_body,
        strip_event, Level, MESSAGE_SEPARATOR,
    };

    #[test]
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
    fn outside_input_cannot_forge_a_line_or_move_fields_into_the_message() {
        let name = "a\n2026-08-02T00:00:00.000Z ERROR  forged\u{1}x\u{1b}[2J\u{9b}.";
        let mut body = String::new();
        crate::log_fields!(body, event = "xfr.refused", zone = %name, "Refused {}", name);
        let (fields, message) = split_body(&body);
        let fields = strip_event(fields, event_code(&body));
        let line = human_line("t", Level::Warn, "xfr.refused", message, &fields);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        let escaped = "a\\x0a2026-08-02T00:00:00.000Z ERROR  forged\\x01x\\x1b[2J\\x9b.";
        assert_eq!(message, format!("Refused {escaped}"));
        assert_eq!(fields.as_ref(), format!("zone={escaped}"));
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(10_957 + 59), (2000, 2, 29), "윤년 2/29");
        assert_eq!(civil_from_days(20_652), (2026, 7, 18));
        assert_eq!(civil_from_days(20_653), (2026, 7, 19));
    }

    #[test]
    fn json_log_values_are_escaped() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn structured_event_code_is_extracted() {
        assert_eq!(
            event_code("event=config.applied count=2 설정 적용"),
            Some("config.applied")
        );
        assert_eq!(event_code("count=2 설정 적용"), None);
    }

    #[test]
    fn fallback_event_code_is_stable_and_machine_readable() {
        assert_eq!(
            fallback_event_code("onetdns_control::metrics", Level::Warn),
            "onetdns_control.metrics.warn"
        );
    }
}
