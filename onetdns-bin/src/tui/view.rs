//! What the console shows. Built from plain values, so it is tested without a terminal.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use onetdns_core::log::Level;
use onetdns_forward::UpstreamStatReport;

const LOG_LINES: usize = 2000;
/// A second q within this time quits.
const QUIT_WINDOW: Duration = Duration::from_secs(3);
const LABEL_WIDTH: usize = 12;
const MAX_LISTENER_ROWS: usize = 3;
const MAX_UPSTREAM_ROWS: usize = 4;
/// The status rows give way so the log keeps at least this many.
const MIN_LOG_ROWS: usize = 3;

const RESET: &str = "\x1b[0m";
const REVERSE: &str = "\x1b[7m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Key {
    Char(char),
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Interrupt,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Action {
    None,
    Quit,
    SetLevel(Level),
}

struct Entry {
    /// `None` for lines the server prints itself, such as the dashboard address.
    level: Option<Level>,
    time: String,
    text: String,
}

pub(super) struct Log {
    entries: VecDeque<Entry>,
    /// Sequence number of the oldest entry.
    first: u64,
}

impl Log {
    pub(super) const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            first: 0,
        }
    }

    pub(super) fn push(&mut self, level: Option<Level>, time: String, text: String) {
        if self.entries.len() == LOG_LINES {
            self.entries.pop_front();
            self.first += 1;
        }
        self.entries.push_back(Entry { level, time, text });
    }

    /// One past the newest entry.
    fn end(&self) -> u64 {
        self.first + self.entries.len() as u64
    }

    fn get(&self, seq: u64) -> Option<&Entry> {
        self.entries
            .get(usize::try_from(seq.checked_sub(self.first)?).ok()?)
    }
}

#[derive(Default)]
pub(super) struct View {
    /// One past the bottom entry while paused or scrolled; `None` follows new lines.
    bottom: Option<u64>,
    quit_armed: Option<Instant>,
    /// Log rows on the last frame, for paging.
    page: usize,
}

impl View {
    pub(super) fn key(&mut self, key: Key, log: &Log, level: Level, now: Instant) -> Action {
        let armed = self
            .quit_armed
            .take()
            .is_some_and(|at| now - at < QUIT_WINDOW);
        let end = log.end();
        let current = self.bottom.unwrap_or(end);
        let page = self.page.max(1) as u64;
        let top = (log.first + 1).min(end);
        let scroll_to = |bottom: u64| (bottom < end).then_some(bottom.max(top));
        match key {
            Key::Interrupt => return Action::Quit,
            Key::Char('q' | 'Q') if armed => return Action::Quit,
            Key::Char('q' | 'Q') => self.quit_armed = Some(now),
            Key::Char('p' | 'P') => {
                self.bottom = match self.bottom {
                    Some(_) => None,
                    None => Some(end),
                }
            }
            Key::Char('l' | 'L') => return Action::SetLevel(next_level(level)),
            Key::Up => self.bottom = Some(current.saturating_sub(1).max(top)),
            Key::PageUp => self.bottom = Some(current.saturating_sub(page).max(top)),
            Key::Down => self.bottom = scroll_to(current + 1),
            Key::PageDown => self.bottom = scroll_to(current + page),
            Key::Home => self.bottom = Some((log.first + page).min(end)),
            Key::End => self.bottom = None,
            Key::Char(_) => {}
        }
        Action::None
    }

    pub(super) fn expire(&mut self, now: Instant) {
        if self
            .quit_armed
            .is_some_and(|at| now.saturating_duration_since(at) >= QUIT_WINDOW)
        {
            self.quit_armed = None;
        }
    }
}

/// Error, warn, info, debug, then back to error.
fn next_level(level: Level) -> Level {
    match level {
        Level::Error => Level::Warn,
        Level::Warn => Level::Info,
        Level::Info => Level::Debug,
        Level::Debug | Level::Trace => Level::Error,
    }
}

pub(super) struct Traffic {
    /// `None` until a second has been measured.
    pub(super) per_second: Option<f64>,
    pub(super) total: u64,
    pub(super) blocked: u64,
    pub(super) cache_hit_pct: f64,
    pub(super) latency_ms: f64,
}

pub(super) struct Status {
    pub(super) version: &'static str,
    /// Mode and backend; `None` before the first configuration loads.
    pub(super) serving: Option<(&'static str, &'static str)>,
    pub(super) uptime: Duration,
    pub(super) traffic: Option<Traffic>,
    pub(super) dashboard: Option<String>,
    /// Kind and bound address.
    pub(super) listeners: Vec<(&'static str, String)>,
    pub(super) upstreams: Vec<UpstreamStatReport>,
    pub(super) level: Level,
}

/// Screen rows, each exactly as wide as the screen except the last, which stops one column short
/// so a terminal that wraps at the margin does not scroll.
pub(super) fn render(
    status: &Status,
    log: &Log,
    view: &mut View,
    cols: usize,
    rows: usize,
) -> Vec<String> {
    if rows == 0 || cols == 0 {
        return Vec::new();
    }
    let mut top = vec![title(status, cols)];
    top.extend(status_rows(status, cols));
    let footer = footer(view, cols.saturating_sub(1));
    let room = rows.saturating_sub(1);
    let keep_top = room.saturating_sub(MIN_LOG_ROWS + 1).max(1).min(top.len());
    top.truncate(keep_top.min(room));

    let mut out = top;
    if out.len() < room {
        out.push(log_bar(status, view, cols));
    }
    let pane = room - out.len();
    view.page = pane;
    out.extend(log_rows(log, view, cols, pane));
    if rows > out.len() {
        out.push(footer);
    }
    out
}

fn title(status: &Status, cols: usize) -> String {
    let mut row = Row::new(cols);
    row.style(REVERSE);
    row.text(&format!(" OnetDNS {}", status.version));
    if let Some((mode, backend)) = status.serving {
        row.text(&format!("   {mode}, {backend}"));
    }
    row.text(&format!("   up {}", uptime(status.uptime)));
    row.fill();
    row.finish()
}

fn status_rows(status: &Status, cols: usize) -> Vec<String> {
    let mut rows = Vec::new();
    if let Some(traffic) = &status.traffic {
        let rate = traffic
            .per_second
            .map_or("-".to_string(), |rate| format!("{rate:.1}"));
        let blocked = percent(traffic.blocked, traffic.total);
        let mut row = Row::new(cols);
        row.text(&format!(
            " queries/s {rate}   total {}   blocked {blocked}   cache hits {:.1}%   latency {:.1} ms",
            traffic.total, traffic.cache_hit_pct, traffic.latency_ms
        ));
        rows.push(row.finish());
    }
    if let Some(url) = &status.dashboard {
        rows.push(labeled(cols, "dashboard", url));
    }
    let listeners: Vec<String> = status
        .listeners
        .iter()
        .map(|(kind, address)| format!("{kind} {address}"))
        .collect();
    rows.extend(packed(cols, "listening", &listeners, MAX_LISTENER_ROWS));
    let shown = status.upstreams.len().min(MAX_UPSTREAM_ROWS);
    for (index, upstream) in status.upstreams.iter().take(shown).enumerate() {
        let label = if index == 0 { "upstream" } else { "" };
        let answered = upstream.ok + upstream.fail;
        let detail = if answered == 0 {
            format!("{}   no answers yet", upstream.label)
        } else {
            format!(
                "{}   {:.0} ms   {} failed",
                upstream.label,
                upstream.ewma_ms,
                percent(upstream.fail, answered)
            )
        };
        rows.push(labeled(cols, label, &detail));
    }
    if status.upstreams.len() > shown {
        let more = format!("+{} more", status.upstreams.len() - shown);
        rows.push(labeled(cols, "", &more));
    }
    rows
}

fn log_bar(status: &Status, view: &View, cols: usize) -> String {
    let left = format!(" log   level {}", status.level.label().to_ascii_lowercase());
    let right = if view.bottom.is_some() { "paused " } else { "" };
    let mut row = Row::new(cols);
    row.style(REVERSE);
    row.text(&left);
    let gap = cols.saturating_sub(row.width + text_width(right));
    row.text(&" ".repeat(gap));
    row.text(right);
    row.fill();
    row.finish()
}

fn footer(view: &View, cols: usize) -> String {
    let text = if view.quit_armed.is_some() {
        " Press q again to quit"
    } else {
        " q quit   p pause   l level   Up/Down PgUp/PgDn scroll   End follow"
    };
    let mut row = Row::new(cols);
    row.style(REVERSE);
    row.text(text);
    row.fill();
    row.finish()
}

/// Entries end at the view's bottom and wrap; the oldest one shown may lose its first rows.
fn log_rows(log: &Log, view: &View, cols: usize, pane: usize) -> Vec<String> {
    let end = view.bottom.unwrap_or(log.end()).min(log.end());
    let mut rows: Vec<String> = Vec::with_capacity(pane);
    let mut seq = end;
    while rows.len() < pane && seq > log.first {
        seq -= 1;
        let Some(entry) = log.get(seq) else { break };
        let mut wrapped = entry_rows(entry, cols);
        wrapped.append(&mut rows);
        rows = wrapped;
    }
    let excess = rows.len().saturating_sub(pane);
    rows.drain(..excess);
    while rows.len() < pane {
        rows.push(" ".repeat(cols));
    }
    rows
}

fn entry_rows(entry: &Entry, cols: usize) -> Vec<String> {
    let (label, color) = match entry.level {
        Some(Level::Error) => ("ERROR", RED),
        Some(Level::Warn) => ("WARN ", YELLOW),
        Some(Level::Info) => ("INFO ", ""),
        Some(Level::Debug) => ("DEBUG", DIM),
        Some(Level::Trace) => ("TRACE", DIM),
        None => ("     ", ""),
    };
    let indent = if cols >= 40 { 15 } else { 0 };
    let mut rows = Vec::new();
    let mut row = Row::new(cols);
    row.text(&entry.time);
    row.text(" ");
    row.style(color);
    row.text(label);
    row.style(RESET);
    row.text(" ");
    for ch in entry.text.chars() {
        if !row.fits(ch) {
            rows.push(row.finish());
            row = Row::new(cols);
            row.text(&" ".repeat(indent));
        }
        row.push(ch);
    }
    rows.push(row.finish());
    rows
}

fn labeled(cols: usize, label: &str, value: &str) -> String {
    let mut row = Row::new(cols);
    row.text(&format!(" {label:<width$}", width = LABEL_WIDTH - 1));
    row.text(value);
    row.finish()
}

/// Items separated by spaces, continued on more rows; the last row says how many did not fit.
fn packed(cols: usize, label: &str, items: &[String], max_rows: usize) -> Vec<String> {
    let mut lines: Vec<Vec<&str>> = Vec::new();
    let mut width = 0;
    let room = cols.saturating_sub(LABEL_WIDTH).max(1);
    for item in items {
        let item_width = text_width(item) + 3;
        if lines.is_empty() || width + item_width > room {
            lines.push(Vec::new());
            width = 0;
        }
        lines.last_mut().expect("a line was pushed").push(item);
        width += item_width;
    }
    let shown: usize = lines.iter().take(max_rows).map(Vec::len).sum();
    lines.truncate(max_rows);
    let mut rows: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let mut value = line.join("   ");
        if index + 1 == lines.len() && shown < items.len() {
            let _ = write!(value, "   +{} more", items.len() - shown);
        }
        rows.push(labeled(cols, if index == 0 { label } else { "" }, &value));
    }
    rows
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "-".to_string();
    }
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

fn uptime(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m {}s", seconds / 60, seconds % 60),
        3600..=86_399 => format!("{}h {}m", seconds / 3600, seconds % 3600 / 60),
        _ => format!("{}d {}h", seconds / 86_400, seconds % 86_400 / 3600),
    }
}

/// Columns a character takes. Hangul, CJK and emoji take two. Control characters never get here:
/// the logger escapes them.
fn char_width(ch: char) -> usize {
    let wide = matches!(
        u32::from(ch),
        0x1100..=0x115F
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA000..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1F64F
            | 0x1F900..=0x1F9FF
            | 0x20000..=0x3FFFD
    );
    if wide {
        2
    } else {
        1
    }
}

fn text_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

/// One screen row: text cut at the width, then padded to it.
struct Row {
    out: String,
    width: usize,
    cols: usize,
}

impl Row {
    fn new(cols: usize) -> Self {
        Self {
            out: String::with_capacity(cols + 16),
            width: 0,
            cols,
        }
    }

    fn fits(&self, ch: char) -> bool {
        self.width + char_width(ch) <= self.cols
    }

    fn push(&mut self, ch: char) {
        if self.fits(ch) {
            self.width += char_width(ch);
            self.out.push(ch);
        }
    }

    fn text(&mut self, text: &str) {
        for ch in text.chars() {
            self.push(ch);
        }
    }

    fn style(&mut self, sgr: &str) {
        self.out.push_str(sgr);
    }

    fn fill(&mut self) {
        while self.width < self.cols {
            self.width += 1;
            self.out.push(' ');
        }
    }

    fn finish(mut self) -> String {
        self.fill();
        self.out.push_str(RESET);
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visible(row: &str) -> String {
        let mut out = String::new();
        let mut chars = row.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn status() -> Status {
        Status {
            version: "1.2.3",
            serving: Some(("personal", "forward")),
            uptime: Duration::from_secs(7_380),
            traffic: Some(Traffic {
                per_second: Some(12.0),
                total: 200,
                blocked: 50,
                cache_hit_pct: 60.0,
                latency_ms: 3.25,
            }),
            dashboard: Some("http://127.0.0.1:8553/".to_string()),
            listeners: vec![
                ("do53-udp", "127.0.0.1:53".to_string()),
                ("do53-tcp", "127.0.0.1:53".to_string()),
            ],
            upstreams: vec![UpstreamStatReport {
                label: "1.1.1.1:53".to_string(),
                queries: 10,
                ok: 9,
                fail: 1,
                ewma_ms: 12.4,
            }],
            level: Level::Info,
        }
    }

    fn log_with(count: usize) -> Log {
        let mut log = Log::new();
        for index in 0..count {
            log.push(
                Some(Level::Info),
                "12:00:00".to_string(),
                format!("line {index}"),
            );
        }
        log
    }

    #[test]
    fn every_row_fills_the_screen_except_the_last() {
        let mut view = View::default();
        let rows = render(&status(), &log_with(3), &mut view, 80, 20);
        assert_eq!(rows.len(), 20);
        for row in &rows[..19] {
            assert_eq!(text_width(&visible(row)), 80, "{row:?}");
        }
        assert_eq!(text_width(&visible(&rows[19])), 79);
        let text: Vec<String> = rows.iter().map(|row| visible(row)).collect();
        assert!(text[0].starts_with(" OnetDNS 1.2.3   personal, forward   up 2h 3m"));
        assert!(text[1].contains("queries/s 12.0   total 200   blocked 25.0%"));
        assert!(text[2].starts_with(" dashboard  http://127.0.0.1:8553/"));
        assert!(text[3].contains("do53-udp 127.0.0.1:53   do53-tcp 127.0.0.1:53"));
        assert!(text[4].contains("1.1.1.1:53   12 ms   10.0% failed"));
        assert!(text[5].starts_with(" log   level info"));
        assert!(text[8].contains("line 2"), "{:?}", text[8]);
        assert!(text[9].trim().is_empty());
    }

    #[test]
    fn a_short_screen_keeps_log_rows() {
        let mut view = View::default();
        let rows = render(&status(), &log_with(10), &mut view, 80, 8);
        assert_eq!(rows.len(), 8);
        assert!(view.page >= MIN_LOG_ROWS, "{}", view.page);
        assert!(visible(&rows[6]).contains("line 9"));
    }

    #[test]
    fn wide_characters_never_overflow_a_row() {
        let mut log = Log::new();
        log.push(
            Some(Level::Warn),
            "12:00:00".to_string(),
            "경로=C:\\Users\\홍길동\\설정".repeat(4),
        );
        let mut view = View::default();
        for row in render(&status(), &log, &mut view, 41, 12) {
            assert!(text_width(&visible(&row)) <= 41, "{row:?}");
        }
    }

    #[test]
    fn many_listeners_say_how_many_did_not_fit() {
        let items: Vec<String> = (0..40).map(|i| format!("doh 10.0.0.{i}:443")).collect();
        let rows = packed(60, "listening", &items, 2);
        assert_eq!(rows.len(), 2);
        let last = visible(&rows[1]);
        assert!(last.contains("more"), "{last}");
        let shown: usize = rows
            .iter()
            .map(|row| visible(row).matches("doh ").count())
            .sum();
        assert!(last.contains(&format!("+{} more", 40 - shown)), "{last}");
    }

    #[test]
    fn scrolling_stops_following_and_end_resumes() {
        let log = log_with(50);
        let now = Instant::now();
        let mut view = View {
            page: 10,
            ..View::default()
        };
        view.key(Key::Up, &log, Level::Info, now);
        assert_eq!(view.bottom, Some(49));
        view.key(Key::PageUp, &log, Level::Info, now);
        assert_eq!(view.bottom, Some(39));
        view.key(Key::Home, &log, Level::Info, now);
        assert_eq!(view.bottom, Some(10));
        view.key(Key::PageUp, &log, Level::Info, now);
        assert_eq!(view.bottom, Some(1), "the oldest line stays on screen");
        view.key(Key::PageDown, &log, Level::Info, now);
        view.key(Key::PageDown, &log, Level::Info, now);
        assert_eq!(view.bottom, Some(21));
        view.key(Key::End, &log, Level::Info, now);
        assert_eq!(view.bottom, None);
        view.key(Key::Char('p'), &log, Level::Info, now);
        assert_eq!(view.bottom, Some(50));
        view.key(Key::Down, &log, Level::Info, now);
        assert_eq!(
            view.bottom, None,
            "scrolling past the newest line follows again"
        );
    }

    #[test]
    fn a_paused_view_stays_put_while_lines_arrive() {
        let mut log = log_with(5);
        let mut view = View::default();
        view.key(Key::Char('p'), &log, Level::Info, Instant::now());
        log.push(Some(Level::Info), "12:00:01".to_string(), "new".to_string());
        let rows = render(&status(), &log, &mut view, 80, 20);
        let text: Vec<String> = rows.iter().map(|row| visible(row)).collect();
        assert!(!text.iter().any(|row| row.contains("new")));
        assert!(text[5].trim_end().ends_with("paused"));
    }

    #[test]
    fn quitting_takes_a_second_q_in_time() {
        let log = Log::new();
        let start = Instant::now();
        let press = |view: &mut View, key: char, after: Duration| {
            view.key(Key::Char(key), &log, Level::Info, start + after)
        };

        let mut view = View::default();
        assert_eq!(press(&mut view, 'q', Duration::ZERO), Action::None);
        assert_eq!(press(&mut view, 'q', Duration::from_secs(1)), Action::Quit);

        let mut view = View::default();
        press(&mut view, 'q', Duration::ZERO);
        assert_eq!(press(&mut view, 'q', QUIT_WINDOW), Action::None, "too late");

        let mut view = View::default();
        press(&mut view, 'q', Duration::ZERO);
        press(&mut view, 'x', Duration::ZERO);
        assert_eq!(
            press(&mut view, 'q', Duration::ZERO),
            Action::None,
            "another key disarms"
        );

        assert_eq!(
            View::default().key(Key::Interrupt, &log, Level::Info, start),
            Action::Quit
        );
    }

    #[test]
    fn the_level_key_cycles_through_four_levels() {
        let log = Log::new();
        let mut view = View::default();
        let mut level = Level::Trace;
        let mut seen = Vec::new();
        for _ in 0..5 {
            let Action::SetLevel(next) = view.key(Key::Char('l'), &log, level, Instant::now())
            else {
                panic!("l must set a level");
            };
            seen.push(next);
            level = next;
        }
        assert_eq!(
            seen,
            [
                Level::Error,
                Level::Warn,
                Level::Info,
                Level::Debug,
                Level::Error
            ]
        );
    }

    #[test]
    fn the_ring_drops_the_oldest_line() {
        let log = log_with(LOG_LINES + 5);
        assert_eq!(log.first, 5);
        assert_eq!(log.get(5).map(|entry| entry.text.as_str()), Some("line 5"));
        assert!(log.get(4).is_none());
    }
}
