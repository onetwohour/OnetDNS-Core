//! What the console shows. Built from plain values, so it is tested without a terminal.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use onetdns_core::log::Level;
use onetdns_forward::UpstreamStatReport;

const LOG_LINES: usize = 2000;
/// A second q within this time quits.
const QUIT_WINDOW: Duration = Duration::from_secs(3);
const LABEL_WIDTH: usize = 13;
const MAX_LISTENER_ROWS: usize = 3;
const MAX_UPSTREAM_ROWS: usize = 4;
/// The status rows give way so the log keeps at least this many.
const MIN_LOG_ROWS: usize = 3;
/// Rate samples kept for the graph, one a second.
pub(super) const RATE_HISTORY: usize = 60;
/// Below this, the metrics share one line of text instead of a tile each.
const MIN_TILE_WIDTH: usize = 14;
/// Shares of failed answers at which an upstream turns amber, then red.
const FLAKY: f64 = 0.05;
const FAILING: f64 = 0.2;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
// The dashboard's dark theme, as the nearest of the 256 standard terminal colors.
const ACCENT: &str = "\x1b[38;5;110m";
const OK: &str = "\x1b[38;5;108m";
const WARN: &str = "\x1b[38;5;179m";
const BAD: &str = "\x1b[38;5;174m";
const MUTED: &str = "\x1b[38;5;246m";
const LINE: &str = "\x1b[38;5;239m";
/// The title and key bars, which set their own text color so a light terminal stays readable.
const BAR: &str = "\x1b[48;5;236;38;5;252m";

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
    /// Empty for lines the server prints itself.
    event: String,
    message: String,
    fields: String,
}

impl Entry {
    fn parts(&self) -> impl Iterator<Item = &str> {
        [&self.event, &self.message, &self.fields]
            .into_iter()
            .map(String::as_str)
            .filter(|part| !part.is_empty())
    }
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

    pub(super) fn push(
        &mut self,
        level: Option<Level>,
        time: String,
        event: &str,
        message: &str,
        fields: &str,
    ) {
        if self.entries.len() == LOG_LINES {
            self.entries.pop_front();
            self.first += 1;
        }
        self.entries.push_back(Entry {
            level,
            time,
            event: event.to_string(),
            message: message.to_string(),
            fields: fields.to_string(),
        });
    }

    /// Each entry as a line of plain text, oldest first.
    pub(super) fn lines(&self) -> impl Iterator<Item = String> + '_ {
        self.entries.iter().map(|entry| {
            let mut line = entry.time.clone();
            for part in entry.parts() {
                line.push_str("  ");
                line.push_str(part);
            }
            line
        })
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
    /// The last RATE_HISTORY rates, oldest first.
    pub(super) recent: Vec<f64>,
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
    let mut row = Row::bar(cols);
    row.paint(ACCENT);
    row.text(" ◆ ");
    row.plain();
    row.add(BOLD);
    row.text("OnetDNS");
    row.paint(MUTED);
    row.text(&format!(" {}", status.version));
    if let Some((mode, backend)) = status.serving {
        row.plain();
        row.text(&format!("   {mode} · {backend}"));
    }
    let (dot, state) = match status.serving {
        Some(_) => (OK, "serving"),
        None => (WARN, "starting"),
    };
    let up = format!("up {}", uptime(status.uptime));
    let right = 2 + text_width(state) + 3 + text_width(&up) + 1;
    if row.width + 3 + right <= cols {
        row.plain();
        row.pad_to(cols - right);
        row.paint(dot);
        row.text("● ");
        row.plain();
        row.text(state);
        row.paint(MUTED);
        row.text(&format!("   {up} "));
    }
    row.plain();
    row.finish()
}

fn status_rows(status: &Status, cols: usize) -> Vec<String> {
    let mut rows = Vec::new();
    if let Some(traffic) = &status.traffic {
        rows.extend(metric_rows(traffic, cols));
    }
    if let Some(url) = &status.dashboard {
        let mut row = Row::new(cols);
        label(&mut row, "Dashboard");
        row.paint(ACCENT);
        row.text(url);
        rows.push(row.finish());
    }
    rows.extend(listener_rows(cols, &status.listeners, MAX_LISTENER_ROWS));
    rows.extend(upstream_rows(cols, &status.upstreams));
    rows
}

/// What a metric tile draws after its value.
enum Gauge {
    None,
    Rates,
    /// A percentage, in a color.
    Share(f64, &'static str),
}

/// A label row over a value row, one tile per metric.
fn metric_rows(traffic: &Traffic, cols: usize) -> Vec<String> {
    let rate = traffic
        .per_second
        .map_or("-".to_string(), |rate| format!("{rate:.1}"));
    let blocked =
        (traffic.total > 0).then(|| traffic.blocked as f64 * 100.0 / traffic.total as f64);
    let tiles = [
        ("QUERIES/S", rate, Gauge::Rates),
        ("TOTAL", grouped(traffic.total), Gauge::None),
        (
            "BLOCKED",
            blocked.map_or("-".to_string(), |share| format!("{share:.1}%")),
            blocked.map_or(Gauge::None, |share| Gauge::Share(share, BAD)),
        ),
        (
            "CACHE HITS",
            format!("{:.1}%", traffic.cache_hit_pct),
            Gauge::Share(traffic.cache_hit_pct, OK),
        ),
        (
            "LATENCY",
            format!("{:.1} ms", traffic.latency_ms),
            Gauge::None,
        ),
    ];
    let tile = cols.saturating_sub(2) / tiles.len();
    if tile < MIN_TILE_WIDTH {
        let mut row = Row::new(cols);
        row.text(" ");
        for (index, (name, value, _)) in tiles.iter().enumerate() {
            if index > 0 {
                row.paint(LINE);
                row.text(" · ");
            }
            row.paint(MUTED);
            row.text(&format!("{} ", name.to_ascii_lowercase()));
            row.plain();
            row.add(BOLD);
            row.text(value);
        }
        return vec![row.finish()];
    }
    let mut labels = Row::new(cols);
    let mut values = Row::new(cols);
    for (index, (name, value, gauge)) in tiles.iter().enumerate() {
        let start = 2 + index * tile;
        labels.plain();
        labels.pad_to(start);
        labels.paint(MUTED);
        labels.text(name);
        values.plain();
        values.pad_to(start);
        values.add(BOLD);
        values.text(value);
        values.plain();
        values.text(" ");
        let room = (start + tile).saturating_sub(values.width + 2);
        match gauge {
            Gauge::Rates if room >= 4 => {
                values.paint(ACCENT);
                values.text(&sparkline(&traffic.recent, room.min(16)));
            }
            Gauge::Share(share, color) if room >= 4 => {
                meter(&mut values, *share, room.min(10), color)
            }
            _ => {}
        }
    }
    vec![labels.finish(), values.finish()]
}

/// The newest `width` rates, each scaled to the largest shown.
fn sparkline(rates: &[f64], width: usize) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let shown = &rates[rates.len().saturating_sub(width)..];
    let peak = shown.iter().copied().fold(0.0_f64, f64::max);
    shown
        .iter()
        .map(|&rate| {
            let step = if peak > 0.0 {
                (rate / peak * 7.0).round() as usize
            } else {
                0
            };
            BARS[step.min(7)]
        })
        .collect()
}

/// `percent` of `width` cells in `color`, the rest dimmed.
fn meter(row: &mut Row, percent: f64, width: usize, color: &'static str) {
    let filled = ((percent / 100.0).clamp(0.0, 1.0) * width as f64).round() as usize;
    row.paint(color);
    row.text(&"━".repeat(filled));
    row.paint(LINE);
    row.text(&"━".repeat(width - filled));
}

/// Listeners separated by dots, continued on more rows; the last row says how many did not fit.
fn listener_rows(
    cols: usize,
    listeners: &[(&'static str, String)],
    max_rows: usize,
) -> Vec<String> {
    const SEPARATOR: &str = " · ";
    let room = cols.saturating_sub(LABEL_WIDTH).max(1);
    let width_of = |(kind, address): &(&str, String)| text_width(kind) + 1 + text_width(address);
    let mut lines: Vec<(Vec<&(&str, String)>, usize)> = Vec::new();
    for item in listeners {
        let width = width_of(item);
        match lines.last_mut() {
            Some((line, used)) if *used + text_width(SEPARATOR) + width <= room => {
                line.push(item);
                *used += text_width(SEPARATOR) + width;
            }
            _ => lines.push((vec![item], width)),
        }
    }
    lines.truncate(max_rows);
    let mut shown: usize = lines.iter().map(|(line, _)| line.len()).sum();
    if shown < listeners.len() {
        // Makes room for the count on the last row.
        if let Some((line, used)) = lines.last_mut() {
            while line.len() > 1 && *used + text_width(&more(listeners.len() - shown)) > room {
                let dropped = line.pop().expect("more than one item");
                *used -= text_width(SEPARATOR) + width_of(dropped);
                shown -= 1;
            }
        }
    }
    let last = lines.len();
    lines
        .iter()
        .enumerate()
        .map(|(index, (line, _))| {
            let mut row = Row::new(cols);
            label(&mut row, if index == 0 { "Listening" } else { "" });
            for (at, (kind, address)) in line.iter().enumerate() {
                if at > 0 {
                    row.paint(LINE);
                    row.text(SEPARATOR);
                }
                row.paint(MUTED);
                row.text(&format!("{kind} "));
                row.plain();
                row.text(address);
            }
            if index + 1 == last && shown < listeners.len() {
                row.paint(MUTED);
                row.text(&more(listeners.len() - shown));
            }
            row.finish()
        })
        .collect()
}

fn more(count: usize) -> String {
    format!("   +{count} more")
}

/// A dot whose color says how often the upstream failed, its name, and its average reply time.
fn upstream_rows(cols: usize, upstreams: &[UpstreamStatReport]) -> Vec<String> {
    let shown = &upstreams[..upstreams.len().min(MAX_UPSTREAM_ROWS)];
    let name_width = shown
        .iter()
        .map(|upstream| text_width(&upstream.label))
        .max()
        .unwrap_or(0)
        .min(32)
        .min(cols.saturating_sub(LABEL_WIDTH + 28));
    let mut rows: Vec<String> = shown
        .iter()
        .enumerate()
        .map(|(index, upstream)| {
            let mut row = Row::new(cols);
            label(&mut row, if index == 0 { "Upstream" } else { "" });
            let answered = upstream.ok + upstream.fail;
            let failed = upstream.fail as f64 / answered.max(1) as f64;
            let health = match answered {
                0 => MUTED,
                _ if failed >= FAILING => BAD,
                _ if failed >= FLAKY => WARN,
                _ => OK,
            };
            row.paint(health);
            row.text("● ");
            row.plain();
            row.text(&clipped(&upstream.label, name_width));
            row.pad_to(LABEL_WIDTH + 2 + name_width + 2);
            if answered == 0 {
                row.paint(MUTED);
                row.text("no answers yet");
            } else {
                row.add(BOLD);
                row.text(&format!("{:>5.0} ms", upstream.ewma_ms));
                row.paint(MUTED);
                row.text(&format!("   {} failed", percent(upstream.fail, answered)));
            }
            row.finish()
        })
        .collect();
    if upstreams.len() > shown.len() {
        let mut row = Row::new(cols);
        label(&mut row, "");
        row.paint(MUTED);
        row.text(more(upstreams.len() - shown.len()).trim_start());
        rows.push(row.finish());
    }
    rows
}

/// At most `width` columns, ending in an ellipsis when cut.
fn clipped(text: &str, width: usize) -> String {
    if text_width(text) <= width {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        if used + char_width(ch) + 1 > width {
            break;
        }
        used += char_width(ch);
        out.push(ch);
    }
    if width > 0 {
        out.push('…');
    }
    out
}

fn label(row: &mut Row, name: &str) {
    row.paint(MUTED);
    row.text(&format!("  {name:<width$}", width = LABEL_WIDTH - 2));
    row.plain();
}

fn log_bar(status: &Status, view: &View, cols: usize) -> String {
    let (state, color) = match view.bottom {
        Some(_) => ("paused", WARN),
        None => ("following", MUTED),
    };
    let mut row = Row::new(cols);
    row.paint(LINE);
    row.text("──");
    row.plain();
    row.add(BOLD);
    row.text(" Log ");
    row.paint(LINE);
    row.text("─");
    row.paint(MUTED);
    row.text(" level ");
    row.paint(ACCENT);
    row.text(&status.level.label().to_ascii_lowercase());
    row.text(" ");
    row.paint(LINE);
    row.rule_to(cols.saturating_sub(text_width(state) + 4));
    row.paint(color);
    row.text(&format!(" {state} "));
    row.paint(LINE);
    row.rule_to(cols);
    row.finish()
}

fn footer(view: &View, cols: usize) -> String {
    let mut row = Row::bar(cols);
    if view.quit_armed.is_some() {
        row.paint(WARN);
        row.add(BOLD);
        row.text(" Press q again to quit");
    } else {
        for (keys, action) in [
            ("q", "quit"),
            ("p", "pause"),
            ("l", "level"),
            ("↑↓ PgUp PgDn", "scroll"),
            ("End", "follow"),
        ] {
            row.paint(ACCENT);
            row.add(BOLD);
            row.text(&format!(" {keys}"));
            row.plain();
            row.text(&format!(" {action}  "));
        }
    }
    row.plain();
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

/// The event in the accent color, the message plain and the fields dimmed. Continued rows line up
/// under the event.
fn entry_rows(entry: &Entry, cols: usize) -> Vec<String> {
    let (tag, color) = match entry.level {
        Some(Level::Error) => ("ERROR", BAD),
        Some(Level::Warn) => ("WARN ", WARN),
        Some(Level::Info) => ("INFO ", OK),
        Some(Level::Debug) => ("DEBUG", MUTED),
        Some(Level::Trace) => ("TRACE", MUTED),
        None => ("     ", ""),
    };
    let mut flow = Flow {
        rows: Vec::new(),
        row: Row::new(cols),
        cols,
        indent: if cols >= 40 { 15 } else { 0 },
    };
    flow.row.paint(MUTED);
    flow.row.text(&entry.time);
    flow.row.text(" ");
    flow.row.paint(color);
    flow.row.text(tag);
    flow.row.text(" ");
    let message = if entry.level.is_some() { "" } else { ACCENT };
    for (index, (part, style)) in [
        (&entry.event, ACCENT),
        (&entry.message, message),
        (&entry.fields, MUTED),
    ]
    .into_iter()
    .filter(|(part, _)| !part.is_empty())
    .enumerate()
    {
        if index > 0 {
            flow.write("  ", "");
        }
        flow.write(part, style);
    }
    flow.rows.push(flow.row.finish());
    flow.rows
}

/// Text that continues on a new row, indented, when it reaches the right edge. Words move to the
/// next row whole unless they are longer than a row.
struct Flow {
    rows: Vec<String>,
    row: Row,
    cols: usize,
    indent: usize,
}

impl Flow {
    fn write(&mut self, text: &str, style: &'static str) {
        self.row.paint(style);
        for word in text.split_inclusive(' ') {
            let width = text_width(word.trim_end_matches(' '));
            if self.row.width > self.indent
                && self.row.width + width > self.cols
                && width <= self.cols - self.indent
            {
                self.wrap(style);
            }
            for ch in word.chars() {
                if !self.row.fits(ch) {
                    if ch == ' ' {
                        continue;
                    }
                    self.wrap(style);
                }
                self.row.push(ch);
            }
        }
    }

    fn wrap(&mut self, style: &'static str) {
        let full = std::mem::replace(&mut self.row, Row::new(self.cols));
        self.rows.push(full.finish());
        self.row.text(&" ".repeat(self.indent));
        self.row.paint(style);
    }
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "-".to_string();
    }
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

/// With a comma every three digits.
fn grouped(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
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

/// One screen row: text cut at the width, then padded to it. Each style starts over from the
/// row's base, so a bar keeps its background.
struct Row {
    out: String,
    width: usize,
    cols: usize,
    base: &'static str,
}

impl Row {
    fn new(cols: usize) -> Self {
        Self {
            out: String::with_capacity(cols + 64),
            width: 0,
            cols,
            base: "",
        }
    }

    fn bar(cols: usize) -> Self {
        let mut row = Self::new(cols);
        row.base = BAR;
        row.plain();
        row
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

    /// Replaces the style.
    fn paint(&mut self, sgr: &str) {
        self.out.push_str(RESET);
        self.out.push_str(self.base);
        self.out.push_str(sgr);
    }

    /// Adds to the style.
    fn add(&mut self, sgr: &str) {
        self.out.push_str(sgr);
    }

    fn plain(&mut self) {
        self.paint("");
    }

    fn pad_to(&mut self, column: usize) {
        while self.width < column.min(self.cols) {
            self.push(' ');
        }
    }

    fn rule_to(&mut self, column: usize) {
        while self.width < column.min(self.cols) {
            self.push('─');
        }
    }

    fn finish(mut self) -> String {
        self.pad_to(self.cols);
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
                recent: vec![2.0, 4.0, 8.0, 12.0],
                total: 12_345,
                blocked: 3_086,
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
                "test.line",
                &format!("line {index}"),
                "",
            );
        }
        log
    }

    fn screen(status: &Status, log: &Log, cols: usize, rows: usize) -> Vec<String> {
        let mut view = View::default();
        render(status, log, &mut view, cols, rows)
            .iter()
            .map(|row| visible(row))
            .collect()
    }

    #[test]
    fn every_row_fills_the_screen_except_the_last() {
        for cols in [80, 120, 60, 41] {
            let mut view = View::default();
            let rows = render(&status(), &log_with(3), &mut view, cols, 20);
            assert_eq!(rows.len(), 20);
            for row in &rows[..19] {
                assert_eq!(text_width(&visible(row)), cols, "{row:?}");
            }
            assert_eq!(text_width(&visible(&rows[19])), cols - 1);
        }
    }

    #[test]
    fn the_status_reads_top_down() {
        let text = screen(&status(), &log_with(3), 100, 20);
        assert!(
            text[0].starts_with(" ◆ OnetDNS 1.2.3   personal · forward"),
            "{}",
            text[0]
        );
        assert!(text[0].ends_with("● serving   up 2h 3m "), "{}", text[0]);
        assert!(
            text[1].contains("QUERIES/S") && text[1].contains("LATENCY"),
            "{}",
            text[1]
        );
        assert!(text[2].contains("12.0 ▂▃▆█"), "{}", text[2]);
        assert!(
            text[2].contains("12,345") && text[2].contains("25.0% ━━"),
            "{}",
            text[2]
        );
        assert!(
            text[2].contains("3.2 ms") || text[2].contains("3.3 ms"),
            "{}",
            text[2]
        );
        assert!(
            text[3].starts_with("  Dashboard  http://127.0.0.1:8553/"),
            "{}",
            text[3]
        );
        assert!(
            text[4].contains("do53-udp 127.0.0.1:53 · do53-tcp 127.0.0.1:53"),
            "{}",
            text[4]
        );
        assert!(
            text[5].contains("● 1.1.1.1:53     12 ms   10.0% failed"),
            "{}",
            text[5]
        );
        assert!(text[6].starts_with("── Log ─ level info ─"), "{}", text[6]);
        assert!(text[6].ends_with(" following ──"), "{}", text[6]);
        assert!(text[9].contains("INFO  test.line  line 2"), "{}", text[9]);
        assert!(text[10].trim().is_empty());
        assert!(
            text[19].starts_with(" q quit   p pause   l level"),
            "{}",
            text[19]
        );
    }

    #[test]
    fn narrow_screens_put_the_metrics_on_one_line() {
        let text = screen(&status(), &log_with(1), 60, 20);
        assert!(
            text[1].starts_with(" queries/s 12.0 · total 12,345 · blocked 25.0%"),
            "{}",
            text[1]
        );
        assert!(text[2].starts_with("  Dashboard"), "{}", text[2]);
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
            "config.path",
            &"경로=C:\\Users\\홍길동\\설정".repeat(4),
            "key=값",
        );
        let mut view = View::default();
        for row in render(&status(), &log, &mut view, 41, 12) {
            assert!(text_width(&visible(&row)) <= 41, "{row:?}");
        }
    }

    #[test]
    fn a_wrapped_entry_keeps_its_color_on_the_next_row() {
        let mut log = Log::new();
        log.push(
            Some(Level::Info),
            "12:00:00".to_string(),
            "e",
            "",
            &"k=v ".repeat(30),
        );
        let entry = log.get(0).unwrap();
        let rows = entry_rows(entry, 50);
        assert!(rows.len() > 1);
        assert!(rows[1].contains(MUTED), "{:?}", rows[1]);
        assert!(visible(&rows[1]).starts_with(&" ".repeat(15)));
    }

    #[test]
    fn words_wrap_whole_unless_longer_than_a_row() {
        let mut log = Log::new();
        log.push(
            Some(Level::Info),
            "12:00:00".to_string(),
            "e",
            "",
            "short upstream=9.9.9.9:53",
        );
        log.push(
            Some(Level::Info),
            "12:00:00".to_string(),
            "e",
            "",
            &"x".repeat(60),
        );
        let rows: Vec<String> = entry_rows(log.get(0).unwrap(), 40)
            .iter()
            .map(|row| visible(row))
            .collect();
        assert_eq!(rows[0].trim_end(), "12:00:00 INFO  e  short");
        assert_eq!(rows[1].trim(), "upstream=9.9.9.9:53");
        let rows = entry_rows(log.get(1).unwrap(), 40);
        assert_eq!(rows.len(), 3);
        assert!(visible(&rows[0]).ends_with('x'));
    }

    #[test]
    fn long_upstream_names_are_cut() {
        assert_eq!(clipped("1.1.1.1:53", 10), "1.1.1.1:53");
        assert_eq!(clipped("https://dns.google/dns-query", 10), "https://d…");
        assert_eq!(clipped("가나다", 4), "가…");
        let upstream = UpstreamStatReport {
            label: "https://a-very-long-resolver-name.example/dns-query".to_string(),
            queries: 10,
            ok: 10,
            fail: 0,
            ewma_ms: 9.0,
        };
        let row = visible(&upstream_rows(60, &[upstream])[0]);
        assert!(row.trim_end().ends_with("0.0% failed"), "{row}");
    }

    #[test]
    fn the_plain_log_joins_the_parts() {
        let mut log = Log::new();
        log.push(
            Some(Level::Info),
            "12:00:00".to_string(),
            "a.b",
            "Did it",
            "n=1",
        );
        log.push(None, "12:00:01".to_string(), "", "Dashboard: http://x/", "");
        let lines: Vec<String> = log.lines().collect();
        assert_eq!(
            lines,
            [
                "12:00:00  a.b  Did it  n=1",
                "12:00:01  Dashboard: http://x/"
            ]
        );
    }

    #[test]
    fn many_listeners_say_how_many_did_not_fit() {
        let items: Vec<(&'static str, String)> = (0..40)
            .map(|i| ("doh", format!("10.0.0.{i}:443")))
            .collect();
        let rows = listener_rows(60, &items, 2);
        assert_eq!(rows.len(), 2);
        let last = visible(&rows[1]);
        let shown: usize = rows
            .iter()
            .map(|row| visible(row).matches("doh ").count())
            .sum();
        assert!(
            last.trim_end().ends_with(&format!("+{} more", 40 - shown)),
            "{last}"
        );
    }

    #[test]
    fn the_rate_graph_scales_to_its_peak() {
        assert_eq!(sparkline(&[0.0, 5.0, 10.0], 5), "▁▅█");
        assert_eq!(sparkline(&[0.0, 0.0], 2), "▁▁");
        assert_eq!(sparkline(&[1.0, 2.0, 3.0, 4.0], 2), "▆█");
    }

    #[test]
    fn upstreams_are_colored_by_how_often_they_fail() {
        let upstream = |ok, fail| UpstreamStatReport {
            label: "u".to_string(),
            queries: ok + fail,
            ok,
            fail,
            ewma_ms: 1.0,
        };
        let dot = |ok, fail| upstream_rows(80, &[upstream(ok, fail)])[0].clone();
        assert!(dot(100, 0).contains(OK));
        assert!(dot(90, 10).contains(WARN));
        assert!(dot(50, 50).contains(BAD));
        assert!(visible(&dot(0, 0)).contains("no answers yet"));
    }

    #[test]
    fn numbers_are_grouped_by_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(12_345_678), "12,345,678");
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
        log.push(Some(Level::Info), "12:00:01".to_string(), "new", "", "");
        let rows = render(&status(), &log, &mut view, 100, 20);
        let text: Vec<String> = rows.iter().map(|row| visible(row)).collect();
        assert!(!text.iter().any(|row| row.contains("new")));
        assert!(text[6].ends_with(" paused ──"), "{}", text[6]);
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
        assert_eq!(
            log.get(5).map(|entry| entry.message.as_str()),
            Some("line 5")
        );
        assert!(log.get(4).is_none());
    }
}
