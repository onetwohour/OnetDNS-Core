#!/usr/bin/env python3
"""Static regression checks for the embedded OnetDNS dashboard.

The checks cover JavaScript syntax, duplicate declarations, complete ko/en/ja/zh
coverage for static and dynamic user-facing copy, terminology regressions, and
critical state-synchronization hooks. Only Python's standard library and Node.js
are required.
"""
from __future__ import annotations

import html.parser
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "crates/onetdns-control/dashboard/index.html"
KOREAN = re.compile(r"[가-힣]")
# "업스트림" is deliberately absent. The config key is `upstream_urls`, so a reader
# who sees "상류" or "상위 서버" cannot connect the screen to the setting they wrote.
# This list only holds terms that have a Korean word the reader already knows.
BANNED_KO = re.compile(
    r"세" r"대 교체|재로드|롤백|리빌드|폴백|프리페치|스테일|핫리로드|"
    r"리스너|업스트림 리졸버|포워딩 대상|zone CRUD|dry explain",
    re.I,
)
BANNED_EN = re.compile(r"server generation|listener generation|hot[- ]?reload", re.I)
BANNED_JA = re.compile(r"サーバー世代|リスナー世代|ロールバック|ホットリロード|アップストリーム")


class VisibleTextParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.values: list[str] = []
        self.ids: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self.hidden_depth += 1
        for key, value in attrs:
            if key == "id" and value:
                self.ids.append(value)
            if key in {"placeholder", "title", "aria-label"} and value:
                self._record(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self._record(data)

    def _record(self, value: str) -> None:
        value = " ".join(value.split())
        if value and KOREAN.search(value) and "{{" not in value:
            self.values.append(value)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def scan_js_string_literals(source: str) -> list[str]:
    """Return Korean JS string/template literal bodies, skipping comments."""
    values: list[str] = []
    i = 0
    while i < len(source):
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = len(source) if end < 0 else end + 2
            continue
        quote = source[i]
        if quote not in "'\"`":
            i += 1
            continue
        j = i + 1
        buf: list[str] = []
        while j < len(source):
            ch = source[j]
            if ch == "\\" and j + 1 < len(source):
                buf.extend(source[j : j + 2])
                j += 2
                continue
            if ch == quote:
                break
            buf.append(ch)
            j += 1
        literal = "".join(buf)
        if KOREAN.search(literal):
            values.append(literal)
        i = min(j + 1, len(source))
    return values


def check_live_chart_buckets_are_time_anchored(source: str) -> None:
    """Old chart columns must not change while their data does not.

    The per-second samples live in a ring that drops from the front once it is
    full. Bucketing by array index therefore re-averages a sliding window every
    tick: columns wobble even where the data is settled, and the bucket id stops
    advancing once the ring saturates, which also kills the slide animation.
    Anchoring buckets to wall time fixes both. This runs the shipped code twice,
    one second apart inside the same bucket, and requires the settled columns to
    come out identical.
    """
    begin = source.find("      bs=Math.max(1,Math.round((liveSec/tickSec)/VIS));")
    if begin < 0:
        fail("live chart bucketing not found; the throughput chart cannot be checked")
    end = source.find(chr(10) + "    }" + chr(10) + "    this._colKey=lastB;", begin)
    if end < 0:
        fail("live chart bucketing not delimited as expected")
    block = source[begin:end]

    harness = (
        "function build(qps, qpsBlocked, qpsT, nowMs) {" + chr(10)
        + "  const VIS = 58, tickSec = 1, liveSec = 300;" + chr(10)
        + "  const self = { qps, qpsBlocked, qpsT };" + chr(10)
        + "  let cols = [], bs = 1, lastB = 0;" + chr(10)
        + "  (function () {" + chr(10)
        + block + chr(10)
        + "  }).call(self);" + chr(10)
        + "  return { cols, bs, lastB };" + chr(10)
        + "}" + chr(10)
        + "const N = 1300, t0 = 1700000000000;" + chr(10)
        + "const qps = [], blocked = [], ts = [];" + chr(10)
        + "for (let i = 0; i < N; i++) { qps.push((i % 17) + 1); blocked.push(i % 3); ts.push(t0 + i * 1000); }" + chr(10)
        + "let prev = null, pairs = 0, moved = 0, advanced = false, bs = 0;" + chr(10)
        + "for (let k = 0; k < 20; k++) {" + chr(10)
        + "  const now = t0 + (N - 1 + k) * 1000;" + chr(10)
        + "  const cur = build(qps, blocked, ts, now);" + chr(10)
        + "  bs = cur.bs;" + chr(10)
        + "  if (prev && prev.lastB === cur.lastB) {" + chr(10)
        + "    pairs++;" + chr(10)
        + "    for (let i = 0; i < cur.cols.length - 1; i++) {" + chr(10)
        + "      if (Math.abs(prev.cols[i].q - cur.cols[i].q) > 1e-9) moved++;" + chr(10)
        + "    }" + chr(10)
        + "  }" + chr(10)
        + "  if (prev && cur.lastB > prev.lastB) advanced = true;" + chr(10)
        + "  prev = cur;" + chr(10)
        + "  qps.shift(); blocked.shift(); ts.shift();" + chr(10)
        + "  qps.push((k % 11) + 1); blocked.push(k % 2); ts.push(t0 + (N + k) * 1000);" + chr(10)
        + "}" + chr(10)
        + "process.stdout.write(JSON.stringify({ pairs, moved, bs, advanced }));" + chr(10)
    )

    with tempfile.TemporaryDirectory(prefix="onetdns-buckets-") as td:
        script = Path(td) / "buckets.js"
        script.write_text(harness, encoding="utf-8")
        got = json.loads(
            subprocess.check_output(["node", str(script)], text=True, encoding="utf-8")
        )

    if got["pairs"] < 2:
        fail(
            "chart bucket ids never held still across a tick, so this check proved "
            "nothing; the bucket size assumption changed"
        )
    if got["moved"]:
        fail(
            "live chart columns move while their data is settled: "
            f"{got['moved']} older-column values changed across {got['pairs']} "
            "ticks inside one bucket. Anchor the buckets to wall time, not to the "
            "sample array index."
        )
    if not got["advanced"]:
        fail(
            "chart bucket id never advances once the sample ring is full, so the "
            "chart redraws instead of sliding. Derive it from the clock."
        )

def check_chart_curve_stays_in_band(source: str) -> None:
    """The throughput curve must not spill outside the drawable band.

    `smoothPath` fits Catmull-Rom tangents, which overshoot at local extrema.
    The SVG sets `overflow:hidden`, so an overshoot is not merely cosmetic --
    peaks and valleys get sliced off flat and the chart shows a plateau where
    the data has a spike. A cubic Bezier stays inside the convex hull of its
    control points, so clamping the control-point y is what keeps the whole
    curve in range. This runs the real function on a deliberately spiky series.
    """
    start = source.find("  smoothPath(pts")
    if start < 0:
        fail("smoothPath not found; the throughput chart cannot be checked")
    end = source.find(chr(10) + "  }", start)
    if end < 0:
        fail("smoothPath body not delimited as expected")
    body = source[start : end + 4].strip()

    lo, hi = 1.5, 98.5
    # 봉우리와 골이 번갈아만 하면 접선이 0이 되어 부풀지 않는다. 실제로 부푸는 모양은
    # 계단 뒤에 평평한 구간이 오는 것이다 -- 트래픽이 뛰어올라 그 수준을 유지할 때다.
    spiky = [[i * 15.0, lo if (i // 2) % 2 else hi] for i in range(40)]

    with tempfile.TemporaryDirectory(prefix="onetdns-chart-") as td:
        script = Path(td) / "curve.js"
        js = (
            "const o = { " + body + " };" + chr(10)
            + "const pts = " + json.dumps(spiky) + ";" + chr(10)
            + "const d = o.smoothPath(pts, " + repr(lo) + ", " + repr(hi) + ");" + chr(10)
            + "const nums = d.match(/-?\\d+\\.?\\d*/g).map(Number);" + chr(10)
            + "const ys = nums.filter((_, i) => i % 2 === 1);" + chr(10)
            + "process.stdout.write(JSON.stringify({min: Math.min(...ys), max: Math.max(...ys)}));" + chr(10)
        )
        script.write_text(js, encoding="utf-8")
        span = json.loads(
            subprocess.check_output(["node", str(script)], text=True, encoding="utf-8")
        )

    slack = 0.01
    if span["min"] < lo - slack or span["max"] > hi + slack:
        fail(
            "throughput curve leaves the drawable band: y spans "
            f"{span['min']:.2f}..{span['max']:.2f}, allowed {lo}..{hi}. "
            "Clamp the Bezier control points, or the chart clips peaks flat."
        )

def check_chart_axis_labels_are_evenly_spaced(source: str) -> None:
    """Grid lines are drawn at equal distances, so their labels must step equally.

    The axis maximum used to be the data maximum plus 6% padding, and the labels
    were that value times 1, 2/3, 1/3 and 0, rounded to integers. On an idle
    resolver that printed 4, 3, 1, 0 against four evenly spaced lines: the same
    gap on screen meant 1 in one place and 2 in the next, so the chart could not
    be read off its own axis. This runs the real function over the range a
    resolver actually reports, from an idle link to a saturated one.
    """
    start = source.find("  niceAxisMax(value,steps)")
    if start < 0:
        fail("niceAxisMax not found; the throughput axis cannot be checked")
    end = source.find(chr(10) + "  }", start)
    if end < 0:
        fail("niceAxisMax body not delimited as expected")
    body = source[start : end + 4].strip()

    fracs = re.search(r"const yFracs=\[([\d.,]+)\];", source)
    if not fracs:
        fail("yFracs not found; the throughput axis cannot be checked")
    steps = [float(value) for value in fracs.group(1).split(",")]
    gaps = {round(steps[i] - steps[i + 1], 6) for i in range(len(steps) - 1)}
    if steps[0] != 1 or steps[-1] != 0 or len(gaps) != 1:
        fail(
            "the throughput axis fractions are not an even ladder from 1 to 0: "
            + str(steps)
            + ". Evenly drawn grid lines would carry uneven labels."
        )

    samples = [4, 4.2, 7, 9, 13, 17, 26, 44, 97, 140, 321, 999, 1500, 4800, 23000, 150000]
    with tempfile.TemporaryDirectory(prefix="onetdns-axis-") as td:
        script = Path(td) / "axis.js"
        js = (
            "const o = { " + body + " };" + chr(10)
            + "const fracs = " + json.dumps(steps) + ";" + chr(10)
            + "const out = " + json.dumps(samples) + ".map(v => {" + chr(10)
            + "  const max = o.niceAxisMax(v, fracs.length - 1);" + chr(10)
            + "  return {v, max, ticks: fracs.map(f => Math.round(max * f))};" + chr(10)
            + "});" + chr(10)
            + "process.stdout.write(JSON.stringify(out));" + chr(10)
        )
        script.write_text(js, encoding="utf-8")
        rows = json.loads(
            subprocess.check_output(["node", str(script)], text=True, encoding="utf-8")
        )

    for row in rows:
        ticks = row["ticks"]
        gaps = {ticks[i] - ticks[i + 1] for i in range(len(ticks) - 1)}
        if len(gaps) != 1:
            fail(
                "the throughput axis labels for a peak of "
                + str(row["v"])
                + " step unevenly: "
                + str(ticks)
                + ". Grid lines are evenly spaced, so the reader would misread every value."
            )
        if len(set(ticks)) != len(ticks):
            fail(
                "the throughput axis repeats a label for a peak of "
                + str(row["v"])
                + ": "
                + str(ticks)
            )
        if row["max"] < row["v"]:
            fail(
                "the throughput axis tops out at "
                + str(row["max"])
                + ", below the peak of "
                + str(row["v"])
                + ". The curve would be drawn past the top grid line."
            )


def check_toast_is_never_painted_behind_an_overlay(source: str) -> None:
    """The toast must outrank every full-screen overlay.

    The login and first-admin screen is an opaque `inset:0` overlay. When the toast
    sat below it, the button worked, validation worked and the server answered, but
    the message was painted behind the overlay: the operator saw nothing at all and
    read it as "the button does nothing". Every other overlay has the same hazard,
    so the rule is that the toast outranks all of them rather than just that one.
    """
    layers = [int(value) for value in re.findall(r"z-index:\s*(\d+)", source)]
    if not layers:
        fail("no z-index declarations found; the stacking check cannot run")
    match = re.search(r"const toastStyle=`[^`]*?z-index:\s*(\d+)", source)
    if not match:
        fail("toastStyle not found, or it no longer declares a z-index")
    toast = int(match.group(1))
    highest_other = max(value for value in layers if value != toast)
    if toast <= highest_other:
        fail(
            "the toast z-index ("
            + str(toast)
            + ") does not outrank every other layer (highest other: "
            + str(highest_other)
            + "). Failure messages would be painted behind an overlay and the"
            " screen would look unresponsive."
        )


def check_hidden_row_controls_keep_their_slot(source: str) -> None:
    """A control a row does not get must still reserve its width.

    Built-in blocklists have no toggle and no delete button: both are driven by the
    safe-browsing and parental-control settings, so showing them here would make the
    row appear broken when the value came straight back. Rendering nothing instead
    slides every later control left, so the update button of a built-in row sits
    where the delete button of every other row is, and the column stops being a
    column. Each control dropped for those rows needs a placeholder of its own width.
    """
    row = re.search(
        r'<sc-for list="\{\{ blocklists \}\}".*?</sc-for>', source, re.S
    )
    if not row:
        fail("the blocklist row template was not found; the slot check cannot run")
    body = row.group(0)
    shown = len(re.findall(r'<sc-if value="\{\{ b\.editable \}\}">', body))
    reserved = re.findall(r'<sc-if value="\{\{ !b\.editable \}\}">(.*?)</sc-if>', body, re.S)
    if shown != len(reserved):
        fail(
            "the blocklist row renders "
            + str(shown)
            + " controls only for editable lists but reserves "
            + str(len(reserved))
            + " placeholders. Built-in rows would pull the remaining controls out of"
            " their column."
        )
    for slot in reserved:
        if not re.search(r"flex:\s*0 0 \d+px", slot):
            fail(
                "a placeholder for a control hidden on built-in rows has no fixed"
                " width (flex:0 0 Npx), so it cannot hold the column."
            )


def check_template_names_are_exposed(source: str) -> None:
    """Every bare name the template reads must be a key of the view object.

    The template only sees what renderVals() returns, together with the methods it
    spreads in with `...this.name()`. A name missing from that object is not an
    error at runtime: an event binding silently gets no handler and a condition is
    simply false. A textarea bound to `value="{{ forms.config }}"` whose handler was
    defined as a method but never exposed kept resetting to empty on every render,
    so typed text vanished while every other check stayed green.
    """
    template = re.sub(r"<script(?:\s[^>]*)?>.*?</script>", "", source, flags=re.S | re.I)
    next_member = re.compile(r"\n  [A-Za-z_$][\w$]*\s*(?:=|\()")
    bodies: list[str] = []
    pending, seen = ["renderVals"], set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        start = source.find("\n  " + name + "(){")
        if start < 0:
            fail(name + "() not found; the template binding check cannot run")
        end = next_member.search(source, start + 5)
        body = source[start : end.start() if end else len(source)]
        bodies.append(body)
        pending += re.findall(r"\.\.\.this\.([A-Za-z_$][\w$]*)\(\)", body)
    view = "\n".join(bodies)
    loop_vars = set(re.findall(r'<sc-for[^>]*\bas="([A-Za-z_]\w*)"', template))
    names: set[str] = set()
    for expr in re.findall(r"\{\{(.*?)\}\}", template):
        expr = re.sub(r"'[^']*'|\"[^\"]*\"", "", expr)
        names.update(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", expr))
    missing = sorted(
        name
        for name in names - loop_vars
        if not re.search(r"(?<![\w$.])" + re.escape(name) + r"(?=\s*[:,}\n])", view)
    )
    if missing:
        fail(
            "the template reads names that the view object does not expose: "
            + ", ".join(missing)
            + ". Add them to renderVals() or a method it spreads in."
        )


def check_conditions_use_only_supported_operators(source: str) -> None:
    """An sc-if condition may only use what support.js resolve() understands.

    resolve() handles a name path, a leading !, ===/!==/==/!=, parentheses and
    literals. Anything else falls through to resolvePath(), which returns undefined
    for an expression like `a && b`, so the block renders as if the condition were
    false. Nothing throws and no other check notices, which is how a panel that was
    supposed to explain a disabled feature silently showed nothing at all. Compose
    the flag in renderVals() and bind the single name instead.
    """
    template = re.sub(r"<script(?:\s[^>]*)?>.*?</script>", "", source, flags=re.S | re.I)
    unsupported = re.compile(r"&&|\|\||[?+\-*/%<>]|(?<![!=<>])=(?![=])")
    offenders = []
    for expr in re.findall(r'<sc-(?:if|for)[^>]*\svalue="\{\{(.*?)\}\}"', template):
        body = re.sub(r"'[^']*'|\"[^\"]*\"", "", expr)
        body = re.sub(r"[!=]==?|!=", "", body)
        if unsupported.search(body):
            offenders.append(expr.strip())
    if offenders:
        fail(
            "sc-if conditions use operators that support.js resolve() cannot parse, "
            "so they always render as false: "
            + ", ".join(offenders)
            + ". Compute the value in renderVals() and bind its name."
        )


def main() -> None:
    source = DASHBOARD.read_text(encoding="utf-8")
    scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", source, re.S | re.I)
    if not scripts:
        fail("no inline script blocks found")

    with tempfile.TemporaryDirectory(prefix="onetdns-dashboard-") as td:
        temp = Path(td)
        combined = temp / "dashboard.js"
        combined.write_text("\n".join(scripts), encoding="utf-8")
        subprocess.run(["node", "--check", str(combined)], check=True)

        start = source.find("const I18N =")
        end = source.find("\nclass Component", start)
        if start < 0 or end < 0:
            fail("I18N block or Component class not found")
        module = temp / "i18n.js"
        module.write_text(
            source[start:end] + "\nprocess.stdout.write(JSON.stringify(I18N));\n",
            encoding="utf-8",
        )
        dictionaries = json.loads(
            subprocess.check_output(["node", str(module)], text=True, encoding="utf-8")
        )

        home_start = source.find("const DEDICATED_HOME = {")
        home_end = source.find("\n};", home_start)
        if home_start < 0 or home_end < 0:
            fail("DEDICATED_HOME map not found; the settings search cannot point anywhere")
        home_module = temp / "dedicated.js"
        home_module.write_text(
            source[home_start : home_end + 3]
            + "\nprocess.stdout.write(JSON.stringify(DEDICATED_HOME));\n",
            encoding="utf-8",
        )
        dedicated_home = json.loads(
            subprocess.check_output(["node", str(home_module)], text=True, encoding="utf-8")
        )

    views = set(re.findall(r"'([a-z]+)'", re.search(r"validViews\(\)\{return new Set\(\[([^\]]*)\]", source).group(1)))
    unknown_homes = sorted(
        {home for home in dedicated_home.values() if home != "settings-quick"} - views
    )
    if unknown_homes:
        fail(f"DEDICATED_HOME points at screens that do not exist: {unknown_homes}")
    # 전용 편집기를 붙이거나 떼면 여기가 걸린다. 검색이 조용히 반쪽이 되는 것을 막는 고의적 핀이다.
    if len(dedicated_home) != 52:
        fail(
            f"DEDICATED_HOME has {len(dedicated_home)} keys, pinned at 52; "
            "update the map and this pin together"
        )

    # Screen copy is keyed by its Korean source text. The server answers in English, so
    # the server messages the dashboard knows are keyed by their English text and need
    # every language except English.
    en = dictionaries.get("en", {})
    ja = dictionaries.get("ja", {})
    zh = dictionaries.get("zh", {})
    ko = dictionaries.get("ko", {})
    expected = set(en) | set(ko)
    for language, dictionary in (("ja", ja), ("zh", zh)):
        if set(dictionary) != expected:
            fail(
                f"translation key mismatch in {language}: "
                f"missing={sorted(expected - set(dictionary))[:10]}, "
                f"extra={sorted(set(dictionary) - expected)[:10]}"
            )
    empty = [
        (language, key)
        for language, dictionary in (("en", en), ("ja", ja), ("zh", zh), ("ko", ko))
        for key, value in dictionary.items()
        if not str(value).strip()
    ]
    if empty:
        fail(f"empty translations: {empty[:10]}")
    untranslated_values = [
        (language, key, value)
        for language, dictionary in (("en", en), ("ja", ja), ("zh", zh))
        for key, value in dictionary.items()
        if KOREAN.search(str(value))
    ]
    if untranslated_values:
        fail(f"Korean text remains in translated values: {untranslated_values[:10]}")
    bad_en = [(key, value) for key, value in en.items() if BANNED_EN.search(str(value))]
    bad_ja = [(key, value) for key, value in ja.items() if BANNED_JA.search(str(value))]
    if bad_en or bad_ja:
        fail(f"translationese terminology remains: en={bad_en[:8]}, ja={bad_ja[:8]}")
    raw_bad = re.findall(
        r"server generation|listener generation|サーバー世代|リスナー世代|ロールバック|ネットワーク世代",
        source,
        re.I,
    )
    if raw_bad:
        fail(f"translationese remains in duplicate or overridden dashboard copy: {sorted(set(raw_bad))}")

    parser = VisibleTextParser()
    parser.feed(source)
    missing = sorted(set(parser.values) - set(en))
    if missing:
        fail("untranslated static strings:\n  " + "\n  ".join(missing))
    awkward_static = sorted(value for value in set(parser.values) if BANNED_KO.search(value))
    if awkward_static:
        fail("deprecated Korean UI terminology remains:\n  " + "\n  ".join(awkward_static))

    duplicate_ids = sorted(key for key, count in Counter(parser.ids).items() if count > 1)
    if duplicate_ids:
        fail(f"duplicate HTML ids: {duplicate_ids}")

    component = source[source.find("class Component") :]
    methods = re.findall(r"^  (?:async\s+)?([A-Za-z_$][\w$]*)\s*\(", component, re.M)
    duplicate_methods = sorted(key for key, count in Counter(methods).items() if count > 1)
    if duplicate_methods:
        fail(f"duplicate class methods: {duplicate_methods}")

    # Remove the dictionary construction before checking runtime literals.
    runtime_scripts = "\n".join(scripts)
    direct_style_strings = re.findall(
        r"(?:React\.createElement|\bR)\([^\r\n]*?\bstyle\s*:\s*['\"`]", runtime_scripts
    )
    if direct_style_strings:
        fail("React elements must receive style objects, not CSS strings")

    i18n_start = runtime_scripts.find("const I18N =")
    class_start = runtime_scripts.find("\nclass Component", i18n_start)
    if i18n_start >= 0 and class_start >= 0:
        runtime_scripts = runtime_scripts[:i18n_start] + runtime_scripts[class_start:]
    internal_suffixes = {"개 ", "개를 ", "번 "}
    dynamic_missing: list[str] = []
    dynamic_awkward: list[str] = []
    for literal in sorted(set(scan_js_string_literals(runtime_scripts))):
        if literal in internal_suffixes:
            continue
        if literal not in en and "this.t(" not in literal and "this.tr(" not in literal:
            dynamic_missing.append(literal)
        if BANNED_KO.search(literal):
            dynamic_awkward.append(literal)
    if dynamic_missing:
        fail("untranslated dynamic Korean strings:\n  " + "\n  ".join(dynamic_missing[:30]))
    if dynamic_awkward:
        fail("deprecated terminology in dynamic UI strings:\n  " + "\n  ".join(dynamic_awkward[:30]))

    required_snippets = [
        "desiredBody._valid!==false",
        "await this.loadConfigState();",
        "pendingLabel:this.t('파일에서 변경됨')",
        "this.resyncRecent()",
        "_upstreamProbeRun",
        "unit:this.unitLabel(fd.unit||'')",
        "proto:(l.proto==='Do53'?'DNS':l.proto)",
        "roleLabel:this.t(",
        "{{ z.serial }}",
        "fd.write_only===true",
        "configDraftDirty",
        "nav.inert=hidden",
        "confirmDestructive(message)",
        "history.pushState({view:v}",
        "loadDashboardFallback()",
        "this.apiGet('/v1/stats')",
        "this.apiGet('/v1/top')",
        "this.apiGet('/v1/stats/history/'+range)",
        "'/v1/backup'",
        "'/v1/cache/flush'",
        "'/v1/rewrites'",
        "'/v1/tls/revocation-check'",
        "{{ schemaHasElsewhere }}",
        "{{ schemaNoMatch }}",
        'id="setup-user"',
        "'/v1/setup'",
        "['main-content','query-drawer']",
    ]
    missing_snippets = [snippet for snippet in required_snippets if snippet not in source]
    if missing_snippets:
        fail(f"critical dashboard safeguards missing: {missing_snippets}")
    if "return localized||this.t('이 설정에 대한 설명이 없습니다.');" not in source:
        fail("settings help no longer uses schema-provided descriptions")
    forbidden_snippets = [
        "z.일련번호",
        "setTimeout(()=>this.flushCfgQueue",
        # 제어 토큰은 API 전용이다. 브라우저가 토큰을 보관하거나 담아 보내면 안 된다.
        "localStorage.setItem('onetdns_token'",
        "h.Authorization='Bearer '+token",
        'id="login-token"',
        # 빈 아이콘을 걸면 브라우저가 /favicon.ico로 되물어 감사 기록이 401로 더러워진다.
        '<link rel="icon" href="data:,">',
        # 첫 실행에서 CLI로 내보내지 않는다. 그 명령은 붙여 넣을 곳도 알려 주지 못한다.
        "onetdns --cli passwd --password-stdin",
        # 읽기 전용 잠금이 템플릿 컨트롤만 고르면 React로 만든 버튼이 그대로 눌린다.
        "button[data-dc-tpl],input[data-dc-tpl]",
    ]
    present_forbidden = [snippet for snippet in forbidden_snippets if snippet in source]
    if present_forbidden:
        fail(f"removed dashboard defects returned: {present_forbidden}")
    for dialog in (
        'id="query-drawer" role="dialog"',
        'id="help-dialog" role="dialog"',
        'id="login-gate" role="dialog"',
    ):
        if dialog not in source:
            fail(f"accessible dialog semantics missing: {dialog}")
    if ':focus-visible' not in source or 'aria-live="{{ toastLive }}"' not in source:
        fail("keyboard focus or live-region accessibility support is missing")

    # 확인 대화상자는 답을 기다려야 한다. await 를 빠뜨리면 Promise 가 늘 참이라
    # 대화상자가 뜨는 것과 동시에 지우는 동작이 실행된다 -- 실제로 그렇게 나갔었다.
    if "window.confirm" in source or "window.alert" in source:
        fail("browser native dialogs are back; use the in-app confirm instead")
    for asker in ("confirmDestructive", "confirmConfigImpact", "askConfirm"):
        pattern = "(?<!await )this\\." + asker + "\\("
        for hit in re.finditer(pattern, source):
            head = source[max(0, hit.start() - 40) : hit.start()].rstrip()
            if head.endswith("return"):
                continue
            line = source.count("\n", 0, hit.start()) + 1
            fail(
                "line "
                + str(line)
                + ": this."
                + asker
                + "() is called without await; the confirm resolves later, so the"
                " action would run while the dialog is still open"
            )

    check_chart_curve_stays_in_band(source)
    check_chart_axis_labels_are_evenly_spaced(source)
    check_live_chart_buckets_are_time_anchored(source)
    check_toast_is_never_painted_behind_an_overlay(source)
    check_hidden_row_controls_keep_their_slot(source)
    check_template_names_are_exposed(source)
    check_conditions_use_only_supported_operators(source)

    print(
        "dashboard verification OK: "
        f"{len(scripts)} script blocks, {len(en)} translation keys/language, "
        f"{len(set(parser.values))} static and {len(set(scan_js_string_literals(runtime_scripts)))} dynamic Korean strings checked"
    )


if __name__ == "__main__":
    main()
