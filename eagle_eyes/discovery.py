"""Find failures on the share and assemble their three inputs.

Given anything the user points at -- one log file, a date folder, a bot folder,
a whole service line -- produce a list of FailureCandidate, each carrying its
log, its screenshot (paired per docs/ARCHITECTURE.md 4.4) and its code file.

Nothing here calls a model or writes anything. Discovery is read-only and
free, so it can always be shown to the user before they commit to a run.
"""

from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Tree layout. Configurable because it is one estate change from being wrong.
# ---------------------------------------------------------------------------

LOGS_SUBDIR = ("logs", "user logs", "logs")
SHOTS_SUBDIR = ("logs", "user logs", "screenshot")

CAPTURE_RE = re.compile(r"Screenshot captured:\s*(.+?)\s*$", re.MULTILINE)
HEADER_RE = re.compile(r"^(\w[\w ]*?)\s*:\s*(.+?)\s*$", re.MULTILINE)
EXC_RE = re.compile(
    r"\[ERROR\]\s*((?:OpenQA|System|iBot)[\w.]*(?:Exception|Error)\s*:.+?)"
    r"(?=\r?\n\s*\(Session info|\r?\n\s+at |\r?\n\d{2}-)",
    re.DOTALL,
)
SHOT_TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})")
LOG_TS_RE = re.compile(r"(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})")

# Screenshot is written just after the log line, effectively never before.
PAIR_WINDOW_BEFORE = timedelta(seconds=2)
PAIR_WINDOW_AFTER = timedelta(seconds=10)


@dataclass
class TreeLocation:
    service_line: str
    bot_number: str
    date: str          # YYYY-MM-DD

    @property
    def label(self) -> str:
        return f"{self.service_line}/{self.bot_number}/{self.date}"


@dataclass
class FailureCandidate:
    log_path: Path
    location: TreeLocation
    exception_type: str = ""
    message: str = ""
    occurred_at: datetime | None = None

    screenshot_path: Path | None = None
    pairing_method: str = "none"          # log_path | timestamp | none
    pairing_note: str = ""

    code_path: Path | None = None
    code_mtime: datetime | None = None
    code_possibly_stale: bool = False

    # user-controllable
    selected: bool = True
    send_screenshot: bool = True
    force_reanalyze: bool = False

    alternatives: list[Path] = field(default_factory=list)

    @property
    def inputs(self) -> str:
        bits = ["log"]
        if self.code_path:
            bits.append("code*" if self.code_possibly_stale else "code")
        if self.screenshot_path and self.send_screenshot:
            bits.append("shot")
        return "+".join(bits)


def decode_text(raw: bytes) -> str:
    """Decode whatever encoding Windows used, normalising line endings.

    The encoding list is not decoration: iBot logs come off Windows hosts as
    utf-8 with a BOM, as utf-16 when something used a .NET default, and as
    cp1252 when an application wrote bytes it called text. Guessing wrong turns
    a stack trace into mojibake and the fingerprint into noise.

    Universal newlines matter for the same reason: CRLF riding into the hash
    made one failure fingerprint differently on Windows and Linux, which is a
    dedup rate silently cut in half.
    """
    # utf-16 is tried ONLY behind a byte-order mark. Without one, any cp1252
    # log with an even number of bytes decodes "successfully" as utf-16 into
    # CJK gibberish -- b"caf\xe9\r\n" comes back as three unrelated
    # characters. No exception, no warning, and the fingerprint downstream is
    # computed over nonsense. A BOM is the only honest signal that a file is
    # utf-16, so that is what gates it.
    encodings = ["utf-8-sig", "utf-8"]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encodings.insert(0, "utf-16")
    encodings.append("cp1252")

    for enc in encodings:
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
        return _newlines(text)
    return _newlines(raw.decode("utf-8", errors="replace"))


def _newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def read_text(path: Path) -> str:
    """Read a file with decode_text's encoding handling."""
    return decode_text(Path(path).read_bytes())


def parse_location(log_path: Path, share_root: Path) -> TreeLocation | None:
    """service_line / bot / Y / M / D from the path, not from file content."""
    try:
        rel = log_path.resolve().relative_to(share_root.resolve()).parts
    except ValueError:
        return None
    if len(rel) < 9 or rel[0] != "data":
        return None
    sl, bot, y, m, d = rel[1], rel[2], rel[3], rel[4], rel[5]
    if not (y.isdigit() and m.isdigit() and d.isdigit()):
        return None
    return TreeLocation(sl, bot, f"{y}-{m}-{d}")


def _parse_log_ts(text: str) -> datetime | None:
    m = LOG_TS_RE.search(text)
    if not m:
        return None
    d, mo, y, h, mi, s = (int(x) for x in m.groups())
    try:
        return datetime(y, mo, d, h, mi, s)
    except ValueError:
        return None


def failure_time(text: str) -> datetime | None:
    """When the failure happened -- the timestamp on the line carrying the exception.

    Not the header's 'Started', which is when the RUN began and can be half an
    hour earlier, and not the trailing 'Run terminated' line either. Both are
    easy to pick up by accident and both are wrong:

      - as `occurred_at` it misreports the failure and skews the code-staleness
        comparison (docs/ARCHITECTURE.md 4.5), which asks whether the code file
        was edited after the failure;
      - as the screenshot pairing anchor it shifts the matching window by
        seconds, which quietly changes which screenshots fall inside it.

    Falls back to the last ERROR line, then to the first timestamp present.
    """
    err_lines = [ln for ln in text.splitlines() if "[ERROR]" in ln]
    for ln in reversed(err_lines):
        if EXC_RE.search(ln) or re.search(r"(?:Exception|Error)\s*:", ln):
            if (ts := _parse_log_ts(ln)) is not None:
                return ts
    for ln in reversed(err_lines):
        if (ts := _parse_log_ts(ln)) is not None:
            return ts
    return _parse_log_ts(text)


def _shot_ts(path: Path) -> datetime | None:
    m = SHOT_TS_RE.search(path.name)
    if not m:
        return None
    return datetime(*(int(x) for x in m.groups()))


def pair_screenshot(log_path: Path, text: str) -> tuple[Path | None, str, str, list[Path]]:
    """Return (screenshot, method, note, alternatives).

    Primary: the log names the file. Take the BASENAME -- the logged path is the
    bot VM's local drive (D:\\...), not the share we read over. See
    docs/ARCHITECTURE.md 4.4.
    """
    shots_dir = log_path.parent.parent / "screenshot"
    available = sorted(shots_dir.glob("*.png")) if shots_dir.is_dir() else []

    m = CAPTURE_RE.search(text)
    if m:
        name = ntpath.basename(m.group(1).strip())
        candidate = shots_dir / name
        if candidate.is_file():
            return candidate, "log_path", "named by the log", available
        return None, "none", f"log names {name}, not present on the share", available

    # Fallback: no capture line. Match on the clock, refuse if ambiguous.
    anchor = failure_time(text)
    if anchor is None:
        return None, "none", "no capture line and no usable timestamp", available

    near = [p for p in available
            if (ts := _shot_ts(p)) is not None
            and anchor - PAIR_WINDOW_BEFORE <= ts <= anchor + PAIR_WINDOW_AFTER]
    if len(near) == 1:
        return near[0], "timestamp", "matched on time (no capture line)", available
    if len(near) > 1:
        return None, "none", f"{len(near)} screenshots in window - refusing to guess", available
    return None, "none", "no capture line, no screenshot near that time", available


def resolve_code(loc: TreeLocation, code_root: Path,
                 occurred_at: datetime | None) -> tuple[Path | None, datetime | None, bool]:
    """Find the bot's code file. Naming convention is OPEN_QUESTIONS.md D7."""
    for name in (f"{loc.bot_number}.txt",
                 f"{loc.service_line}_{loc.bot_number}.txt",
                 f"{loc.bot_number}.cs.txt"):
        p = code_root / name
        if p.is_file():
            mtime = datetime.fromtimestamp(p.stat().st_mtime)
            stale = occurred_at is not None and mtime > occurred_at
            return p, mtime, stale
    hits = sorted(code_root.glob(f"*{loc.bot_number}*"))
    if hits:
        mtime = datetime.fromtimestamp(hits[0].stat().st_mtime)
        return hits[0], mtime, occurred_at is not None and mtime > occurred_at
    return None, None, False


def build_candidate(log_path: Path, share_root: Path, code_root: Path) -> FailureCandidate | None:
    loc = parse_location(log_path, share_root)
    if loc is None:
        return None
    text = read_text(log_path)

    cand = FailureCandidate(log_path=log_path, location=loc)
    if (m := EXC_RE.search(text)):
        raw = m.group(1)
        innermost = raw.split(" ---> ")[-1]
        exc, _, msg = innermost.partition(":")
        cand.exception_type = exc.strip()
        cand.message = " ".join(msg.split())[:300]
    cand.occurred_at = failure_time(text)

    shot, method, note, alts = pair_screenshot(log_path, text)
    cand.screenshot_path, cand.pairing_method, cand.pairing_note = shot, method, note
    cand.alternatives = alts
    cand.send_screenshot = shot is not None

    cand.code_path, cand.code_mtime, cand.code_possibly_stale = resolve_code(
        loc, code_root, cand.occurred_at)
    return cand


def discover(target: Path, share_root: Path, code_root: Path) -> list[FailureCandidate]:
    """target may be one .log file or any folder in the tree."""
    target = Path(target)
    if target.is_file():
        logs = [target]
    elif target.is_dir():
        logs = sorted(p for p in target.rglob("*.log") if p.parent.name == "logs")
    else:
        raise FileNotFoundError(target)

    out = []
    for lp in logs:
        c = build_candidate(lp, share_root, code_root)
        if c is not None:
            out.append(c)
    return out
