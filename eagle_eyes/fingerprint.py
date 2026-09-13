"""Turn a failure into a stable identity, so the same failure is analysed once.

Dedup is the system's primary cost control: a hit costs nothing, and docs/
COST_MODEL.md 5 puts it at roughly 70% of all failures. It is also the primary
silent-failure risk -- a fingerprint that fragments produces correct analyses at
three times the price, with nothing reporting a fault.

The rules here are docs/DATA_MODEL.md 2.2a and 2.3, and every one of them exists
because a specific mistake was caught against real-shaped logs:

  * Fingerprint the INNERMOST exception. .NET wraps retried activities, so
    every retry-wrapped failure in the estate would otherwise share one type.
  * Drop Selenium's `(Session info: chrome=...)` trailer. Chrome auto-updates
    monthly; without this, every fingerprint in the estate rotates overnight.
  * Normalize versions BEFORE integers, or `128.0.6613.120` half-mangles into
    `128.0.<NUM>.120` -- still different between builds, now unreadable too.
  * Keep HRESULTs. `COMException (0x800A03EC)` and `(0x80010105)` are different
    faults with different fixes.
  * Use lookarounds, not `\\b`, for the integer rule: there is no word boundary
    between a digit and a letter, so `\\b\\d{4,}\\b` never matches `15000ms`.
  * Normalize pixel coordinates; they vary with window size.

ALGORITHM_VERSION is part of the hash. Changing any rule means bumping it, which
rotates the cache visibly instead of splitting it silently (DATA_MODEL 2.5).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

ALGORITHM_VERSION = 1

_US, _RS = "\x1f", "\x1e"          # value / list separators, unforgeable in input

CHAIN_SEP = " ---> "
CHAIN_END = "--- End of inner exception stack trace ---"

EXC_HEAD = re.compile(r"([\w.`+]+(?:Exception|Error))(?:\s*\(([^)]*)\))?\s*:\s*(.*)", re.DOTALL)
FRAME = re.compile(r"^\s+at\s+([\w.`+]+)\.([\w`<>]+)\s*\(", re.MULTILINE)

# Ordered. Each entry is (pattern, replacement); order is load-bearing.
NORMALIZE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\s*\(Session info:[^)]*\)"), ""),                      # browser build
    (re.compile(r"\s*\(Driver info:[^)]*\)"), ""),
    (re.compile(r"\b\d+(?:\.\d+){2,}\b"), "<VER>"),                      # BEFORE the integer rule
    (re.compile(r"at point \(\s*-?\d+\s*,\s*-?\d+\s*\)"), "at point (<X>,<Y>)"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?"), "<TS>"),
    (re.compile(r"\d{2}[-/]\d{2}[-/]\d{4}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"(?<!\()\b0x[0-9A-Fa-f]+\b(?!\))"), "<ADDR>"),          # bare only; HRESULTs kept
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
    (re.compile(r"[A-Za-z]:\\(?:[^\\\s\"']+\\)*([^\\\s\"']+)"), r"<PATH>/\1"),   # keep basename
    (re.compile(r"\\\\[^\\\s\"']+\\(?:[^\\\s\"']+\\)*([^\\\s\"']+)"), r"<PATH>/\1"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"idx\s*=\s*['\"]?\d+['\"]?"), "idx=<N>"),               # RPA selectors
    (re.compile(r"(?<!\d)\d{4,}(?!\d)"), "<NUM>"),                       # lookarounds, not \b
    (re.compile(r"\s+"), " "),
]


@dataclass(frozen=True)
class Failure:
    """What identity is computed from. All fields come from the sanitized log."""
    exception_type: str
    message: str
    frames: tuple[str, ...]
    code_location: str

    @property
    def normalized_message(self) -> str:
        return normalize(self.message)[:200]


def normalize(text: str) -> str:
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    for pattern, repl in NORMALIZE:
        out = pattern.sub(repl, out)
    return out.strip().lower()


def unwrap(raw: str) -> tuple[str, str]:
    """Split an exception chain and return (innermost_type, innermost_message).

    An HRESULT in `Name (0x…)` position is part of the identity and is kept in
    the type; anything else in parentheses is dropped.
    """
    innermost = raw.split(CHAIN_SEP)[-1].strip()
    m = EXC_HEAD.match(innermost)
    if not m:
        head = raw.split(CHAIN_SEP)[0]
        return (head.split(":")[0].strip(), head)
    name, paren, message = m.group(1), (m.group(2) or ""), m.group(3)
    if paren.lower().startswith("0x"):
        name = f"{name} ({paren})"
    return name.strip(), message.strip()


def top_frames(text: str, limit: int = 5) -> tuple[str, ...]:
    """Frames nearest the fault, with line numbers dropped.

    .NET prints inner-exception frames ABOVE the `--- End of inner exception
    stack trace ---` marker, and those are the ones at the actual fault site.
    Prefer them; fall back to the whole trace when there is no marker.
    """
    head = text.split(CHAIN_END)[0] if CHAIN_END in text else text
    frames = [f"{ns}.{fn}" for ns, fn in FRAME.findall(head)]
    if not frames:
        frames = [f"{ns}.{fn}" for ns, fn in FRAME.findall(text)]
    return tuple(frames[:limit])


def parse(log_text: str, code_location: str = "") -> Failure | None:
    """Build a Failure from a sanitized log. None when no exception is present."""
    text = log_text.replace("\r\n", "\n").replace("\r", "\n")
    err_lines = [ln for ln in text.splitlines() if "[ERROR]" in ln]
    raw = None
    for ln in reversed(err_lines):
        if EXC_HEAD.search(ln):
            idx = text.index(ln)
            raw = text[idx:]
            break
    if raw is None:
        return None

    m = EXC_HEAD.search(raw)
    chain = raw[m.start():].split("\n   at ")[0]
    exc_type, message = unwrap(chain)
    return Failure(
        exception_type=exc_type,
        message=message,
        frames=top_frames(raw),
        code_location=code_location,
    )


def compute(failure: Failure, *, profile: str = "dotnet",
            algorithm_version: int = ALGORITHM_VERSION) -> str:
    """SHA-256 over the normalized tuple.

    `profile` is in the hash so that parsing a log with a different dialect
    profile can never collide with this one, and changing a profile rotates the
    cache visibly (DATA_MODEL 2.5).
    """
    parts = [
        f"v{algorithm_version}",
        profile,
        failure.exception_type.lower(),
        failure.normalized_message,
        _RS.join(f.lower() for f in failure.frames),
        failure.code_location.lower(),
    ]
    return hashlib.sha256(_US.join(parts).encode("utf-8")).hexdigest()


def fingerprint(log_text: str, code_location: str = "", *,
                profile: str = "dotnet") -> tuple[str, Failure] | None:
    f = parse(log_text, code_location)
    return (compute(f, profile=profile), f) if f else None
