"""The known-pattern library: failures whose fix is already written down.

A pattern is matched against the failure itself -- its exception class and its
message -- not against the fingerprint.

That distinction is the whole reason this file exists. The zero-cost template
path was keyed on the fingerprint hash, and a fingerprint identifies ONE exact
failure: the same exception, the same normalized message, the same top stack
frames, the same code location. A template keyed on it could only ever answer
the single failure it was written for, so nothing was ever worth putting in it
and nothing ever was. Matching on the class of failure is what makes a library
of eight entries able to answer thousands of failures for nothing.

Matching is deliberately conservative, because the cost of a wrong template is
much higher than the cost of a model call:

  * A rule needs the exception class AND the message to agree. Either alone is
    not enough -- HttpRequestException covers 401, 429, DNS failure and a TLS
    error, and "timed out" appears in a selector failure that had nothing to do
    with the network.
  * `exception_any` matches the CLASS NAME -- the segment after the last dot --
    exactly. As a substring, "TimeoutException" also matches
    "WebDriverTimeoutException", which is a selector problem wearing a timeout's
    name and would get the wrong fix.
  * `exclude_any` disqualifies a match outright, so a pattern can say "this
    looks like me and is not".
  * A pattern whose rule would match everything is refused at load rather than
    quietly answering every failure in the estate.

A template answer is not a diagnosis of the failure in front of you; it is the
standard fix for failures of its class. It says so, and it carries a lower
confidence than a real analysis for that reason.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

LIBRARY_PATH = Path(__file__).parent / "patterns.json"

# What a template answer is worth. Below the band a real analysis reaches when
# the evidence points at one cause (0.8-1.0, see prompts/deep.system.txt), and
# deliberately in "a likely cause, with a plausible alternative" territory: the
# fix is known to be right for this CLASS of failure and unverified against this
# one. Presenting it at 0.9 would be the system lying about what it did.
TEMPLATE_CONFIDENCE = 0.6


class PatternError(ValueError):
    """A library entry that would be unsafe or meaningless to load."""


def _class_name(exception_type: str) -> str:
    """`OpenQA.Selenium.NoSuchElementException` -> `nosuchelementexception`."""
    return exception_type.strip().rsplit(".", 1)[-1].strip().lower()


@dataclass(frozen=True)
class Pattern:
    name: str
    failure_type: str
    severity: str
    root_cause: str
    suggested_fix: str
    affected_function: str = ""
    exception_any: tuple[str, ...] = ()
    message_any: tuple[str, ...] = ()
    exclude_any: tuple[str, ...] = ()

    def matches(self, exception_type: str, message: str) -> bool:
        cls = _class_name(exception_type)
        if cls not in self.exception_any:
            return False
        text = f"{exception_type} {message}".lower()
        if any(term in text for term in self.exclude_any):
            return False
        return any(term in text for term in self.message_any)


def _rule(raw: Any, name: str, key: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
        raise PatternError(f"pattern {name!r}: {key} must be a list of strings")
    return tuple(x.strip().lower() for x in raw if x.strip())


def load_patterns(path: Path | None = None) -> list[Pattern]:
    """Read the library file. Raises rather than returning a broken library.

    A pattern answers real failures for free and without review, so a malformed
    entry must stop the load loudly. Silently skipping it would leave a library
    that looks complete and quietly escalates everything it should have caught,
    or -- worse -- one whose surviving entries are wider than intended.
    """
    data = json.loads((path or LIBRARY_PATH).read_text(encoding="utf-8"))
    out: list[Pattern] = []
    seen: set[str] = set()
    for entry in data.get("patterns", []):
        name = str(entry.get("name", "")).strip()
        if not name:
            raise PatternError("a pattern has no name")
        if name in seen:
            raise PatternError(f"duplicate pattern name {name!r}")
        seen.add(name)

        rule = entry.get("match_rule") or {}
        exception_any = _rule(rule.get("exception_any"), name, "exception_any")
        message_any = _rule(rule.get("message_any"), name, "message_any")
        exclude_any = _rule(rule.get("exclude_any"), name, "exclude_any")
        if not exception_any or not message_any:
            raise PatternError(
                f"pattern {name!r} needs both exception_any and message_any. One "
                "alone matches far more than it means to -- the exception class "
                "says how the failure was thrown, not what went wrong.")

        from .analysis import FAILURE_TYPES, SEVERITIES
        failure_type = str(entry.get("failure_type", "")).strip().lower()
        severity = str(entry.get("severity", "")).strip().lower()
        if failure_type not in FAILURE_TYPES:
            raise PatternError(f"pattern {name!r}: unknown failure_type {failure_type!r}")
        if severity not in SEVERITIES:
            raise PatternError(f"pattern {name!r}: unknown severity {severity!r}")

        for required in ("root_cause", "suggested_fix"):
            if not str(entry.get(required, "")).strip():
                raise PatternError(f"pattern {name!r} has no {required}")

        out.append(Pattern(
            name=name, failure_type=failure_type, severity=severity,
            root_cause=str(entry["root_cause"]).strip(),
            suggested_fix=str(entry["suggested_fix"]).strip(),
            affected_function=str(entry.get("affected_function", "")).strip(),
            exception_any=tuple(_class_name(x) for x in exception_any),
            message_any=message_any, exclude_any=exclude_any))
    if not out:
        raise PatternError("the pattern library is empty")
    return out


@dataclass
class PatternLibrary:
    """The patterns in force, in order. First match wins.

    Order is load-bearing and comes from the file, so a narrow pattern can be
    placed ahead of a broad one. `timeout` excludes selector wording and sits
    first for exactly that reason.
    """
    patterns: list[Pattern] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path | None = None) -> "PatternLibrary":
        return cls(load_patterns(path))

    @classmethod
    def empty(cls) -> "PatternLibrary":
        return cls([])

    def __len__(self) -> int:
        return len(self.patterns)

    def match(self, exception_type: str, message: str) -> Pattern | None:
        for p in self.patterns:
            if p.matches(exception_type, message):
                return p
        return None

    def names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self.patterns)


def from_rows(rows: Iterable[Any]) -> PatternLibrary:
    """Build a library from `pattern` table rows.

    The table is what the product actually reads, so a pattern can be switched
    off in the database without a redeploy. `match_rule` is stored as JSON
    because that is what the column has always been declared to hold.
    """
    out: list[Pattern] = []
    for row in rows:
        # A dialect seam. `match_rule` is TEXT in SQLite and JSONB in
        # PostgreSQL, so psycopg hands back a dict where sqlite3 hands back a
        # string -- and json.loads on the dict raises. Decoding here rather
        # than normalising the column keeps JSONB, which is what makes the
        # table queryable on a real server.
        raw = row["match_rule"]
        rule = json.loads(raw or "{}") if isinstance(raw, (str, bytes)) else (raw or {})
        out.append(Pattern(
            name=row["name"],
            failure_type=rule.get("failure_type", "other"),
            severity=row["severity"],
            root_cause=rule.get("root_cause", ""),
            suggested_fix=row["response_template"],
            affected_function=rule.get("affected_function", ""),
            exception_any=tuple(rule.get("exception_any", ())),
            message_any=tuple(rule.get("message_any", ())),
            exclude_any=tuple(rule.get("exclude_any", ()))))
    return PatternLibrary(out)


def to_row(p: Pattern) -> dict[str, Any]:
    """The inverse of `from_rows`, for seeding the table."""
    return {
        "name": p.name,
        "severity": p.severity,
        "response_template": p.suggested_fix,
        "match_rule": json.dumps({
            "failure_type": p.failure_type,
            "root_cause": p.root_cause,
            "affected_function": p.affected_function,
            "exception_any": list(p.exception_any),
            "message_any": list(p.message_any),
            "exclude_any": list(p.exclude_any),
        }, sort_keys=True),
    }
