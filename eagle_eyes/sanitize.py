"""Scrub PII and credentials before anything is stored or sent.

Runs synchronously at ingest, before the first durable write -- docs/SECURITY.md
section 4. Nothing downstream is allowed to see the raw text.

Two limitations are deliberate and documented rather than hidden:

  * Personal names are NOT scrubbed. Reliable name detection needs NER, which
    has poor precision on technical logs and would mangle the identifiers,
    class names and method names the diagnosis depends on. We accept that names
    may survive, and compensate with access control and retention. This is an
    explicit question to security (SECURITY.md 9 Q5), not a silent choice.

  * Client-specific identifier formats must be configured per engagement. A
    policy-number format nobody told us about passes straight through, so
    shipping with an empty client ruleset leaves that class unprotected
    (SECURITY.md 9 Q6).

Rules are ordered: the most specific run first, so a card number is not eaten
by the generic long-digit rule before Luhn can confirm it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _luhn(digits: str) -> bool:
    """Card-number checksum, so we only redact things that really are cards."""
    ds = [int(c) for c in digits if c.isdigit()]
    if not 12 <= len(ds) <= 19:
        return False
    total, parity = 0, len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_sub(m: re.Match) -> str:
    return "<CARD>" if _luhn(m.group(0)) else m.group(0)


# --------------------------------------------------------------------------
# Rules, most specific first
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    repl: str | object


SECRET_RULES: list[Rule] = [
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "<SECRET>"),
    Rule("bearer", re.compile(
        r"(?i)\b(bearer|token|apikey|api[_\- ]?key)\s*[:=]?\s*[^\s;,\"']{8,}"), r"\1=<SECRET>"),
    Rule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{8,}"), "<SECRET>"),
    Rule("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "<SECRET>"),
    Rule("aws_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "<SECRET>"),
    Rule("password_kv", re.compile(
        r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*[^\s;,\"']+"), r"\1=<SECRET>"),
    Rule("connstring", re.compile(
        r"(?i)\b(?:Server|Data Source)\s*=\s*[^;\r\n\"']{1,80};"
        r"(?:\s*[\w ]+\s*=\s*[^;\r\n\"']{0,80};)*"), "<CONNSTR>"),
    Rule("url_userinfo", re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://<SECRET>@"),
]

PII_RULES: list[Rule] = [
    Rule("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"), "<EMAIL>"),
    Rule("card", re.compile(r"\b\d(?:[ -]?\d){11,18}\b"), _card_sub),
    Rule("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), "<BANK>"),
    Rule("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<NATID>"),
    Rule("ni", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b"), "<NATID>"),
    Rule("aadhaar", re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"), "<NATID>"),
    Rule("pan", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "<NATID>"),
    # Deliberately conservative: an international prefix, a parenthesised area
    # code, or an explicit phone label. A greedy pattern here matches dates,
    # ports, row counts and IDs -- and destroying those costs more than a
    # missed phone number, which access control and retention already cover
    # (the same argument as for names, above).
    Rule("phone_intl", re.compile(r"(?<![\w.])\+\d{1,3}[\d\s().-]{7,14}\d(?![\w.])"), "<PHONE>"),
    Rule("phone_paren", re.compile(r"(?<![\w.])\(\d{3,5}\)\s?\d[\d\s.-]{5,12}\d(?![\w.])"), "<PHONE>"),
    Rule("phone_labelled", re.compile(
        r"(?i)\b(phone|tel|telephone|mobile|contact)\s*[:=]?\s*\+?[\d\s().-]{7,16}\d"), r"\1: <PHONE>"),
    Rule("postcode_uk", re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b"), "<POSTCODE>"),
]


# --------------------------------------------------------------------------
# Protected spans
# --------------------------------------------------------------------------
#
# Redaction that destroys a log's structure is worse than no redaction: the
# diagnosis depends on timestamps, stack frames and version strings, and a
# scrubbed-to-mush log helps nobody. The first draft of this module had a phone
# rule that matched "11-09-2026 09" and ate every timestamp in the file.
#
# So: freeze the spans that must survive, run the rules on what is left, then
# put them back. Order of protection matters as much as order of redaction.

PROTECT = [
    re.compile(r"\d{2}[-/]\d{2}[-/]\d{4}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"),   # 11-09-2026 09:41:09.402
    re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?"),       # ISO
    re.compile(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}"),                        # screenshot filenames
    re.compile(r"\b\d+(?:\.\d+){2,}\b"),                                       # 128.0.6613.120
    re.compile(r":line \d+"),                                                    # .NET frame suffix
    re.compile(r"^\s+at .*$", re.MULTILINE),                                     # whole stack frames
    re.compile(r"\b0x[0-9A-Fa-f]+\b"),                                           # HRESULTs / addresses
]

_SENTINEL = "\x00P{}\x00"


def _protect(text: str) -> tuple[str, list[str]]:
    frozen: list[str] = []

    def stash(m: re.Match) -> str:
        frozen.append(m.group(0))
        return _SENTINEL.format(len(frozen) - 1)

    for pattern in PROTECT:
        text = pattern.sub(stash, text)
    return text, frozen


def _restore(text: str, frozen: list[str]) -> str:
    """Restore in reverse, then sweep until stable.

    Protection patterns nest: `^\s+at .*$` swallows a whole stack frame that
    may already contain a frozen `:line 78`. Restoring forwards puts the outer
    span back AFTER its inner placeholder was passed, so the inner one is never
    restored and a raw sentinel leaks into the output. Reverse order fixes the
    one-level case; the sweep makes depth irrelevant.
    """
    for i in range(len(frozen) - 1, -1, -1):
        text = text.replace(_SENTINEL.format(i), frozen[i])

    for _ in range(len(frozen) + 1):
        if "\x00P" not in text:
            break
        for i in range(len(frozen) - 1, -1, -1):
            text = text.replace(_SENTINEL.format(i), frozen[i])
    return text


@dataclass
class SanitizeResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def redactions(self) -> int:
        return sum(self.counts.values())

    def summary(self) -> str:
        if not self.counts:
            return "no redactions"
        parts = sorted(self.counts.items(), key=lambda kv: -kv[1])
        return ", ".join(f"{n}x {k}" for k, n in parts)


def _apply(text: str, rules: list[Rule], counts: dict[str, int]) -> str:
    """Apply rules, counting ACTUAL redactions.

    `re.subn` counts matches, not changes. The card rule replaces only when
    Luhn confirms, so a phone number that merely looks card-shaped was being
    counted as a redacted card while the text was left untouched. That number
    is the evidence handed to security that the scrubber works, so an inflated
    one is worse than no count at all.
    """
    for rule in rules:
        if callable(rule.repl):
            hits = [0]

            def _wrapped(m: re.Match, _fn=rule.repl, _h=hits) -> str:
                out = _fn(m)
                if out != m.group(0):
                    _h[0] += 1
                return out

            text = rule.pattern.sub(_wrapped, text)
            n = hits[0]
        else:
            text, n = rule.pattern.subn(rule.repl, text)
        if n:
            counts[rule.name] = counts.get(rule.name, 0) + n
    return text


def client_rules(patterns: dict[str, str]) -> list[Rule]:
    """Per-engagement identifier formats, e.g. {"policy": r"POL-\\d{6}"}.

    Empty by default, and that gap is the point of SECURITY.md 9 Q6: without
    real formats from the engagement, this class of identifier is unprotected.
    """
    return [Rule(f"client_{k}", re.compile(v), f"<CLIENT_{k.upper()}>")
            for k, v in patterns.items()]


def sanitize_log(text: str, client_patterns: dict[str, str] | None = None) -> SanitizeResult:
    counts: dict[str, int] = {}
    out, frozen = _protect(text)
    out = _apply(out, SECRET_RULES, counts)
    out = _apply(out, client_rules(client_patterns or {}), counts)
    out = _apply(out, PII_RULES, counts)
    return SanitizeResult(_restore(out, frozen), counts)


def sanitize_code(text: str, client_patterns: dict[str, str] | None = None) -> SanitizeResult:
    """Code needs the secret rules hardest; PII in source is rarer but happens."""
    counts: dict[str, int] = {}
    out, frozen = _protect(text)
    out = _apply(out, SECRET_RULES, counts)
    # String literals that look like credentials, e.g. Password = "hunter2"
    out, n = re.subn(
        r'(?i)((?:password|pwd|secret|apikey|api_key|token)\s*[:=]\s*)(["\'])[^"\']{3,}\2',
        r'\1\2<SECRET>\2', out)
    if n:
        counts["code_literal"] = counts.get("code_literal", 0) + n
    out = _apply(out, client_rules(client_patterns or {}), counts)
    out = _apply(out, PII_RULES, counts)
    return SanitizeResult(_restore(out, frozen), counts)


# --------------------------------------------------------------------------
# Canary
# --------------------------------------------------------------------------

CANARY = "CANARY-PII-8f3a2b91-DO-NOT-LEAK"


def canary_check(*texts: str) -> list[str]:
    """Return the texts still containing the canary.

    Seed CANARY into a test failure and assert it never reaches a stored
    analysis or a prompt. A scrubber nobody verifies is a scrubber nobody
    should trust (SECURITY.md 4.3).
    """
    return [t for t in texts if CANARY in t]
