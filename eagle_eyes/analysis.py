"""The analysis engine: triage, route, diagnose, validate.

Pipeline for one failure, per docs/ARCHITECTURE.md section 6:

    sanitize -> fingerprint -> dedup check -> triage -> route -> deep -> validate

Cost control lives in the routing, not in the model choice. In order of effect
(docs/COST_MODEL.md 7): a dedup hit costs nothing, a known-pattern template
costs nothing, triage on a cheap model stops noise reaching an expensive one,
and only then does the choice of text-versus-vision matter -- which is worth
about 6% and is kept mainly as a privacy and quality control.

Prompts live in prompts/ as files, never as inline strings, so they can be
diffed and reviewed like anything else.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .cache import CachedAnalysis, SharedCache
from .fingerprint import Failure, fingerprint
from .model_gateway import Backend, BudgetGuard, ModelReply, Usage
from .sanitize import sanitize_code, sanitize_log

# The screenshot policy modes that EXIST. docs/SECURITY.md section 7 designs
# four; two of them are drawings.
#
#   0  the image is never read and never sent. The report links to where the
#      bot wrote it, on a share the reader could already reach.
#   3  the image is sent to the model exactly as captured -- whole desktop,
#      whatever was on screen, nothing cropped and nothing redacted.
#
# Modes 1 (crop to the failing window) and 2 (crop, then OCR-redact) are the
# ones worth having and neither is built. They are deliberately absent from
# this set rather than accepted and quietly treated as mode 3: a mode that
# claims to protect and does not is worse than no mode at all, because someone
# picks it and stops worrying.
SCREENSHOT_MODES = {0, 3}

# What KIND of failure this is -- a separate axis from `category`, which holds
# the routing decision (noise | known_pattern | novel). The POC prompt kit
# called both of them "category"; two axes deserve two names, and conflating
# them would make "was this deduplicated" and "was this a timeout" the same
# column.
#
# The list is closed because it drives colour, filtering and the known-pattern
# match. A model inventing a nineteenth type would silently fall out of every
# chart, so anything unrecognised becomes `other` rather than being stored.
FAILURE_TYPES = {
    "timeout", "auth", "network", "data_validation", "rate_limit",
    "ssl", "file_io", "selector", "logic_error", "other",
}

# Ordered, because "is this worse than that" is the question a manager asks.
SEVERITIES = ("low", "medium", "high", "critical")

PROMPTS = Path(__file__).parent / "prompts"

# Caps keep one runaway log from blowing the context window and the budget.
LOG_EXCERPT_CHARS = 12_000
CODE_CHARS = 40_000


class Path_(str, Enum):
    DEDUP = "dedup"
    TEMPLATE = "template"
    TEXT = "text"
    VISION = "vision"
    FALLBACK = "fallback"
    SKIPPED = "skipped"


@dataclass
class Analysis:
    root_cause: str
    suggested_fix: str
    confidence: float
    path: str
    category: str = "novel"          # routing: noise | known_pattern | novel
    failure_type: str = ""           # taxonomy: timeout | auth | ssl | ...
    severity: str = ""               # low | medium | high | critical
    affected_function: str = ""
    recommendations: str = ""
    notes: str = ""
    inputs_used: tuple[str, ...] = ()
    model_id: str = ""
    usages: list[Usage] = field(default_factory=list)
    fingerprint: str = ""
    code_possibly_stale: bool = False

    @property
    def cost_usd(self) -> float:
        return sum(u.cost_usd for u in self.usages)

    @property
    def fully_priced(self) -> bool:
        """False when any call used a model with no known rate."""
        return all(u.priced for u in self.usages)

    @property
    def latency_ms(self) -> int:
        return sum(u.latency_ms for u in self.usages)


def load_prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Response handling
# --------------------------------------------------------------------------

def extract_json(text: str) -> dict | None:
    """Pull a JSON object out of a reply that may be wrapped in prose or fences."""
    if not text:
        return None
    for candidate in (text, *re.findall(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)):
        try:
            obj = json.loads(candidate.strip())
            if isinstance(obj, dict):
                return obj
        except ValueError:
            continue
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    return None


def _clamp_confidence(value: object) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _failure_type(value) -> str:
    """Normalise to the closed set, or "" when the model did not say.

    Deliberately not a raise. These fields arrived after thousands of analyses
    were already stored, and a model that omits one -- or invents one -- must
    not turn a good root cause into a parse failure. An empty string reads as
    "not classified" everywhere it is displayed.
    """
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not text:
        return ""
    return text if text in FAILURE_TYPES else "other"


def _severity(value) -> str:
    text = str(value or "").strip().lower()
    return text if text in SEVERITIES else ""


def validate(reply: ModelReply, path: str) -> Analysis:
    """Turn a reply into an Analysis, or into an honest failure.

    A malformed response must never become a fabricated diagnosis presented as
    confident. When parsing fails we say the analysis did not complete and set
    confidence to zero -- docs/ARCHITECTURE.md section 7.
    """
    data = extract_json(reply.text)
    if not data or not str(data.get("root_cause", "")).strip():
        return Analysis(
            root_cause="Analysis did not complete: the model's response could not be parsed.",
            suggested_fix="No fix suggested. Re-run this failure, or inspect it by hand.",
            confidence=0.0,
            path=Path_.FALLBACK.value,
            notes=f"Unparseable response ({len(reply.text)} chars).",
            model_id=reply.usage.model,
            usages=[reply.usage],
        )
    return Analysis(
        root_cause=str(data["root_cause"]).strip(),
        suggested_fix=str(data.get("suggested_fix", "")).strip() or "No fix suggested.",
        confidence=_clamp_confidence(data.get("confidence")),
        path=path,
        category=str(data.get("category", "novel")),
        failure_type=_failure_type(data.get("failure_type")),
        severity=_severity(data.get("severity")),
        affected_function=str(data.get("affected_function") or "").strip()[:120],
        recommendations=str(data.get("recommendations") or "").strip()[:2000],
        notes=str(data.get("notes", "")),
        model_id=reply.usage.model,
        usages=[reply.usage],
    )


@dataclass
class TriageResult:
    category: str
    needs_screenshot: bool
    confidence: float
    usage: Usage | None = None
    notes: str = ""


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class Engine:
    """Owns routing. Knows nothing about providers beyond the Backend protocol."""

    def __init__(self, backend: Backend, models: dict[str, str], *,
                 budget: BudgetGuard | None = None,
                 cache: SharedCache | None = None,
                 screenshot_mode: int = 0,
                 client_patterns: dict[str, str] | None = None,
                 reuse_ttl_days: int = 30) -> None:
        self.backend = backend
        self.models = models
        self.budget = budget or BudgetGuard()
        self.cache = cache
        if screenshot_mode not in SCREENSHOT_MODES:
            raise ValueError(
                f"screenshot_mode {screenshot_mode} does not exist. "
                f"Valid modes: {sorted(SCREENSHOT_MODES)}. "
                "Modes 1 (crop) and 2 (OCR-redact) are designed in docs/SECURITY.md "
                "section 7 but no such code has been written -- selecting one would "
                "have sent the raw screenshot while reporting it protected.")
        self.screenshot_mode = screenshot_mode
        self.client_patterns = client_patterns or {}
        self.reuse_ttl = timedelta(days=reuse_ttl_days)
        self.templates: dict[str, str] = {}

    # -- stages ------------------------------------------------------------

    def triage(self, failure: Failure, log_excerpt: str, code_summary: str,
               bot_label: str) -> TriageResult:
        model = self.models.get("triage", "")
        prompt = load_prompt("triage.user.txt").format(
            bot_label=bot_label, exception_type=failure.exception_type,
            log_excerpt=log_excerpt, code_summary=code_summary)
        self.budget.check(0.01)
        reply = self.backend.complete(
            model, load_prompt("triage.system.txt"),
            [{"type": "text", "text": prompt}], 512)
        self.budget.record(reply.usage)

        data = extract_json(reply.text) or {}
        category = str(data.get("category", "novel"))
        if category not in ("noise", "known_pattern", "novel"):
            category = "novel"
        return TriageResult(
            category=category,
            # Uncertain triage must not escalate: the default is text-only.
            needs_screenshot=bool(data.get("needs_screenshot", False)),
            confidence=_clamp_confidence(data.get("confidence")),
            usage=reply.usage,
            notes=str(data.get("notes", "")),
        )

    def deep(self, failure: Failure, log_excerpt: str, code_text: str,
             code_path: str, code_stale: bool, bot_label: str,
             image: bytes | None = None) -> Analysis:
        inputs = ["log"]
        if code_text:
            inputs.append("code")
        use_vision = image is not None and self.screenshot_mode > 0
        if use_vision:
            inputs.append("screenshot")

        prompt = load_prompt("deep.user.txt").format(
            inputs_provided=", ".join(inputs), bot_label=bot_label,
            exception_type=failure.exception_type, log_excerpt=log_excerpt,
            code_path=code_path or "(none)",
            code_stale="true" if code_stale else "false",
            code_text=code_text or "(no code file available)")

        content: list[dict] = [{"type": "text", "text": prompt}]
        if use_vision:
            content.append({"type": "image", "data": image})

        model = self.models.get("deep", "")
        self.budget.check(0.06)
        reply = self.backend.complete(model, load_prompt("deep.system.txt"), content, 4096)
        self.budget.record(reply.usage)

        analysis = validate(reply, Path_.VISION.value if use_vision else Path_.TEXT.value)
        analysis.inputs_used = tuple(inputs)
        analysis.code_possibly_stale = code_stale
        return analysis

    # -- the whole path ----------------------------------------------------

    def analyse(self, *, log_text: str, code_text: str = "", code_path: str = "",
                code_mtime: str | None = None, code_stale: bool = False,
                bot_label: str = "", code_location: str = "",
                image: bytes | None = None, force: bool = False) -> Analysis:
        """One failure, start to finish. Never raises on model trouble."""
        clean_log = sanitize_log(log_text, self.client_patterns).text
        clean_code = sanitize_code(code_text, self.client_patterns).text if code_text else ""

        fp_result = fingerprint(clean_log, code_location)
        if fp_result is None:
            return Analysis(
                root_cause="No exception found in this log.",
                suggested_fix="Nothing to diagnose. Check that the right file was selected.",
                confidence=0.0, path=Path_.SKIPPED.value)
        fp, failure = fp_result

        # 1. Dedup -- free, and the largest single saving.
        if not force and self.cache:
            hit = self.cache.get(fp, 1, code_mtime=code_mtime)
            if hit:
                return Analysis(
                    root_cause=hit.root_cause, suggested_fix=hit.suggested_fix,
                    confidence=hit.confidence, path=Path_.DEDUP.value,
                    model_id=hit.model_id, fingerprint=fp,
                    notes=f"Reused an analysis from {hit.created_at}.")

        # 2. Known pattern -- also free.
        if fp in self.templates:
            return Analysis(
                root_cause=self.templates[fp], suggested_fix=self.templates[fp],
                confidence=0.9, path=Path_.TEMPLATE.value, category="known_pattern",
                fingerprint=fp)

        log_excerpt = clean_log[-LOG_EXCERPT_CHARS:]
        code_for_model = clean_code[:CODE_CHARS]

        # 3. Triage on the cheap model.
        try:
            t = self.triage(failure, log_excerpt, code_for_model[:2000], bot_label)
        except Exception as exc:
            return self._degraded(fp, f"Triage failed: {exc}")

        if t.category == "noise":
            a = Analysis(
                root_cause="Classified as noise; no action needed.",
                suggested_fix="None.", confidence=t.confidence,
                path=Path_.SKIPPED.value, category="noise", fingerprint=fp,
                notes=t.notes)
            if t.usage:
                a.usages.append(t.usage)
            return a

        # 4. Deep analysis. The escalation gate decides vision.
        send_image = image if (t.needs_screenshot and self.screenshot_mode > 0) else None
        try:
            a = self.deep(failure, log_excerpt, code_for_model, code_path,
                          code_stale, bot_label, send_image)
        except Exception as exc:
            return self._degraded(fp, f"Analysis failed: {exc}")

        a.fingerprint = fp
        a.category = t.category
        if t.usage:
            a.usages.insert(0, t.usage)

        # Stale code cannot support a confident line-level claim.
        if code_stale:
            a.confidence = min(a.confidence, 0.5)
            a.notes = (a.notes + " Code file was edited after the failure; "
                                 "it may not be what the bot was running.").strip()

        if self.cache and a.path in (Path_.TEXT.value, Path_.VISION.value) and a.confidence > 0:
            self.cache.put(CachedAnalysis(
                fingerprint=fp, fingerprint_version=1, root_cause=a.root_cause,
                suggested_fix=a.suggested_fix, confidence=a.confidence,
                path=a.path, model_id=a.model_id, code_mtime=code_mtime))
        return a

    def _degraded(self, fp: str, why: str) -> Analysis:
        """A model or budget problem is reported, never disguised as a diagnosis."""
        return Analysis(
            root_cause=f"Analysis could not be completed. {why}",
            suggested_fix="Re-run this failure once the cause above is resolved.",
            confidence=0.0, path=Path_.FALLBACK.value, fingerprint=fp, notes=why)
