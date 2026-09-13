"""The analysis engine: routing, escalation, fallback and cost accounting.

The model is mocked entirely. Routing logic, the vision escalation gate,
fallback behaviour and cost accounting must all be testable without a network
call -- otherwise the suite gets skipped, and an untested engine is one that
quietly produces confident wrong answers.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.analysis import Analysis, Engine, Path_, extract_json, validate  # noqa: E402
from eagle_eyes.cache import SharedCache  # noqa: E402
from eagle_eyes.model_gateway import BudgetGuard, ModelReply, Usage  # noqa: E402

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check


LOG = """11-09-2026 09:41:09.402 [ERROR] Activity 'Post' failed
11-09-2026 09:41:09.404 [ERROR] OpenQA.Selenium.ElementClickInterceptedException: element click intercepted: not clickable at point (642, 318)
  (Session info: chrome=128.0.6613.120)
   at OpenQA.Selenium.WebElement.Click()
   at iBot.Processes.Finance.AP.Post(String r) in C:\\ibot\\AP.cs:line 78
"""
CODE = 'public void Post(string r) { driver.FindElement(By.Id("btnPost")).Click(); }'


class ScriptedBackend:
    """Returns queued replies and records exactly what it was asked."""
    name = "scripted"

    def __init__(self, *replies: str) -> None:
        self.queue = list(replies)
        self.calls: list[dict] = []

    def complete(self, model, system, content, max_tokens=1024) -> ModelReply:
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        self.calls.append({
            "model": model,
            "system": system,
            "prompt": text,
            "has_image": any(b.get("type") == "image" for b in content),
        })
        body = self.queue.pop(0) if self.queue else "{}"
        return ModelReply(text=body, usage=Usage(
            model=model, input_tokens=len(text) // 4, output_tokens=len(body) // 4,
            latency_ms=5, backend=self.name))


class ExplodingBackend:
    name = "boom"

    def complete(self, *a, **k):
        raise RuntimeError("provider unreachable")


MODELS = {"triage": "m-triage", "deep": "m-deep"}


def triage_json(category="novel", needs=False, conf=0.8) -> str:
    return json.dumps({"category": category, "needs_screenshot": needs, "confidence": conf})


def deep_json(conf=0.85) -> str:
    return json.dumps({"root_cause": "A session banner covered the tab.",
                       "suggested_fix": "Dismiss the banner before clicking.",
                       "confidence": conf, "category": "novel"})


def _engine(backend, **kw) -> Engine:
    kw.setdefault("budget", BudgetGuard(daily_usd=99, per_run_usd=99, single_call_usd=99))
    return Engine(backend, MODELS, **kw)


# ------------------------------------------------------------------ routing

def test_noise_stops_before_deep_analysis() -> None:
    b = ScriptedBackend(triage_json("noise", conf=0.9))
    a = _engine(b).analyse(log_text=LOG, code_text=CODE)
    check("noise never reaches the expensive model", len(b.calls) == 1, f"{len(b.calls)} calls")
    check("and is reported as noise", a.category == "noise" and a.path == Path_.SKIPPED.value)


def test_novel_runs_triage_then_deep() -> None:
    b = ScriptedBackend(triage_json(), deep_json())
    a = _engine(b).analyse(log_text=LOG, code_text=CODE, code_path="AP.cs")
    check("two calls: triage then deep", len(b.calls) == 2)
    check("triage used the cheap model", b.calls[0]["model"] == "m-triage")
    check("deep used the deep model", b.calls[1]["model"] == "m-deep")
    check("a diagnosis came back", "banner" in a.root_cause and a.confidence > 0.8)
    check("both usages are accounted for", len(a.usages) == 2)
    check("inputs used are recorded", set(a.inputs_used) == {"log", "code"})


def test_vision_gate() -> None:
    img = b"\x89PNG-not-really"

    b1 = ScriptedBackend(triage_json(needs=True), deep_json())
    a1 = _engine(b1, screenshot_mode=1).analyse(log_text=LOG, code_text=CODE, image=img)
    check("triage asking for vision sends the image", b1.calls[1]["has_image"])
    check("and the path is recorded as vision", a1.path == Path_.VISION.value)
    check("screenshot is listed in inputs", "screenshot" in a1.inputs_used)

    b2 = ScriptedBackend(triage_json(needs=False), deep_json())
    a2 = _engine(b2, screenshot_mode=1).analyse(log_text=LOG, code_text=CODE, image=img)
    check("triage declining vision withholds the image", not b2.calls[1]["has_image"])
    check("and the path is text", a2.path == Path_.TEXT.value)

    # Mode 0 is the security default: no screenshot may reach a model at all.
    b3 = ScriptedBackend(triage_json(needs=True), deep_json())
    a3 = _engine(b3, screenshot_mode=0).analyse(log_text=LOG, code_text=CODE, image=img)
    check("mode 0 overrides triage and sends nothing", not b3.calls[1]["has_image"])
    check("mode 0 keeps the path text-only", a3.path == Path_.TEXT.value)

    # Uncertain triage must not escalate.
    b4 = ScriptedBackend('{"category":"novel","confidence":0.3}', deep_json())
    _engine(b4, screenshot_mode=1).analyse(log_text=LOG, code_text=CODE, image=img)
    check("a triage reply omitting the field defaults to no vision",
          not b4.calls[1]["has_image"])


def test_dedup_short_circuits() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        cache = SharedCache(d)
        b = ScriptedBackend(triage_json(), deep_json())
        e = _engine(b, cache=cache)
        first = e.analyse(log_text=LOG, code_text=CODE, code_mtime="2026-09-01T00:00:00")
        check("the first failure is analysed", len(b.calls) == 2)
        check("and written to the cache", cache.stats["write_ok"] == 1)

        b2 = ScriptedBackend(triage_json(), deep_json())
        e2 = _engine(b2, cache=SharedCache(d))
        second = e2.analyse(log_text=LOG, code_text=CODE, code_mtime="2026-09-01T00:00:00")
        check("an identical failure costs NO model calls", len(b2.calls) == 0)
        check("and returns the same diagnosis", second.root_cause == first.root_cause)
        check("recorded as a dedup hit", second.path == Path_.DEDUP.value)
        check("with zero cost", second.cost_usd == 0.0)

        b3 = ScriptedBackend(triage_json(), deep_json())
        e3 = _engine(b3, cache=SharedCache(d))
        e3.analyse(log_text=LOG, code_text=CODE, code_mtime="2026-09-01T00:00:00", force=True)
        check("force re-analysis bypasses the cache", len(b3.calls) == 2)

        b4 = ScriptedBackend(triage_json(), deep_json())
        e4 = _engine(b4, cache=SharedCache(d))
        e4.analyse(log_text=LOG, code_text=CODE, code_mtime="2026-09-20T00:00:00")
        check("changed code invalidates the cached analysis", len(b4.calls) == 2)
    finally:
        shutil.rmtree(d)


# ----------------------------------------------------------------- failure

def test_malformed_response_never_fabricates() -> None:
    for bad in ("I'm not sure what happened here.", "", "```json\n{broken",
                '{"confidence": 0.9}'):
        b = ScriptedBackend(triage_json(), bad)
        a = _engine(b).analyse(log_text=LOG, code_text=CODE)
        check(f"unparseable reply {bad[:18]!r} -> fallback", a.path == Path_.FALLBACK.value)
        check("  confidence is zero", a.confidence == 0.0)
        check("  and it says so rather than inventing a cause",
              "did not complete" in a.root_cause.lower())


def test_provider_failure_is_reported() -> None:
    a = _engine(ExplodingBackend()).analyse(log_text=LOG, code_text=CODE)
    check("a dead provider degrades, never raises", a.path == Path_.FALLBACK.value)
    check("confidence zero", a.confidence == 0.0)
    check("the reason is surfaced", "unreachable" in a.notes)


def test_budget_stops_before_the_call() -> None:
    b = ScriptedBackend(triage_json(), deep_json())
    e = _engine(b, budget=BudgetGuard(daily_usd=0.001, per_run_usd=0.001, single_call_usd=0.001))
    a = e.analyse(log_text=LOG, code_text=CODE)
    check("no model call is made once the budget is spent", len(b.calls) == 0)
    check("and it is reported honestly", a.path == Path_.FALLBACK.value)


def test_no_exception_in_log() -> None:
    a = _engine(ScriptedBackend()).analyse(log_text="11-09-2026 09:41:09.402 [INFO ] fine")
    check("a clean log is skipped, not analysed", a.path == Path_.SKIPPED.value)
    check("with no model call and no cost", a.cost_usd == 0.0)


# ------------------------------------------------------------------ safety

def test_stale_code_caps_confidence() -> None:
    b = ScriptedBackend(triage_json(), deep_json(conf=0.95))
    a = _engine(b).analyse(log_text=LOG, code_text=CODE, code_path="AP.cs", code_stale=True)
    check("a confident answer on stale code is capped", a.confidence <= 0.5, str(a.confidence))
    check("and the reason is stated", "edited after the failure" in a.notes)
    check("the prompt told the model the code may be stale",
          'possibly_stale="true"' in b.calls[1]["prompt"])


def test_prompt_hygiene() -> None:
    b = ScriptedBackend(triage_json(), deep_json())
    _engine(b).analyse(log_text=LOG, code_text=CODE, code_path="AP.cs")
    for call in b.calls:
        check(f"{call['model']} system prompt marks inputs untrusted",
              "UNTRUSTED DATA" in call["system"])
    check("inputs are delimited in the prompt",
          "<log>" in b.calls[1]["prompt"] and "<code" in b.calls[1]["prompt"])


def test_pii_never_reaches_the_model() -> None:
    dirty = LOG.replace("Activity 'Post' failed",
                        "Activity failed for a.marchetti@example.com card 4111 1111 1111 1111")
    b = ScriptedBackend(triage_json(), deep_json())
    _engine(b).analyse(log_text=dirty, code_text=CODE)
    sent = " ".join(c["prompt"] for c in b.calls)
    check("the email never reaches a prompt", "a.marchetti@example.com" not in sent)
    check("the card never reaches a prompt", "4111 1111 1111 1111" not in sent)
    check("redaction tokens are present instead", "<EMAIL>" in sent and "<CARD>" in sent)
    check("the exception still reaches the model",
          "ElementClickInterceptedException" in sent)


def test_json_extraction() -> None:
    check("plain JSON", extract_json('{"a": 1}') == {"a": 1})
    check("fenced JSON", extract_json('```json\n{"a": 2}\n```') == {"a": 2})
    check("JSON after prose", extract_json('Here you go:\n{"a": 3}') == {"a": 3})
    check("nested braces", extract_json('x {"a": {"b": 1}} y') == {"a": {"b": 1}})
    check("a brace inside a string does not confuse it",
          extract_json('{"a": "not } the end", "b": 2}')["b"] == 2)
    check("prose only", extract_json("no json at all") is None)


def test_confidence_is_clamped() -> None:
    for raw, want in [(1.7, 1.0), (-3, 0.0), ("high", 0.0), (None, 0.0), (0.6, 0.6)]:
        a = validate(ModelReply(text=json.dumps({"root_cause": "x", "confidence": raw}),
                                usage=Usage(model="m")), "text")
        check(f"confidence {raw!r} -> {want}", abs(a.confidence - want) < 1e-9, str(a.confidence))


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
