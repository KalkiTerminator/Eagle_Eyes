"""Tests for the model boundary. No credentials, no network, no cost."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.model_gateway import (  # noqa: E402
    MODELS, BackendError, BudgetGuard, ByokBackend, MockBackend, Usage,
    _scrub, create_backend, models_for,
)

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

FAKE_KEY = "sk-ant-api03-" + "z" * 40      # not a real key; shape only


def test_backend_selection() -> None:
    check("mock is the default", create_backend({}).name == "mock")
    check("mock selected explicitly", create_backend({"backend": "mock"}).name == "mock")
    try:
        create_backend({"backend": "wat"})
        check("unknown backend rejected", False)
    except BackendError as e:
        check("unknown backend rejected", "unknown backend" in str(e))


def test_byok_governance_guard() -> None:
    """byok outside local needs a named approver -- the point is attribution."""
    check("byok allowed in local", create_backend({"backend": "byok"}, "local") is not None
          if os.environ.get("ANTHROPIC_API_KEY") else True)

    for env in ("exodus", "client", "production"):
        try:
            create_backend({"backend": "byok"}, env)
            check(f"byok refused in '{env}'", False)
        except BackendError as e:
            msg = str(e)
            check(f"byok refused in '{env}'", "refused" in msg)
            check(f"  refusal explains the data path ({env})",
                  "api.anthropic.com" in msg and "AWS account" in msg)

    # with an approver recorded it proceeds to the normal credential path
    try:
        create_backend({"backend": "byok", "byok_approved_by": "J. Okafor, EXL Security"}, "exodus")
        proceeded = True
    except BackendError as e:
        proceeded = "refused" not in str(e)      # a missing key is fine; a refusal is not
    check("a named approver lifts the guard", proceeded)

    check("bedrock never needs an approver",
          "refused" not in _try(lambda: create_backend({"backend": "bedrock", "region": "us-east-1"}, "client")))


def _try(fn) -> str:
    try:
        fn()
        return ""
    except Exception as e:
        return str(e)


def test_key_never_leaks() -> None:
    check("scrubber redacts a key in free text",
          "sk-ant-<REDACTED>" in _scrub(f"failed with key {FAKE_KEY} oh no")
          and FAKE_KEY not in _scrub(f"failed with key {FAKE_KEY}"))

    try:
        from anthropic import Anthropic  # noqa: F401
        sdk = True
    except ImportError:
        sdk = False

    if sdk:
        b = ByokBackend(api_key=FAKE_KEY)
        check("repr shows only a fingerprint", FAKE_KEY not in repr(b) and "..." in repr(b))
        check("key is not stored as a plain attribute",
              not any(FAKE_KEY in str(v) for v in vars(b).values()))
    else:
        print("  SKIP  repr/attribute checks (anthropic SDK not installed here)")


def test_key_file_permissions() -> None:
    if os.name != "posix":
        print("  SKIP  permission check (not posix)")
        return
    d = Path(tempfile.mkdtemp())
    kf = d / "key.txt"
    kf.write_text(FAKE_KEY)
    kf.chmod(0o644)
    try:
        ByokBackend(key_file=kf)
        check("world-readable key file rejected", False)
    except BackendError as e:
        check("world-readable key file rejected", "readable by others" in str(e))

    kf.chmod(0o600)
    err = _try(lambda: ByokBackend(key_file=kf))
    check("mode 600 key file accepted", "readable by others" not in err)


def test_model_ids_differ_by_backend() -> None:
    check("bedrock ids carry the anthropic. prefix",
          all(v.startswith("anthropic.") for v in MODELS["bedrock"].values()))
    check("byok ids carry no prefix",
          not any(v.startswith("anthropic.") for v in MODELS["byok"].values()))
    check("the same logical models either way",
          {k: v.replace("anthropic.", "") for k, v in MODELS["bedrock"].items()} == MODELS["byok"])
    check("models_for falls back to mock", models_for("nonsense") == MODELS["mock"])


def test_cost_accounting() -> None:
    u = Usage(model="claude-sonnet-5", input_tokens=14_200, output_tokens=1_000)
    check("sonnet deep-analysis cost matches COST_MODEL 3",
          abs(u.cost_usd - 0.0384) < 1e-6, f"{u.cost_usd:.6f}")

    b = Usage(model="anthropic.claude-sonnet-5", input_tokens=14_200, output_tokens=1_000)
    check("the anthropic. prefix does not break pricing lookup", abs(b.cost_usd - u.cost_usd) < 1e-9)

    t = Usage(model="claude-haiku-4-5", input_tokens=3_500, output_tokens=150)
    check("haiku triage cost matches COST_MODEL 3", abs(t.cost_usd - 0.00425) < 1e-6, f"{t.cost_usd:.6f}")

    cached = Usage(model="claude-sonnet-5", input_tokens=14_200,
                   cache_read_tokens=9_200, output_tokens=1_000)
    check("cache reads are billed at 0.1x", cached.cost_usd < u.cost_usd)


def test_budget_guard_is_checked_before() -> None:
    g = BudgetGuard(daily_usd=1.0, per_run_usd=0.10, single_call_usd=0.05)
    g.check(0.04)
    check("a normal call passes", True)

    check("an oversized single call is refused", "single call" in _try(lambda: g.check(0.06)))

    for _ in range(2):
        g.record(Usage(model="claude-sonnet-5", input_tokens=14_200, output_tokens=1_000))
    check("the run cap trips once spent", "run budget" in _try(lambda: g.check(0.04)))

    g2 = BudgetGuard(daily_usd=0.05, per_run_usd=10.0, single_call_usd=1.0)
    g2.record(Usage(model="claude-sonnet-5", input_tokens=14_200, output_tokens=1_000))
    check("the daily cap trips independently", "daily budget" in _try(lambda: g2.check(0.02)))


def test_mock_is_usable_without_anything() -> None:
    b = MockBackend()
    r = b.complete("mock-sonnet", "system", [{"type": "text", "text": "a log"}], 100)
    check("mock returns schema-shaped JSON", '"root_cause"' in r.text)
    check("mock records the call", len(b.calls) == 1)
    check("mock costs nothing", r.usage.cost_usd == 0.0)
    check("mock says plainly that nothing was analysed", "MOCK" in r.text)


def test_unknown_pricing_is_not_reported_as_free() -> None:
    known = Usage(model="claude-sonnet-5", input_tokens=1000, output_tokens=100)
    unknown = Usage(model="house-model-v2", input_tokens=1000, output_tokens=100)
    check("a known model is priced", known.priced and known.cost_usd > 0)
    check("an unknown model is flagged unpriced", not unknown.priced)
    check("  and does not claim to be free", unknown.cost_usd == 0.0 and not unknown.priced)
    check("the bedrock prefix still resolves",
          Usage(model="anthropic.claude-sonnet-5", input_tokens=1).priced)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))


