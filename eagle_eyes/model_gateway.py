"""The only module permitted to import a model SDK.

Nothing outside this file imports `anthropic`, boto3, or any provider type.
Swapping provider touches this module and nothing else; CI enforces it with an
import check.

Three backends:

    bedrock   Claude on Amazon Bedrock, in the client's own AWS account.
    byok      Bring Your Own Key -- Claude API direct, with a key you supply.
    mock      Canned responses. No credentials, no network, no cost.

BACKEND CHOICE IS A DATA-GOVERNANCE DECISION, NOT A CONVENIENCE.

With `bedrock`, inference runs inside the client's AWS account and region.
With `byok`, prompt content leaves for api.anthropic.com -- a third party from
the client's point of view. Those are different answers to "where does client
data go", which is the question docs/SECURITY.md is built around.

So `byok` is refused outside local development unless someone is named in
`byok_approved_by`. That is not a technical guard -- it is there so the choice
is deliberate and attributable rather than a line someone changed in a config
file. See docs/SECURITY.md section 12.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

# --------------------------------------------------------------------------
# Model identifiers. Bedrock carries the `anthropic.` prefix; the direct API
# does not. Everything else about the call is identical.
# --------------------------------------------------------------------------

MODELS = {
    "bedrock": {"triage": "anthropic.claude-haiku-4-5",
                "deep":   "anthropic.claude-sonnet-5",
                "opus":   "anthropic.claude-opus-5"},
    "byok":    {"triage": "claude-haiku-4-5",
                "deep":   "claude-sonnet-5",
                "opus":   "claude-opus-5"},
    "mock":    {"triage": "mock-haiku", "deep": "mock-sonnet", "opus": "mock-opus"},
}

# What the model dropdown may offer, and which role each one substitutes for
# `deep`. `smart` is the default and overrides nothing.
#
# An override REPLACES THE DEEP MODEL ONLY. Triage still runs on Haiku, so noise
# is still dropped for a fraction of a cent and only the failures that survive
# reach the chosen model. The POC kit skipped triage entirely on an override,
# which is simpler to explain and sends every noisy line in a batch to Opus.
SELECTABLE: dict[str, tuple[str, str]] = {
    "smart":  ("", "Smart routing — Haiku triages, Sonnet 5 diagnoses"),
    "haiku":  ("triage", "Haiku 4.5 only — fastest and cheapest"),
    "sonnet": ("deep", "Sonnet 5 only — the default diagnosis model"),
    "opus":   ("opus", "Opus 5 only — for the hardest cases"),
}

# USD per million tokens. These are Anthropic first-party list rates and apply
# to `byok`. Bedrock is partner-operated and priced separately -- the table
# below is a PLANNING PROXY for it, not a quote. Re-derive Bedrock figures from
# https://aws.amazon.com/bedrock/pricing/ for your region before any number
# here goes near a budget. docs/COST_MODEL.md section 1 says the same.
PRICING = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-5":  (2.00, 10.00),
    "claude-opus-5":    (5.00, 25.00),
}

# The token profile a call is ASSUMED to have, for the budget check that runs
# before it. docs/COST_MODEL.md section 3 pins these figures and two tests
# assert the resulting costs.
PROFILE = {"deep": (14_200, 1_000), "triage": (3_500, 150)}

# How much the pre-call projection over-estimates. The real token counts arrive
# with the reply, so the check has to guess; guessing high makes the cap
# slightly conservative, guessing low lets through exactly the call the cap
# exists to stop.
PROJECTION_MARGIN = 1.5


# Models that are KNOWN to cost nothing, which is a different statement from a
# model whose price we do not know. MockBackend makes no network call; its
# usages stay `priced = False` so a mock run still reports "no known rate"
# rather than claiming a real $0.0000 bill, but its projection is genuinely
# zero and every cap should admit it.
FREE_MODELS = frozenset(MODELS["mock"].values())


def project(model: str, role: str = "deep") -> float:
    """What a call on this model is projected to cost, before making it.

    Derived from PRICING rather than hard-coded, because a constant pegged to
    one model stops bounding the call the moment another can be selected --
    Opus 5 is two and a half times Sonnet 5, and a $0.06 constant would have
    guarded nothing.

    An unpriced model cannot be projected. That is a refusal rather than a
    default, because `Usage.priced` is False for it, `cost_usd` comes back
    0.0, and the ledger the daily and lifetime caps read would never see the
    spend. A model we cannot price is a model we cannot cap.
    """
    if model in FREE_MODELS:
        return 0.0
    rates = PRICING.get(model.replace("anthropic.", ""))
    if rates is None:
        raise BackendError(
            f"no price is known for model {model!r}, so no budget cap can bound "
            "it. An unpriced call records $0.00 and the daily and lifetime caps "
            "would never see it. Add it to model_gateway.PRICING first.")
    tokens_in, tokens_out = PROFILE.get(role, PROFILE["deep"])
    rate_in, rate_out = rates
    return ((tokens_in * rate_in + tokens_out * rate_out) / 1_000_000) * PROJECTION_MARGIN

KEY_PATTERN = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")

# Seconds before a model call is abandoned. A hung provider must not hold a
# worker until something further up the stack gives up first.
DEFAULT_TIMEOUT_S = 120.0


class BackendError(RuntimeError):
    """Raised with any credential material scrubbed from the message."""


def _scrub(text: str) -> str:
    """Never let key material reach a log, a report, or an exception."""
    return KEY_PATTERN.sub("sk-ant-<REDACTED>", str(text))


@dataclass
class Usage:
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    image_tokens: int = 0
    latency_ms: int = 0
    backend: str = ""

    @property
    def priced(self) -> bool:
        """Whether a rate is known for this model.

        Reporting $0.0000 for a model we have no rate for says "free" when it
        means "unknown" -- a wrong number, and the kind that goes into a budget
        unchallenged. Callers must check this before presenting a total.
        """
        return self.model.replace("anthropic.", "") in PRICING

    @property
    def cost_usd(self) -> float:
        """Cost in USD, or 0.0 when unpriced. Always read `priced` alongside."""
        base = self.model.replace("anthropic.", "")
        rate_in, rate_out = PRICING.get(base, (0.0, 0.0))
        billed_in = max(self.input_tokens - self.cache_read_tokens, 0)
        return (billed_in * rate_in + self.cache_read_tokens * rate_in * 0.1
                + self.output_tokens * rate_out) / 1_000_000


@dataclass
class ModelReply:
    text: str
    usage: Usage
    raw: Any = None


class SpendLedger(Protocol):
    """Where historical spend is read from.

    The point of the indirection: a counter held on the guard object resets
    whenever the object does. In a CLI run that is the same thing as a day. In
    a web service it is the same thing as a request, which makes a field called
    `spent_day` a runaway spend hole with a reassuring name. A ledger backed by
    the database gives the same API an answer that survives.
    """

    def spent_since(self, hours: float) -> float: ...
    def spent_total(self) -> float: ...


class MemoryLedger:
    """In-process. Correct for one CLI run; never correct for a service."""

    def __init__(self) -> None:
        self.entries: list[tuple[datetime, float]] = []

    def record(self, cost: float) -> None:
        self.entries.append((datetime.now(timezone.utc), cost))

    def spent_since(self, hours: float) -> float:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return sum(c for t, c in self.entries if t >= cutoff)

    def spent_total(self) -> float:
        return sum(c for _, c in self.entries)


@dataclass
class BudgetGuard:
    """Checked BEFORE every call, never after.

    `daily_usd` and `total_usd` mean what they say only because they are read
    from a ledger rather than from a field on this object.
    """
    daily_usd: float = 2.00
    per_run_usd: float = 0.50
    single_call_usd: float = 0.05
    total_usd: float | None = None          # hard lifetime ceiling; None = unlimited
    ledger: SpendLedger | None = None
    spent_run: float = 0.0
    enabled: bool = True                    # kill switch, no redeploy required

    def __post_init__(self) -> None:
        if self.ledger is None:
            self.ledger = MemoryLedger()

    def check(self, projected: float) -> None:
        if not self.enabled:
            raise BackendError("model calls are disabled by the kill switch")
        if projected > self.single_call_usd:
            raise BackendError(
                f"single call projected at ${projected:.4f}, cap is ${self.single_call_usd:.2f}")
        if self.spent_run + projected > self.per_run_usd:
            raise BackendError(
                f"run budget ${self.per_run_usd:.2f} would be exceeded "
                f"(spent ${self.spent_run:.4f})")
        day = self.ledger.spent_since(24)
        if day + projected > self.daily_usd:
            raise BackendError(
                f"daily budget ${self.daily_usd:.2f} would be exceeded "
                f"(spent ${day:.4f} in the last 24h)")
        if self.total_usd is not None:
            total = self.ledger.spent_total()
            if total + projected > self.total_usd:
                raise BackendError(
                    f"lifetime cap ${self.total_usd:.2f} would be exceeded "
                    f"(spent ${total:.4f})")

    def record(self, usage: Usage) -> None:
        self.spent_run += usage.cost_usd
        if isinstance(self.ledger, MemoryLedger):
            self.ledger.record(usage.cost_usd)
        # A database-backed ledger reads committed rows; nothing to record here.

    @property
    def spent_day(self) -> float:
        return self.ledger.spent_since(24) if self.ledger else 0.0


class Backend(Protocol):
    name: str
    def complete(self, model: str, system: str, content: list[dict],
                 max_tokens: int) -> ModelReply: ...


# --------------------------------------------------------------------------
# Backends
# --------------------------------------------------------------------------

class MockBackend:
    """Deterministic canned replies. CI runs here exclusively."""
    name = "mock"

    def __init__(self, canned: dict[str, str] | None = None) -> None:
        self.canned = canned or {}
        self.calls: list[dict] = []

    def complete(self, model, system, content, max_tokens=1024) -> ModelReply:
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        self.calls.append({"model": model, "system": system[:80], "chars": len(text)})
        body = self.canned.get(model) or json.dumps({
            "root_cause": "MOCK: no model was called.",
            "suggested_fix": "MOCK: wire a real backend to get a diagnosis.",
            "confidence": 0.0,
        })
        return ModelReply(
            text=body,
            usage=Usage(model=model, input_tokens=len(text) // 4,
                        output_tokens=len(body) // 4, latency_ms=0, backend=self.name),
        )


class BedrockBackend:
    """Claude on Amazon Bedrock. Inference stays in the client's AWS account."""
    name = "bedrock"

    def __init__(self, region: str, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.timeout = timeout
        if not region:
            raise BackendError("bedrock backend needs a region")
        self.region = region
        try:
            from anthropic import AnthropicBedrockMantle
        except ImportError as exc:
            raise BackendError(
                "the anthropic SDK is not installed -- pip install 'anthropic[bedrock]'") from exc
        self._client = AnthropicBedrockMantle(aws_region=region)

    def complete(self, model, system, content, max_tokens=4096) -> ModelReply:
        return _invoke(self._client, self.name, model, system, content, max_tokens,
                       self.timeout)


class ByokBackend:
    """Bring Your Own Key -- Claude API direct.

    The key is read from the environment or a file and is never stored on the
    instance in a form that reaches a repr, a log line, or a traceback.
    """
    name = "byok"

    def __init__(self, api_key: str | None = None, key_file: Path | None = None,
                 base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.timeout = timeout
        key = api_key or os.environ.get("ANTHROPIC_API_KEY") or _read_key_file(key_file)
        if not key:
            raise BackendError(
                "no API key found. Set ANTHROPIC_API_KEY, or point model.key_file at a "
                "file containing only the key. Never put a key in the config file or the repo.")
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise BackendError(
                "the anthropic SDK is not installed -- pip install anthropic") from exc
        self._client = Anthropic(api_key=key, **({"base_url": base_url} if base_url else {}))
        self._fingerprint = f"...{key[-4:]}"      # enough to tell two keys apart, never the key

    def __repr__(self) -> str:                     # keeps the key out of tracebacks
        return f"ByokBackend(key={self._fingerprint})"

    def complete(self, model, system, content, max_tokens=4096) -> ModelReply:
        return _invoke(self._client, self.name, model, system, content, max_tokens,
                       self.timeout)


def _read_key_file(path: Path | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        raise BackendError(f"key file not found: {p}")
    if os.name == "posix" and (p.stat().st_mode & 0o077):
        raise BackendError(f"key file {p} is readable by others -- chmod 600 it first")
    return p.read_text(encoding="utf-8").strip() or None



def _invoke(client, backend: str, model: str, system: str,
            content: list[dict], max_tokens: int,
            timeout: float = DEFAULT_TIMEOUT_S) -> ModelReply:
    """One call shape for both real backends. The SDK surface is identical.

    An explicit timeout matters more in a service than in a CLI: without one a
    hung provider holds a worker until something else gives up first.
    """
    started = time.monotonic()
    try:
        resp = client.with_options(timeout=timeout).messages.create(
            model=model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": content}],
        )
    except Exception as exc:
        raise BackendError(f"{backend} call failed: {_scrub(exc)}") from None

    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    u = resp.usage
    return ModelReply(
        text=text,
        usage=Usage(
            model=model,
            input_tokens=getattr(u, "input_tokens", 0),
            output_tokens=getattr(u, "output_tokens", 0),
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
            latency_ms=int((time.monotonic() - started) * 1000),
            backend=backend,
        ),
        raw=resp,
    )


# --------------------------------------------------------------------------
# Factory, with the governance guard
# --------------------------------------------------------------------------

LOCAL_ENVIRONMENTS = {"local", "dev", "sandbox"}


def current_environment() -> str:
    """Where this process believes it is running.

    Defaults to `production` whenever a server environment variable is present,
    so a deployed instance cannot quietly inherit the permissive `local` rules
    that the BYOK governance guard keys off. Getting this wrong in the safe
    direction costs an extra config line; getting it wrong in the other
    direction disables the guard silently.
    """
    explicit = os.environ.get("EAGLE_EYES_ENV")
    if explicit:
        return explicit.strip().lower()
    server_markers = ("RAILWAY_ENVIRONMENT", "RAILWAY_PROJECT_ID", "PORT",
                      "DYNO", "KUBERNETES_SERVICE_HOST", "WEBSITE_INSTANCE_ID")
    if any(os.environ.get(m) for m in server_markers):
        return "production"
    return "local"


def create_backend(cfg: dict, environment: str | None = None) -> Backend:
    """Build the configured backend, refusing byok outside local without a name.

    `cfg` is the `model:` block. `environment` comes from the profile.
    """
    kind = (cfg.get("backend") or "mock").lower()
    if environment is None:
        environment = current_environment()

    if kind == "byok" and environment.lower() not in LOCAL_ENVIRONMENTS:
        approver = (cfg.get("byok_approved_by") or "").strip()
        if not approver:
            raise BackendError(
                f"backend 'byok' is refused in environment '{environment}'.\n"
                "  With byok, prompt content leaves for api.anthropic.com -- a third party\n"
                "  from the client's point of view. With bedrock it stays in the client's\n"
                "  AWS account. That is a different answer to 'where does client data go',\n"
                "  which is the question docs/SECURITY.md is built around.\n"
                "  If this has genuinely been approved, record who approved it in\n"
                "  model.byok_approved_by. See docs/SECURITY.md section 12.")

    timeout = float(cfg.get("timeout_s") or DEFAULT_TIMEOUT_S)

    if kind == "mock":
        return MockBackend()
    if kind == "bedrock":
        return BedrockBackend(region=cfg.get("region", ""), timeout=timeout)
    if kind == "byok":
        kf = cfg.get("key_file")
        return ByokBackend(key_file=Path(kf) if kf else None,
                           base_url=cfg.get("base_url"), timeout=timeout)
    raise BackendError(f"unknown backend '{kind}' (expected bedrock, byok or mock)")


def sdk_status() -> tuple[bool, str]:
    """Is a provider SDK installed, and which version.

    Exists so that nothing outside this module has to import a provider SDK
    merely to ask whether one is available -- the boundary is worth more than
    the convenience, and tests/test_boundaries.py enforces it.
    """
    try:
        import anthropic
        return True, f"anthropic {getattr(anthropic, '__version__', 'unknown')}"
    except ImportError:
        return False, "anthropic not installed"


def models_for(backend_name: str) -> dict[str, str]:
    return MODELS.get(backend_name, MODELS["mock"])
