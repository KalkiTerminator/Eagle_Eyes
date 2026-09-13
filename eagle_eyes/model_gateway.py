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
from typing import Any, Protocol

# --------------------------------------------------------------------------
# Model identifiers. Bedrock carries the `anthropic.` prefix; the direct API
# does not. Everything else about the call is identical.
# --------------------------------------------------------------------------

MODELS = {
    "bedrock": {"triage": "anthropic.claude-haiku-4-5", "deep": "anthropic.claude-sonnet-5"},
    "byok":    {"triage": "claude-haiku-4-5",           "deep": "claude-sonnet-5"},
    "mock":    {"triage": "mock-haiku",                 "deep": "mock-sonnet"},
}

# USD per million tokens. These are Anthropic first-party list rates and apply
# to `byok`. Bedrock is partner-operated and priced separately -- the table
# below is a PLANNING PROXY for it, not a quote. Re-derive Bedrock figures from
# https://aws.amazon.com/bedrock/pricing/ for your region before any number
# here goes near a budget. docs/COST_MODEL.md section 1 says the same.
PRICING = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-5":  (2.00, 10.00),
}

KEY_PATTERN = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")


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
    def cost_usd(self) -> float:
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


@dataclass
class BudgetGuard:
    """Checked BEFORE every call, never after."""
    daily_usd: float = 2.00
    per_run_usd: float = 0.50
    single_call_usd: float = 0.05
    spent_run: float = 0.0
    spent_day: float = 0.0

    def check(self, projected: float) -> None:
        if projected > self.single_call_usd:
            raise BackendError(
                f"single call projected at ${projected:.4f}, cap is ${self.single_call_usd:.2f}")
        if self.spent_run + projected > self.per_run_usd:
            raise BackendError(
                f"run budget ${self.per_run_usd:.2f} would be exceeded "
                f"(spent ${self.spent_run:.4f})")
        if self.spent_day + projected > self.daily_usd:
            raise BackendError(
                f"daily budget ${self.daily_usd:.2f} would be exceeded "
                f"(spent ${self.spent_day:.4f})")

    def record(self, usage: Usage) -> None:
        self.spent_run += usage.cost_usd
        self.spent_day += usage.cost_usd


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

    def __init__(self, region: str) -> None:
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
        return _invoke(self._client, self.name, model, system, content, max_tokens)


class ByokBackend:
    """Bring Your Own Key -- Claude API direct.

    The key is read from the environment or a file and is never stored on the
    instance in a form that reaches a repr, a log line, or a traceback.
    """
    name = "byok"

    def __init__(self, api_key: str | None = None, key_file: Path | None = None,
                 base_url: str | None = None) -> None:
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
        return _invoke(self._client, self.name, model, system, content, max_tokens)


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
            content: list[dict], max_tokens: int) -> ModelReply:
    """One call shape for both real backends. The SDK surface is identical."""
    started = time.monotonic()
    try:
        resp = client.messages.create(
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


def create_backend(cfg: dict, environment: str = "local") -> Backend:
    """Build the configured backend, refusing byok outside local without a name.

    `cfg` is the `model:` block. `environment` comes from the profile.
    """
    kind = (cfg.get("backend") or "mock").lower()

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

    if kind == "mock":
        return MockBackend()
    if kind == "bedrock":
        return BedrockBackend(region=cfg.get("region", ""))
    if kind == "byok":
        kf = cfg.get("key_file")
        return ByokBackend(key_file=Path(kf) if kf else None, base_url=cfg.get("base_url"))
    raise BackendError(f"unknown backend '{kind}' (expected bedrock, byok or mock)")


def models_for(backend_name: str) -> dict[str, str]:
    return MODELS.get(backend_name, MODELS["mock"])
