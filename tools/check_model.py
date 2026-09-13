#!/usr/bin/env python3
"""
Verify model reachability before building anything on top of it.

This is the "one command settles it" check from docs/ARCHITECTURE.md section 1.
One small real call per model, naming exactly which link in the chain is broken
when it fails: credentials, region, model access, key, or egress.

Covers both backends:

    pip install 'anthropic[bedrock]'
    python3 tools/check_model.py --backend bedrock --region us-east-1

    pip install anthropic
    export ANTHROPIC_API_KEY=...          # never pass a key on the command line
    python3 tools/check_model.py --backend byok

Run it on the machine that will host the analyzer -- locally now, and on Exodus
the day access is granted. On a jump server the likeliest failure is no
outbound egress.

Costs a few cents at most: the prompts are tiny and max_tokens is capped.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

MODELS = {
    "bedrock": ["anthropic.claude-haiku-4-5", "anthropic.claude-sonnet-5"],
    "byok": ["claude-haiku-4-5", "claude-sonnet-5"],
}


def diagnose(err: Exception) -> tuple[str, list[str]]:
    """Map an exception to a cause and the actual next step."""
    name = type(err).__name__
    text = f"{name}: {err}"
    low = text.lower()

    if "accessdenied" in low.replace(" ", "") or "don't have access" in low:
        return ("Model access is not enabled for this model in this region.", [
            "This is the commonest first-run failure and it is NOT a network problem.",
            "AWS Bedrock console -> Model access -> enable the Anthropic models,",
            "in the SAME region you are calling. Enablement is per-account AND per-region.",
            "It can take a few minutes to take effect after you submit it.",
        ])
    if "expiredtoken" in low.replace(" ", "") or "security token" in low:
        return ("Credentials have expired.", ["Refresh your session (aws sso login, or new keys)."])
    if "authentication_error" in low or "invalid x-api-key" in low or "401" in low:
        return ("The API key was rejected.", [
            "Check ANTHROPIC_API_KEY, or the file model.key_file points at.",
            "A key from a different organisation will fail this way too.",
        ])
    if any(k in low for k in ("nocredentials", "unable to locate credentials", "credential")):
        return ("No credentials found.", [
            "bedrock: run 'aws configure', or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY,",
            "         or AWS_PROFILE if you use named profiles.",
            "byok:    set ANTHROPIC_API_KEY, or point model.key_file at a file holding the key.",
            "Use a DEV account or a personal key here, never client production credentials.",
        ])
    if any(k in low for k in ("endpointconnection", "connecttimeout", "could not connect",
                              "name or service not known", "timed out", "connection refused")):
        return ("Cannot reach the Bedrock endpoint at all.", [
            "This is the blocker docs/ARCHITECTURE.md section 1 flags.",
            "On a personal machine: check your own connectivity or proxy settings.",
            "On Exodus: this is almost certainly no outbound egress from the jump server.",
            "Preferred fix is a Bedrock VPC endpoint (PrivateLink), not open internet access.",
            "Set HTTPS_PROXY if the host requires a proxy.",
        ])
    if "validationexception" in low.replace(" ", "") or "invalid model" in low:
        return ("The model ID was rejected.", [
            "On Bedrock, model IDs carry the 'anthropic.' prefix.",
            "Check the model is offered in this region -- availability varies.",
        ])
    if "throttl" in low or "toomanyrequests" in low:
        return ("Throttled.", ["Account quota. Retry, or request a quota increase."])
    if "unrecognizedclient" in low.replace(" ", "") or "invalid" in low and "signature" in low:
        return ("Credentials are present but rejected.", ["Check the key pair and the region."])
    return (f"Unrecognised failure: {name}", [text[:400]])


def make_client(backend: str, region: str):
    if backend == "bedrock":
        from anthropic import AnthropicBedrockMantle
        return AnthropicBedrockMantle(aws_region=region)
    from anthropic import Anthropic
    return Anthropic()          # reads ANTHROPIC_API_KEY; never passed as an argument


def check(model: str, backend: str, region: str) -> bool:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        extra = "'anthropic[bedrock]'" if backend == "bedrock" else "anthropic"
        print(f"  ! The anthropic SDK is not installed.\n    pip install {extra}")
        return False

    print(f"  {model} ... ", end="", flush=True)
    started = time.monotonic()
    try:
        client = make_client(backend, region)
        resp = client.messages.create(
            model=model,
            max_tokens=16,
            messages=[{"role": "user", "content": "Reply with the single word: ok"}],
        )
        elapsed = (time.monotonic() - started) * 1000
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()
        u = resp.usage
        print(f"OK  ({elapsed:.0f}ms, in={u.input_tokens} out={u.output_tokens}, said {text!r})")
        return True
    except Exception as err:  # noqa: BLE001 - this tool exists to interpret any failure
        print("FAILED")
        cause, steps = diagnose(err)
        print(f"    Cause: {cause}")
        for s in steps:
            print(f"      {s}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["bedrock", "byok"], default="bedrock")
    ap.add_argument("--region", help="required for bedrock, e.g. us-east-1")
    ap.add_argument("--models", nargs="*")
    args = ap.parse_args()

    if args.backend == "bedrock" and not args.region:
        ap.error("--region is required for the bedrock backend")

    models = args.models or MODELS[args.backend]
    where = f"Bedrock in {args.region}" if args.backend == "bedrock" else "the Claude API (BYOK)"
    print(f"Checking {where}\n")
    if args.backend == "byok" and not os.environ.get("ANTHROPIC_API_KEY"):
        print("  note: ANTHROPIC_API_KEY is not set in this shell\n")
    results = {m: check(m, args.backend, args.region or "") for m in models}

    print()
    if all(results.values()):
        print(f"All models reachable. Set model.backend: {args.backend} in your config.")
    if args.backend == "byok":
        print("Remember: byok is refused outside local development unless")
        print("model.byok_approved_by names an approver. See docs/SECURITY.md section 12.")
        return 0
    if not any(results.values()):
        print("No model reachable. Fix the cause above before building on Bedrock;")
        print("model.backend: mock keeps local development moving meanwhile.")
        return 1
    ok = [m for m, v in results.items() if v]
    print(f"Partial: {', '.join(ok)} reachable, the rest not.")
    print("Usually means model access is enabled for some models but not others.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
