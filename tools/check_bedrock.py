#!/usr/bin/env python3
"""
Verify Bedrock reachability before building anything on top of it.

This is the "one command settles it" check from docs/ARCHITECTURE.md section 1.
It makes one small real call per model and tells you exactly which link in the
chain is broken when it fails: credentials, region, model access, or egress.

Run it on the machine that will host the analyzer -- locally now, and on Exodus
the day access is granted. The failure it is most likely to catch on a jump
server is no outbound egress.

    pip install 'anthropic[bedrock]'
    python3 tools/check_bedrock.py --region us-east-1

Costs a few cents at most: the prompts are tiny and max_tokens is capped.
"""

from __future__ import annotations

import argparse
import sys
import time

TRIAGE = "anthropic.claude-haiku-4-5"
DEEP = "anthropic.claude-sonnet-5"


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
    if any(k in low for k in ("nocredentials", "unable to locate credentials", "credential")):
        return ("No AWS credentials found.", [
            "Run 'aws configure', or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY,",
            "or AWS_PROFILE if you use named profiles.",
            "Use a DEV account here, not client production credentials -- see LOCAL_DEV.md.",
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


def check(model: str, region: str) -> bool:
    try:
        from anthropic import AnthropicBedrockMantle
    except ImportError:
        print("  ! The anthropic SDK is not installed.")
        print("    pip install 'anthropic[bedrock]'")
        return False

    print(f"  {model} ... ", end="", flush=True)
    started = time.monotonic()
    try:
        client = AnthropicBedrockMantle(aws_region=region)
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
    ap.add_argument("--region", required=True, help="e.g. us-east-1, eu-west-1")
    ap.add_argument("--models", nargs="*", default=[TRIAGE, DEEP])
    args = ap.parse_args()

    print(f"Checking Bedrock in {args.region}\n")
    results = {m: check(m, args.region) for m in args.models}

    print()
    if all(results.values()):
        print("All models reachable. Set model.backend: bedrock in your config.")
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
