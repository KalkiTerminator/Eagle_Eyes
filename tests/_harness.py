"""Shared assertion helper for the suites.

Why this exists rather than a `check()` copied into each file:

Running a suite directly is meant to print every result and then summarise, so
one failure does not hide the next five. But a `check()` that only *records* a
failure returns normally, and pytest — which is what VS Code's test panel and
most CI runners use — treats a function that returns normally as a pass. Every
suite would have reported green while failing, which is worse than having no
test integration at all.

So: collect when run directly, raise when run under pytest. Both runners then
tell the truth, and there is one copy of the logic to keep correct.
"""

from __future__ import annotations

import os
import sys

_UNDER_PYTEST = "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


class Harness:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        suffix = f"  -- {detail}" if detail and not cond else ""
        print(f"  {'PASS' if cond else 'FAIL'}  {name}{suffix}")
        if cond:
            return
        self.failures.append(name)
        if _UNDER_PYTEST:
            raise AssertionError(f"{name}{': ' + detail if detail else ''}")

    def run_all(self, namespace: dict) -> int:
        """Run every test_* in a module and report. Returns an exit code."""
        for fn in [v for k, v in sorted(namespace.items())
                   if k.startswith("test_") and callable(v)]:
            print(f"\n{fn.__name__}")
            fn()
        if self.failures:
            print(f"\n{len(self.failures)} FAILED: {', '.join(self.failures)}")
            return 1
        print("\nAll checks passed.")
        return 0
