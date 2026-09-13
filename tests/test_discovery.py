"""Tests for discovery and pairing.

Runs against the synthetic estate (tools/make_fixtures.py). No credentials, no
network, no model call -- CI must be able to run this on a bare checkout.

    python3 tools/make_fixtures.py --root ./sandbox
    python3 -m pytest tests/ -q        (or: python3 tests/test_discovery.py)
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eagle_eyes.discovery import (  # noqa: E402
    LOG_TS_RE, discover, failure_time, parse_location, read_text,
)

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "sandbox"
SHARE, CODE = SANDBOX / "Network_Sharing_Folder", SANDBOX / "code_folder"

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def test_location_from_path() -> None:
    log = next(SHARE.rglob("*.log"))
    loc = parse_location(log, SHARE)
    check("location parsed from the path, not file content", loc is not None)
    check("service line and bot look right",
          bool(loc and loc.bot_number.startswith("BOT") and loc.service_line.isupper()))
    check("a path outside the share root is rejected",
          parse_location(Path("/etc/passwd"), SHARE) is None)


def test_failure_time_is_the_exception_line() -> None:
    """Regression: occurred_at used to read the header's 'Started' time."""
    bad = 0
    for lp in list(SHARE.rglob("*.log"))[:40]:
        text = read_text(lp)
        err_lines = [ln for ln in text.splitlines() if "[ERROR]" in ln]
        if not err_lines:
            continue
        raw = LOG_TS_RE.search(err_lines[-1])
        if not raw:
            continue
        expect = datetime.strptime(raw.group(0), "%d-%m-%Y %H:%M:%S")
        if failure_time(text) != expect:
            bad += 1
    check("failure_time() returns the exception line's timestamp", bad == 0, f"{bad} wrong")

    started = "Started      : 01-01-2020 00:00:00.000"
    synthetic = (f"Header\n{started}\n"
                 "02-02-2021 11:22:33.000 [ERROR] OpenQA.Selenium.WebDriverException: boom\n")
    check("header 'Started' is never used as the failure time",
          failure_time(synthetic) == datetime(2021, 2, 2, 11, 22, 33))


def test_pairing_uses_the_log() -> None:
    cands = discover(SHARE, SHARE, CODE)
    check("discovery found failures", len(cands) > 100, f"{len(cands)}")
    by_log = [c for c in cands if c.pairing_method == "log_path"]
    check("the log names the screenshot in the normal case",
          len(by_log) / len(cands) > 0.9, f"{len(by_log)}/{len(cands)}")
    check("a paired screenshot actually exists on disk",
          all(c.screenshot_path.is_file() for c in by_log[:50]))


def test_basename_not_logged_path() -> None:
    """The logged path is the VM's D: drive; only the basename is portable."""
    cands = [c for c in discover(SHARE, SHARE, CODE) if c.pairing_method == "log_path"]
    c = cands[0]
    logged = re.search(r"Screenshot captured:\s*(.+)", read_text(c.log_path)).group(1).strip()
    check("the log really does carry a VM-local path", logged.startswith("D:"))
    check("we resolved it under the share root instead",
          str(c.screenshot_path).startswith(str(SHARE)))
    check("basenames match", Path(logged.replace("\\", "/")).name == c.screenshot_path.name)


def test_fallback_refuses_when_ambiguous() -> None:
    """No capture line + two screenshots in the window = attach nothing."""
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(SHARE, tmp / "nsf")
        shutil.copytree(CODE, tmp / "cf")
        bot = tmp / "nsf" / "data" / "FINANCE_AP" / "BOT201"
        for lp in bot.rglob("*.log"):
            lp.write_bytes(re.sub(r".*Screenshot captured:.*\r?\n", "",
                                  lp.read_bytes().decode()).encode())
        cands = sorted(discover(bot, tmp / "nsf", tmp / "cf"), key=lambda c: c.occurred_at)
        close = [c for c in cands if "refusing to guess" in c.pairing_note]
        check("close-together failures refuse to pair", len(close) >= 2, f"{len(close)}")
        check("nothing is attached when it refuses",
              all(c.screenshot_path is None for c in close))
        check("isolated failures still pair on time",
              any(c.pairing_method == "timestamp" for c in cands))
    finally:
        shutil.rmtree(tmp)


def test_degradation() -> None:
    cands = discover(SHARE, SHARE, CODE)
    check("a failure with no screenshot still yields a candidate",
          any(c.screenshot_path is None for c in cands))
    check("a bot with no code file still yields a candidate",
          any(c.code_path is None for c in cands))
    check("every candidate has a log", all(c.log_path.is_file() for c in cands))
    check("exception type was parsed for nearly all",
          sum(1 for c in cands if c.exception_type) / len(cands) > 0.95)


def test_crlf_does_not_leak() -> None:
    cands = discover(SHARE, SHARE, CODE)[:60]
    check("no carriage return in the exception type",
          not any("\r" in c.exception_type for c in cands))
    check("no carriage return in the message",
          not any("\r" in c.message for c in cands))


if __name__ == "__main__":
    if not SHARE.is_dir():
        print(f"Sandbox not found at {SANDBOX}.\n"
              f"Run: python3 tools/make_fixtures.py --root {SANDBOX}")
        sys.exit(2)
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{'All checks passed.' if not _failures else str(len(_failures)) + ' FAILED: ' + ', '.join(_failures)}")
    sys.exit(1 if _failures else 0)
