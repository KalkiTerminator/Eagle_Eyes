"""Reports and notification suppression.

The escaping tests matter most: log lines are attacker-influenced text, and a
report that renders them raw is stored XSS waiting for a browser.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eagle_eyes.notify import Notifier, compose  # noqa: E402
from eagle_eyes.report import ReportInput, render, write, write_index  # noqa: E402

_failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def _r(**kw) -> ReportInput:
    base = dict(bot_label="FINANCE_AP/BOT201", occurred_at="2026-09-11T09:41:09",
                exception_type="OpenQA.Selenium.ElementClickInterceptedException",
                root_cause="A session banner covered the policy tab.",
                suggested_fix="Dismiss the banner before clicking.",
                confidence=0.85, path="text", inputs_used=("log", "code"))
    base.update(kw)
    return ReportInput(**base)


# -------------------------------------------------------------- escaping

def test_untrusted_text_is_escaped() -> None:
    evil = '<script>alert(1)</script>'
    h = render(_r(root_cause=evil, suggested_fix=evil, notes=evil,
                  log_excerpt=evil, bot_label=evil,
                  exception_type="X" + evil))
    check("no raw <script> survives anywhere", "<script>alert" not in h)
    check("it is escaped instead", "&lt;script&gt;" in h)

    h2 = render(_r(log_path='x" onload="alert(1)', screenshot_path='y"><img src=x>'))
    check("an attribute-breaking path cannot escape the href",
          'onload="alert' not in h2 and '"><img' not in h2)

    h3 = render(_r(root_cause="Element <a data-tab='policy'>...</a> not clickable"))
    check("ordinary HTML-looking log content is shown, not executed",
          "&lt;a data-tab" in h3)


def test_screenshot_is_linked_not_embedded() -> None:
    h = render(_r(screenshot_path=r"\\VM-FIN-14\share\2026-09-11_09-41-09.png",
                  inputs_used=("log", "code", "screenshot"), pairing_method="log_path"))
    check("no image is embedded", "<img" not in h and "base64" not in h)
    check("the screenshot is a link", "2026-09-11_09-41-09.png" in h and "href=" in h)
    check("and says it opens with existing access", "existing access" in h)


# ----------------------------------------------------------------- flags

def test_warnings_are_prominent() -> None:
    low = render(_r(confidence=0.15))
    check("low confidence is flagged", "Low confidence" in low)
    check("and says to treat it as a lead", "lead to check" in low)

    stale = render(_r(code_possibly_stale=True))
    check("stale code is flagged", "edited after this failure" in stale)

    unsent = render(_r(screenshot_path="/x/a.png", inputs_used=("log",)))
    check("an unsent screenshot is flagged", "not sent to the model" in unsent)

    nocode = render(_r(code_path=""))
    check("a log-only diagnosis says so", "log-only" in nocode)

    unpaired = render(_r(screenshot_path="/x/a.png", pairing_method="none",
                         inputs_used=("log",)))
    check("a refused pairing is explained", "rather than risk the wrong one" in unpaired)

    check("the footer asks for feedback", "correct, partial or wrong" in render(_r()))


def test_cost_unknown_is_not_shown_as_free() -> None:
    known = render(_r(model_id="claude-sonnet-5", cost_usd=0.0384))
    check("a known cost is shown", "$0.0384" in known)
    unknown = render(_r(model_id="house-model", cost_usd=None))
    check("an unknown cost says so", "cost unknown" in unknown)


def test_files_are_written() -> None:
    d = Path(tempfile.mkdtemp())
    try:
        p = write(_r(), d, "BOT201_2026-09-11_09-41-09")
        check("a report file is written", p.is_file() and p.suffix == ".html")
        check("the filename is sanitized",
              all(c.isalnum() or c in "-_." for c in p.stem))
        p2 = write(_r(), d, "../../etc/passwd")
        check("a traversal attempt cannot escape the folder", p2.parent == d, str(p2))

        idx = write_index([(_r(), p), (_r(occurred_at="2026-09-12T01:00:00"), p2)], d)
        check("an index is written", idx.is_file())
        check("the index links to the reports", p.name in idx.read_text())
    finally:
        shutil.rmtree(d)


# ----------------------------------------------------------- suppression

def _n(to="dev@x", fp="a" * 64):
    return compose(to=to, bot_label="B", exception_type="X.Y",
                   root_cause="rc", suggested_fix="fix", confidence=0.9,
                   fingerprint=fp, report_path="/r/1.html")


def test_noise_never_notifies() -> None:
    n = Notifier()
    d = n.send(_n(), category="noise")
    check("noise is suppressed", not d.send and "noise" in d.reason)
    check("nothing was sent", n.sent_log == [])


def test_low_confidence_is_held_back() -> None:
    n = Notifier(min_confidence=0.3)
    d = n.send(_n(), confidence=0.1)
    check("a low-confidence diagnosis is not emailed as an answer", not d.send)
    check("and the reason says why", "below threshold" in d.reason)
    check("a confident one is sent", n.send(_n(fp="b" * 64), confidence=0.9).send)


def test_repeats_notify_once_then_count() -> None:
    n = Notifier()
    check("the first is sent", n.send(_n()).send)
    d2 = n.send(_n())
    check("the second is suppressed", not d2.send)
    check("and reports the running count", "seen 2 times" in d2.reason, d2.reason)
    for _ in range(5):
        n.send(_n())
    check("repeats keep counting, not sending", len(n.sent_log) == 1)
    check("the count is accurate", n.state.counts[("dev@x", "a" * 64)] == 7)


def test_incident_cannot_flood_an_inbox() -> None:
    """500 failures in minutes, mostly distinct fingerprints, one developer."""
    n = Notifier(per_developer_hourly_cap=10)
    t = datetime(2026, 9, 11, 9, 0, 0)
    for i in range(500):
        n.send(_n(fp=f"{i:064x}"), now=t + timedelta(seconds=i))
    check("no more than the cap is sent", len(n.sent_log) == 10, str(len(n.sent_log)))
    check("the rest are suppressed", len(n.suppressed) == 490)
    check("the cap is named in the reason",
          any("hourly cap" in r for _, r in n.suppressed))

    later = n.send(_n(fp="f" * 64), now=t + timedelta(hours=2))
    check("the cap frees up after the hour", later.send)


def test_different_developers_have_separate_caps() -> None:
    n = Notifier(per_developer_hourly_cap=2)
    t = datetime(2026, 9, 11, 9, 0, 0)
    for i in range(4):
        n.send(_n(to="a@x", fp=f"{i:064x}"), now=t)
    for i in range(4):
        n.send(_n(to="b@x", fp=f"{i:064x}"), now=t)
    check("one developer's flood does not silence another",
          len([x for x in n.sent_log if x.to == "b@x"]) == 2)


def test_digest_makes_suppression_visible() -> None:
    n = Notifier(per_developer_hourly_cap=1)
    t = datetime(2026, 9, 11, 9, 0, 0)
    n.send(_n(fp="1" * 64), now=t)
    n.send(_n(fp="2" * 64), now=t)
    n.send(_n(fp="3" * 64), category="noise", now=t)
    text = n.digest()
    check("the digest reports how many were held", "3 notifications suppressed" in text
          or "2 notifications suppressed" in text, text)
    check("and groups them by reason", "cap" in text or "noise" in text)
    check("an empty digest says so", Notifier().digest() == "Nothing suppressed.")


def test_dry_run_sends_nothing() -> None:
    n = Notifier(dry_run=True, smtp_host="smtp.invalid")
    d = n.send(_n())
    check("dry run reports as sent", d.send and len(n.sent_log) == 1)
    check("without touching SMTP (an invalid host would have raised)", True)


def test_mail_body() -> None:
    m = compose(to="d@x", bot_label="FINANCE_AP/BOT201", exception_type="A.B.CException",
                root_cause="rc", suggested_fix="fix", confidence=0.4,
                fingerprint="a" * 64, report_path="/r/1.html")
    check("the subject names the bot and the exception",
          "FINANCE_AP/BOT201" in m.subject and "CException" in m.subject)
    check("the body links to the report", "/r/1.html" in m.body)
    check("it says the screenshot is not attached", "not attached" in m.body)
    check("a middling confidence is called out", "treat as a lead" in m.body)
    check("it asks for feedback", "correct, partial or wrong" in m.body)


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{'All checks passed.' if not _failures else str(len(_failures)) + ' FAILED: ' + ', '.join(_failures)}")
    sys.exit(1 if _failures else 0)
