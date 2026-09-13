"""Sanitization and fingerprint identity.

Every check here corresponds to a defect that was caught against realistic
inputs. They are regression tests first and specification second.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from eagle_eyes.fingerprint import (  # noqa: E402
    ALGORITHM_VERSION, compute, fingerprint, normalize, parse, top_frames, unwrap,
)
from eagle_eyes.sanitize import CANARY, canary_check, sanitize_code, sanitize_log  # noqa: E402

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check


LOG = """11-09-2026 09:41:09.402 [ERROR] Activity 'Post' failed
11-09-2026 09:41:09.404 [ERROR] iBot.Core.ActivityException: failed after 2 attempts. ---> OpenQA.Selenium.ElementClickInterceptedException: element click intercepted: Element <a data-tab="policy">...</a> is not clickable at point (642, 318). Other element would receive the click: <div class="session-warning-banner">...</div>
  (Session info: chrome=128.0.6613.120)
   at OpenQA.Selenium.WebDriver.UnpackAndThrowOnError(Response r, String c)
   at OpenQA.Selenium.WebElement.Click()
   --- End of inner exception stack trace ---
   at iBot.Runtime.RetryScope.Execute(ActivityContext c, Int32 a) in C:\\build\\RetryScope.cs:line 147
"""


# ---------------------------------------------------------------- sanitize

def test_structure_survives_redaction() -> None:
    """The first draft's phone rule ate every timestamp in the file."""
    text = "11-09-2026 09:41:09.402 [INFO ] call +44 7700 900123 now"
    out = sanitize_log(text).text
    check("timestamps survive", "11-09-2026 09:41:09.402" in out)
    check("log level survives", "[INFO ]" in out)
    check("the phone is still redacted", "<PHONE>" in out)

    out2 = sanitize_log(LOG).text
    check("stack frames survive", "at OpenQA.Selenium.WebElement.Click()" in out2)
    check("':line 147' survives", ":line 147" in out2)
    check("the browser version survives", "128.0.6613.120" in out2)
    check("pixel coordinates survive", "(642, 318)" in out2)
    check("no placeholder sentinel leaks", "\x00" not in out2)


def test_code_structure_survives() -> None:
    out = sanitize_code('var conn = "Server=sql01;Initial Catalog=c;User Id=u;Password=p;";').text
    check("connection string redacted", "<CONNSTR>" in out and "sql01" not in out)
    check("the closing quote and semicolon survive", out.rstrip().endswith('";'))

    out2 = sanitize_code('var c = new Cred { User = "svc", Password = "hunter2" };').text
    check("password literal redacted", "hunter2" not in out2 and "<SECRET>" in out2)
    check("the brace and semicolon survive", out2.rstrip().endswith("};"))


def test_counts_are_real_redactions() -> None:
    """re.subn counts matches; the card rule only replaces when Luhn confirms."""
    r = sanitize_log("call +44 7700 900123 about it")
    check("a card-shaped phone is not counted as a card", "card" not in r.counts, str(r.counts))
    r2 = sanitize_log("card 4111 1111 1111 1111 here")
    check("a real card is redacted and counted",
          r2.counts.get("card") == 1 and "<CARD>" in r2.text)


def test_secrets_and_pii() -> None:
    for raw, token in [
        ("contact a.b@example.com", "<EMAIL>"),
        ("key sk-ant-api03-" + "x" * 30, "<SECRET>"),
        ("AKIAIOSFODNN7EXAMPLE", "<SECRET>"),   # AWS's published example; not a real key
        # The jwt.io sample token; not a real key.
        ("Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
         ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "<SECRET>"),
        ("https://user:pw@host/x", "<SECRET>"),
    ]:
        out = sanitize_log(raw).text
        check(f"redacts {token} in {raw[:22]!r}", token in out)

    r = sanitize_log("policy POL-448404 filed", {"policy": r"POL-\d{6}"})
    check("client-specific identifiers redact when configured", "<CLIENT_POLICY>" in r.text)
    check("and pass through when not configured", "POL-448404" in sanitize_log("policy POL-448404").text)


def test_canary() -> None:
    seeded = f"11-09-2026 09:41:09.402 [ERROR] boom for {CANARY}"
    check("the canary survives sanitization (it is not PII-shaped)",
          canary_check(sanitize_log(seeded).text) != [])
    check("canary_check finds nothing in clean text", canary_check("all clear") == [])


# ------------------------------------------------------------- fingerprint

def test_innermost_exception() -> None:
    t, _ = unwrap("iBot.Core.ActivityException: retried. ---> System.IO.IOException: locked")
    check("unwraps to the innermost type", t == "System.IO.IOException", t)

    t2, _ = unwrap("A.B.OuterException: x ---> C.D.MiddleException: y ---> E.F.InnerException: z")
    check("unwraps a chain deeper than two", t2 == "E.F.InnerException", t2)

    f = parse(LOG)
    check("a real wrapped log yields the inner type",
          f.exception_type == "OpenQA.Selenium.ElementClickInterceptedException", f.exception_type)

    a, _ = unwrap("iBot.Core.ActivityException: x ---> System.Runtime.InteropServices.COMException (0x800A03EC): busy")
    b, _ = unwrap("iBot.Core.ActivityException: y ---> System.Runtime.InteropServices.COMException (0x80010105): threw")
    check("HRESULTs keep distinct COM faults apart", a != b, f"{a} vs {b}")
    check("and stay in the type", "0x800A03EC" in a)


def test_frames_prefer_the_fault_site() -> None:
    frames = top_frames(LOG)
    check("frames come from above the inner-exception marker",
          frames[0].startswith("OpenQA.Selenium"), str(frames[:2]))
    check("the retry scope is not the top frame", "RetryScope" not in frames[0])
    check("line numbers are dropped", not any(":line" in f for f in frames))


def test_normalization_survives_noise() -> None:
    base = "stale element reference: element is not attached\n  (Session info: chrome=%s)"
    check("a Chrome update does not rotate the fingerprint",
          normalize(base % "128.0.6613.120") == normalize(base % "129.0.6668.58"))

    coords = "not clickable at point (%s). Other element would receive the click"
    check("window size does not rotate it",
          normalize(coords % "642, 318") == normalize(coords % "388, 190"))

    # normalize() lowercases at the end, so placeholders come back lowercased.
    check("numbers glued to units normalize (no word boundary after a digit)",
          normalize("timed out after 15000ms") == "timed out after <num>ms")
    check("two unit values collapse to one fingerprint",
          normalize("after 15000ms") == normalize("after 30000ms"))
    check("small integers are kept", "index 3" in normalize("element at index 3"))
    check("paths keep their basename",
          "config.xml" in normalize(r"could not find C:\app\cfg\config.xml"))
    check("timestamps normalize", normalize("at 2026-09-11T09:41:09Z") == "at <ts>")
    check("CRLF never reaches the hash", "\r" not in normalize("a\r\nb"))


def test_identity_is_stable_and_versioned() -> None:
    fp1, f1 = fingerprint(LOG, "AP.cs:Post")
    fp2, _ = fingerprint(LOG.replace("09:41:09.402", "11:02:55.001"), "AP.cs:Post")
    check("the same failure at a different time is the same fingerprint", fp1 == fp2)

    fp3, _ = fingerprint(LOG, "Other.cs:Different")
    check("a different code location is a different fingerprint", fp1 != fp3)

    check("bumping the algorithm version rotates the cache",
          compute(f1, algorithm_version=ALGORITHM_VERSION + 1) != fp1)
    check("a different profile cannot collide",
          compute(f1, profile="python") != compute(f1, profile="dotnet"))

    check("a log with no exception yields nothing",
          fingerprint("11-09-2026 09:41:09.402 [INFO ] all fine") is None)


def test_sanitize_then_fingerprint() -> None:
    """The pipeline order: redaction must not change identity."""
    a = fingerprint(sanitize_log(LOG).text, "AP.cs:Post")[0]
    b = fingerprint(sanitize_log(LOG.replace("Post", "Post")).text, "AP.cs:Post")[0]
    check("sanitized logs still fingerprint", a is not None and a == b)

    with_pii = LOG.replace("failed after 2 attempts", "failed for a.b@example.com")
    other_pii = LOG.replace("failed after 2 attempts", "failed for c.d@example.com")
    fa = fingerprint(sanitize_log(with_pii).text, "AP.cs:Post")[0]
    fb = fingerprint(sanitize_log(other_pii).text, "AP.cs:Post")[0]
    check("two people, one failure -> one fingerprint", fa == fb)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
