"""The web product, driven through HTTP.

Everything here goes through the real ASGI app -- routes, dependencies,
templates, cookies -- because the questions worth asking are about what a
browser can reach, not about what a function returns. tests/test_rbac.py checks
the rules at the data layer; this checks that the pages in front of them do not
open a door around it.

Skipped rather than failed when FastAPI is not installed: the CLI and the other
suites run on the standard library alone, and that is a property worth keeping.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _harness import Harness  # noqa: E402

_h = Harness()
check = _h.check

try:
    from fastapi.testclient import TestClient
    from eagle_eyes.web.app import create_app
    WEB = True
except ImportError as exc:                                  # pragma: no cover
    WEB = False
    WHY = str(exc)

ADMIN_EMAIL = "root@x.com"
ADMIN_PASSWORD = "correct-horse-battery-staple"
USER_PASSWORD = "a-long-enough-password"

ENV = {
    "EAGLE_EYES_SECRET_KEY": "k" * 40,
    "EAGLE_EYES_BACKEND": "mock",
    "EAGLE_EYES_ADMIN_EMAIL": ADMIN_EMAIL,
    "EAGLE_EYES_ADMIN_PASSWORD": ADMIN_PASSWORD,
}


# As in test_rbac.py: the same suite runs against PostgreSQL when
# EAGLE_EYES_TEST_DSN is set, so the deployed dialect is the tested one.
TEST_DSN = os.environ.get("EAGLE_EYES_TEST_DSN", "").strip()


def _client(**extra) -> tuple[TestClient, Path]:
    d = Path(tempfile.mkdtemp())
    env = {**ENV, **extra}
    if TEST_DSN:
        import psycopg
        with psycopg.connect(TEST_DSN, autocommit=True) as c:
            c.execute("DROP SCHEMA public CASCADE")
            c.execute("CREATE SCHEMA public")
        env["DATABASE_URL"] = TEST_DSN
    app = create_app(d / "web.db", env)
    return TestClient(app), d


def _cleanup(c, d: Path) -> None:
    """Close the database as well as removing the directory.

    Against PostgreSQL the app holds a connection pool. Eighteen tests leaving
    eighteen pools open is the same leak a long-running deployment would have,
    so the tests are made to notice it rather than being given a pass.
    """
    try:
        c.app.state.ee.db.close()
    except Exception:
        pass
    shutil.rmtree(d, ignore_errors=True)


def _register(c, email, password=USER_PASSWORD) -> None:
    c.post("/register", data={"email": email, "password": password,
                              "display_name": email.split("@")[0]})


def _login(c, email, password=USER_PASSWORD):
    return c.post("/login", data={"email": email, "password": password},
                  follow_redirects=True)


def _account_ids(c) -> dict[str, int]:
    """Map email -> account id, read off the admin page."""
    html = c.get("/admin").text
    rows = re.findall(
        r'<td>([^<\s]+@[^<\s]+)<div.*?name="account_id" value="(\d+)"',
        html, re.S)
    return {email: int(aid) for email, aid in rows}


def _approve(c, account_id, role="user", scope=()):
    # httpx encodes a dict value that is a list as repeated keys, which is what
    # a multi-select posts. A list of (key, value) tuples is NOT accepted by
    # httpx as form data -- it is treated as a raw byte stream, and the request
    # arrives with an empty body and a 422 that reads like an app bug.
    data = {"account_id": account_id, "role": role, "scope": list(scope)}
    return c.post("/admin/approve", data=data, follow_redirects=True)


def _status_of(c, email: str) -> str:
    """Read an account's status off the admin page, so approval is verified."""
    html = c.get("/admin").text
    m = re.search(
        re.escape(email) + r'<div.*?<span class="pill \w+">(\w+)</span>', html, re.S)
    return m.group(1) if m else "?"


def _sample_log() -> bytes:
    root = Path(__file__).resolve().parents[1] / "sandbox"
    logs = list(root.rglob("*.log")) if root.exists() else []
    if logs:
        return logs[0].read_bytes()
    return (b"13-09-2026 08:07:00.000 [ERROR] OpenQA.Selenium."
            b"ElementClickInterceptedException: element click intercepted\n"
            b"   at Bot.Run() in Bot.cs:line 42\n")


def _submit(c, **files):
    payload = {"log": ("bot.log", _sample_log(), "text/plain")}
    payload.update(files)
    return c.post("/submit",
                  data={"service_line": "INSURANCE_OPS", "bot_number": "BOT001"},
                  files=payload, follow_redirects=False)


def _wait(c, job_url: str, timeout: float = 20.0) -> dict:
    job_id = job_url.rsplit("/", 1)[-1]
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        status = c.get(f"/jobs/{job_id}/status").json()
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.05)
    return status


# ------------------------------------------------------------------ public

def test_public_pages() -> None:
    if not WEB:
        check("web suite skipped -- pip install '.[web]'", True, WHY)
        return
    c, d = _client()
    try:
        r = c.get("/")
        check("the landing page renders", r.status_code == 200)
        check("  and says what the product does",
              "root cause" in r.text.lower())
        check("  and states that this instance is synthetic data only",
              "synthetic data" in r.text.lower())

        check("healthz reports ok", c.get("/healthz").json()["status"] == "ok")
        check("  and reveals nothing about the data",
              set(c.get("/healthz").json()) == {"status"})

        check("the login page renders", c.get("/login").status_code == 200)
        check("the register page renders", c.get("/register").status_code == 200)
        check("API docs are not exposed", c.get("/openapi.json").status_code == 404)
    finally:
        _cleanup(c, d)


def test_anonymous_is_sent_to_sign_in_not_shown_data() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        for path in ("/app", "/admin", "/submit", "/failures/1", "/jobs/abc"):
            r = c.get(path, follow_redirects=False)
            check(f"anonymous {path} does not return content",
                  r.status_code in (303, 401), str(r.status_code))
            check(f"  and {path} redirects to sign-in",
                  r.headers.get("location", "").startswith("/login"),
                  r.headers.get("location", ""))
    finally:
        _cleanup(c, d)


# ------------------------------------------------------------ the gate

def test_a_pending_account_gets_a_login_and_nothing_else() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        r = _login(c, "dev@x.com")
        check("a pending account can sign in", r.status_code == 200)
        check("  and is told it is awaiting approval", "Awaiting approval" in r.text)
        check("  and the page says nothing is hidden behind it",
              "nothing behind it" in r.text)

        check("it cannot open the submit page", c.get("/submit").status_code == 403)
        check("it cannot post a submission", _submit(c).status_code == 403)
        check("it cannot reach admin", c.get("/admin").status_code == 403)
        check("it cannot fetch a failure",
              c.get("/failures/1").status_code in (403, 404))
        check("it cannot approve itself",
              c.post("/admin/approve",
                     data={"account_id": 1, "role": "admin"}).status_code == 403)
    finally:
        _cleanup(c, d)


def test_the_full_journey() -> None:
    """Register, approve, sign in, analyse, read the diagnosis, give feedback."""
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        check("the admin page lists the request", "dev@x.com" in ids, str(ids))
        _approve(c, ids["dev@x.com"], role="user")
        check("approval takes effect", _status_of(c, "dev@x.com") == "approved",
              _status_of(c, "dev@x.com"))
        c.post("/logout")

        _login(c, "dev@x.com")
        r = c.get("/app")
        check("the approved user gets the home page", r.status_code == 200)
        check("  scoped and said to be scoped", "scoped to what you are allowed"
              in r.text)

        r = _submit(c,
                    code=("Bot.cs.txt", b"public class Bot { void Run(){ Click(); } }",
                          "text/plain"),
                    screenshot=("shot.png", b"\x89PNG\r\n\x1a\n" + b"0" * 400,
                                "image/png"))
        check("the submission is accepted", r.status_code == 303, str(r.status_code))

        status = _wait(c, r.headers["location"])
        check("the analysis completes on a worker", status["status"] == "done",
              str(status))
        failure_id = status["result"]["failure_id"]

        r = c.get(f"/failures/{failure_id}")
        check("the diagnosis renders", r.status_code == 200)
        check("  reusing the same report the CLI writes", "Root cause" in r.text)

        r = c.post(f"/failures/{failure_id}/feedback",
                   data={"verdict": "wrong", "comment": "not it"},
                   follow_redirects=True)
        check("feedback is accepted", r.status_code == 200)

        check("the failure appears on the home page",
              str(failure_id) in c.get("/app").text)
    finally:
        _cleanup(c, d)


# --------------------------------------------------------- horizontal access

def test_one_user_cannot_read_anothers_failure_over_http() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "alice@x.com")
        _register(c, "mallory@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        _approve(c, ids["alice@x.com"], role="user")
        _approve(c, ids["mallory@x.com"], role="user")
        c.post("/logout")

        _login(c, "alice@x.com")
        status = _wait(c, _submit(c).headers["location"])
        check("alice's analysis completes", status["status"] == "done", str(status))
        failure_id = status["result"]["failure_id"]
        c.post("/logout")

        _login(c, "mallory@x.com")
        r = c.get(f"/failures/{failure_id}")
        check("mallory cannot read it", r.status_code == 404, str(r.status_code))
        missing = c.get("/failures/999999")
        check("  and a failure that does not exist answers identically",
              missing.status_code == r.status_code)
        check("  deliberately, and the page says so",
              "deliberately the same one" in r.text)

        check("mallory's home lists nothing",
              "Nothing is visible to you yet" in c.get("/app").text)
        check("mallory cannot post feedback on it",
              c.post(f"/failures/{failure_id}/feedback",
                     data={"verdict": "correct"}).status_code == 404)
    finally:
        _cleanup(c, d)


def test_a_job_belongs_to_the_person_who_started_it() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "alice@x.com")
        _register(c, "mallory@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        _approve(c, ids["alice@x.com"], role="user")
        _approve(c, ids["mallory@x.com"], role="user")
        c.post("/logout")

        _login(c, "alice@x.com")
        job_url = _submit(c).headers["location"]
        _wait(c, job_url)
        job_id = job_url.rsplit("/", 1)[-1]
        c.post("/logout")

        _login(c, "mallory@x.com")
        check("another user cannot read the job page",
              c.get(f"/jobs/{job_id}").status_code == 404)
        check("nor its status, which carries the failure id",
              c.get(f"/jobs/{job_id}/status").status_code == 404)
    finally:
        _cleanup(c, d)


# ---------------------------------------------------------------- escalation

def test_a_forged_or_stale_cookie_gets_nothing() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        check("the admin is in", c.get("/admin").status_code == 200)

        real = c.cookies.get("ee_session")
        for label, forged in (
            ("an unsigned session id", "f" * 64),
            ("a wrong signature", "f" * 64 + ".deadbeef"),
            ("a role smuggled into the value", "admin.admin"),
            ("an altered id on a real signature",
             "0" + (real or "x.y")[1:]),
            ("empty", ""),
        ):
            c.cookies.clear()
            c.cookies.set("ee_session", forged)
            r = c.get("/admin", follow_redirects=False)
            check(f"{label} is treated as anonymous", r.status_code == 303,
                  str(r.status_code))
    finally:
        _cleanup(c, d)


def test_suspension_ends_a_live_session() -> None:
    if not WEB:
        return
    c, d = _client()
    admin, _ = None, None
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        _approve(c, ids["dev@x.com"], role="user")
        c.post("/logout")

        _login(c, "dev@x.com")
        check("the user is signed in", c.get("/app").status_code == 200)
        user_cookie = c.cookies.get("ee_session")

        c.cookies.clear()
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        c.post("/admin/status", data={"account_id": ids["dev@x.com"],
                                      "status": "suspended"})
        c.cookies.clear()
        c.cookies.set("ee_session", user_cookie)
        r = c.get("/app", follow_redirects=False)
        check("the suspended user's existing cookie stops working immediately",
              r.status_code == 303, str(r.status_code))
    finally:
        _cleanup(c, d)


def test_a_manager_sees_their_scope_and_no_more() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "alice@x.com")
        _register(c, "mgr@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        _approve(c, ids["alice@x.com"], role="user")
        c.post("/logout")

        _login(c, "alice@x.com")
        status = _wait(c, _submit(c).headers["location"])
        failure_id = status["result"]["failure_id"]
        c.post("/logout")

        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, ids["mgr@x.com"], role="manager", scope=("INSURANCE_OPS",))
        check("a manager can be approved with a scope",
              _status_of(c, "mgr@x.com") == "approved", _status_of(c, "mgr@x.com"))

        c.post("/admin/status", data={"account_id": ids["mgr@x.com"],
                                      "status": "suspended"})
        r = _approve(c, ids["mgr@x.com"], role="manager", scope=())
        check("but an empty scope is refused, not silently accepted",
              _status_of(c, "mgr@x.com") == "suspended", _status_of(c, "mgr@x.com"))
        check("  and the admin is shown why on the page",
              "can see nothing" in r.text, str(r.url))
        _approve(c, ids["mgr@x.com"], role="manager", scope=("INSURANCE_OPS",))
        c.post("/logout")

        _login(c, "mgr@x.com")
        check("the manager sees the failure in their scope",
              c.get(f"/failures/{failure_id}").status_code == 200)
    finally:
        _cleanup(c, d)


# -------------------------------------------------------------------- ingest

def test_uploads_are_validated_not_trusted() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        r = c.post("/submit", data={"service_line": "../../etc",
                                    "bot_number": "BOT001"},
                   files={"log": ("a.log", b"x", "text/plain")})
        check("a path-shaped service line is refused",
              "not allowed" in r.text, str(r.status_code))

        r = c.post("/submit", data={"service_line": "SL", "bot_number": "B1"},
                   files={"log": ("a.log", _sample_log(), "text/plain"),
                          "screenshot": ("evil.png", b"<svg onload=alert(1)>",
                                         "image/png")},
                   follow_redirects=False)
        check("a file claiming to be a PNG but is not is refused",
              r.status_code == 200 and "not a PNG" in r.text)
        check("  because the leading bytes are checked, not the name",
              "leading bytes" in r.text)

        r = c.post("/submit", data={"service_line": "SL", "bot_number": "B1"},
                   files={"log": ("big.log", b"x" * (9 * 1024 * 1024), "text/plain")})
        check("an oversized log is refused", "the limit is" in r.text)
    finally:
        _cleanup(c, d)


def test_an_upload_says_how_it_is_degraded() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        check("the submit page warns before anything is sent",
              "weaker input" in c.get("/submit").text)

        status = _wait(c, _submit(c).headers["location"])
        check("the analysis completes", status["status"] == "done", str(status))
        degradations = " ".join(status["result"]["degradations"])
        check("it says the log was the only input",
              "log alone" in degradations, degradations)
        check("  and that reuse is refused without a code mtime, or code is absent",
              "log alone" in degradations or "NOT be reused" in degradations)

        r = c.get(f"/failures/{status['result']['failure_id']}")
        check("the stored pairing method is 'uploaded', not a claimed pairing",
              r.status_code == 200)
    finally:
        _cleanup(c, d)


# --------------------------------------------------------------------- spend

def test_the_kill_switch_stops_spending_without_a_redeploy() -> None:
    if not WEB:
        return
    c, d = _client(EAGLE_EYES_DISABLE_MODEL="true")
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        check("every page says model calls are off",
              "Model calls are switched off" in c.get("/app").text)

        r = _submit(c)
        check("a submission is refused before anything is queued",
              r.status_code == 200 and "kill switch" in r.text, str(r.status_code))
        check("  and it says nothing was charged", "nothing was charged" in r.text)
    finally:
        _cleanup(c, d)


def test_the_hourly_cap_is_per_person() -> None:
    if not WEB:
        return
    c, d = _client(EAGLE_EYES_HOURLY_ANALYSES="1")
    try:
        _register(c, "one@x.com")
        _register(c, "two@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        ids = _account_ids(c)
        _approve(c, ids["one@x.com"], role="user")
        _approve(c, ids["two@x.com"], role="user")
        c.post("/logout")

        _login(c, "one@x.com")
        first = _submit(c)
        check("the first submission is accepted", first.status_code == 303)
        _wait(c, first.headers["location"])
        second = _submit(c)
        check("the second is refused by the cap",
              "which is the limit" in second.text, str(second.status_code))
        c.post("/logout")

        _login(c, "two@x.com")
        check("and another person is unaffected by it",
              _submit(c).status_code == 303)
    finally:
        _cleanup(c, d)


def test_spend_is_read_from_the_database_not_a_counter() -> None:
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")
        _wait(c, _submit(c).headers["location"])
        c.post("/logout")

        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        r = c.get("/admin")
        check("the admin page reports lifetime spend", "Spent, lifetime" in r.text)
        check("  and says where the figure comes from",
              "committed analyses" in r.text)
    finally:
        _cleanup(c, d)


# ------------------------------------------------------------------ injection

def test_untrusted_content_is_escaped_in_the_page() -> None:
    """A log is attacker-influenced. It reaches a browser, so it must be inert."""
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        nasty = (b"13-09-2026 08:07:00.000 [ERROR] System.InvalidOperationException: "
                 b"<script>alert('xss')</script> failed\n"
                 b"   at Bot.Run() in Bot.cs:line 1\n")
        r = c.post("/submit", data={"service_line": "SL", "bot_number": "B1"},
                   files={"log": ("a.log", nasty, "text/plain")},
                   follow_redirects=False)
        status = _wait(c, r.headers["location"])
        page = c.get(f"/failures/{status['result']['failure_id']}").text
        check("no executable script tag survives into the page",
              "<script>alert('xss')</script>" not in page)
        check("the report is isolated in a sandboxed frame",
              "sandbox" in page and "<iframe" in page)
    finally:
        _cleanup(c, d)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
