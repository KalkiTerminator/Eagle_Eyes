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


NOVEL_LOG = (
    b"13-09-2026 08:07:00.000 [ERROR] Activity 'ResolveRemittanceAccount' failed\n"
    b"13-09-2026 08:07:00.000 [ERROR] System.InvalidOperationException: "
    b"Sequence contains no matching element\n"
    b"   at System.Linq.Enumerable.First[TSource](IEnumerable`1 source, Func`2 predicate)\n"
    b"   at iBot.Processes.Finance.AP_RemittancePosting.ResolveRemittanceAccount"
    b"(String policyRef) in C:\\ibot\\processes\\Finance\\AP_RemittancePosting.cs:line 88\n"
)
"""A failure no pattern in the library answers.

Used where a test needs the MODEL path specifically. The library now answers
the selector and navigation failures the synthetic estate is full of, so a test
that wants to prove the deep path works has to bring a failure the library does
not know -- otherwise it silently starts asserting things about a template.
"""


def _sample_log() -> bytes:
    root = Path(__file__).resolve().parents[1] / "sandbox"
    logs = list(root.rglob("*.log")) if root.exists() else []
    if logs:
        return logs[0].read_bytes()
    return (b"13-09-2026 08:07:00.000 [ERROR] OpenQA.Selenium."
            b"ElementClickInterceptedException: element click intercepted\n"
            b"   at Bot.Run() in Bot.cs:line 42\n")


def _submit(c, **files):
    """Submit through the folder path -- discover, then analyse everything.

    The single-file /submit route is gone; the folder picker handles one file
    as readily as a tree. These helpers moved rather than being deleted, so the
    validation coverage follows the feature instead of disappearing with it.
    """
    paths, parts = [], []
    log = files.pop("log", None) or ("bot.log", _sample_log(), "text/plain")
    rel = "data/INSURANCE_OPS/BOT001/2026/09/13/logs/user logs/logs/" + log[0]
    paths.append(rel)
    parts.append(("files", (rel, log[1], log[2])))
    for kind, spec in files.items():
        where = {"code": "code_folder/", "screenshot":
                 "data/INSURANCE_OPS/BOT001/2026/09/13/logs/user logs/screenshot/"}
        rel = where.get(kind, "") + spec[0]
        paths.append(rel)
        parts.append(("files", (rel, spec[1], spec[2])))
    return c.post("/app/discover", data={"paths": paths}, files=parts,
                  follow_redirects=False)


def _submit_and_run(c, **files):
    """Discover, then analyse every candidate. Returns the job response."""
    r = _submit(c, **files)
    m = re.search(r'name="token" value="(\w+)"', r.text)
    if not m:
        return r
    picks = [str(i) for i in range(r.text.count('name="pick"'))]
    return c.post("/app/analyse", data={"token": m.group(1), "pick": picks},
                  follow_redirects=False)


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
        for path in ("/app", "/admin", "/analytics", "/team", "/failures/1",
                     "/jobs/abc"):
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

        check("it cannot open the Analyse tab's upload",
              "Drop a bot folder" not in c.get("/app").text)
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
        check("  with the tab bar", 'nav class="tabs"' in r.text)
        check("  and the folder picker", "Drop a bot folder" in r.text)

        r = _submit_and_run(c,
                    log=("bot.log", NOVEL_LOG, "text/plain"),
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
        # The evidence table is the part of the page that says what the answer
        # was based on. Both of these were hard-coded empty in the hosted
        # renderer, so every report showed a blank Exception row and claimed
        # "log only" whatever it had read -- and nothing failed, because no
        # test read the table.
        check("  with the exception it was actually thrown from",
              "InvalidOperationException" in r.text, "")
        check("  and the inputs it was actually given",
              "code" in r.text.lower() and "screenshot" in r.text.lower())

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
        status = _wait(c, _submit_and_run(c).headers["location"])
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
              "Nothing visible to you yet" in c.get("/app").text)
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
        job_url = _submit_and_run(c).headers["location"]
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
            # Flip the first character to something guaranteed different.
            # This case used to build "0" + real[1:], which alters nothing at
            # all when the session id already starts with a zero -- a security
            # check that quietly passed for the wrong reason one run in sixteen.
            ("an altered id on a real signature",
             ("1" if (real or "0")[0] == "0" else "0") + (real or "x.y")[1:]),
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
        status = _wait(c, _submit_and_run(c).headers["location"])
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
    """The folder path writes client-chosen paths, so it validates them."""
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        r = c.post("/app/discover",
                   data={"paths": ["../../../../etc/cron.d/x"]},
                   files=[("files", ("x", b"* * * * * root id", "text/plain"))])
        check("a traversing path is refused", "parent traversal refused" in r.text)
        check("  and the Analyse tab comes back with the reason",
              "Drop a bot folder" in r.text)

        r = c.post("/app/discover", data={"paths": ["/etc/passwd"]},
                   files=[("files", ("p", b"root:x:0:0", "text/plain"))])
        check("an absolute path is refused", "absolute path refused" in r.text)

        r = c.post("/app/discover", data={"paths": ["notes/readme.txt"]},
                   files=[("files", ("r", b"nothing here", "text/plain"))])
        check("a folder with no failures in it says so, and invents none",
              "Nothing in that folder looked like a bot failure" in r.text)
        check("  naming the shape discovery expects", "data/&lt;service line&gt;" in r.text
              or "data/<service line>" in r.text)
    finally:
        _cleanup(c, d)


def test_what_the_review_reports_is_what_discovery_found() -> None:
    """The review table is the honest account of a weaker input.

    A folder gives real pairing, so the page shows the real method -- including
    the refusals. Nothing is claimed that discovery did not establish.
    """
    if not WEB:
        return
    c, d = _client()
    try:
        _register(c, "dev@x.com")
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        _approve(c, _account_ids(c)["dev@x.com"], role="user")
        c.post("/logout")
        _login(c, "dev@x.com")

        r = _submit(c, code=("BOT001.txt", b"public class Bot { void Run(){} }",
                             "text/plain"))
        check("the review page renders", r.status_code == 200
              and "What the folder contained" in r.text, str(r.status_code))
        check("  and says nothing has been sent yet",
              "Nothing has been sent to a model" in r.text)
        check("  and counts distinct problems, not just failures",
              "Distinct problems" in r.text)
        check("  and states what it would actually call the model for",
              "Would call the model" in r.text)

        status = _wait(c, _submit_and_run(
            c, code=("BOT001.txt", b"public class Bot {}", "text/plain")
        ).headers["location"])
        check("the analysis completes", status["status"] == "done", str(status))
        check("  reporting how many were analysed and how many deduplicated",
              "analysed" in status["result"] and "deduped" in status["result"],
              str(status.get("result")))
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

        r = _submit_and_run(c)
        check("a submission is refused before anything is queued",
              r.status_code == 200 and "kill switch" in r.text, str(r.status_code))
        check("  and it says nothing was sent or charged",
              "Nothing was sent or charged" in r.text)
        check("  and that the upload was not thrown away for it",
              "upload is still here" in r.text)
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
        first = _submit_and_run(c)
        check("the first submission is accepted", first.status_code == 303)
        _wait(c, first.headers["location"])
        second = _submit_and_run(c)
        check("the second is refused by the cap",
              "which is the limit" in second.text, str(second.status_code))
        c.post("/logout")

        _login(c, "two@x.com")
        check("and another person is unaffected by it",
              _submit_and_run(c).status_code == 303)
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
        _wait(c, _submit_and_run(c).headers["location"])
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
        r = _submit_and_run(c, log=("a.log", nasty, "text/plain"))
        status = _wait(c, r.headers["location"])
        page = c.get(f"/failures/{status['result']['failure_id']}").text
        check("no executable script tag survives into the page",
              "<script>alert('xss')</script>" not in page)
        check("the report is isolated in a sandboxed frame",
              "sandbox" in page and "<iframe" in page)
    finally:
        _cleanup(c, d)


# ------------------------------------------------------------------- email

def _own_a_bot(c, email: str) -> None:
    """Make `email` the owner of every bot, through the app's own repository."""
    from eagle_eyes.storage import BotRepo, Principal, ADMIN
    db = c.app.state.ee.db
    p = Principal("test-setup", ADMIN)
    for row in db.conn.execute("SELECT id FROM bot"):
        BotRepo(db, p).set_owner(row["id"], email)


def _disown_bots(c) -> None:
    """An uploaded bot is owned by whoever uploaded it, so ownerlessness -- the
    state a SCANNED bot starts in -- has to be arranged deliberately."""
    c.app.state.ee.db.conn.execute("UPDATE bot SET owner_dev_id = NULL")


def _set_confidence(c, value: float) -> None:
    """MockBackend answers at confidence 0.0, and 0.0 is correctly held for the
    digest rather than mailed as an answer. Testing the ROUTING therefore needs
    an analysis with a confidence the mock cannot produce."""
    c.app.state.ee.db.conn.execute("UPDATE analysis SET confidence = ?", (value,))


def test_emailing_a_diagnosis_refuses_before_it_guesses() -> None:
    """Three refusals, each of which would be worse as a send.

    Nothing to say, nobody to say it to, or already said -- and the last one is
    the product working, not failing.
    """
    c, d = _client()
    try:
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        r = _submit_and_run(c, log=("bot.log", NOVEL_LOG, "text/plain"))
        failure_id = _wait(c, r.headers["location"])["result"]["failure_id"]

        _set_confidence(c, 0.85)

        # 1. No owner on the bot -> no recipient, and none is invented.
        _disown_bots(c)
        r = c.post(f"/failures/{failure_id}/email", follow_redirects=False)
        check("an ownerless bot is refused", "mail=no_owner" in r.headers["location"],
              r.headers["location"])
        page = c.get(f"/failures/{failure_id}?mail=no_owner").text
        check("  and the page says why, in terms of what to do",
              "Nobody owns this bot" in page and "Team tab" in page)

        # 2. With an owner, the first send goes.
        _own_a_bot(c, "owner@x.com")
        r = c.post(f"/failures/{failure_id}/email", follow_redirects=False)
        where = r.headers["location"]
        check("with an owner it is sent", "mail=dry_run" in where, where)
        check("  as a dry run, because no relay is configured", "mail=sent" not in where)

        # 3. The same failure again is suppressed -- ACROSS REQUESTS, which is
        #    the whole point of the durable store. With the in-memory one a new
        #    Notifier is built per request and this would send every time.
        r = c.post(f"/failures/{failure_id}/email", follow_redirects=False)
        check("the same failure to the same developer is suppressed the second time",
              "mail=suppressed" in r.headers["location"], r.headers["location"])
        check("  and the reason is carried to the page",
              "already+notified" in r.headers["location"]
              or "already%20notified" in r.headers["location"],
              r.headers["location"])

        page = c.get(f"/failures/{failure_id}?mail=suppressed&why=already+notified").text
        check("  which the page shows rather than hiding", "Not sent, on purpose" in page)

        n = c.app.state.ee.db.conn.execute(
            "SELECT COUNT(*) n FROM audit_event WHERE action='notify'").fetchone()["n"]
        check("every attempt is audited, sent or not", n >= 3, str(n))
    finally:
        _cleanup(c, d)


def test_the_recipient_is_the_bot_owner_not_whoever_clicked() -> None:
    """A diagnosis in the wrong inbox is a disclosure as well as a waste."""
    c, d = _client()
    try:
        _login(c, ADMIN_EMAIL, ADMIN_PASSWORD)
        r = _submit_and_run(c, log=("bot.log", NOVEL_LOG, "text/plain"))
        failure_id = _wait(c, r.headers["location"])["result"]["failure_id"]
        _set_confidence(c, 0.85)
        # The uploader owns what they uploaded, so this reassignment is what
        # makes the test mean anything: the owner is now someone else.
        _own_a_bot(c, "owner@x.com")

        c.post(f"/failures/{failure_id}/email", follow_redirects=False)

        # The dry run records the recipient in notification_state, keyed on the
        # developer -- so the address it chose is checkable rather than a claim.
        row = c.app.state.ee.db.conn.execute(
            "SELECT d.email FROM notification_state ns"
            " JOIN developer d ON d.id = ns.developer_id").fetchone()
        check("the mail went to the bot's owner", row is not None
              and row["email"] == "owner@x.com",
              row["email"] if row else "nothing recorded")
        check("  and not to the admin who pressed the button",
              (row["email"] if row else "") != ADMIN_EMAIL)
    finally:
        _cleanup(c, d)


def test_the_html_part_carries_the_severity_as_a_word() -> None:
    """Colour is never the only carrier, in mail least of all.

    Clients invert, re-theme and strip styles, so a severity that exists only
    as a background colour does not exist for some readers at all.
    """
    from eagle_eyes.notify import SEVERITY_COLOUR, compose_html
    from eagle_eyes.web.charts import SEVERITY_STATUS, STATUS_LIGHT

    for severity, (label, colour) in SEVERITY_COLOUR.items():
        html = compose_html(bot_label="SL/BOT1", exception_type="X.YException",
                            root_cause="rc", suggested_fix="sf", confidence=0.9,
                            severity=severity)
        check(f"{severity}: the word is in the mail", label in html)
        check(f"{severity}: the colour matches the product's status palette",
              colour == STATUS_LIGHT[SEVERITY_STATUS[severity]],
              f"{colour} vs {STATUS_LIGHT[SEVERITY_STATUS[severity]]}")

    plain = compose_html(bot_label="SL/BOT1", exception_type="X.YException",
                         root_cause="rc", suggested_fix="sf", confidence=0.9)
    check("an unclassified analysis gets no badge rather than an invented one",
          "CRITICAL" not in plain and "LOW" not in plain)


if __name__ == "__main__":
    sys.exit(_h.run_all(globals()))
