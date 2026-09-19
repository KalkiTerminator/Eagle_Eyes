"""The web application: landing, sign-in, home, report, admin.

WHAT ENFORCES ACCESS. Not these routes. Every read goes through a repository
that requires a Principal, and a Principal can only be built from an approved
account (`auth.Account.principal`). The dependencies below are a convenience so
a page can say "sign in" instead of returning a 500 -- if one were deleted the
data layer would still refuse. That ordering is the point: a route decorator is
a thing someone forgets to add to a new route.

WHAT THIS DEPLOYMENT IS FOR. Synthetic data, shown to people. The model calls
are real and the spend is real, which is why `spend.py` exists. Before a hosted
instance sees client data, docs/PRODUCTION_MIGRATION.md has to be worked
through -- it is a different security argument, not a bigger version of this one.
"""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import runtime, storage
from ..analysis import SCREENSHOT_MODES, Engine
from ..model_gateway import (
    MODELS, SELECTABLE, BackendError, create_backend, current_environment,
    models_for, project,
)
from ..notify import compose, compose_html
from ..report import ReportInput, render
from ..storage import (
    ADMIN, MANAGER, USER, AccessDenied, AnalysisRepo, BotRepo, Database,
    DeveloperRepo, FailureRepo, FeedbackRepo, FingerprintRepo, PatternRepo,
    Principal, now, open_database,
)
from . import charts, mail, spend
from .schedules import (
    MIN_MINUTES, ScheduleRepo, ScheduleRunner, can_scan_this_host,
)
from .auth import (
    APPROVED, REQUESTED, REVOKED, SUSPENDED, Account, AccountRepo, AuthError,
    SESSION_COOKIE, SessionRepo, bootstrap_from_env, read_cookie, sign_cookie,
)
from .ingest import discover_upload, sniff_image
from .jobs import JobQueue
from .tree import UnsafePath, write_tree
from .seed import already_seeded, seed_if_asked, seed_wanted

HERE = Path(__file__).resolve().parent
SECRET_VAR = "EAGLE_EYES_SECRET_KEY"
BACKEND_VAR = "EAGLE_EYES_BACKEND"


# --------------------------------------------------------------------------
# Process state
# --------------------------------------------------------------------------

# How long a review waits for a decision before its uploaded tree is deleted.
# Long enough to read a table of two hundred rows and think about it; short
# enough that a forgotten tab does not keep someone's logs on the server.
REVIEW_TTL = timedelta(minutes=30)


@dataclass
class PendingReview:
    email: str
    root: Path
    candidates: list
    created_at: datetime


class AppState:
    """One database, one queue, one signing key, for the life of the process."""

    def __init__(self, db_path: Path | None = None,
                 env: dict[str, str] | None = None) -> None:
        self.env = dict(env if env is not None else os.environ)
        self.warning = runtime.ephemeral_storage_warning()
        if self.warning:
            print(f"  ! {self.warning}", flush=True)

        # PostgreSQL when DATABASE_URL is set, SQLite otherwise -- the choice
        # a platform makes for you by setting one variable. See
        # storage.open_database and docs/DATA_MODEL.md section 8.
        if not (self.env.get("DATABASE_URL") or "").strip() and db_path is None:
            base = runtime.data_dir()
            base.mkdir(parents=True, exist_ok=True)
            db_path = base / "eagle_eyes.db"
        self.db = open_database(db_path, self.env)
        self.secret = self._secret()
        self.jobs = JobQueue(workers=2)
        self.environment = current_environment()
        bootstrap_from_env(self.db, self.env)
        # The known-pattern library, into the table the engine reads on every
        # analysis. Idempotent, so it re-runs on every boot and a released
        # correction to a fix reaches the instance without a data migration --
        # while an operator's decision to deactivate a pattern survives it.
        PatternRepo(self.db, Principal.local()).sync()
        self.seed_summary: dict | None = None
        # Reviews awaiting a decision: token -> PendingReview. Held in memory
        # on purpose -- a review is a few minutes of someone's attention, not
        # state worth a table, and the temp tree it points at does not survive
        # a restart either.
        #
        # They EXPIRE. Someone who uploads a folder, reads the review table and
        # closes the tab used to leave the whole tree on disk for the life of
        # the process: client-derived content sitting on a server with nothing
        # scheduled to remove it, which is the thing
        # docs/PRODUCTION_MIGRATION.md 1.1 is about.
        self.pending: dict[str, PendingReview] = {}
        self._pending_lock = threading.Lock()

        self.schedules = ScheduleRunner(
            self.db, Principal(actor="scheduler", role=ADMIN),
            lambda schedule: _run_schedule(self, schedule))
        self._start_seeding()

    def hold_review(self, token: str, email: str, root: Path,
                    candidates: list) -> None:
        with self._pending_lock:
            self.pending[token] = PendingReview(
                email=email, root=root, candidates=candidates,
                created_at=datetime.now(timezone.utc))
        self.sweep_reviews()

    def peek_review(self, token: str, email: str) -> "PendingReview | None":
        """Look at a review without claiming it. Expiry still applies."""
        self.sweep_reviews()
        with self._pending_lock:
            held = self.pending.get(token)
            return held if held is not None and held.email == email else None

    def take_review(self, token: str, email: str) -> "PendingReview | None":
        """Claim a review, or None if it has expired or is not theirs."""
        self.sweep_reviews()
        with self._pending_lock:
            held = self.pending.get(token)
            if held is None or held.email != email:
                return None
            return self.pending.pop(token)

    def sweep_reviews(self) -> int:
        """Drop expired reviews and delete the trees they were holding."""
        cutoff = datetime.now(timezone.utc) - REVIEW_TTL
        with self._pending_lock:
            stale = [t for t, r in self.pending.items() if r.created_at < cutoff]
            dropped = [self.pending.pop(t) for t in stale]
        for review in dropped:
            shutil.rmtree(review.root, ignore_errors=True)
        return len(dropped)

    def _start_seeding(self) -> None:
        """Populate the demo on a worker, never on the boot path.

        Generating the estate and running the first analyses takes seconds.
        Doing it before the server binds means the platform's health check
        fails and the deploy is rolled back -- with the logs showing a
        successful seed, which is a confusing way to spend an afternoon.
        """
        if not seed_wanted(self.env) or already_seeded(self.db):
            return

        def run() -> None:
            self.seed_summary = seed_if_asked(self.db, self.engine, self.env)

        threading.Thread(target=run, name="eagle-eyes-seed", daemon=True).start()

    def _secret(self) -> bytes:
        """The session signing key.

        Generated when unset, and that is a real degradation rather than a
        convenience: every restart invalidates every cookie, so people are
        signed out at random. It is announced for exactly that reason -- a
        silent fallback here reads as a flaky login for weeks before anyone
        connects it to a missing variable.
        """
        raw = (self.env.get(SECRET_VAR) or "").strip()
        if len(raw) >= 32:
            return raw.encode("utf-8")
        if raw:
            print(f"  ! {SECRET_VAR} is shorter than 32 characters; ignoring it.",
                  flush=True)
        print(f"  ! {SECRET_VAR} is not set. Sessions are signed with a key "
              f"generated at start-up, so EVERY RESTART SIGNS EVERYONE OUT. "
              f"Set it to keep sessions across deploys.", flush=True)
        return secrets.token_bytes(32)

    def backend_name(self) -> str:
        return (self.env.get(BACKEND_VAR) or "mock").lower()

    def engine(self, choice: str = "smart") -> Engine:
        """A fresh Engine per analysis, with a guard reading committed spend.

        `choice` is a key of `model_gateway.SELECTABLE` and it replaces the DEEP
        model only -- triage still runs on Haiku, so noise is still dropped for
        a fraction of a cent and only the failures that survive reach the chosen
        model.

        It must stay callable with no arguments: the seeder is handed this bound
        method as a factory and calls it with none.

        The BACKEND is never chosen here. It comes from the environment, and the
        byok governance guard keys on the backend rather than on the model, so
        swapping a model within an approved backend correctly does not change
        where prompt content goes. `byok_approved_by` comes from server config
        and must never be reachable from a request -- a user-supplied approver
        would satisfy the guard and defeat it entirely.
        """
        name = self.backend_name()
        backend = create_backend({"backend": name,
                                  "region": self.env.get("AWS_REGION", ""),
                                  "byok_approved_by": self.env.get(
                                      "EAGLE_EYES_BYOK_APPROVED_BY", "")},
                                 self.environment)
        models = dict(models_for(name))
        role = SELECTABLE.get(choice, SELECTABLE["smart"])[0]
        if role:
            # A MERGE, never a replacement: `Engine` reads models["triage"] and
            # models["deep"] with .get(..., ""), so a partial dict would send an
            # empty model id to the provider.
            models["deep"] = models[role]
        return Engine(backend, models,
                      budget=spend.guard_for(self.db, self.env),
                      screenshot_mode=self.screenshot_mode(),
                      library=PatternRepo(self.db, Principal.local()).library())

    def screenshot_mode(self) -> int:
        raw = (self.env.get("EAGLE_EYES_SCREENSHOT_MODE") or "0").strip()
        try:
            mode = int(raw)
        except ValueError:
            return 0
        # An unknown mode falls back to 0 -- the one that sends nothing. A
        # typo must never widen what leaves the estate.
        return mode if mode in SCREENSHOT_MODES else 0


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

def get_state(request: Request) -> AppState:
    return request.app.state.ee


def current_account(request: Request) -> Account | None:
    """The signed-in account, or None. Never raises -- public pages use it too."""
    state: AppState = request.app.state.ee
    raw = request.cookies.get(SESSION_COOKIE, "")
    sid = read_cookie(raw, state.secret)
    if not sid:
        return None
    anon = Principal(actor="anonymous", role=USER)
    account_id = SessionRepo(state.db, anon).lookup(sid)
    if account_id is None:
        return None
    return AccountRepo(state.db, anon).by_id(account_id)


def require_account(request: Request) -> Account:
    account = current_account(request)
    if account is None:
        raise HTTPException(status_code=401, detail="sign in first")
    return account


def require_approved(request: Request) -> Account:
    """An account an admin has granted a role to. Signing in is not enough."""
    account = require_account(request)
    if not account.is_approved:
        raise HTTPException(
            status_code=403,
            detail=f"this account is '{account.status}' and has not been approved")
    return account


def require_admin(request: Request) -> Account:
    account = require_approved(request)
    if account.role != ADMIN:
        raise HTTPException(status_code=403, detail="administrators only")
    return account


# --------------------------------------------------------------------------
# The app
# --------------------------------------------------------------------------

def create_app(db_path: Path | None = None,
               env: dict[str, str] | None = None) -> FastAPI:
    app = FastAPI(title="Eagle Eyes", docs_url=None, redoc_url=None,
                  openapi_url=None)   # the schema lists every route
    app.state.ee = AppState(db_path, env)

    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["money"] = lambda v: f"${(v or 0):,.4f}"
    templates.env.filters["pct"] = lambda v: f"{(v or 0) * 100:.1f}%"
    static = HERE / "static"
    static.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static)), name="static")

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        account = current_account(request)
        state: AppState = request.app.state.ee
        return templates.TemplateResponse(request, name, {
            "account": account,
            "viz_css": charts.palette_css(),
            "tab": ctx.pop("tab", ""),
            "backend": state.backend_name(),
            "environment": state.environment,
            "kill_switch": spend.kill_switch_on(state.env),
            "warning": state.warning,
            **ctx,
        })

    # ---------------------------------------------------------------- public

    @app.get("/healthz")
    def healthz(state: AppState = Depends(get_state)) -> JSONResponse:
        """Liveness for the platform. Deliberately says nothing about data."""
        try:
            state.db.conn.execute("SELECT 1").fetchone()
        except Exception:
            return JSONResponse({"status": "degraded"}, status_code=503)
        return JSONResponse({"status": "ok"})

    @app.get("/", response_class=HTMLResponse)
    def landing(request: Request):
        return page(request, "landing.html")

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = "/app"):
        if current_account(request):
            return RedirectResponse("/app", status_code=303)
        return page(request, "login.html", next=next)

    @app.post("/login")
    def login(request: Request, email: str = Form(...), password: str = Form(...),
              state: AppState = Depends(get_state)):
        anon = Principal(actor="anonymous", role=USER)
        try:
            account = AccountRepo(state.db, anon).authenticate(email, password)
        except AuthError as exc:
            return page(request, "login.html", error=str(exc), next="/app")
        sid = SessionRepo(state.db, anon).create(
            account.id, user_agent=request.headers.get("user-agent", ""))
        resp = RedirectResponse("/app", status_code=303)
        _set_session(resp, sign_cookie(sid, state.secret), request)
        return resp

    @app.get("/register", response_class=HTMLResponse)
    def register_form(request: Request):
        return page(request, "register.html")

    @app.post("/register")
    def register(request: Request, email: str = Form(...),
                 password: str = Form(...), display_name: str = Form(""),
                 state: AppState = Depends(get_state)):
        anon = Principal(actor="anonymous", role=USER)
        try:
            AccountRepo(state.db, anon).register(email, password, display_name)
        except AuthError as exc:
            return page(request, "register.html", error=str(exc))
        return page(request, "registered.html")

    @app.post("/logout")
    def logout(request: Request, state: AppState = Depends(get_state)):
        raw = request.cookies.get(SESSION_COOKIE, "")
        sid = read_cookie(raw, state.secret)
        if sid:
            SessionRepo(state.db, Principal(actor="anonymous", role=USER)).revoke(sid)
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ------------------------------------------------------------------ app

    @app.get("/app", response_class=HTMLResponse)
    def analyse_tab(request: Request, error: str = "",
                    account: Account = Depends(require_account),
                    state: AppState = Depends(get_state)):
        if not account.is_approved:
            return page(request, "pending.html")
        p = account.principal()
        failures = FailureRepo(state.db, p)
        scannable, reason = can_scan_this_host()
        return page(request, "analyse.html", tab="analyse", error=error,
                    stats=failures.stats(),
                    failures=failures.recent(limit=20),
                    schedules=ScheduleRepo(state.db, p).list(),
                    can_scan=scannable, scan_reason=reason)

    @app.post("/app/discover", response_class=HTMLResponse)
    async def discover_folder(request: Request,
                              account: Account = Depends(require_approved),
                              state: AppState = Depends(get_state)):
        """Rebuild the uploaded tree and run the scanner's own discovery over it."""
        form = await request.form()
        uploads = form.getlist("files")
        paths = [str(x) for x in form.getlist("paths")]
        if not uploads:
            return page(request, "analyse.html", tab="analyse",
                        error="No files were received.",
                        stats=FailureRepo(state.db, account.principal()).stats(),
                        failures=[], schedules=[], can_scan=False, scan_reason="")

        items = []
        for i, upload in enumerate(uploads):
            name = paths[i] if i < len(paths) else (upload.filename or "")
            items.append((name, await upload.read()))

        root = Path(tempfile.mkdtemp(prefix="eagle-eyes-upload-"))
        try:
            rebuilt = write_tree(root / "tree", items)
        except UnsafePath as exc:
            shutil.rmtree(root, ignore_errors=True)
            return _analyse_error(request, page, state, account, str(exc))

        candidates, share, code = discover_upload(rebuilt.root)
        if not candidates:
            shutil.rmtree(root, ignore_errors=True)
            return _analyse_error(
                request, page, state, account,
                "Nothing in that folder looked like a bot failure. Discovery "
                "expects a tree shaped like data/<service line>/<bot>/<year>/"
                "<month>/<day>/logs/, and reads the service line and bot number "
                "from those directory names rather than from the log text.")

        token = secrets.token_hex(16)
        state.hold_review(token, account.email, root, candidates)

        seen, rows = set(), []
        for c in candidates:
            fp = (c.exception_type, c.message[:120])
            rows.append({
                "service_line": c.location.service_line,
                "bot_number": c.location.bot_number, "date": c.location.date,
                "exception_type": c.exception_type, "message": c.message,
                "inputs": c.inputs, "pairing_method": c.pairing_method,
                "pairing_note": c.pairing_note,
                "occurred_at": (c.occurred_at.isoformat(timespec="seconds")
                                if c.occurred_at else ""),
                "first_of_fingerprint": fp not in seen})
            seen.add(fp)

        return page(request, "review.html", tab="analyse", token=token,
                    candidates=rows, distinct=len(seen),
                    bots=len({(r["service_line"], r["bot_number"]) for r in rows}),
                    paired=sum(1 for r in rows if r["pairing_method"] != "none"),
                    refused=sum(1 for r in rows if r["pairing_method"] == "none"),
                    skipped=rebuilt.skipped,
                    model_options=_model_options(state))

    @app.post("/app/analyse")
    def analyse_picked(request: Request, token: str = Form(...),
                       pick: list[int] = Form(default=[]),
                       model: str = Form(default="smart"),
                       account: Account = Depends(require_approved),
                       state: AppState = Depends(get_state)):
        # PEEK for the guards, TAKE only once committed. Claiming the review
        # first meant a kill switch, an hourly cap or a forgotten checkbox
        # deleted the uploaded tree -- and a 251-file folder had to be dropped
        # again because someone did not tick a box.
        held = state.peek_review(token, account.email)
        if held is None:
            raise HTTPException(status_code=404, detail="that review has expired")

        if spend.kill_switch_on(state.env):
            return _analyse_error(request, page, state, account,
                                  "Model calls are switched off by the kill "
                                  "switch. Nothing was sent or charged, and "
                                  "your upload is still here.")
        cap = spend.hourly_analysis_cap(state.env)
        used = spend.analyses_this_hour(state.db, account.email)
        if used >= cap:
            return _analyse_error(
                request, page, state, account,
                f"You have run {used} analyses in the last hour, which is the "
                f"limit. It exists so one person cannot exhaust the budget for "
                f"everyone. Your upload is still here.")

        # Validated against the allowlist rather than passed through. A forged
        # value must never reach a provider as a model id, and an unrecognised
        # one falls back to smart routing rather than to an empty string.
        choice = model if model in SELECTABLE else "smart"

        chosen = [held.candidates[i] for i in pick if 0 <= i < len(held.candidates)]
        if not chosen:
            return _analyse_error(request, page, state, account,
                                  "Nothing was ticked, so nothing was sent. "
                                  "Your upload is still here.")

        claimed = state.take_review(token, account.email)
        if claimed is None:                       # expired between peek and take
            raise HTTPException(status_code=404, detail="that review has expired")
        job = state.jobs.submit(
            "scan", account.email,
            lambda: _analyse_candidates(state, account, chosen, claimed.root,
                                        model_choice=choice))
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    # ------------------------------------------------------------ analytics

    @app.get("/analytics", response_class=HTMLResponse)
    def analytics_tab(request: Request,
                      account: Account = Depends(require_approved),
                      state: AppState = Depends(get_state)):
        p = account.principal()
        failures = FailureRepo(state.db, p)
        stats = failures.stats()
        top = failures.top_fingerprints(8)
        for row in top:
            # Show the file, not the whole stored path. The stored value is a
            # share path in a real deployment and a temp directory for seeded
            # data; neither is worth a table column, and the second leaks where
            # the seeder happened to write.
            row["where"] = Path(row["code_location"]).name or "—"
        feedback = FeedbackRepo(state.db, p).tally()
        return page(
            request, "analytics.html", tab="analytics", stats=stats, top=top,
            saved=_saving(stats),
            trend_days=30,
            trend_svg=charts.trend(failures.daily_counts(30)),
            top_svg=charts.bars([(t["exception_type"].rsplit(".", 1)[-1], t["n"])
                                 for t in top]),
            confidence_svg=charts.bars(failures.confidence_buckets(), ordinal=True),
            path_svg=charts.stacked(failures.path_breakdown()),
            feedback=feedback,
            feedback_svg=charts.stacked(sorted(feedback.items())))

    @app.get("/team", response_class=HTMLResponse)
    def team_tab(request: Request,
                 account: Account = Depends(require_approved),
                 state: AppState = Depends(get_state)):
        if account.role not in (MANAGER, ADMIN):
            raise HTTPException(status_code=403,
                                detail="the team view is for managers and administrators")
        p = account.principal()
        failures = FailureRepo(state.db, p)
        stats = failures.stats()
        lines = failures.by_service_line()
        return page(
            request, "team.html", tab="team", stats=stats, lines=lines,
            saved=_saving(stats), bots=failures.by_bot(14),
            lines_svg=charts.bars([(d["service_line"], d["n"]) for d in lines]),
            spend_svg=charts.bars(
                [(d["service_line"], float(d["cost"] or 0)) for d in lines],
                fmt=charts.money))

    # ------------------------------------------------------------ schedules

    @app.post("/schedules")
    def add_schedule(request: Request, name: str = Form(...),
                     target_path: str = Form(...), share_root: str = Form(...),
                     code_root: str = Form(""), every_minutes: int = Form(60),
                     account: Account = Depends(require_approved),
                     state: AppState = Depends(get_state)):
        try:
            ScheduleRepo(state.db, account.principal()).add(
                account.id, name=name, target_path=target_path,
                share_root=share_root, code_root=code_root or share_root,
                every_minutes=every_minutes)
        except (ValueError, *storage.INTEGRITY_ERRORS) as exc:
            return RedirectResponse(f"/app?error={_q(str(exc))}", status_code=303)
        return RedirectResponse("/app", status_code=303)

    @app.post("/schedules/{schedule_id}/toggle")
    def toggle_schedule(schedule_id: int,
                        account: Account = Depends(require_approved),
                        state: AppState = Depends(get_state)):
        repo = ScheduleRepo(state.db, account.principal())
        try:
            repo.set_enabled(schedule_id, not repo.get(schedule_id).enabled)
        except AccessDenied:
            raise HTTPException(status_code=404, detail="no such schedule")
        return RedirectResponse("/app", status_code=303)

    @app.post("/schedules/{schedule_id}/delete")
    def delete_schedule(schedule_id: int,
                        account: Account = Depends(require_approved),
                        state: AppState = Depends(get_state)):
        try:
            ScheduleRepo(state.db, account.principal()).delete(schedule_id)
        except AccessDenied:
            raise HTTPException(status_code=404, detail="no such schedule")
        return RedirectResponse("/app", status_code=303)

    # What the mail route's `?mail=` outcomes mean on the page. Headline, the
    # tone class, and whether a detail line is worth showing. Suppressed is not
    # a failure -- it is the product doing the thing it exists to do -- so it
    # reads as information rather than as an error.
    MAIL_OUTCOMES = {
        "sent": ("Sent to the developer who owns this bot.", "good", True),
        "dry_run": ("Rendered, not sent — no SMTP relay is configured.",
                    "good", True),
        "suppressed": ("Not sent, on purpose.", "warn", True),
        "no_analysis": ("Nothing to send: this failure has no diagnosis yet.",
                        "warn", False),
        "no_owner": ("Nobody owns this bot, so there is no address to send to. "
                     "Assign an owner on the Team tab.", "warn", False),
        "failed": ("The relay refused the message. Nothing was sent and the "
                   "attempt is in the audit log.", "bad", False),
    }

    @app.get("/failures/{failure_id}", response_class=HTMLResponse)
    def failure(request: Request, failure_id: int,
                account: Account = Depends(require_approved),
                state: AppState = Depends(get_state)):
        p = account.principal()
        try:
            row = FailureRepo(state.db, p).get(failure_id)
        except AccessDenied:
            # The same answer whether it does not exist or is not theirs: a
            # distinguishable 404 enumerates which ids are real.
            raise HTTPException(status_code=404, detail="no such failure")
        outcome = request.query_params.get("mail", "")
        headline, tone, show_why = MAIL_OUTCOMES.get(outcome, ("", "", False))
        return page(request, "failure.html", row=row,
                    report=render(_report_input(row, state.db)),
                    mail_live=mail.configured(state.env),
                    mail_outcome=outcome if headline else "",
                    mail_headline=headline, mail_tone=tone,
                    mail_detail=(request.query_params.get("why", "")[:200]
                                 if show_why else ""))

    @app.post("/failures/{failure_id}/feedback")
    def feedback(request: Request, failure_id: int, verdict: str = Form(...),
                 comment: str = Form(""),
                 account: Account = Depends(require_approved),
                 state: AppState = Depends(get_state)):
        p = account.principal()
        try:
            row = FailureRepo(state.db, p).get(failure_id)
        except AccessDenied:
            raise HTTPException(status_code=404, detail="no such failure")
        if row["analysis_id"] is None:
            raise HTTPException(status_code=400, detail="nothing to give feedback on")
        dev_id = DeveloperRepo(state.db, p).ensure(account.email,
                                                   display_name=account.display_name)
        FeedbackRepo(state.db, p).add(row["analysis_id"], failure_id, dev_id,
                                      verdict, comment[:1000])
        return RedirectResponse(f"/failures/{failure_id}", status_code=303)

    @app.post("/failures/{failure_id}/email")
    def email_diagnosis(request: Request, failure_id: int,
                        account: Account = Depends(require_approved),
                        state: AppState = Depends(get_state)):
        """Mail the diagnosis to the developer who owns the bot.

        Three refusals, all of them deliberate:

          * No analysis -- there is nothing to send, and a mail saying so is
            noise in the inbox the suppression rules exist to protect.
          * No owner on the bot -- the recipient is never guessed and never
            defaulted to the person who clicked. A diagnosis in the wrong inbox
            is a disclosure as well as a waste.
          * Suppressed -- the mail is not sent and the reason is shown. That is
            the product working, not failing, so it is reported as an outcome
            rather than as an error.

        The recipient is the BOT OWNER, not the signed-in user, and the route is
        still behind `FailureRepo.get`, so nobody can use it to discover whether
        a failure they cannot see exists.
        """
        p = account.principal()
        try:
            row = FailureRepo(state.db, p).get(failure_id)
        except AccessDenied:
            raise HTTPException(status_code=404, detail="no such failure")
        if row is None:
            raise HTTPException(status_code=404, detail="no such failure")

        repo = FailureRepo(state.db, p)
        if row["analysis_id"] is None:
            repo._audit("notify", "failure", failure_id, "deny")
            return RedirectResponse(f"/failures/{failure_id}?mail=no_analysis",
                                    status_code=303)

        to = DeveloperRepo(state.db, p).email_of(row["owner_dev_id"])
        if not to:
            repo._audit("notify", "failure", failure_id, "deny")
            return RedirectResponse(f"/failures/{failure_id}?mail=no_owner",
                                    status_code=303)

        notifier = mail.notifier_for(state.db, p, state.env)
        base = mail.base_url(state.env)
        url = f"{base}/failures/{failure_id}" if base else ""
        fingerprint_hash = state.db.conn.execute(
            "SELECT hash FROM fingerprint WHERE id=?",
            (row["fingerprint_id"],)).fetchone()["hash"]

        note = compose(
            to=to, bot_label=f"{row['service_line']}/{row['bot_number']}",
            exception_type=row["exception_type"] or "",
            root_cause=row["root_cause"] or "",
            suggested_fix=row["suggested_fix"] or "",
            confidence=row["confidence"] or 0.0,
            fingerprint=fingerprint_hash, report_path=url)
        note.html = compose_html(
            bot_label=f"{row['service_line']}/{row['bot_number']}",
            exception_type=row["exception_type"] or "",
            root_cause=row["root_cause"] or "",
            suggested_fix=row["suggested_fix"] or "",
            confidence=row["confidence"] or 0.0,
            severity=row["severity"] or "", failure_type=row["failure_type"] or "",
            affected_function=row["affected_function"] or "",
            recommendations=row["recommendations"] or "",
            report_url=url, path=row["path"] or "")

        try:
            decision = notifier.send(
                note, category="novel", confidence=row["confidence"] or 0.0)
        except Exception as exc:                  # relay down, auth refused, DNS
            # Never a 500. The relay is outside this process and a page that
            # breaks when it is down tells the user nothing they can act on.
            repo._audit("notify", "failure", failure_id, "deny")
            print(f"  ! mail to {to} failed: {exc}", flush=True)
            return RedirectResponse(f"/failures/{failure_id}?mail=failed",
                                    status_code=303)

        repo._audit("notify", "failure", failure_id,
                    "allow" if decision.send else "deny")
        outcome = ("sent" if mail.configured(state.env) else "dry_run") \
            if decision.send else "suppressed"
        return RedirectResponse(
            f"/failures/{failure_id}?mail={outcome}&why={_q(decision.reason)}",
            status_code=303)

    # --------------------------------------------------------------- upload

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str,
                 account: Account = Depends(require_approved),
                 state: AppState = Depends(get_state)):
        job = state.jobs.get(job_id)
        if job is None or job.actor != account.email:
            raise HTTPException(status_code=404, detail="no such job")
        return page(request, "job.html", job=job)

    @app.get("/jobs/{job_id}/status")
    def job_status(request: Request, job_id: str,
                   account: Account = Depends(require_approved),
                   state: AppState = Depends(get_state)) -> JSONResponse:
        job = state.jobs.get(job_id)
        if job is None or job.actor != account.email:
            raise HTTPException(status_code=404, detail="no such job")
        return JSONResponse(job.as_dict())

    # ---------------------------------------------------------------- admin

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request, error: str = "",
              account: Account = Depends(require_admin),
              state: AppState = Depends(get_state)):
        p = account.principal()
        repo = AccountRepo(state.db, p)
        audit = state.db.conn.execute(
            "SELECT * FROM audit_event ORDER BY occurred_at DESC LIMIT 60").fetchall()
        teams = [r["name"] for r in state.db.conn.execute(
            "SELECT DISTINCT service_line AS name FROM bot ORDER BY 1")]
        return page(request, "admin.html", accounts=repo.list_all(), error=error,
                    audit=audit, teams=teams,
                    spend_total=spend.DatabaseLedger(state.db).spent_total(),
                    spend_day=spend.DatabaseLedger(state.db).spent_since(24))

    @app.post("/admin/approve")
    def admin_approve(request: Request, account_id: int = Form(...),
                      role: str = Form(...), scope: list[str] = Form(default=[]),
                      account: Account = Depends(require_admin),
                      state: AppState = Depends(get_state)):
        repo = AccountRepo(state.db, account.principal())
        try:
            repo.approve(account_id, role=role, scope=frozenset(scope))
            repo.link_developer(account_id)
        except (ValueError, LookupError) as exc:
            return RedirectResponse(f"/admin?error={_q(str(exc))}", status_code=303)
        return RedirectResponse("/admin", status_code=303)

    @app.post("/admin/status")
    def admin_status(request: Request, account_id: int = Form(...),
                     status: str = Form(...),
                     account: Account = Depends(require_admin),
                     state: AppState = Depends(get_state)):
        repo = AccountRepo(state.db, account.principal())
        try:
            repo.set_status(account_id, status)
        except (ValueError, LookupError) as exc:
            return RedirectResponse(f"/admin?error={_q(str(exc))}", status_code=303)
        return RedirectResponse("/admin", status_code=303)

    # ------------------------------------------------------------- handlers

    @app.exception_handler(401)
    def unauthorised(request: Request, exc: HTTPException):
        return RedirectResponse(f"/login?next={_q(request.url.path)}", status_code=303)

    @app.exception_handler(403)
    def forbidden(request: Request, exc: HTTPException):
        return templates.TemplateResponse(
            request, "denied.html",
            {"account": current_account(request), "detail": exc.detail},
            status_code=403)

    @app.exception_handler(404)
    def not_found(request: Request, exc: HTTPException):
        return templates.TemplateResponse(
            request, "denied.html",
            {"account": current_account(request),
             "detail": "That page does not exist, or it is not yours to see. "
                       "Those two answers are deliberately the same one."},
            status_code=404)

    @app.on_event("shutdown")
    def shutdown() -> None:
        app.state.ee.jobs.stop()
        app.state.ee.schedules.stop()
        app.state.ee.db.close()

    return app


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _model_options(state: AppState) -> list[dict]:
    """The model dropdown, with what each choice is projected to cost.

    The figure is the projection the budget guard will actually check, not a
    marketing number -- so if a cap would refuse the choice, the page says so
    before the click rather than after it. `smart` is quoted as triage plus
    deep, because that is what it spends.
    """
    models = models_for(state.backend_name())
    cap = spend.guard_for(state.db, state.env).single_call_usd
    out = []
    for key, (role, label) in SELECTABLE.items():
        try:
            if key == "smart":
                cost = (project(models["triage"], "triage")
                        + project(models["deep"], "deep"))
                worst = project(models["deep"], "deep")
            else:
                cost = project(models["triage"], "triage") + project(models[role], "deep")
                worst = max(project(models["triage"], "triage"),
                            project(models[role], "deep"))
        except BackendError as exc:
            out.append({"key": key, "label": label, "cost": None,
                        "ok": False, "why": str(exc)})
            continue
        out.append({"key": key, "label": label, "cost": cost, "ok": worst <= cap,
                    "why": (f"the per-call cap is ${cap:.2f} and this projects "
                            f"at ${worst:.4f}") if worst > cap else ""})
    return out


def _saving(stats: dict) -> float:
    """What deduplication avoided, at the average cost of the calls made.

    Stated as an estimate rather than a measurement, because the repeats were
    never analysed -- there is no invoice for work that did not happen. The
    average is the only honest basis available.
    """
    analysed = stats["failures"] - stats["deduped"]
    if analysed <= 0 or not stats["spend_usd"]:
        return 0.0
    return (stats["spend_usd"] / analysed) * stats["deduped"]


def _analyse_error(request: Request, page, state: AppState,
                   account: Account, message: str):
    """Re-render the Analyse tab with a reason, rather than a bare error page."""
    p = account.principal()
    failures = FailureRepo(state.db, p)
    scannable, reason = can_scan_this_host()
    return page(request, "analyse.html", tab="analyse", error=message,
                stats=failures.stats(), failures=failures.recent(limit=20),
                schedules=ScheduleRepo(state.db, p).list(),
                can_scan=scannable, scan_reason=reason)


def _analyse_candidates(state: AppState, account: Account,
                        candidates: list, root: Path,
                        model_choice: str = "smart") -> dict:
    """Analyse chosen candidates, then delete the uploaded tree.

    The tree is removed in a finally: it holds whatever the user dropped, and
    an upload directory that outlives the request is a copy of client-derived
    content sitting on a server. docs/PRODUCTION_MIGRATION.md 1.1 is about
    exactly this, and the demo should not quietly do the thing the guide warns
    about.
    """
    from ..discovery import read_text

    p = account.principal()
    engine = state.engine(model_choice)
    bots, fps = BotRepo(state.db, p), FingerprintRepo(state.db, p)
    seen: dict[str, int] = {}
    made = deduped = 0
    first_id = None

    try:
        for c in candidates:
            log_text = read_text(c.log_path)
            code_text = read_text(c.code_path) if c.code_path else ""
            bot_id = bots.upsert(c.location.service_line, c.location.bot_number,
                                 str(c.code_path) if c.code_path else None)
            bots.set_owner(bot_id, account.email)
            bots.set_team(bot_id, c.location.service_line)

            # The screenshot is read ONLY when the policy permits it. Mode 0
            # never opens the file -- the report links to where it sits and the
            # reader's own permissions decide. This used to pass image=None
            # unconditionally, so mode 3 silently did nothing on the main path:
            # the same defect as a mode that claims to crop and does not.
            image = None
            if state.screenshot_mode() and c.screenshot_path and c.send_screenshot:
                try:
                    raw = Path(c.screenshot_path).read_bytes()
                except OSError:
                    raw = b""
                # Checked from the file's own leading bytes before anything is
                # sent. The paired file came out of an upload and is trusted
                # only as far as its name -- forwarding arbitrary bytes to a
                # provider as an image is not something to do on the strength
                # of a .png extension.
                image = raw if raw and sniff_image(raw) else None

            analysis = engine.analyse(
                log_text=log_text, code_text=code_text,
                code_path=str(c.code_path or ""),
                code_mtime=(c.code_mtime.isoformat(timespec="seconds")
                            if c.code_mtime else None),
                code_stale=c.code_possibly_stale,
                bot_label=c.location.label,
                code_location=str(c.code_path or ""),
                image=image)
            if not analysis.fingerprint:
                continue

            fp_id = fps.touch(analysis.fingerprint, 1,
                              c.exception_type or "Unknown", c.message or "",
                              str(c.code_path or ""))
            known = analysis.fingerprint in seen
            if known:
                analysis_id = seen[analysis.fingerprint]
                deduped += 1
            else:
                cost = sum(u.cost_usd for u in analysis.usages if u.priced)
                analysis_id = AnalysisRepo(state.db, p).add(
                    fp_id, path=analysis.path, root_cause=analysis.root_cause,
                    suggested_fix=analysis.suggested_fix,
                    confidence=analysis.confidence,
                    model_id=(analysis.usages[-1].model if analysis.usages else ""),
                    inputs_used=tuple(analysis.inputs_used),
                    tokens_in=sum(u.input_tokens for u in analysis.usages),
                    tokens_out=sum(u.output_tokens for u in analysis.usages),
                    cost_usd=cost,
                    latency_ms=sum(u.latency_ms for u in analysis.usages),
                    cache_read_tokens=sum(u.cache_read_tokens for u in analysis.usages),
                    image_tokens=sum(u.image_tokens for u in analysis.usages),
                    category=analysis.category,
                    failure_type=analysis.failure_type, severity=analysis.severity,
                    affected_function=analysis.affected_function,
                    recommendations=analysis.recommendations)
                seen[analysis.fingerprint] = analysis_id
                made += 1

            failure_id = FailureRepo(state.db, p).add(
                bot_id=bot_id, fingerprint_id=fp_id, analysis_id=analysis_id,
                occurred_at=(c.occurred_at or datetime.now(timezone.utc)).replace(
                    tzinfo=None).isoformat(timespec="seconds"),
                log_path=f"upload://{account.email}/{c.log_path.name}/{now()}",
                screenshot_path=str(c.screenshot_path) if c.screenshot_path else None,
                code_path=str(c.code_path) if c.code_path else None,
                code_possibly_stale=c.code_possibly_stale,
                pairing_method=c.pairing_method,
                log_sanitized=log_text[:20000],
                was_deduped=known, correlation_id=secrets.token_hex(8),
                status="deduped" if known else "analyzed")
            first_id = first_id or failure_id
            _record_analysis(state.db, p, failure_id)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    return {"failure_id": first_id, "analysed": made, "deduped": deduped,
            "candidates": len(candidates)}


def _run_schedule(state: AppState, schedule) -> tuple[int, int]:
    """One scheduled scan. Returns (found, analysed)."""
    from ..discovery import discover

    account = AccountRepo(state.db, Principal(actor="scheduler", role=ADMIN)).by_id(
        schedule.account_id)
    if account is None or not account.is_approved:
        return 0, 0
    candidates = discover(Path(schedule.target_path), Path(schedule.share_root),
                          Path(schedule.code_root))
    if not candidates:
        return 0, 0
    result = _analyse_candidates(state, account, candidates,
                                 Path(tempfile.mkdtemp(prefix="eagle-eyes-noop-")))
    return len(candidates), result["analysed"]


async def _read(upload: UploadFile | None, state: AppState) -> bytes:
    if upload is None or not upload.filename:
        return b""
    return await upload.read()


def _set_session(resp, value: str, request: Request) -> None:
    """Secure only over HTTPS, so local http development still signs in.

    `Secure` on a cookie served over http means the browser drops it and the
    login silently does nothing, which costs an hour to diagnose every time.
    """
    secure = request.url.scheme == "https" or bool(
        request.headers.get("x-forwarded-proto", "").startswith("https"))
    resp.set_cookie(SESSION_COOKIE, value, httponly=True, samesite="lax",
                    secure=secure, path="/", max_age=12 * 3600)


def _q(text: str) -> str:
    from urllib.parse import quote
    return quote(text, safe="")


def _report_input(row, db=None) -> ReportInput:
    """The stored row, as the report renderer wants it.

    `exception_type` and `inputs_used` used to be hard-coded empty here, so
    every hosted report showed a blank Exception row and claimed "log only"
    whatever it had actually read -- on a page whose whole job is to say what
    the diagnosis was based on. Both are stored; neither was being selected.
    """
    decode = db.decode_list if db is not None else Database.decode_list
    return ReportInput(
        bot_label=f"{row['service_line']}/{row['bot_number']}",
        occurred_at=row["occurred_at"],
        exception_type=row["exception_type"] or "",
        root_cause=row["root_cause"] or "No analysis is attached to this failure.",
        suggested_fix=row["suggested_fix"] or "",
        confidence=row["confidence"] or 0.0,
        path=row["path"] or "skipped",
        inputs_used=decode(row["inputs_used"]),
        log_path=row["log_path"],
        screenshot_path=row["screenshot_path"] or "",
        pairing_method=row["pairing_method"] or "none",
        code_path=row["code_path"] or "",
        code_possibly_stale=bool(row["code_possibly_stale"]),
        model_id=row["model_id"] or "",
        log_excerpt=(row["log_sanitized"] or "")[:4000],
    )




def _record_analysis(db: Database, p: Principal, failure_id: int | None) -> None:
    """Record that this principal caused an analysis.

    The per-person hourly cap counts these rows, so this is not bookkeeping --
    without it the cap counts nothing and silently does not apply.
    """
    db.conn.execute(
        "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
        " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
        (p.actor, p.role, "analyse", "failure", str(failure_id or "-"),
         "allow", now()))
