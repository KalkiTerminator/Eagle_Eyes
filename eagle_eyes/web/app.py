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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import runtime
from ..analysis import SCREENSHOT_MODES, Engine
from ..model_gateway import (
    BackendError, MODELS, create_backend, current_environment, models_for,
)
from ..report import ReportInput, render
from ..storage import (
    ADMIN, MANAGER, USER, AccessDenied, AnalysisRepo, BotRepo, Database,
    DeveloperRepo, FailureRepo, FeedbackRepo, FingerprintRepo, Principal,
    now, open_database,
)
from . import spend
from .auth import (
    APPROVED, REQUESTED, REVOKED, SUSPENDED, Account, AccountRepo, AuthError,
    SESSION_COOKIE, SessionRepo, bootstrap_from_env, read_cookie, sign_cookie,
)
from .ingest import IngestError, build_upload
from .jobs import JobQueue

HERE = Path(__file__).resolve().parent
SECRET_VAR = "EAGLE_EYES_SECRET_KEY"
BACKEND_VAR = "EAGLE_EYES_BACKEND"


# --------------------------------------------------------------------------
# Process state
# --------------------------------------------------------------------------

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

    def engine(self) -> Engine:
        """A fresh Engine per analysis, with a guard reading committed spend."""
        name = self.backend_name()
        backend = create_backend({"backend": name,
                                  "region": self.env.get("AWS_REGION", ""),
                                  "byok_approved_by": self.env.get(
                                      "EAGLE_EYES_BYOK_APPROVED_BY", "")},
                                 self.environment)
        return Engine(backend, models_for(name),
                      budget=spend.guard_for(self.db, self.env),
                      screenshot_mode=self._screenshot_mode())

    def _screenshot_mode(self) -> int:
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
    def home(request: Request, account: Account = Depends(require_account),
             state: AppState = Depends(get_state)):
        if not account.is_approved:
            return page(request, "pending.html")
        p = account.principal()
        failures = FailureRepo(state.db, p)
        return page(request, "home.html",
                    stats=failures.stats(),
                    failures=failures.recent(limit=25),
                    jobs=[j.as_dict() for j in state.jobs.for_actor(account.email)
                          if not j.done or (datetime.now(timezone.utc)
                                            - j.created_at).seconds < 600])

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
        return page(request, "failure.html", row=row,
                    report=render(_report_input(row)))

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

    # --------------------------------------------------------------- upload

    @app.get("/submit", response_class=HTMLResponse)
    def submit_form(request: Request,
                    account: Account = Depends(require_approved)):
        return page(request, "submit.html")

    @app.post("/submit")
    async def submit(request: Request,
                     service_line: str = Form(...), bot_number: str = Form(...),
                     log: UploadFile = None, code: UploadFile = None,
                     screenshot: UploadFile = None,
                     account: Account = Depends(require_approved),
                     state: AppState = Depends(get_state)):
        p = account.principal()

        if spend.kill_switch_on(state.env):
            # Checked HERE, before anything else, and not left to the budget
            # guard. Engine.analyse deliberately never raises on model trouble
            # -- it degrades to a zero-confidence fallback so one bad call
            # cannot lose a batch. That is right for a provider hiccup and
            # wrong for a kill switch: the operator would see a page full of
            # "analysis did not complete" and no statement that they had turned
            # it off themselves.
            return page(request, "submit.html",
                        error="Model calls are switched off by the kill switch "
                              "(EAGLE_EYES_DISABLE_MODEL). Nothing was sent and "
                              "nothing was charged. Clear the variable to "
                              "re-enable analysis.")

        cap = spend.hourly_analysis_cap(state.env)
        used = spend.analyses_this_hour(state.db, account.email)
        if used >= cap:
            return page(request, "submit.html",
                        error=f"You have run {used} analyses in the last hour, "
                              f"which is the limit. This exists so one person "
                              f"cannot exhaust the budget for everyone.")

        try:
            upload = build_upload(
                service_line=service_line, bot_number=bot_number,
                log_bytes=await _read(log, state),
                code_bytes=await _read(code, state),
                code_name=(code.filename if code else "") or "",
                image_bytes=await _read(screenshot, state),
                submitted_by=account.email)
        except IngestError as exc:
            return page(request, "submit.html", error=str(exc))

        job = state.jobs.submit(
            "analyse", account.email,
            lambda: _analyse_upload(state, p, upload, account))
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

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
        app.state.ee.db.close()

    return app


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

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


def _report_input(row) -> ReportInput:
    import json
    inputs: tuple[str, ...] = ()
    return ReportInput(
        bot_label=f"{row['service_line']}/{row['bot_number']}",
        occurred_at=row["occurred_at"],
        exception_type="",
        root_cause=row["root_cause"] or "No analysis is attached to this failure.",
        suggested_fix=row["suggested_fix"] or "",
        confidence=row["confidence"] or 0.0,
        path=row["path"] or "skipped",
        inputs_used=inputs,
        log_path=row["log_path"],
        screenshot_path=row["screenshot_path"] or "",
        pairing_method=row["pairing_method"] or "none",
        code_path=row["code_path"] or "",
        code_possibly_stale=bool(row["code_possibly_stale"]),
        model_id=row["model_id"] or "",
        log_excerpt=(row["log_sanitized"] or "")[:4000],
    )


def _analyse_upload(state: AppState, p: Principal, upload, account: Account) -> dict:
    """Run one uploaded failure and store it. Executed on a worker thread."""
    try:
        engine = state.engine()
    except BackendError as exc:
        raise RuntimeError(str(exc)) from exc

    analysis = engine.analyse(
        log_text=upload.log_text, code_text=upload.code_text,
        code_path=upload.code_name, code_mtime=upload.code_mtime,
        code_stale=False, bot_label=upload.label,
        code_location=upload.code_name,
        image=upload.image,
        # An upload has no code mtime, so the reuse gate cannot tell whether
        # the code changed. Refusing reuse is the honest answer -- see
        # ingest.py's module docstring.
        force=not upload.may_reuse)

    bots = BotRepo(state.db, p)
    bot_id = bots.upsert(upload.service_line, upload.bot_number)
    bots.set_owner(bot_id, account.email)

    fp_id = FingerprintRepo(state.db, p).touch(
        analysis.fingerprint or ("0" * 64), 1,
        upload.exception_type or "Unknown", upload.message or "",
        upload.code_name or "")

    # Every call in this analysis, not just the last: triage and deep are two
    # calls and charging for one of them understates the spend the caps read.
    tokens_in = sum(u.input_tokens for u in analysis.usages)
    tokens_out = sum(u.output_tokens for u in analysis.usages)
    cost = sum(u.cost_usd for u in analysis.usages if u.priced)
    latency = sum(u.latency_ms for u in analysis.usages)
    model_id = analysis.usages[-1].model if analysis.usages else ""

    analysis_id = AnalysisRepo(state.db, p).add(
        fp_id, path=analysis.path, root_cause=analysis.root_cause,
        suggested_fix=analysis.suggested_fix, confidence=analysis.confidence,
        model_id=model_id, inputs_used=tuple(analysis.inputs_used),
        tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=cost,
        latency_ms=latency)

    failure_id = FailureRepo(state.db, p).add(
        bot_id=bot_id, fingerprint_id=fp_id, analysis_id=analysis_id,
        occurred_at=upload.occurred_at.replace(tzinfo=None).isoformat(
            timespec="seconds"),
        log_path=f"upload://{account.email}/{now()}",
        screenshot_path="uploaded" if upload.image else None,
        code_path=upload.code_name or None,
        pairing_method=upload.pairing_method,
        log_sanitized=upload.log_text[:20000],
        correlation_id=secrets.token_hex(8))

    _record_analysis(state.db, p, failure_id)
    return {"failure_id": failure_id, "confidence": analysis.confidence,
            "path": analysis.path, "cost_usd": cost,
            "degradations": upload.degradations}


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
