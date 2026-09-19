"""Spend, read from the database rather than from a counter in a process.

This is the half of A1 that only matters once the app is hosted. `BudgetGuard`
asks a `SpendLedger` what has been spent; `MemoryLedger` answers from a list
that dies with the process. On a public URL making real paid calls that is not
a budget, so this answers from `analysis.cost_usd`, which is committed.

Three caps, and they are different questions:

    single call     is this one request unreasonable on its own?
    daily           has today run away?
    total           has this deployment, over its life, cost more than it is
                    worth? This is the one that matters for a demo left running
                    -- a daily cap of $2 still permits $60 a month unattended.

Plus a kill switch, because the only thing worse than an unexpected bill is
finding you need a redeploy to stop it.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ..model_gateway import BudgetGuard
from ..storage import Database

KILL_SWITCH_VAR = "EAGLE_EYES_DISABLE_MODEL"
DAILY_VAR = "EAGLE_EYES_DAILY_USD"
TOTAL_VAR = "EAGLE_EYES_TOTAL_USD"
PER_RUN_VAR = "EAGLE_EYES_PER_RUN_USD"
SINGLE_CALL_VAR = "EAGLE_EYES_SINGLE_CALL_USD"
HOURLY_ANALYSES_VAR = "EAGLE_EYES_HOURLY_ANALYSES"

DEFAULT_DAILY = 2.00
DEFAULT_TOTAL = 25.00
DEFAULT_PER_RUN = 0.50
# Above the projection of the most expensive SELECTABLE model, and that is the
# whole requirement. At 0.05 this sat below the $0.06 a Sonnet deep call is
# projected at, so every deep analysis on the hosted instance was refused
# before it was attempted -- a valid key, an untouched budget, and "single call
# projected at $0.0600, cap is $0.05" instead of a diagnosis. Opus 5 projects
# at $0.144, so admitting it needs 0.20.
#
# This is the weakest of the three caps by design: it only asks whether one
# request is unreasonable on its own, and $0.15 for an Opus call is not. The
# daily ($2) and lifetime ($25) caps are the real protection and are unchanged,
# so the worst case is still a refusal rather than a bill. A test asserts this
# admits every model the dropdown offers.
DEFAULT_SINGLE_CALL = 0.20
DEFAULT_HOURLY_ANALYSES = 20


class DatabaseLedger:
    """Spend as committed rows, so it survives a restart and a second worker."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def spent_since(self, hours: float) -> float:
        cutoff = _stamp(datetime.now(timezone.utc) - timedelta(hours=hours))
        return self.db.conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM analysis WHERE created_at >= ?",
            (cutoff,)).fetchone()[0] or 0.0

    def spent_total(self) -> float:
        return self.db.conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM analysis").fetchone()[0] or 0.0


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def kill_switch_on(env: dict[str, str] | None = None) -> bool:
    """Whether model calls are disabled right now.

    Read fresh on every call, never cached at import: the point of a kill switch
    is that flipping the variable and restarting one worker stops the spend,
    without a redeploy and without a code change.
    """
    env = env if env is not None else os.environ
    return (env.get(KILL_SWITCH_VAR, "") or "").strip().lower() in (
        "1", "true", "yes", "on")


def guard_for(db: Database, env: dict[str, str] | None = None) -> BudgetGuard:
    """A BudgetGuard wired to the database and to the environment's caps."""
    env = env if env is not None else os.environ
    return BudgetGuard(
        daily_usd=_money(env, DAILY_VAR, DEFAULT_DAILY),
        per_run_usd=_money(env, PER_RUN_VAR, DEFAULT_PER_RUN),
        single_call_usd=_money(env, SINGLE_CALL_VAR, DEFAULT_SINGLE_CALL),
        total_usd=_money(env, TOTAL_VAR, DEFAULT_TOTAL),
        ledger=DatabaseLedger(db),
        enabled=not kill_switch_on(env),
    )


def hourly_analysis_cap(env: dict[str, str] | None = None) -> int:
    env = env if env is not None else os.environ
    try:
        return max(0, int(env.get(HOURLY_ANALYSES_VAR, DEFAULT_HOURLY_ANALYSES)))
    except ValueError:
        return DEFAULT_HOURLY_ANALYSES


def analyses_this_hour(db: Database, actor: str) -> int:
    """How many analyses one person has caused in the last hour.

    Per person, not global: a global cap lets one enthusiastic user exhaust the
    budget for everyone, which on a demo URL is the same as taking the demo
    down. Counted from the audit log, which is append-only and already records
    every analysis -- a separate counter would be a second source of truth to
    keep in step.
    """
    cutoff = _stamp(datetime.now(timezone.utc) - timedelta(hours=1))
    return db.conn.execute(
        "SELECT COUNT(*) n FROM audit_event WHERE actor=? AND action='analyse'"
        " AND outcome='allow' AND occurred_at >= ?",
        (actor, cutoff)).fetchone()["n"]


def _money(env: dict[str, str], var: str, default: float) -> float:
    raw = (env.get(var) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default
