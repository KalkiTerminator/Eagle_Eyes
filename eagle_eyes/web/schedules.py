"""Scheduled scans of a path on the machine running this process.

THE SEMANTIC, STATED ONCE: a schedule reads a directory on the host running
Eagle Eyes. Not a path on the user's laptop that they typed into a browser --
the browser cannot reach their filesystem, and the server cannot either. It is
the host's own disk, which is the right thing when the tool runs on the desktop
or jump server that already reaches the share, and a meaningless thing on a
hosted container.

So the runner checks. In a container it records `no_filesystem` and the page
says so, naming what to run locally instead. It does NOT tick over an empty
directory and report success, because a monitoring job that reports healthy
while looking at nothing is the exact failure this product argues against.

Everything else is deliberately reused rather than rebuilt: `discovery.discover`
finds and pairs, the `JobQueue` runs the work off the request path, and the
budget guard and per-person hourly cap still apply -- so a schedule set to five
minutes cannot outspend the caps any more than a person clicking Analyse can.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import runtime
from ..storage import AccessDenied, Repository, now

MIN_MINUTES = 5
TICK_SECONDS = 30.0

# What a run concluded. Recorded rather than inferred, so the page never has to
# guess why a schedule has not produced anything.
OK = "ok"
NO_FILESYSTEM = "no_filesystem"
MISSING_PATH = "missing_path"
NOTHING_FOUND = "nothing_found"
FAILED = "failed"

OUTCOMES = {
    OK: "Scanned",
    NO_FILESYSTEM: "Not run — this instance has no filesystem to scan",
    MISSING_PATH: "That path does not exist on the host",
    NOTHING_FOUND: "Scanned, found no new failures",
    FAILED: "The scan failed",
}


@dataclass(frozen=True)
class Schedule:
    id: int
    account_id: int
    name: str
    target_path: str
    share_root: str
    code_root: str
    every_minutes: int
    enabled: bool
    last_run_at: str | None
    last_outcome: str | None
    last_found: int
    last_analysed: int

    @property
    def outcome_text(self) -> str:
        if not self.last_outcome:
            return "Not run yet"
        return OUTCOMES.get(self.last_outcome, self.last_outcome)

    @property
    def healthy(self) -> bool:
        return self.last_outcome in (OK, NOTHING_FOUND)


class ScheduleRepo(Repository):
    """Schedules belong to the account that made them.

    Scoped by owner rather than by the failure rules: a schedule names a path
    on the host, which is not team data, and one person's scanning arrangements
    are not another's business. An admin sees all of them because someone has
    to be able to find the one that is spending money.
    """

    def _owned(self) -> tuple[str, list]:
        if self.p.is_admin:
            return "", []
        return (" AND s.account_id IN (SELECT id FROM account WHERE email = ?)",
                [self.p.actor.lower()])

    SELECT_ = ("SELECT s.* FROM scan_schedule s")

    def add(self, account_id: int, *, name: str, target_path: str,
            share_root: str, code_root: str, every_minutes: int) -> int:
        name = (name or "").strip()[:80]
        if not name:
            raise ValueError("a schedule needs a name")
        if every_minutes < MIN_MINUTES:
            raise ValueError(
                f"the shortest interval is {MIN_MINUTES} minutes. Anything "
                "faster re-scans a share that has not changed and spends the "
                "budget proving it.")
        for label, value in (("target", target_path), ("share root", share_root)):
            if not (value or "").strip():
                raise ValueError(f"a {label} path is required")
        cur = self.db.conn.execute(
            "INSERT INTO scan_schedule(account_id, name, target_path, share_root,"
            " code_root, every_minutes, enabled, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (account_id, name, target_path.strip(), share_root.strip(),
             (code_root or share_root).strip(), int(every_minutes), True, now()))
        self._audit("create", "schedule", cur.lastrowid)
        return cur.lastrowid

    def list(self) -> list[Schedule]:
        where, args = self._owned()
        rows = self.db.conn.execute(
            f"{self.SELECT_} WHERE TRUE{where} ORDER BY s.created_at DESC",
            args).fetchall()
        return [_build(r) for r in rows]

    def get(self, schedule_id: int) -> Schedule:
        where, args = self._owned()
        row = self.db.conn.execute(
            f"{self.SELECT_} WHERE s.id = ?{where}", [schedule_id, *args]).fetchone()
        if row is None:
            self._audit("read", "schedule", schedule_id, outcome="deny")
            raise AccessDenied(f"no schedule {schedule_id} belongs to {self.p.actor}")
        return _build(row)

    def set_enabled(self, schedule_id: int, enabled: bool) -> None:
        self.get(schedule_id)                     # raises if not theirs
        self.db.conn.execute(
            "UPDATE scan_schedule SET enabled = ? WHERE id = ?",
            (bool(enabled), schedule_id))
        self._audit("enable" if enabled else "disable", "schedule", schedule_id)

    def delete(self, schedule_id: int) -> None:
        self.get(schedule_id)
        self.db.conn.execute("DELETE FROM scan_schedule WHERE id = ?", (schedule_id,))
        self._audit("delete", "schedule", schedule_id)

    def due(self, at: datetime | None = None) -> list[Schedule]:
        """Enabled schedules whose interval has elapsed. Admin-only path --
        the runner uses it, and it deliberately ignores ownership."""
        at = at or datetime.now(timezone.utc)
        rows = self.db.conn.execute(
            "SELECT * FROM scan_schedule WHERE enabled = TRUE").fetchall()
        out = []
        for row in rows:
            s = _build(row)
            if s.last_run_at is None:
                out.append(s)
                continue
            try:
                last = datetime.fromisoformat(s.last_run_at).replace(tzinfo=timezone.utc)
            except ValueError:
                out.append(s)
                continue
            if at - last >= timedelta(minutes=s.every_minutes):
                out.append(s)
        return out

    def record_run(self, schedule_id: int, outcome: str, *,
                   found: int = 0, analysed: int = 0) -> None:
        self.db.conn.execute(
            "UPDATE scan_schedule SET last_run_at = ?, last_outcome = ?,"
            " last_found = ?, last_analysed = ? WHERE id = ?",
            (now(), outcome, found, analysed, schedule_id))


def _build(row) -> Schedule:
    return Schedule(
        id=row["id"], account_id=row["account_id"], name=row["name"],
        target_path=row["target_path"], share_root=row["share_root"],
        code_root=row["code_root"], every_minutes=row["every_minutes"],
        enabled=bool(row["enabled"]), last_run_at=row["last_run_at"],
        last_outcome=row["last_outcome"], last_found=row["last_found"] or 0,
        last_analysed=row["last_analysed"] or 0)


def can_scan_this_host() -> tuple[bool, str]:
    """Whether a schedule can do anything here, and why not when it cannot."""
    if runtime.in_container():
        return False, (
            "This instance runs in a container. It has no desktop and no mapped "
            "share, so a schedule here has nothing to read — it would report "
            "success while scanning an empty directory. Schedules are still "
            "saved: run Eagle Eyes on the machine that can reach the logs "
            "(pip install '.[web]' then uvicorn, or the CLI with --target) and "
            "they will run there.")
    return True, ""


class ScheduleRunner:
    """Wakes periodically, runs what is due. One thread, daemon."""

    def __init__(self, db, principal, run_one, interval: float = TICK_SECONDS) -> None:
        self.db = db
        self.principal = principal
        self.run_one = run_one
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="eagle-eyes-schedules",
                                        daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception as exc:                 # never kill the thread
                print(f"  ! schedule tick failed: {exc}", flush=True)

    def tick(self, at: datetime | None = None) -> int:
        repo = ScheduleRepo(self.db, self.principal)
        ran = 0
        for schedule in repo.due(at):
            scannable, _ = can_scan_this_host()
            if not scannable:
                repo.record_run(schedule.id, NO_FILESYSTEM)
                continue
            if not Path(schedule.target_path).exists():
                repo.record_run(schedule.id, MISSING_PATH)
                continue
            try:
                found, analysed = self.run_one(schedule)
                repo.record_run(schedule.id, OK if found else NOTHING_FOUND,
                                found=found, analysed=analysed)
            except Exception as exc:
                print(f"  ! schedule '{schedule.name}' failed: {exc}", flush=True)
                repo.record_run(schedule.id, FAILED)
            ran += 1
        return ran

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)
