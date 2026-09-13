"""Persistence: schema, migrations, repositories, retention.

Everything else sits on this. Without it there is no failure history, no local
dedup, no feedback, no metrics and nothing to apply a retention policy to.

Two decisions worth knowing before reading:

1. Every repository is constructed WITH A PRINCIPAL. There is no constructor
   without one. Today a local install resolves to an implicit admin and the
   answer is always yes, so nothing is restricted -- but the parameter is
   threaded through every call site now, while it is cheap. When enforcement
   moves server-side (docs/ARCHITECTURE.md, RBAC staging) that becomes a change
   of who answers rather than a rewrite of every caller. Authorization that has
   to be retrofitted is authorization that gets forgotten in one place.

2. The schema lives in schema.sql, not in a string here, and
   docs/DATA_MODEL.md embeds that file verbatim. A test fails if they drift.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SCHEMA_VERSION = 1


def now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _plus(days: int) -> str:
    return (datetime.now(timezone.utc).replace(tzinfo=None)
            + timedelta(days=days)).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

ADMIN, MANAGER, USER = "admin", "manager", "user"


@dataclass(frozen=True)
class Principal:
    """Who is asking. Required by every repository.

    `scope` is the set of team names a manager covers; empty means "own bots
    only" for a user, and is ignored for an admin.
    """
    actor: str
    role: str = USER
    scope: frozenset[str] = frozenset()

    @property
    def is_admin(self) -> bool:
        return self.role == ADMIN

    def may_see_team(self, team: str | None) -> bool:
        if self.is_admin:
            return True
        if self.role == MANAGER:
            return team in self.scope
        return False

    @staticmethod
    def local() -> "Principal":
        """The single operator of a local install.

        A local install cannot enforce roles against its own operator -- they
        own the machine. Pretending otherwise would be theatre, so local mode
        says plainly that the operator is the admin, and the audit log records
        what they did. Real enforcement arrives with the server.
        """
        import getpass
        try:
            who = getpass.getuser()
        except Exception:
            who = "unknown"
        return Principal(actor=who, role=ADMIN)


class AccessDenied(PermissionError):
    pass


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    def migrate(self) -> None:
        """Create or upgrade. Idempotent, so it is safe on every start."""
        current = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if current == 0:
            self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        elif current > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.path} was written by a newer version (schema {current}, "
                f"this build understands {SCHEMA_VERSION}). Upgrade rather than "
                f"risk writing data an older build cannot read.")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    def close(self) -> None:
        self.conn.close()


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

class Repository:
    """Base. A repository cannot be constructed without a principal."""

    def __init__(self, db: Database, principal: Principal) -> None:
        if not isinstance(principal, Principal):
            raise TypeError(
                "a repository needs a Principal. Use Principal.local() for a "
                "single-operator install; never default it to None.")
        self.db = db
        self.p = principal

    def _audit(self, action: str, resource_type: str, resource_id: str,
               outcome: str = "allow") -> None:
        self.db.conn.execute(
            "INSERT INTO audit_event(actor, actor_role, action, resource_type,"
            " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
            (self.p.actor, self.p.role, action, resource_type, str(resource_id),
             outcome, now()))


class BotRepo(Repository):
    def upsert(self, service_line: str, bot_number: str,
               code_path: str | None = None) -> int:
        cur = self.db.conn.execute(
            "SELECT id FROM bot WHERE service_line=? AND bot_number=?",
            (service_line, bot_number))
        row = cur.fetchone()
        if row:
            if code_path:
                self.db.conn.execute("UPDATE bot SET code_path=? WHERE id=?",
                                     (code_path, row["id"]))
            return row["id"]
        cur = self.db.conn.execute(
            "INSERT INTO bot(service_line, bot_number, code_path) VALUES (?,?,?)",
            (service_line, bot_number, code_path))
        return cur.lastrowid


class FingerprintRepo(Repository):
    def touch(self, fp_hash: str, version: int, exception_type: str,
              normalized_message: str, code_location: str,
              retain_days: int = 730) -> int:
        """Record a sighting. Returns the fingerprint id."""
        row = self.db.conn.execute(
            "SELECT id FROM fingerprint WHERE hash=? AND version=?",
            (fp_hash, version)).fetchone()
        if row:
            self.db.conn.execute(
                "UPDATE fingerprint SET last_seen_at=?, occurrence_count=occurrence_count+1"
                " WHERE id=?", (now(), row["id"]))
            return row["id"]
        cur = self.db.conn.execute(
            "INSERT INTO fingerprint(hash, version, exception_type, normalized_message,"
            " code_location, first_seen_at, last_seen_at, expires_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (fp_hash, version, exception_type, normalized_message[:500],
             code_location, now(), now(), _plus(retain_days)))
        return cur.lastrowid

    def recent_analysis(self, fp_id: int, *, within_days: int = 30,
                        code_mtime: str | None = None) -> sqlite3.Row | None:
        """The reuse gate from docs/DATA_MODEL.md 2.6, in SQL.

        Requires: not superseded, inside the TTL, same code version, and no
        developer has marked it wrong.
        """
        cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
                  - timedelta(days=within_days)).isoformat(timespec="seconds")
        sql = ("SELECT a.* FROM analysis a"
               " WHERE a.fingerprint_id=? AND a.is_superseded=0 AND a.created_at >= ?"
               "   AND NOT EXISTS (SELECT 1 FROM feedback f"
               "                   WHERE f.analysis_id=a.id AND f.verdict='wrong')")
        params: list[Any] = [fp_id, cutoff]
        if code_mtime is not None:
            sql += " AND a.code_mtime IS ?"
            params.append(code_mtime)
        sql += " ORDER BY a.created_at DESC LIMIT 1"
        return self.db.conn.execute(sql, params).fetchone()


class AnalysisRepo(Repository):
    def add(self, fingerprint_id: int, *, path: str, root_cause: str,
            suggested_fix: str, confidence: float, model_id: str = "",
            code_mtime: str | None = None, inputs_used: tuple[str, ...] = (),
            tokens_in: int = 0, tokens_out: int = 0, cost_usd: float = 0.0,
            latency_ms: int = 0, retain_days: int = 365) -> int:
        cur = self.db.conn.execute(
            "INSERT INTO analysis(fingerprint_id, path, model_id, code_mtime, root_cause,"
            " suggested_fix, confidence, inputs_used, tokens_in, tokens_out, cost_usd,"
            " latency_ms, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fingerprint_id, path, model_id, code_mtime, root_cause, suggested_fix,
             confidence, json.dumps(list(inputs_used)), tokens_in, tokens_out,
             cost_usd, latency_ms, now(), _plus(retain_days)))
        self._audit("create", "analysis", cur.lastrowid)
        return cur.lastrowid

    def get(self, analysis_id: int) -> sqlite3.Row | None:
        row = self.db.conn.execute("SELECT * FROM analysis WHERE id=?",
                                   (analysis_id,)).fetchone()
        self._audit("read", "analysis", analysis_id, "allow" if row else "deny")
        return row

    def supersede(self, analysis_id: int) -> None:
        self.db.conn.execute("UPDATE analysis SET is_superseded=1 WHERE id=?",
                             (analysis_id,))
        self._audit("supersede", "analysis", analysis_id)


class FailureRepo(Repository):
    def add(self, *, bot_id: int, fingerprint_id: int, occurred_at: str,
            log_path: str, analysis_id: int | None = None,
            screenshot_path: str | None = None, code_path: str | None = None,
            code_mtime: str | None = None, code_possibly_stale: bool = False,
            pairing_method: str = "none", log_sanitized: str = "",
            code_snapshot: str = "", status: str = "analyzed",
            was_deduped: bool = False, correlation_id: str = "",
            content_days: int = 90, retain_days: int = 730) -> int | None:
        """Insert, or None when this log has already been ingested.

        The unique index on log_path is what makes a re-scan a no-op, which is
        what lets the scanner be restarted without reprocessing the estate.
        """
        try:
            cur = self.db.conn.execute(
                "INSERT INTO failure(bot_id, fingerprint_id, analysis_id, occurred_at,"
                " ingested_at, status, was_deduped, log_path, screenshot_path, code_path,"
                " code_mtime, code_possibly_stale, pairing_method, log_sanitized,"
                " code_snapshot, correlation_id, content_expires_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (bot_id, fingerprint_id, analysis_id, occurred_at, now(), status,
                 int(was_deduped), log_path, screenshot_path, code_path, code_mtime,
                 int(code_possibly_stale), pairing_method, log_sanitized, code_snapshot,
                 correlation_id, _plus(content_days), _plus(retain_days)))
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    def recent(self, limit: int = 50) -> list[sqlite3.Row]:
        rows = self.db.conn.execute(
            "SELECT f.*, b.service_line, b.bot_number, a.root_cause, a.confidence"
            " FROM failure f JOIN bot b ON b.id=f.bot_id"
            " LEFT JOIN analysis a ON a.id=f.analysis_id"
            " ORDER BY f.occurred_at DESC LIMIT ?", (limit,)).fetchall()
        return [r for r in rows if self._visible(r)]

    def _visible(self, row: sqlite3.Row) -> bool:
        """Scoping applied here, where the rows are, not at a route.

        Local installs run as admin so this is always True today. It exists so
        that when the server arrives the filter is already in the one place
        every read passes through.
        """
        if self.p.is_admin:
            return True
        if self.p.role == MANAGER:
            return self.p.may_see_team(row["service_line"])
        return True

    def stats(self) -> dict[str, Any]:
        c = self.db.conn
        total = c.execute("SELECT COUNT(*) FROM failure").fetchone()[0]
        deduped = c.execute("SELECT COUNT(*) FROM failure WHERE was_deduped=1").fetchone()[0]
        spend = c.execute("SELECT COALESCE(SUM(cost_usd),0) FROM analysis").fetchone()[0]
        fps = c.execute("SELECT COUNT(*) FROM fingerprint").fetchone()[0]
        return {"failures": total, "deduped": deduped, "fingerprints": fps,
                "dedup_rate": (deduped / total) if total else 0.0,
                "spend_usd": spend}


class FeedbackRepo(Repository):
    """Developer verdicts. The ground truth that makes improvement possible.

    It also invalidates reuse immediately: an analysis marked wrong is never
    served again (see FingerprintRepo.recent_analysis). Feedback is not only
    future training data -- it is the cheapest quality mechanism in the system.
    """

    def add(self, analysis_id: int, failure_id: int, developer_id: int,
            verdict: str, comment: str = "") -> None:
        if verdict not in ("correct", "partial", "wrong"):
            raise ValueError(f"verdict must be correct/partial/wrong, got {verdict!r}")
        self.db.conn.execute(
            "INSERT OR REPLACE INTO feedback(analysis_id, failure_id, developer_id,"
            " verdict, comment, created_at) VALUES (?,?,?,?,?,?)",
            (analysis_id, failure_id, developer_id, verdict, comment, now()))
        self._audit("feedback", "analysis", analysis_id)

    def tally(self) -> dict[str, int]:
        rows = self.db.conn.execute(
            "SELECT verdict, COUNT(*) n FROM feedback GROUP BY verdict").fetchall()
        return {r["verdict"]: r["n"] for r in rows}


class WatermarkRepo(Repository):
    """What the scanner has already processed.

    This is what makes a re-run cheap and a restart safe: the catch-up scan
    (docs/ARCHITECTURE.md 4.3) processes everything since the last mark rather
    than starting from now, so failures that arrived while the host was off are
    not lost.
    """

    def seen(self, file_path: str, mtime: str, size: int) -> bool:
        row = self.db.conn.execute(
            "SELECT file_mtime, file_size FROM scan_watermark WHERE file_path=?",
            (file_path,)).fetchone()
        return bool(row and row["file_mtime"] == mtime and row["file_size"] == size)

    def mark(self, file_path: str, mtime: str, size: int, outcome: str = "ingested") -> None:
        self.db.conn.execute(
            "INSERT OR REPLACE INTO scan_watermark(file_path, file_mtime, file_size,"
            " processed_at, outcome) VALUES (?,?,?,?,?)",
            (file_path, mtime, size, now(), outcome))

    def count(self) -> int:
        return self.db.conn.execute("SELECT COUNT(*) FROM scan_watermark").fetchone()[0]


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------

@dataclass
class RetentionResult:
    content_nulled: int = 0
    failures_deleted: int = 0
    analyses_deleted: int = 0
    fingerprints_deleted: int = 0
    watermarks_deleted: int = 0

    def summary(self) -> str:
        return (f"{self.content_nulled} content nulled, "
                f"{self.failures_deleted} failures, {self.analyses_deleted} analyses, "
                f"{self.fingerprints_deleted} fingerprints, "
                f"{self.watermarks_deleted} watermarks deleted")


def run_retention(db: Database, principal: Principal, *,
                  watermark_days: int = 180, batch: int = 500) -> RetentionResult:
    """Apply the retention policy. Idempotent and safe to re-run.

    Content is nulled before rows are deleted, so a failure keeps its
    fingerprint and timestamps for trend analysis long after its log text is
    gone -- metrics survive, PII does not (docs/DATA_MODEL.md 3).
    """
    if not principal.is_admin:
        raise AccessDenied("only an admin may run retention")

    r = RetentionResult()
    ts = now()
    c = db.conn

    cur = c.execute(
        "UPDATE failure SET log_sanitized=NULL, code_snapshot=NULL"
        " WHERE content_expires_at <= ? AND (log_sanitized IS NOT NULL"
        "    OR code_snapshot IS NOT NULL)", (ts,))
    r.content_nulled = cur.rowcount

    # Children before parents; FKs are enforced.
    cur = c.execute("DELETE FROM failure WHERE expires_at <= ?"
                    " AND id IN (SELECT id FROM failure WHERE expires_at <= ? LIMIT ?)",
                    (ts, ts, batch))
    r.failures_deleted = cur.rowcount

    cur = c.execute(
        "DELETE FROM analysis WHERE expires_at <= ?"
        " AND id NOT IN (SELECT analysis_id FROM failure WHERE analysis_id IS NOT NULL)",
        (ts,))
    r.analyses_deleted = cur.rowcount

    cur = c.execute(
        "DELETE FROM fingerprint WHERE expires_at <= ?"
        " AND id NOT IN (SELECT fingerprint_id FROM failure)"
        " AND id NOT IN (SELECT fingerprint_id FROM analysis)", (ts,))
    r.fingerprints_deleted = cur.rowcount

    cutoff = (datetime.now(timezone.utc).replace(tzinfo=None)
              - timedelta(days=watermark_days)).isoformat(timespec="seconds")
    cur = c.execute("DELETE FROM scan_watermark WHERE processed_at < ?", (cutoff,))
    r.watermarks_deleted = cur.rowcount

    c.execute("INSERT INTO audit_event(actor, actor_role, action, resource_type,"
              " resource_id, outcome, occurred_at) VALUES (?,?,?,?,?,?,?)",
              (principal.actor, principal.role, "retention", "database",
               str(db.path), "allow", now()))
    return r
